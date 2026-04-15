// =============================================================================
//  test_rudp_stream.cpp — tests for the RudpStream Asio AsyncStream adapter.
//
//  Pattern: two Rudp instances ("alice" and "bob") wired together by a
//  FakeWire that captures sends and feeds them to the other side. Each
//  side has a RudpStream wrapping its end of the channel; the FakeWire's
//  receive callback dispatches incoming CHANNEL bytes to the local
//  RudpStream via feed().
//
//  All Asio completion handlers are posted to a single io_context that
//  the test drives manually with poll() / poll_one() / run_one(). Time
//  is advanced by incrementing now_us and passing it to rudp.tick().
//  No real network, no real clock, no async background work.
// =============================================================================

#include <boost/test/unit_test.hpp>

#include <minx/rudp/rudp.h>
#include <minx/rudp/rudp_stream.h>
#include <minx/stdext.h>
#include <minx/types.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/system/error_code.hpp>

#include <cstring>
#include <deque>
#include <string>
#include <vector>

using minx::Bytes;
using minx::MinxStdExtensions;
using minx::Rudp;
using minx::RudpStream;
using minx::SockAddr;

// ---------------------------------------------------------------------------
// Fake wire — same shape as test_rudp.cpp's FakeWire, but routes inbound
// CHANNEL bytes into RudpStream::feed() instead of into a recv vector.
// HANDSHAKE packets are still routed through Rudp::onPacket (so the
// handshake state machine runs); CHANNEL message PAYLOADS get forwarded
// to the corresponding stream.
// ---------------------------------------------------------------------------

namespace {

struct CapturedPacket {
  SockAddr from;
  SockAddr to;
  Bytes bytes;
};

struct StreamWire {
  Rudp& alice;
  Rudp& bob;
  SockAddr aliceAddr;
  SockAddr bobAddr;
  RudpStream* aliceStream = nullptr;
  RudpStream* bobStream = nullptr;
  std::deque<CapturedPacket> queue;
  size_t dropNextAtoB = 0;
  size_t dropNextBtoA = 0;

  StreamWire(Rudp& a, Rudp& b, SockAddr aa, SockAddr ba)
      : alice(a), bob(b), aliceAddr(aa), bobAddr(ba) {

    alice.setSendCallback([this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({aliceAddr, peer, bytes});
    });
    bob.setSendCallback([this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({bobAddr, peer, bytes});
    });

    // When Rudp delivers a reliable CHANNEL message, route the payload
    // into the receiving side's RudpStream. Unreliable arrives via the
    // same callback but the streams discard it (or we ignore here).
    alice.setReceiveCallback([this](const SockAddr& /*peer*/, uint32_t /*cid*/,
                                    const Bytes& data, bool reliable) {
      if (reliable && aliceStream)
        aliceStream->feed(data);
    });
    bob.setReceiveCallback([this](const SockAddr& /*peer*/, uint32_t /*cid*/,
                                  const Bytes& data, bool reliable) {
      if (reliable && bobStream)
        bobStream->feed(data);
    });
  }

  // Drain to convergence. Each captured packet is parsed for its routing
  // key and delivered to the destination Rudp's onPacket(), which may
  // synchronously enqueue more packets that this same loop picks up.
  void deliverAll(uint64_t now_us = 0) {
    while (!queue.empty()) {
      auto pkt = queue.front();
      queue.pop_front();

      const bool aToB = (pkt.from == aliceAddr);
      if (aToB && dropNextAtoB > 0) {
        --dropNextAtoB;
        continue;
      }
      if (!aToB && dropNextBtoA > 0) {
        --dropNextBtoA;
        continue;
      }

      if (pkt.bytes.size() < MinxStdExtensions::KEY_SIZE)
        continue;
      uint64_t be;
      std::memcpy(&be, pkt.bytes.data(), MinxStdExtensions::KEY_SIZE);
      const uint64_t key = boost::endian::big_to_native(be);
      Bytes payload(pkt.bytes.begin() + MinxStdExtensions::KEY_SIZE,
                    pkt.bytes.end());
      if (aToB) {
        bob.onPacket(pkt.from, key, payload, now_us);
      } else {
        alice.onPacket(pkt.from, key, payload, now_us);
      }
    }
  }

  size_t pending() const { return queue.size(); }
};

SockAddr makeAddr(uint16_t port) {
  return SockAddr(boost::asio::ip::make_address("127.0.0.1"), port);
}

// Pump Asio: poll the io_context to drain all currently-posted handlers.
// Each call may post more handlers (e.g. a write completion that triggers
// the next read), which the next poll() call will drain.
void drainAsio(boost::asio::io_context& io) {
  io.restart();
  while (io.poll() > 0) {
    // keep going until no more ready handlers
  }
}

// Run one full tick + wire-deliver + Asio-drain step. Used between
// pushes to give the protocol a chance to make forward progress.
void step(boost::asio::io_context& io, Rudp& a, Rudp& b, StreamWire& wire,
          uint64_t now_us) {
  a.tick(now_us);
  b.tick(now_us);
  wire.deliverAll(now_us);
  drainAsio(io);
}

} // namespace

BOOST_AUTO_TEST_SUITE(RudpStreamSuite)

// ---------------------------------------------------------------------------
// 1. Smoke: construct two streams, no I/O, just lifecycle
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamConstructDestroy) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x1A1A1;
  Rudp alice(cfg);
  cfg.rngSeed = 0x2B2B2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11000), bA = makeAddr(11001);

  boost::asio::io_context io;

  RudpStream aliceStream(alice, bA, /*channel=*/1, io.get_executor());
  RudpStream bobStream(bob, aA, /*channel=*/1, io.get_executor());

  BOOST_TEST(aliceStream.is_open());
  BOOST_TEST(bobStream.is_open());
  BOOST_TEST(aliceStream.available() == 0u);
}

// ---------------------------------------------------------------------------
// 2. Small byte echo: alice writes "hello", bob reads "hello"
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamSmallEcho) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA11CE;
  Rudp alice(cfg);
  cfg.rngSeed = 0xB0B;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11100), bA = makeAddr(11101);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;

  RudpStream aliceStream(alice, bA, 1, io.get_executor());
  RudpStream bobStream(bob, aA, 1, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  uint64_t now = 0;
  const std::string payload = "hello rudp stream";

  // Alice writes the bytes.
  boost::system::error_code writeEc;
  std::size_t writeBytes = 0;
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });

  // Pump until the handshake completes and the bytes land on the wire
  // and bob's stream sees them. Each step: tick both sides, deliver wire,
  // drain posted Asio handlers.
  for (int i = 0; i < 10 && bobStream.available() < payload.size(); ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  BOOST_TEST(writeDone);
  BOOST_TEST(!writeEc);
  BOOST_TEST(writeBytes == payload.size());
  BOOST_TEST(bobStream.available() == payload.size());

  // Bob reads them back.
  std::vector<char> readBuf(payload.size());
  boost::system::error_code readEc;
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream.async_read_some(boost::asio::buffer(readBuf),
                            [&](boost::system::error_code ec, std::size_t n) {
                              readEc = ec;
                              readBytes = n;
                              readDone = true;
                            });

  drainAsio(io);

  BOOST_TEST(readDone);
  BOOST_TEST(!readEc);
  BOOST_TEST(readBytes == payload.size());
  BOOST_TEST(std::string(readBuf.begin(), readBuf.end()) == payload);
}

// ---------------------------------------------------------------------------
// 3. Large fragmented write: 10000 bytes spans many RUDP messages
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamLargeFragmented) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC0FFEE;
  Rudp alice(cfg);
  cfg.rngSeed = 0xDECAF;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11200), bA = makeAddr(11201);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 7, io.get_executor());
  RudpStream bobStream(bob, aA, 7, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  // Build a deterministic 10000-byte payload.
  const size_t N = 10000;
  std::vector<uint8_t> payload(N);
  for (size_t i = 0; i < N; ++i) {
    payload[i] = static_cast<uint8_t>(i & 0xFF);
  }
  // Sanity: this requires fragmentation across multiple RUDP messages.
  BOOST_TEST(N > Rudp::MAX_MESSAGE_SIZE);

  boost::system::error_code writeEc;
  std::size_t writeBytes = 0;
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });

  // Pump until everything has been delivered to bob's stream. Many
  // CHANNEL packets are in flight; each step exchanges one batch and
  // drains acks both ways.
  uint64_t now = 0;
  for (int i = 0; i < 50 && bobStream.available() < N; ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  BOOST_TEST(writeDone);
  BOOST_TEST(!writeEc);
  BOOST_REQUIRE_EQUAL(writeBytes, N);
  BOOST_REQUIRE_EQUAL(bobStream.available(), N);

  // Bob reads it all back into a contiguous buffer. async_read_some
  // returns at most `available` bytes; since we have N in the buffer
  // and we ask for N, it returns N in one go.
  std::vector<uint8_t> readBuf(N);
  boost::system::error_code readEc;
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream.async_read_some(boost::asio::buffer(readBuf),
                            [&](boost::system::error_code ec, std::size_t n) {
                              readEc = ec;
                              readBytes = n;
                              readDone = true;
                            });
  drainAsio(io);

  BOOST_TEST(readDone);
  BOOST_TEST(!readEc);
  BOOST_REQUIRE_EQUAL(readBytes, N);
  BOOST_TEST(readBuf == payload);
}

// ---------------------------------------------------------------------------
// 4. Read before write: bob's reader is parked, alice's bytes arrive,
//    bob's reader fires automatically
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamReadBeforeWrite) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x1234;
  Rudp alice(cfg);
  cfg.rngSeed = 0x5678;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11300), bA = makeAddr(11301);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 3, io.get_executor());
  RudpStream bobStream(bob, aA, 3, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  // Bob installs a pending read FIRST, before any data exists.
  std::vector<char> readBuf(64);
  boost::system::error_code readEc;
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream.async_read_some(boost::asio::buffer(readBuf),
                            [&](boost::system::error_code ec, std::size_t n) {
                              readEc = ec;
                              readBytes = n;
                              readDone = true;
                            });

  drainAsio(io);
  BOOST_TEST(!readDone); // no data, handler not yet invoked

  // Now alice writes.
  const std::string msg = "hi from alice";
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(msg),
    [&](boost::system::error_code, std::size_t) { writeDone = true; });

  // Pump until bob receives and the pending reader fires.
  uint64_t now = 0;
  for (int i = 0; i < 10 && !readDone; ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  BOOST_TEST(writeDone);
  BOOST_TEST(readDone);
  BOOST_TEST(!readEc);
  BOOST_REQUIRE_EQUAL(readBytes, msg.size());
  BOOST_TEST(std::string(readBuf.begin(), readBuf.begin() + readBytes) == msg);
}

// ---------------------------------------------------------------------------
// 5. close() fires a pending reader with eof
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamCloseFiresPendingReaderWithEof) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xEFEF;
  Rudp alice(cfg);
  cfg.rngSeed = 0xFEFE;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11400), bA = makeAddr(11401);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 5, io.get_executor());
  RudpStream bobStream(bob, aA, 5, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  std::vector<char> readBuf(32);
  boost::system::error_code readEc;
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream.async_read_some(boost::asio::buffer(readBuf),
                            [&](boost::system::error_code ec, std::size_t n) {
                              readEc = ec;
                              readBytes = n;
                              readDone = true;
                            });

  drainAsio(io);
  BOOST_TEST(!readDone);

  // Close bob's stream while a reader is parked. The reader should
  // fire with eof and zero bytes.
  bobStream.close();
  drainAsio(io);

  BOOST_TEST(readDone);
  BOOST_TEST(readEc == boost::asio::error::eof);
  BOOST_TEST(readBytes == 0u);
  BOOST_TEST(!bobStream.is_open());
}

// ---------------------------------------------------------------------------
// 6. Operations on a closed stream complete immediately with eof
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamWriteAfterCloseFailsEof) {
  minx::RudpConfig cfg;
  Rudp r(cfg);
  SockAddr peer = makeAddr(11500);
  boost::asio::io_context io;
  RudpStream stream(r, peer, 1, io.get_executor());

  stream.close();
  BOOST_TEST(!stream.is_open());

  const std::string msg = "ignored";
  boost::system::error_code writeEc;
  std::size_t writeBytes = 9999;
  bool writeDone = false;
  stream.async_write_some(boost::asio::buffer(msg),
                          [&](boost::system::error_code ec, std::size_t n) {
                            writeEc = ec;
                            writeBytes = n;
                            writeDone = true;
                          });
  drainAsio(io);

  BOOST_TEST(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::eof);
  BOOST_TEST(writeBytes == 0u);

  std::vector<char> readBuf(32);
  boost::system::error_code readEc;
  std::size_t readBytes = 9999;
  bool readDone = false;
  stream.async_read_some(boost::asio::buffer(readBuf),
                         [&](boost::system::error_code ec, std::size_t n) {
                           readEc = ec;
                           readBytes = n;
                           readDone = true;
                         });
  drainAsio(io);

  BOOST_TEST(readDone);
  BOOST_TEST(readEc == boost::asio::error::eof);
  BOOST_TEST(readBytes == 0u);
}

// ---------------------------------------------------------------------------
// 7. Back-pressure: async_write_some with more bytes than sendBuf can
//    hold is deferred, not failed. The handler stays pending until
//    acks drain sendBuf via onSendBufDrained.
//
// Setup: tight maxReorderMessagesPerChannel so alice's sendBuf fills
// after just a few chunks. Issue one big async_write_some that fills
// and overflows. Expect the handler to NOT fire on the first drain.
// Pump steps (tick + deliver + asio drain) and verify: the write
// completes eventually with success and full byte count, and bob's
// stream receives all the bytes in order.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamBackPressureDeferAndResume) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  // Tight cap: sendBuf will only hold 4 messages at a time. Our
  // payload below produces ~8 chunks, so alice must defer.
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0xBBBB;
  Rudp alice(cfg);
  cfg.rngSeed = 0xCCCC;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11600), bA = makeAddr(11601);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, /*channel=*/9, io.get_executor());
  RudpStream bobStream(bob, aA, /*channel=*/9, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  // Build an 8-chunk payload. MAX_MESSAGE_SIZE is 1245; 8 * 1245 =
  // 9960 bytes, which at 4-msg cap requires at least two full
  // drain-and-refill cycles.
  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N);
  for (std::size_t i = 0; i < N; ++i) {
    payload[i] = static_cast<uint8_t>((i * 31) & 0xFF);
  }

  boost::system::error_code writeEc;
  std::size_t writeBytes = 0;
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });

  // After the initial call, alice's sendBuf is full (4 chunks) and
  // the handler is parked. The remaining 4 chunks are sitting in
  // pendingWriteBuf_. Handler should NOT have fired yet.
  drainAsio(io);
  BOOST_TEST(!writeDone);

  // Pump steps until bob has received everything AND alice's write
  // handler has completed. Each step: alice's pulse flushes some
  // chunks, bob acks, alice's drain callback resumes push, etc.
  uint64_t now = 0;
  for (int i = 0; i < 50 && (!writeDone || bobStream.available() < N); ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  BOOST_TEST(writeDone);
  BOOST_TEST(!writeEc);
  BOOST_REQUIRE_EQUAL(writeBytes, N);
  BOOST_REQUIRE_EQUAL(bobStream.available(), N);

  // Verify byte-exact delivery end-to-end.
  std::vector<uint8_t> readBuf(N);
  boost::system::error_code readEc;
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream.async_read_some(boost::asio::buffer(readBuf),
                            [&](boost::system::error_code ec, std::size_t n) {
                              readEc = ec;
                              readBytes = n;
                              readDone = true;
                            });
  drainAsio(io);

  BOOST_TEST(readDone);
  BOOST_TEST(!readEc);
  BOOST_REQUIRE_EQUAL(readBytes, N);
  BOOST_TEST(readBuf == payload);
}

// ---------------------------------------------------------------------------
// 8. Channel destroyed: deferred writer aborts with operation_aborted.
//    Rudp::close() on a channel with a RudpStream's pending write in flight
//    must run RudpStream::onChannelDestroyed, which fires the handler with
//    operation_aborted (distinct from user-close eof).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamChannelDestroyedAbortsWriter) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4; // force back-pressure
  cfg.rngSeed = 0xE1E1;
  Rudp alice(cfg);
  cfg.rngSeed = 0xE2E2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11700), bA = makeAddr(11701);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 9, io.get_executor());
  RudpStream bobStream(bob, aA, 9, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  // Big write forces pendingWriteHandler_ to park.
  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N, 0xAB);

  boost::system::error_code writeEc;
  std::size_t writeBytes = 9999;
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });
  drainAsio(io);
  BOOST_TEST(!writeDone);

  // Destroy alice's channel directly. fireChannelDestroyed invokes
  // RudpStream::onChannelDestroyed, which aborts the deferred writer
  // with operation_aborted.
  alice.close(bA, 9);
  drainAsio(io);

  BOOST_TEST(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::operation_aborted);
  BOOST_TEST(writeBytes < N);
  BOOST_TEST(!aliceStream.is_open());
}

// ---------------------------------------------------------------------------
// 9. close() (user-level) aborts a deferred writer with eof.
//    Mirror of test 5 (which did the reader). Same back-pressure setup as
//    test 7, but instead of pumping to completion we close the stream and
//    assert the parked handler fires with eof.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamCloseAbortsPendingWriterWithEof) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0xF1F1;
  Rudp alice(cfg);
  cfg.rngSeed = 0xF2F2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11710), bA = makeAddr(11711);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 2, io.get_executor());
  RudpStream bobStream(bob, aA, 2, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N, 0xCD);

  boost::system::error_code writeEc;
  std::size_t writeBytes = 9999;
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });
  drainAsio(io);
  BOOST_TEST(!writeDone);

  // User-level close. Pending writer completes with eof (user closed),
  // not operation_aborted (which is reserved for rudp-level destroy).
  aliceStream.close();
  drainAsio(io);

  BOOST_TEST(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::eof);
  BOOST_TEST(writeBytes < N);
  BOOST_TEST(!aliceStream.is_open());
}

// ---------------------------------------------------------------------------
// 10. Scatter-gather read with partial drain.
//     Exercises both the MutableBufferSequence branch of async_read_some
//     (boost::asio::buffer_copy scatter) and the "caller asks for fewer
//     bytes than available" path — the first read drains 15 of 30 into
//     three 5-byte sub-buffers; a second read drains the remaining 15.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamScatterGatherReadPartial) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAAAA;
  Rudp alice(cfg);
  cfg.rngSeed = 0xBBBB;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11720), bA = makeAddr(11721);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 1, io.get_executor());
  RudpStream bobStream(bob, aA, 1, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  const std::string payload = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"; // 30 bytes
  BOOST_REQUIRE_EQUAL(payload.size(), 30u);
  aliceStream.async_write_some(boost::asio::buffer(payload),
                               [](boost::system::error_code, std::size_t) {});

  uint64_t now = 0;
  for (int i = 0; i < 10 && bobStream.available() < 30; ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }
  BOOST_REQUIRE_EQUAL(bobStream.available(), 30u);

  // Read into 3 small buffers (total 15 bytes).
  std::array<char, 5> a{}, b{}, c{};
  std::array<boost::asio::mutable_buffer, 3> seq = {
    boost::asio::buffer(a),
    boost::asio::buffer(b),
    boost::asio::buffer(c),
  };

  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream.async_read_some(seq, [&](boost::system::error_code, std::size_t n) {
    readBytes = n;
    readDone = true;
  });
  drainAsio(io);

  BOOST_TEST(readDone);
  BOOST_REQUIRE_EQUAL(readBytes, 15u);
  BOOST_TEST(std::string(a.begin(), a.end()) == "ABCDE");
  BOOST_TEST(std::string(b.begin(), b.end()) == "FGHIJ");
  BOOST_TEST(std::string(c.begin(), c.end()) == "KLMNO");
  BOOST_TEST(bobStream.available() == 15u);

  // Second read drains the remaining 15.
  std::vector<char> rest(15);
  std::size_t readBytes2 = 0;
  bool readDone2 = false;
  bobStream.async_read_some(boost::asio::buffer(rest),
                            [&](boost::system::error_code, std::size_t n) {
                              readBytes2 = n;
                              readDone2 = true;
                            });
  drainAsio(io);

  BOOST_TEST(readDone2);
  BOOST_REQUIRE_EQUAL(readBytes2, 15u);
  BOOST_TEST(std::string(rest.begin(), rest.end()) == "PQRSTUVWXYZ0123");
  BOOST_TEST(bobStream.available() == 0u);
}

// ---------------------------------------------------------------------------
// 11. Scatter-gather write with a multi-buffer ConstBufferSequence.
//     startWrite flattens the sequence into pendingWriteBuf_ in order.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamScatterGatherWrite) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xCCCC;
  Rudp alice(cfg);
  cfg.rngSeed = 0xDDDD;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11730), bA = makeAddr(11731);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 1, io.get_executor());
  RudpStream bobStream(bob, aA, 1, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  const std::string p1 = "AAAAA";
  const std::string p2 = "BBBBB";
  const std::string p3 = "CCCCC";
  std::array<boost::asio::const_buffer, 3> seq = {
    boost::asio::buffer(p1),
    boost::asio::buffer(p2),
    boost::asio::buffer(p3),
  };

  boost::system::error_code writeEc;
  std::size_t writeBytes = 0;
  bool writeDone = false;
  aliceStream.async_write_some(
    seq, [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });

  uint64_t now = 0;
  for (int i = 0; i < 10 && bobStream.available() < 15; ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  BOOST_TEST(writeDone);
  BOOST_TEST(!writeEc);
  BOOST_REQUIRE_EQUAL(writeBytes, 15u);
  BOOST_REQUIRE_EQUAL(bobStream.available(), 15u);

  std::vector<char> readBuf(15);
  std::size_t readBytes = 0;
  bobStream.async_read_some(
    boost::asio::buffer(readBuf),
    [&](boost::system::error_code, std::size_t n) { readBytes = n; });
  drainAsio(io);

  BOOST_REQUIRE_EQUAL(readBytes, 15u);
  BOOST_TEST(std::string(readBuf.begin(), readBuf.end()) == "AAAAABBBBBCCCCC");
}

// ---------------------------------------------------------------------------
// 12. A second async_write_some issued while a previous one is still
//     deferred completes immediately with error::in_progress. The first
//     write is NOT disturbed and runs to completion normally.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamConcurrentWriteReturnsInProgress) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0x1111;
  Rudp alice(cfg);
  cfg.rngSeed = 0x2222;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11740), bA = makeAddr(11741);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 3, io.get_executor());
  RudpStream bobStream(bob, aA, 3, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload1(N, 0x01);
  std::vector<uint8_t> payload2(4, 0x02);

  boost::system::error_code ec1, ec2;
  std::size_t n1 = 0, n2 = 9999;
  bool done1 = false, done2 = false;

  // First write defers (8 chunks, 4-msg cap).
  aliceStream.async_write_some(
    boost::asio::buffer(payload1),
    [&](boost::system::error_code ec, std::size_t n) {
      ec1 = ec;
      n1 = n;
      done1 = true;
    });

  // Second write while the first is still parked.
  aliceStream.async_write_some(
    boost::asio::buffer(payload2),
    [&](boost::system::error_code ec, std::size_t n) {
      ec2 = ec;
      n2 = n;
      done2 = true;
    });

  drainAsio(io);

  // The second call must complete immediately with in_progress and 0 bytes.
  BOOST_TEST(done2);
  BOOST_TEST(ec2 == boost::asio::error::in_progress);
  BOOST_TEST(n2 == 0u);

  // The first call is still parked — the reject path on the second write
  // must not have disturbed it.
  BOOST_TEST(!done1);

  // Pump to completion: the first write eventually succeeds in full.
  uint64_t now = 0;
  for (int i = 0; i < 50 && (!done1 || bobStream.available() < N); ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }
  BOOST_TEST(done1);
  BOOST_TEST(!ec1);
  BOOST_REQUIRE_EQUAL(n1, N);
}

// ---------------------------------------------------------------------------
// 13. Packet loss + retransmit: one alice→bob data packet is dropped on
//     the wire, RUDP's RTO fires, the packet is retransmitted, and bob's
//     stream eventually delivers the full payload. Exercises that the
//     stream adapter composes cleanly with RUDP's reliable-delivery
//     guarantees under loss.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamPacketDropRetransmit) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xDEDE;
  Rudp alice(cfg);
  cfg.rngSeed = 0xADAD;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11750), bA = makeAddr(11751);
  StreamWire wire(alice, bob, aA, bA);

  boost::asio::io_context io;
  RudpStream aliceStream(alice, bA, 1, io.get_executor());
  RudpStream bobStream(bob, aA, 1, io.get_executor());
  wire.aliceStream = &aliceStream;
  wire.bobStream = &bobStream;

  // Warm-up exchange gets the handshake out of the way so dropNextAtoB
  // below lands on a data packet, not a HANDSHAKE OPEN.
  const std::string warmup = "warmup";
  aliceStream.async_write_some(boost::asio::buffer(warmup),
                               [](boost::system::error_code, std::size_t) {});
  uint64_t now = 0;
  for (int i = 0; i < 20 && bobStream.available() < warmup.size(); ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }
  BOOST_REQUIRE_EQUAL(bobStream.available(), warmup.size());
  std::vector<char> dropBuf(warmup.size());
  bobStream.async_read_some(boost::asio::buffer(dropBuf),
                            [](boost::system::error_code, std::size_t) {});
  drainAsio(io);
  // A couple more steps so bob's ack of the warmup makes it back to alice
  // and there's nothing stale in alice's sendBuf.
  for (int i = 0; i < 3; ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  // Arm one drop in the alice→bob direction and send the real payload.
  wire.dropNextAtoB = 1;

  const std::string payload = "retransmit-me-please";
  boost::system::error_code writeEc;
  std::size_t writeBytes = 0;
  bool writeDone = false;
  aliceStream.async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeBytes = n;
      writeDone = true;
    });

  // Advance time aggressively so RUDP's pulse machinery notices the
  // missing ack and retransmits.
  for (int i = 0; i < 500 && bobStream.available() < payload.size(); ++i) {
    step(io, alice, bob, wire, now);
    now += 10000; // 10ms per step
  }

  BOOST_TEST(writeDone);
  BOOST_TEST(!writeEc);
  BOOST_REQUIRE_EQUAL(writeBytes, payload.size());
  BOOST_REQUIRE_EQUAL(bobStream.available(), payload.size());

  std::vector<char> readBuf(payload.size());
  std::size_t readBytes = 0;
  bobStream.async_read_some(
    boost::asio::buffer(readBuf),
    [&](boost::system::error_code, std::size_t n) { readBytes = n; });
  drainAsio(io);

  BOOST_REQUIRE_EQUAL(readBytes, payload.size());
  BOOST_TEST(std::string(readBuf.begin(), readBuf.end()) == payload);
}

BOOST_AUTO_TEST_SUITE_END()
