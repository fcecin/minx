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

// One side's Rudp::Listener. Wire output goes into the queue via
// onSend; inbound channels are answered with the pre-built RudpStream
// the test stashed (StreamWire wires this up). All per-channel events
// flow directly to the stream via the Rudp::ChannelHandler base — no
// translation needed.
struct StreamSideListener : public Rudp::Listener {
  std::function<void(const SockAddr&, const Bytes&)> sink;
  std::shared_ptr<RudpStream> inboundStream;

  void onSend(const SockAddr& peer, const Bytes& bytes) override {
    if (sink) sink(peer, bytes);
  }
  std::shared_ptr<Rudp::ChannelHandler> onAccept(const SockAddr&,
                                                 uint32_t) override {
    return inboundStream;
  }
};

struct StreamWire {
  Rudp& alice;
  Rudp& bob;
  StreamSideListener& aliceL;
  StreamSideListener& bobL;
  SockAddr aliceAddr;
  SockAddr bobAddr;
  std::shared_ptr<RudpStream> aliceStream;
  std::shared_ptr<RudpStream> bobStream;
  std::deque<CapturedPacket> queue;
  size_t dropNextAtoB = 0;
  size_t dropNextBtoA = 0;

  StreamWire(Rudp& a, StreamSideListener& al, Rudp& b, StreamSideListener& bl,
             SockAddr aa, SockAddr ba)
      : alice(a), bob(b), aliceL(al), bobL(bl), aliceAddr(aa), bobAddr(ba) {
    aliceL.sink = [this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({aliceAddr, peer, bytes});
    };
    bobL.sink = [this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({bobAddr, peer, bytes});
    };
  }

  // Helper: bind the streams. Caller passes pre-constructed streams
  // (typically owned by the test). Alice's stream gets registered as
  // outbound; bob's is stashed for onAccept to return on inbound.
  void bindStreams(std::shared_ptr<RudpStream> aliceS,
                   std::shared_ptr<RudpStream> bobS,
                   uint32_t channel_id) {
    aliceStream = aliceS;
    bobStream = bobS;
    bobL.inboundStream = bobS;
    alice.registerChannel(bobAddr, channel_id, aliceS);
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

// All tests use this same pattern: two Rudp instances ("alice" and
// "bob") wired via StreamWire, two RudpStreams registered/accepted on
// (peer, channel_id=1), then tests drive I/O. `step(...)` runs one
// tick + deliver + Asio-drain cycle; tests usually call it after
// each push to let the protocol make forward progress.

namespace {

// Standard establish-helper: run pulses + deliver until both sides
// are ESTABLISHED. Most tests start here.
void establish(boost::asio::io_context& io, Rudp& a, Rudp& b,
               StreamWire& wire, uint64_t& now,
               const SockAddr& aliceAddr, uint32_t cid) {
  // Trigger alice's initial OPEN by ticking. Drive until both sides
  // see ESTABLISHED.
  for (int i = 0; i < 10; ++i) {
    step(io, a, b, wire, now);
    if (a.isEstablished(wire.bobAddr, cid) &&
        b.isEstablished(aliceAddr, cid)) {
      return;
    }
    now += 1000;
  }
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Construct / destruct: streams are usable as objects with no I/O.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamConstructDestroy) {
  boost::asio::io_context io;
  auto a = std::make_shared<RudpStream>(io.get_executor());
  auto b = std::make_shared<RudpStream>(io.get_executor());
  BOOST_TEST(a->is_open());
  BOOST_TEST(b->is_open());
  BOOST_TEST(a->available() == 0u);
  BOOST_TEST(!a->getCloseReason().has_value());
}

// ---------------------------------------------------------------------------
// 2. Small echo: alice writes "hello", bob reads "hello".
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamSmallEcho) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA11CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB0B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11100), bA = makeAddr(11101);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, /*cid=*/1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));
  BOOST_REQUIRE(bob.isEstablished(aA, 1));

  const std::string msg = "hello";
  bool writeDone = false;
  std::size_t writeBytes = 0;
  aliceStream->async_write_some(
    boost::asio::buffer(msg),
    [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      writeDone = true;
      writeBytes = n;
    });

  step(io, alice, bob, wire, now);
  BOOST_TEST(writeDone);
  BOOST_TEST(writeBytes == msg.size());

  // Bob now has 5 bytes available; read them.
  std::array<char, 64> rdbuf{};
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream->async_read_some(
    boost::asio::buffer(rdbuf),
    [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      readBytes = n;
      readDone = true;
    });
  step(io, alice, bob, wire, now);
  BOOST_TEST(readDone);
  BOOST_REQUIRE_EQUAL(readBytes, msg.size());
  BOOST_TEST(std::string(rdbuf.data(), readBytes) == msg);
}

// ---------------------------------------------------------------------------
// 3. Large fragmented write: > MAX_MESSAGE_SIZE gets chunked into
//    multiple RUDP messages and reassembled by bob's read buffer.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamLargeFragmented) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA12CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB1B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11110), bA = makeAddr(11111);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  // 10 KB payload — each byte is its index mod 256, so we can verify
  // ordering byte-by-byte after reassembly.
  constexpr std::size_t N = 10 * 1024;
  std::vector<uint8_t> payload(N);
  for (std::size_t i = 0; i < N; ++i) payload[i] = static_cast<uint8_t>(i & 0xFF);

  bool writeDone = false;
  std::size_t writeBytes = 0;
  aliceStream->async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      writeDone = true;
      writeBytes = n;
    });

  // Drive until the write completes (multiple chunks need acks).
  for (int i = 0; i < 100 && !writeDone; ++i) {
    now += 1000;
    step(io, alice, bob, wire, now);
  }
  BOOST_TEST(writeDone);
  BOOST_TEST(writeBytes == N);

  // Drain bob's read side incrementally — multiple async_read_some
  // calls until we've seen all N bytes.
  std::vector<uint8_t> received;
  received.reserve(N);
  for (int i = 0; i < 100 && received.size() < N; ++i) {
    std::array<char, 4096> rdbuf{};
    std::size_t got = 0;
    bool done = false;
    bobStream->async_read_some(
      boost::asio::buffer(rdbuf),
      [&](boost::system::error_code ec, std::size_t n) {
        BOOST_TEST(!ec);
        got = n;
        done = true;
      });
    step(io, alice, bob, wire, now);
    if (done && got > 0) {
      for (std::size_t j = 0; j < got; ++j)
        received.push_back(static_cast<uint8_t>(rdbuf[j]));
    }
    if (!done) {
      now += 1000;
    }
  }
  BOOST_REQUIRE_EQUAL(received.size(), N);
  for (std::size_t i = 0; i < N; ++i) {
    if (received[i] != payload[i]) {
      BOOST_FAIL("payload mismatch at byte " << i);
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// 4. Read before write: bob calls async_read_some BEFORE alice has
//    written anything. The reader is parked. When alice writes, bob's
//    parked read fires.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamReadBeforeWrite) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA13CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB2B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11120), bA = makeAddr(11121);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  std::array<char, 64> rdbuf{};
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream->async_read_some(
    boost::asio::buffer(rdbuf),
    [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      readBytes = n;
      readDone = true;
    });
  drainAsio(io);
  BOOST_TEST(!readDone); // parked

  // Alice writes; bob's reader gets woken by the inbound message.
  aliceStream->async_write_some(boost::asio::buffer(std::string("ping"), 4),
                                [](auto, auto) {});
  step(io, alice, bob, wire, now);
  BOOST_TEST(readDone);
  BOOST_TEST(readBytes == 4u);
  BOOST_TEST(std::string(rdbuf.data(), readBytes) == "ping");
}

// ---------------------------------------------------------------------------
// 5. close() completes a pending reader with eof.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamCloseFiresPendingReaderWithEof) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA14CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB3B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11130), bA = makeAddr(11131);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  std::array<char, 64> rdbuf{};
  boost::system::error_code readEc;
  bool readDone = false;
  bobStream->async_read_some(
    boost::asio::buffer(rdbuf),
    [&](boost::system::error_code ec, std::size_t) {
      readEc = ec;
      readDone = true;
    });
  drainAsio(io);
  BOOST_TEST(!readDone);

  bobStream->close();
  drainAsio(io);
  BOOST_TEST(readDone);
  BOOST_TEST(readEc == boost::asio::error::eof);
  BOOST_TEST(!bobStream->is_open());
}

// ---------------------------------------------------------------------------
// 6. Operations on a closed stream complete immediately with eof.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamWriteAfterCloseFailsEof) {
  boost::asio::io_context io;
  auto stream = std::make_shared<RudpStream>(io.get_executor());

  stream->detach(); // close the stream view; no Rudp behind it
  BOOST_TEST(!stream->is_open());

  bool writeDone = false;
  boost::system::error_code writeEc;
  stream->async_write_some(boost::asio::buffer(std::string("x"), 1),
                           [&](boost::system::error_code ec, std::size_t) {
                             writeEc = ec;
                             writeDone = true;
                           });
  drainAsio(io);
  BOOST_TEST(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::eof);

  // Read on closed stream also completes with eof.
  std::array<char, 4> rdbuf{};
  bool readDone = false;
  boost::system::error_code readEc;
  stream->async_read_some(boost::asio::buffer(rdbuf),
                          [&](boost::system::error_code ec, std::size_t) {
                            readEc = ec;
                            readDone = true;
                          });
  drainAsio(io);
  BOOST_TEST(readDone);
  BOOST_TEST(readEc == boost::asio::error::eof);
}

// ---------------------------------------------------------------------------
// 7. Back-pressure: with sendBuf cap < N chunks, a large write defers
//    partway and resumes when acks free space.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamBackPressureDeferAndResume) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4; // tight cap forces defer
  cfg.rngSeed = 0xA15CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB4B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11140), bA = makeAddr(11141);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  // 8 chunks worth of payload — sendBuf cap is 4, so after 4 chunks
  // are in flight, the writer parks until acks come back.
  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N, 0xAB);

  bool writeDone = false;
  std::size_t writeBytes = 0;
  aliceStream->async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      writeBytes = n;
      writeDone = true;
    });

  // Pump until the write completes. With back-pressure, multiple
  // tick/deliver cycles are needed.
  for (int i = 0; i < 200 && !writeDone; ++i) {
    now += 1000;
    step(io, alice, bob, wire, now);
  }
  BOOST_REQUIRE(writeDone);
  BOOST_TEST(writeBytes == N);
}

// ---------------------------------------------------------------------------
// 8. External channel destruction aborts pending writer with
//    operation_aborted (not eof — the transport was pulled out).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamChannelDestroyedAbortsWriter) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0xA16CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB5B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11150), bA = makeAddr(11151);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 9);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 9);

  // Park a big write in alice's pending state.
  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N, 0xAB);

  boost::system::error_code writeEc;
  bool writeDone = false;
  aliceStream->async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t) {
      writeEc = ec;
      writeDone = true;
    });
  drainAsio(io);
  BOOST_TEST(!writeDone);

  // External destruction (something other than aliceStream->close()).
  alice.closeChannel(bA, 9);
  drainAsio(io);
  BOOST_TEST(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::operation_aborted);
  BOOST_TEST(!aliceStream->is_open());
  BOOST_REQUIRE(aliceStream->getCloseReason().has_value());
  BOOST_TEST(static_cast<int>(*aliceStream->getCloseReason()) ==
             static_cast<int>(Rudp::CloseReason::APPLICATION));
}

// ---------------------------------------------------------------------------
// 9. close() on a stream with a pending writer completes it with eof.
//    Mirror of test 5 but on the writer side.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamCloseAbortsPendingWriterWithEof) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0xA17CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB6B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11160), bA = makeAddr(11161);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N, 0xCD);

  boost::system::error_code writeEc;
  bool writeDone = false;
  aliceStream->async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t) {
      writeEc = ec;
      writeDone = true;
    });
  drainAsio(io);
  BOOST_TEST(!writeDone);

  aliceStream->close();
  drainAsio(io);
  BOOST_TEST(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::eof);
}

// ---------------------------------------------------------------------------
// 10. Scatter-gather read: read into a sequence of buffers.
//     Bob's pending read takes a buffer-sequence; partial fill works.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamScatterGatherReadPartial) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA18CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB7B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11170), bA = makeAddr(11171);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  const std::string msg = "scattergather";
  aliceStream->async_write_some(boost::asio::buffer(msg), [](auto, auto) {});
  step(io, alice, bob, wire, now);

  std::array<char, 5> b1{};
  std::array<char, 5> b2{};
  std::array<char, 5> b3{};
  std::array<boost::asio::mutable_buffer, 3> bufs = {
    boost::asio::buffer(b1), boost::asio::buffer(b2), boost::asio::buffer(b3),
  };

  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream->async_read_some(
    bufs, [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      readBytes = n;
      readDone = true;
    });
  step(io, alice, bob, wire, now);
  BOOST_TEST(readDone);
  // 13 bytes split: 5 + 5 + 3.
  BOOST_REQUIRE_EQUAL(readBytes, msg.size());
  std::string assembled =
    std::string(b1.data(), 5) + std::string(b2.data(), 5) +
    std::string(b3.data(), 3);
  BOOST_TEST(assembled == msg);
}

// ---------------------------------------------------------------------------
// 11. Scatter-gather write: write from a sequence of buffers.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamScatterGatherWrite) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA19CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB8B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11180), bA = makeAddr(11181);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  const std::string p1 = "hello, ";
  const std::string p2 = "world";
  std::array<boost::asio::const_buffer, 2> bufs = {
    boost::asio::buffer(p1), boost::asio::buffer(p2),
  };

  bool writeDone = false;
  std::size_t writeBytes = 0;
  aliceStream->async_write_some(
    bufs, [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      writeDone = true;
      writeBytes = n;
    });
  step(io, alice, bob, wire, now);
  BOOST_TEST(writeDone);
  BOOST_TEST(writeBytes == p1.size() + p2.size());

  std::array<char, 64> rdbuf{};
  std::size_t readBytes = 0;
  bool readDone = false;
  bobStream->async_read_some(
    boost::asio::buffer(rdbuf),
    [&](boost::system::error_code ec, std::size_t n) {
      BOOST_TEST(!ec);
      readBytes = n;
      readDone = true;
    });
  step(io, alice, bob, wire, now);
  BOOST_TEST(readDone);
  BOOST_REQUIRE_EQUAL(readBytes, p1.size() + p2.size());
  BOOST_TEST(std::string(rdbuf.data(), readBytes) == p1 + p2);
}

// ---------------------------------------------------------------------------
// 12. Concurrent writes are not allowed by Asio's AsyncWriteStream
//     contract. The second async_write_some while the first is
//     deferred fails with in_progress.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamConcurrentWriteReturnsInProgress) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4; // force first write to defer
  cfg.rngSeed = 0xA1ACE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB9B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11190), bA = makeAddr(11191);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> p1(N, 0x11);
  std::vector<uint8_t> p2(N, 0x22);

  bool first = false, second = false;
  boost::system::error_code firstEc, secondEc;
  aliceStream->async_write_some(
    boost::asio::buffer(p1),
    [&](boost::system::error_code ec, std::size_t) {
      firstEc = ec;
      first = true;
    });
  drainAsio(io);
  BOOST_TEST(!first);

  // Second concurrent write should fail with in_progress.
  aliceStream->async_write_some(
    boost::asio::buffer(p2),
    [&](boost::system::error_code ec, std::size_t) {
      secondEc = ec;
      second = true;
    });
  drainAsio(io);
  BOOST_TEST(second);
  BOOST_TEST(secondEc == boost::asio::error::in_progress);

  // Drain to completion. First completes successfully.
  for (int i = 0; i < 200 && !first; ++i) {
    now += 1000;
    step(io, alice, bob, wire, now);
  }
  BOOST_TEST(first);
  BOOST_TEST(!firstEc);
}

// ---------------------------------------------------------------------------
// 13. Packet drop + retransmit: drop one alice→bob CHANNEL packet,
//     wait, verify retransmit kicks in and bob receives correctly.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamPacketDropRetransmit) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA1BCE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBAB;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11200), bA = makeAddr(11201);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  const std::string msg = "retransmit-me";
  aliceStream->async_write_some(boost::asio::buffer(msg),
                                [](auto, auto) {});

  // Drop the first alice→bob CHANNEL packet.
  wire.dropNextAtoB = 1;
  step(io, alice, bob, wire, now);

  // Bob has not yet received the message.
  BOOST_TEST(bobStream->available() == 0u);

  // Drive ticks to trigger retransmission. RUDP retransmits when
  // bob's ack info doesn't cover what alice has unacked.
  for (int i = 0; i < 50 && bobStream->available() == 0; ++i) {
    now += 1000;
    step(io, alice, bob, wire, now);
  }

  // Eventually bob sees the message.
  BOOST_TEST(bobStream->available() == msg.size());

  std::array<char, 64> rdbuf{};
  std::size_t readBytes = 0;
  bobStream->async_read_some(
    boost::asio::buffer(rdbuf),
    [&](boost::system::error_code, std::size_t n) { readBytes = n; });
  step(io, alice, bob, wire, now);
  BOOST_TEST(readBytes == msg.size());
  BOOST_TEST(std::string(rdbuf.data(), readBytes) == msg);
}

// ---------------------------------------------------------------------------
// 14. Unreliable bytes route to the application's UnreliableSink, NOT
//     to the byte stream's read buffer. RudpStream treats unreliable
//     as out-of-band garbage that the application policy decides on.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamUnreliableSinkReceives) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA1CCE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBBB;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11210), bA = makeAddr(11211);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  std::vector<Bytes> bobUnreliable;
  bobStream->setUnreliableSink(
    [&](const Bytes& msg) { bobUnreliable.push_back(msg); });

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  // Send unreliable through Rudp directly (not via stream) — Rudp's
  // unreliable lane is per-channel.
  Bytes unreliable;
  const std::string blob = "datagram";
  unreliable.assign(blob.begin(), blob.end());
  alice.push(bA, 1, unreliable, /*reliable=*/false);
  step(io, alice, bob, wire, now);

  BOOST_REQUIRE_EQUAL(bobUnreliable.size(), 1u);
  BOOST_TEST(std::string(bobUnreliable[0].begin(), bobUnreliable[0].end()) ==
             blob);
  // The byte stream remains empty — unreliable did NOT enter the
  // reliable read path.
  BOOST_TEST(bobStream->available() == 0u);
}

// ---------------------------------------------------------------------------
// 15. close() tears down the underlying RUDP channel via
//     rudp.closeChannel. Verifies the 99% intent: closing the stream
//     also closes the wire.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamCloseTearsDownChannel) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA1DCE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBCB;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11220), bA = makeAddr(11221);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  aliceStream->close();
  // Alice's underlying channel is gone.
  BOOST_TEST(!alice.isEstablished(bA, 1));
  BOOST_TEST(alice.channelCount(bA) == 0u);

  // Wire delivers HS_CLOSE to bob; bob's channel goes too.
  step(io, alice, bob, wire, now);
  BOOST_TEST(!bob.isEstablished(aA, 1));
  BOOST_TEST(!bobStream->is_open());
  BOOST_REQUIRE(bobStream->getCloseReason().has_value());
  BOOST_TEST(static_cast<int>(*bobStream->getCloseReason()) ==
             static_cast<int>(Rudp::CloseReason::PEER_CLOSED));
}

// ---------------------------------------------------------------------------
// 16. detach() leaves the underlying RUDP channel alive. Mirror of
//     test 15 but with detach instead of close.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamDetachKeepsChannel) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA1ECE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBDB;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11230), bA = makeAddr(11231);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  aliceStream->detach();
  BOOST_TEST(!aliceStream->is_open());
  // Channel still alive on Rudp.
  BOOST_TEST(alice.isEstablished(bA, 1));
  BOOST_TEST(alice.channelCount(bA) == 1u);
}

// ---------------------------------------------------------------------------
// 17. getCloseReason() reports the underlying channel's CloseReason
//     after an external destruction (idle GC, peer close, etc).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamGetCloseReasonOnIdleGc) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.channelInactivityTimeout = std::chrono::milliseconds(10);
  cfg.rngSeed = 0xA1FCE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBEB;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11240), bA = makeAddr(11241);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  // Advance past idle-timeout AND past pulse cadence so doPulseWork
  // fires and sweeps the idle channel.
  now += 200'000;
  alice.tick(now);
  drainAsio(io);

  BOOST_TEST(!aliceStream->is_open());
  BOOST_REQUIRE(aliceStream->getCloseReason().has_value());
  BOOST_TEST(static_cast<int>(*aliceStream->getCloseReason()) ==
             static_cast<int>(Rudp::CloseReason::IDLE));
}

// ---------------------------------------------------------------------------
// shutdown() — graceful close with SO_LINGER-style timeout.
//
//   18. shutdown() on a quiet stream: no in-flight write → defers
//       close to Rudp's drain check; channel survives until the next
//       pulse drains sendBuf, then HS_CLOSE goes out.
//   19. shutdown() while a write is in flight: the in-flight
//       async_write_some completes successfully (all bytes pushed
//       into sendBuf), THEN the deferred close fires.
//   20. async_write_some after shutdown() returns eof.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStreamShutdownDefersCloseUntilDrain) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA1FCE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBFB;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11240), bA = makeAddr(11241);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));
  BOOST_REQUIRE(bob.isEstablished(aA, 1));

  // No write in flight: shutdown() registers the deferred close
  // immediately. Channel still exists until the next pulse.
  aliceStream->shutdown(std::chrono::seconds(1));
  BOOST_TEST(alice.isEstablished(bA, 1));
  BOOST_TEST(alice.channelCount(bA) == 1u);

  // Pulse: drain check fires (sendBuf empty), HS_CLOSE goes out.
  alice.tick(now);
  BOOST_TEST(!alice.isEstablished(bA, 1));
  BOOST_TEST(alice.channelCount(bA) == 0u);

  // Bob sees the HS_CLOSE and tears down.
  step(io, alice, bob, wire, now);
  BOOST_TEST(!bob.isEstablished(aA, 1));
  BOOST_TEST(!bobStream->is_open());
  BOOST_REQUIRE(bobStream->getCloseReason().has_value());
  BOOST_TEST(static_cast<int>(*bobStream->getCloseReason()) ==
             static_cast<int>(Rudp::CloseReason::PEER_CLOSED));
}

BOOST_AUTO_TEST_CASE(TestRudpStreamShutdownLetsInFlightWriteFinish) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0xA20CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC0B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11250), bA = makeAddr(11251);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  // Park a multi-fragment write that will need more than one push()
  // round to fully drain into sendBuf — bigger than the per-channel
  // reorder cap (4 messages * MAX_MESSAGE_SIZE) ensures back-pressure.
  const std::size_t N = 8 * Rudp::MAX_MESSAGE_SIZE;
  std::vector<uint8_t> payload(N, 0xAB);
  boost::system::error_code writeEc;
  std::size_t writeN = 0;
  bool writeDone = false;
  aliceStream->async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeN = n;
      writeDone = true;
    });
  drainAsio(io);
  // The write should be still in flight (capped at 4 messages, needs
  // more onWritable cycles to push the rest).
  BOOST_REQUIRE(!writeDone);

  // Shutdown WHILE the write is in flight. The drainPendingWrite tail
  // is what schedules the deferred closeChannel — until pendingWriteHandler_
  // fires, no closeChannel is registered. So this is the path we
  // care about.
  aliceStream->shutdown(std::chrono::seconds(5));

  // Drive the protocol forward: bob reads (consuming inboundBuf),
  // ACKs return to alice, drainPendingWrite resumes via onWritable,
  // eventually pushes everything into sendBuf, fires the write
  // completion, the deferred closeChannel registers, and the next
  // pulse's drain check fires HS_CLOSE.
  std::array<uint8_t, 64 * 1024> rbuf{};
  std::function<void()> postRead = [&]() {
    bobStream->async_read_some(
      boost::asio::buffer(rbuf),
      [&](boost::system::error_code ec, std::size_t) {
        if (ec) return;
        postRead();
      });
  };
  postRead();

  for (int i = 0; i < 100 && (alice.channelCount(bA) > 0); ++i) {
    step(io, alice, bob, wire, now);
    now += 1000;
  }

  // Write completion fired with success and the full payload — the
  // in-flight write was NOT aborted by shutdown.
  BOOST_REQUIRE(writeDone);
  BOOST_TEST(!writeEc);
  BOOST_TEST(writeN == N);

  // Channel torn down on both sides via graceful close, not RST or
  // idle GC. (The fact that it tore down at all confirms the deferred
  // close fired after the write drained.)
  BOOST_TEST(!alice.isEstablished(bA, 1));
  BOOST_TEST(!bob.isEstablished(aA, 1));
  BOOST_REQUIRE(bobStream->getCloseReason().has_value());
  BOOST_TEST(static_cast<int>(*bobStream->getCloseReason()) ==
             static_cast<int>(Rudp::CloseReason::PEER_CLOSED));
}

BOOST_AUTO_TEST_CASE(TestRudpStreamWriteAfterShutdownReturnsEof) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA21CE;
  StreamSideListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC1B;
  StreamSideListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11260), bA = makeAddr(11261);
  StreamWire wire(alice, aliceL, bob, bobL, aA, bA);

  boost::asio::io_context io;
  auto aliceStream = std::make_shared<RudpStream>(io.get_executor());
  auto bobStream = std::make_shared<RudpStream>(io.get_executor());
  wire.bindStreams(aliceStream, bobStream, 1);

  uint64_t now = 1000;
  establish(io, alice, bob, wire, now, aA, 1);

  aliceStream->shutdown(std::chrono::seconds(1));

  // New writes after shutdown immediately fail with eof — the stream
  // is still open per is_open() (it's not torn down yet), but writes
  // are gated.
  std::vector<uint8_t> payload(8, 0xCC);
  boost::system::error_code writeEc;
  std::size_t writeN = 1234;
  bool writeDone = false;
  aliceStream->async_write_some(
    boost::asio::buffer(payload),
    [&](boost::system::error_code ec, std::size_t n) {
      writeEc = ec;
      writeN = n;
      writeDone = true;
    });
  drainAsio(io);

  BOOST_REQUIRE(writeDone);
  BOOST_TEST(writeEc == boost::asio::error::eof);
  BOOST_TEST(writeN == 0u);
}

BOOST_AUTO_TEST_SUITE_END()
