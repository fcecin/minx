// =============================================================================
//  test_rudp.cpp — comprehensive test suite for the RUDP suite (v0).
//
//  Pattern: two `Rudp` instances ("alice" and "bob") wired together by a
//  `FakeWire` that captures each instance's outbound packets and feeds them
//  to the other side's onPacket() on demand. No real socket, no real time.
//  Time is advanced manually by incrementing a `now_us` variable and
//  passing it to tick().
//
//  This makes every scenario (loss, reordering, retransmits, handshake
//  retries, GC, caps) a synchronous unit test with no sleeps and no
//  flakiness.
// =============================================================================

#include <boost/test/unit_test.hpp>

#include <minx/buffer.h>
#include <minx/rudp/rudp.h>
#include <minx/stdext.h>
#include <minx/types.h>

#include <boost/endian/conversion.hpp>

#include <chrono>
#include <cstring>
#include <deque>
#include <functional>
#include <vector>

using minx::Bytes;
using minx::MinxStdExtensions;
using minx::Rudp;
using minx::SockAddr;

// ---------------------------------------------------------------------------
// Test plumbing
// ---------------------------------------------------------------------------

namespace {

// One captured outbound packet: who sent it, who it's going to, and the
// raw bytes (which start with the 8-byte stdext routing key — same as
// what would go on the wire to MinxStdExtensions on the other side).
struct CapturedPacket {
  SockAddr from;
  SockAddr to;
  Bytes bytes;
};

// One delivered application message via ReceiveFn.
struct DeliveredMessage {
  SockAddr peer;
  uint32_t channelId;
  Bytes data;
  bool reliable;
};

// FakeWire — a synchronous in-memory transport between two Rudp instances.
// Captures sends, lets the test choose when to deliver them (deliverAll,
// dropNext, etc.), no real IO.
struct FakeWire {
  Rudp& alice;
  Rudp& bob;
  SockAddr aliceAddr;
  SockAddr bobAddr;
  std::deque<CapturedPacket> queue; // FIFO of captured outbound packets
  std::vector<DeliveredMessage> aliceRecv;
  std::vector<DeliveredMessage> bobRecv;
  size_t dropNextAtoB = 0;
  size_t dropNextBtoA = 0;
  // "Drop every Nth packet in this direction" — sustained loss pattern,
  // independent of dropNext*. 0 disables. Counters track total packets
  // considered (whether dropped or delivered) per direction so the pattern
  // is consistent across deliverAll calls.
  size_t dropEveryNthAtoB = 0;
  size_t dropEveryNthBtoA = 0;
  size_t aToBSeq = 0;
  size_t bToASeq = 0;

  FakeWire(Rudp& a, Rudp& b, SockAddr aa, SockAddr ba)
      : alice(a), bob(b), aliceAddr(aa), bobAddr(ba) {

    alice.setSendCallback([this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({aliceAddr, peer, bytes});
    });
    bob.setSendCallback([this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({bobAddr, peer, bytes});
    });

    alice.setReceiveCallback([this](const SockAddr& peer, uint32_t cid,
                                    const Bytes& data, bool reliable) {
      aliceRecv.push_back({peer, cid, data, reliable});
    });
    bob.setReceiveCallback([this](const SockAddr& peer, uint32_t cid,
                                  const Bytes& data, bool reliable) {
      bobRecv.push_back({peer, cid, data, reliable});
    });
  }

  // Drain everything currently captured AND anything that gets
  // re-enqueued during delivery. The loop runs until the queue is
  // empty, so a single call performs an entire round-trip exchange:
  // alice's OPEN -> bob.onPacket -> bob emits ACCEPT (re-enqueued) ->
  // alice.onPacket -> handshake complete. Tests should reason about
  // deliverAll() as "drain to convergence," not "deliver one packet."
  //
  // Honors per-direction drop counters: dropNextAtoB causes the next
  // N packets going alice->bob to be silently discarded, and similarly
  // for dropNextBtoA.
  void deliverAll(uint64_t now_us = 0) {
    while (!queue.empty()) {
      auto pkt = queue.front();
      queue.pop_front();

      const bool aToB = (pkt.from == aliceAddr);
      // One-shot drop counter (e.g. dropNextAtoB = 1 to drop the next
      // a→b packet exactly once).
      if (aToB && dropNextAtoB > 0) {
        --dropNextAtoB;
        continue;
      }
      if (!aToB && dropNextBtoA > 0) {
        --dropNextBtoA;
        continue;
      }
      // Sustained drop pattern (e.g. dropEveryNthAtoB = 3 to drop every
      // 3rd a→b packet). The seq counter increments for every packet
      // considered in that direction so the pattern is consistent
      // across deliverAll calls.
      if (aToB) {
        ++aToBSeq;
        if (dropEveryNthAtoB > 0 && (aToBSeq % dropEveryNthAtoB) == 0) {
          continue;
        }
      } else {
        ++bToASeq;
        if (dropEveryNthBtoA > 0 && (bToASeq % dropEveryNthBtoA) == 0) {
          continue;
        }
      }

      // Parse the routing key off the front (same thing MinxStdExtensions
      // does on a real wire).
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

  // Drain N packets only, leaving the rest queued.
  void deliverN(size_t n, uint64_t now_us = 0) {
    while (n-- > 0 && !queue.empty()) {
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

  // Discard everything currently queued without delivering.
  void clearQueue() { queue.clear(); }

  size_t pending() const { return queue.size(); }
};

// Convenience: build a Bytes from a string literal.
static Bytes B(const char* s) { return Bytes(s, s + std::strlen(s)); }

// Convenience: build a Bytes filled with a single byte value, given length.
static Bytes Bn(uint8_t b, size_t n) {
  Bytes out;
  out.resize(n);
  std::memset(out.data(), static_cast<int>(b), n);
  return out;
}

// Two arbitrary loopback endpoints used as fake addresses. The actual
// IP is irrelevant — the test bridge identifies sender/receiver by
// equality, not by routing.
static SockAddr makeAddr(uint16_t port) {
  return SockAddr(boost::asio::ip::make_address("127.0.0.1"), port);
}

} // namespace

BOOST_AUTO_TEST_SUITE(RudpSuite)

// ---------------------------------------------------------------------------
// 1. Identity constants compose correctly via MinxStdExtensions
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpIdentityConstants) {
  using SE = MinxStdExtensions;
  // Both sub-proto routing keys mask to the same family id.
  static_assert(SE::idOf(Rudp::KEY_V0_HANDSHAKE) == Rudp::EXTENSION_ID);
  static_assert(SE::idOf(Rudp::KEY_V0_CHANNEL) == Rudp::EXTENSION_ID);
  // The high byte of the meta is the version.
  static_assert((SE::metaOf(Rudp::KEY_V0_HANDSHAKE) >> 8) == Rudp::VERSION_V0);
  static_assert((SE::metaOf(Rudp::KEY_V0_CHANNEL) >> 8) == Rudp::VERSION_V0);
  // The low byte of the meta is the sub-proto selector.
  static_assert((SE::metaOf(Rudp::KEY_V0_HANDSHAKE) & 0xFF) ==
                Rudp::SUBPROTO_HANDSHAKE);
  static_assert((SE::metaOf(Rudp::KEY_V0_CHANNEL) & 0xFF) ==
                Rudp::SUBPROTO_CHANNEL);
  // KEY_V0 is an alias for KEY_V0_CHANNEL.
  static_assert(Rudp::KEY_V0 == Rudp::KEY_V0_CHANNEL);
  // Family id is the user-chosen sigil.
  static_assert(Rudp::EXTENSION_ID == 0xFAB1CEC14742ULL);

  BOOST_TEST(Rudp::NAME != nullptr);
  BOOST_TEST(std::strlen(Rudp::NAME) > 0u);
}

// ---------------------------------------------------------------------------
// 2. Construction / destruction; smoke
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpConstructDestroy) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x12345678; // deterministic
  Rudp r(cfg);
  BOOST_TEST(r.peerCount() == 0u);
}

// ---------------------------------------------------------------------------
// 3. Handshake happy path: alice OPENs, bob ACCEPTs, both ESTABLISHED
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpHandshakeHappyPath) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA11CE;
  Rudp alice(cfg);
  cfg.rngSeed = 0xB0B;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9000), bA = makeAddr(9001);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;

  // Alice pushes a reliable message — this triggers OPEN_SENT and
  // queues the message until the handshake completes.
  BOOST_TEST(alice.push(bA, /*channel=*/42, B("hello"), /*reliable=*/true));
  BOOST_REQUIRE_EQUAL(alice.peerCount(), 1u);
  BOOST_REQUIRE_EQUAL(alice.channelCount(bA), 1u);
  BOOST_REQUIRE(!alice.isEstablished(bA, 42));

  // First tick: alice flushes and emits OPEN. With reactive flow, that
  // single tick + the following deliverAll() cascade through the full
  // handshake AND the "hello" data delivery in one pass:
  //   1. tick → alice emits OPEN
  //   2. deliverAll → bob receives OPEN, bob.onPacket fires a pulse,
  //      bob emits ACCEPT (enqueued)
  //   3. deliverAll continues → alice receives ACCEPT, promotes to
  //      ESTABLISHED (drains "hello" into sendBuf), fires a pulse,
  //      emits the "hello" CHANNEL packet
  //   4. deliverAll continues → bob receives "hello", delivers via
  //      receiveFn, fires a pulse, emits ack-only
  //   5. deliverAll continues → alice receives the ack, drops "hello"
  //      from sendBuf, the next pulse has nothing to say, exit
  alice.tick(now);
  BOOST_TEST(wire.pending() == 1u);

  wire.deliverAll(now);
  BOOST_TEST(bob.isEstablished(aA, 42));
  BOOST_TEST(alice.isEstablished(bA, 42));

  // Both sides agree on the session token.
  BOOST_TEST(alice.sessionToken(bA, 42) != 0u);
  BOOST_TEST(alice.sessionToken(bA, 42) == bob.sessionToken(aA, 42));

  // Bob delivered the message via ReceiveFn during the cascade.
  BOOST_REQUIRE(wire.bobRecv.size() >= 1u);
  BOOST_TEST(wire.bobRecv[0].peer == aA);
  BOOST_TEST(wire.bobRecv[0].channelId == 42u);
  BOOST_TEST(wire.bobRecv[0].reliable == true);
  BOOST_TEST(std::string(wire.bobRecv[0].data.begin(),
                         wire.bobRecv[0].data.end()) == "hello");
}

// ---------------------------------------------------------------------------
// 4. Handshake retry: drop the OPEN, advance time, verify retry fires
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpHandshakeRetry) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x111;
  cfg.handshakeRetryInterval = std::chrono::milliseconds(50);
  cfg.handshakeMaxRetries = 3;
  Rudp alice(cfg);
  cfg.rngSeed = 0x222;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9100), bA = makeAddr(9101);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  alice.push(bA, 1, B("ping"), true);
  alice.tick(now);
  BOOST_TEST(wire.pending() == 1u);

  // Drop the OPEN.
  wire.dropNextAtoB = 1;
  wire.deliverAll();
  BOOST_TEST(wire.pending() == 0u);
  BOOST_TEST(!bob.isEstablished(aA, 1));

  // Advance time past the retry interval; retry should fire on next tick.
  now += 60'000; // 60ms > 50ms retry
  alice.tick(now);
  BOOST_TEST(wire.pending() == 1u);

  // Let the retry through. deliverAll drains everything, so this one
  // call exchanges the retried OPEN -> bob -> ACCEPT -> alice cycle in
  // a single pass.
  wire.deliverAll();
  BOOST_TEST(alice.isEstablished(bA, 1));
  BOOST_TEST(bob.isEstablished(aA, 1));
  BOOST_TEST(wire.pending() == 0u);
}

// ---------------------------------------------------------------------------
// 5. Handshake exhaustion: drop everything, verify channel goes away
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpHandshakeExhaustion) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x333;
  cfg.handshakeRetryInterval = std::chrono::milliseconds(50);
  cfg.handshakeMaxRetries = 3;
  Rudp alice(cfg);
  cfg.rngSeed = 0x444;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9200), bA = makeAddr(9201);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  alice.push(bA, 1, B("nope"), true);

  // Drop all the way through. We need: first OPEN + 3 retries = 4 sends.
  wire.dropNextAtoB = 1000; // drop everything

  alice.tick(now); // first OPEN
  for (int i = 0; i < 5; ++i) {
    now += 60'000;
    alice.tick(now);
    wire.deliverAll();
  }

  // After exhaustion, the channel should be gone.
  BOOST_TEST(alice.channelCount(bA) == 0u);
}

// ---------------------------------------------------------------------------
// 6. Single reliable message end-to-end
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpSingleReliableMessage) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAAA;
  Rudp alice(cfg);
  cfg.rngSeed = 0xBBB;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9300), bA = makeAddr(9301);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  alice.push(bA, 7, B("payload-zero"), true);
  alice.tick(now);
  wire.deliverAll(); // OPEN -> bob
  wire.deliverAll(); // ACCEPT -> alice
  alice.tick(now);   // alice flushes the queued message
  wire.deliverAll(); // CHANNEL -> bob

  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 1u);
  BOOST_TEST(wire.bobRecv[0].channelId == 7u);
  BOOST_TEST(wire.bobRecv[0].reliable == true);
  BOOST_TEST(std::string(wire.bobRecv[0].data.begin(),
                         wire.bobRecv[0].data.end()) == "payload-zero");
}

// ---------------------------------------------------------------------------
// 7. Cumulative ack advances correctly under in-order delivery
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpCumulativeAck) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xCCC;
  Rudp alice(cfg);
  cfg.rngSeed = 0xDDD;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9400), bA = makeAddr(9401);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  for (int i = 0; i < 5; ++i) {
    alice.push(bA, 1, Bn(static_cast<uint8_t>('A' + i), 10), true);
  }
  alice.tick(now);
  wire.deliverAll(); // OPEN -> bob
  wire.deliverAll(); // ACCEPT -> alice
  alice.tick(now);
  wire.deliverAll(); // CHANNEL packet with 5 messages -> bob
  // Bob should now have received all 5 in order.
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 5u);
  for (int i = 0; i < 5; ++i) {
    BOOST_TEST(wire.bobRecv[i].data.size() == 10u);
    BOOST_TEST(static_cast<uint8_t>(wire.bobRecv[i].data[0]) ==
               static_cast<uint8_t>('A' + i));
  }

  // Bob's flush will emit an ack-only CHANNEL packet acknowledging up
  // to msg 5. Alice processes that, drops everything from her sendBuf.
  bob.tick(now);
  wire.deliverAll();

  // Alice has nothing left to send and shouldn't emit further packets
  // when she ticks again.
  alice.tick(now);
  // The only thing she might emit is an ack-only response to bob's
  // ack — which happens once if her own ack state changed. Drain.
  wire.deliverAll();
  // After draining, no more pending traffic.
  alice.tick(now);
  bob.tick(now);
  alice.tick(now);
  bob.tick(now);
  // Steady state — should converge to zero pending.
  BOOST_TEST(wire.pending() == 0u);
}

// ---------------------------------------------------------------------------
// 8. Out-of-order delivery via reorder buffer + porosity
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpOutOfOrderViaReorderBuffer) {
  // Strategy: push many messages on alice, drop the first packet
  // (which contains the earliest msg_ids), advance time so alice
  // retransmits, and verify bob ends up with everything in order.
  // This exercises the reorder buffer and porosity bitmap implicitly
  // via the retransmit path.

  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xEEE;
  cfg.handshakeRetryInterval = std::chrono::milliseconds(50);
  Rudp alice(cfg);
  cfg.rngSeed = 0xFFF;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9500), bA = makeAddr(9501);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;

  // Establish channel first (no message loss).
  alice.push(bA, 1, B("init"), true);
  alice.tick(now);
  wire.deliverAll();
  wire.deliverAll();
  // Drain the initial "init" payload to clear it out of the picture.
  alice.tick(now);
  wire.deliverAll();
  bob.tick(now);
  wire.deliverAll();
  alice.tick(now);
  wire.deliverAll();
  wire.bobRecv.clear();

  // Now push 4 messages and verify they all arrive even after we
  // drop alice's first attempt. Each push happens BEFORE the next
  // flush so they ride in the same packet.
  alice.push(bA, 1, B("one"), true);
  alice.push(bA, 1, B("two"), true);
  alice.push(bA, 1, B("three"), true);
  alice.push(bA, 1, B("four"), true);

  // Drop the first packet alice emits.
  wire.dropNextAtoB = 1;
  alice.tick(now);
  wire.deliverAll();

  BOOST_TEST(wire.bobRecv.size() == 0u); // everything dropped

  // Advance time and let alice retransmit. With our every-flush retransmit
  // model, even one more flush should re-send everything in sendBuf.
  now += 100'000;
  alice.tick(now);
  wire.deliverAll();
  // bob now has all four, in order.
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 4u);
  BOOST_TEST(std::string(wire.bobRecv[0].data.begin(),
                         wire.bobRecv[0].data.end()) == "one");
  BOOST_TEST(std::string(wire.bobRecv[1].data.begin(),
                         wire.bobRecv[1].data.end()) == "two");
  BOOST_TEST(std::string(wire.bobRecv[2].data.begin(),
                         wire.bobRecv[2].data.end()) == "three");
  BOOST_TEST(std::string(wire.bobRecv[3].data.begin(),
                         wire.bobRecv[3].data.end()) == "four");
}

// ---------------------------------------------------------------------------
// 9. Unreliable tail: send + receive
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpUnreliableTail) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x1A1;
  Rudp alice(cfg);
  cfg.rngSeed = 0x2B2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9600), bA = makeAddr(9601);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  // Establish channel via a reliable push, drain everything.
  alice.push(bA, 9, B("init"), true);
  alice.tick(now);
  wire.deliverAll();
  wire.deliverAll();
  alice.tick(now);
  wire.deliverAll();
  bob.tick(now);
  wire.deliverAll();
  alice.tick(now);
  wire.deliverAll();
  wire.bobRecv.clear();

  // Push an unreliable blob. Should get delivered as the unreliable tail
  // of the next CHANNEL packet alice sends.
  alice.push(bA, 9, B("game-state-snapshot"), false);
  alice.tick(now);
  wire.deliverAll();

  // Find the unreliable delivery in bob's recv list.
  bool foundUnreliable = false;
  for (auto& r : wire.bobRecv) {
    if (!r.reliable) {
      foundUnreliable = true;
      BOOST_TEST(r.channelId == 9u);
      BOOST_TEST(std::string(r.data.begin(), r.data.end()) ==
                 "game-state-snapshot");
    }
  }
  BOOST_TEST(foundUnreliable);
}

// ---------------------------------------------------------------------------
// 10. Per-peer channel cap rejects the overflow
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpChannelCap) {
  minx::RudpConfig cfg;
  cfg.maxChannelsPerPeer = 3;
  cfg.rngSeed = 0x999;
  Rudp alice(cfg);
  cfg.rngSeed = 0x888;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9700), bA = makeAddr(9701);
  FakeWire wire(alice, bob, aA, bA);

  // Allocate channels 1, 2, 3 — should all succeed.
  BOOST_TEST(alice.push(bA, 1, B("a"), true));
  BOOST_TEST(alice.push(bA, 2, B("b"), true));
  BOOST_TEST(alice.push(bA, 3, B("c"), true));
  // Channel 4 should be rejected.
  BOOST_TEST(!alice.push(bA, 4, B("d"), true));
  BOOST_TEST(alice.channelCount(bA) == 3u);
}

// ---------------------------------------------------------------------------
// 11. Oversize message rejected
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpOversizeRejected) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x77;
  Rudp r(cfg);
  SockAddr peer = makeAddr(9800);
  Bytes huge = Bn(0xAB, Rudp::MAX_MESSAGE_SIZE + 1);
  BOOST_TEST(!r.push(peer, 1, huge, true));
  Bytes max_ok = Bn(0xAB, Rudp::MAX_MESSAGE_SIZE);
  BOOST_TEST(r.push(peer, 1, max_ok, true));
}

// ---------------------------------------------------------------------------
// 12. Channel inactivity GC removes idle channels
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpChannelInactivityGC) {
  minx::RudpConfig cfg;
  cfg.channelInactivityTimeout = std::chrono::milliseconds(100);
  cfg.rngSeed = 0xDEC0;
  Rudp alice(cfg);
  cfg.rngSeed = 0xDED0;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9900), bA = makeAddr(9901);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  alice.push(bA, 1, B("hi"), true);
  alice.tick(now);
  wire.deliverAll();
  wire.deliverAll();
  alice.tick(now);
  wire.deliverAll();

  BOOST_TEST(alice.isEstablished(bA, 1));
  BOOST_TEST(bob.isEstablished(aA, 1));

  // Advance time well past the inactivity timeout.
  now += 200'000;
  alice.tick(now);
  bob.tick(now);

  BOOST_TEST(alice.channelCount(bA) == 0u);
  BOOST_TEST(bob.channelCount(aA) == 0u);
}

// ---------------------------------------------------------------------------
// 12b. close() — local teardown verb, drops channel state immediately.
//
// Verifies that close() is purely local: alice drops her channel, any
// further traffic she pushes goes nowhere (channel must be re-opened),
// and bob's side of the channel is untouched until bob decides what to
// do with it. No wire teardown, no announce — the peer discovers the
// channel is gone via silence or session-token mismatch on the next
// stray packet.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpCloseDropsChannel) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC105E;
  Rudp alice(cfg);
  cfg.rngSeed = 0xC106E;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9910), bA = makeAddr(9911);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 7, B("hello"), true);
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_REQUIRE(alice.isEstablished(bA, 7));
  BOOST_REQUIRE(bob.isEstablished(aA, 7));
  BOOST_REQUIRE_EQUAL(alice.channelCount(bA), 1u);
  BOOST_REQUIRE_EQUAL(bob.channelCount(aA), 1u);

  // close() on a non-existent channel is a no-op — no packet emitted.
  BOOST_REQUIRE_EQUAL(wire.pending(), 0u);
  alice.close(bA, 999);
  BOOST_TEST(alice.channelCount(bA) == 1u);
  BOOST_TEST(wire.pending() == 0u);

  // Close the real channel. State is gone from alice immediately,
  // AND the peer entry is pruned because it had no other channels.
  alice.close(bA, 7);
  BOOST_TEST(alice.channelCount(bA) == 0u);
  BOOST_TEST(alice.peerCount() == 0u);
  BOOST_TEST(!alice.isEstablished(bA, 7));

  // Bob is still established — the HS_CLOSE packet is queued but not
  // yet delivered. Until deliverAll() runs it, bob's side is intact.
  BOOST_TEST(bob.isEstablished(aA, 7) == true);
  BOOST_TEST(bob.channelCount(aA) == 1u);
  BOOST_TEST(wire.pending() == 1u);

  // Deliver the HS_CLOSE. Bob tears down synchronously.
  wire.deliverAll(now);
  BOOST_TEST(!bob.isEstablished(aA, 7));
  BOOST_TEST(bob.channelCount(aA) == 0u);
  BOOST_TEST(bob.peerCount() == 0u);

  // Repeated close is also a no-op — no packet emitted.
  alice.close(bA, 7);
  BOOST_TEST(alice.peerCount() == 0u);
  BOOST_TEST(wire.pending() == 0u);
}

// ---------------------------------------------------------------------------
// 12b'. HS_CLOSE wire behavior: close() on ESTABLISHED emits exactly one
// HS_CLOSE, peer's onChannelDestroyed fires on receive, subsequent stray
// CHANNEL packets addressed to the torn-down channel are dropped as
// unknown.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpCloseEmitsHsCloseToPeer) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC105A;
  Rudp alice(cfg);
  cfg.rngSeed = 0xC105B;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9930), bA = makeAddr(9931);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 3, B("hi"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 3));
  BOOST_REQUIRE(bob.isEstablished(aA, 3));

  // Install destroyed callbacks on both sides to observe the teardown.
  size_t aliceDestroyed = 0, bobDestroyed = 0;
  alice.setChannelDestroyedCallback(bA, 3, [&]() { ++aliceDestroyed; });
  bob.setChannelDestroyedCallback(aA, 3, [&]() { ++bobDestroyed; });

  // alice.close() fires alice's destroyed synchronously and queues one
  // HS_CLOSE on the wire. bob hasn't been notified yet.
  alice.close(bA, 3);
  BOOST_TEST(aliceDestroyed == 1u);
  BOOST_TEST(bobDestroyed == 0u);
  BOOST_TEST(wire.pending() == 1u);

  // Deliver the HS_CLOSE: bob fires destroyed and state is gone.
  wire.deliverAll(now);
  BOOST_TEST(bobDestroyed == 1u);
  BOOST_TEST(!bob.isEstablished(aA, 3));
  BOOST_TEST(bob.channelCount(aA) == 0u);

  // No more packets in flight, no retry.
  BOOST_TEST(wire.pending() == 0u);

  // A stray push from bob to the now-gone channel starts a fresh
  // handshake (channel_id 3 is reusable — nothing remembers it).
  bob.push(aA, 3, B("still there?"), true);
  bob.tick(now);
  BOOST_TEST(wire.pending() >= 1u);
  wire.clearQueue();
}

// ---------------------------------------------------------------------------
// 12b''. close() on a non-ESTABLISHED channel emits no HS_CLOSE.
// Non-ESTABLISHED states have no mutually-known session_token, so the
// peer couldn't authenticate a close even if we sent one.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpCloseOnNonEstablishedEmitsNothing) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC106A;
  Rudp alice(cfg);
  cfg.rngSeed = 0xC106B;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9940), bA = makeAddr(9941);
  FakeWire wire(alice, bob, aA, bA);

  // Push creates a channel in IDLE and queues an OPEN on first tick.
  alice.push(bA, 5, B("hi"), true);
  alice.tick(1000);
  BOOST_REQUIRE_EQUAL(wire.pending(), 1u); // the OPEN
  wire.clearQueue();
  BOOST_REQUIRE(!alice.isEstablished(bA, 5));

  // Close while in OPEN_SENT. No HS_CLOSE emitted.
  alice.close(bA, 5);
  BOOST_TEST(wire.pending() == 0u);
  BOOST_TEST(alice.channelCount(bA) == 0u);
}

// ---------------------------------------------------------------------------
// 12b'''. An HS_CLOSE with a mismatched session_token is dropped
// silently. This is the off-path spoofing defense: without the 64-bit
// session_token, an attacker observing or forging source addresses
// cannot tear down an ESTABLISHED channel.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpHsCloseWrongTokenIsDropped) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC107A;
  Rudp alice(cfg);
  cfg.rngSeed = 0xC107B;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9950), bA = makeAddr(9951);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 11, B("x"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 11));

  // Hand-craft a forged HS_CLOSE with a wrong session_token and feed
  // it to bob directly as if it had arrived over the wire.
  const uint64_t real_token = bob.sessionToken(aA, 11);
  const uint64_t wrong_token = real_token ^ 0xDEADBEEFCAFEBABEULL;

  Bytes fake;
  fake.resize(4 + 1 + 8);
  minx::Buffer fbuf(fake);
  fbuf.put<uint32_t>(11);
  fbuf.put<uint8_t>(static_cast<uint8_t>(Rudp::HS_CLOSE));
  fbuf.put<uint64_t>(wrong_token);
  fake.resize(fbuf.getSize());

  size_t bobDestroyed = 0;
  bob.setChannelDestroyedCallback(aA, 11, [&]() { ++bobDestroyed; });

  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, fake, now);

  // The forged close was dropped; bob is still established.
  BOOST_TEST(bob.isEstablished(aA, 11));
  BOOST_TEST(bobDestroyed == 0u);

  // The legitimate close still works.
  alice.close(bA, 11);
  wire.deliverAll(now);
  BOOST_TEST(!bob.isEstablished(aA, 11));
  BOOST_TEST(bobDestroyed == 1u);
}

// ---------------------------------------------------------------------------
// 12b''''. An HS_CLOSE for a channel that doesn't exist does NOT
// auto-create the channel. This prevents a spoofer from exhausting
// channel slots by flooding HS_CLOSE packets for fabricated channel_ids.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpHsCloseForUnknownChannelDropped) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC108A;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9960);

  // Forge an HS_CLOSE for a channel bob has never heard of.
  Bytes fake;
  fake.resize(4 + 1 + 8);
  minx::Buffer fbuf(fake);
  fbuf.put<uint32_t>(42);
  fbuf.put<uint8_t>(static_cast<uint8_t>(Rudp::HS_CLOSE));
  fbuf.put<uint64_t>(0x1234567890ABCDEFULL);
  fake.resize(fbuf.getSize());

  BOOST_REQUIRE_EQUAL(bob.peerCount(), 0u);
  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, fake, 1000);

  // No channel was created.
  BOOST_TEST(bob.peerCount() == 0u);
  BOOST_TEST(bob.channelCount(aA) == 0u);
}

// ---------------------------------------------------------------------------
// 12c. gc(idleThreshold) — manual idle eviction knob.
//
// Creates three channels on alice at staggered activity times, then
// calls gc() with progressively tighter thresholds and verifies that
// the expected number of channels survive at each step. Exercises:
//   - gc() as a size_t return (count of evictions)
//   - gc() walking all peers/channels
//   - empty peer pruning
//   - the backstop timeout from config is unrelated to gc's threshold
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpGcIdleThreshold) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.channelInactivityTimeout = std::chrono::seconds(3600); // backstop off
  cfg.maxChannelsPerPeer = 3; // this test exercises multi-channel eviction
  cfg.rngSeed = 0x6C6C;
  Rudp alice(cfg);
  cfg.rngSeed = 0x6C6D;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9920), bA = makeAddr(9921);
  FakeWire wire(alice, bob, aA, bA);

  // Channel 1 — established at t = 1000.
  uint64_t now = 1000;
  alice.push(bA, 1, B("one"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  // Channel 2 — established at t = 3000.
  now = 3000;
  alice.push(bA, 2, B("two"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 2));

  // Channel 3 — established at t = 5000.
  now = 5000;
  alice.push(bA, 3, B("three"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 3));

  BOOST_REQUIRE_EQUAL(alice.channelCount(bA), 3u);

  // Jump time forward so all channels have some age, then advance
  // alice's internal time via a tick().
  now = 10000;
  alice.tick(now);

  // At t=10000, channel ages are:
  //   1: ~9000us (last activity at 1000)
  //   2: ~7000us (last activity at 3000)
  //   3: ~5000us (last activity at 5000)
  // Channels 1 and 2 get ack-refreshed through the tick/deliverAll
  // cascade above only when there was actual traffic, so use the
  // exact pattern-under-test: gc() with a threshold.

  // Loose threshold: nothing evicted.
  BOOST_TEST(alice.gc(std::chrono::microseconds(100'000)) == 0u);
  BOOST_TEST(alice.channelCount(bA) == 3u);

  // Threshold 6000us — evicts channels 1 and 2, keeps channel 3.
  BOOST_TEST(alice.gc(std::chrono::microseconds(6000)) == 2u);
  BOOST_TEST(alice.channelCount(bA) == 1u);
  BOOST_TEST(alice.isEstablished(bA, 3));

  // Tighter — evicts channel 3 as well. Empty peer is pruned.
  BOOST_TEST(alice.gc(std::chrono::microseconds(1)) == 1u);
  BOOST_TEST(alice.channelCount(bA) == 0u);
  BOOST_TEST(alice.peerCount() == 0u);

  // Subsequent gc on an empty instance is a zero-op.
  BOOST_TEST(alice.gc(std::chrono::microseconds(0)) == 0u);
}

// ---------------------------------------------------------------------------
// 12d. onSendBufDrained fires on ack-erase, NOT on pure-receive novelty.
//
// Half A: alice pushes a reliable message, bob acks. Verify alice's
//         drain callback fired exactly once (ack shrank sendBuf).
// Half B: alice has NOTHING pending. Bob pushes a reliable message.
//         Alice receives it (novelty = new reorder entry, not ack).
//         Verify alice's drain callback did NOT fire on that side.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpDrainFiresOnAckOnly) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xD1A1;
  Rudp alice(cfg);
  cfg.rngSeed = 0xD1A2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(9930), bA = makeAddr(9931);
  FakeWire wire(alice, bob, aA, bA);

  size_t aliceDrains = 0;
  size_t bobDrains = 0;

  // Alice pushes first (creates channel 1 eagerly via push), then
  // installs the drain callback. Doing it in this order means the
  // callback is in place by the time bob's ack comes back.
  uint64_t now = 1000;
  BOOST_REQUIRE(alice.push(bA, 1, B("hello"), true));
  alice.setSendBufDrainedCallback(bA, 1, [&]() { ++aliceDrains; });

  // Bob's callback is set up BEFORE any channel exists — setXxxCallback
  // with a non-null fn creates the channel on bob's side proactively.
  bob.setSendBufDrainedCallback(aA, 1, [&]() { ++bobDrains; });

  alice.tick(now);
  wire.deliverAll(now);

  // Half A: alice sent, bob acked → alice's drain should have fired
  // at least once. Bob received a message (novelty from reorder) so
  // his drain must NOT have fired.
  BOOST_TEST(alice.isEstablished(bA, 1));
  BOOST_TEST(bob.isEstablished(aA, 1));
  BOOST_TEST(aliceDrains >= 1u);
  BOOST_TEST(bobDrains == 0u);

  // Reset counters for the isolated receive-only test.
  aliceDrains = 0;
  bobDrains = 0;

  // Half B: alice is idle (no pending writes in sendBuf). Bob sends
  // a reliable message. Alice receives it; this IS novel (new
  // reorder entry) but it is NOT an ack-drain. Alice's drain must
  // stay at zero.
  now = 2000;
  BOOST_REQUIRE(bob.push(aA, 1, B("world"), true));
  bob.tick(now);
  wire.deliverAll(now);

  BOOST_TEST(aliceDrains == 0u);
  // Bob's drain MAY fire (alice's ack of bob's message shrank bob's
  // sendBuf) — that's correct behavior.
  BOOST_TEST(bobDrains >= 1u);
}

// ---------------------------------------------------------------------------
// 12e. onChannelDestroyed fires from every destruction path.
//
// Three sub-scenarios in this test:
//   a) close()
//   b) gc(idleThreshold)
//   c) doPulseWork idle-timeout sweep (config.channelInactivityTimeout)
//
// The fourth path, reorder-cap breach, lives in its own test case
// below because it needs the forging helpers that are defined later
// in the file.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpDestroyedFiresFromAllPaths) {
  // (a) close()
  {
    minx::RudpConfig cfg;
    cfg.baseTickInterval = std::chrono::microseconds::zero();
    cfg.rngSeed = 0xDE51;
    Rudp r(cfg);
    size_t destroyed = 0;
    r.setChannelDestroyedCallback(makeAddr(40000), 1, [&]() { ++destroyed; });
    BOOST_TEST(destroyed == 0u);
    r.close(makeAddr(40000), 1);
    BOOST_TEST(destroyed == 1u);
    // Second close is a no-op.
    r.close(makeAddr(40000), 1);
    BOOST_TEST(destroyed == 1u);
  }

  // (b) gc()
  {
    minx::RudpConfig cfg;
    cfg.baseTickInterval = std::chrono::microseconds::zero();
    cfg.rngSeed = 0xDE52;
    Rudp r(cfg);
    size_t destroyed = 0;
    r.setChannelDestroyedCallback(makeAddr(40001), 1, [&]() { ++destroyed; });
    r.tick(100'000); // advance currentTimeUs_ past any reasonable threshold
    BOOST_TEST(r.gc(std::chrono::microseconds(1)) == 1u);
    BOOST_TEST(destroyed == 1u);
  }

  // (c) doPulseWork idle-timeout sweep
  {
    minx::RudpConfig cfg;
    cfg.channelInactivityTimeout = std::chrono::milliseconds(10);
    cfg.rngSeed = 0xDE53;
    Rudp alice(cfg);
    cfg.rngSeed = 0xDE54;
    Rudp bob(cfg);

    SockAddr aA = makeAddr(40002), bA = makeAddr(40003);
    FakeWire wire(alice, bob, aA, bA);

    size_t destroyed = 0;
    uint64_t now = 1000;
    alice.push(bA, 1, B("hi"), true);
    alice.setChannelDestroyedCallback(bA, 1, [&]() { ++destroyed; });
    alice.tick(now);
    wire.deliverAll(now);
    BOOST_REQUIRE(alice.isEstablished(bA, 1));
    BOOST_TEST(destroyed == 0u);

    // Jump time past the idle timeout AND past the next pulse
    // deadline so that tick() runs doPulseWork (which is what
    // actually sweeps idle channels). The default baseTickInterval
    // is 100 ms, so advance at least that far.
    now += 150'000;
    alice.tick(now);
    BOOST_TEST(destroyed == 1u);
  }
}

// ---------------------------------------------------------------------------
// 12f. preEstablishedQueue cap: push() returns false on overflow.
//
// Constrain maxReorderMessagesPerChannel small so we can fill the
// pre-handshake queue quickly. Alice pushes N+1 reliable messages
// before the handshake completes; the N+1th returns false. Then the
// handshake completes, and we verify bob received exactly N messages
// — i.e., no silent data loss.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpPreEstablishedQueueCap) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 3;
  cfg.rngSeed = 0xCA91;
  Rudp alice(cfg);
  cfg.rngSeed = 0xCA92;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(40100), bA = makeAddr(40101);
  FakeWire wire(alice, bob, aA, bA);

  // Push 3 reliable messages BEFORE ticking alice (so the handshake
  // hasn't started yet — first push moves us to OPEN_SENT but the
  // handshake doesn't complete until deliverAll runs). All three
  // land in the pre-established queue.
  BOOST_TEST(alice.push(bA, 1, B("m0"), true) == true);
  BOOST_TEST(alice.push(bA, 1, B("m1"), true) == true);
  BOOST_TEST(alice.push(bA, 1, B("m2"), true) == true);

  // The 4th push must be rejected — queue is at cap.
  BOOST_TEST(alice.push(bA, 1, B("m3"), true) == false);

  // Now complete the handshake and deliver. Only the 3 accepted
  // messages should reach bob; the rejected one is NOT silently
  // dropped inside RUDP because we refused it at push time.
  uint64_t now = 1000;
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_TEST(wire.bobRecv.size() == 3u);
  if (wire.bobRecv.size() == 3u) {
    BOOST_TEST(wire.bobRecv[0].data == B("m0"));
    BOOST_TEST(wire.bobRecv[1].data == B("m1"));
    BOOST_TEST(wire.bobRecv[2].data == B("m2"));
  }
}

// ---------------------------------------------------------------------------
// 12g. Opened callback fires on basic happy-path handshake for both sides.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpOpenedFiresOnHappyPath) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x0FED0A;
  Rudp alice(cfg);
  cfg.rngSeed = 0x0FED0B;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(40200), bA = makeAddr(40201);
  FakeWire wire(alice, bob, aA, bA);

  std::vector<std::pair<SockAddr, uint32_t>> aliceOpens, bobOpens;
  alice.setChannelOpenedCallback(
    [&](const SockAddr& p, uint32_t cid) { aliceOpens.emplace_back(p, cid); });
  bob.setChannelOpenedCallback(
    [&](const SockAddr& p, uint32_t cid) { bobOpens.emplace_back(p, cid); });

  BOOST_TEST(aliceOpens.size() == 0u);
  BOOST_TEST(bobOpens.size() == 0u);

  uint64_t now = 1000;
  BOOST_REQUIRE(alice.push(bA, 5, B("hi"), true));
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_REQUIRE(alice.isEstablished(bA, 5));
  BOOST_REQUIRE(bob.isEstablished(aA, 5));

  // Exactly one Opened fire per side, with the right parameters.
  BOOST_REQUIRE_EQUAL(aliceOpens.size(), 1u);
  BOOST_REQUIRE_EQUAL(bobOpens.size(), 1u);
  BOOST_TEST(aliceOpens[0].first == bA);
  BOOST_TEST(aliceOpens[0].second == 5u);
  BOOST_TEST(bobOpens[0].first == aA);
  BOOST_TEST(bobOpens[0].second == 5u);
}

// ---------------------------------------------------------------------------
// 12h. Accept predicate returning false silently drops the inbound OPEN.
//
// Alice pushes, bob rejects via predicate. Bob should see NO Opened fire.
// Bob's channel count stays at 0 (erased immediately). Alice keeps retrying
// for handshakeMaxRetries times and eventually her own channel goes away
// via handshake exhaustion.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpAcceptRejectsSilently) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.handshakeRetryInterval = std::chrono::microseconds(1);
  cfg.handshakeMaxRetries = 1;
  cfg.rngSeed = 0xADAD1;
  Rudp alice(cfg);
  cfg.rngSeed = 0xADAD2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(40210), bA = makeAddr(40211);
  FakeWire wire(alice, bob, aA, bA);

  size_t rejectCalls = 0;
  bob.setChannelAcceptCallback([&](const SockAddr& /*peer*/, uint32_t /*cid*/) {
    ++rejectCalls;
    return false;
  });

  size_t bobOpens = 0;
  bob.setChannelOpenedCallback([&](const SockAddr&, uint32_t) { ++bobOpens; });

  // Pre-register a Destroyed callback on the (aA, 7) tuple. This
  // eagerly creates the channel in IDLE state with the callback
  // attached. When bob's accept predicate returns false on alice's
  // incoming OPEN, eraseChannelSilent must NOT fire this — that's
  // the whole invariant under test.
  size_t bobDestroyed = 0;
  bob.setChannelDestroyedCallback(aA, 7, [&]() { ++bobDestroyed; });

  uint64_t now = 1000;
  BOOST_REQUIRE(alice.push(bA, 7, B("reject me"), true));
  alice.tick(now);
  wire.deliverAll(now);

  // Bob saw the OPEN, ran the predicate (=>false), erased the channel.
  BOOST_TEST(rejectCalls >= 1u); // could be >1 due to alice retries
  BOOST_TEST(bobOpens == 0u);
  BOOST_TEST(bob.channelCount(aA) == 0u);
  BOOST_TEST(bob.peerCount() == 0u);
  // The destroyed invariant: silent erase does NOT fire destroyed.
  BOOST_TEST(bobDestroyed == 0u);
}

// ---------------------------------------------------------------------------
// 12i. Accept predicate returning true allows the handshake. Verifies the
// predicate fires exactly once AND that Opened fires afterward.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpAcceptAllowsAndOpens) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xACC01;
  Rudp alice(cfg);
  cfg.rngSeed = 0xACC02;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(40220), bA = makeAddr(40221);
  FakeWire wire(alice, bob, aA, bA);

  // Order of events we want to verify:
  //   1. Bob's Accept predicate fires once with (aA, 9).
  //   2. Bob's Opened fires once with (aA, 9), AFTER accept.
  // We record each event with a sequence number and assert ordering.
  std::vector<std::string> events;
  bob.setChannelAcceptCallback([&](const SockAddr& p, uint32_t cid) {
    events.push_back("accept:" + std::to_string(cid));
    (void)p;
    return true;
  });
  bob.setChannelOpenedCallback([&](const SockAddr& p, uint32_t cid) {
    events.push_back("opened:" + std::to_string(cid));
    (void)p;
  });

  uint64_t now = 1000;
  BOOST_REQUIRE(alice.push(bA, 9, B("pls"), true));
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_REQUIRE(bob.isEstablished(aA, 9));
  BOOST_REQUIRE_EQUAL(events.size(), 2u);
  BOOST_TEST(events[0] == "accept:9");
  BOOST_TEST(events[1] == "opened:9");
}

// ---------------------------------------------------------------------------
// 12j. Peer restart fires the full triad in order:
//     Destroyed(old session) → Accept(new session) → Opened(new session).
//
// We use a forged OPEN packet to simulate "peer restarted with a new
// nonce," because the natural FakeWire path would need two Rudp
// instances with shared channel_id but different session tokens,
// which is awkward to set up. forgeHandshakeBody builds the exact
// wire bytes that handleHandshakePacket reads. Note that this test
// lives here with the other API tests even though it uses forging —
// it's a tiny one-off forger that doesn't need the channel-packet
// helpers defined later in the file.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpPeerRestartFiresFullTriad) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBABE1;
  Rudp alice(cfg);
  cfg.rngSeed = 0xBABE2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(40230), bA = makeAddr(40231);
  FakeWire wire(alice, bob, aA, bA);

  // Establish a channel naturally first.
  uint64_t now = 1000;
  BOOST_REQUIRE(alice.push(bA, 3, B("first"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 3));

  // Register bob's lifecycle callbacks AFTER the first handshake so
  // we only see events from the restart onward.
  std::vector<std::string> events;
  bob.setChannelAcceptCallback([&](const SockAddr&, uint32_t cid) {
    events.push_back("accept:" + std::to_string(cid));
    return true;
  });
  bob.setChannelOpenedCallback([&](const SockAddr&, uint32_t cid) {
    events.push_back("opened:" + std::to_string(cid));
  });
  bob.setChannelDestroyedCallback(aA, 3,
                                  [&]() { events.push_back("destroyed"); });

  // Forge an HS_OPEN packet from alice with a DIFFERENT nonce than
  // the one bob currently holds — simulates "alice process restarted
  // and opened fresh with a new nonce." The wire format is the one
  // emitHandshake writes: [channel_id u32 BE][kind u8][nonce u64 BE]
  // [advertised_rate u32 BE][advertised_burst u32 BE].
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(3);                     // channel_id
  fb.put<uint8_t>(Rudp::HS_OPEN);          // kind
  fb.put<uint64_t>(0xF00DF00DF00DF00DULL); // fresh nonce (different)
  fb.put<uint32_t>(0xFFFFFFFFu);           // advertised rate (unlimited)
  fb.put<uint32_t>(0xFFFFFFFFu);           // advertised burst (unlimited)
  body.resize(fb.getSize());

  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, body, now);

  // Expected order: destroyed (old session) → accept (new) → opened (new).
  BOOST_REQUIRE_EQUAL(events.size(), 3u);
  BOOST_TEST(events[0] == "destroyed");
  BOOST_TEST(events[1] == "accept:3");
  BOOST_TEST(events[2] == "opened:3");
  BOOST_TEST(bob.isEstablished(aA, 3));
}

// ===========================================================================
// Forging helpers for the reorder-buffer / porosity stress tests.
//
// Background: my flush logic always packs sendBuf in msg_id order starting
// from the lowest unacked, so a normal alice -> FakeWire -> bob round trip
// cannot produce out-of-order delivery — the reorder buffer is
// structurally unreachable via the natural sender path. To exercise the
// receive-side reorder buffer + porosity logic, the tests below build
// CHANNEL packets manually with chosen msg_id ranges and inject them
// directly into bob.onPacket(), bypassing the FakeWire entirely.
//
// This is the right shape for testing receiver behavior in isolation:
// we're verifying what bob does when it sees specific wire patterns,
// not how alice and bob converge under fair conditions.
// ===========================================================================

namespace {

// Build a fixed-size payload that encodes its own index in the first 4
// bytes (big-endian) followed by 12 bytes of filler. 16 bytes per msg.
static minx::Bytes makeIndexedPayload(uint32_t i) {
  minx::Bytes out;
  out.resize(16);
  out[0] = static_cast<char>((i >> 24) & 0xFF);
  out[1] = static_cast<char>((i >> 16) & 0xFF);
  out[2] = static_cast<char>((i >> 8) & 0xFF);
  out[3] = static_cast<char>((i) & 0xFF);
  for (int j = 4; j < 16; ++j)
    out[j] = static_cast<char>('A' + (i % 26));
  return out;
}

static uint32_t extractPayloadIndex(const minx::Bytes& b) {
  return (static_cast<uint32_t>(static_cast<uint8_t>(b[0])) << 24) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[1])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[2])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[3])));
}

// Append a big-endian uint to a Bytes buffer.
static void pushU8(minx::Bytes& b, uint8_t v) {
  b.push_back(static_cast<char>(v));
}
static void pushU16BE(minx::Bytes& b, uint16_t v) {
  pushU8(b, static_cast<uint8_t>((v >> 8) & 0xFF));
  pushU8(b, static_cast<uint8_t>(v & 0xFF));
}
static void pushU32BE(minx::Bytes& b, uint32_t v) {
  pushU8(b, static_cast<uint8_t>((v >> 24) & 0xFF));
  pushU8(b, static_cast<uint8_t>((v >> 16) & 0xFF));
  pushU8(b, static_cast<uint8_t>((v >> 8) & 0xFF));
  pushU8(b, static_cast<uint8_t>((v) & 0xFF));
}
static void pushU64BE(minx::Bytes& b, uint64_t v) {
  for (int i = 7; i >= 0; --i)
    pushU8(b, static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

// Forge a CHANNEL packet body (the bytes onPacket receives — i.e. AFTER
// the 8-byte stdext routing key has been stripped). Wire layout matches
// local/rudp.md exactly.
static minx::Bytes forgeChannelBody(
  uint32_t channel_id, uint64_t session_token, uint32_t solid_ack,
  uint32_t porosity,
  const std::vector<std::pair<uint32_t, minx::Bytes>>& reliable_msgs) {
  minx::Bytes out;
  pushU32BE(out, channel_id);
  pushU64BE(out, session_token);
  pushU32BE(out, solid_ack);
  pushU32BE(out, porosity);
  pushU8(out, static_cast<uint8_t>(reliable_msgs.size()));
  for (auto& [id, body] : reliable_msgs) {
    pushU32BE(out, id);
    pushU16BE(out, static_cast<uint16_t>(body.size()));
    for (auto c : body)
      out.push_back(c);
  }
  return out;
}

} // namespace

// ---------------------------------------------------------------------------
// 13. STRESS: bulk reliable delivery — 1000 messages, lossless, ordering
//     verified end-to-end.
//
// Exercises:
//   - sendBuf accumulation and erase under sustained ack pressure
//   - emitChannel's packing loop (multiple messages per CHANNEL packet)
//   - MAX_RELIABLE_PER_PACKET ceiling (255) when many messages fit
//   - solidAck advancement across many cumulative-ack rounds
//   - the convergence loop: alice sends a packet of N msgs, bob acks,
//     alice drops them from sendBuf, alice sends the next batch
//
// Failure modes this would catch:
//   - off-by-one in cumulative ack drop (msgs stuck in sendBuf forever)
//   - duplicate delivery on bob's side (idempotent dedup broken)
//   - packing loop emitting fewer messages per packet than it should
//     (test runs much slower than expected, or hits the safety bound)
//   - flush emitting only one message per call (ditto)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStressBulkReliableDelivery) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBEEF;
  Rudp alice(cfg);
  cfg.rngSeed = 0xCAFE;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11000), bA = makeAddr(11001);
  FakeWire wire(alice, bob, aA, bA);

  const size_t N = 1000;

  // Each message is a 16-byte payload encoding its sequence index in
  // the first 4 bytes via makeIndexedPayload (defined in the namespace
  // above for sharing with the wide-gap stress test).

  // Push all N messages onto alice. Channel state is created on the
  // first push and the handshake is queued for the next flush.
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE(alice.push(bA, /*channel=*/42,
                             makeIndexedPayload(static_cast<uint32_t>(i)),
                             /*reliable=*/true));
  }

  // Drive the protocol until convergence: bob has received all N
  // messages AND alice's sendBuf is fully drained.
  uint64_t now = 0;
  const int MAX_STEPS = 1000; // generous upper bound; expected ~30
  int steps = 0;
  while (steps < MAX_STEPS && wire.bobRecv.size() < N) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
    ++steps;
  }

  // Convergence reached.
  BOOST_TEST_MESSAGE("bulk reliable converged in " << steps << " steps");
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), N);

  // Verify strict in-order delivery: index in each received payload
  // must equal its position in the receive list.
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE_EQUAL(wire.bobRecv[i].channelId, 42u);
    BOOST_REQUIRE(wire.bobRecv[i].reliable);
    BOOST_REQUIRE_EQUAL(wire.bobRecv[i].data.size(), 16u);
    const uint32_t got = extractPayloadIndex(wire.bobRecv[i].data);
    BOOST_REQUIRE_EQUAL(got, static_cast<uint32_t>(i));
  }

  // Drive a few more steps so alice can process bob's final ack and
  // empty her sendBuf. Then verify the channel is fully quiescent: no
  // pending packets in either direction.
  for (int i = 0; i < 5; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_TEST(wire.pending() == 0u);
}

// ---------------------------------------------------------------------------
// 14. STRESS: wide-gap reorder buffer — exercise the receive-side reorder
//     buffer + porosity logic by forging a CHANNEL packet whose msg_ids
//     sit far above the receiver's solidAck. The gap is intentionally
//     much wider than the 32-bit porosity window so we hit the
//     "outside the porosity window" code path.
//
// Scenario:
//   1. Establish a real handshake via a normal "init" message (msg 1).
//      After this, bob's solidAck = 1, alice/bob ESTABLISHED.
//   2. Forge a CHANNEL packet containing msgs 50..100 (51 messages,
//      gap of 48 missing msg_ids 2..49) and inject it directly into
//      bob.onPacket(). All 51 messages land in bob's reorder buffer.
//      Nothing is delivered yet because msg 2 is still missing.
//      Verify bobRecv hasn't grown.
//   3. Forge a second CHANNEL packet containing msgs 2..49 (48 msgs)
//      and inject it. Bob receives them, inserts them into the reorder
//      buffer, then deliverInOrder cascades through the entire range
//      and delivers msgs 2..100 in one pass. Verify bobRecv has
//      exactly 99 messages in strict order.
//
// Failure modes this catches:
//   - reorder buffer not actually buffering out-of-order messages
//     (msgs would be silently dropped instead of staying for cascade)
//   - deliverInOrder loop terminates early instead of cascading
//     across the entire newly-bridged range (msgs after the first
//     few would be stuck)
//   - reorder buffer key collision or insertion bugs at scale
//   - solidAck advancement going wrong when many messages drain at
//     once (off-by-one or skipped indices)
//   - reorderBytes accounting mismatch (would surface if we crossed
//     the byte cap, though this test stays well under it)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStressWideGapReorderBuffer) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xCAFE;
  Rudp alice(cfg);
  cfg.rngSeed = 0xBEEFEE;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11100), bA = makeAddr(11101);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 42;

  // Step 1: real handshake via a normal init message. After convergence,
  // bob's solidAck = 1 (init was msg 1) and we know the session_token.
  BOOST_REQUIRE(alice.push(bA, channel, B("init"), true));
  for (int i = 0; i < 10 && !alice.isEstablished(bA, channel); ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE(alice.isEstablished(bA, channel));
  BOOST_REQUIRE(bob.isEstablished(aA, channel));

  // Drain the init delivery on bob's side and clear the recv log.
  for (int i = 0; i < 5; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 1u);
  wire.bobRecv.clear();

  const uint64_t token = bob.sessionToken(aA, channel);
  BOOST_REQUIRE(token != 0);

  // Step 2: forge msgs 50..100 (the high range) and inject into bob.
  // The gap from solidAck=1 to msg 50 is 48 msg_ids wide — well past
  // the 32-bit porosity window of 32 — so this exercises the
  // "outside the porosity window" path of the reorder buffer.
  std::vector<std::pair<uint32_t, minx::Bytes>> highMsgs;
  for (uint32_t id = 50; id <= 100; ++id) {
    highMsgs.emplace_back(id, makeIndexedPayload(id));
  }
  auto highPacket = forgeChannelBody(channel, token, /*solid_ack=*/0,
                                     /*porosity=*/0, highMsgs);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, highPacket, now);

  // Nothing should have been delivered: bob's solidAck is still 1, and
  // msg 2 is the next one needed. All 51 forged msgs are sitting in
  // the reorder buffer waiting for the gap to close.
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 0u);

  // Step 3: forge msgs 2..49 (the missing low range) and inject. Bob's
  // handleChannelPacket buffers all 48 of them, then calls deliverInOrder
  // exactly once at the end of the packet. deliverInOrder cascades
  // through the entire reorder buffer (now containing msgs 2..100)
  // and delivers all 99 in strict order in a single sweep.
  std::vector<std::pair<uint32_t, minx::Bytes>> lowMsgs;
  for (uint32_t id = 2; id <= 49; ++id) {
    lowMsgs.emplace_back(id, makeIndexedPayload(id));
  }
  auto lowPacket = forgeChannelBody(channel, token, /*solid_ack=*/0,
                                    /*porosity=*/0, lowMsgs);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, lowPacket, now);

  // Verify all 99 messages (2..100) were delivered in strict order.
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 99u);
  for (size_t i = 0; i < 99; ++i) {
    const uint32_t expected = static_cast<uint32_t>(i + 2);
    BOOST_REQUIRE_EQUAL(wire.bobRecv[i].channelId, channel);
    BOOST_REQUIRE(wire.bobRecv[i].reliable);
    BOOST_REQUIRE_EQUAL(wire.bobRecv[i].data.size(), 16u);
    const uint32_t got = extractPayloadIndex(wire.bobRecv[i].data);
    BOOST_REQUIRE_EQUAL(got, expected);
  }

  BOOST_TEST_MESSAGE("wide-gap cascade delivered 99 msgs in one sweep");
}

// ---------------------------------------------------------------------------
// 15. STRESS: reorder buffer message-count cap. Forge a packet with more
//     out-of-order messages than the per-channel reorder buffer can hold.
//     The receiver must close the channel cleanly and let it be GC'd on
//     the next tick.
//
// Failure modes this catches:
//   - cap comparison off-by-one (`>` vs `>=`) letting one extra msg in
//     before the kill
//   - reorderBytes accounting drift if the kill path forgets to clean up
//   - GC failing to evict CLOSED channels (channelCount stays non-zero)
//   - delivery callback fires after the kill (would surface as bobRecv
//     growing past the pre-stress baseline)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStressReorderBufferMessageCap) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xDEAD;
  // Very small cap so we trip it with a forged packet of just 6 messages.
  cfg.maxReorderMessagesPerChannel = 5;
  Rudp alice(cfg);
  cfg.rngSeed = 0xBEEF1;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11200), bA = makeAddr(11201);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 99;

  // Establish the channel via a normal init message.
  BOOST_REQUIRE(alice.push(bA, channel, B("init"), true));
  for (int i = 0; i < 10 && !alice.isEstablished(bA, channel); ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE(alice.isEstablished(bA, channel));
  BOOST_REQUIRE(bob.isEstablished(aA, channel));

  // Drain the init delivery and reset the recv log.
  for (int i = 0; i < 5; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), 1u);
  wire.bobRecv.clear();

  const uint64_t token = bob.sessionToken(aA, channel);
  BOOST_REQUIRE(token != 0);

  // Forge a packet with 6 out-of-order messages (all msg_ids well above
  // bob's solidAck=1). The cap is 5, so the 6th insert pushes the
  // reorder buffer past the limit and trips the kill path.
  //
  // Important: each forged msg uses makeIndexedPayload (16 bytes), so
  // total bytes = 6 * 16 = 96, far below the byte cap. We're testing
  // the message-count branch in isolation.
  std::vector<std::pair<uint32_t, minx::Bytes>> msgs;
  for (uint32_t id = 100; id < 106; ++id) { // 6 msgs
    msgs.emplace_back(id, makeIndexedPayload(id));
  }
  auto packet = forgeChannelBody(channel, token, /*solid_ack=*/0,
                                 /*porosity=*/0, msgs);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, packet, now);

  // The cap tripped during the inbound packet processing, marking the
  // channel CLOSED. With the reactive pulse model, onPacket runs the
  // GC pass inline as part of its post-processing pulse — so the
  // CLOSED channel is evicted from peers_ before onPacket returns.
  // No transient-state observation window: by the time we check, the
  // channel is gone.
  BOOST_TEST(!bob.isEstablished(aA, channel));
  BOOST_TEST(bob.channelCount(aA) == 0u);
  BOOST_TEST(bob.peerCount() == 0u);
  // No messages should have been delivered: the cap tripped before
  // deliverInOrder ran, AND the gap from solidAck=1 → msg 100 means
  // nothing would have been deliverable anyway.
  BOOST_TEST(wire.bobRecv.size() == 0u);
}

// ---------------------------------------------------------------------------
// 15b. onChannelDestroyed fires from the reorder-cap breach path.
//
// Same shape as TestRudpStressReorderBufferMessageCap but with a
// destroyed callback registered before the forged burst. Verifies
// that the reorder-cap breach path — which sets state to CLOSED in
// handleChannelPacket, then relies on doPulseWork's eager-drop loop
// to erase — fires the destroyed callback before the erase.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpDestroyedFiresOnReorderCapBreach) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 5;
  cfg.rngSeed = 0xDE56;
  Rudp alice(cfg);
  cfg.rngSeed = 0xDE57;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11250), bA = makeAddr(11251);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 77;

  // Establish the channel via a normal init message.
  BOOST_REQUIRE(alice.push(bA, channel, B("init"), true));
  for (int i = 0; i < 10 && !alice.isEstablished(bA, channel); ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE(bob.isEstablished(aA, channel));

  // Register destroyed callback AFTER handshake so we only count the
  // breach event.
  size_t destroyed = 0;
  bob.setChannelDestroyedCallback(aA, channel, [&]() { ++destroyed; });

  // Forge a 6-msg packet that overruns the 5-entry cap.
  const uint64_t token = bob.sessionToken(aA, channel);
  std::vector<std::pair<uint32_t, minx::Bytes>> msgs;
  for (uint32_t id = 100; id < 106; ++id) {
    msgs.emplace_back(id, makeIndexedPayload(id));
  }
  auto packet = forgeChannelBody(channel, token, /*solid_ack=*/0,
                                 /*porosity=*/0, msgs);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, packet, now);

  // Breach path: handleChannelPacket set state=CLOSED, returned, the
  // inline-pulse machinery inside onPacket ran doPulseWork which
  // eager-dropped the CLOSED channel, firing our destroyed callback
  // exactly once along the way.
  BOOST_TEST(destroyed == 1u);
  BOOST_TEST(bob.channelCount(aA) == 0u);
}

// ---------------------------------------------------------------------------
// 16. STRESS: reorder buffer byte cap. Same shape as #15 but trips the
//     byte branch instead of the message-count branch. Uses larger
//     messages so we hit `reorderBytes > maxReorderBytesPerChannel`
//     before the message count cap.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStressReorderBufferByteCap) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xFADE;
  // High message cap so the byte cap is what trips first.
  cfg.maxReorderMessagesPerChannel = 1000;
  // Byte cap is 600 — two 500-byte messages will exceed it.
  cfg.maxReorderBytesPerChannel = 600;
  Rudp alice(cfg);
  cfg.rngSeed = 0xFADE2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11300), bA = makeAddr(11301);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 7;

  // Establish via init.
  BOOST_REQUIRE(alice.push(bA, channel, B("init"), true));
  for (int i = 0; i < 10 && !alice.isEstablished(bA, channel); ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE(alice.isEstablished(bA, channel));
  BOOST_REQUIRE(bob.isEstablished(aA, channel));
  for (int i = 0; i < 5; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  wire.bobRecv.clear();

  const uint64_t token = bob.sessionToken(aA, channel);
  BOOST_REQUIRE(token != 0);

  // Forge a packet with 2 out-of-order messages, each 500 bytes. Total
  // 1000 bytes of reorderBytes — the byte cap is 600, so the second
  // insert crosses the line and trips the kill.
  //
  // Packet size sanity: 21 (header) + 2 * (6 + 500) = 1033 bytes. Fits
  // comfortably in MINX's 1280-byte EXTENSION DATA budget.
  std::vector<std::pair<uint32_t, minx::Bytes>> msgs;
  for (uint32_t id = 50; id < 52; ++id) {
    minx::Bytes body;
    body.resize(500);
    for (int j = 0; j < 500; ++j) {
      body[j] = static_cast<char>((id + j) & 0xFF);
    }
    msgs.emplace_back(id, body);
  }
  auto packet = forgeChannelBody(channel, token, /*solid_ack=*/0,
                                 /*porosity=*/0, msgs);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, packet, now);

  // Channel killed by the byte cap branch.
  BOOST_TEST(!bob.isEstablished(aA, channel));
  BOOST_TEST(wire.bobRecv.size() == 0u);

  // GC sweeps it on the next tick.
  bob.tick(now);
  BOOST_TEST(bob.channelCount(aA) == 0u);
  BOOST_TEST(bob.peerCount() == 0u);
}

// ---------------------------------------------------------------------------
// 17. STRESS: bulk reliable delivery WITH PACKET LOSS — 1000 messages
//     pushed end-to-end while the wire drops every 3rd a→b packet
//     (~33% sustained loss in the data direction). Verifies that the
//     natural retransmit path under realistic loss converges to
//     in-order delivery of every message with no duplicates.
//
// What this exercises that the lossless bulk test (#13) did not:
//   - emitChannel re-sending the same sendBuf prefix on each retry
//     (instead of advancing) until acks confirm receipt
//   - The receiver's "msg_id <= solidAck" duplicate-drop branch firing
//     on retransmits that DID successfully arrive previously
//   - Convergence under continuous packet loss — the test must complete
//     in O(no-loss steps × (1 + loss_rate)) ish, not blow up
//   - Deterministic loss patterns producing reproducible step counts
//     (the seeded RNG + fixed drop pattern means this number is the
//     same on every run, so a future regression that increases the
//     count will surface immediately)
//
// Failure modes this catches:
//   - retransmit logic that advances sendBuf prematurely (msgs go
//     missing forever)
//   - duplicate dedup on the receiver firing on the wrong condition
//     (msgs delivered twice, count exceeds N)
//   - cumulative ack going backward after a dropped ack-only packet
//   - sustained loss leading to runaway state growth (we'd see step
//     count explode past the safety bound)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpStressBulkWithLoss) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC0DE;
  Rudp alice(cfg);
  cfg.rngSeed = 0xF00D;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(11400), bA = makeAddr(11401);
  FakeWire wire(alice, bob, aA, bA);

  // Drop every 3rd a→b packet (data direction). Acks (b→a) flow freely.
  // This isolates the test to the retransmit path on the data side.
  wire.dropEveryNthAtoB = 3;

  const size_t N = 1000;
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE(alice.push(bA, /*channel=*/42,
                             makeIndexedPayload(static_cast<uint32_t>(i)),
                             /*reliable=*/true));
  }

  uint64_t now = 0;
  const int MAX_STEPS = 1000; // generous; expected on the order of 50-80
  int steps = 0;
  while (steps < MAX_STEPS && wire.bobRecv.size() < N) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
    ++steps;
  }

  BOOST_TEST_MESSAGE("bulk + 33% a→b loss converged in " << steps << " steps");
  BOOST_REQUIRE_EQUAL(wire.bobRecv.size(), N);

  // Strict in-order delivery: the index encoded in each payload must
  // equal the position in the receive list.
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE_EQUAL(wire.bobRecv[i].channelId, 42u);
    BOOST_REQUIRE(wire.bobRecv[i].reliable);
    BOOST_REQUIRE_EQUAL(wire.bobRecv[i].data.size(), 16u);
    const uint32_t got = extractPayloadIndex(wire.bobRecv[i].data);
    BOOST_REQUIRE_EQUAL(got, static_cast<uint32_t>(i));
  }

  // Drive a few more steps so alice's sendBuf can drain to empty after
  // bob's final ack arrives. Then verify the wire is quiescent.
  for (int i = 0; i < 10; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_TEST(wire.pending() == 0u);
}

// ===========================================================================
// Per-channel token bucket
// ===========================================================================

// Negotiation: effective bucket is min(local, peer) per parameter.
// alice advertises a SMALL burst, bob advertises a LARGE burst; alice
// also has a very low rate so the bucket can't refill meaningfully
// during the test. The observable consequence on bob's send side is
// that bob can only emit ~min(alice.burst, bob.burst) = alice.burst
// bytes before the bucket latches.
BOOST_AUTO_TEST_CASE(TestRudpBucketNegotiationSmallerWins) {
  minx::RudpConfig aliceCfg;
  aliceCfg.baseTickInterval = std::chrono::microseconds::zero();
  aliceCfg.rngSeed = 0xB0C1;
  aliceCfg.perChannelBytesPerSecond = 1;      // effectively no refill
  aliceCfg.perChannelBurstBytes = 4000;       // the small side
  Rudp alice(aliceCfg);

  minx::RudpConfig bobCfg;
  bobCfg.baseTickInterval = std::chrono::microseconds::zero();
  bobCfg.rngSeed = 0xB0C2;
  bobCfg.perChannelBytesPerSecond = 1'000'000; // generous local config
  bobCfg.perChannelBurstBytes = 1'000'000;     // the large side
  Rudp bob(bobCfg);

  SockAddr aA = makeAddr(10000), bA = makeAddr(10001);
  FakeWire wire(alice, bob, aA, bA);

  // Establish a channel. The handshake OPEN/ACCEPT carries each side's
  // advertised params; both sides freeze their effective bucket at
  // handshake completion.
  uint64_t now = 1000;
  alice.push(bA, 1, B("warmup"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));
  BOOST_REQUIRE(bob.isEstablished(aA, 1));

  // Now hammer bob's outbound: push many full-size reliable messages.
  // bob's effective bucket is min(1MB, 4000) = 4000 bytes. Each packet
  // carries a channel header (~29 bytes) plus the reliable message
  // payload (≤1245). So the bucket should allow at most ~4 packets'
  // worth of bytes before latching.
  Bytes big = Bn('x', Rudp::MAX_MESSAGE_SIZE);
  for (int i = 0; i < 50; ++i) {
    bob.push(aA, 1, big, true);
  }
  wire.clearQueue();

  // Tick bob at FIXED `now` (no dt between calls). At dt=0 the bucket
  // refill is a no-op, so once the bucket exhausts after the first
  // burst, emission stops for good. This is the clean way to measure
  // the "burst capacity before any refill" ceiling.
  size_t emittedBytes = 0;
  for (int i = 0; i < 20; ++i) {
    bob.tick(now);
    while (!wire.queue.empty()) {
      emittedBytes += wire.queue.front().bytes.size();
      wire.queue.pop_front();
    }
  }

  // Emitted bytes should be bounded by the effective burst PLUS at most
  // one packet of overshoot (the one-packet overshoot design).
  const size_t ceiling =
    aliceCfg.perChannelBurstBytes + Rudp::MAX_PACKET_SIZE;
  BOOST_TEST(emittedBytes <= ceiling);
  BOOST_TEST(emittedBytes > 0u);
}

// Exhaustion + refill: after the bucket latches, bob stops emitting.
// Advancing time enough to refill unlatches and lets more bytes flow.
BOOST_AUTO_TEST_CASE(TestRudpBucketExhaustionAndRefill) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xB0C3;
  cfg.perChannelBytesPerSecond = 10'000; // 10 KB/sec refill
  cfg.perChannelBurstBytes = 2000;       // 2 KB initial burst
  Rudp alice(cfg);
  cfg.rngSeed = 0xB0C4;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(10010), bA = makeAddr(10011);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 1, B("warmup"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  // Push a lot of data into alice's sendBuf.
  Bytes big = Bn('A', Rudp::MAX_MESSAGE_SIZE);
  for (int i = 0; i < 30; ++i) {
    alice.push(bA, 1, big, true);
  }

  // Phase 1: fixed `now` so the bucket can't refill. Once the initial
  // capacity is drained and the charge latches, emission stops.
  wire.clearQueue();
  size_t phase1Bytes = 0;
  for (int i = 0; i < 20; ++i) {
    alice.tick(now);
    while (!wire.queue.empty()) {
      phase1Bytes += wire.queue.front().bytes.size();
      wire.queue.pop_front();
    }
  }
  const size_t ceiling1 = cfg.perChannelBurstBytes + Rudp::MAX_PACKET_SIZE;
  BOOST_TEST(phase1Bytes <= ceiling1);
  BOOST_TEST(phase1Bytes > 0u);

  // Remember how much was emitted before the bucket latched.
  const size_t beforeRefill = phase1Bytes;

  // Phase 2: advance time by 500ms. At 10 KB/s that's ~5 KB of tokens,
  // more than enough to top off the 2 KB capacity and allow another
  // burst's worth of emission.
  now += 500'000;
  size_t phase2Bytes = 0;
  for (int i = 0; i < 20; ++i) {
    alice.tick(now);
    while (!wire.queue.empty()) {
      phase2Bytes += wire.queue.front().bytes.size();
      wire.queue.pop_front();
    }
  }
  // After refill, alice can emit more. The total over both phases
  // should exceed the initial burst (strict proof that refill cleared
  // the latch).
  BOOST_TEST(phase2Bytes > 0u);
  BOOST_TEST(beforeRefill + phase2Bytes > cfg.perChannelBurstBytes);
}

// Both sides advertise PER_CHANNEL_UNLIMITED for both parameters (i.e.
// default config on both). initChannelBucket's short-circuit at
// rudp.cpp:140 disables pacing entirely when EITHER effective parameter
// is still UNLIMITED after the min(local, peer) reduction — so with both
// sides at UNLIMITED the bucket is disabled and any amount of data
// flows without latching.
BOOST_AUTO_TEST_CASE(TestRudpBucketBothUnlimitedPacingDisabled) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xB0C7;
  // defaults: perChannelBytesPerSecond == perChannelBurstBytes ==
  // PER_CHANNEL_UNLIMITED
  Rudp alice(cfg);
  cfg.rngSeed = 0xB0C8;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(10030), bA = makeAddr(10031);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 1, B("warmup"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  // Push way more than any finite burst would allow, at time=now+1us
  // so a finite rate couldn't have refilled.
  Bytes big = Bn('X', Rudp::MAX_MESSAGE_SIZE);
  for (int i = 0; i < 50; ++i) {
    alice.push(bA, 1, big, true);
  }
  wire.clearQueue();
  size_t emitted = 0;
  for (int i = 0; i < 80; ++i) {
    alice.tick(now);
    while (!wire.queue.empty()) {
      emitted += wire.queue.front().bytes.size();
      wire.queue.pop_front();
    }
    now += 1;
  }
  // With pacing disabled, bob receives everything. Worst case with a
  // finite bucket would have been ~(burst + MTU). We've pushed ~50
  // MTUs, so exceeding any small-burst ceiling proves pacing is off.
  BOOST_TEST(emitted > static_cast<size_t>(20 * Rudp::MAX_MESSAGE_SIZE));
}

// ===========================================================================
// Simultaneous open — both sides push first, HS_OPENs cross on the wire
// ===========================================================================

// Both sides push() before any handshake traffic crosses. Both emit
// HS_OPEN. When the peer's OPEN arrives while we're in OPEN_SENT, the
// code (rudp.cpp:849) treats it as simultaneous-open, reuses our
// already-generated nonce as N_b, and promotes to ESTABLISHED. Both
// sides end up with the same session_token (deriveSessionToken is
// commutative under XOR, see rudp.cpp:426).
BOOST_AUTO_TEST_CASE(TestRudpSimultaneousOpenBothSidesPush) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x51A1;
  Rudp alice(cfg);
  cfg.rngSeed = 0x51A2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(10100), bA = makeAddr(10101);
  FakeWire wire(alice, bob, aA, bA);

  // Both sides push before the other's OPEN arrives. tick() on each
  // emits HS_OPEN; they race through the queue.
  alice.push(bA, 77, B("from-alice"), true);
  bob.push(aA, 77, B("from-bob"), true);
  alice.tick(1000);
  bob.tick(1000);
  // Wire now has two queued HS_OPENs — one from each side.
  BOOST_REQUIRE_EQUAL(wire.pending(), 2u);

  // Deliver. Each side's OPEN triggers the simultaneous-open path on
  // the other, which emits an ACCEPT. Then the ACCEPTs are ignored
  // (because state is already ESTABLISHED by the simultaneous-open
  // path), but re-acking is harmless.
  wire.deliverAll(1000);

  BOOST_TEST(alice.isEstablished(bA, 77));
  BOOST_TEST(bob.isEstablished(aA, 77));
  // The session_token is derived from both nonces and is symmetric
  // (XOR), so both sides agree.
  BOOST_TEST(alice.sessionToken(bA, 77) == bob.sessionToken(aA, 77));
  BOOST_TEST(alice.sessionToken(bA, 77) != 0u);

  // Drive a few more ticks + delivers so each side's pushed message
  // drains and gets delivered to the peer's ReceiveFn.
  for (int i = 0; i < 10; ++i) {
    alice.tick(1000 + i);
    bob.tick(1000 + i);
    wire.deliverAll(1000 + i);
  }
  BOOST_TEST(!wire.aliceRecv.empty());
  BOOST_TEST(!wire.bobRecv.empty());
}

// ===========================================================================
// Pulse machinery: deadline advancement, catchup
// ===========================================================================

// With a non-zero baseTickInterval, nextDeadlineUs advances from 0 to
// (now + interval) on the first external call that initializes the
// pulse. Subsequent tick()s before the deadline don't fire pulses
// and don't move the deadline.
BOOST_AUTO_TEST_CASE(TestRudpPulseDeadlineAdvances) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::milliseconds(100); // 100_000 us
  cfg.rngSeed = 0xBEAD;
  Rudp r(cfg);
  // Install callbacks so sendFn/receiveFn are non-null (doPulseWork
  // returns early if sendFn is unset).
  r.setSendCallback([](const SockAddr&, const Bytes&) {});
  r.setReceiveCallback([](const SockAddr&, uint32_t, const Bytes&, bool) {});

  // Before any call, deadline is the init sentinel (0).
  BOOST_TEST(r.nextDeadlineUs() == 0u);

  // First tick arms the deadline = now + interval.
  r.tick(1'000'000);
  BOOST_TEST(r.nextDeadlineUs() == 1'000'000u + 100'000u);

  // tick() well before the deadline does NOT move it.
  r.tick(1'050'000);
  BOOST_TEST(r.nextDeadlineUs() == 1'000'000u + 100'000u);

  // tick() AT the deadline fires a pulse and resets to now + interval.
  r.tick(1'100'000);
  BOOST_TEST(r.nextDeadlineUs() == 1'100'000u + 100'000u);
}

// tick() that's overdue by N intervals fires catchup pulses — each
// pulse gets its own per-channel packet-emission budget, so a long-
// slept caller can emit multiple packets on a single tick(). Bounded
// by an internal cap (MAX_PULSES_PER_CALL = 100).
//
// The key observable: a single tick() after a long idle period emits
// MORE than one packet on a channel with many full-size messages
// queued, because each caught-up pulse adds one packet to the per-
// channel budget.
BOOST_AUTO_TEST_CASE(TestRudpPulseCatchupOnOverdue) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::milliseconds(10); // 10ms interval
  cfg.rngSeed = 0xBEA3;
  Rudp alice(cfg);
  cfg.rngSeed = 0xBEA4;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(10210), bA = makeAddr(10211);
  FakeWire wire(alice, bob, aA, bA);

  // Establish the channel and drain the warmup traffic by running a
  // few tick/deliver cycles with time advancing well past the 10ms
  // interval. After this loop alice.sendBuf and the wire are both
  // empty and both sides have up-to-date deadlines.
  uint64_t now = 1'000'000;
  alice.push(bA, 1, B("warmup"), true);
  for (int i = 0; i < 10; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll(now);
    now += 20'000; // 2 intervals per loop
  }
  BOOST_REQUIRE(alice.isEstablished(bA, 1));
  wire.clearQueue();

  // Push 10 full-size reliable messages. At MAX_MESSAGE_SIZE each,
  // only one fits per packet — so N packets emitted ≈ N pulses fired.
  Bytes big = Bn('C', Rudp::MAX_MESSAGE_SIZE);
  for (int i = 0; i < 10; ++i) {
    alice.push(bA, 1, big, true);
  }

  // Jump time forward by 100ms = 10 intervals past alice's current
  // deadline (already set to ~now + 10ms from the last tick()). A
  // single tick() here must fire multiple catchup pulses and emit
  // multiple packets — strictly more than the "one packet per pulse"
  // that a non-overdue tick would produce.
  now += 100'000;
  alice.tick(now);
  const size_t overdueTickPackets = wire.pending();
  BOOST_TEST(overdueTickPackets >= 2u); // proves catchup > one pulse
  BOOST_TEST(overdueTickPackets <= 100u); // capped at MAX_PULSES_PER_CALL
}

// ===========================================================================
// Edge cases: symmetric close, close vs peer-restart race, sendBuf full
// ===========================================================================

// Both sides call close() simultaneously. Each emits an HS_CLOSE; the
// HS_CLOSEs cross on the wire. Each side's inbound HS_CLOSE arrives
// for a channel the receiving side has already erased, so it's
// dropped at findChannel (no crash, no double-destroyed fire).
BOOST_AUTO_TEST_CASE(TestRudpSymmetricCloseIsIdempotent) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xEDC1;
  Rudp alice(cfg);
  cfg.rngSeed = 0xEDC2;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(10300), bA = makeAddr(10301);
  FakeWire wire(alice, bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 2, B("x"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 2));
  BOOST_REQUIRE(bob.isEstablished(aA, 2));

  size_t aliceDestroyed = 0, bobDestroyed = 0;
  alice.setChannelDestroyedCallback(bA, 2, [&]() { ++aliceDestroyed; });
  bob.setChannelDestroyedCallback(aA, 2, [&]() { ++bobDestroyed; });

  // Both close BEFORE delivering either HS_CLOSE — each HS_CLOSE is
  // queued on the wire with the other side still live.
  alice.close(bA, 2);
  bob.close(aA, 2);
  BOOST_TEST(aliceDestroyed == 1u);
  BOOST_TEST(bobDestroyed == 1u);
  BOOST_TEST(wire.pending() == 2u);

  // Deliver both crossed HS_CLOSEs. Each targets a channel the
  // receiver has already erased — they're dropped at findChannel.
  // No callbacks fire again; the counters stay at 1.
  wire.deliverAll(now);
  BOOST_TEST(aliceDestroyed == 1u);
  BOOST_TEST(bobDestroyed == 1u);
  BOOST_TEST(alice.peerCount() == 0u);
  BOOST_TEST(bob.peerCount() == 0u);
}

// Peer-restart race: alice has an ESTABLISHED channel, then bob forgets
// state and sends a fresh HS_OPEN with a new nonce. Before alice
// processes bob's OPEN, a stale HS_CLOSE (with the OLD session_token)
// would arrive from the network — it must NOT tear down the
// newly-restarted channel.
//
// We simulate: bob restarts (re-construct), sends fresh OPEN; alice
// processes it (fires destroyed for old session, accepts new session);
// then a stale HS_CLOSE bearing the OLD token arrives — must be dropped
// on the session_token mismatch check.
BOOST_AUTO_TEST_CASE(TestRudpStaleHsCloseAfterPeerRestartIsDropped) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xEDC3;
  Rudp alice(cfg);
  cfg.rngSeed = 0xEDC4;
  std::unique_ptr<Rudp> bob(new Rudp(cfg));

  SockAddr aA = makeAddr(10310), bA = makeAddr(10311);
  FakeWire wire(alice, *bob, aA, bA);

  uint64_t now = 1000;
  alice.push(bA, 3, B("hi"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 3));
  const uint64_t oldToken = alice.sessionToken(bA, 3);
  BOOST_REQUIRE(oldToken != 0u);

  // Simulate peer restart: drop the old bob and construct a fresh one
  // with different RNG (so new nonce, new token). Rewire.
  bob.reset();
  cfg.rngSeed = 0xEDC5;
  bob.reset(new Rudp(cfg));
  FakeWire wire2(alice, *bob, aA, bA);

  // Fresh bob pushes → emits a new HS_OPEN with a new nonce.
  bob->push(aA, 3, B("reborn"), true);
  bob->tick(now);
  wire2.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 3));
  const uint64_t newToken = alice.sessionToken(bA, 3);
  BOOST_REQUIRE(newToken != 0u);
  BOOST_TEST(oldToken != newToken);

  // Inject a stale HS_CLOSE carrying the OLD token directly to alice
  // (as if it had been delayed in the network and arrives now).
  Bytes stale;
  stale.resize(4 + 1 + 8);
  minx::Buffer sbuf(stale);
  sbuf.put<uint32_t>(3);
  sbuf.put<uint8_t>(static_cast<uint8_t>(Rudp::HS_CLOSE));
  sbuf.put<uint64_t>(oldToken);
  stale.resize(sbuf.getSize());

  size_t aliceDestroyed = 0;
  alice.setChannelDestroyedCallback(bA, 3, [&]() { ++aliceDestroyed; });

  alice.onPacket(bA, Rudp::KEY_V0_HANDSHAKE, stale, now);

  // Stale HS_CLOSE bounced on token mismatch. New channel still live.
  BOOST_TEST(alice.isEstablished(bA, 3));
  BOOST_TEST(aliceDestroyed == 0u);
  BOOST_TEST(alice.sessionToken(bA, 3) == newToken);
}

// push() returns false when sendBuf hits its cap on an ESTABLISHED
// channel (not the preEstablishedQueue path). The channel is already
// up; the ack window hasn't drained yet; a burst that outpaces the
// acks must fail push() rather than overflow sendBuf.
BOOST_AUTO_TEST_CASE(TestRudpPushFailsWhenSendBufFullOnEstablished) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 3; // tiny cap to force the condition
  cfg.rngSeed = 0xEDC6;
  Rudp alice(cfg);
  cfg.rngSeed = 0xEDC7;
  Rudp bob(cfg);

  SockAddr aA = makeAddr(10320), bA = makeAddr(10321);
  FakeWire wire(alice, bob, aA, bA);

  // Establish the channel with a trivial warm-up that gets acked.
  uint64_t now = 1000;
  alice.push(bA, 1, B("warmup"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));
  // Drive until the warm-up is fully acked and sendBuf is empty.
  for (int i = 0; i < 5; ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll(now);
  }

  // Intercept the wire so alice's outbound packets can't be acked:
  // we just drop everything. alice's sendBuf grows without draining.
  wire.clearQueue();
  wire.dropEveryNthAtoB = 1; // drop every alice→bob packet

  // First 3 pushes fill sendBuf up to the cap of 3.
  BOOST_TEST(alice.push(bA, 1, B("m0"), true) == true);
  BOOST_TEST(alice.push(bA, 1, B("m1"), true) == true);
  BOOST_TEST(alice.push(bA, 1, B("m2"), true) == true);
  // Fourth push is rejected — sendBuf is full on an ESTABLISHED
  // channel. Not a preEstablishedQueue path: the channel is live.
  BOOST_TEST(alice.push(bA, 1, B("m3"), true) == false);
}

BOOST_AUTO_TEST_SUITE_END()
