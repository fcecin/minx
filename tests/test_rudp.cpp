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

#include <crc32c/crc32c.h>
#include <array>

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

class TestListener; // fwd

// TestChannelHandler — Rudp::ChannelHandler subclass that captures the
// per-channel lifecycle into easily-inspectable members. Carries a
// back-pointer to its TestListener so the listener can fire
// listener-level hooks (with the (peer, cid) tag) for tests that
// don't want to fish out the handler first.
class TestChannelHandler : public Rudp::ChannelHandler {
public:
  // Set by TestListener at handler-creation time.
  TestListener* listener = nullptr;
  std::pair<SockAddr, uint32_t> key{}; // (peer, cid) — duplicated from
                                       // base accessors so listener-
                                       // level hooks can dispatch
                                       // before onOpened has populated
                                       // the base's peer_/cid_ (it
                                       // hasn't yet at construction).

  bool opened = false;
  bool established = false;
  bool closed = false;
  std::optional<Rudp::CloseReason> closedReason;
  std::vector<Bytes> reliableMessages;
  std::vector<Bytes> unreliableMessages;
  std::size_t writableCount = 0;

  // Per-handler hooks. Tests that want behavior on a specific
  // (peer, cid) install these on the matching handler.
  std::function<void()> openedHook;
  std::function<void()> establishedHook;
  std::function<void()> writableHook;
  std::function<void(Rudp::CloseReason)> closedHook;

  void onOpened() override;
  void onEstablished() override;
  void onReliableMessage(const Bytes& m) override;
  void onUnreliableMessage(const Bytes& m) override;
  void onWritable() override;
  void onClosed(Rudp::CloseReason r) override;
};

// TestListener — Rudp::Listener subclass with default-construct-and-
// stash semantics for inbound channels. onAccept creates a fresh
// TestChannelHandler and remembers it in `handlers` keyed by
// (peer, cid). Tests inspect with `handler(p, c)`.
//
// For outbound (we initiate), tests use `registerChannel(rudp, p, c)`
// which constructs a handler, calls rudp.registerChannel, and stashes
// the handler in the same map.
class TestListener : public Rudp::Listener {
public:
  // FakeWire installs this to route outbound packets into its queue.
  std::function<void(const SockAddr&, const Bytes&)> sink;

  // (peer, cid) → handler map. Holds shared_ptr to keep the handler
  // alive even after Rudp drops its ref (e.g. so tests can inspect
  // a channel's final state post-close). Replaced on peer-restart;
  // for events that survive map mutations, see the flat logs below.
  std::map<std::pair<SockAddr, uint32_t>,
           std::shared_ptr<TestChannelHandler>> handlers;

  // Flat event logs across all handlers ever owned by this listener,
  // in event order. Survive handler replacement (peer-restart). Used
  // by tests that just want "did N events happen" without caring
  // which channel.
  struct DeliveredMessage {
    SockAddr peer;
    uint32_t channelId;
    Bytes data;
    bool reliable;
  };
  std::vector<DeliveredMessage> received;
  std::vector<std::pair<SockAddr, uint32_t>> opens;        // onOpened
  std::vector<std::pair<SockAddr, uint32_t>> establishes;  // onEstablished
  std::vector<std::pair<SockAddr, uint32_t>> writables;
  struct ClosedEvent {
    SockAddr peer;
    uint32_t cid;
    Rudp::CloseReason reason;
  };
  std::vector<ClosedEvent> closes;

  // Captured non-channel events.
  std::vector<std::pair<SockAddr, uint32_t>> acceptCalls;
  struct AbuseEvent {
    SockAddr peer;
    uint32_t cid;
    Rudp::AbuseSignal signal;
  };
  std::vector<AbuseEvent> abuses;

  // Optional pre-decision predicate. If set and returns false,
  // onAccept rejects (returns nullptr to Rudp). If unset, default
  // is to accept and construct a handler.
  std::function<bool(const SockAddr&, uint32_t)> acceptPredicate;

  // Optional handler factory. If set, called by onAccept to make
  // the handler instead of the default `std::make_shared<TestChannelHandler>()`.
  // Useful when a test wants to install hooks before onOpened fires.
  std::function<std::shared_ptr<TestChannelHandler>(const SockAddr&,
                                                    uint32_t)>
    handlerFactory;

  // Listener-level hooks. These fire from the matching event method
  // on every TestChannelHandler this listener owns, with the (peer,
  // cid) tag for filtering. Installed AFTER channel registration still
  // applies to existing channels (handlers fire via the back-pointer
  // every time, not at construction time).
  std::function<void(const SockAddr&, uint32_t)> openedHook;
  std::function<void(const SockAddr&, uint32_t)> establishedHook;
  std::function<void(const SockAddr&, uint32_t)> writableHook;
  std::function<void(const SockAddr&, uint32_t, Rudp::CloseReason)> closedHook;

  // Listener overrides.
  void onSend(const SockAddr& peer, const Bytes& bytes) override {
    if (sink) sink(peer, bytes);
  }
  std::shared_ptr<Rudp::ChannelHandler> onAccept(
    const SockAddr& peer, uint32_t cid) override {
    acceptCalls.emplace_back(peer, cid);
    if (acceptPredicate && !acceptPredicate(peer, cid)) {
      return nullptr;
    }
    auto h = handlerFactory ? handlerFactory(peer, cid)
                            : std::make_shared<TestChannelHandler>();
    h->listener = this;
    h->key = {peer, cid};
    handlers[{peer, cid}] = h;
    return h;
  }
  void onAbuse(const SockAddr& peer, uint32_t cid,
               Rudp::AbuseSignal sig) override {
    abuses.push_back({peer, cid, sig});
  }

  // ---- Test helpers ----

  /// Outbound registration helper: construct a TestChannelHandler,
  /// register it on the channel via rudp.registerChannel, and stash it
  /// in handlers[]. Returns the handler (or nullptr if registration
  /// failed, e.g. cap exhausted).
  std::shared_ptr<TestChannelHandler> registerChannel(Rudp& r, const SockAddr& peer,
                                            uint32_t cid) {
    auto h = std::make_shared<TestChannelHandler>();
    h->listener = this;
    h->key = {peer, cid};
    if (!r.registerChannel(peer, cid, h)) return nullptr;
    handlers[{peer, cid}] = h;
    return h;
  }

  /// Look up a handler by (peer, cid). Returns nullptr if not found.
  std::shared_ptr<TestChannelHandler> handler(const SockAddr& peer,
                                              uint32_t cid) const {
    auto it = handlers.find({peer, cid});
    return (it != handlers.end()) ? it->second : nullptr;
  }

  /// Test-side push helper: idempotently register the channel (with a
  /// default TestChannelHandler) on first call, then forward to
  /// rudp.push. Consults Rudp's authoritative view of channel
  /// existence (not our local map) so a previously-closed channel
  /// gets a fresh registration rather than reusing a dead handler.
  bool push(Rudp& r, const SockAddr& peer, uint32_t cid,
            const Bytes& msg, bool reliable) {
    if (!r.channelHandler(peer, cid)) {
      if (!registerChannel(r, peer, cid)) return false;
    }
    return r.push(peer, cid, msg, reliable);
  }

  /// Reset all captured messages (flat log + per-handler).
  void clearMessages() {
    received.clear();
    for (auto& [_, h] : handlers) {
      h->reliableMessages.clear();
      h->unreliableMessages.clear();
    }
  }

  /// Convenience aggregators kept for tests that read count-only.
  std::size_t establishedCount() const { return establishes.size(); }
  std::size_t closedCount() const { return closes.size(); }
};

// Out-of-line TestChannelHandler definitions: dispatch listener-level
// hooks AND populate the listener's flat event logs via the back-
// pointer. Both interfaces are kept in sync; tests use whichever fits.
inline void TestChannelHandler::onOpened() {
  opened = true;
  if (listener) {
    listener->opens.emplace_back(key.first, key.second);
  }
  if (openedHook) openedHook();
  if (listener && listener->openedHook) {
    listener->openedHook(key.first, key.second);
  }
}

inline void TestChannelHandler::onEstablished() {
  established = true;
  if (listener) {
    listener->establishes.emplace_back(key.first, key.second);
  }
  if (establishedHook) establishedHook();
  if (listener && listener->establishedHook) {
    listener->establishedHook(key.first, key.second);
  }
}

inline void TestChannelHandler::onReliableMessage(const Bytes& m) {
  reliableMessages.push_back(m);
  if (listener) {
    listener->received.push_back({key.first, key.second, m, /*reliable=*/true});
  }
}

inline void TestChannelHandler::onUnreliableMessage(const Bytes& m) {
  unreliableMessages.push_back(m);
  if (listener) {
    listener->received.push_back({key.first, key.second, m, /*reliable=*/false});
  }
}

inline void TestChannelHandler::onWritable() {
  ++writableCount;
  if (listener) {
    listener->writables.emplace_back(key.first, key.second);
  }
  if (writableHook) writableHook();
  if (listener && listener->writableHook) {
    listener->writableHook(key.first, key.second);
  }
}

inline void TestChannelHandler::onClosed(Rudp::CloseReason r) {
  closed = true;
  closedReason = r;
  if (listener) {
    listener->closes.push_back({key.first, key.second, r});
  }
  if (closedHook) closedHook(r);
  if (listener && listener->closedHook) {
    listener->closedHook(key.first, key.second, r);
  }
}

// FakeWire — synchronous in-memory transport between two Rudp instances.
// Owns no Rudp; the test constructs the Rudp pair externally with their
// own TestListener instances and hands references to the wire.
struct FakeWire {
  Rudp& alice;
  Rudp& bob;
  TestListener& aliceL;
  TestListener& bobL;
  SockAddr aliceAddr;
  SockAddr bobAddr;
  std::deque<CapturedPacket> queue;
  size_t dropNextAtoB = 0;
  size_t dropNextBtoA = 0;
  size_t dropEveryNthAtoB = 0;
  size_t dropEveryNthBtoA = 0;
  size_t aToBSeq = 0;
  size_t bToASeq = 0;

  FakeWire(Rudp& a, TestListener& al, Rudp& b, TestListener& bl, SockAddr aa,
           SockAddr ba)
      : alice(a), bob(b), aliceL(al), bobL(bl), aliceAddr(aa), bobAddr(ba) {
    aliceL.sink = [this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({aliceAddr, peer, bytes});
    };
    bobL.sink = [this](const SockAddr& peer, const Bytes& bytes) {
      queue.push_back({bobAddr, peer, bytes});
    };
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

// CRC trailer helper, used by forged-packet tests. RUDP expects every
// on-wire packet to carry a CRC32C trailer covering [routing_key_BE]
// [body]. Forged bodies fed directly to onPacket() need the same
// trailer or they're dropped at the CRC check.
//
// Both the key serialization and the trailer go through minx::Buffer
// to guarantee the same BE encoding the wire-side appendCrc32cTrailer
// (in src/rudp.cpp) uses — no hand-rolled byte shuffling.
static void appendCrcTrailer(uint64_t key, minx::Bytes& body) {
  minx::Bytes keyScratch;
  keyScratch.resize(8);
  minx::Buffer kb(keyScratch);
  kb.put<uint64_t>(key);
  uint32_t acc = ::crc32c_value(
    reinterpret_cast<const uint8_t*>(keyScratch.data()), 8);
  if (!body.empty())
    acc = ::crc32c_extend(
      acc, reinterpret_cast<const uint8_t*>(body.data()), body.size());
  const size_t oldSize = body.size();
  body.resize(oldSize + 4);
  minx::Buffer tail(body);
  tail.setWritePos(oldSize);
  tail.put<uint32_t>(acc);
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
  TestListener listener;
  Rudp r(&listener, cfg);
  BOOST_TEST(r.peerCount() == 0u);
}

// ---------------------------------------------------------------------------
// 3. Handshake happy path: alice OPENs, bob ACCEPTs, both ESTABLISHED
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpHandshakeHappyPath) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xA11CE;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB0B;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9000), bA = makeAddr(9001);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;

  // Adopt + push: app constructs a handler, registers it on (peer,
  // cid), then queues a message. The push triggers OPEN_SENT and
  // holds the message until the handshake completes.
  auto aliceH = aliceL.registerChannel(alice, bA, /*channel=*/42);
  BOOST_REQUIRE(aliceH);
  BOOST_TEST(aliceH->opened); // onOpened fires on registration
  BOOST_TEST(aliceL.push(alice, bA,/*channel=*/42, B("hello"), /*reliable=*/true));
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

  // Bob's onAccept auto-created a handler; check it received the
  // message reliably.
  auto bobH = bobL.handler(aA, 42);
  BOOST_REQUIRE(bobH);
  BOOST_TEST(bobH->established);
  BOOST_REQUIRE(bobH->reliableMessages.size() >= 1u);
  BOOST_TEST(std::string(bobH->reliableMessages[0].begin(),
                         bobH->reliableMessages[0].end()) == "hello");
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x222;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9100), bA = makeAddr(9101);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  aliceL.push(alice, bA,1, B("ping"), true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x444;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9200), bA = makeAddr(9201);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  aliceL.push(alice, bA,1, B("nope"), true);

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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBBB;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9300), bA = makeAddr(9301);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  aliceL.push(alice, bA,7, B("payload-zero"), true);
  alice.tick(now);
  wire.deliverAll(); // OPEN -> bob
  wire.deliverAll(); // ACCEPT -> alice
  alice.tick(now);   // alice flushes the queued message
  wire.deliverAll(); // CHANNEL -> bob

  BOOST_REQUIRE_EQUAL(bobL.received.size(), 1u);
  BOOST_TEST(bobL.received[0].channelId == 7u);
  BOOST_TEST(bobL.received[0].reliable == true);
  BOOST_TEST(std::string(bobL.received[0].data.begin(),
                         bobL.received[0].data.end()) == "payload-zero");
}

// ---------------------------------------------------------------------------
// 7. Cumulative ack advances correctly under in-order delivery
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpCumulativeAck) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xCCC;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xDDD;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9400), bA = makeAddr(9401);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  for (int i = 0; i < 5; ++i) {
    aliceL.push(alice, bA,1, Bn(static_cast<uint8_t>('A' + i), 10), true);
  }
  alice.tick(now);
  wire.deliverAll(); // OPEN -> bob
  wire.deliverAll(); // ACCEPT -> alice
  alice.tick(now);
  wire.deliverAll(); // CHANNEL packet with 5 messages -> bob
  // Bob should now have received all 5 in order.
  BOOST_REQUIRE_EQUAL(bobL.received.size(), 5u);
  for (int i = 0; i < 5; ++i) {
    BOOST_TEST(bobL.received[i].data.size() == 10u);
    BOOST_TEST(static_cast<uint8_t>(bobL.received[i].data[0]) ==
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xFFF;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9500), bA = makeAddr(9501);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;

  // Establish channel first (no message loss).
  aliceL.push(alice, bA,1, B("init"), true);
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
  bobL.clearMessages();

  // Now push 4 messages and verify they all arrive even after we
  // drop alice's first attempt. Each push happens BEFORE the next
  // flush so they ride in the same packet.
  aliceL.push(alice, bA,1, B("one"), true);
  aliceL.push(alice, bA,1, B("two"), true);
  aliceL.push(alice, bA,1, B("three"), true);
  aliceL.push(alice, bA,1, B("four"), true);

  // Drop the first packet alice emits.
  wire.dropNextAtoB = 1;
  alice.tick(now);
  wire.deliverAll();

  BOOST_TEST(bobL.received.size() == 0u); // everything dropped

  // Advance time and let alice retransmit. With our every-flush retransmit
  // model, even one more flush should re-send everything in sendBuf.
  now += 100'000;
  alice.tick(now);
  wire.deliverAll();
  // bob now has all four, in order.
  BOOST_REQUIRE_EQUAL(bobL.received.size(), 4u);
  BOOST_TEST(std::string(bobL.received[0].data.begin(),
                         bobL.received[0].data.end()) == "one");
  BOOST_TEST(std::string(bobL.received[1].data.begin(),
                         bobL.received[1].data.end()) == "two");
  BOOST_TEST(std::string(bobL.received[2].data.begin(),
                         bobL.received[2].data.end()) == "three");
  BOOST_TEST(std::string(bobL.received[3].data.begin(),
                         bobL.received[3].data.end()) == "four");
}

// ---------------------------------------------------------------------------
// 9. Unreliable tail: send + receive
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpUnreliableTail) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x1A1;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x2B2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9600), bA = makeAddr(9601);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  // Establish channel via a reliable push, drain everything.
  aliceL.push(alice, bA,9, B("init"), true);
  alice.tick(now);
  wire.deliverAll();
  wire.deliverAll();
  alice.tick(now);
  wire.deliverAll();
  bob.tick(now);
  wire.deliverAll();
  alice.tick(now);
  wire.deliverAll();
  bobL.clearMessages();

  // Push an unreliable blob. Should get delivered as the unreliable tail
  // of the next CHANNEL packet alice sends.
  aliceL.push(alice, bA,9, B("game-state-snapshot"), false);
  alice.tick(now);
  wire.deliverAll();

  // Find the unreliable delivery in bob's recv list.
  bool foundUnreliable = false;
  for (auto& r : bobL.received) {
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x888;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9700), bA = makeAddr(9701);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Allocate channels 1, 2, 3 — should all succeed.
  BOOST_TEST(aliceL.push(alice, bA,1, B("a"), true));
  BOOST_TEST(aliceL.push(alice, bA,2, B("b"), true));
  BOOST_TEST(aliceL.push(alice, bA,3, B("c"), true));
  // Channel 4 should be rejected.
  BOOST_TEST(!aliceL.push(alice, bA,4, B("d"), true));
  BOOST_TEST(alice.channelCount(bA) == 3u);
}

// ---------------------------------------------------------------------------
// 11. Oversize message rejected
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpOversizeRejected) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x77;
  TestListener listener;
  Rudp r(&listener, cfg);
  SockAddr peer = makeAddr(9800);
  Bytes huge = Bn(0xAB, Rudp::MAX_MESSAGE_SIZE + 1);
  BOOST_TEST(!listener.push(r, peer, 1, huge, true));
  Bytes max_ok = Bn(0xAB, Rudp::MAX_MESSAGE_SIZE);
  BOOST_TEST(listener.push(r, peer, 1, max_ok, true));
}

// ---------------------------------------------------------------------------
// 12. Channel inactivity GC removes idle channels
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpChannelInactivityGC) {
  minx::RudpConfig cfg;
  cfg.channelInactivityTimeout = std::chrono::milliseconds(100);
  cfg.rngSeed = 0xDEC0;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xDED0;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9900), bA = makeAddr(9901);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  aliceL.push(alice, bA,1, B("hi"), true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC106E;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9910), bA = makeAddr(9911);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,7, B("hello"), true);
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_REQUIRE(alice.isEstablished(bA, 7));
  BOOST_REQUIRE(bob.isEstablished(aA, 7));
  BOOST_REQUIRE_EQUAL(alice.channelCount(bA), 1u);
  BOOST_REQUIRE_EQUAL(bob.channelCount(aA), 1u);

  // close() on a non-existent channel is a no-op — no packet emitted.
  BOOST_REQUIRE_EQUAL(wire.pending(), 0u);
  alice.closeChannel(bA, 999);
  BOOST_TEST(alice.channelCount(bA) == 1u);
  BOOST_TEST(wire.pending() == 0u);

  // Close the real channel. State is gone from alice immediately,
  // AND the peer entry is pruned because it had no other channels.
  alice.closeChannel(bA, 7);
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
  alice.closeChannel(bA, 7);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC105B;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9930), bA = makeAddr(9931);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,3, B("hi"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 3));
  BOOST_REQUIRE(bob.isEstablished(aA, 3));

  // Install destroyed hooks on both sides to observe the teardown.
  size_t aliceDestroyed = 0, bobDestroyed = 0;
  aliceL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == bA && c == 3) ++aliceDestroyed;
  };
  bobL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == aA && c == 3) ++bobDestroyed;
  };

  // alice.closeChannel() fires alice's destroyed synchronously and queues one
  // HS_CLOSE on the wire. bob hasn't been notified yet.
  alice.closeChannel(bA, 3);
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
  bobL.push(bob, aA,3, B("still there?"), true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC106B;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9940), bA = makeAddr(9941);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Push creates a channel in IDLE and queues an OPEN on first tick.
  aliceL.push(alice, bA,5, B("hi"), true);
  alice.tick(1000);
  BOOST_REQUIRE_EQUAL(wire.pending(), 1u); // the OPEN
  wire.clearQueue();
  BOOST_REQUIRE(!alice.isEstablished(bA, 5));

  // Close while in OPEN_SENT. No HS_CLOSE emitted.
  alice.closeChannel(bA, 5);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC107B;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9950), bA = makeAddr(9951);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,11, B("x"), true);
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
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, fake);

  size_t bobDestroyed = 0;
  bobL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == aA && c == 11) ++bobDestroyed;
  };

  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, fake, now);

  // The forged close was dropped; bob is still established.
  BOOST_TEST(bob.isEstablished(aA, 11));
  BOOST_TEST(bobDestroyed == 0u);

  // The legitimate close still works.
  alice.closeChannel(bA, 11);
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
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9960);

  // Forge an HS_CLOSE for a channel bob has never heard of.
  Bytes fake;
  fake.resize(4 + 1 + 8);
  minx::Buffer fbuf(fake);
  fbuf.put<uint32_t>(42);
  fbuf.put<uint8_t>(static_cast<uint8_t>(Rudp::HS_CLOSE));
  fbuf.put<uint64_t>(0x1234567890ABCDEFULL);
  fake.resize(fbuf.getSize());
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, fake);

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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x6C6D;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9920), bA = makeAddr(9921);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Channel 1 — established at t = 1000.
  uint64_t now = 1000;
  aliceL.push(alice, bA,1, B("one"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  // Channel 2 — established at t = 3000.
  now = 3000;
  aliceL.push(alice, bA,2, B("two"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 2));

  // Channel 3 — established at t = 5000.
  now = 5000;
  aliceL.push(alice, bA,3, B("three"), true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xD1A2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(9930), bA = makeAddr(9931);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  size_t aliceDrains = 0;
  size_t bobDrains = 0;

  // Drain hooks track per-(peer, cid) writable events. The TestListener
  // is installed at construction, so there's no race here.
  aliceL.writableHook = [&](const SockAddr& p, uint32_t c) {
    if (p == bA && c == 1) ++aliceDrains;
  };
  bobL.writableHook = [&](const SockAddr& p, uint32_t c) {
    if (p == aA && c == 1) ++bobDrains;
  };

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,1, B("hello"), true));

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
  BOOST_REQUIRE(bobL.push(bob, aA,1, B("world"), true));
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
  // The new model fires onClosed only for channels that became visible
  // to the listener — i.e. channels created by push() or admitted by
  // onAccept(true). We seed each sub-test with push() so the channel
  // is visible before the destruction path under test fires.

  // (a) closeChannel()
  {
    minx::RudpConfig cfg;
    cfg.baseTickInterval = std::chrono::microseconds::zero();
    cfg.rngSeed = 0xDE51;
    TestListener listener;
    Rudp r(&listener, cfg);
    SockAddr p = makeAddr(40000);
    auto h = listener.registerChannel(r, p, 1);
    BOOST_REQUIRE(h);
    BOOST_TEST(listener.closedCount() == 0u);
    r.closeChannel(p, 1);
    BOOST_TEST(listener.closedCount() == 1u);
    BOOST_TEST(h->closed);
    BOOST_TEST(static_cast<int>(h->closedReason.value()) ==
               static_cast<int>(Rudp::CloseReason::APPLICATION));
    // Second close is a no-op.
    r.closeChannel(p, 1);
    BOOST_TEST(listener.closedCount() == 1u);
  }

  // (b) gc()
  {
    minx::RudpConfig cfg;
    cfg.baseTickInterval = std::chrono::microseconds::zero();
    cfg.rngSeed = 0xDE52a;
    TestListener aliceL;
    Rudp alice(&aliceL, cfg);
    cfg.rngSeed = 0xDE52b;
    TestListener bobL;
    Rudp bob(&bobL, cfg);

    SockAddr aA = makeAddr(40001), bA = makeAddr(40010);
    FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

    uint64_t now = 1000;
    auto aliceH = aliceL.registerChannel(alice, bA, 1);
    aliceL.push(alice, bA,1, B("seed"), true);
    alice.tick(now);
    wire.deliverAll(now);
    BOOST_REQUIRE(alice.isEstablished(bA, 1));

    // Established channel: lastActivity stops bumping after the
    // ack settles. Advance time and call gc with a tight threshold.
    now += 10'000;
    alice.tick(now);
    BOOST_TEST(alice.gc(std::chrono::microseconds(1)) == 1u);
    BOOST_REQUIRE_EQUAL(aliceL.closedCount(), 1u);
    BOOST_TEST(static_cast<int>(aliceH->closedReason.value()) ==
               static_cast<int>(Rudp::CloseReason::IDLE));
  }

  // (c) doPulseWork idle-timeout sweep
  {
    minx::RudpConfig cfg;
    cfg.channelInactivityTimeout = std::chrono::milliseconds(10);
    cfg.rngSeed = 0xDE53;
    TestListener aliceL;
    Rudp alice(&aliceL, cfg);
    cfg.rngSeed = 0xDE54;
    TestListener bobL;
    Rudp bob(&bobL, cfg);

    SockAddr aA = makeAddr(40002), bA = makeAddr(40003);
    FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

    uint64_t now = 1000;
    auto aliceH = aliceL.registerChannel(alice, bA, 1);
    aliceL.push(alice, bA,1, B("hi"), true);
    alice.tick(now);
    wire.deliverAll(now);
    BOOST_REQUIRE(alice.isEstablished(bA, 1));
    BOOST_TEST(aliceL.closedCount() == 0u);

    // Jump time past the idle timeout AND past the next pulse
    // deadline so that tick() runs doPulseWork (which is what
    // actually sweeps idle channels). Default baseTickInterval is
    // 100 ms, so advance at least that far.
    now += 150'000;
    alice.tick(now);
    BOOST_REQUIRE_EQUAL(aliceL.closedCount(), 1u);
    BOOST_TEST(static_cast<int>(aliceH->closedReason.value()) ==
               static_cast<int>(Rudp::CloseReason::IDLE));
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xCA92;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40100), bA = makeAddr(40101);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Push 3 reliable messages BEFORE ticking alice (so the handshake
  // hasn't started yet — first push moves us to OPEN_SENT but the
  // handshake doesn't complete until deliverAll runs). All three
  // land in the pre-established queue.
  BOOST_TEST(aliceL.push(alice, bA,1, B("m0"), true) == true);
  BOOST_TEST(aliceL.push(alice, bA,1, B("m1"), true) == true);
  BOOST_TEST(aliceL.push(alice, bA,1, B("m2"), true) == true);

  // The 4th push must be rejected — queue is at cap.
  BOOST_TEST(aliceL.push(alice, bA,1, B("m3"), true) == false);

  // Now complete the handshake and deliver. Only the 3 accepted
  // messages should reach bob; the rejected one is NOT silently
  // dropped inside RUDP because we refused it at push time.
  uint64_t now = 1000;
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_TEST(bobL.received.size() == 3u);
  if (bobL.received.size() == 3u) {
    BOOST_TEST(bobL.received[0].data == B("m0"));
    BOOST_TEST(bobL.received[1].data == B("m1"));
    BOOST_TEST(bobL.received[2].data == B("m2"));
  }
}

// ---------------------------------------------------------------------------
// 12g. Opened callback fires on basic happy-path handshake for both sides.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpOpenedFiresOnHappyPath) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0x0FED0A;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x0FED0B;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40200), bA = makeAddr(40201);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Listener captures opens automatically; no extra hook needed.
  BOOST_TEST(aliceL.establishedCount() == 0u);
  BOOST_TEST(bobL.establishedCount() == 0u);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,5, B("hi"), true));
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_REQUIRE(alice.isEstablished(bA, 5));
  BOOST_REQUIRE(bob.isEstablished(aA, 5));

  // Exactly one handler per side has established for (bA,5) / (aA,5).
  BOOST_REQUIRE_EQUAL(aliceL.establishedCount(), 1u);
  BOOST_REQUIRE_EQUAL(bobL.establishedCount(), 1u);
  BOOST_REQUIRE(aliceL.handler(bA, 5));
  BOOST_TEST(aliceL.handler(bA, 5)->established);
  BOOST_REQUIRE(bobL.handler(aA, 5));
  BOOST_TEST(bobL.handler(aA, 5)->established);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xADAD2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40210), bA = makeAddr(40211);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  bobL.acceptPredicate = [](const SockAddr&, uint32_t) { return false; };
  // Tests inspect bobL.acceptCalls.size() / opens.size() / closes.size().

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,7, B("reject me"), true));
  alice.tick(now);
  wire.deliverAll(now);

  // Bob saw the OPEN, ran the predicate (=>false), erased the channel.
  BOOST_TEST(bobL.acceptCalls.size() >= 1u); // could be >1 due to alice retries
  BOOST_TEST(bobL.establishedCount() == 0u);
  BOOST_TEST(bob.channelCount(aA) == 0u);
  BOOST_TEST(bob.peerCount() == 0u);
  // Closed invariant: a channel rejected by onAccept never became
  // visible to the listener and so produces NO onClosed event.
  BOOST_TEST(bobL.closedCount() == 0u);
}

// ---------------------------------------------------------------------------
// 12i. Accept predicate returning true allows the handshake. Verifies the
// predicate fires exactly once AND that Opened fires afterward.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpAcceptAllowsAndOpens) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xACC01;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xACC02;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40220), bA = makeAddr(40221);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Order of events we want to verify:
  //   1. Bob's Accept predicate fires once with (aA, 9).
  //   2. Bob's Opened fires once with (aA, 9), AFTER accept.
  // We record each event with a sequence number and assert ordering.
  std::vector<std::string> events;
  bobL.acceptPredicate = [&](const SockAddr&, uint32_t cid) {
    events.push_back("accept:" + std::to_string(cid));
    return true;
  };
  bobL.openedHook = [&](const SockAddr&, uint32_t cid) {
    events.push_back("opened:" + std::to_string(cid));
  };

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,9, B("pls"), true));
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBABE2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40230), bA = makeAddr(40231);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Establish a channel naturally first.
  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,3, B("first"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 3));

  // Register bob's hooks AFTER the first handshake so we only see
  // events from the restart onward.
  std::vector<std::string> events;
  bobL.acceptPredicate = [&](const SockAddr&, uint32_t cid) {
    events.push_back("accept:" + std::to_string(cid));
    return true;
  };
  bobL.openedHook = [&](const SockAddr&, uint32_t cid) {
    events.push_back("opened:" + std::to_string(cid));
  };
  bobL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == aA && c == 3) events.push_back("destroyed");
  };

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
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, body);

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
  // ConstBuffer reads in BE the same way Buffer writes in BE.
  minx::ConstBuffer rb(b);
  return rb.get<uint32_t>();
}

// Forge a CHANNEL packet body (the bytes onPacket receives — i.e. AFTER
// the 8-byte stdext routing key has been stripped). Wire layout matches
// the wire-side emitChannel in src/rudp.cpp exactly. All BE work goes
// through minx::Buffer.
static minx::Bytes forgeChannelBody(
  uint32_t channel_id, uint64_t session_token, uint32_t solid_ack,
  uint32_t porosity,
  const std::vector<std::pair<uint32_t, minx::Bytes>>& reliable_msgs) {
  minx::Bytes out;
  out.resize(out.max_size());
  minx::Buffer buf(out);
  buf.put<uint32_t>(channel_id);
  buf.put<uint64_t>(session_token);
  buf.put<uint32_t>(solid_ack);
  buf.put<uint32_t>(porosity);
  buf.put<uint8_t>(static_cast<uint8_t>(reliable_msgs.size()));
  for (auto& [id, body] : reliable_msgs) {
    buf.put<uint32_t>(id);
    buf.put<uint16_t>(static_cast<uint16_t>(body.size()));
    buf.put(std::span<const char>{body.data(), body.size()});
  }
  out.resize(buf.getSize());
  appendCrcTrailer(minx::Rudp::KEY_V0_CHANNEL, out);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xCAFE;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11000), bA = makeAddr(11001);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  const size_t N = 1000;

  // Each message is a 16-byte payload encoding its sequence index in
  // the first 4 bytes via makeIndexedPayload (defined in the namespace
  // above for sharing with the wide-gap stress test).

  // Push all N messages onto alice. Channel state is created on the
  // first push and the handshake is queued for the next flush.
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE(aliceL.push(alice, bA,/*channel=*/42,
                             makeIndexedPayload(static_cast<uint32_t>(i)),
                             /*reliable=*/true));
  }

  // Drive the protocol until convergence: bob has received all N
  // messages AND alice's sendBuf is fully drained.
  uint64_t now = 0;
  const int MAX_STEPS = 1000; // generous upper bound; expected ~30
  int steps = 0;
  while (steps < MAX_STEPS && bobL.received.size() < N) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
    ++steps;
  }

  // Convergence reached.
  BOOST_TEST_MESSAGE("bulk reliable converged in " << steps << " steps");
  BOOST_REQUIRE_EQUAL(bobL.received.size(), N);

  // Verify strict in-order delivery: index in each received payload
  // must equal its position in the receive list.
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE_EQUAL(bobL.received[i].channelId, 42u);
    BOOST_REQUIRE(bobL.received[i].reliable);
    BOOST_REQUIRE_EQUAL(bobL.received[i].data.size(), 16u);
    const uint32_t got = extractPayloadIndex(bobL.received[i].data);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBEEFEE;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11100), bA = makeAddr(11101);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 42;

  // Step 1: real handshake via a normal init message. After convergence,
  // bob's solidAck = 1 (init was msg 1) and we know the session_token.
  BOOST_REQUIRE(aliceL.push(alice, bA,channel, B("init"), true));
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
  BOOST_REQUIRE_EQUAL(bobL.received.size(), 1u);
  bobL.clearMessages();

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
  BOOST_REQUIRE_EQUAL(bobL.received.size(), 0u);

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
  BOOST_REQUIRE_EQUAL(bobL.received.size(), 99u);
  for (size_t i = 0; i < 99; ++i) {
    const uint32_t expected = static_cast<uint32_t>(i + 2);
    BOOST_REQUIRE_EQUAL(bobL.received[i].channelId, channel);
    BOOST_REQUIRE(bobL.received[i].reliable);
    BOOST_REQUIRE_EQUAL(bobL.received[i].data.size(), 16u);
    const uint32_t got = extractPayloadIndex(bobL.received[i].data);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBEEF1;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11200), bA = makeAddr(11201);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 99;

  // Establish the channel via a normal init message.
  BOOST_REQUIRE(aliceL.push(alice, bA,channel, B("init"), true));
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
  BOOST_REQUIRE_EQUAL(bobL.received.size(), 1u);
  bobL.clearMessages();

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
  BOOST_TEST(bobL.received.size() == 0u);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xDE57;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11250), bA = makeAddr(11251);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 77;

  // Establish the channel via a normal init message.
  BOOST_REQUIRE(aliceL.push(alice, bA,channel, B("init"), true));
  for (int i = 0; i < 10 && !alice.isEstablished(bA, channel); ++i) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
  }
  BOOST_REQUIRE(bob.isEstablished(aA, channel));

  // Register destroyed hook AFTER handshake so we only count the
  // breach event.
  size_t destroyed = 0;
  bobL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == aA && c == channel) ++destroyed;
  };

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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xFADE2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11300), bA = makeAddr(11301);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 0;
  const uint32_t channel = 7;

  // Establish via init.
  BOOST_REQUIRE(aliceL.push(alice, bA,channel, B("init"), true));
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
  bobL.clearMessages();

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
  BOOST_TEST(bobL.received.size() == 0u);

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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xF00D;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(11400), bA = makeAddr(11401);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Drop every 3rd a→b packet (data direction). Acks (b→a) flow freely.
  // This isolates the test to the retransmit path on the data side.
  wire.dropEveryNthAtoB = 3;

  const size_t N = 1000;
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE(aliceL.push(alice, bA,/*channel=*/42,
                             makeIndexedPayload(static_cast<uint32_t>(i)),
                             /*reliable=*/true));
  }

  uint64_t now = 0;
  const int MAX_STEPS = 1000; // generous; expected on the order of 50-80
  int steps = 0;
  while (steps < MAX_STEPS && bobL.received.size() < N) {
    alice.tick(now);
    bob.tick(now);
    wire.deliverAll();
    now += 1000;
    ++steps;
  }

  BOOST_TEST_MESSAGE("bulk + 33% a→b loss converged in " << steps << " steps");
  BOOST_REQUIRE_EQUAL(bobL.received.size(), N);

  // Strict in-order delivery: the index encoded in each payload must
  // equal the position in the receive list.
  for (size_t i = 0; i < N; ++i) {
    BOOST_REQUIRE_EQUAL(bobL.received[i].channelId, 42u);
    BOOST_REQUIRE(bobL.received[i].reliable);
    BOOST_REQUIRE_EQUAL(bobL.received[i].data.size(), 16u);
    const uint32_t got = extractPayloadIndex(bobL.received[i].data);
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
  TestListener aliceL;
  Rudp alice(&aliceL, aliceCfg);

  minx::RudpConfig bobCfg;
  bobCfg.baseTickInterval = std::chrono::microseconds::zero();
  bobCfg.rngSeed = 0xB0C2;
  bobCfg.perChannelBytesPerSecond = 1'000'000; // generous local config
  bobCfg.perChannelBurstBytes = 1'000'000;     // the large side
  TestListener bobL;
  Rudp bob(&bobL, bobCfg);

  SockAddr aA = makeAddr(10000), bA = makeAddr(10001);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Establish a channel. The handshake OPEN/ACCEPT carries each side's
  // advertised params; both sides freeze their effective bucket at
  // handshake completion.
  uint64_t now = 1000;
  aliceL.push(alice, bA,1, B("warmup"), true);
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
    bobL.push(bob, aA,1, big, true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB0C4;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(10010), bA = makeAddr(10011);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,1, B("warmup"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  // Push a lot of data into alice's sendBuf.
  Bytes big = Bn('A', Rudp::MAX_MESSAGE_SIZE);
  for (int i = 0; i < 30; ++i) {
    aliceL.push(alice, bA,1, big, true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xB0C8;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(10030), bA = makeAddr(10031);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,1, B("warmup"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 1));

  // Push way more than any finite burst would allow, at time=now+1us
  // so a finite rate couldn't have refilled.
  Bytes big = Bn('X', Rudp::MAX_MESSAGE_SIZE);
  for (int i = 0; i < 50; ++i) {
    aliceL.push(alice, bA,1, big, true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0x51A2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(10100), bA = makeAddr(10101);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Both sides push before the other's OPEN arrives. tick() on each
  // emits HS_OPEN; they race through the queue.
  aliceL.push(alice, bA,77, B("from-alice"), true);
  bobL.push(bob, aA,77, B("from-bob"), true);
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
  BOOST_TEST(!aliceL.received.empty());
  BOOST_TEST(!bobL.received.empty());
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
  TestListener listener;
  Rudp r(&listener, cfg);

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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBEA4;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(10210), bA = makeAddr(10211);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Establish the channel and drain the warmup traffic by running a
  // few tick/deliver cycles with time advancing well past the 10ms
  // interval. After this loop alice.sendBuf and the wire are both
  // empty and both sides have up-to-date deadlines.
  uint64_t now = 1'000'000;
  aliceL.push(alice, bA,1, B("warmup"), true);
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
    aliceL.push(alice, bA,1, big, true);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xEDC2;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(10300), bA = makeAddr(10301);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,2, B("x"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 2));
  BOOST_REQUIRE(bob.isEstablished(aA, 2));

  size_t aliceDestroyed = 0, bobDestroyed = 0;
  aliceL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == bA && c == 2) ++aliceDestroyed;
  };
  bobL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == aA && c == 2) ++bobDestroyed;
  };

  // Both close BEFORE delivering either HS_CLOSE — each HS_CLOSE is
  // queued on the wire with the other side still live.
  alice.closeChannel(bA, 2);
  bob.closeChannel(aA, 2);
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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xEDC4;
  TestListener bobL;
  std::unique_ptr<Rudp> bob(new Rudp(&bobL, cfg));

  SockAddr aA = makeAddr(10310), bA = makeAddr(10311);
  FakeWire wire(alice, aliceL, *bob, bobL, aA, bA);

  uint64_t now = 1000;
  aliceL.push(alice, bA,3, B("hi"), true);
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 3));
  const uint64_t oldToken = alice.sessionToken(bA, 3);
  BOOST_REQUIRE(oldToken != 0u);

  // Simulate peer restart: drop the old bob and construct a fresh one
  // with different RNG (so new nonce, new token). Rewire.
  bob.reset();
  cfg.rngSeed = 0xEDC5;
  TestListener bobL2;
  bob.reset(new Rudp(&bobL2, cfg));
  FakeWire wire2(alice, aliceL, *bob, bobL2, aA, bA);

  // Fresh bob pushes → emits a new HS_OPEN with a new nonce.
  bobL2.push(*bob, aA, 3, B("reborn"), true);
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
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, stale);

  size_t aliceDestroyed = 0;
  aliceL.closedHook = [&](const SockAddr& p, uint32_t c, Rudp::CloseReason) {
    if (p == bA && c == 3) ++aliceDestroyed;
  };

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
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xEDC7;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(10320), bA = makeAddr(10321);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Establish the channel with a trivial warm-up that gets acked.
  uint64_t now = 1000;
  aliceL.push(alice, bA,1, B("warmup"), true);
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
  BOOST_TEST(aliceL.push(alice, bA,1, B("m0"), true) == true);
  BOOST_TEST(aliceL.push(alice, bA,1, B("m1"), true) == true);
  BOOST_TEST(aliceL.push(alice, bA,1, B("m2"), true) == true);
  // Fourth push is rejected — sendBuf is full on an ESTABLISHED
  // channel. Not a preEstablishedQueue path: the channel is live.
  BOOST_TEST(aliceL.push(alice, bA,1, B("m3"), true) == false);
}

// ---------------------------------------------------------------------------
// Per-channel ChannelMetrics: bytesSent / bytesReceived / openedAtUs / null
// ---------------------------------------------------------------------------
//
// metricsFor() returns null for unknown (peer, channel_id). After a
// handshake, both peers' metrics show non-zero bytesSent and bytesReceived
// for handshake bytes, and openedAtUs equals the now_us at promote time.
// After a reliable round-trip, byte counters grow further.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpMetricsBytesAndOpenedAt) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE71;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE72;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40500), bA = makeAddr(40501);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // Unknown channel before any push: nullopt.
  BOOST_TEST(!alice.metricsFor(bA, 4).has_value());
  BOOST_TEST(!bob.metricsFor(aA, 4).has_value());

  uint64_t now = 1234567;
  BOOST_REQUIRE(aliceL.push(alice, bA,4, B("hello-bob"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 4));
  BOOST_REQUIRE(bob.isEstablished(aA, 4));

  auto am = alice.metricsFor(bA, 4);
  auto bm = bob.metricsFor(aA, 4);
  BOOST_REQUIRE(am.has_value());
  BOOST_REQUIRE(bm.has_value());

  // openedAtUs is exactly the now_us we drove the handshake under.
  BOOST_TEST(am->openedAtUs == now);
  BOOST_TEST(bm->openedAtUs == now);

  // Both sides put bytes on the wire (alice: OPEN + first CHANNEL packet;
  // bob: ACCEPT + first CHANNEL packet w/ ack).
  BOOST_TEST(am->bytesSent > 0u);
  BOOST_TEST(am->bytesReceived > 0u);
  BOOST_TEST(bm->bytesSent > 0u);
  BOOST_TEST(bm->bytesReceived > 0u);

  // Symmetry: alice's "sent" equals what bob counted as "received" plus
  // any in-flight packets — but in the steady state after deliverAll,
  // every emitted packet has been delivered to the other side. So:
  // alice.bytesSent == bob.bytesReceived (and vice versa).
  BOOST_TEST(am->bytesSent == bm->bytesReceived);
  BOOST_TEST(bm->bytesSent == am->bytesReceived);

  // Now push a second message and verify counters grow monotonically.
  const uint64_t sentBefore = am->bytesSent;
  BOOST_REQUIRE(aliceL.push(alice, bA,4, B("again"), true));
  alice.tick(now);
  wire.deliverAll(now);
  auto am2 = alice.metricsFor(bA, 4);
  BOOST_REQUIRE(am2.has_value());
  BOOST_TEST(am2->bytesSent > sentBefore);
}

// ---------------------------------------------------------------------------
// memoryByteSeconds grows when buffers are non-empty across pulses.
// We construct a tightly controlled scenario:
//   1. Establish a channel and drain to empty buffers.
//   2. Stop wire delivery so any push() into sendBuf stays there.
//   3. Push exactly one MSG_BYTES-byte message at t = T0 (sendBuf
//      now holds MSG_BYTES bytes).
//   4. Advance time to T0 + DURATION_S seconds via tick().
//   5. Expected delta = MSG_BYTES * DURATION_S byte-seconds, exactly.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpMetricsMemoryIntegral) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE73;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE74;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40510), bA = makeAddr(40511);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1'000'000;
  BOOST_REQUIRE(aliceL.push(alice, bA,9, B("x"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(alice.isEstablished(bA, 9));

  // Drain to empty buffers, then advance the integral clock to
  // currentTimeUs_ via a tick(). After this, alice's channel has
  // empty sendBuf / reorder / preEstablished / pendingUnreliable.
  alice.tick(now);
  auto am0 = alice.metricsFor(bA, 9);
  BOOST_REQUIRE(am0.has_value());
  const uint64_t baseline = am0->memoryByteSeconds;

  // Stop delivery: any push() from here goes into sendBuf and stays.
  wire.dropEveryNthAtoB = 1;

  // Push exactly MSG_BYTES bytes at time `now`, then advance time
  // by exactly DURATION_S seconds. The integral over that window
  // should equal MSG_BYTES * DURATION_S.
  static constexpr size_t MSG_BYTES = 100;
  static constexpr uint64_t DURATION_S = 5;

  BOOST_REQUIRE(aliceL.push(alice, bA,9, Bn('Q', MSG_BYTES), true));
  // Force an immediate pulse so sendBuf actually contains the
  // message before our timing window starts.
  alice.tick(now);
  wire.clearQueue();
  const uint64_t startTime = now;

  now = startTime + DURATION_S * 1'000'000ULL;
  alice.tick(now);
  wire.clearQueue();

  auto am1 = alice.metricsFor(bA, 9);
  BOOST_REQUIRE(am1.has_value());
  const uint64_t delta = am1->memoryByteSeconds - baseline;
  // Exact match: 100 bytes * 5 s = 500 byte-seconds.
  BOOST_TEST(delta == MSG_BYTES * DURATION_S);
}

// ---------------------------------------------------------------------------
// ChannelLifecycleHook fires opened=true on ESTABLISHED and opened=false
// on subsequent destroy. Pairing invariant: rejected accept produces
// neither event.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpLifecycleHookOpenAndClose) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE75;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE76;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40520), bA = makeAddr(40521);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  auto aliceH = aliceL.registerChannel(alice, bA, 11);
  BOOST_REQUIRE(aliceL.push(alice, bA,11, B("hi"), true));
  alice.tick(now);
  wire.deliverAll(now);

  BOOST_REQUIRE_EQUAL(aliceL.establishedCount(), 1u);
  BOOST_REQUIRE_EQUAL(bobL.establishedCount(), 1u);
  BOOST_TEST(aliceH->established);
  auto bobH = bobL.handler(aA, 11);
  BOOST_REQUIRE(bobH);
  BOOST_TEST(bobH->established);

  // Close from alice. onClosed should fire on alice immediately
  // (reason APPLICATION) and on bob once HS_CLOSE has been delivered
  // (reason PEER_CLOSED).
  alice.closeChannel(bA, 11);
  BOOST_REQUIRE_EQUAL(aliceL.closedCount(), 1u);
  BOOST_TEST(aliceH->closed);
  BOOST_TEST(static_cast<int>(aliceH->closedReason.value()) ==
             static_cast<int>(Rudp::CloseReason::APPLICATION));
  wire.deliverAll(now);
  BOOST_REQUIRE_EQUAL(bobL.closedCount(), 1u);
  BOOST_TEST(static_cast<int>(bobH->closedReason.value()) ==
             static_cast<int>(Rudp::CloseReason::PEER_CLOSED));
}

BOOST_AUTO_TEST_CASE(TestRudpLifecycleHookRejectedAcceptFiresNothing) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.handshakeRetryInterval = std::chrono::microseconds(1);
  cfg.handshakeMaxRetries = 1;
  cfg.rngSeed = 0xBE77;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE78;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40530), bA = makeAddr(40531);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  bobL.acceptPredicate = [](const SockAddr&, uint32_t) { return false; };

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,13, B("nope"), true));
  alice.tick(now);
  wire.deliverAll(now);

  // Bob's accept rejected — no opens / closes on bob's side.
  BOOST_TEST(bobL.establishedCount() == 0u);
  BOOST_TEST(bobL.closedCount() == 0u);
  // Alice never got an ACCEPT, so her channel never reached
  // ESTABLISHED. After handshake exhaustion her channel is GC'd. The
  // listener invariant: a channel that was visible (push() created
  // it) but never opened still fires onClosed once destroyed.
  for (int i = 0; i < 5; ++i) {
    now += 100;
    alice.tick(now);
    wire.clearQueue();
  }
  BOOST_TEST(alice.channelCount(bA) == 0u);
  BOOST_TEST(aliceL.establishedCount() == 0u);
  BOOST_REQUIRE_EQUAL(aliceL.closedCount(), 1u);
  auto aliceHFailed = aliceL.handler(bA, 13);
  BOOST_REQUIRE(aliceHFailed);
  BOOST_TEST(static_cast<int>(aliceHFailed->closedReason.value()) ==
             static_cast<int>(Rudp::CloseReason::HANDSHAKE_FAILED));
}

// ---------------------------------------------------------------------------
// closeChannel() on one side emits HS_CLOSE; the other side's
// listener sees the close as PEER_CLOSED. The closing side's
// listener sees the reason it passed in (APPLICATION here, since
// RUDP only enumerates reasons it can itself produce — application-
// level "why" stays in the application's own bookkeeping).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpCloseChannelSymmetricCloseReasons) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE79;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE7A;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40540), bA = makeAddr(40541);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,17, B("hi"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 17));

  // Bob closes the channel. The wire carries an HS_CLOSE that tears
  // down alice's side too.
  auto bobH = bobL.handler(aA, 17);
  BOOST_REQUIRE(bobH);
  bob.closeChannel(aA, 17, minx::Rudp::CloseReason::APPLICATION);
  BOOST_TEST(bob.channelCount(aA) == 0u);
  BOOST_REQUIRE_EQUAL(bobL.closedCount(), 1u);
  BOOST_TEST(static_cast<int>(bobH->closedReason.value()) ==
             static_cast<int>(Rudp::CloseReason::APPLICATION));

  wire.deliverAll(now);
  BOOST_TEST(alice.channelCount(bA) == 0u);
  BOOST_REQUIRE_EQUAL(aliceL.closedCount(), 1u);
  auto aliceH = aliceL.handler(bA, 17);
  BOOST_REQUIRE(aliceH);
  // Alice's listener sees PEER_CLOSED — the HS_CLOSE packet is just
  // a teardown hint; bob's reason stays in bob's bookkeeping.
  BOOST_TEST(static_cast<int>(aliceH->closedReason.value()) ==
             static_cast<int>(Rudp::CloseReason::PEER_CLOSED));
}

// ---------------------------------------------------------------------------
// gc(threshold) fires the lifecycle hook with CloseReason::IDLE.
// Establish a channel, advance wall-clock past the threshold, call
// gc(threshold), and verify opened=false fired with the IDLE reason.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpLifecycleHookGcFiresIdle) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE7F;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE80;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40555), bA = makeAddr(40556);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,51, B("hi"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 51));
  BOOST_REQUIRE_EQUAL(bobL.establishedCount(), 1u);

  // Advance bob's notion of time well past any imaginable threshold,
  // then call gc() with a tight threshold so the channel is evicted.
  now += 10'000'000; // +10 s
  bob.tick(now);
  const size_t evicted = bob.gc(std::chrono::seconds(1));
  BOOST_TEST(evicted == 1u);

  BOOST_REQUIRE_EQUAL(bobL.closedCount(), 1u);
  auto bobH = bobL.handler(aA, 51);
  BOOST_REQUIRE(bobH);
  BOOST_TEST(static_cast<int>(bobH->closedReason.value()) ==
             static_cast<int>(Rudp::CloseReason::IDLE));
}

// ---------------------------------------------------------------------------
// Peer restart fires lifecycle hook as (true → false → true): the old
// session's destroy event, then the new session's open event.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpLifecycleHookPeerRestart) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE7B;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE7C;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40550), bA = makeAddr(40551);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,19, B("v1"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 19));
  BOOST_REQUIRE_EQUAL(bobL.establishedCount(), 1u);

  // Forge an HS_OPEN with a different nonce, simulating peer restart.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(19);
  fb.put<uint8_t>(Rudp::HS_OPEN);
  fb.put<uint64_t>(0xDEADBEEFDEADBEEFULL);
  fb.put<uint32_t>(0xFFFFFFFFu);
  fb.put<uint32_t>(0xFFFFFFFFu);
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, body);
  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, body, now);

  // Old session: closed with PEER_RESTART. New session: opened.
  BOOST_REQUIRE_EQUAL(bobL.closedCount(), 1u);
  BOOST_TEST(static_cast<int>(bobL.closes[0].reason) ==
             static_cast<int>(Rudp::CloseReason::PEER_RESTART));
  BOOST_REQUIRE_EQUAL(bobL.establishedCount(), 2u);
}

// ---------------------------------------------------------------------------
// Peer-restart resets per-session metrics: the new session starts with
// zeroed bytesSent/bytesReceived, a fresh openedAtUs, and a re-anchored
// memoryByteSeconds clock.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpMetricsResetOnPeerRestart) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xBE7D;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xBE7E;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40560), bA = makeAddr(40561);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 5000;
  BOOST_REQUIRE(aliceL.push(alice, bA,21, B("first session"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 21));

  // Bob sees non-zero counters for the first session.
  auto m1 = bob.metricsFor(aA, 21);
  BOOST_REQUIRE(m1.has_value());
  BOOST_TEST(m1->bytesReceived > 0u);
  BOOST_TEST(m1->bytesSent > 0u);
  BOOST_TEST(m1->openedAtUs == 5000u);

  // Forge a peer-restart OPEN at a later wall-clock.
  now = 9000;
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(21);
  fb.put<uint8_t>(Rudp::HS_OPEN);
  fb.put<uint64_t>(0xCAFEBABECAFEBABEULL);
  fb.put<uint32_t>(0xFFFFFFFFu);
  fb.put<uint32_t>(0xFFFFFFFFu);
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, body);
  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, body, now);

  auto m2 = bob.metricsFor(aA, 21);
  BOOST_REQUIRE(m2.has_value());
  // New session: openedAtUs reflects the restart time, not the original.
  BOOST_TEST(m2->openedAtUs == 9000u);
  // bytesReceived starts fresh at the bytes for this single OPEN
  // packet. We compute the expected wire size symbolically rather
  // than hard-coding so wire-format tweaks don't silently break the
  // test: HS_OPEN body = channel_id u32 + kind u8 + nonce u64 +
  // advertised_rate u32 + advertised_burst u32 = 21 bytes; plus the
  // 8-byte stdext routing key consumed by the dispatcher and the
  // 4-byte CRC32C trailer.
  static constexpr size_t HS_OPEN_BODY_SIZE = 4 + 1 + 8 + 4 + 4;
  static constexpr size_t HS_OPEN_WIRE_SIZE =
    HS_OPEN_BODY_SIZE + MinxStdExtensions::KEY_SIZE + Rudp::CRC_SIZE;
  BOOST_TEST(m2->bytesReceived == HS_OPEN_WIRE_SIZE);
  // bytesSent was reset and then bumped by the ACCEPT bob just emitted.
  BOOST_TEST(m2->bytesSent > 0u);
  BOOST_TEST(m2->bytesSent < m1->bytesSent);
}

// ---------------------------------------------------------------------------
// CRC-corrupted packets still bill the addressed channel. Closes the
// attack vector where an adversary deliberately corrupts inbound
// packets to consume bandwidth + parsing CPU without being charged.
//
// We forge a CHANNEL packet against an existing established channel
// with a valid channel_id at body[0..3] but a deliberately broken
// CRC trailer. Bob's view of the channel must still see bytesReceived
// grow by the wire size — even though the packet is dropped at CRC
// verification before any further parsing.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpMetricsCorruptPacketStillBilled) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC0DEC0;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC0DEC1;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40570), bA = makeAddr(40571);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,23, B("setup"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 23));

  auto m0 = bob.metricsFor(aA, 23);
  BOOST_REQUIRE(m0.has_value());
  const uint64_t baselineRcv = m0->bytesReceived;

  // Forge a CHANNEL-shaped body whose channel_id resolves to bob's
  // existing channel 23, but whose CRC trailer is deliberately
  // garbage. The session_token slot is left at zero — that's also
  // wrong, but the CRC check fires first and short-circuits the
  // session_token comparison.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(23);                  // channel_id (valid)
  fb.put<uint64_t>(0xDEADDEADDEADDEADULL); // session_token (wrong)
  fb.put<uint32_t>(0);                   // solid_ack
  fb.put<uint32_t>(0);                   // porosity
  fb.put<uint8_t>(0);                    // reliable_count
  fb.put<uint32_t>(0xBADBAD00u);         // bogus "CRC" trailer
  body.resize(fb.getSize());

  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, now);

  auto m1 = bob.metricsFor(aA, 23);
  BOOST_REQUIRE(m1.has_value());
  // The corrupt packet was dropped at CRC verify, but bytesReceived
  // grew by the full wire size (body + 8-byte routing key).
  const uint64_t expected = body.size() + MinxStdExtensions::KEY_SIZE;
  BOOST_TEST(m1->bytesReceived == baselineRcv + expected);
}

// ---------------------------------------------------------------------------
// Wrong-session-token packets to an existing channel are billed even
// though they are dropped before any further processing. Same attack
// vector concern as the corrupt-CRC case, but with a valid CRC and a
// forged session_token.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpMetricsWrongTokenStillBilled) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xC0DEC2;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xC0DEC3;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40580), bA = makeAddr(40581);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,25, B("setup"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 25));

  auto m0 = bob.metricsFor(aA, 25);
  BOOST_REQUIRE(m0.has_value());
  const uint64_t baselineRcv = m0->bytesReceived;

  // Forge a CHANNEL packet with valid CRC but wrong session_token.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(25);
  fb.put<uint64_t>(0x1234567812345678ULL); // wrong session_token
  fb.put<uint32_t>(0);
  fb.put<uint32_t>(0);
  fb.put<uint8_t>(0);
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_CHANNEL, body);

  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, now);

  auto m1 = bob.metricsFor(aA, 25);
  BOOST_REQUIRE(m1.has_value());
  const uint64_t expected = body.size() + MinxStdExtensions::KEY_SIZE;
  BOOST_TEST(m1->bytesReceived == baselineRcv + expected);
}

// ---------------------------------------------------------------------------
// Abuse signals — observability path with null Minx.
//
// Each of the three strong signals fires the AbuseSignalCallback when
// detected. We pass a null Minx (the default), so no real banAddress
// happens; the callback is the only side-effect we observe. This is
// the intended test pattern: tests don't mock Minx, they just leave
// it null and verify the signal via the callback.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalForgedSessionTokenChannel) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB001;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xAB002;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40600), bA = makeAddr(40601);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // bobL.abuses is automatically populated by TestListener.

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,31, B("setup"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 31));
  BOOST_TEST(bobL.abuses.size() == 0u);

  // Forge a CHANNEL packet with valid CRC but wrong session_token —
  // looks like off-path injection on a known channel.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(31);
  fb.put<uint64_t>(0x1111111111111111ULL); // wrong session_token
  fb.put<uint32_t>(0);
  fb.put<uint32_t>(0);
  fb.put<uint8_t>(0);
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_CHANNEL, body);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, now);

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(bobL.abuses[0].peer == aA);
  BOOST_TEST(bobL.abuses[0].cid == 31u);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::FORGED_SESSION_TOKEN_CHANNEL));
}

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalForgedHsClose) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB003;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xAB004;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40610), bA = makeAddr(40611);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // bobL.abuses is automatically populated by TestListener.

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,33, B("setup"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 33));
  BOOST_TEST(bobL.abuses.size() == 0u);

  // Forge an HS_CLOSE with valid CRC but wrong session_token.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(33);                        // channel_id
  fb.put<uint8_t>(Rudp::HS_CLOSE);             // kind
  fb.put<uint64_t>(0x2222222222222222ULL);     // wrong session_token
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, body);
  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, body, now);

  // Channel must still be alive — forged close was rejected.
  BOOST_TEST(bob.isEstablished(aA, 33));

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(bobL.abuses[0].peer == aA);
  BOOST_TEST(bobL.abuses[0].cid == 33u);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::FORGED_SESSION_TOKEN_HS_CLOSE));
}

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalReorderCapBreach) {
  // Tighten the reorder cap to a small number so the test can trip it
  // with a handful of forged messages instead of thousands.
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.maxReorderMessagesPerChannel = 4;
  cfg.rngSeed = 0xAB005;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xAB006;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40620), bA = makeAddr(40621);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  // bobL.abuses is automatically populated by TestListener.

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,35, B("setup"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 35));
  const uint64_t aliceToBobToken = bob.sessionToken(aA, 35);

  // Forge CHANNEL packets carrying wide-gap reliable msg_ids so the
  // reorder buffer can never deliver in-order — they all sit in the
  // reorder map. msg_id 1 is needed first to release them; we send
  // ids 100..104 instead. After 5 such packets we exceed cap=4.
  for (uint32_t mid = 100; mid <= 105; ++mid) {
    minx::Bytes body;
    body.resize(body.max_size());
    minx::Buffer fb(body);
    fb.put<uint32_t>(35);                    // channel_id
    fb.put<uint64_t>(aliceToBobToken);       // valid token
    fb.put<uint32_t>(0);                     // solid_ack
    fb.put<uint32_t>(0);                     // porosity
    fb.put<uint8_t>(1);                      // reliable_count
    fb.put<uint32_t>(mid);                   // msg_id
    fb.put<uint16_t>(2);                     // len
    fb.put<uint8_t>('x');
    fb.put<uint8_t>('y');
    body.resize(fb.getSize());
    appendCrcTrailer(Rudp::KEY_V0_CHANNEL, body);
    bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, now);
    if (!bobL.abuses.empty()) break;
  }

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(bobL.abuses[0].peer == aA);
  BOOST_TEST(bobL.abuses[0].cid == 35u);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::REORDER_CAP_BREACH));
}

// ---------------------------------------------------------------------------
// Smoke test: a clean handshake + reliable round-trip produces no
// abuse signals. Guards against false positives on the happy path.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Soft abuse signals (CRC failure, stray, truncated). One-off
// occurrences are noise; sustained ones become abuse via MINX's
// spam filter. We test only that the signal fires — the filter's
// own threshold logic is tested in MINX's spam_filter tests.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalCrcFailure) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB101;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40700);
  // bobL.abuses is automatically populated by TestListener.

  // CHANNEL-shaped body with a deliberately wrong CRC trailer.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(99);                  // channel_id
  fb.put<uint64_t>(0);                   // session_token
  fb.put<uint32_t>(0);
  fb.put<uint32_t>(0);
  fb.put<uint8_t>(0);
  fb.put<uint32_t>(0xBADBAD00u);         // bogus "CRC" trailer
  body.resize(fb.getSize());

  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, /*now_us=*/1000);

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(bobL.abuses[0].peer == aA);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::CRC_FAILURE));
  // Severity classifier: this is a soft signal.
  BOOST_TEST(Rudp::isStrongAbuseSignal(bobL.abuses[0].signal) == false);
}

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalStrayHsClose) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB102;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40710);
  // bobL.abuses is automatically populated by TestListener.

  // HS_CLOSE for a channel that doesn't exist on bob's side.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(77);
  fb.put<uint8_t>(Rudp::HS_CLOSE);
  fb.put<uint64_t>(0xDEAD);
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_HANDSHAKE, body);
  bob.onPacket(aA, Rudp::KEY_V0_HANDSHAKE, body, /*now_us=*/1000);

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::STRAY_HS_CLOSE));
  BOOST_TEST(Rudp::isStrongAbuseSignal(bobL.abuses[0].signal) == false);
}

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalStrayChannelPacket) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB103;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40720);
  // bobL.abuses is automatically populated by TestListener.

  // CHANNEL packet for a channel that doesn't exist on bob's side.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(88);                  // unknown channel_id
  fb.put<uint64_t>(0);
  fb.put<uint32_t>(0);
  fb.put<uint32_t>(0);
  fb.put<uint8_t>(0);
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_CHANNEL, body);
  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, /*now_us=*/1000);

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::STRAY_CHANNEL_PACKET));
  BOOST_TEST(Rudp::isStrongAbuseSignal(bobL.abuses[0].signal) == false);
}

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalTruncatedPacket) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB104;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40730);
  // bobL.abuses is automatically populated by TestListener.

  // CHANNEL-shaped body that is shorter than CHANNEL_FIXED_HEADER (21
  // bytes) — but still long enough to pass the CRC32C trailer check.
  // Body of 8 bytes (4 garbage + 4 CRC) is the shortest packet that
  // gets a valid CRC.
  minx::Bytes body;
  body.resize(body.max_size());
  minx::Buffer fb(body);
  fb.put<uint32_t>(0xABCD0123u); // 4 bytes of "channel_id"-ish padding
  body.resize(fb.getSize());
  appendCrcTrailer(Rudp::KEY_V0_CHANNEL, body);

  bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, /*now_us=*/1000);

  BOOST_REQUIRE_EQUAL(bobL.abuses.size(), 1u);
  BOOST_TEST(static_cast<int>(bobL.abuses[0].signal) ==
             static_cast<int>(Rudp::AbuseSignal::TRUNCATED_PACKET));
  BOOST_TEST(Rudp::isStrongAbuseSignal(bobL.abuses[0].signal) == false);
}

// Sustained CRC failures from one peer fire the soft signal each
// time. The point of this test is to verify the firing rate, not the
// spam-filter threshold logic itself (which lives in MINX). With
// minx_ null, the only effect is repeated callback invocations.
BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalCrcFailureSustained) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB105;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40740);

  for (int i = 0; i < 50; ++i) {
    minx::Bytes body;
    body.resize(body.max_size());
    minx::Buffer fb(body);
    fb.put<uint32_t>(static_cast<uint32_t>(i));
    fb.put<uint64_t>(0);
    fb.put<uint32_t>(0);
    fb.put<uint32_t>(0);
    fb.put<uint8_t>(0);
    fb.put<uint32_t>(0xDEADBEEFu); // wrong CRC every time
    body.resize(fb.getSize());
    bob.onPacket(aA, Rudp::KEY_V0_CHANNEL, body, /*now_us=*/1000);
  }

  size_t crcFails = 0;
  for (auto& a : bobL.abuses) {
    if (a.signal == Rudp::AbuseSignal::CRC_FAILURE) ++crcFails;
  }
  BOOST_TEST(crcFails == 50u);
}

BOOST_AUTO_TEST_CASE(TestRudpAbuseSignalNoFalsePositives) {
  minx::RudpConfig cfg;
  cfg.baseTickInterval = std::chrono::microseconds::zero();
  cfg.rngSeed = 0xAB007;
  TestListener aliceL;
  Rudp alice(&aliceL, cfg);
  cfg.rngSeed = 0xAB008;
  TestListener bobL;
  Rudp bob(&bobL, cfg);

  SockAddr aA = makeAddr(40630), bA = makeAddr(40631);
  FakeWire wire(alice, aliceL, bob, bobL, aA, bA);

  uint64_t now = 1000;
  BOOST_REQUIRE(aliceL.push(alice, bA,41, B("hello"), true));
  alice.tick(now);
  wire.deliverAll(now);
  BOOST_REQUIRE(bob.isEstablished(aA, 41));
  BOOST_REQUIRE(alice.isEstablished(bA, 41));

  BOOST_REQUIRE(bobL.push(bob, aA,41, B("world"), true));
  bob.tick(now);
  wire.deliverAll(now);

  alice.closeChannel(bA, 41);
  wire.deliverAll(now);

  BOOST_TEST(aliceL.abuses.size() == 0u);
  BOOST_TEST(bobL.abuses.size() == 0u);
}

BOOST_AUTO_TEST_SUITE_END()
