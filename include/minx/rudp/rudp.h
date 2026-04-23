#ifndef _MINX_RUDP_H_
#define _MINX_RUDP_H_

/**
 * ==========================================================================
 * NOTE: RUDP is an experimental protocol.
 *       Both the code and the docs are mostly machine-generated.
 * ==========================================================================
 *
 * RUDP — Reliable UDP transport for MINX, layered as a MINX_EXTENSION suite.
 *
 * - Rides on MINX_EXTENSION via MinxStdExtensions, identified by a
 *   single 6-byte family id (0xFAB1CEC14742) plus 2 meta bytes that
 *   encode (version, sub-protocol).
 * - Two sub-protocols inside the suite:
 *     0x00 = HANDSHAKE  (OPEN / ACCEPT)
 *     0x01 = CHANNEL    (reliable + unreliable data flow)
 * - "Channels" are radio-frequency-style: both sides agree on a uint32
 *   channel_id out-of-band and start talking. Lazy state creation per
 *   (peer_addr, channel_id) on first push or first inbound packet.
 * - Cumulative ack + 32-bit SACK porosity bitmap for selective
 *   retransmit. Per-channel in-order delivery via a reorder buffer.
 * - One-round-trip handshake exchanges nonces; session_token is
 *   derived from both. Off-path injection is defended by the same
 *   "response goes to the claimed IP" trick MINX tickets use, just
 *   transposed up to RUDP's layer.
 * - Passive state machine: no threads, no timers, no io_context. The
 *   application drives time via tick(now_us) and packets via push() /
 *   flush() / onPacket().
 */

#include <minx/csprng.h>
#include <minx/stdext.h>
#include <minx/types.h>

#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>

namespace minx {

// ---------------------------------------------------------------------------
// RudpConfig — operational tuning, all defaulted, all configurable per-instance
// ---------------------------------------------------------------------------

struct RudpConfig {
  /// Sentinel value for the per-channel bucket params below meaning
  /// "unlimited on this side." When both sides keep the default, the
  /// effective bucket is unlimited and pacing is disabled entirely —
  /// the historical behavior before token buckets existed.
  static constexpr uint32_t PER_CHANNEL_UNLIMITED = 0xFFFFFFFFu;

  /// Per-channel token bucket parameters. See the formal model comment
  /// at the top of src/rudp.cpp. Both fields are advertised to the peer
  /// in the handshake OPEN/ACCEPT; the channel's effective bucket is
  /// min(local, peer) on each parameter independently (smaller config
  /// wins per parameter). perChannelBytesPerSecond is the refill rate R
  /// and perChannelBurstBytes is the capacity C (the maximum burst a
  /// freshly-idle channel can emit in one pulse before R kicks in).
  uint32_t perChannelBytesPerSecond = PER_CHANNEL_UNLIMITED;
  uint32_t perChannelBurstBytes = PER_CHANNEL_UNLIMITED;

  /// Per-peer channel cap. Hard ceiling on peers_[addr].channels.size().
  /// Reaching it makes new channel allocation fail at push() / inbound time.
  /// Default 1 is deliberately tight — a peer only gets one multiplexed
  /// stream unless the app explicitly bumps this. Worst-case per-peer
  /// buffer budget scales linearly with this value (see the reorder caps
  /// below), so leaving it at 1 keeps a freshly-accepted peer bounded at
  /// roughly one reorder buffer's worth of RAM.
  size_t maxChannelsPerPeer = 1;

  /// Per-channel reorder buffer caps. Either bound trips first.
  size_t maxReorderMessagesPerChannel = 1024;
  size_t maxReorderBytesPerChannel = 1024 * 1024; // 1 MB

  /// Channel idle GC. Drop stale (peer_addr, channel_id) entries after
  /// this long with no traffic in either direction. NAT mappings die
  /// sooner; conservative under that.
  std::chrono::microseconds channelInactivityTimeout = std::chrono::seconds(60);

  /// Handshake retry policy: how long to wait for an ACCEPT after sending
  /// OPEN before retrying, and the maximum total attempts before giving up.
  std::chrono::microseconds handshakeRetryInterval =
    std::chrono::milliseconds(200);
  size_t handshakeMaxRetries = 3;

  /// Optional fixed RNG seed for deterministic tests. Zero means seed
  /// from the OS CSPRNG via std::random_device. Non-zero values are
  /// fed directly into the Csprng's deterministic constructor (paired
  /// with 0 for the second key half) so two Rudp instances built with
  /// the same seed produce the same nonce stream.
  uint64_t rngSeed = 0;

  /// Internal "pulse" cadence — RUDP's rate-limit primitive. Each
  /// pulse emits up to one packet per channel-with-data; a channel's
  /// steady-state packet rate is therefore 1 / baseTickInterval.
  /// The application can call tick() and onPacket() at any rate it
  /// likes:
  ///
  ///   * Slower than this interval — RUDP catches up by firing N
  ///     pulses per call, where N = elapsed intervals. Each pulse
  ///     emits up to one packet per channel-with-data, advancing
  ///     a per-channel cursor through sendBuf so consecutive packets
  ///     in the same call carry different message ranges (not
  ///     duplicates). N is capped (see MAX_PULSES_PER_CALL in
  ///     rudp.cpp) to bound the burst; as long as tick() is called
  ///     at least every `cap * base`, no rate is lost to the cap.
  ///
  ///   * Faster than this interval — most calls do nothing (the
  ///     deadline check finds we're not yet due). Cheap.
  ///
  /// Default 100 ms (10 Hz) = 10 pkt/s/channel ceiling. Good for
  /// interactive / low-bandwidth. Bulk callers (file stores,
  /// compute streaming) will drop this to 1-10 ms depending on the
  /// throughput they need. The timer cadence on the calling side
  /// can stay coarse — e.g. base=1 ms + timer=10 ms gives 1000
  /// pkt/s/channel with only 100 wakeups/sec.
  std::chrono::microseconds baseTickInterval = std::chrono::milliseconds(100);
};

// ---------------------------------------------------------------------------
// Rudp — the suite, as a passive state machine driven by the application
// ---------------------------------------------------------------------------

class Rudp {
public:
  // -----------------------------------------------------------------------
  // Identity on the MinxStdExtensions wire
  // -----------------------------------------------------------------------

  /// 6-byte extension family identifier for the RUDP suite.
  static constexpr uint64_t EXTENSION_ID = 0xFAB1CEC14742ULL;

  /// Suite version. Lives in the high byte of the 2-byte meta of the
  /// stdext routing key. Bumping this is how RUDP would evolve to a
  /// fully separate v1 implementation routed to different code.
  static constexpr uint8_t VERSION_V0 = 0x00;

  /// In-suite protocol selectors (low byte of the 2-byte meta).
  static constexpr uint8_t SUBPROTO_HANDSHAKE = 0x00;
  static constexpr uint8_t SUBPROTO_CHANNEL = 0x01;

  /// Wire routing keys composed via MinxStdExtensions::makeKey. Both
  /// mask to the same low-48 family id (RUDP), so registering ONE of
  /// them with MinxStdExtensions catches packets for both sub-protos —
  /// the dispatcher inside Rudp inspects the low meta byte to fork.
  static constexpr uint64_t KEY_V0_HANDSHAKE = MinxStdExtensions::makeKey(
    static_cast<uint16_t>((VERSION_V0 << 8) | SUBPROTO_HANDSHAKE),
    EXTENSION_ID);
  static constexpr uint64_t KEY_V0_CHANNEL = MinxStdExtensions::makeKey(
    static_cast<uint16_t>((VERSION_V0 << 8) | SUBPROTO_CHANNEL), EXTENSION_ID);

  /// Convenience alias: this is the value to register with
  /// MinxStdExtensions::registerExtension when wiring RUDP into a
  /// stdext builder. Both KEY_V0_HANDSHAKE and KEY_V0_CHANNEL mask to
  /// the same family — picking either works.
  static constexpr uint64_t KEY_V0 = KEY_V0_CHANNEL;

  /// Human-readable suite name. Independent of the routing key — for
  /// logs, registries, and grep only.
  static constexpr const char* NAME = "MINX-RUDP";

  // -----------------------------------------------------------------------
  // Wire size constants
  // -----------------------------------------------------------------------

  /// MINX EXTENSION DATA budget RUDP gets to fill (= MAX_DATA_SIZE).
  static constexpr size_t MAX_PACKET_SIZE = 1280;

  /// Every RUDP datagram carries a CRC32C trailer covering the
  /// routing key + body. Corrupted packets are dropped at the top of
  /// onPacket() before any parsing — cheap defense in depth against
  /// UDP's 16-bit checksum and router-level bit flips. Hardware-
  /// accelerated on x86-64 (SSE4.2), so the cost is nanoseconds.
  static constexpr size_t CRC_SIZE = 4;

  /// Header overhead of a CHANNEL packet, including the 8-byte stdext
  /// routing key. See local/rudp.md for the byte-by-byte breakdown.
  ///   8  routing key
  ///   4  channel_id
  ///   8  session_token
  ///   4  solid_ack
  ///   4  porosity
  ///   1  reliable_count
  static constexpr size_t CHANNEL_HEADER_SIZE = 29;

  /// Per-message overhead for each reliable message inside a CHANNEL
  /// packet (msg_id u32 + len u16).
  static constexpr size_t RELIABLE_MESSAGE_OVERHEAD = 6;

  /// Maximum bytes available for application payload (reliable messages
  /// + opaque unreliable tail) inside one CHANNEL packet.
  static constexpr size_t MAX_PAYLOAD_PER_PACKET =
    MAX_PACKET_SIZE - CHANNEL_HEADER_SIZE - CRC_SIZE; // 1247

  /// Maximum size of a single reliable message that can ride in one
  /// packet. push() rejects anything larger.
  static constexpr size_t MAX_MESSAGE_SIZE =
    MAX_PAYLOAD_PER_PACKET - RELIABLE_MESSAGE_OVERHEAD; // 1241

  /// Maximum reliable messages per packet (uint8 count field).
  static constexpr size_t MAX_RELIABLE_PER_PACKET = 255;

  // -----------------------------------------------------------------------
  // Handshake packet kinds (low byte after channel_id in HANDSHAKE packets)
  // -----------------------------------------------------------------------

  enum HandshakeKind : uint8_t {
    HS_OPEN = 0x00,
    HS_ACCEPT = 0x01,
    // Fire-and-forget teardown hint emitted by close() on an ESTABLISHED
    // channel. Carries only (channel_id, session_token) — the token
    // authenticates the close and prevents off-path spoofing. One-shot,
    // no retry; if lost, the peer falls back to its own idle-GC. See
    // src/rudp.cpp for the wire layout.
    HS_CLOSE = 0x02,
  };

  // -----------------------------------------------------------------------
  // Application callbacks (installed once after construction)
  // -----------------------------------------------------------------------

  /// RUDP calls this when it has a packet to put on the wire. The
  /// application's glue typically forwards this directly to
  /// minx->sendExtension(peer, bytes). The Bytes already starts with
  /// the 8-byte stdext routing key; no further wrapping is needed.
  using SendFn = std::function<void(const SockAddr& peer, const Bytes& bytes)>;

  /// RUDP calls this when a message has been delivered to the
  /// application — post-dedup, post-reorder, in-order for reliable
  /// messages. The `reliable` flag distinguishes the two delivery
  /// streams. Unreliable deliveries fire once per inbound CHANNEL
  /// packet that has a non-empty unreliable tail.
  using ReceiveFn =
    std::function<void(const SockAddr& peer, uint32_t channel_id,
                       const Bytes& message, bool reliable)>;

  void setSendCallback(SendFn fn);
  void setReceiveCallback(ReceiveFn fn);

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  explicit Rudp(RudpConfig config = {});
  ~Rudp();

  Rudp(const Rudp&) = delete;
  Rudp& operator=(const Rudp&) = delete;
  Rudp(Rudp&&) = delete;
  Rudp& operator=(Rudp&&) = delete;

  // -----------------------------------------------------------------------
  // Application input verbs
  // -----------------------------------------------------------------------

  /// Enqueue an outbound message. Pure data-in; nothing leaves the wire.
  /// If the channel doesn't exist yet, it's created in IDLE and the
  /// next flush() / tick() will start a handshake. The message will be
  /// emitted once the channel reaches ESTABLISHED.
  ///
  /// Returns false if:
  ///   - msg.size() > MAX_MESSAGE_SIZE
  ///   - the per-peer channel cap is exhausted
  ///   - reliable=true and the per-channel send buffer is full
  bool push(const SockAddr& peer, uint32_t channel_id, const Bytes& msg,
            bool reliable);

  /// Drain pending packets to the SendFn callback right now. No time
  /// advance. Called after push() if the application wants minimum
  /// latency, or implicitly from tick().
  void flush();

  /// Advance time. Run handshake retries, channel inactivity GC, and
  /// then flush(). Called by the application from its own loop on
  /// whatever cadence it picks.
  void tick(uint64_t now_us);

  /// Inbound from the wire. The application's stdext handler calls
  /// this when an EXTENSION packet routed to the RUDP family arrives.
  /// `payload` is the bytes after the 8-byte stdext routing key (which
  /// MinxStdExtensions has already consumed); `key` is the full
  /// unmasked routing key — RUDP reads the meta low byte off it to
  /// fork between the handshake and channel sub-protos.
  ///
  /// `now_us` is the application's current wall-clock time in
  /// microseconds. RUDP uses it for the same time-dependent state
  /// transitions tick() uses (idle GC, handshake retries, pulse
  /// scheduling). Importantly: onPacket may run a pulse INLINE if
  /// enough time has elapsed since the last pulse to cross the
  /// deadline — so the application does NOT need to call tick()
  /// right after onPacket(). The reactive fast path is "packet
  /// arrives → process → emit response on the same call stack," with
  /// no scheduler round-trip required.
  void onPacket(const SockAddr& peer, uint64_t key, const Bytes& payload,
                uint64_t now_us);

  /// Hint: the absolute timestamp (microseconds) at which the
  /// application's scheduler should call tick() at the latest if no
  /// onPacket() arrives in the meantime. Use this to set the next
  /// fire of a boost::asio::steady_timer. The timer is a fallback;
  /// reactive emits from onPacket cover the steady state.
  uint64_t nextDeadlineUs() const noexcept { return nextDeadlineUs_; }

  // -----------------------------------------------------------------------
  // Local state management
  // -----------------------------------------------------------------------
  //
  // close() optionally emits a single HS_CLOSE teardown hint to the
  // peer before dropping local state — see below. gc() and the pulse
  // idle-GC do NOT emit any wire packet; they silently drop state and
  // let the peer's own idle-GC notice. The asymmetry is deliberate:
  // close() is the app's unilateral teardown signal (bad header, policy
  // rejection, protocol error) where the peer would otherwise hang
  // until its own ~60s idle-GC fires; gc() is memory pressure where
  // the peer will hit its own idle-GC at roughly the same time anyway
  // and the extra packets per channel are wasteful.

  /// Drop a single channel immediately. Whatever state the channel
  /// was in (IDLE, OPEN_SENT, ACCEPT_SENT, ESTABLISHED, CLOSED),
  /// after this call the (peer, channel_id) tuple is gone from the
  /// internal maps and any future packets arriving for it will be
  /// dropped as "unknown channel." If the peer has no other channels
  /// left, its PeerState entry is also evicted. No-op if the channel
  /// doesn't exist.
  ///
  /// If the channel was ESTABLISHED, a single HS_CLOSE packet is
  /// emitted to the peer carrying the channel's session_token. The
  /// peer verifies the token against its current session and tears
  /// down its own side synchronously (fires onChannelDestroyed,
  /// erases state). This avoids the ~60s hang where the peer keeps
  /// retransmitting pending sends into the void. Fire-and-forget:
  /// HS_CLOSE is not retried, and loss of that single packet just
  /// falls back to the peer's normal idle-GC.
  void close(const SockAddr& peer, uint32_t channel_id);

  /// Evict every channel whose last activity is older than
  /// `idleThreshold` relative to the current internal time
  /// (currentTimeUs_, which is updated by every tick() / onPacket()
  /// call). Returns the number of channels actually evicted. Empty
  /// peers are also pruned. Use this under memory pressure: walk the
  /// threshold down from "relaxed" (say 60s) toward "aggressive" (say
  /// 3s) until enough slots free up to accept new channels.
  ///
  /// Does NOT emit HS_CLOSE (unlike close()). The peer discovers the
  /// eviction via its own idle-GC or via the session-token check on
  /// the next stray packet.
  ///
  /// The backstop idle GC inside the pulse machinery — which fires at
  /// config_.channelInactivityTimeout (60s by default) every pulse —
  /// is still active. gc() is the manual knob you turn in addition to
  /// that, when the floor is not tight enough for your load.
  size_t gc(std::chrono::microseconds idleThreshold);

  // -----------------------------------------------------------------------
  // Write-path back-pressure callbacks
  // -----------------------------------------------------------------------
  //
  // A RUDP channel's sendBuf is a bounded queue of unacked reliable
  // messages. A producer that writes faster than acks come back will
  // eventually hit the cap and push() will start returning false. For
  // a stream adapter (RudpStream / Beast / HTTP), that's a signal to
  // DEFER the pending async_write_some handler rather than error it
  // out — the stream owes Beast a partial completion or nothing at
  // all, never a "success with 0 bytes."
  //
  // The two callbacks below are the minimum API surface for idiomatic
  // back-pressure handling:
  //
  //   onSendBufDrained: called whenever sendBuf shrinks due to an
  //     inbound ack or due to a completed handshake draining
  //     preEstablishedQueue into sendBuf. The stream uses this to
  //     retry its pending write and, on success, complete the
  //     handler. Fires at most once per packet processed (not per
  //     erased entry) so repeated small acks coalesce into one wake.
  //
  //   onChannelDestroyed: called exactly once, synchronously, just
  //     before the channel's state is erased from the internal maps
  //     by ANY destruction path (close, gc, idle GC, reorder-cap
  //     breach, peer restart). The callback must NOT re-enter Rudp
  //     for this same channel. Stream adapters use this to complete
  //     any pending async handlers with operation_aborted so the
  //     application's Beast / HTTP callbacks get a clean failure
  //     instead of hanging forever.
  //
  // Both callbacks are per-channel, stored in ChannelState. Setting
  // the callback on a non-existent (peer, channel_id) tuple creates
  // the channel. Setting a null callback on a non-existent channel
  // is a no-op (no channel is created). Clearing an existing
  // callback is done by passing nullptr / empty std::function.

  using SendBufDrainedFn = std::function<void()>;
  using ChannelDestroyedFn = std::function<void()>;

  void setSendBufDrainedCallback(const SockAddr& peer, uint32_t channel_id,
                                 SendBufDrainedFn fn);
  void setChannelDestroyedCallback(const SockAddr& peer, uint32_t channel_id,
                                   ChannelDestroyedFn fn);

  // -----------------------------------------------------------------------
  // Channel lifecycle — Accept / Opened
  // -----------------------------------------------------------------------
  //
  // Two globally-installed callbacks that expose the full channel
  // lifecycle to the Rudp consumer. Together with the per-channel
  // onChannelDestroyed above, they form a clean triad:
  //
  //   Accept    — "a peer wants to open a channel on us. Allow?"
  //               Predicate. Only fires on fresh inbound HS_OPEN.
  //               Pure policy; the app should NOT install per-channel
  //               callbacks here (install them from Opened instead).
  //               If unset, Rudp accepts every inbound OPEN.
  //
  //   Opened    — "this channel just transitioned to ESTABLISHED."
  //               Fires exactly once per ESTABLISHED transition, from
  //               a single chokepoint inside promoteToEstablished. All
  //               paths flow through it: fresh peer accept, our own
  //               initiated handshake completing, simultaneous open,
  //               peer restart after a session reset. This is THE place
  //               to hook per-channel setup — install drain / destroyed
  //               callbacks, construct a RudpStream, register the
  //               channel with your application's state, etc.
  //
  //   Destroyed — "this channel is gone." Symmetric to Opened.
  //               Already exists (per-channel). Fires from every
  //               destruction path EXCEPT silent rejection via the
  //               Accept predicate — see invariant below.
  //
  // INVARIANTS:
  //
  //   1. Every Opened is followed by exactly one Destroyed. Guaranteed.
  //   2. Destroyed CAN fire for a channel that never saw Opened — but
  //      only for channels the app initiated (via push()) that failed
  //      to reach ESTABLISHED (e.g. handshake exhaustion). Those still
  //      need to notify the app their push was eventually lost.
  //   3. Destroyed NEVER fires for channels the app rejected via a
  //      false return from the Accept predicate. Those channels were
  //      only proposals; the app never "owned" them.
  //
  // ACCEPT FIRES ON:
  //
  //   - Fresh inbound HS_OPEN on an IDLE or CLOSED channel.
  //   - Peer restart: inbound HS_OPEN with a different nonce on a
  //     channel currently in ACCEPT_SENT or ESTABLISHED. The old
  //     session's Destroyed fires first; then Accept fires for the
  //     new session with the new nonce.
  //
  // ACCEPT DOES NOT FIRE ON:
  //
  //   - OPEN_SENT paths (simultaneous open). We already committed
  //     on our side via push(); the peer's OPEN just completes the
  //     handshake. The app did its decision at push() time.
  //   - Duplicate HS_OPEN (same nonce we already accepted). Pure
  //     idempotent retransmit.
  //
  // THREADING:
  //
  //   Both callbacks run inline on the thread that drove the
  //   triggering packet through onPacket(). Keep them cheap — a slow
  //   predicate or setup handler stalls MINX's IO thread. Install a
  //   RudpStream, register state, and return. Do the heavy lifting
  //   later from the stream's executor, not from inside these hooks.

  using ChannelAcceptFn =
    std::function<bool(const SockAddr& peer, uint32_t channel_id)>;
  using ChannelOpenedFn =
    std::function<void(const SockAddr& peer, uint32_t channel_id)>;

  void setChannelAcceptCallback(ChannelAcceptFn fn);
  void setChannelOpenedCallback(ChannelOpenedFn fn);

  // -----------------------------------------------------------------------
  // Inspection (mostly for tests and debugging)
  // -----------------------------------------------------------------------

  size_t peerCount() const { return peers_.size(); }
  size_t channelCount(const SockAddr& peer) const;
  bool isEstablished(const SockAddr& peer, uint32_t channel_id) const;
  /// Read-only access to the current session token of a channel; 0 if
  /// not established. Useful for tests.
  uint64_t sessionToken(const SockAddr& peer, uint32_t channel_id) const;

private:
  // -----------------------------------------------------------------------
  // Internal state model — never touched outside this class
  // -----------------------------------------------------------------------

  enum class HandshakeState : uint8_t {
    IDLE,        // nothing started yet
    OPEN_SENT,   // we sent OPEN, waiting for ACCEPT
    ACCEPT_SENT, // we received OPEN and replied with ACCEPT (peer-initiated)
    ESTABLISHED, // both sides agree on session_token
    CLOSED,      // handshake exhausted or torn down (transient before evict)
  };

  struct ChannelState {
    // Handshake
    HandshakeState handshakeState = HandshakeState::IDLE;
    uint64_t nonceLocal = 0;   // ours: N_a if we OPEN'd, N_b if peer did
    uint64_t nonceRemote = 0;  // theirs: corresponding nonce
    uint64_t sessionToken = 0; // f(N_a, N_b), valid in ESTABLISHED
    uint64_t lastHandshakeAttemptUs = 0;
    size_t handshakeRetries = 0;
    bool weInitiated = false; // true if we sent OPEN, false if peer did

    // Outbound (us → them)
    uint32_t nextSeq = 1;              // next msg_id to assign (start at 1)
    std::map<uint32_t, Bytes> sendBuf; // unacked, msg_id → bytes
    Bytes pendingUnreliable;           // overwrite slot; cleared on emit

    // Outbound queue for application messages pushed while not yet
    // ESTABLISHED. Drained into sendBuf once handshake completes.
    std::vector<Bytes> preEstablishedQueue;

    // Inbound (them → us)
    uint32_t solidAck = 0;                // last contiguous-delivered msg_id
    std::map<uint32_t, Bytes> reorderBuf; // out-of-order arrivals
    size_t reorderBytes = 0;

    // Tracks what we last *sent* for ack info, so we know if our
    // outbound ack state is stale (and needs another packet).
    uint32_t lastSentSolidAck = 0;
    uint32_t lastSentPorosity = 0;
    bool hasSentAnything = false;

    // Write-path back-pressure callbacks. See setSendBufDrainedCallback
    // and setChannelDestroyedCallback on the Rudp class for the public
    // API. Stored per-channel so dispatch is direct — no filtering on
    // channel_id.
    //
    // onSendBufDrained fires whenever an inbound CHANNEL packet's ack
    // loops actually erased at least one entry from sendBuf, OR when a
    // completed handshake drained preEstablishedQueue into sendBuf.
    // Stream adapters use this to resume deferred async_write_some
    // handlers after sendBuf hits its cap.
    //
    // onChannelDestroyed fires exactly once, just before the channel's
    // state is erased from peers_ by any of the destruction paths
    // (close, gc, idle GC, CLOSED drop, peer restart). The callback
    // runs with the channel still alive in memory, but MUST NOT call
    // back into Rudp to touch this same channel — it's about to vanish.
    // Stream adapters use this to abort any pending write/read handlers
    // with operation_aborted.
    std::function<void()> onSendBufDrained;
    std::function<void()> onChannelDestroyed;

    // Per-channel token bucket. Values are frozen at handshake
    // completion (min of local config and peer-advertised values) and
    // never renegotiated. See the formal model comment at the top of
    // src/rudp.cpp. bucketEnabled==false means the effective rate or
    // capacity is "unlimited" — refill / charge are no-ops and the
    // bucket never stalls the channel.
    //
    // bucketExhausted is the "stop sending" flag: set by a charge that
    // drove tokens to zero (or below, saturated), cleared by a refill
    // that brought tokens back above zero. emitChannel checks it at
    // the top of each burst iteration and breaks out of the burst
    // (but not out of the packet that tripped the flag — overshoot by
    // up to one MTU per exhaustion cycle is allowed by design, so we
    // never have to pre-check whether a packet "fits").
    bool bucketEnabled = false;
    bool bucketExhausted = false;
    uint32_t bucketRateBps = 0;      // effective R, bytes per second
    uint32_t bucketCapacity = 0;     // effective C, bytes
    uint64_t bucketTokensScaled = 0; // current tokens × 1e6 (micro-bytes)
    uint64_t bucketLastRefillUs = 0;

    // Bookkeeping
    uint64_t lastActivityUs = 0;
  };

  struct PeerState {
    std::unordered_map<uint32_t, ChannelState> channels;
  };

  // -----------------------------------------------------------------------
  // Internal helpers (defined in rudp.cpp)
  // -----------------------------------------------------------------------

  // Channel state lookup / creation
  ChannelState* getOrCreateChannel(const SockAddr& peer, uint32_t channel_id);
  ChannelState* findChannel(const SockAddr& peer, uint32_t channel_id);
  const ChannelState* findChannel(const SockAddr& peer,
                                  uint32_t channel_id) const;

  // Inbound dispatch. Historically these returned a "novel"/"not
  // novel" flag used by a deadline-halving tweak in onPacket; the
  // halving only moved one pulse earlier by < base and reset to the
  // normal cadence afterwards, so it was a latency micro-tweak with
  // no throughput effect and has been removed. The bool return value
  // is preserved for potential future use (and because some tests
  // inspect it) but is otherwise unused by callers.
  bool handleHandshakePacket(const SockAddr& peer, const Bytes& payload);
  bool handleChannelPacket(const SockAddr& peer, const Bytes& payload);

  // Outbound builders / emitters
  void emitHandshake(const SockAddr& peer, uint32_t channel_id,
                     ChannelState& cs, HandshakeKind kind);
  // Separate emitter for HS_CLOSE: shorter wire layout (no nonce, no
  // bucket advertisements, just the session_token that authenticates
  // the close). One-shot, no retry, best effort.
  void emitHandshakeClose(const SockAddr& peer, uint32_t channel_id,
                          uint64_t session_token);
  // Burst-aware channel emitter. Emits up to `maxPackets` CHANNEL
  // packets in this call, advancing a local cursor through sendBuf so
  // consecutive packets carry different message ranges. The first
  // packet carries the unreliable tail (if any); subsequent packets in
  // the burst carry only reliable msgs. Returns the number of packets
  // actually emitted.
  size_t emitChannel(const SockAddr& peer, uint32_t channel_id,
                     ChannelState& cs, size_t maxPackets);

  // Per-channel logic. promoteToEstablished takes (peer, cid) as
  // well so it can fire channelOpenedFn_ at its single chokepoint.
  void promoteToEstablished(const SockAddr& peer, uint32_t channel_id,
                            ChannelState& cs);
  void deliverInOrder(const SockAddr& peer, uint32_t channel_id,
                      ChannelState& cs);
  uint32_t computePorosity(const ChannelState& cs) const;
  bool channelHasSomethingToSay(const ChannelState& cs) const;

  // Crypto-ish (no actual crypto — just a deterministic combiner)
  static uint64_t deriveSessionToken(uint64_t na, uint64_t nb);

  // Back-pressure callback fire helpers. fireSendBufDrained is
  // re-entrant-safe (callback may trigger another push); the callback
  // is invoked in place without moving it out. fireChannelDestroyed
  // is one-shot: it moves the callback out before invoking so a
  // destruction path that somehow re-enters can't fire it twice.
  void fireSendBufDrained(ChannelState& cs);
  void fireChannelDestroyed(ChannelState& cs);

  // Erase a channel from peers_ without firing the Destroyed
  // callback. Used only from the Accept-predicate rejection path,
  // where the channel was only ever a proposal and the app never
  // "owned" it. Also prunes empty peer entries.
  void eraseChannelSilent(const SockAddr& peer, uint32_t channel_id);

  // Per-channel token bucket. See the formal model comment at the top
  // of src/rudp.cpp. initChannelBucket is called exactly once per
  // channel, at handshake completion, with the peer's advertised values.
  void initChannelBucket(ChannelState& cs, uint32_t peerRate,
                         uint32_t peerBurst);
  // Lazy refill to currentTimeUs_. Clears bucketExhausted if the
  // refill brought tokens back above zero.
  void refillChannelBucket(ChannelState& cs);
  // Charge the bucket for `bytes` JUST EMITTED. Tokens saturate to
  // zero on underflow (one-packet overshoot per exhaustion cycle is
  // allowed). Sets bucketExhausted when tokens reach zero so that the
  // next burst iteration stops.
  void chargeChannelBucket(ChannelState& cs, size_t bytes);

  // -----------------------------------------------------------------------
  // Members
  // -----------------------------------------------------------------------

  // Pulse machinery: the time-as-parameter / no-internal-timer model.
  //
  // RUDP knows TIME but does not own a TIMER. Every external entry
  // point (tick or onPacket) is an opportunity for RUDP to do its
  // pulse work — GC + flush — if the deadline has arrived. Between
  // calls, time stops; there is no background work.
  //
  // nextDeadlineUs_ is the wall-clock timestamp at which RUDP wants
  // to fire its next pulse. tick() and onPacket() both check it and
  // catch up if overdue, firing N pulses where N = (elapsed / base).
  uint64_t nextDeadlineUs_ = 0;
  uint64_t baseTickIntervalUs_ = 0; // cached from config_.baseTickInterval
  bool pulseInitialized_ = false;   // first tick/onPacket arms the deadline

  // Cached config-derived constants (avoid re-reading config every call).
  uint64_t channelInactivityUs_ = 0;
  uint64_t handshakeRetryUs_ = 0;

  // Forward-progress helpers used by the pulse machinery.
  void initPulseDeadlineIfNeeded(uint64_t now_us);
  void runPulses(uint64_t now_us);
  void doPulseWork(uint64_t now_us, size_t maxPacketsPerChannel);

  RudpConfig config_;
  std::map<SockAddr, PeerState>
    peers_; // SockAddr is comparable, std::map is fine
  SendFn sendFn_;
  ReceiveFn receiveFn_;
  ChannelAcceptFn channelAcceptFn_;
  ChannelOpenedFn channelOpenedFn_;
  Csprng rng_;
  uint64_t currentTimeUs_ = 0; // last time provided to tick()
};

} // namespace minx

#endif
