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
 *     0x00 = HANDSHAKE  (OPEN / ACCEPT / CLOSE)
 *     0x01 = CHANNEL    (reliable + unreliable data flow)
 * - Channel = (peer_addr, uint32 channel_id). Both sides agree on the
 *   channel_id out-of-band and start talking. Lazy state creation per
 *   tuple on first push() or first inbound packet.
 * - Cumulative ack + 32-bit SACK porosity bitmap for selective
 *   retransmit. Per-channel in-order delivery via a reorder buffer.
 * - One-round-trip handshake exchanges nonces; session_token is
 *   derived from both. Off-path injection is defended by the same
 *   "response goes to the claimed IP" trick MINX tickets use.
 * - Passive state machine: no threads, no timers, no io_context.
 *   The application drives time via tick(now_us) and packets via
 *   push() / flush() / onPacket(). All events fire synchronously
 *   on the calling thread through Rudp::Listener.
 */

#include <minx/csprng.h>
#include <minx/stdext.h>
#include <minx/types.h>

#include <boost/asio/ip/udp.hpp>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <iosfwd>
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>

namespace minx {

// Forward declaration. RUDP holds a non-owning Minx* (may be null
// for tests / standalone use) for spam / abuse feedback. We don't
// include <minx/minx.h> here to keep this header light; the full
// definition is only needed at the call sites in rudp.cpp.
class Minx;

// ---------------------------------------------------------------------------
// RudpConfig — operational tuning, all defaulted, all configurable per-instance
// ---------------------------------------------------------------------------

struct RudpConfig {
  /// Sentinel value for the per-channel bucket params below meaning
  /// "unlimited on this side." When both sides keep the default, the
  /// effective bucket is unlimited and pacing is disabled entirely.
  static constexpr uint32_t PER_CHANNEL_UNLIMITED = 0xFFFFFFFFu;

  /// Per-channel token bucket parameters. Both sides advertise their
  /// LOCAL config in the OPEN/ACCEPT handshake; the channel's effective
  /// bucket is min(local, peer) per parameter. perChannelBytesPerSecond
  /// is the refill rate R; perChannelBurstBytes is the capacity C.
  uint32_t perChannelBytesPerSecond = PER_CHANNEL_UNLIMITED;
  uint32_t perChannelBurstBytes = PER_CHANNEL_UNLIMITED;

  /// Per-peer channel cap. Default 1 keeps a freshly-accepted peer
  /// bounded at roughly one reorder buffer's worth of RAM.
  size_t maxChannelsPerPeer = 1;

  /// Per-channel reorder buffer caps. Either bound trips first.
  size_t maxReorderMessagesPerChannel = 1024;
  size_t maxReorderBytesPerChannel = 1024 * 1024; // 1 MB

  /// Channel idle GC: drop stale tuples with no traffic for this long.
  std::chrono::microseconds channelInactivityTimeout = std::chrono::seconds(60);

  /// Handshake retry policy.
  std::chrono::microseconds handshakeRetryInterval =
    std::chrono::milliseconds(200);
  size_t handshakeMaxRetries = 3;

  /// Optional fixed RNG seed for deterministic tests. Zero means seed
  /// from the OS CSPRNG.
  uint64_t rngSeed = 0;

  /// Internal "pulse" cadence — RUDP's rate-limit primitive. Each
  /// pulse emits up to one packet per channel-with-data; steady-state
  /// packet rate per channel is therefore 1 / baseTickInterval. Slow
  /// callers get catch-up bursts; fast callers no-op until the
  /// deadline arrives. Default 100 ms (10 Hz). Bulk callers will drop
  /// this to 1-10 ms.
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

  static constexpr uint64_t EXTENSION_ID = 0xFAB1CEC14742ULL;
  static constexpr uint8_t VERSION_V0 = 0x00;
  static constexpr uint8_t SUBPROTO_HANDSHAKE = 0x00;
  static constexpr uint8_t SUBPROTO_CHANNEL = 0x01;

  static constexpr uint64_t KEY_V0_HANDSHAKE = MinxStdExtensions::makeKey(
    static_cast<uint16_t>((VERSION_V0 << 8) | SUBPROTO_HANDSHAKE),
    EXTENSION_ID);
  static constexpr uint64_t KEY_V0_CHANNEL = MinxStdExtensions::makeKey(
    static_cast<uint16_t>((VERSION_V0 << 8) | SUBPROTO_CHANNEL), EXTENSION_ID);

  /// Convenience alias: register either KEY_V0_* with MinxStdExtensions;
  /// both mask to the same family id (RUDP).
  static constexpr uint64_t KEY_V0 = KEY_V0_CHANNEL;

  static constexpr const char* NAME = "MINX-RUDP";

  // -----------------------------------------------------------------------
  // Wire size constants
  // -----------------------------------------------------------------------

  /// MINX EXTENSION DATA budget RUDP gets to fill (= MAX_DATA_SIZE).
  static constexpr size_t MAX_PACKET_SIZE = 1280;

  /// Every RUDP datagram carries a CRC32C trailer covering the
  /// routing key + body.
  static constexpr size_t CRC_SIZE = 4;

  /// Header overhead of a CHANNEL packet, including the 8-byte stdext
  /// routing key. 8 (key) + 4 (channel_id) + 8 (token) + 4 (solid_ack)
  /// + 4 (porosity) + 1 (reliable_count) = 29.
  static constexpr size_t CHANNEL_HEADER_SIZE = 29;

  /// Per-message overhead inside a CHANNEL packet (msg_id u32 + len u16).
  static constexpr size_t RELIABLE_MESSAGE_OVERHEAD = 6;

  static constexpr size_t MAX_PAYLOAD_PER_PACKET =
    MAX_PACKET_SIZE - CHANNEL_HEADER_SIZE - CRC_SIZE; // 1247
  static constexpr size_t MAX_MESSAGE_SIZE =
    MAX_PAYLOAD_PER_PACKET - RELIABLE_MESSAGE_OVERHEAD; // 1241
  static constexpr size_t MAX_RELIABLE_PER_PACKET = 255;

  // -----------------------------------------------------------------------
  // Handshake packet kinds (low byte after channel_id in HANDSHAKE packets)
  // -----------------------------------------------------------------------

  enum HandshakeKind : uint8_t {
    HS_OPEN = 0x00,
    HS_ACCEPT = 0x01,
    HS_CLOSE = 0x02, // teardown hint, fire-and-forget
  };

  // -----------------------------------------------------------------------
  // Per-channel measurement (for upper-layer billing / accounting)
  // -----------------------------------------------------------------------
  //
  // Cumulative monotone counters per channel. Upper layers read on a
  // tick, diff against last-seen, charge the payer for the delta.
  //
  //   bytesSent          — wire bytes RUDP put on the wire for this
  //                        channel (full datagram, includes the 8-byte
  //                        stdext routing key and 4-byte CRC32C
  //                        trailer). Includes handshake bytes.
  //   bytesReceived      — wire bytes RUDP attributed to this channel.
  //                        Charged BEFORE CRC verification using the
  //                        channel_id field at the same body offset
  //                        for both sub-protos, so CRC-corrupted /
  //                        wrong-token / truncated packets still bill.
  //                        Packets whose channel_id matches no
  //                        existing channel are NOT billed here —
  //                        that's MINX's IP-level spam-filter
  //                        territory.
  //   memoryByteSeconds  — cumulative integral of (currentBufferBytes
  //                        × elapsed_seconds) across the channel's
  //                        post-handshake life. Updated lazily on
  //                        each pulse and once at destruction.
  //   openedAtUs         — time the channel reached ESTABLISHED, in
  //                        the same wall-clock domain the application
  //                        feeds to tick() / onPacket(). Zero for
  //                        channels that never reached ESTABLISHED.

  struct ChannelMetrics {
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    uint64_t memoryByteSeconds = 0;
    uint64_t openedAtUs = 0;
  };

  // -----------------------------------------------------------------------
  // CloseReason — the union of every reason a channel might end its life
  // -----------------------------------------------------------------------
  //
  // Caller-supplied (APPLICATION, INSUFFICIENT_FUNDS) and RUDP-internal
  // (the rest). Surfaced on Listener::onClosed and accepted by
  // closeChannel().

  enum class CloseReason : uint8_t {
    APPLICATION = 0,      // app-initiated close (default for closeChannel)
    IDLE = 1,             // idle GC fired
    HANDSHAKE_FAILED = 2, // sent OPEN, never got ACCEPT
    REORDER_BREACH = 3,   // reorder buffer cap breached (resource attack)
    PEER_CLOSED = 4,      // peer sent HS_CLOSE
    PEER_RESTART = 5,     // peer reset its end (different nonce on est. ch.)
  };
  // RUDP only enumerates reasons it can itself produce or represent.
  // Application-level "why am I closing" (billing eviction, abuse
  // policy, etc.) is the application's bookkeeping — closeChannel()
  // always tags those as APPLICATION on the wire / listener; the
  // application records its own context separately.

  // -----------------------------------------------------------------------
  // AbuseSignal — wire-level peer behavior detected by RUDP
  // -----------------------------------------------------------------------
  //
  // RUDP detects misbehavior MINX's own ipFilter / spamFilter cannot
  // see (they require parsing the EXTENSION payload). When Rudp was
  // constructed with a non-null Minx*, RUDP feeds these back
  // automatically: STRONG → minx_->banAddress(peer.address()) (drops
  // subsequent UDP packets from that peer at MINX dispatch); SOFT →
  // minx_->checkSpam(addr, true) (count-min sketch with threshold
  // logic). The Listener::onAbuse hook fires regardless, for
  // application-level metrics / logging / tests.

  enum class AbuseSignal : uint8_t {
    // Strong: single occurrence is sufficient evidence of off-path
    // injection or a deliberate resource attack.
    FORGED_SESSION_TOKEN_CHANNEL = 0,
    FORGED_SESSION_TOKEN_HS_CLOSE = 1,
    REORDER_CAP_BREACH = 2,
    // Soft: individual occurrences are plausibly noise (wire
    // corruption, races against our own GC, stale retransmits, MTU
    // issues). Sustained occurrences from one peer are abuse.
    CRC_FAILURE = 3,
    STRAY_HS_CLOSE = 4,
    STRAY_CHANNEL_PACKET = 5,
    TRUNCATED_PACKET = 6,
  };

  /// Severity classifier — public so consumers of Listener::onAbuse
  /// can apply the same split for metrics / dashboards without
  /// duplicating the table.
  static constexpr bool isStrongAbuseSignal(AbuseSignal s) {
    switch (s) {
    case AbuseSignal::FORGED_SESSION_TOKEN_CHANNEL:
    case AbuseSignal::FORGED_SESSION_TOKEN_HS_CLOSE:
    case AbuseSignal::REORDER_CAP_BREACH:
      return true;
    case AbuseSignal::CRC_FAILURE:
    case AbuseSignal::STRAY_HS_CLOSE:
    case AbuseSignal::STRAY_CHANNEL_PACKET:
    case AbuseSignal::TRUNCATED_PACKET:
      return false;
    }
    return false;
  }

  // -----------------------------------------------------------------------
  // ChannelHandler — per-channel lifecycle, lives in app code
  // -----------------------------------------------------------------------
  //
  // Each Rudp channel has at most one ChannelHandler bound to it. The
  // handler is the application's per-channel state object: stream
  // adapters, session contexts, parsers, etc. all subclass
  // ChannelHandler and let Rudp dispatch per-channel events directly
  // to them — no app-side (peer, cid) → handler map needed.
  //
  // Lifecycle (the WebSocket-style arc):
  //
  //   onOpened ─[ onEstablished ]─ ... onReliableMessage / onWritable / ...
  //                                                                 │
  //                                                            onClosed
  //
  // onOpened wraps the maximally-expansive lifetime: the handler is
  // wired into Rudp's tracking and may push() / closeChannel() / etc.
  // through its rudp() / peer() / channelId() back-references.
  // onClosed fires exactly once at the end. onEstablished is the
  // intermediate event marking the handshake's completion (channel is
  // ready for end-to-end I/O); it MAY NOT fire if the channel dies
  // before reaching ESTABLISHED.
  //
  // Pairing invariant: every onOpened is followed by exactly one
  // onClosed. There is no other terminal event.
  //
  // Re-entrancy: handler methods may call back into Rudp on the same
  // channel (push, closeChannel) — except from inside onClosed, which
  // is the final notification before Rudp drops its shared_ptr ref.
  //
  // Lifetime: Rudp holds a std::shared_ptr<ChannelHandler> for each
  // channel. The application typically holds its own shared_ptr too
  // (e.g. via ownership of a derived class). Rudp's ref drops AFTER
  // onClosed returns; if the app holds no other refs, the handler
  // dies then. Otherwise it survives.

  struct ChannelHandler {
    virtual ~ChannelHandler() = default;

    /// Earliest event. Fires after Rudp has wired the handler into
    /// its tracking and the protected back-references are set —
    /// rudp(), peer(), channelId() are all safe to call from here on.
    /// Pairs with onClosed.
    virtual void onOpened() {}

    /// Intermediate event: the channel reached ESTABLISHED state
    /// (handshake complete, end-to-end I/O is reliable). Fires once
    /// per ESTABLISHED transition. May NOT fire — channels that die
    /// before ESTABLISHED (handshake exhaustion, accept-then-immediate-
    /// close, ...) skip this and go straight to onClosed.
    virtual void onEstablished() {}

    /// Reliable message delivered in order.
    virtual void onReliableMessage(const Bytes& /*msg*/) {}

    /// Unreliable message delivered (the optional datagram tail of a
    /// CHANNEL packet). Fires once per inbound CHANNEL packet that
    /// carries a non-empty unreliable section.
    virtual void onUnreliableMessage(const Bytes& /*msg*/) {}

    /// sendBuf shrank — back-pressure cleared. Stream adapters use
    /// this to resume a deferred async_write_some.
    virtual void onWritable() {}

    /// Final event. Fires exactly once after onOpened, regardless of
    /// how the channel ended. Rudp drops its shared_ptr ref after
    /// this returns.
    virtual void onClosed(CloseReason /*reason*/) {}

  protected:
    /// Back-references injected by Rudp at registration time. Stable for
    /// the handler's tracked lifetime. After onClosed returns, Rudp
    /// drops its ref to the handler; rudp() / peer() / channelId()
    /// remain set on the (possibly-still-alive) handler object so the
    /// application can read them post-close, but rudp() may dangle if
    /// the Rudp instance is destroyed first.
    Rudp* rudp() const noexcept { return rudp_; }
    const SockAddr& peer() const noexcept { return peer_; }
    uint32_t channelId() const noexcept { return cid_; }

  private:
    friend class Rudp;
    Rudp* rudp_ = nullptr;
    SockAddr peer_;
    uint32_t cid_ = 0;
  };

  // -----------------------------------------------------------------------
  // Listener — non-channel events + the channel-handler factory
  // -----------------------------------------------------------------------
  //
  // The Listener is the application's single, global Rudp endpoint.
  // It carries the events that DON'T live on a per-channel handler:
  //
  //   onSend         — wire output port (mandatory)
  //   onAccept       — predicate AND factory for inbound channels.
  //                    Returning a non-null shared_ptr<ChannelHandler>
  //                    accepts and installs the handler. Returning
  //                    null rejects the inbound channel silently.
  //   onAbuse        — wire-level peer-behavior signals
  //
  // Per-channel events (onOpened / onEstablished / onMessage /
  // onWritable / onClosed) live on Rudp::ChannelHandler instead.
  //
  // Re-entrancy: callbacks may call back into Rudp from this thread.
  // Threading: all callbacks run on the thread driving tick() /
  // onPacket() / closeChannel() / push().

  struct Listener {
    virtual ~Listener() = default;

    /// Mandatory. Rudp has bytes to send to `peer`. `bytes` already
    /// starts with the 8-byte stdext routing key — no further
    /// wrapping needed; glue typically forwards to
    /// minx->sendExtension(peer, bytes).
    virtual void onSend(const SockAddr& peer, const Bytes& bytes) = 0;

    /// Predicate AND factory for inbound channels. Fires on a fresh
    /// HS_OPEN (not on duplicate retransmits, not on simultaneous-
    /// open where we already committed via push()). Return non-null
    /// to accept the channel — Rudp installs the returned handler
    /// and fires handler->onOpened() immediately. Return null to
    /// reject silently.
    ///
    /// Default: reject all (apps that don't override accept nothing).
    virtual std::shared_ptr<ChannelHandler> onAccept(
      const SockAddr& /*peer*/, uint32_t /*channel_id*/) {
      return nullptr;
    }

    /// Wire-level peer behavior. channel_id may be 0 when the signal
    /// can't be attributed to a specific channel (e.g. CRC failure
    /// on a too-short packet). Fires regardless of whether minx_
    /// was provided at construction.
    virtual void onAbuse(const SockAddr& /*peer*/, uint32_t /*channel_id*/,
                         AbuseSignal /*signal*/) {}
  };

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /// `listener` is mandatory and bound at construction. Asserted
  /// non-null. Must outlive *this.
  ///
  /// `minx` is an optional non-owning back-pointer to the MINX
  /// instance this RUDP rides on. When non-null, abuse signals are
  /// fed back automatically (banAddress for strong, checkSpam for
  /// soft). When null, only Listener::onAbuse fires; no IP-level
  /// action is taken (used by tests). Must outlive *this if non-null.
  Rudp(Listener* listener, RudpConfig config = {}, Minx* minx = nullptr);
  ~Rudp();

  Rudp(const Rudp&) = delete;
  Rudp& operator=(const Rudp&) = delete;
  Rudp(Rudp&&) = delete;
  Rudp& operator=(Rudp&&) = delete;

  // -----------------------------------------------------------------------
  // Application input verbs
  // -----------------------------------------------------------------------

  /// Adopt a per-channel handler. This is the OUTBOUND handshake
  /// side's "Opened" trigger: the application constructs a
  /// ChannelHandler subclass and registers it on a (peer, cid)
  /// tuple. Rudp:
  ///   1. Creates the channel state.
  ///   2. Injects rudp/peer/cid back-references into the handler.
  ///   3. Fires handler->onOpened().
  ///   4. Marks the channel OPEN_SENT and picks a nonce — the next
  ///      pulse emits the OPEN packet, kicking off the handshake.
  ///
  /// Returns false if:
  ///   - the per-peer channel cap is exhausted, OR
  ///   - the (peer, cid) is already registered (use channelHandler()
  ///     to read the existing one; programmer error to re-register).
  /// On false return, the handler shared_ptr is unaffected — the
  /// caller can drop or retry.
  ///
  /// On the INBOUND side, Listener::onAccept performs the equivalent
  /// role (predicate + factory). The application doesn't call this
  /// for peer-initiated channels.
  bool registerChannel(const SockAddr& peer, uint32_t channel_id,
                    std::shared_ptr<ChannelHandler> handler);

  /// Read accessor. Returns the handler bound to (peer, cid), or
  /// nullptr if the channel doesn't exist or has no handler. Useful
  /// for operations that originate outside the listener / handler
  /// (e.g. application-level ticks that want to push to a known
  /// channel without going through the listener).
  std::shared_ptr<ChannelHandler> channelHandler(
    const SockAddr& peer, uint32_t channel_id) const;

  /// Enqueue an outbound message on an existing channel. The channel
  /// must have been registered (via registerChannel for outbound or
  /// onAccept for inbound) — push() does NOT create channels.
  ///
  /// Returns false if:
  ///   - msg.size() > MAX_MESSAGE_SIZE
  ///   - the channel doesn't exist (not registered)
  ///   - reliable=true and the per-channel send buffer is full
  bool push(const SockAddr& peer, uint32_t channel_id, const Bytes& msg,
            bool reliable);

  /// Drain pending packets through Listener::onSend right now. No time
  /// advance. Called after push() if minimum latency is desired, or
  /// implicitly from tick().
  void flush();

  /// Advance time. Run handshake retries, channel inactivity GC, and
  /// then a pulse.
  void tick(uint64_t now_us);

  /// Inbound from the wire. The application's stdext handler calls
  /// this when an EXTENSION packet routed to the RUDP family arrives.
  /// `payload` is the bytes after the 8-byte stdext routing key (which
  /// MinxStdExtensions has already consumed); `key` is the full
  /// unmasked routing key.
  ///
  /// `now_us` advances RUDP's internal clock. onPacket may fire a
  /// pulse INLINE if enough time has elapsed since the last pulse —
  /// the application does NOT need to call tick() right after.
  void onPacket(const SockAddr& peer, uint64_t key, const Bytes& payload,
                uint64_t now_us);

  /// Hint: the absolute timestamp (microseconds) by which the
  /// application's scheduler should call tick() at the latest if no
  /// onPacket() arrives in the meantime. Use to set the next fire of
  /// a steady_timer.
  uint64_t nextDeadlineUs() const noexcept { return nextDeadlineUs_; }

  /// Drop a channel.
  ///
  /// `timeout == 0` (default): immediate teardown. The (peer,
  /// channel_id) tuple is erased synchronously; if the channel was
  /// ESTABLISHED, a single HS_CLOSE packet is emitted to the peer
  /// (fire-and-forget) so the peer's side tears down synchronously
  /// rather than waiting for its own idle-GC. Pending bytes in
  /// `sendBuf` are dropped — RST-equivalent. The reason is forwarded
  /// to Listener::onClosed. No-op if the channel doesn't exist.
  ///
  /// `timeout > 0`: graceful close. Marks the channel for "drain
  /// then close": the channel keeps pulsing normally until
  /// `sendBuf` empties (all reliable bytes ACK'd), at which point
  /// HS_CLOSE is emitted and the channel is destroyed. If the
  /// timeout elapses with bytes still pending, falls back to
  /// immediate teardown. The application is expected to stop
  /// calling push() on this channel after closeChannel returns —
  /// gating new writes is the application's responsibility (see
  /// RudpStream's `closed_` flag for the pattern). Same SO_LINGER
  /// shape: timeout=0 is RST, timeout>0 is a deadlined graceful
  /// close. Only meaningful for ESTABLISHED channels; for any
  /// other state, falls through to the immediate path.
  void closeChannel(const SockAddr& peer, uint32_t channel_id,
                    CloseReason reason = CloseReason::APPLICATION,
                    std::chrono::microseconds timeout =
                      std::chrono::microseconds(0));

  /// Evict every channel whose last activity is older than
  /// `idleThreshold` relative to RUDP's current internal time.
  /// Returns the number of channels actually evicted. Listener::onClosed
  /// fires for each with reason = IDLE. Does NOT emit HS_CLOSE.
  size_t gc(std::chrono::microseconds idleThreshold);

  // -----------------------------------------------------------------------
  // Read-only inspection
  // -----------------------------------------------------------------------

  /// Snapshot of a channel's metrics, by value. nullopt if not tracked.
  /// memoryByteSeconds is updated on each pulse and once at destruction;
  /// reads in between can lag by up to one pulse interval.
  std::optional<ChannelMetrics> metricsFor(const SockAddr& peer,
                                           uint32_t channel_id) const;

  // -----------------------------------------------------------------------
  // Debug / test inspection (not part of the production API contract)
  // -----------------------------------------------------------------------

  size_t peerCount() const { return peers_.size(); }
  size_t channelCount(const SockAddr& peer) const;
  bool isEstablished(const SockAddr& peer, uint32_t channel_id) const;
  /// Current session token; 0 if not ESTABLISHED. Tests only.
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
    uint64_t nonceLocal = 0;
    uint64_t nonceRemote = 0;
    uint64_t sessionToken = 0;
    uint64_t lastHandshakeAttemptUs = 0;
    size_t handshakeRetries = 0;
    bool weInitiated = false;

    // Outbound
    uint32_t nextSeq = 1;
    std::map<uint32_t, Bytes> sendBuf;
    Bytes pendingUnreliable;
    std::vector<Bytes> preEstablishedQueue;

    // Inbound
    uint32_t solidAck = 0;
    std::map<uint32_t, Bytes> reorderBuf;
    size_t reorderBytes = 0;

    // Outbound ack-state tracking
    uint32_t lastSentSolidAck = 0;
    uint32_t lastSentPorosity = 0;
    bool hasSentAnything = false;

    // Per-channel token bucket (frozen at handshake completion)
    bool bucketEnabled = false;
    bool bucketExhausted = false;
    uint32_t bucketRateBps = 0;
    uint32_t bucketCapacity = 0;
    uint64_t bucketTokensScaled = 0;
    uint64_t bucketLastRefillUs = 0;

    // Bookkeeping
    uint64_t lastActivityUs = 0;

    // Metrics: cumulative counters + the integral's per-channel state.
    ChannelMetrics metrics;
    uint64_t metricsLastUpdateUs = 0;
    uint64_t metricsMemRemainderUs = 0; // [0, 1_000_000)

    // Per-channel handler. Set once at registration time (registerChannel
    // for outbound, onAccept-returns-non-null for inbound). Cleared
    // after onClosed fires and just before the channel is erased.
    // Pairing invariant: every registered channel fires
    // handler->onOpened() at registration time and exactly one
    // handler->onClosed(reason) on destruction; nothing else binds
    // those two events.
    std::shared_ptr<ChannelHandler> handler;
    // Whether onEstablished has fired at least once for this
    // incarnation. Reset on peer-restart (fresh session).
    bool handlerEstablished = false;

    // Reason stamped onto the channel when its handshakeState
    // transitions to CLOSED (handshake exhaustion, reorder cap
    // breach), so the doPulseWork drop loop can pass it to
    // destroyChannel without losing the cause.
    CloseReason closeReason = CloseReason::APPLICATION;

    // Graceful "drain then close" state, set by closeChannel(...,
    // timeout>0). Pulse loop watches sendBuf: when it empties (or
    // when closeOnDrainDeadlineUs elapses, whichever comes first),
    // emits a single HS_CLOSE and tears down. Until then the
    // channel keeps pulsing normally — retransmits in flight,
    // ACKs in, no new push() calls expected from the application.
    bool closeOnDrain = false;
    CloseReason closeOnDrainReason = CloseReason::APPLICATION;
    uint64_t closeOnDrainDeadlineUs = 0;
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

  // Inbound dispatch.
  // wireBytes is the original on-wire size of the packet (post-stdext-
  // key, includes CRC trailer); used for HS_OPEN-creates-fresh-channel
  // bytesReceived charge that onPacket couldn't do up front.
  // inboundCharged is true iff onPacket already attributed wireBytes to
  // an existing (peer, channel_id).
  void handleHandshakePacket(const SockAddr& peer, const Bytes& payload,
                             size_t wireBytes, bool inboundCharged);
  void handleChannelPacket(const SockAddr& peer, const Bytes& payload);

  // Outbound emitters. Each charges cs.metrics.bytesSent internally.
  void emitHandshake(const SockAddr& peer, uint32_t channel_id,
                     ChannelState& cs, HandshakeKind kind);
  void emitHandshakeClose(const SockAddr& peer, uint32_t channel_id,
                          ChannelState& cs);
  size_t emitChannel(const SockAddr& peer, uint32_t channel_id,
                     ChannelState& cs, size_t maxPackets);

  // Per-channel logic.
  void promoteToEstablished(const SockAddr& peer, uint32_t channel_id,
                            ChannelState& cs);
  void deliverInOrder(const SockAddr& peer, uint32_t channel_id,
                      ChannelState& cs);
  uint32_t computePorosity(const ChannelState& cs) const;
  bool channelHasSomethingToSay(const ChannelState& cs) const;

  // Crypto-ish (deterministic combiner).
  static uint64_t deriveSessionToken(uint64_t na, uint64_t nb);

  // Erase a channel from peers_ silently (no handler->onClosed).
  // Used only from the onAccept-rejection path, where no handler
  // was ever installed.
  void eraseChannelSilent(const SockAddr& peer, uint32_t channel_id);

  // Wire a freshly-created ChannelState's handler: inject the
  // back-references (rudp_/peer_/cid_) into the handler object,
  // store it on cs.handler, and fire handler->onOpened(). Called
  // from registerChannel (outbound) and from the onAccept-true path
  // (inbound).
  void wireHandler(const SockAddr& peer, uint32_t channel_id,
                   ChannelState& cs,
                   std::shared_ptr<ChannelHandler> handler);

  // Buffer accounting + integral advance, called from doPulseWork and
  // destroyChannel.
  size_t channelBufferBytes(const ChannelState& cs) const;
  void updateMemoryIntegral(ChannelState& cs);

  // Centralized teardown: final integral update, fire
  // handler->onClosed (if a handler is bound), drop the handler ref.
  // Caller is responsible for the map erase that follows.
  void destroyChannel(const SockAddr& peer, uint32_t channel_id,
                      ChannelState& cs, CloseReason reason);

  // Abuse signal: log + (if minx_) ban or spamFilter + onAbuse.
  void reportAbuse(const SockAddr& peer, uint32_t channel_id,
                   AbuseSignal signal);

  // Per-channel token bucket.
  void initChannelBucket(ChannelState& cs, uint32_t peerRate,
                         uint32_t peerBurst);
  void refillChannelBucket(ChannelState& cs);
  void chargeChannelBucket(ChannelState& cs, size_t bytes);

  // Pulse machinery.
  void initPulseDeadlineIfNeeded(uint64_t now_us);
  void runPulses(uint64_t now_us);
  void doPulseWork(uint64_t now_us, size_t maxPacketsPerChannel);

  // -----------------------------------------------------------------------
  // Members
  // -----------------------------------------------------------------------

  uint64_t nextDeadlineUs_ = 0;
  uint64_t baseTickIntervalUs_ = 0;
  bool pulseInitialized_ = false;
  uint64_t channelInactivityUs_ = 0;
  uint64_t handshakeRetryUs_ = 0;

  RudpConfig config_;
  std::map<SockAddr, PeerState> peers_;
  Listener* listener_; // mandatory, asserted non-null at construction
  Minx* minx_;         // optional, may be null
  Csprng rng_;
  uint64_t currentTimeUs_ = 0;
};

/// Stream operators for the public Rudp enums. Print the enum name
/// without the `Rudp::CloseReason::` / `Rudp::AbuseSignal::` prefix
/// for log readability; unknown numeric values print as "?(N)".
std::ostream& operator<<(std::ostream& os, Rudp::CloseReason r);
std::ostream& operator<<(std::ostream& os, Rudp::AbuseSignal s);

} // namespace minx

#endif
