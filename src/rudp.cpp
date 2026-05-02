#include <minx/blog.h>
LOG_MODULE_DISABLED("rudp")

#include <minx/rudp/rudp.h>

#include <minx/buffer.h>
#include <minx/minx.h> // for Minx::banAddress on the abuse-feedback path

#include <crc32c/crc32c.h>

#include <algorithm>
#include <span>

namespace minx {

// ===========================================================================
// CRC32C wire integrity
// ===========================================================================
//
// Every RUDP datagram carries a 4-byte CRC32C trailer covering the
// entire on-wire packet (routing key + body). The trailer is appended
// by the send path (appendCrc32cTrailer) and checked + stripped by
// onPacket (verifyAndStripCrc32cTrailer). Corruption that sneaks past
// UDP's 16-bit checksum — router bit flips, memory corruption, etc.
// — is caught here and the packet is dropped as if it had never
// arrived; RUDP's retransmit handles recovery transparently.
//
// The CRC covers the routing key (8 bytes, serialized BE) + the body
// bytes (what MinxStdExtensions hands to onPacket() as `payload`,
// minus the last 4 bytes which ARE the trailer). Computing with
// crc32c_extend lets us hash the two ranges as a single logical
// stream without a copy.
//
// Hardware-accelerated on x86-64 via SSE4.2 (detected at runtime by
// the google/crc32c library). Sub-microsecond per packet; free
// compared to a UDP send.

// CRC32C over [key BE | body]. Key encoding goes through minx::Buffer
// to guarantee identical BE serialization to the put<uint64_t>() calls
// in the emit functions; receivers must verify with the same routing
// key the sender used.
static uint32_t computeCrc32cOverKeyAndBody(
    uint64_t key, const uint8_t* body, size_t bodyLen) {
  Bytes keyBytes;
  keyBytes.resize(MinxStdExtensions::KEY_SIZE);
  Buffer kb(keyBytes);
  kb.put<uint64_t>(key);
  uint32_t acc = ::crc32c_value(
    reinterpret_cast<const uint8_t*>(keyBytes.data()),
    MinxStdExtensions::KEY_SIZE);
  if (bodyLen > 0)
    acc = ::crc32c_extend(acc, body, bodyLen);
  return acc;
}

// Called by every emit function after pkt is fully built. pkt at
// this point is the full on-wire datagram (routing key + body),
// which is what the peer's UDP socket will see. We compute CRC32C
// over it and append 4 BE bytes via Buffer — same serialization the
// put<uint32_t>() calls in the emit functions use, so receivers
// decode the trailer with the same ConstBuffer primitives. Caller
// must have left CRC_SIZE of headroom in whatever budget math it
// did.
static void appendCrc32cTrailer(Bytes& pkt) {
  const auto* data = reinterpret_cast<const uint8_t*>(pkt.data());
  uint32_t crc = ::crc32c_value(data, pkt.size());
  const size_t oldSize = pkt.size();
  pkt.resize(oldSize + Rudp::CRC_SIZE);
  Buffer tail(pkt);
  tail.setWritePos(oldSize);
  tail.put<uint32_t>(crc);
}

// Returns true if the trailer checks out; `payload` is mutated to
// remove the 4-byte trailer. Returns false on length-too-short or
// mismatch; in the false case payload may have been truncated.
// Caller must treat "false" as "drop the packet, take no action".
static bool verifyAndStripCrc32cTrailer(
    uint64_t key, Bytes& payload) {
  if (payload.size() < Rudp::CRC_SIZE) return false;
  const size_t bodyLen = payload.size() - Rudp::CRC_SIZE;
  const auto* data = reinterpret_cast<const uint8_t*>(payload.data());
  uint32_t expected = computeCrc32cOverKeyAndBody(key, data, bodyLen);
  ConstBuffer tail(payload);
  tail.setReadPos(bodyLen);
  uint32_t got = tail.get<uint32_t>();
  if (expected != got) return false;
  payload.resize(bodyLen);
  return true;
}

// ===========================================================================
// File-static helpers
// ===========================================================================
//
// Read a variable-length slice of bytes from the middle of a
// ConstBuffer. The AutoBuffer API exposes fixed-size typed reads
// (get<T>) and drain-to-end reads (getRemainingBytesSpan), but no
// "consume N bytes as a Bytes" primitive — that's what this is.
//
// The caller must have verified `buf.getRemainingBytesCount() >= len`
// before calling. No bounds check in here.
static Bytes readSliceBytes(ConstBuffer& buf, size_t len) {
  const size_t start = buf.getReadPos();
  const auto backing = buf.getBackingSpan();
  const char* first = reinterpret_cast<const char*>(backing.data() + start);
  Bytes result(first, first + len);
  buf.setReadPos(start + len);
  return result;
}

// ===========================================================================
// Per-channel token bucket — formal model
// ===========================================================================
//
// Each ESTABLISHED channel carries a token bucket that paces how fast
// we put bytes on the wire for that channel. The bucket is
// characterized by two parameters:
//
//     R  — refill rate, in bytes per second
//     C  — capacity (maximum burst), in bytes
//
// The bucket holds tokens(t) at time t. The capacity ceiling gives
//
//     0 ≤ tokens(t) ≤ C
//
// with the initial state at handshake completion
//
//     tokens(t₀) = C          (start full → allow an immediate full burst)
//
// Refill rule (continuous, evaluated lazily at each operation):
//
//     tokens(t) = min(C, tokens(t_prev) + R × (t − t_prev))
//
// where t and t_prev are in microseconds. The multiplication is
// performed in scaled integer units — 1 byte = 1,000,000 micro-bytes —
// so fractional refills are preserved exactly without floating point.
//
// Charge rule — charge(B, t):   [check-then-act, NOT check-before-act]
//
//     tokens(t) ← max(0, tokens(t) − B)
//     exhausted ← (tokens(t) == 0)
//
//     The packet has ALREADY BEEN SENT before charge is called. The
//     bucket does not refuse packets — it absorbs the charge and then
//     sets an "exhausted" latch if tokens have hit zero. The caller
//     checks the latch at the top of every burst iteration (AFTER a
//     lazy refill that may have cleared it); if set, the burst stops
//     WITHOUT building or sending another packet.
//
//     This deliberately allows a one-packet overshoot per exhaustion
//     cycle: a bucket with 1 token remaining still permits a full-MTU
//     send and then latches. Over time the average rate converges to
//     R within a tolerance of one MTU per cycle, with zero "will this
//     packet fit?" pre-check math and no rollback of iterators or
//     queued unreliable data. The simplicity is the feature.
//
// Negotiation (handshake):
//
//     Each side advertises its LOCAL configuration (R_local, C_local)
//     in its OPEN/ACCEPT packet. The channel's effective bucket is
//
//         R_eff = min(R_local, R_peer)
//         C_eff = min(C_local, C_peer)
//
//     "Smaller config wins" on both parameters, independently. This
//     guarantees that (a) neither side floods the other beyond what it
//     has declared it is willing to receive, and (b) the channel's
//     effective rate is always ≤ what each side is willing to source.
//
// Sentinel value (UNLIMITED):
//
//     RudpConfig::PER_CHANNEL_UNLIMITED == UINT32_MAX means "no limit
//     on this side." If after negotiation either R_eff or C_eff is
//     UNLIMITED, the bucket is disabled for that channel and both
//     refillChannelBucket / chargeChannelBucket are no-ops. This is
//     the default, making token-bucket pacing opt-in via config.
//
// Layer placement:
//
//     Token buckets live in RUDP, not MINX, because pacing is the
//     application's PRIOR KNOWLEDGE of the link — the bucket encodes
//     static, operator-supplied rates that do not need in-band
//     feedback. Each RUDP channel has its own independent bucket. A
//     MINX socket carrying P peers × M channels-per-peer effectively
//     shapes P × M × R_eff bytes/sec total, so the operator's sizing
//     rule is
//
//         link_rate ≥ P_max × M_max × R_eff
//
//     and is pure static configuration. No adaptive/AIMD loop is
//     required and none is present.
// ===========================================================================

// Microseconds per second. Used in two unrelated places: the byte-
// bucket scale (1 byte == USEC_PER_SEC scaled units) and the metric
// integral's seconds/microseconds split. The literal would otherwise
// repeat ~5x with no name.
static constexpr uint64_t USEC_PER_SEC = 1'000'000ULL;

// Scale factor: 1 byte == TOKEN_SCALE units in bucketTokensScaled. We
// work in scaled integer units so that (R bytes/sec) × (Δt µs) divides
// cleanly: R × Δt_us is exactly the number of micro-bytes to add.
static constexpr uint64_t TOKEN_SCALE = USEC_PER_SEC;

void Rudp::initChannelBucket(ChannelState& cs, uint32_t peerRate,
                             uint32_t peerBurst) {
  const uint32_t localRate = config_.perChannelBytesPerSecond;
  const uint32_t localBurst = config_.perChannelBurstBytes;

  const uint32_t effRate = std::min(localRate, peerRate);
  const uint32_t effBurst = std::min(localBurst, peerBurst);

  const bool unlimited = (effRate == RudpConfig::PER_CHANNEL_UNLIMITED) ||
                         (effBurst == RudpConfig::PER_CHANNEL_UNLIMITED);

  cs.bucketEnabled = !unlimited;
  cs.bucketExhausted = false;
  cs.bucketRateBps = effRate;
  cs.bucketCapacity = effBurst;
  cs.bucketTokensScaled =
    unlimited ? 0 : static_cast<uint64_t>(effBurst) * TOKEN_SCALE;
  cs.bucketLastRefillUs = currentTimeUs_;

  LOGTRACE << "init bucket" << VAR(localRate) << VAR(peerRate) << VAR(effRate)
           << VAR(localBurst) << VAR(peerBurst) << VAR(effBurst)
           << VAR(cs.bucketEnabled);
}

void Rudp::refillChannelBucket(ChannelState& cs) {
  if (!cs.bucketEnabled)
    return;

  const uint64_t now_us = currentTimeUs_;
  const uint64_t cap_scaled =
    static_cast<uint64_t>(cs.bucketCapacity) * TOKEN_SCALE;

  if (now_us > cs.bucketLastRefillUs && cs.bucketRateBps > 0 &&
      cs.bucketTokensScaled < cap_scaled) {
    const uint64_t dt = now_us - cs.bucketLastRefillUs;
    const uint64_t rate = cs.bucketRateBps;
    const uint64_t deficit = cap_scaled - cs.bucketTokensScaled;
    // dt needed to top up to full: ceil(deficit / rate). If we have
    // more elapsed time than that, just snap to full — avoids any
    // chance of overflow in the rate*dt multiplication.
    const uint64_t maxUsefulDt = (deficit + rate - 1) / rate;
    if (dt >= maxUsefulDt) {
      cs.bucketTokensScaled = cap_scaled;
    } else {
      // rate × dt < rate × maxUsefulDt ≤ deficit + rate, so the
      // product is bounded well below 2⁶³ for any uint32 config.
      cs.bucketTokensScaled += rate * dt;
      if (cs.bucketTokensScaled > cap_scaled) {
        cs.bucketTokensScaled = cap_scaled;
      }
    }
  }
  cs.bucketLastRefillUs = now_us;

  // Clear the exhaustion latch as soon as any positive balance exists.
  if (cs.bucketTokensScaled > 0) {
    cs.bucketExhausted = false;
  }
}

void Rudp::chargeChannelBucket(ChannelState& cs, size_t bytes) {
  if (!cs.bucketEnabled)
    return;

  const uint64_t cost_scaled = static_cast<uint64_t>(bytes) * TOKEN_SCALE;
  if (cost_scaled >= cs.bucketTokensScaled) {
    // Underflow — saturate to zero and latch the bucket as exhausted.
    // The packet has already been sent; we tolerate the overshoot.
    cs.bucketTokensScaled = 0;
    cs.bucketExhausted = true;
  } else {
    cs.bucketTokensScaled -= cost_scaled;
    // Note: we do NOT latch here on cs.bucketTokensScaled == 0 because
    // the branch above already covers that case (cost_scaled == tokens
    // enters the "underflow" arm via the >= test).
  }
}

// ===========================================================================
// Construction / destruction
// ===========================================================================

Rudp::Rudp(Listener* listener, RudpConfig config, Minx* minx)
    : config_(config),
      listener_(listener),
      minx_(minx),
      rng_(config.rngSeed != 0 ? Csprng(config.rngSeed, 0) : Csprng()) {
  // Listener is mandatory. The whole API funnels through it; running
  // without one is never useful — even the simplest test wires a
  // SendListener to capture outbound bytes.
  assert(listener_ != nullptr && "Rudp: listener must not be null");
  // Cache config-derived constants so we don't keep re-converting
  // chrono::microseconds → uint64 on every call. baseTickInterval == 0
  // is a special "no pacing" mode where every external call fires
  // exactly one pulse (used by tests and by applications that want
  // full reactive operation without the periodic floor).
  baseTickIntervalUs_ = static_cast<uint64_t>(config_.baseTickInterval.count());
  channelInactivityUs_ =
    static_cast<uint64_t>(config_.channelInactivityTimeout.count());
  handshakeRetryUs_ =
    static_cast<uint64_t>(config_.handshakeRetryInterval.count());
  LOGTRACE << "Rudp" << VAR(HEXU64(KEY_V0_HANDSHAKE))
           << VAR(HEXU64(KEY_V0_CHANNEL)) << VAR(baseTickIntervalUs_);
}

Rudp::~Rudp() { LOGTRACE << "~Rudp"; }

// ===========================================================================
// Inspection helpers
// ===========================================================================

size_t Rudp::channelCount(const SockAddr& peer) const {
  auto it = peers_.find(peer);
  return it == peers_.end() ? 0 : it->second.channels.size();
}

bool Rudp::isEstablished(const SockAddr& peer, uint32_t channel_id) const {
  const auto* cs = findChannel(peer, channel_id);
  return cs && cs->handshakeState == HandshakeState::ESTABLISHED;
}

uint64_t Rudp::sessionToken(const SockAddr& peer, uint32_t channel_id) const {
  const auto* cs = findChannel(peer, channel_id);
  return cs ? cs->sessionToken : 0;
}

// ===========================================================================
// Write-path back-pressure callbacks — setters + fire helpers
// ===========================================================================

void Rudp::eraseChannelSilent(const SockAddr& peer, uint32_t channel_id) {
  auto pit = peers_.find(peer);
  if (pit == peers_.end())
    return;
  pit->second.channels.erase(channel_id);
  if (pit->second.channels.empty()) {
    peers_.erase(pit);
  }
}

void Rudp::wireHandler(const SockAddr& peer, uint32_t channel_id,
                       ChannelState& cs,
                       std::shared_ptr<ChannelHandler> handler) {
  // Inject the back-references the handler will use to push /
  // closeChannel / etc. from inside its event methods. Then store
  // the shared_ptr on the channel and fire onOpened — earliest
  // event in the lifecycle.
  handler->rudp_ = this;
  handler->peer_ = peer;
  handler->cid_ = channel_id;
  cs.handler = std::move(handler);
  cs.handlerEstablished = false;
  cs.handler->onOpened();
}

bool Rudp::registerChannel(const SockAddr& peer, uint32_t channel_id,
                        std::shared_ptr<ChannelHandler> handler) {
  // Programmer-error guard: re-registering an existing channel is
  // not supported (use channelHandler() to inspect the existing
  // handler if you need to).
  if (findChannel(peer, channel_id) != nullptr) {
    LOGDEBUG << "registerChannel: already registered" << SVAR(peer)
             << VAR(channel_id);
    return false;
  }
  ChannelState* cs = getOrCreateChannel(peer, channel_id);
  if (!cs) {
    return false; // per-peer channel cap
  }
  wireHandler(peer, channel_id, *cs, std::move(handler));
  // Kick off the handshake: outbound registration is the application's
  // declaration "I want this channel," and the wire-level cost of
  // owning a channel is the OPEN. State IDLE → OPEN_SENT here so
  // the next pulse emits the OPEN packet (no need for the app to
  // call push() with dummy data just to start the handshake).
  cs->weInitiated = true;
  cs->nonceLocal = rng_.next();
  cs->handshakeState = HandshakeState::OPEN_SENT;
  cs->handshakeRetries = 0;
  cs->lastHandshakeAttemptUs = currentTimeUs_;
  return true;
}

std::shared_ptr<Rudp::ChannelHandler>
Rudp::channelHandler(const SockAddr& peer, uint32_t channel_id) const {
  const auto* cs = findChannel(peer, channel_id);
  return cs ? cs->handler : nullptr;
}

void Rudp::reportAbuse(const SockAddr& peer, uint32_t channel_id,
                       AbuseSignal signal) {
  LOGDEBUG << "abuse signal" << SVAR(peer) << VAR(channel_id) << VAR(signal);
  if (minx_) {
    if (isStrongAbuseSignal(signal)) {
      // Strong signal: immediate ban. MINX's ipFilter drops subsequent
      // UDP packets from this peer's prefix. Minx::banAddress already
      // short-circuits for loopback under trustLoopback.
      minx_->banAddress(peer.address());
    } else {
      // Soft signal: feed MINX's count-min-sketch spam filter and let
      // its threshold decide. One-off is noise; recurring is abuse.
      // We ignore the boolean return: by the time it would say "over
      // threshold" the filter is already dropping that peer's packets
      // at MINX dispatch, which is the action we'd take anyway.
      (void)minx_->checkSpam(peer.address(), /*alsoUpdate=*/true);
    }
  }
  // Observability: every signal goes to the listener regardless of
  // whether minx_ was provided. Tests pass null Minx and observe via
  // the listener alone.
  listener_->onAbuse(peer, channel_id, signal);
}

// ===========================================================================
// Per-channel metrics — buffer integral + lookup + centralized teardown
// ===========================================================================

size_t Rudp::channelBufferBytes(const ChannelState& cs) const {
  // Sum the application-visible memory the channel is currently
  // holding. The numbers in cs.* are already maintained by the
  // existing code paths; this helper just totals them on demand.
  size_t total = cs.reorderBytes;
  total += cs.pendingUnreliable.size();
  for (const auto& kv : cs.sendBuf) {
    total += kv.second.size();
  }
  for (const auto& m : cs.preEstablishedQueue) {
    total += m.size();
  }
  return total;
}

void Rudp::updateMemoryIntegral(ChannelState& cs) {
  // Lazy advance of memoryByteSeconds to currentTimeUs_. Called from
  // doPulseWork (per pulse) and destroyChannel (final). Cheap:
  // O(sendBuf size) for the buffer sum, with sendBuf bounded by
  // maxReorderMessagesPerChannel (1024 by default).
  //
  // We accumulate in byte-microseconds (buf × dt_us) and carry the
  // sub-second remainder across calls. Splitting dt into seconds and
  // microseconds before multiplying avoids overflow at long idle
  // intervals (a never-touched channel could see dt of weeks).
  if (currentTimeUs_ <= cs.metricsLastUpdateUs) {
    cs.metricsLastUpdateUs = currentTimeUs_;
    return;
  }
  const uint64_t dt = currentTimeUs_ - cs.metricsLastUpdateUs;
  const uint64_t buf = static_cast<uint64_t>(channelBufferBytes(cs));
  cs.metricsLastUpdateUs = currentTimeUs_;
  if (buf == 0) {
    // No buffers held in this interval — integral doesn't move,
    // remainder stays where it was.
    return;
  }
  // Whole seconds of dt go straight into byte-seconds.
  //
  // Overflow analysis. buf is bounded by the per-channel reorder cap
  // (~1 MB ≈ 2^20). dt_us_rem < USEC_PER_SEC ≈ 2^20, so buf * dt_us_rem
  // ≤ 2^40 — comfortably below 2^64. dt_s is dt / USEC_PER_SEC, so
  // buf * dt_s could theoretically overflow only if the channel
  // survives ~3 million years of wall-clock with a full-megabyte
  // buffer the entire time. Not a realistic scenario; uint64
  // wraparound here is left as a documented (impossible-to-hit) edge.
  const uint64_t dt_s = dt / USEC_PER_SEC;
  const uint64_t dt_us_rem = dt % USEC_PER_SEC;
  cs.metrics.memoryByteSeconds += buf * dt_s;
  // Sub-second portion accumulates in the remainder; overflow into
  // byte-seconds whenever the remainder crosses USEC_PER_SEC. The
  // remainder is bounded above by buf * USEC_PER_SEC + USEC_PER_SEC
  // < 2^41, so adding can't itself wrap; we only need one carry into
  // byte-seconds.
  cs.metricsMemRemainderUs += buf * dt_us_rem;
  if (cs.metricsMemRemainderUs >= USEC_PER_SEC) {
    cs.metrics.memoryByteSeconds += cs.metricsMemRemainderUs / USEC_PER_SEC;
    cs.metricsMemRemainderUs %= USEC_PER_SEC;
  }
}

std::optional<Rudp::ChannelMetrics>
Rudp::metricsFor(const SockAddr& peer, uint32_t channel_id) const {
  const auto* cs = findChannel(peer, channel_id);
  if (!cs) return std::nullopt;
  return cs->metrics;
}

void Rudp::destroyChannel(const SockAddr& peer, uint32_t channel_id,
                          ChannelState& cs, CloseReason reason) {
  // 1) Final metrics integral update so the listener's onClosed sees
  //    a closed-out memoryByteSeconds when it calls metricsFor().
  updateMemoryIntegral(cs);
  // 2) handler->onClosed fires exactly once per registered channel.
  //    Move the shared_ptr out before invoking so we can drop
  //    Rudp's ref AFTER the call returns (the handler can rely on
  //    being alive during onClosed) without the call site needing
  //    to do its own ownership dance. (peer, cid) parameters are
  //    unused here — the handler reads them via its protected
  //    accessors, which were injected at registration.
  if (auto handler = std::move(cs.handler)) {
    cs.handler.reset();
    cs.handlerEstablished = false;
    handler->onClosed(reason);
    // handler shared_ptr drops here when the local goes out of
    // scope, releasing Rudp's ref. App-side refs (if any) survive.
  }
  (void)peer;
  (void)channel_id;
}

std::ostream& operator<<(std::ostream& os, Rudp::CloseReason r) {
  switch (r) {
  case Rudp::CloseReason::APPLICATION:      return os << "APPLICATION";
  case Rudp::CloseReason::IDLE:             return os << "IDLE";
  case Rudp::CloseReason::HANDSHAKE_FAILED: return os << "HANDSHAKE_FAILED";
  case Rudp::CloseReason::REORDER_BREACH:   return os << "REORDER_BREACH";
  case Rudp::CloseReason::PEER_CLOSED:      return os << "PEER_CLOSED";
  case Rudp::CloseReason::PEER_RESTART:     return os << "PEER_RESTART";
  }
  return os << "?(" << static_cast<int>(r) << ")";
}

std::ostream& operator<<(std::ostream& os, Rudp::AbuseSignal s) {
  switch (s) {
  case Rudp::AbuseSignal::FORGED_SESSION_TOKEN_CHANNEL:
    return os << "FORGED_SESSION_TOKEN_CHANNEL";
  case Rudp::AbuseSignal::FORGED_SESSION_TOKEN_HS_CLOSE:
    return os << "FORGED_SESSION_TOKEN_HS_CLOSE";
  case Rudp::AbuseSignal::REORDER_CAP_BREACH:
    return os << "REORDER_CAP_BREACH";
  case Rudp::AbuseSignal::CRC_FAILURE:
    return os << "CRC_FAILURE";
  case Rudp::AbuseSignal::STRAY_HS_CLOSE:
    return os << "STRAY_HS_CLOSE";
  case Rudp::AbuseSignal::STRAY_CHANNEL_PACKET:
    return os << "STRAY_CHANNEL_PACKET";
  case Rudp::AbuseSignal::TRUNCATED_PACKET:
    return os << "TRUNCATED_PACKET";
  }
  return os << "?(" << static_cast<int>(s) << ")";
}

// ===========================================================================
// Local state management — close / gc
// ===========================================================================

void Rudp::closeChannel(const SockAddr& peer, uint32_t channel_id,
                        CloseReason reason,
                        std::chrono::microseconds timeout) {
  auto pit = peers_.find(peer);
  if (pit == peers_.end())
    return;
  auto& peerState = pit->second;
  auto cit = peerState.channels.find(channel_id);
  if (cit == peerState.channels.end())
    return;
  ChannelState& cs = cit->second;

  // Graceful "drain then close" path: timeout > 0 and channel is
  // ESTABLISHED. Mark the channel so the pulse loop fires HS_CLOSE
  // when sendBuf empties (or the deadline elapses, whichever comes
  // first). For non-ESTABLISHED channels, graceful is meaningless
  // (no session token, no reliable byte stream to drain) — fall
  // through to immediate teardown. A second closeChannel call on
  // an already-marked channel escalates to immediate (RST).
  if (timeout.count() > 0 &&
      cs.handshakeState == HandshakeState::ESTABLISHED &&
      !cs.closeOnDrain) {
    cs.closeOnDrain = true;
    cs.closeOnDrainReason = reason;
    cs.closeOnDrainDeadlineUs = currentTimeUs_ +
      static_cast<uint64_t>(timeout.count());
    LOGTRACE << "closeChannel deferred (drain then close)"
             << SVAR(peer) << VAR(channel_id) << VAR(reason)
             << VAR(timeout.count());
    return;
  }

  LOGTRACE << "closeChannel" << SVAR(peer) << VAR(channel_id) << VAR(reason);
  // Best-effort teardown hint to the peer. Only meaningful once both
  // sides agree on a session_token — emit for ESTABLISHED only. Other
  // states have no mutually-known token, so silently drop as before
  // (the peer's handshake retry / idle-GC will notice on its own).
  if (cs.handshakeState == HandshakeState::ESTABLISHED) {
    emitHandshakeClose(peer, channel_id, cs); // charges bytesSent internally
  }
  // Centralized teardown: final integral update + Listener::onClosed,
  // done before erase so the listener can call metricsFor() to read
  // final values. The reason is forwarded to the listener.
  destroyChannel(peer, channel_id, cs, reason);
  peerState.channels.erase(cit);
  if (peerState.channels.empty()) {
    peers_.erase(pit);
  }
}

size_t Rudp::gc(std::chrono::microseconds idleThreshold) {
  const uint64_t thresholdUs = static_cast<uint64_t>(idleThreshold.count());
  size_t evicted = 0;

  for (auto pit = peers_.begin(); pit != peers_.end();) {
    auto& peerState = pit->second;

    for (auto cit = peerState.channels.begin();
         cit != peerState.channels.end();) {
      ChannelState& cs = cit->second;
      const uint64_t age = (currentTimeUs_ > cs.lastActivityUs)
                             ? (currentTimeUs_ - cs.lastActivityUs)
                             : 0;
      if (age >= thresholdUs) {
        LOGTRACE << "gc evict" << SVAR(pit->first) << VAR(cit->first)
                 << VAR(age);
        destroyChannel(pit->first, cit->first, cs, CloseReason::IDLE);
        cit = peerState.channels.erase(cit);
        ++evicted;
      } else {
        ++cit;
      }
    }

    if (peerState.channels.empty()) {
      pit = peers_.erase(pit);
    } else {
      ++pit;
    }
  }
  return evicted;
}

// ===========================================================================
// Channel state lookup / creation
// ===========================================================================

Rudp::ChannelState* Rudp::findChannel(const SockAddr& peer,
                                      uint32_t channel_id) {
  auto pit = peers_.find(peer);
  if (pit == peers_.end())
    return nullptr;
  auto cit = pit->second.channels.find(channel_id);
  return cit == pit->second.channels.end() ? nullptr : &cit->second;
}

const Rudp::ChannelState* Rudp::findChannel(const SockAddr& peer,
                                            uint32_t channel_id) const {
  auto pit = peers_.find(peer);
  if (pit == peers_.end())
    return nullptr;
  auto cit = pit->second.channels.find(channel_id);
  return cit == pit->second.channels.end() ? nullptr : &cit->second;
}

Rudp::ChannelState* Rudp::getOrCreateChannel(const SockAddr& peer,
                                             uint32_t channel_id) {
  auto& peerState = peers_[peer]; // creates if absent
  auto cit = peerState.channels.find(channel_id);
  if (cit != peerState.channels.end()) {
    return &cit->second;
  }
  // Channel cap check before allocating a new one
  if (peerState.channels.size() >= config_.maxChannelsPerPeer) {
    LOGDEBUG << "channel cap reached for peer" << SVAR(peer)
             << VAR(peerState.channels.size());
    // If we just created an empty PeerState, and this is its first attempted
    // channel which we're rejecting, leave the empty PeerState behind — the
    // GC will clean it up. Cheap.
    return nullptr;
  }
  auto& cs = peerState.channels[channel_id];
  cs.lastActivityUs = currentTimeUs_;
  // Anchor the memory-integral clock at creation so the first
  // updateMemoryIntegral on this channel computes a sensible dt.
  // promoteToEstablished re-anchors at the ESTABLISHED transition so
  // the integral effectively measures post-handshake lifetime; the
  // pre-handshake interval contributes zero to memoryByteSeconds.
  cs.metricsLastUpdateUs = currentTimeUs_;
  return &cs;
}

// ===========================================================================
// Cryptographic-ish helpers
// ===========================================================================

uint64_t Rudp::deriveSessionToken(uint64_t na, uint64_t nb) {
  // v0: simple XOR. Both sides need both nonces to compute it; an
  // off-path attacker who didn't see one of them (because it was in
  // a packet sent to the legitimate IP) cannot reconstruct. v0+ may
  // strengthen this by mixing in channel_id and a domain separator.
  return na ^ nb;
}

uint32_t Rudp::computePorosity(const ChannelState& cs) const {
  // Bit i set means msg_id (solidAck + 1 + i) has been received and is
  // sitting in the reorder buffer. Window covers solidAck+1..solidAck+32.
  uint32_t porosity = 0;
  if (cs.reorderBuf.empty())
    return 0;
  // std::map is ordered, so we can iterate from the lower bound.
  auto begin = cs.reorderBuf.upper_bound(cs.solidAck);
  for (auto it = begin; it != cs.reorderBuf.end(); ++it) {
    const uint32_t id = it->first;
    if (id <= cs.solidAck)
      continue; // shouldn't happen
    const uint32_t offset = id - cs.solidAck - 1;
    if (offset >= 32)
      break; // out of window
    porosity |= (uint32_t{1} << offset);
  }
  return porosity;
}

bool Rudp::channelHasSomethingToSay(const ChannelState& cs) const {
  if (!cs.sendBuf.empty())
    return true;
  if (!cs.pendingUnreliable.empty())
    return true;
  if (!cs.hasSentAnything) {
    // First-ever flush of an established channel: send our initial ack info.
    return true;
  }
  if (cs.solidAck != cs.lastSentSolidAck)
    return true;
  if (computePorosity(cs) != cs.lastSentPorosity)
    return true;
  return false;
}

// ===========================================================================
// Application interface — push
// ===========================================================================

bool Rudp::push(const SockAddr& peer, uint32_t channel_id, const Bytes& msg,
                bool reliable) {
  if (msg.size() > MAX_MESSAGE_SIZE) {
    LOGDEBUG << "push reject: oversize" << VAR(msg.size())
             << VAR(MAX_MESSAGE_SIZE);
    return false;
  }
  // push() does NOT create channels. The caller must have registered
  // the channel first (registerChannel for outbound; onAccept-true on
  // the inbound side). This guarantees every channel always has a
  // handler — no events get dispatched into the void.
  ChannelState* cs = findChannel(peer, channel_id);
  if (!cs) {
    LOGDEBUG << "push reject: channel not registered" << SVAR(peer)
             << VAR(channel_id);
    return false;
  }

  cs->lastActivityUs = currentTimeUs_;

  if (!reliable) {
    // Overwrite slot. Latest wins.
    cs->pendingUnreliable.assign(msg.begin(), msg.end());
    return true;
  }

  // Reliable path. If not yet established, queue for after handshake;
  // otherwise allocate a msg_id and put it in sendBuf.
  if (cs->handshakeState != HandshakeState::ESTABLISHED) {
    // Cap preEstablishedQueue at the same ceiling as sendBuf. This
    // guarantees promoteToEstablished can drain the whole queue into
    // sendBuf at handshake completion with zero overflow — otherwise
    // the drain's `break` on cap would silently drop bytes, which is
    // indistinguishable to the caller from success. A caller that
    // hits this cap gets a clean `false` return and is expected to
    // defer the write via the same back-pressure path that handles
    // an established-but-full sendBuf.
    if (cs->preEstablishedQueue.size() >=
        config_.maxReorderMessagesPerChannel) {
      LOGDEBUG << "push reject: preEstablished queue full"
               << VAR(cs->preEstablishedQueue.size());
      return false;
    }
    cs->preEstablishedQueue.push_back(msg);
    if (cs->handshakeState == HandshakeState::IDLE) {
      // Initiate the handshake: pick our nonce, stamp the time, mark
      // OPEN_SENT. The actual emit happens in the next flush().
      cs->weInitiated = true;
      cs->nonceLocal = rng_.next();
      cs->handshakeState = HandshakeState::OPEN_SENT;
      cs->handshakeRetries = 0;
      cs->lastHandshakeAttemptUs = currentTimeUs_;
    }
    return true;
  }

  // Already established: assign a msg_id and enqueue.
  // Soft cap: keep send buffer below the per-channel reorder cap so a
  // pathological sender doesn't run away. Same numeric ceiling for now.
  if (cs->sendBuf.size() >= config_.maxReorderMessagesPerChannel) {
    LOGDEBUG << "push reject: send buffer full" << VAR(cs->sendBuf.size());
    return false;
  }
  const uint32_t id = cs->nextSeq++;
  cs->sendBuf[id] = msg;
  return true;
}

// ===========================================================================
// Application interface — flush
// ===========================================================================

void Rudp::flush() {
  // Public flush API: a manual override that fires one pulse worth of
  // work right now, without consulting the deadline. Useful for
  // applications that want to push a message and immediately put it on
  // the wire without waiting for the next tick. Internally this is just
  // doPulseWork(currentTimeUs_, 1) — one packet per channel-with-data.
  doPulseWork(currentTimeUs_, 1);
}

// ===========================================================================
// Pulse machinery: time as parameter, no internal timer
//
// RUDP knows TIME but does not own a TIMER. tick() and onPacket() are the
// only two ways time advances. Both call runPulses() which checks the
// deadline and fires the appropriate amount of work.
// ===========================================================================

void Rudp::initPulseDeadlineIfNeeded(uint64_t now_us) {
  if (!pulseInitialized_) {
    pulseInitialized_ = true;
    // First call: arm the deadline AT now, so the first tick/onPacket
    // fires exactly one pulse to bootstrap the protocol. Subsequent
    // pulses follow the configured cadence.
    nextDeadlineUs_ = now_us;
  }
}

void Rudp::runPulses(uint64_t now_us) {
  initPulseDeadlineIfNeeded(now_us);

  // baseTickIntervalUs_ == 0 is the "no pacing" mode used by tests and
  // by applications that want pure reactive operation: every external
  // call fires exactly one pulse, no catch-up math, no deadline.
  if (baseTickIntervalUs_ == 0) {
    doPulseWork(now_us, 1);
    return;
  }

  if (now_us < nextDeadlineUs_) {
    // Not yet due. Cheap exit — most calls under fast external ticking
    // (e.g. 100 Hz with 100ms cadence) take this path 99 out of 100
    // times.
    return;
  }

  // How many pulse intervals have elapsed since the last pulse boundary?
  // Each elapsed interval entitles us to one packet per channel-with-data,
  // because that's the work a single pulse would have done at the
  // configured cadence. So a slow caller gets a burst proportional to
  // how long they slept.
  const uint64_t overdueUs = now_us - nextDeadlineUs_;
  size_t intervalsBudget = (overdueUs / baseTickIntervalUs_) + 1;

  // Cap to prevent runaway in case of clock jumps or a very-long-idle
  // first call. 100 packets per channel per call is plenty for any
  // realistic catch-up; protects against pathological inputs.
  static constexpr size_t MAX_PULSES_PER_CALL = 100;
  if (intervalsBudget > MAX_PULSES_PER_CALL) {
    intervalsBudget = MAX_PULSES_PER_CALL;
  }

  doPulseWork(now_us, intervalsBudget);

  // Reset the deadline to one full interval ahead of now.
  nextDeadlineUs_ = now_us + baseTickIntervalUs_;
}

void Rudp::doPulseWork(uint64_t now_us, size_t maxPacketsPerChannel) {
  // 0) Advance memory integrals for every live channel up to now_us.
  //    Done before the destroy loop so channels that are about to be
  //    GC'd see their last-window integral go in (destroyChannel
  //    re-runs updateMemoryIntegral, which becomes a no-op when
  //    metricsLastUpdateUs has already been snapped to now_us).
  for (auto& peerEntry : peers_) {
    for (auto& chEntry : peerEntry.second.channels) {
      updateMemoryIntegral(chEntry.second);
    }
  }

  // 1) Handshake retries + GC of CLOSED / idle channels.
  for (auto pit = peers_.begin(); pit != peers_.end();) {
    auto& peerState = pit->second;

    for (auto cit = peerState.channels.begin();
         cit != peerState.channels.end();) {
      ChannelState& cs = cit->second;
      bool drop = false;
      // dropReason starts at the channel's stamped closeReason —
      // that's set at the moment we transition into CLOSED (e.g.
      // reorder breach in handleChannelPacket). Idle GC and
      // handshake exhaustion below override it with their own
      // reason, since those paths discover the trigger here.
      CloseReason dropReason = cs.closeReason;

      // Idle GC
      if (now_us > cs.lastActivityUs &&
          (now_us - cs.lastActivityUs) >= channelInactivityUs_) {
        LOGTRACE << "GC idle channel" << SVAR(pit->first) << VAR(cit->first);
        drop = true;
        dropReason = CloseReason::IDLE;
      }

      // Handshake retry
      if (!drop && cs.handshakeState == HandshakeState::OPEN_SENT) {
        const uint64_t since = (now_us > cs.lastHandshakeAttemptUs)
                                 ? (now_us - cs.lastHandshakeAttemptUs)
                                 : 0;
        if (since >= handshakeRetryUs_) {
          if (cs.handshakeRetries >= config_.handshakeMaxRetries) {
            LOGDEBUG << "handshake exhausted" << SVAR(pit->first)
                     << VAR(cit->first);
            cs.handshakeState = HandshakeState::CLOSED;
            cs.closeReason = CloseReason::HANDSHAKE_FAILED;
            drop = true;
            dropReason = CloseReason::HANDSHAKE_FAILED;
          } else {
            ++cs.handshakeRetries;
            cs.lastHandshakeAttemptUs = now_us;
          }
        }
      }

      // Drop CLOSED channels eagerly. The stamped closeReason on the
      // channel (from the reorder-breach path or from handshake
      // exhaustion above) is already in dropReason.
      if (cs.handshakeState == HandshakeState::CLOSED) {
        drop = true;
      }

      // closeChannel(timeout > 0) deferred close. Fire HS_CLOSE the
      // moment sendBuf empties (graceful) OR when the deadline
      // elapses (RST fallback). pendingUnreliable is also drained
      // — unreliable bytes don't retransmit but we want them to
      // have at least one shot on the wire before we tear down.
      if (!drop && cs.closeOnDrain) {
        const bool drained =
          cs.sendBuf.empty() && cs.pendingUnreliable.empty();
        const bool timedOut = (now_us >= cs.closeOnDrainDeadlineUs);
        if (drained || timedOut) {
          if (cs.handshakeState == HandshakeState::ESTABLISHED) {
            emitHandshakeClose(pit->first, cit->first, cs);
          }
          drop = true;
          dropReason = cs.closeOnDrainReason;
          LOGTRACE << "closeOnDrain fired"
                   << SVAR(pit->first) << VAR(cit->first)
                   << VAR(drained) << VAR(timedOut);
        }
      }

      if (drop) {
        destroyChannel(pit->first, cit->first, cs, dropReason);
        cit = peerState.channels.erase(cit);
      } else {
        ++cit;
      }
    }

    if (peerState.channels.empty()) {
      pit = peers_.erase(pit);
    } else {
      ++pit;
    }
  }

  // 2) Walk all channels and emit packets, honoring the per-channel
  //    burst budget.
  for (auto& [peerAddr, peerState] : peers_) {
    for (auto& [channel_id, cs] : peerState.channels) {
      switch (cs.handshakeState) {
      case HandshakeState::IDLE:
        // No outbound action — push() promotes IDLE to OPEN_SENT,
        // and an inbound OPEN promotes IDLE directly to ACCEPT_SENT.
        break;

      case HandshakeState::OPEN_SENT:
        // (Re-)emit OPEN if this is the first attempt OR the GC pass
        // just bumped the retry counter (signaled by lastHandshake ==
        // currentTime, both of which were just set in the GC loop).
        if (cs.handshakeRetries == 0 || cs.lastHandshakeAttemptUs == now_us) {
          emitHandshake(peerAddr, channel_id, cs, HS_OPEN);
        }
        break;

      case HandshakeState::ACCEPT_SENT:
        // Peer-initiated. ACCEPT was emitted inline by handleHandshake;
        // nothing more here.
        break;

      case HandshakeState::ESTABLISHED:
        if (channelHasSomethingToSay(cs)) {
          emitChannel(peerAddr, channel_id, cs, maxPacketsPerChannel);
        }
        break;

      case HandshakeState::CLOSED:
        // Will be GC'd next pulse.
        break;
      }
    }
  }
}

// ===========================================================================
// Application interface — tick
// ===========================================================================

void Rudp::tick(uint64_t now_us) {
  currentTimeUs_ = now_us;
  runPulses(now_us);
}

// ===========================================================================
// Application interface — onPacket (inbound dispatch)
// ===========================================================================

void Rudp::onPacket(const SockAddr& peer, uint64_t key, const Bytes& payload,
                    uint64_t now_us) {
  currentTimeUs_ = now_us;
  initPulseDeadlineIfNeeded(now_us);

  // Verify the routing key actually belongs to this RUDP version.
  // (MinxStdExtensions already routed by family id; we double-check
  // version here so a mis-routed v1 packet doesn't get parsed by v0.)
  const uint16_t meta = MinxStdExtensions::metaOf(key);
  const uint8_t version = static_cast<uint8_t>((meta >> 8) & 0xFF);
  const uint8_t subproto = static_cast<uint8_t>(meta & 0xFF);

  if (version != VERSION_V0) {
    LOGDEBUG << "drop: wrong RUDP version" << VAR(version);
    return;
  }
  if (MinxStdExtensions::idOf(key) != EXTENSION_ID) {
    LOGDEBUG << "drop: wrong RUDP family id";
    return;
  }

  // Attribute the inbound wire bytes to the addressed channel BEFORE
  // CRC verification, before parsing the session_token, before
  // anything that could reject the packet. The channel_id field sits
  // at the same body offset (bytes 0..3) for both sub-protos
  // (HANDSHAKE and CHANNEL), so we can read it from the still-
  // untrusted bytes without parsing the rest. Charging here closes
  // the attack vector where an adversary deliberately corrupts
  // packets aimed at a known channel to consume bandwidth + parsing
  // CPU without being billed for it.
  //
  // Bit-flips that happen to flip channel_id to ANOTHER existing
  // channel_id mis-attribute the bytes, which is acceptable: SOME
  // channel is still being billed. Packets whose channel_id matches
  // no existing channel are not billed here — those fall through to
  // MINX's IP-level spam filter (SpamFilter), which is the correct
  // layer for charging garbage traffic that doesn't belong to any
  // RUDP channel.
  const size_t wireBytes = payload.size() + MinxStdExtensions::KEY_SIZE;
  bool inboundCharged = false;
  uint32_t probedChannelId = 0;
  bool haveProbedChannelId = false;
  if (payload.size() >= sizeof(uint32_t)) {
    ConstBuffer probe(payload);
    probedChannelId = probe.get<uint32_t>();
    haveProbedChannelId = true;
    if (ChannelState* preCs = findChannel(peer, probedChannelId)) {
      preCs->metrics.bytesReceived += wireBytes;
      inboundCharged = true;
    }
  }

  // Verify the CRC32C trailer. Corrupted packets are dropped — but
  // also fed to MINX's spam filter as a soft abuse signal: CRC32C is
  // mathematically robust on a clean wire, so a peer producing
  // recurring CRC failures is forging without bothering to compute
  // the trailer. The bytesReceived pre-charge above already happened
  // (so corrupt packets still bill the addressed channel for
  // bandwidth), independent of this signal.
  Bytes body = payload; // copy so we can truncate the trailer
  if (!verifyAndStripCrc32cTrailer(key, body)) {
    reportAbuse(peer, haveProbedChannelId ? probedChannelId : 0,
                AbuseSignal::CRC_FAILURE);
    return;
  }

  // Process the packet. Each handler returns a "novel" bool that used
  // to feed a scheduleHalvedFire() deadline tweak; that tweak only
  // shifted one pulse earlier by < base and reverted to normal
  // cadence afterwards, so it was a sub-millisecond latency micro-
  // optimization with no throughput effect. Removed. The bool return
  // is kept in the handler signatures for potential future use.
  switch (subproto) {
  case SUBPROTO_HANDSHAKE:
    (void)handleHandshakePacket(peer, body, wireBytes, inboundCharged);
    break;
  case SUBPROTO_CHANNEL:
    (void)handleChannelPacket(peer, body);
    break;
  default:
    LOGDEBUG << "drop: unknown RUDP sub-proto" << VAR(subproto);
    break;
  }

  // Run pulses if the deadline has now passed (i.e. enough time has
  // elapsed since the last call).
  runPulses(now_us);
}

// ===========================================================================
// Inbound HANDSHAKE
// ===========================================================================
//
// HANDSHAKE packets share a 5-byte header and then vary by kind:
//
//   [channel_id : uint32 BE]
//   [kind       : uint8    ]
//
// Kind = HS_OPEN / HS_ACCEPT (21-byte body total):
//   [nonce            : uint64 BE]
//   [advertised_rate  : uint32 BE]   // bytes/sec, UNLIMITED = no cap
//   [advertised_burst : uint32 BE]   // bytes, UNLIMITED = no cap
//
// Kind = HS_CLOSE (13-byte body total):
//   [session_token : uint64 BE]     // authenticates the close
//
// HS_CLOSE deliberately never auto-creates a channel and is dropped
// silently unless the named channel exists, is ESTABLISHED, and the
// session_token matches. That keeps an off-path spoofer from allocating
// channel slots or tearing down unrelated sessions.
// ===========================================================================

void Rudp::handleHandshakePacket(const SockAddr& peer, const Bytes& payload,
                                 size_t wireBytes, bool inboundCharged) {
  static constexpr size_t HANDSHAKE_HEADER_SIZE = 4 + 1;
  static constexpr size_t HANDSHAKE_OPEN_ACCEPT_BODY_SIZE =
    HANDSHAKE_HEADER_SIZE + 8 + 4 + 4; // 21
  static constexpr size_t HANDSHAKE_CLOSE_BODY_SIZE =
    HANDSHAKE_HEADER_SIZE + 8; // 13

  if (payload.size() < HANDSHAKE_HEADER_SIZE) {
    LOGDEBUG << "drop: handshake packet too short for header"
             << VAR(payload.size());
    reportAbuse(peer, /*channel_id=*/0, AbuseSignal::TRUNCATED_PACKET);
    return;
  }
  ConstBuffer buf(payload);
  const uint32_t channel_id = buf.get<uint32_t>();
  const uint8_t kind = buf.get<uint8_t>();

  // HS_CLOSE is parsed and dispatched separately because it never
  // creates a channel (unlike HS_OPEN/HS_ACCEPT which go through
  // getOrCreateChannel) and has its own wire shape.
  if (kind == HS_CLOSE) {
    if (payload.size() < HANDSHAKE_CLOSE_BODY_SIZE) {
      LOGDEBUG << "drop: HS_CLOSE packet too short" << VAR(payload.size());
      reportAbuse(peer, channel_id, AbuseSignal::TRUNCATED_PACKET);
      return;
    }
    const uint64_t session_token = buf.get<uint64_t>();
    ChannelState* cs = findChannel(peer, channel_id);
    if (!cs) {
      LOGTRACE << "drop: HS_CLOSE for unknown channel" << VAR(channel_id);
      reportAbuse(peer, channel_id, AbuseSignal::STRAY_HS_CLOSE);
      return;
    }
    // Only ESTABLISHED channels have a mutually-known session_token.
    // Anything else (IDLE, OPEN_SENT, ACCEPT_SENT, CLOSED) is either
    // a race against our own closeChannel() or a stale/spoofed
    // packet.
    if (cs->handshakeState != HandshakeState::ESTABLISHED) {
      LOGTRACE << "drop: HS_CLOSE in non-ESTABLISHED state"
               << VAR(channel_id)
               << VAR(static_cast<int>(cs->handshakeState));
      reportAbuse(peer, channel_id, AbuseSignal::STRAY_HS_CLOSE);
      return;
    }
    if (cs->sessionToken != session_token) {
      LOGTRACE << "drop: HS_CLOSE with mismatched session_token"
               << VAR(channel_id);
      // Forgery aimed at tearing down an existing session. Strong
      // signal — same severity as the CHANNEL-packet mismatch.
      reportAbuse(peer, channel_id,
                  AbuseSignal::FORGED_SESSION_TOKEN_HS_CLOSE);
      return;
    }
    LOGTRACE << "received HS_CLOSE, tearing down channel"
             << VAR(channel_id);
    // bytesReceived was already charged in onPacket via the pre-CRC
    // attribution path. The charge sits on the channel's metrics
    // before destroyChannel fires Listener::onClosed, so an
    // onClosed handler reading metricsFor() sees the close packet
    // accounted for.
    destroyChannel(peer, channel_id, *cs, CloseReason::PEER_CLOSED);
    auto pit = peers_.find(peer);
    if (pit != peers_.end()) {
      pit->second.channels.erase(channel_id);
      if (pit->second.channels.empty()) {
        peers_.erase(pit);
      }
    }
    return;
  }

  if (payload.size() < HANDSHAKE_OPEN_ACCEPT_BODY_SIZE) {
    LOGDEBUG << "drop: handshake packet too short" << VAR(payload.size());
    reportAbuse(peer, channel_id, AbuseSignal::TRUNCATED_PACKET);
    return;
  }
  const uint64_t nonce = buf.get<uint64_t>();
  const uint32_t peerRate = buf.get<uint32_t>();
  const uint32_t peerBurst = buf.get<uint32_t>();

  ChannelState* cs = getOrCreateChannel(peer, channel_id);
  if (!cs)
    return; // channel cap rejected
  cs->lastActivityUs = currentTimeUs_;

  switch (kind) {
  case HS_OPEN: {
    // Peer wants to open this channel with their nonce as N_a.
    // Our role is the receiver here: pick our N_b, derive token,
    // mark ACCEPT_SENT, emit ACCEPT in the next flush.
    switch (cs->handshakeState) {
    case HandshakeState::IDLE:
    case HandshakeState::CLOSED: {
      // Listener::onAccept is predicate AND handler factory in one.
      // Returning a non-null shared_ptr accepts and supplies the
      // handler. Returning null rejects the inbound channel
      // silently — no events fire, channel is erased.
      auto handler = listener_->onAccept(peer, channel_id);
      if (!handler) {
        LOGTRACE << "accept rejected" << VAR(channel_id);
        eraseChannelSilent(peer, channel_id);
        return;
      }
      if (!inboundCharged) {
        cs->metrics.bytesReceived += wireBytes;
      }
      cs->weInitiated = false;
      cs->nonceRemote = nonce;
      cs->nonceLocal = rng_.next();
      cs->sessionToken = deriveSessionToken(cs->nonceRemote, cs->nonceLocal);
      cs->handshakeState = HandshakeState::ACCEPT_SENT;
      cs->lastHandshakeAttemptUs = currentTimeUs_;
      initChannelBucket(*cs, peerRate, peerBurst);
      // Wire the handler now: rudp/peer/cid back-references are
      // injected, handler->onOpened() fires. After this the handler
      // can validly call rudp()->push() etc. from any subsequent
      // event method.
      wireHandler(peer, channel_id, *cs, std::move(handler));
      // Emit the ACCEPT, then ESTABLISHED.
      emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
      promoteToEstablished(peer, channel_id, *cs);
      return;
    }
    case HandshakeState::OPEN_SENT: {
      // Simultaneous open: both sides sent OPEN at roughly the same
      // time, racing. The peer's OPEN wins; we accept theirs and
      // discard our own pending OPEN. Accept predicate does NOT
      // fire here — the handler was already wired at registerChannel
      // time on our side. wireBytes was already charged by onPacket.
      cs->weInitiated = false;
      cs->nonceRemote = nonce;
      // Reuse our previously-generated nonce as N_b (don't waste it).
      cs->sessionToken = deriveSessionToken(cs->nonceRemote, cs->nonceLocal);
      cs->handshakeState = HandshakeState::ACCEPT_SENT;
      cs->lastHandshakeAttemptUs = currentTimeUs_;
      initChannelBucket(*cs, peerRate, peerBurst);
      emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
      promoteToEstablished(peer, channel_id, *cs);
      return;
    }
    case HandshakeState::ACCEPT_SENT:
    case HandshakeState::ESTABLISHED: {
      // Already accepted/established. The peer may not have received
      // our ACCEPT — re-emit it idempotently. The session_token
      // doesn't change. wireBytes already charged by onPacket.
      if (cs->nonceRemote == nonce) {
        emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
        return;
      }
      // Different N_a means a fresh OPEN attempt — likely the peer
      // restarted. The old session is dead from any stream
      // adapter's perspective: different session token, reset
      // sendBuf, reset reorder state. Fire onChannelDestroyed so
      // any pending write/read handler completes with an abort
      // error. Then re-run the accept predicate on the NEW session
      // — it's a new logical connection and deserves a fresh
      // policy decision. If accepted, reset state and continue.
      // If rejected, erase the whole channel and return (the old
      // session already got its Destroyed fire).
      destroyChannel(peer, channel_id, *cs, CloseReason::PEER_RESTART);
      auto newHandler = listener_->onAccept(peer, channel_id);
      if (!newHandler) {
        LOGTRACE << "accept rejected on peer-restart" << VAR(channel_id);
        eraseChannelSilent(peer, channel_id);
        return;
      }
      cs->weInitiated = false;
      cs->nonceRemote = nonce;
      cs->nonceLocal = rng_.next();
      cs->sessionToken = deriveSessionToken(cs->nonceRemote, cs->nonceLocal);
      cs->handshakeState = HandshakeState::ACCEPT_SENT;
      cs->lastHandshakeAttemptUs = currentTimeUs_;
      cs->sendBuf.clear();
      cs->reorderBuf.clear();
      cs->reorderBytes = 0;
      cs->solidAck = 0;
      cs->nextSeq = 1;
      cs->lastSentSolidAck = 0;
      cs->lastSentPorosity = 0;
      cs->hasSentAnything = false;
      // Reset metrics for the new session: counters and integral
      // start fresh; openedAtUs is re-stamped in promoteToEstablished.
      // The OLD session's pre-charge from onPacket was already
      // visible to the listener inside destroyChannel above; we wipe
      // it now for the NEW session.
      cs->metrics = ChannelMetrics{};
      cs->metricsLastUpdateUs = currentTimeUs_;
      cs->metricsMemRemainderUs = 0;
      // Re-attribute the OPEN packet's wire bytes to the new session.
      // onPacket pre-charged them to the old session before we knew
      // this was a peer-restart; without this re-charge they'd vanish
      // from accounting.
      cs->metrics.bytesReceived += wireBytes;
      initChannelBucket(*cs, peerRate, peerBurst);
      // Wire the new handler — fresh onOpened for the new session.
      wireHandler(peer, channel_id, *cs, std::move(newHandler));
      emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
      promoteToEstablished(peer, channel_id, *cs);
      return;
    }
    }
    break;
  }

  case HS_ACCEPT: {
    // Peer is accepting our OPEN. Their nonce is N_b. wireBytes
    // already charged by onPacket — the channel pre-existed in
    // OPEN_SENT (we sent the OPEN, so getOrCreateChannel didn't
    // create it).
    if (cs->handshakeState != HandshakeState::OPEN_SENT) {
      LOGDEBUG << "drop: ACCEPT in unexpected state"
               << VAR(static_cast<int>(cs->handshakeState));
      return;
    }
    cs->nonceRemote = nonce;
    cs->sessionToken = deriveSessionToken(cs->nonceLocal, cs->nonceRemote);
    initChannelBucket(*cs, peerRate, peerBurst);
    promoteToEstablished(peer, channel_id, *cs);
    return;
  }

  default:
    LOGDEBUG << "drop: unknown handshake kind" << VAR(kind);
    break;
  }
}

void Rudp::promoteToEstablished(const SockAddr& peer, uint32_t channel_id,
                                ChannelState& cs) {
  cs.handshakeState = HandshakeState::ESTABLISHED;
  // Stamp the metrics open-time AND start the integral clock at the
  // ESTABLISHED transition. The integral could have been ticking
  // from channel creation, but per-channel billing only cares about
  // the post-handshake lifetime — anything before is the cost of
  // opening, not of holding open. Reset metricsLastUpdateUs to
  // currentTimeUs_ so the first integral update advances from here.
  cs.metrics.openedAtUs = currentTimeUs_;
  cs.metricsLastUpdateUs = currentTimeUs_;

  // Drain any application messages pushed before the handshake
  // completed into the real send buffer. push() caps
  // preEstablishedQueue at maxReorderMessagesPerChannel, so starting
  // from an empty sendBuf we are guaranteed to fit everything — the
  // break below is a belt-and-suspenders guard, not a real drop path.
  const bool hadPending = !cs.preEstablishedQueue.empty();
  for (auto& msg : cs.preEstablishedQueue) {
    if (cs.sendBuf.size() >= config_.maxReorderMessagesPerChannel)
      break;
    const uint32_t id = cs.nextSeq++;
    cs.sendBuf[id] = std::move(msg);
  }
  cs.preEstablishedQueue.clear();

  // Single chokepoint for handler->onEstablished: every path to
  // ESTABLISHED (fresh peer accept, self-initiated-got-ACCEPT,
  // simultaneous open, peer restart after reset) flows through here.
  cs.handlerEstablished = true;
  if (cs.handler) {
    cs.handler->onEstablished();
  }

  // Wake any stream that deferred a write during handshake. The
  // onWritable callback is safe to fire even if nothing was pending;
  // the handler is expected to be a cheap "do I have pending write?
  // if so retry, else no-op." Fired AFTER onEstablished so the
  // handler's "I'm ready" hook runs first.
  if (hadPending && cs.handler) {
    cs.handler->onWritable();
  }

  // Reset the channel's stamped closeReason so a later destruction
  // doesn't accidentally inherit a stale value.
  cs.closeReason = CloseReason::APPLICATION;
  (void)peer;
  (void)channel_id;
}

// ===========================================================================
// Inbound CHANNEL
// ===========================================================================
//
// CHANNEL packet body (after the stdext routing key, which onPacket has
// already consumed):
//
//   [channel_id    : uint32 BE]
//   [session_token : uint64 BE]
//   [solid_ack     : uint32 BE]
//   [porosity      : uint32 BE]
//   [reliable_count: uint8    ]
//   reliable_count × [msg_id : uint32 BE][len : uint16 BE][bytes]
//   ... opaque unreliable bytes to end of payload ...
// ===========================================================================

void Rudp::handleChannelPacket(const SockAddr& peer, const Bytes& payload) {
  // Pre-length-check on the fixed channel header, matching minx.cpp's
  // inbound pattern. 21 = 4 + 8 + 4 + 4 + 1.
  static constexpr size_t CHANNEL_FIXED_HEADER = 4 + 8 + 4 + 4 + 1;
  if (payload.size() < CHANNEL_FIXED_HEADER) {
    LOGDEBUG << "drop: channel packet too short" << VAR(payload.size());
    reportAbuse(peer, /*channel_id=*/0, AbuseSignal::TRUNCATED_PACKET);
    return;
  }
  ConstBuffer buf(payload);
  const uint32_t channel_id = buf.get<uint32_t>();
  const uint64_t session_token = buf.get<uint64_t>();
  const uint32_t solid_ack = buf.get<uint32_t>();
  const uint32_t porosity = buf.get<uint32_t>();
  const uint8_t reliable_count = buf.get<uint8_t>();

  ChannelState* cs = findChannel(peer, channel_id);
  if (!cs) {
    LOGTRACE << "drop: channel packet for unknown channel" << VAR(channel_id);
    reportAbuse(peer, channel_id, AbuseSignal::STRAY_CHANNEL_PACKET);
    return;
  }
  if (cs->handshakeState != HandshakeState::ESTABLISHED) {
    LOGTRACE << "drop: channel packet on un-established channel"
             << VAR(static_cast<int>(cs->handshakeState));
    reportAbuse(peer, channel_id, AbuseSignal::STRAY_CHANNEL_PACKET);
    return;
  }
  if (cs->sessionToken != session_token) {
    LOGDEBUG << "drop: session_token mismatch" << VAR(channel_id);
    reportAbuse(peer, channel_id,
                AbuseSignal::FORGED_SESSION_TOKEN_CHANNEL);
    return;
  }

  cs->lastActivityUs = currentTimeUs_;
  // bytesReceived was already charged in onPacket via the pre-CRC
  // attribution path.

  bool ackedSomething = false;

  // ---- 1) Process the peer's ack info: drop confirmed entries ----

  // Cumulative ack.
  for (auto it = cs->sendBuf.begin(); it != cs->sendBuf.end();) {
    if (it->first <= solid_ack) {
      it = cs->sendBuf.erase(it);
      ackedSomething = true;
    } else {
      break;
    }
  }

  // SACK porosity.
  for (uint32_t i = 0; i < 32; ++i) {
    if ((porosity & (uint32_t{1} << i)) == 0)
      continue;
    const uint32_t id = solid_ack + 1 + i;
    if (cs->sendBuf.erase(id) > 0) {
      ackedSomething = true;
    }
  }

  // Fire onWritable BEFORE processing incoming messages and BEFORE any
  // short-circuit return below — the moment sendBuf shrank, the
  // stream's pending write may become unblocked, and we want the
  // handler to see it before any other logic on this call stack.
  // The handler is allowed (and expected) to push() more bytes back
  // into sendBuf from this callback; that's the whole point.
  if (ackedSomething && cs->handler) {
    cs->handler->onWritable();
  }

  // ---- 2) Process incoming reliable messages ----

  for (uint8_t m = 0; m < reliable_count; ++m) {
    if (buf.getRemainingBytesCount() < RELIABLE_MESSAGE_OVERHEAD) {
      LOGDEBUG << "drop: truncated reliable msg header";
      return;
    }
    const uint32_t msg_id = buf.get<uint32_t>();
    const uint16_t len = buf.get<uint16_t>();
    if (buf.getRemainingBytesCount() < len) {
      LOGDEBUG << "drop: truncated reliable msg body";
      return;
    }
    Bytes msgBytes = readSliceBytes(buf, len);

    if (msg_id <= cs->solidAck) {
      continue; // retransmit; already delivered
    }
    if (cs->reorderBuf.find(msg_id) != cs->reorderBuf.end()) {
      continue; // already buffered
    }
    cs->reorderBytes += msgBytes.size();
    cs->reorderBuf.emplace(msg_id, std::move(msgBytes));

    if (cs->reorderBuf.size() > config_.maxReorderMessagesPerChannel ||
        cs->reorderBytes > config_.maxReorderBytesPerChannel) {
      LOGDEBUG << "reorder cap breach — closing channel" << VAR(channel_id);
      // Resource attack: peer sent enough out-of-order messages to
      // overrun our reorder buffer. We're already closing the channel
      // (state -> CLOSED, GC'd next pulse); also penalize the peer's
      // IP so a follow-up handshake can't just redo it.
      reportAbuse(peer, channel_id, AbuseSignal::REORDER_CAP_BREACH);
      cs->handshakeState = HandshakeState::CLOSED;
      cs->closeReason = CloseReason::REORDER_BREACH;
      return;
    }
  }

  // ---- 3) Drain anything contiguous from the reorder buffer ----
  // Each contiguous message fires handler->onReliableMessage in order.

  deliverInOrder(peer, channel_id, *cs);

  // ---- 4) Process the unreliable tail ----

  if (buf.getRemainingBytesCount() > 0) {
    Bytes tail = buf.getRemainingBytes<Bytes>();
    if (cs->handler) {
      cs->handler->onUnreliableMessage(tail);
    }
  }
}

void Rudp::deliverInOrder(const SockAddr& peer, uint32_t channel_id,
                          ChannelState& cs) {
  // Walk the reorder buffer from the oldest entry, delivering anything
  // that's contiguous (msg_id == solidAck + 1).
  while (true) {
    auto it = cs.reorderBuf.begin();
    if (it == cs.reorderBuf.end())
      break;
    if (it->first != cs.solidAck + 1)
      break;

    if (cs.handler) {
      cs.handler->onReliableMessage(it->second);
    }
    cs.reorderBytes -= it->second.size();
    cs.solidAck = it->first;
    cs.reorderBuf.erase(it);
  }
  (void)peer;
  (void)channel_id;
}

// ===========================================================================
// Outbound emitters
// ===========================================================================

void Rudp::emitHandshake(const SockAddr& peer, uint32_t channel_id,
                         ChannelState& cs, HandshakeKind kind) {
  // Canonical MINX write pattern: pre-size the destination Bytes to
  // its max capacity (O(1) on static_vector), wrap in a Buffer, write
  // fields via put<>(), then trim to buf.getSize(). No hand-rolled
  // endian/memcpy — logkv::serializer<T> inside put<>() handles the
  // BE conversion identically to minx.cpp's send path.
  Bytes pkt;
  pkt.resize(pkt.max_size());
  Buffer buf(pkt);
  buf.put<uint64_t>(KEY_V0_HANDSHAKE);
  buf.put<uint32_t>(channel_id);
  buf.put<uint8_t>(static_cast<uint8_t>(kind));
  buf.put<uint64_t>(cs.nonceLocal);
  // Advertised per-channel token bucket parameters (see formal model
  // at top of this file). Both sides send their LOCAL configuration;
  // the effective bucket at handshake completion is min(local, peer)
  // per parameter independently.
  buf.put<uint32_t>(config_.perChannelBytesPerSecond);
  buf.put<uint32_t>(config_.perChannelBurstBytes);
  pkt.resize(buf.getSize());

  cs.lastActivityUs = currentTimeUs_;
  appendCrc32cTrailer(pkt);
  LOGTRACE << "emit handshake" << VAR(channel_id) << VAR(static_cast<int>(kind))
           << VAR(pkt.size());
  cs.metrics.bytesSent += pkt.size();
  listener_->onSend(peer, pkt);
}

// HS_CLOSE wire layout (after the 8-byte stdext routing key consumed by
// onPacket):
//
//   [channel_id    : uint32 BE]
//   [kind          : uint8    ]   // HS_CLOSE = 0x02
//   [session_token : uint64 BE]
//
// Total body: 13 bytes. No nonce, no bucket advertisements — HS_CLOSE is
// a terminal packet, there is nothing left to negotiate. The token is
// the authenticator: only the two sides of an ESTABLISHED channel know
// it, so an off-path attacker forging a close is blocked by the
// session_token check on receipt.
void Rudp::emitHandshakeClose(const SockAddr& peer, uint32_t channel_id,
                              ChannelState& cs) {
  Bytes pkt;
  pkt.resize(pkt.max_size());
  Buffer buf(pkt);
  buf.put<uint64_t>(KEY_V0_HANDSHAKE);
  buf.put<uint32_t>(channel_id);
  buf.put<uint8_t>(static_cast<uint8_t>(HS_CLOSE));
  buf.put<uint64_t>(cs.sessionToken);
  pkt.resize(buf.getSize());
  appendCrc32cTrailer(pkt);
  LOGTRACE << "emit HS_CLOSE" << VAR(channel_id) << VAR(pkt.size());
  cs.metrics.bytesSent += pkt.size();
  listener_->onSend(peer, pkt);
}

size_t Rudp::emitChannel(const SockAddr& peer, uint32_t channel_id,
                         ChannelState& cs, size_t maxPackets) {
  if (maxPackets == 0)
    return 0;

  const uint32_t porosity = computePorosity(cs);

  // Burst loop: emit up to `maxPackets` packets in one call. Each packet
  // picks up where the previous one left off in sendBuf, via the local
  // cursor `it`. Same channel header (ack info, session_token, etc.) on
  // every packet — the receiver's state hasn't changed during the burst,
  // so the ack info is the same. The unreliable tail goes only on the
  // FIRST packet of the burst.
  auto it = cs.sendBuf.begin();
  size_t packetsEmitted = 0;

  while (packetsEmitted < maxPackets) {
    // Refill the bucket to "now" and check the exhaustion latch. The
    // refill may clear an earlier latch if enough time has passed to
    // bring tokens back above zero. If it's still latched, stop the
    // burst — every prior packet in this burst already went out.
    refillChannelBucket(cs);
    if (cs.bucketExhausted) {
      LOGTRACE << "bucket exhausted" << VAR(channel_id) << VAR(packetsEmitted);
      break;
    }

    // Pass 1 — measure: figure out exactly how many messages fit in
    // this packet (and leave `budget` pointing at the bytes remaining
    // after them, which is the room available for the unreliable
    // tail). No bytes written yet; `it` is not advanced here.
    //
    // CRC_SIZE is reserved at the tail because appendCrc32cTrailer
    // runs after we serialize the body.
    const size_t headerSize =
      MinxStdExtensions::KEY_SIZE + 4 + 8 + 4 + 4 + 1; // 29
    size_t budget = MAX_PACKET_SIZE - headerSize - CRC_SIZE;
    size_t reliableCount = 0;
    auto itScan = it;
    while (itScan != cs.sendBuf.end() &&
           reliableCount < MAX_RELIABLE_PER_PACKET) {
      const size_t needed = RELIABLE_MESSAGE_OVERHEAD + itScan->second.size();
      if (needed > budget)
        break;
      budget -= needed;
      ++reliableCount;
      ++itScan;
    }

    // Pass 2 — write: canonical MINX Buffer write. Knowing reliableCount
    // up front means we don't need a placeholder-and-patch trick for
    // the count byte; we just write it at its natural position.
    Bytes pkt;
    pkt.resize(pkt.max_size());
    Buffer buf(pkt);
    buf.put<uint64_t>(KEY_V0_CHANNEL);
    buf.put<uint32_t>(channel_id);
    buf.put<uint64_t>(cs.sessionToken);
    buf.put<uint32_t>(cs.solidAck);
    buf.put<uint32_t>(porosity);
    buf.put<uint8_t>(static_cast<uint8_t>(reliableCount));

    for (auto cit = it; cit != itScan; ++cit) {
      const auto& [id, body] = *cit;
      buf.put<uint32_t>(id);
      buf.put<uint16_t>(static_cast<uint16_t>(body.size()));
      buf.put(std::span<const char>{body.data(), body.size()});
    }
    it = itScan; // commit the burst cursor past the messages we wrote

    // Unreliable tail goes only on the FIRST packet of the burst.
    // Subsequent packets in the same burst carry only reliable msgs.
    if (packetsEmitted == 0) {
      if (!cs.pendingUnreliable.empty()) {
        if (cs.pendingUnreliable.size() <= budget) {
          buf.put(std::span<const char>{cs.pendingUnreliable.data(),
                                        cs.pendingUnreliable.size()});
        } else {
          LOGTRACE << "unreliable dropped: no budget"
                   << VAR(cs.pendingUnreliable.size()) << VAR(budget);
        }
        cs.pendingUnreliable.clear();
      }
    }

    pkt.resize(buf.getSize());
    appendCrc32cTrailer(pkt);

    LOGTRACE << "emit channel" << VAR(channel_id) << VAR(reliableCount)
             << VAR(pkt.size()) << VAR(packetsEmitted);
    cs.metrics.bytesSent += pkt.size();
    listener_->onSend(peer, pkt);
    ++packetsEmitted;

    // Charge the bucket for this packet's bytes. If tokens hit zero,
    // the next iteration's refill+check will stop the burst. If the
    // packet overshot (cost > tokens), the overshoot is absorbed —
    // see the formal model comment for why this is deliberate.
    chargeChannelBucket(cs, pkt.size());

    // Continue the burst only if there are more reliable msgs queued.
    // (The first packet always emits — even with zero reliable msgs —
    // because it carries fresh ack info or unreliable. Subsequent
    // packets in the burst only exist to drain sendBuf faster.)
    if (it == cs.sendBuf.end())
      break;
  }

  // Only record the "last sent" ack state if we actually put a packet
  // on the wire in this call. A pure bucket-stall (packetsEmitted == 0)
  // means nothing reached the peer, so our outbound ack state is still
  // stale and the next pulse must retry.
  if (packetsEmitted > 0) {
    cs.lastSentSolidAck = cs.solidAck;
    cs.lastSentPorosity = porosity;
    cs.hasSentAnything = true;
    cs.lastActivityUs = currentTimeUs_;
  }

  return packetsEmitted;
}

} // namespace minx
