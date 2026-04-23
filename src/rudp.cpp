#include <minx/blog.h>
LOG_MODULE_DISABLED("rudp")

#include <minx/rudp/rudp.h>

#include <minx/buffer.h>

#include <algorithm>
#include <span>

namespace minx {

// ===========================================================================
// File-static helpers
// ===========================================================================
//
// Reading a variable-length slice of bytes out of the middle of a
// ConstBuffer is the one byte-shuffling primitive the AutoBuffer API
// does not expose directly: get<T>() is for fixed-size typed reads,
// getRemainingBytesSpan() / getRemainingBytes<R>() drain to end. This
// helper fills the gap, and in the process works around an AutoBuffer
// quirk: setReadPos refuses positions == backing-span end (it uses
// `r >= buf_.size()` where `>` would be correct), so when the slice
// ends exactly at the buffer's end we advance the cursor via
// getRemainingBytesSpan() — the one API that permits r_ to land on s_.
//
// The caller must have verified `buf.getRemainingBytesCount() >= len`
// before calling. No bounds check in here.
static Bytes readSliceBytes(ConstBuffer& buf, size_t len) {
  const size_t start = buf.getReadPos();
  const auto backing = buf.getBackingSpan();
  const char* first = reinterpret_cast<const char*>(backing.data() + start);
  Bytes result(first, first + len);
  const size_t newPos = start + len;
  if (newPos < backing.size()) {
    buf.setReadPos(newPos);
  } else {
    // At exact end-of-buffer. setReadPos would throw; drain instead.
    (void)buf.getRemainingBytesSpan();
  }
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

// Scale factor: 1 byte == TOKEN_SCALE units in bucketTokensScaled. We
// work in scaled integer units so that (R bytes/sec) × (Δt µs) divides
// cleanly: R × Δt_us is exactly the number of micro-bytes to add.
static constexpr uint64_t TOKEN_SCALE = 1'000'000ULL;

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

Rudp::Rudp(RudpConfig config)
    : config_(config),
      rng_(config.rngSeed != 0 ? Csprng(config.rngSeed, 0) : Csprng()) {
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

void Rudp::setSendCallback(SendFn fn) { sendFn_ = std::move(fn); }
void Rudp::setReceiveCallback(ReceiveFn fn) { receiveFn_ = std::move(fn); }

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

void Rudp::setSendBufDrainedCallback(const SockAddr& peer, uint32_t channel_id,
                                     SendBufDrainedFn fn) {
  // Create the channel if a real callback is being installed; if it's
  // a clear (empty function), only touch an existing channel.
  ChannelState* cs =
    fn ? getOrCreateChannel(peer, channel_id) : findChannel(peer, channel_id);
  if (!cs)
    return;
  cs->onSendBufDrained = std::move(fn);
}

void Rudp::setChannelDestroyedCallback(const SockAddr& peer,
                                       uint32_t channel_id,
                                       ChannelDestroyedFn fn) {
  ChannelState* cs =
    fn ? getOrCreateChannel(peer, channel_id) : findChannel(peer, channel_id);
  if (!cs)
    return;
  cs->onChannelDestroyed = std::move(fn);
}

void Rudp::fireSendBufDrained(ChannelState& cs) {
  if (cs.onSendBufDrained) {
    // Re-entry safe: the callback may call back into push() which
    // touches sendBuf, but we're not iterating sendBuf here.
    cs.onSendBufDrained();
  }
}

void Rudp::fireChannelDestroyed(ChannelState& cs) {
  if (cs.onChannelDestroyed) {
    // Move out the callback before invoking so that even if the
    // handler somehow routes back into this channel's destruction
    // again (it shouldn't), it can't re-fire.
    auto fn = std::move(cs.onChannelDestroyed);
    cs.onChannelDestroyed = nullptr;
    fn();
  }
}

void Rudp::eraseChannelSilent(const SockAddr& peer, uint32_t channel_id) {
  auto pit = peers_.find(peer);
  if (pit == peers_.end())
    return;
  pit->second.channels.erase(channel_id);
  if (pit->second.channels.empty()) {
    peers_.erase(pit);
  }
}

void Rudp::setChannelAcceptCallback(ChannelAcceptFn fn) {
  channelAcceptFn_ = std::move(fn);
}

void Rudp::setChannelOpenedCallback(ChannelOpenedFn fn) {
  channelOpenedFn_ = std::move(fn);
}

// ===========================================================================
// Local state management — close / gc
// ===========================================================================

void Rudp::close(const SockAddr& peer, uint32_t channel_id) {
  auto pit = peers_.find(peer);
  if (pit == peers_.end())
    return;
  auto& peerState = pit->second;
  auto cit = peerState.channels.find(channel_id);
  if (cit == peerState.channels.end())
    return;
  LOGTRACE << "close" << SVAR(peer) << VAR(channel_id);
  // Best-effort teardown hint to the peer. Only meaningful once both
  // sides agree on a session_token — emit for ESTABLISHED only. Other
  // states have no mutually-known token, so silently drop as before
  // (the peer's handshake retry / idle-GC will notice on its own).
  if (cit->second.handshakeState == HandshakeState::ESTABLISHED) {
    emitHandshakeClose(peer, channel_id, cit->second.sessionToken);
  }
  // Fire the destroyed callback BEFORE erase so the callback still
  // has a live ChannelState reference if it needs to inspect anything.
  fireChannelDestroyed(cit->second);
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
        fireChannelDestroyed(cs);
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
  ChannelState* cs = getOrCreateChannel(peer, channel_id);
  if (!cs) {
    return false; // channel cap exhausted
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
  if (!sendFn_)
    return;
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
  if (!sendFn_)
    return;

  // 1) Handshake retries + GC of CLOSED / idle channels.
  for (auto pit = peers_.begin(); pit != peers_.end();) {
    auto& peerState = pit->second;

    for (auto cit = peerState.channels.begin();
         cit != peerState.channels.end();) {
      ChannelState& cs = cit->second;
      bool drop = false;

      // Idle GC
      if (now_us > cs.lastActivityUs &&
          (now_us - cs.lastActivityUs) >= channelInactivityUs_) {
        LOGTRACE << "GC idle channel" << SVAR(pit->first) << VAR(cit->first);
        drop = true;
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
            drop = true;
          } else {
            ++cs.handshakeRetries;
            cs.lastHandshakeAttemptUs = now_us;
          }
        }
      }

      // Drop CLOSED channels eagerly
      if (cs.handshakeState == HandshakeState::CLOSED) {
        drop = true;
      }

      if (drop) {
        fireChannelDestroyed(cs);
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

  // Process the packet. Each handler returns a "novel" bool that used
  // to feed a scheduleHalvedFire() deadline tweak; that tweak only
  // shifted one pulse earlier by < base and reverted to normal
  // cadence afterwards, so it was a sub-millisecond latency micro-
  // optimization with no throughput effect. Removed. The bool return
  // is kept in the handler signatures for potential future use.
  switch (subproto) {
  case SUBPROTO_HANDSHAKE:
    (void)handleHandshakePacket(peer, payload);
    break;
  case SUBPROTO_CHANNEL:
    (void)handleChannelPacket(peer, payload);
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

bool Rudp::handleHandshakePacket(const SockAddr& peer, const Bytes& payload) {
  static constexpr size_t HANDSHAKE_HEADER_SIZE = 4 + 1;
  static constexpr size_t HANDSHAKE_OPEN_ACCEPT_BODY_SIZE =
    HANDSHAKE_HEADER_SIZE + 8 + 4 + 4; // 21
  static constexpr size_t HANDSHAKE_CLOSE_BODY_SIZE =
    HANDSHAKE_HEADER_SIZE + 8; // 13

  if (payload.size() < HANDSHAKE_HEADER_SIZE) {
    LOGDEBUG << "drop: handshake packet too short for header"
             << VAR(payload.size());
    return false;
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
      return false;
    }
    const uint64_t session_token = buf.get<uint64_t>();
    ChannelState* cs = findChannel(peer, channel_id);
    if (!cs) {
      LOGTRACE << "drop: HS_CLOSE for unknown channel" << VAR(channel_id);
      return false;
    }
    // Only ESTABLISHED channels have a mutually-known session_token.
    // Anything else (IDLE, OPEN_SENT, ACCEPT_SENT, CLOSED) is either
    // a race against our own close() or a stale/spoofed packet; drop.
    if (cs->handshakeState != HandshakeState::ESTABLISHED) {
      LOGTRACE << "drop: HS_CLOSE in non-ESTABLISHED state"
               << VAR(channel_id)
               << VAR(static_cast<int>(cs->handshakeState));
      return false;
    }
    if (cs->sessionToken != session_token) {
      LOGTRACE << "drop: HS_CLOSE with mismatched session_token"
               << VAR(channel_id);
      return false;
    }
    LOGTRACE << "received HS_CLOSE, tearing down channel"
             << VAR(channel_id);
    fireChannelDestroyed(*cs);
    auto pit = peers_.find(peer);
    if (pit != peers_.end()) {
      pit->second.channels.erase(channel_id);
      if (pit->second.channels.empty()) {
        peers_.erase(pit);
      }
    }
    return true; // novel: channel torn down by peer
  }

  if (payload.size() < HANDSHAKE_OPEN_ACCEPT_BODY_SIZE) {
    LOGDEBUG << "drop: handshake packet too short" << VAR(payload.size());
    return false;
  }
  const uint64_t nonce = buf.get<uint64_t>();
  const uint32_t peerRate = buf.get<uint32_t>();
  const uint32_t peerBurst = buf.get<uint32_t>();

  ChannelState* cs = getOrCreateChannel(peer, channel_id);
  if (!cs)
    return false; // channel cap rejected
  cs->lastActivityUs = currentTimeUs_;

  switch (kind) {
  case HS_OPEN: {
    // Peer wants to open this channel with their nonce as N_a.
    // Our role is the receiver here: pick our N_b, derive token,
    // mark ACCEPT_SENT, emit ACCEPT in the next flush.
    switch (cs->handshakeState) {
    case HandshakeState::IDLE:
    case HandshakeState::CLOSED: {
      // Apply the accept predicate BEFORE touching any state. If
      // the app says no, erase the freshly-created channel and
      // return without firing Destroyed — the channel was only
      // ever a proposal, the app never owned it.
      if (channelAcceptFn_ && !channelAcceptFn_(peer, channel_id)) {
        LOGTRACE << "accept rejected" << VAR(channel_id);
        eraseChannelSilent(peer, channel_id);
        return false; // not novel: silent drop
      }
      cs->weInitiated = false;
      cs->nonceRemote = nonce;
      cs->nonceLocal = rng_.next();
      cs->sessionToken = deriveSessionToken(cs->nonceRemote, cs->nonceLocal);
      cs->handshakeState = HandshakeState::ACCEPT_SENT;
      cs->lastHandshakeAttemptUs = currentTimeUs_;
      initChannelBucket(*cs, peerRate, peerBurst);
      // Emit the ACCEPT immediately. After this, ESTABLISHED.
      emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
      promoteToEstablished(peer, channel_id, *cs);
      return true; // novel: state transition + ACCEPT sent
    }
    case HandshakeState::OPEN_SENT: {
      // Simultaneous open: both sides sent OPEN at roughly the same
      // time, racing. The first OPEN to arrive wins. We treat the
      // peer's OPEN as authoritative and switch roles: discard our
      // own pending OPEN, accept theirs. Accept predicate does NOT
      // fire here — we already committed on our side by calling
      // push(); the app decided at push time.
      cs->weInitiated = false;
      cs->nonceRemote = nonce;
      // Reuse our previously-generated nonce as N_b (don't waste it).
      cs->sessionToken = deriveSessionToken(cs->nonceRemote, cs->nonceLocal);
      cs->handshakeState = HandshakeState::ACCEPT_SENT;
      cs->lastHandshakeAttemptUs = currentTimeUs_;
      initChannelBucket(*cs, peerRate, peerBurst);
      emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
      promoteToEstablished(peer, channel_id, *cs);
      return true; // novel: state transition + ACCEPT sent
    }
    case HandshakeState::ACCEPT_SENT:
    case HandshakeState::ESTABLISHED: {
      // Already accepted/established. The peer may not have received
      // our ACCEPT — re-emit it idempotently. The session_token
      // doesn't change.
      if (cs->nonceRemote == nonce) {
        emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
        return false; // duplicate OPEN, no novelty
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
      fireChannelDestroyed(*cs);
      if (channelAcceptFn_ && !channelAcceptFn_(peer, channel_id)) {
        LOGTRACE << "accept rejected on peer-restart" << VAR(channel_id);
        eraseChannelSilent(peer, channel_id);
        return true; // novel: old session destroyed
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
      initChannelBucket(*cs, peerRate, peerBurst);
      emitHandshake(peer, channel_id, *cs, HS_ACCEPT);
      promoteToEstablished(peer, channel_id, *cs);
      return true; // novel: peer restarted, full reset
    }
    }
    break;
  }

  case HS_ACCEPT: {
    // Peer is accepting our OPEN. Their nonce is N_b.
    if (cs->handshakeState != HandshakeState::OPEN_SENT) {
      LOGDEBUG << "drop: ACCEPT in unexpected state"
               << VAR(static_cast<int>(cs->handshakeState));
      return false;
    }
    cs->nonceRemote = nonce;
    cs->sessionToken = deriveSessionToken(cs->nonceLocal, cs->nonceRemote);
    initChannelBucket(*cs, peerRate, peerBurst);
    promoteToEstablished(peer, channel_id, *cs);
    return true; // novel: ESTABLISHED transition + sendBuf has data
  }

  default:
    LOGDEBUG << "drop: unknown handshake kind" << VAR(kind);
    break;
  }
  return false;
}

void Rudp::promoteToEstablished(const SockAddr& peer, uint32_t channel_id,
                                ChannelState& cs) {
  cs.handshakeState = HandshakeState::ESTABLISHED;
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

  // Wake any stream that deferred a write during handshake. The
  // drain callback is safe to fire even if nothing was pending; the
  // stream handler is expected to be a cheap "do I have pending
  // write? if so retry, else no-op."
  if (hadPending) {
    fireSendBufDrained(cs);
  }

  // Single chokepoint for the Opened event: every path to ESTABLISHED
  // — fresh peer accept, self-initiated-got-ACCEPT, simultaneous open,
  // peer restart after reset — comes through here. Fire the global
  // lifecycle callback so the app can install per-channel hooks,
  // construct a RudpStream, etc.
  if (channelOpenedFn_) {
    channelOpenedFn_(peer, channel_id);
  }
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

bool Rudp::handleChannelPacket(const SockAddr& peer, const Bytes& payload) {
  // Pre-length-check on the fixed channel header, matching minx.cpp's
  // inbound pattern. 21 = 4 + 8 + 4 + 4 + 1.
  static constexpr size_t CHANNEL_FIXED_HEADER = 4 + 8 + 4 + 4 + 1;
  if (payload.size() < CHANNEL_FIXED_HEADER) {
    LOGDEBUG << "drop: channel packet too short" << VAR(payload.size());
    return false;
  }
  ConstBuffer buf(payload);
  const uint32_t channel_id = buf.get<uint32_t>();
  const uint64_t session_token = buf.get<uint64_t>();
  const uint32_t solid_ack = buf.get<uint32_t>();
  const uint32_t porosity = buf.get<uint32_t>();
  const uint8_t reliable_count = buf.get<uint8_t>();

  ChannelState* cs = findChannel(peer, channel_id);
  if (!cs) {
    // Unknown channel. Drop — handshake must come first to establish
    // the session_token. This also defends against state-DoS via
    // forged channel_ids.
    LOGTRACE << "drop: channel packet for unknown channel" << VAR(channel_id);
    return false;
  }
  if (cs->handshakeState != HandshakeState::ESTABLISHED) {
    LOGTRACE << "drop: channel packet on un-established channel"
             << VAR(static_cast<int>(cs->handshakeState));
    return false;
  }
  if (cs->sessionToken != session_token) {
    LOGDEBUG << "drop: session_token mismatch" << VAR(channel_id);
    return false;
  }

  cs->lastActivityUs = currentTimeUs_;

  // Track two independent kinds of novelty:
  //
  //   ackedSomething  — the peer's ack info erased at least one entry
  //                     from our sendBuf. This is the "write-path
  //                     back-pressure relieved" signal and drives
  //                     onSendBufDrained.
  //
  //   receivedNew     — we buffered a message we hadn't seen before.
  //                     This is the "receiver has something new to
  //                     ack" signal; it is NOT back-pressure relief
  //                     and must NOT wake a pending write.
  //
  // The bool return (OR of the two) is legacy: it used to drive a
  // deadline-halving tweak in onPacket that's since been removed. It
  // remains in the handler signature for potential future use.
  bool ackedSomething = false;
  bool receivedNew = false;

  // ---- 1) Process the peer's ack info: drop confirmed entries ----

  // Cumulative ack: drop everything in sendBuf with msg_id <= solid_ack.
  for (auto it = cs->sendBuf.begin(); it != cs->sendBuf.end();) {
    if (it->first <= solid_ack) {
      it = cs->sendBuf.erase(it);
      ackedSomething = true;
    } else {
      break; // map is ordered; once we exceed solid_ack we're done
    }
  }

  // SACK porosity: drop entries whose corresponding bit is set.
  for (uint32_t i = 0; i < 32; ++i) {
    if ((porosity & (uint32_t{1} << i)) == 0)
      continue;
    const uint32_t id = solid_ack + 1 + i;
    if (cs->sendBuf.erase(id) > 0) {
      ackedSomething = true;
    }
  }

  // Fire the drain callback BEFORE processing incoming messages and
  // BEFORE returning on any short/truncated path — the moment sendBuf
  // shrank, the stream's pending write may become unblocked, and we
  // want it to run before any other logic on this call stack. The
  // callback is allowed (and expected) to call push() to stuff more
  // bytes back into sendBuf; that's the whole point.
  if (ackedSomething) {
    fireSendBufDrained(*cs);
  }

  // ---- 2) Process incoming reliable messages ----

  for (uint8_t m = 0; m < reliable_count; ++m) {
    if (buf.getRemainingBytesCount() < RELIABLE_MESSAGE_OVERHEAD) {
      LOGDEBUG << "drop: truncated reliable msg header";
      return ackedSomething || receivedNew;
    }
    const uint32_t msg_id = buf.get<uint32_t>();
    const uint16_t len = buf.get<uint16_t>();
    if (buf.getRemainingBytesCount() < len) {
      LOGDEBUG << "drop: truncated reliable msg body";
      return ackedSomething || receivedNew;
    }
    Bytes msgBytes = readSliceBytes(buf, len);

    if (msg_id <= cs->solidAck) {
      // Already delivered; this is a retransmit from the peer. Drop.
      // NOT novel — this msg is already covered by previously-sent acks.
      continue;
    }
    if (cs->reorderBuf.find(msg_id) != cs->reorderBuf.end()) {
      // Already buffered out-of-order. NOT novel — the porosity bit for
      // this msg is already set in our outbound state, the peer just
      // hasn't received our ack yet (or is retransmitting because they
      // didn't see our ack).
      continue;
    }
    // New message. Buffer it. The reorder buffer cap is enforced after
    // insertion; if we breach the cap, the channel is reset (DoS defense).
    cs->reorderBytes += msgBytes.size();
    cs->reorderBuf.emplace(msg_id, std::move(msgBytes));
    receivedNew = true; // we have something new to ack

    if (cs->reorderBuf.size() > config_.maxReorderMessagesPerChannel ||
        cs->reorderBytes > config_.maxReorderBytesPerChannel) {
      LOGDEBUG << "reorder cap breach — closing channel" << VAR(channel_id);
      cs->handshakeState = HandshakeState::CLOSED;
      return ackedSomething || receivedNew;
    }
  }

  // ---- 3) Drain anything contiguous from the reorder buffer ----

  deliverInOrder(peer, channel_id, *cs);

  // ---- 4) Process the unreliable tail ----
  //
  // Whatever bytes remain in the payload after the reliable section
  // are the unreliable blob. No length prefix; "the rest of the packet."

  if (buf.getRemainingBytesCount() > 0) {
    Bytes tail = buf.getRemainingBytes<Bytes>();
    if (receiveFn_) {
      receiveFn_(peer, channel_id, tail, /*reliable=*/false);
    }
    // Receiving unreliable data isn't itself novel for outbound state —
    // unreliable doesn't get acked, so there's nothing new for us to
    // tell the peer. Don't flag novelty for unreliable arrivals.
  }

  return ackedSomething || receivedNew;
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

    if (receiveFn_) {
      receiveFn_(peer, channel_id, it->second, /*reliable=*/true);
    }
    cs.reorderBytes -= it->second.size();
    cs.solidAck = it->first;
    cs.reorderBuf.erase(it);
  }
}

// ===========================================================================
// Outbound emitters
// ===========================================================================

void Rudp::emitHandshake(const SockAddr& peer, uint32_t channel_id,
                         ChannelState& cs, HandshakeKind kind) {
  if (!sendFn_)
    return;

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
  LOGTRACE << "emit handshake" << VAR(channel_id) << VAR(static_cast<int>(kind))
           << VAR(pkt.size());
  sendFn_(peer, pkt);
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
                              uint64_t session_token) {
  if (!sendFn_)
    return;
  Bytes pkt;
  pkt.resize(pkt.max_size());
  Buffer buf(pkt);
  buf.put<uint64_t>(KEY_V0_HANDSHAKE);
  buf.put<uint32_t>(channel_id);
  buf.put<uint8_t>(static_cast<uint8_t>(HS_CLOSE));
  buf.put<uint64_t>(session_token);
  pkt.resize(buf.getSize());
  LOGTRACE << "emit HS_CLOSE" << VAR(channel_id) << VAR(pkt.size());
  sendFn_(peer, pkt);
}

size_t Rudp::emitChannel(const SockAddr& peer, uint32_t channel_id,
                         ChannelState& cs, size_t maxPackets) {
  if (!sendFn_ || maxPackets == 0)
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
    const size_t headerSize =
      MinxStdExtensions::KEY_SIZE + 4 + 8 + 4 + 4 + 1; // 29
    size_t budget = MAX_PACKET_SIZE - headerSize;
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

    LOGTRACE << "emit channel" << VAR(channel_id) << VAR(reliableCount)
             << VAR(pkt.size()) << VAR(packetsEmitted);
    sendFn_(peer, pkt);
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
