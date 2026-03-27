#include <minx/proxy/minxproxy.h>

#include <minx/blog.h>

#include <boost/endian/conversion.hpp>

#include <algorithm>
#include <cstring>

LOG_MODULE_DISABLED("minx_proxy")

namespace minx {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;
using steady_clock = std::chrono::steady_clock;

// =====================================================================
// Construction / Destruction
// =====================================================================

MinxProxy::MinxProxy(asio::io_context& io, const tcp::endpoint& listenEp,
                     const udp::endpoint& upstreamEp,
                     const MinxProxyConfig& config)
    : io_(io), config_(config),
      upstreamAddr_(udp::endpoint(upstreamEp.address(), upstreamEp.port())),
      minx_(this, config.minxConfig),
      server_(io, listenEp, *this, MAX_UDP_BYTES, config.maxClients),
      sweepTimer_(io), rng_(std::random_device{}()),
      distrib_(1, std::numeric_limits<uint64_t>::max()) {
  LOGINFO << "proxy starting, upstream=" << upstreamEp
          << " channels=" << config.numChannels;

  // Open the Minx UDP socket on an ephemeral port.
  minx_.openSocket(upstreamEp.address(), 0, io, io);

  // Initialize and handshake all channels.
  channels_.resize(config_.numChannels);
  for (size_t i = 0; i < channels_.size(); ++i) {
    handshakeChannel(i);
  }

  scheduleSweep();
}

MinxProxy::~MinxProxy() { stop(); }

void MinxProxy::stop() {
  sweepTimer_.cancel();
  server_.stop();
  minx_.closeSocket(true);
}

size_t MinxProxy::readyChannelCount() const {
  size_t count = 0;
  for (auto& ch : channels_) {
    if (ch.state == Channel::State::READY)
      ++count;
  }
  return count;
}

// =====================================================================
// Channel Management
// =====================================================================

void MinxProxy::handshakeChannel(size_t idx) {
  auto& ch = channels_[idx];
  uint64_t gpw = minx_.generatePassword() & ~LOSS_BIT;
  ch.state = Channel::State::HANDSHAKING;
  ch.spendable = 0;
  ch.sentGPassword = gpw;
  ch.sentAt = steady_clock::now();
  pendingResponses_[gpw] = {nullptr, 0, idx, ch.sentAt, MINX_GET_INFO};
  minx_.sendGetInfo(upstreamAddr_, {0, gpw, {}});
  LOGTRACE << "handshakeChannel" << VAR(idx) << VAR(HEXU64(gpw));
}

size_t MinxProxy::findReadyChannel() const {
  for (size_t i = 0; i < channels_.size(); ++i) {
    if (channels_[i].state == Channel::State::READY)
      return i;
  }
  return channels_.size();
}

void MinxProxy::onChannelReady(size_t idx, uint64_t newSpendable) {
  auto& ch = channels_[idx];
  ch.state = Channel::State::READY;
  ch.spendable = newSpendable;
  LOGTRACE << "onChannelReady" << VAR(idx) << VAR(HEXU64(newSpendable));
  tryProcessQueue();
}

void MinxProxy::tryProcessQueue() {
  while (!queue_.empty()) {
    size_t chIdx = findReadyChannel();
    if (chIdx >= channels_.size())
      break;
    auto req = std::move(queue_.front());
    queue_.pop_front();
    if (req.client->isClosed())
      continue;
    parseAndForward(req.client, req.data.data(), req.data.size());
  }
}

// =====================================================================
// TcpServerHandler
// =====================================================================

void MinxProxy::onConnect(const TcpSessionPtr& session) {
  LOGDEBUG << "client connected" << VAR(session->label());
}

void MinxProxy::onMessage(const TcpSessionPtr& session, const uint8_t* data,
                          size_t len) {
  LOGTRACE << "onMessage" << VAR(len) << VAR(session->label());
  if (len < 2)
    return;

  uint8_t msgType = data[0];

  // Parse gpassword (at offset 2 after type+version, 8 bytes big-endian).
  uint64_t clientGPw = 0;
  if (len >= 10) {
    uint64_t gpw_be;
    std::memcpy(&gpw_be, &data[2], 8);
    clientGPw = boost::endian::big_to_native(gpw_be);
  }

  switch (msgType) {
  case MINX_GET_INFO:
    // Serve from cache if available; otherwise drop.
    if (hasCachedInfo()) {
      buildAndSendInfo(session, clientGPw);
    } else {
      LOGDEBUG << "no cached INFO yet, dropping GET_INFO";
    }
    return;

  case MINX_INIT:
    // Swallowed — not forwarded to upstream.
    return;

  default:
    break;
  }

  if (shouldDropForward())
    return; // simulated forward-path loss

  parseAndForward(session, data, len);
}

void MinxProxy::onDisconnect(const TcpSessionPtr& session) {
  LOGDEBUG << "client disconnected" << VAR(session->label());
}

// =====================================================================
// Parsing and Forwarding
// =====================================================================

static uint64_t readBE64(const uint8_t* p) {
  uint64_t v;
  std::memcpy(&v, p, 8);
  return boost::endian::big_to_native(v);
}

bool MinxProxy::parseAndForward(const TcpSessionPtr& session,
                                const uint8_t* data, size_t len) {
  if (len < 2)
    return true; // drop silently, don't queue

  uint8_t msgType = data[0];
  uint8_t version = data[1];

  switch (msgType) {
  case MINX_MESSAGE: {
    if (len < MinxMessage::SIZE + 1)
      return true; // malformed, drop
    uint64_t clientGPw = readBE64(&data[2]);
    uint64_t clientSPw = readBE64(&data[10]);
    Bytes payload(data + 1 + MinxMessage::SIZE, data + len);
    MinxMessage parsed{version, clientGPw, clientSPw, std::move(payload)};
    if (!filterMessage(session, parsed)) {
      session->close();
      return true; // filtered out, don't queue
    }
    forwardMessage(session, std::move(parsed));
    return true; // might have queued internally if no channel
  }
  case MINX_PROVE_WORK: {
    if (len < MinxProveWork::SIZE + 1)
      return true; // malformed, drop
    uint64_t clientGPw = readBE64(&data[2]);
    uint64_t clientSPw = readBE64(&data[10]);
    size_t off = 1 + 1 + 8 + 8; // type + version + gpassword + spassword
    Hash ckey, hdata, solution;
    std::memcpy(ckey.data(), &data[off], 32);
    off += 32;
    std::memcpy(hdata.data(), &data[off], 32);
    off += 32;
    uint64_t time = readBE64(&data[off]);
    off += 8;
    uint64_t nonce = readBE64(&data[off]);
    off += 8;
    std::memcpy(solution.data(), &data[off], 32);
    off += 32;
    std::vector<char> extraData(data + off, data + len);
    MinxProveWork parsed{version, clientGPw, clientSPw,
                         ckey,    hdata,     time,
                         nonce,   solution,  std::move(extraData)};
    if (!filterProveWork(session, parsed)) {
      session->close();
      return true;
    }
    forwardProveWork(session, std::move(parsed));
    return true;
  }
  default:
    LOGDEBUG << "unknown message type for forwarding" << VAR(msgType);
    return true; // drop, don't queue
  }
}

void MinxProxy::forwardMessage(const TcpSessionPtr& session,
                               MinxMessage&& msg) {
  size_t chIdx = findReadyChannel();
  if (chIdx >= channels_.size()) {
    if (config_.maxQueueSize > 0 && queue_.size() >= config_.maxQueueSize) {
      LOGDEBUG << "queue full, dropping MESSAGE" << VAR(queue_.size());
      return;
    }
    // Re-serialize for queueing. Build minimal raw buffer.
    std::vector<uint8_t> raw;
    raw.push_back(MINX_MESSAGE);
    raw.push_back(msg.version);
    uint64_t gpw_be = boost::endian::native_to_big(msg.gpassword);
    raw.insert(raw.end(), reinterpret_cast<uint8_t*>(&gpw_be),
               reinterpret_cast<uint8_t*>(&gpw_be) + 8);
    uint64_t spw_be = boost::endian::native_to_big(msg.spassword);
    raw.insert(raw.end(), reinterpret_cast<uint8_t*>(&spw_be),
               reinterpret_cast<uint8_t*>(&spw_be) + 8);
    raw.insert(raw.end(), msg.data.begin(), msg.data.end());
    queue_.push_back({session, msg.gpassword, std::move(raw)});
    LOGTRACE << "no ready channel, queued" << VAR(queue_.size());
    return;
  }

  auto& ch = channels_[chIdx];
  uint64_t proxyGPw = generateProxyGPassword();
  uint64_t spassword = ch.spendable;

  ch.state = Channel::State::BUSY;
  ch.sentGPassword = proxyGPw;
  ch.sentAt = steady_clock::now();
  ch.spendable = 0;

  pendingResponses_[proxyGPw] = {session, msg.gpassword, chIdx, ch.sentAt,
                                 MINX_MESSAGE};

  minx_.sendMessage(upstreamAddr_,
                    {msg.version, proxyGPw, spassword, std::move(msg.data)});
}

void MinxProxy::forwardProveWork(const TcpSessionPtr& session,
                                 MinxProveWork&& msg) {
  size_t chIdx = findReadyChannel();
  if (chIdx >= channels_.size()) {
    if (config_.maxQueueSize > 0 && queue_.size() >= config_.maxQueueSize) {
      LOGDEBUG << "queue full, dropping PROVE_WORK" << VAR(queue_.size());
      return;
    }
    // Re-serialize for queueing.
    std::vector<uint8_t> raw;
    raw.push_back(MINX_PROVE_WORK);
    raw.push_back(msg.version);
    uint64_t gpw_be = boost::endian::native_to_big(msg.gpassword);
    raw.insert(raw.end(), reinterpret_cast<uint8_t*>(&gpw_be),
               reinterpret_cast<uint8_t*>(&gpw_be) + 8);
    uint64_t spw_be = boost::endian::native_to_big(msg.spassword);
    raw.insert(raw.end(), reinterpret_cast<uint8_t*>(&spw_be),
               reinterpret_cast<uint8_t*>(&spw_be) + 8);
    raw.insert(raw.end(), msg.ckey.begin(), msg.ckey.end());
    raw.insert(raw.end(), msg.hdata.begin(), msg.hdata.end());
    uint64_t time_be = boost::endian::native_to_big(msg.time);
    raw.insert(raw.end(), reinterpret_cast<uint8_t*>(&time_be),
               reinterpret_cast<uint8_t*>(&time_be) + 8);
    uint64_t nonce_be = boost::endian::native_to_big(msg.nonce);
    raw.insert(raw.end(), reinterpret_cast<uint8_t*>(&nonce_be),
               reinterpret_cast<uint8_t*>(&nonce_be) + 8);
    raw.insert(raw.end(), msg.solution.begin(), msg.solution.end());
    raw.insert(raw.end(), msg.data.begin(), msg.data.end());
    queue_.push_back({session, msg.gpassword, std::move(raw)});
    LOGTRACE << "no ready channel, queued" << VAR(queue_.size());
    return;
  }

  auto& ch = channels_[chIdx];
  uint64_t proxyGPw = generateProxyGPassword();
  uint64_t spassword = ch.spendable;

  ch.state = Channel::State::BUSY;
  ch.sentGPassword = proxyGPw;
  ch.sentAt = steady_clock::now();
  ch.spendable = 0;

  pendingResponses_[proxyGPw] = {session, msg.gpassword, chIdx, ch.sentAt,
                                 MINX_PROVE_WORK};

  minx_.sendProveWork(upstreamAddr_,
                      {msg.version, proxyGPw, spassword, msg.ckey, msg.hdata,
                       msg.time, msg.nonce, msg.solution, std::move(msg.data)});
}

// =====================================================================
// MinxListener (upstream responses)
// =====================================================================

bool MinxProxy::isConnected(const SockAddr& /*addr*/) {
  // Accept all messages from upstream.
  return true;
}

void MinxProxy::incomingInit(const SockAddr& /*addr*/,
                             const MinxInit& /*msg*/) {
  // Upstream shouldn't send us INIT, ignore.
}

void MinxProxy::incomingGetInfo(const SockAddr& /*addr*/,
                                const MinxGetInfo& /*msg*/) {
  // Upstream shouldn't send us GET_INFO, ignore.
}

void MinxProxy::incomingInfo(const SockAddr& /*addr*/, const MinxInfo& msg) {
  LOGDEBUG << "received INFO from upstream" << VAR(HEXU64(msg.gpassword))
           << VAR(HEXU64(msg.spassword));

  // Always update the cached INFO.
  cachedInfo_.clear();
  cachedInfo_.push_back(MINX_INFO);
  cachedInfo_.push_back(msg.version);
  // Reserve 8 bytes for gpassword (filled per-client).
  cachedInfo_.resize(cachedInfo_.size() + 8, 0);
  // Reserve 8 bytes for spassword (filled per-client).
  cachedInfo_.resize(cachedInfo_.size() + 8, 0);
  // skey (32 bytes)
  cachedInfo_.insert(cachedInfo_.end(), msg.skey.begin(), msg.skey.end());
  // difficulty
  cachedInfo_.push_back(msg.difficulty);
  // data
  cachedInfo_.insert(cachedInfo_.end(), msg.data.begin(), msg.data.end());

  // Route to pending.
  auto it = pendingResponses_.find(msg.spassword);
  if (it == pendingResponses_.end())
    return;

  auto pending = it->second;
  pendingResponses_.erase(it);

  // If this was a client request (not a channel handshake), route to client.
  if (pending.client && !pending.client->isClosed()) {
    buildAndSendInfo(pending.client, pending.clientGPassword);
  }

  // Channel gets its new ticket from the server's gpassword.
  if (msg.gpassword > 0) {
    onChannelReady(pending.channelIdx, msg.gpassword);
  } else {
    // No ticket in response — re-handshake.
    handshakeChannel(pending.channelIdx);
  }
}

void MinxProxy::incomingMessage(const SockAddr& /*addr*/,
                                const MinxMessage& msg) {
  LOGTRACE << "received MESSAGE from upstream" << VAR(HEXU64(msg.gpassword))
           << VAR(HEXU64(msg.spassword));

  auto it = pendingResponses_.find(msg.spassword);
  if (it == pendingResponses_.end()) {
    LOGTRACE << "no pending for MESSAGE spassword=" << msg.spassword;
    return;
  }

  auto pending = it->second;
  pendingResponses_.erase(it);

  bool dropped = (msg.spassword & LOSS_BIT) != 0;

  if (!dropped && pending.client && !pending.client->isClosed()) {
    // Build response for client with ticket rewriting.
    std::vector<uint8_t> buf;
    buf.push_back(MINX_MESSAGE);
    buf.push_back(msg.version);
    uint64_t clientNewGPw = distrib_(rng_) & ~LOSS_BIT;
    uint64_t gpw_be = boost::endian::native_to_big(clientNewGPw);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&gpw_be),
               reinterpret_cast<uint8_t*>(&gpw_be) + 8);
    uint64_t spw_be = boost::endian::native_to_big(pending.clientGPassword);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&spw_be),
               reinterpret_cast<uint8_t*>(&spw_be) + 8);
    buf.insert(buf.end(), msg.data.begin(), msg.data.end());
    pending.client->send(buf);
  }

  // Channel always recovers its ticket, even on simulated loss.
  if (msg.gpassword > 0) {
    onChannelReady(pending.channelIdx, msg.gpassword);
  } else {
    handshakeChannel(pending.channelIdx);
  }
}

void MinxProxy::incomingProveWork(const SockAddr& /*addr*/,
                                  const MinxProveWork& msg,
                                  int /*difficulty*/) {
  LOGDEBUG << "received PROVE_WORK from upstream" << VAR(HEXU64(msg.spassword));

  auto it = pendingResponses_.find(msg.spassword);
  if (it == pendingResponses_.end())
    return;

  auto pending = it->second;
  pendingResponses_.erase(it);

  bool dropped = (msg.spassword & LOSS_BIT) != 0;

  if (!dropped && pending.client && !pending.client->isClosed()) {
    std::vector<uint8_t> buf;
    buf.push_back(MINX_PROVE_WORK);
    buf.push_back(msg.version);
    uint64_t clientNewGPw = distrib_(rng_) & ~LOSS_BIT;
    uint64_t gpw_be = boost::endian::native_to_big(clientNewGPw);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&gpw_be),
               reinterpret_cast<uint8_t*>(&gpw_be) + 8);
    uint64_t spw_be = boost::endian::native_to_big(pending.clientGPassword);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&spw_be),
               reinterpret_cast<uint8_t*>(&spw_be) + 8);
    buf.insert(buf.end(), msg.ckey.begin(), msg.ckey.end());
    buf.insert(buf.end(), msg.hdata.begin(), msg.hdata.end());
    uint64_t time_be = boost::endian::native_to_big(msg.time);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&time_be),
               reinterpret_cast<uint8_t*>(&time_be) + 8);
    uint64_t nonce_be = boost::endian::native_to_big(msg.nonce);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&nonce_be),
               reinterpret_cast<uint8_t*>(&nonce_be) + 8);
    buf.insert(buf.end(), msg.solution.begin(), msg.solution.end());
    buf.insert(buf.end(), msg.data.begin(), msg.data.end());
    pending.client->send(buf);
  }

  // Channel always recovers its ticket, even on simulated loss.
  if (msg.gpassword > 0) {
    onChannelReady(pending.channelIdx, msg.gpassword);
  } else {
    handshakeChannel(pending.channelIdx);
  }
}

// =====================================================================
// Internal
// =====================================================================

void MinxProxy::buildAndSendInfo(const TcpSessionPtr& session,
                                 uint64_t clientGPassword) {
  if (cachedInfo_.empty())
    return;

  // Copy the cached INFO and patch in the client's ticket.
  std::vector<uint8_t> buf = cachedInfo_;

  // gpassword at offset 2 — give client a fresh one (protocol compat).
  uint64_t freshGPw = distrib_(rng_);
  uint64_t gpw_be = boost::endian::native_to_big(freshGPw);
  std::memcpy(&buf[2], &gpw_be, 8);

  // spassword at offset 10 — echo the client's gpassword.
  uint64_t spw_be = boost::endian::native_to_big(clientGPassword);
  std::memcpy(&buf[10], &spw_be, 8);

  session->send(buf);
}

bool MinxProxy::shouldDropForward() {
  if (config_.packetLossBps == 0)
    return false;
  size_t c = lossFwdCount_++;
  size_t i = c % 10000;
  return (i + 1) * config_.packetLossBps / 10000 >
         i * config_.packetLossBps / 10000;
}

uint64_t MinxProxy::generateProxyGPassword() {
  uint64_t gpw = minx_.generatePassword() & ~LOSS_BIT; // 63 bits
  if (config_.packetLossBps > 0) {
    size_t c = lossRetCount_++;
    size_t i = c % 10000;
    if ((i + 1) * config_.packetLossBps / 10000 >
        i * config_.packetLossBps / 10000)
      gpw |= LOSS_BIT;
  }
  return gpw;
}

void MinxProxy::scheduleSweep() {
  sweepTimer_.expires_after(config_.sweepInterval);
  sweepTimer_.async_wait([this](boost::system::error_code ec) {
    if (ec)
      return;

    auto now = steady_clock::now();

    // Timeout channels that have been HANDSHAKING or BUSY too long.
    for (size_t i = 0; i < channels_.size(); ++i) {
      auto& ch = channels_[i];
      if ((ch.state == Channel::State::HANDSHAKING ||
           ch.state == Channel::State::BUSY) &&
          (now - ch.sentAt) > config_.channelTimeout) {
        LOGTRACE << "channel timeout" << VAR(i);
        pendingResponses_.erase(ch.sentGPassword);
        handshakeChannel(i);
      }
    }

    // Clean up queued requests for closed clients.
    queue_.erase(
      std::remove_if(queue_.begin(), queue_.end(),
                     [](const auto& req) { return req.client->isClosed(); }),
      queue_.end());

    scheduleSweep();
  });
}

} // namespace minx
