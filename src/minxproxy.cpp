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

static uint64_t readBE64(const uint8_t* p) {
  uint64_t v;
  std::memcpy(&v, p, sizeof(v));
  return boost::endian::big_to_native(v);
}

static void appendBE64(std::vector<uint8_t>& buf, uint64_t v) {
  uint64_t be = boost::endian::native_to_big(v);
  buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&be),
             reinterpret_cast<uint8_t*>(&be) + sizeof(be));
}

static constexpr size_t MSG_TYPE_SIZE = 1;
static constexpr size_t WIRE_GPASSWORD_OFF =
  MSG_TYPE_SIZE + sizeof(MinxInit::version);
static constexpr size_t WIRE_SPASSWORD_OFF =
  WIRE_GPASSWORD_OFF + sizeof(MinxMessage::gpassword);
static constexpr size_t WIRE_HEADER_SIZE =
  WIRE_SPASSWORD_OFF + sizeof(MinxMessage::spassword);
static constexpr size_t WIRE_MIN_SIZE = WIRE_GPASSWORD_OFF;

MinxProxy::MinxProxy(const tcp::endpoint& listenEp,
                     const udp::endpoint& upstreamEp,
                     const MinxProxyConfig& config)
    : io_(), config_(config),
      workGuard_(boost::asio::make_work_guard(io_)),
      upstreamAddr_(udp::endpoint(upstreamEp.address(), upstreamEp.port())),
      minx_(this, config.minxConfig),
      server_(io_, listenEp, *this, MAX_UDP_BYTES, config.maxClients),
      sweepTimer_(io_), rng_(std::random_device{}()),
      distrib_(1, std::numeric_limits<uint64_t>::max()) {
  LOGINFO << "proxy starting, upstream=" << upstreamEp
          << " channels=" << config.numChannels;

  minx_.openSocket(upstreamEp.address(), 0, io_, io_);

  channels_.resize(config_.numChannels);
  for (size_t i = 0; i < channels_.size(); ++i) {
    handshakeChannel(i);
  }

  scheduleSweep();

  running_ = true;
  thread_ = std::thread([this]() {
    try {
      io_.run();
    } catch (const std::exception& e) {
      LOGERROR << "proxy io thread exception: " << e.what();
    }
  });
}

MinxProxy::~MinxProxy() { stop(); }

void MinxProxy::stop() {
  if (!running_.exchange(false))
    return;

  asio::post(io_, [this]() {
    sweepTimer_.cancel();
    server_.stop();
    minx_.closeSocket(true);
  });

  workGuard_.reset();

  if (thread_.get_id() != std::this_thread::get_id()) {
    if (thread_.joinable())
      thread_.join();
  } else {
    thread_.detach();
  }
}

bool MinxProxy::verifyProveWork(const MinxProveWork& msg) {
  if (!powEngine_ || !powEngine_->isReady()) {
    Hash zero{};
    if (upstreamSkey_ == zero)
      return false;

    if (!powEngine_) {
      powEngine_ = std::make_unique<PoWEngine>(
        std::span<const uint8_t>(upstreamSkey_.data(), upstreamSkey_.size()),
        config_.powFullDataset);
      powEngine_->initialize();
    }

    if (!powEngine_->isReady())
      return false;
  }

  auto releaser = powEngine_->getVM();
  randomx_vm* vm = releaser.vm();
  if (!vm)
    return false;

  Hash calculated;
  minx_.calculatePoW(vm, msg, calculated);
  return calculated == msg.solution;
}

size_t MinxProxy::readyChannelCount() const {
  size_t count = 0;
  for (auto& ch : channels_) {
    if (ch.state == Channel::State::READY)
      ++count;
  }
  return count;
}

void MinxProxy::handshakeChannel(size_t idx) {
  auto& ch = channels_[idx];
  uint64_t gpw = minx_.generatePassword() & ~LOSS_BIT;
  ch.state = Channel::State::HANDSHAKING;
  ch.spendable = 0;
  ch.sentGPassword = gpw;
  ch.sentAt = steady_clock::now();
  pendingResponses_[gpw] = {nullptr, 0, idx, MINX_GET_INFO};
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

void MinxProxy::onConnect(const TcpSessionPtr& session) {
  LOGDEBUG << "client connected" << VAR(session->label());
}

void MinxProxy::onMessage(const TcpSessionPtr& session, const uint8_t* data,
                          size_t len) {
  LOGTRACE << "onMessage" << VAR(len) << VAR(session->label());
  if (len < WIRE_MIN_SIZE)
    return;

  uint8_t msgType = data[0];

  uint64_t clientGPw = 0;
  if (len >= WIRE_GPASSWORD_OFF + sizeof(MinxInit::gpassword)) {
    clientGPw = readBE64(&data[WIRE_GPASSWORD_OFF]);
  }

  switch (msgType) {
  case MINX_GET_INFO:
    if (hasCachedInfo()) {
      buildAndSendInfo(session, clientGPw);
    } else {
      LOGDEBUG << "no cached INFO yet, dropping GET_INFO";
    }
    return;

  case MINX_INIT:
    return;

  default:
    break;
  }

  if (shouldDropForward())
    return;

  // If no channel is ready, queue the raw wire bytes for later.
  // When dequeued, tryProcessQueue re-enters parseAndForward so
  // filters still run on the second pass.
  if (findReadyChannel() >= channels_.size()) {
    if (config_.maxQueueSize > 0 && queue_.size() >= config_.maxQueueSize) {
      LOGDEBUG << "queue full, dropping" << VAR(queue_.size());
      return;
    }
    queue_.push_back(
      {session, clientGPw, std::vector<uint8_t>(data, data + len)});
    LOGTRACE << "no ready channel, queued" << VAR(queue_.size());
    return;
  }

  parseAndForward(session, data, len);
}

void MinxProxy::onDisconnect(const TcpSessionPtr& session) {
  LOGDEBUG << "client disconnected" << VAR(session->label());
}

void MinxProxy::parseAndForward(const TcpSessionPtr& session,
                                const uint8_t* data, size_t len) {
  if (len < WIRE_MIN_SIZE)
    return;

  uint8_t msgType = data[0];
  uint8_t version = data[1];

  switch (msgType) {
  case MINX_MESSAGE: {
    if (len < MSG_TYPE_SIZE + MinxMessage::SIZE)
      return;
    uint64_t clientGPw = readBE64(&data[WIRE_GPASSWORD_OFF]);
    uint64_t clientSPw = readBE64(&data[WIRE_SPASSWORD_OFF]);
    Bytes payload(data + MSG_TYPE_SIZE + MinxMessage::SIZE, data + len);
    MinxMessage parsed{version, clientGPw, clientSPw, std::move(payload)};
    if (!filterMessage(session, parsed)) {
      session->close();
      return;
    }
    forwardMessage(session, std::move(parsed));
    return;
  }
  case MINX_PROVE_WORK: {
    if (len < MSG_TYPE_SIZE + MinxProveWork::SIZE)
      return;
    uint64_t clientGPw = readBE64(&data[WIRE_GPASSWORD_OFF]);
    uint64_t clientSPw = readBE64(&data[WIRE_SPASSWORD_OFF]);
    size_t off = WIRE_HEADER_SIZE;
    Hash ckey, hdata, solution;
    std::memcpy(ckey.data(), &data[off], sizeof(Hash));
    off += sizeof(Hash);
    std::memcpy(hdata.data(), &data[off], sizeof(Hash));
    off += sizeof(Hash);
    uint64_t time = readBE64(&data[off]);
    off += sizeof(uint64_t);
    uint64_t nonce = readBE64(&data[off]);
    off += sizeof(uint64_t);
    std::memcpy(solution.data(), &data[off], sizeof(Hash));
    off += sizeof(Hash);
    std::vector<char> extraData(data + off, data + len);
    MinxProveWork parsed{version, clientGPw, clientSPw,
                         ckey,    hdata,     time,
                         nonce,   solution,  std::move(extraData)};
    if (!filterProveWork(session, parsed)) {
      session->close();
      return;
    }
    forwardProveWork(session, std::move(parsed));
    return;
  }
  default:
    LOGDEBUG << "unknown message type for forwarding" << VAR(msgType);
    return;
  }
}

void MinxProxy::forwardMessage(const TcpSessionPtr& session,
                               MinxMessage&& msg) {
  size_t chIdx = findReadyChannel();
  auto& ch = channels_[chIdx];
  uint64_t proxyGPw = generateProxyGPassword();
  uint64_t spassword = ch.spendable;

  ch.state = Channel::State::BUSY;
  ch.sentGPassword = proxyGPw;
  ch.sentAt = steady_clock::now();
  ch.spendable = 0;

  pendingResponses_[proxyGPw] = {session, msg.gpassword, chIdx, MINX_MESSAGE};

  minx_.sendMessage(upstreamAddr_,
                    {msg.version, proxyGPw, spassword, std::move(msg.data)});
}

void MinxProxy::forwardProveWork(const TcpSessionPtr& session,
                                 MinxProveWork&& msg) {
  size_t chIdx = findReadyChannel();
  auto& ch = channels_[chIdx];
  uint64_t proxyGPw = generateProxyGPassword();
  uint64_t spassword = ch.spendable;

  ch.state = Channel::State::BUSY;
  ch.sentGPassword = proxyGPw;
  ch.sentAt = steady_clock::now();
  ch.spendable = 0;

  pendingResponses_[proxyGPw] = {session, msg.gpassword, chIdx, MINX_PROVE_WORK};

  minx_.sendProveWork(upstreamAddr_,
                      {msg.version, proxyGPw, spassword, msg.ckey, msg.hdata,
                       msg.time, msg.nonce, msg.solution, std::move(msg.data)});
}

bool MinxProxy::isConnected(const SockAddr& /*addr*/) { return true; }

void MinxProxy::incomingInit(const SockAddr& /*addr*/,
                             const MinxInit& /*msg*/) {}

void MinxProxy::incomingGetInfo(const SockAddr& /*addr*/,
                                const MinxGetInfo& /*msg*/) {}

void MinxProxy::incomingInfo(const SockAddr& /*addr*/, const MinxInfo& msg) {
  LOGDEBUG << "received INFO from upstream" << VAR(HEXU64(msg.gpassword))
           << VAR(HEXU64(msg.spassword));

  cachedInfo_.clear();
  cachedInfo_.push_back(MINX_INFO);
  cachedInfo_.push_back(msg.version);
  cachedInfo_.resize(cachedInfo_.size() + sizeof(MinxInfo::gpassword) +
                     sizeof(MinxInfo::spassword), 0);
  upstreamSkey_ = msg.skey;
  cachedInfo_.insert(cachedInfo_.end(), msg.skey.begin(), msg.skey.end());
  cachedInfo_.push_back(msg.difficulty);
  cachedInfo_.insert(cachedInfo_.end(), msg.data.begin(), msg.data.end());

  auto it = pendingResponses_.find(msg.spassword);
  if (it == pendingResponses_.end())
    return;

  auto pending = it->second;
  pendingResponses_.erase(it);

  if (pending.client && !pending.client->isClosed()) {
    buildAndSendInfo(pending.client, pending.clientGPassword);
  }

  if (msg.gpassword > 0) {
    onChannelReady(pending.channelIdx, msg.gpassword);
  } else {
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
    std::vector<uint8_t> buf;
    buf.push_back(MINX_MESSAGE);
    buf.push_back(msg.version);
    appendBE64(buf, distrib_(rng_) & ~LOSS_BIT);
    appendBE64(buf, pending.clientGPassword);
    buf.insert(buf.end(), msg.data.begin(), msg.data.end());
    pending.client->send(buf);
  }

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
    appendBE64(buf, distrib_(rng_) & ~LOSS_BIT);
    appendBE64(buf, pending.clientGPassword);
    buf.insert(buf.end(), msg.ckey.begin(), msg.ckey.end());
    buf.insert(buf.end(), msg.hdata.begin(), msg.hdata.end());
    appendBE64(buf, msg.time);
    appendBE64(buf, msg.nonce);
    buf.insert(buf.end(), msg.solution.begin(), msg.solution.end());
    buf.insert(buf.end(), msg.data.begin(), msg.data.end());
    pending.client->send(buf);
  }

  if (msg.gpassword > 0) {
    onChannelReady(pending.channelIdx, msg.gpassword);
  } else {
    handshakeChannel(pending.channelIdx);
  }
}

void MinxProxy::buildAndSendInfo(const TcpSessionPtr& session,
                                 uint64_t clientGPassword) {
  if (cachedInfo_.empty())
    return;

  std::vector<uint8_t> buf = cachedInfo_;

  uint64_t freshGPw = distrib_(rng_);
  uint64_t gpw_be = boost::endian::native_to_big(freshGPw);
  std::memcpy(&buf[WIRE_GPASSWORD_OFF], &gpw_be, sizeof(MinxInfo::gpassword));

  uint64_t spw_be = boost::endian::native_to_big(clientGPassword);
  std::memcpy(&buf[WIRE_SPASSWORD_OFF], &spw_be, sizeof(MinxInfo::spassword));

  session->send(buf);
}

bool MinxProxy::shouldDropForward() {
  if (config_.packetLossBps == 0)
    return false;
  size_t c = lossFwdCount_++;
  size_t i = c % BASIS_POINTS;
  return (i + 1) * config_.packetLossBps / BASIS_POINTS >
         i * config_.packetLossBps / BASIS_POINTS;
}

uint64_t MinxProxy::generateProxyGPassword() {
  uint64_t gpw = minx_.generatePassword() & ~LOSS_BIT;
  if (config_.packetLossBps > 0) {
    size_t c = lossRetCount_++;
    size_t i = c % BASIS_POINTS;
    if ((i + 1) * config_.packetLossBps / BASIS_POINTS >
        i * config_.packetLossBps / BASIS_POINTS)
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

    queue_.erase(
      std::remove_if(queue_.begin(), queue_.end(),
                     [](const auto& req) { return req.client->isClosed(); }),
      queue_.end());

    scheduleSweep();
  });
}

} // namespace minx
