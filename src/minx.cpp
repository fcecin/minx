#include <minx/minx.h>

#include <minx/blog.h>
LOG_MODULE_DISABLED("minx")

namespace minx {

const size_t HASH_INPUT_SIZE = sizeof(minx::Hash) * 2 + sizeof(uint64_t) * 2;

struct ScopeExit {
  std::function<void()> fn_;
  ScopeExit(std::function<void()> fn) : fn_(std::move(fn)) {}
  ~ScopeExit() { fn_(); }
};

std::ostream& operator<<(std::ostream& os, const MinxInit& m) {
  return os << "{MinxInit v" << static_cast<int>(m.version)
            << " gpass:" << std::hex << m.gpassword << std::dec
            << " data: " << m.data << "}";
}

std::ostream& operator<<(std::ostream& os, const MinxGetInfo& m) {
  return os << "{MinxGetInfo v" << static_cast<int>(m.version)
            << " gpass:" << std::hex << m.gpassword << std::dec
            << " data:" << m.data << "}";
}

std::ostream& operator<<(std::ostream& os, const MinxMessage& m) {
  return os << "{MinxMessage v" << static_cast<int>(m.version)
            << " gpass:" << std::hex << m.gpassword << " spass:" << m.spassword
            << std::dec << " data:" << m.data << "}";
}

std::ostream& operator<<(std::ostream& os, const MinxInfo& m) {
  return os << "{MinxInfo v" << static_cast<int>(m.version)
            << " gpass:" << std::hex << m.gpassword << " spass:" << m.spassword
            << std::dec << " diff:" << static_cast<int>(m.difficulty)
            << " skey:" << blog::to_vec(m.skey) << " data:" << m.data << "}";
}

std::ostream& operator<<(std::ostream& os, const MinxProveWork& m) {
  return os << "{MinxProveWork v" << static_cast<int>(m.version)
            << " gpass:" << std::hex << m.gpassword << " spass:" << m.spassword
            << std::dec << " ckey:" << blog::to_vec(m.ckey)
            << " hdata:" << blog::to_vec(m.hdata) << " time:" << m.time
            << " nonce:" << m.nonce << " soln:" << blog::to_vec(m.solution)
            << " data:" << m.data << "}";
}

Minx::Minx(MinxListener* listener, uint64_t minProveWorkTimestamp,
           uint64_t spendSlotSize, int randomXVMsToKeep, int randomXInitThreads)
    : listener_(listener), minProveWorkTimestamp_(minProveWorkTimestamp),
      spendSlotSize_(spendSlotSize), randomXVMsToKeep_(randomXVMsToKeep),
      randomXInitThreads_(randomXInitThreads), passwords_(1'000'000, 60),
      gen_(std::random_device{}()),
      genDistrib_(1, std::numeric_limits<uint64_t>::max()),
      spamFilter_(1'000'000, 3, 250, 3600) {
  LOGTRACE << "Minx";
  if (!listener_) {
    throw std::runtime_error("listener cannot be nullptr");
  }
  recvBuffers_ = std::make_unique<RecvBuffers>();
  for (auto& buf : *recvBuffers_) {
    buf.setSizeToCapacity();
  }
  workerThread_ = std::thread(&Minx::workerLoop, this);
  updatePoWSpendCache();
  LOGTRACE << "Minx done";
}

Minx::~Minx() {
  LOGTRACE << "~Minx";
  closeSocket();
  LOGTRACE << "~Minx stop worker and engines";
  {
    std::lock_guard lock(queueMutex_);
    stopWorker_ = true;
    auto it = engines_.begin();
    while (it != engines_.end()) {
      it->second->stop();
      ++it;
    }
  }
  LOGTRACE << "~Minx join worker";
  queueCondVar_.notify_one();
  if (workerThread_.joinable()) {
    workerThread_.join();
  }
  LOGTRACE << "~Minx done";
}

uint64_t Minx::generatePassword() {
  std::lock_guard<std::mutex> lock(genMutex_);
  while (true) {
    uint64_t val = genDistrib_(gen_);
    if (!passwords_.get(val)) {
      return val;
    }
  }
}

void Minx::allocatePassword(uint64_t password) {
  LOGTRACE << "allocatePassword" << VAR(HEXU64(password));
  passwords_.put(password);
}

bool Minx::spendPassword(uint64_t password) {
  bool found = passwords_.erase(password);
  LOGTRACE << "spendPassword" << VAR(HEXU64(password)) << VAR(found);
  return found;
}

void Minx::openSocket(const SockAddr& addr, IOContext& netIO,
                      IOContext& taskIO) {
  LOGTRACE << "openSocket";
  std::lock_guard lock(socketStateMutex_);
  if (socket_) {
    LOGTRACE << "openSocket no socket";
    return;
  }
  netIO_ = &netIO;
  taskIO_ = &taskIO;
  taskIOWorkGuard_ = std::make_unique<
    boost::asio::executor_work_guard<IOContext::executor_type>>(
    taskIO_->get_executor());
  netIOStrand_ =
    std::make_unique<boost::asio::strand<IOContext::executor_type>>(
      netIO_->get_executor());
  netIORetryTimer_ = std::make_unique<boost::asio::steady_timer>(*netIO_);
  socket_ = std::make_unique<boost::asio::ip::udp::socket>(*netIO_);
  socket_->open(addr.protocol());
  if (addr.protocol() == boost::asio::ip::udp::v6()) {
    boost::system::error_code ec;
    socket_->set_option(boost::asio::ip::v6_only(false), ec);
    if (ec) {
      LOGTRACE << "openSocket ipv6 failed to set option v6_only == false";
    }
  }
  socket_->bind(addr);
  receive();
  LOGTRACE << "openSocket done";
}

void Minx::closeSocket() {
  LOGTRACE << "closeSocket";
  {
    std::lock_guard lock(socketStateMutex_);
    if (!socket_) {
      return;
    }
    if (netIORetryTimer_) {
      boost::system::error_code ec;
      netIORetryTimer_->cancel(ec);
    }
    std::atomic<bool> done_flag(false);
    boost::asio::post(*netIOStrand_, [this, &done_flag]() {
      if (socket_) {
        boost::system::error_code ec;
        socket_->close(ec);
        socket_.reset();
      }
      done_flag = true;
    });
    LOGTRACE << "closeSocket join netIO";
    while (!done_flag || netIOHandlerCount_ > 0) {
      if (netIO_)
        netIO_->poll();
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    netIORetryTimer_.reset();
    netIOStrand_.reset();
    netIO_ = nullptr;
  }
  // TODO: This bit here is unprotected from multithreading because
  // taskIO execution can actually trigger callbacks into client code.
  // But really, who is going to call openSocket() / closeSocket()
  // in rapid succession from different threads?
  // In any case, the actual solution is fixing this handlerCount
  // nonsense and using shared_from_this.
  LOGTRACE << "closeSocket join taskIO";
  while (taskIOHandlerCount_ > 0) {
    if (taskIO_) {
      try {
        taskIO_->poll();
      } catch (...) {
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  {
    std::lock_guard lock(socketStateMutex_);
    taskIOWorkGuard_.reset();
    taskIO_ = nullptr;
  }
  LOGTRACE << "closeSocket done";
}

void Minx::sendInit(const SockAddr& addr, const MinxInit& msg) {
  LOGDEBUG << "sendInit" << VAR(addr) << SVAR(msg);
  auto buf = acquireSendBuffer();
  buf->put<uint8_t>(MINX_INIT);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword);
  }
  buf->put(bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendMessage(const SockAddr& addr, const MinxMessage& msg) {
  LOGDEBUG << "sendMessage" << VAR(addr) << SVAR(msg);
  auto buf = acquireSendBuffer();
  buf->put<uint8_t>(MINX_MESSAGE);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword);
  }
  buf->put(msg.spassword);
  buf->put(bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendGetInfo(const SockAddr& addr, const MinxGetInfo& msg) {
  LOGDEBUG << "sendGetInfo" << VAR(addr) << SVAR(msg);
  auto buf = acquireSendBuffer();
  buf->put<uint8_t>(MINX_GET_INFO);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword);
  }
  buf->put(bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendInfo(const SockAddr& addr, const MinxInfo& msg) {
  LOGDEBUG << "sendInfo" << VAR(addr) << SVAR(msg);
  auto buf = acquireSendBuffer();
  buf->put<uint8_t>(MINX_INFO);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword);
  }
  buf->put(msg.spassword);
  buf->put(msg.skey);
  buf->put(msg.difficulty);
  buf->put(bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendProveWork(const SockAddr& addr, const MinxProveWork& msg) {
  LOGDEBUG << "sendProveWork" << VAR(addr) << SVAR(msg);
  auto buf = acquireSendBuffer();
  buf->put<uint8_t>(MINX_PROVE_WORK);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword);
  }
  buf->put(msg.spassword);
  buf->put(msg.ckey);
  buf->put(msg.hdata);
  buf->put(msg.time);
  buf->put(msg.nonce);
  buf->put(msg.solution);
  buf->put(bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendApplication(const SockAddr& addr, const Bytes& data,
                           const uint8_t code) {
  LOGDEBUG << "sendApplication" << VAR(addr) << VAR(code) << VAR(data);
  if (code > MINX_APPLICATION_MAX) {
    throw std::runtime_error("invalid application message code");
  }
  auto buf = acquireSendBuffer();
  buf->put(code);
  buf->put(bytesAsSpan(data));
  doSocketSend(addr, buf);
}

void Minx::sendExtension(const SockAddr& addr, const Bytes& data) {
  LOGDEBUG << "sendExtension" << VAR(addr) << VAR(data);
  auto buf = acquireSendBuffer();
  buf->put<uint8_t>(MINX_EXTENSION);
  buf->put<uint8_t>(0x0);
  buf->put(bytesAsSpan(data));
  doSocketSend(addr, buf);
}

int Minx::queryPoW(const uint64_t time, const Hash& solution,
                   uint64_t epochSecs) {
  LOGTRACE << "queryPoW" << VAR(time) << BVAR(solution) << VAR(epochSecs);
  uint64_t now = epochSecs;
  if (!now) {
    now = getSecsSinceEpoch();
  }
  bool forceSpendCacheUpdate = false;
  {
    std::shared_lock lock(spendMutex_);
    if (time < spendBaseTime_ || time > now + PROVE_WORK_FUTURE_DRIFT_SECS) {
      return MINX_SOLUTION_UNTIMELY;
    }
    size_t slot_index = (time - spendBaseTime_) / spendSlotSize_;
    if (slot_index >= spend_.size()) {
      // Maybe the spend cache just needs updating
      forceSpendCacheUpdate = true;
    } else {
      if (spend_[slot_index].count(solution)) {
        return MINX_SOLUTION_SPENT;
      }
    }
  }
  if (forceSpendCacheUpdate) {
    updatePoWSpendCache(now);
    std::shared_lock lock(spendMutex_);
    if (time < spendBaseTime_) {
      return MINX_SOLUTION_UNTIMELY;
    }
    size_t slot_index = (time - spendBaseTime_) / spendSlotSize_;
    if (slot_index >= spend_.size()) {
      throw std::runtime_error("double-spend logic error");
    }
    if (spend_[slot_index].count(solution)) {
      return MINX_SOLUTION_SPENT;
    }
  }
  return MINX_SOLUTION_UNSPENT;
}

uint64_t Minx::updatePoWSpendCache(uint64_t epochSecs) {
  uint64_t now = epochSecs;
  if (!now) {
    now = getSecsSinceEpoch();
  }
  std::lock_guard lock(spendMutex_);
  const uint64_t current_slot_time = (now / spendSlotSize_) * spendSlotSize_;
  const uint64_t target_base_time = current_slot_time - spendSlotSize_;
  if (target_base_time < spendBaseTime_ ||
      target_base_time >= spendBaseTime_ + (spend_.size() * spendSlotSize_)) {
    spend_.clear();
    spendBaseTime_ = target_base_time;
    spend_.emplace_back();
    spend_.emplace_back();
    spend_.emplace_back();
  } else {
    const uint64_t next_slot_time = current_slot_time + spendSlotSize_;
    size_t needed_idx = (next_slot_time - spendBaseTime_) / spendSlotSize_;
    while (spend_.size() <= needed_idx) {
      spend_.emplace_back();
    }
    while (spendBaseTime_ < target_base_time) {
      if (!spend_.empty()) {
        spend_.pop_front();
      }
      spendBaseTime_ += spendSlotSize_;
    }
  }
  return spendBaseTime_;
}

bool Minx::replayPoW(const uint64_t time, const Hash& solution) {
  std::lock_guard lock(spendMutex_);
  if (time < spendBaseTime_) {
    return false;
  }
  size_t slot_index = (time - spendBaseTime_) / spendSlotSize_;
  if (slot_index >= spend_.size()) {
    return false;
  }
  return spend_[slot_index].insert(solution).second;
}

uint64_t Minx::filterPoW(const MinxProveWork& msg, const int difficulty) {
  if (difficulty < minDiff_) {
    return MINX_ERROR_LOW_DIFF;
  }

  const uint64_t now = getSecsSinceEpoch();
  if (minProveWorkTimestamp_ > 0 && now < minProveWorkTimestamp_) {
    return MINX_ERROR_UNTIMELY_POW;
  }

  int queryResult = queryPoW(msg.time, msg.solution, now);
  switch (queryResult) {
  case MINX_SOLUTION_SPENT:
    return MINX_ERROR_DOUBLE_SPEND;
  case MINX_SOLUTION_UNTIMELY:
    return MINX_ERROR_UNTIMELY_POW;
  case MINX_SOLUTION_UNSPENT:
    return 0;
  default:
    throw std::runtime_error("queryPoW is broken");
  }
}

void Minx::calculatePoW(randomx_vm* rxvmPtr, const MinxProveWork& msg,
                        Hash& calculatedHash) {
  minx::ArrayBuffer<HASH_INPUT_SIZE> input_buffer;
  input_buffer.put(msg.ckey);
  input_buffer.put(msg.hdata);
  input_buffer.put(msg.time);
  input_buffer.put(msg.nonce);
  randomx_calculate_hash(rxvmPtr, input_buffer.getBackingSpan().data(),
                         input_buffer.getSize(), calculatedHash.data());
  LOGTRACE << "calculatePoW" << SVAR(msg) << BVAR(calculatedHash);
}

uint64_t Minx::processPoW(const SockAddr& addr, const MinxProveWork& msg,
                          const int difficulty, bool isWorkHashValid) {
  if (isWorkHashValid) {
    std::lock_guard lock(spendMutex_);
    // If bucket was dropped because it got old while we verified the hash,
    // even better: no need to store the hash, as any hash that would go into
    // these deleted buckets can no longer be spent.
    if (msg.time >= spendBaseTime_) {
      size_t slot_index = (msg.time - spendBaseTime_) / spendSlotSize_;
      if (slot_index >= spend_.size()) {
        // Shouldn't happen, since buckets should only be deleted by moving
        // spendBaseTime_. But guard against that anyway.
        return MINX_ERROR_UNEXPECTED;
      }
      spend_[slot_index].insert(msg.solution);
    }
    listener_->incomingProveWork(addr, msg, difficulty);
  } else {
    // need to penalize sender since randomx_calculate_hash() was expensive.
    // solution might have been altered by MitM or the sender address might
    // be spoofed, but this penalty cannot be avoided in any case.
    ipFilter_.reportIP(addr.address());
    return MINX_ERROR_MISMATCHED_POW;
  }
  return 0;
}

int Minx::verifyPoWs(const size_t limit) {
  Hash key;
  {
    std::lock_guard lock(keyMutex_);
    if (!keySet_) {
      throw std::runtime_error(
        "cannot call verifyPoWs() before setServerKey()");
    }
    key = key_;
  }
  std::shared_ptr<PoWEngine> engine_ptr = getPoWEngine(key);
  if (!engine_ptr) {
    return -1;
  }
  if (!engine_ptr->isReady()) {
    return -2;
  }
  auto releaser = engine_ptr->getVM();
  randomx_vm* vm = releaser.vm();
  if (!vm) { // never happens
    throw std::runtime_error("verifyPoWs() got randomx_vm* nullptr");
  }
  size_t verified_count = 0;
  while (limit == 0 || verified_count < limit) {
    std::optional<std::pair<MinxProveWork, SockAddr>> work_item_opt;
    {
      std::lock_guard lock(workMutex_);
      if (work_.empty()) {
        break;
      }
      work_item_opt.emplace(std::move(work_.front()));
      work_.pop();
    }
    ++verified_count;

    const MinxProveWork& work_item = work_item_opt->first;
    const SockAddr& work_sockaddr = work_item_opt->second;

    if (ipFilter_.checkIP(work_sockaddr.address())) {
      LOGTRACE << "verifyPoWs() dropped work from IP filtered address"
               << VAR(work_sockaddr);
      continue;
    }

    if (spamFilter_.check(work_sockaddr.address(), false)) {
      LOGTRACE << "verifyPoWs() dropped work from Spam filtered address"
               << VAR(work_sockaddr);
      continue;
    }

    uint8_t work_diff = getDifficulty(work_item.solution);

    uint64_t ferr = filterPoW(work_item, work_diff);
    if (ferr > 0) {
      lastError_ = ferr;
      continue;
    }

    Hash calculated_hash;
    calculatePoW(vm, work_item, calculated_hash);

    bool work_valid = calculated_hash == work_item.solution;

    uint64_t perr = processPoW(work_sockaddr, work_item, work_diff, work_valid);
    if (perr > 0) {
      lastError_ = perr;
    }
  }
  return verified_count;
}

size_t Minx::getVerifyPoWQueueSize() {
  std::lock_guard lock(workMutex_);
  return work_.size();
}

void Minx::createPoWEngine(const Hash& key) {
  LOGTRACE << "createPoWEngine" << BVAR(key);
  {
    std::lock_guard lock(enginesMutex_);
    if (stopWorker_) {
      return;
    }
    if (engines_.count(key)) {
      return;
    }
    engines_.try_emplace(key, std::make_shared<PoWEngine>(std::span(key),
                                                          useDataset_,
                                                          randomXVMsToKeep_));
  }
  {
    std::lock_guard lock(queueMutex_);
    pendingInitializations_.push(key);
  }
  queueCondVar_.notify_one();
};

std::shared_ptr<PoWEngine> Minx::getPoWEngine(const Hash& key) {
  std::shared_ptr<PoWEngine> engine_ptr;
  {
    std::lock_guard lock(enginesMutex_);
    auto it = engines_.find(key);
    if (it != engines_.end()) {
      engine_ptr = it->second;
    }
  }
  return engine_ptr;
}

bool Minx::checkPoWEngine(const Hash& key) {
  std::shared_ptr<PoWEngine> engine_ptr = getPoWEngine(key);
  if (!engine_ptr) {
    LOGTRACE << "checkPoWEngine not found" << BVAR(key);
    return false;
  }
  auto state = engine_ptr->getState();
  if (state == PoWEngineState::Error) {
    LOGTRACE << "checkPoWEngine State=Error" << BVAR(key);
    throw std::runtime_error("VM initialization failed: " +
                             engine_ptr->getErrorMessage());
  }
  bool ready = engine_ptr->isReady();
  return ready;
}

bool Minx::destroyPoWEngine(const Hash& key) {
  LOGTRACE << "destroyPoWEngine" << BVAR(key);
  std::lock_guard{enginesMutex_};
  auto it = engines_.find(key);
  if (it == engines_.end()) {
    LOGTRACE << "destroyPoWEngine not found" << BVAR(key);
    return false;
  }
  engines_.erase(it);
  return true;
}

std::optional<MinxProveWork>
Minx::proveWork(const Hash& myKey, const Hash& hdata, const Hash& targetKey,
                int difficulty, int numThreads, uint64_t startNonce,
                uint64_t maxIters) {
  LOGTRACE << "proveWork" << BVAR(myKey) << BVAR(hdata) << BVAR(targetKey)
           << VAR(difficulty) << VAR(numThreads) << VAR(startNonce)
           << VAR(maxIters);
  std::shared_ptr<PoWEngine> engine_ptr;
  {
    std::lock_guard lock(enginesMutex_);
    auto it = engines_.find(targetKey);
    if (it != engines_.end()) {
      engine_ptr = it->second;
    }
  }
  if (!engine_ptr) {
    throw std::runtime_error("PoWEngine not found");
  }
  if (!engine_ptr->isReady()) {
    throw std::runtime_error("PoWEngine not ready");
  }
  std::atomic<bool> solution_found = false;
  std::atomic<uint64_t> nonce_counter = startNonce;
  uint64_t maxNonce;
  if (maxIters > 0) {
    maxNonce = startNonce + maxIters;
  } else {
    maxNonce = std::numeric_limits<uint64_t>::max();
  }
  std::optional<MinxProveWork> result;
  std::mutex result_mutex;
  if (numThreads <= 0) {
    numThreads = std::max(std::thread::hardware_concurrency(),
                          static_cast<unsigned int>(1));
  }
  std::vector<std::thread> threads;
  threads.reserve(numThreads);
  for (size_t i = 0; i < numThreads; ++i) {
    threads.emplace_back([&, i]() {
      auto releaser = engine_ptr->getVM();
      randomx_vm* vm = releaser.vm();
      if (!vm) {
        return;
      }
      while (true) {
        uint64_t nonce = nonce_counter.fetch_add(1, std::memory_order_relaxed);
        if (solution_found.load(std::memory_order_relaxed) ||
            nonce >= maxNonce) {
          break;
        }

        const auto p1 = std::chrono::system_clock::now();
        const uint64_t time = getSecsSinceEpoch();

        minx::ArrayBuffer<HASH_INPUT_SIZE> input_buffer;
        input_buffer.put(myKey);
        input_buffer.put(hdata);
        input_buffer.put(time);
        input_buffer.put(nonce);
        Hash solution_hash;
        randomx_calculate_hash(vm, input_buffer.getBackingSpan().data(),
                               input_buffer.getSize(), solution_hash.data());

        if (getDifficulty(solution_hash) >= difficulty) {
          bool already_found =
            solution_found.exchange(true, std::memory_order_acq_rel);
          if (!already_found) {
            std::lock_guard<std::mutex> lock(result_mutex);
            result.emplace(MinxProveWork{
              0, 0, 0, myKey, hdata, time, nonce, solution_hash, {}});
          }
          break;
        }
      }
    });
  }
  for (auto& t : threads) {
    if (t.joinable()) {
      t.join();
    }
  }
  return result;
}

void Minx::banAddress(const IPAddr& addr) {
  LOGTRACE << "banAddress" << VAR(addr);
  ipFilter_.reportIP(addr);
}

bool Minx::checkSpam(const IPAddr& addr, bool alsoUpdate) {
  return spamFilter_.check(addr, alsoUpdate);
}

std::shared_ptr<minx::Buffer> Minx::acquireSendBuffer() {
  std::unique_lock lock(sendBufferPoolMutex_);
  if (!sendBufferPool_.empty()) {
    auto buf = std::move(sendBufferPool_.back());
    sendBufferPool_.pop_back();
    lock.unlock();
    buf->clear();
    return buf;
  }
  lock.unlock();
  return std::make_shared<minx::VectorBuffer>(MAX_UDP_BYTES);
}

void Minx::releaseSendBuffer(std::shared_ptr<minx::Buffer> buf) {
  std::lock_guard lock(sendBufferPoolMutex_);
  if (sendBufferPool_.size() < SEND_BUFFER_POOL_MAX_SIZE) {
    sendBufferPool_.push_back(std::move(buf));
  }
}

void Minx::doSocketSend(const SockAddr& addr,
                        const std::shared_ptr<minx::Buffer>& buf) {
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  socket_->async_send_to(
    buf->getAsioBufferToRead(), addr,
    [this, buf](const boost::system::error_code&, std::size_t) {
      this->releaseSendBuffer(buf);
    });
}

void Minx::receive() {
  size_t bufIndex = 0;
  {
    std::lock_guard lock(recvBuffersMutex_);
    auto& slot = recvBuffersInfo_[recvBuffersIndex_];
    if (slot.busy_) {
      // If no more slots, of which are plenty, should wait a long time anyways.
      netIORetryTimer_->expires_after(std::chrono::milliseconds(100));
      netIORetryTimer_->async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted) {
          // closeSocket() was called and we killer the timer somewhere in there
          return;
        }
        if (ec) {
          throw std::runtime_error("boost timer returned a fatal error: " +
                                   std::to_string(ec.value()) + " (" +
                                   ec.message() + ")");
        }
        receive();
      });
      return;
    }
    slot.busy_ = true;
    bufIndex = recvBuffersIndex_;
    ++recvBuffersIndex_;
    if (recvBuffersIndex_ >= RECV_BUFFER_ARRAY_SIZE)
      recvBuffersIndex_ = 0;
  }

  auto& buf = (*recvBuffers_)[bufIndex];
  auto& slot = recvBuffersInfo_[bufIndex];
  ++netIOHandlerCount_;
  socket_->async_receive_from(
    buf.getAsioBufferToWrite(), slot.remoteAddr_,
    boost::asio::bind_executor(
      *netIOStrand_, std::bind_front(&Minx::onReceivePacket, this, bufIndex)));
}

void Minx::onReceivePacket(size_t slotIndex,
                           const boost::system::error_code& error,
                           size_t bytes_transferred) {
  ScopeExit onExit([&]() { --netIOHandlerCount_; });

  auto& slot = recvBuffersInfo_[slotIndex];

  if (error == boost::asio::error::operation_aborted) {
    slot.busy_ = false;
    return; // socket is closing; don't post another receive
  }

  try {
    if (error || bytes_transferred < sizeof(uint8_t) ||
        bytes_transferred == MAX_UDP_BYTES ||
        ipFilter_.checkIP(slot.remoteAddr_.address())) {
      // drop message
      slot.busy_ = false;
    } else {
      ++taskIOHandlerCount_;
      try {
        boost::asio::post(*taskIO_,
                          std::bind_front(&Minx::onProcessPacket, this,
                                          slotIndex, bytes_transferred));
      } catch (const std::exception&) { // should never happen
        slot.busy_ = false;
        --taskIOHandlerCount_;
      }
    }
  } catch (const std::exception& ex) { // should never happen
    receive();
    throw ex;
  }
  receive();
}

void Minx::onProcessPacket(size_t slotIndex, size_t bytes_transferred) {
  auto& slot = recvBuffersInfo_[slotIndex];

  ScopeExit onExit([&]() {
    slot.busy_ = false;
    --taskIOHandlerCount_;
  });

  auto& remoteAddr_ = slot.remoteAddr_;
  auto& buffer_ = (*recvBuffers_)[slotIndex];

  uint8_t code;
  buffer_.setSize(bytes_transferred);
  buffer_.setReadPos(0);
  code = buffer_.get<uint8_t>();

  switch (code) {
  case MINX_INIT: {
    if (spamFilter_.updateAndCheck(remoteAddr_.address())) {
      LOGTRACE << "onProcessPacket MINX_INIT caught by spam filter";
      ipFilter_.reportIP(remoteAddr_.address());
      break;
    }
    size_t bytes_expected = sizeof(code) + MinxInit::SIZE;
    if (bytes_transferred < bytes_expected) {
      LOGTRACE << "onProcessPacket MINX_INIT message too short"
               << VAR(bytes_transferred) << VAR(bytes_expected);
      lastError_ = MINX_ERROR_BAD_INIT;
      break;
    }
    const uint8_t version = buffer_.get<uint8_t>();
    const uint64_t gpassword = buffer_.get<uint64_t>();
    Bytes data = buffer_.getRemainingBytes();
    MinxInit msg{version, gpassword, data};
    LOGTRACE << "onProcessPacket MINX_INIT" << SVAR(msg);
    listener_->incomingInit(remoteAddr_, msg);
    break;
  }

  case MINX_MESSAGE: {
    size_t bytes_expected = sizeof(code) + MinxMessage::SIZE;
    if (bytes_transferred < bytes_expected) {
      LOGTRACE << "onProcessPacket MINX_MESSAGE message too short"
               << VAR(bytes_transferred) << VAR(bytes_expected);
      lastError_ = MINX_ERROR_BAD_MESSAGE;
      break;
    }
    const uint8_t version = buffer_.get<uint8_t>();
    const uint64_t gpassword = buffer_.get<uint64_t>();
    const uint64_t spassword = buffer_.get<uint64_t>();
    if (spassword == 0 || !spendPassword(spassword)) {
      LOGTRACE << "onProcessPacket MINX_MESSAGE bad spend password"
               << VAR(HEXU64(spassword));
      lastError_ = MINX_ERROR_BAD_MESSAGE;
      break;
    }
    Bytes data = buffer_.getRemainingBytes();
    MinxMessage msg{version, gpassword, spassword, data};
    LOGTRACE << "onProcessPacket MINX_MESSAGE" << SVAR(msg);
    listener_->incomingMessage(remoteAddr_, msg);
    break;
  }

  case MINX_GET_INFO: {
    if (spamFilter_.updateAndCheck(remoteAddr_.address())) {
      LOGTRACE << "onProcessPacket MINX_GET_INFO caught by spam filter";
      ipFilter_.reportIP(remoteAddr_.address());
      break;
    }
    size_t bytes_expected = sizeof(code) + MinxGetInfo::SIZE;
    if (bytes_transferred < bytes_expected) {
      LOGTRACE << "onProcessPacket MINX_GET_INFO message too short"
               << VAR(bytes_transferred) << VAR(bytes_expected);
      lastError_ = MINX_ERROR_BAD_GET_INFO;
      break;
    }
    const uint8_t version = buffer_.get<uint8_t>();
    const uint64_t gpassword = buffer_.get<uint64_t>();
    Bytes data = buffer_.getRemainingBytes();
    MinxGetInfo msg{version, gpassword, data};
    LOGTRACE << "onProcessPacket MINX_GET_INFO" << SVAR(msg);
    listener_->incomingGetInfo(remoteAddr_, msg);
    break;
  }

  case MINX_INFO: {
    size_t bytes_expected = sizeof(code) + MinxInfo::SIZE;
    if (bytes_transferred < bytes_expected) {
      LOGTRACE << "onProcessPacket MINX_INFO message too short"
               << VAR(bytes_transferred) << VAR(bytes_expected);
      lastError_ = MINX_ERROR_BAD_INFO;
      break;
    }
    const uint8_t version = buffer_.get<uint8_t>();
    const uint8_t engine_id = version & 0x0F;
    if (engine_id != 0x0) {
      LOGTRACE << "onProcessPacket MINX_INFO bad engine" << VAR(version)
               << VAR(engine_id);
      lastError_ = MINX_ERROR_BAD_INFO;
      break;
    }
    const uint64_t gpassword = buffer_.get<uint64_t>();
    const uint64_t spassword = buffer_.get<uint64_t>();
    if (spassword == 0 || !spendPassword(spassword)) {
      LOGTRACE << "onProcessPacket MINX_INFO bad spend password"
               << VAR(HEXU64(spassword));
      lastError_ = MINX_ERROR_BAD_INFO;
      break;
    }
    Hash skey = buffer_.get<Hash>();
    const uint8_t difficulty = buffer_.get<uint8_t>();
    Bytes data = buffer_.getRemainingBytes();
    MinxInfo msg{version, gpassword, spassword, difficulty, skey, data};
    LOGTRACE << "onProcessPacket MINX_INFO" << SVAR(msg);
    listener_->incomingInfo(remoteAddr_, msg);
    break;
  }

  case MINX_PROVE_WORK: {
    size_t bytes_expected = sizeof(code) + MinxProveWork::SIZE;
    if (bytes_transferred < bytes_expected) {
      LOGTRACE << "onProcessPacket MINX_PROVE_WORK message too short"
               << VAR(bytes_transferred) << VAR(bytes_expected);
      lastError_ = MINX_ERROR_BAD_PROVE_WORK;
      break;
    }
    const uint8_t version = buffer_.get<uint8_t>();
    const uint8_t engine_id = version & 0x0F;
    if (engine_id != 0x0) {
      LOGTRACE << "onProcessPacket MINX_PROVE_WORK bad engine" << VAR(version)
               << VAR(engine_id);
      lastError_ = MINX_ERROR_BAD_PROVE_WORK;
      break;
    }
    const uint64_t gpassword = buffer_.get<uint64_t>();
    const uint64_t spassword = buffer_.get<uint64_t>();
    Hash ckey = buffer_.get<Hash>();
    Hash hdata = buffer_.get<Hash>();
    const uint64_t time = buffer_.get<uint64_t>();
    const uint64_t nonce = buffer_.get<uint64_t>();
    Hash solution = buffer_.get<Hash>();
    Bytes data = buffer_.getRemainingBytes();
    bool password_matched = spassword > 0 && spendPassword(spassword);
    if (!password_matched) {
      if (!listener_->isConnected(remoteAddr_)) {
        LOGTRACE << "onProcessPacket MINX_PROVE_WORK not connected"
                 << VAR(HEXU64(spassword));
        lastError_ = MINX_ERROR_NOT_CONNECTED;
        break;
      }
    }
    MinxProveWork msg{version, gpassword, spassword, ckey, hdata,
                      time,    nonce,     solution,  data};
    LOGTRACE << "onProcessPacket MINX_PROVE_WORK" << SVAR(msg);
    if (listener_->delegateProveWork(remoteAddr_, msg)) {
      std::lock_guard lock(workMutex_);
      work_.push({std::move(msg), remoteAddr_});
    }
    break;
  }

  case MINX_EXTENSION: {
    uint8_t version;
    size_t bytes_expected = sizeof(code) + sizeof(version);
    if (bytes_transferred < bytes_expected) {
      LOGTRACE << "onProcessPacket MINX_EXTENSION message too short"
               << VAR(bytes_transferred) << VAR(bytes_expected);
      lastError_ = MINX_ERROR_BAD_EXTENSION;
      break;
    }
    version = buffer_.get<uint8_t>();
    Bytes data = buffer_.getRemainingBytes();
    listener_->incomingExtension(remoteAddr_, data);
    break;
  }

  default: {
    // Any other code is an APPLICATION message code [0x00, 0xFB]
    Bytes data = buffer_.getRemainingBytes();
    LOGTRACE << "onProcessPacket MINX_APPLICATION message too short"
             << VAR(code) << VAR(data);
    listener_->incomingApplication(remoteAddr_, code, data);
  } break;
  }
}

void Minx::workerLoop() {
  LOGTRACE << "workerLoop";
  while (!stopWorker_) {
    Hash keyToInitialize;
    {
      std::unique_lock lock(queueMutex_);
      queueCondVar_.wait(lock, [this] {
        return !pendingInitializations_.empty() || stopWorker_;
      });
      if (stopWorker_) {
        LOGTRACE << "workerLoop stopWorker_";
        return;
      }
      if (pendingInitializations_.empty()) {
        continue;
      }
      keyToInitialize = pendingInitializations_.front();
      pendingInitializations_.pop();
    }
    std::shared_ptr<PoWEngine> engine_ptr;
    {
      std::lock_guard lock(enginesMutex_);
      auto it = engines_.find(keyToInitialize);
      if (it != engines_.end()) {
        engine_ptr = it->second;
        LOGTRACE << "workerLoop found engine to init" << BVAR(keyToInitialize)
                 << BVAR(engine_ptr->getKey());
      } else {
        LOGTRACE << "workerLoop did not find engine to init"
                 << BVAR(keyToInitialize);
      }
    }
    if (engine_ptr) {
      LOGTRACE << "workerLoop initialize engine" << VAR(randomXInitThreads_)
               << BVAR(engine_ptr->getKey());
      engine_ptr->initialize(randomXInitThreads_);
    } else {
      LOGERROR << "workerLoop null PoWEngine";
      throw std::runtime_error("missing PoWEngine to initialize");
    }
  }
  LOGTRACE << "workerLoop done";
}

} // namespace minx