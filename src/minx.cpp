#include <minx/minx.h>

namespace minx {

const size_t HASH_INPUT_SIZE = sizeof(minx::Hash) * 2 + sizeof(uint64_t) * 2;

template <typename T> class AtomicDec {
public:
  AtomicDec(std::atomic<T>& c) : c_(c) {}
  ~AtomicDec() { --c_; }

private:
  std::atomic<T>& c_;
};

Minx::Minx(MinxListener* listener, int randomXThreads, uint64_t spendSlotSize)
    : listener_(listener), randomXThreads_(randomXThreads),
      spendSlotSize_(spendSlotSize), passwords_(1'000'000, 60),
      gen_(std::random_device{}()),
      genDistrib_(1, std::numeric_limits<uint64_t>::max()) {
  if (!listener_) {
    throw std::runtime_error("listener cannot be nullptr");
  }
  buffer_.setSize(0x10000);
  workerThread_ = std::thread(&Minx::workerLoop, this);
}

Minx::~Minx() {
  closeSocket();
  stopWorker_.store(true);
  queueCondVar_.notify_one();
  if (workerThread_.joinable()) {
    workerThread_.join();
  }
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

void Minx::allocatePassword(uint64_t password, const IPAddr& addr) {
  passwords_.put(password, addr);
}

bool Minx::spendPassword(uint64_t password, const IPAddr& addr) {
  auto ip_opt = passwords_.get(password);
  if (ip_opt && ip_opt.value() == addr) {
    passwords_.erase(password);
    return true;
  }
  return false;
}

void Minx::openSocket(IOContext& ioc, const SockAddr& addr) {
  std::lock_guard lock(socketStateMutex_);
  if (socket_) {
    return;
  }
  io_context_ = &ioc;
  strand_ = std::make_unique<boost::asio::strand<IOContext::executor_type>>(
    io_context_->get_executor());
  socket_ = std::make_unique<boost::asio::ip::udp::socket>(*io_context_, addr);
  receive();
}

void Minx::closeSocket() {
  std::lock_guard lock(socketStateMutex_);
  if (!socket_) {
    return;
  }
  std::atomic<bool> done_flag(false);
  boost::asio::post(*strand_, [this, &done_flag]() {
    if (socket_) {
      boost::system::error_code ec;
      socket_->close(ec);
      socket_.reset();
    }
    done_flag.store(true);
  });
  while (!done_flag.load() && handlerCount_ > 0) {
    io_context_->poll();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  strand_.reset();
  io_context_ = nullptr;
}

void Minx::sendInit(const SockAddr& addr, const MinxInit& msg) {
  auto buf =
    std::make_shared<minx::VectorBuffer>(1 + MinxInit::SIZE + msg.data.size());
  buf->put<uint8_t>(MINX_INIT);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword, addr.address());
  }
  buf->put(logkv::bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendMessage(const SockAddr& addr, const MinxMessage& msg) {
  auto buf = std::make_shared<minx::VectorBuffer>(1 + MinxMessage::SIZE +
                                                  msg.data.size());
  buf->put<uint8_t>(MINX_MESSAGE);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword, addr.address());
  }
  buf->put(msg.spassword);
  buf->put(logkv::bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendGetInfo(const SockAddr& addr, const MinxGetInfo& msg) {
  auto buf = std::make_shared<minx::VectorBuffer>(1 + MinxGetInfo::SIZE +
                                                  msg.data.size());
  buf->put<uint8_t>(MINX_GET_INFO);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword, addr.address());
  }
  buf->put(logkv::bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendInfo(const SockAddr& addr, const MinxInfo& msg) {
  auto buf =
    std::make_shared<minx::VectorBuffer>(1 + MinxInfo::SIZE + msg.data.size());
  buf->put<uint8_t>(MINX_INFO);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword, addr.address());
  }
  buf->put(msg.spassword);
  buf->put(msg.skey);
  buf->put(msg.difficulty);
  buf->put(logkv::bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendProveWork(const SockAddr& addr, const MinxProveWork& msg) {
  auto buf = std::make_shared<minx::VectorBuffer>(1 + MinxProveWork::SIZE +
                                                  msg.data.size());
  buf->put<uint8_t>(MINX_PROVE_WORK);
  buf->put(msg.version);
  buf->put(msg.gpassword);
  if (msg.gpassword > 0) {
    allocatePassword(msg.gpassword, addr.address());
  }
  buf->put(msg.spassword);
  buf->put(msg.ckey);
  buf->put(msg.hdata);
  buf->put(msg.time);
  buf->put(msg.nonce);
  buf->put(msg.solution);
  buf->put(logkv::bytesAsSpan(msg.data));
  doSocketSend(addr, buf);
}

void Minx::sendApplication(const SockAddr& addr, const Bytes& data,
                           const uint8_t code) {
  if (code > MINX_APPLICATION_MAX) {
    throw std::runtime_error("invalid application message code");
  }
  auto buf = std::make_shared<minx::VectorBuffer>(1 + data.size());
  buf->put(code);
  buf->put(logkv::bytesAsSpan(data));
  doSocketSend(addr, buf);
}

void Minx::sendExtension(const SockAddr& addr, const Bytes& data) {
  auto buf = std::make_shared<minx::VectorBuffer>(2 + data.size());
  buf->put<uint8_t>(MINX_EXTENSION);
  buf->put<uint8_t>(0x0);
  buf->put(logkv::bytesAsSpan(data));
  doSocketSend(addr, buf);
}

void Minx::verifyPoWs(const size_t limit) {
  std::lock_guard lock(verifyPoWsMutex_);
  Hash key;
  {
    std::lock_guard lock(keyMutex_);
    if (!keySet_) {
      throw std::runtime_error(
        "cannot call verifyPoWs() before setServerKey()");
    }
    key = key_;
  }
  std::shared_ptr<PoWEngine> engine_ptr;
  {
    std::lock_guard lock(vmsMutex_);
    auto it = vms_.find(key);
    if (it != vms_.end()) {
      engine_ptr = it->second;
    }
  }
  if (!engine_ptr || !engine_ptr->isReady()) {
    return;
  }
  randomx_vm* vm = engine_ptr->getVM();

  {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    const uint64_t current_slot_time = (now / spendSlotSize_) * spendSlotSize_;
    if (current_slot_time < spendBaseTime_ ||
        current_slot_time >= spendBaseTime_ + spend_.size() * spendSlotSize_) {
      spend_.clear();
      spendBaseTime_ = current_slot_time;
      spend_.emplace_back();
      spend_.emplace_back();
    } else {
      const size_t current_slot_idx =
        (current_slot_time - spendBaseTime_) / spendSlotSize_;
      if (current_slot_idx == spend_.size() - 1) {
        spend_.emplace_back();
      }
    }
    while (spend_.size() > 2) {
      spend_.pop_front();
      spendBaseTime_ += spendSlotSize_;
    }
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

    MinxProveWork& work_item = work_item_opt->first;
    SockAddr& work_sockaddr = work_item_opt->second;
    ++verified_count;

    uint8_t work_diff = getDifficulty(work_item.solution);
    if (work_diff < minDiff_) {
      lastError_ = MINX_ERROR_LOW_DIFF;
      continue;
    }

    size_t slot_index;
    {
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
      if (work_item.time < spendBaseTime_ || work_item.time > now + 5 * 60) {
        lastError_ = MINX_ERROR_UNTIMELY_POW;
        continue;
      }
      slot_index = (work_item.time - spendBaseTime_) / spendSlotSize_;
      if (slot_index >= spend_.size()) {
        throw std::runtime_error("double-spend logic error");
      }
      if (spend_[slot_index].count(work_item.solution)) {
        lastError_ = MINX_ERROR_DOUBLE_SPEND;
        continue;
      }
    }

    minx::ArrayBuffer<HASH_INPUT_SIZE> input_buffer;
    input_buffer.put(work_item.ckey);
    input_buffer.put(work_item.hdata);
    input_buffer.put(work_item.time);
    input_buffer.put(work_item.nonce);
    Hash calculated_hash;
    randomx_calculate_hash(vm, input_buffer.getBackingSpan().data(),
                           input_buffer.getSize(), calculated_hash.data());

    if (calculated_hash == work_item.solution) {
      spend_[slot_index].insert(work_item.solution);
      listener_->incomingProveWork(work_sockaddr, work_item, work_diff);
    } else {
      lastError_ = MINX_ERROR_MISMATCHED_POW;
      // need to penalize sender since randomx_calculate_hash() was expensive.
      // solution might have been altered by MitM or the sender address might
      // be spoofed, but this penalty cannot be avoided in any case.
      ipFilter_.reportIP(work_sockaddr.address());
    }
  }
}

void Minx::createVM(const Hash& key) {
  {
    std::lock_guard lock(vmsMutex_);
    if (vms_.count(key)) {
      return;
    }
    vms_.try_emplace(key,
                     std::make_shared<PoWEngine>(std::span(key), useDataset_));
  }
  {
    std::lock_guard lock(queueMutex_);
    pendingInitializations_.push(key);
  }
  queueCondVar_.notify_one();
};

std::shared_ptr<PoWEngine> Minx::getVM(const Hash& key) {
  std::shared_ptr<PoWEngine> engine_ptr;
  {
    std::lock_guard lock(vmsMutex_);
    auto it = vms_.find(key);
    if (it != vms_.end()) {
      engine_ptr = it->second;
    }
  }
  return engine_ptr;
}

bool Minx::checkVM(const Hash& key) {
  std::shared_ptr<PoWEngine> engine_ptr = getVM(key);
  if (!engine_ptr) {
    return false;
  }
  auto state = engine_ptr->getState();
  if (state == PoWEngineState::Error) {
    throw std::runtime_error("VM initialization failed: " +
                             engine_ptr->getErrorMessage());
  }
  return engine_ptr->isReady();
}

bool Minx::destroyVM(const Hash& key) {
  std::lock_guard{vmsMutex_};
  auto it = vms_.find(key);
  if (it == vms_.end()) {
    return false;
  }
  vms_.erase(it);
  return true;
}

std::optional<MinxProveWork>
Minx::proveWork(const Hash& myKey, const Hash& hdata, const Hash& targetKey,
                int difficulty, int numThreads, uint64_t startNonce,
                uint64_t maxIters, int maxVMs) {
  std::shared_ptr<PoWEngine> engine_ptr;
  {
    std::lock_guard lock(vmsMutex_);
    auto it = vms_.find(targetKey);
    if (it != vms_.end()) {
      engine_ptr = it->second;
    }
  }
  if (!engine_ptr) {
    throw std::runtime_error("VM not found");
  }
  if (!engine_ptr->isReady()) {
    throw std::runtime_error("VM not ready");
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
      randomx_vm* vm = engine_ptr->getVM(i);
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
        const uint64_t time = std::chrono::duration_cast<std::chrono::seconds>(
                                p1.time_since_epoch())
                                .count();

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
  if (maxVMs > 0) {
    engine_ptr->resizeVMs(maxVMs);
  }
  return result;
}

void Minx::banAddress(const IPAddr& addr) { ipFilter_.reportIP(addr); }

void Minx::doSocketSend(const SockAddr& addr,
                        const std::shared_ptr<minx::Buffer>& buf) {
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  socket_->async_send_to(
    buf->getAsioBufferToRead(), addr,
    [buf](const boost::system::error_code&, std::size_t) {});
}

void Minx::receive() {
  ++handlerCount_;
  socket_->async_receive_from(
    buffer_.getAsioBufferToWrite(), remoteAddr_,
    boost::asio::bind_executor(*strand_,
                               std::bind_front(&Minx::onReceive, this)));
}

void Minx::onReceive(const boost::system::error_code& error,
                     size_t bytes_transferred) {
  AtomicDec<uint64_t> dec(handlerCount_);
  if (error == boost::asio::error::operation_aborted) {
    // socket is closing; don't post another receive
    return;
  }
  try {
    uint8_t code;
    if (error || bytes_transferred < sizeof(code) ||
        ipFilter_.checkIP(remoteAddr_.address())) {
      // drop message
    } else {
      // process message
      // note that this calls application callbacks (listener_)
      buffer_.setSize(bytes_transferred);
      buffer_.setReadPos(0);
      code = buffer_.get<uint8_t>();

      switch (code) {
      case MINX_INIT: {
        size_t bytes_expected = sizeof(code) + MinxInit::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_INIT;
          break;
        }
        const uint8_t version = buffer_.get<uint8_t>();
        const uint64_t gpassword = buffer_.get<uint64_t>();
        Bytes data = buffer_.getRemainingBytes();
        MinxInit msg{version, gpassword, data};
        listener_->incomingInit(remoteAddr_, msg);
        break;
      }

      case MINX_MESSAGE: {
        size_t bytes_expected = sizeof(code) + MinxMessage::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_MESSAGE;
          break;
        }
        const uint8_t version = buffer_.get<uint8_t>();
        const uint64_t gpassword = buffer_.get<uint64_t>();
        const uint64_t spassword = buffer_.get<uint64_t>();
        if (spassword == 0 ||
            !spendPassword(spassword, remoteAddr_.address())) {
          lastError_ = MINX_ERROR_BAD_MESSAGE;
          break;
        }
        Bytes data = buffer_.getRemainingBytes();
        MinxMessage msg{version, gpassword, spassword, data};
        listener_->incomingMessage(remoteAddr_, msg);
        break;
      }

      case MINX_GET_INFO: {
        size_t bytes_expected = sizeof(code) + MinxGetInfo::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_GET_INFO;
          break;
        }
        const uint8_t version = buffer_.get<uint8_t>();
        const uint64_t gpassword = buffer_.get<uint64_t>();
        Bytes data = buffer_.getRemainingBytes();
        MinxGetInfo msg{version, gpassword, data};
        listener_->incomingGetInfo(remoteAddr_, msg);
        break;
      }

      case MINX_INFO: {
        size_t bytes_expected = sizeof(code) + MinxInfo::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_INFO;
          break;
        }
        const uint8_t version = buffer_.get<uint8_t>();
        const uint8_t engine_id = version & 0x0F;
        if (engine_id != 0x0) {
          lastError_ = MINX_ERROR_BAD_INFO;
          break;
        }
        const uint64_t gpassword = buffer_.get<uint64_t>();
        const uint64_t spassword = buffer_.get<uint64_t>();
        if (spassword == 0 ||
            !spendPassword(spassword, remoteAddr_.address())) {
          lastError_ = MINX_ERROR_BAD_INFO;
          break;
        }
        Hash skey = buffer_.get<Hash>();
        const uint8_t difficulty = buffer_.get<uint8_t>();
        Bytes data = buffer_.getRemainingBytes();
        MinxInfo msg{version, gpassword, spassword, difficulty, skey, data};
        listener_->incomingInfo(remoteAddr_, msg);
        break;
      }

      case MINX_PROVE_WORK: {
        size_t bytes_expected = sizeof(code) + MinxProveWork::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_PROVE_WORK;
          break;
        }
        const uint8_t version = buffer_.get<uint8_t>();
        const uint8_t engine_id = version & 0x0F;
        if (engine_id != 0x0) {
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
        bool password_matched =
          spassword > 0 && spendPassword(spassword, remoteAddr_.address());
        if (!password_matched) {
          if (!listener_->isConnected(remoteAddr_)) {
            lastError_ = MINX_ERROR_NOT_CONNECTED;
            break;
          }
        }
        MinxProveWork msg{version, gpassword, spassword, ckey, hdata,
                          time,    nonce,     solution,  data};
        {
          std::lock_guard lock(workMutex_);
          work_.push({std::move(msg), remoteAddr_});
        }
        break;
      }

      case MINX_EXTENSION: {
        uint8_t version;
        size_t bytes_expected = sizeof(code) + sizeof(version);
        if (bytes_transferred < bytes_expected) {
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
        listener_->incomingApplication(remoteAddr_, code, data);
      } break;
      }
    }
  } catch (const std::exception& ex) {
    // just to ensure receive() still gets called.
    // app's io_context run thread can figure out what to do with the exception.
    // if it's handled, the receive loop continues normally.
    receive();
    throw ex;
  }
  receive();
}

void Minx::workerLoop() {
  while (!stopWorker_) {
    Hash keyToInitialize;
    {
      std::unique_lock lock(queueMutex_);
      queueCondVar_.wait(lock, [this] {
        return !pendingInitializations_.empty() || stopWorker_;
      });
      if (stopWorker_ && pendingInitializations_.empty()) {
        return;
      }
      keyToInitialize = pendingInitializations_.front();
      pendingInitializations_.pop();
    }
    std::shared_ptr<PoWEngine> engine_ptr;
    {
      std::lock_guard lock(vmsMutex_);
      auto it = vms_.find(keyToInitialize);
      if (it != vms_.end()) {
        engine_ptr = it->second;
      }
    }
    if (engine_ptr) {
      engine_ptr->initialize(randomXThreads_);
    } else {
      throw std::runtime_error("missing PoWEngine to initialize");
    }
  }
}

} // namespace minx