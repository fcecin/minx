#include <boost/endian/conversion.hpp>
#include <minx/minx.h>
#include <random>
#include <sstream>

namespace minx {

template <typename T> class AtomicDec {
public:
  AtomicDec(std::atomic<T>& c) : c_(c) {}
  ~AtomicDec() { --c_; }

private:
  std::atomic<T>& c_;
};

Minx::Minx(MinxListener* listener, int randomXThreads, uint64_t spendSlotSize)
    : listener_(listener), randomXThreads_(randomXThreads),
      spendSlotSize_(spendSlotSize), passwords_(1'000'000, 60) {
  if (!listener_) {
    throw std::runtime_error("listener cannot be nullptr");
  }
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
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->push_back(MINX_INIT);
  buf->push_back(msg.version);
  buf->insert(buf->end(), msg.data.data(), msg.data.data() + msg.data.size());
  socket_->async_send_to(boost::asio::buffer(*buf), addr,
                         boost::asio::detached);
}

void Minx::sendInitAck(const SockAddr& addr, const MinxInitAck& msg) {
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->push_back(MINX_INIT_ACK);
  buf->push_back(msg.version);
  const uint64_t password_be = boost::endian::native_to_big(msg.password);
  const uint8_t* p_password = reinterpret_cast<const uint8_t*>(&password_be);
  buf->insert(buf->end(), p_password, p_password + sizeof(password_be));
  if (msg.password > 0) {
    passwords_.put(msg.password, addr.address());
  }
  buf->insert(buf->end(), msg.skey.begin(), msg.skey.end());
  buf->push_back(msg.difficulty);
  buf->insert(buf->end(), msg.data.data(), msg.data.data() + msg.data.size());
  socket_->async_send_to(boost::asio::buffer(*buf), addr,
                         boost::asio::detached);
}

void Minx::sendProveWork(const SockAddr& addr, const MinxProveWork& msg) {
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->push_back(MINX_PROVE_WORK);
  buf->push_back(msg.version);
  const uint64_t password_be = boost::endian::native_to_big(msg.password);
  const uint8_t* p_password = reinterpret_cast<const uint8_t*>(&password_be);
  buf->insert(buf->end(), p_password, p_password + sizeof(password_be));
  buf->insert(buf->end(), msg.ckey.begin(), msg.ckey.end());
  const uint64_t time_be = boost::endian::native_to_big(msg.time);
  const uint8_t* p_time = reinterpret_cast<const uint8_t*>(&time_be);
  buf->insert(buf->end(), p_time, p_time + sizeof(time_be));
  const uint64_t nonce_be = boost::endian::native_to_big(msg.nonce);
  const uint8_t* p_nonce = reinterpret_cast<const uint8_t*>(&nonce_be);
  buf->insert(buf->end(), p_nonce, p_nonce + sizeof(nonce_be));
  buf->insert(buf->end(), msg.solution.begin(), msg.solution.end());
  buf->insert(buf->end(), msg.data.data(), msg.data.data() + msg.data.size());
  socket_->async_send_to(boost::asio::buffer(*buf), addr,
                         boost::asio::detached);
}

void Minx::sendApplication(const SockAddr& addr, const Bytes& data,
                           const uint8_t code) {
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  if (code > MINX_APPLICATION_MAX) {
    throw std::runtime_error("invalid application message code");
  }
  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->push_back(code);
  buf->insert(buf->end(), data.data(), data.data() + data.size());
  socket_->async_send_to(boost::asio::buffer(*buf), addr,
                         boost::asio::detached);
}

void Minx::sendExtension(const SockAddr& addr, const Bytes& data) {
  std::shared_lock lock(socketStateMutex_);
  if (!socket_) {
    throw std::runtime_error("no socket");
  }
  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->push_back(MINX_EXTENSION);
  buf->push_back(0x0);
  buf->insert(buf->end(), data.data(), data.data() + data.size());
  socket_->async_send_to(boost::asio::buffer(*buf), addr,
                         boost::asio::detached);
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
      work_.pop_front();
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

    std::vector<uint8_t> input_buffer;
    input_buffer.reserve(sizeof(Hash) + sizeof(uint64_t) * 2);
    input_buffer.insert(input_buffer.end(), work_item.ckey.begin(),
                        work_item.ckey.end());
    const uint64_t time_be = boost::endian::native_to_big(work_item.time);
    const uint8_t* time_bytes = reinterpret_cast<const uint8_t*>(&time_be);
    input_buffer.insert(input_buffer.end(), time_bytes,
                        time_bytes + sizeof(time_be));
    const uint64_t nonce_be = boost::endian::native_to_big(work_item.nonce);
    const uint8_t* nonce_bytes = reinterpret_cast<const uint8_t*>(&nonce_be);
    input_buffer.insert(input_buffer.end(), nonce_bytes,
                        nonce_bytes + sizeof(nonce_be));

    Hash calculated_hash;
    randomx_calculate_hash(vm, input_buffer.data(), input_buffer.size(),
                           calculated_hash.data());

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

std::optional<MinxProveWork> Minx::proveWork(const Hash& myKey,
                                             const Hash& targetKey,
                                             int difficulty, int numThreads,
                                             int maxVMs) {
  std::shared_ptr<PoWEngine> engine_ptr;
  {
    std::lock_guard lock(vmsMutex_);
    auto it = vms_.find(targetKey);
    if (it != vms_.end()) {
      engine_ptr = it->second;
    }
  }
  if (!engine_ptr || !engine_ptr->isReady()) {
    return std::nullopt;
  }
  std::atomic<bool> solution_found = false;
  std::atomic<uint64_t> nonce_counter = 0;
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
      while (!solution_found.load(std::memory_order_relaxed)) {
        const auto p1 = std::chrono::system_clock::now();
        const uint64_t time = std::chrono::duration_cast<std::chrono::seconds>(
                                p1.time_since_epoch())
                                .count();
        uint64_t nonce = nonce_counter.fetch_add(1, std::memory_order_relaxed);
        std::vector<uint8_t> input_buffer;
        input_buffer.reserve(sizeof(Hash) + sizeof(uint64_t) * 2);
        input_buffer.insert(input_buffer.end(), myKey.begin(), myKey.end());
        const uint64_t time_be = boost::endian::native_to_big(time);
        const uint8_t* time_bytes = reinterpret_cast<const uint8_t*>(&time_be);
        input_buffer.insert(input_buffer.end(), time_bytes,
                            time_bytes + sizeof(time));
        const uint64_t nonce_be = boost::endian::native_to_big(nonce);
        const uint8_t* nonce_bytes =
          reinterpret_cast<const uint8_t*>(&nonce_be);
        input_buffer.insert(input_buffer.end(), nonce_bytes,
                            nonce_bytes + sizeof(nonce));
        Hash solution_hash;
        randomx_calculate_hash(vm, input_buffer.data(), input_buffer.size(),
                               solution_hash.data());
        if (getDifficulty(solution_hash) >= difficulty) {
          bool already_found =
            solution_found.exchange(true, std::memory_order_acq_rel);
          if (!already_found) {
            std::lock_guard<std::mutex> lock(result_mutex);
            result.emplace(
              MinxProveWork{0, 0, myKey, time, nonce, solution_hash, {}});
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

void Minx::receive() {
  ++handlerCount_;
  socket_->async_receive_from(
    boost::asio::buffer(buffer_), remoteAddr_,
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
      code = buffer_[0];
      const char* p = buffer_.data();

      switch (code) {
      case MINX_INIT: {
        size_t bytes_expected = sizeof(code) + MinxInit::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_INIT;
          break;
        }

        const uint8_t version = p[sizeof(code)];
        Bytes data;
        if (bytes_transferred > bytes_expected) {
          data.assign(&p[2], bytes_transferred - bytes_expected);
        }

        MinxInit msg{version, data};
        listener_->incomingInit(remoteAddr_, msg);
        break;
      }

      case MINX_INIT_ACK: {
        size_t bytes_expected = sizeof(code) + MinxInitAck::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_INIT_ACK;
          break;
        }

        const uint8_t version = p[sizeof(code)];
        const uint8_t engine_id = version & 0x0F;
        if (engine_id != 0x0) {
          lastError_ = MINX_ERROR_BAD_INIT_ACK;
          break;
        }

        size_t offset = sizeof(code) + sizeof(version);

        uint64_t password_be;
        memcpy(&password_be, &p[offset], sizeof(password_be));
        const uint64_t password = boost::endian::big_to_native(password_be);
        offset += sizeof(password);

        Hash skey;
        memcpy(skey.data(), &p[offset], sizeof(skey));
        offset += sizeof(skey);

        const uint8_t difficulty = p[offset];
        offset += sizeof(difficulty);

        Bytes data;
        if (bytes_transferred > offset) {
          data.assign(&p[offset], bytes_transferred - offset);
        }
        MinxInitAck msg{version, password, difficulty, skey, data};
        listener_->incomingInitAck(remoteAddr_, msg);
        break;
      }

      case MINX_PROVE_WORK: {
        size_t bytes_expected = sizeof(code) + MinxProveWork::SIZE;
        if (bytes_transferred < bytes_expected) {
          lastError_ = MINX_ERROR_BAD_PROVE_WORK;
          break;
        }

        const uint8_t version = p[sizeof(code)];
        const uint8_t engine_id = version & 0x0F;
        if (engine_id != 0x0) {
          lastError_ = MINX_ERROR_BAD_PROVE_WORK;
          break;
        }

        size_t offset = sizeof(code) + sizeof(version);

        uint64_t password_be;
        memcpy(&password_be, &p[offset], sizeof(password_be));
        uint64_t password = boost::endian::big_to_native(password_be);
        offset += sizeof(password);

        Hash ckey;
        memcpy(ckey.data(), &p[offset], sizeof(ckey));
        offset += sizeof(ckey);

        uint64_t time_be;
        memcpy(&time_be, &p[offset], sizeof(time_be));
        const uint64_t time = boost::endian::big_to_native(time_be);
        offset += sizeof(time);

        uint64_t nonce_be;
        memcpy(&nonce_be, &p[offset], sizeof(nonce_be));
        const uint64_t nonce = boost::endian::big_to_native(nonce_be);
        offset += sizeof(nonce);

        Hash solution;
        memcpy(solution.data(), &p[offset], sizeof(solution));
        offset += sizeof(solution);

        Bytes data;
        if (bytes_transferred > offset) {
          data.assign(&p[offset], bytes_transferred - offset);
        }

        bool password_matched = false;
        if (password > 0) {
          auto ip_opt = passwords_.get(password);
          if (ip_opt && ip_opt.value() == remoteAddr_.address()) {
            passwords_.erase(password);
            password_matched = true;
          }
        }

        if (!password_matched) {
          if (!listener_->isConnected(remoteAddr_)) {
            lastError_ = MINX_ERROR_NOT_CONNECTED;
            break;
          }
        }

        MinxProveWork msg{version, password, ckey, time, nonce, solution, data};
        {
          std::lock_guard lock(workMutex_);
          work_.push_back({std::move(msg), remoteAddr_});
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
        version = p[sizeof(code)];
        Bytes data;
        if (bytes_transferred > bytes_expected) {
          data.assign(&p[bytes_expected], bytes_transferred - bytes_expected);
        }
        listener_->incomingExtension(remoteAddr_, data);
        break;
      }

      default: {
        // Any other code is an APPLICATION message code [0x00, 0xFB]
        Bytes data;
        if (bytes_transferred > sizeof(code)) {
          data.assign(&p[sizeof(code)], bytes_transferred - sizeof(code));
        }
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