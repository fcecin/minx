#include <minx/powengine.h>

#include <minx/blog.h>
LOG_MODULE_DISABLED("powengine")

#include <logkv/hex.h>

RandomXVM::RandomXVM(randomx_vm* vm) : vm_(vm) {
  if (!vm_) {
    throw std::runtime_error(
      "RandomXVM cannot be constructed from a randomx_vm* nullptr");
  }
}

RandomXVM::~RandomXVM() {
  randomx_destroy_vm(vm_);
  vm_ = nullptr;
}

randomx_vm* RandomXVM::vm() { return vm_; }

RandomXVMReleaser::RandomXVMReleaser(PoWEngine* powEngine,
                                     std::shared_ptr<RandomXVM> rxvmSptr)
    : powEngine_(powEngine), rxvmSptr_(rxvmSptr) {
  if (!powEngine_) {
    throw std::runtime_error("RandomXVMReleaser cannot be constructed "
                             "from a PoWEngine* nullptr");
  }
  ++powEngine_->pendingReleasers_;
}

RandomXVMReleaser::~RandomXVMReleaser() {
  powEngine_->releaseVM(rxvmSptr_);
  --powEngine_->pendingReleasers_;
}

randomx_vm* RandomXVMReleaser::vm() {
  return rxvmSptr_ ? rxvmSptr_->vm() : nullptr;
}

PoWEngine::PoWEngine(std::span<const uint8_t> key, bool full_mem, int vmsToKeep)
    : is_full_mem_(full_mem), key_(key.begin(), key.end()) {
  vmsToKeep_ = vmsToKeep;
  if (vmsToKeep_ < 1) {
    vmsToKeep = std::thread::hardware_concurrency() * 2;
  }
  if (!key_.empty()) {
    size_t len = std::min(key_.size(), size_t{4});
    instanceName_ = std::string(8, '\0');
    logkv::encodeHex(instanceName_.data(), instanceName_.size(),
                     reinterpret_cast<const char*>(key_.data()), len, true);
  }
}

PoWEngine::~PoWEngine() {
  LOGTRACE << "~PoWEngine start";
  destruction_requested_ = true;
  while (state_ == PoWEngineState::Initializing) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  LOGTRACE << "~PoWEngine waiting releasers";
  while (pendingReleasers_ > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  LOGTRACE << "~PoWEngine cleaning up";
  cleanup();
  LOGTRACE << "~PoWEngine done";
}

PoWEngine::PoWEngine(PoWEngine&& other) noexcept {
  move_from(std::move(other));
}

PoWEngine& PoWEngine::operator=(PoWEngine&& other) noexcept {
  if (this != &other) {
    cleanup();
    move_from(std::move(other));
  }
  return *this;
}

// if num_threads < 1, it will be set to max(1, thread::hardware_concurrency())
bool PoWEngine::initialize(int num_threads) {
  LOGTRACE << "initialize" << VAR(num_threads) << VAR(key_);
  PoWEngineState expected = PoWEngineState::Uninitialized;
  if (!state_.compare_exchange_strong(expected, PoWEngineState::Initializing)) {
    while (getState() == PoWEngineState::Initializing) {
      if (destruction_requested_)
        break;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    bool ready = isReady();
    LOGTRACE << "initialize skipped" << VAR(ready);
    return ready;
  }
  LOGTRACE << "initialize starting";
  try {
    if (destruction_requested_) {
      LOGTRACE << "initialize aborted";
      throw std::runtime_error("Initialization aborted before start.");
    }
    randomx_flags flags = randomx_get_flags();
    if (is_full_mem_) {
      flags |= RANDOMX_FLAG_FULL_MEM;
    }
    LOGTRACE << "initialize allocate cache";
    cache_ = randomx_alloc_cache(flags);
    if (cache_ == nullptr) {
      LOGTRACE << "initialize allocate cache failed";
      throw std::runtime_error("Failed to allocate RandomX cache");
    }
    LOGTRACE << "initialize allocate cache done";
    if (destruction_requested_) {
      LOGTRACE << "initialize aborted before init cache";
      throw std::runtime_error("Initialization aborted before init cache.");
    }
    LOGTRACE << "initialize init cache";
    randomx_init_cache(cache_, key_.data(), key_.size());
    LOGTRACE << "initialize init cache done";
    if (is_full_mem_) {
      LOGTRACE << "initialize allocate dataset";
      dataset_ = randomx_alloc_dataset(flags);
      if (dataset_ == nullptr) {
        LOGTRACE << "initialize allocate dataset failed";
        throw std::runtime_error("Failed to allocate RandomX dataset");
      }
      LOGTRACE << "initialize allocate dataset done";
      std::vector<std::thread> thread_pool;
      try {
        if (destruction_requested_) {
          LOGTRACE << "initialize aborted before init dataset";
          throw std::runtime_error(
            "Initialization aborted before init dataset.");
        }
        if (num_threads < 1) {
          num_threads = std::max(static_cast<unsigned int>(1),
                                 std::thread::hardware_concurrency());
        }
        const unsigned long total_item_count = randomx_dataset_item_count();
        const unsigned long items_per_thread = total_item_count / num_threads;
        unsigned long start_item = 0;

        auto batch_worker = [this](unsigned long start, unsigned long count) {
          constexpr unsigned long BATCH_SIZE = 32768;
          unsigned long processed = 0;
          unsigned long iters = 0;
          while (processed < count) {
            if (destruction_requested_) {
              LOGTRACE << "initialize interrupted init thread" << VAR(start)
                       << VAR(processed) << VAR(count) << VAR(iters);
              return;
            }
            ++iters;
            unsigned long current_batch =
              std::min(BATCH_SIZE, count - processed);
            randomx_init_dataset(dataset_, cache_, start + processed,
                                 current_batch);
            processed += current_batch;
          }
        };
        LOGTRACE << "initialize spawning threads" << VAR(num_threads);
        for (int i = 0; i < num_threads - 1; ++i) {
          thread_pool.emplace_back(batch_worker, start_item, items_per_thread);
          start_item += items_per_thread;
        }
        unsigned long remaining_items = total_item_count - start_item;
        if (remaining_items > 0) {
          batch_worker(start_item, remaining_items);
        }
        LOGTRACE << "initialize joining threads" << VAR(num_threads);
        for (auto& t : thread_pool) {
          t.join();
        }
      } catch (...) {
        LOGTRACE << "initialize crashed; joining threads";
        for (auto& t : thread_pool) {
          if (t.joinable())
            t.join();
        }
        throw;
      }
    }
    if (destruction_requested_) {
      LOGTRACE << "initialize aborted before finishing";
      throw std::runtime_error(
        "Initialization aborted after before finishing.");
    }
    auto rxvmSptr = acquireVM();
    releaseVM(rxvmSptr);
    LOGTRACE << "initialize finished";
    state_ = PoWEngineState::Ready;
    return true;
  } catch (const std::runtime_error& e) {
    error_message_ = e.what();
    LOGTRACE << "initialize error" << VAR(error_message_);
    state_ = PoWEngineState::Error;
    cleanup();
    return false;
  }
}

void PoWEngine::stop() {
  LOGTRACE << "PoWEngine stopped.";
  destruction_requested_ = true;
}

PoWEngineState PoWEngine::getState() const { return state_; }

bool PoWEngine::isReady() const { return getState() == PoWEngineState::Ready; }

bool PoWEngine::hasError() const { return getState() == PoWEngineState::Error; }

std::string PoWEngine::getErrorMessage() const { return error_message_; }

RandomXVMReleaser PoWEngine::getVM() {
  std::shared_ptr<RandomXVM> rxvmSptr;
  try {
    rxvmSptr = acquireVM();
  } catch (const std::runtime_error& e) {
    // rxvmSptr will be empty if failed to allocate randomx_vm*
  }
  return RandomXVMReleaser(this, rxvmSptr);
}

std::shared_ptr<RandomXVM> PoWEngine::acquireVM() {
  if (!isReady()) {
    return nullptr;
  }
  randomx_flags flags = randomx_get_flags();
  if (is_full_mem_) {
    flags |= RANDOMX_FLAG_FULL_MEM;
  }
  std::unique_lock lock(vmPoolMutex_);
  if (vmPool_.size() > 1024) {
    throw std::runtime_error("Too many RandomX VMs were created for the same "
                             "PoWEngine (this is likely a bug)");
  }
  if (!vmPool_.empty()) {
    auto rxvmSptr = std::move(vmPool_.back());
    vmPool_.pop_back();
    lock.unlock();
    return rxvmSptr;
  }
  lock.unlock();
  randomx_vm* rxvmPtr = randomx_create_vm(flags, cache_, dataset_);
  if (rxvmPtr == nullptr) {
    throw std::runtime_error("Failed to allocate a new RandomX VM");
  }
  return std::make_shared<RandomXVM>(rxvmPtr);
}

void PoWEngine::releaseVM(std::shared_ptr<RandomXVM> rxvmSptr) {
  if (!rxvmSptr)
    return;
  std::lock_guard lock(vmPoolMutex_);
  if (vmPool_.size() < vmsToKeep_) {
    vmPool_.push_back(std::move(rxvmSptr));
  }
}

std::vector<uint8_t> PoWEngine::getKey() { return key_; }

void PoWEngine::cleanup() {
  {
    std::lock_guard<std::mutex> lock(vmPoolMutex_);
    vmPool_.clear();
  }
  if (dataset_)
    randomx_release_dataset(dataset_);
  if (cache_)
    randomx_release_cache(cache_);
  dataset_ = nullptr;
  cache_ = nullptr;
  key_.clear();
  // instanceName_.clear(); -- used by dtor to print
  error_message_.clear();
}

void PoWEngine::move_from(PoWEngine&& other) {
  std::lock_guard<std::mutex> lock(other.vmPoolMutex_);
  cache_ = other.cache_;
  dataset_ = other.dataset_;
  vmPool_ = std::move(other.vmPool_);
  is_full_mem_ = other.is_full_mem_;
  key_ = std::move(other.key_);
  instanceName_ = std::move(other.instanceName_);
  error_message_ = std::move(other.error_message_);
  state_.store(other.state_.load(std::memory_order_relaxed),
               std::memory_order_relaxed);
  destruction_requested_.store(
    other.destruction_requested_.load(std::memory_order_relaxed),
    std::memory_order_relaxed);
  other.cache_ = nullptr;
  other.dataset_ = nullptr;
  other.state_.store(PoWEngineState::Uninitialized);
  other.destruction_requested_.store(false);
  other.key_.clear();
  other.instanceName_.clear();
  other.error_message_.clear();
}