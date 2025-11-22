#ifndef _MINXPOWENGINE_H_
#define _MINXPOWENGINE_H_

#include <atomic>
#include <chrono>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

#include <randomx.h>

/**
 * PoWEngine state.
 */
enum class PoWEngineState {
  Uninitialized,
  Initializing,
  Ready,
  Error
};

/**
 * Lifetime wrapper for a single RandomX VM.
 */
class RandomXVM {
public:
  RandomXVM(randomx_vm* vm) : vm_(vm) {
    if (!vm_) {
      throw std::runtime_error(
        "RandomXVM cannot be constructed from a randomx_vm* nullptr");
    }
  }
  ~RandomXVM() {
    randomx_destroy_vm(vm_);
    vm_ = nullptr;
  }
  randomx_vm* vm() { return vm_; }

private:
  randomx_vm* vm_;
};

/**
 * Lifetime wrapper for a RandomXVM being PoWEngine::releaseVM()'d back into the
 * VM pool. Pending releasers will block the PoWEngine destructor.
 */
class PoWEngine;
class RandomXVMReleaser {
public:
  RandomXVMReleaser(PoWEngine* powEngine, std::shared_ptr<RandomXVM> rxvmSptr);
  ~RandomXVMReleaser();
  randomx_vm* vm() { return rxvmSptr_ ? rxvmSptr_->vm() : nullptr; }

private:
  PoWEngine* powEngine_;
  std::shared_ptr<RandomXVM> rxvmSptr_;
};

/**
 * RandomX cache, dataset, and VMs for a given key.
 */
class PoWEngine {
public:
  explicit PoWEngine(std::span<const uint8_t> key, bool full_mem = true,
                     int vmsToKeep = 256)
      : is_full_mem_(full_mem), key_(key.begin(), key.end()) {
    vmsToKeep_ = vmsToKeep;
    if (vmsToKeep_ < 1) {
      vmsToKeep = std::thread::hardware_concurrency() * 2;
    }
  }

  ~PoWEngine() {
    destruction_requested_ = true;
    while (state_ == PoWEngineState::Initializing) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    while (pendingReleasers_ > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    cleanup();
  }

  PoWEngine(const PoWEngine&) = delete;

  PoWEngine& operator=(const PoWEngine&) = delete;

  PoWEngine(PoWEngine&& other) noexcept { move_from(std::move(other)); }

  PoWEngine& operator=(PoWEngine&& other) noexcept {
    if (this != &other) {
      cleanup();
      move_from(std::move(other));
    }
    return *this;
  }

  // if num_threads < 1, it will be set to max(1,
  // thread::hardware_concurrency())
  bool initialize(int num_threads = 0) {
    PoWEngineState expected = PoWEngineState::Uninitialized;
    if (!state_.compare_exchange_strong(expected,
                                        PoWEngineState::Initializing)) {
      while (getState() == PoWEngineState::Initializing) {
        if (destruction_requested_)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      return isReady();
    }
    try {
      if (destruction_requested_) {
        throw std::runtime_error("Initialization aborted before start.");
      }
      randomx_flags flags = randomx_get_flags();
      if (is_full_mem_) {
        flags |= RANDOMX_FLAG_FULL_MEM;
      }
      cache_ = randomx_alloc_cache(flags);
      if (cache_ == nullptr)
        throw std::runtime_error("Failed to allocate RandomX cache");
      randomx_init_cache(cache_, key_.data(), key_.size());
      if (is_full_mem_) {
        dataset_ = randomx_alloc_dataset(flags);
        if (dataset_ == nullptr)
          throw std::runtime_error("Failed to allocate RandomX dataset");
        std::vector<std::thread> thread_pool;
        try {
          if (num_threads < 1) {
            num_threads = std::max(static_cast<unsigned int>(1),
                                   std::thread::hardware_concurrency());
          }
          const unsigned long total_item_count = randomx_dataset_item_count();
          const unsigned long items_per_thread = total_item_count / num_threads;
          unsigned long start_item = 0;
          for (int i = 0; i < num_threads - 1; ++i) {
            thread_pool.emplace_back(&randomx_init_dataset, dataset_, cache_,
                                     start_item, items_per_thread);
            start_item += items_per_thread;
          }
          unsigned long remaining_items = total_item_count - start_item;
          if (remaining_items > 0) {
            randomx_init_dataset(dataset_, cache_, start_item, remaining_items);
          }
          for (auto& t : thread_pool) {
            t.join();
          }
        } catch (...) {
          for (auto& t : thread_pool) {
            if (t.joinable())
              t.join();
          }
          throw;
        }
      }
      if (destruction_requested_) {
        throw std::runtime_error(
          "Initialization aborted after dataset creation.");
      }
      auto rxvmSptr = acquireVM();
      releaseVM(rxvmSptr);
      state_ = PoWEngineState::Ready;
      return true;
    } catch (const std::runtime_error& e) {
      error_message_ = e.what();
      state_ = PoWEngineState::Error;
      cleanup();
      return false;
    }
  }

  PoWEngineState getState() const {
    return state_;
  }

  bool isReady() const { return getState() == PoWEngineState::Ready; }

  bool hasError() const { return getState() == PoWEngineState::Error; }

  std::string getErrorMessage() const { return error_message_; }

  RandomXVMReleaser getVM() {
    std::shared_ptr<RandomXVM> rxvmSptr;
    try {
      rxvmSptr = acquireVM();
    } catch (const std::runtime_error& e) {
      // rxvmSptr will be empty if failed to allocate randomx_vm*
    }
    return RandomXVMReleaser(this, rxvmSptr);
  }

  std::shared_ptr<RandomXVM> acquireVM() {
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

  void releaseVM(std::shared_ptr<RandomXVM> rxvmSptr) {
    if (!rxvmSptr)
      return;
    std::lock_guard lock(vmPoolMutex_);
    if (vmPool_.size() < vmsToKeep_) {
      vmPool_.push_back(std::move(rxvmSptr));
    }
  }

private:
  randomx_cache* cache_ = nullptr;
  randomx_dataset* dataset_ = nullptr;

  bool is_full_mem_ = false;
  std::vector<uint8_t> key_;

  std::vector<std::shared_ptr<RandomXVM>> vmPool_;
  std::mutex vmPoolMutex_;
  int vmsToKeep_ = 0;

  std::atomic<PoWEngineState> state_ = PoWEngineState::Uninitialized;
  std::atomic<bool> destruction_requested_ = false;
  std::string error_message_;

  friend class RandomXVMReleaser;
  std::atomic<int64_t> pendingReleasers_ = 0;

  void cleanup() {
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
    error_message_.clear();
  }

  void move_from(PoWEngine&& other) {
    std::lock_guard<std::mutex> lock(other.vmPoolMutex_);
    cache_ = other.cache_;
    dataset_ = other.dataset_;
    vmPool_ = std::move(other.vmPool_);
    is_full_mem_ = other.is_full_mem_;
    key_ = std::move(other.key_);
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
    other.error_message_.clear();
  }
};

#endif