#ifndef _MINXPOWENGINE_H_
#define _MINXPOWENGINE_H_

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <randomx.h>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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
 * RandomX cache, dataset, and VMs for a given key.
 */
class PoWEngine {
public:
  explicit PoWEngine(std::span<const uint8_t> key, bool full_mem = true)
      : is_full_mem_(full_mem), key_(key.begin(), key.end()) {}

  ~PoWEngine() {
    destruction_requested_.store(true, std::memory_order_release);
    while (state_.load(std::memory_order_acquire) ==
           PoWEngineState::Initializing) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
        if (destruction_requested_.load(std::memory_order_acquire))
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      return isReady();
    }
    try {
      if (destruction_requested_.load(std::memory_order_acquire)) {
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
      if (destruction_requested_.load(std::memory_order_acquire)) {
        throw std::runtime_error(
          "Initialization aborted after dataset creation.");
      }
      randomx_vm* initial_vm = randomx_create_vm(flags, cache_, dataset_);
      if (initial_vm == nullptr)
        throw std::runtime_error("Failed to create initial RandomX VM");
      vms_.push_back(initial_vm);
      state_.store(PoWEngineState::Ready, std::memory_order_release);
      return true;
    } catch (const std::runtime_error& e) {
      error_message_ = e.what();
      state_.store(PoWEngineState::Error, std::memory_order_release);
      cleanup();
      return false;
    }
  }

  PoWEngineState getState() const {
    return state_.load(std::memory_order_acquire);
  }

  bool isReady() const { return getState() == PoWEngineState::Ready; }

  bool hasError() const { return getState() == PoWEngineState::Error; }

  std::string getErrorMessage() const { return error_message_; }

  randomx_vm* getVM(size_t index = 0) {
    if (!isReady()) {
      return nullptr;
    }
    randomx_flags flags = randomx_get_flags();
    if (is_full_mem_) {
      flags |= RANDOMX_FLAG_FULL_MEM;
    }
    std::lock_guard<std::mutex> lock(vms_mutex_);
    while (index >= vms_.size()) {
      randomx_vm* vm = randomx_create_vm(flags, cache_, dataset_);
      if (vm == nullptr) {
        throw std::runtime_error("Failed to create RandomX VM at index " +
                                 std::to_string(vms_.size()));
      }
      vms_.push_back(vm);
    }
    return vms_[index];
  }

  void resizeVMs(size_t count) {
    if (!isReady()) {
      return;
    }
    std::lock_guard<std::mutex> lock(vms_mutex_);
    if (count < vms_.size()) {
      for (size_t i = count; i < vms_.size(); ++i) {
        if (vms_[i] != nullptr) {
          randomx_destroy_vm(vms_[i]);
        }
      }
      vms_.resize(count);
    }
  }

private:
  randomx_cache* cache_ = nullptr;
  randomx_dataset* dataset_ = nullptr;
  std::vector<randomx_vm*> vms_;
  std::mutex vms_mutex_;

  bool is_full_mem_ = false;
  std::vector<uint8_t> key_;
  std::atomic<PoWEngineState> state_ = PoWEngineState::Uninitialized;
  std::atomic<bool> destruction_requested_ = false;
  std::string error_message_;

  void cleanup() {
    {
      std::lock_guard<std::mutex> lock(vms_mutex_);
      for (randomx_vm* vm : vms_) {
        if (vm)
          randomx_destroy_vm(vm);
      }
      vms_.clear();
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
    std::lock_guard<std::mutex> lock(other.vms_mutex_);
    cache_ = other.cache_;
    dataset_ = other.dataset_;
    vms_ = std::move(other.vms_);
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