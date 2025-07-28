#ifndef _MINXPOWENGINE_H_
#define _MINXPOWENGINE_H_

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
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
 * RandomX cache, dataset, and VM for a given key.
 */
class PoWEngine {
public:
  explicit PoWEngine(std::span<const uint8_t> key, bool full_mem = true)
      : is_full_mem_(full_mem), key_(key.begin(), key.end()) {
  }

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
      PoWEngineState finalState = getState();
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
          std::queue<std::pair<unsigned long, unsigned long>> work_queue;
          std::mutex queue_mutex;
          const unsigned long total_item_count = randomx_dataset_item_count();
          const unsigned long batch_size = 16384;
          for (unsigned long i = 0; i < total_item_count; i += batch_size) {
            unsigned long count = std::min(batch_size, total_item_count - i);
            work_queue.push({i, count});
          }
          auto worker_task = [&]() {
            while (true) {
              if (destruction_requested_.load(std::memory_order_acquire))
                break;
              std::pair<unsigned long, unsigned long> job;
              {
                std::lock_guard lock(queue_mutex);
                if (work_queue.empty())
                  break;
                job = work_queue.front();
                work_queue.pop();
              }
              randomx_init_dataset(dataset_, cache_, job.first, job.second);
            }
          };
          if (num_threads < 1) {
            num_threads = std::max(static_cast<unsigned int>(1),
                                   std::thread::hardware_concurrency());
          }
          for (int i = 0; i < num_threads - 1; ++i) {
            thread_pool.emplace_back(worker_task);
          }
          worker_task();
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
      vm_ = randomx_create_vm(flags, cache_, dataset_);
      if (vm_ == nullptr)
        throw std::runtime_error("Failed to create RandomX VM");
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

  randomx_vm* getVM() const { return isReady() ? vm_ : nullptr; }

private:
  randomx_cache* cache_ = nullptr;
  randomx_dataset* dataset_ = nullptr;
  randomx_vm* vm_ = nullptr;
  bool is_full_mem_ = false;
  std::vector<uint8_t> key_;
  std::atomic<PoWEngineState> state_ = PoWEngineState::Uninitialized;
  std::atomic<bool> destruction_requested_ = false;
  std::string error_message_;

  void cleanup() {
    if (vm_)
      randomx_destroy_vm(vm_);
    if (dataset_)
      randomx_release_dataset(dataset_);
    if (cache_)
      randomx_release_cache(cache_);
    vm_ = nullptr;
    dataset_ = nullptr;
    cache_ = nullptr;
    key_.clear();
    error_message_.clear();
  }

  void move_from(PoWEngine&& other) {
    cache_ = other.cache_;
    dataset_ = other.dataset_;
    vm_ = other.vm_;
    is_full_mem_ = other.is_full_mem_;
    state_.store(other.state_.load(std::memory_order_relaxed),
                 std::memory_order_relaxed);
    destruction_requested_.store(
      other.destruction_requested_.load(std::memory_order_relaxed),
      std::memory_order_relaxed);
    key_ = std::move(other.key_);
    error_message_ = std::move(other.error_message_);
    other.cache_ = nullptr;
    other.dataset_ = nullptr;
    other.vm_ = nullptr;
    other.state_.store(PoWEngineState::Uninitialized);
    other.destruction_requested_.store(false);
    other.key_.clear();
    other.error_message_.clear();
  }
};

#endif