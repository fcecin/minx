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
  RandomXVM(randomx_vm* vm);
  ~RandomXVM();
  randomx_vm* vm();

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
  randomx_vm* vm();

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
                     int vmsToKeep = 256);
  ~PoWEngine();
  PoWEngine(const PoWEngine&) = delete;
  PoWEngine& operator=(const PoWEngine&) = delete;
  PoWEngine(PoWEngine&& other) noexcept;
  PoWEngine& operator=(PoWEngine&& other) noexcept;

  bool initialize(int num_threads = 0);
  void stop();
  PoWEngineState getState() const;
  bool isReady() const;
  bool hasError() const;
  std::string getErrorMessage() const;
  RandomXVMReleaser getVM();
  std::shared_ptr<RandomXVM> acquireVM();
  void releaseVM(std::shared_ptr<RandomXVM> rxvmSptr);
  std::vector<uint8_t> getKey();

private:
  void cleanup();
  void move_from(PoWEngine&& other);

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
};

#endif