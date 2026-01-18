#ifndef _MINX_H_
#define _MINX_H_

#include <array>
#include <deque>
#include <map>
#include <queue>
#include <random>
#include <shared_mutex>
#include <unordered_set>

#include <randomx.h>

#include <minx/bucketcache.h>
#include <minx/buffer.h>
#include <minx/filter.h>
#include <minx/powengine.h>
#include <minx/types.h>

namespace minx {

/**
 * MINX message code.
 */
enum minx_code_t : uint8_t {
  MINX_APPLICATION_MIN = 0x00,
  MINX_APPLICATION_MAX = 0xF9,
  MINX_APPLICATION_DEFAULT = MINX_APPLICATION_MAX,
  MINX_INIT = 0xFA,
  MINX_MESSAGE = 0xFB,
  MINX_GET_INFO = 0xFC,
  MINX_INFO = 0xFD,
  MINX_PROVE_WORK = 0xFE,
  MINX_EXTENSION = 0xFF
};

/**
 * MINX error code for Minx::getLastError().
 */
enum {
  MINX_ERROR_LOW_DIFF = 0x01,
  MINX_ERROR_BAD_GET_INFO = 0x02,
  MINX_ERROR_BAD_INFO = 0x03,
  MINX_ERROR_BAD_PROVE_WORK = 0x04,
  MINX_ERROR_BAD_EXTENSION = 0x05,
  MINX_ERROR_NOT_CONNECTED = 0x06,
  MINX_ERROR_DOUBLE_SPEND = 0x07,
  MINX_ERROR_UNTIMELY_POW = 0x08,
  MINX_ERROR_MISMATCHED_POW = 0x09,
  MINX_ERROR_BAD_INIT = 0x0A,
  MINX_ERROR_BAD_MESSAGE = 0x0B,
  MINX_ERROR_UNEXPECTED = 0xFF
};

/**
 * MINX queryPoW() result.
 */
enum {
  MINX_SOLUTION_UNSPENT = 0x00,
  MINX_SOLUTION_SPENT = 0x01,
  MINX_SOLUTION_UNTIMELY = 0x02,
  // Not atually returned by queryPoW(), but can be used by the app.
  MINX_SOLUTION_UNKNOWN = 0x03
};

/**
 * INIT message.
 * @var MinxInit::version Sender's MINX version.
 * @var MinxInit::gpassword Generated ticket to store at receiver.
 * @var MinxInit::data Application-specific data.
 */
struct MinxInit {
  const uint8_t version;
  const uint64_t gpassword;
  Bytes data;
  static constexpr size_t SIZE = sizeof(version) + sizeof(gpassword);
};

/**
 * MESSAGE message.
 * @var MinxMessage::version Sender's MINX version.
 * @var MinxMessage::gpassword Generated ticket to store at receiver.
 * @var MinxMessage::spassword Forwarded ticket to spend at receiver.
 * @var MinxMessage::data Application-specific data.
 */
struct MinxMessage {
  const uint8_t version;
  const uint64_t gpassword;
  const uint64_t spassword;
  Bytes data;
  static constexpr size_t SIZE =
    sizeof(version) + sizeof(gpassword) + sizeof(spassword);
};

/**
 * GET_INFO message.
 * Same format as the INIT message.
 */
struct MinxGetInfo : MinxInit {};

/**
 * INFO message.
 * @var MinxInfo::version Sender's MINX version.
 * @var MinxInfo::gpassword Generated ticket to store at receiver.
 * @var MinxInfo::spassword Forwarded ticket to spend at receiver.
 * @var MinxInfo::difficulty Minimum solution difficulty for PROVE_WORK.
 * @var MinxInfo::skey Server public key for the RandomX miner VM.
 * @var MinxInfo::data Application-specific data.
 */
struct MinxInfo {
  const uint8_t version;
  const uint64_t gpassword;
  const uint64_t spassword;
  const uint8_t difficulty;
  Hash skey;
  Bytes data;
  static constexpr size_t SIZE = sizeof(version) + sizeof(gpassword) +
                                 sizeof(spassword) + sizeof(difficulty) +
                                 sizeof(skey);
};

/**
 * PROVE_WORK message.
 * @var MinxProveWork::version Sender's MINX version.
 * @var MinxProveWork::gpassword Generated ticket to store at receiver.
 * @var MinxProveWork::spassword Forwarded ticket to spend at receiver.
 * @var MinxProveWork::ckey Client public key that gets credit for the solution.
 * @var MinxProveWork::hdata Secure hash over `data` (provided by application).
 * @var MinxProveWork::time Solution seconds since epoch.
 * @var MinxProveWork::nonce Solution nonce.
 * @var MinxProveWork::solution RandomX hash over ckey,time,nonce for skey VM.
 * @var MinxProveWork::data Application-specific data.
 */
struct MinxProveWork {
  const uint8_t version;
  const uint64_t gpassword;
  const uint64_t spassword;
  Hash ckey;
  Hash hdata;
  const uint64_t time;
  const uint64_t nonce;
  Hash solution;
  std::vector<char> data;
  static constexpr size_t SIZE =
    sizeof(version) + sizeof(gpassword) + sizeof(spassword) + sizeof(ckey) +
    sizeof(hdata) + sizeof(time) + sizeof(nonce) + sizeof(solution);
};

/**
 * Interface for receiving messages, called from the provided MinxIOContext.
 * NOTE: These callbacks are NOT guaranteed to be thread-safe.
 */
class MinxListener {
public:
  /**
   * Check if the application considers a remote address whitelisted.
   * @param addr Remote UDP socket sender address.
   * @return `true` if `addr` is authorized for communication by the
   * application, `false` otherwise.
   */
  virtual bool isConnected(const SockAddr& addr) { return false; }

  /**
   * Check if MINX should validate this PROVE_WORK message on behalf of the
   * application, or whether the application wants to deal with it (using
   * `filterPoW`, `calculatePoW` and `processPoW`).
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   * @return `true` to allow the MINX engine to deal with PoW validation
   * internally, `false` to let the application handle it.
   */
  virtual bool delegateProveWork(const SockAddr& addr,
                                 const MinxProveWork& msg) {
    return true;
  }

  /**
   * Receive INIT message.
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   */
  virtual void incomingInit(const SockAddr& addr, const MinxInit& msg) {}

  /**
   * Receive MESSAGE message.
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   */
  virtual void incomingMessage(const SockAddr& addr, const MinxMessage& msg) {}

  /**
   * Receive GET_INFO message.
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   */
  virtual void incomingGetInfo(const SockAddr& addr, const MinxGetInfo& msg) {}

  /**
   * Receive INFO message.
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   */
  virtual void incomingInfo(const SockAddr& addr, const MinxInfo& msg) {}

  /**
   * Receive PROVE_WORK message with a validated work item.
   * Application should persist `msg.time` and `msg.solution` in a double-spend
   * database for fault-tolerance (assuming the server key is kept the same).
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   * @param difficulty Precomputed difficulty.
   */
  virtual void incomingProveWork(const SockAddr& addr, const MinxProveWork& msg,
                                 const int difficulty) {}

  /**
   * Receive EXTENSION message.
   * @param addr Remote UDP socket sender address.
   * @param data Extension data.
   */
  virtual void incomingExtension(const SockAddr& addr, const Bytes& data) {}

  /**
   * Receive APPLICATION message.
   * @param addr Remote UDP socket sender address.
   * @param code The specific application message code.
   * @param data Application data.
   */
  virtual void incomingApplication(const SockAddr& addr, const uint8_t code,
                                   const Bytes& data) {}
};

/**
 * Configuration parameters for the Minx instance.
 */
struct MinxConfig {
  /**
   * The sliding-window PoW spend table has 1 hour slots by default.
   */
  static constexpr size_t DEFAULT_SPEND_SLOT_SIZE_SECS = 3600;

  /**
   * Instance string name for logging. Use "" to not log an instance name.
   */
  std::string instanceName = "";

  /**
   * If greater than zero, minimum value for any incoming MinxProveWork::time.
   * Any PROVE_WORK message with a smaller timestamp will be rejected as
   * untimely. This has to be used if the application is not persisting the
   * double-spend database. A good value is probably (spendSlotSize * 2 +
   * Minx::PROVE_WORK_FUTURE_DRIFT_SECS).
   */
  uint64_t minProveWorkTimestamp = 0;

  /**
   * Duration of each PoW spend table time slot in seconds.
   */
  uint64_t spendSlotSize = DEFAULT_SPEND_SLOT_SIZE_SECS;

  /**
   * Maximum number of internal `randomx_vm` objects to keep inside each
   * Minx::getPoWEngine(). If < 1, will use thread::hardware_concurrency * 2).
   */
  int randomXVMsToKeep = 0;

  /**
   * Number of threads to use when initializing a RandomX dataset. If < 1,
   * will use thread::hardware_concurrency().
   */
  int randomXInitThreads = 0;

  /**
   * Number of non-handshaked packets that will be received from same IP block
   * in the spam filter's window (which defaults to 1 hour)
   */
  uint16_t spamThreshold = 250;

  /**
   * If `true`, packets received from loopback addresses will be trusted and not
   * subject to filtering (default: `false`).
   */
  bool trustLoopback = false;

  /**
   * Size of receive ring buffer (number of 2048 byte buffers).
   */
  size_t recvBuffersSize = 16384;
};

/**
 * MINX reference implementation.
 */
class Minx {
private:
  // TODO:
  // - remove handlerCount_ & enable_shared_from_this for a MinxImpl

  // A prefix (defined by filter.h) can only have MAX_WORK_PER_PREFIX pending
  // work items in work_. This is to prevent attacks where an attacker will
  // submit many (valid or invalid) PoW tickets to try and overload the PoW
  // validation queue. If the tickets are invalid, the host and all its
  // tickets will be purged without checking, but the work queue still has to
  // reach the point where it processes them.
  static constexpr size_t MAX_WORK_PER_PREFIX = 128;

  // Protocols implemented on Minx shouldn't push the total packet size over
  // the guaranteed IPv6 MTU of 1280 bytes in any case. All incoming packets
  // with size exactly MAX_UDP_BYTES are assumed to be truncated and are
  // dropped (an application should not be generating packets of size anywhere
  // near MAX_UDP_BYTES anyway).
  static constexpr size_t MAX_UDP_BYTES = 2048;
  static constexpr size_t SEND_BUFFER_POOL_MAX_SIZE = 256;

  struct RecvSlot {
    SockAddr remoteAddr_;
    bool busy_ = false;
  };
  using RecvBuffersInfo = std::vector<RecvSlot>;
  using RecvBufferType = ArrayBuffer<MAX_UDP_BYTES>;
  using RecvBuffers = std::unique_ptr<RecvBufferType[]>;

  RecvBuffers recvBuffers_;
  RecvBuffersInfo recvBuffersInfo_;
  std::mutex recvBuffersMutex_;
  size_t recvBuffersIndex_ = 0;

  std::mutex sendBufferPoolMutex_;
  std::vector<std::shared_ptr<minx::Buffer>> sendBufferPool_;

  MinxListener* listener_ = nullptr;

  std::shared_mutex socketStateMutex_;
  std::unique_ptr<boost::asio::ip::udp::socket> socket_;
  std::atomic<bool> socketClosing_ = false;

  IOContext* netIO_ = nullptr;
  std::unique_ptr<boost::asio::strand<IOContext::executor_type>> netIOStrand_;
  std::atomic<uint64_t> netIOHandlerCount_ = 0;
  std::unique_ptr<boost::asio::steady_timer> netIORetryTimer_;

  IOContext* taskIO_ = nullptr;
  std::atomic<uint64_t> taskIOHandlerCount_ = 0;
  std::unique_ptr<boost::asio::executor_work_guard<IOContext::executor_type>>
    taskIOWorkGuard_;

  Hash key_;
  bool keySet_ = false;
  std::mutex keyMutex_;

  std::map<Hash, std::shared_ptr<PoWEngine>> engines_;
  std::mutex enginesMutex_;

  std::atomic<bool> useDataset_ = true;
  std::queue<Hash> pendingInitializations_;
  std::mutex queueMutex_;
  std::condition_variable queueCondVar_;
  std::thread workerThread_;
  std::atomic<bool> stopWorker_ = false;

  std::map<boost::asio::ip::address, size_t> workPrefixCounts_;
  std::queue<std::pair<MinxProveWork, SockAddr>> work_;
  std::mutex workMutex_;

  std::unordered_set<Hash, SecureHashHasher> workChecking_;
  std::mutex workCheckingMutex_;

  uint8_t minDiff_ = 1;

  std::shared_mutex spendMutex_;
  uint64_t spendBaseTime_ = 0;
  std::deque<std::unordered_set<Hash, SecureHashHasher>> spend_;

  BucketCache<uint64_t, void> passwords_;

  IPFilter ipFilter_;

  std::atomic<uint64_t> lastError_;

  std::mutex genMutex_;
  std::mt19937_64 gen_;
  std::uniform_int_distribution<uint64_t> genDistrib_;

  SpamFilter spamFilter_;

  MinxConfig config_;

  uint64_t updatePoWSpendCacheInternal(uint64_t epochSecs = 0);

  std::shared_ptr<minx::Buffer> acquireSendBuffer();

  void releaseSendBuffer(std::shared_ptr<minx::Buffer> buf);

  void doSocketSend(const SockAddr& addr,
                    const std::shared_ptr<minx::Buffer>& buf);

  void receive();

  void onReceivePacket(size_t bufIndex, const boost::system::error_code& error,
                       size_t bytes_transferred);

  void onProcessPacket(size_t slotIndex, size_t bytes_transferred);

  void workerLoop();

protected:
  MINX_LOG_INSTANCE_STANDARD_BOILERPLATE

public:
  // Incoming PROVE_WORK timestamps are allowed to be at most this number of
  // seconds into the future (5 minutes)
  static constexpr uint64_t PROVE_WORK_FUTURE_DRIFT_SECS = 300;

  /**
   * Constructor.
   * @param listener The `MinxListener` to use.
   * @param config The config parameters to use.
   */
  Minx(MinxListener* listener, const MinxConfig config = {});

  /**
   * Destructor.
   */
  virtual ~Minx();

  /**
   * Get last error code.
   * @return Last error code.
   */
  uint64_t getLastError() const { return lastError_; }

  /**
   * Clear last error code.
   */
  void clearLastError() { lastError_ = 0; }

  /**
   * Set my server key.
   * @param key RandomX key for validating incoming PROVE_WORK messages.
   */
  void setServerKey(const Hash& key) {
    std::lock_guard{keyMutex_};
    key_ = key;
    keySet_ = true;
  }

  /**
   * Unset my server key.
   */
  void unsetServerKey() {
    std::lock_guard{keyMutex_};
    key_ = {};
    keySet_ = false;
  }

  /**
   * Set minimum difficulty.
   * @param diff Minimum PoW difficulty.
   */
  void setMinimumDifficulty(uint8_t minDiff) { minDiff_ = minDiff; }

  /**
   * Get minimum difficulty.
   * @return Current minimum PoW difficulty.
   */
  uint8_t getMinimumDifficulty() { return minDiff_; }

  /**
   * Set whether to use RandoMX datasets or just the cache.
   * @param useDataset `true` to allocate the full dataset, `false` to just
   * use the cache.
   */
  void setUseDataset(bool useDataset) { useDataset_ = useDataset; };

  /**
   * Generate a non-zero random password to send in messages.
   * @return A random and fresh password value not previously seen from or to
   * any remote IP address.
   */
  uint64_t generatePassword();

  /**
   * Store a redeemable password ticket for a remote host.
   * @param password The password ticket to allocate.
   */
  void allocatePassword(uint64_t password);

  /**
   * Check for a redeemable password ticket from a remote host.
   * @param password The password ticket to check.
   * @return `true` if a match was found and the password ticket was consumed,
   * `false` otherwise.
   */
  bool spendPassword(uint64_t password);

  /**
   * Open the UDP socket if one was not previously opened.
   * The `boost::asio::io_context` objects are externally-provided, which
   * gives the client full control over threading. NOTE: Using more than one
   * thread to run `netIO` currently makes no sense since all operations
   * (send, receive) are serialized using a strand. NOTE: Threads running
   * `taskIO` can invoke the `MinxListener` callbacks.
   * @param sockAddr The local IP address and port (0=auto) to bind to.
   * @param netIO The `boost::asio::io_context` for a net recv/send thread.
   * @param taskIO The `boost::asio::io_context` for message processing
   * threads.
   * @return Bound port number if opened a socket, zero otherwise.
   * @throws A runtime exception on any error.
   */
  uint16_t openSocket(const SockAddr& sockAddr, IOContext& netIO,
                      IOContext& taskIO);

  /**
   * Open the UDP socket if one was not previously opened.
   * The `boost::asio::io_context` objects are externally-provided, which
   * gives the client full control over threading. NOTE: Using more than one
   * thread to run `netIO` currently makes no sense since all operations
   * (send, receive) are serialized using a strand. NOTE: Threads running
   * `taskIO` can invoke the `MinxListener` callbacks.
   * @param ipAddr The local IP address to bind to.
   * @param port The local port to bind to (0=auto).
   * @param netIO The `boost::asio::io_context` for a net recv/send thread.
   * @param taskIO The `boost::asio::io_context` for message processing
   * threads.
   * @return Bound port number if opened a socket, zero otherwise.
   * @throws A runtime exception on any error.
   */
  uint16_t openSocket(const IPAddr& ipAddr, uint16_t port, IOContext& netIO,
                      IOContext& taskIO);

  /**
   * Close the UDP socket if one was previously opened.
   * @param shouldPoll `true` (default) to poll the `IOContext`s during
   * shutdown, `false` if caller is pumping the `IOContext`s during shutdown.
   */
  void closeSocket(bool shouldPoll = true);

  /**
   * Send INIT message.
   * @param addr Remote UDP socket receiver address.
   * @param msg The MINX message.
   */
  void sendInit(const SockAddr& addr, const MinxInit& msg);

  /**
   * Send MESSAGE message.
   * @param addr Remote UDP socket receiver address.
   * @param msg The MINX message.
   */
  void sendMessage(const SockAddr& addr, const MinxMessage& msg);

  /**
   * Send GET_INFO message.
   * @param addr Remote UDP socket receiver address.
   * @param msg The MINX message.
   */
  void sendGetInfo(const SockAddr& addr, const MinxGetInfo& msg);

  /**
   * Send INFO message.
   * @param addr Remote UDP socket receiver address.
   * @param msg The MINX message.
   */
  void sendInfo(const SockAddr& addr, const MinxInfo& msg);

  /**
   * Send PROVE_WORK message.
   * @param addr Remote UDP socket receiver address.
   * @param msg The MINX message.
   */
  void sendProveWork(const SockAddr& addr, const MinxProveWork& msg);

  /**
   * Send EXTENSION message.
   * @param addr Remote UDP socket receiver address.
   * @param data Extension data.
   */
  void sendExtension(const SockAddr& addr, const Bytes& data);

  /**
   * Send APPLICATION message.
   * @param addr Remote UDP socket receiver address.
   * @param data Application-specific data.
   * @param code Message code to use.
   */
  void sendApplication(const SockAddr& addr, const Bytes& data,
                       const uint8_t code = MINX_APPLICATION_DEFAULT);

  /**
   * Check if a PoW solution is spent.
   * @param time The timestamp of the PoW solution to check.
   * @param solution The hash of the PoW solution check.
   * @param epochSecs Current time in seconds since epoch to use as the
   * current time. If `0` (default), get the current time from the system
   * clock.
   * @return `MINX_SOLUTION_UNSPENT` if the solution is timely and not spent,
   * `MINX_SOLUTION_SPENT` if the solution is timely and spent, or
   * `MINX_SOLUTION_UNTIMELY` if the solution's timestamp is outside the
   * double-spend table's tracking window.
   */
  int queryPoW(const uint64_t time, const Hash& solution,
               uint64_t epochSecs = 0);

  /**
   * Checks if the double-spend cache's bucket list should be updated by, for
   * example, dropping old buckets or inserting new buckets. This method must
   * be called before `verifyPoWs` (and `replayPoW` calls if they are not
   * called right after the Minx constructor).
   * @param epochSecs Current time in seconds since epoch to use as the
   * current time. If `0` (default), get the current time from the system
   * clock.
   * @return Earliest time in seconds since epoch that can be stored in the
   * double-spend cache. Earlier solution times are too old and won't be
   * spendable at all in any case. The application can safely delete any
   * persisted PoWs older than this.
   */
  uint64_t updatePoWSpendCache(uint64_t epochSecs = 0);

  /**
   * Replay a persisted PoW solution into the double-spend cache.
   * @param time The persisted MinxProveWork::time field.
   * @param solution The persisted MinxProveWork::solution field.
   * @return `true` if replay was successful, `false` if the given time
   * falls outside of the cache or the solution was already present
   * (double-spend).
   */
  bool replayPoW(const uint64_t time, const Hash& solution);

  /**
   * Check a PROVE_WORK message for minimum difficulty and time constraints.
   * These checks precede RandomX hashing (`calculatePoW`).
   * @param msg The MINX message.
   * @param difficulty Precomputed difficulty.
   * @return Zero if `msg` is valid, otherwise an error code.
   */
  uint64_t filterPoW(const MinxProveWork& msg, const int difficulty);

  /**
   * Hashes a given PROVE_WORK message (needed before `processPoW`).
   * Getting a randomx_vm* to use is the responsibility of the caller.
   * See: `Minx::getPoWEngine` and `PoWEngine`.
   * @param rxvmPtr RandomX machine to use for validation.
   * @param msg The PROVE_WORK message to compute the hash for.
   * @param calculatedHash Outparam filled with the computed hash.
   */
  void calculatePoW(randomx_vm* rxvmPtr, const MinxProveWork& msg,
                    Hash& calculatedHash);

  /**
   * Inject a PROVE_WORK message that has been verified with `calculatePoW`.
   * @param addr Remote UDP socket sender address.
   * @param msg The MINX message.
   * @param difficulty Precomputed difficulty.
   * @param isWorkHashValid `true` if the calculated hash over `msg` matches
   * `msg.solution`, `false` otherwise.
   * @return Zero if no processing errors, otherwise an error code.
   */
  uint64_t processPoW(const SockAddr& addr, const MinxProveWork& msg,
                      const int difficulty, bool isWorkHashValid);

  /**
   * Verify any pending incoming PoWs (can be called by multiple threads).
   * Pending PoWs are only verified after the server key's PoWEngine is ready.
   * @param limit Maximum number of PoW hashes to validate in this call, or
   * `0` to validate all pending PoW hashes.
   * @return If zero or greater, number of PoW verification jobs performed,
   * otherwise a temporary error occurred (no PoWEngine, or engine not ready).
   */
  int verifyPoWs(const size_t limit = 0);

  /**
   * Get current PoW verification work queue size.
   * @return PoW work queue size.
   */
  size_t getVerifyPoWQueueSize();

  /**
   * Create a RandomX PoWEngine (asynchronous).
   * @param key The RandomX PoWEngine key.
   */
  void createPoWEngine(const Hash& key);

  /**
   * Get a RandomX PoWEngine.
   * A PoWEngine is a wrapper for the RandomX dataset and cache, and it can
   * allocate multiple `randomx_vm` objects to provide multithreaded hashing.
   * @param key The RandomX PoWEngine key.
   */
  std::shared_ptr<PoWEngine> getPoWEngine(const Hash& key);

  /**
   * Check if a RandomX PoWEngine exists and is ready or throw on any failure.
   * @param key The RandomX PowEngine key.
   * @return `true` if the PowEngine exists and is ready, `false` otherwise.
   * @throws `runtime_error` if PoWEngine state is Error or Aborted.
   */
  bool checkPoWEngine(const Hash& key);

  /**
   * Destroy a RandomX PoWEngine.
   * @param key The RandomX PoWEngine key.
   * @return `true` if the PoWEngine was found and deleted, `false` otherwise.
   */
  bool destroyPoWEngine(const Hash& key);

  /**
   * Mine a RandomX hash (synchronous).
   * @param myKey The key that gets the credit for the hashing work.
   * @param hdata Application-defined component of the PoW puzzle.
   * @param targetKey The RandomX VM key to mine a hash for.
   * @param difficulty The minimum difficulty for the solution.
   * @param numThreads Number of threads to use for mining; default is 1. A
   * value of 0 means `std::hardware_concurrency`.
   * @param startNonce Starting nonce value for solution search (default: 0).
   * @param maxIters Maximum number of solutions to try; if zero, will try
   * until a solution is found.
   * @return Proof-of-Work template message with the mined solution, or an
   * empty optional if the solution was not found in `maxIters` iterations.
   * @throws std::runtime_error if VM not found or is not ready.
   */
  std::optional<MinxProveWork> proveWork(const Hash& myKey, const Hash& hdata,
                                         const Hash& targetKey, int difficulty,
                                         int numThreads = 1,
                                         uint64_t startNonce = 0,
                                         uint64_t maxIters = 0);

  /**
   * Add an IP address pattern to the IP filter.
   * Ban range is /56 for IPv6 or /24 for IPv4; LSBs are discarded. See
   * `ipfilter.h`.
   * @param addr IP block to ban temporarily; to emulate a permanent ban, call
   * this once per hour.
   */
  void banAddress(const IPAddr& addr);

  /**
   * Check an IP address against the spam filter.
   * @param addr IP address to check against the spam filter.
   * @param alsoUpdate `true` to update the spam counter (+1) as well, `false`
   * to just read the spam filter.
   * @return `true` if address is flagged by the spam filter, `false`
   * otherwise.
   */
  bool checkSpam(const IPAddr& addr, bool alsoUpdate = true);
};

std::ostream& operator<<(std::ostream& os, const MinxInit& m);
std::ostream& operator<<(std::ostream& os, const MinxGetInfo& m);
std::ostream& operator<<(std::ostream& os, const MinxMessage& m);
std::ostream& operator<<(std::ostream& os, const MinxInfo& m);
std::ostream& operator<<(std::ostream& os, const MinxProveWork& m);

} // namespace minx

#endif