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
#include <minx/ipfilter.h>
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
  MINX_ERROR_BAD_MESSAGE = 0x0B
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
struct MinxGetInfo: MinxInit {};

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
  const uint64_t time;
  const uint64_t nonce;
  Hash solution;
  Bytes data;
  static constexpr size_t SIZE =
    sizeof(version) + sizeof(gpassword) + sizeof(spassword) + sizeof(ckey) +
    sizeof(time) + sizeof(nonce) + sizeof(solution);
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
 * MINX reference implementation.
 */
class Minx {
private:
  // TODO:
  // - use multiple buffer_ & remoteAddr_ to receive
  // - move packet processing outside of onReceive(); either to an internal
  // thread pool or just use the io_context_
  // - don't allocate new buffers for serializing each outgoing message
  // - remove handlerCount_ & enable_shared_from_this for a MinxImpl
  ArrayBuffer<0x10000> buffer_;
  MinxListener* listener_ = nullptr;
  IOContext* io_context_ = nullptr;
  std::unique_ptr<boost::asio::strand<IOContext::executor_type>> strand_;
  std::atomic<uint64_t> handlerCount_ = 0;
  std::shared_mutex socketStateMutex_;

  std::unique_ptr<boost::asio::ip::udp::socket> socket_;
  SockAddr remoteAddr_;

  Hash key_;
  bool keySet_ = false;
  std::mutex keyMutex_;

  std::map<Hash, std::shared_ptr<PoWEngine>> vms_;
  std::mutex vmsMutex_;

  std::atomic<bool> useDataset_ = true;
  int randomXThreads_;
  std::queue<Hash> pendingInitializations_;
  std::mutex queueMutex_;
  std::condition_variable queueCondVar_;
  std::thread workerThread_;
  std::atomic<bool> stopWorker_ = false;

  std::queue<std::pair<MinxProveWork, SockAddr>> work_;
  std::mutex workMutex_;

  uint8_t minDiff_ = 1;

  std::mutex verifyPoWsMutex_; // also protects spend_
  uint64_t spendSlotSize_;
  uint64_t spendBaseTime_ = 0;
  std::deque<std::unordered_set<Hash, SecureHashHasher>> spend_;

  BucketCache<uint64_t, IPAddr> passwords_;

  IPFilter ipFilter_;

  std::atomic<uint64_t> lastError_;

  std::mutex genMutex_;
  std::mt19937_64 gen_;
  std::uniform_int_distribution<uint64_t> genDistrib_;

  void doSocketSend(const SockAddr& addr,
                    const std::shared_ptr<minx::Buffer>& buf);

  void receive();

  void onReceive(const boost::system::error_code& error,
                 size_t bytes_transferred);

  void workerLoop();

public:
  /**
   * Constructor.
   * @param listener The `MinxListener` to use.
   * @param randomXThreads Number of threads to use when initializing a RandomX
   * dataset (if less than 1, will use thread::hardware_concurrency()).
   * @param spendSlotSize Duration of each double-spend time slot in seconds
   * (default: 1 hour).
   */
  Minx(MinxListener* listener, int randomXThreads = 0,
       uint64_t spendSlotSize = 60 * 60);

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
   * @param useDataset `true` to allocate the full dataset, `false` to just use
   * the cache.
   */
  void setUseDataset(bool useDataset) { useDataset_ = useDataset; };

  /**
   * Generate a non-zero random password to send in INIT or INIT_ACK messages.
   * @return A random and fresh password value not previously seen from or to
   * any remote IP address.
   */
  uint64_t generatePassword();

  /**
   * Store a redeemable password ticket for a remote host.
   * @param password The password ticket to allocate.
   * @param addr The host address to associate with the password ticket.
   */
  void allocatePassword(uint64_t password, const IPAddr& addr);

  /**
   * Check for a redeemable password ticket from a remote host.
   * @param password The password ticket to check.
   * @param addr The host address associated with the password ticket.
   * @return `true` if a match was found and the password ticket was consumed,
   * `false` otherwise.
   */
  bool spendPassword(uint64_t password, const IPAddr& addr);

  /**
   * Open the UDP socket if one was not previously opened.
   * The `boost::asio::io_context` is externally-provided, which allows the
   * client full control of network processing (threaded vs single-thread, etc).
   * @param ioc The `boost::asio::io_context` to use.
   * @param sockaddr The local IP address and port to bind to.
   * @throws A runtime exception on any error.
   */
  void openSocket(IOContext& ioc, const SockAddr& addr);

  /**
   * Close the UDP socket if one was previously opened.
   */
  void closeSocket();

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
   * Verify any pending incoming PoWs.
   * Pending PoWs are only verified after the VM for our key is ready.
   */
  void verifyPoWs(const size_t limit = 0);

  /**
   * Create a RandomX VM (asynchronous).
   * @param key The RandomX VM key.
   */
  void createVM(const Hash& key);

  /**
   * Get a RandomX VM.
   * @param key The RandomX VM key.
   */
  std::shared_ptr<PoWEngine> getVM(const Hash& key);

  /**
   * Check if a RandomX VM exists and is ready or throw on any failure.
   * @param key The RandomX VM key.
   * @return `true` if the VM exists and is ready, `false` otherwise.
   * @throws `runtime_error` if VM state is Error or Aborted.
   */
  bool checkVM(const Hash& key);

  /**
   * Destroy a RandomX VM.
   * @param key The RandomX VM key.
   * @return `true` if the VM was found and deleted, `false` otherwise.
   */
  bool destroyVM(const Hash& key);

  /**
   * Mine a RandomX hash (synchronous).
   * @param myKey The key that gets the credit for the hashing work.
   * @param targetKey The RandomX VM key to mine a hash for.
   * @param difficulty The minimum difficulty for the solution.
   * @param numThreads Number of threads to use for mining; default is 1. A
   * value of 0 means `std::hardware_concurrency`.
   * @param maxVms Maximum number of RandomX VMs to keep in memory after mining;
   * default is 1 (one VM needs to be allocated per thread requested). A value
   * of 0 means keeping all VMs already allocated.
   * @return Proof-of-Work template message with the mined solution (but without
   * `version`, `password`, and `data`), or an empty optional if VM not found or
   * is not ready.
   */
  std::optional<MinxProveWork> proveWork(const Hash& myKey,
                                         const Hash& targetKey, int difficulty,
                                         int numThreads = 1, int maxVMs = 1);

  /**
   * Add an IP address pattern to the IP filter.
   * Ban range is /56 for IPv6 or /24 for IPv4; LSBs are discarded. See
   * `ipfilter.h`.
   * @param addr IP block to ban temporarily; to emulate a permanent ban, call
   * this once per hour.
   */
  void banAddress(const IPAddr& addr);
};

} // namespace minx

#endif