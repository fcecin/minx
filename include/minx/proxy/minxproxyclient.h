#ifndef _MINX_PROXY_MINXPROXYCLIENT_H_
#define _MINX_PROXY_MINXPROXYCLIENT_H_

/**
 * MinxProxyClient — TCP client that talks to a MinxProxy.
 *
 * Drop-in replacement for Minx in client applications. Provides the same
 * send methods (sendGetInfo, sendMessage, sendProveWork) and delivers
 * responses through the same MinxListener callback interface. Uses TCP
 * with 2-byte big-endian length-prefixed framing (matching MinxProxy's
 * TcpServer protocol).
 *
 * Also provides a self-contained PoW mining pipeline (single PoWEngine)
 * without any of Minx's server-side complexity (no spend tracking, no
 * spam filters, no IP bans, no multi-peer support).
 *
 * Lifecycle:
 *   1. Construct with a MinxListener* (callback receiver)
 *   2. connect(endpoint) — TCP connect + start async read loop
 *   3. send*() as needed
 *   4. disconnect() or destroy
 *
 * Owns its own io_context and thread for async I/O.
 */

#include <minx/minx.h>
#include <minx/powengine.h>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <thread>
#include <vector>

namespace minx {

class MinxProxyClient {
public:
  /**
   * @param listener Callback receiver for incoming messages.
   * @param useDataset If true, PoW engine uses full RandomX dataset (~2GB).
   */
  explicit MinxProxyClient(MinxListener* listener, bool useDataset = true);
  ~MinxProxyClient();

  MinxProxyClient(const MinxProxyClient&) = delete;
  MinxProxyClient& operator=(const MinxProxyClient&) = delete;

  // -- Connection --

  /** Connect to a MinxProxy via TCP. Starts the IO thread. */
  bool connect(const boost::asio::ip::tcp::endpoint& proxyEp);

  /** Disconnect and stop the IO thread. */
  void disconnect();

  /** Check if connected. */
  bool isConnected() const { return connected_; }

  // -- Send methods (mirror Minx interface) --
  // The addr parameter is ignored (there's only one peer: the proxy).
  // Not thread-safe: callers must serialize send calls.

  void sendGetInfo(const SockAddr& addr, const MinxGetInfo& msg);
  void sendMessage(const SockAddr& addr, const MinxMessage& msg);
  void sendProveWork(const SockAddr& addr, const MinxProveWork& msg);

  // -- Password generation --

  uint64_t generatePassword();

  // -- PoW mining (local, self-contained) --

  /** Configure whether to use full RandomX dataset. Call before mining. */
  void setUseDataset(bool useDataset) { useDataset_ = useDataset; }

  /**
   * Create a PoW engine for the given key (async initialization).
   * Only one engine is maintained at a time.
   */
  void createPoWEngine(const Hash& key);

  /** Check if the PoW engine exists and is ready. */
  bool checkPoWEngine(const Hash& key);

  /**
   * Mine a RandomX hash (synchronous, blocks until found or maxIters).
   * Same interface as Minx::proveWork().
   */
  std::optional<MinxProveWork> proveWork(const Hash& myKey, const Hash& hdata,
                                         const Hash& targetKey, int difficulty,
                                         int numThreads = 1,
                                         uint64_t startNonce = 0,
                                         uint64_t maxIters = 0);

private:
  // -- TCP framing --
  void sendRaw(const std::vector<uint8_t>& data);
  void startRead();
  void onReadHeader(boost::system::error_code ec, size_t bytes);
  void onReadBody(boost::system::error_code ec, size_t bytes, uint16_t len);
  void dispatchMessage(const uint8_t* data, size_t len);

  // -- Serialization helpers --
  static void appendU8(std::vector<uint8_t>& buf, uint8_t v);
  static void appendU64(std::vector<uint8_t>& buf, uint64_t v);
  static void appendHash(std::vector<uint8_t>& buf, const Hash& h);
  static void appendBytes(std::vector<uint8_t>& buf, const Bytes& b);

  MinxListener* listener_;
  bool useDataset_;
  std::atomic<bool> connected_{false};

  // IO
  boost::asio::io_context io_;
  std::unique_ptr<boost::asio::executor_work_guard<
    boost::asio::io_context::executor_type>> workGuard_;
  std::thread ioThread_;
  boost::asio::ip::tcp::socket socket_;
  uint8_t headerBuf_[2]{};

  // RNG for password generation
  std::mt19937_64 rng_{std::random_device{}()};
  std::uniform_int_distribution<uint64_t> distrib_;

  // PoW engine (one at a time)
  std::shared_ptr<PoWEngine> powEngine_;
  Hash powEngineKey_{};
};

} // namespace minx

#endif
