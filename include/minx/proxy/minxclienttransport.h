#ifndef _MINX_PROXY_MINXCLIENTTRANSPORT_H_
#define _MINX_PROXY_MINXCLIENTTRANSPORT_H_

/**
 * MinxClientTransport — unified client transport for MINX.
 *
 * Facade that hides whether the underlying transport is UDP (via Minx)
 * or TCP (via MinxProxyClient). Owns all IO lifecycle (threads, contexts).
 *
 * Construction:
 *   - MinxClientTransport(listener)           → UDP mode
 *   - MinxClientTransport(listener, proxyEp)  → TCP mode
 *
 * The listener receives incoming messages regardless of transport.
 */

#include <minx/minx.h>
#include <minx/proxy/minxproxyclient.h>

#include <memory>
#include <optional>
#include <thread>

namespace minx {

class MinxClientTransport {
public:
  /**
   * Construct in UDP mode (direct connection to server).
   * @param listener Callback receiver for incoming messages.
   * @param serverEndpoint UDP endpoint of the MINX server.
   * @param config Minx configuration.
   */
  MinxClientTransport(MinxListener* listener,
                      const boost::asio::ip::udp::endpoint& serverEndpoint,
                      const MinxConfig& config = MinxConfig{"cl"});

  /**
   * Construct in TCP mode (connection through a MinxProxy).
   * @param listener Callback receiver for incoming messages.
   * @param proxyEndpoint TCP endpoint of the MinxProxy.
   */
  MinxClientTransport(MinxListener* listener,
                      const boost::asio::ip::tcp::endpoint& proxyEndpoint);

  ~MinxClientTransport();

  MinxClientTransport(const MinxClientTransport&) = delete;
  MinxClientTransport& operator=(const MinxClientTransport&) = delete;

  /** Whether this transport is in TCP proxy mode. */
  bool isTcp() const { return tcp_ != nullptr; }

  // -- Lifecycle --

  /**
   * Start the transport.
   * UDP: opens socket on localPort, starts IO threads.
   * TCP: connects to the proxy endpoint.
   * @param localPort Local port for UDP binding (ignored in TCP mode).
   * @return true on success.
   */
  bool start(uint16_t localPort = 0);

  /** Stop the transport. Joins threads, releases resources. */
  void stop();

  // -- Send methods --
  // Destination is set at construction (server endpoint or proxy endpoint).

  void sendGetInfo(const MinxGetInfo& msg);
  void sendMessage(const MinxMessage& msg);
  void sendProveWork(const MinxProveWork& msg);

  /** Generate a random password for ticket exchange. */
  uint64_t generatePassword();

  // -- PoW mining --

  void setUseDataset(bool useDataset);
  void createPoWEngine(const Hash& key);
  bool checkPoWEngine(const Hash& key);

  std::optional<MinxProveWork> proveWork(const Hash& myKey, const Hash& hdata,
                                         const Hash& targetKey, int difficulty,
                                         int numThreads = 1,
                                         uint64_t startNonce = 0,
                                         uint64_t maxIters = 0);

private:
  MinxListener* listener_;
  bool useDataset_ = true;

  // UDP mode members (null in TCP mode)
  std::unique_ptr<Minx> udp_;
  SockAddr serverAddr_;
  IOContext netIO_;
  IOContext taskIO_;
  std::unique_ptr<boost::asio::executor_work_guard<IOContext::executor_type>>
    taskIOWorkGuard_;
  std::thread netIOThread_;
  std::thread taskIOThread_;

  // TCP mode members (null in UDP mode)
  std::unique_ptr<MinxProxyClient> tcp_;
  boost::asio::ip::tcp::endpoint proxyEndpoint_;
};

} // namespace minx

#endif
