#include <minx/proxy/minxclienttransport.h>

#include <minx/blog.h>

LOG_MODULE_DISABLED("minx_client_transport")

namespace minx {

// =============================================================================
// Construction
// =============================================================================

MinxClientTransport::MinxClientTransport(MinxListener* listener,
                                         const MinxConfig& config)
  : listener_(listener) {
  udp_ = std::make_unique<Minx>(listener, config);
}

MinxClientTransport::MinxClientTransport(
  MinxListener* listener,
  const boost::asio::ip::tcp::endpoint& proxyEndpoint)
  : listener_(listener), proxyEndpoint_(proxyEndpoint) {
  tcp_ = std::make_unique<MinxProxyClient>(listener);
}

MinxClientTransport::~MinxClientTransport() { stop(); }

// =============================================================================
// Lifecycle
// =============================================================================

bool MinxClientTransport::start(uint16_t localPort) {
  if (udp_) {
    taskIOWorkGuard_ = std::make_unique<
      boost::asio::executor_work_guard<IOContext::executor_type>>(
      taskIO_.get_executor());
    SockAddr localAddr(boost::asio::ip::udp::v6(), localPort);
    udp_->openSocket(localAddr, netIO_, taskIO_);
    netIOThread_ = std::thread([this]() { netIO_.run(); });
    taskIOThread_ = std::thread([this]() { taskIO_.run(); });
    return true;
  }
  if (tcp_) {
    return tcp_->connect(proxyEndpoint_);
  }
  return false;
}

void MinxClientTransport::stop() {
  if (udp_) {
    udp_->closeSocket(false);
    if (taskIOWorkGuard_) {
      taskIOWorkGuard_->reset();
      taskIOWorkGuard_.reset();
    }
    netIO_.stop();
    taskIO_.stop();
    if (netIOThread_.joinable())
      netIOThread_.join();
    if (taskIOThread_.joinable())
      taskIOThread_.join();
  }
  if (tcp_) {
    tcp_->disconnect();
  }
}

// =============================================================================
// Send methods
// =============================================================================

void MinxClientTransport::sendGetInfo(const SockAddr& addr,
                                      const MinxGetInfo& msg) {
  if (udp_) udp_->sendGetInfo(addr, msg);
  else if (tcp_) tcp_->sendGetInfo(addr, msg);
}

void MinxClientTransport::sendMessage(const SockAddr& addr,
                                      const MinxMessage& msg) {
  if (udp_) udp_->sendMessage(addr, msg);
  else if (tcp_) tcp_->sendMessage(addr, msg);
}

void MinxClientTransport::sendProveWork(const SockAddr& addr,
                                        const MinxProveWork& msg) {
  if (udp_) udp_->sendProveWork(addr, msg);
  else if (tcp_) tcp_->sendProveWork(addr, msg);
}

uint64_t MinxClientTransport::generatePassword() {
  if (udp_) return udp_->generatePassword();
  if (tcp_) return tcp_->generatePassword();
  return 0;
}

// =============================================================================
// PoW mining
// =============================================================================

void MinxClientTransport::setUseDataset(bool useDataset) {
  useDataset_ = useDataset;
  if (udp_) udp_->setUseDataset(useDataset);
  if (tcp_) tcp_->setUseDataset(useDataset);
}

void MinxClientTransport::createPoWEngine(const Hash& key) {
  if (udp_) udp_->createPoWEngine(key);
  else if (tcp_) tcp_->createPoWEngine(key);
}

bool MinxClientTransport::checkPoWEngine(const Hash& key) {
  if (udp_) return udp_->checkPoWEngine(key);
  if (tcp_) return tcp_->checkPoWEngine(key);
  return false;
}

std::optional<MinxProveWork>
MinxClientTransport::proveWork(const Hash& myKey, const Hash& hdata,
                               const Hash& targetKey, int difficulty,
                               int numThreads, uint64_t startNonce,
                               uint64_t maxIters) {
  if (udp_)
    return udp_->proveWork(myKey, hdata, targetKey, difficulty, numThreads,
                           startNonce, maxIters);
  if (tcp_)
    return tcp_->proveWork(myKey, hdata, targetKey, difficulty, numThreads,
                           startNonce, maxIters);
  return {};
}

} // namespace minx
