#ifndef MINXRUNNER_H
#define MINXRUNNER_H

#include <minx/minx.h>

namespace minx {

/**
 * Minx wrapper with thread management.
 */
class MinxRunner : public Minx {
public:
  MinxRunner(MinxListener* listener, const MinxConfig config = {}, size_t taskThreads = 0, size_t powThreads = 0);

  virtual ~MinxRunner();

  /**
   * Open the socket and start all background threads (net, task, pow).
   * @param addr The address to bind to (port 0=auto).
   * @return The bound port.
   */
  uint16_t start(const SockAddr& addr);

  /**
   * Open the socket and start all background threads (net, task, pow).
   * @param ip The IP address to bind to.
   * @param port The port to bind to (0=auto).
   * @return The bound port.
   */
  uint16_t start(const IPAddr& ip, uint16_t port);

  /**
   * Stop all threads and close the socket.
   */
  void stop();

private:
  IOContext netIO_;
  std::optional<boost::asio::executor_work_guard<IOContext::executor_type>>
    netWorkGuard_;
  std::vector<std::thread> netThreads_;

  IOContext taskIO_;
  std::optional<boost::asio::executor_work_guard<IOContext::executor_type>>
    taskWorkGuard_;
  size_t taskThreadCount_;
  std::vector<std::thread> taskThreads_;

  size_t powThreadCount_;
  std::vector<std::thread> powThreads_;

  std::atomic<bool> running_{false};
  std::mutex runnerMutex_;

  void powWorkerLoop();
};

} // namespace minx

#endif