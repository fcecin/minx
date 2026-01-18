#include <minx/minxrunner.h>

#include <minx/blog.h>
LOG_MODULE_DISABLED("minxr")

namespace minx {

MinxRunner::MinxRunner(MinxListener* listener, const MinxConfig config,
                       size_t taskThreads, size_t powThreads)
    : Minx(listener, config) {
  if (taskThreads == 0) {
    unsigned int hw = std::thread::hardware_concurrency();
    if (hw == 0)
      hw = 1;
    taskThreadCount_ = static_cast<size_t>(std::ceil(hw * 0.75));
    if (taskThreadCount_ < 1)
      taskThreadCount_ = 1;
  } else {
    taskThreadCount_ = taskThreads;
  }

  if (powThreads == 0) {
    powThreadCount_ = 1;
  } else {
    powThreadCount_ = powThreads;
  }
}

MinxRunner::~MinxRunner() { stop(); }

uint16_t MinxRunner::start(const SockAddr& addr) {
  std::lock_guard<std::mutex> lock(runnerMutex_);
  if (running_) {
    return 0;
  }

  LOGTRACE << "start starting" << VAR(taskThreadCount_) << VAR(powThreadCount_)
           << VAR(addr);

  uint16_t port = this->openSocket(addr, netIO_, taskIO_);
  if (port == 0) {
    LOGTRACE << "start failed opensocket";
    return 0;
  }

  running_ = true;

  netWorkGuard_.emplace(boost::asio::make_work_guard(netIO_));
  taskWorkGuard_.emplace(boost::asio::make_work_guard(taskIO_));

  netThreads_.emplace_back([this]() {
    try {
      netIO_.run();
    } catch (const std::exception& e) {
      LOGERROR << "MinxRunner NetIO exception: " << e.what();
    }
  });

  for (size_t i = 0; i < taskThreadCount_; ++i) {
    taskThreads_.emplace_back([this]() {
      try {
        taskIO_.run();
      } catch (const std::exception& e) {
        LOGERROR << "MinxRunner TaskIO exception: " << e.what();
      }
    });
  }

  for (size_t i = 0; i < powThreadCount_; ++i) {
    powThreads_.emplace_back(&MinxRunner::powWorkerLoop, this);
  }

  LOGTRACE << "start started" << VAR(port);
  return port;
}

uint16_t MinxRunner::start(const IPAddr& ip, uint16_t port) {
  return start(SockAddr(ip, port));
}

void MinxRunner::stop() {
  std::lock_guard<std::mutex> lock(runnerMutex_);
  if (!running_) {
    return;
  }

  LOGTRACE << "stop stopping";
  running_ = false;

  this->closeSocket();

  netIO_.stop();
  taskIO_.stop();

  for (auto& t : netThreads_)
    if (t.joinable())
      t.join();
  netThreads_.clear();

  for (auto& t : taskThreads_)
    if (t.joinable())
      t.join();
  taskThreads_.clear();

  for (auto& t : powThreads_)
    if (t.joinable())
      t.join();
  powThreads_.clear();

  netIO_.reset();
  taskIO_.reset();

  netWorkGuard_.reset();
  taskWorkGuard_.reset();

  LOGTRACE << "stop stopped";
}

void MinxRunner::powWorkerLoop() {
  LOGTRACE << "powworker started";
  while (running_) {
    int processed = 0;
    try {
      processed = this->verifyPoWs();
    } catch (...) {
    }

    // Prevents busy looping if no work is available.
    // But even if we had >0 work, yielding a bit helps with testing.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  LOGTRACE << "powworker stopped";
}

} // namespace minx