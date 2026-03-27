// Rapid Minx/MinxRunner create-destroy stress test.
// Prints one line per iteration so the harness can detect hangs.
// Exit 0 = all iterations completed.
//
// Phase 1: bare Minx ctor/dtor (no socket) — workerThread_ shutdown race
// Phase 2: MinxRunner start/stop with UDP traffic in-flight — hot teardown

#include <minx/minx.h>
#include <minx/minxrunner.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

class NullListener : public minx::MinxListener {};

class CountingListener : public minx::MinxListener {
public:
  std::atomic<int> inits{0};
  std::atomic<int> messages{0};
  std::atomic<int> getInfos{0};

  bool isConnected(const minx::SockAddr&) override { return true; }

  void incomingInit(const minx::SockAddr&, const minx::MinxInit&) override {
    inits++;
  }
  void incomingMessage(const minx::SockAddr&,
                       const minx::MinxMessage&) override {
    messages++;
  }
  void incomingGetInfo(const minx::SockAddr&,
                       const minx::MinxGetInfo&) override {
    getInfos++;
  }
};

int main(int argc, char* argv[]) {
  int bareIters = 200;
  int hotIters = 50;
  int msgsPerIter = 20;

  if (argc > 1)
    bareIters = std::stoi(argv[1]);
  if (argc > 2)
    hotIters = std::stoi(argv[2]);
  if (argc > 3)
    msgsPerIter = std::stoi(argv[3]);

  NullListener nullListener;

  // Phase 1: bare Minx ctor/dtor (no socket) — exercises workerThread_ race
  for (int i = 0; i < bareIters; ++i) {
    auto m = std::make_unique<minx::Minx>(&nullListener);
    m.reset();
    std::cout << "bare " << (i + 1) << "/" << bareIters << std::endl;
  }

  // Phase 2: two MinxRunners exchanging traffic, then torn down mid-flight
  minx::MinxConfig cfg;
  cfg.trustLoopback = true;
  cfg.spamThreshold = 65535;

  auto loopback = boost::asio::ip::make_address("127.0.0.1");

  for (int i = 0; i < hotIters; ++i) {
    CountingListener listenerA, listenerB;

    auto a =
      std::make_unique<minx::MinxRunner>(&listenerA, cfg, 1 /* taskThreads */);
    auto b =
      std::make_unique<minx::MinxRunner>(&listenerB, cfg, 1 /* taskThreads */);

    uint16_t portA = a->start(loopback, 0);
    uint16_t portB = b->start(loopback, 0);

    minx::SockAddr addrA(loopback, portA);
    minx::SockAddr addrB(loopback, portB);

    // Fire a burst of messages in both directions — don't wait for delivery
    for (int j = 0; j < msgsPerIter; ++j) {
      uint64_t gpA = a->generatePassword();
      uint64_t gpB = b->generatePassword();

      a->sendInit(addrB, {0, gpA, {}});
      b->sendInit(addrA, {0, gpB, {}});

      a->sendGetInfo(addrB, {0, gpA, {}});
      b->sendGetInfo(addrA, {0, gpB, {}});

      a->sendMessage(addrB, {0, gpA, 0, {}});
      b->sendMessage(addrA, {0, gpB, 0, {}});
    }

    // Tear down immediately while IO is in-flight
    a->stop();
    b->stop();
    a.reset();
    b.reset();

    std::cout << "hot " << (i + 1) << "/" << hotIters << std::endl;
  }

  std::cout << "OK" << std::endl;
  return 0;
}
