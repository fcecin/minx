#ifndef MINX_MOCK_H
#define MINX_MOCK_H

#include <minx/minx.h>

#include <functional>

namespace minx_test {

class MinxMockListener : public minx::MinxListener {
public:
  struct Stats {
    std::atomic<int> init{0}, message{0}, getInfo{0}, info{0};
    std::atomic<int> proveWork{0}, extension{0}, application{0};
  } stats;

  std::function<bool(const minx::SockAddr&)> onIsConnected;
  std::function<void(const minx::SockAddr&, const minx::MinxInit&)> onInit;
  std::function<void(const minx::SockAddr&, const minx::MinxMessage&)>
    onMessage;
  std::function<void(const minx::SockAddr&, const minx::MinxGetInfo&)>
    onGetInfo;
  std::function<void(const minx::SockAddr&, const minx::MinxInfo&)> onInfo;
  std::function<void(const minx::SockAddr&, const minx::MinxProveWork&, int)>
    onProveWork;
  std::function<void(const minx::SockAddr&, const minx::Bytes&)> onExtension;
  std::function<void(const minx::SockAddr&, uint8_t, const minx::Bytes&)>
    onApplication;

  bool isConnected(const minx::SockAddr& addr) override {
    return onIsConnected ? onIsConnected(addr) : true;
  }
  void incomingInit(const minx::SockAddr& addr,
                    const minx::MinxInit& msg) override {
    stats.init++;
    if (onInit)
      onInit(addr, msg);
  }
  void incomingMessage(const minx::SockAddr& addr,
                       const minx::MinxMessage& msg) override {
    stats.message++;
    if (onMessage)
      onMessage(addr, msg);
  }
  void incomingGetInfo(const minx::SockAddr& addr,
                       const minx::MinxGetInfo& msg) override {
    stats.getInfo++;
    if (onGetInfo)
      onGetInfo(addr, msg);
  }
  void incomingInfo(const minx::SockAddr& addr,
                    const minx::MinxInfo& msg) override {
    stats.info++;
    if (onInfo)
      onInfo(addr, msg);
  }
  void incomingProveWork(const minx::SockAddr& addr,
                         const minx::MinxProveWork& msg, int diff) override {
    stats.proveWork++;
    if (onProveWork)
      onProveWork(addr, msg, diff);
  }
  void incomingExtension(const minx::SockAddr& addr,
                         const minx::Bytes& data) override {
    stats.extension++;
    if (onExtension)
      onExtension(addr, data);
  }
  void incomingApplication(const minx::SockAddr& addr, const uint8_t code,
                           const minx::Bytes& data) override {
    stats.application++;
    if (onApplication)
      onApplication(addr, code, data);
  }
};

struct TestNode {
  std::string name;
  minx::IOContext netio;
  minx::IOContext taskio;
  minx::SockAddr addr;
  minx::Hash key;

  MinxMockListener listener;
  std::unique_ptr<minx::Minx> minx;

  TestNode(std::string n, std::string ip, uint16_t port);
  ~TestNode();

  void createServerPoWEngine(bool useDataset);

  void createClientPoWEngine(const minx::Hash& targetKey, bool useDataset);

  void createPoWEngine(const minx::Hash& engineKey,
                       const std::string& logLabel);

  void startNetwork(int minDiff = 1);

  void startFull(bool useDataset, int minDiff = 1) {
    createServerPoWEngine(useDataset);
    startNetwork(minDiff);
  }

  void poll();
  void processPoW();
};

struct MinxMockFixture {

  std::vector<TestNode*> activeNodes;

  MinxMockFixture();
  ~MinxMockFixture();

  void registerNode(TestNode& node);
  void pollAll(int cycles = 1);
  void waitForCondition(std::function<bool()> predicate, int timeoutSecs = 5);

  minx::MinxProveWork mineValidPoW(TestNode& miner, const minx::Hash& targetKey,
                                   int diff, uint64_t spassword);
};

} // namespace minx_test

#endif