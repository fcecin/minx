#include <atomic>
#include <deque>
#include <iomanip>
#include <iostream>
#include <minx/blog.h>
#include <minx/minxrunner.h>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <vector>

const int DIFFICULTY = 2;
const int WORKER_THREADS = 4;
const int BATCH_SIZE = 4;
const int PRESSURE_BATCH_SIZE = 20;

minx::Hash generateRandomHash() {
  minx::Hash hash;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  for (size_t i = 0; i < hash.size() / sizeof(uint64_t); ++i) {
    reinterpret_cast<uint64_t*>(hash.data())[i] = dis(gen);
  }
  return hash;
}

class TestServerListener : public minx::MinxListener {
public:
  std::atomic<int> successCount{0};
  minx::Minx* minx_ = nullptr;
  minx::Hash skey_;

  std::set<std::thread::id> seenThreads;
  std::mutex threadMutex;

  TestServerListener(const minx::Hash& key) : skey_(key) {}

  bool isConnected(const minx::SockAddr& addr) override { return true; }

  void incomingGetInfo(const minx::SockAddr& addr,
                       const minx::MinxGetInfo& msg) override {
    minx::MinxInfo info = {0, minx_->generatePassword(), msg.gpassword,
                           DIFFICULTY, skey_};
    minx_->sendInfo(addr, info);
  }

  void incomingProveWork(const minx::SockAddr& addr,
                         const minx::MinxProveWork& msg,
                         const int diff) override {
    auto tid = std::this_thread::get_id();
    {
      std::lock_guard lock(threadMutex);
      seenThreads.insert(tid);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    successCount++;
  }

  void resetStats() {
    successCount = 0;
    std::lock_guard lock(threadMutex);
    seenThreads.clear();
  }
};

class TestClientListener : public minx::MinxListener {
public:
  minx::Minx* minx_ = nullptr;
  minx::Hash ckey_;
  minx::SockAddr server_addr_;

  std::optional<minx::MinxInfo> lastInfo_;
  bool infoReceived_ = false;

  TestClientListener(const minx::Hash& key, const minx::SockAddr& srv)
      : ckey_(key), server_addr_(srv) {}

  void incomingInfo(const minx::SockAddr& addr,
                    const minx::MinxInfo& msg) override {
    lastInfo_.emplace(msg);
    infoReceived_ = true;
    minx_->createPoWEngine(msg.skey);
  }

  void sendPoW(int nonceOffset, bool corrupt = false, bool duplicate = false) {
    if (!lastInfo_)
      return;

    auto pow = minx_->proveWork(ckey_, {}, lastInfo_->skey,
                                lastInfo_->difficulty, 1, nonceOffset * 100000);
    if (pow) {
      uint64_t finalNonce = pow->nonce;
      if (corrupt) {
        finalNonce += 1;
      }

      minx::MinxProveWork pmsg = {
        pow->version, pow->gpassword, lastInfo_->gpassword,
        pow->ckey,    pow->hdata,     pow->time,
        finalNonce,   pow->solution,  pow->data};

      minx_->sendProveWork(server_addr_, pmsg);

      if (duplicate) {
        minx_->sendProveWork(server_addr_, pmsg);
      }
    }
  }
};

int main(int argc, char* argv[]) {
  if (argc > 1 && std::string(argv[1]) == "-v") {
    blog::enable("minx");
    blog::enable("minxr");
    blog::set_level(blog::trace);
  }

  std::cout << "🚀 Starting Parallel PoW Verification Tests..." << std::endl;

  minx::Hash srvKey = generateRandomHash();
  minx::Hash cliKey = generateRandomHash();
  minx::SockAddr srvAddr(boost::asio::ip::address::from_string("127.0.0.1"),
                         9000);
  minx::SockAddr cliAddr(boost::asio::ip::address::from_string("127.0.0.1"),
                         9001);

  TestServerListener srvListener(srvKey);
  minx::MinxConfig srvConf;
  srvConf.instanceName = "Server";
  srvConf.trustLoopback = true;

  minx::MinxRunner server(&srvListener, srvConf, 4, WORKER_THREADS);
  srvListener.minx_ = &server;
  server.setServerKey(srvKey);
  server.setMinimumDifficulty(DIFFICULTY);
  server.createPoWEngine(srvKey);

  TestClientListener cliListener(cliKey, srvAddr);
  minx::MinxConfig cliConf;
  cliConf.instanceName = "Client";
  cliConf.trustLoopback = true;

  minx::MinxRunner client(&cliListener, cliConf, 1, 1);
  cliListener.minx_ = &client;

  server.start(srvAddr);
  client.start(cliAddr);

  std::cout << "--- Phase 0: Handshake & VM Init ---" << std::endl;
  client.sendGetInfo(srvAddr, {0, client.generatePassword(), {}});

  while (!cliListener.infoReceived_ || !client.checkPoWEngine(srvKey)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  std::cout << "✅ VM Ready." << std::endl;

  std::cout << "\n--- Phase 1: Parallel Distribution (" << BATCH_SIZE
            << " items) ---" << std::endl;
  srvListener.resetStats();
  for (int i = 0; i < BATCH_SIZE; ++i)
    cliListener.sendPoW(i);

  for (int i = 0; i < 20; ++i) {
    if (srvListener.successCount >= BATCH_SIZE)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  std::cout << "  -> Validated: " << srvListener.successCount << "/"
            << BATCH_SIZE << std::endl;
  std::cout << "  -> Threads Used: " << srvListener.seenThreads.size() << "/"
            << WORKER_THREADS << std::endl;
  if (srvListener.successCount == BATCH_SIZE &&
      srvListener.seenThreads.size() > 1)
    std::cout << "✅ PASS: Distributed Work." << std::endl;
  else {
    std::cerr << "❌ FAIL: Distribution issues." << std::endl;
    return 1;
  }

  std::cout << "\n--- Phase 2: In-Flight Deduplication ---" << std::endl;
  srvListener.resetStats();
  cliListener.sendPoW(100, false, true);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  std::cout << "  -> Validated: " << srvListener.successCount << " (Expected 1)"
            << std::endl;
  if (srvListener.successCount == 1)
    std::cout << "✅ PASS: Duplicate Filtered." << std::endl;
  else {
    std::cerr << "❌ FAIL: Duplicate accepted." << std::endl;
    return 1;
  }

  std::cout << "\n--- Phase 3: Queue Pressure & Draining ("
            << PRESSURE_BATCH_SIZE << " items) ---" << std::endl;
  srvListener.resetStats();

  for (int i = 0; i < PRESSURE_BATCH_SIZE; ++i)
    cliListener.sendPoW(1000 + i);

  size_t maxQ = 0;
  for (int i = 0; i < 60; ++i) {
    size_t q = server.getVerifyPoWQueueSize();
    if (q > maxQ)
      maxQ = q;
    if (srvListener.successCount >= PRESSURE_BATCH_SIZE)
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  std::cout << "  -> Max Queue Depth Detected: " << maxQ << std::endl;
  std::cout << "  -> Final Validated: " << srvListener.successCount << "/"
            << PRESSURE_BATCH_SIZE << std::endl;
  std::cout << "  -> Final Queue Size: " << server.getVerifyPoWQueueSize()
            << std::endl;

  if (srvListener.successCount == PRESSURE_BATCH_SIZE && maxQ > 0 &&
      server.getVerifyPoWQueueSize() == 0)
    std::cout << "✅ PASS: Queue Buffered and Drained." << std::endl;
  else {
    std::cerr << "❌ FAIL: Queue logic failure." << std::endl;
    return 1;
  }

  std::cout << "\n--- Phase 4: Invalid PoW Handling (Destructive/Ban) ---"
            << std::endl;
  srvListener.resetStats();
  uint64_t errBefore = server.getLastError();
  cliListener.sendPoW(200, true, false);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  uint64_t errAfter = server.getLastError();

  std::cout << "  -> Validated: " << srvListener.successCount << " (Expected 0)"
            << std::endl;
  std::cout << "  -> LastError: " << errAfter << " (Expected > 0)" << std::endl;

  if (srvListener.successCount == 0 && errAfter != errBefore)
    std::cout << "✅ PASS: Invalid PoW Rejected." << std::endl;
  else {
    std::cerr << "❌ FAIL: Invalid PoW accepted or error not logged."
              << std::endl;
    return 1;
  }

  std::cout << "\n🎉 ALL TESTS PASSED." << std::endl;
  client.stop();
  server.stop();
  return 0;
}