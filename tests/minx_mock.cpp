#include "minx_mock.h"

#include <boost/test/unit_test.hpp>
#include <random>

namespace minx_test {

minx::Hash makeKey() {
  minx::Hash h;
  for (auto& b : h)
    b = rand() % 255;
  return h;
}

TestNode::TestNode(std::string n, std::string ip, uint16_t port)
    : name(n), addr(boost::asio::ip::address::from_string(ip), port),
      key(makeKey()) {
  minx = std::make_unique<minx::Minx>(&listener, minx::MinxConfig{});
}

TestNode::~TestNode() {
  if (minx)
    minx->closeSocket();
}

void TestNode::createPoWEngine(const minx::Hash& engineKey,
                                const std::string& logLabel) {
  BOOST_TEST_MESSAGE("Node [" << name << "]: Initializing " << logLabel
                              << "...");
  auto start_time = std::chrono::high_resolution_clock::now();
  minx->createPoWEngine(engineKey);
  while (!minx->checkPoWEngine(engineKey)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration_ms =
    std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time)
      .count();
  BOOST_TEST_MESSAGE("Node [" << name << "]: " << logLabel
                              << " READY. Took: " << duration_ms << " ms");
}

void TestNode::createServerPoWEngine(bool useDataset) {
  minx->setUseDataset(useDataset);
  minx->setServerKey(key);
  std::string modeStr =
    useDataset ? "SERVER Engine (Full Dataset)" : "SERVER Engine (Cache Only)";
  createPoWEngine(key, modeStr);
}

void TestNode::createClientPoWEngine(const minx::Hash& targetKey,
                                  bool useDataset) {
  minx->setUseDataset(useDataset);
  std::string modeStr =
    useDataset ? "CLIENT Engine (Full Dataset)" : "CLIENT Engine (Cache Only)";
  createPoWEngine(targetKey, modeStr);
}

void TestNode::startNetwork(int minDiff) {
  minx->setMinimumDifficulty(minDiff);
  minx->openSocket(addr, netio, taskio);
}

void TestNode::poll() {
  bool net_busy, task_busy;
  do {
    net_busy = (netio.poll_one() > 0);
    task_busy = (taskio.poll_one() > 0);
  } while (net_busy || task_busy);
}

void TestNode::processPoW() {
  minx->updatePoWSpendCache();
  minx->verifyPoWs();
}

MinxMockFixture::MinxMockFixture() {}
MinxMockFixture::~MinxMockFixture() {}

void MinxMockFixture::registerNode(TestNode& node) {
  activeNodes.push_back(&node);
}

void MinxMockFixture::pollAll(int cycles) {
  for (int i = 0; i < cycles; ++i) {
    for (auto* node : activeNodes) {
      node->poll();
      if (node->minx->checkPoWEngine(node->key)) {
        node->processPoW();
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

void MinxMockFixture::waitForCondition(std::function<bool()> predicate,
                                       int timeoutSecs) {
  auto start = std::chrono::steady_clock::now();
  while (!predicate()) {
    pollAll();
    if (std::chrono::steady_clock::now() - start >
        std::chrono::seconds(timeoutSecs)) {
      throw std::runtime_error("Timeout waiting for condition");
    }
  }
}

minx::MinxProveWork MinxMockFixture::mineValidPoW(TestNode& miner,
                                                  const minx::Hash& targetKey,
                                                  int diff,
                                                  uint64_t spassword) {
  auto res = miner.minx->proveWork(miner.key, {}, targetKey, diff);
  if (!res)
    throw std::runtime_error("Mining failed");
  minx::MinxProveWork msg = *res;
  minx::MinxProveWork finalMsg = {
    0,         0,          spassword,     res->ckey, res->hdata,
    res->time, res->nonce, res->solution, {}};
  return finalMsg;
}

} // namespace minx_test