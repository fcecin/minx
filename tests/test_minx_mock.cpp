#include <boost/test/unit_test.hpp>

#include "minx_mock.h"

using namespace minx_test;

BOOST_FIXTURE_TEST_SUITE(MinxMockValidationSuite, MinxMockFixture)

BOOST_AUTO_TEST_CASE(TestFullHandshakeAndMining) {
  BOOST_TEST_MESSAGE("--- Starting Happy Path Test ---");

  TestNode serverNode("Server", "127.0.0.1", 9000);
  registerNode(serverNode);
  serverNode.startFull(false, 1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    BOOST_TEST_MESSAGE("Server: Received GET_INFO, sending INFO");
    minx::MinxInfo infoMsg = {
      0, serverNode.minx->generatePassword(), msg.gpassword, 1, serverNode.key,
      {}};
    serverNode.minx->sendInfo(addr, infoMsg);
  };

  serverNode.listener.onProveWork =
    [&](const minx::SockAddr& addr, const minx::MinxProveWork& msg, int diff) {
      BOOST_TEST_MESSAGE("Server: Validated PROVE_WORK successfully!");
    };

  TestNode clientNode("Client", "127.0.0.1", 9001);
  registerNode(clientNode);

  clientNode.startNetwork(1);

  minx::Hash capturedServerKey;
  bool infoReceived = false;

  clientNode.listener.onInfo = [&](const minx::SockAddr& addr,
                                   const minx::MinxInfo& msg) {
    BOOST_TEST_MESSAGE("Client: Received INFO, capturing Server Key");
    capturedServerKey = msg.skey;
    infoReceived = true;
  };

  BOOST_TEST_MESSAGE("Client: Sending GET_INFO");
  clientNode.minx->sendGetInfo(serverNode.addr,
                               {0, clientNode.minx->generatePassword(), {}});

  waitForCondition([&]() { return infoReceived; }, 5);
  BOOST_TEST(infoReceived == true);

  BOOST_CHECK_EQUAL_COLLECTIONS(capturedServerKey.begin(),
                                capturedServerKey.end(), serverNode.key.begin(),
                                serverNode.key.end());

  clientNode.createClientPoWEngine(capturedServerKey, true);

  BOOST_TEST_MESSAGE("Client: Waiting for VM initialization...");
  waitForCondition(
    [&]() { return clientNode.minx->checkPoWEngine(capturedServerKey); }, 30);

  BOOST_TEST_MESSAGE("Client: Mining...");
  auto powMsg = mineValidPoW(clientNode, capturedServerKey, 1, 0);

  clientNode.minx->sendProveWork(serverNode.addr, powMsg);

  waitForCondition([&]() { return serverNode.listener.stats.proveWork > 0; },
                   5);

  BOOST_TEST(serverNode.listener.stats.proveWork == 1);
  BOOST_TEST(serverNode.minx->getLastError() == 0);

  BOOST_TEST_MESSAGE("--- Happy Path Test Complete ---");
}

BOOST_AUTO_TEST_CASE(TestDoubleSpendRejection) {
  BOOST_TEST_MESSAGE("--- Starting Double Spend Test ---");

  TestNode serverNode("Server", "127.0.0.1", 9000);
  registerNode(serverNode);
  serverNode.startFull(false, 1);

  TestNode clientNode("Client", "127.0.0.1", 9001);
  registerNode(clientNode);
  clientNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](auto addr, auto msg) {
    serverNode.minx->sendInfo(addr,
                              {0, 0, msg.gpassword, 1, serverNode.key, {}});
  };

  auto res = serverNode.minx->proveWork(clientNode.key, {}, serverNode.key, 1);
  if (!res)
    BOOST_FAIL("Mining failed");

  minx::MinxProveWork powMsg = {
    0, 0, 0, res->ckey, res->hdata, res->time, res->nonce, res->solution, {}};

  BOOST_TEST_MESSAGE("Client: Sending PoW #1 (Original)");
  clientNode.minx->sendProveWork(serverNode.addr, powMsg);
  waitForCondition([&]() { return serverNode.listener.stats.proveWork == 1; });

  BOOST_TEST(serverNode.minx->getLastError() == 0);

  BOOST_TEST_MESSAGE("Client: Sending PoW #2 (Replay Attack)");
  clientNode.minx->sendProveWork(serverNode.addr, powMsg);

  pollAll(10);

  BOOST_TEST(serverNode.listener.stats.proveWork == 1,
             "Listener count should not increase for double spend");

  BOOST_TEST(serverNode.minx->getLastError() == minx::MINX_ERROR_DOUBLE_SPEND,
             "Server last error should be DOUBLE_SPEND (7)");

  BOOST_TEST_MESSAGE("--- Double Spend Test Complete ---");
}

BOOST_AUTO_TEST_CASE(TestBannedIP) {
  BOOST_TEST_MESSAGE("--- Starting IP Ban Test ---");

  TestNode serverNode("Server", "127.0.0.1", 9000);
  registerNode(serverNode);
  serverNode.startNetwork();

  TestNode clientNode("Client", "127.0.0.1", 9001);
  registerNode(clientNode);
  clientNode.startNetwork();

  BOOST_TEST_MESSAGE("Server: Banning Client IP "
                     << clientNode.addr.address().to_string());
  serverNode.minx->banAddress(clientNode.addr.address());

  BOOST_TEST_MESSAGE("Client: Sending GET_INFO (Expect Silence)");
  clientNode.minx->sendGetInfo(serverNode.addr, {0, 0, {}});

  pollAll(20);

  BOOST_TEST(serverNode.listener.stats.getInfo == 0,
             "Banned IP should not trigger listener callbacks");

  BOOST_TEST_MESSAGE("--- IP Ban Test Complete ---");
}

BOOST_AUTO_TEST_CASE(TestApplicationMessage) {
  BOOST_TEST_MESSAGE("--- Starting App Message Test ---");

  TestNode serverNode("Server", "127.0.0.1", 9000);
  registerNode(serverNode);
  serverNode.startNetwork();

  TestNode clientNode("Client", "127.0.0.1", 9001);
  registerNode(clientNode);
  clientNode.startNetwork();

  const minx::Bytes secretPayload = {(char)0xDE, (char)0xAD, (char)0xBE,
                                     (char)0xEF};

  const uint8_t appCode = 0xAA;
  bool msgReceived = false;

  serverNode.listener.onApplication =
    [&](const minx::SockAddr& addr, uint8_t code, const minx::Bytes& data) {
      BOOST_TEST_MESSAGE("Server: Received App Message");
      BOOST_TEST(code == appCode);
      BOOST_TEST(data == secretPayload);
      msgReceived = true;
    };

  clientNode.minx->sendApplication(serverNode.addr, secretPayload, appCode);

  waitForCondition([&]() { return msgReceived; });

  BOOST_TEST(msgReceived == true);
  BOOST_TEST(serverNode.listener.stats.application == 1);

  BOOST_TEST_MESSAGE("--- App Message Test Complete ---");
}

BOOST_AUTO_TEST_CASE(TestParallelPoWBurst) {
  BOOST_TEST_MESSAGE("--- Starting Parallel Burst Test (Multi-threaded) ---");

  const int NUM_EXTRA_CLIENTS = 16;
  const int POWS_PER_CLIENT = 5;
  const int TOTAL_EXPECTED = NUM_EXTRA_CLIENTS * POWS_PER_CLIENT;
  const int TEST_DIFFICULTY = 1;
  const int NUM_THREADS = 16;

  TestNode serverNode("Server", "127.0.0.1", 9000);

  serverNode.startFull(false, TEST_DIFFICULTY);
  serverNode.minx->updatePoWSpendCache();

  std::atomic<int> processedCount{0};
  serverNode.listener.onProveWork = [&](const minx::SockAddr&,
                                        const minx::MinxProveWork&,
                                        int) { processedCount++; };

  std::vector<std::unique_ptr<TestNode>> fleet;
  for (int i = 0; i < NUM_EXTRA_CLIENTS; ++i) {
    auto node = std::make_unique<TestNode>("Bot_" + std::to_string(i),
                                           "127.0.0.1", 9010 + i);

    node->startNetwork(TEST_DIFFICULTY);
    fleet.push_back(std::move(node));
  }

  struct PendingPacket {
    minx::MinxProveWork msg;
    TestNode* sender;
  };
  std::vector<PendingPacket> burstQueue;

  BOOST_TEST_MESSAGE("Step 1: Pre-mining " << TOTAL_EXPECTED
                                           << " solutions with difficulty "
                                           << TEST_DIFFICULTY << "...");

  for (int i = 0; i < NUM_EXTRA_CLIENTS; ++i) {
    auto& bot = fleet[i];
    for (int j = 0; j < POWS_PER_CLIENT; ++j) {
      uint64_t uniqueTicket = (i * 10000) + j + 1;
      serverNode.minx->allocatePassword(uniqueTicket, bot->addr.address());

      minx::Hash uniqueHdata;
      std::fill(uniqueHdata.begin(), uniqueHdata.end(), 0);
      std::memcpy(uniqueHdata.data(), &uniqueTicket, sizeof(uniqueTicket));

      auto res = serverNode.minx->proveWork(bot->key, uniqueHdata,
                                            serverNode.key, TEST_DIFFICULTY);
      if (!res)
        BOOST_FAIL("Mining failed");

      minx::MinxProveWork msg = {
        0,         0,          uniqueTicket,  res->ckey, res->hdata,
        res->time, res->nonce, res->solution, {}};
      burstQueue.push_back({msg, bot.get()});
    }
  }

  BOOST_TEST_MESSAGE("Step 2: Bursting " << burstQueue.size() << " packets...");
  for (auto& packet : burstQueue) {
    packet.sender->minx->sendProveWork(serverNode.addr, packet.msg);
  }

  BOOST_TEST_MESSAGE("Step 3: Ingesting packets (Network Only)...");

  auto ingestStart = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - ingestStart <
         std::chrono::seconds(1)) {

    serverNode.poll();

    for (auto& bot : fleet)
      bot->poll();

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  BOOST_TEST_MESSAGE("Step 4: Launching " << NUM_THREADS
                                          << " parallel verifiers...");

  std::vector<std::thread> verifierThreads;
  std::mutex mm;
  for (int i = 0; i < NUM_THREADS; ++i) {
    verifierThreads.emplace_back([&, i]() {
      int myCount = 0;
      while (true) {
        int result = serverNode.minx->verifyPoWs(1);

        if (result < 0) {
          std::lock_guard lock(mm);
          BOOST_TEST_MESSAGE("Thread " << i << " ERROR: " << result);
          break;
        }
        if (result == 0)
          break;

        myCount += result;
      }
      std::lock_guard lock(mm);
      BOOST_TEST_MESSAGE("Thread "
                         << i << " finished. Verified hashes: " << myCount);
    });
  }

  for (auto& t : verifierThreads)
    t.join();

  BOOST_TEST(serverNode.listener.stats.proveWork == TOTAL_EXPECTED,
             "Expected " << TOTAL_EXPECTED << ", Got "
                         << serverNode.listener.stats.proveWork);

  BOOST_TEST_MESSAGE("Verified " << serverNode.listener.stats.proveWork << "/"
                                 << TOTAL_EXPECTED << " hashes.");

  BOOST_TEST(serverNode.minx->getLastError() == 0);

  BOOST_TEST_MESSAGE("--- Parallel Burst Test Complete ---");
}

BOOST_AUTO_TEST_SUITE_END()