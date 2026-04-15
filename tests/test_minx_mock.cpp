#include <boost/test/unit_test.hpp>

#include <minx/stdext.h>

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

  serverNode.listener.onProveWork = [&](const minx::SockAddr& /*addr*/,
                                        const minx::MinxProveWork& /*msg*/,
                                        int /*diff*/) {
    BOOST_TEST_MESSAGE("Server: Validated PROVE_WORK successfully!");
  };

  TestNode clientNode("Client", "127.0.0.1", 9001);
  registerNode(clientNode);

  clientNode.startNetwork(1);

  minx::Hash capturedServerKey;
  bool infoReceived = false;

  clientNode.listener.onInfo = [&](const minx::SockAddr& /*addr*/,
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

  minx::MinxConfig cfg;
  cfg.trustLoopback = false;
  TestNode serverNode("Server", "127.0.0.1", 9000, cfg);
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
    [&](const minx::SockAddr& /*addr*/, uint8_t code, const minx::Bytes& data) {
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
      serverNode.minx->allocatePassword(uniqueTicket);

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

BOOST_AUTO_TEST_CASE(TestSampledSpamBlocking) {
  minx::MinxConfig cfg;
  cfg.spamThreshold = 2;
  cfg.spamSampleRate = 4;
  cfg.trustLoopback = true; // bypass tickets, but NOT spam (isConnected=false)

  TestNode serverNode("Server", "127.0.0.1", 9100, cfg);
  registerNode(serverNode);
  serverNode.startNetwork();

  TestNode clientNode("Client", "127.0.0.1", 9101);
  registerNode(clientNode);
  clientNode.startNetwork();

  const int TOTAL = 200;
  for (int i = 0; i < TOTAL; ++i) {
    minx::MinxMessage msg{0, 0, 0, {(char)0xAB}};
    clientNode.minx->sendMessage(serverNode.addr, msg);
  }

  waitForCondition([&]() { return serverNode.listener.stats.message >= 1; }, 3);

  pollAll(50);

  int received = serverNode.listener.stats.message;
  BOOST_TEST_MESSAGE("Received " << received << " / " << TOTAL);
  BOOST_TEST(received > 0, "Should receive some messages");
  BOOST_TEST(received < TOTAL, "Should have dropped some messages");
}

BOOST_AUTO_TEST_CASE(TestNoSamplingWhenDisabled) {
  minx::MinxConfig cfg;
  cfg.spamThreshold = 2;
  cfg.spamSampleRate = 0;
  cfg.trustLoopback = false;

  TestNode serverNode("Server", "127.0.0.1", 9110, cfg);
  registerNode(serverNode);
  serverNode.startNetwork();

  TestNode clientNode("Client", "127.0.0.1", 9111);
  registerNode(clientNode);
  clientNode.startNetwork();

  serverNode.listener.onIsConnected = [](const minx::SockAddr&) {
    return true;
  };

  const int TOTAL = 200;
  for (int i = 0; i < TOTAL; ++i) {
    minx::MinxMessage msg{0, 0, 0, {(char)0xAB}};
    clientNode.minx->sendMessage(serverNode.addr, msg);
  }

  waitForCondition([&]() { return serverNode.listener.stats.message >= 1; }, 3);

  pollAll(50);

  int received = serverNode.listener.stats.message;
  BOOST_TEST_MESSAGE("Received " << received << " / " << TOTAL);
  BOOST_TEST(received == TOTAL,
             "All messages should pass when sampling is disabled");
}

BOOST_AUTO_TEST_CASE(TestInitStillFilteredIndependently) {
  minx::MinxConfig cfg;
  cfg.spamThreshold = 2;
  cfg.spamSampleRate = 0;
  cfg.trustLoopback = false;

  TestNode serverNode("Server", "127.0.0.1", 9120, cfg);
  registerNode(serverNode);
  serverNode.startNetwork();

  TestNode clientNode("Client", "127.0.0.1", 9121);
  registerNode(clientNode);
  clientNode.startNetwork();

  const int TOTAL = 100;
  for (int i = 0; i < TOTAL; ++i) {
    minx::MinxInit msg{0, 0, {}};
    clientNode.minx->sendInit(serverNode.addr, msg);
  }

  waitForCondition([&]() { return serverNode.listener.stats.init >= 1; }, 3);

  pollAll(50);

  int received = serverNode.listener.stats.init;
  BOOST_TEST_MESSAGE("INIT received " << received << " / " << TOTAL);
  BOOST_TEST(received > 0, "Should receive some INITs");
  BOOST_TEST(received < TOTAL,
             "INIT should be rate-limited by amplification filter");
}

// Helper: build a raw EXTENSION payload in the std-extension wire format
// — 8 bytes of routing key (uint64 big-endian) followed by body — and
// return it as a minx::Bytes that can be handed to Minx::sendExtension.
static minx::Bytes makeStdExtPacket(uint64_t key,
                                    const std::vector<uint8_t>& body) {
  minx::Bytes out;
  minx::MinxStdExtensions::appendKey(out, key);
  for (uint8_t b : body)
    out.push_back(static_cast<char>(b));
  return out;
}

BOOST_AUTO_TEST_CASE(TestStdExtensionsBuilderDispatch) {
  BOOST_TEST_MESSAGE("--- Starting StdExtensions Builder Dispatch Test ---");

  // Round-trip the key helpers before touching the network.
  {
    using SE = minx::MinxStdExtensions;
    constexpr uint64_t composed = SE::makeKey(0x0107, 0xCE53AABBCCDDULL);
    static_assert(composed == 0x0107CE53AABBCCDDULL);
    static_assert(SE::metaOf(composed) == 0x0107);
    static_assert(SE::idOf(composed) == 0xCE53AABBCCDDULL);
    // makeKey must mask high bits of the id argument
    static_assert(SE::makeKey(0x0001, 0xFFFFCE53AABBCCDDULL) ==
                  0x0001CE53AABBCCDDULL);
    // appendKey + readKey round-trip via boost::endian
    minx::Bytes buf;
    SE::appendKey(buf, composed);
    BOOST_TEST(buf.size() == SE::KEY_SIZE);
    BOOST_TEST(SE::readKey(buf) == composed);
    // readKey on a too-short buffer returns 0
    minx::Bytes shortBuf;
    shortBuf.push_back((char)0xAA);
    BOOST_TEST(SE::readKey(shortBuf) == 0u);
  }

  TestNode serverNode("Server", "127.0.0.1", 9200);
  registerNode(serverNode);
  serverNode.startNetwork();

  TestNode clientNode("Client", "127.0.0.1", 9201);
  registerNode(clientNode);
  clientNode.startNetwork();

  // Two distinct extensions, registered with the canonical "high 2 bytes
  // zero" form. Wire packets will arrive with non-zero meta in the high
  // bytes and must still dispatch correctly thanks to the KEY_MASK.
  const uint64_t KEY_A = 0xCE53AABBCCDDULL; // 0x0000CE53AABBCCDD
  const uint64_t KEY_B = 0xFF1122334455ULL; // 0x0000FF1122334455
  // A third key that nobody registers — must be dropped silently.
  const uint64_t KEY_UNKNOWN = 0xDEADBEEF0001ULL;

  std::atomic<int> handlerACalls{0};
  std::atomic<int> handlerBCalls{0};
  std::atomic<uint64_t> lastKeyA{0};
  std::atomic<uint64_t> lastKeyB{0};
  minx::Bytes lastPayloadA;
  minx::Bytes lastPayloadB;
  std::mutex payloadMutex;

  // Scope the builder explicitly to prove it can die immediately after
  // build() and the closure inside Minx still works.
  {
    minx::MinxStdExtensions stdExt;

    stdExt.registerExtension(KEY_A,
                             [&](const minx::SockAddr& /*addr*/, uint64_t key,
                                 const minx::Bytes& payload) {
                               ++handlerACalls;
                               lastKeyA = key;
                               std::lock_guard<std::mutex> lock(payloadMutex);
                               lastPayloadA = payload;
                             });

    stdExt.registerExtension(KEY_B,
                             [&](const minx::SockAddr& /*addr*/, uint64_t key,
                                 const minx::Bytes& payload) {
                               ++handlerBCalls;
                               lastKeyB = key;
                               std::lock_guard<std::mutex> lock(payloadMutex);
                               lastPayloadB = payload;
                             });

    // Registering with junk in the high 2 bytes must collapse to the
    // same masked entry — the second register replaces, not duplicates.
    stdExt.registerExtension(
      0xFFFFCE53AABBCCDDULL,
      [&](const minx::SockAddr&, uint64_t, const minx::Bytes&) {
        ++handlerACalls; // sentinel: should never actually fire if the
                         // real KEY_A handler below replaces it
      });
    stdExt.registerExtension(KEY_A,
                             [&](const minx::SockAddr& /*addr*/, uint64_t key,
                                 const minx::Bytes& payload) {
                               ++handlerACalls;
                               lastKeyA = key;
                               std::lock_guard<std::mutex> lock(payloadMutex);
                               lastPayloadA = payload;
                             });

    BOOST_TEST(stdExt.size() == 2); // A and B, masked-collapsed

    // Move-consume the builder. After this, stdExt is an empty husk.
    serverNode.minx->setExtensionHandler(std::move(stdExt).build());
  } // stdExt dies here — closure inside Minx must keep working

  // Send packet for KEY_A with meta=0x0107 packed into the high 2 bytes
  // of the wire key. The router must mask, find KEY_A, dispatch.
  {
    auto pkt =
      makeStdExtPacket(0x0107CE53AABBCCDDULL, {0xDE, 0xAD, 0xBE, 0xEF});
    clientNode.minx->sendExtension(serverNode.addr, pkt);
  }

  // Send packet for KEY_B with meta=0x0203 in the high 2 bytes.
  {
    auto pkt = makeStdExtPacket(0x0203FF1122334455ULL, {0x11, 0x22, 0x33});
    clientNode.minx->sendExtension(serverNode.addr, pkt);
  }

  // Send packet for an unknown key — must be silently dropped, even with
  // junk in the meta bytes.
  {
    auto pkt = makeStdExtPacket(0xFFFFULL << 48 | KEY_UNKNOWN, {0x99});
    clientNode.minx->sendExtension(serverNode.addr, pkt);
  }

  // Send a too-short packet (only 4 bytes of the 8-byte key) — drop.
  {
    minx::Bytes shortPkt;
    shortPkt.push_back((char)0x00);
    shortPkt.push_back((char)0x00);
    shortPkt.push_back((char)0xCE);
    shortPkt.push_back((char)0x53);
    clientNode.minx->sendExtension(serverNode.addr, shortPkt);
  }

  waitForCondition([&]() { return handlerACalls == 1 && handlerBCalls == 1; },
                   5);

  // Drain a few cycles to let any rogue callbacks land if the dispatcher
  // is leaky.
  pollAll(20);

  BOOST_TEST(handlerACalls == 1);
  BOOST_TEST(handlerBCalls == 1);
  // Handler must receive the FULL unmasked wire key, including the meta.
  BOOST_TEST(lastKeyA.load() == 0x0107CE53AABBCCDDULL);
  BOOST_TEST(lastKeyB.load() == 0x0203FF1122334455ULL);

  {
    std::lock_guard<std::mutex> lock(payloadMutex);
    BOOST_TEST(lastPayloadA.size() == 4u);
    BOOST_TEST(lastPayloadB.size() == 3u);
    BOOST_TEST((uint8_t)lastPayloadA[0] == 0xDE);
    BOOST_TEST((uint8_t)lastPayloadA[3] == 0xEF);
    BOOST_TEST((uint8_t)lastPayloadB[0] == 0x11);
    BOOST_TEST((uint8_t)lastPayloadB[2] == 0x33);
  }

  BOOST_TEST_MESSAGE("--- StdExtensions Builder Dispatch Test Complete ---");
}

BOOST_AUTO_TEST_SUITE_END()