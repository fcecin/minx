#include <boost/test/unit_test.hpp>

#include "minx_mock.h"
#include <minx/proxy/minxproxy.h>
#include <minx/proxy/tcp_server.h>

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

using namespace minx_test;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// Minimal TCP client for talking to the proxy.
class ProxyTestClient {
public:
  ProxyTestClient(asio::io_context& io) : sock_(io) {}

  void connect(uint16_t port) {
    sock_.connect(
      tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), port));
  }

  void sendRaw(const uint8_t* data, size_t len) {
    uint8_t header[2];
    header[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
    header[1] = static_cast<uint8_t>(len & 0xFF);
    asio::write(sock_, asio::buffer(header, 2));
    asio::write(sock_, asio::buffer(data, len));
  }

  void sendGetInfo(uint64_t gpassword) {
    std::vector<uint8_t> buf;
    buf.push_back(minx::MINX_GET_INFO);
    buf.push_back(0); // version
    uint64_t gpw_be = boost::endian::native_to_big(gpassword);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&gpw_be),
               reinterpret_cast<uint8_t*>(&gpw_be) + 8);
    sendRaw(buf.data(), buf.size());
  }

  void sendInit(uint64_t gpassword) {
    std::vector<uint8_t> buf;
    buf.push_back(minx::MINX_INIT);
    buf.push_back(0); // version
    uint64_t gpw_be = boost::endian::native_to_big(gpassword);
    buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&gpw_be),
               reinterpret_cast<uint8_t*>(&gpw_be) + 8);
    sendRaw(buf.data(), buf.size());
  }

  void sendProveWork(uint64_t gpassword, uint64_t spassword,
                     const minx::Hash& ckey, const minx::Hash& hdata,
                     uint64_t time, uint64_t nonce,
                     const minx::Hash& solution) {
    std::vector<uint8_t> buf;
    buf.push_back(minx::MINX_PROVE_WORK);
    buf.push_back(0); // version
    auto append64 = [&](uint64_t v) {
      uint64_t be = boost::endian::native_to_big(v);
      buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&be),
                 reinterpret_cast<uint8_t*>(&be) + 8);
    };
    append64(gpassword);
    append64(spassword);
    buf.insert(buf.end(), ckey.begin(), ckey.end());
    buf.insert(buf.end(), hdata.begin(), hdata.end());
    append64(time);
    append64(nonce);
    buf.insert(buf.end(), solution.begin(), solution.end());
    sendRaw(buf.data(), buf.size());
  }

  std::vector<uint8_t> recvMsg() {
    uint8_t header[2];
    asio::read(sock_, asio::buffer(header, 2));
    uint16_t len = (static_cast<uint16_t>(header[0]) << 8) |
                   static_cast<uint16_t>(header[1]);
    std::vector<uint8_t> buf(len);
    asio::read(sock_, asio::buffer(buf));
    return buf;
  }

  bool hasData() { return sock_.available() > 0; }

  void close() {
    boost::system::error_code ec;
    sock_.shutdown(tcp::socket::shutdown_both, ec);
    sock_.close(ec);
  }

  void sendMessage(uint64_t gpassword, uint64_t spassword,
                   const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> buf;
    buf.push_back(minx::MINX_MESSAGE);
    buf.push_back(0); // version
    auto append64 = [&](uint64_t v) {
      uint64_t be = boost::endian::native_to_big(v);
      buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&be),
                 reinterpret_cast<uint8_t*>(&be) + 8);
    };
    append64(gpassword);
    append64(spassword);
    buf.insert(buf.end(), payload.begin(), payload.end());
    sendRaw(buf.data(), buf.size());
  }

  tcp::socket& socket() { return sock_; }

private:
  tcp::socket sock_;
};

// Simulated packet loss for all proxy tests (basis points, 500 = 5%).
static constexpr uint16_t PROXY_TEST_PACKET_LOSS_BPS = 500;

inline minx::MinxConfig testServerConfig() {
  minx::MinxConfig cfg;
  cfg.trustLoopback = true;
  return cfg;
}

inline minx::MinxProxyConfig testProxyConfig() {
  minx::MinxProxyConfig cfg;
  cfg.packetLossBps = PROXY_TEST_PACKET_LOSS_BPS;
  cfg.channelTimeout = std::chrono::seconds(3);
  cfg.sweepInterval = std::chrono::seconds(1);
  return cfg;
}

// Fixture: server node + proxy + proxyIO polling.
struct ProxyTestFixture : MinxMockFixture {
  boost::asio::io_context proxyIO;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
    proxyWorkGuard{proxyIO.get_executor()};

  void pollAllWithProxy(int cycles = 1) {
    for (int i = 0; i < cycles; ++i) {
      for (auto* node : activeNodes) {
        node->poll();
        if (node->minx->checkPoWEngine(node->key))
          node->processPoW();
      }
      proxyIO.poll();
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }

  void waitForProxy(std::function<bool()> predicate, int timeoutSecs = 30) {
    auto start = std::chrono::steady_clock::now();
    while (!predicate()) {
      pollAllWithProxy();
      if (std::chrono::steady_clock::now() - start >
          std::chrono::seconds(timeoutSecs)) {
        BOOST_FAIL("Timeout waiting for proxy condition");
      }
    }
  }
};

BOOST_FIXTURE_TEST_SUITE(MinxProxySuite, ProxyTestFixture)

BOOST_AUTO_TEST_CASE(TestProxyGetInfo) {
  BOOST_TEST_MESSAGE("--- Proxy: GET_INFO through proxy ---");

  // Server on UDP.
  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  // Server responds to GET_INFO with INFO.
  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    BOOST_TEST_MESSAGE("Server: got GET_INFO");
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  // Proxy.
  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  // Wait for proxy to get its initial INFO cache.
  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  BOOST_TEST_MESSAGE("Proxy has cached INFO");

  // TCP client connects and sends GET_INFO.
  auto proxyPort = proxy.port();
  ProxyTestClient client(proxyIO);
  client.connect(proxyPort);
  pollAllWithProxy(5);

  uint64_t clientGPw = 0xDEADBEEF;
  client.sendGetInfo(clientGPw);

  // Poll until client has data.
  waitForProxy([&]() { return client.hasData(); }, 10);

  auto reply = client.recvMsg();
  BOOST_REQUIRE(reply.size() >= 1 + 1 + 8 + 8 + 32 + 1); // INFO min size
  BOOST_TEST(reply[0] == minx::MINX_INFO);

  // Check spassword matches our gpassword.
  uint64_t replySPw;
  std::memcpy(&replySPw, &reply[10], 8);
  replySPw = boost::endian::big_to_native(replySPw);
  BOOST_TEST(replySPw == clientGPw);

  // Check server key.
  minx::Hash replyKey;
  std::memcpy(replyKey.data(), &reply[18], 32);
  BOOST_CHECK_EQUAL_COLLECTIONS(replyKey.begin(), replyKey.end(),
                                serverNode.key.begin(), serverNode.key.end());

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: GET_INFO test complete ---");
}

BOOST_AUTO_TEST_CASE(TestProxyMultipleClientsGetInfo) {
  BOOST_TEST_MESSAGE("--- Proxy: Multiple clients GET_INFO ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  // Two clients send GET_INFO.
  auto proxyPort = proxy.port();
  ProxyTestClient c1(proxyIO);
  ProxyTestClient c2(proxyIO);
  c1.connect(proxyPort);
  c2.connect(proxyPort);
  pollAllWithProxy(5);

  uint64_t gpw1 = 0x1111, gpw2 = 0x2222;
  c1.sendGetInfo(gpw1);
  c2.sendGetInfo(gpw2);

  waitForProxy([&]() { return c1.hasData() && c2.hasData(); }, 10);

  auto r1 = c1.recvMsg();
  auto r2 = c2.recvMsg();

  // Each client should get their own spassword back.
  uint64_t spw1, spw2;
  std::memcpy(&spw1, &r1[10], 8);
  spw1 = boost::endian::big_to_native(spw1);
  std::memcpy(&spw2, &r2[10], 8);
  spw2 = boost::endian::big_to_native(spw2);

  BOOST_TEST(spw1 == gpw1);
  BOOST_TEST(spw2 == gpw2);

  c1.close();
  c2.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Multiple clients GET_INFO complete ---");
}

BOOST_AUTO_TEST_CASE(TestProxyFullPoWFlow) {
  BOOST_TEST_MESSAGE("--- Proxy: Full PoW flow ---");

  // Server.
  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startFull(false, 1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  serverNode.listener.onProveWork = [&](const minx::SockAddr& addr,
                                        const minx::MinxProveWork& msg,
                                        int /*diff*/) {
    BOOST_TEST_MESSAGE("Server: Validated PROVE_WORK!");
    // Respond to keep the proxy channel's ticket chain alive.
    serverNode.minx->sendMessage(
      addr, {0, serverNode.minx->generatePassword(), msg.gpassword, {}});
  };

  // Proxy.
  auto proxyCfg = testProxyConfig();
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  // Client mines a valid PoW using the test infrastructure.
  TestNode clientMiner("ClientMiner", "127.0.0.1", 0);
  registerNode(clientMiner);
  clientMiner.createClientPoWEngine(serverNode.key, true);

  BOOST_TEST_MESSAGE("Client: Mining...");
  auto powMsg = mineValidPoW(clientMiner, serverNode.key, 1, 0);

  // TCP client sends the PROVE_WORK through proxy.
  auto proxyPort = proxy.port();
  ProxyTestClient client(proxyIO);
  client.connect(proxyPort);
  pollAllWithProxy(5);

  uint64_t clientGPw = 0xCAFE;
  client.sendProveWork(clientGPw, 0, powMsg.ckey, powMsg.hdata, powMsg.time,
                       powMsg.nonce, powMsg.solution);

  waitForProxy([&]() { return client.hasData(); }, 10);

  BOOST_TEST(serverNode.listener.stats.proveWork == 1);
  BOOST_TEST(serverNode.minx->getLastError() == 0);
  auto reply = client.recvMsg();
  BOOST_REQUIRE(reply.size() >= 18);
  BOOST_TEST(reply[0] == minx::MINX_MESSAGE);
  // spassword should echo the client's original gpassword (0xCAFE).
  uint64_t spw;
  std::memcpy(&spw, &reply[10], 8);
  spw = boost::endian::big_to_native(spw);
  BOOST_TEST(spw == 0xCAFEu);

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Full PoW flow complete ---");
}

BOOST_AUTO_TEST_CASE(TestProxyClientDisconnectCleansUp) {
  BOOST_TEST_MESSAGE("--- Proxy: Client disconnect cleanup ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  auto proxyPort = proxy.port();
  ProxyTestClient client(proxyIO);
  client.connect(proxyPort);
  pollAllWithProxy(5);
  BOOST_TEST(proxy.clientCount() == 1);

  client.close();
  waitForProxy([&]() { return proxy.clientCount() == 0; }, 10);
  BOOST_TEST(proxy.clientCount() == 0);

  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Client disconnect cleanup complete ---");
}

// -----------------------------------------------------------------------
// Cached GET_INFO: client GET_INFO served from cache, not forwarded
// to the server again.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyCachedGetInfo) {
  BOOST_TEST_MESSAGE("--- Proxy: Cached GET_INFO ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  // Record server GET_INFO count after proxy warmup.
  int baseGetInfo = serverNode.listener.stats.getInfo.load();
  BOOST_TEST_MESSAGE("Base getInfo count after warmup: " << baseGetInfo);

  auto proxyPort = proxy.port();

  // Client 1 sends GET_INFO — should be served from cache.
  ProxyTestClient c1(proxyIO);
  c1.connect(proxyPort);
  pollAllWithProxy(5);
  c1.sendGetInfo(0x1111);
  waitForProxy([&]() { return c1.hasData(); }, 10);
  auto r1 = c1.recvMsg();
  BOOST_TEST(r1[0] == minx::MINX_INFO);

  // Client 2 also sends GET_INFO — also from cache.
  ProxyTestClient c2(proxyIO);
  c2.connect(proxyPort);
  pollAllWithProxy(5);
  c2.sendGetInfo(0x2222);
  waitForProxy([&]() { return c2.hasData(); }, 10);
  auto r2 = c2.recvMsg();
  BOOST_TEST(r2[0] == minx::MINX_INFO);

  // Server getInfo count should NOT have increased beyond warmup.
  pollAllWithProxy(10);
  int finalGetInfo = serverNode.listener.stats.getInfo.load();
  BOOST_TEST_MESSAGE("Final getInfo count: " << finalGetInfo << " (was "
                                             << baseGetInfo << ")");
  BOOST_TEST(finalGetInfo == baseGetInfo);

  c1.close();
  c2.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Cached GET_INFO complete ---");
}

// -----------------------------------------------------------------------
// INIT swallowed: proxy handles INIT locally, never forwards to server.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyInitSwallowed) {
  BOOST_TEST_MESSAGE("--- Proxy: INIT swallowed ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  // Client sends INIT through proxy.
  ProxyTestClient client(proxyIO);
  client.connect(proxy.port());
  pollAllWithProxy(5);

  client.sendInit(0xBEEF);

  // Poll plenty to give it time to propagate (if it were forwarded).
  pollAllWithProxy(50);

  // Server should have received 0 INITs.
  BOOST_TEST(serverNode.listener.stats.init == 0);

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: INIT swallowed complete ---");
}

// -----------------------------------------------------------------------
// Max clients: reject connections beyond the configured limit.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyMaxClientsRejection) {
  BOOST_TEST_MESSAGE("--- Proxy: Max clients rejection ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 1; // Only allow 1 client
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  auto proxyPort = proxy.port();

  // Client 1 connects OK.
  ProxyTestClient c1(proxyIO);
  c1.connect(proxyPort);
  pollAllWithProxy(5);
  BOOST_TEST(proxy.clientCount() == 1);

  // Client 1 can get data.
  c1.sendGetInfo(0x1111);
  waitForProxy([&]() { return c1.hasData(); }, 10);
  auto r1 = c1.recvMsg();
  BOOST_TEST(r1[0] == minx::MINX_INFO);

  // Client 2 should be rejected (maxClients=1).
  ProxyTestClient c2(proxyIO);
  c2.connect(proxyPort);
  pollAllWithProxy(10);

  // Proxy should still have only 1 client.
  BOOST_TEST(proxy.clientCount() == 1);

  c1.close();
  c2.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Max clients rejection complete ---");
}

// -----------------------------------------------------------------------
// Client disconnect: client disconnects, proxy cleans up, new client works.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyClientDisconnectAndReconnect) {
  BOOST_TEST_MESSAGE("--- Proxy: Client disconnect and reconnect ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  auto proxyPort = proxy.port();

  // Client 1 connects, gets INFO, then disconnects.
  {
    ProxyTestClient c1(proxyIO);
    c1.connect(proxyPort);
    pollAllWithProxy(5);
    BOOST_TEST(proxy.clientCount() == 1);

    c1.sendGetInfo(0x1111);
    waitForProxy([&]() { return c1.hasData(); }, 10);
    auto r1 = c1.recvMsg();
    BOOST_TEST(r1[0] == minx::MINX_INFO);

    c1.close();
  }

  waitForProxy([&]() { return proxy.clientCount() == 0; }, 10);
  BOOST_TEST(proxy.clientCount() == 0);

  // New client connects and works fine.
  ProxyTestClient c2(proxyIO);
  c2.connect(proxyPort);
  pollAllWithProxy(5);
  BOOST_TEST(proxy.clientCount() == 1);

  c2.sendGetInfo(0x2222);
  waitForProxy([&]() { return c2.hasData(); }, 10);
  auto r2 = c2.recvMsg();
  BOOST_TEST(r2[0] == minx::MINX_INFO);

  // Verify spassword is correct for the new client.
  uint64_t spw2;
  std::memcpy(&spw2, &r2[10], 8);
  spw2 = boost::endian::big_to_native(spw2);
  BOOST_TEST(spw2 == 0x2222u);

  c2.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Client disconnect and reconnect complete ---");
}

// -----------------------------------------------------------------------
// Multiple concurrent PROVE_WORK: two clients mine and submit.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyMultipleConcurrentProveWork) {
  BOOST_TEST_MESSAGE("--- Proxy: Multiple concurrent PoW ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startFull(false, 1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  serverNode.listener.onProveWork = [&](const minx::SockAddr& addr,
                                        const minx::MinxProveWork& msg,
                                        int /*diff*/) {
    BOOST_TEST_MESSAGE("Server: Validated PROVE_WORK!");
    serverNode.minx->sendMessage(
      addr, {0, serverNode.minx->generatePassword(), msg.gpassword, {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  // Two miners produce valid PoWs.
  TestNode miner1("Miner1", "127.0.0.1", 0);
  TestNode miner2("Miner2", "127.0.0.1", 0);
  registerNode(miner1);
  registerNode(miner2);
  miner1.createClientPoWEngine(serverNode.key, true);
  miner2.createClientPoWEngine(serverNode.key, true);

  BOOST_TEST_MESSAGE("Mining PoW 1...");
  auto pow1 = mineValidPoW(miner1, serverNode.key, 1, 0);
  BOOST_TEST_MESSAGE("Mining PoW 2...");
  auto pow2 = mineValidPoW(miner2, serverNode.key, 1, 0);

  // Two TCP clients submit PoWs through proxy.
  auto proxyPort = proxy.port();
  ProxyTestClient c1(proxyIO);
  ProxyTestClient c2(proxyIO);
  c1.connect(proxyPort);
  c2.connect(proxyPort);
  pollAllWithProxy(5);

  c1.sendProveWork(0xCAFE, 0, pow1.ckey, pow1.hdata, pow1.time, pow1.nonce,
                   pow1.solution);
  c2.sendProveWork(0xBEEF, 0, pow2.ckey, pow2.hdata, pow2.time, pow2.nonce,
                   pow2.solution);

  waitForProxy([&]() { return c1.hasData() && c2.hasData(); }, 10);

  BOOST_TEST(serverNode.listener.stats.proveWork >= 2);
  BOOST_TEST(serverNode.minx->getLastError() == 0);
  auto r1 = c1.recvMsg();
  auto r2 = c2.recvMsg();
  BOOST_REQUIRE(r1.size() >= 18);
  BOOST_REQUIRE(r2.size() >= 18);
  BOOST_TEST(r1[0] == minx::MINX_MESSAGE);
  BOOST_TEST(r2[0] == minx::MINX_MESSAGE);
  // Each response's spassword should echo the respective client's gpassword.
  uint64_t spw1, spw2;
  std::memcpy(&spw1, &r1[10], 8);
  spw1 = boost::endian::big_to_native(spw1);
  std::memcpy(&spw2, &r2[10], 8);
  spw2 = boost::endian::big_to_native(spw2);
  // One should be 0xCAFE, the other 0xBEEF (order may vary).
  BOOST_TEST((spw1 == 0xCAFEu || spw1 == 0xBEEFu));
  BOOST_TEST((spw2 == 0xCAFEu || spw2 == 0xBEEFu));
  BOOST_TEST(spw1 != spw2);

  c1.close();
  c2.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Multiple concurrent PoW complete ---");
}

// -----------------------------------------------------------------------
// MESSAGE relay: a MINX_MESSAGE gets relayed through the proxy with
// payload preserved.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyMessageRelay) {
  BOOST_TEST_MESSAGE("--- Proxy: MESSAGE relay ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  minx::Bytes receivedPayload;
  serverNode.listener.onMessage = [&](const minx::SockAddr& addr,
                                      const minx::MinxMessage& msg) {
    BOOST_TEST_MESSAGE("Server: Received MESSAGE through proxy");
    receivedPayload = msg.data;
    // Respond to keep the proxy channel's ticket chain alive.
    serverNode.minx->sendMessage(
      addr, {0, serverNode.minx->generatePassword(), msg.gpassword, {}});
  };

  auto proxyCfg = testProxyConfig();
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  ProxyTestClient client(proxyIO);
  client.connect(proxy.port());
  pollAllWithProxy(5);

  // Send MESSAGE with a payload.
  std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
  client.sendMessage(0xAAAA, 0, payload);

  waitForProxy([&]() { return serverNode.listener.stats.message >= 1; }, 10);

  BOOST_TEST(serverNode.listener.stats.message >= 1);
  // Bytes is vector<char>, so cast for comparison.
  std::vector<uint8_t> gotPayload(receivedPayload.begin(),
                                  receivedPayload.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(gotPayload.begin(), gotPayload.end(),
                                payload.begin(), payload.end());

  // Verify the server's response made it back to the client.
  waitForProxy([&]() { return client.hasData(); }, 10);
  auto reply = client.recvMsg();
  BOOST_REQUIRE(reply.size() >= 18);
  BOOST_TEST(reply[0] == minx::MINX_MESSAGE);
  // spassword should echo the client's original gpassword (0xAAAA).
  uint64_t spw;
  std::memcpy(&spw, &reply[10], 8);
  spw = boost::endian::big_to_native(spw);
  BOOST_TEST(spw == 0xAAAAu);

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: MESSAGE relay complete ---");
}

// =======================================================================
// ADVANCED / STRESS TESTS
// =======================================================================

// -----------------------------------------------------------------------
// Stress: many clients simultaneously request GET_INFO.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyStressManyClients) {
  BOOST_TEST_MESSAGE("--- Proxy: Stress many clients ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  std::atomic<int> messageCount{0};
  serverNode.listener.onMessage = [&](const minx::SockAddr& addr,
                                      const minx::MinxMessage& msg) {
    ++messageCount;
    // Respond to keep proxy channels flowing.
    serverNode.minx->sendMessage(
      addr, {0, serverNode.minx->generatePassword(), msg.gpassword, {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 100;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  auto proxyPort = proxy.port();

  constexpr int N = 50;
  constexpr int ROUNDS = 5;
  std::vector<std::unique_ptr<ProxyTestClient>> clients;
  clients.reserve(N);

  // Connect all clients.
  for (int i = 0; i < N; ++i) {
    clients.push_back(std::make_unique<ProxyTestClient>(proxyIO));
    clients.back()->connect(proxyPort);
  }
  pollAllWithProxy(10);
  BOOST_TEST(proxy.clientCount() == N);

  // Phase 1: All clients send GET_INFO and verify cached INFO response.
  for (int round = 0; round < ROUNDS; ++round) {
    for (int i = 0; i < N; ++i) {
      uint64_t gpw = static_cast<uint64_t>((round << 16) | (i + 1));
      clients[i]->sendGetInfo(gpw);
    }
    waitForProxy(
      [&]() {
        for (auto& c : clients)
          if (!c->hasData())
            return false;
        return true;
      },
      10);
    for (int i = 0; i < N; ++i) {
      auto reply = clients[i]->recvMsg();
      BOOST_REQUIRE(reply.size() >= 18);
      BOOST_TEST(reply[0] == minx::MINX_INFO);
      uint64_t spw;
      std::memcpy(&spw, &reply[10], 8);
      spw = boost::endian::big_to_native(spw);
      uint64_t expectedGpw = static_cast<uint64_t>((round << 16) | (i + 1));
      BOOST_TEST(spw == expectedGpw);
    }
  }

  // Phase 2: All clients send MESSAGE × ROUNDS, wait for server to receive.
  for (int round = 0; round < ROUNDS; ++round) {
    for (int i = 0; i < N; ++i) {
      uint64_t gpw = static_cast<uint64_t>((round << 16) | (i + 1));
      std::vector<uint8_t> payload = {
        static_cast<uint8_t>(round), static_cast<uint8_t>(i & 0xFF),
        static_cast<uint8_t>((i >> 8) & 0xFF), 0xAA};
      clients[i]->sendMessage(gpw, 0, payload);
    }
  }

  // Forward-path loss: server receives expectedDeliveries of total sent.
  int totalSent = N * ROUNDS;
  int expectedAtServer = static_cast<int>(
    minx::expectedDeliveries(totalSent, PROXY_TEST_PACKET_LOSS_BPS));
  waitForProxy([&]() { return messageCount.load() >= expectedAtServer; }, 30);
  BOOST_TEST(messageCount.load() == expectedAtServer);

  // Drain any MESSAGE responses that arrived at clients.
  pollAllWithProxy(20);

  // Disconnect half the clients, verify proxy tracks correctly.
  for (int i = 0; i < N / 2; ++i) {
    clients[i]->close();
  }
  waitForProxy(
    [&]() { return proxy.clientCount() == static_cast<size_t>(N - N / 2); },
    10);
  BOOST_TEST(proxy.clientCount() == static_cast<size_t>(N - N / 2));

  // Drain any buffered MESSAGE responses from Phase 2.
  for (int i = N / 2; i < N; ++i) {
    while (clients[i]->hasData())
      clients[i]->recvMsg();
  }

  // Remaining clients still work (GET_INFO served from cache).
  for (int i = N / 2; i < N; ++i) {
    clients[i]->sendGetInfo(0xFACE);
  }
  waitForProxy(
    [&]() {
      for (int i = N / 2; i < N; ++i)
        if (!clients[i]->hasData())
          return false;
      return true;
    },
    10);
  for (int i = N / 2; i < N; ++i) {
    auto reply = clients[i]->recvMsg();
    BOOST_TEST(reply[0] == minx::MINX_INFO);
  }

  for (int i = N / 2; i < N; ++i)
    clients[i]->close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Stress many clients complete ---");
}

// -----------------------------------------------------------------------
// Stress: rapid connect/disconnect cycles, proxy stays healthy.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyStressRapidConnectDisconnect) {
  BOOST_TEST_MESSAGE("--- Proxy: Stress rapid connect/disconnect ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 100;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  auto proxyPort = proxy.port();

  // 30 cycles of connect, send GET_INFO, get response, disconnect.
  constexpr int CYCLES = 30;
  for (int i = 0; i < CYCLES; ++i) {
    ProxyTestClient client(proxyIO);
    client.connect(proxyPort);
    pollAllWithProxy(3);

    client.sendGetInfo(static_cast<uint64_t>(0x2000 + i));
    waitForProxy([&]() { return client.hasData(); }, 10);

    auto reply = client.recvMsg();
    BOOST_TEST(reply[0] == minx::MINX_INFO);

    client.close();
    pollAllWithProxy(3);
  }

  // Proxy should be clean — 0 clients remaining.
  waitForProxy([&]() { return proxy.clientCount() == 0; }, 10);
  BOOST_TEST(proxy.clientCount() == 0);

  // One more client should work fine after the stress.
  ProxyTestClient finalClient(proxyIO);
  finalClient.connect(proxyPort);
  pollAllWithProxy(5);
  finalClient.sendGetInfo(0xF1A1);
  waitForProxy([&]() { return finalClient.hasData(); }, 10);
  auto reply = finalClient.recvMsg();
  BOOST_TEST(reply[0] == minx::MINX_INFO);

  finalClient.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Stress rapid connect/disconnect complete ---");
}

// -----------------------------------------------------------------------
// Max clients: slot frees up after disconnect, new client can connect.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyMaxClientsReconnectAfterSlotFrees) {
  BOOST_TEST_MESSAGE("--- Proxy: Max clients reconnect after slot frees ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 2;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  auto proxyPort = proxy.port();

  // Fill both slots.
  ProxyTestClient c1(proxyIO), c2(proxyIO);
  c1.connect(proxyPort);
  c2.connect(proxyPort);
  pollAllWithProxy(5);
  BOOST_TEST(proxy.clientCount() == 2);

  // Third client should be rejected.
  ProxyTestClient c3(proxyIO);
  c3.connect(proxyPort);
  pollAllWithProxy(10);
  BOOST_TEST(proxy.clientCount() == 2);
  c3.close();

  // Free one slot.
  c1.close();
  waitForProxy([&]() { return proxy.clientCount() == 1; }, 10);

  // New client should now be accepted.
  ProxyTestClient c4(proxyIO);
  c4.connect(proxyPort);
  pollAllWithProxy(5);
  BOOST_TEST(proxy.clientCount() == 2);

  // New client can get data.
  c4.sendGetInfo(0x4444);
  waitForProxy([&]() { return c4.hasData(); }, 10);
  auto reply = c4.recvMsg();
  BOOST_TEST(reply[0] == minx::MINX_INFO);

  c2.close();
  c4.close();
  proxy.stop();
  BOOST_TEST_MESSAGE(
    "--- Proxy: Max clients reconnect after slot frees complete ---");
}

// -----------------------------------------------------------------------
// Malformed message: proxy doesn't crash, other clients still work.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyMalformedMessage) {
  BOOST_TEST_MESSAGE("--- Proxy: Malformed message ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  auto proxyCfg = testProxyConfig();
  proxyCfg.maxClients = 10;
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  auto proxyPort = proxy.port();

  // Bad client sends various malformed messages.
  ProxyTestClient badClient(proxyIO);
  badClient.connect(proxyPort);
  pollAllWithProxy(5);

  // 1-byte message (too short for any valid MINX message).
  uint8_t tiny[] = {0xFF};
  badClient.sendRaw(tiny, 1);
  pollAllWithProxy(10);

  // Unknown message type with valid length.
  uint8_t unknown[] = {0x42, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00};
  badClient.sendRaw(unknown, sizeof(unknown));
  pollAllWithProxy(10);

  // Good client should still work fine.
  ProxyTestClient goodClient(proxyIO);
  goodClient.connect(proxyPort);
  pollAllWithProxy(5);

  goodClient.sendGetInfo(0x600D);
  waitForProxy([&]() { return goodClient.hasData(); }, 10);
  auto reply = goodClient.recvMsg();
  BOOST_TEST(reply[0] == minx::MINX_INFO);

  badClient.close();
  goodClient.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Malformed message complete ---");
}

// -----------------------------------------------------------------------
// Burst messages from single client: rapid-fire many messages.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyBurstMessagesFromSingleClient) {
  BOOST_TEST_MESSAGE("--- Proxy: Burst messages from single client ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  std::atomic<int> messageCount{0};
  serverNode.listener.onMessage = [&](const minx::SockAddr& addr,
                                      const minx::MinxMessage& msg) {
    ++messageCount;
    // Respond to keep proxy channels flowing.
    serverNode.minx->sendMessage(
      addr, {0, serverNode.minx->generatePassword(), msg.gpassword, {}});
  };

  auto proxyCfg = testProxyConfig();
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  ProxyTestClient client(proxyIO);
  client.connect(proxy.port());
  pollAllWithProxy(5);

  // Burst 100 messages.
  constexpr int N = 100;
  std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
  for (int i = 0; i < N; ++i) {
    client.sendMessage(static_cast<uint64_t>(0x3000 + i), 0, payload);
  }

  // Forward-path loss: server receives expectedDeliveries(N) messages.
  int expectedAtServer =
    static_cast<int>(minx::expectedDeliveries(N, PROXY_TEST_PACKET_LOSS_BPS));
  waitForProxy([&]() { return messageCount.load() >= expectedAtServer; }, 10);
  BOOST_TEST(messageCount.load() == expectedAtServer);

  // Return-path loss: client receives expectedDeliveries of what the server
  // got.
  int expected = static_cast<int>(
    minx::expectedDeliveries(expectedAtServer, PROXY_TEST_PACKET_LOSS_BPS));
  int responsesRead = 0;
  {
    auto start = std::chrono::steady_clock::now();
    while (true) {
      pollAllWithProxy();
      while (client.hasData()) {
        auto reply = client.recvMsg();
        BOOST_REQUIRE(reply.size() >= 18);
        BOOST_TEST(reply[0] == minx::MINX_MESSAGE);
        uint64_t spw;
        std::memcpy(&spw, &reply[10], 8);
        spw = boost::endian::big_to_native(spw);
        BOOST_TEST((spw >= 0x3000u && spw < static_cast<uint64_t>(0x3000 + N)));
        ++responsesRead;
        start = std::chrono::steady_clock::now();
      }
      if (std::chrono::steady_clock::now() - start > std::chrono::seconds(5))
        break;
    }
  }
  BOOST_TEST_MESSAGE("Burst: " << responsesRead << " of " << N
                               << " responses (expected " << expected << ")");
  BOOST_TEST(responsesRead == expected);

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE(
    "--- Proxy: Burst messages from single client complete ---");
}

// -----------------------------------------------------------------------
// Interleaved message types: mix GET_INFO, INIT, MESSAGE from same client.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyInterleavedMessageTypes) {
  BOOST_TEST_MESSAGE("--- Proxy: Interleaved message types ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };

  std::atomic<int> messageCount{0};
  serverNode.listener.onMessage = [&](const minx::SockAddr& addr,
                                      const minx::MinxMessage& msg) {
    ++messageCount;
    // Respond to keep proxy channels flowing.
    serverNode.minx->sendMessage(
      addr, {0, serverNode.minx->generatePassword(), msg.gpassword, {}});
  };

  auto proxyCfg = testProxyConfig();
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);

  ProxyTestClient client(proxyIO);
  client.connect(proxy.port());
  pollAllWithProxy(5);

  std::vector<uint8_t> payload = {0xAA, 0xBB};

  // Rapid interleaved: GET_INFO, INIT, MESSAGE, GET_INFO, MESSAGE, INIT
  client.sendGetInfo(0x5001);
  client.sendInit(0x5002);
  client.sendMessage(0x5003, 0, payload);
  client.sendGetInfo(0x5004);
  client.sendMessage(0x5005, 0, payload);
  client.sendInit(0x5006);

  // Wait for both GET_INFO responses (and drain any MESSAGE responses).
  int infoCount = 0;
  int msgResponseCount = 0;
  auto start = std::chrono::steady_clock::now();
  while (infoCount < 2 || msgResponseCount < 2) {
    pollAllWithProxy();
    if (client.hasData()) {
      auto reply = client.recvMsg();
      if (!reply.empty()) {
        if (reply[0] == minx::MINX_INFO)
          ++infoCount;
        else if (reply[0] == minx::MINX_MESSAGE)
          ++msgResponseCount;
      }
    }
    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(30))
      BOOST_FAIL("Timeout waiting for interleaved responses");
  }
  BOOST_TEST(infoCount == 2);

  // Wait for both MESSSAGEs to arrive at server.
  waitForProxy([&]() { return messageCount >= 2; }, 10);
  BOOST_TEST(messageCount >= 2);

  // INITs should not have been forwarded.
  BOOST_TEST(serverNode.listener.stats.init == 0);

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Interleaved message types complete ---");
}

// -----------------------------------------------------------------------
// Pending sweep: stale pending requests get cleaned up by the timer.
// -----------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(TestProxyChannelRecoveryAfterTimeout) {
  BOOST_TEST_MESSAGE("--- Proxy: Channel recovery after timeout ---");

  TestNode serverNode("Server", "127.0.0.1", 0, testServerConfig());
  registerNode(serverNode);
  serverNode.startNetwork(1);

  // Server responds to GET_INFO but does NOT respond to MESSAGE.
  // This means channels that forward messages will never get new tickets
  // and must timeout + re-handshake.
  serverNode.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                      const minx::MinxGetInfo& msg) {
    serverNode.minx->sendInfo(addr, {0,
                                     serverNode.minx->generatePassword(),
                                     msg.gpassword,
                                     1,
                                     serverNode.key,
                                     {}});
  };
  // Deliberately no onMessage handler — server silently drops messages.

  auto proxyCfg = testProxyConfig();
  proxyCfg.numChannels = 4;
  proxyCfg.channelTimeout = std::chrono::seconds(1);
  proxyCfg.sweepInterval = std::chrono::seconds(1);
  auto proxyListenEp =
    tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
  auto proxyUpstreamEp = boost::asio::ip::udp::endpoint(
    asio::ip::address::from_string("127.0.0.1"), serverNode.boundPort());
  minx::MinxProxy proxy(proxyIO, proxyListenEp, proxyUpstreamEp, proxyCfg);

  waitForProxy([&]() { return proxy.hasCachedInfo(); }, 10);
  waitForProxy([&]() { return proxy.readyChannelCount() == 4; }, 10);

  ProxyTestClient client(proxyIO);
  client.connect(proxy.port());
  pollAllWithProxy(5);

  // Send messages — these consume channels but get no responses.
  std::vector<uint8_t> payload = {0x01};
  for (int i = 0; i < 4; ++i) {
    client.sendMessage(static_cast<uint64_t>(0x6000 + i), 0, payload);
  }
  pollAllWithProxy(5);

  // All channels should be busy now.
  BOOST_TEST(proxy.readyChannelCount() == 0u);
  BOOST_TEST_MESSAGE(
    "Ready channels after sending: " << proxy.readyChannelCount());

  // Wait for channels to timeout and re-handshake back to READY.
  waitForProxy([&]() { return proxy.readyChannelCount() == 4; }, 15);
  BOOST_TEST(proxy.readyChannelCount() == 4u);
  BOOST_TEST_MESSAGE(
    "Ready channels after recovery: " << proxy.readyChannelCount());

  // Proxy should still be functional.
  client.sendGetInfo(0x7777);
  waitForProxy([&]() { return client.hasData(); }, 10);
  auto reply = client.recvMsg();
  BOOST_TEST(reply[0] == minx::MINX_INFO);

  client.close();
  proxy.stop();
  BOOST_TEST_MESSAGE("--- Proxy: Channel recovery after timeout complete ---");
}

BOOST_AUTO_TEST_SUITE_END()
