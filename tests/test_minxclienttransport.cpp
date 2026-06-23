#include <boost/test/unit_test.hpp>

#include <minx/proxy/minxclienttransport.h>

#include "minx_mock.h"

#include <atomic>

using namespace minx_test;

BOOST_FIXTURE_TEST_SUITE(MinxClientTransportSuite, MinxMockFixture)

BOOST_AUTO_TEST_CASE(TestUdpRemoteRedirect) {
  BOOST_TEST_MESSAGE("--- Starting UDP Remote Redirect Test ---");

  TestNode serverA("ServerA", "::1", 9400);
  registerNode(serverA);
  serverA.startNetwork(1);
  serverA.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                   const minx::MinxGetInfo& msg) {
    serverA.minx->sendInfo(addr, {0, serverA.minx->generatePassword(),
                                  msg.gpassword, 1, serverA.key, {}});
  };

  TestNode serverB("ServerB", "::1", 9401);
  registerNode(serverB);
  serverB.startNetwork(1);
  serverB.listener.onGetInfo = [&](const minx::SockAddr& addr,
                                   const minx::MinxGetInfo& msg) {
    serverB.minx->sendInfo(addr, {0, serverB.minx->generatePassword(),
                                  msg.gpassword, 1, serverB.key, {}});
  };

  MinxMockListener clientListener;
  std::atomic<bool> gotA{false}, gotB{false};
  clientListener.onInfo = [&](const minx::SockAddr&,
                              const minx::MinxInfo& msg) {
    if (msg.skey == serverA.key)
      gotA = true;
    else if (msg.skey == serverB.key)
      gotB = true;
  };

  minx::MinxClientTransport client(&clientListener, serverA.addr);
  client.setUseDataset(false);
  BOOST_TEST(client.start(0));

  BOOST_TEST_MESSAGE("Client: GET_INFO to ServerA");
  client.sendGetInfo({0, client.generatePassword(), {}});
  waitForCondition([&]() { return gotA.load(); }, 5);
  BOOST_TEST(gotA.load());

  BOOST_TEST_MESSAGE("Client: re-point to ServerB");
  BOOST_TEST(client.setRemoteEndpoint(serverB.addr));

  client.sendGetInfo({0, client.generatePassword(), {}});
  waitForCondition([&]() { return gotB.load(); }, 5);
  BOOST_TEST(gotB.load());

  BOOST_TEST(serverA.listener.stats.getInfo == 1);
  BOOST_TEST(serverB.listener.stats.getInfo >= 1);

  client.stop();

  BOOST_TEST_MESSAGE("--- UDP Remote Redirect Test Complete ---");
}

BOOST_AUTO_TEST_CASE(TestWrongModeReturnsFalse) {
  BOOST_TEST_MESSAGE("--- Starting Wrong Mode Test ---");

  MinxMockListener l;
  boost::asio::ip::udp::endpoint udpEp(boost::asio::ip::address_v6::loopback(),
                                       9400);
  boost::asio::ip::tcp::endpoint tcpEp(boost::asio::ip::address_v6::loopback(),
                                       9401);

  minx::MinxClientTransport udpClient(&l, udpEp);
  BOOST_TEST(udpClient.setRemoteEndpoint(udpEp));
  BOOST_TEST(!udpClient.setRemoteEndpoint(tcpEp));

  minx::MinxClientTransport tcpClient(&l, tcpEp);
  BOOST_TEST(!tcpClient.setRemoteEndpoint(udpEp));

  BOOST_TEST_MESSAGE("--- Wrong Mode Test Complete ---");
}

BOOST_AUTO_TEST_SUITE_END()
