#include <boost/test/unit_test.hpp>

#include <minx/blog.h>
#include <minx/proxy/tcp_server.h>

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

static constexpr size_t TEST_MAX_MSG_SIZE = 2048;

// Helper: connect a raw TCP client, send a length-prefixed message.
class TestTcpClient {
public:
  TestTcpClient(asio::io_context& io) : sock_(io) {}

  void connect(uint16_t port) {
    sock_.connect(
      tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), port));
  }

  void sendMsg(const uint8_t* data, size_t len) {
    uint8_t header[2];
    header[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
    header[1] = static_cast<uint8_t>(len & 0xFF);
    asio::write(sock_, asio::buffer(header, 2));
    asio::write(sock_, asio::buffer(data, len));
  }

  void sendMsg(const std::string& s) {
    sendMsg(reinterpret_cast<const uint8_t*>(s.data()), s.size());
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

  void close() {
    boost::system::error_code ec;
    sock_.shutdown(tcp::socket::shutdown_both, ec);
    sock_.close(ec);
  }

  tcp::socket& socket() { return sock_; }

private:
  tcp::socket sock_;
};

// Spy handler that records events.
struct SpyHandler : minx::TcpServerHandler {
  std::atomic<int> connects{0};
  std::atomic<int> disconnects{0};
  std::atomic<int> messages{0};
  std::vector<std::vector<uint8_t>> received;
  minx::TcpSessionPtr lastSession;

  bool echoMode = false;

  void onConnect(const minx::TcpSessionPtr& session) override {
    ++connects;
    lastSession = session;
  }

  void onMessage(const minx::TcpSessionPtr& session, const uint8_t* data,
                 size_t len) override {
    ++messages;
    received.emplace_back(data, data + len);
    if (echoMode) {
      session->send(data, len);
    }
  }

  void onDisconnect(const minx::TcpSessionPtr& /*session*/) override {
    ++disconnects;
  }
};

// Poll io_context until a condition is met or timeout.
static void pollUntil(asio::io_context& io, std::function<bool()> pred,
                      int timeoutMs = 5000) {
  auto start = std::chrono::steady_clock::now();
  while (!pred()) {
    io.poll_one();
    if (std::chrono::steady_clock::now() - start >
        std::chrono::milliseconds(timeoutMs)) {
      BOOST_FAIL("pollUntil timeout");
    }
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }
  // Drain remaining handlers.
  io.poll();
}

static auto anyEp() {
  return tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 0);
}

BOOST_AUTO_TEST_SUITE(TcpServerSuite)

BOOST_AUTO_TEST_CASE(TestConnectDisconnect) {
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);

  pollUntil(io, [&]() { return handler.connects >= 1; });
  BOOST_TEST(handler.connects == 1);
  BOOST_TEST(server.clientCount() == 1);

  client.close();
  pollUntil(io, [&]() { return handler.disconnects >= 1; });
  BOOST_TEST(handler.disconnects == 1);

  server.stop();
}

BOOST_AUTO_TEST_CASE(TestSendReceiveMessage) {
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 1; });

  std::string msg = "hello proxy";
  client.sendMsg(msg);

  pollUntil(io, [&]() { return handler.messages >= 1; });
  BOOST_TEST(handler.messages == 1);
  BOOST_REQUIRE(handler.received.size() == 1);

  std::string got(handler.received[0].begin(), handler.received[0].end());
  BOOST_TEST(got == "hello proxy");

  client.close();
  server.stop();
}

BOOST_AUTO_TEST_CASE(TestEchoRoundTrip) {
  asio::io_context io;
  SpyHandler handler;
  handler.echoMode = true;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 1; });

  std::string msg = "round trip";
  client.sendMsg(msg);

  pollUntil(io, [&]() { return handler.messages >= 1; });

  // Poll a bit more so the echo write completes.
  for (int i = 0; i < 50; ++i) {
    io.poll_one();
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }

  auto reply = client.recvMsg();
  std::string got(reply.begin(), reply.end());
  BOOST_TEST(got == "round trip");

  client.close();
  server.stop();
}

BOOST_AUTO_TEST_CASE(TestMultipleMessages) {
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 1; });

  for (int i = 0; i < 10; ++i) {
    std::string msg = "msg" + std::to_string(i);
    client.sendMsg(msg);
  }

  pollUntil(io, [&]() { return handler.messages >= 10; });
  BOOST_TEST(handler.messages == 10);
  BOOST_TEST(handler.received.size() == 10u);

  for (int i = 0; i < 10; ++i) {
    std::string expected = "msg" + std::to_string(i);
    std::string got(handler.received[i].begin(), handler.received[i].end());
    BOOST_TEST(got == expected);
  }

  client.close();
  server.stop();
}

BOOST_AUTO_TEST_CASE(TestMultipleClients) {
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE, 10);
  auto port = server.port();

  TestTcpClient c1(io), c2(io), c3(io);
  c1.connect(port);
  c2.connect(port);
  c3.connect(port);

  pollUntil(io, [&]() { return handler.connects >= 3; });
  BOOST_TEST(handler.connects == 3);
  BOOST_TEST(server.clientCount() == 3);

  c1.sendMsg("from1");
  c2.sendMsg("from2");
  c3.sendMsg("from3");

  pollUntil(io, [&]() { return handler.messages >= 3; });
  BOOST_TEST(handler.messages == 3);

  c1.close();
  c2.close();
  c3.close();
  pollUntil(io, [&]() { return handler.disconnects >= 3; });
  BOOST_TEST(handler.disconnects == 3);
  BOOST_TEST(server.clientCount() == 0);

  server.stop();
}

BOOST_AUTO_TEST_CASE(TestMaxClientsRejection) {
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE, 2);
  auto port = server.port();

  TestTcpClient c1(io), c2(io);
  c1.connect(port);
  c2.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 2; });
  BOOST_TEST(server.clientCount() == 2);

  // Third client should get rejected.
  TestTcpClient c3(io);
  c3.connect(port);

  for (int i = 0; i < 100; ++i) {
    io.poll_one();
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }

  BOOST_TEST(server.clientCount() == 2);
  BOOST_TEST(handler.connects == 2);

  c1.close();
  c2.close();
  c3.close();
  server.stop();
}

BOOST_AUTO_TEST_CASE(TestServerSendToClient) {
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 1; });

  std::string msg = "server push";
  handler.lastSession->send(reinterpret_cast<const uint8_t*>(msg.data()),
                            msg.size());

  for (int i = 0; i < 50; ++i) {
    io.poll_one();
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }

  auto reply = client.recvMsg();
  std::string got(reply.begin(), reply.end());
  BOOST_TEST(got == "server push");

  client.close();
  server.stop();
}

BOOST_AUTO_TEST_CASE(TestLargeMessage) {
  asio::io_context io;
  SpyHandler handler;
  handler.echoMode = true;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 1; });

  std::vector<uint8_t> big(2048);
  for (size_t i = 0; i < big.size(); ++i)
    big[i] = static_cast<uint8_t>(i & 0xFF);

  client.sendMsg(big.data(), big.size());

  pollUntil(io, [&]() { return handler.messages >= 1; });

  for (int i = 0; i < 100; ++i) {
    io.poll_one();
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }

  auto reply = client.recvMsg();
  BOOST_TEST(reply.size() == 2048u);
  BOOST_TEST(reply == big);

  client.close();
  server.stop();
}

BOOST_AUTO_TEST_CASE(TestBurstSendFromServer) {
  // Regression: calling send() multiple times before polling must not
  // overlap async_write operations.  Without a write queue the frames
  // get interleaved and the client sees corrupted framing.
  asio::io_context io;
  SpyHandler handler;
  minx::TcpServer server(io, anyEp(), handler, TEST_MAX_MSG_SIZE);
  auto port = server.port();

  TestTcpClient client(io);
  client.connect(port);
  pollUntil(io, [&]() { return handler.connects >= 1; });

  // Shrink the server-side send buffer so that large async_writes require
  // multiple async_write_some iterations, exposing interleaving bugs.
  boost::asio::socket_base::send_buffer_size opt(1024);
  handler.lastSession->socket().set_option(opt);

  // Burst 200 large messages from server to client.  Each message is
  // near-max size so that async_write has real work to do and overlapping
  // calls corrupt the byte stream.
  constexpr int N = 200;
  constexpr size_t MSG_SIZE = 2000;
  std::vector<std::vector<uint8_t>> sent(N);
  for (int i = 0; i < N; ++i) {
    sent[i].resize(MSG_SIZE);
    for (size_t j = 0; j < MSG_SIZE; ++j)
      sent[i][j] = static_cast<uint8_t>((i + j) & 0xFF);
    handler.lastSession->send(sent[i].data(), sent[i].size());
  }

  // Read each message back, polling the server between reads so the
  // write queue drains.
  for (int i = 0; i < N; ++i) {
    while (client.socket().available() < 2 + MSG_SIZE) {
      io.poll();
    }
    auto reply = client.recvMsg();
    BOOST_REQUIRE_EQUAL(reply.size(), MSG_SIZE);
    BOOST_TEST(reply == sent[i]);
  }

  client.close();
  server.stop();
}

BOOST_AUTO_TEST_SUITE_END()
