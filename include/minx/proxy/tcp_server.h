#ifndef _MINX_PROXY_TCP_SERVER_H_
#define _MINX_PROXY_TCP_SERVER_H_

/**
 * Async TCP server with length-prefixed (2-byte big-endian) framing.
 *
 * TcpServer accepts connections and manages TcpSession lifetimes.
 * Each TcpSession reads length-prefixed messages and delivers them
 * to a TcpServerHandler callback interface.  Sending is also
 * length-prefixed and fully async.
 *
 * The server runs entirely on a single io_context (no threads, no
 * strands needed when driven from one thread).
 */

#include <minx/blog.h>

#include <boost/asio.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace minx {

static constexpr size_t TCP_FRAME_HEADER_SIZE = 2;

class TcpSession;
class TcpServer;
using TcpSessionPtr = std::shared_ptr<TcpSession>;

// ---------------------------------------------------------------------
// TcpServerHandler — callback interface
// ---------------------------------------------------------------------
struct TcpServerHandler {
  virtual ~TcpServerHandler() = default;

  /** Called when a new client connects. */
  virtual void onConnect(const TcpSessionPtr& session) = 0;

  /** Called when a complete message is received from a client. */
  virtual void onMessage(const TcpSessionPtr& session, const uint8_t* data,
                         size_t len) = 0;

  /** Called when a client disconnects (or an error closes the session). */
  virtual void onDisconnect(const TcpSessionPtr& session) = 0;
};

// ---------------------------------------------------------------------
// TcpSession
// ---------------------------------------------------------------------
class TcpSession : public std::enable_shared_from_this<TcpSession> {
public:
  TcpSession(boost::asio::ip::tcp::socket sock, TcpServer& server,
             size_t maxMsgSize);

  void start();
  void close();
  bool isClosed() const { return closed_; }
  const std::string& label() const { return label_; }

  /** Send a length-prefixed message to this client. */
  void send(const uint8_t* data, size_t len);
  void send(const std::vector<uint8_t>& data);
  boost::asio::ip::tcp::socket& socket() { return sock_; }

private:
  void readHeader();
  void readBody(uint16_t len);

  void doWrite();

  boost::asio::ip::tcp::socket sock_;
  TcpServer& server_;
  size_t maxMsgSize_;
  std::string label_;
  bool closed_ = false;
  bool writing_ = false;

  using FrameBuf = std::shared_ptr<std::vector<uint8_t>>;
  FrameBuf acquireFrame(size_t len);
  void releaseFrame(FrameBuf buf);

  uint8_t headerBuf_[TCP_FRAME_HEADER_SIZE]{};
  std::vector<uint8_t> bodyBuf_;
  std::deque<FrameBuf> writeQueue_;
  std::vector<FrameBuf> framePool_;
  static constexpr size_t FRAME_POOL_MAX_SIZE = 1024;
};

// ---------------------------------------------------------------------
// TcpServer
// ---------------------------------------------------------------------
class TcpServer {
public:
  TcpServer(boost::asio::io_context& io,
            const boost::asio::ip::tcp::endpoint& listenEp,
            TcpServerHandler& handler, size_t maxMsgSize,
            size_t maxClients = 1000);

  void stop();
  size_t clientCount() const { return sessions_.size(); }
  boost::asio::io_context& io() { return io_; }
  uint16_t port() const { return acceptor_.local_endpoint().port(); }

private:
  friend class TcpSession;
  void accept();
  void removeSession(const TcpSessionPtr& session);

  boost::asio::io_context& io_;
  boost::asio::ip::tcp::acceptor acceptor_;
  TcpServerHandler& handler_;
  size_t maxClients_;
  size_t maxMsgSize_;
  std::unordered_set<TcpSessionPtr> sessions_;
};

} // namespace minx

#endif
