#include <minx/proxy/tcp_server.h>

LOG_MODULE_DISABLED("tcp_server")

namespace minx {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// =====================================================================
// TcpSession
// =====================================================================

TcpSession::TcpSession(tcp::socket sock, TcpServer& server, size_t maxMsgSize)
    : sock_(std::move(sock)), server_(server), maxMsgSize_(maxMsgSize),
      bodyBuf_(maxMsgSize) {
  boost::system::error_code ec;
  auto ep = sock_.remote_endpoint(ec);
  if (!ec) {
    label_ = ep.address().to_string() + ":" + std::to_string(ep.port());
  }
}

void TcpSession::start() {
  LOGDEBUG << "session start" << VAR(label_);
  readHeader();
}

void TcpSession::close() {
  if (closed_)
    return;
  closed_ = true;
  boost::system::error_code ec;
  sock_.shutdown(tcp::socket::shutdown_both, ec);
  sock_.close(ec);
  LOGDEBUG << "session closed" << VAR(label_);
}

TcpSession::FrameBuf TcpSession::acquireFrame(size_t len) {
  size_t totalLen = TCP_FRAME_HEADER_SIZE + len;
  if (!framePool_.empty()) {
    auto buf = std::move(framePool_.back());
    framePool_.pop_back();
    buf->resize(totalLen);
    return buf;
  }
  return std::make_shared<std::vector<uint8_t>>(totalLen);
}

void TcpSession::releaseFrame(FrameBuf buf) {
  if (framePool_.size() < FRAME_POOL_MAX_SIZE) {
    framePool_.push_back(std::move(buf));
  }
}

void TcpSession::send(const uint8_t* data, size_t len) {
  LOGTRACE << "send" << VAR(len) << VAR(closed_) << VAR(label_);
  if (closed_ || len == 0 || len > maxMsgSize_)
    return;

  auto frame = acquireFrame(len);
  (*frame)[0] = static_cast<uint8_t>((len >> 8) & 0xFF);
  (*frame)[1] = static_cast<uint8_t>(len & 0xFF);
  std::memcpy(frame->data() + TCP_FRAME_HEADER_SIZE, data, len);

  writeQueue_.push_back(std::move(frame));
  if (!writing_) {
    doWrite();
  }
}

void TcpSession::doWrite() {
  if (closed_ || writeQueue_.empty()) {
    writing_ = false;
    return;
  }
  writing_ = true;
  auto frame = writeQueue_.front();
  writeQueue_.pop_front();

  auto self = shared_from_this();
  asio::async_write(
    sock_, asio::buffer(*frame),
    [this, self, frame](boost::system::error_code ec, size_t n) mutable {
      LOGTRACE << "doWrite cb" << SVAR(ec) << VAR(n) << VAR(label_);
      releaseFrame(std::move(frame));
      if (ec) {
        if (!closed_) {
          close();
          server_.removeSession(self);
        }
        return;
      }
      doWrite();
    });
}

void TcpSession::send(const std::vector<uint8_t>& data) {
  send(data.data(), data.size());
}

void TcpSession::readHeader() {
  if (closed_) {
    LOGTRACE << "readHeader skip (closed)" << VAR(label_);
    return;
  }
  LOGTRACE << "readHeader begin" << VAR(label_);
  auto self = shared_from_this();
  asio::async_read(
    sock_, asio::buffer(headerBuf_, TCP_FRAME_HEADER_SIZE),
    [this, self](boost::system::error_code ec, size_t n) {
      LOGTRACE << "readHeader cb" << SVAR(ec) << VAR(n) << VAR(label_);
      if (ec) {
        close();
        server_.removeSession(self);
        return;
      }
      uint16_t len = (static_cast<uint16_t>(headerBuf_[0]) << 8) |
                     static_cast<uint16_t>(headerBuf_[1]);
      if (len == 0 || len > maxMsgSize_) {
        LOGDEBUG << "bad frame length" << VAR(len) << VAR(label_);
        close();
        server_.removeSession(self);
        return;
      }
      readBody(len);
    });
}

void TcpSession::readBody(uint16_t len) {
  LOGTRACE << "readBody begin" << VAR(len) << VAR(label_);
  auto self = shared_from_this();
  asio::async_read(sock_, asio::buffer(bodyBuf_, len),
                   [this, self, len](boost::system::error_code ec, size_t n) {
                     LOGTRACE << "readBody cb" << SVAR(ec) << VAR(n)
                              << VAR(label_);
                     if (ec) {
                       close();
                       server_.removeSession(self);
                       return;
                     }
                     server_.handler_.onMessage(self, bodyBuf_.data(), len);
                     readHeader();
                   });
}

// =====================================================================
// TcpServer
// =====================================================================

TcpServer::TcpServer(asio::io_context& io, const tcp::endpoint& listenEp,
                     TcpServerHandler& handler, size_t maxMsgSize,
                     size_t maxClients)
    : io_(io), acceptor_(io, listenEp), handler_(handler),
      maxClients_(maxClients), maxMsgSize_(maxMsgSize) {
  LOGINFO << "listening on " << listenEp;
  accept();
}

void TcpServer::stop() {
  boost::system::error_code ec;
  acceptor_.close(ec);
  for (auto& s : sessions_) {
    s->close();
  }
  sessions_.clear();
}

void TcpServer::accept() {
  acceptor_.async_accept(
    [this](boost::system::error_code ec, tcp::socket sock) {
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERROR << "accept error" << SVAR(ec);
        }
        return;
      }

      if (sessions_.size() >= maxClients_) {
        LOGWARNING << "connection limit reached (" << maxClients_
                   << "), rejecting";
        sock.close();
      } else {
        auto session =
          std::make_shared<TcpSession>(std::move(sock), *this, maxMsgSize_);
        sessions_.insert(session);
        handler_.onConnect(session);
        session->start();
      }

      accept();
    });
}

void TcpServer::removeSession(const TcpSessionPtr& session) {
  if (sessions_.erase(session) > 0) {
    handler_.onDisconnect(session);
  }
}

} // namespace minx
