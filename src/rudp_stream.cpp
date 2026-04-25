#include <minx/blog.h>
LOG_MODULE_DISABLED("rudp_stream")

#include <minx/rudp/rudp_stream.h>

#include <algorithm>

namespace minx {

RudpStream::RudpStream(executor_type ex) : ex_(std::move(ex)) {
  LOGTRACE << "RudpStream";
}

RudpStream::~RudpStream() {
  LOGTRACE << "~RudpStream";
  // Best-effort: detach (NOT close — at destruction time we don't
  // want to inadvertently send an HS_CLOSE if something unexpected
  // is happening). Idempotent if already closed.
  detach();
}

// ---------------------------------------------------------------------------
// Rudp::ChannelHandler overrides
// ---------------------------------------------------------------------------

void RudpStream::onOpened() {
  // The handler is now wired into Rudp; rudp() / peer() / channelId()
  // are valid. Nothing to do at this layer; subclasses or the
  // application can override and chain if they need a "channel
  // exists" hook before ESTABLISHED.
  LOGTRACE << "onOpened" << VAR(channelId());
}

void RudpStream::onReliableMessage(const Bytes& msg) {
  if (closed_) {
    LOGTRACE << "onReliableMessage dropped: closed" << VAR(msg.size());
    return;
  }
  if (msg.empty())
    return;

  for (auto b : msg) {
    inboundBuf_.push_back(static_cast<uint8_t>(b));
  }
  LOGTRACE << "onReliableMessage appended" << VAR(msg.size())
           << VAR(inboundBuf_.size());

  if (pendingReader_) {
    auto reader = std::move(pendingReader_);
    pendingReader_ = nullptr;
    reader(boost::system::error_code{});
  }
}

void RudpStream::onUnreliableMessage(const Bytes& msg) {
  // Unreliable bytes never enter the byte stream's read path.
  // Application decides policy via the optional UnreliableSink.
  if (closed_)
    return;
  if (unreliableSink_) {
    unreliableSink_(msg);
  }
}

void RudpStream::onWritable() {
  if (closed_)
    return;
  drainPendingWrite();
}

void RudpStream::onClosed(Rudp::CloseReason reason) {
  if (closed_)
    return;
  LOGTRACE << "onClosed" << VAR(channelId()) << VAR(reason);
  closed_ = true;
  closeReason_ = reason;

  const auto ec = closeReasonToError(reason);

  if (pendingReader_) {
    auto r = std::move(pendingReader_);
    pendingReader_ = nullptr;
    r(ec);
  }

  if (pendingWriteHandler_) {
    auto h = std::move(pendingWriteHandler_);
    pendingWriteHandler_ = nullptr;
    const std::size_t pushed = pendingWriteOffset_;
    pendingWriteBuf_.clear();
    pendingWriteOffset_ = 0;
    boost::asio::post(ex_, [h = std::move(h), ec, pushed]() mutable {
      h(ec, pushed);
    });
  }
}

// ---------------------------------------------------------------------------
// Application controls
// ---------------------------------------------------------------------------

void RudpStream::setUnreliableSink(UnreliableSink sink) {
  unreliableSink_ = std::move(sink);
}

void RudpStream::close() {
  doClose(/*tearDownChannel=*/true);
}

void RudpStream::detach() {
  doClose(/*tearDownChannel=*/false);
}

void RudpStream::doClose(bool tearDownChannel) {
  if (closed_)
    return;
  closed_ = true;
  // closeReason_ stays nullopt: app-driven teardown has no "reason"
  // beyond the call itself. (Compare onClosed() which populates from
  // the channel's actual end cause.)
  LOGTRACE << "doClose" << VAR(channelId()) << VAR(tearDownChannel);

  if (pendingReader_) {
    auto reader = std::move(pendingReader_);
    pendingReader_ = nullptr;
    reader(boost::asio::error::eof);
  }

  if (pendingWriteHandler_) {
    auto h = std::move(pendingWriteHandler_);
    pendingWriteHandler_ = nullptr;
    const std::size_t pushed = pendingWriteOffset_;
    pendingWriteBuf_.clear();
    pendingWriteOffset_ = 0;
    boost::asio::post(ex_, [h = std::move(h), pushed]() mutable {
      h(boost::asio::error::eof, pushed);
    });
  }

  if (tearDownChannel && rudp()) {
    rudp()->closeChannel(peer(), channelId(), Rudp::CloseReason::APPLICATION);
  }
}

// ---------------------------------------------------------------------------
// Byte-pump helpers
// ---------------------------------------------------------------------------

std::size_t RudpStream::drainBytes(uint8_t* dst, std::size_t maxBytes) {
  const std::size_t take =
    std::min(maxBytes, static_cast<std::size_t>(inboundBuf_.size()));
  for (std::size_t i = 0; i < take; ++i) {
    dst[i] = inboundBuf_.front();
    inboundBuf_.pop_front();
  }
  return take;
}

void RudpStream::drainPendingWrite() {
  if (!pendingWriteHandler_)
    return;

  const std::size_t total = pendingWriteBuf_.size();
  const uint8_t* src = pendingWriteBuf_.data();

  while (pendingWriteOffset_ < total) {
    const std::size_t remaining = total - pendingWriteOffset_;
    const std::size_t take =
      std::min(static_cast<std::size_t>(Rudp::MAX_MESSAGE_SIZE), remaining);

    Bytes chunk;
    chunk.resize(take);
    std::memcpy(chunk.data(), src + pendingWriteOffset_, take);

    if (!rudp() ||
        !rudp()->push(peer(), channelId(), chunk, /*reliable=*/true)) {
      LOGTRACE << "write deferred" << VAR(pendingWriteOffset_) << VAR(total);
      return;
    }
    pendingWriteOffset_ += take;
  }

  const std::size_t bytesWritten = total;
  auto h = std::move(pendingWriteHandler_);
  pendingWriteHandler_ = nullptr;
  pendingWriteBuf_.clear();
  pendingWriteOffset_ = 0;
  boost::asio::post(ex_, [h = std::move(h), bytesWritten]() mutable {
    h(boost::system::error_code{}, bytesWritten);
  });
}

// ---------------------------------------------------------------------------
// CloseReason → error_code mapping
// ---------------------------------------------------------------------------

boost::system::error_code
RudpStream::closeReasonToError(Rudp::CloseReason reason) {
  switch (reason) {
  case Rudp::CloseReason::PEER_CLOSED:
    // Clean remote disconnect; classic eof for the Beast/Asio user.
    return boost::asio::error::eof;
  case Rudp::CloseReason::APPLICATION:
  case Rudp::CloseReason::IDLE:
  case Rudp::CloseReason::HANDSHAKE_FAILED:
  case Rudp::CloseReason::REORDER_BREACH:
  case Rudp::CloseReason::PEER_RESTART:
    // Transport pulled out from under the stream. operation_aborted
    // matches Asio's "the operation was cancelled out from under
    // you." Application can call getCloseReason() for the cause.
    return boost::asio::error::operation_aborted;
  }
  return boost::asio::error::operation_aborted;
}

// ---------------------------------------------------------------------------
// Completion-posting helpers
// ---------------------------------------------------------------------------

void RudpStream::postError(ErasedHandler h, boost::system::error_code ec) {
  boost::asio::post(ex_, [h = std::move(h), ec]() mutable { h(ec, 0); });
}

void RudpStream::postRead(ErasedHandler h, std::size_t copied) {
  boost::asio::post(ex_, [h = std::move(h), copied]() mutable {
    h(boost::system::error_code{}, copied);
  });
}

} // namespace minx
