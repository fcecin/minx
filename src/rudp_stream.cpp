#include <minx/blog.h>
LOG_MODULE_DISABLED("rudp_stream")

#include <minx/rudp/rudp_stream.h>

#include <algorithm>

namespace minx {

RudpStream::RudpStream(Rudp& rudp, SockAddr peer, uint32_t channel_id,
                       executor_type ex)
    : rudp_(rudp), peer_(std::move(peer)), channel_id_(channel_id),
      ex_(std::move(ex)) {
  LOGTRACE << "RudpStream" << VAR(channel_id_);

  // Register the write-path back-pressure callbacks on the underlying
  // Rudp channel. Capturing `this` is safe as long as the destructor
  // unregisters before the stream's lifetime ends, which close()
  // (called unconditionally from ~RudpStream) handles.
  rudp_.setSendBufDrainedCallback(peer_, channel_id_,
                                  [this]() { onChannelDrained(); });
  rudp_.setChannelDestroyedCallback(peer_, channel_id_,
                                    [this]() { onChannelDestroyed(); });
}

RudpStream::~RudpStream() {
  LOGTRACE << "~RudpStream" << VAR(channel_id_);
  // Best-effort cleanup: complete any pending reader with eof so its
  // captured handler isn't leaked. close() is idempotent so this is
  // safe even after explicit close().
  close();
}

// ---------------------------------------------------------------------------
// Application integration
// ---------------------------------------------------------------------------

void RudpStream::feed(const Bytes& bytes) {
  if (closed_) {
    LOGTRACE << "feed dropped: closed" << VAR(bytes.size());
    return;
  }
  if (bytes.empty())
    return;

  // Append to the inbound byte buffer. Bytes is a static_vector<char,...>;
  // we treat them as uint8_t for the deque<uint8_t> destination.
  for (auto b : bytes) {
    inboundBuf_.push_back(static_cast<uint8_t>(b));
  }
  LOGTRACE << "feed appended" << VAR(bytes.size()) << VAR(inboundBuf_.size());

  // If a reader was waiting on bytes, fire it now.
  if (pendingReader_) {
    auto reader = std::move(pendingReader_);
    pendingReader_ = nullptr;
    reader(boost::system::error_code{});
  }
}

void RudpStream::close() {
  if (closed_)
    return;
  closed_ = true;
  LOGTRACE << "close" << VAR(channel_id_);

  // Complete any pending reader with eof (explicit user close).
  if (pendingReader_) {
    auto reader = std::move(pendingReader_);
    pendingReader_ = nullptr;
    reader(boost::asio::error::eof);
  }

  // Complete any pending deferred-write handler with eof, returning
  // however many bytes already made it into RUDP's sendBuf before
  // the stream was closed. From Beast's perspective this is the
  // standard "stream went away mid-write" completion.
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

  // Unregister our callbacks from the Rudp channel so that any later
  // drain or destroy event can't fire into a dead stream. Clearing
  // on a non-existent channel is a no-op inside Rudp.
  rudp_.setSendBufDrainedCallback(peer_, channel_id_, nullptr);
  rudp_.setChannelDestroyedCallback(peer_, channel_id_, nullptr);
}

// ---------------------------------------------------------------------------
// Byte-pump helpers used by the templated startRead / startWrite paths
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
    return; // nothing deferred

  const std::size_t total = pendingWriteBuf_.size();
  const uint8_t* src = pendingWriteBuf_.data();

  while (pendingWriteOffset_ < total) {
    const std::size_t remaining = total - pendingWriteOffset_;
    const std::size_t take =
      std::min(static_cast<std::size_t>(Rudp::MAX_MESSAGE_SIZE), remaining);

    // Build a Bytes for this chunk. Bytes is a static_vector<char,...>
    // so we copy through the (signed) char interface.
    Bytes chunk;
    chunk.resize(take);
    std::memcpy(chunk.data(), src + pendingWriteOffset_, take);

    if (!rudp_.push(peer_, channel_id_, chunk, /*reliable=*/true)) {
      // RUDP is back-pressured (sendBuf cap or preEstablishedQueue
      // cap). Leave the pending state in place; onChannelDrained()
      // will resume this loop when an ack shrinks sendBuf or a
      // handshake completes.
      LOGTRACE << "write deferred" << VAR(pendingWriteOffset_) << VAR(total);
      return;
    }
    pendingWriteOffset_ += take;
  }

  // All bytes pushed. Snapshot, clear state, post completion so
  // Beast's write_some loop can re-enter with the next chunk (or
  // fire its outer completion).
  const std::size_t bytesWritten = total;
  auto h = std::move(pendingWriteHandler_);
  pendingWriteHandler_ = nullptr;
  pendingWriteBuf_.clear();
  pendingWriteOffset_ = 0;
  boost::asio::post(ex_, [h = std::move(h), bytesWritten]() mutable {
    h(boost::system::error_code{}, bytesWritten);
  });
}

void RudpStream::onChannelDrained() {
  // Called synchronously from Rudp::handleChannelPacket (or
  // promoteToEstablished) when sendBuf has room again. Try to push
  // whatever is still pending. Cheap no-op if nothing is deferred.
  drainPendingWrite();
}

void RudpStream::onChannelDestroyed() {
  // The underlying channel is about to be erased from Rudp's maps.
  // Mark ourselves closed and abort any pending handlers with
  // operation_aborted (as opposed to eof, which is the user-close
  // semantic). After this point the stream is permanently dead;
  // the application should construct a fresh RudpStream if it
  // wants to continue on the same (peer, channel_id) tuple.
  LOGTRACE << "onChannelDestroyed" << VAR(channel_id_);
  closed_ = true;

  if (pendingReader_) {
    auto r = std::move(pendingReader_);
    pendingReader_ = nullptr;
    r(boost::asio::error::operation_aborted);
  }

  if (pendingWriteHandler_) {
    auto h = std::move(pendingWriteHandler_);
    pendingWriteHandler_ = nullptr;
    const std::size_t pushed = pendingWriteOffset_;
    pendingWriteBuf_.clear();
    pendingWriteOffset_ = 0;
    boost::asio::post(ex_, [h = std::move(h), pushed]() mutable {
      h(boost::asio::error::operation_aborted, pushed);
    });
  }

  // Do NOT call setXxxCallback(nullptr) here — Rudp has already
  // moved-out our callback by the time fireChannelDestroyed invoked
  // us, and is about to erase the ChannelState entirely.
}

void RudpStream::postError(
  std::function<void(boost::system::error_code, std::size_t)> h,
  boost::system::error_code ec) {
  boost::asio::post(ex_, [h = std::move(h), ec]() mutable { h(ec, 0); });
}

void RudpStream::postRead(
  std::function<void(boost::system::error_code, std::size_t)> h,
  std::size_t copied) {
  boost::asio::post(ex_, [h = std::move(h), copied]() mutable {
    h(boost::system::error_code{}, copied);
  });
}

} // namespace minx
