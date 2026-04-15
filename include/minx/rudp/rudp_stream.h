#ifndef _MINX_RUDP_STREAM_H_
#define _MINX_RUDP_STREAM_H_

/**
 * ==========================================================================
 * NOTE: RUDP is an experimental protocol.
 *       Both the code and the docs are mostly machine-generated.
 * ==========================================================================
 *
 * RudpStream — Asio AsyncStream adapter for a single RUDP channel.
 *
 * Bolts a Rudp-managed channel onto the Asio AsyncStream concept so that
 * any byte-stream library that operates over Asio (Boost.Beast HTTP and
 * WebSocket, in-memory pipes, custom serializers) can read and write
 * through RUDP without knowing anything about RUDP's wire format.
 *
 * Layering picture:
 *
 *   Application (e.g. Beast HTTP)
 *       |  async_read_some / async_write_some
 *       v
 *   RudpStream                <-- you are here
 *       |  push() / receive callback
 *       v
 *   Rudp (handshake, ack, retransmit, in-order delivery)
 *       |  setSendCallback / onPacket
 *       v
 *   MinxStdExtensions
 *       |  registerExtension / extension handler
 *       v
 *   Minx EXTENSION (0xFF) lane
 *       |  raw UDP datagrams
 *       v
 *   The wire
 *
 * Threading: NOT thread-safe. RudpStream and the Rudp it wraps must all
 * be touched from the same thread. The recommended pattern is to drive
 * everything from a single boost::asio::io_context's thread.
 *
 * Inbound flow:
 *   1. The application installs Rudp's setReceiveCallback so that
 *      whenever a CHANNEL message for this stream's (peer, channel_id)
 *      arrives, it forwards the bytes to RudpStream::feed().
 *   2. feed() appends the bytes to an internal buffer. If a pending
 *      async_read_some call is waiting, it completes with the
 *      now-available bytes.
 *   3. async_read_some called when the buffer has bytes drains them
 *      synchronously and posts the completion handler on the executor.
 *
 * Outbound flow:
 *   1. async_write_some is called with one or more buffers.
 *   2. RudpStream chunks the input into ≤ Rudp::MAX_MESSAGE_SIZE pieces
 *      and calls Rudp::push(reliable=true) for each.
 *   3. The completion handler fires once all chunks are queued (the
 *      actual wire emission happens later, when Rudp::flush()/tick()
 *      is invoked by the application's loop).
 *
 * Lifecycle:
 *   close() marks the stream closed and completes any pending reader
 *   with boost::asio::error::eof. Subsequent async operations also
 *   complete immediately with eof. The RUDP channel itself is NOT
 *   torn down by close() — it will be GC'd by Rudp's idle timer when
 *   no traffic flows for the configured inactivity window.
 */

#include <minx/rudp/rudp.h>
#include <minx/types.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <utility>
#include <vector>

namespace minx {

class RudpStream {
public:
  using executor_type = boost::asio::any_io_executor;

  RudpStream(Rudp& rudp, SockAddr peer, uint32_t channel_id, executor_type ex);

  ~RudpStream();

  RudpStream(const RudpStream&) = delete;
  RudpStream& operator=(const RudpStream&) = delete;
  RudpStream(RudpStream&&) = delete;
  RudpStream& operator=(RudpStream&&) = delete;

  // -----------------------------------------------------------------------
  // Application integration
  // -----------------------------------------------------------------------

  /// Called by the application's Rudp receive callback (or by a routing
  /// dispatcher) when a CHANNEL message for this stream's (peer, channel)
  /// pair arrives. Appends the bytes to the inbound buffer and, if a
  /// pending reader is waiting, completes it.
  void feed(const Bytes& bytes);

  /// Closes the stream. Any pending reader completes with
  /// boost::asio::error::eof. Subsequent reads and writes complete
  /// immediately with eof. Idempotent.
  void close();

  /// True until close() is called.
  bool is_open() const noexcept { return !closed_; }

  /// Number of bytes currently sitting in the inbound buffer waiting
  /// to be drained by a future async_read_some. Mostly for tests.
  std::size_t available() const noexcept { return inboundBuf_.size(); }

  // -----------------------------------------------------------------------
  // Asio AsyncStream concept
  // -----------------------------------------------------------------------

  executor_type get_executor() const noexcept { return ex_; }

  template <typename MutableBufferSequence, typename ReadHandler>
  auto async_read_some(const MutableBufferSequence& buffers,
                       ReadHandler&& handler) {
    return boost::asio::async_initiate<
      ReadHandler, void(boost::system::error_code, std::size_t)>(
      [this, &buffers](auto&& h) {
        startRead(buffers, std::forward<decltype(h)>(h));
      },
      handler);
  }

  template <typename ConstBufferSequence, typename WriteHandler>
  auto async_write_some(const ConstBufferSequence& buffers,
                        WriteHandler&& handler) {
    return boost::asio::async_initiate<
      WriteHandler, void(boost::system::error_code, std::size_t)>(
      [this, &buffers](auto&& h) {
        startWrite(buffers, std::forward<decltype(h)>(h));
      },
      handler);
  }

private:
  // ---- Non-template helpers implemented in rudp_stream.cpp ----

  /// Drain up to `maxBytes` from inboundBuf_ into `dst`. Returns the
  /// number of bytes actually copied.
  std::size_t drainBytes(uint8_t* dst, std::size_t maxBytes);

  /// Try to push as many bytes as possible from the currently-pending
  /// write buffer (pendingWriteBuf_) into RUDP, starting at
  /// pendingWriteOffset_. If the full buffer drains, posts the
  /// completion handler with (success, bytes_written) and clears the
  /// pending state. If push() fails partway, updates the offset and
  /// returns without calling the handler — the handler is deferred
  /// until the next onChannelDrained() notification from Rudp.
  void drainPendingWrite();

  /// Rudp → RudpStream callback: sendBuf shrank (ack) or
  /// preEstablishedQueue drained (handshake completed). Resume the
  /// deferred write, if any.
  void onChannelDrained();

  /// Rudp → RudpStream callback: the underlying channel is about to
  /// be erased by some destruction path (close, gc, idle sweep,
  /// reorder-cap breach, peer restart). Mark the stream closed and
  /// complete any pending reader / writer with operation_aborted.
  void onChannelDestroyed();

  /// Post an "no data, error" completion to `ex_`.
  void postError(std::function<void(boost::system::error_code, std::size_t)> h,
                 boost::system::error_code ec);

  /// Post a "n bytes copied, no error" completion to `ex_`.
  void postRead(std::function<void(boost::system::error_code, std::size_t)> h,
                std::size_t copied);

  // ---- Templated entry points (read/write start) ----

  template <typename MutableBufferSequence, typename Handler>
  void startRead(const MutableBufferSequence& buffers, Handler&& handler) {
    // Compute the destination capacity from the Asio buffer sequence.
    const std::size_t capacity = boost::asio::buffer_size(buffers);

    // Erase the handler to a std::function so we can stash it if needed.
    // Boost.Beast's internal handler ops are MOVE-ONLY, and std::function
    // requires its target to be copy-constructible. To bridge, wrap the
    // handler in a shared_ptr and capture the shared_ptr in a copyable
    // lambda — classic shared-ptr-holder trick.
    auto handlerHolder =
      std::make_shared<std::decay_t<Handler>>(std::forward<Handler>(handler));
    std::function<void(boost::system::error_code, std::size_t)> erased(
      [handlerHolder](boost::system::error_code ec, std::size_t n) mutable {
        (*handlerHolder)(ec, n);
      });

    if (closed_) {
      postError(std::move(erased), boost::asio::error::eof);
      return;
    }

    if (!inboundBuf_.empty()) {
      // Synchronous fast path: drain into a temporary contiguous buffer,
      // then scatter into the user's buffer sequence via buffer_copy.
      std::size_t take =
        std::min(capacity, static_cast<std::size_t>(inboundBuf_.size()));
      std::vector<uint8_t> tmp(take);
      std::size_t copied = drainBytes(tmp.data(), take);
      // Scatter into the caller's MutableBufferSequence.
      boost::asio::buffer_copy(buffers,
                               boost::asio::buffer(tmp.data(), copied));
      postRead(std::move(erased), copied);
      return;
    }

    // No data yet. Stash a closure that will drain and post when feed()
    // or close() drives it. The closure captures the buffer sequence by
    // copy because the caller's buffers reference may not survive.
    pendingReader_ = [this, buffers, handler = std::move(erased)](
                       boost::system::error_code ec) mutable {
      if (ec) {
        postError(std::move(handler), ec);
        return;
      }
      const std::size_t cap = boost::asio::buffer_size(buffers);
      std::size_t take =
        std::min(cap, static_cast<std::size_t>(inboundBuf_.size()));
      std::vector<uint8_t> tmp(take);
      std::size_t copied = drainBytes(tmp.data(), take);
      boost::asio::buffer_copy(buffers,
                               boost::asio::buffer(tmp.data(), copied));
      postRead(std::move(handler), copied);
    };
  }

  template <typename ConstBufferSequence, typename Handler>
  void startWrite(const ConstBufferSequence& buffers, Handler&& handler) {
    // See startRead for why the handler is wrapped in a shared_ptr
    // before erasure into std::function. Beast's internal write ops
    // are move-only.
    auto handlerHolder =
      std::make_shared<std::decay_t<Handler>>(std::forward<Handler>(handler));
    std::function<void(boost::system::error_code, std::size_t)> erased(
      [handlerHolder](boost::system::error_code ec, std::size_t n) mutable {
        (*handlerHolder)(ec, n);
      });

    if (closed_) {
      postError(std::move(erased), boost::asio::error::eof);
      return;
    }

    if (pendingWriteHandler_) {
      // Asio's AsyncWriteStream contract is one outstanding
      // async_write_some per stream. A concurrent write while a
      // previous one is still deferred means the caller violated
      // that. Fail the new call with in_progress and leave the
      // existing deferred state alone.
      postError(std::move(erased), boost::asio::error::in_progress);
      return;
    }

    // Flatten all source buffers into a single contiguous vector for
    // chunking. For typical Beast usage the buffer sequence is one or
    // two buffers, so the copy is small. A future optimization could
    // chunk per-buffer-pair without flattening.
    const std::size_t total = boost::asio::buffer_size(buffers);
    pendingWriteBuf_.assign(total, 0);
    boost::asio::buffer_copy(
      boost::asio::buffer(pendingWriteBuf_.data(), pendingWriteBuf_.size()),
      buffers);
    pendingWriteOffset_ = 0;
    pendingWriteHandler_ = std::move(erased);

    // drainPendingWrite() either completes the handler synchronously
    // (fast path, no back-pressure) or leaves it stashed for the
    // next onChannelDrained() notification.
    drainPendingWrite();
  }

  // ---- Members ----

  Rudp& rudp_;
  SockAddr peer_;
  uint32_t channel_id_;
  executor_type ex_;

  std::deque<uint8_t> inboundBuf_;
  std::function<void(boost::system::error_code)> pendingReader_;

  // Deferred-completion write state. When drainPendingWrite() can't
  // push a chunk because RUDP's sendBuf is full, it leaves these
  // populated and returns without calling the handler. The next
  // onChannelDrained() notification resumes the push from
  // pendingWriteOffset_. Only one write can be deferred at a time
  // (Asio's AsyncWriteStream contract is strictly serial).
  std::vector<uint8_t> pendingWriteBuf_;
  std::size_t pendingWriteOffset_ = 0;
  std::function<void(boost::system::error_code, std::size_t)>
    pendingWriteHandler_;

  bool closed_ = false;
};

} // namespace minx

#endif
