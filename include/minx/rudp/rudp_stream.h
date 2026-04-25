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
 * Wraps one Rudp channel as a boost::asio::AsyncStream so libraries
 * that operate over Asio (Boost.Beast HTTP / WebSocket, in-memory
 * pipes, ad-hoc serializers) can read/write through RUDP without
 * knowing anything about RUDP's wire format.
 *
 * --- Shape ---
 *
 * RudpStream IS a Rudp::ChannelHandler. The application's
 * Rudp::Listener::onAccept returns a freshly-constructed
 * std::shared_ptr<RudpStream> for inbound channels; for outbound,
 * the application passes the stream to Rudp::registerChannel(p, c, ...).
 * Rudp injects rudp() / peer() / channelId() back-references and
 * dispatches per-channel events directly to the stream's overrides.
 *
 * --- Unreliable on a stream channel ---
 *
 * Unreliable RUDP messages are the optional datagram tail of CHANNEL
 * packets — out-of-band to the reliable byte sequence and with no
 * meaningful translation to a stream abstraction. RudpStream never
 * mixes unreliable bytes into the byte stream's read path. By default
 * onUnreliableMessage just drops; the application may install
 * setUnreliableSink() to receive them and decide policy (log,
 * abuse-report, force-close, ignore). Receiving unreliable on a
 * stream channel is unusual and arguably suspicious.
 *
 * --- Lifecycle ---
 *
 * close() — application-side teardown. Marks the stream closed,
 * completes pending handlers with eof, AND tears down the underlying
 * RUDP channel via rudp()->closeChannel(...). 99% default intent.
 *
 * detach() — close the stream but leave the underlying RUDP channel
 * alive. Same handler-completion semantics. Rare.
 *
 * onClosed(reason) — driven by Rudp when the channel ended on its
 * own. Pending handlers complete with operation_aborted; reason
 * stored in getCloseReason().
 *
 * --- Threading ---
 *
 * NOT thread-safe. RudpStream and its Rudp must be touched from the
 * same thread (typically a single io_context).
 */

#include <minx/rudp/rudp.h>
#include <minx/types.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace minx {

class RudpStream : public Rudp::ChannelHandler {
public:
  using executor_type = boost::asio::any_io_executor;

  /// Construct a stream. Rudp injects the back-references
  /// (rudp() / peer() / channelId()) when the stream is bound to a
  /// channel — either via Rudp::registerChannel() (outbound) or by
  /// being returned from Listener::onAccept() (inbound). Per-channel
  /// methods on this class are safe to invoke only AFTER onOpened()
  /// has fired.
  explicit RudpStream(executor_type ex);
  ~RudpStream() override;

  RudpStream(const RudpStream&) = delete;
  RudpStream& operator=(const RudpStream&) = delete;
  RudpStream(RudpStream&&) = delete;
  RudpStream& operator=(RudpStream&&) = delete;

  // -----------------------------------------------------------------------
  // Rudp::ChannelHandler overrides — called by Rudp directly
  // -----------------------------------------------------------------------

  void onOpened() override;
  void onReliableMessage(const Bytes& msg) override;
  void onUnreliableMessage(const Bytes& msg) override;
  void onWritable() override;
  void onClosed(Rudp::CloseReason reason) override;

  // -----------------------------------------------------------------------
  // Application controls
  // -----------------------------------------------------------------------

  /// Install a sink for unreliable bytes. Default: dropped silently.
  /// Pass an empty function to remove.
  using UnreliableSink = std::function<void(const Bytes& msg)>;
  void setUnreliableSink(UnreliableSink sink);

  /// Close the stream AND tear down the underlying RUDP channel via
  /// rudp()->closeChannel(peer(), channelId(), APPLICATION). Pending
  /// handlers complete with eof. Idempotent.
  void close();

  /// Close the stream WITHOUT tearing down the underlying RUDP
  /// channel. Same handler-completion semantics as close(). Rare;
  /// for keep-alive scenarios where another consumer drives the
  /// channel. Idempotent.
  void detach();

  /// True until the stream is closed by any path.
  bool is_open() const noexcept { return !closed_; }

  /// CloseReason that ended this stream, if any. Populated by
  /// onClosed(); close()/detach() leave this nullopt.
  std::optional<Rudp::CloseReason> getCloseReason() const noexcept {
    return closeReason_;
  }

  /// Bytes sitting in the read buffer. Test/debug only — production
  /// uses async_read_some.
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
  using ErasedHandler =
    std::function<void(boost::system::error_code, std::size_t)>;

  template <typename Handler> static ErasedHandler eraseHandler(Handler&& h) {
    auto holder = std::make_shared<std::decay_t<Handler>>(std::forward<Handler>(h));
    return ErasedHandler(
      [holder](boost::system::error_code ec, std::size_t n) mutable {
        (*holder)(ec, n);
      });
  }

  std::size_t drainBytes(uint8_t* dst, std::size_t maxBytes);
  void drainPendingWrite();
  void doClose(bool tearDownChannel);
  static boost::system::error_code closeReasonToError(Rudp::CloseReason r);
  void postError(ErasedHandler h, boost::system::error_code ec);
  void postRead(ErasedHandler h, std::size_t copied);

  template <typename MutableBufferSequence, typename Handler>
  void startRead(const MutableBufferSequence& buffers, Handler&& handler) {
    auto erased = eraseHandler(std::forward<Handler>(handler));

    if (closed_) {
      postError(std::move(erased),
                closeReason_ ? closeReasonToError(*closeReason_)
                             : boost::asio::error::eof);
      return;
    }

    if (!inboundBuf_.empty()) {
      const std::size_t capacity = boost::asio::buffer_size(buffers);
      std::size_t take =
        std::min(capacity, static_cast<std::size_t>(inboundBuf_.size()));
      std::vector<uint8_t> tmp(take);
      std::size_t copied = drainBytes(tmp.data(), take);
      boost::asio::buffer_copy(buffers,
                               boost::asio::buffer(tmp.data(), copied));
      postRead(std::move(erased), copied);
      return;
    }

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
    auto erased = eraseHandler(std::forward<Handler>(handler));

    if (closed_) {
      postError(std::move(erased),
                closeReason_ ? closeReasonToError(*closeReason_)
                             : boost::asio::error::eof);
      return;
    }

    if (pendingWriteHandler_) {
      postError(std::move(erased), boost::asio::error::in_progress);
      return;
    }

    const std::size_t total = boost::asio::buffer_size(buffers);
    pendingWriteBuf_.assign(total, 0);
    boost::asio::buffer_copy(
      boost::asio::buffer(pendingWriteBuf_.data(), pendingWriteBuf_.size()),
      buffers);
    pendingWriteOffset_ = 0;
    pendingWriteHandler_ = std::move(erased);

    drainPendingWrite();
  }

  // ---- Members ----

  executor_type ex_;

  std::deque<uint8_t> inboundBuf_;
  std::function<void(boost::system::error_code)> pendingReader_;

  std::vector<uint8_t> pendingWriteBuf_;
  std::size_t pendingWriteOffset_ = 0;
  ErasedHandler pendingWriteHandler_;

  UnreliableSink unreliableSink_;
  std::optional<Rudp::CloseReason> closeReason_;
  bool closed_ = false;
};

} // namespace minx

#endif
