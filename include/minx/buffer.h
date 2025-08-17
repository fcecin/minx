#ifndef _MINX_BUFFER_H_
#define _MINX_BUFFER_H_

#include <boost/asio/buffer.hpp>
#include <boost/endian/conversion.hpp>

#include <logkv/autoser.h>
#include <logkv/bytes.h>

namespace minx {

/**
 * Reads and writes a backing byte span.
 */
class Buffer {
public:
  Buffer() : r_(0), w_(0), s_(0) {}

  explicit Buffer(std::span<uint8_t> backingSpan)
      : buf_(backingSpan), r_(0), w_(0), s_(0) {}

  virtual ~Buffer() = default;

  std::span<const uint8_t> getBackingSpan() const { return buf_; }

  void setBackingSpan(std::span<uint8_t> external_buffer) {
    buf_ = external_buffer;
  }

  template <typename T> void put(const T& val) {
    logkv::Writer writer(&buf_[w_], buf_.size() - w_);
    try {
      writer.write(val);
      w_ += writer.bytes_processed();
      s_ = std::max(s_, w_);
    } catch (const logkv::insufficient_buffer&) {
      throw std::out_of_range("write exceeds backing buffer size");
    }
  }

  template <typename T> void get(T&& val) {
    logkv::Reader reader(&buf_[r_], s_ - r_);
    try {
      reader.read(val);
      r_ += reader.bytes_processed();
    } catch (const logkv::insufficient_buffer&) {
      throw std::out_of_range("cannot read past data size");
    }
  }

  template <typename T> T get() {
    T val;
    logkv::Reader reader(&buf_[r_], s_ - r_);
    try {
      reader.read(val);
      r_ += reader.bytes_processed();
      return val;
    } catch (const logkv::insufficient_buffer&) {
      throw std::out_of_range("cannot read past data size");
    }
  }

  logkv::Bytes getRemainingBytes() {
    logkv::Bytes result(getRemainingBytesCount());
    get(logkv::bytesAsSpan(result));
    return result;
  }

  size_t getRemainingBytesCount() const { return s_ > r_ ? s_ - r_ : 0; }

  size_t getSize() const { return s_; }

  void setSize(size_t s) {
    if (s > buf_.size()) {
      throw std::out_of_range("data size greater than backing buffer size");
    }
    s_ = s;
  }

  size_t getWritePos() const { return w_; }

  void setWritePos(size_t w) {
    if (w >= buf_.size()) {
      throw std::out_of_range("cannot write past backing buffer size");
    }
    w_ = w;
  }

  size_t getReadPos() const { return r_; }

  void setReadPos(size_t r) {
    if (r >= buf_.size()) {
      throw std::out_of_range("cannot read past backing buffer size");
    }
    r_ = r;
  }

  void clear() {
    r_ = 0;
    w_ = 0;
    s_ = 0;
  }

  boost::asio::const_buffer getAsioBufferToRead() const {
    return boost::asio::buffer(buf_.data(), s_);
  }

  boost::asio::mutable_buffer getAsioBufferToWrite() {
    return boost::asio::buffer(buf_.data(), buf_.size());
  }

private:
  std::span<uint8_t> buf_;
  size_t s_;
  size_t w_;
  size_t r_;
};

/**
 * Buffer with backing byte array.
 */
template <size_t N> class ArrayBuffer : public Buffer {
public:
  ArrayBuffer() : Buffer(arrayBuf_) {}

private:
  std::array<uint8_t, N> arrayBuf_;
};

/**
 * Buffer with backing byte vector.
 */
class VectorBuffer : public Buffer {
public:
  VectorBuffer(const size_t size) {
    vectorBuf_.resize(size);
    setBackingSpan(vectorBuf_);
  }

private:
  std::vector<uint8_t> vectorBuf_;
};

} // namespace minx

#endif