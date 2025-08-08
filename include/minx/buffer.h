#ifndef _MINX_BUFFER_H_
#define _MINX_BUFFER_H_

#include <boost/asio/buffer.hpp>
#include <boost/endian/conversion.hpp>

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

  void putByte(uint8_t val) { putData(&val, sizeof(val)); }

  void putUint64(uint64_t val) {
    const uint64_t val_be = boost::endian::native_to_big(val);
    putData(&val_be, sizeof(val_be));
  }

  void putByteVector(const std::vector<uint8_t>& data) {
    putData(data.data(), data.size());
  }

  template <size_t N> void putByteArray(const std::array<uint8_t, N>& arr) {
    putData(arr.data(), arr.size());
  }

  void putBytes(const logkv::Bytes& bytes) {
    putData(bytes.data(), bytes.size());
  }

  uint8_t getByte() {
    uint8_t val;
    getData(&val, 1);
    return val;
  }

  uint64_t getUint64() {
    uint64_t val_be;
    getData(&val_be, sizeof(val_be));
    return boost::endian::big_to_native(val_be);
  }

  std::vector<uint8_t> getByteVector(size_t len) {
    std::vector<uint8_t> result(len);
    getData(result.data(), result.size());
    return result;
  }

  template <size_t N> std::array<uint8_t, N> getByteArray() {
    std::array<uint8_t, N> result;
    getData(result.data(), result.size());
    return result;
  }

  logkv::Bytes getBytes(size_t len) {
    logkv::Bytes result(len);
    getData(result.data(), result.size());
    return result;
  }

  logkv::Bytes getRemainingBytes() {
    return getBytes(getRemainingBytesCount());
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
  void putData(const void* src, size_t size) {
    if (size) {
      if (w_ + size > buf_.size()) {
        throw std::out_of_range("write exceeds backing buffer size");
      }
      std::memcpy(&buf_[w_], src, size);
      w_ += size;
      s_ = std::max(s_, w_);
    }
  }

  void getData(void* dest, size_t size) {
    if (r_ + size > s_) {
      throw std::out_of_range("cannot read past data size");
    }
    std::memcpy(dest, &buf_[r_], size);
    r_ += size;
  }

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