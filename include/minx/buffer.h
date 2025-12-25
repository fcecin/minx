#ifndef _MINXBUFFER_H_
#define _MINXBUFFER_H_

#include <boost/asio/buffer.hpp>
#include <boost/endian/conversion.hpp>

#include <logkv/autoser.h>

#include <minx/types.h>

namespace minx {

/**
 * Reads and writes a backing byte span.
 * Uses `logkv::serializer` to `get` and `put` objects.
 */
template <typename T> class AutoBuffer {
public:
  static_assert(sizeof(T) == 1, "AutoBuffer<T> does not support sizeof(T) > 1");

  static constexpr bool IsMutable = !std::is_const_v<T>;

  AutoBuffer() : r_(0), w_(0), s_(0) {}

  explicit AutoBuffer(std::span<T> backingSpan)
      : buf_(backingSpan), r_(0), w_(0),
        s_(IsMutable ? 0 : backingSpan.size()) {}

  template <typename C> explicit AutoBuffer(C& c) { setBackingContainer<C>(c); }

  virtual ~AutoBuffer() = default;

  auto data() {
    return reinterpret_cast<std::conditional_t<IsMutable, char*, const char*>>(
      &buf_[0]);
  }

  std::span<const uint8_t> getBackingSpan() const { return buf_; }

  void setBackingSpan(std::span<T> external_buffer) {
    buf_ = external_buffer;
    r_ = 0;
    w_ = 0;
    if constexpr (!IsMutable) {
      s_ = buf_.size();
    } else {
      s_ = 0;
    }
  }

  template <typename C> void setBackingContainer(C& c) {
    auto* ptr = std::data(c);
    size_t len = std::size(c);
    using TargetType = std::conditional_t<IsMutable, uint8_t, const uint8_t>;
    if constexpr (IsMutable) {
      static_assert(!std::is_const_v<std::remove_pointer_t<decltype(ptr)>>,
                    "Const C cannot back non-const T");
    }
    setBackingSpan(
      std::span<TargetType>(reinterpret_cast<TargetType*>(ptr), len));
  }

  template <typename V, bool M = IsMutable, typename = std::enable_if_t<M>>
  void put(const V& val) {
    logkv::Writer writer(const_cast<uint8_t*>(&buf_[w_]), buf_.size() - w_);
    try {
      writer.write(val);
      w_ += writer.bytes_processed();
      s_ = std::max(s_, w_);
    } catch (const logkv::insufficient_buffer&) {
      throw std::out_of_range("write exceeds backing buffer size");
    }
  }

  boost::asio::mutable_buffer getAsioBufferToWrite() {
    static_assert(IsMutable,
                  "Cannot get mutable ASIO buffer from a ConstBuffer");
    return boost::asio::buffer(const_cast<uint8_t*>(buf_.data()), buf_.size());
  }

  template <typename V> void get(V&& val) {
    logkv::Reader reader(&buf_[r_], s_ - r_);
    try {
      reader.read(val);
      r_ += reader.bytes_processed();
    } catch (const logkv::insufficient_buffer&) {
      throw std::out_of_range("cannot read past data size");
    }
  }

  template <typename V> V get() {
    V val;
    logkv::Reader reader(&buf_[r_], s_ - r_);
    try {
      reader.read(val);
      r_ += reader.bytes_processed();
      return val;
    } catch (const logkv::insufficient_buffer&) {
      throw std::out_of_range("cannot read past data size");
    }
  }

  /**
   * Returns a view of the remaining bytes and advance the read cursor.
   * WARNING: The returned span points to internal memory. Use "immediately"
   * (for example, in the same scope); do NOT store the pointer long-term.
   */
  std::span<const uint8_t> getRemainingBytesSpan(size_t maxSize = 0) {
    size_t count = getRemainingBytesCount();

    if (maxSize > 0 && count > maxSize) {
      throw std::runtime_error(std::format(
        "AutoBuffer::getRemainingBytesSpan(): maximum size exceeded: {} > {}",
        count, maxSize));
    }
    std::span<const uint8_t> result(buf_.data() + r_, count);
    r_ += count; // fake zero-copy read
    return result;
  }

  template <typename R> R getRemainingBytes(size_t maxSize = 0) {
    size_t count = getRemainingBytesCount();
    if (maxSize > 0 && count > maxSize) {
      throw std::runtime_error(std::format(
        "AutoBuffer::getRemainingBytes(): maximum size exceeded: {} > {}",
        count, maxSize));
    }
    R result(count);
    if (count > 0) {
      std::memcpy(result.data(), &buf_[r_], count);
      r_ += count;
    }
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

  void setSizeToCapacity() { s_ = buf_.size(); }

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

private:
  std::span<T> buf_;
  size_t s_;
  size_t w_;
  size_t r_;
};

using Buffer = AutoBuffer<uint8_t>;

using ConstBuffer = AutoBuffer<const uint8_t>;

/**
 * Buffer with backing byte array.
 */
template <size_t N> class ArrayBuffer : public Buffer {
public:
  ArrayBuffer() : Buffer(arrayBuf_) {}
  ArrayBuffer(const ArrayBuffer&) = delete;
  ArrayBuffer& operator=(const ArrayBuffer&) = delete;
  ArrayBuffer(ArrayBuffer&&) = delete;
  ArrayBuffer& operator=(ArrayBuffer&&) = delete;

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