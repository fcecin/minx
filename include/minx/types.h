#ifndef _MINXTYPES_H_
#define _MINXTYPES_H_

#include <bit>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/container/small_vector.hpp>
#include <boost/endian/conversion.hpp>

#include <logkv/bytes.h>

namespace minx {

using SockAddr = boost::asio::ip::udp::endpoint;
using IPAddr = boost::asio::ip::address;
using IOContext = boost::asio::io_context;
using Bytes = boost::container::small_vector<char, 256>;
using Hash = std::array<uint8_t, 32>;

inline void bytesToHash(Hash& dest, const Bytes& src) {
  if (src.size() != 64) {
    throw std::invalid_argument("src is not a 64-byte buffer");
  }
  logkv::decodeHex(reinterpret_cast<char*>(dest.data()), dest.size(),
                   reinterpret_cast<const char*>(src.data()), src.size());
}

inline void hashToBytes(Bytes& dest, const Hash& src, bool upper = false) {
  if (dest.size() != 64) {
    throw std::invalid_argument("dest is not a 64-byte buffer");
  }
  logkv::encodeHex(reinterpret_cast<char*>(dest.data()), dest.size(),
                   reinterpret_cast<const char*>(src.data()), src.size(),
                   upper);
}

inline void stringToHash(Hash& dest, const std::string& src) {
  if (src.size() != 64) {
    throw std::invalid_argument("src is not a 64-character string");
  }
  logkv::decodeHex(reinterpret_cast<char*>(dest.data()), dest.size(),
                   src.data(), src.size());
}

inline void hashToString(const Hash& src, std::string& dest,
                         bool upper = false) {
  dest.resize(64);
  logkv::encodeHex(dest.data(), dest.size(),
                   reinterpret_cast<const char*>(src.data()), src.size(),
                   upper);
}

inline std::string hashToString(const Hash& src, bool upper = false) {
  std::string dest(64, '\0');
  logkv::encodeHex(dest.data(), dest.size(),
                   reinterpret_cast<const char*>(src.data()), src.size(),
                   upper);
  return dest;
}

inline std::string hashToBinaryString(const minx::Hash& hash) {
  std::string binaryString;
  binaryString.reserve(256);
  for (const auto& byte : hash) {
    for (int i = 7; i >= 0; --i) {
      binaryString += ((byte >> i) & 1) ? '1' : '0';
    }
  }
  return binaryString;
}

struct SecureHashHasher {
  std::size_t operator()(const std::array<unsigned char, 32>& arr) const {
    size_t hash_value;
    std::memcpy(&hash_value, arr.data(), sizeof(size_t));
    return hash_value;
  }
};

inline std::span<std::byte> bytesAsSpan(minx::Bytes& b) {
  return {reinterpret_cast<std::byte*>(b.data()), b.size()};
}

inline std::span<const std::byte> bytesAsSpan(const minx::Bytes& b) {
  return {reinterpret_cast<const std::byte*>(b.data()), b.size()};
}

inline int getDifficulty(const Hash& hash) {
  int difficulty = 0;
  for (size_t i = 0; i < 4; ++i) {
    uint64_t chunk;
    std::memcpy(&chunk, hash.data() + (i * 8), 8);
    chunk = boost::endian::big_to_native(chunk);
    if (chunk == 0) {
      difficulty += 64;
    } else {
      difficulty += std::countl_zero(chunk);
      return difficulty;
    }
  }
  return difficulty;
}

inline uint64_t getSecsSinceEpoch() {
  return std::chrono::duration_cast<std::chrono::seconds>(
           std::chrono::system_clock::now().time_since_epoch())
    .count();
}

} // namespace minx

#endif