#ifndef _MINXTYPES_H_
#define _MINXTYPES_H_

#include <boost/asio.hpp>

#include <logkv/bytes.h>

namespace minx {

using SockAddr = boost::asio::ip::udp::endpoint;
using IPAddr = boost::asio::ip::address;
using IOContext = boost::asio::io_context;
using Bytes = logkv::Bytes;
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

inline int getDifficulty(const Hash& hash) {
  int difficulty = 0;
  for (uint8_t byte : hash) {
    if (byte == 0x00) {
      difficulty += 8;
    } else {
      int leading_zeros_in_byte = 0;
      uint8_t mask = 0x80;
      while ((byte & mask) == 0) {
        ++leading_zeros_in_byte;
        mask >>= 1;
      }
      difficulty += leading_zeros_in_byte;
      break;
    }
  }
  return difficulty;
}

} // namespace minx

inline std::ostream& operator<<(std::ostream& os, const minx::Hash& hash) {
  os << std::hex << std::setfill('0');
  for (const auto& byte : hash) {
    os << std::setw(2) << static_cast<int>(byte);
  }
  os << std::dec;
  return os;
}

#endif