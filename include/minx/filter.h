#ifndef _MINXFILTER_H_
#define _MINXFILTER_H_

#include <boost/asio.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <vector>

#include <cppsiphash/siphash.hpp>

#include <minx/bucketcache.h>
#include <minx/types.h>

namespace minx {

/**
 * Return the /24 (IPv4) or /56 (IPv6) address prefix.
 * This just zeroes out the corresponding suffix of the given address.
 * For IPv4-mapped IPv6 addresses, the IPv4 prefix is returned instead.
 */
inline boost::asio::ip::address
getAddressPrefix(boost::asio::ip::address addr) {
  if (addr.is_v6() && addr.to_v6().is_v4_mapped()) {
    addr = addr.to_v6().to_v4();
  }
  if (addr.is_v4()) {
    auto bytes = addr.to_v4().to_bytes();
    bytes[3] = 0;
    return boost::asio::ip::address_v4(bytes);
  }
  auto bytes = addr.to_v6().to_bytes();
  std::memset(bytes.data() + 7, 0, 9);
  return boost::asio::ip::address_v6(bytes);
}

class PacketGuard {
public:
  PacketGuard(size_t width, size_t depth, uint16_t threshold)
      : width_(width), depth_(depth), threshold_(threshold) {
    table_.resize(depth * width, 0);
    genKeys();
  }

  bool check(const boost::asio::ip::address& addr, bool alsoUpdate = false) {
    auto bucket = getAddressPrefix(addr);
    const uint8_t* data = nullptr;
    size_t len = 0;
    boost::asio::ip::address_v4::bytes_type bytes_v4;
    boost::asio::ip::address_v6::bytes_type bytes_v6;
    if (bucket.is_v4()) {
      bytes_v4 = bucket.to_v4().to_bytes();
      data = bytes_v4.data();
      len = bytes_v4.size();
    } else {
      bytes_v6 = bucket.to_v6().to_bytes();
      data = bytes_v6.data();
      len = bytes_v6.size();
    }

    uint16_t min_val = std::numeric_limits<uint16_t>::max();
    size_t min_idx = 0;
    for (size_t r = 0; r < depth_; ++r) {
      uint64_t hash = siphash::siphash24(data, len, &keys_[r]);
      size_t idx = (r * width_) + (hash % width_);
      uint16_t val = table_[idx];
      if (val <= min_val) {
        min_val = val;
        min_idx = idx;
      }
    }
    if (min_val > threshold_) {
      return true;
    }
    if (alsoUpdate && min_val < std::numeric_limits<uint16_t>::max()) {
      ++table_[min_idx];
    }
    return false;
  }

  void reset() {
    std::memset(table_.data(), 0, table_.size() * sizeof(uint16_t));
    genKeys();
  }

private:
  void genKeys() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    keys_.clear();
    keys_.reserve(depth_);
    for (size_t i = 0; i < depth_; ++i) {
      keys_.push_back({gen(), gen()});
    }
  }

  size_t width_;
  size_t depth_;
  uint16_t threshold_;
  std::vector<uint16_t> table_;
  std::vector<siphash::Key> keys_;
};

/**
 * An UDP packet spam filter.
 * With some probability, accepts `threshold * depth` packets from `addr` in a
 * time interval between `duration_sec` and `duration_sec * 2`.
 * This is intended to be used for unconfirmed (non-3-way-handshaked) addresses
 * in order to help deter DoS amplification attacks.
 * Params `width` and `depth` need to be adjusted based on expected traffic and
 * may need to be exposed as app configs.
 * Allocates `4 * width * depth` bytes and runs `depth` SipHash ops per query.
 * All IPv4 addresses within the same /24 share the same spam budget.
 * All IPv6 addresses within the same /56 share the same spam budget.
 * NOTE: This class is thread-safe.
 */
class SpamFilter {
public:
  SpamFilter(size_t width, size_t depth, uint8_t threshold, int durationSecs)
      : currentIndex_(0),
        rotationInterval_(std::chrono::seconds(durationSecs)) {
    buckets_[0] = std::make_unique<PacketGuard>(width, depth, threshold);
    buckets_[1] = std::make_unique<PacketGuard>(width, depth, threshold);
    lastRotation_ = std::chrono::steady_clock::now();
  }

  bool
  updateAndCheck(const boost::asio::ip::address& addr,
                 const std::chrono::steady_clock::time_point* clock = nullptr) {
    return check(addr, true, clock);
  }

  bool check(const boost::asio::ip::address& addr, bool alsoUpdate = false,
             const std::chrono::steady_clock::time_point* clock = nullptr) {
    auto now = (clock) ? *clock : std::chrono::steady_clock::now();
    std::lock_guard{mutex_};
    if (now - lastRotation_ > rotationInterval_) {
      currentIndex_ = !currentIndex_;
      buckets_[currentIndex_]->reset();
      lastRotation_ = now;
    }
    int olderIndex = !currentIndex_;
    if (buckets_[olderIndex]->check(addr, alsoUpdate)) {
      return true;
    }
    return buckets_[currentIndex_]->check(addr, alsoUpdate);
  }

private:
  mutable std::mutex mutex_;
  std::array<std::unique_ptr<PacketGuard>, 2> buckets_;
  int currentIndex_;
  std::chrono::steady_clock::time_point lastRotation_;
  std::chrono::seconds rotationInterval_;
};

/**
 * An IP address filtering system for nodes in a fully-open P2P network.
 * The filter is very conservative, since it is biased towards protecting the
 * service node, which is a P2P node instead of a well-provisioned server.
 * Reported IPv6 addresses will temporarily ban their entire /56 for one hour.
 * Reported IPv4 addresses will temporarily ban their entire /24 for one hour.
 */
class IPFilter {
private:
  // TODO: map ipv4 to ipv6 (e.g. use prefix 0xFF) and delete ipv4_
  BucketCache<uint64_t> ipv6_;
  BucketCache<uint32_t> ipv4_;

public:
  /**
   * Construct a default IPFilter which can handle at least a million IP address
   * blocks of IPv4 or IPv6 addresses and resets every hour (or earlier if the
   * filter is full).
   */
  IPFilter() : ipv6_(1'000'000, 3600), ipv4_(1'000'000, 3600) {}

  /**
   * Construct an IPFilter with a given depth and bucket flip timeout.
   */
  IPFilter(size_t width, int durationSecs)
      : ipv6_(width, durationSecs), ipv4_(width, durationSecs) {}

  /**
   * Check if an IP address is flagged as a potential attacker.
   * @param addr The IP address to check.
   * @return `true` if the IP address is banned, `false` otherwise.
   */
  bool checkIP(const IPAddr& addr) {
    auto bucket = getAddressPrefix(addr);
    if (bucket.is_v4()) {
      const uint32_t ipv4_addr = bucket.to_v4().to_uint();
      return ipv4_.get(ipv4_addr);
    }
    if (bucket.is_v6()) {
      const auto bytes = bucket.to_v6().to_bytes();
      uint64_t prefix = 0;
      memcpy(&prefix, bytes.data(), 8);
      return ipv6_.get(prefix);
    }
    return false;
  }

  /**
   * Flag an IP address as a potential attacker.
   * @param addr The IP address to ban.
   */
  void reportIP(const IPAddr& addr) {
    auto bucket = getAddressPrefix(addr);
    if (bucket.is_v4()) {
      const uint32_t ipv4_addr = bucket.to_v4().to_uint();
      ipv4_.put(ipv4_addr);
    } else if (bucket.is_v6()) {
      const auto bytes = bucket.to_v6().to_bytes();
      uint64_t prefix = 0;
      memcpy(&prefix, bytes.data(), 8);
      ipv6_.put(prefix);
    }
  }
};

} // namespace minx

#endif