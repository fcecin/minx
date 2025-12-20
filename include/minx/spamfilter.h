#pragma once

#include <array>
#include <chrono>
#include <limits>
#include <random>
#include <vector>

#include <boost/asio.hpp>

#include <cppsiphash/siphash.hpp>

class PacketGuard {
public:
  PacketGuard(size_t width, size_t depth, uint8_t threshold)
      : width_(width), depth_(depth), threshold_(threshold) {
    table_.resize(depth * width, 0);
    genKeys();
  }

  bool check(const boost::asio::ip::address& addr, bool alsoUpdate = false) {
    const uint8_t* data = nullptr;
    size_t len = 0;
    boost::asio::ip::address_v4::bytes_type bytes_v4;
    boost::asio::ip::address_v6::bytes_type bytes_v6;
    if (addr.is_v4()) {
      bytes_v4 = addr.to_v4().to_bytes();
      bytes_v4[3] = 0;
      data = bytes_v4.data();
      len = bytes_v4.size();
    } else {
      bytes_v6 = addr.to_v6().to_bytes();
      std::fill(bytes_v6.begin() + 7, bytes_v6.end(), 0);
      data = bytes_v6.data();
      len = bytes_v6.size();
    }

    uint8_t min_val = std::numeric_limits<uint8_t>::max();
    size_t min_idx = 0;
    for (size_t r = 0; r < depth_; ++r) {
      uint64_t hash = siphash::siphash24(data, len, &keys_[r]);
      size_t idx = (r * width_) + (hash % width_);
      uint8_t val = table_[idx];
      if (val <= min_val) {
        min_val = val;
        min_idx = idx;
      }
    }
    if (min_val > threshold_) {
      return true;
    }
    if (alsoUpdate && min_val < std::numeric_limits<uint8_t>::max()) {
      ++table_[min_idx];
    }
    return false;
  }

  void reset() {
    std::memset(table_.data(), 0, table_.size());
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
  uint8_t threshold_;
  std::vector<uint8_t> table_;
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
 * Allocates `2 * width * depth` bytes and runs `depth` SipHash ops per query.
 * All IPv4 addresses within the same /24 share the same spam budget.
 * All IPv6 addresses within the same /56 share the same spam budget.
 * NOTE: This class is thread-safe.
 */
class SpamFilter {
public:
  SpamFilter(size_t width, size_t depth, uint8_t threshold, int duration_sec)
      : currentIndex_(0),
        rotationInterval_(std::chrono::seconds(duration_sec)) {
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
