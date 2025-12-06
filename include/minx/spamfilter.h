#pragma once

#include <array>
#include <chrono>
#include <limits>
#include <vector>
#include <random>

#include <boost/asio.hpp>

#include <cppsiphash/siphash.hpp>

class PacketSketch {
public:
  PacketSketch(size_t width, size_t depth) : width_(width), depth_(depth) {
    table_.resize(depth * width, 0);
    genKeys();
  }

  bool updateAndCheck(const void* data, size_t len, uint32_t threshold) {
    uint32_t min = std::numeric_limits<uint32_t>::max();
    for (size_t r = 0; r < depth_; ++r) {
      uint64_t hash = siphash::siphash24(data, len, &keys_[r]);
      size_t idx = (r * width_) + (hash % width_);
      if (table_[idx] < 255) {
        table_[idx]++;
      }
      if (table_[idx] < min) {
        min = table_[idx];
      }
    }
    return min > threshold;
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
    for (size_t i = 0; i < depth_; ++i) {
      keys_.push_back({gen(), gen()});
    }
  }

  size_t width_;
  size_t depth_;
  std::vector<uint8_t> table_;
  std::vector<siphash::Key> keys_;
};

class PacketGuard {
public:
  PacketGuard(size_t width, size_t depth, uint32_t threshold)
      : sketch_(width, depth), threshold_(threshold) {}
  bool updateAndCheck(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) {
      auto bytes = addr.to_v4().to_bytes();
      return sketch_.updateAndCheck(bytes.data(), bytes.size(), threshold_);
    } else if (addr.is_v6()) {
      auto bytes = addr.to_v6().to_bytes();
      return sketch_.updateAndCheck(bytes.data(), bytes.size(), threshold_);
    }
    return false;
  }

  void reset() { sketch_.reset(); }

private:
  PacketSketch sketch_;
  uint32_t threshold_;
};

class SpamFilter {
public:
  SpamFilter(size_t width, size_t depth, uint32_t threshold, int duration_sec)
      : currentIndex_(0),
        rotationInterval_(std::chrono::seconds(duration_sec)) {
    buckets_[0] = std::make_unique<PacketGuard>(width, depth, threshold);
    buckets_[1] = std::make_unique<PacketGuard>(width, depth, threshold);
    lastRotation_ = std::chrono::steady_clock::now();
  }

  bool
  updateAndCheck(const boost::asio::ip::address& addr,
                 const std::chrono::steady_clock::time_point* clock = nullptr) {
    auto now = (clock) ? *clock : std::chrono::steady_clock::now();
    if (now - lastRotation_ > rotationInterval_) {
      currentIndex_ = (currentIndex_ == 0) ? 1 : 0;
      buckets_[currentIndex_]->reset();
      lastRotation_ = now;
    }
    int olderIndex = (currentIndex_ == 0) ? 1 : 0;
    if (buckets_[olderIndex]->updateAndCheck(addr)) {
      return true;
    }
    return buckets_[currentIndex_]->updateAndCheck(addr);
  }

private:
  std::array<std::unique_ptr<PacketGuard>, 2> buckets_;
  int currentIndex_;
  std::chrono::steady_clock::time_point lastRotation_;
  std::chrono::seconds rotationInterval_;
};
