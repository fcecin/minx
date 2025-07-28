#ifndef _MINXIPFILTER_H_
#define _MINXIPFILTER_H_

#include <minx/bucketcache.h>
#include <minx/types.h>

namespace minx {

/**
 * An IP address filtering system for nodes in a fully-open P2P network.
 * The filter is very conservative, since it is biased towards protecting the
 * service node, which is a P2P node instead of a well-provisioned server.
 * Reported IPv6 addresses will temporarily ban their entire /56 for one hour.
 * Reported IPv4 addresses will temporarily ban their entire /24 for one hour.
 */
class IPFilter {
private:
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
   * Check if an IP address is flagged as a potential attacker.
   * @param addr The IP address to check.
   * @return `true` if the IP address is banned, `false` otherwise.
   */
  bool checkIP(const IPAddr& addr) {
    if (addr.is_v4()) {
      const uint32_t ipv4_addr = addr.to_v4().to_uint();
      const uint32_t prefix = ipv4_addr & 0xFFFFFF00;
      return ipv4_.get(prefix);
    }
    if (addr.is_v6()) {
      const auto bytes = addr.to_v6().to_bytes();
      uint64_t prefix = 0;
      memcpy(&prefix, bytes.data(), 7);
      return ipv6_.get(prefix);
    }
    return false;
  }

  /**
   * Flag an IP address as a potential attacker.
   * @param addr The IP address to ban.
   */
  void reportIP(const IPAddr& addr) {
    if (addr.is_v4()) {
      const uint32_t ipv4_addr = addr.to_v4().to_uint();
      const uint32_t prefix = ipv4_addr & 0xFFFFFF00;
      ipv4_.put(prefix);
    } else if (addr.is_v6()) {
      const auto bytes = addr.to_v6().to_bytes();
      uint64_t prefix = 0;
      memcpy(&prefix, bytes.data(), 7);
      ipv6_.put(prefix);
    }
  }
};

} // namespace minx

#endif