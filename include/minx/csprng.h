#ifndef _MINX_CSPRNG_H_
#define _MINX_CSPRNG_H_

/**
 * Csprng — cryptographically secure pseudo-random uint64 source.
 *
 * Output is computationally indistinguishable from uniform random for
 * any attacker who does not know the key.
 *
 * The (uint64_t, uint64_t) constructor lets tests pin the key and
 * produce a deterministic output stream. Two Csprng instances built
 * with the same key produce the same sequence. Use only for tests as
 * security relies on the key being secret to attackers.
 */

#include <cppsiphash/siphash.hpp>

#include <cstddef>
#include <cstdint>

namespace minx {

class Csprng {
public:
  Csprng();

  Csprng(uint64_t key0, uint64_t key1);

  uint64_t next();

  uint64_t nextNonZero();

  void fill(void* dst, std::size_t len);

private:
  siphash::Key key_;
  uint64_t counter_ = 0;
};

} // namespace minx

#endif
