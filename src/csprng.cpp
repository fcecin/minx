#include <minx/blog.h>
LOG_MODULE_DISABLED("csprng")

#include <minx/csprng.h>

#include <cstring>
#include <random>

namespace minx {

namespace {

uint64_t draw_seed_word() {
  std::random_device rd;
  const uint64_t hi = static_cast<uint64_t>(rd());
  const uint64_t lo = static_cast<uint64_t>(rd());
  return (hi << 32) | lo;
}

} // namespace

Csprng::Csprng() : key_(draw_seed_word(), draw_seed_word()) {
  LOGTRACE << "Csprng (entropy seeded)";
}

Csprng::Csprng(uint64_t key0, uint64_t key1) : key_(key0, key1) {
  LOGTRACE << "Csprng (deterministic seed)";
}

uint64_t Csprng::next() {
  const uint64_t out = siphash::siphash24(counter_, key_);
  ++counter_;
  return out;
}

uint64_t Csprng::nextNonZero() {
  uint64_t v = next();
  while (v == 0) {
    v = next();
  }
  return v;
}

void Csprng::fill(void* dst, std::size_t len) {
  uint8_t* p = static_cast<uint8_t*>(dst);
  while (len >= sizeof(uint64_t)) {
    const uint64_t v = next();
    std::memcpy(p, &v, sizeof(v));
    p += sizeof(v);
    len -= sizeof(v);
  }
  if (len > 0) {
    const uint64_t v = next();
    std::memcpy(p, &v, len);
  }
}

} // namespace minx
