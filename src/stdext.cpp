#include <minx/blog.h>
LOG_MODULE_DISABLED("stdext")

#include <minx/stdext.h>

namespace minx {

MinxStdExtensions::MinxStdExtensions() { LOGTRACE << "MinxStdExtensions"; }

MinxStdExtensions::~MinxStdExtensions() { LOGTRACE << "~MinxStdExtensions"; }

void MinxStdExtensions::registerExtension(uint64_t key, ExtHandler handler) {
  uint64_t masked = key & KEY_MASK;
  LOGTRACE << "registerExtension" << VAR(HEXU64(masked));
  table_[masked] = std::move(handler);
}

bool MinxStdExtensions::unregisterExtension(uint64_t key) {
  uint64_t masked = key & KEY_MASK;
  LOGTRACE << "unregisterExtension" << VAR(HEXU64(masked));
  return table_.erase(masked) > 0;
}

MinxExtensionHandler MinxStdExtensions::build() && {
  LOGTRACE << "build" << VAR(table_.size());
  // Move the registration table into the closure. After this, *this is
  // empty (the moved-from std::unordered_map is in a valid but unspecified
  // state — typically empty — and the builder is safely destructible).
  return [t = std::move(table_)](const SockAddr& addr, const Bytes& data) {
    // readKey returns 0 on a short buffer; check explicitly so we can
    // tell "no key" apart from "key is literally zero."
    if (data.size() < KEY_SIZE) {
      LOGTRACE << "stdext drop: short" << VAR(data.size());
      return;
    }

    // Bytes 0..7 — routing key, big-endian. Lookup is by the low 48 bits
    // (idOf); the high 2 bytes are extension metadata and not part of
    // the route. The handler still receives the unmasked wire key so it
    // can decode them itself.
    uint64_t key = readKey(data);
    auto it = t.find(idOf(key));
    if (it == t.end()) {
      LOGTRACE << "stdext drop: unknown" << VAR(HEXU64(idOf(key)));
      return;
    }

    // Build a payload slice from byte 8 onwards.
    Bytes payload(data.begin() + KEY_SIZE, data.end());
    LOGTRACE << "stdext dispatch" << VAR(HEXU64(key)) << VAR(payload.size());
    it->second(addr, key, payload);
  };
}

} // namespace minx
