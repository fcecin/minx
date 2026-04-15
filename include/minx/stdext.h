#ifndef _MINX_STDEXT_H_
#define _MINX_STDEXT_H_

#include <minx/minx.h>
#include <minx/types.h>

#include <boost/endian/conversion.hpp>

#include <cstdint>
#include <cstring>
#include <functional>
#include <unordered_map>

namespace minx {

/**
 * MinxStdExtensions: optional standard MINX_EXTENSION router for MINX.
 */
class MinxStdExtensions {
public:
  static constexpr size_t KEY_SIZE = 8;

  static constexpr uint64_t KEY_MASK = 0x0000FFFFFFFFFFFFULL;

  static constexpr uint64_t makeKey(uint16_t meta, uint64_t id) {
    return (static_cast<uint64_t>(meta) << 48) | (id & KEY_MASK);
  }

  static constexpr uint16_t metaOf(uint64_t key) {
    return static_cast<uint16_t>(key >> 48);
  }

  static constexpr uint64_t idOf(uint64_t key) { return key & KEY_MASK; }

  static inline void appendKey(Bytes& out, uint64_t key) {
    const uint64_t be = boost::endian::native_to_big(key);
    const size_t pos = out.size();
    out.resize(pos + KEY_SIZE);
    std::memcpy(out.data() + pos, &be, KEY_SIZE);
  }

  static inline uint64_t readKey(const Bytes& data, size_t offset = 0) {
    if (data.size() < offset + KEY_SIZE)
      return 0;
    uint64_t be;
    std::memcpy(&be, data.data() + offset, KEY_SIZE);
    return boost::endian::big_to_native(be);
  }

  /**
   * Handler signature for a registered extension.
   * @param addr Remote UDP socket sender address.
   * @param key The full 8-byte routing key as it arrived on the wire,
   * unmasked. The handler can extract the high 2 bytes (e.g.
   * `static_cast<uint16_t>(key >> 48)`) to read the extension-private
   * metadata.
   * @param payload Extension-defined bytes following the 8-byte key.
   */
  using ExtHandler = std::function<void(const SockAddr& addr, uint64_t key,
                                        const Bytes& payload)>;

  MinxStdExtensions();
  ~MinxStdExtensions();

  /**
   * Register a handler for a routing key. Replaces any previous handler
   * for the same masked key (the high 2 bytes are masked off before
   * insert). Must be called before `build()`.
   * @param key The routing key. The high 2 bytes are ignored.
   * @param handler Callable invoked when a matching packet arrives.
   */
  void registerExtension(uint64_t key, ExtHandler handler);

  /**
   * Remove a registered handler. Returns true if an entry was removed.
   * The high 2 bytes of the key are ignored. Must be called before `build()`.
   * @param key The routing key to unregister.
   */
  bool unregisterExtension(uint64_t key);

  /**
   * Number of currently registered extensions (mostly for tests).
   */
  size_t size() const { return table_.size(); }

  /**
   * Consume this builder and produce a self-contained dispatcher closure.
   * The returned closure owns the moved-out registration table outright;
   * after this call, the MinxStdExtensions instance is empty and can be
   * destroyed immediately.
   *
   * The `&&` ref-qualifier enforces single-use at compile time: callers
   * MUST invoke this on an rvalue, e.g.
   *
   *     minx->setExtensionHandler(std::move(stdExt).build());
   */
  MinxExtensionHandler build() &&;

private:
  std::unordered_map<uint64_t, ExtHandler> table_;
};

} // namespace minx

#endif
