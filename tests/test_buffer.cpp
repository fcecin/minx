#include <boost/test/unit_test.hpp>

#include <minx/buffer.h>

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(BufferSuite)

// getBytesSpan returns a zero-copy view of exactly N bytes and advances
// the read cursor; consecutive calls walk the buffer.
BOOST_AUTO_TEST_CASE(GetBytesSpanReadsExactAndAdvances) {
  std::vector<uint8_t> store(64);
  minx::Buffer buf(store);
  const std::array<uint8_t, 4> payload{0xDE, 0xAD, 0xBE, 0xEF};
  buf.putBytes(payload);
  buf.setReadPos(0);

  auto a = buf.getBytesSpan(2);
  BOOST_REQUIRE_EQUAL(a.size(), 2u);
  BOOST_CHECK_EQUAL(a[0], 0xDE);
  BOOST_CHECK_EQUAL(a[1], 0xAD);
  BOOST_CHECK_EQUAL(buf.getReadPos(), 2u);

  auto b = buf.getBytesSpan(2);
  BOOST_CHECK_EQUAL(b[0], 0xBE);
  BOOST_CHECK_EQUAL(b[1], 0xEF);
  BOOST_CHECK_EQUAL(buf.getRemainingBytesCount(), 0u);
}

// getBytes<R> copies exactly N bytes into a fresh container and advances.
BOOST_AUTO_TEST_CASE(GetBytesCopiesIntoContainer) {
  std::vector<uint8_t> store(16);
  minx::Buffer buf(store);
  const std::array<uint8_t, 3> payload{1, 2, 3};
  buf.putBytes(payload);

  buf.setReadPos(0);
  auto v = buf.getBytes<std::vector<uint8_t>>(3);
  BOOST_REQUIRE_EQUAL(v.size(), 3u);
  BOOST_CHECK_EQUAL(v[0], 1);
  BOOST_CHECK_EQUAL(v[2], 3);

  buf.setReadPos(0);
  auto s = buf.getBytes<std::string>(3);
  BOOST_REQUIRE_EQUAL(s.size(), 3u);
  BOOST_CHECK_EQUAL(static_cast<uint8_t>(s[1]), 2);
}

// Short reads throw std::runtime_error (consistent with getRemainingBytes*).
BOOST_AUTO_TEST_CASE(GetBytesThrowsOnShortRead) {
  std::vector<uint8_t> store(8);
  minx::Buffer buf(store);
  buf.put<uint16_t>(0x1234); // 2 bytes available
  buf.setReadPos(0);

  BOOST_CHECK_THROW(buf.getBytesSpan(3), std::runtime_error);
  BOOST_CHECK_THROW(buf.getBytes<std::vector<uint8_t>>(3), std::runtime_error);
  // Boundary: exactly the available count succeeds.
  BOOST_CHECK_NO_THROW(buf.getBytesSpan(2));
}

// putBytes appends raw bytes, advances the write cursor, grows the data
// size, and round-trips through getBytes.
BOOST_AUTO_TEST_CASE(PutBytesAppendsAndRoundTrips) {
  std::vector<uint8_t> store(16);
  minx::Buffer buf(store);
  const std::array<uint8_t, 5> payload{9, 8, 7, 6, 5};

  buf.putBytes(payload);
  BOOST_CHECK_EQUAL(buf.getWritePos(), 5u);
  BOOST_CHECK_EQUAL(buf.getSize(), 5u);

  buf.setReadPos(0);
  auto got = buf.getBytes<std::vector<uint8_t>>(5);
  BOOST_CHECK_EQUAL_COLLECTIONS(got.begin(), got.end(), payload.begin(),
                                payload.end());
}

// putBytes throws std::runtime_error when it would exceed the backing.
BOOST_AUTO_TEST_CASE(PutBytesThrowsOnOverflow) {
  std::vector<uint8_t> store(4);
  minx::Buffer buf(store);
  const std::array<uint8_t, 5> tooBig{};
  BOOST_CHECK_THROW(buf.putBytes(tooBig), std::runtime_error);
}

// The wire-parser pattern: write [u64][u16 len][len bytes], then parse it
// back with get<T>() + getBytes(len) — no manual offset arithmetic.
BOOST_AUTO_TEST_CASE(MixedScalarAndBytesRoundTrip) {
  std::vector<uint8_t> store(64);
  minx::Buffer buf(store);
  const std::string name = "hello";

  buf.put<uint64_t>(0x1122334455667788ull);
  buf.put<uint16_t>(static_cast<uint16_t>(name.size()));
  buf.putBytes(std::span<const uint8_t>(
    reinterpret_cast<const uint8_t*>(name.data()), name.size()));

  buf.setReadPos(0);
  BOOST_CHECK_EQUAL(buf.get<uint64_t>(), 0x1122334455667788ull);
  const uint16_t n = buf.get<uint16_t>();
  BOOST_REQUIRE_EQUAL(n, name.size());
  BOOST_CHECK_EQUAL(buf.getBytes<std::string>(n), name);
}

// getBytesSpan/getBytes work on a read-only ConstBuffer too (putBytes does
// not — it is gated on IsMutable).
BOOST_AUTO_TEST_CASE(ConstBufferReadsBytes) {
  std::array<uint8_t, 5> data{10, 20, 30, 40, 50};
  minx::ConstBuffer cbuf(data);

  auto span = cbuf.getBytesSpan(3);
  BOOST_REQUIRE_EQUAL(span.size(), 3u);
  BOOST_CHECK_EQUAL(span[2], 30);
  BOOST_CHECK_EQUAL(cbuf.getRemainingBytesCount(), 2u);
}

BOOST_AUTO_TEST_SUITE_END()
