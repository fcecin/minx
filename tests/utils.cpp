#include <boost/test/unit_test.hpp>
#include <minx/types.h>

#include <iomanip>
#include <iostream>
#include <vector>

namespace {

struct UtilsFixture {
  UtilsFixture() = default;
  minx::Hash makeHashWithDifficulty(int n) {
    minx::Hash h;
    h.fill(0xFF);
    if (n >= 256) {
      h.fill(0x00);
      return h;
    }
    int byte_idx = n / 8;
    int bit_idx = n % 8;
    for (int i = 0; i < byte_idx; ++i) {
      h[i] = 0x00;
    }
    uint8_t terminator = static_cast<uint8_t>(0x80 >> bit_idx);
    h[byte_idx] = terminator;
    return h;
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(UtilsSuite, UtilsFixture)

BOOST_AUTO_TEST_CASE(TestGetDifficulty_AllPrefixes) {
  for (int expected_diff = 0; expected_diff <= 256; ++expected_diff) {
    minx::Hash h = makeHashWithDifficulty(expected_diff);
    int calculated = minx::getDifficulty(h);
    if (calculated != expected_diff) {
      BOOST_TEST_MESSAGE("Failed at expected difficulty: " << expected_diff);
      BOOST_TEST_MESSAGE("Calculated: " << calculated);
      std::stringstream ss;
      ss << std::hex << std::setfill('0');
      for (auto b : h)
        ss << std::setw(2) << (int)b;
      BOOST_TEST_MESSAGE("Hash: " << ss.str());
    }
    BOOST_TEST(calculated == expected_diff);
  }
}

BOOST_AUTO_TEST_CASE(TestGetDifficulty_ByteBoundaries) {
  std::vector<int> boundaries = {0, 8, 16, 24, 32, 40, 48, 56, 64};
  for (int diff : boundaries) {
    minx::Hash h = makeHashWithDifficulty(diff);
    BOOST_TEST(minx::getDifficulty(h) == diff,
               "Failed at byte boundary " << diff);
  }
}

BOOST_AUTO_TEST_CASE(TestGetDifficulty_Word64Boundaries) {
  std::vector<int> boundaries = {64, 128, 192, 256};
  for (int diff : boundaries) {
    minx::Hash h = makeHashWithDifficulty(diff);
    BOOST_TEST(minx::getDifficulty(h) == diff,
               "Failed at 64-bit word boundary " << diff);
  }
}

BOOST_AUTO_TEST_CASE(TestHexConversions) {
  minx::Hash original;
  original.fill(0xAB);

  std::string hex = minx::hashToString(original);
  BOOST_TEST(hex.size() == 64);
  BOOST_TEST(hex.substr(0, 2) == "ab");

  minx::Hash restored;
  minx::stringToHash(restored, hex);
  BOOST_TEST(original == restored);

  minx::Bytes b;
  b.resize(64);
  minx::hashToBytes(b, original);
  BOOST_TEST(b.size() == 64);

  minx::Hash fromBytes;
  minx::bytesToHash(fromBytes, b);
  BOOST_TEST(original == fromBytes);

  std::string hexOut;
  hexOut.resize(64);
  minx::hashToString(original, hexOut);
  BOOST_TEST(hexOut == hex);
}

BOOST_AUTO_TEST_SUITE_END()