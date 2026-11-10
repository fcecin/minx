#include <boost/test/unit_test.hpp>

#include <minx/powengine.h>

#include <array>
#include <cstdint>
#include <span>

BOOST_AUTO_TEST_SUITE(PoWEngineSuite)

// vmsToKeep < 1 selects the default pool size.
BOOST_AUTO_TEST_CASE(TestDefaultPoolKeepsReleasedVM) {
  std::array<uint8_t, 32> key{};
  key[0] = 0x42;
  PoWEngine engine(std::span<const uint8_t>(key), /*full_mem=*/false,
                   /*vmsToKeep=*/0);
  BOOST_REQUIRE(engine.initialize(1));

  auto first = engine.acquireVM();
  BOOST_REQUIRE(first);
  engine.releaseVM(first);
  auto second = engine.acquireVM();
  BOOST_REQUIRE(second);
  BOOST_TEST(second == first, "the pooled VM must be reused");
}

BOOST_AUTO_TEST_SUITE_END()
