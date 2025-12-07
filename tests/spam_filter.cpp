#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>
#include <chrono>
#include <minx/spamfilter.h>
#include <thread>

namespace {

using boost::asio::ip::address;

struct SpamFilterFixture {
  static constexpr size_t TEST_WIDTH = 1000;
  static constexpr size_t TEST_DEPTH = 3;
  static constexpr uint32_t TEST_THRESHOLD = 5;
  static constexpr int ROTATION_SEC = 60;
  static constexpr int PASSING_CAPACITY = (TEST_THRESHOLD + 1) * TEST_DEPTH;

  std::unique_ptr<SpamFilter> filter;
  std::chrono::steady_clock::time_point mockClock;

  SpamFilterFixture() {
    filter = std::make_unique<SpamFilter>(TEST_WIDTH, TEST_DEPTH,
                                          TEST_THRESHOLD, ROTATION_SEC);
    mockClock = std::chrono::steady_clock::now();
  }

  void advanceTime(int seconds) { mockClock += std::chrono::seconds(seconds); }

  void spam(const std::string& ip_str, int count) {
    address addr = address::from_string(ip_str);
    for (int i = 0; i < count; ++i) {
      filter->updateAndCheck(addr, &mockClock);
    }
  }

  bool check(const std::string& ip_str) {
    return filter->updateAndCheck(address::from_string(ip_str), &mockClock);
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(SpamFilterSuite, SpamFilterFixture)

BOOST_AUTO_TEST_CASE(TestBelowThreshold) {
  std::string ip = "192.168.1.1";
  for (int i = 0; i < PASSING_CAPACITY; ++i) {
    BOOST_TEST(check(ip) == false, "Packet " << i + 1 << " should pass");
  }
}

BOOST_AUTO_TEST_CASE(TestAboveThreshold) {
  std::string ip = "192.168.1.1";
  spam(ip, PASSING_CAPACITY);
  BOOST_TEST(check(ip) == true, "Packet 19 (Capacity+1) should drop");
}

BOOST_AUTO_TEST_CASE(TestIPv4_IPv6_Independence) {
  std::string ipv4 = "192.168.1.1";
  std::string ipv6 = "2001:db8::1";
  spam(ipv4, PASSING_CAPACITY + 1);
  BOOST_TEST(check(ipv4) == true, "IPv4 should be blocked");
  BOOST_TEST(check(ipv6) == false,
             "IPv6 address should not be affected by IPv4 spam");
}

BOOST_AUTO_TEST_CASE(TestRotationRetention) {
  std::string ip = "10.0.0.5";
  int half_load = PASSING_CAPACITY / 2;
  spam(ip, half_load);
  BOOST_TEST(check(ip) == false);
  advanceTime(ROTATION_SEC + 1);
  BOOST_TEST(check(ip) == false, "Packet after rotation should pass");
  int remaining_to_fill = PASSING_CAPACITY - half_load;
  spam(ip, remaining_to_fill);
  BOOST_TEST(check(ip) == true,
             "Accumulated history in Older bucket should trigger block");
}

BOOST_AUTO_TEST_CASE(TestExpiration) {
  std::string ip = "10.0.0.5";
  spam(ip, PASSING_CAPACITY + 5);
  BOOST_TEST(check(ip) == true);
  advanceTime(ROTATION_SEC + 1);
  BOOST_TEST(check(ip) == true);
  advanceTime(ROTATION_SEC + 1);
  BOOST_TEST(check(ip) == false, "After two rotations, the ban should expire");
}

BOOST_AUTO_TEST_CASE(TestHotInOldPersistsToNew) {
  std::string ip = "10.0.0.99";
  spam(ip, PASSING_CAPACITY + 1);
  BOOST_TEST(check(ip) == true);
  advanceTime(ROTATION_SEC + 1);
  BOOST_TEST(check(ip) == true);
  advanceTime(ROTATION_SEC + 1);
  BOOST_TEST(check(ip) == false,
             "Ban drops after 2nd rotation because logic short-circuits");
}

BOOST_AUTO_TEST_CASE(TestCounterSaturation) {
  std::string ip = "1.2.3.4";
  int huge_load = 255 * TEST_DEPTH + 100;
  spam(ip, huge_load);
  BOOST_TEST(check(ip) == true);
  BOOST_TEST(check(ip) == true, "Counter should saturate, not wrap");
}

BOOST_AUTO_TEST_CASE(TestDifferentIPs) {
  std::string bad_ip = "6.6.6.6";
  std::string good_ip = "1.1.1.1";
  spam(bad_ip, PASSING_CAPACITY + 1);
  BOOST_TEST(check(bad_ip) == true);
  BOOST_TEST(check(good_ip) == false, "Innocent IP should not be blocked");
}

BOOST_AUTO_TEST_CASE(TestExactThresholdBoundary) {
  std::string ip = "192.168.9.9";
  spam(ip, PASSING_CAPACITY);
  BOOST_TEST(check(ip) == true, "Packet 19 should drop");
  std::string ip2 = "192.168.9.10";
  spam(ip2, PASSING_CAPACITY - 1);
  BOOST_TEST(check(ip2) == false, "Packet 18 should still pass");
}

BOOST_AUTO_TEST_SUITE_END()