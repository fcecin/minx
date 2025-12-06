#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>
#include <chrono>
#include <minx/spamfilter.h>
#include <thread>

namespace {

using boost::asio::ip::address;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;

struct SpamFilterFixture {
  static constexpr size_t TEST_WIDTH = 1000;
  static constexpr size_t TEST_DEPTH = 3;
  static constexpr uint32_t TEST_THRESHOLD = 5;
  static constexpr int ROTATION_SEC = 60;

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
  for (int i = 0; i < 5; ++i) {
    BOOST_TEST(check(ip) == false, "Packet " << i + 1 << " should pass");
  }
}

BOOST_AUTO_TEST_CASE(TestAboveThreshold) {
  std::string ip = "192.168.1.1";
  spam(ip, 5);
  BOOST_TEST(check(ip) == true, "Packet 6 should drop");
}

BOOST_AUTO_TEST_CASE(TestIPv4_IPv6_Independence) {
  std::string ipv4 = "192.168.1.1";
  std::string ipv6 = "2001:db8::1";
  spam(ipv4, 100);
  BOOST_TEST(check(ipv4) == true, "IPv4 should be blocked");
  BOOST_TEST(check(ipv6) == false,
             "IPv6 address should not be affected by IPv4 spam");
}

BOOST_AUTO_TEST_CASE(TestRotationRetention) {
  std::string ip = "10.0.0.5";
  spam(ip, 3);
  BOOST_TEST(check(ip) == false);
  advanceTime(61);
  BOOST_TEST(check(ip) == false, "Packet after rotation should pass");
  BOOST_TEST(check(ip) == true,
             "Accumulated history in Older bucket should trigger block");
}

BOOST_AUTO_TEST_CASE(TestExpiration) {
  std::string ip = "10.0.0.5";
  spam(ip, 100);
  BOOST_TEST(check(ip) == true);
  advanceTime(61);
  BOOST_TEST(check(ip) == true);
  advanceTime(61);
  BOOST_TEST(check(ip) == false, "After two rotations, the ban should expire");
}

BOOST_AUTO_TEST_CASE(TestHotInOldPersistsToNew) {
  std::string ip = "10.0.0.99";
  spam(ip, 6);
  BOOST_TEST(check(ip) == true);
  advanceTime(61);
  BOOST_TEST(check(ip) == true);
  advanceTime(61);
  BOOST_TEST(check(ip) == false,
             "If early exit logic is used, the ban drops after 2nd rotation "
             "even if sustained traffic continued");
}

BOOST_AUTO_TEST_CASE(TestCounterSaturation) {
  std::string ip = "1.2.3.4";
  spam(ip, 300);
  BOOST_TEST(check(ip) == true);
  BOOST_TEST(check(ip) == true, "Counter should saturate, not wrap");
}

BOOST_AUTO_TEST_CASE(TestDifferentIPs) {
  std::string bad_ip = "6.6.6.6";
  std::string good_ip = "1.1.1.1";
  spam(bad_ip, 10);
  BOOST_TEST(check(bad_ip) == true);
  BOOST_TEST(check(good_ip) == false,
             "Innocent IP should not be blocked (assuming no collision)");
}

BOOST_AUTO_TEST_CASE(TestExactThresholdBoundary) {
  std::string ip = "192.168.9.9";
  spam(ip, 4);
  BOOST_TEST(check(ip) == false, "Packet 5 (Count=5) should pass");
  BOOST_TEST(check(ip) == true, "Packet 6 (Count=6) should drop");
}

BOOST_AUTO_TEST_SUITE_END()