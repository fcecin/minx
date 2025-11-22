#include <boost/test/unit_test.hpp>

#include <minx/minx.h>

namespace {

class MinxMockListener : public minx::MinxListener {
};

minx::Hash makeHash(uint64_t id) {
  minx::Hash h;
  std::fill(h.begin(), h.end(), 0);
  std::memcpy(h.data(), &id, sizeof(id));
  return h;
}

struct MinxFixture {
  MinxMockListener listener;
  const uint64_t SLOT_SIZE = 1000;
  std::unique_ptr<minx::Minx> minx;
  uint64_t uniqueHashId = 0;
  MinxFixture() {
    minx = std::make_unique<minx::Minx>(&listener, 0, SLOT_SIZE);
  }
  bool isTimeAccepted(uint64_t t) {
    return minx->replayPoW(t, makeHash(++uniqueHashId));
  }
  bool isSpecificPoWAccepted(uint64_t t, const minx::Hash& h) {
    return minx->replayPoW(t, h);
  }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(MinxPoWCacheSuite, MinxFixture)

BOOST_AUTO_TEST_CASE(TestInitializationWindow) {
  minx->updatePoWSpendCache(10000);
  BOOST_TEST(isTimeAccepted(10000) == true, "Current time should be accepted");
  BOOST_TEST(isTimeAccepted(10500) == true,
             "Mid-current slot should be accepted");
  BOOST_TEST(isTimeAccepted(9000) == true,
             "Previous slot start should be accepted");
  BOOST_TEST(isTimeAccepted(9999) == true,
             "Previous slot end should be accepted");
  BOOST_TEST(isTimeAccepted(11000) == true,
             "Next slot start should be accepted");
  BOOST_TEST(isTimeAccepted(11999) == true, "Next slot end should be accepted");
  BOOST_TEST(isTimeAccepted(8999) == false,
             "Time before previous slot should be rejected");
  BOOST_TEST(isTimeAccepted(12000) == false,
             "Time after next slot should be rejected");
}

BOOST_AUTO_TEST_CASE(TestNormalSlide) {
  minx->updatePoWSpendCache(10000);
  minx->updatePoWSpendCache(11000);
  BOOST_TEST(isTimeAccepted(9000) == false, "Slot T-2 should now be dropped");
  BOOST_TEST(isTimeAccepted(9999) == false);
  BOOST_TEST(isTimeAccepted(10000) == true);
  BOOST_TEST(isTimeAccepted(12000) == true,
             "New future slot should be accepted");
}

BOOST_AUTO_TEST_CASE(TestMicroSlide) {
  minx->updatePoWSpendCache(10000);
  minx->updatePoWSpendCache(10500);
  BOOST_TEST(isTimeAccepted(9000) == true);
  BOOST_TEST(isTimeAccepted(11999) == true);
}

BOOST_AUTO_TEST_CASE(TestGapReset) {
  minx->updatePoWSpendCache(10000);
  BOOST_TEST(isTimeAccepted(10000) == true);
  minx->updatePoWSpendCache(50000);
  BOOST_TEST(isTimeAccepted(10000) == false, "Old data should be wiped on gap");
  BOOST_TEST(isTimeAccepted(11000) == false);
  BOOST_TEST(isTimeAccepted(49000) == true, "New Previous accepted");
  BOOST_TEST(isTimeAccepted(50000) == true, "New Current accepted");
  BOOST_TEST(isTimeAccepted(51000) == true, "New Next accepted");
}

BOOST_AUTO_TEST_CASE(TestLagCatchup) {
  minx->updatePoWSpendCache(10000);
  minx->updatePoWSpendCache(12000);
  BOOST_TEST(isTimeAccepted(10000) == false);
  BOOST_TEST(isTimeAccepted(11000) == true);
  BOOST_TEST(isTimeAccepted(13000) == true);
}

BOOST_AUTO_TEST_CASE(TestBucketPersistence) {
  minx->updatePoWSpendCache(10000);
  minx::Hash hashA = makeHash(100);
  BOOST_TEST(isSpecificPoWAccepted(10000, hashA) == true,
             "First insert should succeed");
  BOOST_TEST(isSpecificPoWAccepted(10000, hashA) == false,
             "Immediate duplicate should fail");
  minx::Hash hashB = makeHash(200);
  BOOST_TEST(isSpecificPoWAccepted(11000, hashB) == true);
  minx->updatePoWSpendCache(11000);
  BOOST_TEST(isSpecificPoWAccepted(10000, hashA) == false,
             "Duplicate in slided bucket should still fail");
  BOOST_TEST(isSpecificPoWAccepted(11000, hashB) == false,
             "Duplicate in slided bucket should still fail");
  BOOST_TEST(isTimeAccepted(10000) == true,
             "New item in Previous bucket should succeed");
  BOOST_TEST(isTimeAccepted(11000) == true,
             "New item in Current bucket should succeed");
}

BOOST_AUTO_TEST_CASE(TestLagCatchupPersistence) {
  minx->updatePoWSpendCache(10000);
  minx::Hash hashFuture = makeHash(300);
  BOOST_TEST(isSpecificPoWAccepted(11000, hashFuture) == true);
  minx->updatePoWSpendCache(12000);
  BOOST_TEST(isSpecificPoWAccepted(11000, hashFuture) == false,
             "History must survive lag jump");
}

BOOST_AUTO_TEST_CASE(TestFullHistoryReplayAfterCrash) {
  struct PersistedStamp {
    uint64_t time;
    minx::Hash solution;
  };
  std::vector<PersistedStamp> db;
  const uint64_t START_TIME = 10000;
  uint64_t currentTime = START_TIME;
  for (int i = 0; i < 10; ++i) {
    currentTime = START_TIME + (i * 1000);
    minx->updatePoWSpendCache(currentTime);
    for (int offset = 100; offset < 1000; offset += 200) {
      uint64_t stampTime = currentTime + offset;
      minx::Hash solution = makeHash(++uniqueHashId);
      bool liveInsert = minx->replayPoW(stampTime, solution);
      BOOST_TEST(liveInsert == true, "Live insertion must succeed");
      db.push_back({stampTime, solution});
    }
  }
  minx->updatePoWSpendCache(0);
  const uint64_t restartTime = currentTime + 1000;
  minx->updatePoWSpendCache(restartTime);
  const uint64_t validStart = 19000;
  const uint64_t validEnd = 22000;
  int acceptedCount = 0;
  int rejectedCount = 0;
  for (const auto& record : db) {
    bool accepted = minx->replayPoW(record.time, record.solution);
    bool shouldBeValid = (record.time >= validStart && record.time < validEnd);
    if (shouldBeValid) {
      BOOST_TEST(accepted == true, "Valid history (time "
                                     << record.time
                                     << ") should be accepted after restart");
      acceptedCount++;
    } else {
      BOOST_TEST(accepted == false, "Stale history (time "
                                      << record.time
                                      << ") should be rejected after restart");
      rejectedCount++;
    }
  }
  BOOST_TEST(acceptedCount == 5,
             "Should have preserved exactly the last bucket's worth of data");
  BOOST_TEST(rejectedCount == 45, "Should have discarded the 9 older buckets");
}

BOOST_AUTO_TEST_SUITE_END()