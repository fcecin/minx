#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <cstring>
#include <minx/minx.h>
#include <vector>

// --- Mocks and Helpers ---

namespace {

// A dummy listener since Minx constructor requires one
class MockListener : public minx::MinxListener {
public:
  // We don't need to implement logic here for these specific tests
};

// Helper to generate unique Hashes so we don't trigger "Double Spend"
// errors when we are actually testing "Time Validity".
minx::Hash makeHash(uint64_t id) {
  minx::Hash h;
  // Fill hash with 0
  std::fill(h.begin(), h.end(), 0);
  // Copy ID into the beginning of the hash
  std::memcpy(h.data(), &id, sizeof(id));
  return h;
}

struct MinxFixture {
  MockListener listener;
  // Slot size = 1000 seconds for easy math
  const uint64_t SLOT_SIZE = 1000;
  // RandomX threads = 0 (we aren't testing mining)
  std::unique_ptr<minx::Minx> minx;
  uint64_t uniqueHashId = 0;

  MinxFixture() {
    // Create Minx with 1000s slot size
    minx = std::make_unique<minx::Minx>(&listener, 0, SLOT_SIZE);
  }

  // Helper to check if a specific time is accepted by the window
  bool isTimeAccepted(uint64_t t) {
    // Always use a fresh, unique hash to avoid "Duplicate" rejections
    return minx->replayPoW(t, makeHash(++uniqueHashId));
  }

  // Helper to check if a specific hash is accepted (for duplicate testing)
  bool isSpecificPoWAccepted(uint64_t t, const minx::Hash& h) {
    return minx->replayPoW(t, h);
  }
};

} // namespace

// --- Test Cases ---

BOOST_FIXTURE_TEST_SUITE(MinxPoWCacheSuite, MinxFixture)

BOOST_AUTO_TEST_CASE(TestInitializationWindow) {
  // Initialize at time = 10,000
  // Current Slot starts at 10,000.
  // Expected Window: [Previous(9000), Current(10000), Next(11000)]
  // Range: [9000, 12000)
  minx->updatePoWDoubleSpendCache(10000);

  // 1. Test Valid Range
  BOOST_TEST(isTimeAccepted(10000) == true, "Current time should be accepted");
  BOOST_TEST(isTimeAccepted(10500) == true,
             "Mid-current slot should be accepted");

  // 2. Test Previous Slot Tolerance (-1 slot)
  BOOST_TEST(isTimeAccepted(9000) == true,
             "Previous slot start should be accepted");
  BOOST_TEST(isTimeAccepted(9999) == true,
             "Previous slot end should be accepted");

  // 3. Test Future Tolerance (+1 slot)
  BOOST_TEST(isTimeAccepted(11000) == true,
             "Next slot start should be accepted");
  BOOST_TEST(isTimeAccepted(11999) == true, "Next slot end should be accepted");

  // 4. Test Out of Bounds (Too Old)
  BOOST_TEST(isTimeAccepted(8999) == false,
             "Time before previous slot should be rejected");

  // 5. Test Out of Bounds (Too Future)
  BOOST_TEST(isTimeAccepted(12000) == false,
             "Time after next slot should be rejected");
}

BOOST_AUTO_TEST_CASE(TestNormalSlide) {
  // Start at 10,000
  minx->updatePoWDoubleSpendCache(10000);

  // Move forward 1 slot to 11,000
  // New Current: 11,000
  // New Window: [10000, 11000, 12000]
  // Range: [10000, 13000)
  minx->updatePoWDoubleSpendCache(11000);

  // 1. Verify 9000 (Old Previous) is now dropped
  BOOST_TEST(isTimeAccepted(9000) == false, "Slot T-2 should now be dropped");
  BOOST_TEST(isTimeAccepted(9999) == false);

  // 2. Verify 10000 is still valid (now Previous)
  BOOST_TEST(isTimeAccepted(10000) == true);

  // 3. Verify 12000 is now valid (new Next)
  BOOST_TEST(isTimeAccepted(12000) == true,
             "New future slot should be accepted");
}

BOOST_AUTO_TEST_CASE(TestMicroSlide) {
  // Start at 10,000
  minx->updatePoWDoubleSpendCache(10000);

  // Move forward slightly (within same slot)
  minx->updatePoWDoubleSpendCache(10500);

  // Window should not change: [9000, 10000, 11000]
  BOOST_TEST(isTimeAccepted(9000) == true);
  BOOST_TEST(isTimeAccepted(11999) == true);
}

BOOST_AUTO_TEST_CASE(TestGapReset) {
  // Start at 10,000. Valid: [9000...12000)
  minx->updatePoWDoubleSpendCache(10000);
  BOOST_TEST(isTimeAccepted(10000) == true);

  // Massive Jump to 50,000 (System Sleep / Restart)
  // New Current: 50,000
  // New Window: [49000, 50000, 51000]
  minx->updatePoWDoubleSpendCache(50000);

  // 1. Old data should be gone
  BOOST_TEST(isTimeAccepted(10000) == false, "Old data should be wiped on gap");
  BOOST_TEST(isTimeAccepted(11000) == false);

  // 2. New window should be active
  BOOST_TEST(isTimeAccepted(49000) == true, "New Previous accepted");
  BOOST_TEST(isTimeAccepted(50000) == true, "New Current accepted");
  BOOST_TEST(isTimeAccepted(51000) == true, "New Next accepted");
}

BOOST_AUTO_TEST_CASE(TestLagCatchup) {
  // Scenario where we drift 2 slots but not enough for a full reset
  // Start: 10,000. Window: [9000, 10000, 11000]
  minx->updatePoWDoubleSpendCache(10000);

  // Move to 12,000 (Skipped 11,000 entirely)
  // New Current: 12,000.
  // Target Base (Previous): 11,000.
  // Target End: 11,000 + 3000 = 14,000.
  // Check overlap against old: [9000 + 3000 = 12000].
  // Target Base (11000) < Old End (12000). OVERLAP EXISTS.
  // Code should slide, not reset.
  minx->updatePoWDoubleSpendCache(12000);

  // New Window should be: [11000, 12000, 13000]

  // 10,000 should be dropped (it is now T-2)
  BOOST_TEST(isTimeAccepted(10000) == false);

  // 11,000 should be active (now Previous)
  BOOST_TEST(isTimeAccepted(11000) == true);

  // 13,000 should be active (new Next)
  BOOST_TEST(isTimeAccepted(13000) == true);
}

BOOST_AUTO_TEST_CASE(TestBucketPersistence) {
  // 1. Initialize at 10,000. Window: [9000, 10000, 11000]
  minx->updatePoWDoubleSpendCache(10000);

  // 2. Insert a specific PoW into the "Current" bucket (10,000)
  minx::Hash hashA = makeHash(100);
  BOOST_TEST(isSpecificPoWAccepted(10000, hashA) == true,
             "First insert should succeed");

  // 3. Verify Double-Spend logic immediately
  BOOST_TEST(isSpecificPoWAccepted(10000, hashA) == false,
             "Immediate duplicate should fail");

  // 4. Insert a specific PoW into the "Next" bucket (11,000)
  minx::Hash hashB = makeHash(200);
  BOOST_TEST(isSpecificPoWAccepted(11000, hashB) == true);

  // --- SLIDE THE WINDOW ---
  // Advance time to 11,000.
  // Old "Current" (10000) becomes "Previous".
  // Old "Next" (11000) becomes "Current".
  // Old "Previous" (9000) is dropped.
  // CRITICAL: The buckets for 10000 and 11000 must be PRESERVED, not cleared.
  minx->updatePoWDoubleSpendCache(11000);

  // 5. Verify Persistence of HashA (now in Previous bucket)
  // If the slide logic incorrectly cleared the deque, this would return TRUE
  // (Fail).
  BOOST_TEST(isSpecificPoWAccepted(10000, hashA) == false,
             "Duplicate in slided bucket should still fail");

  // 6. Verify Persistence of HashB (now in Current bucket)
  BOOST_TEST(isSpecificPoWAccepted(11000, hashB) == false,
             "Duplicate in slided bucket should still fail");

  // 7. Verify we can still add NEW items to those buckets
  BOOST_TEST(isTimeAccepted(10000) == true,
             "New item in Previous bucket should succeed");
  BOOST_TEST(isTimeAccepted(11000) == true,
             "New item in Current bucket should succeed");
}

BOOST_AUTO_TEST_CASE(TestLagCatchupPersistence) {
  // Start: 10,000. Window: [9000, 10000, 11000]
  minx->updatePoWDoubleSpendCache(10000);

  // Insert hash into 11,000 (Future bucket)
  minx::Hash hashFuture = makeHash(300);
  BOOST_TEST(isSpecificPoWAccepted(11000, hashFuture) == true);

  // Lag Jump to 12,000.
  // Window becomes [11000, 12000, 13000]
  // 11,000 should move from "Next" to "Previous". It must NOT be wiped.
  minx->updatePoWDoubleSpendCache(12000);

  // Verify 11,000 bucket history survived the lag jump
  BOOST_TEST(isSpecificPoWAccepted(11000, hashFuture) == false,
             "History must survive lag jump");
}

BOOST_AUTO_TEST_CASE(TestFullHistoryReplayAfterCrash) {
  // --- PHASE 1: Run and Accumulate History ---

  // We will store all persisted stamps here (our "Database")
  struct PersistedStamp {
    uint64_t time;
    minx::Hash solution;
  };
  std::vector<PersistedStamp> db;

  const uint64_t START_TIME = 10000;
  uint64_t currentTime = START_TIME;

  // Slide 10 times (10 buckets: 10,000 to 19,000)
  for (int i = 0; i < 10; ++i) {
    currentTime = START_TIME + (i * 1000);

    // Update Minx to this time
    minx->updatePoWDoubleSpendCache(currentTime);

    // Insert 5 items per bucket, 200s apart
    // Offsets: +100, +300, +500, +700, +900
    for (int offset = 100; offset < 1000; offset += 200) {
      uint64_t stampTime = currentTime + offset;
      minx::Hash solution = makeHash(++uniqueHashId);

      // 1. Insert into Minx (simulating live traffic)
      bool liveInsert = minx->replayPoW(stampTime, solution);
      BOOST_TEST(liveInsert == true, "Live insertion must succeed");

      // 2. Persist to DB
      db.push_back({stampTime, solution});
    }
  }

  // At this point:
  // Current Time: 19,000
  // Minx Window: [18000 (Prev), 19000 (Curr), 20000 (Next)]
  // DB contains stamps from 10,000 up to 19,900.

  // --- PHASE 2: The Crash ---

  // Force destruction of all buckets by jumping to Epoch 0.
  // This simulates the server process dying and losing RAM.
  minx->updatePoWDoubleSpendCache(0); // or just create a new Minx object

  // --- PHASE 3: The Restart ---

  // Restart the server 1 hour (1 slot) AFTER the last known time.
  // Last known time was 19,000. We wake up at 20,000.
  const uint64_t restartTime = currentTime + 1000; // 20,000
  minx->updatePoWDoubleSpendCache(restartTime);

  // CALCULATE EXPECTED WINDOW:
  // Restart Time: 20,000
  // Current Slot: 20,000
  // Window Base (Previous): 19,000
  // Window End (Exclusive): 22,000 (Base + 3 slots: 19k, 20k, 21k)
  // Valid Range: [19000, 22000)
  const uint64_t validStart = 19000;
  const uint64_t validEnd = 22000;

  // --- PHASE 4: Replay and Verify ---

  // We replay EVERY stamp from the DB.
  // Minx should accept the ones in the new window and reject the old ones.

  int acceptedCount = 0;
  int rejectedCount = 0;

  for (const auto& record : db) {
    // Attempt to restore state
    bool accepted = minx->replayPoW(record.time, record.solution);

    // Determine if it *should* be accepted based on our external logic
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

  // Sanity check counts
  // We had 10 buckets (10k...19k) with 5 items each = 50 total items.
  // Only the 19k bucket (5 items) falls into the new [19k, 22k) window.
  BOOST_TEST(acceptedCount == 5,
             "Should have preserved exactly the last bucket's worth of data");
  BOOST_TEST(rejectedCount == 45, "Should have discarded the 9 older buckets");
}

BOOST_AUTO_TEST_SUITE_END()