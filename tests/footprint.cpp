// The memory and the threads of a Minx: its spam filter has the width of
// its config, and its PoW worker thread starts only with the first PoW
// engine. A client that only carries RUDP needs neither the wide filter of
// a server nor the worker. Linux only: the tests read /proc/self/status.

#ifdef __linux__

#include <boost/test/unit_test.hpp>

#include <minx/minx.h>

#include <malloc.h>

#include <fstream>
#include <string>

namespace {

class Listener : public minx::MinxListener {};

// A field of /proc/self/status, in its unit (kB for VmRSS).
long statusField(const std::string& name) {
  std::ifstream f("/proc/self/status");
  std::string line;
  while (std::getline(f, line))
    if (line.rfind(name + ":", 0) == 0)
      return std::stol(line.substr(name.size() + 1));
  return -1;
}

minx::MinxConfig smallRing(size_t width) {
  minx::MinxConfig c{};
  c.recvBuffersSize = 16;
  c.spamFilterWidth = width;
  return c;
}

// The growth of the RSS while a Minx with this filter width exists.
long rssGrowthKb(size_t width) {
  // Big blocks come from mmap, so each Minx gets fresh pages and its
  // counters show in the RSS.
  mallopt(M_MMAP_THRESHOLD, 64 * 1024);
  Listener l;
  const long before = statusField("VmRSS");
  minx::Minx m(&l, smallRing(width));
  return statusField("VmRSS") - before;
}

} // namespace

BOOST_AUTO_TEST_SUITE(MinxFootprintSuite)

// The default filter (for a server) costs about 12MB. A narrow one (for a
// client) costs almost nothing.
BOOST_AUTO_TEST_CASE(TestSpamFilterWidth) {
  const long narrow = rssGrowthKb(1000);
  const long wide = rssGrowthKb(minx::MinxConfig::DEFAULT_SPAM_FILTER_WIDTH);
  BOOST_TEST(narrow < 2048, "narrow filter: " << narrow << " kB");
  BOOST_TEST(wide > 10 * 1024, "wide filter: " << wide << " kB");
}

// A Minx that makes no PoW engine runs no worker thread.
BOOST_AUTO_TEST_CASE(TestNoWorkerWithoutPoW) {
  Listener l;
  const long before = statusField("Threads");
  {
    minx::Minx m(&l, smallRing(1000));
    BOOST_TEST(statusField("Threads") == before);
  }
  BOOST_TEST(statusField("Threads") == before);
}

BOOST_AUTO_TEST_SUITE_END()

#endif
