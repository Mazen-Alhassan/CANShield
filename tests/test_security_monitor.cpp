#include "canshield/security_monitor.hpp"
#include "test_framework.hpp"

using canshield::LatencyStats;

TEST_CASE("LatencyStats with no samples reports zero for everything") {
    LatencyStats s;
    CHECK_EQ(s.count(), std::size_t(0));
    CHECK_EQ(s.max_ns(), std::uint64_t(0));
    CHECK_EQ(s.mean_ns(), 0.0);
    CHECK_EQ(s.percentile_ns(0.5), std::uint64_t(0));
}

TEST_CASE("LatencyStats tracks count, max and mean across samples") {
    LatencyStats s;
    s.add(10);
    s.add(30);
    s.add(20);
    CHECK_EQ(s.count(), std::size_t(3));
    CHECK_EQ(s.max_ns(), std::uint64_t(30));
    CHECK_EQ(s.mean_ns(), 20.0);
}

TEST_CASE("LatencyStats::percentile_ns clamps p<=0 and p>=1 to the extremes") {
    LatencyStats s;
    s.add(30);
    s.add(10);
    s.add(20);
    CHECK_EQ(s.percentile_ns(0.0), std::uint64_t(10));
    CHECK_EQ(s.percentile_ns(-1.0), std::uint64_t(10));
    CHECK_EQ(s.percentile_ns(1.0), std::uint64_t(30));
    CHECK_EQ(s.percentile_ns(2.0), std::uint64_t(30));
}

TEST_CASE("LatencyStats::percentile_ns interpolates over sorted samples") {
    LatencyStats s;
    for (std::uint64_t v : {40, 10, 30, 20}) s.add(v);
    // sorted: 10,20,30,40 -> idx = size_t(p * 3 + 0.5)
    CHECK_EQ(s.percentile_ns(1.0 / 3.0), std::uint64_t(20));  // idx 1
    CHECK_EQ(s.percentile_ns(0.5), std::uint64_t(30));        // idx 2
}

TEST_CASE("LatencyStats::reset clears samples, max and mean") {
    LatencyStats s;
    s.add(5);
    s.add(15);
    s.reset();
    CHECK_EQ(s.count(), std::size_t(0));
    CHECK_EQ(s.max_ns(), std::uint64_t(0));
    CHECK_EQ(s.mean_ns(), 0.0);
}

int main() { return canshield::test::run_all(); }
