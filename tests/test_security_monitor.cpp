#include "canshield/message_catalog.hpp"
#include "canshield/security_monitor.hpp"
#include "test_framework.hpp"

using canshield::Alert;
using canshield::CanFrame;
using canshield::IDetector;
using canshield::LatencyStats;
using canshield::SecurityMonitor;

namespace {
// always raises exactly one alert per inspected frame, independent of any
// catalog, so SecurityMonitor's own bookkeeping can be tested in isolation.
struct AlwaysFiresDetector : IDetector {
    const char* name() const override { return "always_fires"; }
    void inspect(const CanFrame& f, std::vector<Alert>& out) override {
        out.push_back(Alert{f.timestamp_us, f.id, name(), "test", canshield::Severity::Low});
    }
};
}  // namespace

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

TEST_CASE("SecurityMonitor with no detectors added processes frames but raises nothing") {
    SecurityMonitor mon(canshield::default_catalog(), /*with_defaults=*/false);
    CanFrame f;
    CHECK_EQ(mon.process(f), std::size_t(0));
    CHECK_EQ(mon.frames_processed(), std::uint64_t(1));
    CHECK_EQ(mon.alerts_raised(), std::uint64_t(0));
}

TEST_CASE("SecurityMonitor accumulates alerts and invokes the sink") {
    SecurityMonitor mon(canshield::default_catalog(), /*with_defaults=*/false);
    mon.add_detector(std::make_unique<AlwaysFiresDetector>());
    int sink_calls = 0;
    mon.set_sink([&](const Alert&) { ++sink_calls; });

    CanFrame f;
    CHECK_EQ(mon.process(f), std::size_t(1));
    CHECK_EQ(mon.process(f), std::size_t(1));

    CHECK_EQ(mon.frames_processed(), std::uint64_t(2));
    CHECK_EQ(mon.alerts_raised(), std::uint64_t(2));
    CHECK_EQ(mon.alerts().size(), std::size_t(2));
    CHECK_EQ(sink_calls, 2);
}

TEST_CASE("SecurityMonitor::set_store_alerts(false) still counts but drops history") {
    SecurityMonitor mon(canshield::default_catalog(), /*with_defaults=*/false);
    mon.add_detector(std::make_unique<AlwaysFiresDetector>());
    mon.set_store_alerts(false);

    CanFrame f;
    mon.process(f);
    CHECK_EQ(mon.alerts_raised(), std::uint64_t(1));
    CHECK_TRUE(mon.alerts().empty());
}

TEST_CASE("SecurityMonitor::reset clears counters, history and latency") {
    SecurityMonitor mon(canshield::default_catalog(), /*with_defaults=*/false);
    mon.add_detector(std::make_unique<AlwaysFiresDetector>());

    CanFrame f;
    mon.process(f);
    mon.reset();

    CHECK_EQ(mon.frames_processed(), std::uint64_t(0));
    CHECK_EQ(mon.alerts_raised(), std::uint64_t(0));
    CHECK_TRUE(mon.alerts().empty());
    CHECK_EQ(mon.latency().count(), std::size_t(0));
}

int main() { return canshield::test::run_all(); }
