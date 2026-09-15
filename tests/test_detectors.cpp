#include <set>
#include <string>
#include <vector>

#include "canshield/attack_injector.hpp"
#include "canshield/ecu_simulator.hpp"
#include "canshield/proprietary_protocol.hpp"
#include "canshield/security_monitor.hpp"
#include "test_framework.hpp"

using namespace canshield;

static std::vector<CanFrame> benign_trace(double seconds) {
    EcuSimulator sim(default_catalog());
    std::vector<CanFrame> v;
    sim.generate(static_cast<std::uint64_t>(seconds * 1e6),
                 [&](const CanFrame& f) { v.push_back(f); });
    return v;
}

// run a scenario, return the set of detector names that fired inside the window
static std::set<std::string> detectors_fired(AttackType t) {
    auto benign = benign_trace(6.0);
    AttackInjector inj(default_catalog());
    Scenario sc = inj.inject(t, benign, 2'000'000, 3'000'000);

    SecurityMonitor mon(default_catalog());
    for (auto& lf : sc.frames) mon.process(lf.frame);

    std::set<std::string> fired;
    for (auto& a : mon.alerts())
        if (a.timestamp_us >= sc.window_start_us && a.timestamp_us < sc.window_end_us)
            fired.insert(a.detector);
    return fired;
}

TEST_CASE("clean traffic produces essentially no alerts (low false positives)") {
    auto benign = benign_trace(10.0);
    SecurityMonitor mon(default_catalog());
    for (auto& f : benign) mon.process(f);
    // a handful tolerated for warm-up; must be far below traffic volume
    CHECK_TRUE(mon.alerts_raised() < benign.size() / 1000);
}

TEST_CASE("checksum tamper is caught by the checksum detector") {
    auto f = detectors_fired(AttackType::ChecksumTamper);
    CHECK_TRUE(f.count("checksum") > 0);
}

TEST_CASE("flood is caught by rate/unknown-id detectors") {
    auto f = detectors_fired(AttackType::Flood);
    CHECK_TRUE(f.count("rate") > 0 || f.count("unknown_id") > 0);
}

TEST_CASE("fuzz is caught (unknown id / protocol / checksum)") {
    auto f = detectors_fired(AttackType::Fuzz);
    CHECK_TRUE(f.count("unknown_id") > 0 || f.count("protocol") > 0 ||
               f.count("checksum") > 0);
}

TEST_CASE("diagnostic abuse is caught by the diagnostic detector") {
    auto f = detectors_fired(AttackType::DiagAbuse);
    CHECK_TRUE(f.count("diagnostic") > 0 || f.count("rate") > 0);
}

TEST_CASE("rpm spoof is caught (timing / range / counter)") {
    auto f = detectors_fired(AttackType::RpmSpoof);
    CHECK_TRUE(f.count("timing") > 0 || f.count("range") > 0 ||
               f.count("counter") > 0);
}

TEST_CASE("replay is caught (counter / timing)") {
    auto f = detectors_fired(AttackType::Replay);
    CHECK_TRUE(f.count("counter") > 0 || f.count("timing") > 0);
}

TEST_CASE("wheel masquerade is caught (counter / timing / range)") {
    auto f = detectors_fired(AttackType::WheelMasquerade);
    CHECK_TRUE(!f.empty());
}

TEST_CASE("bus-off storm is caught by the protocol detector") {
    auto f = detectors_fired(AttackType::BusOff);
    CHECK_TRUE(f.count("protocol") > 0);
}

TEST_CASE("adversarial injection is caught by the timing detector") {
    auto f = detectors_fired(AttackType::AdversarialInject);
    CHECK_TRUE(f.count("timing") > 0 || f.count("counter") > 0);
}

TEST_CASE("per-frame detection latency stays well under 1ms") {
    auto benign = benign_trace(10.0);
    SecurityMonitor mon(default_catalog());
    for (auto& f : benign) mon.process(f);
    // p99 detection latency < 1ms (1e6 ns) is the headline requirement
    CHECK_TRUE(mon.latency().percentile_ns(0.99) < 1'000'000ull);
}

// the tests above run whole attack scenarios through the full chain; these
// exercise individual detectors directly, in isolation, against hand-built
// frames so each detector's own trigger condition is pinned down.

TEST_CASE("ProtocolDetector flags a dlc mismatch against the catalog") {
    MessageCatalog cat = default_catalog();
    ProtocolDetector pd(cat);
    CanFrame f;
    f.id = 0x100;  // PT_EngineData expects dlc 8
    f.dlc = 4;
    std::vector<Alert> out;
    pd.inspect(f, out);
    CHECK_TRUE(!out.empty());
}

TEST_CASE("RangeDetector flags a signal value outside its physical range") {
    MessageCatalog cat = default_catalog();
    RangeDetector rd(cat);
    CanFrame f;
    f.id = 0x100;
    f.dlc = 8;
    f.set_be(0, 2, 40000);  // EngineRPM raw*0.25 = 10000, above the 8000 max
    std::vector<Alert> out;
    rd.inspect(f, out);
    CHECK_TRUE(!out.empty());
}

TEST_CASE("TimingDetector flags an arrival faster than tolerance allows") {
    MessageCatalog cat = default_catalog();
    TimingDetector td(cat);
    CanFrame f;
    f.id = 0x400;  // IC_VehicleSpeed, 20ms period
    f.dlc = 4;
    std::vector<Alert> out;
    f.timestamp_us = 0;
    td.inspect(f, out);
    CHECK_TRUE(out.empty());  // no prior arrival to compare against yet

    f.timestamp_us = 1000;  // 1ms later, well under the 10ms tolerance floor
    td.inspect(f, out);
    CHECK_TRUE(!out.empty());
}

TEST_CASE("UnknownIdDetector flags an id absent from the bus matrix") {
    MessageCatalog cat = default_catalog();
    UnknownIdDetector ud(cat);
    CanFrame known;
    known.id = 0x100;  // present in the default catalog
    std::vector<Alert> out;
    ud.inspect(known, out);
    CHECK_TRUE(out.empty());

    CanFrame unknown;
    unknown.id = 0x999;  // not present
    ud.inspect(unknown, out);
    CHECK_TRUE(!out.empty());
}

TEST_CASE("CounterDetector flags a rolling counter that skips") {
    MessageCatalog cat = default_catalog();
    const MessageDef* m = nullptr;
    for (auto& kv : cat.messages()) if (kv.has_integrity) { m = &kv; break; }
    CHECK_TRUE(m != nullptr);

    CounterDetector cd(cat);
    CanFrame f;
    f.id = m->id;
    f.dlc = m->dlc;
    proto::set_rolling_counter(f, m->dlc, 0);
    std::vector<Alert> out;
    cd.inspect(f, out);
    CHECK_TRUE(out.empty());  // first frame just seeds the counter

    proto::set_rolling_counter(f, m->dlc, 5);  // skips ahead instead of 0->1
    cd.inspect(f, out);
    CHECK_TRUE(!out.empty());
}

int main() { return canshield::test::run_all(); }
