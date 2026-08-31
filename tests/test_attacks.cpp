#include <vector>

#include "canshield/attack_injector.hpp"
#include "canshield/ecu_simulator.hpp"
#include "canshield/proprietary_protocol.hpp"
#include "test_framework.hpp"

using namespace canshield;

static std::vector<CanFrame> benign_trace(double seconds) {
    EcuSimulator sim(default_catalog());
    std::vector<CanFrame> v;
    sim.generate(static_cast<std::uint64_t>(seconds * 1e6),
                 [&](const CanFrame& f) { v.push_back(f); });
    return v;
}

TEST_CASE("every attack type injects malicious frames in-window") {
    auto benign = benign_trace(5.0);
    AttackInjector inj(default_catalog());
    AttackType types[] = {
        AttackType::RpmSpoof,        AttackType::Replay,
        AttackType::Flood,           AttackType::Fuzz,
        AttackType::DiagAbuse,       AttackType::WheelMasquerade,
        AttackType::SpeedFreeze,     AttackType::ChecksumTamper,
        AttackType::BusOff,          AttackType::AdversarialInject};
    for (auto t : types) {
        Scenario sc = inj.inject(t, benign, 2'000'000, 3'000'000);
        CHECK_TRUE(sc.attack_count > 0);
        CHECK_TRUE(sc.benign_count > 0);
        // frames stay timestamp-sorted after merge
        bool sorted = true;
        for (std::size_t i = 1; i < sc.frames.size(); ++i)
            if (sc.frames[i].frame.timestamp_us <
                sc.frames[i - 1].frame.timestamp_us)
                sorted = false;
        CHECK_TRUE(sorted);
    }
}

TEST_CASE("flood raises frame rate massively inside the window") {
    auto benign = benign_trace(5.0);
    AttackInjector inj(default_catalog());
    Scenario sc = inj.inject(AttackType::Flood, benign, 2'000'000, 3'000'000);
    int flood = 0;
    for (auto& lf : sc.frames)
        if (lf.label == AttackType::Flood) ++flood;
    CHECK_TRUE(flood >= 900);  // ~1000 frames at 1ms over 1s
}

TEST_CASE("checksum tamper breaks the proprietary checksum") {
    auto benign = benign_trace(5.0);
    AttackInjector inj(default_catalog());
    Scenario sc = inj.inject(AttackType::ChecksumTamper, benign, 2'000'000, 3'000'000);
    int bad = 0;
    for (auto& lf : sc.frames)
        if (lf.label == AttackType::ChecksumTamper)
            if (!proto::checksum_valid(lf.frame, 8)) ++bad;
    CHECK_TRUE(bad > 0);  // tampered frames now fail checksum
}

TEST_CASE("masquerade silences the real ABS ECU in-window") {
    auto benign = benign_trace(5.0);
    AttackInjector inj(default_catalog());
    Scenario sc = inj.inject(AttackType::WheelMasquerade, benign, 2'000'000, 3'000'000);
    int real_in_window = 0, fake_in_window = 0;
    for (auto& lf : sc.frames) {
        if (lf.frame.id != 0x200) continue;
        bool inw = lf.frame.timestamp_us >= 2'000'000 &&
                   lf.frame.timestamp_us < 3'000'000;
        if (!inw) continue;
        if (lf.is_attack()) ++fake_in_window; else ++real_in_window;
    }
    CHECK_EQ(real_in_window, 0);   // real ECU is silenced
    CHECK_TRUE(fake_in_window > 0);  // impostor took over
}

int main() { return canshield::test::run_all(); }
