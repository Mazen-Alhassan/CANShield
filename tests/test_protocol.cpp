#include "canshield/ecu_simulator.hpp"
#include "canshield/message_catalog.hpp"
#include "canshield/proprietary_protocol.hpp"
#include "test_framework.hpp"

using namespace canshield;

TEST_CASE("signal bit codec round-trips a physical value") {
    SignalDef rpm{"EngineRPM", 0, 16, 0.25, 0.0, 0.0, 8000.0, "rpm"};
    CanFrame f;
    f.dlc = 8;
    rpm.pack_phys(f, 2500.0);
    CHECK_TRUE(std::abs(rpm.extract_phys(f) - 2500.0) < 0.25);
}

TEST_CASE("12-bit signals pack without clobbering neighbors") {
    SignalDef fl{"WheelSpeedFL", 0, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"};
    SignalDef fr{"WheelSpeedFR", 12, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"};
    CanFrame f;
    f.dlc = 8;
    fl.pack_phys(f, 100.0);
    fr.pack_phys(f, 50.0);
    CHECK_TRUE(std::abs(fl.extract_phys(f) - 100.0) < 0.0625);
    CHECK_TRUE(std::abs(fr.extract_phys(f) - 50.0) < 0.0625);
}

TEST_CASE("proprietary checksum detects a single-bit payload change") {
    CanFrame f(0x100, 8, {0x10, 0x20, 0x30, 0x40, 0x50, 0x00, 0x00, 0x00});
    proto::apply_integrity(f, 8, 3);
    CHECK_TRUE(proto::checksum_valid(f, 8));
    CHECK_EQ(proto::rolling_counter(f, 8), 3);

    f.data[2] ^= 0x01;  // tamper
    CHECK_FALSE(proto::checksum_valid(f, 8));
}

TEST_CASE("rolling counter succession") {
    CHECK_TRUE(proto::counter_follows(3, 4));
    CHECK_TRUE(proto::counter_follows(15, 0));  // wraps mod 16
    CHECK_FALSE(proto::counter_follows(3, 5));  // skipped
    CHECK_FALSE(proto::counter_follows(3, 3));  // repeat
}

TEST_CASE("simulator produces well-formed, valid frames for known ids") {
    EcuSimulator sim(default_catalog());
    std::uint64_t good = 0, total = 0;
    sim.generate(1'000'000, [&](const CanFrame& f) {
        ++total;
        const MessageDef* m = sim.catalog().find(f.id);
        CHECK_TRUE(m != nullptr);
        CHECK_TRUE(f.is_well_formed());
        if (m && m->has_integrity) {
            if (proto::checksum_valid(f, m->dlc)) ++good;
        }
    });
    CHECK_TRUE(total > 0);
    CHECK_EQ(good, total ? good : 0);  // every integrity frame must be valid
    CHECK_TRUE(good > 0);
}

TEST_CASE("counter actually increments across successive frames of an id") {
    EcuSimulator sim(default_catalog());
    std::vector<std::uint8_t> seen;
    sim.generate(200'000, [&](const CanFrame& f) {
        if (f.id == 0x100) seen.push_back(proto::rolling_counter(f, 8));
    });
    CHECK_TRUE(seen.size() >= 3);
    // consecutive frames follow the mod-16 succession
    bool ok = true;
    for (std::size_t i = 1; i < seen.size(); ++i)
        if (!proto::counter_follows(seen[i - 1], seen[i])) ok = false;
    CHECK_TRUE(ok);
}

int main() { return canshield::test::run_all(); }
