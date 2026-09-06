#include "canshield/ecu_simulator.hpp"
#include "test_framework.hpp"

using canshield::VehicleModel;

TEST_CASE("VehicleModel stays within physical ranges over a full drive cycle") {
    VehicleModel m(42);
    for (int i = 0; i < 6000; ++i) {  // 60s at 10ms steps: one full drive cycle
        m.advance(0.01);
        CHECK_TRUE(m.rpm >= 700.0 && m.rpm <= 7000.0);
        CHECK_TRUE(m.speed_kmh >= 0.0);
        CHECK_TRUE(m.throttle_pct >= 0.0 && m.throttle_pct <= 100.0);
        CHECK_TRUE(m.brake_bar >= 0.0 && m.brake_bar <= 100.0);
        CHECK_TRUE(m.gear >= 0 && m.gear <= 5);
        for (double w : m.wheel_kmh) CHECK_TRUE(w >= 0.0);
    }
}

TEST_CASE("VehicleModel coolant warms monotonically toward operating temp") {
    VehicleModel m(1);
    double prev = m.coolant_c;
    for (int i = 0; i < 100; ++i) {
        m.advance(1.0);
        CHECK_TRUE(m.coolant_c >= prev - 1e-9);
        prev = m.coolant_c;
    }
    CHECK_TRUE(m.coolant_c > 80.0);   // ~92 after 100s of warm-up
    CHECK_TRUE(m.coolant_c <= 92.0 + 1e-6);
}

int main() { return canshield::test::run_all(); }
