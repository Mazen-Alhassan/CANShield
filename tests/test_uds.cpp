#include <atomic>
#include <thread>

#include "canshield/message_catalog.hpp"
#include "canshield/uds.hpp"
#include "canshield/virtual_bus.hpp"
#include "test_framework.hpp"

using namespace canshield;

TEST_CASE("single frame pack/parse round-trip") {
    auto f = uds::pack_single_frame(0x7E0, {0x27, 0x01});
    auto p = uds::parse_single_frame(f);
    CHECK_EQ(p.size(), std::size_t(2));
    CHECK_EQ(p[0], 0x27);
    CHECK_EQ(p[1], 0x01);
}

TEST_CASE("empty payload pack/parse round-trip is a no-op") {
    auto f = uds::pack_single_frame(0x7E0, {});
    auto p = uds::parse_single_frame(f);
    CHECK_EQ(p.size(), std::size_t(0));
}

TEST_CASE("recovered key algorithm matches the ecu") {
    // full unlock flow over a virtual bus
    auto bus = VirtualCanBus::create();
    auto ecu_tx = bus->attach("ecu");
    auto att_tx = bus->attach("att");
    std::atomic<bool> stop{false};
    uds::UdsEcu ecu(diag::kObdPhysicalRequest, diag::kObdResponse, 0xBEEF);
    std::thread t([&] { ecu.run(ecu_tx, &stop); });

    uds::UdsClient c(att_tx, diag::kObdPhysicalRequest, diag::kObdResponse);

    // locked: reset is denied
    auto r = c.request({uds::kEcuReset, 0x01});
    CHECK_EQ(r[0], uds::kNegative);

    // get seed, compute key, unlock
    r = c.request({uds::kSecurityAccess, 0x01});
    std::uint16_t seed = (r[2] << 8) | r[3];
    std::uint16_t key = uds::key_from_seed(seed);
    r = c.request({uds::kSecurityAccess, 0x02,
                   static_cast<std::uint8_t>(key >> 8),
                   static_cast<std::uint8_t>(key & 0xFF)});
    CHECK_EQ(r[0], uds::kSecurityAccess + uds::kPositive);

    // unlocked: reset now accepted
    r = c.request({uds::kEcuReset, 0x01});
    CHECK_EQ(r[0], uds::kEcuReset + uds::kPositive);

    stop = true;
    t.join();
}

TEST_CASE("wrong key is rejected") {
    auto bus = VirtualCanBus::create();
    auto ecu_tx = bus->attach("ecu");
    auto att_tx = bus->attach("att");
    std::atomic<bool> stop{false};
    uds::UdsEcu ecu(diag::kObdPhysicalRequest, diag::kObdResponse, 0x1111);
    std::thread t([&] { ecu.run(ecu_tx, &stop); });

    uds::UdsClient c(att_tx, diag::kObdPhysicalRequest, diag::kObdResponse);
    c.request({uds::kSecurityAccess, 0x01});
    auto r = c.request({uds::kSecurityAccess, 0x02, 0x00, 0x00});  // bad key
    CHECK_EQ(r[0], uds::kNegative);
    CHECK_EQ(r[2], uds::kNrcInvalidKey);

    stop = true;
    t.join();
}

int main() { return canshield::test::run_all(); }
