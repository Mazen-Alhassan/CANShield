#include "canshield/message_catalog.hpp"
#include "test_framework.hpp"

using namespace canshield;

TEST_CASE("MessageCatalog finds a known id and rejects an unknown one") {
    MessageCatalog cat;
    MessageDef m;
    m.id = 0x123;
    m.dlc = 8;
    cat.add(m);

    CHECK_TRUE(cat.known(0x123));
    CHECK_TRUE(cat.find(0x123) != nullptr);
    CHECK_EQ(cat.find(0x123)->dlc, 8);
    CHECK_FALSE(cat.known(0x456));
    CHECK_TRUE(cat.find(0x456) == nullptr);
    CHECK_EQ(cat.size(), static_cast<std::size_t>(1));
}

TEST_CASE("MessageCatalog re-adding an id replaces the earlier definition") {
    MessageCatalog cat;
    MessageDef a;
    a.id = 0x10;
    a.dlc = 4;
    cat.add(a);
    MessageDef b;
    b.id = 0x10;
    b.dlc = 8;
    cat.add(b);

    // by_id_ points at the latest entry for a repeated id.
    CHECK_EQ(cat.find(0x10)->dlc, 8);
    // both definitions still live in messages(), so size grows even on overwrite.
    CHECK_EQ(cat.size(), static_cast<std::size_t>(2));
}

TEST_CASE("MessageDef::period_us converts ms to us, aperiodic stays zero") {
    MessageDef m;
    m.period_ms = 20;
    CHECK_EQ(m.period_us(), static_cast<std::uint64_t>(20000));

    MessageDef aperiodic;
    aperiodic.period_ms = 0;
    CHECK_EQ(aperiodic.period_us(), static_cast<std::uint64_t>(0));
}

TEST_CASE("SignalDef::in_range is inclusive of both bounds") {
    SignalDef s{"S", 0, 8, 1.0, 0.0, 10.0, 20.0, ""};
    CHECK_TRUE(s.in_range(10.0));
    CHECK_TRUE(s.in_range(20.0));
    CHECK_TRUE(s.in_range(15.0));
    CHECK_FALSE(s.in_range(9.999));
    CHECK_FALSE(s.in_range(20.001));
}

int main() { return canshield::test::run_all(); }
