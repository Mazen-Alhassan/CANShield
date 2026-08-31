#include "canshield/can_frame.hpp"
#include "test_framework.hpp"

using canshield::CanFrame;

TEST_CASE("CanFrame well-formedness") {
    CanFrame f;
    f.id = 0x123;
    f.dlc = 8;
    CHECK_TRUE(f.is_well_formed());

    f.dlc = 9;  // classic CAN maxes at 8 data bytes
    CHECK_FALSE(f.is_well_formed());

    f.dlc = 8;
    f.id = 0x800;  // exceeds 11-bit standard id range
    CHECK_FALSE(f.is_well_formed());

    f.extended = true;  // now 29-bit ids are allowed
    CHECK_TRUE(f.is_well_formed());

    f.id = 0x20000000;  // exceeds 29-bit range
    CHECK_FALSE(f.is_well_formed());
}

TEST_CASE("CanFrame big-endian pack/unpack round-trip") {
    CanFrame f;
    f.dlc = 8;
    f.set_be(0, 2, 0xABCD);
    f.set_be(2, 4, 0x11223344);
    CHECK_EQ(f.data[0], 0xAB);
    CHECK_EQ(f.data[1], 0xCD);
    CHECK_EQ(f.data[2], 0x11);
    CHECK_EQ(f.data[5], 0x44);
    CHECK_EQ(f.get_be(0, 2), 0xABCDull);
    CHECK_EQ(f.get_be(2, 4), 0x11223344ull);
}

TEST_CASE("CanFrame out-of-bounds access is safe") {
    CanFrame f;
    f.dlc = 8;
    f.set_be(6, 4, 0xDEADBEEF);  // would overflow -> no-op
    CHECK_EQ(f.get_be(0, 8), 0ull);
    CHECK_EQ(f.get_be(7, 4), 0ull);  // out of bounds read -> 0
}

TEST_CASE("CanFrame to_string candump format") {
    CanFrame f(0x123, 4, {0x11, 0x22, 0x33, 0x44});
    CHECK_EQ(f.to_string(), std::string("123#11223344"));

    CanFrame e(0x18DAF110, 2, {0xAA, 0xBB});
    e.extended = true;
    CHECK_EQ(e.to_string(), std::string("18DAF110#AABB"));
}

TEST_CASE("CanFrame CSV round-trip") {
    CanFrame f(0x7DF, 8, {0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00});
    f.timestamp_us = 1234567890;
    std::string csv = f.to_csv();

    CanFrame g;
    CHECK_TRUE(CanFrame::from_csv(csv, g));
    CHECK_EQ(g.id, 0x7DFu);
    CHECK_EQ(g.dlc, 8);
    CHECK_EQ(g.timestamp_us, 1234567890ull);
    CHECK_TRUE(f == g);
}

TEST_CASE("CanFrame CSV rejects malformed input") {
    CanFrame g;
    CHECK_FALSE(CanFrame::from_csv("only,three,fields", g));
    CHECK_FALSE(CanFrame::from_csv("1,123,0,9,0,0,", g));       // dlc>8
    CHECK_FALSE(CanFrame::from_csv("1,123,0,2,0,0,ABC", g));    // odd hex len
}

int main() { return canshield::test::run_all(); }
