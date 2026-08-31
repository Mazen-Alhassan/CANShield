#include "canshield/proprietary_protocol.hpp"

namespace canshield {
namespace proto {

std::uint8_t rolling_counter(const CanFrame& f, std::uint8_t dlc) {
    if (dlc < 2) return 0;
    return static_cast<std::uint8_t>((f.data[counter_byte(dlc)] >> 4) & 0x0F);
}

void set_rolling_counter(CanFrame& f, std::uint8_t dlc, std::uint8_t counter) {
    if (dlc < 2) return;
    std::size_t idx = counter_byte(dlc);
    std::uint8_t low = f.data[idx] & 0x0F;  // preserve reserved low nibble
    f.data[idx] = static_cast<std::uint8_t>(((counter & 0x0F) << 4) | low);
}

std::uint8_t compute_checksum(const CanFrame& f, std::uint8_t dlc) {
    if (dlc < 1) return 0;
    std::uint16_t sum = kChecksumSeed;
    for (std::size_t i = 0; i < static_cast<std::size_t>(dlc - 1); ++i) {
        sum += f.data[i];
    }
    return static_cast<std::uint8_t>(sum & 0xFF);
}

void apply_integrity(CanFrame& f, std::uint8_t dlc, std::uint8_t counter) {
    set_rolling_counter(f, dlc, counter);
    f.data[checksum_byte(dlc)] = compute_checksum(f, dlc);
}

bool checksum_valid(const CanFrame& f, std::uint8_t dlc) {
    if (dlc < 1) return false;
    return f.data[checksum_byte(dlc)] == compute_checksum(f, dlc);
}

}  // namespace proto
}  // namespace canshield
