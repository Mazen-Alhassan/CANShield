#ifndef CANSHIELD_PROPRIETARY_PROTOCOL_HPP
#define CANSHIELD_PROPRIETARY_PROTOCOL_HPP

#include <cstdint>

#include "canshield/can_frame.hpp"

namespace canshield {
// reverse-engineered "subsonic motors" integrity scheme:
//   counter  = high nibble of byte[dlc-2], increments mod 16 each tx
//   checksum = byte[dlc-1] = (seed + sum(data[0..dlc-2])) & 0xff
// full writeup in docs/protocol-reverse-engineering.md
namespace proto {

// fixed additive seed recovered during reverse engineering.
constexpr std::uint8_t kChecksumSeed = 0xA5;

// byte index of the counter (high nibble) and checksum for a given dlc.
inline std::size_t counter_byte(std::uint8_t dlc) { return dlc >= 2 ? dlc - 2 : 0; }
inline std::size_t checksum_byte(std::uint8_t dlc) { return dlc >= 1 ? dlc - 1 : 0; }

// read the 4-bit rolling counter from a frame.
std::uint8_t rolling_counter(const CanFrame& f, std::uint8_t dlc);

// write the 4-bit rolling counter (only the high nibble of counter_byte).
void set_rolling_counter(CanFrame& f, std::uint8_t dlc, std::uint8_t counter);

// compute the expected checksum over data[0..dlc-2].
std::uint8_t compute_checksum(const CanFrame& f, std::uint8_t dlc);

// set counter + checksum on `f`. Call after all signal bytes are packed.
void apply_integrity(CanFrame& f, std::uint8_t dlc, std::uint8_t counter);

// true if the frame's checksum byte matches the computed checksum.
bool checksum_valid(const CanFrame& f, std::uint8_t dlc);

// whether `next` is the valid successor counter of `prev` (i.e. (prev+1)&0xF).
inline bool counter_follows(std::uint8_t prev, std::uint8_t next) {
    return next == ((prev + 1) & 0x0F);
}

}  // namespace proto
}  // namespace canshield

#endif  // CANSHIELD_PROPRIETARY_PROTOCOL_HPP
