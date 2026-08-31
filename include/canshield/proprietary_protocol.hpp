// CANShield - proprietary_protocol.hpp
// The "Subsonic Motors" proprietary message-integrity scheme, as reverse
// engineered from bus captures (see docs/protocol-reverse-engineering.md).
//
// Reverse-engineered format for integrity-protected periodic messages:
//   * Rolling counter: the high nibble of byte[dlc-2] is a 4-bit counter that
//     increments (mod 16) on every transmission of that message id. The low
//     nibble is reserved (zero) in this matrix.
//   * Checksum: byte[dlc-1] = (kMagic + sum(data[0..dlc-2])) & 0xFF, i.e. the
//     8-bit sum of all preceding bytes (including the counter byte) plus a
//     fixed per-protocol seed. This XOR/sum-with-seed style is typical of OEM
//     "alive/CRC" pairs and was recovered by observing which byte changed with
//     every message and which stayed constant for constant payloads.
//
// Both the ECU simulator (producer) and the security monitor (validator) call
// into this single source of truth, so a mismatch means genuine tampering, not
// a modeling discrepancy.
#ifndef CANSHIELD_PROPRIETARY_PROTOCOL_HPP
#define CANSHIELD_PROPRIETARY_PROTOCOL_HPP

#include <cstdint>

#include "canshield/can_frame.hpp"

namespace canshield {
namespace proto {

// Fixed additive seed recovered during reverse engineering.
constexpr std::uint8_t kChecksumSeed = 0xA5;

// Byte index of the counter (high nibble) and checksum for a given dlc.
inline std::size_t counter_byte(std::uint8_t dlc) { return dlc >= 2 ? dlc - 2 : 0; }
inline std::size_t checksum_byte(std::uint8_t dlc) { return dlc >= 1 ? dlc - 1 : 0; }

// Read the 4-bit rolling counter from a frame.
std::uint8_t rolling_counter(const CanFrame& f, std::uint8_t dlc);

// Write the 4-bit rolling counter (only the high nibble of counter_byte).
void set_rolling_counter(CanFrame& f, std::uint8_t dlc, std::uint8_t counter);

// Compute the expected checksum over data[0..dlc-2].
std::uint8_t compute_checksum(const CanFrame& f, std::uint8_t dlc);

// Set counter + checksum on `f`. Call after all signal bytes are packed.
void apply_integrity(CanFrame& f, std::uint8_t dlc, std::uint8_t counter);

// True if the frame's checksum byte matches the computed checksum.
bool checksum_valid(const CanFrame& f, std::uint8_t dlc);

// Whether `next` is the valid successor counter of `prev` (i.e. (prev+1)&0xF).
inline bool counter_follows(std::uint8_t prev, std::uint8_t next) {
    return next == ((prev + 1) & 0x0F);
}

}  // namespace proto
}  // namespace canshield

#endif  // CANSHIELD_PROPRIETARY_PROTOCOL_HPP
