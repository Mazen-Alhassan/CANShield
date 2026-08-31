// CANShield - Automotive CAN bus security research testbed
// can_frame.hpp - Core Classic-CAN (CAN 2.0A/B) frame model.
//
// This is the single data structure shared by every component: the ECU
// simulator produces CanFrames, the transport carries them, the attack
// injector forges them, and the security monitor inspects them. Keeping it
// small and copyable (no heap) is what makes <1ms detection latency practical.
#ifndef CANSHIELD_CAN_FRAME_HPP
#define CANSHIELD_CAN_FRAME_HPP

#include <array>
#include <cstdint>
#include <string>

namespace canshield {

// Monotonic microsecond clock used for all frame timestamps and latency
// measurements. Monotonic (not wall-clock) so timing math is never disturbed
// by NTP steps or DST.
std::uint64_t now_micros();

// A single Classic CAN frame. Classic CAN carries at most 8 data bytes; the
// arbitration id is 11-bit (standard) or 29-bit (extended).
struct CanFrame {
    std::uint32_t id = 0;              // arbitration id (11- or 29-bit)
    std::uint8_t  dlc = 0;            // data length code, 0..8 for classic CAN
    std::array<std::uint8_t, 8> data{}; // payload; bytes [dlc..8) are unused
    std::uint64_t timestamp_us = 0;   // capture/tx time, microseconds (monotonic)
    bool extended = false;            // true => 29-bit id
    bool rtr = false;                 // remote transmission request
    bool error = false;              // error frame marker

    CanFrame() = default;
    CanFrame(std::uint32_t id_, std::uint8_t dlc_, std::array<std::uint8_t, 8> d,
             bool extended_ = false)
        : id(id_), dlc(dlc_), data(d), extended(extended_) {}

    // Highest valid arbitration id for the current frame width.
    std::uint32_t id_mask() const { return extended ? 0x1FFFFFFFu : 0x7FFu; }

    // Structural validity per the CAN spec (independent of any protocol we
    // layer on top). The security monitor treats violations as protocol
    // anomalies rather than trusting the bus to reject them.
    bool is_well_formed() const {
        if (dlc > 8) return false;
        if (id > id_mask()) return false;
        return true;
    }

    // Extract a big-endian (Motorola) unsigned integer from `len` bytes of the
    // payload starting at byte `start`. Most automotive signals are packed
    // big-endian. Returns 0 if the range is out of bounds.
    std::uint64_t get_be(std::size_t start, std::size_t len) const;

    // Pack `value` as a big-endian unsigned integer into `len` bytes starting
    // at `start`. No-op if the range is out of bounds.
    void set_be(std::size_t start, std::size_t len, std::uint64_t value);

    // candump-style rendering, e.g. "123#1122334455667788" (id in hex, then
    // '#', then payload bytes in hex). Extended ids are zero-padded to 8 hex
    // digits, standard ids to 3.
    std::string to_string() const;

    // A stable one-line CSV record: ts_us,id_hex,ext,dlc,rtr,err,payload_hex
    std::string to_csv() const;

    // Parse a CSV record produced by to_csv(). Returns false on malformed
    // input (the frame is left in an unspecified state).
    static bool from_csv(const std::string& line, CanFrame& out);

    bool operator==(const CanFrame& o) const {
        return id == o.id && dlc == o.dlc && data == o.data &&
               extended == o.extended && rtr == o.rtr && error == o.error;
    }
    bool operator!=(const CanFrame& o) const { return !(*this == o); }
};

}  // namespace canshield

#endif  // CANSHIELD_CAN_FRAME_HPP
