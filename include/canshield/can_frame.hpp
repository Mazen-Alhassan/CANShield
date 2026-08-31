#ifndef CANSHIELD_CAN_FRAME_HPP
#define CANSHIELD_CAN_FRAME_HPP

#include <array>
#include <cstdint>
#include <string>

namespace canshield {

// monotonic microsecond clock for all timestamps and latency math
std::uint64_t now_micros();

// one classic CAN frame (<=8 data bytes, 11- or 29-bit id)
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

    // highest valid id for the current frame width
    std::uint32_t id_mask() const { return extended ? 0x1FFFFFFFu : 0x7FFu; }

    // structural validity per the CAN spec. the monitor checks this itself
    // instead of trusting the bus to reject bad frames
    bool is_well_formed() const {
        if (dlc > 8) return false;
        if (id > id_mask()) return false;
        return true;
    }

    // read `len` payload bytes from `start` as a big-endian int (0 if oob)
    std::uint64_t get_be(std::size_t start, std::size_t len) const;

    // pack `value` big-endian into `len` bytes at `start` (no-op if oob)
    void set_be(std::size_t start, std::size_t len, std::uint64_t value);

    // candump style, e.g. "123#1122334455667788"
    std::string to_string() const;

    // one csv row: ts_us,id_hex,ext,dlc,rtr,err,payload_hex
    std::string to_csv() const;

    // parse a row from to_csv(); false if malformed
    static bool from_csv(const std::string& line, CanFrame& out);

    bool operator==(const CanFrame& o) const {
        return id == o.id && dlc == o.dlc && data == o.data &&
               extended == o.extended && rtr == o.rtr && error == o.error;
    }
    bool operator!=(const CanFrame& o) const { return !(*this == o); }
};

}  // namespace canshield

#endif  // CANSHIELD_CAN_FRAME_HPP
