#ifndef CANSHIELD_MESSAGE_CATALOG_HPP
#define CANSHIELD_MESSAGE_CATALOG_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "canshield/can_frame.hpp"

namespace canshield {

// one physical signal packed into a message payload. Bits are numbered
// big-endian / MSB-first: bit 0 is the most-significant bit of data byte 0,
// bit 7 its least-significant, bit 8 the MSB of byte 1, and so on. The signal
// occupies `length_bits` contiguous bits. physical = raw * scale + offset.
struct SignalDef {
    std::string name;
    std::size_t start_bit = 0;
    std::size_t length_bits = 8;
    double scale = 1.0;
    double offset = 0.0;
    double min_phys = 0.0;
    double max_phys = 0.0;
    std::string unit;

    std::uint64_t extract_raw(const CanFrame& f) const;
    double extract_phys(const CanFrame& f) const {
        return static_cast<double>(extract_raw(f)) * scale + offset;
    }
    // pack a physical value into `f`, clamped to the signal's raw bit-width.
    void pack_phys(CanFrame& f, double phys) const;

    bool in_range(double phys) const {
        return phys >= min_phys && phys <= max_phys;
    }
};

// one message (CAN id) in the matrix.
struct MessageDef {
    std::uint32_t id = 0;
    bool extended = false;
    std::string name;
    std::string ecu;              // authorized transmitting ECU
    std::uint8_t dlc = 8;
    std::uint32_t period_ms = 0;  // 0 => aperiodic / event-triggered (e.g. diag)
    bool has_integrity = false;   // uses the proprietary counter+checksum scheme
    std::vector<SignalDef> signals;

    // expected inter-arrival time in microseconds (0 for aperiodic).
    std::uint64_t period_us() const {
        return static_cast<std::uint64_t>(period_ms) * 1000ull;
    }
};

// the whole bus matrix, indexed by id for O(1) lookup during monitoring.
class MessageCatalog {
public:
    void add(const MessageDef& m) {
        by_id_[m.id] = messages_.size();
        messages_.push_back(m);
    }
    const std::vector<MessageDef>& messages() const { return messages_; }

    const MessageDef* find(std::uint32_t id) const {
        auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &messages_[it->second];
    }
    bool known(std::uint32_t id) const { return by_id_.count(id) != 0; }
    std::size_t size() const { return messages_.size(); }

private:
    std::vector<MessageDef> messages_;
    std::unordered_map<std::uint32_t, std::size_t> by_id_;
};

// the default "Subsonic Motors" bus matrix used throughout the testbed.
MessageCatalog default_catalog();

// Well-known diagnostic ids (UDS / OBD-II over CAN).
namespace diag {
constexpr std::uint32_t kObdFunctionalRequest = 0x7DF;  // broadcast tester req
constexpr std::uint32_t kObdPhysicalRequest = 0x7E0;    // addressed to ECU
constexpr std::uint32_t kObdResponse = 0x7E8;           // ECU response
}  // namespace diag

}  // namespace canshield

#endif  // CANSHIELD_MESSAGE_CATALOG_HPP
