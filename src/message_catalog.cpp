// CANShield - message_catalog.cpp
#include "canshield/message_catalog.hpp"

#include <cmath>

namespace canshield {

namespace {
// Big-endian / MSB-first contiguous bit extraction. bit 0 == MSB of data[0].
std::uint64_t extract_bits_be(const std::array<std::uint8_t, 8>& d,
                              std::size_t start_bit, std::size_t len) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < len; ++i) {
        std::size_t bit = start_bit + i;
        std::size_t byte = bit / 8;
        if (byte >= 8) break;
        std::size_t off = 7 - (bit % 8);  // MSB-first within a byte
        std::uint64_t b = (d[byte] >> off) & 0x1u;
        v = (v << 1) | b;
    }
    return v;
}

void pack_bits_be(std::array<std::uint8_t, 8>& d, std::size_t start_bit,
                  std::size_t len, std::uint64_t value) {
    for (std::size_t i = 0; i < len; ++i) {
        std::size_t bit = start_bit + i;
        std::size_t byte = bit / 8;
        if (byte >= 8) break;
        std::size_t off = 7 - (bit % 8);
        // Bit (len-1-i) of value maps to output bit i (MSB-first).
        std::uint64_t b = (value >> (len - 1 - i)) & 0x1u;
        if (b) {
            d[byte] |= static_cast<std::uint8_t>(1u << off);
        } else {
            d[byte] &= static_cast<std::uint8_t>(~(1u << off));
        }
    }
}
}  // namespace

std::uint64_t SignalDef::extract_raw(const CanFrame& f) const {
    return extract_bits_be(f.data, start_bit, length_bits);
}

void SignalDef::pack_phys(CanFrame& f, double phys) const {
    double raw_d = (phys - offset) / scale;
    if (raw_d < 0) raw_d = 0;
    // Clamp to the signal's bit width.
    std::uint64_t max_raw = (length_bits >= 64)
                                ? ~0ull
                                : ((1ull << length_bits) - 1ull);
    std::uint64_t raw = static_cast<std::uint64_t>(std::llround(raw_d));
    if (raw > max_raw) raw = max_raw;
    pack_bits_be(f.data, start_bit, length_bits, raw);
}

// --------------------------------------------------------------------------
// The "Subsonic Motors" bus matrix.
//
// Convention for integrity-protected periodic messages: signal payload lives in
// bytes [0 .. dlc-3]; byte[dlc-2] carries the rolling counter (high nibble);
// byte[dlc-1] carries the checksum. See proprietary_protocol.hpp.
// --------------------------------------------------------------------------
MessageCatalog default_catalog() {
    MessageCatalog c;

    // Steering Angle Sensor - 100 Hz. angle is offset-encoded so straight-ahead
    // is mid-scale; range +/- 780 deg over the raw 16-bit field.
    c.add(MessageDef{
        0x0A0, false, "SAS_SteeringAngle", "SAS", 4, 10, true,
        {{"SteeringAngle", 0, 16, 0.0233, -780.0, -780.0, 779.0, "deg"}}});

    // Powertrain engine data - 100 Hz.
    c.add(MessageDef{
        0x100, false, "PT_EngineData", "Powertrain", 8, 10, true,
        {
            {"EngineRPM", 0, 16, 0.25, 0.0, 0.0, 8000.0, "rpm"},
            {"CoolantTemp", 16, 8, 1.0, -40.0, -40.0, 150.0, "degC"},
            {"ThrottlePosition", 24, 8, 0.4, 0.0, 0.0, 100.0, "%"},
            {"EngineLoad", 32, 8, 0.4, 0.0, 0.0, 100.0, "%"},
            {"IntakeAirTemp", 40, 8, 1.0, -40.0, -40.0, 150.0, "degC"},
            // bytes 6,7 reserved for counter+checksum
        }});

    // Transmission - 50 Hz.
    c.add(MessageDef{
        0x120, false, "PT_Transmission", "Powertrain", 4, 20, true,
        {
            {"SelectedGear", 0, 4, 1.0, 0.0, 0.0, 8.0, "gear"},
            {"TransTemp", 8, 8, 1.0, -40.0, -40.0, 150.0, "degC"},
        }});

    // ABS wheel speeds - 100 Hz. Four 12-bit wheel speeds (0.0625 km/h/bit).
    c.add(MessageDef{
        0x200, false, "ABS_WheelSpeeds", "Brake_ABS", 8, 10, true,
        {
            {"WheelSpeedFL", 0, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"},
            {"WheelSpeedFR", 12, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"},
            {"WheelSpeedRL", 24, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"},
            {"WheelSpeedRR", 36, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"},
            // byte 6 counter, byte 7 checksum
        }});

    // Brake status - 50 Hz.
    c.add(MessageDef{
        0x210, false, "ABS_BrakeStatus", "Brake_ABS", 4, 20, true,
        {
            {"BrakePressure", 0, 8, 0.5, 0.0, 0.0, 127.0, "bar"},
            {"BrakePedalPressed", 8, 1, 1.0, 0.0, 0.0, 1.0, "bool"},
        }});

    // Instrument cluster vehicle speed - 50 Hz.
    c.add(MessageDef{
        0x400, false, "IC_VehicleSpeed", "Cluster", 4, 20, true,
        {{"VehicleSpeed", 0, 16, 0.01, 0.0, 0.0, 300.0, "km/h"}}});

    // Body control - 10 Hz (slow status).
    c.add(MessageDef{
        0x300, false, "BCM_BodyStatus", "Body", 4, 100, true,
        {
            {"DoorsOpen", 0, 4, 1.0, 0.0, 0.0, 15.0, "bitfield"},
            {"LightsOn", 4, 1, 1.0, 0.0, 0.0, 1.0, "bool"},
            {"DoorsLocked", 5, 1, 1.0, 0.0, 0.0, 1.0, "bool"},
        }});

    // Diagnostic ids: aperiodic (period_ms = 0), no proprietary integrity
    // scheme (UDS/OBD-II has its own service/PID structure). Present so the
    // monitor recognizes them as known ids and can flag diagnostic *abuse*
    // (excessive rate) rather than treating them as unknown.
    c.add(MessageDef{diag::kObdFunctionalRequest, false, "OBD_FunctionalRequest",
                     "Tester", 8, 0, false, {}});
    c.add(MessageDef{diag::kObdPhysicalRequest, false, "OBD_PhysicalRequest",
                     "Tester", 8, 0, false, {}});
    c.add(MessageDef{diag::kObdResponse, false, "OBD_Response", "Powertrain", 8,
                     0, false, {}});

    return c;
}

}  // namespace canshield
