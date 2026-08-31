// CANShield - can_frame.cpp
#include "canshield/can_frame.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>

namespace canshield {

std::uint64_t now_micros() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<microseconds>(steady_clock::now().time_since_epoch())
            .count());
}

std::uint64_t CanFrame::get_be(std::size_t start, std::size_t len) const {
    if (len == 0 || start + len > 8) return 0;
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < len; ++i) {
        v = (v << 8) | data[start + i];
    }
    return v;
}

void CanFrame::set_be(std::size_t start, std::size_t len, std::uint64_t value) {
    if (len == 0 || len > 8 || start + len > 8) return;
    for (std::size_t i = 0; i < len; ++i) {
        // Most-significant byte first.
        std::size_t shift = (len - 1 - i) * 8;
        data[start + i] = static_cast<std::uint8_t>((value >> shift) & 0xFF);
    }
}

std::string CanFrame::to_string() const {
    char buf[32];
    if (extended) {
        std::snprintf(buf, sizeof(buf), "%08X#", id);
    } else {
        std::snprintf(buf, sizeof(buf), "%03X#", id);
    }
    std::string out(buf);
    if (rtr) {
        out += "R";  // remote frame carries no data bytes
        return out;
    }
    char hex[3];
    for (std::size_t i = 0; i < dlc && i < 8; ++i) {
        std::snprintf(hex, sizeof(hex), "%02X", data[i]);
        out += hex;
    }
    return out;
}

std::string CanFrame::to_csv() const {
    std::ostringstream os;
    char idbuf[16];
    std::snprintf(idbuf, sizeof(idbuf), "%X", id);
    os << timestamp_us << ',' << idbuf << ',' << (extended ? 1 : 0) << ','
       << static_cast<int>(dlc) << ',' << (rtr ? 1 : 0) << ','
       << (error ? 1 : 0) << ',';
    char hex[3];
    for (std::size_t i = 0; i < dlc && i < 8; ++i) {
        std::snprintf(hex, sizeof(hex), "%02X", data[i]);
        os << hex;
    }
    return os.str();
}

bool CanFrame::from_csv(const std::string& line, CanFrame& out) {
    std::vector<std::string> f;
    std::string cur;
    std::istringstream is(line);
    while (std::getline(is, cur, ',')) f.push_back(cur);
    if (f.size() < 6) return false;

    out = CanFrame{};
    try {
        out.timestamp_us = std::stoull(f[0]);
        out.id = static_cast<std::uint32_t>(std::stoul(f[1], nullptr, 16));
        out.extended = (f[2] == "1");
        int dlc = std::stoi(f[3]);
        if (dlc < 0 || dlc > 8) return false;
        out.dlc = static_cast<std::uint8_t>(dlc);
        out.rtr = (f[4] == "1");
        out.error = (f[5] == "1");
    } catch (...) {
        return false;
    }

    const std::string payload = (f.size() >= 7) ? f[6] : std::string();
    if (payload.size() % 2 != 0) return false;
    std::size_t nbytes = payload.size() / 2;
    if (nbytes > 8) return false;
    for (std::size_t i = 0; i < nbytes; ++i) {
        std::string byte = payload.substr(i * 2, 2);
        try {
            out.data[i] = static_cast<std::uint8_t>(std::stoul(byte, nullptr, 16));
        } catch (...) {
            return false;
        }
    }
    return true;
}

}  // namespace canshield
