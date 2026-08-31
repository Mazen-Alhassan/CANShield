#include "canshield/detectors.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "canshield/proprietary_protocol.hpp"

namespace canshield {

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "?";
}

namespace {
std::string idhex(std::uint32_t id) {
    char b[16];
    std::snprintf(b, sizeof(b), "0x%X", id);
    return b;
}
}  // namespace

void UnknownIdDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    if (!cat_.known(f.id)) {
        out.push_back({f.timestamp_us, f.id, name(),
                       "id " + idhex(f.id) + " not in bus matrix",
                       Severity::High});
    }
}

void ProtocolDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    if (f.error) {
        out.push_back({f.timestamp_us, f.id, name(), "error frame on bus",
                       Severity::High});
        return;
    }
    if (!f.is_well_formed()) {
        out.push_back({f.timestamp_us, f.id, name(), "malformed frame",
                       Severity::High});
        return;
    }
    const MessageDef* m = cat_.find(f.id);
    if (m && f.dlc != m->dlc) {
        out.push_back({f.timestamp_us, f.id, name(),
                       "dlc " + std::to_string(f.dlc) + " != expected " +
                           std::to_string(m->dlc),
                       Severity::Medium});
    }
}

void ChecksumDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    const MessageDef* m = cat_.find(f.id);
    if (!m || !m->has_integrity || f.error) return;
    if (f.dlc != m->dlc) return;  // dlc handled by protocol detector
    if (!proto::checksum_valid(f, m->dlc)) {
        out.push_back({f.timestamp_us, f.id, name(),
                       "checksum mismatch on " + m->name, Severity::High});
    }
}

void CounterDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    const MessageDef* m = cat_.find(f.id);
    if (!m || !m->has_integrity || f.error || f.dlc != m->dlc) return;
    std::uint8_t c = proto::rolling_counter(f, m->dlc);
    St& s = state_[f.id];
    if (s.have && !proto::counter_follows(s.last, c)) {
        out.push_back({f.timestamp_us, f.id, name(),
                       "counter " + std::to_string(c) + " does not follow " +
                           std::to_string(s.last) + " on " + m->name,
                       Severity::High});
    }
    s.have = true;
    s.last = c;
}

void TimingDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    const MessageDef* m = cat_.find(f.id);
    if (!m || m->period_us() == 0 || f.error) return;
    auto it = last_us_.find(f.id);
    if (it != last_us_.end()) {
        std::uint64_t dt = f.timestamp_us - it->second;
        std::uint64_t lo = static_cast<std::uint64_t>(m->period_us() * (1.0 - tol_));
        if (dt < lo) {
            out.push_back({f.timestamp_us, f.id, name(),
                           "inter-arrival " + std::to_string(dt) +
                               "us below expected ~" +
                               std::to_string(m->period_us()) + "us on " +
                               m->name,
                           Severity::Medium});
        }
    }
    last_us_[f.id] = f.timestamp_us;
}

void RangeDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    const MessageDef* m = cat_.find(f.id);
    if (!m || f.error || f.dlc != m->dlc) return;
    for (const auto& s : m->signals) {
        double v = s.extract_phys(f);
        if (!s.in_range(v)) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.2f", v);
            out.push_back({f.timestamp_us, f.id, name(),
                           s.name + "=" + buf + " out of range on " + m->name,
                           Severity::Medium});
        }
    }
}

void RateDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    if (f.error) return;
    Win& w = win_[f.id];
    w.ts.push_back(f.timestamp_us);
    // drop timestamps older than the window
    std::uint64_t cutoff = f.timestamp_us > window_us_ ? f.timestamp_us - window_us_ : 0;
    std::size_t keep = 0;
    while (keep < w.ts.size() && w.ts[keep] < cutoff) ++keep;
    if (keep) w.ts.erase(w.ts.begin(), w.ts.begin() + keep);

    const MessageDef* m = cat_.find(f.id);
    if (m && m->period_us() > 0) {
        // expected count in the window; alert if we exceed it by burst factor
        double expected = static_cast<double>(window_us_) / m->period_us();
        if (w.ts.size() > expected * burst_ && w.ts.size() > 5) {
            out.push_back({f.timestamp_us, f.id, name(),
                           "rate burst on " + m->name + ": " +
                               std::to_string(w.ts.size()) + " in window vs ~" +
                               std::to_string((int)expected),
                           Severity::High});
        }
    } else if (!m) {
        // unknown id arriving fast -> flood
        if (w.ts.size() > 20) {
            out.push_back({f.timestamp_us, f.id, name(),
                           "flood of unknown id " + idhex(f.id) + ": " +
                               std::to_string(w.ts.size()) + " in window",
                           Severity::Critical});
        }
    }
}

void PhysicsConsistencyDetector::inspect(const CanFrame& f,
                                         std::vector<Alert>& out) {
    if (f.error) return;
    // cache the latest physical values from the relevant ids
    if (f.id == 0x400 && f.dlc == 4) {  // IC_VehicleSpeed
        vehicle_speed_ = f.get_be(0, 2) * 0.01;
        have_speed_ = true;
    } else if (f.id == 0x200 && f.dlc == 8) {  // ABS wheel speeds (four 12-bit)
        double fl = ((f.get_be(0, 2) >> 4) & 0xFFF) * 0.0625;
        std::uint64_t raw_fr = ((f.data[1] & 0x0F) << 8) | f.data[2];
        double fr = raw_fr * 0.0625;
        mean_wheel_ = (fl + fr) / 2.0;  // front axle is enough for the check
        have_wheel_ = true;
    } else if (f.id == 0x100 && f.dlc == 8) {  // engine rpm
        rpm_ = f.get_be(0, 2) * 0.25;
        have_rpm_ = true;
    } else {
        return;
    }

    // wheel speed vs vehicle speed must track within tolerance
    if (have_speed_ && have_wheel_ &&
        std::abs(mean_wheel_ - vehicle_speed_) > 18.0) {
        char b[96];
        std::snprintf(b, sizeof(b),
                      "wheel speed %.1f km/h disagrees with vehicle speed %.1f km/h",
                      mean_wheel_, vehicle_speed_);
        out.push_back({f.timestamp_us, f.id, name(), b, Severity::High});
    }
    // engine racing while the car is not moving -> implausible
    if (have_rpm_ && have_speed_ && have_wheel_ && rpm_ > 4000.0 &&
        vehicle_speed_ < 5.0 && mean_wheel_ < 5.0) {
        char b[96];
        std::snprintf(b, sizeof(b), "rpm %.0f implausible at standstill", rpm_);
        out.push_back({f.timestamp_us, f.id, name(), b, Severity::High});
    }
}

void DiagnosticDetector::inspect(const CanFrame& f, std::vector<Alert>& out) {
    // only the OBD/UDS id band
    bool is_diag = (f.id >= 0x700 && f.id <= 0x7FF);
    if (!is_diag || f.error) return;
    auto& h = hits_[f.id];
    h.push_back(f.timestamp_us);
    std::uint64_t cutoff = f.timestamp_us > window_us_ ? f.timestamp_us - window_us_ : 0;
    std::size_t keep = 0;
    while (keep < h.size() && h[keep] < cutoff) ++keep;
    if (keep) h.erase(h.begin(), h.begin() + keep);
    if (static_cast<int>(h.size()) > max_) {
        out.push_back({f.timestamp_us, f.id, name(),
                       "diagnostic flood on " + idhex(f.id) + ": " +
                           std::to_string(h.size()) + "/s",
                       Severity::High});
    }
}

}  // namespace canshield
