#include "canshield/detectors.hpp"

#include <algorithm>
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
