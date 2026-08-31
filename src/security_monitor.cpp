#include "canshield/security_monitor.hpp"

#include <algorithm>
#include <chrono>

namespace canshield {

std::uint64_t LatencyStats::percentile_ns(double p) const {
    if (samples_.empty()) return 0;
    std::vector<std::uint64_t> s = samples_;  // copy so we don't disturb order
    std::sort(s.begin(), s.end());
    if (p <= 0) return s.front();
    if (p >= 1) return s.back();
    std::size_t idx = static_cast<std::size_t>(p * (s.size() - 1) + 0.5);
    return s[idx];
}

SecurityMonitor::SecurityMonitor(MessageCatalog cat, bool with_defaults)
    : cat_(std::move(cat)) {
    if (with_defaults) {
        // order roughly cheapest-first; all run every frame
        add_detector(std::make_unique<UnknownIdDetector>(cat_));
        add_detector(std::make_unique<ProtocolDetector>(cat_));
        add_detector(std::make_unique<ChecksumDetector>(cat_));
        add_detector(std::make_unique<CounterDetector>(cat_));
        add_detector(std::make_unique<TimingDetector>(cat_));
        add_detector(std::make_unique<RangeDetector>(cat_));
        add_detector(std::make_unique<RateDetector>(cat_));
        add_detector(std::make_unique<DiagnosticDetector>());
    }
}

std::size_t SecurityMonitor::process(const CanFrame& f) {
    scratch_.clear();

    auto t0 = std::chrono::steady_clock::now();
    for (auto& d : detectors_) d->inspect(f, scratch_);
    auto t1 = std::chrono::steady_clock::now();

    latency_.add(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));

    ++frames_;
    alert_total_ += scratch_.size();
    for (auto& a : scratch_) {
        if (sink_) sink_(a);
        if (store_) alerts_.push_back(a);
    }
    return scratch_.size();
}

void SecurityMonitor::reset() {
    alerts_.clear();
    latency_.reset();
    frames_ = 0;
    alert_total_ = 0;
}

}  // namespace canshield
