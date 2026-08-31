#ifndef CANSHIELD_SECURITY_MONITOR_HPP
#define CANSHIELD_SECURITY_MONITOR_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "canshield/detectors.hpp"
#include "canshield/message_catalog.hpp"

namespace canshield {

// per-frame detection latency, in nanoseconds. samples are kept so we can
// report real percentiles (the <1ms claim needs the tail, not just the mean).
class LatencyStats {
public:
    void add(std::uint64_t ns) {
        samples_.push_back(ns);
        if (ns > max_) max_ = ns;
        sum_ += ns;
    }
    std::size_t count() const { return samples_.size(); }
    std::uint64_t max_ns() const { return max_; }
    double mean_ns() const {
        return samples_.empty() ? 0.0 : double(sum_) / samples_.size();
    }
    std::uint64_t percentile_ns(double p) const;  // p in [0,1]
    void reset() { samples_.clear(); max_ = 0; sum_ = 0; }

private:
    std::vector<std::uint64_t> samples_;
    std::uint64_t max_ = 0;
    std::uint64_t sum_ = 0;
};

// owns the detector chain, runs every frame through it, times the work, and
// collects alerts. same object serves the live monitor and the offline harness.
class SecurityMonitor {
public:
    using AlertSink = std::function<void(const Alert&)>;

    // owns the catalog so detectors can safely hold references to it even when
    // callers pass a temporary (e.g. default_catalog()).
    explicit SecurityMonitor(MessageCatalog cat, bool with_defaults = true);

    void add_detector(std::unique_ptr<IDetector> d) {
        detectors_.push_back(std::move(d));
    }

    // run one frame through the chain. returns alerts raised for this frame.
    // records detection latency and (if enabled) stores alerts / calls sink.
    std::size_t process(const CanFrame& f);

    const std::vector<Alert>& alerts() const { return alerts_; }
    const LatencyStats& latency() const { return latency_; }
    std::uint64_t frames_processed() const { return frames_; }
    std::uint64_t alerts_raised() const { return alert_total_; }

    void set_store_alerts(bool s) { store_ = s; }
    void set_sink(AlertSink s) { sink_ = std::move(s); }
    void reset();

private:
    MessageCatalog cat_;
    std::vector<std::unique_ptr<IDetector>> detectors_;
    std::vector<Alert> alerts_;
    std::vector<Alert> scratch_;  // reused per frame to avoid allocations
    LatencyStats latency_;
    AlertSink sink_;
    bool store_ = true;
    std::uint64_t frames_ = 0;
    std::uint64_t alert_total_ = 0;
};

}  // namespace canshield

#endif
