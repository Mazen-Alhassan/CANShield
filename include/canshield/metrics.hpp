#ifndef CANSHIELD_METRICS_HPP
#define CANSHIELD_METRICS_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace canshield {

struct ConfusionMatrix {
    std::uint64_t tp = 0, fp = 0, tn = 0, fn = 0;

    void add(bool truth_attack, bool predicted_attack) {
        if (truth_attack && predicted_attack) ++tp;
        else if (!truth_attack && predicted_attack) ++fp;
        else if (!truth_attack && !predicted_attack) ++tn;
        else ++fn;
    }
    double precision() const { return (tp + fp) ? double(tp) / (tp + fp) : 0.0; }
    double recall() const { return (tp + fn) ? double(tp) / (tp + fn) : 0.0; }
    double f1() const {
        double p = precision(), r = recall();
        return (p + r) ? 2 * p * r / (p + r) : 0.0;
    }
    double accuracy() const {
        std::uint64_t n = tp + fp + tn + fn;
        return n ? double(tp + tn) / n : 0.0;
    }
    double fpr() const { return (fp + tn) ? double(fp) / (fp + tn) : 0.0; }
    ConfusionMatrix& operator+=(const ConfusionMatrix& o) {
        tp += o.tp; fp += o.fp; tn += o.tn; fn += o.fn;
        return *this;
    }
};

struct ScenarioResult {
    std::string attack;
    std::uint64_t total_frames = 0;
    std::uint64_t benign_frames = 0;
    std::uint64_t attack_frames = 0;
    std::uint64_t alerts = 0;
    ConfusionMatrix cm;               // windowed (bucketed) scoring
    bool detected = false;
    double time_to_detect_ms = -1.0;  // first in-window alert, relative to onset
    double lat_mean_ns = 0, lat_p50_ns = 0, lat_p99_ns = 0, lat_p999_ns = 0,
           lat_max_ns = 0;
    std::map<std::string, std::uint64_t> detector_counts;
};

struct Campaign {
    std::vector<ScenarioResult> results;
    std::uint64_t bucket_us = 10000;

    std::uint64_t total_frames() const {
        std::uint64_t n = 0;
        for (auto& r : results) n += r.total_frames;
        return n;
    }
    ConfusionMatrix aggregate_cm() const {
        ConfusionMatrix c;
        for (auto& r : results) c += r.cm;
        return c;
    }
    int detected_count() const {
        int n = 0;
        for (auto& r : results) n += r.detected ? 1 : 0;
        return n;
    }
};

// report writers
std::string render_markdown(const Campaign& c);
void write_csv(const Campaign& c, const std::string& path);
void write_json(const Campaign& c, const std::string& path);

}  // namespace canshield

#endif
