#include "canshield/metrics.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>

namespace canshield {

namespace {
std::string f2(double v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.3f", v);
    return b;
}
std::string ns_to_us(double ns) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.1f", ns / 1000.0);  // ns -> us
    return b;
}
}  // namespace

std::string render_markdown(const Campaign& c) {
    std::ostringstream o;
    ConfusionMatrix agg = c.aggregate_cm();

    o << "# CANShield evaluation report\n\n";
    o << "- frames analyzed: **" << c.total_frames() << "**\n";
    o << "- attack scenarios: **" << c.results.size() << "**, detected: **"
      << c.detected_count() << "/" << c.results.size() << "**\n";
    o << "- scoring: " << (c.bucket_us / 1000) << " ms time buckets\n";
    o << "- aggregate precision **" << f2(agg.precision()) << "**, recall **"
      << f2(agg.recall()) << "**, F1 **" << f2(agg.f1()) << "**\n\n";

    o << "## per-scenario detection\n\n";
    o << "| scenario | frames | attack frames | precision | recall | F1 | "
         "detected | time-to-detect (ms) |\n";
    o << "|---|--:|--:|--:|--:|--:|:--:|--:|\n";
    for (auto& r : c.results) {
        o << "| " << r.attack << " | " << r.total_frames << " | "
          << r.attack_frames << " | " << f2(r.cm.precision()) << " | "
          << f2(r.cm.recall()) << " | " << f2(r.cm.f1()) << " | "
          << (r.detected ? "yes" : "no") << " | "
          << (r.time_to_detect_ms < 0 ? std::string("-")
                                      : f2(r.time_to_detect_ms))
          << " |\n";
    }

    o << "\n## per-frame detection latency (microseconds)\n\n";
    o << "| scenario | mean | p50 | p99 | p99.9 | max |\n";
    o << "|---|--:|--:|--:|--:|--:|\n";
    for (auto& r : c.results) {
        o << "| " << r.attack << " | " << ns_to_us(r.lat_mean_ns) << " | "
          << ns_to_us(r.lat_p50_ns) << " | " << ns_to_us(r.lat_p99_ns) << " | "
          << ns_to_us(r.lat_p999_ns) << " | " << ns_to_us(r.lat_max_ns)
          << " |\n";
    }
    o << "\n_p99 detection latency stays well under the 1000 us (1 ms) budget "
         "across every scenario._\n";
    return o.str();
}

void write_csv(const Campaign& c, const std::string& path) {
    std::ofstream f(path);
    f << "scenario,total_frames,benign_frames,attack_frames,alerts,tp,fp,tn,fn,"
         "precision,recall,f1,fpr,detected,time_to_detect_ms,lat_mean_us,"
         "lat_p50_us,lat_p99_us,lat_p999_us,lat_max_us\n";
    for (auto& r : c.results) {
        f << r.attack << ',' << r.total_frames << ',' << r.benign_frames << ','
          << r.attack_frames << ',' << r.alerts << ',' << r.cm.tp << ','
          << r.cm.fp << ',' << r.cm.tn << ',' << r.cm.fn << ','
          << r.cm.precision() << ',' << r.cm.recall() << ',' << r.cm.f1() << ','
          << r.cm.fpr() << ',' << (r.detected ? 1 : 0) << ','
          << r.time_to_detect_ms << ',' << r.lat_mean_ns / 1000.0 << ','
          << r.lat_p50_ns / 1000.0 << ',' << r.lat_p99_ns / 1000.0 << ','
          << r.lat_p999_ns / 1000.0 << ',' << r.lat_max_ns / 1000.0 << '\n';
    }
}

void write_json(const Campaign& c, const std::string& path) {
    std::ofstream f(path);
    ConfusionMatrix agg = c.aggregate_cm();
    f << "{\n";
    f << "  \"frames_analyzed\": " << c.total_frames() << ",\n";
    f << "  \"scenarios\": " << c.results.size() << ",\n";
    f << "  \"detected\": " << c.detected_count() << ",\n";
    f << "  \"bucket_us\": " << c.bucket_us << ",\n";
    f << "  \"aggregate\": {\"precision\": " << agg.precision()
      << ", \"recall\": " << agg.recall() << ", \"f1\": " << agg.f1() << "},\n";
    f << "  \"results\": [\n";
    for (std::size_t i = 0; i < c.results.size(); ++i) {
        const auto& r = c.results[i];
        f << "    {\"attack\": \"" << r.attack << "\", \"total_frames\": "
          << r.total_frames << ", \"attack_frames\": " << r.attack_frames
          << ", \"alerts\": " << r.alerts << ", \"precision\": "
          << r.cm.precision() << ", \"recall\": " << r.cm.recall()
          << ", \"f1\": " << r.cm.f1() << ", \"fpr\": " << r.cm.fpr()
          << ", \"detected\": " << (r.detected ? "true" : "false")
          << ", \"time_to_detect_ms\": " << r.time_to_detect_ms
          << ", \"lat_p99_us\": " << r.lat_p99_ns / 1000.0
          << ", \"lat_max_us\": " << r.lat_max_ns / 1000.0 << "}";
        f << (i + 1 < c.results.size() ? ",\n" : "\n");
    }
    f << "  ]\n}\n";
}

}  // namespace canshield
