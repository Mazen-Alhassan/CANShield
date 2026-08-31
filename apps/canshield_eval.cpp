#include <cstdio>
#include <fstream>
#include <vector>

#include "canshield/attack_injector.hpp"
#include "canshield/cli.hpp"
#include "canshield/ecu_simulator.hpp"
#include "canshield/metrics.hpp"
#include "canshield/security_monitor.hpp"

using namespace canshield;

static ScenarioResult run_scenario(AttackType type, std::uint64_t seed,
                                    std::uint64_t dur_us, std::uint64_t ws,
                                    std::uint64_t we, std::uint64_t bucket_us) {
    // fresh, distinct benign traffic for this scenario
    EcuSimulator sim(default_catalog(), seed);
    std::vector<CanFrame> benign;
    benign.reserve(dur_us / 2000);
    sim.generate(dur_us, [&](const CanFrame& f) { benign.push_back(f); });

    AttackInjector inj(default_catalog(), seed);
    Scenario sc = inj.inject(type, benign, ws, we);

    SecurityMonitor mon(default_catalog());
    for (auto& lf : sc.frames) mon.process(lf.frame);

    // bucketed truth vs prediction
    std::uint64_t max_ts = sc.frames.empty() ? 0 : sc.frames.back().frame.timestamp_us;
    std::size_t nb = static_cast<std::size_t>(max_ts / bucket_us) + 2;
    std::vector<char> truth(nb, 0), pred(nb, 0);
    for (auto& lf : sc.frames)
        if (lf.is_attack()) truth[lf.frame.timestamp_us / bucket_us] = 1;

    ScenarioResult r;
    r.attack = to_string(type);
    r.total_frames = sc.frames.size();
    r.benign_frames = sc.benign_count;
    r.attack_frames = sc.attack_count;
    r.alerts = mon.alerts_raised();

    double first_detect = -1.0;
    const std::uint64_t grace = 200000;  // allow rate-window lag past onset
    for (auto& a : mon.alerts()) {
        pred[a.timestamp_us / bucket_us] = 1;
        r.detector_counts[a.detector]++;
        if (a.timestamp_us >= ws && a.timestamp_us < we + grace) {
            double ttd = (double(a.timestamp_us) - double(ws)) / 1000.0;
            if (ttd < 0) ttd = 0;
            if (first_detect < 0 || ttd < first_detect) first_detect = ttd;
        }
    }
    r.detected = first_detect >= 0;
    r.time_to_detect_ms = first_detect;

    for (std::size_t b = 0; b < nb; ++b) r.cm.add(truth[b] != 0, pred[b] != 0);

    const auto& L = mon.latency();
    r.lat_mean_ns = L.mean_ns();
    r.lat_p50_ns = L.percentile_ns(0.50);
    r.lat_p99_ns = L.percentile_ns(0.99);
    r.lat_p999_ns = L.percentile_ns(0.999);
    r.lat_max_ns = L.max_ns();
    return r;
}

int main(int argc, char** argv) {
    Args args(argc, argv);
    if (args.has("--help")) {
        std::printf(
            "usage: canshield_eval [--seconds N] [--attack-start S] "
            "[--attack-len L] [--bucket-ms B] [--out-dir DIR]\n");
        return 0;
    }
    double seconds = args.getf("--seconds", 220.0);
    double a_start = args.getf("--attack-start", 90.0);
    double a_len = args.getf("--attack-len", 60.0);
    std::uint64_t bucket_us = static_cast<std::uint64_t>(args.geti("--bucket-ms", 10) * 1000);
    std::string out = args.get("--out-dir", "data");

    std::uint64_t dur_us = static_cast<std::uint64_t>(seconds * 1e6);
    std::uint64_t ws = static_cast<std::uint64_t>(a_start * 1e6);
    std::uint64_t we = static_cast<std::uint64_t>((a_start + a_len) * 1e6);

    AttackType types[] = {
        AttackType::RpmSpoof,        AttackType::Replay,
        AttackType::Flood,           AttackType::Fuzz,
        AttackType::DiagAbuse,       AttackType::WheelMasquerade,
        AttackType::SpeedFreeze,     AttackType::ChecksumTamper,
        AttackType::BusOff,          AttackType::AdversarialInject};

    Campaign camp;
    camp.bucket_us = bucket_us;
    int i = 0;
    for (auto t : types) {
        std::fprintf(stderr, "[%d/10] %-20s ", i + 1, to_string(t));
        ScenarioResult r = run_scenario(t, 1000 + i, dur_us, ws, we, bucket_us);
        std::fprintf(stderr,
                     "frames=%llu  P=%.3f R=%.3f F1=%.3f  ttd=%.1fms  p99=%.1fus\n",
                     (unsigned long long)r.total_frames, r.cm.precision(),
                     r.cm.recall(), r.cm.f1(), r.time_to_detect_ms,
                     r.lat_p99_ns / 1000.0);
        camp.results.push_back(std::move(r));
        ++i;
    }

    std::string md = render_markdown(camp);
    std::printf("\n%s\n", md.c_str());

    write_csv(camp, out + "/eval_results.csv");
    write_json(camp, out + "/eval_results.json");
    std::ofstream mdf(out + "/eval_report.md");
    mdf << md;

    std::fprintf(stderr,
                 "\ntotal frames analyzed: %llu   detected: %d/10   "
                 "aggregate F1: %.3f\nwrote %s/eval_results.csv, .json, "
                 "eval_report.md\n",
                 (unsigned long long)camp.total_frames(), camp.detected_count(),
                 camp.aggregate_cm().f1(), out.c_str());
    return 0;
}
