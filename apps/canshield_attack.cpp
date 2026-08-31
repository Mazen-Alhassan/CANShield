// generates a benign trace with one attack overlaid, written as a labeled csv
// (last column is the ground-truth attack label). feed it to canshield_monitor.

#include <cstdio>
#include <fstream>

#include "canshield/attack_injector.hpp"
#include "canshield/cli.hpp"
#include "canshield/ecu_simulator.hpp"

using namespace canshield;

int main(int argc, char** argv) {
    Args args(argc, argv);
    if (args.has("--help") || !args.has("--attack")) {
        std::printf(
            "usage: canshield_attack --attack NAME [--seconds N] "
            "[--attack-start S] [--attack-len L] [--out FILE]\n"
            "  attacks: rpm_spoof replay flood_dos fuzz diag_abuse\n"
            "           wheel_masquerade speed_freeze checksum_tamper\n"
            "           bus_off adversarial_inject\n");
        return args.has("--help") ? 0 : 1;
    }

    bool ok = false;
    AttackType type = attack_from_string(args.get("--attack"), &ok);
    if (!ok) {
        std::fprintf(stderr, "unknown attack: %s\n", args.get("--attack").c_str());
        return 1;
    }

    double seconds = args.getf("--seconds", 20.0);
    double a_start = args.getf("--attack-start", 8.0);
    double a_len = args.getf("--attack-len", 6.0);
    std::string out = args.get("--out", "data/attack_trace.csv");

    EcuSimulator sim(default_catalog());
    std::vector<CanFrame> benign;
    sim.generate(static_cast<std::uint64_t>(seconds * 1e6),
                 [&](const CanFrame& f) { benign.push_back(f); });

    AttackInjector inj(default_catalog());
    Scenario sc = inj.inject(type, benign,
                             static_cast<std::uint64_t>(a_start * 1e6),
                             static_cast<std::uint64_t>((a_start + a_len) * 1e6));

    std::ofstream f(out);
    for (auto& lf : sc.frames)
        f << lf.frame.to_csv() << ',' << to_string(lf.label) << '\n';

    std::fprintf(stderr,
                 "wrote %s: %llu frames (%llu benign, %llu %s) window [%.1f,%.1f]s\n",
                 out.c_str(), (unsigned long long)sc.frames.size(),
                 (unsigned long long)sc.benign_count,
                 (unsigned long long)sc.attack_count, to_string(type), a_start,
                 a_start + a_len);
    return 0;
}
