// generates normal vehicle traffic, either printed or written to a csv trace

#include <cstdio>
#include <fstream>

#include "canshield/cli.hpp"
#include "canshield/ecu_simulator.hpp"

using namespace canshield;

int main(int argc, char** argv) {
    Args args(argc, argv);
    if (args.has("--help")) {
        std::printf(
            "usage: canshield_ecu_sim [--seconds N] [--out trace.csv] [--print]\n"
            "  --seconds N   duration of traffic to generate (default 10)\n"
            "  --out FILE    write csv trace (ts,id,ext,dlc,rtr,err,payload)\n"
            "  --print       print candump-style lines to stdout\n");
        return 0;
    }

    double seconds = args.getf("--seconds", 10.0);
    std::string out = args.get("--out");
    bool print = args.has("--print") || out.empty();

    EcuSimulator sim(default_catalog());
    std::ofstream ofs;
    if (!out.empty()) ofs.open(out);

    std::uint64_t n = sim.generate(
        static_cast<std::uint64_t>(seconds * 1e6), [&](const CanFrame& f) {
            if (ofs.is_open()) ofs << f.to_csv() << "\n";
            if (print) std::printf("%10llu  %s\n",
                                   (unsigned long long)f.timestamp_us,
                                   f.to_string().c_str());
        });

    std::fprintf(stderr, "generated %llu frames over %.1fs (%.0f frames/s)\n",
                 (unsigned long long)n, seconds, n / seconds);
    return 0;
}
