#include <atomic>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <string>

#include "canshield/cli.hpp"
#include "canshield/message_catalog.hpp"
#include "canshield/security_monitor.hpp"
#include "canshield/socketcan_transport.hpp"

using namespace canshield;

static std::atomic<bool> g_stop{false};
static void on_sigint(int) { g_stop = true; }

static void summary(SecurityMonitor& mon) {
    std::map<std::string, std::uint64_t> by_det;
    for (auto& a : mon.alerts()) by_det[a.detector]++;

    std::printf("\n---- summary ----\n");
    std::printf("frames processed : %llu\n",
                (unsigned long long)mon.frames_processed());
    std::printf("alerts raised    : %llu\n",
                (unsigned long long)mon.alerts_raised());
    for (auto& kv : by_det)
        std::printf("  %-12s : %llu\n", kv.first.c_str(),
                    (unsigned long long)kv.second);
    const auto& L = mon.latency();
    std::printf("detection latency: mean %.2f us, p50 %.2f us, p99 %.2f us, "
                "max %.2f us\n",
                L.mean_ns() / 1000.0, L.percentile_ns(0.50) / 1000.0,
                L.percentile_ns(0.99) / 1000.0, L.max_ns() / 1000.0);
}

int main(int argc, char** argv) {
    Args args(argc, argv);
    if (args.has("--help")) {
        std::printf(
            "usage: canshield_monitor (--in trace.csv | --iface vcan0) "
            "[--max-print N] [--json] [--summary-only] [--rate-window-ms N] "
            "[--rate-burst F] [--diag-window-ms N] [--diag-max N]\n");
        return 0;
    }
    std::signal(SIGINT, on_sigint);

    std::uint64_t rate_window_us =
        static_cast<std::uint64_t>(args.geti("--rate-window-ms", 100)) * 1000;
    double rate_burst = args.getf("--rate-burst", 3.0);
    std::uint64_t diag_window_us =
        static_cast<std::uint64_t>(args.geti("--diag-window-ms", 1000)) * 1000;
    int diag_max = static_cast<int>(args.geti("--diag-max", 20));

    SecurityMonitor mon(default_catalog(), /*with_defaults=*/false);
    const MessageCatalog& cat = mon.catalog();
    mon.add_detector(std::make_unique<UnknownIdDetector>(cat));
    mon.add_detector(std::make_unique<ProtocolDetector>(cat));
    mon.add_detector(std::make_unique<ChecksumDetector>(cat));
    mon.add_detector(std::make_unique<CounterDetector>(cat));
    mon.add_detector(std::make_unique<TimingDetector>(cat));
    mon.add_detector(std::make_unique<RangeDetector>(cat));
    mon.add_detector(std::make_unique<RateDetector>(cat, rate_window_us, rate_burst));
    mon.add_detector(std::make_unique<PhysicsConsistencyDetector>());
    mon.add_detector(std::make_unique<DiagnosticDetector>(diag_window_us, diag_max));
    bool json_out = args.has("--json");
    bool summary_only = args.has("--summary-only");
    long max_print = summary_only ? 0 : args.geti("--max-print", 40);
    long printed = 0;
    auto sink = [&](const Alert& a) {
        if (printed < max_print) {
            if (json_out) {
                std::string reason;
                reason.reserve(a.reason.size());
                for (char c : a.reason) {
                    if (c == '"' || c == '\\') reason += '\\';
                    reason += c;
                }
                std::printf(
                    "{\"t\":%llu,\"id\":\"0x%X\",\"detector\":\"%s\","
                    "\"severity\":\"%s\",\"reason\":\"%s\"}\n",
                    (unsigned long long)a.timestamp_us, a.can_id,
                    a.detector.c_str(), to_string(a.severity), reason.c_str());
            } else {
                std::printf("[ALERT] t=%-10llu id=0x%-3X %-11s %-9s %s\n",
                            (unsigned long long)a.timestamp_us, a.can_id,
                            a.detector.c_str(), to_string(a.severity),
                            a.reason.c_str());
            }
            ++printed;
            if (printed == max_print && !json_out)
                std::printf("... (further alerts suppressed; see summary)\n");
        }
    };
    mon.set_sink(sink);

    std::string infile = args.get("--in");
    std::string iface = args.get("--iface");

    if (!infile.empty()) {
        std::ifstream f(infile);
        if (!f) {
            std::fprintf(stderr, "cannot open %s\n", infile.c_str());
            return 1;
        }
        std::string line;
        CanFrame frame;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            if (CanFrame::from_csv(line, frame)) mon.process(frame);
        }
    } else if (!iface.empty()) {
        SocketCanTransport tx;
        if (!tx.open(iface)) {
            std::fprintf(stderr, "%s\n", tx.last_error().c_str());
            return 1;
        }
        std::fprintf(stderr, "monitoring %s (ctrl-c to stop)...\n", iface.c_str());
        CanFrame frame;
        while (!g_stop.load()) {
            if (tx.receive(frame, 200000)) mon.process(frame);
        }
    } else {
        std::fprintf(stderr, "need --in FILE or --iface IFACE\n");
        return 1;
    }

    summary(mon);
    return 0;
}
