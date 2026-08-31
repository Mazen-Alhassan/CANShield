#include "canshield/attack_injector.hpp"

#include <algorithm>

#include "canshield/proprietary_protocol.hpp"

namespace canshield {

const char* to_string(AttackType t) {
    switch (t) {
        case AttackType::None: return "benign";
        case AttackType::RpmSpoof: return "rpm_spoof";
        case AttackType::Replay: return "replay";
        case AttackType::Flood: return "flood_dos";
        case AttackType::Fuzz: return "fuzz";
        case AttackType::DiagAbuse: return "diag_abuse";
        case AttackType::WheelMasquerade: return "wheel_masquerade";
        case AttackType::SpeedFreeze: return "speed_freeze";
        case AttackType::ChecksumTamper: return "checksum_tamper";
        case AttackType::BusOff: return "bus_off";
        case AttackType::AdversarialInject: return "adversarial_inject";
    }
    return "unknown";
}

CanFrame AttackInjector::forge(std::uint32_t id, std::uint8_t counter,
                               bool valid_integrity) {
    CanFrame f;
    const MessageDef* m = cat_.find(id);
    f.id = id;
    f.extended = m ? m->extended : false;
    f.dlc = m ? m->dlc : 8;
    f.data.fill(0);
    if (m && m->has_integrity && valid_integrity) {
        proto::apply_integrity(f, m->dlc, counter);
    }
    return f;
}

Scenario AttackInjector::inject(AttackType type,
                                const std::vector<CanFrame>& benign,
                                std::uint64_t ws, std::uint64_t we) {
    Scenario sc;
    sc.type = type;
    sc.window_start_us = ws;
    sc.window_end_us = we;

    std::vector<LabeledFrame> out;
    out.reserve(benign.size() + 4096);

    // helper: is this benign frame dropped by the attack? (masquerade/suspension)
    auto dropped = [&](const CanFrame& f) -> bool {
        if (type == AttackType::WheelMasquerade && f.id == 0x200 &&
            f.timestamp_us >= ws && f.timestamp_us < we) {
            return true;  // real ABS ECU is silenced
        }
        return false;
    };

    // copy benign frames (some mutated in place for the tamper attack)
    for (const auto& bf : benign) {
        if (dropped(bf)) continue;
        LabeledFrame lf;
        lf.frame = bf;
        lf.label = AttackType::None;

        if (type == AttackType::ChecksumTamper && bf.id == 0x100 &&
            bf.timestamp_us >= ws && bf.timestamp_us < we) {
            // flip a signal bit but leave the checksum byte untouched
            lf.frame.data[1] ^= 0x08;
            lf.label = AttackType::ChecksumTamper;
        }
        out.push_back(lf);
    }

    auto add = [&](CanFrame f, std::uint64_t ts) {
        f.timestamp_us = ts;
        out.push_back(LabeledFrame{f, type});
    };

    std::uniform_int_distribution<int> byte(0, 255);
    std::uniform_int_distribution<std::uint32_t> anyid(0, 0x7FF);
    std::uniform_int_distribution<int> dlcd(0, 8);

    switch (type) {
        case AttackType::None:
        case AttackType::ChecksumTamper:
            break;  // already handled above

        case AttackType::RpmSpoof: {
            // fabricate engine frames at 5ms (2x legit rate), false 6500 rpm,
            // valid checksum + plausible counter -> caught by rate/content
            SignalDef rpm{"EngineRPM", 0, 16, 0.25, 0.0, 0.0, 8000.0, "rpm"};
            std::uint8_t ctr = 0;
            for (std::uint64_t t = ws; t < we; t += 5000) {
                CanFrame f = forge(0x100, ctr, /*valid=*/true);
                rpm.pack_phys(f, 6500.0);
                proto::apply_integrity(f, f.dlc, ctr);
                ctr = (ctr + 1) & 0x0F;
                add(f, t);
            }
            break;
        }

        case AttackType::Replay: {
            // capture ~400ms of early idle traffic, replay it verbatim in-window
            std::uint64_t cap_start = 0, cap_end = 400000;
            std::vector<CanFrame> captured;
            for (const auto& bf : benign)
                if (bf.timestamp_us >= cap_start && bf.timestamp_us < cap_end)
                    captured.push_back(bf);
            if (!captured.empty()) {
                std::uint64_t base = captured.front().timestamp_us;
                for (const auto& cf : captured) {
                    std::uint64_t ts = ws + (cf.timestamp_us - base);
                    if (ts >= we) break;
                    add(cf, ts);  // stale counters + stale content
                }
            }
            break;
        }

        case AttackType::Flood: {
            // id 0x000 (max priority) at 1ms -> ~1000 fps, bus starvation
            for (std::uint64_t t = ws; t < we; t += 1000) {
                CanFrame f;
                f.id = 0x000;
                f.dlc = 8;
                f.data.fill(0xFF);
                add(f, t);
            }
            break;
        }

        case AttackType::Fuzz: {
            // random ids and payloads every 2ms
            for (std::uint64_t t = ws; t < we; t += 2000) {
                CanFrame f;
                f.id = anyid(rng_);
                f.dlc = static_cast<std::uint8_t>(dlcd(rng_));
                for (int i = 0; i < f.dlc; ++i)
                    f.data[i] = static_cast<std::uint8_t>(byte(rng_));
                add(f, t);
            }
            break;
        }

        case AttackType::DiagAbuse: {
            // hammer OBD functional requests (tester-present / read-DTC) at 5ms
            for (std::uint64_t t = ws; t < we; t += 5000) {
                CanFrame f;
                f.id = diag::kObdFunctionalRequest;  // 0x7DF
                f.dlc = 8;
                f.data = {0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                add(f, t);
            }
            break;
        }

        case AttackType::WheelMasquerade: {
            // real 0x200 dropped above; impersonate it at 10ms with false 5 km/h
            SignalDef fl{"WheelSpeedFL", 0, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"};
            SignalDef fr{"WheelSpeedFR", 12, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"};
            SignalDef rl{"WheelSpeedRL", 24, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"};
            SignalDef rr{"WheelSpeedRR", 36, 12, 0.0625, 0.0, 0.0, 250.0, "km/h"};
            std::uint8_t ctr = 0;
            for (std::uint64_t t = ws; t < we; t += 10000) {
                CanFrame f = forge(0x200, ctr, true);
                fl.pack_phys(f, 5.0); fr.pack_phys(f, 5.0);
                rl.pack_phys(f, 5.0); rr.pack_phys(f, 5.0);
                proto::apply_integrity(f, f.dlc, ctr);
                ctr = (ctr + 1) & 0x0F;
                add(f, t);
            }
            break;
        }

        case AttackType::SpeedFreeze: {
            // fabricate vehicle-speed = 0 at 10ms alongside the real 20ms frames
            SignalDef sp{"VehicleSpeed", 0, 16, 0.01, 0.0, 0.0, 300.0, "km/h"};
            std::uint8_t ctr = 0;
            for (std::uint64_t t = ws; t < we; t += 10000) {
                CanFrame f = forge(0x400, ctr, true);
                sp.pack_phys(f, 0.0);
                proto::apply_integrity(f, f.dlc, ctr);
                ctr = (ctr + 1) & 0x0F;
                add(f, t);
            }
            break;
        }

        case AttackType::BusOff: {
            // error-frame storm targeting the bus at 2ms
            for (std::uint64_t t = ws; t < we; t += 2000) {
                CanFrame f;
                f.id = 0x100;
                f.dlc = 0;
                f.error = true;
                add(f, t);
            }
            break;
        }

        case AttackType::AdversarialInject: {
            // just-in-time: a spoof 0x0A0 ~1ms before each real one, doubling
            // its arrival rate with off-cadence timing
            std::uint8_t ctr = 0;
            for (std::uint64_t t = ws + 9000; t < we; t += 10000) {
                CanFrame f = forge(0x0A0, ctr, true);
                proto::apply_integrity(f, f.dlc, ctr);
                ctr = (ctr + 1) & 0x0F;
                add(f, t);
            }
            break;
        }
    }

    std::stable_sort(out.begin(), out.end(),
                     [](const LabeledFrame& a, const LabeledFrame& b) {
                         return a.frame.timestamp_us < b.frame.timestamp_us;
                     });

    for (auto& lf : out) (lf.is_attack() ? sc.attack_count : sc.benign_count)++;
    sc.frames = std::move(out);
    return sc;
}

}  // namespace canshield
