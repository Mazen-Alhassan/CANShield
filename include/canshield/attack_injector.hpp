#ifndef CANSHIELD_ATTACK_INJECTOR_HPP
#define CANSHIELD_ATTACK_INJECTOR_HPP

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "canshield/message_catalog.hpp"

namespace canshield {

enum class AttackType {
    None = 0,
    RpmSpoof,           // fabricate extra engine frames with false high rpm
    Replay,             // re-inject a captured slice of earlier traffic
    Flood,              // dominant low-id frames to starve the bus (DoS)
    Fuzz,               // random ids + random payloads
    DiagAbuse,          // flood UDS/OBD diagnostic requests while driving
    WheelMasquerade,    // silence ABS ECU, impersonate it with false speeds
    SpeedFreeze,        // fabricate vehicle-speed=0 while moving
    ChecksumTamper,     // alter payload of real frames, leave checksum stale
    BusOff,             // error-frame storm to force a target ECU bus-off
    AdversarialInject,  // just-in-time frame injected right before each real one
};

const char* to_string(AttackType t);

struct LabeledFrame {
    CanFrame frame;
    AttackType label = AttackType::None;  // None => benign ground truth
    bool is_attack() const { return label != AttackType::None; }
};

struct Scenario {
    AttackType type;
    std::uint64_t window_start_us = 0;
    std::uint64_t window_end_us = 0;
    std::vector<LabeledFrame> frames;  // merged, timestamp-sorted, labeled
    std::uint64_t benign_count = 0;
    std::uint64_t attack_count = 0;
};

// builds labeled attack traces by overlaying one attack on a benign trace.
class AttackInjector {
public:
    AttackInjector(MessageCatalog cat, std::uint64_t seed = 42)
        : cat_(std::move(cat)), rng_(seed) {}

    // overlay `type` on `benign` (already timestamp-sorted) within the window.
    Scenario inject(AttackType type, const std::vector<CanFrame>& benign,
                    std::uint64_t win_start_us, std::uint64_t win_end_us);

private:
    // forge a catalog frame; optionally with a valid proprietary checksum.
    CanFrame forge(std::uint32_t id, std::uint8_t counter, bool valid_integrity);

    MessageCatalog cat_;
    std::mt19937 rng_;
};

}  // namespace canshield

#endif
