#include "canshield/uds.hpp"

namespace canshield {
namespace uds {

std::uint16_t key_from_seed(std::uint16_t seed) {
    // trivial obfuscation, exactly the kind real ecus have shipped
    return static_cast<std::uint16_t>((seed ^ 0x1234) + 0x1111);
}

CanFrame pack_single_frame(std::uint32_t id, const std::vector<std::uint8_t>& p) {
    CanFrame f;
    f.id = id;
    f.dlc = 8;
    f.data.fill(0xAA);  // padding
    f.data[0] = static_cast<std::uint8_t>(p.size() & 0x0F);  // SF pci = length
    for (std::size_t i = 0; i < p.size() && i < 7; ++i) f.data[i + 1] = p[i];
    return f;
}

std::vector<std::uint8_t> parse_single_frame(const CanFrame& f) {
    std::vector<std::uint8_t> out;
    std::size_t len = f.data[0] & 0x0F;
    for (std::size_t i = 0; i < len && i + 1 < 8; ++i) out.push_back(f.data[i + 1]);
    return out;
}

std::vector<std::uint8_t> UdsClient::request(const std::vector<std::uint8_t>& payload,
                                             std::int64_t timeout_us) {
    tx_->send(pack_single_frame(req_id_, payload));
    CanFrame f;
    std::uint64_t deadline = now_micros() + static_cast<std::uint64_t>(timeout_us);
    while (now_micros() < deadline) {
        if (tx_->receive(f, 50000) && f.id == resp_id_) return parse_single_frame(f);
    }
    return {};
}

void UdsEcu::handle(const std::vector<std::uint8_t>& req, const TransportPtr& tx) {
    auto reply = [&](std::vector<std::uint8_t> p) {
        tx->send(pack_single_frame(resp_id_, p));
    };
    if (req.empty()) return;
    std::uint8_t sid = req[0];

    if (sid == kSecurityAccess && req.size() >= 2) {
        std::uint8_t sub = req[1];
        if (sub == 0x01) {  // request seed
            expected_key_ = key_from_seed(seed_);
            reply({kSecurityAccess + kPositive, 0x01,
                   static_cast<std::uint8_t>(seed_ >> 8),
                   static_cast<std::uint8_t>(seed_ & 0xFF)});
        } else if (sub == 0x02 && req.size() >= 4) {  // send key
            std::uint16_t key = (req[2] << 8) | req[3];
            if (key == expected_key_) {
                unlocked_ = true;
                reply({kSecurityAccess + kPositive, 0x02});
            } else {
                reply({kNegative, kSecurityAccess, kNrcInvalidKey});
            }
        }
    } else if (sid == kEcuReset) {
        if (unlocked_) {
            reply({kEcuReset + kPositive, 0x01});
            unlocked_ = false;  // reboot re-locks
        } else {
            reply({kNegative, kEcuReset, kNrcSecurityDenied});
        }
    }
}

void UdsEcu::run(const TransportPtr& tx, const std::atomic<bool>* stop) {
    CanFrame f;
    while (!stop || !stop->load()) {
        if (tx->receive(f, 100000) && f.id == req_id_) handle(parse_single_frame(f), tx);
    }
}

}  // namespace uds
}  // namespace canshield
