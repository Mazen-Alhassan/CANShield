#ifndef CANSHIELD_UDS_HPP
#define CANSHIELD_UDS_HPP

#include <atomic>
#include <cstdint>
#include <vector>

#include "canshield/transport.hpp"

namespace canshield {
namespace uds {

// uds service ids we care about
constexpr std::uint8_t kEcuReset = 0x11;
constexpr std::uint8_t kSecurityAccess = 0x27;
constexpr std::uint8_t kPositive = 0x40;  // add to sid for a positive reply
constexpr std::uint8_t kNegative = 0x7F;

// negative response codes
constexpr std::uint8_t kNrcSecurityDenied = 0x33;
constexpr std::uint8_t kNrcInvalidKey = 0x35;

// weak seed->key routine recovered by reverse engineering the ecu
std::uint16_t key_from_seed(std::uint16_t seed);

// a diagnostic ecu with a lazy seed/key scheme. run() serves requests until
// *stop is set. this is the "vulnerable target".
class UdsEcu {
public:
    UdsEcu(std::uint32_t req_id, std::uint32_t resp_id, std::uint16_t seed = 0xBEEF)
        : req_id_(req_id), resp_id_(resp_id), seed_(seed) {}

    void run(const TransportPtr& tx, const std::atomic<bool>* stop);
    bool unlocked() const { return unlocked_; }

private:
    void handle(const std::vector<std::uint8_t>& req, const TransportPtr& tx);
    std::uint32_t req_id_, resp_id_;
    std::uint16_t seed_;
    std::uint16_t expected_key_ = 0;
    bool unlocked_ = false;
};

// sends single-frame uds requests and waits for the reply
class UdsClient {
public:
    UdsClient(TransportPtr tx, std::uint32_t req_id, std::uint32_t resp_id)
        : tx_(std::move(tx)), req_id_(req_id), resp_id_(resp_id) {}

    // send `payload`, return the reply bytes (empty on timeout)
    std::vector<std::uint8_t> request(const std::vector<std::uint8_t>& payload,
                                      std::int64_t timeout_us = 500000);

private:
    TransportPtr tx_;
    std::uint32_t req_id_, resp_id_;
};

// iso-tp single-frame helpers (payload must be <= 7 bytes)
CanFrame pack_single_frame(std::uint32_t id, const std::vector<std::uint8_t>& payload);
std::vector<std::uint8_t> parse_single_frame(const CanFrame& f);

}  // namespace uds
}  // namespace canshield

#endif
