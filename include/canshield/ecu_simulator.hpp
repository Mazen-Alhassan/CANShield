#ifndef CANSHIELD_ECU_SIMULATOR_HPP
#define CANSHIELD_ECU_SIMULATOR_HPP

#include <atomic>
#include <cstdint>
#include <functional>
#include <random>
#include <unordered_map>

#include "canshield/message_catalog.hpp"
#include "canshield/transport.hpp"

namespace canshield {

// simple vehicle physics so signals look real and stay correlated
// (rpm tracks speed, wheel speeds track speed, etc.)
class VehicleModel {
public:
    explicit VehicleModel(std::uint64_t seed = 1);

    // advance state by dt seconds along a repeating drive cycle
    void advance(double dt_s);

    double speed_kmh = 0.0;
    double rpm = 800.0;
    double throttle_pct = 0.0;
    double brake_bar = 0.0;
    double coolant_c = 20.0;
    double engine_load_pct = 0.0;
    double steering_deg = 0.0;
    int gear = 0;
    double wheel_kmh[4] = {0, 0, 0, 0};  // FL, FR, RL, RR

private:
    double t_ = 0.0;
    std::mt19937 rng_;
    std::normal_distribution<double> noise_{0.0, 1.0};
    double n(double sd) { return noise_(rng_) * sd; }
    double target_speed() const;  // drive-cycle setpoint at current t_
};

// turns the vehicle model into correctly-formatted CAN frames (counter +
// checksum applied) at each message's period. works two ways:
//   * generate(): fast offline trace, synthetic timestamps, for the harness
//   * run(): real-time send loop over a transport, for the live demo
class EcuSimulator {
public:
    using Sink = std::function<void(const CanFrame&)>;

    EcuSimulator(MessageCatalog catalog, std::uint64_t seed = 1)
        : catalog_(std::move(catalog)), model_(seed) {}

    const MessageCatalog& catalog() const { return catalog_; }

    // emit every periodic message due in [0, duration_us), in timestamp order.
    // returns number of frames produced.
    std::uint64_t generate(std::uint64_t duration_us, const Sink& sink);

    // real-time loop: send periodic frames until *stop becomes true.
    void run(const TransportPtr& tx, const std::atomic<bool>* stop);

    // build the current frame for one message id (signals + integrity).
    // exposed so the attack injector can forge frames that look legitimate.
    CanFrame build_frame(const MessageDef& m);

private:
    void fill_signals(const MessageDef& m, CanFrame& f);

    MessageCatalog catalog_;
    VehicleModel model_;
    std::unordered_map<std::uint32_t, std::uint8_t> counters_;  // per-id rolling
};

}  // namespace canshield

#endif
