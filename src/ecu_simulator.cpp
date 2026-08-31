#include "canshield/ecu_simulator.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <queue>
#include <thread>

#include "canshield/proprietary_protocol.hpp"

namespace canshield {

VehicleModel::VehicleModel(std::uint64_t seed) : rng_(seed) {}

double VehicleModel::target_speed() const {
    // repeating 60s cycle: idle, accelerate, cruise, brake, stop
    double p = std::fmod(t_, 60.0);
    if (p < 10.0) return 0.0;
    if (p < 25.0) return 80.0 * (p - 10.0) / 15.0;  // ramp up to 80
    if (p < 45.0) return 80.0;                        // cruise
    if (p < 55.0) return 80.0 * (55.0 - p) / 10.0;   // ramp down
    return 0.0;
}

void VehicleModel::advance(double dt_s) {
    t_ += dt_s;

    double tgt = target_speed();
    double accel = (tgt - speed_kmh) * 0.6;  // simple first-order approach
    accel = std::clamp(accel, -25.0, 15.0);
    speed_kmh += accel * dt_s;
    if (speed_kmh < 0) speed_kmh = 0;

    // pedals follow the sign of acceleration
    if (accel > 0.5) {
        throttle_pct = std::clamp(8.0 + accel * 4.0 + n(0.5), 0.0, 100.0);
        brake_bar = 0.0;
    } else if (accel < -0.5) {
        throttle_pct = std::clamp(n(0.3), 0.0, 100.0);
        brake_bar = std::clamp(-accel * 2.0 + n(0.3), 0.0, 100.0);
    } else {
        throttle_pct = std::clamp((speed_kmh > 1.0 ? 6.0 : 2.0) + n(0.4), 0.0, 100.0);
        brake_bar = 0.0;
    }

    engine_load_pct = std::clamp(throttle_pct * 0.9 + 10.0 + n(1.0), 0.0, 100.0);

    // gear from speed
    if (speed_kmh < 1.0) gear = (throttle_pct > 3.0 ? 1 : 0);
    else if (speed_kmh < 20.0) gear = 1;
    else if (speed_kmh < 40.0) gear = 2;
    else if (speed_kmh < 60.0) gear = 3;
    else if (speed_kmh < 80.0) gear = 4;
    else gear = 5;

    // rpm correlated with speed and throttle, idle floor at 800
    rpm = std::clamp(800.0 + speed_kmh * 28.0 + throttle_pct * 12.0 + n(15.0),
                     700.0, 7000.0);

    // coolant warms toward operating temp
    coolant_c += (92.0 - coolant_c) * 0.01 * dt_s * 10.0;

    // gentle steering wander
    steering_deg = 12.0 * std::sin(t_ * 0.15) + n(0.4);

    // each wheel = speed with a little independent noise
    for (int i = 0; i < 4; ++i) wheel_kmh[i] = std::max(0.0, speed_kmh + n(0.25));
}

void EcuSimulator::fill_signals(const MessageDef& m, CanFrame& f) {
    for (const auto& s : m.signals) {
        double v = 0.0;
        const std::string& nm = s.name;
        if (nm == "EngineRPM") v = model_.rpm;
        else if (nm == "CoolantTemp") v = model_.coolant_c;
        else if (nm == "ThrottlePosition") v = model_.throttle_pct;
        else if (nm == "EngineLoad") v = model_.engine_load_pct;
        else if (nm == "IntakeAirTemp") v = 25.0;
        else if (nm == "SelectedGear") v = model_.gear;
        else if (nm == "TransTemp") v = model_.coolant_c - 5.0;
        else if (nm == "WheelSpeedFL") v = model_.wheel_kmh[0];
        else if (nm == "WheelSpeedFR") v = model_.wheel_kmh[1];
        else if (nm == "WheelSpeedRL") v = model_.wheel_kmh[2];
        else if (nm == "WheelSpeedRR") v = model_.wheel_kmh[3];
        else if (nm == "BrakePressure") v = model_.brake_bar;
        else if (nm == "BrakePedalPressed") v = model_.brake_bar > 1.0 ? 1.0 : 0.0;
        else if (nm == "VehicleSpeed") v = model_.speed_kmh;
        else if (nm == "SteeringAngle") v = model_.steering_deg;
        else if (nm == "DoorsOpen") v = 0.0;
        else if (nm == "LightsOn") v = 1.0;
        else if (nm == "DoorsLocked") v = 1.0;
        else v = s.min_phys;
        s.pack_phys(f, v);
    }
}

CanFrame EcuSimulator::build_frame(const MessageDef& m) {
    CanFrame f;
    f.id = m.id;
    f.extended = m.extended;
    f.dlc = m.dlc;
    f.data.fill(0);
    fill_signals(m, f);
    if (m.has_integrity) {
        std::uint8_t& ctr = counters_[m.id];
        proto::apply_integrity(f, m.dlc, ctr);
        ctr = (ctr + 1) & 0x0F;
    }
    return f;
}

std::uint64_t EcuSimulator::generate(std::uint64_t duration_us, const Sink& sink) {
    // min-heap of (next_send_us, message index) so frames come out time-ordered
    struct Ev {
        std::uint64_t t;
        std::size_t idx;
        bool operator>(const Ev& o) const { return t > o.t; }
    };
    std::priority_queue<Ev, std::vector<Ev>, std::greater<Ev>> pq;

    const auto& msgs = catalog_.messages();
    for (std::size_t i = 0; i < msgs.size(); ++i) {
        if (msgs[i].period_us() > 0) pq.push({0, i});
    }

    std::uint64_t count = 0;
    std::uint64_t last_model_us = 0;
    while (!pq.empty()) {
        Ev e = pq.top();
        if (e.t >= duration_us) break;
        pq.pop();

        // advance the shared model to this frame's time
        if (e.t > last_model_us) {
            model_.advance((e.t - last_model_us) / 1e6);
            last_model_us = e.t;
        }

        CanFrame f = build_frame(msgs[e.idx]);
        f.timestamp_us = e.t;
        sink(f);
        ++count;

        pq.push({e.t + msgs[e.idx].period_us(), e.idx});
    }
    return count;
}

void EcuSimulator::run(const TransportPtr& tx, const std::atomic<bool>* stop) {
    const auto& msgs = catalog_.messages();
    std::uint64_t start = now_micros();
    std::vector<std::uint64_t> next(msgs.size(), 0);
    std::uint64_t last_model = start;

    while (!stop || !stop->load()) {
        std::uint64_t nowu = now_micros();
        model_.advance((nowu - last_model) / 1e6);
        last_model = nowu;
        std::uint64_t rel = nowu - start;

        for (std::size_t i = 0; i < msgs.size(); ++i) {
            if (msgs[i].period_us() == 0) continue;
            if (rel >= next[i]) {
                CanFrame f = build_frame(msgs[i]);
                tx->send(f);
                next[i] += msgs[i].period_us();
                if (next[i] <= rel) next[i] = rel + msgs[i].period_us();
            }
        }
        std::this_thread::sleep_for(std::chrono::microseconds(500));
    }
}

}  // namespace canshield
