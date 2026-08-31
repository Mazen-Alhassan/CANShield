// CANShield - virtual_bus.cpp
#include "canshield/virtual_bus.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>

namespace canshield {

// One attached node. Holds a thread-safe inbound queue that the bus pushes into
// and receive() pops from.
class VirtualCanEndpoint : public ICanTransport,
                           public std::enable_shared_from_this<VirtualCanEndpoint> {
public:
    VirtualCanEndpoint(std::shared_ptr<VirtualCanBus> bus, std::string name)
        : bus_(std::move(bus)), name_(std::move(name)) {}

    ~VirtualCanEndpoint() override { close(); }

    bool send(const CanFrame& frame) override {
        if (closed_) return false;
        if (!frame.is_well_formed() && !frame.error) {
            // Allow deliberately malformed frames only when flagged as error
            // frames; otherwise reject so bugs surface. Attackers craft
            // protocol anomalies via valid-but-suspicious frames, not by
            // violating the frame's structural invariants here.
            return false;
        }
        auto bus = bus_.lock();
        if (!bus) return false;
        bus->broadcast(frame, this);
        return true;
    }

    bool receive(CanFrame& out, std::int64_t timeout_us) override {
        std::unique_lock<std::mutex> lk(qmtx_);
        auto has_frame = [this] { return !queue_.empty() || closed_; };
        if (timeout_us < 0) {
            qcv_.wait(lk, has_frame);
        } else if (timeout_us == 0) {
            if (!has_frame()) return false;
        } else {
            qcv_.wait_for(lk, std::chrono::microseconds(timeout_us), has_frame);
        }
        if (queue_.empty()) return false;  // timed out or closed while empty
        out = queue_.front();
        queue_.pop_front();
        return true;
    }

    std::string name() const override { return "virtual:" + name_; }

    void close() override {
        if (closed_.exchange(true)) return;
        if (auto bus = bus_.lock()) bus->detach(this);
        {
            std::lock_guard<std::mutex> lk(qmtx_);
        }
        qcv_.notify_all();
    }

    // Called by the bus (under no endpoint lock) to deliver a frame.
    void enqueue(const CanFrame& frame) {
        {
            std::lock_guard<std::mutex> lk(qmtx_);
            if (closed_) return;
            queue_.push_back(frame);
        }
        qcv_.notify_one();
    }

private:
    std::weak_ptr<VirtualCanBus> bus_;
    std::string name_;
    std::atomic<bool> closed_{false};

    std::mutex qmtx_;
    std::condition_variable qcv_;
    std::deque<CanFrame> queue_;
};

TransportPtr VirtualCanBus::attach(const std::string& node_name) {
    auto ep = std::make_shared<VirtualCanEndpoint>(shared_from_this(), node_name);
    std::lock_guard<std::mutex> lk(mtx_);
    endpoints_.push_back(ep);
    return ep;
}

void VirtualCanBus::broadcast(const CanFrame& frame, VirtualCanEndpoint* sender) {
    CanFrame stamped = frame;
    // The bus is the serialization point: stamp arrival time here so every
    // receiver observes a single consistent timestamp and total ordering.
    stamped.timestamp_us = now_micros();
    frame_count_.fetch_add(1);

    // Snapshot live endpoints under the lock, then deliver outside it so a slow
    // receiver cannot block the sender while holding the bus mutex.
    std::vector<std::shared_ptr<VirtualCanEndpoint>> live;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        live.reserve(endpoints_.size());
        for (auto& w : endpoints_) {
            if (auto ep = w.lock()) live.push_back(std::move(ep));
        }
    }
    for (auto& ep : live) {
        if (ep.get() == sender) continue;  // nodes don't hear their own frames
        ep->enqueue(stamped);
    }
}

void VirtualCanBus::detach(VirtualCanEndpoint* leaving) {
    std::lock_guard<std::mutex> lk(mtx_);
    endpoints_.erase(
        std::remove_if(endpoints_.begin(), endpoints_.end(),
                       [&](const std::weak_ptr<VirtualCanEndpoint>& w) {
                           auto ep = w.lock();
                           return !ep || ep.get() == leaving;
                       }),
        endpoints_.end());
}

std::size_t VirtualCanBus::endpoint_count() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::size_t n = 0;
    for (auto& w : endpoints_) {
        if (!w.expired()) ++n;
    }
    return n;
}

}  // namespace canshield
