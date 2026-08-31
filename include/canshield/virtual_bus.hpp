// CANShield - virtual_bus.hpp
// An in-process, broadcast CAN bus used for development and automated testing
// on any OS. It models the essential property of a real CAN bus: it is a shared
// broadcast medium, so every frame transmitted by one node is delivered to all
// other attached nodes, in a single global order, each stamped with the moment
// it entered the bus.
//
// This is what lets the ECU simulator, attack injector and IDS be exercised on
// a laptop with no CAN hardware; on a Raspberry Pi you swap it for
// SocketCanTransport against vcan0/can0 with no other code changes.
#ifndef CANSHIELD_VIRTUAL_BUS_HPP
#define CANSHIELD_VIRTUAL_BUS_HPP

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "canshield/transport.hpp"

namespace canshield {

class VirtualCanEndpoint;  // implements ICanTransport

// The shared bus. Create one, then attach() an endpoint per node (each ECU, the
// attacker, the monitor). Endpoints keep the bus alive via shared_ptr; the bus
// tracks endpoints weakly so closing an endpoint cleanly removes it.
class VirtualCanBus : public std::enable_shared_from_this<VirtualCanBus> {
public:
    static std::shared_ptr<VirtualCanBus> create() {
        return std::shared_ptr<VirtualCanBus>(new VirtualCanBus());
    }

    // Attach a new endpoint. `node_name` is for diagnostics only.
    TransportPtr attach(const std::string& node_name);

    // Total number of frames that have crossed the bus since creation.
    std::uint64_t total_frames() const { return frame_count_.load(); }

    // Number of currently attached (live) endpoints.
    std::size_t endpoint_count() const;

private:
    friend class VirtualCanEndpoint;
    VirtualCanBus() = default;

    // Deliver `frame` to every attached endpoint except `sender`. Called by an
    // endpoint's send(). Assigns the bus-entry timestamp and a monotonically
    // increasing sequence number that establishes the global bus order.
    void broadcast(const CanFrame& frame, VirtualCanEndpoint* sender);

    // Drop dead (expired) endpoints and, optionally, `leaving`.
    void detach(VirtualCanEndpoint* leaving);

    mutable std::mutex mtx_;
    std::vector<std::weak_ptr<VirtualCanEndpoint>> endpoints_;
    std::atomic<std::uint64_t> frame_count_{0};
};

}  // namespace canshield

#endif  // CANSHIELD_VIRTUAL_BUS_HPP
