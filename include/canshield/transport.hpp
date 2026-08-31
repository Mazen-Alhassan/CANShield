#ifndef CANSHIELD_TRANSPORT_HPP
#define CANSHIELD_TRANSPORT_HPP

#include <cstdint>
#include <memory>
#include <string>

#include "canshield/can_frame.hpp"

namespace canshield {

// A CAN bus endpoint. A node writes frames with send() and reads every frame
// on the bus (except, conventionally, its own) with receive().
class ICanTransport {
public:
    virtual ~ICanTransport() = default;

    // transmit `frame` onto the bus. Returns false if the transport is closed
    // or the frame is malformed. The transport is responsible for stamping the
    // frame's timestamp_us at the point it hits the bus if it is zero.
    virtual bool send(const CanFrame& frame) = 0;

    // receive the next frame into `out`.
    //   timeout_us <  0 : block indefinitely
    //   timeout_us == 0 : non-blocking poll
    //   timeout_us >  0 : block up to that many microseconds
    // returns true if a frame was delivered, false on timeout/closed.
    virtual bool receive(CanFrame& out, std::int64_t timeout_us) = 0;

    // interface name, e.g. "vcan0" or "virtual:monitor".
    virtual std::string name() const = 0;

    // detach from the bus / close the socket. Idempotent.
    virtual void close() = 0;
};

using TransportPtr = std::shared_ptr<ICanTransport>;

}  // namespace canshield

#endif  // CANSHIELD_TRANSPORT_HPP
