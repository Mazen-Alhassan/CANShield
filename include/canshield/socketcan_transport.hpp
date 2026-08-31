#ifndef CANSHIELD_SOCKETCAN_TRANSPORT_HPP
#define CANSHIELD_SOCKETCAN_TRANSPORT_HPP

#include <string>

#include "canshield/transport.hpp"

namespace canshield {

class SocketCanTransport : public ICanTransport {
public:
    SocketCanTransport() = default;
    ~SocketCanTransport() override { close(); }

    // bind to a SocketCAN interface (e.g. "vcan0", "can0"). Returns false and
    // sets last_error() on failure (interface missing, no permission, or not
    // built with SocketCAN support). When loopback is true the socket also
    // receives frames it transmits, which the IDS uses to self-monitor.
    bool open(const std::string& ifname, bool loopback = true);

    bool send(const CanFrame& frame) override;
    bool receive(CanFrame& out, std::int64_t timeout_us) override;
    std::string name() const override { return ifname_.empty() ? "socketcan:<unbound>" : ifname_; }
    void close() override;

    // true on platforms/builds where SocketCAN is compiled in.
    static bool available();

    const std::string& last_error() const { return last_error_; }

private:
    int fd_ = -1;
    std::string ifname_;
    std::string last_error_;
};

}  // namespace canshield

#endif  // CANSHIELD_SOCKETCAN_TRANSPORT_HPP
