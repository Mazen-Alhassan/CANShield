// CANShield - socketcan_transport.cpp
#include "canshield/socketcan_transport.hpp"

#ifdef CANSHIELD_HAVE_SOCKETCAN

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace canshield {

bool SocketCanTransport::available() { return true; }

bool SocketCanTransport::open(const std::string& ifname, bool loopback) {
    close();
    last_error_.clear();

    fd_ = ::socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd_ < 0) {
        last_error_ = std::string("socket(PF_CAN): ") + std::strerror(errno);
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        last_error_ = std::string("ioctl(SIOCGIFINDEX ") + ifname + "): " +
                      std::strerror(errno);
        close();
        return false;
    }

    // Receive own transmitted frames when loopback is requested (lets a single
    // process both inject and monitor for testing/self-checks).
    int recv_own = loopback ? 1 : 0;
    ::setsockopt(fd_, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &recv_own,
                 sizeof(recv_own));

    struct sockaddr_can addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        last_error_ = std::string("bind(") + ifname + "): " + std::strerror(errno);
        close();
        return false;
    }

    ifname_ = ifname;
    return true;
}

bool SocketCanTransport::send(const CanFrame& frame) {
    if (fd_ < 0) return false;
    struct can_frame cf;
    std::memset(&cf, 0, sizeof(cf));
    cf.can_id = frame.id;
    if (frame.extended) cf.can_id |= CAN_EFF_FLAG;
    if (frame.rtr) cf.can_id |= CAN_RTR_FLAG;
    if (frame.error) cf.can_id |= CAN_ERR_FLAG;
    cf.can_dlc = frame.dlc > 8 ? 8 : frame.dlc;
    for (int i = 0; i < cf.can_dlc; ++i) cf.data[i] = frame.data[i];

    ssize_t n = ::write(fd_, &cf, sizeof(cf));
    return n == static_cast<ssize_t>(sizeof(cf));
}

bool SocketCanTransport::receive(CanFrame& out, std::int64_t timeout_us) {
    if (fd_ < 0) return false;

    if (timeout_us >= 0) {
        struct timeval tv;
        tv.tv_sec = timeout_us / 1000000;
        tv.tv_usec = timeout_us % 1000000;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd_, &rfds);
        int r = ::select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
        if (r <= 0) return false;  // timeout or error
    }

    struct can_frame cf;
    ssize_t n = ::read(fd_, &cf, sizeof(cf));
    if (n < static_cast<ssize_t>(sizeof(cf))) return false;

    out = CanFrame{};
    out.extended = (cf.can_id & CAN_EFF_FLAG) != 0;
    out.rtr = (cf.can_id & CAN_RTR_FLAG) != 0;
    out.error = (cf.can_id & CAN_ERR_FLAG) != 0;
    out.id = cf.can_id & (out.extended ? CAN_EFF_MASK : CAN_SFF_MASK);
    out.dlc = cf.can_dlc > 8 ? 8 : cf.can_dlc;
    for (int i = 0; i < out.dlc; ++i) out.data[i] = cf.data[i];
    out.timestamp_us = now_micros();
    return true;
}

void SocketCanTransport::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    ifname_.clear();
}

}  // namespace canshield

#else  // !CANSHIELD_HAVE_SOCKETCAN  -- portable stub for macOS/Windows dev

namespace canshield {

bool SocketCanTransport::available() { return false; }

bool SocketCanTransport::open(const std::string& ifname, bool /*loopback*/) {
    ifname_ = ifname;
    last_error_ =
        "SocketCAN not available on this platform; build on Linux and use "
        "vcan0/can0, or use VirtualCanBus for development.";
    return false;
}

bool SocketCanTransport::send(const CanFrame&) { return false; }
bool SocketCanTransport::receive(CanFrame&, std::int64_t) { return false; }
void SocketCanTransport::close() { fd_ = -1; ifname_.clear(); }

}  // namespace canshield

#endif  // CANSHIELD_HAVE_SOCKETCAN
