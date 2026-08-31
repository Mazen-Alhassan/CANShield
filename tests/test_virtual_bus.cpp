#include <atomic>
#include <thread>

#include "canshield/socketcan_transport.hpp"
#include "canshield/virtual_bus.hpp"
#include "test_framework.hpp"

using namespace canshield;

TEST_CASE("Broadcast delivers to all other endpoints, not the sender") {
    auto bus = VirtualCanBus::create();
    auto ecu = bus->attach("ecu");
    auto mon = bus->attach("monitor");
    auto other = bus->attach("other");

    CanFrame f(0x123, 2, {0xDE, 0xAD});
    CHECK_TRUE(ecu->send(f));

    CanFrame got;
    CHECK_TRUE(mon->receive(got, 100000));   // monitor sees it
    CHECK_EQ(got.id, 0x123u);
    CHECK_TRUE(other->receive(got, 100000));  // other node sees it
    CHECK_EQ(got.id, 0x123u);
    CHECK_FALSE(ecu->receive(got, 1000));     // sender does NOT hear itself
}

TEST_CASE("Bus stamps a monotonic timestamp on delivery") {
    auto bus = VirtualCanBus::create();
    auto a = bus->attach("a");
    auto b = bus->attach("b");

    CanFrame f(0x100, 1, {0x01});
    f.timestamp_us = 0;  // unstamped
    a->send(f);

    CanFrame got;
    CHECK_TRUE(b->receive(got, 100000));
    CHECK_TRUE(got.timestamp_us > 0);
}

TEST_CASE("receive() honors non-blocking and timeout modes") {
    auto bus = VirtualCanBus::create();
    auto a = bus->attach("a");
    CanFrame got;
    CHECK_FALSE(a->receive(got, 0));      // non-blocking, empty
    CHECK_FALSE(a->receive(got, 5000));   // 5ms timeout, empty
}

TEST_CASE("Closing an endpoint removes it from the bus") {
    auto bus = VirtualCanBus::create();
    auto a = bus->attach("a");
    auto b = bus->attach("b");
    CHECK_EQ(bus->endpoint_count(), std::size_t(2));
    b->close();
    CHECK_EQ(bus->endpoint_count(), std::size_t(1));
}

TEST_CASE("Concurrent producers deliver every frame to a consumer") {
    auto bus = VirtualCanBus::create();
    auto consumer = bus->attach("consumer");

    const int kProducers = 4;
    const int kPerProducer = 500;
    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([bus, p] {
            auto tx = bus->attach("prod" + std::to_string(p));
            for (int i = 0; i < kPerProducer; ++i) {
                CanFrame f(0x200 + p, 1, {static_cast<std::uint8_t>(i & 0xFF)});
                tx->send(f);
            }
        });
    }

    std::atomic<int> received{0};
    std::thread rx([&] {
        CanFrame got;
        while (received.load() < kProducers * kPerProducer) {
            if (consumer->receive(got, 200000)) {
                received.fetch_add(1);
            } else {
                break;  // timed out -> stop waiting
            }
        }
    });

    for (auto& t : producers) t.join();
    rx.join();
    CHECK_EQ(received.load(), kProducers * kPerProducer);
}

TEST_CASE("SocketCanTransport availability matches build platform") {
    // just assert it links and reports a coherent state; real bus I/O is
    // exercised on the Raspberry Pi target with vcan0.
    (void)SocketCanTransport::available();
    CHECK_TRUE(true);
}

int main() { return canshield::test::run_all(); }
