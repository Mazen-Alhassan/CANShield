# architecture

## the idea

A real car has a bunch of ECUs (engine, ABS, body, cluster...) sharing one CAN bus.
CAN has no authentication — any node can send any message id — so an attacker with bus
access can spoof, replay, or flood. CANShield builds that world in software and then tries
to catch the attacks.

## data flow

```
                      +--------------------+
                      |   ECU simulator    |  vehicle physics -> realistic
                      | (engine, abs, ...) |  periodic frames w/ counter+checksum
                      +---------+----------+
                                | CanFrame
                                v
   +--------------------+   shared bus   +--------------------+
   |  attack injector   |-------------- >|  security monitor  |
   | (10 scenarios)     |  CanFrame      |  (9 detectors)     |
   +--------------------+                +---------+----------+
                                                   | Alert
                                                   v
                                    +-----------------------------+
                                    | evaluation harness / CLIs   |
                                    | precision/recall/F1, latency|
                                    +-----------------------------+
```

The "shared bus" is an interface (`ICanTransport`), not a concrete thing. That's the key
design choice: it has two implementations and everything above it is identical either way.

- `VirtualCanBus` — in-process broadcast bus. Any OS, no hardware. Used for dev, tests, and
  the offline evaluation.
- `SocketCanTransport` — real Linux SocketCAN (`vcan0` / `can0`). Used on the Raspberry Pi.

So the same ECU sim, the same attacks, and the same detectors run on a laptop and on a Pi.

## pieces

| file | what it is |
|---|---|
| `can_frame.hpp/.cpp` | the frame struct + bit-level big-endian signal codec |
| `transport.hpp` | the `ICanTransport` interface |
| `virtual_bus.*` | in-process broadcast bus (thread-safe, total-ordered) |
| `socketcan_transport.*` | real SocketCAN, with a portable stub off-Linux |
| `message_catalog.*` | the "Subsonic Motors" bus matrix (ids, periods, signals, ranges) |
| `proprietary_protocol.*` | the reverse-engineered counter + checksum scheme |
| `ecu_simulator.*` | vehicle model + frame generator (offline + real-time) |
| `attack_injector.*` | the 10 attack scenarios, producing labeled traces |
| `detectors.*` | the 9 individual detectors |
| `security_monitor.*` | runs the detector chain, times each frame, collects alerts |
| `metrics.*` | confusion matrix, report writers (md/csv/json) |

## how detection is timed

`SecurityMonitor::process()` wraps just the detector chain in a `steady_clock` measurement
(nanoseconds) and stores every sample, so the report can show real percentiles (p50/p99/p999/max),
not just an average. The detectors are written to be allocation-light and O(1)-ish per frame,
which is what keeps the tail under the 1 ms budget.

## why it stays fast

- one flat `CanFrame` (no heap, `std::array<uint8,8>`), copyable
- catalog lookups are a single hash-map hit per id
- the per-frame alert buffer is reused (`scratch_`) so a clean frame does zero allocation
- rate/timing detectors keep small per-id sliding windows, trimmed in place

The offline harness processes ~1.9M frames/sec single-threaded on a laptop, which is far
above the ~460 frames/sec a real bus at these periods produces.
