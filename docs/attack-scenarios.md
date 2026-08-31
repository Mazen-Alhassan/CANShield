# attack scenarios

Ten attacks, each injected over an otherwise-normal trace with ground-truth labels so the
harness can score detection. They're chosen to hit different detectors — some are loud
(flood), some are subtle (masquerade).

| # | name | what it does | primarily caught by |
|---|------|--------------|---------------------|
| 1 | `rpm_spoof` | fabricates extra `0x100` engine frames at 2× rate with false 6500 rpm | timing, range, physics, counter |
| 2 | `replay` | captures ~400 ms of early idle traffic and replays it verbatim later | counter, timing |
| 3 | `flood_dos` | blasts id `0x000` (max priority) at 1 ms to starve the bus | rate, unknown-id |
| 4 | `fuzz` | random ids + random payloads sprayed on the bus | unknown-id, protocol, checksum |
| 5 | `diag_abuse` | floods OBD/UDS request `0x7DF` (tester-present) while "driving" | diagnostic, rate |
| 6 | `wheel_masquerade` | silences the real ABS ECU and impersonates `0x200` with false low speeds | physics, counter |
| 7 | `speed_freeze` | fabricates vehicle-speed = 0 on `0x400` while the car is moving | rate, timing, physics |
| 8 | `checksum_tamper` | flips a signal bit in real `0x100` frames, leaves the checksum stale | checksum |
| 9 | `bus_off` | error-frame storm aimed at forcing a target ECU into bus-off | protocol |
| 10 | `adversarial_inject` | injects a spoofed `0x0A0` ~1 ms *before* each real one | timing, counter |

## the detectors

| detector | catches |
|---|---|
| `unknown_id` | ids not in the bus matrix (fuzz, flood junk) |
| `protocol` | error frames, malformed frames, wrong DLC |
| `checksum` | broken proprietary checksum (tamper, fuzz) |
| `counter` | rolling counter that repeats/skips (replay, masquerade, injection) |
| `timing` | inter-arrival shorter than the id's period (injection, spoof) |
| `rate` | per-id / unknown-id bursts over a sliding window (flood, spoof, diag) |
| `range` | decoded signal outside its physical min/max (spoofed values) |
| `physics` | cross-signal contradictions: wheel speed vs vehicle speed, rpm vs motion |
| `diagnostic` | diagnostic ids appearing at abnormal rate while driving |

## the interesting one: masquerade

`wheel_masquerade` is the hard case and the reason the physics detector exists. The attacker
does everything "right": stops the real ECU, sends `0x200` at the correct 10 ms period, with a
valid checksum and a self-consistent rolling counter. Structurally it's a perfect ABS message.

The only thing it can't fake is agreement with the *rest* of the bus: it reports 5 km/h while
the cluster's `0x400` vehicle speed still says 80. The physics detector flags that mismatch.

But when the car is actually going slow (idle/stop parts of the drive cycle), 5 km/h isn't a
contradiction, so those moments are genuinely ambiguous. That's why masquerade recall is ~0.63
instead of ~1.0 — and that's the honest answer, not a bug. Catching it fully would need either
a second trusted speed source or a model of plausible dynamics.

## reproducing one

```sh
./build/canshield_attack --attack wheel_masquerade --seconds 20 \
    --attack-start 8 --attack-len 6 --out data/masq.csv
./build/canshield_monitor --in data/masq.csv
```
