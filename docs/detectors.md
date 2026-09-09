# detectors

Short reference for each of the 9 detectors in the chain (`include/canshield/detectors.hpp`,
`src/detectors.cpp`). Every detector implements `IDetector::inspect()` and runs on every frame
in bus order; a frame can trip more than one.

| detector | catches | severity |
|---|---|---|
| `unknown_id` | a CAN id not present in the bus matrix at all (fuzzing, junk injection) | High |
| `protocol` | error frames, malformed frames, or a DLC that disagrees with the catalog for a known id | High / Medium |
| `checksum` | a payload whose reverse-engineered checksum doesn't match, on integrity-protected messages | High |
| `counter` | a rolling counter that doesn't advance by exactly one (replay, masquerade) | High |
| `timing` | an inter-arrival gap shorter than the message's expected period allows, by a configurable tolerance | Medium |
| `range` | a decoded signal value outside its physical min/max (spoofed values) | Medium |
| `rate` | a per-id burst above its expected rate, or a flood of an unknown id, in a sliding time window | High / Critical |
| `physics` | wheel speed disagreeing with vehicle speed, or engine RPM implausible for the car being stationary | High |
| `diagnostic` | diagnostic/UDS ids (0x700-0x7FF) arriving more often than expected while driving | High |

`unknown_id`, `protocol`, `checksum`, `counter`, `timing`, and `range` only need the current
frame plus a small amount of per-id state (or none at all). `rate` and `diagnostic` keep a
trimmed per-id timestamp window, sized in microseconds via a constructor parameter (defaults:
100ms window / 3x burst factor for `rate`, 1s window / 20 hits for `diagnostic`). `physics` has
no config; it simply caches the last few signal values it needs for the cross-check.
