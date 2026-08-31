# reverse engineering the "subsonic motors" protocol

The point of this part was to practice the thing you actually do on a real car: you capture
CAN traffic you don't have a spec for, and you figure out the message format from patterns.

"Subsonic Motors" is a made-up OEM. The format below is what a `candump` session on its bus
would look like, and how you'd recover it. (In this repo the "answer" lives in
`message_catalog.cpp` and `proprietary_protocol.cpp`, but the process is the interesting bit.)

## step 1 — which ids exist, and how often

Log everything and count ids by arrival rate:

```
id     count/s   guess
0x0A0    100      fast, safety-ish -> steering?
0x100    100      fast -> engine
0x200    100      fast -> wheel speeds / abs
0x120     50
0x210     50
0x400     50      -> dashboard speed
0x300     10      slow status -> body
0x7DF     0*      only shows up with a scan tool -> diagnostics
```

Fixed periods + a small id number usually means a safety/powertrain message. That already
tells you a lot before decoding a single byte.

## step 2 — find the signals

Pick one id (say `0x100`) and watch bytes change while you do something to the car
(rev the engine on a bench, spin a wheel, etc.):

- bytes 0–1 swing smoothly with engine speed and land around `0x0C80` at idle. `0x0C80` = 3200,
  and 3200 × 0.25 = 800 rpm. So **rpm = be16(byte0..1) × 0.25**.
- byte 2 sits near `0x3C` (60) and creeps up as the engine warms. 60 − 40 = 20 °C on a cold
  start → **coolant = byte2 − 40**.
- and so on for throttle / load.

Scale-and-offset (`phys = raw·scale + offset`) covers almost every automotive signal, so you
just fit those two numbers to known physical values.

## step 3 — the two weird bytes at the end

The last two bytes of every periodic message don't look like signals:

- **byte[dlc-2]'s high nibble increments every single message** — `0,1,2,...,F,0,1,...` — and
  wraps at 16. Same payload, still changes. That's a classic **rolling / alive counter**.
- **byte[dlc-1] changes even when nothing else does, but is identical for identical payloads.**
  That's a **checksum** over the message.

To recover the checksum, hold the payload constant and solve. Summing bytes `0..dlc-2` and
comparing to byte[dlc-1] leaves a constant difference every time — that constant is a fixed
seed. Here it works out to:

```
checksum = (0xA5 + sum(byte[0 .. dlc-2])) & 0xFF
```

The counter byte is *included* in the sum, which is why the checksum still changes each
message even for a constant payload. `0xA5` is the seed you'd recover by subtraction.

## the recovered format (integrity-protected periodic messages)

```
 byte:   0            dlc-3   dlc-2      dlc-1
        +----...------+------+----------+----------+
        |  signals    | ...  | counter  | checksum |
        +----...------+------+----------+----------+
                              hi nibble
```

- signals: bytes `[0 .. dlc-3]`, big-endian, scale+offset per signal
- counter: high nibble of byte `[dlc-2]`, `+1 mod 16` each transmission
- checksum: `byte[dlc-1] = (0xA5 + sum(byte[0..dlc-2])) & 0xFF`

## why the IDS cares

Once you know this, three cheap checks fall out, and they're exactly what a naive attacker
trips over:

- **checksum** — modify a byte in flight and forget to recompute it → mismatch.
- **counter** — inject or replay a frame and the counter repeats or skips instead of
  following `+1`.
- **range** — a spoofed value that's outside the signal's real min/max stands out.

A *sophisticated* attacker who knows all of this (valid checksum, continued counter, correct
timing) defeats those three — which is the whole reason the monitor also has a cross-signal
physics detector. See `docs/attack-scenarios.md`.
