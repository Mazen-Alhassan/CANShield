# running on a raspberry pi (real socketcan)

The whole point of the transport abstraction is that this is the *same* code as the laptop
build — you just point it at a real SocketCAN interface instead of the virtual bus.

## option A — virtual can (no extra hardware)

Good enough to run the ECU sim, attacks, and monitor as separate processes over the kernel's
CAN stack. Works on any Linux box, including a Pi.

```sh
# bring up vcan0 (see scripts/setup_vcan.sh)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# build
cmake -S . -B build && cmake --build build -j

# terminal 1: pump normal traffic onto the bus  (also works with cangen from can-utils)
./build/canshield_ecu_sim --print   # or wire send() to vcan0

# terminal 2: watch it
candump vcan0

# terminal 3: run the IDS live
./build/canshield_monitor --iface vcan0
```

When SocketCAN headers are present, CMake prints
`SocketCAN available -> real CAN transport enabled` at configure time and
`canshield_monitor --iface vcan0` binds a real raw CAN socket.

## option B — two pis, real wires (ECU-to-ECU)

This is the setup the project is modeled on: two nodes on a physical CAN bus.

- 2× Raspberry Pi, each with an MCP2515 CAN HAT (or a Pi + USB-CAN adapter)
- CANH↔CANH, CANL↔CANL between them, 120 Ω termination at both ends

Enable the controller in `/boot/config.txt`:

```
dtparam=spi=on
dtoverlay=mcp2515-can0,oscillator=8000000,interrupt=25
```

Bring the interface up at 500 kbit/s:

```sh
sudo ip link set can0 up type can bitrate 500000
candump can0        # sanity check
```

Then run the ECU simulator on one Pi and `canshield_monitor --iface can0` on the other. An
attack Pi (or the same one) can inject with `canshield_attack` piped onto `can0` via
`cansend` / a small sender using `SocketCanTransport::send`.

## notes

- `SocketCanTransport::open()` uses `CAN_RAW_RECV_OWN_MSGS` so a single process can both
  inject and monitor for a quick self-test.
- everything here is classic CAN (≤ 8 data bytes). CAN-FD would need the `canfd_frame` path.
- keep it on a bench. Don't wire this into a car you care about.
