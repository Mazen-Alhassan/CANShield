#!/usr/bin/env bash
# bring up a virtual can interface (linux only). usage: sudo ./setup_vcan.sh [name]
set -e
IF="${1:-vcan0}"

if [[ "$(uname)" != "Linux" ]]; then
  echo "vcan is linux-only. on macOS use the VirtualCanBus build instead." >&2
  exit 1
fi

sudo modprobe vcan
if ip link show "$IF" >/dev/null 2>&1; then
  echo "$IF already exists"
else
  sudo ip link add dev "$IF" type vcan
fi
sudo ip link set up "$IF"
echo "$IF is up:"
ip -details link show "$IF"
