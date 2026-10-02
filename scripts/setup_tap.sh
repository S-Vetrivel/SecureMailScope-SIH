#!/bin/bash
set -e

IFACE=${1:-tap0}

echo "Setting up TAP interface: $IFACE"
sudo ip tuntap add dev $IFACE mode tap
sudo ip link set dev $IFACE up
echo "Interface $IFACE is now UP and ready for capture."
