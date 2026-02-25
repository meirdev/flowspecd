#!/bin/bash
# Set up test environment with network namespaces for rust-router
# This creates a Layer 2 bridge setup where the router can transparently forward
# Run with: sudo ./scripts/test-env-up.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Creating test network environment..."

# Cleanup any previous setup
"$SCRIPT_DIR/test-env-down.sh" 2>/dev/null || true

# Create namespaces for simulated hosts
ip netns add host-a
ip netns add host-b

# Create veth pairs connecting hosts to router interfaces
ip link add veth-wan type veth peer name veth-a
ip link add veth-lan type veth peer name veth-b

# Move host-side veths into namespaces
ip link set veth-a netns host-a
ip link set veth-b netns host-b

# Configure host-a (connected to WAN side)
ip netns exec host-a ip link set lo up
ip netns exec host-a ip link set veth-a up
ip netns exec host-a ip addr add 10.0.0.10/24 dev veth-a
# Add ARP entry for host-b (we'll update this after getting host-b's MAC)

# Configure host-b (connected to LAN side)
ip netns exec host-b ip link set lo up
ip netns exec host-b ip link set veth-b up
ip netns exec host-b ip addr add 10.0.0.20/24 dev veth-b

# Get MAC addresses for static ARP entries
MAC_A=$(ip netns exec host-a cat /sys/class/net/veth-a/address)
MAC_B=$(ip netns exec host-b cat /sys/class/net/veth-b/address)

# Add static ARP entries so hosts know each other's MAC addresses
# (since they're on different veth pairs, ARP broadcasts need to be forwarded)
ip netns exec host-a ip neigh add 10.0.0.20 lladdr $MAC_B dev veth-a nud permanent
ip netns exec host-b ip neigh add 10.0.0.10 lladdr $MAC_A dev veth-b nud permanent

# Bring up router-side interfaces in promiscuous mode (required for bridging)
ip link set veth-wan up promisc on
ip link set veth-lan up promisc on

# Disable kernel features that interfere with user-space routing
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
echo 0 > /proc/sys/net/ipv4/conf/veth-wan/rp_filter 2>/dev/null || true
echo 0 > /proc/sys/net/ipv4/conf/veth-lan/rp_filter 2>/dev/null || true

# Disable IPv6 to reduce noise
echo 1 > /proc/sys/net/ipv6/conf/veth-wan/disable_ipv6 2>/dev/null || true
echo 1 > /proc/sys/net/ipv6/conf/veth-lan/disable_ipv6 2>/dev/null || true

echo ""
echo "=========================================="
echo "Test environment ready!"
echo "=========================================="
echo ""
echo "Topology (Layer 2 bridge):"
echo ""
echo "  host-a (10.0.0.10)          host-b (10.0.0.20)"
echo "  MAC: $MAC_A    MAC: $MAC_B"
echo "         |                           |"
echo "      veth-a                      veth-b"
echo "         |                           |"
echo "     veth-wan ---[ ROUTER ]--- veth-lan"
echo ""
echo "Static ARP entries configured for both directions."
echo ""
echo "To run the router:"
echo "  sudo ./target/release/rust-router --config scripts/test-config.toml"
echo ""
echo "To test (while router is running):"
echo "  sudo ip netns exec host-a ping -c 3 10.0.0.20"
echo "  sudo ip netns exec host-b ping -c 3 10.0.0.10"
echo ""
echo "To monitor stats:"
echo "  curl http://127.0.0.1:8070/stats"
echo ""
echo "To tear down:"
echo "  sudo ./scripts/test-env-down.sh"
