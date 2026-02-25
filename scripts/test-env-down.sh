#!/bin/bash
# Tear down test environment for rust-router
# Run with: sudo ./scripts/test-env-down.sh

echo "Tearing down test network environment..."

# Delete veth pairs (automatically removes the peer)
ip link del veth-wan 2>/dev/null || true
ip link del veth-lan 2>/dev/null || true

# Delete bridge if exists
ip link del br-router 2>/dev/null || true

# Delete namespaces
ip netns del host-a 2>/dev/null || true
ip netns del host-b 2>/dev/null || true
ip netns del wan-ns 2>/dev/null || true
ip netns del lan-ns 2>/dev/null || true

echo "Done."
