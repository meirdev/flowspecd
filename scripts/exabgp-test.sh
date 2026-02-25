#!/bin/bash
# Test ExaBGP FlowSpec with rust-router
# Run with: ./scripts/exabgp-test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PIPE_PATH="/var/run/exabgp.cmd"

echo "=========================================="
echo "ExaBGP FlowSpec Test"
echo "=========================================="
echo ""
echo "Prerequisites:"
echo "  1. Install ExaBGP: pip install exabgp"
echo "  2. Run the router: sudo ./target/release/rust-router --config scripts/test-config.toml"
echo ""

# Create named pipe for FlowSpec commands
if [ ! -p "$PIPE_PATH" ]; then
    echo "Creating named pipe at $PIPE_PATH..."
    sudo mkfifo "$PIPE_PATH"
    sudo chmod 666 "$PIPE_PATH"
fi

echo "Starting ExaBGP..."
echo "Press Ctrl+C to stop"
echo ""
echo "In another terminal, send FlowSpec rules with:"
echo ""
echo "  # Drop all ICMP traffic:"
echo "  echo 'announce flow route { match { protocol icmp; } then { discard; } }' > $PIPE_PATH"
echo ""
echo "  # Rate limit SSH (port 22) to 10KB/s:"
echo "  echo 'announce flow route { match { destination-port 22; protocol tcp; } then { rate-limit 10000; } }' > $PIPE_PATH"
echo ""
echo "  # Drop traffic from specific source:"
echo "  echo 'announce flow route { match { source 10.0.0.10/32; } then { discard; } }' > $PIPE_PATH"
echo ""
echo "  # Withdraw a rule:"
echo "  echo 'withdraw flow route { match { protocol icmp; } then { discard; } }' > $PIPE_PATH"
echo ""
echo "=========================================="
echo ""

# Run ExaBGP
cd "$PROJECT_DIR"
env exabgp.daemon.daemonize=false \
    exabgp.log.level=INFO \
    exabgp.log.destination=stderr \
    uv run exabgp py/exabgp.conf
