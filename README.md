# rust-router

A minimal, efficient software router written in Rust with BGP FlowSpec and IPFIX support.

## Features

- **Packet Forwarding**: Forward packets between WAN and LAN interfaces
- **BGP FlowSpec**: Receive traffic filtering rules via BGP (RFC 5575)
- **IPFIX Export**: Export flow statistics to collectors (RFC 7011)
- **REST API**: Query rules and statistics via HTTP
- **Per-Rule Statistics**: Track packets, bytes, drops, and rate-limits per FlowSpec rule

## Requirements

- Linux (requires raw socket access)
- Root privileges or `CAP_NET_ADMIN` capability
- Rust 1.70+ (for building)

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

## Configuration

Create a configuration file (see `config/router.toml` for a full example):

```toml
[router]
router_id = "10.0.0.1"
log_level = "info"

[[interfaces]]
name = "eth0"
role = "wan"

[[interfaces]]
name = "eth1"
role = "lan"

[bgp]
local_as = 65001
listen_port = 179

[[bgp.peers]]
address = "10.0.0.2"
remote_as = 65002
flowspec = true

[ipfix]
collector = "10.0.0.100:4739"
export_interval_secs = 60
sampling_rate = 1  # 1 = sample every packet, N = sample 1 in N packets

[api]
listen = "127.0.0.1:8080"

[flowspec]
default_action = "accept"

[[flowspec.rules]]
name = "block-ssh-bruteforce"
dst_port = { start = 22, end = 22 }
protocol = 6
action = "rate_limit"
rate_limit_bps = 10000
```

## Running

```bash
# Run with default config path
sudo ./target/release/rust-router

# Run with custom config
sudo ./target/release/rust-router --config /path/to/config.toml

# Enable verbose logging
sudo ./target/release/rust-router --verbose
```

## REST API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /stats` | All statistics (global, interfaces, rules) |
| `GET /stats/global` | Global packet counters |
| `GET /stats/interfaces` | Per-interface statistics |
| `GET /stats/rules` | Per-FlowSpec-rule statistics |
| `GET /rules` | List all active FlowSpec rules |

### Example API Usage

```bash
# Health check
curl http://127.0.0.1:8080/health

# Get all statistics
curl http://127.0.0.1:8080/stats

# Get FlowSpec rules
curl http://127.0.0.1:8080/rules
```

## FlowSpec Actions

| Action | Description |
|--------|-------------|
| `accept` | Forward the packet normally |
| `drop` | Drop the packet silently |
| `rate_limit` | Apply rate limiting (bytes/second) |

## FlowSpec Rule Matching

Rules can match on:
- Source/destination IP prefix
- IP protocol (TCP=6, UDP=17, ICMP=1)
- Source/destination port or port range
- DSCP value

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Testing with Network Namespaces

Create a test environment using Linux network namespaces:

```bash
# Create namespaces
sudo ip netns add wan-ns
sudo ip netns add lan-ns

# Create veth pairs
sudo ip link add veth-wan type veth peer name veth-wan-ns
sudo ip link add veth-lan type veth peer name veth-lan-ns

# Move veth ends to namespaces
sudo ip link set veth-wan-ns netns wan-ns
sudo ip link set veth-lan-ns netns lan-ns

# Configure IP addresses
sudo ip addr add 10.0.0.1/24 dev veth-wan
sudo ip addr add 192.168.1.1/24 dev veth-lan
sudo ip netns exec wan-ns ip addr add 10.0.0.2/24 dev veth-wan-ns
sudo ip netns exec lan-ns ip addr add 192.168.1.2/24 dev veth-lan-ns

# Bring up interfaces
sudo ip link set veth-wan up
sudo ip link set veth-lan up
sudo ip netns exec wan-ns ip link set veth-wan-ns up
sudo ip netns exec lan-ns ip link set veth-lan-ns up

# Run router (update config to use veth-wan and veth-lan)
sudo ./target/release/rust-router --config config/router.toml

# Test from WAN namespace
sudo ip netns exec wan-ns ping 192.168.1.2
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      rust-router                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ BGP Speaker │  │   IPFIX     │  │    REST API         │  │
│  │ (FlowSpec)  │  │  Exporter   │  │    (axum)           │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │              │
│         ▼                │                     │              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              FlowSpec Rule Engine                     │   │
│  │  (drop / accept / rate-limit with counters)          │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Packet Forwarding Engine                    │   │
│  │                  (pnet)                               │   │
│  └──────────────────────────────────────────────────────┘   │
│              │                              │                │
│              ▼                              ▼                │
│          [WAN]                          [LAN]               │
└─────────────────────────────────────────────────────────────┘
```

## Performance

- User-space packet processing using `pnet`
- Lock-free statistics using atomic counters
- Efficient rule matching with DashMap
- Estimated throughput: ~1 Gbps (depends on CPU)
- Memory usage: ~20-50 MB

## License

MIT
