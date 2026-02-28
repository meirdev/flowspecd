# flowspecd

A BGP FlowSpec daemon that receives FlowSpec rules via BGP and translates them into nftables firewall rules.

## Features

- **BGP FSM**: Full RFC 4271 compliant finite state machine
- **FlowSpec support**: RFC 5575/8955 IPv4 FlowSpec
- **nftables backend**: Translates FlowSpec rules to nftables
- **Named pipe control**: Inject FlowSpec commands locally via FIFO
- **GoBGP compatible**: Tested with GoBGP as upstream router

## Usage

```bash
# Passive mode (listen for incoming connections)
flowspecd --listen 0.0.0.0:179 --pipe /tmp/flowspec.pipe

# Active mode (connect to peer)
flowspecd --connect 10.0.0.2:179 --my-as 65001 --pipe /tmp/flowspec.pipe
```

### Options

- `--my-as`: Local AS number (default: 65001)
- `--bgp-id`: BGP router ID as dotted decimal or hex (default: 10.0.0.1)
- `--hold-time`: Hold time in seconds (default: 180)
- `--listen`: Listen address ip:port (default: 127.0.0.1:1179)
- `--connect`: Connect to peer ip:port instead of listening
- `--dry-run`: Print nft commands without executing
- `--metrics-port`: Prometheus metrics port (disabled if not set)
- `--pipe`: Path to command pipe (FIFO) for runtime FlowSpec injection

### Named Pipe Commands

Send FlowSpec commands via the control pipe at `/tmp/flowspec.pipe`:

```bash
# Announce a discard rule
echo "announce flowspec source 10.0.0.0/24 destination-port =80 then discard" > /tmp/flowspec.pipe

# Withdraw a rule
echo "withdraw flowspec source 10.0.0.0/24 destination-port =80" > /tmp/flowspec.pipe

# Graceful shutdown
echo "shutdown" > /tmp/flowspec.pipe
```
