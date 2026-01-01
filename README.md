# Toralizer: Bulletproof Tor Enforcement
Toralizer is a security tool for Linux (Debian-based) that enforces Tor routing for specific applications using Linux Network Namespaces and Nftables. 
It creates an isolated network environment where the only exit path is through the Tor network.

## Features
- **Kernel-Level Enforcement**: Uses Network Namespaces (netns) to strictly isolate the target process.
- **Fail-Closed**: Firewall rules strictly drop any traffic that isn't TCP (redirected to Tor) or DNS (redirected to Tor).
- **No Leaks**: DNS is forced through Tor's DNSPort. IPv6 and UDP (non-DNS) are blocked.
- **Programmatic & CLI**: Works as a command-line wrapper or a Go library.

## Prerequisites

1. **OS**: Debian 11/12 (or similar Linux).
2. **Root Access**: Required for namespace creation and firewall modification.
3. **Dependencies**:
- `tor` (System service)
- `nftables`
- `iproute2`
- `go` (to build)

## Installation

1. **Configure Tor**: run `/scripts/installer.sh`
```shell
sudo ./scripts/installer.sh
```
- the argument in the above is `debian` - that's the name of the user whose .bashrc will be updated to contain the GOROOT variable 

*Note: We bind to 0.0.0.0 or ensure the Tor daemon can accept connections from the virtual interfaces created by Toralizer.*

Restart Tor:
```shell
systemctl restart tor
```

2. **Validate System**: Run the provided check script:
```shell
chmod +x setup_check.sh
sudo ./setup_check.sh
```

3. **Build Toralizer**: 
```shell
go build -o toralizer toralizer.go
```

## Usage

### CLI Mode
To run an application through Tor:

```shell
sudo ./toralizer curl https://check.torproject.org/api/ip
```

### To verify DNS leak protection:
```shell
# Should resolve via Tor exit node, not your ISP
sudo ./toralizer dig google.com
```

To run an interactive shell inside the Tor sandbox:
```shell
sudo ./toralizer run /bin/bash
```

## How it Works

1. **Isolation**: toralizer creates a new Network Namespace (ip netns). The process inside has no access to your physical network interfaces.
2. **Link**: A virtual ethernet pair (veth) connects the namespace to the host.
3. **Routing**: The namespace routes all traffic to the host end of the veth pair.
4. **Enforcement**: nftables rules on the host intercept traffic arriving from the veth interface:
- **TCP**: Redirected to 127.0.0.1:9040 (Tor TransPort).
- **DNS (UDP 53)**: Redirected to 127.0.0.1:9053 (Tor DNSPort).
- **Everything Else**: DROPPED.

### Security Notes
- **IPv6**: Currently disabled/ignored inside the namespace (IPv4 only logic).
- **UDP**: Blocked (except DNS). Applications relying on UDP (like WebRTC or QUIC) will fail or fallback to TCP if supported.
- **Root**: The tool must run as root, but the target application runs with "preserved credentials" (currently root in the namespace). For production use, consider dropping privileges inside the nsenter call.

## Debugging commands
```shell
sudo tcpdump -v -ni lo tcp port 9053 # watch all tcp traffic on port 9053
sudo tcpdump -v -ni lo udp port 9053
sudo nft -a list chain inet toralizer pre-<uuid>
```