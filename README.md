# gecit

DPI bypass tool using eBPF. Injects fake TLS ClientHello packets to desynchronize Deep Packet Inspection middleboxes. Includes built-in DoH DNS resolver.

**Linux**: eBPF sock_ops — hooks directly into the kernel TCP stack. No proxy, no traffic redirection.  
**macOS**: HTTP CONNECT proxy with system-wide configuration.

```
sudo gecit run
```

> **Disclaimer**: This project is for educational and research purposes only. gecit demonstrates eBPF capabilities in the context of network programming and TLS protocol analysis. It does NOT hide your IP address, encrypt your traffic, or provide anonymity. Use is entirely at your own risk. Users are responsible for complying with all applicable laws in their jurisdiction.

## How it works

```
App connects to target:443
    ↓
eBPF sock_ops fires (inside kernel, before app sends data)
    ↓
Perf event → Go goroutine → raw socket sends fake ClientHello (TTL=8)
    ↓
Fake reaches DPI → DPI records "google.com" → allows connection
Fake expires before server (low TTL) → server never sees it
    ↓
Real ClientHello passes through → DPI already desynchronized
```

Some ISPs inspect the TLS ClientHello SNI field to identify and block specific domains. gecit sends a fake ClientHello with a different SNI (`www.google.com`) and a low TTL before the real one. The DPI processes the fake and lets the connection through. The fake packet expires before reaching the server due to its low TTL.

Additionally, some ISPs poison DNS responses. gecit includes a built-in DoH (DNS-over-HTTPS) server that resolves domains through encrypted HTTPS, bypassing DNS-level blocking.

See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) for the full technical explanation.

## Installation

### Pre-built binaries

Download from [releases](https://github.com/boratanrikulu/gecit/releases):

```bash
# Linux (amd64)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-linux-amd64 -o gecit
chmod +x gecit
sudo ./gecit run

# Linux (arm64)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-linux-arm64 -o gecit
chmod +x gecit
sudo ./gecit run

# macOS (Apple Silicon)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-darwin-arm64 -o gecit
chmod +x gecit
sudo ./gecit run
```

### Building from source

Requires Go 1.21+. Linux builds need kernel 5.10+, clang, and llvm-strip for BPF compilation. macOS builds need libpcap (included with Xcode CLI tools).

```bash
git clone https://github.com/boratanrikulu/gecit.git
cd gecit

make gecit-linux-amd64    # Linux x86_64
make gecit-linux-arm64    # Linux ARM64
make gecit-darwin-arm64   # macOS Apple Silicon

sudo ./bin/gecit-linux-arm64 run
```

gecit sets up everything automatically:
- **DoH DNS server** on `127.0.0.1:53` (bypasses DNS poisoning)
- **System DNS** pointed to the local DoH server
- **Linux**: eBPF program attached to cgroup (fake injection + MSS fragmentation)
- **macOS**: System HTTPS proxy set (all apps use it automatically)

Press `Ctrl+C` to stop — everything is restored (DNS, proxy settings, BPF programs).

## Usage

```bash
# Default settings (TTL=8, DoH via Cloudflare 1.1.1.1)
sudo gecit run

# Custom TTL (adjust based on hop count to DPI)
sudo gecit run --fake-ttl 12

# Custom DoH upstream
sudo gecit run --doh https://8.8.8.8/dns-query

# Check system capabilities
sudo gecit status
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--fake-ttl` | `8` | TTL for fake packets (must reach DPI but expire before server) |
| `--doh` | `https://1.1.1.1/dns-query` | DoH upstream URL |
| `--mss` | `40` | TCP MSS for ClientHello fragmentation (Linux) |
| `--ports` | `443` | Target destination ports |
| `--interface` | auto | Network interface |

### Finding the right TTL

The fake packet TTL must be high enough to reach the DPI (typically 2-4 hops) but low enough to expire before the server (typically 10+ hops).

```bash
traceroute -n target.com
```

The DPI is usually at the first few ISP hops. Default TTL=8 works for most networks.

## Platform differences

| | Linux | macOS |
|---|---|---|
| **DPI bypass** | eBPF sock_ops (kernel-level, no proxy) | HTTP CONNECT proxy (system-wide) |
| **Connection detection** | BPF perf events (synchronous, before app sends data) | pcap SYN-ACK capture |
| **Fake injection** | Raw socket | Raw socket |
| **DNS bypass** | DoH server + `/etc/resolv.conf` | DoH server + `networksetup` |
| **App configuration** | None needed | None needed (system proxy) |
| **Root required** | Yes (`CAP_BPF`) | Yes (raw socket + system settings) |

## FAQ

**Does this hide my IP address?**
No. Your ISP can still see which IP addresses you connect to. gecit only prevents the ISP from reading the domain name (SNI) in the TLS handshake.

**Does this work against all DPI?**
It works against DPI systems that inspect individual TCP segments without full reassembly. More sophisticated systems (like those used in China) may detect and block this technique.

**Is this a VPN?**
No. There is no tunnel, no encryption of traffic, and no remote server involved. gecit operates entirely locally.

**Why eBPF?**
eBPF hooks into the kernel's TCP stack synchronously — the fake packet is sent before the application can write any data. This guarantees correct ordering without needing a proxy or packet interception.

## Architecture

```
┌──────────┐   ┌────────────────────┐   ┌────────────┐
│ eBPF     │──>│ Perf Event Buffer  │──>│ Go         │
│ sock_ops │   │ (conn details)     │   │ goroutine  │
│          │   └────────────────────┘   │            │
│ Sets MSS │                            │ Sends fake │
│ per-conn │                            │ via raw    │
│          │                            │ socket     │
└──────────┘                            └────────────┘
     │                                        │
     ▼                                        ▼
┌────────────────────────────────────────────────────┐
│ Linux Kernel TCP Stack                             │
│ (fragments ClientHello due to small MSS)           │
└────────────────────────────────────────────────────┘
     │
     ▼
┌──────────┐        ┌──────────┐        ┌──────────┐
│ Fake pkt │        │ Real     │        │ Server   │
│ TTL=8    │───────>│ segments │───────>│ receives │
│ dies at  │  DPI   │ pass     │  DPI   │ real     │
│ hop 8    │sees it │ through  │allows  │ data     │
└──────────┘        └──────────┘        └──────────┘
```

## Roadmap

- [x] Linux — eBPF sock_ops
- [x] macOS — HTTP CONNECT proxy
- [x] DoH DNS resolver
- [ ] Windows — WinDivert packet splitting
- [ ] Auto-TTL detection (traceroute to find DPI hop count)
- [ ] ECH (Encrypted Client Hello) support

## License

GPL-3.0. See [LICENSE](LICENSE).

Copyright (c) 2026 Bora Tanrikulu \<me@bora.sh\>
