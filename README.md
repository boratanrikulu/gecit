# gecit

[Türkçe](README.tr.md)

DPI bypass tool. Injects fake TLS ClientHello packets to desynchronize Deep Packet Inspection middleboxes. Includes built-in DoH DNS resolver.

**Linux**: eBPF sock_ops - hooks directly into the kernel TCP stack. No proxy, no traffic redirection.  
**macOS/Windows**: TUN-based transparent proxy - intercepts all traffic at the IP layer via a virtual network interface.

```
sudo gecit run
```

> **Disclaimer**: This project is for educational and research purposes only. gecit demonstrates eBPF and network programming capabilities in the context of TLS protocol analysis. It does NOT hide your IP address, encrypt your traffic, or provide anonymity. Use is entirely at your own risk. Users are responsible for complying with all applicable laws in their jurisdiction.

## How it works

```
App connects to target:443
    ↓
gecit intercepts the connection
  Linux:  eBPF sock_ops fires (inside kernel, before app sends data)
  macOS/Windows: TUN device captures packet, gVisor netstack terminates TCP
    ↓
Fake ClientHello with SNI "www.google.com" sent with low TTL
    ↓
Fake reaches DPI → DPI records "google.com" → allows connection
Fake expires before server (low TTL) → server never sees it
    ↓
Real ClientHello passes through → DPI already desynchronized
```

Some ISPs inspect the TLS ClientHello SNI field to identify and block specific domains. gecit sends a fake ClientHello with a different SNI (`www.google.com`) and a low TTL before the real one. The DPI processes the fake and lets the connection through. The fake packet expires before reaching the server due to its low TTL.

Additionally, some ISPs poison DNS responses. gecit includes a built-in DoH (DNS-over-HTTPS) server that resolves domains through encrypted HTTPS, bypassing DNS-level blocking.

## Requirements

| | Linux | macOS | Windows |
|---|---|---|---|
| **OS** | Kernel 5.10+ | macOS 12+ (Monterey) | Windows 10+ |
| **Privileges** | root / sudo | root / sudo | Administrator |
| **Dependencies** | None | None | [Npcap](https://npcap.com) |

### Windows notes

- **Npcap**: Download and install from [npcap.com](https://npcap.com/#download). Required for seq/ack extraction and fake packet injection.
- **Windows Defender**: May flag gecit as `Win32/Wacapew.A!ml` (false positive). gecit creates a TUN interface, modifies DNS, and uses raw sockets - Defender flags this behavior. Add an exception: Windows Security → Virus & threat protection → Exclusions → Add gecit.exe.
- **Run as Administrator**: Right-click PowerShell → "Run as Administrator", then run `.\gecit.exe run`.

## Installation

### Quick install (Linux, recommended)

One line — detects arch, verifies SHA256, installs to `/usr/local/bin`, sets up a systemd service, enables and starts it:

```bash
curl -fsSL https://raw.githubusercontent.com/boratanrikulu/gecit/main/scripts/install.sh | sudo bash
```

Optional flags and env vars:

```bash
# Pin a specific version
curl -fsSL https://raw.githubusercontent.com/boratanrikulu/gecit/main/scripts/install.sh | sudo VERSION=v0.1.4 bash

# Install but don't start the service
curl -fsSL https://raw.githubusercontent.com/boratanrikulu/gecit/main/scripts/install.sh | sudo bash -s -- --no-start

# Uninstall (stops + disables service, runs gecit cleanup, removes binary and unit file)
curl -fsSL https://raw.githubusercontent.com/boratanrikulu/gecit/main/scripts/install.sh | sudo bash -s -- --uninstall
```

The installer requires Linux kernel 5.10+, systemd, and `amd64` or `arm64`. After installation, customize CLI flags (e.g. `--fake-ttl`, `--doh-upstream`) with `sudo systemctl edit gecit`.

### Pre-built binaries (manual)

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

# macOS (Intel)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-darwin-amd64 -o gecit
chmod +x gecit
sudo ./gecit run

# Windows (amd64) - requires Npcap (npcap.com)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-windows-amd64.exe -o gecit.exe
gecit.exe run
```

### Building from source

Requires Go 1.24+. Linux builds need kernel 5.10+, clang, and llvm-strip for BPF compilation. Windows builds need [Npcap SDK](https://npcap.com/guide/npcap-devguide.html).

```bash
git clone https://github.com/boratanrikulu/gecit.git
cd gecit

make gecit-linux-amd64    # Linux x86_64
make gecit-linux-arm64    # Linux ARM64
make gecit-darwin-arm64   # macOS Apple Silicon
make gecit-darwin-amd64   # macOS Intel
make gecit-windows-amd64  # Windows x86_64 (requires Npcap SDK)

sudo ./bin/gecit-linux-arm64 run
```

gecit sets up everything automatically:
- **DoH DNS server** on `127.0.0.1:53` (bypasses DNS poisoning)
- **System DNS** pointed to the local DoH server
- **Linux**: eBPF program attached to cgroup (fake injection + MSS fragmentation)
- **macOS/Windows**: TUN virtual interface with automatic routing (all apps intercepted)

Press `Ctrl+C` to stop - everything is restored (DNS, routes, BPF programs). Windows requires [Npcap](https://npcap.com) for full DPI bypass support.

If gecit crashes, run `sudo gecit cleanup` to restore system settings.

## Usage

```bash
# Default (TTL=8, Cloudflare DoH)
sudo gecit run

# Use Google DoH
sudo gecit run --doh-upstream google

# Multiple upstreams (fallback order)
sudo gecit run --doh-upstream cloudflare,quad9

# Custom DoH URL
sudo gecit run --doh-upstream https://8.8.8.8/dns-query

# Custom TTL
sudo gecit run --fake-ttl 12

# Check system capabilities
sudo gecit status

# Restore system settings after a crash
sudo gecit cleanup
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--doh-upstream` | `cloudflare` | DoH upstream: preset name or URL. Comma-separated for fallback. |
| `--fake-ttl` | `8` | TTL for fake packets (must reach DPI but expire before server) |
| `--mss` | `40` | TCP MSS for ClientHello fragmentation (Linux) |
| `--ports` | `443` | Target destination ports |
| `--interface` | auto | Network interface |
| `-v` | off | Verbose/debug logging |

### DoH presets

| Preset | Upstream |
|--------|----------|
| `cloudflare` | `https://1.1.1.1/dns-query` |
| `google` | `https://8.8.8.8/dns-query` |
| `quad9` | `https://9.9.9.9:5053/dns-query` |
| `nextdns` | `https://dns.nextdns.io/dns-query` |
| `adguard` | `https://dns.adguard-dns.com/dns-query` |

### Finding the right TTL

The fake packet TTL must be high enough to reach the DPI (typically 2-4 hops) but low enough to expire before the server (typically 10+ hops).

```bash
traceroute -n target.com
```

The DPI is usually at the first few ISP hops. Default TTL=8 works for most networks.

## Platform differences

| | Linux | macOS | Windows |
|---|---|---|---|
| **Engine** | eBPF sock_ops | TUN + gVisor netstack | TUN + gVisor netstack |
| **Connection detection** | BPF perf events | TUN packet interception | TUN packet interception |
| **Fake injection** | Raw socket | Raw socket | Raw socket via Npcap |
| **DNS bypass** | DoH + `/etc/resolv.conf` | DoH + `networksetup` | DoH + `netsh` |
| **App configuration** | None needed | None needed (all apps via TUN) | None needed (all apps via TUN) |
| **Root required** | Yes (`CAP_BPF`) | Yes (TUN + raw socket) | Yes (Administrator) |

## FAQ

**Does this hide my IP address?**
No. Your ISP can still see which IP addresses you connect to. gecit only prevents the ISP from reading the domain name (SNI) in the TLS handshake.

**Does this work against all DPI?**
It works against DPI systems that inspect individual TCP segments without full reassembly. More sophisticated systems (like those used in China) may detect and block this technique.

**Is this a VPN?**
No. There is no tunnel, no encryption of traffic, and no remote server involved. gecit operates entirely locally. On macOS/Windows, it uses a TUN interface (similar to VPN plumbing) but traffic goes directly to the internet - no remote server.

**Why eBPF on Linux?**
eBPF hooks into the kernel's TCP stack synchronously - the fake packet is sent before the application can write any data. This guarantees correct ordering without needing a proxy or packet interception. Only the handshake touches userspace; data flows through the kernel at full speed.

**Why TUN on macOS/Windows?**
These platforms don't expose kernel-level hooks like eBPF. A TUN virtual interface intercepts all traffic at the IP layer, providing the same coverage as eBPF but with traffic flowing through userspace.

**Why not WinDivert?**
Most Windows DPI bypass tools use WinDivert, but its code signing certificate expired in 2023. This triggers Windows Defender warnings and blocks driver installation on some systems. gecit uses a TUN-based approach instead, which relies on properly signed drivers and avoids these issues.

## Architecture

### Linux (eBPF)

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
```

### macOS/Windows (TUN)

```
┌──────────┐   ┌────────────────────┐   ┌────────────┐
│ App      │──>│ TUN device         │──>│ gVisor     │
│ connects │   │ (utun on macOS)    │   │ netstack   │
│ to :443  │   └────────────────────┘   │ terminates │
│          │                            │ TCP        │
└──────────┘                            └────────────┘
                                              │
                                              ▼
                                        ┌────────────┐
                                        │ gecit      │
                                        │ handler    │
                                        │            │
                                        │ 1. Dial    │
                                        │    server  │
                                        │ 2. Inject  │
                                        │    fake    │
                                        │ 3. Forward │
                                        │    real    │
                                        │ 4. Pipe    │
                                        └────────────┘
```

## Roadmap

- [x] Linux - eBPF sock_ops
- [x] macOS - TUN transparent proxy
- [x] DoH DNS resolver
- [x] Windows - TUN transparent proxy
- [ ] Auto-TTL detection (traceroute to find DPI hop count)
- [ ] ECH (Encrypted Client Hello) support

## License

GPL-3.0. See [LICENSE](LICENSE).

Copyright (c) 2026 Bora Tanrikulu \<me@bora.sh\>
