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
- **Unsigned installer**: gecit has no code-signing certificate, so SmartScreen shows a warning. Choose "More info" → "Run anyway".

## Installation

### Package managers

```bash
# macOS
brew install boratanrikulu/tap/gecit
```

Grab the matching package for your distro from
[releases](https://github.com/boratanrikulu/gecit/releases), then:

```bash
# Debian, Ubuntu
sudo dpkg -i gecit_*_linux_amd64.deb

# Fedora, RHEL
sudo rpm -i gecit_*_linux_amd64.rpm

# Alpine
sudo apk add --allow-untrusted gecit_*_linux_amd64.apk
```

amd64 and arm64 are both published. The deb and the rpm install `/usr/bin/gecit`
and a systemd unit, and leave the unit disabled. Installing a DPI bypass should
not repoint your resolver on its own, and a package manager has no way to ask:

```bash
sudo systemctl enable --now gecit
sudo systemctl status gecit
sudo systemctl stop gecit     # restores DNS
```

Removing the package stops the service first, which is what puts your original
nameservers back. `/etc/gecit/config.yaml` is left in place.

Alpine has no systemd, so nothing starts gecit for you there. Run
`sudo gecit run` yourself, or write an OpenRC service for it.

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

# macOS (Intel)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-darwin-amd64 -o gecit
chmod +x gecit
sudo ./gecit run

# Windows (amd64) - requires Npcap (npcap.com)
curl -L https://github.com/boratanrikulu/gecit/releases/latest/download/gecit-windows-amd64.exe -o gecit.exe
gecit.exe run
```

### Windows installer

The MSI installs gecit to `C:\Program Files\gecit`, registers it as a Windows
service, adds it to `PATH`, and writes a default config. Grab
`gecit-<version>-amd64.msi` from [releases](https://github.com/boratanrikulu/gecit/releases).

Install Npcap first. Its license forbids redistribution, so the MSI cannot
bundle it and refuses to install without it.

The installer asks whether gecit should start at boot, and for the DoH upstream
and fake TTL. Uncheck the box to register the service without running it.

For an unattended install:

```powershell
msiexec /i gecit-0.1.4-amd64.msi /qn DOHUPSTREAM=quad9 FAKETTL=12
msiexec /i gecit-0.1.4-amd64.msi /qn AUTOSTART=0
```

Uninstall from Add/Remove Programs, or `msiexec /x gecit-0.1.4-amd64.msi /qn`.
Uninstalling restores DNS and routes first. Your config file and logs are left
in place.

### Building from source

Requires Go 1.24+. Linux builds need kernel 5.10+, clang, and llvm-strip for BPF compilation. Windows builds are pure Go and cross-compile from any host.

```bash
git clone https://github.com/boratanrikulu/gecit.git
cd gecit

make gecit-linux-amd64    # Linux x86_64
make gecit-linux-arm64    # Linux ARM64
make gecit-darwin-arm64   # macOS Apple Silicon
make gecit-darwin-amd64   # macOS Intel
make gecit-windows-amd64  # Windows x86_64

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

# Which build is this
gecit version
```

### Windows service

```powershell
gecit service install     # register with Windows, start at boot
gecit service start
gecit service status
gecit service stop
gecit service restart
gecit service set-start --manual   # stop starting at boot
gecit service uninstall
```

The MSI does this for you. These commands are for a plain `gecit.exe` without
the installer, and for changing an installed service afterwards.

The service logs to `C:\ProgramData\gecit\gecit.log`, rotating at 10 MB and
keeping 3 files. Start, stop and start failures also land in the Windows
Application event log under the source `gecit`.

### Web panel

`gecit run` also serves a local panel: live counters, the log stream, the
domains it injected into, and the config file as a form.

```bash
sudo gecit run              # prints the panel URL, token included
sudo gecit status           # prints it again later
sudo gecit run --panel=false
sudo gecit run --panel-addr 127.0.0.1:9000   # move it off the default port
```

Open it at `http://gecit.localhost:8088`, which is the URL gecit prints.
Anything under `.localhost` is reserved by RFC 6761 and mapped to loopback by
the browser itself, so there is no DNS record, no hosts file and nothing to
clean up. It resolves the same with `--doh=false`, and in a browser that does
its own DoH. `http://127.0.0.1:8088` works just as well.

It binds to `127.0.0.1:8088` and refuses any address that is not loopback. A
port already in use is a warning rather than a failure: gecit runs without the
panel rather than not at all.
Every API call needs a token kept in `/etc/gecit/panel.token` (`%ProgramData%\gecit\panel.token`
on Windows), readable by root or Administrators only. Open the URL once and the
browser keeps the token, so afterwards the address alone is enough. A token the
panel stops accepting is dropped and the page asks for a new one. To reach it from another machine, forward the
port over SSH rather than changing the address.

The panel can start and stop the engine, and saving the config from it rewrites
`config.yaml`. Applying restarts the engine, which hands system DNS back and
takes it again, so expect a second without name resolution. A value passed as a
flag on the command line still wins over the file, and the panel says so next to
the ones it affects.

The activity list lives in memory only and goes when gecit stops. It holds
domain names, so it is worth knowing it is there. The log is a separate matter:
a Windows service writes it to `C:\ProgramData\gecit\gecit.log`, so whatever
the level emits is kept on disk. DNS lookups are logged at debug, which is off
by default; switching the level in the panel turns every resolved domain into a
line in that file.

The first run creates `panel.token` next to the config file. Delete it to
invalidate every URL handed out so far; the next start writes a new one.

### Config file

A service started by Windows or systemd has no command line, so gecit reads
settings from a file. Flags you pass still win over it.

| Platform | Path |
|---|---|
| Linux, macOS | `/etc/gecit/config.yaml` |
| Windows | `C:\ProgramData\gecit\config.yaml` |

```bash
gecit config path          # print the path in use
gecit config init          # write a commented default, never overwrites
gecit --config ./my.yaml run
```

With no config file, gecit runs on its built-in defaults.

`config init` needs root or Administrator: the file configures a process that
runs as root or LocalSystem, so it is written where an unprivileged user
cannot reach it. On Windows the directory is created with an explicit ACL for
the same reason.

`doh_upstream` must name a preset or an `https` URL. A cleartext upstream would
hand every lookup on the machine to whoever is on the path, and gecit has
already pointed the system resolver at itself.

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--doh` | `true` | Enable the built-in DoH DNS resolver |
| `--doh-upstream` | `cloudflare` | DoH upstream: preset name or URL. Comma-separated for fallback. |
| `--fake-ttl` | `8` | TTL for fake packets (must reach DPI but expire before server) |
| `--mss` | `88` | TCP MSS for ClientHello fragmentation (Linux) |
| `--restore-after-bytes` | `600` | Restore normal MSS after N bytes (Linux) |
| `--restore-mss` | `0` | Restored MSS value, 0 = auto/1460 (Linux) |
| `--cgroup` | `/sys/fs/cgroup` | cgroup v2 path (Linux) |
| `--ports` | `443` | Target destination ports |
| `--interface` | auto | Network interface |
| `-v` | off | Verbose/debug logging |
| `--panel` | `true` | Serve the local web panel |
| `--panel-addr` | `127.0.0.1:8088` | Panel address, loopback only |
| `--config` | per-platform | Config file path (see Config file above) |

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
- [x] Local web panel
- [x] Packages - deb, rpm, apk, Homebrew tap, MSI
- [ ] Auto-TTL detection (traceroute to find DPI hop count)
- [ ] ECH (Encrypted Client Hello) support

## License

GPL-3.0. See [LICENSE](LICENSE).

Copyright (c) 2026 Bora Tanrikulu \<me@bora.sh\>
