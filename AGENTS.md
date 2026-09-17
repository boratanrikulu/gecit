# AGENTS.md

Notes for agents working in this repo. Facts here were verified against the
code, not assumed. If you verify something non-obvious, add it.

## What gecit is

DPI bypass. Injects fake TLS ClientHello packets with a low TTL so a
middlebox sees them and the real server does not. Bundles a DoH resolver to
sidestep DNS poisoning. One binary, one command, and defaults that work with
no config file.

## Layout

```
cmd/gecit/app/     cobra commands: run, status, cleanup, config, service
pkg/engine/        Engine interface (Start/Stop/Mode) + Config struct
pkg/ebpf/          Linux engine: sock_ops, kernel side written in Go via gobee
pkg/tun/           macOS/Windows engine: sing-tun + gVisor netstack
pkg/rawsock/       raw packet injection, per-OS
pkg/capture/       new-connection detection, per-OS
pkg/seqtrack/      seq/ack extraction feeding the fake packets
pkg/dns/           DoH server + system DNS takeover/restore, per-OS
pkg/fake/          fake ClientHello construction
```

Two engines behind one interface (`pkg/engine/engine.go:7`): eBPF sock_ops on
Linux, TUN transparent proxy on macOS and Windows. `newPlatformEngine` has one
definition per platform: `run_linux.go` by filename suffix, `run_tun.go` by
`//go:build (darwin || windows) && with_gvisor`.

## Build tags

- `with_gvisor` is required for every macOS and Windows build. `pkg/tun` is
  `//go:build (darwin || windows) && with_gvisor`. Without it the TUN engine
  does not compile in and the binary is useless on those platforms.
- `integration` gates `pkg/ebpf/manager_integration_test.go`, which needs root.
- `pkg/capture` and `pkg/rawsock` select Windows files by filename suffix.
  Windows builds are pure Go: build them with `CGO_ENABLED=0`.

## Commands

```bash
make bpf-all                 # gobee translate + clang compile, required before Linux build
make gecit-linux-amd64       # implies bpf-all
make gecit-windows-amd64
make vet                     # go vet -tags with_gvisor ./...
make fmt
go test -race -tags with_gvisor -timeout 60s ./...
```

Without `-tags with_gvisor` the suite fails to build on macOS and Windows:
`cmd/gecit/app` imports `pkg/tun`, which is `(darwin || windows) &&
with_gvisor`. Cross-check every target before calling anything done:

```bash
go vet -tags with_gvisor ./...                                    # darwin
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet -tags with_gvisor ./...
GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go vet ./...               # needs bpf-translate
```

`GOOS=windows ... ./...` only works when the gobee bindings are absent. gobee
generates `pkg/ebpf/bpf/sockops_bindings.go` with no build constraint while it
imports `golang.org/x/sys/unix`, so once `make bpf-all` has run in a tree, that
package breaks any whole-module Windows command. The binary is unaffected;
nothing imports it on Windows.

`make bpf-all` needs clang, llvm, libbpf-dev. The compiled objects are
committed under `pkg/ebpf/bpf/bin/` and `.gitignore` whitelists them.

## Windows facts

Verified, and each one changes a decision somewhere. Paths naming
`internal/wintun/...` or `pcap_windows.go` are in `$(go env GOMODCACHE)`, not
in this repo.

- **wintun.dll is embedded in the binary.** sing-tun memory-loads it:
  `internal/wintun/dll_windows_amd64.go` is a `//go:embed amd64/wintun.dll`,
  loaded through `memmod.LoadLibrary` in `dll_windows.go:86`. Nothing has to
  ship or install a wintun DLL.

- **gopacket/pcap needs no cgo on Windows.** `pcap_windows.go` contains zero
  cgo; it `LoadLibrary`s `wpcap.dll` at runtime (`LoadWinPCAP`,
  `pcap_windows.go:161`) after pointing the DLL search path at
  `%SystemRoot%\System32\Npcap` (`initDllPath`, `pcap_windows.go:29`). Only
  `pcap_unix.go` is cgo.

- Consequence: the Windows binary cross-compiles from Linux or macOS with
  `CGO_ENABLED=0`, and CI needs neither MinGW nor the Npcap SDK. Npcap is
  still required at runtime.

- windows/arm64 cannot build at all: gopacket ships `defs_windows_386.go` and
  `defs_windows_amd64.go` only. The failure is in the dependency, not in
  gecit, which is why the release matrix is amd64 only.

- **Npcap absence does not crash.** `pcapFindAllDevs` calls `LoadWinPCAP()`
  and returns its error (`pcap_windows.go:642`), so `capture.NpcapAvailable()`
  reports false instead of dereferencing a null proc address.

- `C:\ProgramData` lets any user create a subdirectory and own what they
  create. `gecit`'s data directory holds the config a LocalSystem service
  reads, so it is created with an explicit DACL (SYSTEM and Administrators
  full, everyone else read) in `cmd/gecit/app/datadir_windows.go`, and the MSI
  applies the same one. Do not replace either with a plain `os.MkdirAll`.

- gecit takes over system DNS by pointing the active interface at `127.0.0.1`
  via `netsh` and leaves a breadcrumb at `%ProgramData%\gecit-dns-backup`
  (`pkg/dns/system_windows.go:12`). A hard kill leaves the machine without
  working DNS until `gecit cleanup` runs.

## Conventions

- Comments describe the current state. No "used to be X", no phase or plan
  references in code, CLI help, or docs.
- No em dashes anywhere, including code comments and commit messages.
- Short functions, no premature helpers, no docstrings on obvious functions.
- Commits: conventional-commits, imperative, lowercase subject, no trailing
  period, no AI attribution.
- Branches: `feat/<author>_<description>`, `fix/<author>_<description>`.
- Format with `gofmt` before calling anything done.
- Release tags are `vX.Y.Z`, candidates `vX.Y.Z-rc.N`. The dot is required:
  it makes the number a numeric identifier under SemVer, so `rc.10` sorts after
  `rc.2`. Written `rc10` it is one alphanumeric identifier compared as text and
  `rc10` sorts before `rc2`, which matters because gecit is a Go module people
  `go install`. The release workflow only builds an MSI for these two shapes.
- The MSI version drops the `v` and turns a candidate into a fourth field, so
  `v0.2.0-rc.1` builds `0.2.0.1`. MSI compares only the first three fields,
  which is why a release installs over its own candidate and why `gecit.wxs`
  needs `AllowSameVersionUpgrades`.
- Config lives in `config.yaml`: `/etc/gecit/` on unix, `%ProgramData%\gecit\`
  on Windows. Adding a key means adding it to `configKeys` in
  `cmd/gecit/app/config.go`, or the loader rejects it as unknown.

## Two invariants that look like cleanup opportunities

Both were bugs once. Neither failure is visible without a Windows box.

- **Only `run` loads the config file.** Do not hang `loadConfig` off
  `rootCmd.PersistentPreRunE`. `cleanup` is what gives a machine its resolver
  back after gecit took it, and the uninstaller calls it; a typo in
  `config.yaml` must not be able to stop that. `status` and the `service` verbs
  are the same argument.

- **The service restart policy lives in `gecit service set-recovery`, not in
  the MSI.** Restart actions alone do nothing here: the SCM runs them for a
  reported stop only when `FailureActionsOnNonCrashFailures` is set, and a
  failed engine start reports a stop with an exit code. MSI cannot set that
  flag, so the installer calls the CLI. Moving this back into
  `util:ServiceConfig` would compile, install, and never restart anything.
