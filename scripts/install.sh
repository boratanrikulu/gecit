#!/usr/bin/env bash
#
# gecit installer
#
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/boratanrikulu/gecit/main/scripts/install.sh | sudo bash
#
# Pinned version:
#   curl -fsSL .../install.sh | sudo VERSION=v0.1.4 bash
#
# Skip auto-start:
#   curl -fsSL .../install.sh | sudo bash -s -- --no-start
#
# Uninstall:
#   curl -fsSL .../install.sh | sudo bash -s -- --uninstall

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO="boratanrikulu/gecit"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
BIN_PATH="${BIN_DIR}/gecit"
UNIT_PATH="/etc/systemd/system/gecit.service"
MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=10

# ---------------------------------------------------------------------------
# Output helpers (ANSI only, matches scripts/demo.sh style)
# ---------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' NC=''
fi

step() { printf "\n  ${BOLD}[%s/%s]${NC} %s\n" "$1" "$2" "$3"; }
ok()   { printf "  ${GREEN}OK${NC}   %s\n" "$*"; }
info() { printf "  ${CYAN}..${NC}   %s\n" "$*"; }
warn() { printf "  ${YELLOW}WARN${NC} %s\n" "$*"; }
err()  { printf "\n  ${RED}ERROR${NC} %s\n\n" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
gecit installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/boratanrikulu/gecit/main/scripts/install.sh | sudo bash
  curl -fsSL .../install.sh | sudo bash -s -- [flags]

Flags:
  --no-start       install but don't start the service
  --no-enable      install but don't enable or start the service
  --uninstall      stop, disable, and remove gecit
  -h, --help       show this help

Environment:
  VERSION=vX.Y.Z   pin to a specific release (default: latest)
  PREFIX=/path     install root (default: /usr/local; binary at $PREFIX/bin/gecit)
  NO_COLOR=1       disable ANSI colors

EOF
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

NO_START=0
NO_ENABLE=0
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-start)   NO_START=1 ;;
        --no-enable)  NO_ENABLE=1; NO_START=1 ;;
        --uninstall)  UNINSTALL=1 ;;
        -h|--help)    usage 0 ;;
        *)            printf "Unknown flag: %s\n\n" "$1" >&2; usage 1 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root. Re-run with:
    curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh | sudo bash"
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

detect_os() {
    case "$(uname -s)" in
        Linux) OS=linux ;;
        *) err "Only Linux is supported by this installer (got $(uname -s)). See README for macOS/Windows setup." ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) err "Unsupported architecture: $(uname -m). Supported: amd64, arm64." ;;
    esac
}

detect_kernel() {
    local kver major minor
    kver="$(uname -r)"
    major="${kver%%.*}"
    minor="${kver#*.}"; minor="${minor%%.*}"
    if [ "$major" -lt "$MIN_KERNEL_MAJOR" ] || \
       { [ "$major" -eq "$MIN_KERNEL_MAJOR" ] && [ "$minor" -lt "$MIN_KERNEL_MINOR" ]; }; then
        err "gecit needs Linux kernel ${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR}+ for eBPF sock_ops (you have ${kver})."
    fi
}

detect_systemd() {
    if [ ! -d /run/systemd/system ]; then
        err "systemd not detected (no /run/systemd/system). This installer only configures systemd."
    fi
}

require_tools() {
    local missing=()
    for t in curl sha256sum install systemctl awk; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        err "Missing required tools: ${missing[*]}"
    fi
}

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------

resolve_version() {
    if [ -n "${VERSION:-}" ]; then
        info "Using pinned version: ${VERSION}"
        return
    fi
    info "Resolving latest release from GitHub..."
    local resp
    if ! resp="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"; then
        err "Could not reach GitHub API. Set VERSION=vX.Y.Z to pin manually."
    fi
    if [[ "$resp" =~ \"tag_name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
        VERSION="${BASH_REMATCH[1]}"
    else
        err "Could not parse release tag from GitHub response. Set VERSION=vX.Y.Z to pin manually."
    fi
    info "Latest release: ${VERSION}"
}

# ---------------------------------------------------------------------------
# Existing install handling
# ---------------------------------------------------------------------------

backup_existing() {
    local found=0
    if systemctl is-active --quiet gecit 2>/dev/null; then
        info "Stopping running gecit service..."
        systemctl stop gecit
        found=1
    fi
    if [ -f "$UNIT_PATH" ]; then
        info "Backing up existing unit to ${UNIT_PATH}.bak"
        cp -p "$UNIT_PATH" "${UNIT_PATH}.bak"
        found=1
    fi
    if [ -f "$BIN_PATH" ]; then
        info "Backing up existing binary to ${BIN_PATH}.bak"
        cp -p "$BIN_PATH" "${BIN_PATH}.bak"
        found=1
    fi
    if [ "$found" -eq 0 ]; then
        info "No existing install found"
    fi
}

# ---------------------------------------------------------------------------
# Download + verify
# ---------------------------------------------------------------------------

download_and_verify() {
    TMPDIR="$(mktemp -d -t gecit-install.XXXXXX)"
    trap 'rm -rf "$TMPDIR"' EXIT

    local asset="gecit-${OS}-${ARCH}"
    local bin_url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
    local sum_url="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

    info "Downloading ${asset}..."
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "${TMPDIR}/gecit" "$bin_url"; then
        err "Failed to download ${bin_url}. Check that release ${VERSION} has a ${asset} asset."
    fi

    info "Downloading checksums.txt..."
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "${TMPDIR}/checksums.txt" "$sum_url"; then
        err "Failed to download ${sum_url}."
    fi

    info "Verifying SHA256..."
    local expected actual
    # Upstream checksums.txt entries can be either "<sha>  <asset>" or
    # "<sha>  <subdir>/<asset>". Match either form on the last field.
    expected="$(awk -v f="$asset" '$NF == f || $NF ~ ("/"f"$") { print $1; exit }' "${TMPDIR}/checksums.txt")"
    if [ -z "$expected" ]; then
        err "No checksum entry for ${asset} in checksums.txt."
    fi
    actual="$(sha256sum "${TMPDIR}/gecit" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        err "Checksum mismatch for ${asset}.
    expected: ${expected}
    actual:   ${actual}"
    fi
    ok "Checksum verified"
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

install_binary() {
    install -d -m 0755 "$BIN_DIR"
    install -m 0755 "${TMPDIR}/gecit" "$BIN_PATH"
    ok "Installed binary at ${BIN_PATH}"
}

write_unit() {
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=gecit DPI bypass (eBPF)
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} run
ExecStopPost=${BIN_PATH} cleanup
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$UNIT_PATH"
    ok "Wrote systemd unit at ${UNIT_PATH}"
}

activate_service() {
    systemctl daemon-reload
    if [ "$NO_ENABLE" -eq 1 ]; then
        info "Skipping enable + start (--no-enable)"
        return
    fi
    systemctl enable gecit >/dev/null 2>&1 || warn "systemctl enable returned non-zero"
    ok "Service enabled"
    if [ "$NO_START" -eq 1 ]; then
        info "Skipping start (--no-start)"
        return
    fi
    if ! systemctl start gecit 2>/dev/null; then
        warn "systemctl start gecit failed. Check: journalctl -u gecit -n 50"
        return
    fi
    sleep 1
    if systemctl is-active --quiet gecit; then
        ok "Service active"
    else
        warn "Service did not become active. Check: journalctl -u gecit -n 50"
    fi
}

print_install_summary() {
    local active
    active="$(systemctl is-active gecit 2>/dev/null || true)"
    [ -z "$active" ] && active="not running"
    printf "\n"
    printf "  %sgecit %s installed%s\n" "$BOLD" "$VERSION" "$NC"
    printf "  ----------------------------------------\n"
    printf "  binary:   %s\n" "$BIN_PATH"
    printf "  unit:     %s\n" "$UNIT_PATH"
    printf "  status:   %s\n" "$active"
    printf "\n"
    printf "  %sCommon commands%s\n" "$BOLD" "$NC"
    printf "    sudo systemctl status gecit\n"
    printf "    sudo systemctl restart gecit\n"
    printf "    sudo journalctl -u gecit -f\n"
    printf "    sudo gecit status\n"
    printf "\n"
    printf "  %sCustomize flags%s (--fake-ttl, --doh-upstream, --ports, ...)\n" "$BOLD" "$NC"
    printf "    sudo systemctl edit gecit\n"
    printf "\n"
    printf "  %sUninstall%s\n" "$BOLD" "$NC"
    printf "    curl -fsSL https://raw.githubusercontent.com/%s/main/scripts/install.sh | sudo bash -s -- --uninstall\n" "$REPO"
    printf "\n"
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

run_uninstall() {
    info "Uninstalling gecit..."
    if systemctl is-active --quiet gecit 2>/dev/null; then
        info "Stopping service (ExecStopPost runs gecit cleanup to restore DNS state)..."
        systemctl stop gecit
    elif [ -x "$BIN_PATH" ]; then
        info "Service not running; invoking gecit cleanup directly..."
        "$BIN_PATH" cleanup || warn "gecit cleanup returned non-zero (may be benign)"
    fi
    if systemctl is-enabled --quiet gecit 2>/dev/null; then
        systemctl disable gecit >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT_PATH" "${UNIT_PATH}.bak"
    rm -f "$BIN_PATH" "${BIN_PATH}.bak"
    systemctl daemon-reload
    ok "gecit removed"
    printf "\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    printf "\n  %sgecit installer%s\n" "$BOLD" "$NC"
    printf "  ----------------------------------------\n"

    if [ "$UNINSTALL" -eq 1 ]; then
        run_uninstall
        return
    fi

    step 1 7 "Preflight"
    detect_os
    detect_arch
    detect_kernel
    detect_systemd
    require_tools
    ok "${OS}/${ARCH}, kernel $(uname -r), systemd present"

    step 2 7 "Resolve version"
    resolve_version

    step 3 7 "Download and verify"
    download_and_verify

    step 4 7 "Back up existing install (if any)"
    backup_existing

    step 5 7 "Install binary"
    install_binary

    step 6 7 "Write systemd unit"
    write_unit

    step 7 7 "Activate service"
    activate_service

    print_install_summary
}

main "$@"
