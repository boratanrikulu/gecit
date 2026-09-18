#!/bin/sh
set -e

# systemctl exists in plenty of containers that are not booted by systemd, and
# not at all on Alpine, so every call here tolerates failure rather than testing
# for the binary.
systemctl daemon-reload >/dev/null 2>&1 || true

# The unit ships disabled. Installing a DPI bypass should not repoint the
# machine's resolver on its own, and a package manager has no way to ask.
# `systemctl enable --now gecit` is the opt-in.
#
# Restarting only what is already running moves a live service onto the new
# binary without starting one nobody asked for. The test is `is-active` rather
# than `is-enabled` because an enabled but stopped service should stay stopped.
if systemctl is-active --quiet gecit.service; then
	systemctl restart gecit.service >/dev/null 2>&1 || true
fi

# Renders /etc/gecit/config.yaml from the binary's own defaults, and leaves an
# existing file alone. gecit runs on those defaults with no config file at all,
# so a failure here is not worth failing the install over.
/usr/bin/gecit config init || true
