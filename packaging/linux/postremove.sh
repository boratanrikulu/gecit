#!/bin/sh
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# /etc/gecit stays. postinstall wrote it rather than the package manager, so
# nothing here owns it, and an upgrade runs this script too.
