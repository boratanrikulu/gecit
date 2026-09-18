#!/bin/sh
set -e

# dpkg runs this before unpacking a new version as well as before a removal,
# and only the removal should stop anything. apk runs it on removal alone and
# passes a version string, which matches none of these words. rpm has its own
# copy of this script because it passes a count instead.
case "${1:-}" in
upgrade | deconfigure | failed-upgrade) exit 0 ;;
esac

# Stopping is what gives the machine its resolver back. gecit restores
# /etc/resolv.conf when it catches the SIGTERM systemd sends, and nothing else
# does: `gecit cleanup` is a stub on Linux.
systemctl stop gecit.service >/dev/null 2>&1 || true

# The enable symlink lives in /etc/systemd/system and belongs to systemd, not to
# the package, so removing the package leaves it dangling. Reinstalling would
# then start gecit at boot without anyone asking for it.
systemctl disable gecit.service >/dev/null 2>&1 || true
