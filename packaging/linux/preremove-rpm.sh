#!/bin/sh
set -e

# rpm passes the number of copies that will remain: 1 while upgrading, 0 on a
# real erase. It also runs the new package's %post before this one, the reverse
# of dpkg, so stopping on an upgrade would kill the service that %post just
# restarted. packaging/linux/preremove.sh is the dpkg and apk version.
[ "${1:-0}" = "0" ] || exit 0

# Stopping is what gives the machine its resolver back. gecit restores
# /etc/resolv.conf when it catches the SIGTERM systemd sends, and nothing else
# does: `gecit cleanup` is a stub on Linux.
systemctl stop gecit.service >/dev/null 2>&1 || true

# The enable symlink lives in /etc/systemd/system and belongs to systemd, not to
# the package, so removing the package leaves it dangling. Reinstalling would
# then start gecit at boot without anyone asking for it.
systemctl disable gecit.service >/dev/null 2>&1 || true
