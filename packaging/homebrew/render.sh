#!/usr/bin/env bash
#
# Renders the Homebrew cask to stdout.
#
#   packaging/homebrew/render.sh 0.2.0 \
#     dist/gecit_0.2.0_darwin_amd64.tar.gz \
#     dist/gecit_0.2.0_darwin_arm64.tar.gz > Casks/gecit.rb
set -euo pipefail

if [ $# -ne 3 ]; then
	echo "usage: $0 VERSION DARWIN_AMD64_TARBALL DARWIN_ARM64_TARBALL" >&2
	exit 2
fi

version=$1
amd64_tarball=$2
arm64_tarball=$3
template="$(dirname "$0")/gecit.rb.tmpl"

# The cask builds its URLs from `v#{version}`, so a leading v here would ask for
# a tag named vv0.2.0.
case "$version" in
v*)
	echo "version must not start with v, got $version" >&2
	exit 1
	;;
esac

# A missing tarball has to stop the render. The digest is produced inside a
# command substitution that sed takes as an argument, where a non-zero exit is
# discarded even under `set -e`, so without this the script would happily emit
# `sha256 ""` and publish a cask nobody can install.
for tarball in "$amd64_tarball" "$arm64_tarball"; do
	if [ ! -f "$tarball" ]; then
		echo "$tarball does not exist" >&2
		exit 1
	fi
done

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

sed -e "s|@@VERSION@@|$version|g" \
	-e "s|@@SHA256_AMD64@@|$(sha256 "$amd64_tarball")|g" \
	-e "s|@@SHA256_ARM64@@|$(sha256 "$arm64_tarball")|g" \
	"$template"
