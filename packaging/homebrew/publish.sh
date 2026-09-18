#!/usr/bin/env bash
#
# Renders the cask and pushes it to boratanrikulu/homebrew-tap, which is what
# makes `brew install boratanrikulu/tap/gecit` resolve to this release.
#
# Needs HOMEBREW_TAP_GITHUB_TOKEN, a PAT with contents write on the tap repo.
# It is an environment secret, so the job that runs this has to declare
# `environment: release` or the variable arrives empty.
set -euo pipefail

if [ $# -ne 3 ]; then
	echo "usage: $0 VERSION DARWIN_AMD64_TARBALL DARWIN_ARM64_TARBALL" >&2
	exit 2
fi

version=$1
amd64_tarball=$2
arm64_tarball=$3

: "${HOMEBREW_TAP_GITHUB_TOKEN:?set it to a PAT with contents write on boratanrikulu/homebrew-tap}"

# git runs the credential helper below as a child process, so the token has to
# be in its environment. Unexported, the helper returns an empty password and
# the push fails as a wrong password rather than a missing one.
export HOMEBREW_TAP_GITHUB_TOKEN

tap_dir=$(mktemp -d)
trap 'rm -rf "$tap_dir"' EXIT

# The token stays out of the remote URL. Embedding it would write it in
# cleartext into the clone's .git/config and put it in this process's argv.
git clone --depth 1 https://github.com/boratanrikulu/homebrew-tap.git "$tap_dir"

"$(dirname "$0")/render.sh" "$version" "$amd64_tarball" "$arm64_tarball" \
	>"$tap_dir/Casks/gecit.rb"

cd "$tap_dir"
git config user.name "boratanrikulu"
git config user.email "me@bora.sh"
git add Casks/gecit.rb

# Re-running this job renders the same cask from the same release artifact, and
# `git commit` exits non-zero with nothing staged.
if git diff --cached --quiet; then
	echo "Casks/gecit.rb is already at $version"
	exit 0
fi

git commit -m "gecit $version"

# The credential helper feeds the token on stdin instead of putting it in the
# URL, so it reaches neither argv nor .git/config. The empty helper first clears
# any inherited one.
git -c credential.helper= \
	-c credential.helper='!f() { echo username=x-access-token; echo "password=$HOMEBREW_TAP_GITHUB_TOKEN"; }; f' \
	push
