#!/usr/bin/env bash
# Set the crate and Debian package version: Cargo.toml, Cargo.lock, debian/changelog.
#   scripts/set-version.sh 0.2.0
set -euo pipefail
version=${1:?usage: set-version.sh X.Y.Z}
repo_url=https://github.com/yousafsyed/pocketkey

sed -i "0,/^version = \".*\"/s//version = \"$version\"/" Cargo.toml
cargo update --workspace --offline >/dev/null

tmp=$(mktemp)
cat > "$tmp" <<ENTRY
pocketkey ($version-1) unstable; urgency=medium

  * Release $version. Changes: $repo_url/releases/tag/v$version

 -- ${DEBFULLNAME:-pocketkey release bot} <${DEBEMAIL:-actions@github.com}>  $(date -R)

ENTRY
cat debian/changelog >> "$tmp"
mv "$tmp" debian/changelog
echo "version set to $version"
