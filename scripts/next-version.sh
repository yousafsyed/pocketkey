#!/usr/bin/env bash
# Print the next semantic version based on commits since the last v* tag.
#
#   feat!: / BREAKING CHANGE  -> major
#   feat:                     -> minor
#   anything else             -> patch
#
# Prints nothing (exit 0) when there are no releasable commits since the tag.
set -euo pipefail

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
IFS=. read -r major minor patch <<<"$current"

last_tag=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
if [ -z "$last_tag" ]; then
  # First release: publish the version already in Cargo.toml.
  echo "$current"
  exit 0
fi
range=$last_tag..HEAD
commits=$(git log --format='%s%n%b' "$range" | grep -v '^chore(release):' || true)

if [ -z "$(printf '%s' "$commits" | tr -d '[:space:]')" ]; then
  exit 0
fi

if printf '%s\n' "$commits" | grep -qE '^[a-zA-Z]+(\([^)]*\))?!:|^BREAKING CHANGE'; then
  echo "$((major + 1)).0.0"
elif printf '%s\n' "$commits" | grep -qE '^feat(\([^)]*\))?:'; then
  echo "$major.$((minor + 1)).0"
else
  echo "$major.$minor.$((patch + 1))"
fi
