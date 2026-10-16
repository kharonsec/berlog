#!/usr/bin/env bash
# Fail unless the pushed tag is exactly "v" + the [package] version in
# Cargo.toml, which is the single source of truth for the version (the binary's
# --version is env!("CARGO_PKG_VERSION")). Prints the version on success.
#
# Usage: check-version.sh <tag>
set -euo pipefail

tag="${1:?usage: check-version.sh <tag>}"
version=$(sed -n '/^\[package\]/,/^\[/ s/^version *= *"\([^"]*\)"$/\1/p' Cargo.toml | head -n1)

if [ -z "$version" ]; then
  echo "::error::could not read [package] version from Cargo.toml" >&2
  exit 1
fi
if [ "$tag" != "v$version" ]; then
  echo "::error::tag '$tag' does not match Cargo.toml version '$version' (expected tag 'v$version')" >&2
  exit 1
fi
echo "$version"
