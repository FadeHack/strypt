#!/usr/bin/env bash
# Write a CycloneDX SBOM per release target (ADR-0054). Any host can write any target's SBOM:
# it reads Cargo.lock, and builds nothing.
#
# Usage: scripts/sbom.sh OUTDIR TARGET...    (needs cargo-cyclonedx, version pinned in release.yml)
set -euo pipefail

[ $# -gt 1 ] || { echo "usage: scripts/sbom.sh OUTDIR TARGET..." >&2; exit 2; }
OUT=$(mkdir -p "$1" && cd "$1" && pwd -P); shift
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"

# Omits the timestamp's clock and the random serial number (cargo-cyclonedx 0.5.9).
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)

for T in "$@"; do
  NAME="strypt-$VERSION-$T.cdx.json"
  cargo cyclonedx -q --format json --spec-version 1.5 --target "$T" --no-build-deps \
    --override-filename sbom-tmp
  # Workspace crates are identified by their absolute path, which is the builder's, not strypt's.
  sed -E 's#path\+file://[^"]*/crates/#path+file:///strypt/crates/#g' crates/strypt/sbom-tmp.json \
    > "$OUT/$NAME"
  rm -f crates/*/sbom-tmp.json
  if grep -o 'file:///[^"]*' "$OUT/$NAME" | grep -qv '^file:///strypt/'; then
    echo "::error::$NAME still names a local path" >&2; exit 1
  fi
  echo "$OUT/$NAME"
done
