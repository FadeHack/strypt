#!/usr/bin/env bash
# Write a CycloneDX SBOM per release target (ADR-0054). Any host can write any target's SBOM:
# it reads Cargo.lock, and builds nothing.
#
# Usage: scripts/sbom.sh [--gui] OUTDIR TARGET...    (needs cargo-cyclonedx, version pinned in release.yml)
# --gui writes strypt-gui's. universal-apple-darwin is the .dmg's two Mac targets merged: their
# dependency edges differ (cpufeatures), and the binary carries both.
set -euo pipefail

PKG=strypt; [[ ${1:-} == --gui ]] && { PKG=strypt-gui; shift; }
[ $# -gt 1 ] || { echo "usage: scripts/sbom.sh [--gui] OUTDIR TARGET..." >&2; exit 2; }
OUT=$(mkdir -p "$1" && cd "$1" && pwd -P); shift
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"

# Omits the timestamp's clock and the random serial number (cargo-cyclonedx 0.5.9).
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)

sbom() {
  cargo cyclonedx -q --format json --spec-version 1.5 --target "$1" --no-build-deps \
    --override-filename sbom-tmp
  # Workspace crates are identified by their absolute path, which is the builder's, not strypt's.
  sed -E 's#path\+file://[^"]*/crates/#path+file:///strypt/crates/#g' "crates/$PKG/sbom-tmp.json" > "$2"
  rm -f crates/*/sbom-tmp.json
}

for T in "$@"; do
  NAME="$PKG-$VERSION-$T.cdx.json"
  if [ "$T" = universal-apple-darwin ]; then
    sbom aarch64-apple-darwin "$OUT/$NAME.arm"
    sbom x86_64-apple-darwin "$OUT/$NAME.x86"
    jq -n --slurpfile a "$OUT/$NAME.arm" --slurpfile b "$OUT/$NAME.x86" '$a[0] as $x | $b[0] as $y | $x
      | .components = ([$x.components[], $y.components[]] | unique_by(.["bom-ref"]))
      | .dependencies = ([$x.dependencies[], $y.dependencies[]] | group_by(.ref)
          | map(([.[].dependsOn // [] | .[]] | unique) as $d | {ref: .[0].ref}
                + if $d == [] then {} else {dependsOn: $d} end))
      | .metadata.properties = ([$x.metadata.properties[], $y.metadata.properties[]] | unique)' \
      > "$OUT/$NAME"
    rm -f "$OUT/$NAME.arm" "$OUT/$NAME.x86"
  else
    sbom "$T" "$OUT/$NAME"
  fi
  if grep -o 'file:///[^"]*' "$OUT/$NAME" | grep -qv '^file:///strypt/'; then
    echo "::error::$NAME still names a local path" >&2; exit 1
  fi
  echo "$OUT/$NAME"
done
