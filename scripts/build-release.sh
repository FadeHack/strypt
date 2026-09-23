#!/usr/bin/env bash
# Build one release binary reproducibly (ADR-0050). CI runs this, and so does anyone verifying a
# release: same commit, same target, same OS image -> same bytes.
#
# Usage: scripts/build-release.sh [--gui] TARGET [OUTDIR]    (default OUTDIR: target/release-artifacts)
# --gui builds strypt-gui instead of the CLI (ADR-0062).
set -euo pipefail

PKG=strypt; [[ ${1:-} == --gui ]] && { PKG=strypt-gui; shift; }
TARGET=${1:?usage: scripts/build-release.sh [--gui] TARGET [OUTDIR]}
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
mkdir -p "${2:-$ROOT/target/release-artifacts}"
OUT=$(cd "${2:-$ROOT/target/release-artifacts}" && pwd -P)
cd "$ROOT"
rustup toolchain install --no-self-update >/dev/null   # the one rust-toolchain.toml pins
rustup target add "$TARGET" >/dev/null

# rustc sees Windows paths, so remap prefixes must be spelled the Windows way under Git Bash.
native() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
S=/; command -v cygpath >/dev/null && S='\'
SRC=$(native "$ROOT")
CARGO=$(native "${CARGO_HOME:-$HOME/.cargo}")
STD_SRC="$(native "$(rustc --print sysroot)")${S}lib${S}rustlib${S}src${S}rust"
COMMIT=$(rustc -vV | sed -n 's/^commit-hash: //p')

flags=(
  "--remap-path-prefix=$SRC=/strypt"
  "--remap-path-prefix=$CARGO=/cargo"
  # With rust-src installed, std's paths resolve into the toolchain; map them back to what a
  # machine without it embeds.
  "--remap-path-prefix=$STD_SRC=/rustc/$COMMIT"
)
# Apple's ld hashes object-file paths into LC_UUID; --remap-path-prefix does not reach it.
# -S drops the debug map, whose paths into RUSTUP_HOME changed the GUI's UUID (ADR-0062).
[[ $TARGET == *-apple-darwin ]] && flags+=("-Clink-arg=-Wl,-oso_prefix,$SRC/" "-Clink-arg=-Wl,-S")
# link.exe stamps the PE header with the link time; rustc never passes /Brepro itself.
[[ $TARGET == *-windows-msvc ]] && flags+=("-Clink-arg=/Brepro")

SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct)
export SOURCE_DATE_EPOCH
# The unit separator lets a path contain spaces, which RUSTFLAGS cannot.
CARGO_ENCODED_RUSTFLAGS=$(IFS=$'\x1f'; printf '%s' "${flags[*]}")
export CARGO_ENCODED_RUSTFLAGS
unset RUSTFLAGS CARGO_TARGET_DIR

cargo build --release --locked -p "$PKG" --target "$TARGET" --target-dir "$ROOT/target"

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
EXE=; [[ $TARGET == *-windows-* ]] && EXE=.exe
NAME="$PKG-$VERSION-$TARGET$EXE"
mkdir -p "$OUT"
cp "target/$TARGET/release/$PKG$EXE" "$OUT/$NAME"
echo "$OUT/$NAME"
