#!/usr/bin/env bash
# strypt — filesystem-constraints matrix (ADR-0043, TESTING_STRATEGY §2.7).
#
# Runs the real CLI against hostile filesystem shapes and asserts the fail-closed contract: the
# destination is replaced in full or left untouched, no `.strypt-*.tmp` survives, and a refusal
# exits 3 with nothing on stdout, which is where `strip` reports success.
#
# Linux only. Run as a non-root user with passwordless sudo, which does the mounting: root would
# walk through the permission cases. Needs dosfstools and exfatprogs.
#
# Usage: scripts/fs-matrix.sh [BINARY]    (default: target/debug/strypt)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/strypt}"

die() { echo "error: $*" >&2; exit 2; }
[ "$(uname -s)" = Linux ] || die "Linux only"
[ "$(id -u)" -ne 0 ] || die "run as a non-root user; root bypasses the permission cases"
sudo -n true 2>/dev/null || die "needs passwordless sudo to mount"
[ -x "$BIN" ] || die "no binary at $BIN"
BIN="$(realpath "$BIN")"

W="$(mktemp -d)"
MOUNTS=()
cleanup() {
  for ((i = ${#MOUNTS[@]} - 1; i >= 0; i--)); do sudo umount "${MOUNTS[$i]}" 2>/dev/null || true; done
  chmod -R u+w "$W" 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT
failed=0

mount_tmpfs() { # DIR SIZE
  mkdir -p "$1"
  sudo mount -t tmpfs -o "size=$2,uid=$(id -u),gid=$(id -g),mode=0755" tmpfs "$1"
  MOUNTS+=("$1")
}

mount_image() { # DIR FSTYPE
  mkdir -p "$1"
  truncate -s 32M "$1.img"
  "mkfs.$2" "$1.img" >/dev/null
  sudo mount -o "loop,uid=$(id -u),gid=$(id -g)" -t "$2" "$1.img" "$1"
  MOUNTS+=("$1")
}

# A 2 MiB WAV with an artist tag: large enough to overrun the small volume, and edited by chunk
# surgery (ADR-0039), so the output is nearly as large as the input.
python3 - "$W/in.wav" <<'PY'
import struct, sys
data = bytes(2 * 1024 * 1024)
fmt = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
info = b"INFO" + b"IART" + struct.pack("<I", 6) + b"Nobody"
body = (b"fmt " + struct.pack("<I", len(fmt)) + fmt
        + b"LIST" + struct.pack("<I", len(info)) + info
        + b"data" + struct.pack("<I", len(data)) + data)
open(sys.argv[1], "wb").write(b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WAVE" + body)
PY
IN="$W/in.wav"

run() { # ARGS... — sets rc, leaves stdout and stderr in $W/out and $W/err
  set +e
  "$BIN" "$@" >"$W/out" 2>"$W/err"
  rc=$?
  set -e
}

snapshot() { (cd "$1" && find . -type f -print0 | sort -z | xargs -0r sha256sum); }

temporaries() { find "$W" -name '.strypt-*.tmp' 2>/dev/null; }

fail() { echo "✗ $1 — $2"; sed 's/^/    /' "$W/err"; failed=1; }

# expect_refused NAME DIR STAGE ARGS... — exit 3 at STAGE, silent stdout, DIR byte-identical,
# no temporary. STAGE pins the refusal to the planted fault rather than to any failure.
expect_refused() {
  local name=$1 dir=$2 stage=$3 before
  shift 3
  before=$(snapshot "$dir")
  run "$@"
  if [ "$rc" -ne 3 ]; then fail "$name" "exit $rc, expected 3"
  elif ! grep -qF "while $stage" "$W/err"; then fail "$name" "refused, but not while $stage"
  elif [ -s "$W/out" ]; then fail "$name" "reported success: $(head -1 "$W/out")"
  elif [ "$(snapshot "$dir")" != "$before" ]; then fail "$name" "destination changed"
  elif [ -n "$(temporaries)" ]; then fail "$name" "temporary survived: $(temporaries)"
  else echo "✓ $name"
  fi
}

# expect_written NAME DEST ARGS... — exit 0, DEST identical to the reference, no temporary.
expect_written() {
  local name=$1 dest=$2
  shift 2
  run "$@"
  if [ "$rc" -ne 0 ]; then fail "$name" "exit $rc, expected 0"
  elif ! cmp -s "$dest" "$REF"; then fail "$name" "output differs from the reference"
  elif [ -n "$(temporaries)" ]; then fail "$name" "temporary survived: $(temporaries)"
  else echo "✓ $name  (mode $(stat -c %a "$dest"))"
  fi
}

mkdir "$W/ref"
run strip --output-dir "$W/ref" "$IN"
[ "$rc" -eq 0 ] || { cat "$W/err" >&2; die "baseline strip failed (exit $rc)"; }
REF="$W/ref/in.stripped.wav"
CREATE="creating a temporary file"

echo "== read-only volume"
mount_tmpfs "$W/ro" 8m
cp "$IN" "$W/ro/x.wav"
sudo mount -o remount,ro "$W/ro"
expect_refused "read-only: output dir" "$W/ro" "$CREATE" strip --output-dir "$W/ro" "$IN"
expect_refused "read-only: in place" "$W/ro" "$CREATE" strip --in-place "$W/ro/x.wav"

echo "== full volume (ENOSPC mid-write)"
mount_tmpfs "$W/full" 1m
head -c 102400 /dev/urandom >"$W/full/in.stripped.wav"
expect_refused "full volume: existing file survives" "$W/full" "writing output" strip --force --output-dir "$W/full" "$IN"

for fs in vfat exfat; do
  echo "== $fs (no Unix permission model)"
  mount_image "$W/$fs" "$fs"
  expect_written "$fs: new file" "$W/$fs/in.stripped.wav" strip --output-dir "$W/$fs" "$IN"
  expect_written "$fs: replace" "$W/$fs/in.stripped.wav" strip --force --output-dir "$W/$fs" "$IN"
  cp "$IN" "$W/$fs/x.wav"
  expect_written "$fs: in place" "$W/$fs/x.wav" strip --in-place "$W/$fs/x.wav"
done

echo "== destination on a different mount from TMPDIR"
mount_tmpfs "$W/tmpdir" 8m
mount_tmpfs "$W/dest" 8m
TMPDIR="$W/tmpdir" expect_written "cross-mount: TMPDIR elsewhere" "$W/dest/in.stripped.wav" \
  strip --output-dir "$W/dest" "$IN"
[ -z "$(ls -A "$W/tmpdir")" ] || fail "cross-mount: TMPDIR untouched" "wrote into TMPDIR: $(ls -A "$W/tmpdir")"

echo "== unwritable directory, writable file"
mkdir "$W/locked"
cp "$IN" "$W/locked/x.wav"
head -c 1024 /dev/urandom >"$W/locked/in.stripped.wav"
chmod 644 "$W/locked/"*
chmod 555 "$W/locked"
expect_refused "locked dir: in place" "$W/locked" "$CREATE" strip --in-place "$W/locked/x.wav"
expect_refused "locked dir: replace" "$W/locked" "$CREATE" strip --force --output-dir "$W/locked" "$IN"

echo
[ "$failed" -eq 0 ] || { echo "The fail-closed contract broke on at least one filesystem."; exit 1; }
echo "Every case held the fail-closed contract."
