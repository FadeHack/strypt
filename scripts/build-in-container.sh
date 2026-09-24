#!/usr/bin/env bash
# Run build-release.sh --gui inside Ubuntu 22.04, so the Linux GUI's glibc floor is 2.35, not the
# host's (ADR-0062). The image and rustup-init are pinned by digest; apt's packages are not, so the
# linker is recorded: LD_NOTE, if set, names a file that receives it.
#
# Usage: scripts/build-in-container.sh TARGET [OUTDIR]    (TARGET: the host's own architecture)
set -euo pipefail

TARGET=${1:?usage: scripts/build-in-container.sh TARGET [OUTDIR]}
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
mkdir -p "${2:-$ROOT/target/release-artifacts}"
OUT=$(cd "${2:-$ROOT/target/release-artifacts}" && pwd -P)

# Digests checked 2026-09-24: Docker Hub's index for ubuntu:22.04, and rustup 1.29.1's .sha256 files.
IMAGE=ubuntu:22.04@sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02
RUSTUP=1.29.1
case $TARGET in
  x86_64-unknown-linux-gnu) ARCH=x86_64 SHA=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71 ;;
  aarch64-unknown-linux-gnu) ARCH=aarch64 SHA=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433 ;;
  *) echo "not a Linux GUI target: $TARGET" >&2; exit 1 ;;
esac
HOST=$(uname -m); [[ $HOST == arm64 ]] && HOST=aarch64   # macOS spells it arm64
[[ $HOST == "$ARCH" ]] || { echo "$TARGET must be built on an $ARCH host" >&2; exit 1; }

env=(-e "RUSTUP=$RUSTUP" -e "SHA=$SHA" -e "OWNER=$(id -u):$(id -g)")
[[ -n ${CARGO_HOME:-} ]] && env+=(-e "CARGO_HOME=$CARGO_HOME")
[[ -n ${RUSTUP_HOME:-} ]] && env+=(-e "RUSTUP_HOME=$RUSTUP_HOME")

docker run --rm -i "${env[@]}" \
  --mount "type=bind,src=$ROOT,dst=$ROOT" --mount "type=bind,src=$OUT,dst=$OUT" \
  "$IMAGE" bash -s -- "$ROOT" "$TARGET" "$OUT" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl gcc libc6-dev git >/dev/null
git config --global --add safe.directory '*'   # the bind mount belongs to the host's user
curl --proto '=https' -fsSLo /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/$RUSTUP/$2/rustup-init"
echo "$SHA  /tmp/rustup-init" | sha256sum -c --quiet -
chmod 755 /tmp/rustup-init
/tmp/rustup-init -y -q --no-modify-path --default-toolchain none --profile minimal
export PATH=${CARGO_HOME:-$HOME/.cargo}/bin:$PATH
bash "$1/scripts/build-release.sh" --gui "$2" "$3"
ld --version | head -1 > "$3/.linker"
chown -R "$OWNER" "$1/target" "$3"
EOF

if [[ -n ${LD_NOTE:-} ]]; then mv "$OUT/.linker" "$LD_NOTE"; else rm "$OUT/.linker"; fi
