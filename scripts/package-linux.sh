#!/usr/bin/env bash
# Wrap a Linux GUI binary from build-release.sh --gui into an AppImage (ADR-0062 decision 3).
# appimagetool and its runtime are downloaded and checked against pinned digests before either is
# used; without --runtime-file, appimagetool would fetch an unpinned runtime itself.
#
# Usage: scripts/package-linux.sh BINARY [OUTDIR]     (Linux x86_64 or aarch64 host)
#   -> OUTDIR/strypt-gui-<version>-<target>.AppImage
set -euo pipefail

BIN=${1:?usage: scripts/package-linux.sh BINARY [OUTDIR]}
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
OUT=${2:-$ROOT/target/release-artifacts}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -P)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)
export SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct)
(cd "$ROOT" && rustup toolchain install --no-self-update >/dev/null)   # the one rust-toolchain.toml pins

case $BIN in
  *-x86_64-unknown-linux-gnu) ARCH=x86_64 TARGET=x86_64-unknown-linux-gnu ;;
  *-aarch64-unknown-linux-gnu) ARCH=aarch64 TARGET=aarch64-unknown-linux-gnu ;;
  *) echo "not a Linux GUI binary: $BIN" >&2; exit 1 ;;
esac

# SHA-256s from each GitHub release's asset digests, checked 2026-09-24.
TOOL_URL=https://github.com/AppImage/appimagetool/releases/download/1.9.1
RUNTIME_URL=https://github.com/AppImage/type2-runtime/releases/download/20251108
declare -A SHA=(
  [appimagetool-x86_64.AppImage]=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
  [appimagetool-aarch64.AppImage]=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
  [runtime-x86_64]=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
  [runtime-aarch64]=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
)

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
fetch() {   # URL NAME
  curl -fsSL --proto '=https' -o "$STAGE/$2" "$1/$2"
  echo "${SHA[$2]}  $STAGE/$2" | sha256sum -c --quiet -
}
TOOL=appimagetool-$(uname -m).AppImage
fetch "$TOOL_URL" "$TOOL"
fetch "$RUNTIME_URL" "runtime-$ARCH"
chmod 755 "$STAGE/$TOOL"

APPDIR=$STAGE/strypt.AppDir
mkdir -p "$APPDIR/usr/bin"
install -m 755 "$BIN" "$APPDIR/usr/bin/strypt-gui"   # artifact downloads drop the mode
ln -s usr/bin/strypt-gui "$APPDIR/AppRun"
(cd "$ROOT" && cargo run -q --release --locked -p strypt-mark -- png "$APPDIR/strypt.png")
ln -s strypt.png "$APPDIR/.DirIcon"
cat > "$APPDIR/strypt.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=strypt
Comment=Remove hidden metadata from files
Exec=strypt-gui
Icon=strypt
Categories=Utility;
Terminal=false
EOF
find "$APPDIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

APPIMAGE=$OUT/strypt-gui-$VERSION-$TARGET.AppImage
# Extract-and-run needs no FUSE on the build host. No -u or -g, so no update URL is embedded, and
# no VERSION, which appimagetool would write into the desktop file.
env -u VERSION APPIMAGE_EXTRACT_AND_RUN=1 ARCH=$ARCH "$STAGE/$TOOL" --no-appstream \
  --runtime-file "$STAGE/runtime-$ARCH" "$APPDIR" "$APPIMAGE"
echo "$APPIMAGE"
