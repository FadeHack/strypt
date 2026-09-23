#!/usr/bin/env bash
# Wrap the two macOS GUI binaries from build-release.sh --gui into one universal strypt.app,
# ad-hoc signed as a whole, inside a .dmg (ADR-0062). Signing only the binary leaves a bundle
# Finder calls "damaged", so the bundle is signed and verified or nothing is written.
#
# Usage: scripts/package-macos.sh ARM64_BINARY X86_64_BINARY [OUTDIR]
#   -> OUTDIR/strypt.app and OUTDIR/strypt-gui-<version>-universal-apple-darwin.dmg
set -euo pipefail

ARM=${1:?usage: scripts/package-macos.sh ARM64_BINARY X86_64_BINARY [OUTDIR]}
X86=${2:?usage: scripts/package-macos.sh ARM64_BINARY X86_64_BINARY [OUTDIR]}
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
OUT=${3:-$ROOT/target/release-artifacts}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd -P)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)
SOURCE_DATE_EPOCH=$(git -C "$ROOT" log -1 --format=%ct)
(cd "$ROOT" && rustup toolchain install --no-self-update >/dev/null)   # the one rust-toolchain.toml pins

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
APP=$STAGE/strypt.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

lipo -create -output "$APP/Contents/MacOS/strypt-gui" "$ARM" "$X86"
chmod 755 "$APP/Contents/MacOS/strypt-gui"   # artifact downloads drop the mode
(cd "$ROOT" && cargo run -q --release --locked -p strypt-mark -- icns "$APP/Contents/Resources/strypt.icns")
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>en</string>
	<key>CFBundleDisplayName</key><string>strypt</string>
	<key>CFBundleExecutable</key><string>strypt-gui</string>
	<key>CFBundleIconFile</key><string>strypt</string>
	<key>CFBundleIdentifier</key><string>io.github.fadehack.strypt</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>strypt</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$VERSION</string>
	<key>CFBundleVersion</key><string>$VERSION</string>
	<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
# The .dmg is not reproducible whatever the times say (ADR-0062); fixed times keep the .app so.
find "$APP" -exec touch -h -t "$(date -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" {} +

rm -rf "$OUT/strypt.app"
cp -Rp "$APP" "$OUT/strypt.app"
ln -s /Applications "$STAGE/Applications"
DMG=$OUT/strypt-gui-$VERSION-universal-apple-darwin.dmg
hdiutil create -quiet -ov -volname strypt -fs HFS+ -format UDZO -srcfolder "$STAGE" "$DMG"
echo "$DMG"
