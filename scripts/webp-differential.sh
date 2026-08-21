#!/usr/bin/env bash
# strypt — WebP differential against mat2 (docs/ROADMAP.md Phase 1 exit criterion 3)
#
# This comparison was recorded as NEVER RUN in docs/THREAT_MODEL.md §7.4 from 2026-08-19 to
# 2026-08-21. Not because it was forgotten: mat2's WebP path goes through GdkPixbuf, and
# without a WebP pixbuf loader mat2 fails on the ORIGINAL fixtures too, so the comparison said
# nothing about strypt. Recording that as a gap rather than a pass is the whole point — a
# differential that both tools fail identically is not evidence of anything.
#
# The prerequisite is one package. On macOS:
#     brew install webp-pixbuf-loader
# Verify it registered before trusting a run:
#     gdk-pixbuf-query-loaders | grep -i webp
# If that prints nothing, mat2 cannot read WebP and every "ok" below is meaningless.
#
# THE QUESTION. Exit criterion 3 asks whether strypt removes at least what mat2 removes. Per
# fixture: which tags does mat2 make disappear, and does strypt make all of those disappear
# too? A tag mat2 removes and strypt keeps is a gap to fix or to document.
#
# Exit 0 = no gaps. Exit 1 = at least one gap, leak, or frame loss.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
STRYPT="$REPO/target/release/strypt"
CORPUS="${1:-$REPO/corpus/webp}"

for tool in exiftool mat2 webpinfo; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
[ -x "$STRYPT" ] || { echo "no release binary at $STRYPT — run: cargo build --release" >&2; exit 2; }

if ! gdk-pixbuf-query-loaders 2>/dev/null | grep -qi webp; then
  echo "REFUSING TO RUN: no GdkPixbuf WebP loader, so mat2 cannot read WebP." >&2
  echo "Install it (brew install webp-pixbuf-loader) — otherwise this script would" >&2
  echo "report a clean sweep that proves nothing. This is exactly the §7.4 trap." >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Structural properties are what the picture IS, not metadata about it. A tool that removed
# these would be corrupting the image, so their presence in output is expected, not a finding.
#
# "WebP Flags" is structural only conditionally, so it is checked separately below: it is the
# VP8X byte declaring which chunks the file has. strypt clears its ICC/Exif/XMP bits and keeps
# the chunk (ADR-0023); mat2 drops VP8X entirely. Counting it as an ordinary removable tag
# scores strypt as leaking when the surviving bits say only "has alpha" or "is animated" —
# which describe the picture, not its provenance. That false positive fired on 12 of 14
# fixtures the first time this ran.
#
# "Alpha Preprocessing/Filtering/Compression" are ALPH-chunk bitstream parameters — how the
# alpha channel is encoded, not a statement about who made the file. They cannot be dropped
# without re-encoding the transparency, mat2 keeps them too (and its re-encode sometimes ADDS
# them), and the fingerprinting they do carry is the encoder-fingerprint residual risk already
# recorded in docs/THREAT_MODEL.md §7.4 and §4.7. Filtered here so the columns are not padded
# by three constants on every file with alpha.
STRUCTURAL='^(ExifTool Version Number|File Name|Directory|File Size|File Modification|File Access|File Inode|File Permissions|File Type|MIME Type|Image Width|Image Height|Image Size|Megapixels|VP8 Version|Horizontal Scale|Vertical Scale|Alpha Is Used|Alpha Preprocessing|Alpha Filtering|Alpha Compression|Animation|Background Color|Frame|Duration|Canvas|Bit Depth|Color Type|Compression|Filter|Interlace|Palette|Transparency|WebP Flags)'

# VP8X bits that name metadata. If one survives in strypt's output the file still claims
# metadata it no longer has, and that IS a finding regardless of what mat2 did.
METADATA_BITS='EXIF|XMP|ICC Profile'

tags() { exiftool "$1" 2>/dev/null | sed 's/ *:.*//;s/ *$//' | grep -Ev "$STRUCTURAL" | sort -u; }
frames() { webpinfo "$1" 2>/dev/null | grep -c 'ANMF'; }

printf '%-30s %6s %6s %6s   %s\n' FIXTURE ORIG STRYPT MAT2 VERDICT
printf '%s\n' "---------------------------------------------------------------------------------"

overall=0
for f in "$CORPUS"/*.webp; do
  [ -e "$f" ] || { echo "no .webp files in $CORPUS" >&2; exit 2; }
  name=$(basename "$f")

  cp "$f" "$WORK/s-$name"; cp "$f" "$WORK/m-$name"
  "$STRYPT" strip --in-place --force "$WORK/s-$name" >/dev/null 2>&1; s_rc=$?
  mat2 --inplace "$WORK/m-$name" >/dev/null 2>&1; m_rc=$?

  tags "$f" > "$WORK/orig.txt"; tags "$WORK/s-$name" > "$WORK/strypt.txt"; tags "$WORK/m-$name" > "$WORK/mat2.txt"
  o=$(wc -l < "$WORK/orig.txt" | tr -d ' '); s=$(wc -l < "$WORK/strypt.txt" | tr -d ' '); m=$(wc -l < "$WORK/mat2.txt" | tr -d ' ')

  # Tags mat2 removed (present originally, absent from mat2's output) that strypt still has.
  gap=$(comm -12 <(comm -23 "$WORK/orig.txt" "$WORK/mat2.txt") "$WORK/strypt.txt")
  stale=$(exiftool -WebP_Flags -s3 "$WORK/s-$name" 2>/dev/null | grep -Eo "$METADATA_BITS" | paste -sd, -)
  of=$(frames "$f"); sf=$(frames "$WORK/s-$name"); mf=$(frames "$WORK/m-$name")

  if [ -n "$stale" ]; then
    verdict="LEAK: VP8X still claims $stale"; overall=1
  elif [ "$s_rc" -eq 0 ] && [ "$of" -gt 0 ] && [ "$sf" -ne "$of" ]; then
    verdict="FRAME LOSS: strypt $of->$sf"; overall=1
  elif [ "$s_rc" -ne 0 ] && [ "$m_rc" -eq 0 ]; then
    verdict="strypt REFUSED (rc=$s_rc), mat2 processed"; overall=1
  elif [ -n "$gap" ]; then
    verdict="GAP: $(echo "$gap" | paste -sd, -)"; overall=1
  elif [ "$s_rc" -ne 0 ]; then
    verdict="both refused (strypt rc=$s_rc, mat2 rc=$m_rc)"
  else
    verdict="ok"
    # Not a strypt finding, but recorded: mat2 decodes and re-encodes through GdkPixbuf, which
    # flattens an animation to a single still. That is the other side of the trade in §7.4 —
    # re-encoding also destroys the encoder fingerprint that strypt deliberately leaves alone.
    [ "$of" -gt 0 ] && [ "$mf" -ne "$of" ] && verdict="ok (note: mat2 $of->$mf frames)"
  fi

  printf '%-30s %6s %6s %6s   %s\n' "$name" "$o" "$s" "$m" "$verdict"
done

echo
if [ $overall -eq 0 ]; then echo "overall: no gaps"; else echo "overall: GAPS FOUND — see above"; fi
exit $overall
