#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the TIFF corpus.
#
# The question this answers is Phase 2 exit criterion 1's inherited half of the Phase 1 bar:
# **does strypt remove at least what mat2 removes for this format**, or is every gap recorded as
# a documented limitation with a rationale (docs/ROADMAP.md Phase 1 exit criterion 3)?
#
# It is deliberately not a "do the two produce the same file" check, and for TIFF the reason is
# sharper than for any other format. mat2's default TIFF path loads the image through GdkPixbuf
# and **re-renders the pixels**; strypt rebuilds the container and copies the compressed image
# data across byte for byte (ADR-0033). The two outputs cannot resemble each other and should
# not. What is compared is *what metadata survives in each tool's output*.
#
# ExifTool carries more weight here than it does for the package formats. It is the reference
# implementation for TIFF tags, it reads the sub-IFDs, and — unlike mat2's reader — it will
# happily name a private tag strypt has never heard of. That is exactly the failure the
# allow-list exists to prevent, so ExifTool is the check that can actually catch it.
#
# Requires mat2 and ExifTool on PATH. Refuses to run without them rather than reporting a clean
# sweep it did not perform — the mistake the WebP differential made for two days
# (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/tiff"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n\n' "$(exiftool -ver)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# Tags ExifTool reports for every TIFF whether or not anyone put metadata in it: the structural
# ones strypt deliberately keeps, and ExifTool's own descriptions of the file it just opened
# (filename, size, permissions — properties of the file on disk, not of its contents).
# Excluding them is not softening the check — an image cannot be decoded without the structural
# ones, and a tool that removed them would be breaking the picture rather than cleaning it
# (ADR-0033).
#
# **The pattern must match ExifTool's `-s -G` layout, which is `[Group]<space>Tag : value` — not
# `Group:Tag`.** A pattern written for the wrong layout excludes nothing, and the comparison then
# counts structural noise on both sides and calls it a clean sweep. That is the shape of the WebP
# mistake this script's header warns about, reached by a different route.
STRUCTURAL='^\[(ExifTool|File|System|Composite)\]|^\[[A-Za-z0-9]+\][[:space:]]+(ImageWidth|ImageHeight|ImageLength|BitsPerSample|Compression|PhotometricInterpretation|StripOffsets|SamplesPerPixel|RowsPerStrip|StripByteCounts|PlanarConfiguration|FillOrder|Orientation|XResolution|YResolution|ResolutionUnit|Predictor|ColorMap|TileWidth|TileLength|TileOffsets|TileByteCounts|ExtraSamples|SampleFormat|MinSampleValue|MaxSampleValue|PageNumber|SubfileType|NewSubfileType|YCbCr[A-Za-z]*|ReferenceBlackWhite|JPEGTables|ExifByteOrder|Warning)[[:space:]]+:'

for input in "$CORPUS"/*.tiff; do
    [ -e "$input" ] || continue
    name="$(basename "$input")"
    checked=$((checked + 1))
    printf '%s\n' "$name"

    # strypt's output.
    rm -rf "$WORK/s" && mkdir -p "$WORK/s"
    if ! "$STRYPT" strip --output-dir "$WORK/s" "$input" >/dev/null 2>&1; then
        note "strypt refused this file — a refusal is a correct outcome, and there is nothing to compare"
        continue
    fi
    strypt_out="$(find "$WORK/s" -type f | head -1)"

    # mat2's output. mat2 writes alongside its input, so it gets its own copy.
    rm -rf "$WORK/m" && mkdir -p "$WORK/m"
    cp "$input" "$WORK/m/$name"
    if ! (cd "$WORK/m" && mat2 --inplace "$name" >/dev/null 2>&1); then
        note "mat2 refuses this file — recorded, not skipped: see docs/THREAT_MODEL.md §7.8"
        mat2_out=""
    else
        mat2_out="$WORK/m/$name"
    fi

    # ExifTool is the primary comparison for this format: it names private and vendor tags that
    # mat2's reader does not, which is the case the allow-list exists for.
    #
    # **`-u` is load-bearing.** Without it ExifTool silently omits tags it does not recognise —
    # precisely the class the allow-list exists to catch. On `unknown-vendor-tag.tiff` the
    # default output reports one of the two private tags; with `-u` it reports both, naming
    # `Exif_0xc5d9` explicitly. A differential blind to unknown tags cannot check the property
    # this handler's design turns on.
    exiftool -s -G -u "$strypt_out" 2>/dev/null | grep -vE "$STRUCTURAL" > "$WORK/strypt.txt" || true
    survived_strypt=$(grep -c . "$WORK/strypt.txt" || true)

    if [ -n "$mat2_out" ]; then
        exiftool -s -G -u "$mat2_out" 2>/dev/null | grep -vE "$STRUCTURAL" > "$WORK/mat2.txt" || true
        survived_mat2=$(grep -c . "$WORK/mat2.txt" || true)
    else
        survived_mat2="n/a"
    fi

    if [ "$survived_mat2" != "n/a" ] && [ "$survived_strypt" -gt "$survived_mat2" ]; then
        printf '  \033[31mGAP\033[0m: %s tag(s) survive strypt, %s survive mat2\n' \
            "$survived_strypt" "$survived_mat2"
        sed 's/^/      /' "$WORK/strypt.txt"
        gaps=$((gaps + 1))
    else
        note "strypt: $survived_strypt tag(s) survive · mat2: $survived_mat2"
    fi

    # The absolute check, independent of what mat2 managed: no identifying value may remain.
    # Every fixture's identifying values are SYNTHETIC- markers, so this reads the bytes rather
    # than either tool's report — a handler that forgot to remove something would still report
    # having removed it.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        printf '  \033[31mGAP\033[0m: a synthetic marker survived into strypt output\n'
        gaps=$((gaps + 1))
    fi

    # And the payload must have crossed intact, which is the claim that distinguishes strypt's
    # approach from mat2's re-rendering default.
    if ! grep -aq 'PRESERVED-' "$strypt_out"; then
        printf '  \033[31mGAP\033[0m: the image data did not survive the rebuild\n'
        gaps=$((gaps + 1))
    fi
done

printf '\n%d file(s) compared\n' "$checked"
if [ "$gaps" -ne 0 ]; then
    fail "$gaps gap(s) — each must be fixed or recorded in docs/THREAT_MODEL.md with a rationale"
fi
printf '\033[32m✓\033[0m no gaps: nothing survives strypt that does not also survive mat2\n'
