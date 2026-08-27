#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the HEIF and AVIF corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes for these formats**, or is every gap recorded as
# a documented limitation with a rationale?
#
# Not a "same file" check. mat2 reaches these formats through a decoder and re-encodes; strypt
# rebuilds the container and copies the coded picture across byte for byte (ADR-0034). The outputs
# cannot resemble each other. What is compared is what metadata survives in each.
#
# mat2 0.15.0 handles image/avif *and* image/heic, though its README lists only avif — verified by
# `mat2 -l` on 2026-08-27 rather than read off the README.
#
# mat2's *default* mode declines HEIC — "HEIC files can't be thoroughly cleaned. Use lightweight
# mode instead." — so for those files this script falls back to `mat2 -L` and says which mode ran.
# Comparing against a refusal would compare against nothing (the WebP mistake in §7.4). Recording
# the mode matters because lightweight mode is a weaker operation than the default: it rewrites the
# container without re-rendering, which is what strypt does too, so for HEIC the two tools are
# being asked the same question rather than different ones.
#
# Requires mat2, ExifTool, and libheif's heif-convert on PATH. Refuses to run without them rather
# than reporting a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

# ExifTool walks a file's atoms in Perl hash order, which is randomised per process, and on some of
# these fixtures the order decides whether it raises "Chunk offset in iloc atom is outside media
# data" and refuses to write. The same bytes then succeed or fail run to run — measured 2026-08-27,
# and it goes away entirely with the seed pinned. mat2 shells out to ExifTool, so it inherits this.
#
# Pinning makes the gate reproducible. It does not soften the comparison: strypt's side of every
# check runs regardless, and a run where mat2 fails is scored as no comparison, never as a pass.
export PERL_HASH_SEED=0 PERL_PERTURB_KEYS=0

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/heif"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v heif-convert >/dev/null 2>&1 || fail "heif-convert (libheif) is not installed; the decode check cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n' "$(exiftool -ver)"
printf 'libheif:  %s\n\n' "$(heif-convert --version 2>&1 | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# Tags ExifTool reports for any file of these formats whether or not anyone put metadata in it.
#
# The `[QuickTime]` group is filtered tag by tag rather than as a whole. That group is where this
# container's *structure* is reported — brands, decoder configuration, dimensions — but it is also
# where a surviving `uuid` box or an unrecognised item would appear, so excluding it wholesale
# would hide exactly what this script exists to find. Only the structural tags are named.
#
# `MajorBrand`, `MinorVersion` and `CompatibleBrands` are excluded because strypt copies them
# deliberately: they declare which codec and profile a reader needs, and a file that stopped
# claiming them would stop opening. They are a producer fingerprint in the sense of
# docs/THREAT_MODEL.md §4.7, which strypt does not address for any format.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[QuickTime\][[:space:]]+(MajorBrand|MinorVersion|CompatibleBrands|HandlerType|HandlerDescription|MediaDataSize|MediaDataOffset|MediaData|PrimaryItemReference|ImageSpatialExtent|ImageWidth|ImageHeight|ImagePixelDepth|Rotation|Warning|AV1Configuration.*|SeqProfile|SeqLevelIdx0|SeqTier0|HighBitDepth|TwelveBit|ChromaFormat|ChromaSamplePosition|InitialDelaySamples|HEVCConfiguration.*|GeneralProfile.*|GeneralTierFlag|GeneralLevelIDC|GenProfileCompatibilityFlags|ConstraintIndicatorFlags|MinSpatialSegmentationIDC|ParallelismType|BitDepthLuma|BitDepthChroma|AverageFrameRate|ConstantFrameRate|NumTemporalLayers|TemporalIDNested|LengthSizeMinusOne|CleanAperture.*|ColorRepresentation|ColorProfiles|VideoFullRangeFlag|ColorPrimaries|TransferCharacteristics|MatrixCoefficients)[[:space:]]+:'

for input in "$CORPUS"/*.avif "$CORPUS"/*.heic; do
    [ -e "$input" ] || continue
    name="$(basename "$input")"
    checked=$((checked + 1))
    printf '%s\n' "$name"

    rm -rf "$WORK/s" && mkdir -p "$WORK/s"
    if ! "$STRYPT" strip --output-dir "$WORK/s" "$input" >/dev/null 2>&1; then
        note "strypt refused this file — a refusal is a correct outcome, and there is nothing to compare"
        continue
    fi
    strypt_out="$(find "$WORK/s" -type f | head -1)"

    # mat2 writes alongside its input, so it gets its own copy.
    rm -rf "$WORK/m" && mkdir -p "$WORK/m"
    cp "$input" "$WORK/m/$name"
    if (cd "$WORK/m" && mat2 --inplace "$name" >/dev/null 2>&1); then
        mat2_out="$WORK/m/$name"
        mat2_mode="default"
    elif (cd "$WORK/m" && mat2 -L --inplace "$name" >/dev/null 2>&1); then
        mat2_out="$WORK/m/$name"
        mat2_mode="lightweight"
    else
        note "mat2 refuses this file in both modes — recorded, not skipped: docs/THREAT_MODEL.md §7.10"
        mat2_out=""
        mat2_mode="refused"
    fi

    # `-u` is load-bearing: without it ExifTool omits tags it does not recognise, which is exactly
    # the class an allow-list exists to catch.
    exiftool -s -G -u -a "$strypt_out" 2>/dev/null | grep -vE "$STRUCTURAL" > "$WORK/strypt.txt" || true
    survived_strypt=$(grep -c . "$WORK/strypt.txt" || true)

    if [ -n "$mat2_out" ]; then
        exiftool -s -G -u -a "$mat2_out" 2>/dev/null | grep -vE "$STRUCTURAL" > "$WORK/mat2.txt" || true
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
        note "strypt: $survived_strypt tag(s) survive · mat2 ($mat2_mode): $survived_mat2"
    fi

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it. It is the only check
    # covering the unknown item type and the vendor property, which ExifTool does not report.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        printf '  \033[31mGAP\033[0m: a synthetic marker survived into strypt output\n'
        gaps=$((gaps + 1))
    fi

    # The output must still be an image. A rebuild that produced a valid-looking container with no
    # decodable picture in it is the failure in docs/THREAT_MODEL.md §5.4, and strypt's own report
    # cannot see it — so an independent decoder is asked.
    if ! heif-convert "$strypt_out" "$WORK/out.png" >/dev/null 2>&1; then
        printf '  \033[31mGAP\033[0m: the stripped file no longer decodes\n'
        gaps=$((gaps + 1))
    elif heif-convert "$input" "$WORK/in.png" >/dev/null 2>&1 \
         && command -v magick >/dev/null 2>&1; then
        # And the pixels must be the ones that went in. strypt never re-encodes (ADR-0034), so
        # this is an equality check rather than a tolerance.
        # `compare -metric AE` prints "0 (0)" — the count, then the same figure normalised.
        differing="$(magick compare -metric AE "$WORK/in.png" "$WORK/out.png" null: 2>&1 | awk '{print $1; exit}')"
        if [ "$differing" != "0" ]; then
            printf '  \033[31mGAP\033[0m: the picture changed — %s differing pixel(s)\n' "$differing"
            gaps=$((gaps + 1))
        else
            note "the picture is unchanged: 0 differing pixels"
        fi
    fi

    # ExifTool does not report an ICC profile in either format — it raises "Bad length ICC_Profile"
    # and names nothing (measured 2026-08-27), so the tag comparison above is blind to it and
    # ImageMagick is asked instead. Its removal is a decision (ADR-0034), so it is checked, not
    # assumed.
    if [ "$name" = "icc-profile.avif" ] && command -v magick >/dev/null 2>&1; then
        if magick identify -verbose "$strypt_out" 2>/dev/null | grep -qi 'Profile-icc'; then
            printf '  \033[31mGAP\033[0m: the ICC profile survived\n'
            gaps=$((gaps + 1))
        elif magick identify -verbose "$input" 2>/dev/null | grep -qi 'Profile-icc'; then
            note "the ICC profile is gone, and ImageMagick saw it in the input"
        else
            printf '  \033[31mGAP\033[0m: ImageMagick cannot see the ICC profile in the input either — this check proves nothing\n'
            gaps=$((gaps + 1))
        fi
    fi

    # Numeric colour signalling is kept on purpose, so its absence from the filter above is a
    # declared decision rather than a hidden softening of the sweep.
    if [ "$name" = "nclx-colour.avif" ]; then
        if exiftool -s -G -u -a "$strypt_out" 2>/dev/null | grep -q 'ColorPrimaries\|ColorRepresentation'; then
            note "nclx colour signalling survives, as intended"
        else
            printf '  \033[31mGAP\033[0m: numeric colour signalling was removed with the ICC profiles\n'
            gaps=$((gaps + 1))
        fi
    fi
done

# An untested gate provides confidence without protection (CLAUDE.md §6). The filter above is the
# whole comparison, so it is run once against the *unstripped* corpus: if it does not light up
# there, a clean sweep over the stripped corpus means nothing.
#
# `icc-profile.avif` and `thumbnail.heic` are deliberately not in this list. ExifTool reports
# neither an ICC profile nor a thumbnail item for these formats, so the filter genuinely cannot see
# them and claiming otherwise would be the failure this self-check exists to catch. They are
# covered instead by the ICC check above, by the marker sweep, and by the independent box walker in
# `crates/strypt-core/tests/heif.rs`. That no third-party tool here can see a HEIF thumbnail item
# is itself recorded in docs/THREAT_MODEL.md §7.10.
printf '\nself-check: the filter against unstripped fixtures\n'
caught=0
missed=""
for input in "$CORPUS"/exif.avif "$CORPUS"/exif.heic "$CORPUS"/xmp.heic "$CORPUS"/exif-and-xmp.avif \
             "$CORPUS"/uuid-xmp.heic; do
    n="$(exiftool -s -G -u -a "$input" 2>/dev/null | grep -vcE "$STRUCTURAL" || true)"
    if [ "$n" -gt 0 ]; then
        caught=$((caught + 1))
    else
        missed="$missed $(basename "$input")"
    fi
done
if [ -n "$missed" ]; then
    fail "the filter is blind to:$missed — it would report a clean sweep it did not perform"
fi
note "$caught/5 unstripped fixtures light the filter up, so a clean sweep means something"

printf '\n%d file(s) compared\n' "$checked"
if [ "$gaps" -ne 0 ]; then
    fail "$gaps gap(s) — each must be fixed or recorded in docs/THREAT_MODEL.md with a rationale"
fi
printf '\033[32m✓\033[0m no gaps: nothing survives strypt that does not also survive mat2\n'
