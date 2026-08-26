#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the GIF corpus.
#
# The question this answers is Phase 2 exit criterion 1's inherited half of the Phase 1 bar:
# **does strypt remove at least what mat2 removes for this format**, or is every gap recorded as a
# documented limitation with a rationale (docs/ROADMAP.md Phase 1 exit criterion 3)?
#
# It is deliberately not a "do the two produce the same file" check. mat2's GIF path loads the
# image through GdkPixbuf and **re-renders it**; strypt removes whole extension blocks and copies
# every other byte through untouched. The two outputs cannot resemble each other and should not.
# What is compared is *what metadata survives in each tool's output*.
#
# Requires mat2 and ExifTool on PATH. Refuses to run without them rather than reporting a clean
# sweep it did not perform — the mistake the WebP differential made for two days
# (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/gif"
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

# Tags ExifTool reports for every GIF whether or not anyone put metadata in it.
#
# **The `[File]` group is filtered tag by tag rather than as a whole, and that is load-bearing.**
# ExifTool files a GIF's comment extension under `[File] Comment`, not under `[GIF]` — so the
# blanket `^\[File\]` exclusion the TIFF script uses would hide the single most common leak this
# format has. Only ExifTool's own descriptions of the file on disk are excluded here.
#
# `Duration`, `FrameCount`, and `TransparentColor` come from graphic control extensions, which
# strypt keeps: they set a frame's delay and its transparent palette index, so a tool that removed
# them would be changing how the image looks rather than cleaning it. mat2 keeps them too.
#
# **`AnimationIterations` is excluded deliberately, and it is the one exclusion that is a
# decision rather than bookkeeping.** It is the NETSCAPE2.0 loop count, which strypt keeps on
# purpose: it is a rendering instruction, it is identical in every looping GIF ever written, and
# removing it would turn a user's animation into a one-shot. strypt declares it as retained in its
# own report rather than staying silent, and the check below asserts that it really does survive —
# so this exclusion is paired with a positive claim rather than quietly softening the sweep.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\][[:space:]]+(FileName|Directory|FileSize|FileModifyDate|FileAccessDate|FileInodeChangeDate|FilePermissions|FileType|FileTypeExtension|MIMEType)[[:space:]]+:|^\[GIF\][[:space:]]+(GIFVersion|ImageWidth|ImageHeight|HasColorMap|ColorResolutionDepth|BitsPerPixel|BackgroundColor|PixelAspectRatio|FrameCount|Duration|TransparentColor|AnimationIterations|Warning)[[:space:]]+:'

for input in "$CORPUS"/*.gif; do
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
        note "mat2 refuses this file — recorded, not skipped: see docs/THREAT_MODEL.md §7.9"
        mat2_out=""
    else
        mat2_out="$WORK/m/$name"
    fi

    # `-u` is load-bearing: without it ExifTool silently omits tags it does not recognise, which
    # is precisely the class an allow-list exists to catch.
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

    # The absolute check, independent of what either tool reported: no identifying value may
    # remain. Every fixture's identifying values are SYNTHETIC- markers, so this reads the bytes
    # rather than a report — a handler that forgot to remove something would still report having
    # removed it. It is the only check that covers the unknown application block and the
    # undefined-label extension, which ExifTool does not report at all.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        printf '  \033[31mGAP\033[0m: a synthetic marker survived into strypt output\n'
        gaps=$((gaps + 1))
    fi

    # The picture must have crossed intact. GIF pixels are LZW-compressed, so no marker can be
    # planted in them the way TIFF's fixtures do; what is checked here is that the frames are all
    # still present and the image still decodes. The byte-for-byte claim is owned by
    # crates/strypt-core/tests/gif.rs, which walks the blocks independently.
    before="$(exiftool -s3 -ImageSize -FrameCount "$input" 2>/dev/null | tr '\n' ' ')"
    after="$(exiftool -s3 -ImageSize -FrameCount "$strypt_out" 2>/dev/null | tr '\n' ' ')"
    if [ "$before" != "$after" ]; then
        printf '  \033[31mGAP\033[0m: the image changed — was [%s], now [%s]\n' "$before" "$after"
        gaps=$((gaps + 1))
    fi

    # And the loop count must survive, which is what makes its exclusion from the filter above a
    # declared decision rather than a hidden softening of the sweep.
    if [ "$name" = "animated-loop.gif" ]; then
        if [ -z "$(exiftool -s3 -AnimationIterations "$strypt_out" 2>/dev/null)" ]; then
            printf '  \033[31mGAP\033[0m: the loop count did not survive — the animation no longer loops\n'
            gaps=$((gaps + 1))
        else
            note "the loop count survives, as intended"
        fi
    fi

    # A clean GIF must come back byte-identical. No other format in this tree can promise that of
    # its whole file, and a regression in the copy path would show up here first.
    if [ "$name" = "clean.gif" ] && ! cmp -s "$input" "$strypt_out"; then
        printf '  \033[31mGAP\033[0m: a clean file was not returned byte-identical\n'
        gaps=$((gaps + 1))
    fi
done

printf '\n%d file(s) compared\n' "$checked"
if [ "$gaps" -ne 0 ]; then
    fail "$gaps gap(s) — each must be fixed or recorded in docs/THREAT_MODEL.md with a rationale"
fi
printf '\033[32m✓\033[0m no gaps: nothing survives strypt that does not also survive mat2\n'
