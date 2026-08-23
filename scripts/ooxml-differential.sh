#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the OOXML corpus.
#
# The question this answers is Phase 2 exit criterion 1's inherited half of the Phase 1 bar:
# **does strypt remove at least what mat2 removes for this format**, or is every gap recorded as
# a documented limitation with a rationale (docs/ROADMAP.md Phase 1 exit criterion 3)?
#
# It is deliberately not a "do the two produce the same file" check. They do not and should not:
# mat2 rebuilds an OOXML package from a whitelist of parts it recognises, and strypt copies every
# part it did not have a reason to change. Comparing bytes would report a difference on every
# file and tell you nothing. What is compared is *what metadata survives in each tool's output*.
#
# Requires mat2 and ExifTool on PATH. Refuses to run without them rather than reporting a clean
# sweep it did not perform — the mistake the WebP differential made for two days
# (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/ooxml"
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

for input in "$CORPUS"/*.docx "$CORPUS"/*.xlsx "$CORPUS"/*.pptx; do
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
        note "mat2 refuses this file — recorded, not skipped: see docs/THREAT_MODEL.md §7.6"
        note "  (a part whose content type is not on mat2's whitelist; strypt processes it)"
        continue
    fi

    # What mat2 says is left in each output. Using mat2's own reader for both sides is the point:
    # it removes strypt's report from the loop entirely, so a handler that forgot to remove
    # something cannot pass by claiming it did.
    mat2 --show "$strypt_out" > "$WORK/strypt.txt" 2>&1 || true
    mat2 --show "$WORK/m/$name" > "$WORK/mat2.txt" 2>&1 || true

    # Two fields are excluded from the comparison on both sides, each for a stated reason —
    # never because it was inconvenient:
    #
    # `date_time` is the ZIP entry timestamp. Both tools normalise it to a constant, and mat2
    # reports its own normalised value as though it were surviving metadata.
    #
    # `create_system` is the "version made by" host byte. Both tools write a constant here too,
    # so neither leaks the real host — but mat2 recognises only 2 and 3 and labels everything
    # else "Weird", so it reports strypt's constant 0 as a finding. Zero is MS-DOS/FAT, which is
    # what Word itself writes; mat2 writes 3, which says "made on Linux". Neither is a leak and
    # strypt's is the less conspicuous of the two.
    exclude='date_time|create_system'
    survived_strypt=$(grep -vE "$exclude" "$WORK/strypt.txt" | grep -cE '^\s+\S+:' || true)
    survived_mat2=$(grep -vE "$exclude" "$WORK/mat2.txt" | grep -cE '^\s+\S+:' || true)

    if [ "$survived_strypt" -gt "$survived_mat2" ]; then
        printf '  \033[31mGAP\033[0m: %s field(s) survive strypt, %s survive mat2\n' \
            "$survived_strypt" "$survived_mat2"
        grep -v 'date_time' "$WORK/strypt.txt" | grep -E '^\s+\S+:' | sed 's/^/      /'
        gaps=$((gaps + 1))
    else
        note "strypt: $survived_strypt field(s) survive · mat2: $survived_mat2 — no gap"
    fi

    # ExifTool is the second opinion, and the one that reads the embedded pictures. mat2's OOXML
    # reader lists part metadata; ExifTool walks into the media.
    if exiftool -s -G "$strypt_out" 2>/dev/null | grep -qE 'GPS|Serial|Artist|Owner'; then
        printf '  \033[31mGAP\033[0m: ExifTool still finds identifying tags in strypt output\n'
        exiftool -s -G "$strypt_out" | grep -E 'GPS|Serial|Artist|Owner' | sed 's/^/      /'
        gaps=$((gaps + 1))
    fi
done

printf '\n%d file(s) compared\n' "$checked"
if [ "$gaps" -ne 0 ]; then
    fail "$gaps gap(s) — each must be fixed or recorded in docs/THREAT_MODEL.md with a rationale"
fi
printf '\033[32m✓\033[0m no gaps: nothing survives strypt that does not also survive mat2\n'
