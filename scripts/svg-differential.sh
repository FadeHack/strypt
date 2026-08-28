#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the SVG corpus.
#
# The question this answers is Phase 2 exit criterion 1's inherited half of the Phase 1 bar:
# **does strypt remove at least what mat2 removes for this format**, or is every gap recorded as a
# documented limitation with a rationale (docs/ROADMAP.md Phase 1 exit criterion 3)?
#
# SVG inverts the usual comparison: mat2 re-renders the document through Rsvg, so it removes
# strictly more — the accessibility text and the script strypt will not touch — while destroying
# ids, grouping, animation and the author's editable structure. Neither behaviour is a defect
# (ADR-0035, docs/THREAT_MODEL.md §7.11), so this script checks both directions: nothing survives
# strypt that does not survive mat2, and the drawing crossed strypt intact.
#
# Requires mat2 and ExifTool on PATH. Refuses to run without them rather than reporting a clean
# sweep it did not perform — the mistake the WebP differential made for two days
# (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/svg"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap()  { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

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

# Tags ExifTool reports for every SVG whether or not anyone put metadata in it.
#
# `Title` and `Desc` are the exception that is a decision rather than bookkeeping: strypt keeps
# the accessibility text and mat2 removes it (ADR-0035 §5). The check below asserts it really does
# survive, so the exclusion is paired with a positive claim rather than softening the sweep.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[SVG\][[:space:]]+(Xmlns|ImageWidth|ImageHeight|ViewBox|Title|Desc|Warning)[[:space:]]+:'

for input in "$CORPUS"/*.svg; do
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
        note "mat2 refuses this file — recorded, not skipped: see docs/THREAT_MODEL.md §7.11"
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
    # removed it. It is the only check that covers the unknown vendor namespace and the stylesheet
    # comment, neither of which ExifTool reports at all.
    #
    # A marker spelled -KEPT- is one strypt deliberately does not remove: the accessibility text
    # of ADR-0035 §5 and the external reference of §3, each declared in the report.
    if grep -ao 'SYNTHETIC-[A-Z0-9-]*' "$strypt_out" | grep -v -- '-KEPT-' | grep -q .; then
        gap "a synthetic marker survived into strypt output"
        grep -ao 'SYNTHETIC-[A-Z0-9-]*' "$strypt_out" | grep -v -- '-KEPT-' | sed 's/^/      /'
    fi

    # The half of the comparison that runs the other way: mat2's output does not contain this
    # shape at all, because Rsvg re-drew it as a filtered compositing group.
    shape="$(grep -ao '<rect id="PRESERVED-SHAPE"[^>]*/>' "$input" || true)"
    if [ -z "$shape" ]; then
        gap "the fixture has no PRESERVED-SHAPE marker — regenerate corpus/svg"
    elif ! grep -aqF "$shape" "$strypt_out"; then
        gap "the drawing did not cross the strip intact"
    fi

    # The positive half of the Title/Desc exclusion above.
    if [ "$name" = "accessibility-text.svg" ]; then
        if ! grep -aq 'SYNTHETIC-TITLE-KEPT-0013' "$strypt_out" \
            || ! grep -aq 'SYNTHETIC-DESC-KEPT-0014' "$strypt_out"; then
            gap "the accessibility text did not survive — a screen reader now has nothing to announce"
        else
            note "the accessibility text survives, as intended; mat2 removes it"
        fi
    fi

    # A clean SVG must come back byte-identical. Only GIF makes the same promise of a whole file,
    # and both can only make it because they are edited by deletion rather than rebuilt.
    if [ "$name" = "clean.svg" ] && ! cmp -s "$input" "$strypt_out"; then
        gap "a clean file was not returned byte-identical"
    fi
done

# The documented capability gap, asserted rather than described: mat2 accepts a scripted SVG and
# strypt refuses it, so mat2 is the better recommendation for that file (ADR-0035 §2, ADR-0012).
# This fails if strypt ever stops refusing.
printf '\nrefusals strypt makes and mat2 does not:\n'
for name in script-element event-handler foreign-object javascript-href; do
    input="$CORPUS/malformed/$name.svg"
    [ -e "$input" ] || continue
    rm -rf "$WORK/s" && mkdir -p "$WORK/s"
    if "$STRYPT" strip --output-dir "$WORK/s" "$input" >/dev/null 2>&1; then
        gap "$name.svg was processed rather than refused"
    else
        note "$name.svg — refused, as ADR-0035 §2 requires"
    fi
done

printf '\n%d file(s) compared\n' "$checked"
if [ "$gaps" -ne 0 ]; then
    fail "$gaps gap(s) — each must be fixed or recorded in docs/THREAT_MODEL.md with a rationale"
fi
printf '\033[32m✓\033[0m no gaps: nothing survives strypt that does not also survive mat2, and the drawing is intact\n'
