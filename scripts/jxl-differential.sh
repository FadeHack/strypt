#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the JPEG XL corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes**, or is every gap recorded as a documented
# limitation with a rationale?
#
# Unlike the raster comparisons, both tools are doing the same *kind* of work here. mat2's
# `JXLParser` is an `ExiftoolParser` running `_lightweight_cleanup()` — it shells out to ExifTool
# and edits the container rather than re-rendering (verified against libmat2/images.py,
# 2026-08-29), which is what strypt does too (ADR-0036). So the box-level comparison below is a
# fair one in both directions, and the reverse direction is the interesting one: measured on
# 2026-08-29, ExifTool leaves `jumb`, `jbrd`, `jxli`, `free` and `skip` where strypt removes them.
#
# **No JPEG XL decoder is used, or needed.** strypt never enters the codestream, ExifTool does not
# either, and the fixtures' codestream is a header stub rather than a picture
# (corpus/tools/make_jxl_fixtures.py). The "still an image" check is therefore structural: the
# output must still identify as JXL and report the dimensions it went in with.
#
# Requires mat2, ExifTool, and python3 on PATH. Refuses to run without them rather than reporting
# a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/jxl"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap() { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed; the box walk cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n\n' "$(exiftool -ver)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# The top-level box types of a file, in order. Written here rather than borrowed from strypt: a
# comparison that used the code under test to read its own output would prove nothing.
cat > "$WORK/boxes.py" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
if d[:2] == b"\xff\x0a":
    print("codestream")
    raise SystemExit
at, out = 0, []
while at + 8 <= len(d):
    n = struct.unpack(">I", d[at:at + 4])[0]
    kind = d[at + 4:at + 8].decode("latin1")
    size = len(d) - at if n == 0 else (struct.unpack(">Q", d[at + 8:at + 16])[0] if n == 1 else n)
    if size < 8 or at + size > len(d):
        out.append("TRUNCATED")
        break
    out.append(kind)
    at += size
if at != len(d):
    out.append("TRAILING")
print(" ".join(out))
PY

# Tags ExifTool reports for any JPEG XL whether or not anyone put metadata in it: the file's own
# identity, its dimensions, and the brands that declare which decoder it needs. A file that stopped
# claiming those would stop opening, and strypt copies them deliberately.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[Jpeg2000\][[:space:]]+(MajorBrand|MinorVersion|CompatibleBrands)[[:space:]]+:'

for input in "$CORPUS"/*.jxl; do
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
        mat2_out="$WORK/m/$name"; mat2_mode="default"
    elif (cd "$WORK/m" && mat2 -L --inplace "$name" >/dev/null 2>&1); then
        mat2_out="$WORK/m/$name"; mat2_mode="lightweight"
    else
        note "mat2 refuses this file in both modes — recorded, not skipped: docs/THREAT_MODEL.md §7.12"
        mat2_out=""; mat2_mode="refused"
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
        gap "$survived_strypt tag(s) survive strypt, $survived_mat2 survive mat2"
        sed 's/^/      /' "$WORK/strypt.txt"
    else
        note "strypt: $survived_strypt tag(s) survive · mat2 ($mat2_mode): $survived_mat2"
    fi

    # The box-level view, which the tag comparison cannot give: ExifTool reports nothing at all for
    # a `free`, a `skip`, or a `jbrd`, so a box that survives one tool and not the other is
    # invisible above. This is where the reverse direction shows up.
    before="$(python3 "$WORK/boxes.py" "$input")"
    after="$(python3 "$WORK/boxes.py" "$strypt_out")"
    note "boxes: $before  →  $after"
    if [ -n "$mat2_out" ]; then
        mat2_boxes="$(python3 "$WORK/boxes.py" "$mat2_out")"
        for box in $mat2_boxes; do
            case " $after " in
                *" $box "*) ;;
                *) note "strypt removed '$box', mat2 kept it" ;;
            esac
        done
        for box in $after; do
            case " $mat2_boxes " in
                *" $box "*) ;;
                *) gap "'$box' survives strypt and not mat2" ;;
            esac
        done
    fi

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it. It is the only check that
    # covers the `brob` payload and the padding boxes, which ExifTool names nothing for.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        gap "a synthetic marker survived into strypt output"
    fi

    # The output must still be the image that went in. No decoder is involved (see the header), so
    # this asks ExifTool for the file's identity and its dimensions, which it reads from the
    # codestream rather than from any box strypt touched.
    identity_in="$(exiftool -s3 -FileType -ImageWidth -ImageHeight "$input" 2>/dev/null | tr '\n' ' ')"
    identity_out="$(exiftool -s3 -FileType -ImageWidth -ImageHeight "$strypt_out" 2>/dev/null | tr '\n' ' ')"
    if [ "$identity_in" != "$identity_out" ]; then
        gap "the stripped file is no longer the same image: '$identity_in' became '$identity_out'"
    fi
done

# An untested gate provides confidence without protection (CLAUDE.md §6). The filter above is the
# whole tag comparison, so it is run once against the *unstripped* corpus: if it does not light up
# there, a clean sweep over the stripped corpus means nothing.
#
# Only the fixtures ExifTool can actually see metadata in are listed. It reports nothing for a
# `jbrd`, a `free`, a `skip`, or a `jxli`, and that is itself recorded in docs/THREAT_MODEL.md
# §7.12 — those are covered by the box walk and the marker sweep above instead.
printf '\nself-check: the filter against unstripped fixtures\n'
caught=0
missed=""
for input in "$CORPUS"/exif.jxl "$CORPUS"/xmp.jxl "$CORPUS"/jumbf.jxl "$CORPUS"/kitchen-sink.jxl; do
    n="$(exiftool -s -G -u -a "$input" 2>/dev/null | grep -vcE "$STRUCTURAL" || true)"
    if [ "$n" -gt 0 ]; then
        caught=$((caught + 1))
    else
        missed="$missed $(basename "$input")"
    fi
done
if [ -n "$missed" ]; then
    fail "the filter sees nothing in:$missed — it would report a clean sweep over anything"
fi
printf '  the filter reports metadata in all %s unstripped fixtures\n' "$caught"

printf '\n%s fixture(s) compared\n' "$checked"
if [ "$gaps" -gt 0 ]; then
    fail "$gaps gap(s) — each needs a fix or a documented limitation in docs/THREAT_MODEL.md §7.12"
fi
printf '\033[32m✓\033[0m no gaps: strypt removes at least what mat2 removes across the corpus\n'
