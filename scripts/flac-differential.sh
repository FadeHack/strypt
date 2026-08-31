#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the FLAC corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes**, or is every gap recorded as a documented
# limitation with a rationale?
#
# Both tools edit the block list rather than re-encoding, so the comparison is fair in both
# directions. mat2's `FLACParser` uses mutagen, which knows the Vorbis comment and the picture
# block and nothing else; the reverse direction is therefore the interesting one, and the block
# walk below is where it shows up (measured 2026-09-01: mat2 keeps APPLICATION, CUESHEET, and
# reserved block types where strypt removes them).
#
# **No FLAC decoder is used, or needed** — but the fixtures are real decodable audio, so the
# "still the same recording" check below is a real one: ffmpeg re-reads the output and its MD5 of
# the decoded samples must match the input's.
#
# Requires mat2, ExifTool, ffmpeg, and python3 on PATH. Refuses to run without them rather than
# reporting a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/flac"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap() { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v ffmpeg >/dev/null 2>&1 || fail "ffmpeg is not installed; the audio-identity check cannot run"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed; the block walk cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n' "$(exiftool -ver)"
printf 'ffmpeg:   %s\n\n' "$(ffmpeg -version 2>/dev/null | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# The metadata block types of a file, in order, by their RFC 9639 §8.2 names. Written here rather
# than borrowed from strypt: a comparison that used the code under test to read its own output
# would prove nothing.
cat > "$WORK/blocks.py" <<'PY'
import struct, sys
NAMES = {0: "STREAMINFO", 1: "PADDING", 2: "APPLICATION", 3: "SEEKTABLE",
         4: "VORBIS_COMMENT", 5: "CUESHEET", 6: "PICTURE", 127: "FORBIDDEN"}
d = open(sys.argv[1], "rb").read()
if d[:4] != b"fLaC":
    print("NOT-FLAC")
    raise SystemExit
at, out = 4, []
while at + 4 <= len(d):
    head = d[at]
    n = struct.unpack(">I", b"\x00" + d[at + 1:at + 4])[0]
    out.append(NAMES.get(head & 0x7F, f"RESERVED-{head & 0x7F}"))
    at += 4 + n
    if at > len(d):
        out.append("TRUNCATED")
        break
    if head & 0x80:
        break
else:
    out.append("TRUNCATED")
print(" ".join(out))
PY

# Tags ExifTool reports for any FLAC whether or not anyone put metadata in it: the file's own
# identity, its stream parameters, and the durations composed from them. A file that stopped
# claiming those would stop playing, and strypt copies them deliberately.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[FLAC\][[:space:]]+(BlockSizeMin|BlockSizeMax|FrameSizeMin|FrameSizeMax|SampleRate|Channels|BitsPerSample|TotalSamples|MD5Signature)[[:space:]]+:'

for input in "$CORPUS"/*.flac; do
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
        note "mat2 refuses this file in both modes — recorded, not skipped: docs/THREAT_MODEL.md §7.13"
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

    # The block-level view, which the tag comparison cannot give: ExifTool names nothing for an
    # APPLICATION block or a reserved type, so a block that survives one tool and not the other is
    # invisible above. This is where the reverse direction shows up.
    before="$(python3 "$WORK/blocks.py" "$input")"
    after="$(python3 "$WORK/blocks.py" "$strypt_out")"
    note "blocks: $before  →  $after"
    if [ -n "$mat2_out" ]; then
        mat2_blocks="$(python3 "$WORK/blocks.py" "$mat2_out")"
        for b in $mat2_blocks; do
            case " $after " in
                *" $b "*) ;;
                *) note "strypt removed '$b', mat2 kept it" ;;
            esac
        done
        for b in $after; do
            case " $mat2_blocks " in
                *" $b "*) ;;
                *) gap "'$b' survives strypt and not mat2" ;;
            esac
        done
    fi

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it. It is the only check that
    # covers the APPLICATION payload and the padding, which ExifTool names nothing for.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        gap "a synthetic marker survived into strypt output"
    fi

    # The output must still be the recording that went in, sample for sample. Decoding both and
    # comparing MD5s is stronger than any structural check: it would catch a handler that had
    # corrupted a frame while leaving the file superficially well-formed.
    # `-map 0:a` is load-bearing: ffmpeg exposes cover art as a video stream, so without it the
    # hash covers the picture too and every fixture that loses one looks like corrupted audio.
    md5_in="$(ffmpeg -v error -i "$input" -map 0:a -f md5 - 2>/dev/null || echo IN-FAILED)"
    md5_out="$(ffmpeg -v error -i "$strypt_out" -map 0:a -f md5 - 2>/dev/null || echo OUT-FAILED)"
    if [ "$md5_in" != "$md5_out" ]; then
        gap "the stripped file is no longer the same audio: '$md5_in' became '$md5_out'"
    fi
done

# An untested gate provides confidence without protection (CLAUDE.md §6). The filter above is the
# whole tag comparison, so it is run once against the *unstripped* corpus: if it does not light up
# there, a clean sweep over the stripped corpus means nothing.
#
# Only the fixtures ExifTool can actually see metadata in are listed. It reports nothing for an
# APPLICATION block or a reserved type, and that is itself recorded in docs/THREAT_MODEL.md §7.13
# — those are covered by the block walk and the marker sweep above instead.
printf '\nself-check: the filter against unstripped fixtures\n'
caught=0
missed=""
for input in "$CORPUS"/vorbis-comment.flac "$CORPUS"/cover-art.flac "$CORPUS"/cuesheet.flac "$CORPUS"/kitchen-sink.flac; do
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
    fail "$gaps gap(s) — each needs a fix or a documented limitation in docs/THREAT_MODEL.md §7.13"
fi
printf '\033[32m✓\033[0m no gaps: strypt removes at least what mat2 removes across the corpus\n'
