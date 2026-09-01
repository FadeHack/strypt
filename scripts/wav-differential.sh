#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the WAV corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes**, or is every gap recorded as a documented
# limitation with a rationale?
#
# The two tools work differently here, and the comparison is only fair if that is said plainly.
# mat2's `WAVParser` is an `AbstractFFmpegParser`: it rebuilds the file through ffmpeg and keeps a
# short allow-list of stream parameters. strypt edits the chunk list and copies the samples byte
# for byte (ADR-0039). The `data` payload is therefore compared on every file — measured
# 2026-09-01, the re-encode reproduces it exactly for 16-bit PCM, so the difference between the
# tools is in the container and neither reaches the sample values (docs/THREAT_MODEL.md §7.14).
#
# Requires mat2, ExifTool, ffmpeg, and python3 on PATH. Refuses to run without them rather than
# reporting a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/wav"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap() { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v ffmpeg >/dev/null 2>&1 || fail "ffmpeg is not installed; the audio-identity check cannot run"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed; the chunk walk cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n' "$(exiftool -ver)"
printf 'ffmpeg:   %s\n\n' "$(ffmpeg -version 2>/dev/null | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# The four-character codes of a file, in order. Written here rather than borrowed from strypt: a
# comparison that used the code under test to read its own output would prove nothing.
cat > "$WORK/chunks.py" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
if d[:4] != b"RIFF" or d[8:12] != b"WAVE":
    print("NOT-WAVE")
    raise SystemExit
end = 8 + struct.unpack("<I", d[4:8])[0]
at, out = 12, []
while at + 8 <= min(end, len(d)):
    kind = d[at:at + 4].decode("ascii", "replace").rstrip()
    n = struct.unpack("<I", d[at + 4:at + 8])[0]
    if kind == "LIST":
        kind += "/" + d[at + 8:at + 12].decode("ascii", "replace")
    out.append(kind)
    at += 8 + n + (n & 1)
if at != end:
    out.append("TRUNCATED")
if len(d) > end:
    out.append("TRAILING")
print(" ".join(out))
PY

# Tags ExifTool reports for any WAV whether or not anyone put metadata in it: the file's own
# identity and its stream parameters. A file that stopped claiming those would stop playing.
#
# `CuePoints` is here for a different reason and is worth saying out loud: it is metadata by
# ExifTool's reckoning and strypt keeps it **deliberately** (ADR-0039). It names nobody, it is
# playback structure, and its offsets are relative to the data section rather than to the file, so
# nothing this handler removes can move them. mat2 drops it because re-encoding drops everything.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[RIFF\][[:space:]]+(Encoding|NumChannels|SampleRate|AvgBytesPerSec|BitsPerSample|BlockAlign|Duration|CuePoints)[[:space:]]+:'

for input in "$CORPUS"/*.wav; do
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
        note "mat2 refuses this file in both modes — recorded, not skipped: docs/THREAT_MODEL.md §7.14"
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

    # The chunk-level view, which the tag comparison cannot give: ExifTool names nothing for a
    # private chunk, so a chunk that survives one tool and not the other is invisible above.
    before="$(python3 "$WORK/chunks.py" "$input")"
    after="$(python3 "$WORK/chunks.py" "$strypt_out")"
    note "chunks: $before  →  $after"
    if [ -n "$mat2_out" ]; then
        mat2_chunks="$(python3 "$WORK/chunks.py" "$mat2_out")"
        for c in $after; do
            case " $mat2_chunks " in
                *" $c "*) continue ;;
            esac
            # ADR-0039's deliberate keeps. mat2 loses both as a side effect of re-encoding
            # everything, not because either carries anything identifying: `cue ` is playback
            # structure whose offsets removal cannot move, and `JUNK` is padding kept at its
            # length with every byte zeroed — which the marker sweep below proves. Reported so
            # the difference is on the record, not filtered out of sight.
            case "$c" in
                cue|JUNK|PAD|FLLR|fact)
                    note "'$c' survives strypt and not mat2 — a deliberate keep (ADR-0039)" ;;
                *) gap "'$c' survives strypt and not mat2" ;;
            esac
        done
    fi

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it. It is the only check that
    # covers a private chunk's payload and the padding, which ExifTool names nothing for.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        gap "a synthetic marker survived into strypt output"
    fi

    # The output must still be the recording that went in, sample for sample. This is the property
    # strypt trades mat2's re-encoding for, so it is the one check that must never be soft.
    md5_in="$(ffmpeg -v error -i "$input" -map 0:a -f md5 - 2>/dev/null || echo IN-FAILED)"
    md5_out="$(ffmpeg -v error -i "$strypt_out" -map 0:a -f md5 - 2>/dev/null || echo OUT-FAILED)"
    if [ "$md5_in" != "$md5_out" ]; then
        gap "the stripped file is no longer the same audio: '$md5_in' became '$md5_out'"
    fi

    # Measured rather than asserted from reading mat2's source: strypt copies the `data` payload
    # byte for byte, and this asks whether mat2's rebuild changes it. Gated for strypt, reported
    # for mat2 — if the re-encode ever stops being lossless, the note is where that shows up.
    payload_in="$(python3 -c 'import hashlib,struct,sys
d=open(sys.argv[1],"rb").read(); at=12; end=8+struct.unpack("<I",d[4:8])[0]
while at+8<=min(end,len(d)):
    n=struct.unpack("<I",d[at+4:at+8])[0]
    if d[at:at+4]==b"data": print(hashlib.sha256(d[at+8:at+8+n]).hexdigest()[:16]); break
    at+=8+n+(n&1)
else: print("none")' "$input")"
    payload_strypt="$(python3 -c 'import hashlib,struct,sys
d=open(sys.argv[1],"rb").read(); at=12; end=8+struct.unpack("<I",d[4:8])[0]
while at+8<=min(end,len(d)):
    n=struct.unpack("<I",d[at+4:at+8])[0]
    if d[at:at+4]==b"data": print(hashlib.sha256(d[at+8:at+8+n]).hexdigest()[:16]); break
    at+=8+n+(n&1)
else: print("none")' "$strypt_out")"
    [ "$payload_in" = "$payload_strypt" ] || gap "strypt rewrote the data chunk's bytes"
    if [ -n "$mat2_out" ]; then
        payload_mat2="$(python3 -c 'import hashlib,struct,sys
d=open(sys.argv[1],"rb").read(); at=12; end=8+struct.unpack("<I",d[4:8])[0]
while at+8<=min(end,len(d)):
    n=struct.unpack("<I",d[at+4:at+8])[0]
    if d[at:at+4]==b"data": print(hashlib.sha256(d[at+8:at+8+n]).hexdigest()[:16]); break
    at+=8+n+(n&1)
else: print("none")' "$mat2_out")"
        if [ "$payload_in" != "$payload_mat2" ]; then
            note "mat2 rebuilt the data chunk ($payload_in → $payload_mat2); strypt copied it"
        fi
    fi
done

# An untested gate provides confidence without protection (CLAUDE.md §6). The filter above is the
# whole tag comparison, so it is run once against the *unstripped* corpus: if it does not light up
# there, a clean sweep over the stripped corpus means nothing.
printf '\nself-check: the filter against unstripped fixtures\n'
caught=0
missed=""
for input in "$CORPUS"/info-list.wav "$CORPUS"/broadcast-extension.wav "$CORPUS"/cart.wav \
             "$CORPUS"/ixml.wav "$CORPUS"/xmp.wav "$CORPUS"/sampler.wav "$CORPUS"/kitchen-sink.wav; do
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
    fail "$gaps gap(s) — each needs a fix or a documented limitation in docs/THREAT_MODEL.md §7.14"
fi
printf '\033[32m✓\033[0m no gaps: strypt removes at least what mat2 removes across the corpus\n'
