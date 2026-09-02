#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the MP3 corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes**, or is every gap recorded as a documented
# limitation with a rationale?
#
# Both tools edit rather than re-encode here, so the comparison is closer than WAV's was. mat2's
# `MP3Parser` deletes the ID3 tag through mutagen; strypt deletes every tag at both ends
# (ADR-0040). The frames are compared on every file, and neither tool touches them.
#
# Requires mat2, ExifTool, ffmpeg, and python3 on PATH. Refuses to run without them rather than
# reporting a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/mp3"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap() { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v ffmpeg >/dev/null 2>&1 || fail "ffmpeg is not installed; the audio-identity check cannot run"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed; the tag walk cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n' "$(exiftool -ver)"
printf 'ffmpeg:   %s\n\n' "$(ffmpeg -version 2>/dev/null | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# The tags at each end of a file, the padding between them and the audio, and a hash of the frames
# themselves. Written here rather than borrowed from strypt: a comparison that used the code under
# test to read its own output would prove nothing.
cat > "$WORK/walk.py" <<'PY'
import hashlib, struct, sys

d = open(sys.argv[1], "rb").read()
out, at = [], 0
while d[at:at + 3] == b"ID3":
    major, flags = d[at + 3], d[at + 5]
    size = 0
    for b in d[at + 6:at + 10]:
        size = size * 128 + (b & 0x7F)
    total = 10 + size + (10 if flags & 0x10 and major == 4 else 0)
    out.append(f"ID3v2.{major}")
    at += total
    if total <= 10 or at > len(d):
        out.append("BAD-HEAD")
        break

end, tail = len(d), []
while True:
    if end - at >= 128 and d[end - 128:end - 125] == b"TAG":
        cut = end - 128
        if cut - at >= 227 and d[cut - 227:cut - 223] == b"TAG+":
            cut -= 227
            tail.append("ID3v1+TAG+")
        else:
            tail.append("ID3v1")
        end = cut
        continue
    if end - at >= 32 and d[end - 32:end - 24] == b"APETAGEX":
        size = struct.unpack("<I", d[end - 20:end - 16])[0]
        flags = struct.unpack("<I", d[end - 12:end - 8])[0]
        tail.append("APE")
        end -= size + (32 if flags & 0x8000_0000 else 0)
        continue
    if end - at >= 26 and d[end - 9:end] == b"LYRICS200":
        tail.append("Lyrics3v2")
        end -= int(d[end - 15:end - 9]) + 15
        continue
    if end - at > 9 and d[end - 9:end] == b"LYRICSEND":
        window_at = max(at, end - 5100)
        cut = d[window_at:end].rfind(b"LYRICSBEGIN")
        if cut < 0:
            break
        tail.append("Lyrics3v1")
        end = window_at + cut
        continue
    break

padding = 0
while at + padding < end and d[at + padding] == 0:
    padding += 1
at += padding
if padding:
    out.append(f"{padding} padding byte(s)")

frames, scan = 0, at
while scan + 4 <= end and d[scan] == 0xFF and d[scan + 1] & 0xE0 == 0xE0:
    frames += 1
    scan += 417
out += [f"{frames} frame(s)"] + tail[::-1]
print(" ".join(out) if out else "NOTHING")
print(hashlib.sha256(d[at:end]).hexdigest()[:16] if end > at else "none")
PY

# Tags ExifTool reports for any MP3 whether or not anyone put metadata in it: the file's own
# identity and the stream parameters read straight out of the frame header. A file that stopped
# claiming those would stop playing.
#
# `VBRFrames` and `VBRBytes` are deliberately NOT filtered. They come from the Xing header frame,
# which strypt keeps and declares (ADR-0040), and a keep that the differential hides is a keep
# nobody can audit. They are reported by name below instead.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[MPEG\][[:space:]]+(MPEGAudioVersion|AudioLayer|AudioBitrate|SampleRate|ChannelMode|MSStereo|IntensityStereo|CopyrightFlag|OriginalMedia|Emphasis)[[:space:]]+:'

for input in "$CORPUS"/*.mp3; do
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
        note "mat2 refuses this file in both modes — recorded, not skipped: docs/THREAT_MODEL.md §7.15"
        mat2_out=""; mat2_mode="refused"
    fi

    # `-u` is load-bearing: without it ExifTool omits tags it does not recognise, which is exactly
    # the class a scrubber is most likely to miss.
    exiftool -s -G -u -a "$strypt_out" 2>/dev/null | grep -vE "$STRUCTURAL" > "$WORK/strypt.txt" || true
    survived_strypt=$(grep -c . "$WORK/strypt.txt" || true)

    if [ -n "$mat2_out" ]; then
        exiftool -s -G -u -a "$mat2_out" 2>/dev/null | grep -vE "$STRUCTURAL" > "$WORK/mat2.txt" || true
        survived_mat2=$(grep -c . "$WORK/mat2.txt" || true)
    else
        survived_mat2="n/a"
    fi

    if [ "$survived_mat2" != "n/a" ] && [ "$survived_strypt" -gt "$survived_mat2" ]; then
        # The VBR header is the one thing strypt keeps on purpose. Anything else outranking mat2
        # is a gap.
        if grep -qvE '^\[MPEG\][[:space:]]+VBR' "$WORK/strypt.txt"; then
            gap "$survived_strypt tag(s) survive strypt, $survived_mat2 survive mat2"
            sed 's/^/      /' "$WORK/strypt.txt"
        else
            note "only the Xing/VBRI header survives strypt and not mat2 — a deliberate keep (ADR-0040)"
        fi
    else
        note "strypt: $survived_strypt tag(s) survive · mat2 ($mat2_mode): $survived_mat2"
    fi

    # The structural view, which the tag comparison cannot give: ExifTool names nothing at all for
    # an APE item or a Lyrics3 field, so a whole tag can survive and be invisible above.
    before="$(python3 "$WORK/walk.py" "$input" | head -1)"
    after="$(python3 "$WORK/walk.py" "$strypt_out" | head -1)"
    note "tags: $before  →  $after"
    case "$after" in
        *ID3*|*APE*|*Lyrics*|*padding*)
            gap "a tag survives in strypt's output: $after" ;;
    esac
    if [ -n "$mat2_out" ]; then
        mat2_tags="$(python3 "$WORK/walk.py" "$mat2_out" | head -1)"
        note "mat2: $mat2_tags"
    fi

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        gap "a synthetic marker survived into strypt output"
    fi

    # The output must still be the recording that went in, sample for sample. This is the property
    # both tools trade a rebuild for, so it is the one check that must never be soft.
    md5_in="$(ffmpeg -v error -i "$input" -map 0:a -f md5 - 2>/dev/null || echo IN-FAILED)"
    md5_out="$(ffmpeg -v error -i "$strypt_out" -map 0:a -f md5 - 2>/dev/null || echo OUT-FAILED)"
    if [ "$md5_in" != "$md5_out" ]; then
        gap "the stripped file is no longer the same audio: '$md5_in' became '$md5_out'"
    fi

    # Stronger than the decode above, and the reason this format is cheap: the frames are supposed
    # to arrive byte for byte, not merely to decode alike.
    frames_in="$(python3 "$WORK/walk.py" "$input" | tail -1)"
    frames_out="$(python3 "$WORK/walk.py" "$strypt_out" | tail -1)"
    [ "$frames_in" = "$frames_out" ] || gap "strypt rewrote the frames ($frames_in → $frames_out)"
done

# An untested gate provides confidence without protection (CLAUDE.md §6). Two things are checked,
# because two things are being trusted.
printf '\nself-check: the filter against unstripped fixtures\n'
missed=""
caught=0
for input in "$CORPUS"/id3v2-4.mp3 "$CORPUS"/id3v2-3.mp3 "$CORPUS"/id3v2-2.mp3 \
             "$CORPUS"/id3v1.mp3 "$CORPUS"/ape.mp3 "$CORPUS"/cover-art.mp3 \
             "$CORPUS"/kitchen-sink.mp3; do
    n="$(exiftool -s -G -u -a "$input" 2>/dev/null | grep -vcE "$STRUCTURAL" || true)"
    if [ "$n" -gt 0 ]; then
        caught=$((caught + 1))
    else
        missed="$missed $(basename "$input")"
    fi
done
[ -n "$missed" ] && fail "the filter sees nothing in:$missed — it would report a clean sweep over anything"
printf '  the filter reports metadata in all %s unstripped fixtures\n' "$caught"

# The tag walk is the check that catches what ExifTool names nothing for, so it too has to be
# proven able to fail. A file that was never stripped must light it up.
printf '\nself-check: the tag walk against a pass-through stand-in\n'
standin="$WORK/passthrough.mp3"
cp "$CORPUS/kitchen-sink.mp3" "$standin"
walked="$(python3 "$WORK/walk.py" "$standin" | head -1)"
case "$walked" in
    *ID3*|*APE*|*Lyrics*) printf '  the walk reports: %s\n' "$walked" ;;
    *) fail "the tag walk reports '$walked' for an unstripped file — it would pass anything" ;;
esac
if ! grep -aq 'SYNTHETIC' "$standin"; then
    fail "the marker sweep sees nothing in an unstripped file — it would pass anything"
fi
printf '  the marker sweep finds SYNTHETIC markers in the same file\n'

printf '\n%s fixture(s) compared\n' "$checked"
if [ "$gaps" -gt 0 ]; then
    fail "$gaps gap(s) — each needs a fix or a documented limitation in docs/THREAT_MODEL.md §7.15"
fi
printf '\033[32m✓\033[0m no gaps: strypt removes at least what mat2 removes across the corpus\n'
