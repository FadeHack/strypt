#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the Ogg corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes**, or is every gap recorded as a documented
# limitation with a rationale?
#
# Both tools rebuild the stream — mat2 through mutagen, strypt page by page (ADR-0041) — so the
# comparison is about what reaches the output, not about editing style. Two differences are
# measured here rather than asserted from reading source: mat2 keeps the vendor string and the
# stream serial number, and strypt clears both.
#
# Requires mat2, ExifTool, ffmpeg, and python3 on PATH. Refuses to run without them rather than
# reporting a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/ogg"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap() { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v ffmpeg >/dev/null 2>&1 || fail "ffmpeg is not installed; the audio-identity check cannot run"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed; the page walk cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n' "$(exiftool -ver)"
printf 'ffmpeg:   %s\n\n' "$(ffmpeg -version 2>/dev/null | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# The page structure of a file: serial numbers, page count, sequence numbers, granule positions.
# Written here rather than borrowed from strypt: a comparison that used the code under test to read
# its own output would prove nothing. The CRC is deliberately not checked — ffmpeg below is the
# independent judge of whether the bytes are still a playable stream.
cat > "$WORK/pages.py" <<'PY'
import struct, sys
d = open(sys.argv[1], "rb").read()
at, serials, seq, gran = 0, [], [], []
while at + 27 <= len(d) and d[at:at + 4] == b"OggS":
    granule, serial, page = struct.unpack("<QII", d[at + 6:at + 22])
    n = d[at + 26]
    if at + 27 + n > len(d):
        break
    if serial not in serials:
        serials.append(serial)
    seq.append(page)
    gran.append("-1" if granule == 0xFFFFFFFFFFFFFFFF else str(granule))
    at += 27 + n + sum(d[at + 27:at + 27 + n])
tail = "" if at == len(d) else " +%d-trailing-bytes" % (len(d) - at)
print("serials=%s pages=%d seq=%s granules=%s%s" % (
    ",".join("0x%x" % s for s in serials), len(seq),
    "0.." + str(seq[-1]) if seq == list(range(len(seq))) else ",".join(map(str, seq)),
    ",".join(gran), tail))
PY

# Tags ExifTool reports for any Ogg whether or not anyone put metadata in it: the file's own
# identity and its stream parameters. A file that stopped claiming those would stop playing.
#
# `MD5Signature` is here for a different reason and is worth saying out loud: it is the Ogg-FLAC
# `STREAMINFO` audio checksum, and strypt keeps it **deliberately** (ADR-0038 decision 4, carried
# into ADR-0041). It is derived from the samples the file already carries, so its holder can
# recompute it; strypt declares the retention rather than removing it silently.
STRUCTURAL='^\[(ExifTool|Composite)\]|^\[File\]|^\[(Vorbis|Opus|FLAC)\][[:space:]]+(VorbisVersion|OpusVersion|AudioChannels|Channels|SampleRate|OutputGain|NominalBitrate|MaxBitrate|MinBitrate|BlockSizeMin|BlockSizeMax|FrameSizeMin|FrameSizeMax|BitsPerSample|TotalSamples|MD5Signature|Duration)[[:space:]]+:'

# strypt empties the comment header rather than deleting it (ADR-0041 decision 8), so ExifTool
# prints `Vendor` with nothing after the colon. An empty tag carries no metadata by definition, and
# the self-check below proves this line does not swallow a populated one.
tags() { exiftool -s -G -u -a "$1" 2>/dev/null | grep -vE "$STRUCTURAL" | grep -vE ':[[:space:]]*$' || true; }

for input in "$CORPUS"/*.ogg "$CORPUS"/*.opus "$CORPUS"/*.oga; do
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
        note "mat2 refuses this file in both modes — recorded, not skipped: docs/THREAT_MODEL.md §7.16"
        mat2_out=""; mat2_mode="refused"
    fi

    # `-u` is load-bearing: without it ExifTool omits tags it does not recognise, which is exactly
    # the class an allow-list exists to catch.
    tags "$strypt_out" > "$WORK/strypt.txt"
    survived_strypt=$(grep -c . "$WORK/strypt.txt" || true)

    if [ -n "$mat2_out" ]; then
        tags "$mat2_out" > "$WORK/mat2.txt"
        survived_mat2=$(grep -c . "$WORK/mat2.txt" || true)
    else
        survived_mat2="n/a"
    fi

    if [ "$survived_mat2" != "n/a" ] && [ "$survived_strypt" -gt "$survived_mat2" ]; then
        gap "$survived_strypt tag(s) survive strypt, $survived_mat2 survive mat2"
        sed 's/^/      /' "$WORK/strypt.txt"
    else
        note "strypt: $survived_strypt tag(s) survive · mat2 ($mat2_mode): $survived_mat2"
        [ "$survived_mat2" = "n/a" ] || [ "$survived_mat2" -eq 0 ] || sed 's/^/      mat2 keeps: /' "$WORK/mat2.txt"
    fi

    # The page-level view, which the tag comparison cannot give: ExifTool names nothing for a
    # serial number, and the serial is itself an identifier (ADR-0041 decision 5).
    note "pages: $(python3 "$WORK/pages.py" "$input")"
    note "    →  $(python3 "$WORK/pages.py" "$strypt_out")"
    case "$(python3 "$WORK/pages.py" "$strypt_out")" in
        serials=0x0\ *) ;;
        *) gap "the stream serial number survived into strypt output" ;;
    esac
    if [ -n "$mat2_out" ]; then
        note "    mat2:  $(python3 "$WORK/pages.py" "$mat2_out")"
    fi

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        gap "a synthetic marker survived into strypt output"
    fi
    if [ -n "$mat2_out" ] && grep -aq 'SYNTHETIC' "$mat2_out"; then
        note "a synthetic marker survives mat2 — the vendor string, which mat2 keeps and strypt clears"
    fi

    # The output must still be the recording that went in, sample for sample. This is what the
    # rebuild is for, so it is the one check that must never be soft.
    md5_in="$(ffmpeg -v error -i "$input" -map 0:a -f md5 - 2>/dev/null || echo IN-FAILED)"
    md5_out="$(ffmpeg -v error -i "$strypt_out" -map 0:a -f md5 - 2>/dev/null || echo OUT-FAILED)"
    if [ "$md5_in" != "$md5_out" ]; then
        gap "the stripped file is no longer the same audio: '$md5_in' became '$md5_out'"
    fi
done

# An untested gate provides confidence without protection (CLAUDE.md §6). Two self-checks, because
# there are two gates: the tag filter, and the page walk plus marker sweep.
printf '\nself-check 1: the tag filter against unstripped fixtures\n'
caught=0
missed=""
for input in "$CORPUS"/vorbis.ogg "$CORPUS"/vorbis-cover-art.ogg "$CORPUS"/vorbis-many-comments.ogg \
             "$CORPUS"/opus.opus "$CORPUS"/opus-padding.opus "$CORPUS"/ogg-flac.oga \
             "$CORPUS"/ogg-flac-blocks.oga; do
    n="$(tags "$input" | grep -c . || true)"
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

printf '\nself-check 2: the page walk and marker sweep against a pass-through stand-in\n'
# A tool that copied its input and reported success is the failure mode this whole script exists to
# catch (docs/THREAT_MODEL.md §4). So the per-file checks above are run once against exactly that,
# and both must fire.
cp "$CORPUS/vorbis.ogg" "$WORK/passthrough.ogg"
serial_fired=no
case "$(python3 "$WORK/pages.py" "$WORK/passthrough.ogg")" in
    serials=0x0\ *) ;;
    *) serial_fired=yes ;;
esac
marker_fired=no
grep -aq 'SYNTHETIC' "$WORK/passthrough.ogg" && marker_fired=yes
[ "$serial_fired" = yes ] || fail "the page walk does not notice a surviving serial number — it proves nothing above"
[ "$marker_fired" = yes ] || fail "the marker sweep does not notice a surviving marker — it proves nothing above"
printf '  both the serial check and the marker sweep reject a pass-through\n'

printf '\n%s fixture(s) compared\n' "$checked"
if [ "$gaps" -gt 0 ]; then
    fail "$gaps gap(s) — each needs a fix or a documented limitation in docs/THREAT_MODEL.md §7.16"
fi
printf '\033[32m✓\033[0m no gaps: strypt removes at least what mat2 removes across the corpus\n'
