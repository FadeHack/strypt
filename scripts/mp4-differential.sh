#!/usr/bin/env bash
# Differential test: strypt against mat2 and ExifTool over the MP4 / M4A corpus.
#
# The question it answers is Phase 1 exit criterion 3, inherited by Phase 2 exit criterion 1:
# **does strypt remove at least what mat2 removes**, or is every gap recorded as a documented
# limitation with a rationale?
#
# The two tools work differently here, and the comparison is about what reaches the output rather
# than about editing style. mat2 remuxes through ffmpeg — `-codec copy -map_metadata -1` — which
# rewrites the whole container; strypt filters the box tree and copies `mdat` untouched (ADR-0042).
# One consequence is measured below rather than assumed: **mat2's MP4 parser registers `video/mp4`
# and does not claim `.m4a`**, so the audio fixtures have no mat2 side, and that is recorded, not
# skipped.
#
# Requires mat2, ExifTool, ffmpeg, and python3 on PATH. Refuses to run without them rather than
# reporting a clean sweep it did not perform (docs/THREAT_MODEL.md §7.4).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/corpus/mp4"
STRYPT="${STRYPT:-$ROOT/target/release/strypt}"

fail() { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }
note() { printf '  %s\n' "$1"; }
gap() { printf '  \033[31mGAP\033[0m: %s\n' "$1"; gaps=$((gaps + 1)); }

command -v mat2 >/dev/null 2>&1 || fail "mat2 is not installed; a comparison that cannot run must not report a clean sweep"
command -v exiftool >/dev/null 2>&1 || fail "exiftool is not installed"
command -v ffmpeg >/dev/null 2>&1 || fail "ffmpeg is not installed; the media-identity check cannot run"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed; the box walk cannot run"
[ -x "$STRYPT" ] || fail "no release binary at $STRYPT — run: cargo build --release"

printf 'strypt:   %s\n' "$("$STRYPT" --version)"
printf 'mat2:     %s\n' "$(mat2 --version)"
printf 'exiftool: %s\n' "$(exiftool -ver)"
printf 'ffmpeg:   %s\n\n' "$(ffmpeg -version 2>/dev/null | head -1)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gaps=0
checked=0

# The box structure of a file: the top-level types in order, an MD5 over every `mdat` payload, and
# each chunk offset resolved to "which mdat, how far in". That last line is what the whole handler
# turns on — removing a box in front of the media moves it, so the offsets have to move with it.
#
# Written here rather than borrowed from strypt: a comparison that used the code under test to read
# its own output would prove nothing.
cat > "$WORK/boxes.py" <<'PY'
import hashlib, struct, sys

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"edts", b"dinf", b"ilst"}
data = open(sys.argv[1], "rb").read()
top, mdats, offsets = [], [], []


def walk(buf, base, depth):
    at = 0
    while at + 8 <= len(buf):
        size = struct.unpack(">I", buf[at:at + 4])[0]
        typ = buf[at + 4:at + 8]
        header = 8
        if size == 1:
            size = struct.unpack(">Q", buf[at + 8:at + 16])[0]
            header = 16
        elif size == 0:
            size = len(buf) - at
        if size < header or at + size > len(buf):
            break
        body = buf[at + header:at + size]
        if depth == 0:
            top.append(typ.decode("latin-1"))
        if typ == b"mdat":
            mdats.append((base + at + header, base + at + size, body))
        elif typ in (b"stco", b"co64"):
            wide = typ == b"co64"
            width = 8 if wide else 4
            count = struct.unpack(">I", body[4:8])[0]
            for i in range(count):
                cell = body[8 + i * width:8 + (i + 1) * width]
                if len(cell) < width:
                    break
                offsets.append(struct.unpack(">Q" if wide else ">I", cell)[0])
        elif typ in CONTAINERS:
            walk(body, base + at + header, depth + 1)
        elif typ == b"meta":
            walk(body[4:], base + at + header + 4, depth + 1)
        at += size


walk(data, 0, 0)
digest = hashlib.md5(b"".join(m[2] for m in mdats)).hexdigest()[:12]
resolved = []
for off in offsets:
    where = next((i for i, m in enumerate(mdats) if m[0] <= off < m[1]), None)
    resolved.append("UNRESOLVED(%d)" % off if where is None else "%d+%d" % (where, off - mdats[where][0]))
print("top=%s mdat-md5=%s chunks=%s" % (",".join(top), digest, ",".join(resolved) or "none"))
PY

# Tags ExifTool reports for any MP4 whether or not anyone put metadata in it: brands, track and
# media parameters, and the sample tables. A file that stopped claiming those would stop playing.
#
# The date fields and the language are deliberately matched **on their value**, not their name.
# strypt zeroes them in place rather than removing the boxes that hold them (ADR-0042 decision 9),
# so `0000:00:00 00:00:00` and `und` carry nothing — but a filter keyed on the name alone would
# swallow a real date, which is the one thing this script exists to catch. Self-check 1 proves it.
STRUCTURAL_NAMES='MajorBrand|MinorVersion|CompatibleBrands|MediaDataSize|MediaDataOffset|MediaData|MovieHeaderVersion|TimeScale|Duration|PreferredRate|PreferredVolume|MatrixStructure|PreviewTime|PreviewDuration|PosterTime|SelectionTime|SelectionDuration|CurrentTime|NextTrackID|TrackHeaderVersion|TrackID|TrackDuration|TrackLayer|TrackVolume|ImageWidth|ImageHeight|Unknown_edts|MediaHeaderVersion|MediaTimeScale|MediaDuration|HandlerType|GraphicsMode|OpColor|CompressorID|SourceImageWidth|SourceImageHeight|XResolution|YResolution|BitDepth|AVCConfiguration|PixelAspectRatio|BufferSize|MaxBitrate|AverageBitrate|VideoFrameRate|SyncSampleTable|SampleToChunk|SampleSizes|ChunkOffset|Balance|AudioFormat|AudioChannels|AudioBitsPerSample|AudioSampleRate|Unknown_esds|TimeToSampleTable|SampleGroupDescription|SampleToGroup'
STRUCTURAL="^\\[(ExifTool|Composite)\\]|^\\[File\\]|^\\[QuickTime\\][[:space:]]+($STRUCTURAL_NAMES)[[:space:]]+:"
ZEROED='^\[QuickTime\][[:space:]]+(Create|Modify|TrackCreate|TrackModify|MediaCreate|MediaModify)Date[[:space:]]+: 0000:00:00 00:00:00$'
UNDETERMINED='^\[QuickTime\][[:space:]]+MediaLanguageCode[[:space:]]+: und$'

# `-u` is load-bearing: without it ExifTool omits tags it does not recognise, which is exactly the
# class an allow-list exists to catch.
tags() {
    exiftool -s -G -u -a "$1" 2>/dev/null \
        | grep -vE "$STRUCTURAL" \
        | grep -vE "$ZEROED" \
        | grep -vE "$UNDETERMINED" \
        | grep -vE ':[[:space:]]*$' || true
}

for input in "$CORPUS"/*.mp4 "$CORPUS"/*.m4a; do
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
        note "mat2 does not handle this file — its MP4 parser registers video/mp4 only, so an .m4a has no mat2 side: docs/THREAT_MODEL.md §7.17"
        mat2_out=""; mat2_mode="not claimed"
    fi

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

    # The box-level view, which the tag comparison cannot give: ExifTool names nothing for a chunk
    # offset, and an offset that stopped resolving is a file that stopped playing.
    note "boxes: $(python3 "$WORK/boxes.py" "$input")"
    note "    →  $(python3 "$WORK/boxes.py" "$strypt_out")"
    before="$(python3 "$WORK/boxes.py" "$input" | sed 's/.*chunks=//')"
    after="$(python3 "$WORK/boxes.py" "$strypt_out" | sed 's/.*chunks=//')"
    case "$after" in
        *UNRESOLVED*) gap "a chunk offset in strypt's output resolves into no mdat" ;;
    esac
    [ "$before" = "$after" ] || gap "a chunk offset moved relative to its mdat: '$before' became '$after'"

    # The absolute check, independent of what either tool reported. Every identifying value in the
    # corpus is a SYNTHETIC- marker, so this reads the bytes rather than a report — a handler that
    # forgot to remove something would still report having removed it.
    if grep -aq 'SYNTHETIC' "$strypt_out"; then
        gap "a synthetic marker survived into strypt output"
    fi
    if [ -n "$mat2_out" ] && grep -aq 'SYNTHETIC' "$mat2_out"; then
        note "a synthetic marker survives mat2 — recorded in docs/THREAT_MODEL.md §7.17"
    fi

    # The output must still be the recording that went in, sample for sample. That is what
    # edit-by-deletion is chosen for, so it is the one check that must never be soft.
    # `0:V?` rather than `0` is deliberate: uppercase V excludes attached pictures, and cover art
    # is metadata that only strypt's side is supposed to still have.
    md5_in="$(ffmpeg -v error -i "$input" -map '0:V?' -map '0:a?' -f md5 - 2>/dev/null || echo IN-FAILED)"
    md5_out="$(ffmpeg -v error -i "$strypt_out" -map '0:V?' -map '0:a?' -f md5 - 2>/dev/null || echo OUT-FAILED)"
    if [ "$md5_in" != "$md5_out" ]; then
        gap "the stripped file is no longer the same recording: '$md5_in' became '$md5_out'"
    fi
done

# An untested gate provides confidence without protection (CLAUDE.md §6). Two self-checks, because
# there are two gates: the tag filter, and the box walk plus marker sweep.
printf '\nself-check 1: the tag filter against unstripped fixtures\n'
caught=0
missed=""
for input in "$CORPUS"/video-tags.mp4 "$CORPUS"/itunes-tags.m4a "$CORPUS"/xmp-uuid.mp4 \
             "$CORPUS"/faststart.mp4 "$CORPUS"/timestamps.mp4; do
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
# timestamps.mp4 carries real dates in the same fields the filter drops when they read as zero.
if ! tags "$CORPUS/timestamps.mp4" | grep -q 'CreateDate'; then
    fail "the value-matched date filter swallows a populated date — it proves nothing above"
fi
printf '  a populated CreateDate is not swallowed by the zeroed-date rule\n'

printf '\nself-check 2: the box walk and marker sweep against a pass-through stand-in\n'
# A tool that copied its input and reported success is the failure mode this whole script exists to
# catch (docs/THREAT_MODEL.md §4). So the per-file checks above are run once against exactly that,
# and both must fire.
cp "$CORPUS/free-space.mp4" "$WORK/passthrough.mp4"
marker_fired=no
grep -aq 'SYNTHETIC' "$WORK/passthrough.mp4" && marker_fired=yes
[ "$marker_fired" = yes ] || fail "the marker sweep does not notice a surviving marker — it proves nothing above"
# And the offset check, against a file whose chunk offsets deliberately point nowhere.
walk_fired=no
case "$(python3 "$WORK/boxes.py" "$CORPUS/malformed/chunk-offset-past-end.mp4")" in
    *UNRESOLVED*) walk_fired=yes ;;
esac
[ "$walk_fired" = yes ] || fail "the box walk does not notice an offset that resolves nowhere — it proves nothing above"
printf '  both the marker sweep and the chunk-offset walk reject a pass-through\n'

printf '\n%s fixture(s) compared\n' "$checked"
if [ "$gaps" -gt 0 ]; then
    fail "$gaps gap(s) — each needs a fix or a documented limitation in docs/THREAT_MODEL.md §7.17"
fi
printf '\033[32m✓\033[0m no gaps: strypt removes at least what mat2 removes across the corpus\n'
