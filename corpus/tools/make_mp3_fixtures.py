#!/usr/bin/env python3
"""Generate the MP3 fixtures in ``corpus/mp3``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design.

**These are real, playable MP3 files.** mat2 reaches MP3 through mutagen and ExifTool reads the
frame header directly, and the differential is worthless if the comparison tool refuses the input.
The audio is four MPEG-1 Layer III frames at 128 kbps, 44.1 kHz mono, whose main data is zeroed —
which decodes as silence.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "mp3"
MALFORMED = OUT / "malformed"

# MPEG-1 Layer III, no CRC, 128 kbps, 44.1 kHz, mono, no padding: 144 * 128000 / 44100 = 417.
FRAME_HEADER = b"\xff\xfb\x90\xc0"
FRAME_BYTES = 417
# MPEG-1 mono (§2.4.1.7).
SIDE_INFO = 17


def frame():
    return FRAME_HEADER + b"\x00" * (FRAME_BYTES - len(FRAME_HEADER))


def audio(count=4):
    return frame() * count


def syncsafe(n):
    """Four bytes of seven bits each (ID3v2 §6.2)."""
    return bytes(((n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F))


def id3v2_frame(fid, text, major=4):
    """One text frame: an encoding byte, then the value. `03` is UTF-8 in v2.4."""
    payload = b"\x03" + text
    if major == 2:
        return fid + struct.pack(">I", len(payload))[1:] + payload
    size = syncsafe(len(payload)) if major == 4 else struct.pack(">I", len(payload))
    return fid + size + b"\x00\x00" + payload


def id3v2(frames, major=4, flags=0x00, extended=b"", footer=False):
    body = extended + b"".join(frames)
    header = b"ID3" + bytes((major, 0, flags)) + syncsafe(len(body))
    out = header + body
    if footer:
        out += b"3DI" + bytes((major, 0, flags)) + syncsafe(len(body))
    return out


def unsynchronise(body):
    """§6.1 in the writing direction: every `FF` gains a `00` behind it."""
    out = bytearray()
    for byte in body:
        out.append(byte)
        if byte == 0xFF:
            out.append(0x00)
    return bytes(out)


def id3v1(fields, extended=False):
    tag = bytearray(b"\x00" * 128)
    tag[0:3] = b"TAG"
    for at, value in fields:
        tag[at : at + len(value)] = value
    out = b""
    if extended:
        ext = bytearray(b"\x00" * 227)
        ext[0:4] = b"TAG+"
        ext[4:4 + len(b"SYNTHETIC-LONG-TITLE-0020")] = b"SYNTHETIC-LONG-TITLE-0020"
        out += bytes(ext)
    return out + bytes(tag)


def ape(items, with_header=True):
    body = b""
    for key, value in items:
        body += struct.pack("<II", len(value), 0) + key + b"\x00" + value
    size = len(body) + 32

    def block(flags):
        return (
            b"APETAGEX"
            + struct.pack("<III", 2000, size, len(items))
            + struct.pack("<I", flags)
            + b"\x00" * 8
        )

    out = block(0xA000_0000) if with_header else b""
    return out + body + block(0x8000_0000 if with_header else 0)


def lyrics3v2(text):
    """A `LYR` field, then the six-digit size — which counts neither itself nor `LYRICS200`."""
    body = b"LYRICSBEGIN" + b"LYR" + f"{len(text):05d}".encode("ascii") + text
    return body + f"{len(body):06d}".encode("ascii") + b"LYRICS200"


def lyrics3v1(text):
    return b"LYRICSBEGIN" + text + b"LYRICSEND"


def xing(marker=b"Xing", lame=b"LAME3.100"):
    """A VBR header frame: a real frame a decoder plays as silence, and the encoder's signature."""
    body = bytearray(frame())
    at = len(FRAME_HEADER) + SIDE_INFO
    body[at : at + 4] = marker
    # Flags, frame count, byte count, then the LAME extension where a real encoder writes it.
    body[at + 4 : at + 16] = struct.pack(">III", 0x03, 4, FRAME_BYTES * 4)
    body[at + 36 : at + 36 + len(lame)] = lame
    return bytes(body)


def vbri():
    """Fraunhofer's spelling, at a fixed offset of 32 bytes past the header."""
    body = bytearray(frame())
    body[36:40] = b"VBRI"
    body[40:49] = b"SYNTH-VBR"
    return bytes(body)


def write(path, blob):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    print(f"  {path.relative_to(ROOT.parent)}  ({len(blob)} bytes)")


V24_FRAMES = [
    (b"TPE1", b"SYNTHETIC-ARTIST-0001"),
    (b"TIT2", b"SYNTHETIC-TITLE-0002"),
    (b"TALB", b"SYNTHETIC-ALBUM-0003"),
    (b"TCOM", b"SYNTHETIC-COMPOSER-0004"),
    (b"TENC", b"SYNTHETIC-TAGGER-0005"),
    (b"TSSE", b"SYNTHETIC-ENCODER-0006"),
    (b"TDRC", b"2026-09-02T11:00:00"),
    (b"TDTG", b"2026-09-02T11:30:00"),
    (b"TCOP", b"SYNTHETIC-COPYRIGHT-0007"),
    (b"TSRC", b"SYNTHETIC-ISRC-0008"),
    (b"COMM", b"SYNTHETIC-COMMENT-0009"),
    (b"TXXX", b"SYNTHETIC-USERTEXT-0010"),
    (b"TLOC", b"SYNTHETIC-LOCATION-0011"),
]

V23_FRAMES = [
    (b"TPE1", b"SYNTHETIC-ARTIST-0012"),
    (b"TYER", b"2026"),
    (b"TDAT", b"0209"),
    (b"TIME", b"1100"),
    (b"TENC", b"SYNTHETIC-TAGGER-0013"),
]

V22_FRAMES = [
    (b"TP1", b"SYNTHETIC-ARTIST-0014"),
    (b"TEN", b"SYNTHETIC-TAGGER-0015"),
    (b"TYE", b"2026"),
]

APE_ITEMS = [
    (b"Artist", b"SYNTHETIC-ARTIST-0016"),
    (b"Tool Name", b"SYNTHETIC-TOOL-0017"),
    (b"Comment", b"SYNTHETIC-COMMENT-0018"),
    (b"ISRC", b"SYNTHETIC-ISRC-0019"),
]

V1_FIELDS = [
    (3, b"SYNTHETIC-TITLE-0021"),
    (33, b"SYNTHETIC-ARTIST-0022"),
    (63, b"SYNTHETIC-ALBUM-0023"),
    (93, b"2026"),
    (97, b"SYNTHETIC-COMMENT-0024"),
]


def main():
    print("writing MP3 fixtures")

    # Nothing to remove. strypt must hand this back byte-identical.
    write(OUT / "clean.mp3", audio())

    write(
        OUT / "id3v2-4.mp3",
        id3v2([id3v2_frame(f, t) for f, t in V24_FRAMES]) + audio(),
    )
    write(
        OUT / "id3v2-3.mp3",
        id3v2([id3v2_frame(f, t, major=3) for f, t in V23_FRAMES], major=3) + audio(),
    )
    write(
        OUT / "id3v2-2.mp3",
        id3v2([id3v2_frame(f, t, major=2) for f, t in V22_FRAMES], major=2) + audio(),
    )

    # §6.1: the tag's own bytes are escaped so nothing in it looks like a frame sync. Frame sizes
    # inside are measured in de-escaped bytes, so a reader that skips the step lands nowhere.
    unsync_frames = b"".join(
        id3v2_frame(f, t, major=3) for f, t in [(b"TIT2", b"SYNTHETIC\xff\x00-TITLE-0025")]
    )
    body = unsynchronise(unsync_frames)
    write(
        OUT / "unsynchronised.mp3",
        b"ID3\x03\x00\x80" + syncsafe(len(body)) + body + audio(),
    )

    # §3.2's extended header, whose size is counted differently in v2.3 and v2.4.
    write(
        OUT / "extended-header.mp3",
        id3v2(
            [id3v2_frame(b"TPE1", b"SYNTHETIC-ARTIST-0026")],
            flags=0x40,
            extended=syncsafe(6) + b"\x01\x00",
        )
        + audio(),
    )

    # §3.1's footer, which is ten bytes the size field does not count.
    write(
        OUT / "footer.mp3",
        id3v2([id3v2_frame(b"TIT2", b"SYNTHETIC-TITLE-0027")], flags=0x10, footer=True)
        + audio(),
    )

    # Taggers really do write a second tag in front of the first.
    write(
        OUT / "stacked-tags.mp3",
        id3v2([id3v2_frame(b"TIT2", b"SYNTHETIC-TITLE-0028")])
        + id3v2([id3v2_frame(b"TPE1", b"SYNTHETIC-ARTIST-0029")])
        + audio(),
    )

    write(OUT / "id3v1.mp3", audio() + id3v1(V1_FIELDS))
    write(OUT / "id3v1-extended.mp3", audio() + id3v1(V1_FIELDS, extended=True))
    write(OUT / "ape.mp3", audio() + ape(APE_ITEMS))
    write(OUT / "ape-no-header.mp3", audio() + ape(APE_ITEMS, with_header=False))
    write(OUT / "lyrics3v2.mp3", audio() + lyrics3v2(b"SYNTHETIC-LYRIC-0030"))
    write(OUT / "lyrics3v1.mp3", audio() + lyrics3v1(b"SYNTHETIC-LYRIC-0031"))

    # Cover art is an ordinary image with whatever its own container carries, and `GEOB` is any
    # file at all under a name the tagger chose.
    art = b"\x00image/png\x00\x03SYNTHETIC-COVER-0032\x00\x89PNG\r\n\x1a\n"
    geob = b"\x00application/octet-stream\x00SYNTHETIC-FILE-0033\x00\x00SYNTHETIC-BLOB-0034"
    write(
        OUT / "cover-art.mp3",
        id3v2([b"APIC" + syncsafe(len(art)) + b"\x00\x00" + art]) + audio(),
    )
    write(
        OUT / "embedded-object.mp3",
        id3v2([b"GEOB" + syncsafe(len(geob)) + b"\x00\x00" + geob]) + audio(),
    )

    priv = b"SYNTHETIC-OWNER-0035\x00SYNTHETIC-PRIVATE-0036"
    write(
        OUT / "private-frame.mp3",
        id3v2([b"PRIV" + syncsafe(len(priv)) + b"\x00\x00" + priv]) + audio(),
    )

    # A frame identifier nobody has a name for is where a tagger puts what it does not want read.
    write(
        OUT / "unknown-frame.mp3",
        id3v2([id3v2_frame(b"ZZZZ", b"SYNTHETIC-UNKNOWN-0037")]) + audio(),
    )

    # The encoder fingerprint that stays: a real frame inside the encoded stream (ADR-0037).
    write(OUT / "vbr-xing.mp3", xing() + audio(3))
    write(OUT / "vbr-info.mp3", xing(marker=b"Info") + audio(3))
    write(OUT / "vbr-vbri.mp3", vbri() + audio(3))

    # Some taggers pad past the size their own header declares. Zeros, so nothing is hidden — but
    # the file changes size, and the report has to account for it.
    write(
        OUT / "leading-padding.mp3",
        id3v2([id3v2_frame(b"TIT2", b"SYNTHETIC-TITLE-0038")]) + b"\x00" * 512 + audio(),
    )

    # No leading padding here, and that is deliberate: `leading-padding.mp3` covers it, and a run
    # of zeros in front of a Xing frame stops ffmpeg reading that frame as a VBR header, so the
    # differential's decode comparison would be measuring ffmpeg rather than strypt.
    write(
        OUT / "kitchen-sink.mp3",
        id3v2(
            [id3v2_frame(f, t) for f, t in V24_FRAMES]
            + [
                b"APIC" + syncsafe(len(art)) + b"\x00\x00" + art,
                b"PRIV" + syncsafe(len(priv)) + b"\x00\x00" + priv,
                id3v2_frame(b"ZZZZ", b"SYNTHETIC-UNKNOWN-0037"),
            ]
        )
        + xing()
        + audio(3)
        + lyrics3v2(b"SYNTHETIC-LYRIC-0030")
        + ape(APE_ITEMS)
        + id3v1(V1_FIELDS, extended=True),
    )

    print("writing malformed MP3 fixtures")

    good = id3v2([id3v2_frame(f, t) for f, t in V24_FRAMES]) + audio()

    # Cut short mid-tag. Refused, not repaired: a cleaned copy of a truncated file would be a
    # repair the user never asked for, presented as a clean version. The cut lands inside the tag,
    # so the size in the header runs past what is there.
    write(MALFORMED / "truncated.mp3", good[:200])

    # A tag size larger than the file. Refused rather than clamped — that number is the boundary
    # between metadata and audio, and a clamped one puts the boundary inside the audio.
    write(
        MALFORMED / "tag-size-past-end.mp3",
        good[:6] + syncsafe(0x0010_0000) + good[10:],
    )

    # §6.2 makes the size syncsafe. A set high bit means the writer's length is not this reader's.
    write(MALFORMED / "non-syncsafe-size.mp3", good[:6] + b"\x80" + good[7:])

    # §3.1 promises a later major version keeps the header but not the body — so its length field
    # is one this code has never read.
    write(MALFORMED / "unknown-major-version.mp3", good[:3] + b"\x05" + good[4:])

    # An APE footer whose flag claims a header that is not there.
    broken = bytearray(ape(APE_ITEMS))
    broken[0:8] = b"XXXXXXXX"
    write(MALFORMED / "ape-header-missing.mp3", audio() + bytes(broken))

    # A tail tag whose size reaches below the head tags: without the floor it would swallow the
    # audio, and the file would strip to nothing while reporting success.
    swallow = bytearray(ape(APE_ITEMS, with_header=False))
    swallow[-20:-16] = struct.pack("<I", 0x000F_FFFF)
    write(MALFORMED / "tail-tag-below-floor.mp3", audio() + bytes(swallow))

    # Tags and nothing else. It would otherwise strip to an empty file, reported as a success.
    write(
        MALFORMED / "no-audio.mp3",
        id3v2([id3v2_frame(b"TIT2", b"SYNTHETIC-TITLE-0039")]) + id3v1(V1_FIELDS),
    )

    # Arbitrary bytes between the tag and the first frame: exactly where something would be hidden
    # from a tool that skipped ahead to the first sync.
    write(
        MALFORMED / "hidden-before-audio.mp3",
        id3v2([id3v2_frame(b"TIT2", b"SYNTHETIC-TITLE-0040")])
        + b"SYNTHETIC-HIDDEN-0041"
        + audio(),
    )

    # The same frame grammar, a different format. Named rather than walked (ADR-0027).
    write(MALFORMED / "layer-two.mp3", b"\xff\xfd\x90\xc0" + audio()[4:])

    # `01` is reserved in the version field, so where the audio begins would be a guess.
    write(MALFORMED / "reserved-version.mp3", b"\xff\xeb\x90\xc0" + audio()[4:])

    # `1111` in the bitrate index is forbidden outright.
    write(MALFORMED / "forbidden-bitrate.mp3", b"\xff\xfb\xf0\xc0" + audio()[4:])


if __name__ == "__main__":
    sys.exit(main())
