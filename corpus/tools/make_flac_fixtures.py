#!/usr/bin/env python3
"""Generate the FLAC fixtures in ``corpus/flac``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design.

**These are real, decodable FLAC files**, unlike the JPEG XL stubs next door: mat2 reaches FLAC
through mutagen, which will not open a file whose frames do not parse, and the differential is
worthless if the comparison tool refuses the input. The audio is one 4096-sample frame of digital
silence — a constant subframe, a CRC-8 header and a CRC-16 footer (RFC 9639 section 9) — and
``STREAMINFO``'s MD5 is the real MD5 of those samples, so ``flac -t`` passes.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import hashlib
import pathlib
import struct
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "flac"
MALFORMED = OUT / "malformed"

MAGIC = b"fLaC"

STREAMINFO, PADDING, APPLICATION, SEEKTABLE, VORBIS_COMMENT, CUESHEET, PICTURE = range(7)

BLOCKSIZE = 4096
SAMPLE_RATE = 44100
CHANNELS = 1
BITS = 16


def crc8(data):
    """Polynomial 0x07, initial value 0 — the frame-header check of section 9.1.7."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def crc16(data):
    """Polynomial 0x8005, initial value 0 — the whole-frame check of section 9.3."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x8005) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def frame():
    """One fixed-blocksize frame of 4096 silent mono samples, as a constant subframe.

    Header: the 14-bit sync, blocking strategy 0, block size code 0b1100 (4096), sample rate code
    0b1001 (44.1 kHz), mono, 16 bits per sample, frame number 0.
    """
    header = bytes([0xFF, 0xF8, 0xC9, 0x08, 0x00])
    header += bytes([crc8(header)])
    # Subframe header 0x00 is type CONSTANT with no wasted bits; the value follows at the declared
    # sample size, and the frame is already byte-aligned.
    body = header + b"\x00" + struct.pack(">h", 0)
    return body + struct.pack(">H", crc16(body))


AUDIO = frame()
# Section 8.2's MD5 is of the *unencoded* audio: interleaved samples, little-endian, 2 bytes each.
AUDIO_MD5 = hashlib.md5(b"\x00" * (BLOCKSIZE * CHANNELS * (BITS // 8))).digest()


def streaminfo(md5=AUDIO_MD5):
    packed = (SAMPLE_RATE << 44) | ((CHANNELS - 1) << 41) | ((BITS - 1) << 36) | BLOCKSIZE
    return (
        struct.pack(">HH", BLOCKSIZE, BLOCKSIZE)
        + b"\x00" * 6  # min and max frame size: unknown
        + struct.pack(">Q", packed)
        + md5
    )


def block(kind, payload, last=False):
    return bytes([kind | (0x80 if last else 0)]) + struct.pack(">I", len(payload))[1:] + payload


def flac(*blocks, info=None, audio=AUDIO):
    """A file: marker, ``STREAMINFO`` first, the rest in order, then frames."""
    body = [block(STREAMINFO, streaminfo() if info is None else info)]
    body += list(blocks)
    out = bytearray(MAGIC)
    for index, raw in enumerate(body):
        raw = bytearray(raw)
        if index == len(body) - 1:
            raw[0] |= 0x80
        out += raw
    return bytes(out + audio)


def comment(vendor, *items):
    payload = struct.pack("<I", len(vendor)) + vendor
    payload += struct.pack("<I", len(items))
    for item in items:
        payload += struct.pack("<I", len(item)) + item
    return block(VORBIS_COMMENT, payload)


TAGS = comment(
    b"SYNTHETIC-ENCODER-0001",
    b"ARTIST=SYNTHETIC-ARTIST-0002",
    b"TITLE=A Recording",
    b"ALBUM=SYNTHETIC-ALBUM-0003",
    b"DATE=2019-01-02",
    b"COMMENT=SYNTHETIC-COMMENT-0004",
    b"ENCODED-BY=SYNTHETIC-ENCODED-BY-0005",
    b"ENCODER_SETTINGS=SYNTHETIC-SETTINGS-0006",
    b"MUSICBRAINZ_TRACKID=SYNTHETIC-MBID-0007",
    b"LOCATION=SYNTHETIC-LOCATION-0008",
    b"ORGANIZATION=SYNTHETIC-ORGANIZATION-0009",
)


def png_chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


def cover_png():
    """A 1x1 greyscale PNG carrying its own ``tEXt``.

    The text is there to make a point the tests assert: the picture is removed with its block, so
    the metadata inside it never has to be reached. ADR-0029's descent into embedded images does
    not extend to this group (ADR-0037).
    """
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00", 9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"tEXt", b"Author\x00SYNTHETIC-COVER-AUTHOR-0010")
        + png_chunk(b"IDAT", idat)
        + png_chunk(b"IEND", b"")
    )


def picture(kind=3, description=b"SYNTHETIC-COVER-DESCRIPTION-0011"):
    data = cover_png()
    mime = b"image/png"
    payload = struct.pack(">I", kind)
    payload += struct.pack(">I", len(mime)) + mime
    payload += struct.pack(">I", len(description)) + description
    payload += struct.pack(">IIII", 1, 1, 8, 0)
    payload += struct.pack(">I", len(data)) + data
    return block(PICTURE, payload)


def cuesheet():
    """Section 8.6. The catalogue number and the per-track ISRC are what make this metadata."""
    payload = b"SYNTHETIC-CATALOGUE-0012".ljust(128, b"\x00")
    payload += struct.pack(">Q", 88200)
    payload += b"\x80" + b"\x00" * 258  # CD flag set, then the reserved run
    payload += bytes([2])
    # One audio track, then the mandatory lead-out.
    payload += struct.pack(">Q", 0) + bytes([1]) + b"SYNISRC00013"
    payload += b"\x00" * 14 + bytes([1])
    payload += struct.pack(">Q", 0) + bytes([1]) + b"\x00\x00\x00"
    payload += struct.pack(">Q", BLOCKSIZE) + bytes([170]) + b"\x00" * 12
    payload += b"\x00" * 14 + bytes([0])
    return block(CUESHEET, payload)


def seektable(points=4):
    payload = b""
    for i in range(points):
        payload += struct.pack(">QQH", i * 1024, i * 16, 1024)
    return block(SEEKTABLE, payload)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT.parent)}  ({len(data)} bytes)")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)
    print("FLAC fixtures:")

    # The baseline, and the promise deletion can make that a rebuild cannot: nothing to remove, so
    # the output is the input. The padding is the zeros section 8.2 calls for.
    write(OUT / "clean.flac", flac(block(PADDING, b"\x00" * 512)))

    write(OUT / "vorbis-comment.flac", flac(TAGS))
    write(OUT / "cover-art.flac", flac(picture()))
    write(OUT / "cuesheet.flac", flac(cuesheet()))
    write(OUT / "seektable.flac", flac(seektable(), TAGS))
    write(OUT / "application.flac", flac(block(APPLICATION, b"ATCHSYNTHETIC-APPLICATION-0014")))

    # Padding whose bytes are not zeros: the block keeps its length and loses its contents, so a
    # tagger still has its room and whatever was left there is gone.
    write(
        OUT / "padding-with-data.flac",
        flac(TAGS, block(PADDING, b"SYNTHETIC-PADDING-0015".ljust(512, b"\x00"))),
    )

    # Section 8.2 reserves types 7 to 126. Removed unread: an unrecognised block in a format whose
    # metadata lives in blocks is more likely to be metadata than not.
    write(OUT / "reserved-block.flac", flac(block(20, b"SYNTHETIC-RESERVED-BLOCK-0016")))

    # An all-zero MD5 means "unknown" (section 8.2), so there is no fingerprint to declare.
    write(OUT / "no-audio-md5.flac", flac(TAGS, info=streaminfo(md5=b"\x00" * 16)))

    write(
        OUT / "kitchen-sink.flac",
        flac(
            seektable(),
            TAGS,
            picture(),
            picture(kind=8, description=b"SYNTHETIC-ARTIST-PHOTO-0017"),
            cuesheet(),
            block(APPLICATION, b"ATCHSYNTHETIC-APPLICATION-0014"),
            block(20, b"SYNTHETIC-RESERVED-BLOCK-0016"),
            block(PADDING, b"SYNTHETIC-PADDING-0015".ljust(512, b"\x00")),
        ),
    )


    # Tags glued to the ends of a FLAC. Neither is FLAC and a decoder skips both, so they survive
    # every block this handler cleans. Refused outright until the MP3 tranche put an ID3 reader in
    # the tree; read and removed since (ADR-0040 lifts ADR-0038 decision 7).
    id3_body = b"TXXX" + struct.pack(">I", 30) + b"\x00\x00" + b"\x00SYNTHETIC-ID3-0018\x00"
    id3 = b"ID3\x04\x00\x00" + bytes([0, 0, 1, 0x7F]) + id3_body.ljust(255, b"\x00")
    write(OUT / "id3-prefixed.flac", id3 + flac(TAGS))

    v1 = bytearray(b"\x00" * 128)
    v1[0:3] = b"TAG"
    v1[33:33 + len(b"SYNTHETIC-ID3V1-0019")] = b"SYNTHETIC-ID3V1-0019"
    write(OUT / "appended-tags.flac", id3 + flac(TAGS) + bytes(v1))

    write(MALFORMED / "wrong-marker.flac", b"fLaD" + flac(TAGS)[4:])

    # Section 8.2: STREAMINFO is mandatory and comes first, at exactly 34 bytes.
    write(MALFORMED / "no-streaminfo.flac", MAGIC + block(VORBIS_COMMENT, b"\x00" * 8, last=True) + AUDIO)
    write(
        MALFORMED / "streaminfo-wrong-length.flac",
        MAGIC + block(STREAMINFO, streaminfo()[:30], last=True) + AUDIO,
    )
    write(MALFORMED / "second-streaminfo.flac", flac(block(STREAMINFO, streaminfo())))

    # Section 8.1 forbids type 127 so that a block header can never look like a frame sync.
    write(MALFORMED / "forbidden-block-type.flac", flac(block(127, b"\x00" * 4)))

    # A block claiming more bytes than the file holds.
    write(MALFORMED / "block-overruns-file.flac", flac(TAGS)[: -len(AUDIO) - 8])

    # A length that lies without overrunning: the blocks end where no frame sync begins, so the
    # walk has landed somewhere the file does not agree with.
    write(MALFORMED / "no-frame-sync.flac", flac(TAGS)[: -len(AUDIO)] + b"\x00" * len(AUDIO))


if __name__ == "__main__":
    sys.exit(main())
