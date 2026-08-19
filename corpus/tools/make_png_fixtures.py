#!/usr/bin/env python3
"""Generate the PNG fixtures in ``corpus/png``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with Pillow installed is a corpus nobody regenerates.

Every fixture is a **real, decodable PNG**. The base image below is a 16x16 greyscale gradient
encoded once and committed here as a literal, so this script needs no encoder; the fixtures are
that image with metadata chunks spliced in around it. Nothing here re-encodes anything, which
is also what strypt itself refuses to do.

**The compressed chunks use stored (uncompressed) deflate blocks.** That is a legal zlib
stream, which keeps every fixture decodable, and it has a useful side effect: the text inside a
``zTXt`` or a compressed ``iTXt`` is visible in the file's raw bytes, so a test can assert that
strypt's *output* does not contain it rather than trusting strypt's report. It also removes the
last dependency on a compressor's version-to-version output, which is what determinism needs.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker. One deliberate exception is prefixed ``PRESERVED-`` instead: it lives in an unknown
critical chunk, which strypt keeps on purpose, so it must not be swept up by the test that
asserts no ``SYNTHETIC`` marker survives.
"""

import base64
import pathlib
import sys
import zlib

# The TIFF builder is shared with the JPEG fixtures rather than copied: a PNG ``eXIf`` chunk
# holds exactly the block a JPEG ``APP1`` holds, minus the introducer, and two copies of that
# layout logic would drift.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from make_jpeg_fixtures import ascii_tag, tiff  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parents[1] / "png"

SIGNATURE = b"\x89PNG\r\n\x1a\n"

# A 16x16 greyscale gradient: signature, IHDR, IDAT, IEND. Committed as a literal so that
# regenerating the corpus never depends on a compressor's output.
BASE = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAAAAAA6mKC9AAABG0lEQVR42gEQAe/+AAAQIDBAUGBw"
    "gJCgsMDQ4PAAAREhMUFRYXGBkaGxwdHh8QACEiIyQlJicoKSorLC0uLyAAMTIzNDU2Nzg5Ojs8PT"
    "4/MABBQkNERUZHSElKS0xNTk9AAFFSU1RVVldYWVpbXF1eX1AAYWJjZGVmZ2hpamtsbW5vYABxcn"
    "N0dXZ3eHl6e3x9fn9wAIGCg4SFhoeIiYqLjI2Oj4AAkZKTlJWWl5iZmpucnZ6fkAChoqOkpaanqK"
    "mqq6ytrq+gALGys7S1tre4ubq7vL2+v7AAwcLDxMXGx8jJysvMzc7PwADR0tPU1dbX2Nna29zd3t"
    "/QAOHi4+Tl5ufo6err7O3u7+AA8fLz9PX29/j5+vv8/f7/8Dn3+BMcT5VgAAAABJRU5ErkJggg=="
)


def chunk(kind: bytes, data: bytes) -> bytes:
    """One chunk: length, four-byte type, payload, and the CRC of type and payload."""
    body = kind + data
    return len(data).to_bytes(4, "big") + body + zlib.crc32(body).to_bytes(4, "big")


def split_base() -> tuple[bytes, bytes]:
    """The base image as (IHDR chunk, everything after it)."""
    ihdr_length = int.from_bytes(BASE[8:12], "big")
    end = 8 + 12 + ihdr_length
    return BASE[8:end], BASE[end:]


def build(extra: bytes = b"", trailing: bytes = b"") -> bytes:
    """The base image with `extra` chunks inserted straight after IHDR."""
    ihdr, rest = split_base()
    return SIGNATURE + ihdr + extra + rest + trailing


def zlib_stored(data: bytes) -> bytes:
    """`data` wrapped in a zlib stream of stored deflate blocks.

    RFC 1950 header, RFC 1951 type-0 blocks, Adler-32 trailer. Legal, decodable, deterministic,
    and it leaves the payload readable in the file's bytes so a test can look for it.
    """
    out = bytearray(b"\x78\x01")
    blocks = [data[i : i + 0xFFFF] for i in range(0, len(data), 0xFFFF)] or [b""]
    for index, block in enumerate(blocks):
        out.append(1 if index == len(blocks) - 1 else 0)
        out += len(block).to_bytes(2, "little")
        out += (len(block) ^ 0xFFFF).to_bytes(2, "little")
        out += block
    out += zlib.adler32(data).to_bytes(4, "big")
    return bytes(out)


def text(keyword: bytes, value: bytes) -> bytes:
    """A `tEXt` chunk: keyword, NUL, Latin-1 text (W3C PNG Third Edition 11.3.3.2)."""
    return chunk(b"tEXt", keyword + b"\x00" + value)


def ztxt(keyword: bytes, value: bytes) -> bytes:
    """A `zTXt` chunk: keyword, NUL, compression method, compressed text (11.3.3.3)."""
    return chunk(b"zTXt", keyword + b"\x00\x00" + zlib_stored(value))


def itxt(keyword: bytes, value: bytes, *, compressed: bool) -> bytes:
    """An `iTXt` chunk (11.3.3.4).

    Keyword, NUL, compression flag, compression method, language tag, translated keyword, and
    UTF-8 text — of which only the text is ever compressed, which is the whole reason strypt
    needs no decompressor to know what this chunk is (ADR-0022).
    """
    head = keyword + b"\x00" + (b"\x01\x00" if compressed else b"\x00\x00") + b"\x00\x00"
    return chunk(b"iTXt", head + (zlib_stored(value) if compressed else value))


XMP_PACKET = (
    b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
    b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about="" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
    b'xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">'
    b"<dc:creator><rdf:Seq><rdf:li>SYNTHETIC-PNG-XMP-CREATOR-0006"
    b"</rdf:li></rdf:Seq></dc:creator>"
    b"<xmp:CreatorTool>SYNTHETIC-PNG-XMP-TOOL-0007</xmp:CreatorTool>"
    b"<xmpMM:DocumentID>uuid:SYNTHETIC-PNG-DOCUMENT-ID-0008</xmpMM:DocumentID>"
    b'</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
)


def write(name: str, data: bytes) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"{path.relative_to(OUT.parents[1])}: {len(data)} bytes")


def malformed() -> None:
    """Deliberately broken files. Each is a shape a real parser bug would hide behind."""
    valid = build(text(b"Author", b"SYNTHETIC-PNG-AUTHOR-0001"))

    # A chunk that claims more bytes than the file holds. A parser that trusted it would read
    # past the end; one that clamped would silently parse the wrong bytes and report on them.
    past_end = bytearray(valid)
    past_end[8:12] = (0x0010_0000).to_bytes(4, "big")
    write("malformed/length-past-end.png", bytes(past_end))

    # A length with the high bit set. 5.3 caps a chunk at 2**31 - 1, so this is a lying field
    # rather than a very large chunk, and on a 32-bit target it is also an overflow attempt.
    high_bit = bytearray(valid)
    high_bit[8:12] = (0xFFFF_FFFF).to_bytes(4, "big")
    write("malformed/length-high-bit.png", bytes(high_bit))

    # Ends before IEND. strypt refuses rather than completing it: handing back a repaired copy
    # of a damaged file, presented as a clean version of it, is not something a user asked for.
    write("malformed/no-iend.png", valid[: len(valid) - 12])

    # A chunk type that is not four letters. 5.4 requires letters, so this means the walk has
    # lost its place, and continuing would be slicing arbitrary bytes out of the file.
    write("malformed/bad-chunk-type.png", build(chunk(b"\x00\x01\x02\x03", b"")))

    # IHDR is not first (5.6). The file's shape is not one strypt has understood, so a
    # "cleaned" copy of it would be a guess.
    write(
        "malformed/no-ihdr.png",
        SIGNATURE + text(b"Author", b"SYNTHETIC-PNG-AUTHOR-0001") + split_base()[1],
    )

    # A text chunk with no NUL separator: malformed, and on its way out regardless. Refusing
    # the whole file over it would cost the user their strip to make a point.
    write(
        "malformed/text-without-separator.png",
        build(chunk(b"tEXt", b"SYNTHETIC-PNG-NO-SEPARATOR-0015")),
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # 1. The ordinary case: an editor writes its name, a user writes a comment.
    write(
        "text-chunks.png",
        build(
            text(b"Author", b"SYNTHETIC-PNG-AUTHOR-0001")
            + text(b"Software", b"SYNTHETIC-PNG-SOFTWARE-0002")
            + text(b"Comment", b"SYNTHETIC-PNG-COMMENT-0003")
        ),
    )

    # 2. A thumbnailer's record of where the original lived. `Thumb::URI` is a full path, so it
    # names a home directory, and a home directory names a person. Freedesktop thumbnail spec.
    write(
        "thumbnail-uri.png",
        build(
            text(b"Thumb::URI", b"file:///home/SYNTHETIC-PNG-USER-0004/pictures/img.png")
            + text(b"Thumb::MTime", b"1755561600")
        ),
    )

    # 3. Compressed text. The keyword is readable, the text is not, and strypt removes the
    # chunk without inflating anything (ADR-0022).
    write("compressed-text.png", build(ztxt(b"Comment", b"SYNTHETIC-PNG-ZTXT-0005")))

    # 4. An XMP packet in an uncompressed iTXt: reported property by property.
    write("xmp-packet.png", build(itxt(b"XML:com.adobe.xmp", XMP_PACKET, compressed=False)))

    # 5. The same packet compressed. Removed identically; reported as one item rather than
    # itemised, which is the documented cost of not carrying a decompressor.
    write(
        "xmp-compressed.png",
        build(itxt(b"XML:com.adobe.xmp", XMP_PACKET, compressed=True)),
    )

    # 6. An eXIf chunk: the same TIFF block a JPEG carries, without the introducer. GPS in a
    # PNG is rarer than in a JPEG and no less dangerous when it is there.
    rational = lambda *values: b"".join(
        n.to_bytes(4, "little") + (1).to_bytes(4, "little") for n in values
    )
    exif = tiff(
        ifd0=[
            ascii_tag(0x010F, b"SYNTHETIC-PNG-CAMERA-MAKE-0009"),
            ascii_tag(0x0110, b"SYNTHETIC-PNG-CAMERA-MODEL-0010"),
            ascii_tag(0x0132, b"2026:08:19 12:30:45"),
        ],
        gps=[
            ascii_tag(0x0001, b"N"),
            # 51/1 30/1 0/1 — a coordinate that names a city centre and nobody's home.
            (0x0002, 5, 3, rational(51, 30, 0)),
            ascii_tag(0x0003, b"W"),
            (0x0004, 5, 3, rational(0, 7, 0)),
        ],
    )
    write("exif-gps.png", build(chunk(b"eXIf", exif)))

    # 7. An ICC profile. The profile name is in the clear and is the identifying part: a
    # per-device profile is a fingerprint, and its name routinely carries the vendor.
    profile = b"SYNTHETIC-PNG-ICC-PROFILE-BODY-0011" + b"\x00" * 32
    write(
        "icc-profile.png",
        build(chunk(b"iCCP", b"SYNTHETIC-PNG-ICC-VENDOR-0012\x00\x00" + zlib_stored(profile))),
    )

    # 8. A last-modified time, to the second. On its own it is correlating rather than
    # identifying; combined with anything else it narrows the field sharply.
    write("timestamp.png", build(chunk(b"tIME", bytes([0x07, 0xEA, 8, 19, 12, 30, 45]))))

    # 9. ImageMagick's habit: a whole Exif block stored as hex text under a `Raw profile type`
    # keyword. Tools that only look at eXIf chunks walk straight past this.
    raw_exif = b"\nexif\n%8d\n" % len(exif) + exif.hex().encode() + b"\n"
    write("raw-profile.png", build(text(b"Raw profile type exif", raw_exif)))

    # 10. Chunks strypt does not know. The ancillary one goes — a private chunk can hold
    # anything, and copying through what you do not understand is not scrubbing. The critical
    # one stays, because dropping it would break the file for every decoder, and the report
    # says so rather than leaving the user to find out.
    write(
        "unknown-chunks.png",
        build(
            chunk(b"prVW", b"SYNTHETIC-PNG-PREVIEW-0013")
            + chunk(b"VeND", b"PRESERVED-PNG-CRITICAL-0014")
        ),
    )

    # 11. Rendering chunks, none of which name anybody, all of which change how the image looks
    # or prints if they are dropped. A tEXt rides along so the file is not otherwise clean.
    write(
        "rendering-chunks.png",
        build(
            chunk(b"gAMA", (45455).to_bytes(4, "big"))
            + chunk(b"sRGB", b"\x00")
            + chunk(b"pHYs", (2835).to_bytes(4, "big") + (2835).to_bytes(4, "big") + b"\x01")
            + chunk(b"bKGD", (0).to_bytes(2, "big"))
            + text(b"Comment", b"SYNTHETIC-PNG-COMMENT-0003")
        ),
    )

    # 12. A whole second image after IEND. Nothing reads past that chunk and few users know
    # anything can be there, which is exactly what makes it a good hiding place.
    second = build(text(b"Comment", b"SYNTHETIC-PNG-SECOND-IMAGE-0016"))
    write("trailing-data.png", build(trailing=second))

    # 13. Nothing to find. A tool that invents findings teaches users to ignore it.
    write("clean.png", build())

    malformed()


if __name__ == "__main__":
    main()
