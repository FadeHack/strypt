#!/usr/bin/env python3
"""Generate the WebP fixtures in ``corpus/webp``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with a WebP encoder installed is a corpus nobody regenerates.

Every fixture is a **real, decodable WebP**. The two base images below are 16x16 encodings of
the same picture the PNG fixtures use, produced once with ``cwebp 1.6.0`` and committed here as
literals; the fixtures are those bitstreams with container chunks arranged around them. Nothing
here re-encodes anything, which is also what strypt itself refuses to do.

The lossless base is 25 bytes of payload — an odd length, so it carries the RIFF padding byte
(RFC 9649 section 2.3). That is deliberate: a handler that dropped the pad when copying a chunk
through would shift every chunk after it by one byte, and no fixture with an even payload would
ever catch it.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker. One deliberate exception is prefixed ``PRESERVED-`` instead: it lives in an animation
frame strypt cannot parse and therefore keeps on purpose, so it must not be swept up by the
test that asserts no ``SYNTHETIC`` marker survives.
"""

import base64
import pathlib
import sys

# The TIFF builder is shared with the JPEG fixtures rather than copied: a WebP ``EXIF`` chunk
# holds exactly the block a JPEG ``APP1`` holds, minus the introducer, and two copies of that
# layout logic would drift.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from make_jpeg_fixtures import ascii_tag, tiff  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parents[1] / "webp"

# 16x16, encoded once with `cwebp -lossless -exact` and `cwebp -q 80` respectively. Committed
# as literals so that regenerating the corpus never depends on an encoder's version-to-version
# output. Both are simple-format files: a bare RIFF header and one bitstream chunk.
BASE_LOSSLESS = base64.b64decode(
    "UklGRiYAAABXRUJQVlA4TBkAAAAvD8ADAM1VIKL/ASJtm83B/Bs+PI2IpOVdAA=="
)
BASE_LOSSY = base64.b64decode(
    "UklGRjgAAABXRUJQVlA4ICwAAACwAQCdASoQABAAAUAmJaQAAh2+xqAAAP7+k0q/+AnxNvn"
    "+Onxkl6HEA8AAAA=="
)

CANVAS = 16

# VP8X flag bits, numbered from the most significant bit as RFC 9649 section 2.7 numbers them:
# two reserved bits, then ICC, alpha, Exif, XMP, animation, and one more reserved bit.
ICC = 0b0010_0000
ALPHA = 0b0001_0000
EXIF = 0b0000_1000
XMP = 0b0000_0100
ANIM = 0b0000_0010


def chunk(kind: bytes, data: bytes) -> bytes:
    """One chunk: a four-character code, a little-endian size, the payload, and — when the
    size is odd — the single zero padding byte RIFF requires (section 2.3)."""
    return kind + len(data).to_bytes(4, "little") + data + (b"\x00" if len(data) % 2 else b"")


def build(*chunks: bytes) -> bytes:
    """A RIFF/WEBP container around `chunks`.

    The declared size counts the ``WEBP`` form type and everything after it, but not the eight
    bytes of the RIFF header itself.
    """
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + len(body).to_bytes(4, "little") + body


def bitstream(base: bytes) -> bytes:
    """The single image chunk out of a simple-format base file, padding byte included."""
    return base[12:]


def vp8x(flags: int) -> bytes:
    """The extended-format header: flags, three reserved bytes, and the canvas width and
    height as 24-bit values, each stored minus one (section 2.7)."""
    payload = bytes([flags, 0, 0, 0])
    payload += (CANVAS - 1).to_bytes(3, "little") + (CANVAS - 1).to_bytes(3, "little")
    return chunk(b"VP8X", payload)


def anmf(*sub_chunks: bytes) -> bytes:
    """One animation frame: sixteen bytes of position, size, duration, and flags, then the
    frame's own sub-chunks (section 2.7.1.1)."""
    header = (0).to_bytes(3, "little") + (0).to_bytes(3, "little")
    header += (CANVAS - 1).to_bytes(3, "little") + (CANVAS - 1).to_bytes(3, "little")
    header += (100).to_bytes(3, "little") + bytes([0])
    return chunk(b"ANMF", header + b"".join(sub_chunks))


def anim() -> bytes:
    """The animation's global parameters: background colour and loop count. Names nobody."""
    return chunk(b"ANIM", (0).to_bytes(4, "little") + (0).to_bytes(2, "little"))


RATIONAL = lambda *values: b"".join(  # noqa: E731
    n.to_bytes(4, "little") + (1).to_bytes(4, "little") for n in values
)

EXIF_BLOCK = tiff(
    ifd0=[
        ascii_tag(0x010F, b"SYNTHETIC-WEBP-CAMERA-MAKE-0001"),
        ascii_tag(0x0110, b"SYNTHETIC-WEBP-CAMERA-MODEL-0002"),
        ascii_tag(0x0132, b"2026:08:19 12:30:45"),
    ],
    gps=[
        ascii_tag(0x0001, b"N"),
        # 51/1 30/1 0/1 — a coordinate that names a city centre and nobody's home.
        (0x0002, 5, 3, RATIONAL(51, 30, 0)),
        ascii_tag(0x0003, b"W"),
        (0x0004, 5, 3, RATIONAL(0, 7, 0)),
    ],
)

XMP_PACKET = (
    b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
    b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about="" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
    b'xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">'
    b"<dc:creator><rdf:Seq><rdf:li>SYNTHETIC-WEBP-XMP-CREATOR-0003"
    b"</rdf:li></rdf:Seq></dc:creator>"
    b"<xmp:CreatorTool>SYNTHETIC-WEBP-XMP-TOOL-0004</xmp:CreatorTool>"
    b"<xmpMM:DocumentID>uuid:SYNTHETIC-WEBP-DOCUMENT-ID-0005</xmpMM:DocumentID>"
    b'</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
)

# An ICC profile's own tags carry the vendor, the model, and the calibration date. strypt does
# not read inside one — it removes the chunk whole — so the body only needs to be identifiable.
ICC_PROFILE = b"SYNTHETIC-WEBP-ICC-PROFILE-0006" + b"\x00" * 97


def write(name: str, data: bytes) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"{path.relative_to(OUT.parents[1])}: {len(data)} bytes")


def malformed() -> None:
    """Deliberately broken files. Each is a shape a real parser bug would hide behind."""
    valid = build(vp8x(EXIF), bitstream(BASE_LOSSLESS), chunk(b"EXIF", EXIF_BLOCK))

    # A RIFF size claiming more bytes than the file holds. A parser that clamped it to the real
    # length would silently parse a different extent than the file declares and report on it.
    past_end = bytearray(valid)
    past_end[4:8] = (0x0010_0000).to_bytes(4, "little")
    write("malformed/riff-size-past-end.webp", bytes(past_end))

    # A chunk claiming more than the RIFF size says is left. Same lie, one level down.
    lying_chunk = build(
        vp8x(EXIF),
        bitstream(BASE_LOSSLESS),
        b"EXIF" + (0x0010_0000).to_bytes(4, "little") + b"II\x2a\x00",
    )
    write("malformed/chunk-size-past-end.webp", lying_chunk)

    # No bitstream and no frame. Stripping this would leave a valid-looking container with no
    # picture in it, reported as a success — so it is refused instead.
    write("malformed/no-picture-chunk.webp", build(vp8x(EXIF), chunk(b"EXIF", EXIF_BLOCK)))

    # A four-character code that is not ASCII. A code is ASCII by definition, so this means the
    # walk has lost its place and continuing would slice arbitrary bytes out of the file.
    write(
        "malformed/bad-fourcc.webp",
        build(vp8x(0), bitstream(BASE_LOSSLESS), chunk(b"\x00\x01\x02\x03", b"")),
    )

    # Ends mid-chunk. strypt refuses rather than completing it: handing back a repaired copy of
    # a damaged file, presented as a clean version of it, is not something a user asked for.
    write("malformed/truncated.webp", valid[: len(valid) - 20])

    # A VP8X of the wrong length. Section 2.7 fixes it at ten bytes, so the flags byte and the
    # canvas dimensions are not where the specification puts them and must not be guessed at.
    write(
        "malformed/vp8x-wrong-length.webp",
        build(chunk(b"VP8X", b"\x00" * 8), bitstream(BASE_LOSSLESS)),
    )

    # Metadata before the header chunk. Section 2.7 opens an extended file with VP8X and a
    # simple file with a bitstream; anything else is a shape strypt has not understood.
    write(
        "malformed/first-chunk-is-metadata.webp",
        build(chunk(b"EXIF", EXIF_BLOCK), bitstream(BASE_LOSSLESS)),
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    lossless = bitstream(BASE_LOSSLESS)

    # 1. The ordinary case for a photograph: a camera's Exif block, GPS included.
    write("exif-gps.webp", build(vp8x(EXIF), lossless, chunk(b"EXIF", EXIF_BLOCK)))

    # 2. An XMP packet — the fuller record, with the editing tool and a document identifier
    # that links every copy and every revision of one image to each other.
    write("xmp-packet.webp", build(vp8x(XMP), lossless, chunk(b"XMP ", XMP_PACKET)))

    # 3. An embedded ICC profile. A per-device profile is a fingerprint.
    write("icc-profile.webp", build(vp8x(ICC), chunk(b"ICCP", ICC_PROFILE), lossless))

    # 4. All three at once, with the alpha bit also set so the test can prove that clearing the
    # metadata flags leaves the flags describing the picture alone.
    write(
        "all-metadata.webp",
        build(
            vp8x(ICC | ALPHA | EXIF | XMP),
            chunk(b"ICCP", ICC_PROFILE),
            lossless,
            chunk(b"EXIF", EXIF_BLOCK),
            chunk(b"XMP ", XMP_PACKET),
        ),
    )

    # 5. A chunk strypt does not know. RFC 9649 section 2.7.1.6 asks writers to preserve these;
    # strypt removes them, because an unknown chunk can hold anything and the same section
    # makes them ignorable, so dropping one cannot break a decoder.
    write(
        "unknown-chunk.webp",
        build(vp8x(0), lossless, chunk(b"PRVW", b"SYNTHETIC-WEBP-PREVIEW-0007")),
    )

    # 6. An animation whose frames must survive untouched, carrying an Exif block that must not.
    write(
        "animated.webp",
        build(
            vp8x(ANIM | EXIF),
            anim(),
            anmf(lossless),
            anmf(lossless),
            chunk(b"EXIF", EXIF_BLOCK),
        ),
    )

    # 7. A chunk hidden inside an animation frame. Section 2.7.1.1 explicitly allows unknown
    # chunks there, which makes the inside of a frame a hiding place with the specification's
    # blessing — so strypt filters a frame's sub-chunks the same way it filters the top level.
    write(
        "animation-frame-chunk.webp",
        build(
            vp8x(ANIM),
            anim(),
            anmf(lossless, chunk(b"JUNK", b"SYNTHETIC-WEBP-IN-FRAME-0008")),
        ),
    )

    # 8. A frame whose sub-chunk area does not parse: a length running past the end of the
    # frame. strypt keeps the frame exactly as it arrived and says the bytes went unexamined,
    # rather than half-parsing it or refusing the whole file.
    broken_frame = (
        (0).to_bytes(3, "little")
        + (0).to_bytes(3, "little")
        + (CANVAS - 1).to_bytes(3, "little")
        + (CANVAS - 1).to_bytes(3, "little")
        + (100).to_bytes(3, "little")
        + bytes([0])
        + b"VP8L\xff\xff\xff\xffPRESERVED-WEBP-IN-BROKEN-FRAME-0009"
    )
    write(
        "unparsable-frame.webp",
        build(vp8x(ANIM), anim(), chunk(b"ANMF", broken_frame)),
    )

    # 9. A whole second WebP file after the RIFF chunk the header declares. Nothing reads past
    # that boundary and few users know anything can be there, which is what makes it a good
    # hiding place for an uncropped copy of a cropped picture.
    write(
        "trailing-data.webp",
        build(vp8x(0), lossless) + build(vp8x(XMP), lossless, chunk(b"XMP ", XMP_PACKET)),
    )

    # 10. Flags that were already lying: the header claims an ICC profile, Exif, and XMP that
    # the file does not have. There is nothing to remove, and strypt still hands back a file
    # that tells the truth about itself.
    write("stale-flags.webp", build(vp8x(ICC | EXIF | XMP), lossless))

    # 11. An Exif chunk written with JPEG's `Exif\0\0` introducer, which the container
    # specification does not put here. Six extra bytes shift every offset inside the TIFF
    # block, so a reader that does not notice produces a confident parse of the wrong bytes.
    write(
        "exif-introducer.webp",
        build(vp8x(EXIF), lossless, chunk(b"EXIF", b"Exif\x00\x00" + EXIF_BLOCK)),
    )

    # 12-14. Nothing to find. The two simple-format files cannot carry metadata at all —
    # section 2.7 requires a VP8X header before any of the three metadata chunks — so they are
    # a guaranteed byte-identical pass-through rather than merely a file with nothing in it.
    # The extended one proves the same for a VP8X whose flags describe only the picture.
    write("clean-lossless.webp", BASE_LOSSLESS)
    write("clean-lossy.webp", BASE_LOSSY)
    write("clean-extended.webp", build(vp8x(0), lossless))

    malformed()


if __name__ == "__main__":
    main()
