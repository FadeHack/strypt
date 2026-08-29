#!/usr/bin/env python3
"""Generate the JPEG XL fixtures in ``corpus/jxl``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design.

**The codestream in these fixtures is a header, not a picture.** Every other image generator here
either synthesises a decodable image or embeds a recorded codestream, because mat2 reaches those
formats through a decoder. JPEG XL is the exception in exactly the way that matters: mat2's
``JXLParser`` is an ``ExiftoolParser`` running ``_lightweight_cleanup()``, so the comparison tool
reads the box layer and never decodes either. The stub below is a valid ISO/IEC 18181-1 section
9.1 signature plus a ``SizeHeader`` and an all-default ``ImageMetadata`` — enough that ExifTool
reports 8x8 and identifies the file — and nothing after it. strypt never enters the codestream
(ADR-0036), so no fixture here needs one.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "jxl"
MALFORMED = OUT / "malformed"

# ISO/IEC 18181-2 section 5.2: length 12, type `JXL `, then the same CR-LF-EOF-LF tail PNG uses.
SIGNATURE = b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a"


def bare_codestream():
    """A signature plus the smallest legal header: an 8x8 image, everything else defaulted.

    Bit packing is LSB-first (ISO/IEC 18181-1 section 3). ``div8`` says the height is a multiple
    of eight, ``ratio`` 1 makes the width equal it, and ``all_default`` takes every remaining
    ``ImageMetadata`` field — bit depth, colour encoding, orientation, preview, animation — at its
    default.
    """
    bits = []

    def write(value, count):
        for i in range(count):
            bits.append((value >> i) & 1)

    write(1, 1)  # SizeHeader: div8
    write(0, 5)  # ysize_div8 - 1, so 8 pixels
    write(1, 3)  # ratio 1:1
    write(1, 1)  # ImageMetadata: all_default
    while len(bits) % 8:
        bits.append(0)
    packed = bytearray()
    for i in range(0, len(bits), 8):
        packed.append(sum(bit << j for j, bit in enumerate(bits[i : i + 8])))
    return b"\xff\x0a" + bytes(packed)


CODESTREAM = bare_codestream() + b"\x00" * 8


def box(kind, payload):
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def box_to_end(kind, payload):
    """A box declaring size 0: it runs to the end of the file (section 4.2). Legal for the last."""
    return b"\x00\x00\x00\x00" + kind + payload


def ftyp(brand=b"jxl "):
    return box(b"ftyp", brand + b"\x00\x00\x00\x00" + b"jxl ")


def container(*boxes, brand=b"jxl "):
    return SIGNATURE + ftyp(brand) + b"".join(boxes)


def jxlc():
    return box(b"jxlc", CODESTREAM)


def tiff_ifd(entries):
    """A little-endian TIFF structure: header, one IFD, then the values it points at."""
    header = b"II\x2a\x00" + struct.pack("<I", 8)
    count = len(entries)
    # Header, entry count, entries, and the next-IFD offset all precede the value area.
    values_at = 8 + 2 + count * 12 + 4
    directory = struct.pack("<H", count)
    values = b""
    for tag, field_type, value in entries:
        if isinstance(value, bytes):
            payload = value
            length = len(payload)
            if length <= 4:
                directory += struct.pack("<HHI", tag, field_type, length) + payload.ljust(4, b"\x00")
            else:
                directory += struct.pack("<HHII", tag, field_type, length, values_at + len(values))
                values += payload
        else:
            directory += struct.pack("<HHII", tag, field_type, 1, value)
    return header + directory + struct.pack("<I", 0) + values


def exif_box(payload):
    """Section 5.3: the payload opens with a four-byte offset to the TIFF header."""
    return box(b"Exif", struct.pack(">I", 0) + payload)


EXIF = tiff_ifd(
    [
        (0x010E, 2, b"SYNTHETIC-DESCRIPTION-0001\x00"),  # ImageDescription
        (0x010F, 2, b"SYNTHETIC-CAMERA-MAKE-0002\x00"),  # Make
        (0x0110, 2, b"SYNTHETIC-CAMERA-MODEL-0003\x00"),  # Model
        (0x0131, 2, b"SYNTHETIC-SOFTWARE-0004\x00"),  # Software
        (0x013B, 2, b"SYNTHETIC-ARTIST-0005\x00"),  # Artist
        (0x0132, 2, b"2019:01:02 03:04:05\x00"),  # DateTime
    ]
)

XMP = (
    b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"'
    b' xmlns:dc="http://purl.org/dc/elements/1.1/"'
    b' xmlns:xmp="http://ns.adobe.com/xap/1.0/">'
    b"<rdf:Description>"
    b"<dc:creator>SYNTHETIC-XMP-CREATOR-0006</dc:creator>"
    b"<xmp:CreatorTool>SYNTHETIC-XMP-TOOL-0007</xmp:CreatorTool>"
    b"<xmp:CreateDate>2019-01-02T03:04:05</xmp:CreateDate>"
    b"</rdf:Description></rdf:RDF></x:xmpmeta>"
    b'<?xpacket end="w"?>'
)

# A JUMBF superbox: a description box naming the C2PA manifest, then its content. Real C2PA
# carries the capture device, the edit history, and the signing identity.
JUMBF = box(
    b"jumb",
    box(b"jumd", b"c2pa" + b"\x00" * 12 + b"\x03" + b"c2pa/SYNTHETIC-MANIFEST-0008\x00")
    + box(b"json", b'{"claim_generator":"SYNTHETIC-C2PA-GENERATOR-0009"}'),
)[8:]

# `brob` names the box it wraps in its first four bytes, and the rest is a Brotli stream. It is
# **not** valid Brotli here and does not need to be: nothing in this project inflates it, because
# a box that is being deleted does not have to be read first (ADR-0036 section 4).
BROB = b"Exif" + b"\x1b\x2a\x00SYNTHETIC-BROTLI-PAYLOAD-0010"

# `jbrd` holds what libjxl's `JPEGData` needs to rebuild the original JPEG bit-exactly, including
# its `app_data` and `com_data` — that file's APPn and COM marker segments, verbatim.
JBRD = b"\x01\x00\x0a" + b"\xff\xfeSYNTHETIC-JPEG-COMMENT-0011\x00" + b"\xff\xee\x00\x0eAdobe\x00d\x80"

# An index of keyframe offsets: not needed to display an animation, and it indexes a file strypt
# is editing, so it goes (ADR-0036 section 6).
JXLI = struct.pack(">IIQQI", 0, 1, 0, 0, 1000)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT.parent)}  ({len(data)} bytes)")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)
    print("JPEG XL fixtures:")

    # The baseline. A deletion-edited format can promise a clean file comes back byte-identical,
    # and this is the fixture that holds that promise in place.
    write(OUT / "clean.jxl", container(jxlc()))

    # The other spelling, which has no box layer at all: accepted, reported clean, returned
    # unchanged, with the report saying the codestream was not entered (ADR-0036 section 2).
    write(OUT / "bare-codestream.jxl", CODESTREAM)

    write(OUT / "exif.jxl", container(exif_box(EXIF), jxlc()))
    write(OUT / "xmp.jxl", container(box(b"xml ", XMP), jxlc()))
    write(OUT / "jumbf.jxl", container(box(b"jumb", JUMBF), jxlc()))
    write(OUT / "brotli-compressed.jxl", container(box(b"brob", BROB), jxlc()))
    write(OUT / "jpeg-reconstruction.jxl", container(box(b"jbrd", JBRD), exif_box(EXIF), jxlc()))
    write(OUT / "frame-index.jxl", container(box(b"jxli", JXLI), jxlc()))

    # Padding boxes are ignorable by definition, which makes them a place to keep something.
    write(
        OUT / "padding.jxl",
        container(box(b"free", b"SYNTHETIC-FREE-BOX-0012"), jxlc(), box(b"skip", b"SYNTHETIC-SKIP-BOX-0013")),
    )

    # A level box and a codestream split across two partial boxes: both kept, both copied byte for
    # byte, with metadata removed from between them.
    half = len(CODESTREAM) // 2
    write(
        OUT / "level-and-partial-codestream.jxl",
        container(
            box(b"jxll", b"\x05"),
            box(b"jxlp", struct.pack(">I", 0) + CODESTREAM[:half]),
            exif_box(EXIF),
            box(b"jxlp", struct.pack(">I", 0x80000001) + CODESTREAM[half:]),
        ),
    )

    # Section 4.2's size-0 box: it runs to the end of the file. Deletion preserves that meaning,
    # because nothing is ever inserted after it.
    write(OUT / "size-zero-final.jxl", container(exif_box(EXIF), box_to_end(b"jxlc", CODESTREAM)))

    # Metadata after the codestream rather than before it, which is where a tool that appended it
    # to a finished file puts it.
    write(OUT / "metadata-after-codestream.jxl", container(jxlc(), exif_box(EXIF), box(b"xml ", XMP)))

    write(
        OUT / "kitchen-sink.jxl",
        container(
            box(b"jxll", b"\x05"),
            exif_box(EXIF),
            box(b"xml ", XMP),
            box(b"jumb", JUMBF),
            box(b"brob", BROB),
            box(b"jbrd", JBRD),
            box(b"jxli", JXLI),
            box(b"free", b"SYNTHETIC-FREE-BOX-0012"),
            jxlc(),
        ),
    )

    # An unknown top-level box. Refused rather than copied through: in a format that keeps its
    # metadata in top-level boxes, an unrecognised one is more likely to be metadata than not.
    write(
        MALFORMED / "unknown-box.jxl",
        container(box(b"vndr", b"SYNTHETIC-UNKNOWN-BOX-0015"), jxlc()),
    )

    # The signature box is fixed by section 5.2. A file starting with something else is refused
    # rather than scanned for boxes on a guess about what it is.
    write(MALFORMED / "no-signature.jxl", ftyp() + jxlc())
    write(MALFORMED / "wrong-brand.jxl", container(jxlc(), brand=b"jpeg"))
    write(MALFORMED / "signature-wrong-length.jxl", box(b"JXL ", b"\x0d\x0a\x87\x0a\x00") + ftyp() + jxlc())

    # Bytes after the last box. The format has no terminator, so this is either a truncated box
    # or something appended — refused either way, unlike GIF, whose §27 trailer defines an end.
    write(MALFORMED / "trailing-data.jxl", container(jxlc()) + b"SYNTHETIC-TRAILING-DATA-0014")

    # A container with no codestream at all: not an image, and not a file to report success on.
    write(MALFORMED / "no-codestream.jxl", container(exif_box(EXIF)))

    # A box declaring more bytes than the file holds.
    overrun = container(exif_box(EXIF), jxlc())
    write(MALFORMED / "box-overruns-file.jxl", overrun[:-4])

    # A box whose declared size is smaller than its own header: the non-termination case.
    write(MALFORMED / "box-size-below-header.jxl", SIGNATURE + ftyp() + b"\x00\x00\x00\x04jxlc")

    # An Exif box whose TIFF-header offset points past the end of its own payload. Reported as an
    # unparsed region and removed anyway — it is an Exif box either way.
    write(
        MALFORMED / "exif-offset-past-end.jxl",
        container(box(b"Exif", struct.pack(">I", 0xFFFF) + EXIF), jxlc()),
    )


if __name__ == "__main__":
    sys.exit(main())
