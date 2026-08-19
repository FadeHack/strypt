#!/usr/bin/env python3
"""Generate the JPEG fixtures in ``corpus/jpeg``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with Pillow installed is a corpus nobody regenerates.

Every fixture is a **real, decodable JPEG**. The base image below was encoded once with
libjpeg-turbo's ``cjpeg`` and is committed here as a literal so that this script needs no
encoder; the fixtures are that image with metadata segments spliced in around it. Nothing here
re-encodes anything, which is also what strypt itself refuses to do.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-…-000N``
marker, so a test can assert on the bytes of strypt's *output* rather than on strypt's own
report — a handler that forgot to remove something would still report having removed it.
"""

import base64
import pathlib

OUT = pathlib.Path(__file__).resolve().parents[1] / "jpeg"

# A 16×16 greyscale gradient, quality 60, encoded once with `cjpeg -optimize -grayscale`.
# Segments: APP0 (JFIF, no thumbnail), DQT, SOF0, two DHTs, SOS, entropy data, EOI.
BASE = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA0JCgsKCA0LCgsODg0PEyAVExISEyccHhcgLikxMC4p"
    "LSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//wAALCAAQABABAREA/8QAFgABAQEAAAAA"
    "AAAAAAAAAAAAAAYH/8QAFxAAAwEAAAAAAAAAAAAAAAAAABViof/aAAgBAQAAPwCVQRgQRhqiCMCC"
    "MP/Z"
)

THUMB = object()  # sentinel: "the offset the thumbnail ended up at"

SOI = b"\xff\xd8"
EOI = b"\xff\xd9"


def segment(marker: int, payload: bytes) -> bytes:
    """One marker segment: FF, marker, length including itself, payload."""
    return bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def split_base() -> tuple[bytes, bytes]:
    """The base image as (leading APP0 segment, everything after it)."""
    app0_length = int.from_bytes(BASE[4:6], "big")
    end = 4 + app0_length
    return BASE[2:end], BASE[end:]


def build(extra: bytes = b"", *, app0: bytes | None = None, trailing: bytes = b"") -> bytes:
    """The base image with `extra` segments inserted straight after the APP0 header."""
    base_app0, rest = split_base()
    return SOI + (base_app0 if app0 is None else app0) + extra + rest + trailing


def tiff(ifd0, exif=None, gps=None, thumbnail=None):
    """A little-endian TIFF block: IFD0, an optional thumbnail IFD1, and sub-directories.

    Every value longer than four bytes is stored out of line, at an absolute offset from the
    start of this block — which is what makes a TIFF a graph rather than a list, and why
    strypt removes the whole block instead of editing tags out of one.
    """
    header = b"II\x2a\x00" + (8).to_bytes(4, "little")

    pointers = []
    entry_count = len(ifd0) + (1 if exif else 0) + (1 if gps else 0)
    offset = len(header)
    offset += 2 + 12 * entry_count + 4

    ifd1 = []
    ifd1_offset = 0
    if thumbnail is not None:
        # 0x0201 JPEGInterchangeFormat, 0x0202 JPEGInterchangeFormatLength.
        ifd1 = [(0x0201, 4, 1, THUMB), (0x0202, 4, 1, len(thumbnail))]
        ifd1_offset = offset
        offset += 2 + 12 * len(ifd1) + 4

    exif_offset = 0
    if exif:
        exif_offset = offset
        offset += 2 + 12 * len(exif) + 4
    gps_offset = 0
    if gps:
        gps_offset = offset
        offset += 2 + 12 * len(gps) + 4

    values_offset = offset
    values = bytearray()
    thumbnail_at = values_offset
    if thumbnail is not None:
        values += thumbnail
        if len(values) % 2:
            values.append(0)

    def pack(entries, next_ifd):
        out = len(entries).to_bytes(2, "little")
        for tag, field_type, count, value in entries:
            out += tag.to_bytes(2, "little")
            out += field_type.to_bytes(2, "little")
            out += count.to_bytes(4, "little")
            if value is THUMB:
                out += thumbnail_at.to_bytes(4, "little")
            elif isinstance(value, int):
                out += value.to_bytes(4, "little")
            elif len(value) <= 4:
                # TIFF 6.0 §2: a value of four bytes or fewer lives in the entry itself. Real
                # encoders do this, and a reader is entitled to expect it — a two-byte string
                # written out of line is read as an offset by anything conformant.
                out += value.ljust(4, b"\x00")
            else:
                out += (values_offset + len(values)).to_bytes(4, "little")
                values.extend(value)
                if len(values) % 2:
                    values.append(0)
        return out + next_ifd.to_bytes(4, "little")

    if exif:
        pointers.append((0x8769, 4, 1, exif_offset))
    if gps:
        pointers.append((0x8825, 4, 1, gps_offset))

    block = header + pack(list(ifd0) + pointers, ifd1_offset)
    if ifd1:
        block += pack(ifd1, 0)
    if exif:
        block += pack(exif, 0)
    if gps:
        block += pack(gps, 0)
    return block + bytes(values)


def ascii_tag(tag: int, text: bytes) -> tuple:
    return (tag, 2, len(text) + 1, text + b"\x00")


def write(name: str, data: bytes) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def malformed() -> None:
    """Files that are deliberately broken, for the fuzzer to start from and for the handler
    to refuse.

    A seed corpus of nothing but valid files teaches the fuzzer that files are valid, and it
    spends its budget rediscovering the ways they are not (`docs/TESTING_STRATEGY.md` §2.4).
    Each of these is a shape that a real parser bug would hide behind.
    """
    base_app0, rest = split_base()

    # A segment whose declared length runs past the end of the file.
    write("malformed/length-past-end.jpg",
          SOI + base_app0 + b"\xff\xe1\xff\xf0" + b"Exif\x00\x00II*\x00" + rest)

    # A declared length below the two bytes the length field itself occupies. Subtracting
    # without a check wraps to 65534.
    write("malformed/length-below-minimum.jpg",
          SOI + base_app0 + b"\xff\xe1\x00\x00" + rest)

    # An Exif pointer that points back at IFD0: a legal-looking cycle.
    cycle = b"II\x2a\x00" + (8).to_bytes(4, "little")
    cycle += (1).to_bytes(2, "little")
    cycle += (0x8769).to_bytes(2, "little") + (4).to_bytes(2, "little")
    cycle += (1).to_bytes(4, "little") + (8).to_bytes(4, "little")
    cycle += (0).to_bytes(4, "little")
    write("malformed/exif-cycle.jpg",
          build(segment(0xE1, b"Exif\x00\x00" + cycle)))

    # A tag claiming four billion components, at an offset near the end of the address space.
    huge = b"II\x2a\x00" + (8).to_bytes(4, "little")
    huge += (1).to_bytes(2, "little")
    huge += (0x013B).to_bytes(2, "little") + (2).to_bytes(2, "little")
    huge += (0xFFFFFFFF).to_bytes(4, "little") + (0xFFFFFFF0).to_bytes(4, "little")
    huge += (0).to_bytes(4, "little")
    write("malformed/exif-huge-count.jpg",
          build(segment(0xE1, b"Exif\x00\x00" + huge)))

    # A file that simply stops, with no end-of-image marker.
    write("malformed/no-eoi.jpg", build()[:-2])

    # A long run of fill bytes before a marker. Legal (T.81 §B.1.1.2) and rarely exercised.
    write("malformed/fill-byte-run.jpg",
          SOI + base_app0 + b"\xff" * 64 + b"\xfe\x00\x06fill" + rest)

    # An Exif block whose TIFF header is not a TIFF header at all.
    write("malformed/exif-not-tiff.jpg",
          build(segment(0xE1, b"Exif\x00\x00" + b"not a tiff header")))


def main() -> None:
    # 1. The baseline case: what a phone photograph carries.
    exif = tiff(
        ifd0=[
            ascii_tag(0x010F, b"SYNTHETIC-CAMERA-MAKE-0001"),
            ascii_tag(0x0110, b"SYNTHETIC-CAMERA-MODEL-0002"),
            ascii_tag(0x0131, b"SYNTHETIC-SOFTWARE-0003"),
            ascii_tag(0x013B, b"SYNTHETIC-ARTIST-0004"),
            ascii_tag(0x0132, b"2026:01:01 00:00:00"),
        ],
        exif=[
            ascii_tag(0x9003, b"2026:01:01 00:00:00"),
            ascii_tag(0xA431, b"SYNTHETIC-BODY-SERIAL-0005"),
            # UserComment is UNDEFINED, not ASCII: the first eight bytes name the character
            # set. Writing it as ASCII is a common producer bug and makes ExifTool warn.
            (0x9286, 7, 8 + 27, b"ASCII\x00\x00\x00SYNTHETIC-USER-COMMENT-0006\x00"),
        ],
        gps=[
            ascii_tag(0x0001, b"N"),
            # Three RATIONALs: degrees, minutes, seconds. 51/1 30/1 0/1 — a coordinate that
            # names a city centre and nobody's home.
            (0x0002, 5, 3, b"".join(
                n.to_bytes(4, "little") + (1).to_bytes(4, "little") for n in (51, 30, 0))),
            ascii_tag(0x0003, b"W"),
            (0x0004, 5, 3, b"".join(
                n.to_bytes(4, "little") + (1).to_bytes(4, "little") for n in (0, 7, 0))),
        ],
    )
    write("exif-gps.jpg", build(segment(0xE1, b"Exif\x00\x00" + exif)))

    # 2. An Exif thumbnail: a second, complete image inside the first. It is made from the
    # base image with a comment spliced in, so a test can assert that the *thumbnail's* bytes
    # are gone rather than merely that IFD1 is.
    thumbnail = build(segment(0xFE, b"SYNTHETIC-THUMBNAIL-0007"))
    with_thumb = tiff(
        ifd0=[ascii_tag(0x010F, b"SYNTHETIC-CAMERA-MAKE-0001")],
        thumbnail=thumbnail,
    )
    write("exif-thumbnail.jpg", build(segment(0xE1, b"Exif\x00\x00" + with_thumb)))

    # 3. An XMP packet, which carries a fuller record than Exif does and links every copy of
    # the file through its document identifier.
    packet = (
        b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description rdf:about="" '
        b'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
        b'xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/">'
        b"<dc:creator><rdf:Seq><rdf:li>SYNTHETIC-XMP-CREATOR-0008"
        b"</rdf:li></rdf:Seq></dc:creator>"
        b"<xmp:CreatorTool>SYNTHETIC-XMP-TOOL-0009</xmp:CreatorTool>"
        b"<xmpMM:DocumentID>uuid:SYNTHETIC-DOCUMENT-ID-0010</xmpMM:DocumentID>"
        b"</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
    )
    write(
        "xmp-packet.jpg",
        build(segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + packet)),
    )

    # 4. A comment segment: free text, written by a person, in a slot nothing displays.
    write("comment.jpg", build(segment(0xFE, b"SYNTHETIC-COMMENT-0011")))

    # 5. Photoshop image resources, which is where IPTC by-line and location fields live.
    iptc = (
        b"\x1c\x02\x50" + len(b"SYNTHETIC-BYLINE-0012").to_bytes(2, "big")
        + b"SYNTHETIC-BYLINE-0012"
        + b"\x1c\x02\x5a" + len(b"SYNTHETIC-CITY-0013").to_bytes(2, "big")
        + b"SYNTHETIC-CITY-0013"
    )
    irb = b"8BIM\x04\x04\x00\x00" + len(iptc).to_bytes(4, "big") + iptc
    if len(irb) % 2:
        irb += b"\x00"
    write("photoshop-iptc.jpg", build(segment(0xED, b"Photoshop 3.0\x00" + irb)))

    # 6. An ICC profile. Removing it changes how a wide-gamut image renders, and it is removed
    # anyway: profile descriptions routinely name the device or vendor that made them.
    profile = (
        (128 + 12 + 20).to_bytes(4, "big") + b"SYNTHETIC-ICC-VENDOR-0014"
        + b"\x00" * (128 - 4 - 25)
        + (1).to_bytes(4, "big") + b"desc" + (12).to_bytes(4, "big")
        + (20).to_bytes(4, "big") + b"SYNTHETIC-DEVICE-0015"[:20]
    )
    write("icc-profile.jpg", build(segment(0xE2, b"ICC_PROFILE\x00\x01\x01" + profile)))

    # 7. A JFIF thumbnail: 3×3 uncompressed RGB inside the APP0 header itself. The header is
    # kept and the thumbnail is not, so this fixture tests a rewrite rather than a removal.
    thumb_rgb = b"SYNTHETIC-JFIF-THUMB-0016xy"[:27]
    jfif = b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01" + bytes([3, 3]) + thumb_rgb
    write("jfif-thumbnail.jpg", build(app0=segment(0xE0, jfif)))

    # 8. The Adobe colour-transform marker, which is kept on purpose and declared as kept.
    write("adobe-marker.jpg", build(segment(0xEE, b"Adobe\x00\x64\x00\x00\x00\x00\x02")))

    # 9. A whole second image after the EOI marker — where a phone's multi-picture extension
    # keeps a full-resolution frame. No viewer shows it; every forensic tool finds it.
    second = build(segment(0xFE, b"SYNTHETIC-SECOND-IMAGE-0017"))
    write("trailing-data.jpg", build(trailing=second))

    # 10. Nothing to find. A tool that invents findings teaches users to ignore it.
    write("clean.jpg", build())

    malformed()


if __name__ == "__main__":
    main()
