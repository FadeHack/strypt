#!/usr/bin/env python3
"""Generate the TIFF fixtures in ``corpus/tiff``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with a particular imaging library installed is a corpus nobody
regenerates.

Every fixture is a **structurally real TIFF**: a byte-order mark and the magic number 42
(TIFF 6.0 section 2), a directory whose entries are sorted ascending by tag as that section
requires, and strips of image data the directory actually points at. They are minimal rather
than rich — a fixture exists to exercise one decision in the handler, and a fixture carrying a
photograph's worth of unrelated tags makes it harder to see which byte the test is about.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report —
a handler that forgot to remove something would still cheerfully report having removed it.

The pixel payload of every fixture is the same marker, ``PRESERVED-TIFF-PIXELS``, so a test can
assert that the image data crossed the rebuild byte for byte (ADR-0033).
"""

import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "tiff"
MALFORMED = OUT / "malformed"

# The image data every fixture carries. Twenty bytes, so a single strip is comfortably
# out-of-line and the "did the picture survive" assertion has something unmistakable to find.
PIXELS = b"PRESERVED-TIFF-PIXELS"

BYTE, ASCII, SHORT, LONG, RATIONAL, UNDEFINED = 1, 2, 3, 4, 5, 7

TYPE_SIZE = {BYTE: 1, ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8, UNDEFINED: 1}

# Tags used below, by name, so the fixtures read as documents rather than as hex.
NEW_SUBFILE_TYPE = 0x00FE
IMAGE_WIDTH = 0x0100
IMAGE_LENGTH = 0x0101
BITS_PER_SAMPLE = 0x0102
COMPRESSION = 0x0103
PHOTOMETRIC = 0x0106
DOCUMENT_NAME = 0x010D
IMAGE_DESCRIPTION = 0x010E
MAKE = 0x010F
MODEL = 0x0110
STRIP_OFFSETS = 0x0111
SAMPLES_PER_PIXEL = 0x0115
ROWS_PER_STRIP = 0x0116
STRIP_BYTE_COUNTS = 0x0117
PLANAR_CONFIG = 0x011C
SOFTWARE = 0x0131
DATE_TIME = 0x0132
ARTIST = 0x013B
HOST_COMPUTER = 0x013C
COLOR_MAP = 0x0140
XMP = 0x02BC
COPYRIGHT = 0x8298
EXIF_IFD = 0x8769
ICC_PROFILE = 0x8773
IPTC = 0x83BB
GPS_IFD = 0x8825


def ascii_tag(tag, text):
    """An ASCII tag. TIFF 6.0 counts the terminating NUL in the count."""
    value = text.encode("ascii") + b"\0"
    return (tag, ASCII, len(value), value)


def short_tag(tag, *values):
    return (tag, SHORT, len(values), b"".join(struct.pack("<H", v) for v in values))


def long_tag(tag, *values):
    return (tag, LONG, len(values), b"".join(struct.pack("<I", v) for v in values))


def undefined_tag(tag, blob):
    return (tag, UNDEFINED, len(blob), blob)


def structural(width=7, height=3):
    """The tags a reader needs to decode the strips, and nothing more."""
    return [
        short_tag(IMAGE_WIDTH, width),
        short_tag(IMAGE_LENGTH, height),
        short_tag(BITS_PER_SAMPLE, 8),
        short_tag(COMPRESSION, 1),
        short_tag(PHOTOMETRIC, 1),
        short_tag(SAMPLES_PER_PIXEL, 1),
        short_tag(ROWS_PER_STRIP, height),
        short_tag(PLANAR_CONFIG, 1),
    ]


def build(pages, subdirs=None):
    """Write a little-endian TIFF.

    ``pages`` is a list of ``(tags, strips)``. ``subdirs`` maps a placeholder key to a list of
    tags forming a sub-directory (an Exif or GPS IFD); a page tag whose value is that key is
    rewritten into a pointer to it.

    Laid out header, then per page: directory, out-of-line values, strips. Sub-directories go
    last. Every offset is resolved in a second pass, so nothing here depends on the order the
    pieces happen to be built in.
    """
    subdirs = subdirs or {}

    prepared = []
    for tags, strips in pages:
        entries = list(tags)
        entries.append((STRIP_OFFSETS, LONG, len(strips), None))
        entries.append((STRIP_BYTE_COUNTS, LONG, len(strips), None))
        entries.sort(key=lambda e: e[0])
        prepared.append((entries, strips))

    # Pass one: sizes, which fix every offset.
    cursor = 8
    page_at, value_at, data_at = [], [], []
    for entries, strips in prepared:
        page_at.append(cursor)
        cursor += 2 + 12 * len(entries) + 4
        values = []
        for tag, ftype, count, value in entries:
            size = count * TYPE_SIZE[ftype] if value is not None else 4 * len(strips)
            if size > 4:
                values.append(cursor)
                cursor += size + size % 2
            else:
                values.append(None)
        value_at.append(values)
        data = []
        for strip in strips:
            data.append(cursor)
            cursor += len(strip) + len(strip) % 2
        data_at.append(data)

    sub_at = {}
    sub_blocks = {}
    for key, tags in subdirs.items():
        tags = sorted(tags, key=lambda e: e[0])
        sub_at[key] = cursor
        block_start = cursor
        cursor += 2 + 12 * len(tags) + 4
        values = []
        for tag, ftype, count, value in tags:
            size = count * TYPE_SIZE[ftype]
            if size > 4:
                values.append(cursor)
                cursor += size + size % 2
            else:
                values.append(None)
        sub_blocks[key] = (tags, values, block_start)

    # Pass two: bytes.
    out = bytearray(b"II" + struct.pack("<HI", 42, page_at[0]))

    def emit_directory(entries, values, next_offset, strips=None, strip_offsets=None):
        block = bytearray(struct.pack("<H", len(entries)))
        for index, (tag, ftype, count, value) in enumerate(entries):
            if value is None:
                # A regenerated geometry tag: offsets or byte counts.
                if tag == STRIP_OFFSETS:
                    value = b"".join(struct.pack("<I", o) for o in strip_offsets)
                else:
                    value = b"".join(struct.pack("<I", len(s)) for s in strips)
            elif isinstance(value, str):
                # A sub-directory placeholder.
                value = struct.pack("<I", sub_at[value])
            block += struct.pack("<HHI", tag, ftype, count)
            if len(value) <= 4:
                block += value.ljust(4, b"\0")
            else:
                block += struct.pack("<I", values[index])
        block += struct.pack("<I", next_offset)
        tail = bytearray()
        for index, (tag, ftype, count, value) in enumerate(entries):
            if values[index] is None:
                continue
            if value is None:
                if tag == STRIP_OFFSETS:
                    value = b"".join(struct.pack("<I", o) for o in strip_offsets)
                else:
                    value = b"".join(struct.pack("<I", len(s)) for s in strips)
            tail += value
            if len(value) % 2:
                tail += b"\0"
        return block + tail

    for index, (entries, strips) in enumerate(prepared):
        following = page_at[index + 1] if index + 1 < len(prepared) else 0
        out += emit_directory(
            entries, value_at[index], following, strips, data_at[index]
        )
        for strip in strips:
            out += strip
            if len(strip) % 2:
                out += b"\0"

    for key, (tags, values, _) in sub_blocks.items():
        out += emit_directory(tags, values, 0)

    return bytes(out)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT.parent)}  ({len(data)} bytes)")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)
    print("TIFF fixtures:")

    # The baseline: nothing identifying at all. Proves a clean file still rebuilds, and gives
    # the idempotence test something whose second pass must equal its first.
    write(OUT / "clean.tiff", build([(structural(), [PIXELS])]))

    # The ordinary case: the tags a camera or scanner writes.
    write(
        OUT / "identifying-tags.tiff",
        build(
            [
                (
                    structural()
                    + [
                        ascii_tag(MAKE, "SYNTHETIC-MAKE-0001"),
                        ascii_tag(MODEL, "SYNTHETIC-MODEL-0002"),
                        ascii_tag(SOFTWARE, "SYNTHETIC-SOFTWARE-0003"),
                        ascii_tag(ARTIST, "SYNTHETIC-ARTIST-0004"),
                        ascii_tag(DATE_TIME, "2026:08:25 11:04:00"),
                        ascii_tag(HOST_COMPUTER, "SYNTHETIC-HOSTNAME-0005"),
                        ascii_tag(COPYRIGHT, "SYNTHETIC-COPYRIGHT-0006"),
                        ascii_tag(IMAGE_DESCRIPTION, "SYNTHETIC-DESCRIPTION-0007"),
                        ascii_tag(DOCUMENT_NAME, "SYNTHETIC-DOCNAME-0008"),
                    ],
                    [PIXELS],
                )
            ]
        ),
    )

    # A private tag no table has heard of. **The fixture that justifies the allow-list running
    # in the direction it does** (ADR-0033): under a deny-list this survives by being unknown.
    write(
        OUT / "unknown-vendor-tag.tiff",
        build(
            [
                (
                    structural()
                    + [
                        ascii_tag(0xC5D9, "SYNTHETIC-VENDOR-SERIAL-0009"),
                        ascii_tag(0xFDE8, "SYNTHETIC-PRIVATE-0010"),
                    ],
                    [PIXELS],
                )
            ]
        ),
    )

    # Metadata reached through a pointer rather than sitting in IFD0.
    write(
        OUT / "exif-and-gps.tiff",
        build(
            [(structural() + [(EXIF_IFD, LONG, 1, "exif"), (GPS_IFD, LONG, 1, "gps")], [PIXELS])],
            subdirs={
                "exif": [
                    ascii_tag(0xA430, "SYNTHETIC-OWNER-0011"),
                    ascii_tag(0xA431, "SYNTHETIC-BODY-SERIAL-0012"),
                    ascii_tag(0x9003, "2026:08:25 11:05:00"),
                    ascii_tag(0x9286, "SYNTHETIC-USER-COMMENT-0013"),
                ],
                "gps": [
                    ascii_tag(0x0001, "N"),
                    (0x0002, RATIONAL, 3, struct.pack("<6I", 51, 1, 30, 1, 0, 1)),
                    ascii_tag(0x0003, "W"),
                    (0x0004, RATIONAL, 3, struct.pack("<6I", 0, 1, 7, 1, 0, 1)),
                ],
            },
        ),
    )

    # XMP, IPTC, and an ICC profile: three whole metadata containers carried as tag values.
    write(
        OUT / "packets.tiff",
        build(
            [
                (
                    structural()
                    + [
                        undefined_tag(
                            XMP,
                            b'<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
                            b"<dc:creator>SYNTHETIC-XMP-CREATOR-0014</dc:creator>"
                            b"</x:xmpmeta><?xpacket end=\"w\"?>",
                        ),
                        undefined_tag(IPTC, b"\x1c\x02\x50SYNTHETIC-IPTC-BYLINE-0015"),
                        undefined_tag(
                            ICC_PROFILE,
                            b"\0\0\0\x30SYNTHETIC-ICC-DEVICE-0016".ljust(48, b"\0"),
                        ),
                    ],
                    [PIXELS],
                )
            ]
        ),
    )

    # A reduced-resolution second directory: a thumbnail, which survives every crop and every
    # redaction applied to the picture it was made from (`docs/THREAT_MODEL.md` section 3).
    write(
        OUT / "reduced-resolution-thumbnail.tiff",
        build(
            [
                (structural(), [PIXELS]),
                (
                    structural(2, 1)
                    + [long_tag(NEW_SUBFILE_TYPE, 1), ascii_tag(ARTIST, "SYNTHETIC-THUMB-ARTIST-0017")],
                    [b"SYNTHETIC-THUMBNAIL-PIXELS-0018"],
                ),
            ]
        ),
    )

    # Three pages, each with its own metadata. The scanned-dossier case: every page must
    # survive, and every page's metadata must not.
    write(
        OUT / "multi-page.tiff",
        build(
            [
                (
                    structural() + [ascii_tag(ARTIST, f"SYNTHETIC-PAGE-ARTIST-{n:04d}")],
                    [f"PRESERVED-TIFF-PIXELS-PAGE-{n}".encode("ascii")],
                )
                for n in (1, 2, 3)
            ]
        ),
    )

    # Several strips, so the regenerated geometry is an out-of-line array rather than an
    # inline value — a different code path in the writer.
    write(
        OUT / "multi-strip.tiff",
        build(
            [
                (
                    structural(7, 3)
                    + [short_tag(ROWS_PER_STRIP, 1), ascii_tag(SOFTWARE, "SYNTHETIC-SOFTWARE-0019")],
                    [b"PRESERVED-STRIP-ONE-01", b"PRESERVED-STRIP-TWO-02", b"PRESERVED-STRIP-3"],
                )
            ]
        ),
    )

    # A palette image: ColorMap is a large structural value that must be carried across, and it
    # exercises the writer's out-of-line value path for a *kept* tag.
    palette = b"".join(struct.pack("<H", (i * 257) % 65536) for i in range(3 * 16))
    write(
        OUT / "palette.tiff",
        build(
            [
                (
                    [
                        short_tag(IMAGE_WIDTH, 7),
                        short_tag(IMAGE_LENGTH, 3),
                        short_tag(BITS_PER_SAMPLE, 4),
                        short_tag(COMPRESSION, 1),
                        short_tag(PHOTOMETRIC, 3),
                        short_tag(SAMPLES_PER_PIXEL, 1),
                        short_tag(ROWS_PER_STRIP, 3),
                        short_tag(PLANAR_CONFIG, 1),
                        (COLOR_MAP, SHORT, 3 * 16, palette),
                        ascii_tag(ARTIST, "SYNTHETIC-PALETTE-ARTIST-0020"),
                    ],
                    [PIXELS],
                )
            ]
        ),
    )

    # Big-endian, because every offset and every length below is read in the declared order and
    # a handler that assumed one is wrong on half the world's scanners.
    little = build([(structural() + [ascii_tag(ARTIST, "SYNTHETIC-BE-ARTIST-0021")], [PIXELS])])
    write(OUT / "big-endian.tiff", to_big_endian(little))

    print("Malformed TIFF fixtures:")

    clean = build([(structural(), [PIXELS])])

    # BigTIFF: the same byte-order mark, magic 43, eight-byte offsets. Refused by name rather
    # than parsed as the TIFF it is not (ADR-0033).
    write(MALFORMED / "bigtiff.tiff", b"II" + struct.pack("<HHHQ", 43, 8, 0, 16) + clean[16:])

    # A directory chain that points back at itself.
    cycle = bytearray(clean)
    first = struct.unpack_from("<I", cycle, 4)[0]
    count = struct.unpack_from("<H", cycle, first)[0]
    struct.pack_into("<I", cycle, first + 2 + 12 * count, first)
    write(MALFORMED / "directory-cycle.tiff", bytes(cycle))

    # A strip that claims to live past the end of the file.
    runaway = bytearray(clean)
    at = runaway.find(struct.pack("<I", runaway.find(PIXELS)))
    struct.pack_into("<I", runaway, at, 0xFFFF0000)
    write(MALFORMED / "strip-out-of-range.tiff", bytes(runaway))

    # Truncated part-way through the directory.
    write(MALFORMED / "truncated-directory.tiff", clean[: 8 + 14])

    # A directory claiming far more entries than the file holds.
    liar = bytearray(clean)
    struct.pack_into("<H", liar, struct.unpack_from("<I", liar, 4)[0], 0xFFFF)
    write(MALFORMED / "entry-count-lies.tiff", bytes(liar))

    # No dimensions: a directory that cannot describe an image.
    write(
        MALFORMED / "no-dimensions.tiff",
        build([([short_tag(COMPRESSION, 1), short_tag(PHOTOMETRIC, 1)], [PIXELS])]),
    )


def to_big_endian(data):
    """Re-emit a little-endian fixture in big-endian form.

    Byte-swapping a TIFF means swapping every field *as its type*, which is the whole reason a
    fixture like this is worth having: it is exactly the work a reader has to get right.
    """
    out = bytearray(data)
    out[0:2] = b"MM"
    struct.pack_into(">H", out, 2, 42)
    first = struct.unpack_from("<I", data, 4)[0]
    struct.pack_into(">I", out, 4, first)

    at = first
    count = struct.unpack_from("<H", data, at)[0]
    struct.pack_into(">H", out, at, count)
    at += 2
    for _ in range(count):
        tag, ftype, n = struct.unpack_from("<HHI", data, at)
        struct.pack_into(">HHI", out, at, tag, ftype, n)
        size = n * TYPE_SIZE[ftype]
        if size <= 4:
            swap_value(data, out, at + 8, ftype, n)
        else:
            offset = struct.unpack_from("<I", data, at + 8)[0]
            struct.pack_into(">I", out, at + 8, offset)
            swap_value(data, out, offset, ftype, n)
        at += 12
    struct.pack_into(">I", out, at, struct.unpack_from("<I", data, at)[0])
    return bytes(out)


def swap_value(data, out, at, ftype, count):
    if ftype in (BYTE, ASCII, UNDEFINED):
        return
    width = TYPE_SIZE[ftype]
    if ftype == RATIONAL:
        width, count = 4, count * 2
    fmt = {2: "H", 4: "I"}[width]
    for index in range(count):
        spot = at + index * width
        struct.pack_into(">" + fmt, out, spot, struct.unpack_from("<" + fmt, data, spot)[0])


if __name__ == "__main__":
    sys.exit(main())
