#!/usr/bin/env python3
"""Generate the GIF fixtures in ``corpus/gif``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with a particular imaging library installed is a corpus nobody
regenerates.

**Every fixture is a real, decodable GIF**, LZW and all. That costs this file an encoder it
would otherwise not need, and it buys the thing that matters: mat2's GIF path re-renders the
image through GdkPixbuf, so a fixture it cannot open makes the differential comparison say
nothing at all — the mistake the WebP comparison made for two days
(``docs/THREAT_MODEL.md`` section 7.4).

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report —
a handler that forgot to remove something would still cheerfully report having removed it.

The pixel payload cannot carry a marker the way TIFF's does, because it is LZW-compressed. The
"the picture crossed intact" claim is therefore owned by the integration tests, which compare the
image blocks byte for byte in ``crates/strypt-core/tests/gif.rs``.
"""

import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "gif"
MALFORMED = OUT / "malformed"

TRAILER = b"\x3b"
EXTENSION = 0x21
IMAGE_SEPARATOR = 0x2C

LABEL_PLAIN_TEXT = 0x01
LABEL_GRAPHIC_CONTROL = 0xF9
LABEL_COMMENT = 0xFE
LABEL_APPLICATION = 0xFF

# A four-entry palette, so the LZW minimum code size is 2 — the smallest the format permits
# (GIF89a section 22) and the one every real encoder uses for an image this simple.
PALETTE = bytes([0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255])
PALETTE_BITS = 1  # 3 * 2^(N+1) = 12 bytes

WIDTH = HEIGHT = 8


def pixels(shift=0):
    """An 8x8 pattern. ``shift`` makes each animation frame visibly different."""
    return [((x + y + shift) // 2) % 4 for y in range(HEIGHT) for x in range(WIDTH)]


def lzw(data, min_code_size=2):
    """GIF's variable-width LZW (section 22), written out rather than imported.

    The width rule is the one giflib uses: the code width grows once the *next* code to be
    assigned no longer fits in it. Getting that boundary wrong produces a file that most
    decoders still open and one does not, which is the least useful kind of fixture.
    """
    clear, eoi = 1 << min_code_size, (1 << min_code_size) + 1
    table = {bytes([i]): i for i in range(clear)}
    next_code, width = eoi + 1, min_code_size + 1

    out = bytearray()
    buffer = count = 0

    def emit(code):
        nonlocal buffer, count
        buffer |= code << count
        count += width
        while count >= 8:
            out.append(buffer & 0xFF)
            buffer >>= 8
            count -= 8

    emit(clear)
    run = bytes([data[0]])
    for value in data[1:]:
        longer = run + bytes([value])
        if longer in table:
            run = longer
            continue
        emit(table[run])
        table[longer] = next_code
        next_code += 1
        if next_code >= (1 << width) and width < 12:
            width += 1
        run = bytes([value])
    emit(table[run])
    emit(eoi)
    if count:
        out.append(buffer & 0xFF)
    return bytes([min_code_size]) + sub_blocks(bytes(out))


def sub_blocks(payload):
    """A sub-block chain: 255 bytes at a time, then the terminating zero (section 15)."""
    out = bytearray()
    for at in range(0, len(payload), 255):
        part = payload[at : at + 255]
        out.append(len(part))
        out += part
    out.append(0)
    return bytes(out)


def header(version=b"GIF89a", global_table=True):
    """Signature, logical screen descriptor, and the global colour table (sections 17-18)."""
    packed = (0x80 | (PALETTE_BITS & 7)) if global_table else 0
    out = version + struct.pack("<HHBBB", WIDTH, HEIGHT, packed, 0, 0)
    return out + PALETTE if global_table else out


def image(shift=0, interlaced=False, local_table=False):
    """An image descriptor and its compressed data (sections 20 and 22)."""
    packed = (0x40 if interlaced else 0) | ((0x80 | PALETTE_BITS) if local_table else 0)
    data = pixels(shift)
    if interlaced:
        # Rows in the order section 20 defines: every 8th from row 0, then from row 4, then
        # every 4th from row 2, then every 2nd from row 1.
        order = list(range(0, HEIGHT, 8)) + list(range(4, HEIGHT, 8))
        order += list(range(2, HEIGHT, 4)) + list(range(1, HEIGHT, 2))
        rows = [data[r * WIDTH : (r + 1) * WIDTH] for r in order]
        data = [value for row in rows for value in row]
    out = bytes([IMAGE_SEPARATOR]) + struct.pack("<HHHHB", 0, 0, WIDTH, HEIGHT, packed)
    if local_table:
        out += PALETTE
    return out + lzw(data)


def extension(label, payload):
    return bytes([EXTENSION, label]) + sub_blocks(payload)


def application(identifier, payload):
    """An application extension: eleven bytes of identifier as one sub-block, then data."""
    assert len(identifier) == 11, identifier
    return bytes([EXTENSION, LABEL_APPLICATION, 11]) + identifier + sub_blocks(payload)


def graphic_control(delay=10, transparent=None):
    """Disposal method, delay, and transparent colour index (section 23)."""
    packed = 0x08 | (0x01 if transparent is not None else 0)
    return extension(
        LABEL_GRAPHIC_CONTROL,
        struct.pack("<BHB", packed, delay, transparent or 0),
    )


def loop_extension(count=0):
    """The NETSCAPE2.0 loop count: the one application extension strypt keeps."""
    return application(b"NETSCAPE2.0", struct.pack("<BH", 1, count))


def xmp(packet):
    """XMP as the XMP specification part 3 section 1.1.2 stores it in a GIF.

    The packet is laid down **raw**, not as a sub-block chain, and a 258-byte magic trailer of
    descending values makes the packet's own bytes fall where a sub-block walk needs its length
    bytes. A walker that lands anywhere inside the trailer descends to the terminating zero, so
    the block ends where it should whatever the packet's text happens to be.
    """
    trailer = bytes([0x01]) + bytes(range(255, -1, -1)) + b"\x00"
    return bytes([EXTENSION, LABEL_APPLICATION, 11]) + b"XMP DataXMP" + packet + trailer


def plain_text(text):
    """A plain-text extension: twelve bytes of grid geometry, then the text (section 24)."""
    geometry = struct.pack("<HHHHBBBB", 0, 0, WIDTH, HEIGHT, 8, 8, 1, 0)
    return bytes([EXTENSION, LABEL_PLAIN_TEXT, 12]) + geometry + sub_blocks(text)


def gif(*blocks, version=b"GIF89a"):
    return header(version) + b"".join(blocks) + TRAILER


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT.parent)}  ({len(data)} bytes)")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)
    print("GIF fixtures:")

    # The baseline: nothing identifying at all. A block-list format can promise that a clean file
    # comes back byte-identical, and this is the fixture that holds that promise in place.
    write(OUT / "clean.gif", gif(image()))

    # The ordinary case. A comment extension holds whatever the producing tool felt like putting
    # there, which in real files is routinely a filename or a person.
    write(
        OUT / "comment.gif",
        gif(extension(LABEL_COMMENT, b"SYNTHETIC-COMMENT-0001"), image()),
    )

    # Several comments, one of them long enough to span more than one sub-block, because the
    # chain walk is where a length field gets mishandled.
    write(
        OUT / "long-comment.gif",
        gif(
            extension(LABEL_COMMENT, b"SYNTHETIC-LONG-COMMENT-0002 " + b"." * 600),
            extension(LABEL_COMMENT, b"SYNTHETIC-SECOND-COMMENT-0003"),
            image(),
        ),
    )

    # XMP, in the raw-packet-plus-magic-trailer layout the XMP specification defines for GIF.
    write(
        OUT / "xmp.gif",
        gif(
            xmp(
                b'<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>'
                b"<dc:creator>SYNTHETIC-XMP-CREATOR-0004</dc:creator>"
                b"<xmp:CreatorTool>SYNTHETIC-XMP-TOOL-0005</xmp:CreatorTool>"
                b'<xmpMM:DocumentID>uuid:SYNTHETIC-0006</xmpMM:DocumentID>'
                b'</rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
            ),
            image(),
        ),
    )

    # What ImageMagick and Photoshop write: whole 8BIM, IPTC, and ICC blocks carried as
    # application extensions. The IPTC one holds a by-line, which is a person's name.
    write(
        OUT / "application-blocks.gif",
        gif(
            application(b"ICCRGBG1012", b"\0\0\0\x30SYNTHETIC-ICC-DEVICE-0007"),
            application(b"MGK8BIM0000", b"8BIM\x04\x04SYNTHETIC-8BIM-0008"),
            application(b"MGKIPTC0000", b"\x1c\x02\x50SYNTHETIC-IPTC-BYLINE-0009"),
            image(),
        ),
    )

    # A vendor block no table has heard of. **The fixture that justifies the allow-list running
    # in the direction it does**: under a deny-list this survives by being unknown.
    write(
        OUT / "unknown-application.gif",
        gif(
            application(b"VENDORX1.0\x00", b"SYNTHETIC-VENDOR-SERIAL-0010"),
            image(),
        ),
    )

    # An animation that loops. The loop count is the one application extension strypt keeps, and
    # this fixture is what proves it still does — three frames, three graphic control blocks, and
    # a comment that must not survive any of it.
    write(
        OUT / "animated-loop.gif",
        gif(
            loop_extension(),
            extension(LABEL_COMMENT, b"SYNTHETIC-ANIMATION-COMMENT-0011"),
            graphic_control(),
            image(0),
            graphic_control(),
            image(1),
            graphic_control(),
            image(2),
        ),
    )

    # The same animation without a loop block, so a test can tell "kept the one that was there"
    # from "writes one regardless".
    write(
        OUT / "animated-no-loop.gif",
        gif(graphic_control(), image(0), graphic_control(), image(1)),
    )

    # Transparency and a delay: rendering instructions that must cross untouched, or the image
    # changes in front of the user.
    write(
        OUT / "transparency.gif",
        gif(
            graphic_control(delay=50, transparent=3),
            extension(LABEL_COMMENT, b"SYNTHETIC-TRANSPARENT-COMMENT-0012"),
            image(),
        ),
    )

    # A plain-text extension and the graphic control block in front of it. The pair goes
    # together: leaving the control block would hand its delay to the following image.
    write(
        OUT / "plain-text.gif",
        gif(
            graphic_control(),
            plain_text(b"SYNTHETIC-PLAINTEXT-0013"),
            graphic_control(),
            image(),
        ),
    )

    # An interlaced image with its own local colour table — two structural flags that must
    # survive, on a code path that is easy to skip past by accident.
    write(
        OUT / "interlaced-local-table.gif",
        gif(
            extension(LABEL_COMMENT, b"SYNTHETIC-INTERLACED-COMMENT-0014"),
            image(interlaced=True, local_table=True),
        ),
    )

    # An extension under a label the format does not define. Nobody can say what is in it, and a
    # scrubber that copies through what it does not understand is not scrubbing.
    write(
        OUT / "unknown-extension.gif",
        gif(extension(0x42, b"SYNTHETIC-UNKNOWN-EXTENSION-0015"), image()),
    )

    # Bytes after the trailer. Nothing reads them, few users know they can be there, and they are
    # a convenient place to keep a second copy of an image whose visible version was cropped.
    write(
        OUT / "trailing-data.gif",
        gif(image()) + b"SYNTHETIC-APPENDED-0016",
    )

    # GIF87a: no extension blocks existed in it, and files spelling it while carrying them are
    # common. Handled the same way rather than refused on a version string no decoder enforces.
    write(
        OUT / "gif87a.gif",
        header(b"GIF87a") + extension(LABEL_COMMENT, b"SYNTHETIC-87A-COMMENT-0017")
        + image() + TRAILER,
    )

    print("Malformed GIF fixtures:")

    clean = gif(image())

    # Ends part-way through the logical screen descriptor.
    write(MALFORMED / "truncated-header.gif", clean[:10])

    # No trailer: the block sequence simply stops. Refused rather than completed, because a
    # repaired copy of a damaged file is not the file the user handed over.
    write(MALFORMED / "no-trailer.gif", clean[:-1])

    # A sub-block claiming more bytes than the file holds.
    runaway = bytearray(gif(extension(LABEL_COMMENT, b"short"), image()))
    runaway[len(header()) + 2] = 0xFF
    write(MALFORMED / "sub-block-past-end.gif", bytes(runaway))

    # A chain whose terminating zero never arrives.
    write(
        MALFORMED / "unterminated-sub-blocks.gif",
        header() + bytes([EXTENSION, LABEL_COMMENT, 5]) + b"short",
    )

    # A byte where section 17 permits only an extension introducer, an image separator, or the
    # trailer. The walk is no longer where it thinks it is, so it stops.
    bad = bytearray(clean)
    bad[len(header())] = 0x99
    write(MALFORMED / "bad-introducer.gif", bytes(bad))

    # A global colour table the file is too short to contain.
    write(
        MALFORMED / "colour-table-past-end.gif",
        b"GIF89a" + struct.pack("<HHBBB", WIDTH, HEIGHT, 0x87, 0, 0) + PALETTE,
    )


if __name__ == "__main__":
    sys.exit(main())
