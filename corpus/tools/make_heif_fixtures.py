#!/usr/bin/env python3
"""Generate the HEIF and AVIF fixtures in ``corpus/heif``.

Deterministic: two runs produce byte-identical files, so a fixture in ``git diff`` means this
generator changed.

**Every fixture is a real, decodable image.** That matters for the same reason it did for GIF
(``docs/THREAT_MODEL.md`` section 7.9): mat2 reaches these formats through a decoder, so a fixture
it cannot open makes the differential say nothing at all.

Unlike the other generators in this directory, this one cannot synthesise its payload — nobody
writes an AV1 or HEVC encoder in a fixture script. Instead it embeds **one recorded codestream per
codec**, extracted once from ImageMagick 7.1.2 / libheif 1.23.1 output, and builds every container
around them by hand. So there is still no third-party dependency at generation time, and the
exotic structures below — ``idat`` construction, thumbnail references, unknown item types — are
reachable in a way no encoder would produce on request.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "heif"
MALFORMED = OUT / "malformed"

# Recorded from real encoder output. See the module docstring.
FTYP_AVIF = b"avif\x00\x00\x00\x00mif1avifmiaf"
FTYP_HEIC = b"heix\x00\x00\x00\x00mif1heixmiaf"
AV1C = b"\x81@l\x00"
ISPE_AVIF = b"\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10"
PIXI = b"\x00\x00\x00\x00\x03\x0c\x0c\x0c"
CODESTREAM_AV01 = (
    b"\x12\x00\n\tX\x0c\xff\xda\xd0\x10\xd0n\x102%\x19G\x87\x86!\x89\xa6\x9af\x80\x00"
    b"\x00u\x85\x92\xe6\xde+\x03\x85\x05\xfd\xe4Hx\xea\xb5\x7fJI\x15P\xc7\xfaF\xae\x80"
)
HVCC = (
    b"\x01\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\xf0\x00\xfc\xfd\xfc\xfc\x00\x00"
    b"\x0f\x03`\x00\x01\x00\x17@\x01\x0c\x01\xff\xff\x04\x08\x00\x00\x03\x00\x99\xb8\x00\x00"
    b"\x03\x00\x00\x1e\xba\x02@a\x00\x01\x00)B\x01\x01\x04\x08\x00\x00\x03\x00\x99\xb8\x00\x00"
    b"\x03\x00\x00\x1e\xa0 \x81\x04R\x96\xea\xae\x9a\xe6\xe0!\xa0\xc0\x80\x00\x00\x0c\x80\x00"
    b"\x00\x03\x00\x84b\x00\x01\x00\x06D\x01\xc1s\xc1\x89"
)
ISPE_HEIC = b"\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00@"
CLAP = (
    b"\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00\x01"
    b"\xff\xff\xff\xd0\x00\x00\x00\x02\xff\xff\xff\xd0\x00\x00\x00\x02"
)
CODESTREAM_HVC1 = (
    b"\x00\x00\x00>(\x01\xaf\x13!p\xe3\xc0\xf5*4c\x83\x1e\xeb\xfd\xc5\x04\x16\xd6\xc7W\xc1"
    b"\x9e\xbch\x9a\x8d\x1f\x95L}\xe8\xcd0\xd8\x0f\xf6\xbfE$m}^?6\x1d\x9d\xb9\xf76\xcb\xde"
    b"\xaee4\xb5%\xfa\xef\xf5\x80"
)

# The 16-byte extended type the XMP specification fixes for a `uuid` box.
XMP_UUID = bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC")


def box(kind, payload):
    return struct.pack(">I", len(payload) + 8) + kind + payload


def full(kind, version, flags, payload):
    return box(kind, bytes([version]) + flags.to_bytes(3, "big") + payload)


def hdlr(name=b""):
    return full("hdlr".encode(), 0, 0, b"\x00" * 4 + b"pict" + b"\x00" * 12 + name + b"\x00")


def infe(item_id, kind, name=b"", content_type=None):
    body = struct.pack(">HH", item_id, 0) + kind + name + b"\x00"
    if content_type is not None:
        body += content_type + b"\x00"
    return full(b"infe", 2, 0, body)


def iinf(entries):
    return full(b"iinf", 0, 0, struct.pack(">H", len(entries)) + b"".join(entries))


def iloc(items, construction=0):
    """``items`` is a list of ``(item_id, offset, length)``, at fixed 4-byte widths."""
    body = struct.pack(">HH", (4 << 12) | (4 << 8), len(items))
    for item_id, offset, length in items:
        body += struct.pack(">HHHH", item_id, construction, 0, 1)
        body += struct.pack(">II", offset, length)
    return full(b"iloc", 1, 0, body)


def iref(refs):
    """``refs`` is a list of ``(type, from_id, [to_ids])``."""
    body = b""
    for kind, src, targets in refs:
        body += box(kind, struct.pack(">HH", src, len(targets)) + b"".join(
            struct.pack(">H", t) for t in targets))
    return full(b"iref", 0, 0, body)


def iprp(properties, associations):
    """``properties`` is ``[(type, payload)]``; ``associations`` ``[(item_id, [(idx, ess)])]``."""
    ipco = box(b"ipco", b"".join(box(k, p) for k, p in properties))
    body = struct.pack(">I", len(associations))
    for item_id, entries in associations:
        body += struct.pack(">H", item_id) + bytes([len(entries)])
        for index, essential in entries:
            body += bytes([(0x80 if essential else 0) | index])
    return box(b"iprp", ipco + full(b"ipma", 0, 0, body))


def assemble(ftyp, meta_children, payloads, extra_top=b"", trailing=b"", construction=0,
             idat=None):
    """Lay out a file, computing every ``iloc`` offset against the finished ``meta``.

    ``payloads`` is ``[(item_id, bytes)]`` in the order they are written into ``mdat``.
    """
    def build(offsets):
        children = []
        for child in meta_children:
            children.append(iloc(offsets, construction) if child is None else child)
        if idat is not None:
            children.append(box(b"idat", idat))
        return full(b"meta", 0, 0, b"".join(children))

    placeholder = [(i, 0, len(p)) for i, p in payloads]
    probe = build(placeholder)
    head = len(box(b"ftyp", ftyp)) + len(probe) + len(extra_top)
    base = head + 8
    offsets, cursor = [], base
    for item_id, payload in payloads:
        offsets.append((item_id, 0 if construction == 1 else cursor, len(payload)))
        cursor += len(payload)
    meta = build(offsets)
    assert len(meta) == len(probe), "layout is not offset-invariant"
    mdat = box(b"mdat", b"".join(p for _, p in payloads))
    return box(b"ftyp", ftyp) + meta + extra_top + mdat + trailing


def tiff_exif(marker):
    """A little-endian TIFF block with an Artist, a Software tag, and a GPS directory."""
    # Placed explicitly rather than through a helper: the offsets have to be right, and two small
    # directories are easier to read laid out than generated.
    artist = f"SYNTHETIC-ARTIST-{marker}".encode() + b"\x00"
    software = f"SYNTHETIC-SOFTWARE-{marker}".encode() + b"\x00"
    ifd0_count, gps_count = 3, 2
    ifd0_start = 8
    ifd0_size = 2 + 12 * ifd0_count + 4
    gps_start = ifd0_start + ifd0_size
    gps_size = 2 + 12 * gps_count + 4
    value_start = gps_start + gps_size

    values = artist + software
    gps_values = struct.pack("<IIIIII", 51, 1, 30, 1, 0, 1)
    values += gps_values

    ifd0 = struct.pack("<H", ifd0_count)
    ifd0 += struct.pack("<HHII", 0x013B, 2, len(artist), value_start)
    ifd0 += struct.pack("<HHII", 0x0131, 2, len(software), value_start + len(artist))
    ifd0 += struct.pack("<HHII", 0x8825, 4, 1, gps_start)
    ifd0 += struct.pack("<I", 0)

    gps = struct.pack("<H", gps_count)
    gps += struct.pack("<HHI", 0x0001, 2, 2) + b"N\x00\x00\x00"
    gps += struct.pack("<HHII", 0x0002, 5, 3, value_start + len(artist) + len(software))
    gps += struct.pack("<I", 0)

    return b"II\x2a\x00" + struct.pack("<I", ifd0_start) + ifd0 + gps + values


def exif_item(marker):
    """An `Exif` item payload: the four-byte header offset, then the TIFF block (section A.2.1)."""
    return struct.pack(">I", 0) + tiff_exif(marker)


def xmp_packet(marker):
    return (
        b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">'
        b"<dc:creator>SYNTHETIC-CREATOR-" + marker.encode() + b"</dc:creator>"
        b"<dc:title>SYNTHETIC-TITLE-" + marker.encode() + b"</dc:title>"
        b"</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
    )


def icc_profile(marker):
    """A `colr` payload of type `prof`: an ICC profile whose description names its device."""
    body = b"SYNTHETIC-ICC-DEVICE-" + marker.encode()
    return b"prof" + struct.pack(">I", len(body) + 132).ljust(128, b"\x00") + body


def base_image(codec):
    if codec == "avif":
        return FTYP_AVIF, b"av01", [(b"av1C", AV1C), (b"ispe", ISPE_AVIF), (b"pixi", PIXI)], \
            CODESTREAM_AV01
    return FTYP_HEIC, b"hvc1", [(b"hvcC", HVCC), (b"ispe", ISPE_HEIC), (b"clap", CLAP),
                                (b"pixi", PIXI)], CODESTREAM_HVC1


def simple(codec, *, extra_items=(), extra_props=(), extra_top=b"", trailing=b"",
           handler=b"", primary_name=b"", refs=(), construction=0, primary=1,
           idat=None):
    """Build a file: the picture as item 1, plus whatever ``extra_items`` adds.

    ``extra_items`` is ``[(kind, payload, name, content_type)]``, numbered from 2.
    """
    ftyp, kind, props, codestream = base_image(codec)
    all_props = list(props) + list(extra_props)
    infes = [infe(1, kind, primary_name)]
    payloads = [(1, codestream)]
    for n, (ikind, payload, name, ctype) in enumerate(extra_items, start=2):
        infes.append(infe(n, ikind, name, ctype))
        payloads.append((n, payload))

    associations = [(1, [(i + 1, k in (b"av1C", b"hvcC", b"ispe")) for i, (k, _) in
                         enumerate(all_props)])]
    children = [
        hdlr(handler),
        full(b"pitm", 0, 0, struct.pack(">H", primary)),
        iinf(infes),
        None,  # iloc, filled in by assemble once the layout is known
        iprp(all_props, associations),
    ]
    if refs:
        children.insert(4, iref(refs))
    return assemble(ftyp, children, payloads, extra_top, trailing, construction, idat)


def write(directory, name, data):
    path = directory / name
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT.parent)}  {len(data)} bytes")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)
    print("well-formed:")

    write(OUT, "clean.avif", simple("avif"))
    write(OUT, "clean.heic", simple("heic"))

    write(OUT, "exif.avif", simple(
        "avif", extra_items=[(b"Exif", exif_item("0001"), b"", None)],
        refs=[(b"cdsc", 2, [1])]))
    write(OUT, "exif.heic", simple(
        "heic", extra_items=[(b"Exif", exif_item("0002"), b"", None)],
        refs=[(b"cdsc", 2, [1])]))

    write(OUT, "xmp.heic", simple(
        "heic", extra_items=[(b"mime", xmp_packet("0003"), b"", b"application/rdf+xml")],
        refs=[(b"cdsc", 2, [1])]))

    write(OUT, "exif-and-xmp.avif", simple(
        "avif",
        extra_items=[(b"Exif", exif_item("0004"), b"", None),
                     (b"mime", xmp_packet("0005"), b"", b"application/rdf+xml")],
        refs=[(b"cdsc", 2, [1]), (b"cdsc", 3, [1])]))

    # The leak that survives cropping: a second coded image bound by a `thmb` reference.
    #
    # The marker is appended to the codestream because nothing else can see this item: ExifTool,
    # ImageMagick and libheif all decline to enumerate it (measured 2026-08-27), so without a
    # marker in its bytes the differential would have no way to tell whether it survived.
    write(OUT, "thumbnail.heic", simple(
        "heic", extra_items=[(b"hvc1", CODESTREAM_HVC1 + b"SYNTHETIC-THUMBNAIL-0016", b"", None)],
        refs=[(b"thmb", 2, [1])]))

    write(OUT, "icc-profile.avif", simple(
        "avif", extra_props=[(b"colr", icc_profile("0006"))]))
    # nclx is kept: numeric colour signalling naming no device.
    write(OUT, "nclx-colour.avif", simple(
        "avif", extra_props=[(b"colr", b"nclx\x00\x01\x00\x0d\x00\x01\x80")]))

    write(OUT, "uuid-xmp.heic", simple(
        "heic", extra_top=box(b"uuid", XMP_UUID + xmp_packet("0007"))))

    write(OUT, "free-space.avif", simple(
        "avif", extra_top=box(b"free", b"SYNTHETIC-FREE-0008") + box(b"skip", b"\x00" * 8)))

    # A vendor item type nobody has heard of. The allow-list must drop it for being unrecognised.
    write(OUT, "unknown-item.avif", simple(
        "avif", extra_items=[(b"XPRV", b"SYNTHETIC-VENDOR-ITEM-0009", b"", None)]))

    # `udes` names its image in free text; `XPRP` is a vendor property.
    write(OUT, "unknown-property.heic", simple(
        "heic", extra_props=[
            (b"udes", b"\x00\x00\x00\x00en\x00SYNTHETIC-DESC-0010\x00\x00\x00"),
            (b"XPRP", b"SYNTHETIC-VENDOR-PROP-0011")]))

    # The two free-text fields that are not metadata boxes.
    write(OUT, "named-item.avif", simple(
        "avif", handler=b"SYNTHETIC-HANDLER-0012",
        primary_name=b"SYNTHETIC-ITEM-NAME-0013"))

    # Construction method 1: payloads in `meta`'s own `idat` rather than in `mdat`.
    exif = exif_item("0014")
    write(OUT, "idat-item.heic", simple(
        "heic", extra_items=[(b"Exif", exif, b"", None)], construction=1,
        idat=CODESTREAM_HVC1 + exif))

    # `xml ` sits inside `meta`, where a top-level rule would never look (section 8.11.2).
    ftyp, kind, props, codestream = base_image("avif")
    children = [
        hdlr(),
        full(b"pitm", 0, 0, struct.pack(">H", 1)),
        iinf([infe(1, kind)]),
        None,
        iprp(props, [(1, [(i + 1, True) for i in range(len(props))])]),
        box(b"xml ", b"<meta>SYNTHETIC-META-XML-0015</meta>"),
    ]
    write(OUT, "meta-xml.avif", assemble(ftyp, children, [(1, codestream)]))

    write(OUT, "trailing-data.heic", simple(
        "heic", trailing=b"SYNTHETIC-TRAILING-0016"))

    print("malformed:")
    good = simple("avif")
    write(MALFORMED, "truncated.avif", good[: len(good) // 2])

    # A box declaring less than its own header, nested inside `meta` where the walk is strict:
    # accepting it would advance the cursor by nothing and read the same offset forever.
    write(MALFORMED, "box-size-below-header.avif",
          box(b"ftyp", FTYP_AVIF)
          + full(b"meta", 0, 0, hdlr() + struct.pack(">I", 4) + b"free"))

    # An extent pointing past the end of the file.
    ftyp, kind, props, codestream = base_image("avif")
    children = [
        hdlr(),
        full(b"pitm", 0, 0, struct.pack(">H", 1)),
        iinf([infe(1, kind)]),
        iloc([(1, 0xFFFF00, len(codestream))]),
        iprp(props, [(1, [(1, True)])]),
    ]
    write(MALFORMED, "iloc-out-of-range.avif",
          box(b"ftyp", ftyp) + full(b"meta", 0, 0, b"".join(children)) + box(b"mdat", codestream))

    # `pitm` names the Exif item, so the primary would be removed and no picture would survive.
    write(MALFORMED, "primary-is-metadata.avif", simple(
        "avif", extra_items=[(b"Exif", exif_item("0017"), b"", None)], primary=2))

    # Construction method 2: an extent into another item, which cannot be relocated.
    write(MALFORMED, "construction-method-2.heic", simple("heic", construction=2))

    write(MALFORMED, "live-photo.heic",
          simple("heic") + box(b"moov", box(b"mvhd", b"\x00" * 8)))

    # `infe` version 1 predates `item_type`, so no item's kind can be known.
    ftyp, kind, props, codestream = base_image("avif")
    children = [
        hdlr(),
        full(b"pitm", 0, 0, struct.pack(">H", 1)),
        full(b"iinf", 0, 0, struct.pack(">H", 1)
             + full(b"infe", 1, 0, struct.pack(">HH", 1, 0) + b"\x00\x00")),
        iloc([(1, 0, len(codestream))]),
        iprp(props, [(1, [(1, True)])]),
    ]
    write(MALFORMED, "infe-version-1.avif",
          box(b"ftyp", ftyp) + full(b"meta", 0, 0, b"".join(children)) + box(b"mdat", codestream))

    # A non-zero data_reference_index: the payload is in another file entirely.
    body = struct.pack(">HH", (4 << 12) | (4 << 8), 1)
    body += struct.pack(">HHHH", 1, 0, 1, 1) + struct.pack(">II", 0, len(codestream))
    children = [
        hdlr(),
        full(b"pitm", 0, 0, struct.pack(">H", 1)),
        iinf([infe(1, kind)]),
        full(b"iloc", 1, 0, body),
        iprp(props, [(1, [(1, True)])]),
    ]
    write(MALFORMED, "external-data-reference.avif",
          box(b"ftyp", ftyp) + full(b"meta", 0, 0, b"".join(children)) + box(b"mdat", codestream))

    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
