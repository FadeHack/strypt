#!/usr/bin/env python3
"""Generate the MP4 and M4A fixtures in ``corpus/mp4``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design.

**These are real, decodable files.** mat2 reaches MP4 through ffmpeg and the differential checks
the media with it, so a fixture no decoder accepts would prove nothing. An H.264 and an AAC
elementary stream are not hand-writable, so two minimal recordings — 0.4 s of black at 16x16 and
0.2 s of a 440 Hz tone — were produced once with ffmpeg 9.0.1 and are embedded below as base64.
Everything after that is this script's own work: the boxes it inserts, and the chunk offsets it
recomputes each time it changes the layout.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import base64
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "mp4"
MALFORMED = OUT / "malformed"

# Box types whose payload is a list of further boxes.
CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"dinf", b"edts", b"ilst"}
# The same, behind a version-and-flags prefix.
FULL_CONTAINERS = {b"meta": 4}

A = b"\xa9"  # the copyright sign that opens every QuickTime user-data atom


# --- BASE_M4A: 0.2 s of a 440 Hz tone, AAC, from ffmpeg 9.0.1. See corpus/MANIFEST.md.
BASE_M4A_B64 = (
    "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"
    "CGlsc3Q="
)

# --- BASE_MP4: 0.4 s of black at 16x16, H.264, from ffmpeg 9.0.1. See corpus/MANIFEST.md.
BASE_MP4_B64 = (
    "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAnZtZGF0AAACUwYF//9P3EXpvebZSLeWLNgg2SPu"
    "73gyNjQgLSBjb3JlIDE2NSByMzIyMiBiMzU2MDVhIC0gSC4yNjQvTVBFRy00IEFWQyBjb2RlYyAtIENvcHlsZWZ0IDIwMDMt"
    "MjAyNSAtIGh0dHA6Ly93d3cudmlkZW9sYW4ub3JnL3gyNjQuaHRtbCAtIG9wdGlvbnM6IGNhYmFjPTAgcmVmPTEgZGVibG9j"
    "az0wOjA6MCBhbmFseXNlPTA6MCBtZT1kaWEgc3VibWU9MCBwc3k9MSBwc3lfcmQ9MS4wMDowLjAwIG1peGVkX3JlZj0wIG1l"
    "X3JhbmdlPTE2IGNocm9tYV9tZT0xIHRyZWxsaXM9MCA4eDhkY3Q9MCBjcW09MCBkZWFkem9uZT0yMSwxMSBmYXN0X3Bza2lw"
    "PTEgY2hyb21hX3FwX29mZnNldD0wIHRocmVhZHM9MSBsb29rYWhlYWRfdGhyZWFkcz0xIHNsaWNlZF90aHJlYWRzPTAgbnI9"
    "MCBkZWNpbWF0ZT0xIGludGVybGFjZWQ9MCBibHVyYXlfY29tcGF0PTAgY29uc3RyYWluZWRfaW50cmE9MCBiZnJhbWVzPTAg"
    "d2VpZ2h0cD0wIGtleWludD0yNTAga2V5aW50X21pbj01IHNjZW5lY3V0PTAgaW50cmFfcmVmcmVzaD0wIHJjPWNyZiBtYnRy"
    "ZWU9MCBjcmY9MjMuMCBxY29tcD0wLjYwIHFwbWluPTAgcXBtYXg9NjkgcXBzdGVwPTQgaXBfcmF0aW89MS40MCBhcT0wAIAA"
    "AAAKZYiEOiYoAAkC4AAAAAVBmiA+lAAAAwRtb292AAAAbG12aGQAAAAAAAAAAAAAAAAAAAPoAAABkAABAAABAAAAAAAAAAAA"
    "AAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACU3Ry"
    "YWsAAABcdGtoZAAAAAMAAAAAAAAAAAAAAAEAAAAAAAABkAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAA"
    "AAAAAAAAAAAAAEAAAAAAEAAAABAAAAAAACRlZHRzAAAAHGVsc3QAAAAAAAAAAQAAAZAAAAAAAAEAAAAAActtZGlhAAAAIG1k"
    "aGQAAAAAAAAAAAAAAAAAACgAAAAQAFXEAAAAAAAtaGRscgAAAAAAAAAAdmlkZQAAAAAAAAAAAAAAAFZpZGVvSGFuZGxlcgAA"
    "AAF2bWluZgAAABR2bWhkAAAAAQAAAAAAAAAAAAAAJGRpbmYAAAAcZHJlZgAAAAAAAAABAAAADHVybCAAAAABAAABNnN0YmwA"
    "AAC2c3RzZAAAAAAAAAABAAAApmF2YzEAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAEAAQAEgAAABIAAAAAAAAAAEMTGF2YyBs"
    "aWJ4MjY0AAAAAAAAAAAAAAAAAAAAAAAAAAAY//8AAAAsYXZjQwFCwAr/4QAVZ0LACtp7ARAAAAMAEAAAAwCg8SJqAQAEaM4P"
    "yAAAABBwYXNwAAAAAQAAAAEAAAAUYnRydAAAAAAAADCYAAAAAAAAABhzdHRzAAAAAAAAAAEAAAACAAAIAAAAABRzdHNzAAAA"
    "AAAAAAEAAAABAAAAHHN0c2MAAAAAAAAAAQAAAAEAAAACAAAAAQAAABxzdHN6AAAAAAAAAAAAAAACAAACZQAAAAkAAAAUc3Rj"
    "bwAAAAAAAAABAAAAMAAAAD11ZHRhAAAANW1ldGEAAAAAAAAAIWhkbHIAAAAAAAAAAG1kaXJhcHBsAAAAAAAAAAAAAAAACGls"
    "c3Q="
)


class Box:
    """One box, parsed far enough to be edited and written back."""

    def __init__(self, typ, payload=b"", children=None, prefix=b"", force64=False):
        self.typ = typ
        self.payload = payload
        self.children = children
        self.prefix = prefix
        self.force64 = force64

    def body(self):
        if self.children is None:
            return self.payload
        return self.prefix + b"".join(c.body_boxed() for c in self.children)

    def body_boxed(self):
        body = self.body()
        if self.force64:
            return struct.pack(">I", 1) + self.typ + struct.pack(">Q", len(body) + 16) + body
        return struct.pack(">I", len(body) + 8) + self.typ + body

    def find(self, *path):
        node = self
        for name in path:
            node = next(c for c in (node.children or []) if c.typ == name)
        return node

    def drop(self, *path):
        parent = self.find(*path[:-1])
        parent.children = [c for c in parent.children if c.typ != path[-1]]


def parse(data):
    """Parse a byte string into a list of boxes, descending into the container types."""
    out, at = [], 0
    while at + 8 <= len(data):
        size, typ = struct.unpack(">I", data[at : at + 4])[0], data[at + 4 : at + 8]
        header, force64 = 8, False
        if size == 1:
            size = struct.unpack(">Q", data[at + 8 : at + 16])[0]
            header, force64 = 16, True
        elif size == 0:
            size = len(data) - at
        body = data[at + header : at + size]
        if typ in CONTAINERS:
            out.append(Box(typ, children=parse(body), force64=force64))
        elif typ in FULL_CONTAINERS:
            n = FULL_CONTAINERS[typ]
            out.append(Box(typ, children=parse(body[n:]), prefix=body[:n], force64=force64))
        else:
            out.append(Box(typ, payload=body, force64=force64))
        at += size
    return out


def assemble(tops):
    """Serialise top-level boxes and point every chunk offset at the `mdat` payload.

    Every fixture here has one `mdat` holding one chunk, so the whole relocation table is a single
    number — which is the point: the generator rewrites it from the layout it just produced, and
    strypt has to arrive at the same answer from the other direction.
    """
    # Probe pass: the offset tables are fixed-width, so writing them wrong does not change where
    # anything lands. The second pass writes them right.
    for _ in range(2):
        blob = b"".join(t.body_boxed() for t in tops)
        at, data_start = 0, None
        while at + 8 <= len(blob):
            size, typ = struct.unpack(">I", blob[at : at + 4])[0], blob[at + 4 : at + 8]
            header = 8
            if size == 1:
                size, header = struct.unpack(">Q", blob[at + 8 : at + 16])[0], 16
            elif size == 0:
                size = len(blob) - at
            if typ == b"mdat":
                data_start = at + header
            at += size
        if data_start is None:
            return blob
        for top in tops:
            if top.typ == b"moov":
                _point_chunks(top, data_start)
    return blob


def _point_chunks(node, data_start):
    for child in node.children or []:
        if child.typ in (b"stco", b"co64"):
            count = struct.unpack(">I", child.payload[4:8])[0]
            width = 8 if child.typ == b"co64" else 4
            fmt = ">Q" if width == 8 else ">I"
            child.payload = child.payload[:8] + b"".join(
                struct.pack(fmt, data_start) for _ in range(count)
            )
        _point_chunks(child, data_start)


def write(directory, name, data):
    directory.mkdir(parents=True, exist_ok=True)
    directory.joinpath(name).write_bytes(data)
    print(f"  {name}  {len(data)} bytes")


def atom(typ, text):
    """A `udta` free-text atom: a two-byte length, a two-byte language, then the text."""
    payload = text.encode()
    return Box(typ, struct.pack(">HH", len(payload), 0x55C4) + payload)


def ilst_item(typ, text, kind=1):
    """An iTunes list item: one named atom holding a `data` box of the declared type."""
    body = text if isinstance(text, bytes) else text.encode()
    data = Box(b"data", struct.pack(">II", kind, 0) + body)
    return Box(typ, children=[data])


def meta_box(items, handler_name=b"SYNTHETIC-HANDLER-0009"):
    hdlr = Box(b"hdlr", b"\x00" * 4 + b"\x00\x00\x00\x00mdirappl" + b"\x00" * 9 + handler_name)
    return Box(b"meta", children=[hdlr, Box(b"ilst", children=items)], prefix=b"\x00" * 4)


def baseline(blob):
    """The base recording with everything strypt removes taken out, by this script's own hand.

    This is what every other fixture must strip back to, byte for byte. Deriving it here rather
    than from strypt's output is the whole point: a test comparing the tool against itself proves
    nothing (`docs/TESTING_STRATEGY.md` §2.2).
    """
    tops = [t for t in parse(blob) if t.typ not in (b"free", b"skip", b"wide")]
    moov = next(t for t in tops if t.typ == b"moov")
    moov.children = [c for c in moov.children if c.typ in (b"mvhd", b"trak")]
    # The `hdlr` name — ffmpeg writes "SoundHandler" and "VideoHandler" there.
    hdlr = moov.find(b"trak", b"mdia", b"hdlr")
    hdlr.payload = hdlr.payload[:24] + b"\x00"
    # §12.1.3's `compressorname`, 32 bytes into a video sample entry — ffmpeg writes "Lavc libx264".
    if hdlr.payload[8:12] == b"vide":
        stsd = moov.find(b"trak", b"mdia", b"minf", b"stbl", b"stsd")
        at = 8 + 8 + 42
        stsd.payload = stsd.payload[:at] + b"\x00" * 32 + stsd.payload[at + 32:]
    return tops


def with_boxes(blob, extra_top=(), moov_extra=(), trak_extra=()):
    """The baseline with metadata put back in, so a fixture is the clean file plus what goes."""
    tops = baseline(blob)
    moov = next(t for t in tops if t.typ == b"moov")
    hdlr = moov.find(b"trak", b"mdia", b"hdlr")
    hdlr.payload = hdlr.payload[:24] + b"SYNTHETIC-HANDLER-0010\x00"
    if hdlr.payload[8:12] == b"vide":
        name = b"SYNTHETIC-ENCODER-0027"
        stsd = moov.find(b"trak", b"mdia", b"minf", b"stbl", b"stsd")
        at = 8 + 8 + 42
        field = bytes([len(name)]) + name + b"\x00" * (31 - len(name))
        stsd.payload = stsd.payload[:at] + field + stsd.payload[at + 32:]
    moov.children.extend(moov_extra)
    moov.find(b"trak").children.extend(trak_extra)
    for where, box in extra_top:
        tops.insert(where, box)
    return assemble(tops)


def set_times(moov):
    """Put a real date in every timestamp field, and a language in `mdhd`.

    2026-08-01T00:00:00Z, counted from the 1904 epoch §8.2.2 uses.
    """
    when = struct.pack(">I", 3869510400)
    mvhd = moov.find(b"mvhd")
    mvhd.payload = mvhd.payload[:4] + when + when + mvhd.payload[12:]
    # The 24 pre_defined bytes §8.2.2 says should be zero: poster, preview, selection, current.
    mvhd.payload = mvhd.payload[:72] + struct.pack(">6I", 1, 2, 3, 4, 5, 6) + mvhd.payload[96:]
    tkhd = moov.find(b"trak", b"tkhd")
    tkhd.payload = tkhd.payload[:4] + when + when + tkhd.payload[12:]
    mdhd = moov.find(b"trak", b"mdia", b"mdhd")
    mdhd.payload = mdhd.payload[:4] + when + when + mdhd.payload[12:20] + b"\x15\xc7" + mdhd.payload[22:]


def main():
    base_m4a = base64.b64decode(BASE_M4A_B64)
    base_mp4 = base64.b64decode(BASE_MP4_B64)

    print("well-formed:")
    write(OUT, "clean.mp4", assemble(baseline(base_mp4)))
    write(OUT, "clean.m4a", assemble(baseline(base_m4a)))

    # The atom every phone writes into every video it records: an ISO-6709 coordinate.
    write(
        OUT,
        "video-tags.mp4",
        with_boxes(
            base_mp4,
            moov_extra=[
                Box(
                    b"udta",
                    children=[
                        atom(A + b"xyz", "+12.3456-098.7654/SYNTHETIC-GPS-0001"),
                        atom(A + b"nam", "SYNTHETIC-TITLE-0002"),
                        atom(A + b"day", "SYNTHETIC-DATE-0003"),
                        atom(A + b"too", "SYNTHETIC-ENCODER-0004"),
                        atom(A + b"mak", "SYNTHETIC-MAKE-0005"),
                        atom(A + b"mod", "SYNTHETIC-MODEL-0006"),
                    ],
                )
            ],
        ),
    )

    # The other place the same material lives: an iTunes list under `moov/udta/meta`.
    write(
        OUT,
        "itunes-tags.m4a",
        with_boxes(
            base_m4a,
            moov_extra=[
                Box(
                    b"udta",
                    children=[
                        meta_box(
                            [
                                ilst_item(A + b"nam", "SYNTHETIC-TITLE-0011"),
                                ilst_item(A + b"ART", "SYNTHETIC-ARTIST-0012"),
                                ilst_item(A + b"too", "SYNTHETIC-ENCODER-0013"),
                                ilst_item(A + b"cmt", "SYNTHETIC-COMMENT-0014"),
                                ilst_item(b"covr", b"\x89PNG\r\n\x1a\nSYNTHETIC-COVER-0015", 14),
                                Box(
                                    b"----",
                                    children=[
                                        Box(b"mean", b"\x00" * 4 + b"com.apple.iTunes"),
                                        Box(b"name", b"\x00" * 4 + b"SYNTHETIC-KEY-0016"),
                                        Box(b"data", struct.pack(">II", 1, 0) + b"SYNTHETIC-VALUE-0017"),
                                    ],
                                ),
                            ]
                        )
                    ],
                )
            ],
        ),
    )

    # Adobe's XMP packet, in the `uuid` box §4.2 makes anybody's extension point.
    xmp = (
        b"\xbe\x7a\xcf\xcb\x97\xa9\x42\xe8\x9c\x71\x99\x94\x91\xe3\xaf\xac"
        b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description dc:creator="SYNTHETIC-CREATOR-0018" '
        b'xmp:CreatorTool="SYNTHETIC-TOOL-0019"/></rdf:RDF></x:xmpmeta>'
        b"<?xpacket end=\"w\"?>"
    )
    write(OUT, "xmp-uuid.mp4", with_boxes(base_mp4, extra_top=[(1, Box(b"uuid", xmp))]))

    # Free space, which is where a producer parks a deleted atom rather than rewriting the file.
    write(
        OUT,
        "free-space.mp4",
        with_boxes(
            base_mp4,
            extra_top=[
                (1, Box(b"free", b"SYNTHETIC-FREE-0020" + b"\x00" * 13)),
                (3, Box(b"skip", b"SYNTHETIC-SKIP-0021" + b"\x00" * 13)),
            ],
        ),
    )

    # `moov` in front of `mdat` — the "faststart" layout a file gets before it is streamed. The
    # interesting half is that removing anything now moves the media, where in the other layout it
    # does not.
    tops = baseline(base_mp4)
    moov = next(t for t in tops if t.typ == b"moov")
    moov.children.append(Box(b"udta", children=[atom(A + b"nam", "SYNTHETIC-TITLE-0022")]))
    tops = [t for t in tops if t.typ != b"moov"]
    tops.insert(1, moov)
    tops.insert(1, Box(b"free", b"SYNTHETIC-FREE-0023" + b"\x00" * 5))
    write(OUT, "faststart.mp4", assemble(tops))

    # A `mdat` carrying the 64-bit size escape, which is how a file over 4 GB spells it. The header
    # form has to survive the copy or every offset behind it is wrong.
    tops = baseline(base_mp4)
    next(t for t in tops if t.typ == b"mdat").force64 = True
    tops.insert(1, Box(b"free", b"SYNTHETIC-FREE-0024" + b"\x00" * 5))
    write(OUT, "sixty-four-bit-mdat.mp4", assemble(tops))

    # Timestamps and a language in the three mandatory header boxes, which are edited rather than
    # removed because the boxes have to stay.
    tops = baseline(base_mp4)
    set_times(next(t for t in tops if t.typ == b"moov"))
    write(OUT, "timestamps.mp4", assemble(tops))

    # Microsoft's `Xtra`, and an `iods` — two boxes that are neither on a keep list nor anything
    # strypt has heard of, so they exercise the drop-and-report path rather than a named rule.
    write(
        OUT,
        "unknown-boxes.mp4",
        with_boxes(
            base_mp4,
            moov_extra=[Box(b"iods", b"\x00" * 4 + b"SYNTHETIC-IODS-0025")],
            trak_extra=[Box(b"Xtra", b"SYNTHETIC-XTRA-0026")],
        ),
    )

    print("malformed:")
    _malformed(base_mp4, base_m4a)
    print("done")
    return 0


def _malformed(base_mp4, base_m4a):
    def tops_of(blob):
        return baseline(blob)

    # Fragmented: the sample offsets move into structures strypt does not rewrite.
    tops = tops_of(base_mp4)
    tops.append(Box(b"moof", b"\x00" * 8))
    write(MALFORMED, "fragmented.mp4", assemble(tops))

    tops = tops_of(base_mp4)
    next(t for t in tops if t.typ == b"moov").children.append(Box(b"mvex", b"\x00" * 8))
    write(MALFORMED, "movie-extends.mp4", assemble(tops))

    # Common Encryption, spelled both ways strypt looks for it.
    tops = tops_of(base_mp4)
    stsd = next(t for t in tops if t.typ == b"moov").find(
        b"trak", b"mdia", b"minf", b"stbl", b"stsd"
    )
    stsd.payload = stsd.payload[:12] + b"encv" + stsd.payload[16:]
    write(MALFORMED, "encrypted-sample-entry.mp4", assemble(tops))

    tops = tops_of(base_mp4)
    next(t for t in tops if t.typ == b"moov").children.append(Box(b"pssh", b"\x00" * 20))
    write(MALFORMED, "protection-system.mp4", assemble(tops))

    # A chunk offset pointing at a box that is about to be deleted, and one past the end of the
    # file. Neither can be relocated, so neither may be guessed at.
    tops = tops_of(base_mp4)
    tops.insert(1, Box(b"free", b"\x00" * 24))
    blob = bytearray(assemble(tops))
    _repoint(blob, 8)
    write(MALFORMED, "chunk-offset-into-free.mp4", bytes(blob))

    tops = tops_of(base_mp4)
    blob = bytearray(assemble(tops))
    _repoint(blob, len(blob) + 4096)
    write(MALFORMED, "chunk-offset-past-end.mp4", bytes(blob))

    # A track whose samples are in another file: §8.7.2's self-contained flag cleared.
    tops = tops_of(base_mp4)
    dref = next(t for t in tops if t.typ == b"moov").find(
        b"trak", b"mdia", b"minf", b"dinf", b"dref"
    )
    dref.payload = dref.payload[:16] + b"\x00\x00\x00\x00" + dref.payload[20:]
    write(MALFORMED, "external-data-reference.mp4", assemble(tops))

    tops = [t for t in tops_of(base_mp4) if t.typ != b"moov"]
    write(MALFORMED, "no-movie-box.mp4", assemble(tops))

    tops = tops_of(base_mp4)
    tops.append(next(t for t in tops_of(base_mp4) if t.typ == b"moov"))
    write(MALFORMED, "two-movie-boxes.mp4", assemble(tops))

    tops = tops_of(base_mp4)
    moov = next(t for t in tops if t.typ == b"moov")
    moov.children = [c for c in moov.children if c.typ != b"trak"]
    write(MALFORMED, "no-track.mp4", assemble(tops))

    blob = assemble(tops_of(base_mp4))
    write(MALFORMED, "truncated.mp4", blob[: len(blob) // 2])

    # Refused on the brand alone, before any of the above is looked at.
    for name, brand in (
        ("quicktime.mov", b"qt  "),
        ("protected.m4a", b"M4P "),
        ("three-gpp.mp4", b"3gp4"),
        ("fragmented-brand.mp4", b"dash"),
    ):
        tops = tops_of(base_m4a if name.endswith(".m4a") else base_mp4)
        ftyp = next(t for t in tops if t.typ == b"ftyp")
        ftyp.payload = brand + ftyp.payload[4:8] + brand + ftyp.payload[12:]
        write(MALFORMED, name, assemble(tops))


def _repoint(blob, value):
    """Point every `stco` entry in an assembled file at `value`."""
    at = blob.find(b"stco")
    count = struct.unpack(">I", blob[at + 8 : at + 12])[0]
    for i in range(count):
        start = at + 12 + i * 4
        blob[start : start + 4] = struct.pack(">I", value)


if __name__ == "__main__":
    sys.exit(main())
