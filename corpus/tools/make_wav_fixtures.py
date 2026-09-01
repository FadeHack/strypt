#!/usr/bin/env python3
"""Generate the WAV fixtures in ``corpus/wav``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design.

**These are real, playable WAV files.** mat2 reaches WAV through ffmpeg, which will not open a
file whose ``fmt `` does not parse, and the differential is worthless if the comparison tool
refuses the input. The audio is a quarter-second of 16-bit mono PCM at 8 kHz.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "wav"
MALFORMED = OUT / "malformed"

SAMPLE_RATE = 8000
CHANNELS = 1
BITS = 16
FRAMES = SAMPLE_RATE // 4


def chunk(kind, payload):
    """One RIFF chunk, with the pad byte an odd payload requires."""
    assert len(kind) == 4
    out = kind + struct.pack("<I", len(payload)) + payload
    return out + b"\x00" * (len(payload) & 1)


def riff(parts, form=b"WAVE", magic=b"RIFF"):
    body = form + b"".join(parts)
    return magic + struct.pack("<I", len(body)) + body


def fmt():
    """The PCM form: 16 bytes, no extension size field."""
    block_align = CHANNELS * BITS // 8
    return chunk(
        b"fmt ",
        struct.pack(
            "<HHIIHH",
            1,
            CHANNELS,
            SAMPLE_RATE,
            SAMPLE_RATE * block_align,
            block_align,
            BITS,
        ),
    )


def data():
    """A 440 Hz tone, so a decoded-audio MD5 comparison has something to compare."""
    samples = bytearray()
    for n in range(FRAMES):
        value = int(12000 * math.sin(2 * math.pi * 440 * n / SAMPLE_RATE))
        samples += struct.pack("<h", value)
    return chunk(b"data", bytes(samples))


def info(tags):
    body = b"INFO" + b"".join(chunk(tag, value + b"\x00") for tag, value in tags)
    return chunk(b"LIST", body)


def adtl():
    """A cue point's label and note, plus a labelled text region."""
    body = b"adtl"
    body += chunk(b"labl", struct.pack("<I", 1) + b"SYNTHETIC-LABEL-0010\x00")
    body += chunk(b"note", struct.pack("<I", 1) + b"SYNTHETIC-NOTE-0011\x00")
    body += chunk(
        b"ltxt",
        struct.pack("<IIIHHHH", 1, 100, 0x72676E20, 0, 0, 0, 0)
        + b"SYNTHETIC-REGION-0012\x00",
    )
    return chunk(b"LIST", body)


def cue():
    """One cue point. Its offsets are relative to the data section, not to the file."""
    point = struct.pack("<IIIIII", 1, 0, 0x64617461, 0, 0, 400)
    return chunk(b"cue ", struct.pack("<I", 1) + point)


def bext():
    """EBU Tech 3285, the Broadcast Wave extension."""
    body = bytearray(602)
    body[0:31] = b"SYNTHETIC-DESCRIPTION-0013".ljust(31, b"\x00")[:31]
    body[256:288] = b"SYNTHETIC-ORIGINATOR-0014".ljust(32, b"\x00")
    body[288:320] = b"SYNTHETIC-ORIGREF-0015".ljust(32, b"\x00")
    body[320:330] = b"2026-09-01"
    body[330:338] = b"12:00:00"
    struct.pack_into("<Q", body, 338, 0)
    struct.pack_into("<H", body, 346, 2)
    body[348:412] = b"SYNTHETIC-UMID-0016".ljust(64, b"\x00")
    history = b"A=PCM,F=8000,W=16,M=mono,T=SYNTHETIC-DECK-0017\r\n"
    return chunk(b"bext", bytes(body) + history)


def cart():
    """AES46-2002, the radio traffic chunk."""
    body = bytearray(2048)
    body[0:4] = b"0101"
    body[4:68] = b"SYNTHETIC-TITLE-0018".ljust(64, b"\x00")
    body[68:132] = b"SYNTHETIC-CART-ARTIST-0019".ljust(64, b"\x00")
    body[132:196] = b"SYNTHETIC-CUTID-0020".ljust(64, b"\x00")
    body[196:260] = b"SYNTHETIC-CLIENT-0021".ljust(64, b"\x00")
    body[388:398] = b"2026/09/01"
    body[420:484] = b"SYNTHETIC-PRODUCER-APP-0022".ljust(64, b"\x00")
    body[484:548] = b"1.0-SYNTHETIC-0023".ljust(64, b"\x00")
    body[1024:2048] = b"https://synthetic.invalid/0024".ljust(1024, b"\x00")
    return chunk(b"cart", bytes(body))


def ixml():
    """A field recorder's XML block: project, scene, take, and the recorder's serial."""
    doc = (
        b"<BWFXML><PROJECT>SYNTHETIC-PROJECT-0025</PROJECT>"
        b"<SCENE>SYNTHETIC-SCENE-0026</SCENE><TAKE>7</TAKE>"
        b"<NOTE>SYNTHETIC-NOTE-0027</NOTE>"
        b"<SPEED><MASTER_SPEED>25/1</MASTER_SPEED></SPEED>"
        b"<DEVICE><SERIAL>SYNTHETIC-SERIAL-0028</SERIAL></DEVICE></BWFXML>"
    )
    return chunk(b"iXML", doc)


def xmp():
    packet = (
        b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description xmp:CreatorTool="SYNTHETIC-TOOL-0029"'
        b' xmpMM:DocumentID="uuid:SYNTHETIC-0030"'
        b' dc:creator="SYNTHETIC-CREATOR-0031"/>'
        b"</rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
    )
    return chunk(b"_PMX", packet)


def id3():
    """An ID3v2.4 tag inside an `id3 ` chunk. Dropped whole; never parsed (ADR-0037)."""
    frame = b"TPE1" + struct.pack(">I", 27) + b"\x00\x00" + b"\x03SYNTHETIC-ID3-ARTIST-0032"
    size = len(frame)
    syncsafe = bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F, (size >> 7) & 0x7F, size & 0x7F])
    return chunk(b"id3 ", b"ID3\x04\x00\x00" + syncsafe + frame)


def smpl():
    """A sampler chunk: MIDI manufacturer and product numbers, and one loop."""
    head = struct.pack("<IIIIIIIII", 0x0000_0001, 0x0000_002A, 125000, 60, 0, 0, 0x11223344, 1, 0)
    loop = struct.pack("<IIIIII", 0, 0, 0, 400, 0, 0)
    return chunk(b"smpl", head + loop)


def junk(text):
    return chunk(b"JUNK", text.ljust(64, b"\x00"))


def write(path, blob):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    print(f"  {path.relative_to(ROOT.parent)}  ({len(blob)} bytes)")


INFO_TAGS = [
    (b"IART", b"SYNTHETIC-ARTIST-0001"),
    (b"INAM", b"SYNTHETIC-TITLE-0002"),
    (b"ICRD", b"2026-09-01"),
    (b"ISFT", b"SYNTHETIC-RECORDER-0003"),
    (b"IENG", b"SYNTHETIC-ENGINEER-0004"),
    (b"ITCH", b"SYNTHETIC-TECHNICIAN-0005"),
    (b"ICMT", b"SYNTHETIC-COMMENT-0006"),
    (b"ICOP", b"SYNTHETIC-COPYRIGHT-0007"),
    (b"IARL", b"SYNTHETIC-ARCHIVE-0008"),
    (b"ISRC", b"SYNTHETIC-SOURCE-0009"),
]


def main():
    print("writing WAV fixtures")

    # Nothing to remove. strypt must hand this back byte-identical.
    write(OUT / "clean.wav", riff([fmt(), data()]))

    write(OUT / "info-list.wav", riff([fmt(), info(INFO_TAGS), data()]))
    write(OUT / "adtl-list.wav", riff([fmt(), data(), cue(), adtl()]))
    write(OUT / "broadcast-extension.wav", riff([fmt(), bext(), data()]))
    write(OUT / "cart.wav", riff([fmt(), cart(), data()]))
    write(OUT / "ixml.wav", riff([fmt(), data(), ixml()]))
    write(OUT / "xmp.wav", riff([fmt(), data(), xmp()]))
    write(OUT / "id3.wav", riff([fmt(), data(), id3()]))
    write(OUT / "sampler.wav", riff([fmt(), data(), smpl()]))

    # Padding is zeroed at its length rather than dropped (ADR-0039, following ADR-0038): a
    # producer that reserved room by writing out an old buffer left whatever was in it.
    write(OUT / "padding.wav", riff([fmt(), junk(b"SYNTHETIC-LEFTOVER-0033"), data()]))

    # A cue point survives, because nothing this handler removes can move its offsets.
    write(OUT / "cue-points.wav", riff([fmt(), data(), cue()]))

    # A chunk nobody has a name for is where a producer puts what they do not want looked at.
    write(
        OUT / "unknown-chunk.wav",
        riff([fmt(), data(), chunk(b"PrVw", b"SYNTHETIC-PRIVATE-0034")]),
    )

    # Nothing reads past the length the RIFF header declares.
    write(OUT / "trailing.wav", riff([fmt(), data()]) + b"SYNTHETIC-APPENDED-0035")

    write(
        OUT / "kitchen-sink.wav",
        riff(
            [
                fmt(),
                junk(b"SYNTHETIC-LEFTOVER-0033"),
                bext(),
                cart(),
                info(INFO_TAGS),
                data(),
                cue(),
                adtl(),
                ixml(),
                xmp(),
                id3(),
                smpl(),
                chunk(b"DISP", struct.pack("<I", 1) + b"SYNTHETIC-DISPLAY-0036\x00"),
                chunk(b"CSET", struct.pack("<HHHH", 1252, 0, 9, 1)),
                chunk(b"PrVw", b"SYNTHETIC-PRIVATE-0034"),
            ]
        )
        + b"SYNTHETIC-APPENDED-0035",
    )

    print("writing malformed WAV fixtures")

    good = riff([fmt(), info(INFO_TAGS), data()])

    # Cut short mid-chunk. Refused, not repaired: a cleaned copy of a truncated file would be a
    # repair the user never asked for, presented as a clean version.
    write(MALFORMED / "truncated.wav", good[: len(good) // 2])

    # A RIFF size claiming more than the file holds.
    write(
        MALFORMED / "riff-size-past-end.wav",
        good[:4] + struct.pack("<I", 0x00FF_FFFF) + good[8:],
    )

    # A chunk claiming more than the RIFF extent says is left.
    write(
        MALFORMED / "chunk-past-extent.wav",
        riff([fmt(), b"iXML" + struct.pack("<I", 0x0010_0000) + b"<x/>", data()]),
    )

    # A four-character code that is not ASCII: the walk is no longer where it thinks it is.
    write(
        MALFORMED / "non-ascii-code.wav",
        riff([fmt(), data(), b"\x00\x01\x02\x03" + struct.pack("<I", 0)]),
    )

    # No audio, and no format. Either strips to a valid-looking container of nothing.
    write(MALFORMED / "no-data.wav", riff([fmt(), bext()]))
    write(MALFORMED / "no-fmt.wav", riff([data(), info(INFO_TAGS)]))

    # A `fmt ` shorter than the PCM form is not a `fmt `.
    write(MALFORMED / "short-fmt.wav", riff([chunk(b"fmt ", b"\x01\x00\x01\x00"), data()]))

    # A wave list: the one shape where a cue offset indexes into something removal could move.
    # Refused by name rather than edited (ADR-0039).
    wavl = chunk(b"LIST", b"wavl" + data() + chunk(b"slnt", struct.pack("<I", 100)))
    write(MALFORMED / "wave-list.wav", riff([fmt(), wavl]))

    # RF64 is a different container, not a large WAV: the real sizes live in `ds64` and the RIFF
    # size field is a placeholder. Named at detection rather than walked as WAV.
    ds64 = chunk(b"ds64", struct.pack("<QQQI", 0, len(data()) - 8, FRAMES, 0))
    write(
        MALFORMED / "rf64.wav",
        b"RF64" + struct.pack("<I", 0xFFFF_FFFF) + b"WAVE" + ds64 + fmt() + data(),
    )

    # A RIFF container that is neither WebP nor WAV.
    write(MALFORMED / "avi.wav", riff([chunk(b"LIST", b"hdrl")], form=b"AVI "))


if __name__ == "__main__":
    sys.exit(main())
