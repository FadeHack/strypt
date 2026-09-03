#!/usr/bin/env python3
"""Generate the Ogg fixtures in ``corpus/ogg``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design.

**These are real, decodable Ogg files.** mat2 reaches Ogg through mutagen and the differential
checks the audio with ffmpeg, so a fixture no decoder accepts would prove nothing. A Vorbis setup
header is a codebook table nobody can hand-write, so the identification, setup and audio packets
below were produced once with ffmpeg 9.0.1 and are embedded here as base64 — the pagination, the
CRCs and every comment are this script's own work.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report.
"""

import base64
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "ogg"
MALFORMED = OUT / "malformed"


def _b64(*parts):
    return base64.b64decode("".join(parts))


# --- VORBIS: from ffmpeg 9.0.1, see corpus/MANIFEST.md
VORBIS_ID = _b64(
    "AXZvcmJpcwAAAAACRKwAAAAAAAAAAAAAAAAAALsB"
)
VORBIS_SETUP = _b64(
    "BXZvcmJpcxxCQ1YCABAAAIR0mlmqASLMQIaB0JCVAAACAABghCIMMSA0ZCUAABAAACCGkoNoQmvON+c4aJaDplJsTgcn"
    "Um2e5KZibs4555xzsjlnjHPOOacoZxaDZkJrzjknMWiWgmZCa84550lsHrSmSmvOOWecczoYZ4RxzjmnSWsepGZjbc45"
    "Z0FrmqPmUmzOOSdSbp7U5lJtzjnnnHPOOeecc845p3pxOgfnhHPOOSdqb67lJnRxzjnnk3G6NyeEc84555xzzjnnnHPO"
    "OScIDVkJAAABABCEYWMYdwqC9DkaiFGEmIZMetA9OkyCxiCnkHo0OhoppQ5CSWWclNIJQkNWAgCAAAAQQkghhRRSSCGF"
    "FFJIIYUYYoghhpxyyimooJJKKqooo8wyyyyzzDLLLLMOO+usww5DDDHE0EorsdRUW4011pp7zrnmIK2V1lprrZRSSiml"
    "lILQkJUAAAgAAIGQQQYZZBRSSCGFGGLKKaecggoqIDRkJQAABgDAIWeggQYaaKCBBhpooHHGGYgggggiqKSSTDoKKbXY"
    "aswx116DDjr3nnvvufgchFJKKaWUUkoppZRSSiklCA1ZCQCAAAAACCGEEFJIIYUUUooxxhxzDjoJJQRCQ1YCAGAAAAwx"
    "xBhkkEFIIYUYYoopxxxzDDoIIZRSUmihhVxqiCWWVlqJpaWYaoux1lhz7THW3nvvvffee++99957zoHQkJUAQAQAAIMM"
    "IogggowxBiEEhIasBABAAAAQYogxxiCEEFKIIaecgkwy6aSjkAKhISsBACcAAIQRRyRxBBJnoIEIKqkgo8xCLLG11lpr"
    "rbXWWmuttdZaa6211lprrbXWWmuttdZaay0QGrISAIgAAGCQQQYZRBBBBBlkgNCQlQAACAAAI4xABBmlFGOOOeYYdNBB"
    "Jx2FFlogNGQlAOAEAEAgoYgyzDAEEVVUUUYVVRRSRymllFJKKaWUUkoppZRSSimllFJKKaWUUkoppVRKKaUEQkNWAgBk"
    "AACQopRSKS1FgiKlGKQYS0YVc1BaiqhyDFLNqVLOIOYklogxhJSTVDLmFEIMQuocdUwpBi2VGELGGKTYckuhcw4IDVkh"
    "AIRmADgcB5AsC5AsCwAAAAAAAAAkTQM0zwMszQMAAAAAAAAASdMAy9MAzfMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJA0DdA8D9A8DwAAAAAAAAA0zwM8TwQ8UQQA"
    "AAAAAAAAy/MATfQATxQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAJA0DdA8D9A8DwAAAAAAAAAszwM8UQQ0TwQAAAAAAAAAy/MATxQBT/QAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAKOAAAClgIhYasCADiBAAckgRJ"
    "giRB8wCSZUHToGkwTYBkWdA0aBpMEwAAAAAAAAAAAABJ06Bp0DSIIkDSNGgaNA2iCAAAAAAAAAAAAICkadA0aBpEESBp"
    "GjQNmgZRBAAAAAAAAAAAAMAzTYgiRBGmCfBME6IIUYRpAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAJHAAABUwoA4WG"
    "rAgA4gQAHI5iWQAA4DiOZQEAgOM4lgUAAJZliSIAAFiWJooAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAkcAAAFTCgDhYasBACiAAAcimJZwHEsCziOZQFJsiyAZQE0"
    "D6BpAFEEAAIAAA0cAAAFbNCUWByg0JCVAEAUAIBBcSxL00SRJGma5okiSdI0zxNFmuZ5nmea8DzPM02IoiiaJkRRFE0T"
    "pmmaqgpMU1UFAAAaOAAACtigKbE4QKEhKwGAkAAAh6JYlqZ5nueJommqJknSNM8TRVE0TdNUVZKkaZ4niqJomqapqixL"
    "0zxPFEXRNFVVVaFpnieKomiaqqq68DzPE0VRNE1VdV14nueJoiiapqq6LkRRFE3TNFVTVV0XiKJpmqaqqqrrAtETRdNU"
    "Vdd1XeB5omiaquqqrgtE0zRVVVVdV5YBpmmaquq6sgxQVVV1XdeVZYCqqqrruq4sA1TVdV1XlmUZgOu6rizLsgAAQAQH"
    "AEABI+gko8oibDThwgNQaMiKACAKAAAwhinFlDKMSQgphIYxCSGFkElJqbSUKgiplFRKBSGVkkrJKKWUWkoVhFRKKqWC"
    "kEpJpRQAAIvgAACLYCEUGrISAMgDACCMUYoxxpyTCCnFmHPOSYSUYsw556RSjDnnnHNSSsYcc845KaVzzjnnnJSSOeec"
    "c05K6ZxzzjknpZTSOeeck1JKCaFz0EkppXTOOecEAIAaOAAACtgosjnBSFChISsBgFQAAIPjWJameZ4omqYlSZrmeZ4n"
    "iqapSZKmeZ7niaJq8jzPE0VRNE1V5XmeJ4qiaJqqynVF0TRNU1VVlyyLommapqq6LkzTNFXVdV0Xpmmaquq6rgvbVlVV"
    "dV1Zhm2rqqq6riwD13VdWbZlIMuuK7u2LAAAXsEBANTAhtURTorGAgsNWQkAZAAAEMYgpBBCSBmEkEIIIaUUQgIAAAkc"
    "AAAFTCgDhYasBABSAQAAY6y11lprrTXQWWuttdZaKyCz1lprrbXWWmuttdZaa6211FprrbXWWmuttdZaa6211lprrbXW"
    "WmuttdZaa6211lprrbXWWmuttdZaa6211lprrbXWWksppZRSSimllFJKKaWUUkoppZRSAUC/Fg4A/xA2rI5wUjQWWGjI"
    "SgAgHAAAMEYpxhyDUEopFUKMOScdldZirBBizDkJKbUWW/GccxBKSKW1GIvnnINQSkqx1VhUCqGUlFKLLdaiUuiopJRS"
    "azUWY0wqqbXWYquxGGNSCi211mKMxQhbU2otttpqLMbYmkoLLcYYYzHCFxlbi6m2WoMxwsgWS0u11hqMMUb31mKpreZi"
    "jA++thRLjDUXAODu4ACAqGDjDCtJZ4WjwYWGrAQAQgIACISUYowxxpxzzjmpFGOOOeecgxBCKJVijDHnnIMQQgglY4w5"
    "5xyEEEIIoZSSMecchBBCCCGklDrnHIQQQgghhFJK55yDEEIIIYRQSukghBBCCCGEEkopKYUQQgghhBBCKimlEEIIoZQQ"
    "SkglpRRCCCGEUEoJKaWUQgihlBBCKCGllFJKIYQQQimlpJRSSqmEUkIJoYRUSkophRJCCKWUklJKKZVSQiihhFJKSSml"
    "lFIIIYRSSgEAgAgOAIACRtBJRpVF2GjChQcgAAAABAAgCJEZIlGwAAwOVABCwhQAUFhgkAMADQ4PaRcX0GWAC7q460AI"
    "QQhCEIsDKCABByfc8MQbnnCDE3SKSg0IAAAAAAAZAHwAACQPQERENHMQERITFBUWFxgZGhscAACAAAIAABAAAAAAAAgA"
    "AAAAEA=="
)
VORBIS_AUDIO = _b64(
    "vrfygUZ0FUILUggXMo5DCGWEhPZWPtCIrkJoQQrhQsZxCKGMkNCPoiyLoiyLoiyLoiwLAIDNchUBAAAAAAAAAAAAAGvE"
    "WmOsCohaicyo1IQE6HV6S425hbmFmYWpuYmJMWFcXHx8TFxsbExMbGwkJtqz06Pb7XS63U6n7Tad9uWrl69evnr56uWr"
    "l6/0Qz/0Qz/0Qz8eP378+PHjx48fP378+PHjx48fP34cH41Go9FoNBqNRqOeE8KbBgrW/wmI/xIx9kfse9EIO2WinBDe"
    "NFCw/k9A/JeIsT9i34tG2CkTwRICAAAAAAAAAAAAAAAAAAAAAETRcBkAhMbUwkxqJQAAXjfTGYovgTCDEPRws2iEhTJR"
    "3UxnKL4EwgxC0MPNohEWykQvWmH7/QQAcMZgWVZVVRUAAACw2x0dDLU7WAzDsDlaRahVrWcCmGgNqAadhblRRWMws0hM"
    "YhKJi4gwNj4+YXx8bDREkUhMXFxcTCQQYdjt2bNnz25b0jSdTqdHp9NEtW232+1227akaTqdTqdpQrVtt9vttm2Rpmk6"
    "nUaTff369el88eKFJvv69euTfPHiRbKvX79e8sWLF8m+fn0ueb/QrP9/HR+X///O+Pj6/78zPr7+/++Mj+///zY+vv//"
    "2/j4/v9v43H7v7aNx+3/2jYet/9r23jc/vfbuLX//eG49f37w3Hr+9fhuHz/OhyX71+H4wI+V2MBQ3aFFgTxJmx0I4TQ"
    "iLkaCxiyK7QgiDdhoxshhEb8kEVZlEUZKcqiWgEAOHuMJsuynKuqqgJgsCKKGBE1Ysgoi7LIyMhISBODULVG1WA0mFqY"
    "GRVF4xJNTOKJSTxBbEAYiU+QaIKEcbERE0Rj4hMkjIuNhFIYiY2Lj4uNiQo33R49e/Ts0W1K2k7PHj17dJs2qul2evbo"
    "dtqotJ1up9vpNiVt0+307HQ7bVTTdrqdbqdtStqm2+l22qaimrbT7XSbNiXtq1evDp6XL1/q/K9evRqely9fFv+rV68m"
    "npcvX1bPq1eHRL18qbvn1atDol6+1N3z6tXIcrHyfPVqJJ6XLyvPF2+5aD9fvOWi/fLiLS7aLy/e4qK+vMjior68yOKi"
    "vrzI4qK+vLC4yMsLi4u8vLC4yEuKxcp+SbXFyn5JtcXKfkm1RXu/eG3R3i9eW7T3i9cA"
)
VORBIS_LACING = [182, 76, 278, 343]
VORBIS_GRANULE = 2688

# --- OPUS: from ffmpeg 9.0.1, see corpus/MANIFEST.md
OPUS_HEAD = _b64(
    "T3B1c0hlYWQBATgBgLsAAAAAAA=="
)
OPUS_AUDIO = _b64(
    "eIGnXWyemawAAAgK4FrVEZxEMRUFez3mfhy4+Q1ZWV8h0Lo6pY51ODwaGB+5+vFq2fXVcJFPCzga/phDsLVDqvBZa+L0"
    "NQ4NAGXEDRLh4XJsQY0ykTiyyEiUgOWl6gR4n2cB5/yVTU6qGKcZ3+VcWd/7bqEzZfWopUkN5Fd3h48KQtCSRpH9H9Q7"
    "cD/31ZeoOFaCUiVwC7qWPBwPT0H3ib14mrLfdZz8SzpFfihacofGg4g7HEcqFigYE0QB/7oPk8Kx4XXYo/yU0WxOgXG2"
    "8yAjp5/11uf3LN18BXgGOiaBc8bAKnPAhzWzA0hLNCu6cSVZZuXWHooBsfwRQN1GgSOmKt8ZIQ=="
)
OPUS_LACING = [95, 66, 59, 42]
OPUS_GRANULE = 3192

# --- FLAC: from ffmpeg 9.0.1, see corpus/MANIFEST.md
FLAC_MAPPING = _b64(
    "f0ZMQUMBAAABZkxhQwAAACIEAAQAAAAAAAgVCsRA8AAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
FLAC_AUDIO = _b64(
    "//ipCABQTAAAAQAB/wL9A/gE7gXg5iSY1v3wxB9IDp+PQJrAChMmZChmSSTIUKGGShCmBEMhUNM5oUyXlnM5OSWSU8PJ"
    "kk5MlDDDw4ThKE5MmTJmUM4WSIaU00yeZSczOZMKFChQpMySFJkwhSHJnMyU5QpmZz+cKUMpmZMlCeEochQwzDJhOFDh"
    "kk4FhKQoWQ0KFPNMuUKc0KhLJmGhwszJwzJhMMhkyZCk4aGYUhYRCXDy5poSlJElKToSwpOEQJQyhQ4ZIUkkMhw5kyTJ"
    "hmFMyhSSlJfznw4WShSUk5MwzIUkwkwnhQmTJwzhlDmcsLLMllKSh5yZyhLDkyShhYUhkKGQpkkyFCSZykpnymUzOdPC"
    "yhZPJhzDJKFITJkJQmSSSTChKSThQLJKU8pKE5woXyzTwplCwplIc5MOQmSUJMKFDChQkoFhzAiScOSkynlKU2Qpnn5T"
    "OeZJoFJOpYL/+KkIAVdOD6YP0w/xD/4P/A/pD8YPk+Ym2McCFKwWP6Fgvb7zwPCABylKS/ZzCIWGFgUlChk4STJkkmTA"
    "oTDDMzJQImcyfQ52ESUpSRDzmEScKHJkyFJDhMJkmEoFgUJhhOHOEslJQ0Il9ynz8/KTDMMmYUOBQKSEoZDJJJkOFIUK"
    "BQslC5KeWVJE+aBBDSU5zKShwoSTJMJMChMkoBQmShlCgUlDkoUlND+cplKShZmk5kwoZMMKQoSZDDJJhkMKBycIgUkz"
    "OUIlKU5ZE2WFlKETMoaBEMnDhwzCSSGSTCZJKBkwwpJQ5nP8tCnlJ5Q5c0CIYUzkoSSQiBKBkKGGGZJJMhSYcoU4RClO"
    "nJELnIhllCkKFAiSmShYYYZCgZJMMwmBSSQoaGSc84XCyhGadCpTQpykiFJQzChkKSTDJhMMMhkKHJyShKEwpPClOfnP"
    "0oUyESmSyaFMoZMCkkKQKEwwzDDJkmTkzOGcOUNC8vsoQDV6//h5CAICVTFMBn0FjwScA6QCqAGqAKrmKoe1ODAP+p/8"
    "n8FAbIAMlAiQggUpTywiEQiEQyhQxAiHhSSZKARJDJDOBQyFCQoTAoUAggZQIhmUkiBfecssL7KShEKU0KFCkOHCYTMI"
    "UDDJJJJCgUChQlCUwIIFJYaU+hEppynmclmUyUMkMkJkkmTJQKBQMw4eBoZkyU00pQpwjJEKhENNKHzKE5mGTCYUCIFA"
    "oFCYUJIUJJMJEhwmczNCyhEMzOf7IhEKUzMmSgZkOHIUCgZhkwyQoFIUMnCJJSUCJmhECIWmlCJlCIcsCw2ZMOFIUkhk"
    "mGZMOBSGTJQloOU="
)
FLAC_LACING = [353, 373, 251]
FLAC_GRANULE = 2646


def split(blob, lengths):
    """The audio packets, cut back out of the blob they were stored as."""
    out, at = [], 0
    for n in lengths:
        out.append(blob[at : at + n])
        at += n
    return out


VORBIS_PACKETS = split(VORBIS_AUDIO, VORBIS_LACING)
OPUS_PACKETS = split(OPUS_AUDIO, OPUS_LACING)
FLAC_PACKETS = split(FLAC_AUDIO, FLAC_LACING)

# The `STREAMINFO` block inside the mapping packet: `\x7fFLAC`, two version bytes, a 16-bit header
# count, `fLaC`, then the block itself. ffmpeg leaves the audio MD5 zero when it writes this header
# into a non-seekable Ogg stream, and RFC 9639 §8.2 spells zero as "unknown", so a synthetic one is
# stamped in — otherwise no fixture exercises the retention ADR-0038 decision 4 requires.
FLAC_STREAMINFO_BLOCK = FLAC_MAPPING[13:35] + bytes([0xAB]) * 16 + FLAC_MAPPING[51:]

NO_GRANULE = 0xFFFFFFFFFFFFFFFF
CONTINUED, BOS, EOS = 0x01, 0x02, 0x04


def crc(data):
    """RFC 3533 §6.2: polynomial 0x04c11db7, unreflected, no final xor."""
    r = 0
    for byte in data:
        r = (r ^ (byte << 24)) & 0xFFFFFFFF
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if r & 0x80000000 else (r << 1) & 0xFFFFFFFF
    return r


def raw_page(flags, granule, serial, sequence, lacing, body):
    out = bytearray(b"OggS\x00")
    out.append(flags)
    out += struct.pack("<QIII", granule, serial, sequence, 0)
    out.append(len(lacing))
    out += bytes(lacing) + body
    out[22:26] = struct.pack("<I", crc(bytes(out)))
    return bytes(out)


def paginate(serial, groups):
    """Lay `groups` — a list of (granule, [packet, ...]) — out as pages.

    One page per group, split at 255 segments with a −1 granule where a packet runs on, which is
    the layout strypt rebuilds to. The last page is flagged as the end of the stream.
    """
    out, sequence, lacing, body, continued = bytearray(), 0, [], bytearray(), False
    pages = []
    for granule, packets in groups:
        for packet in packets:
            written = 0
            while True:
                if len(lacing) == 255:
                    pages.append((CONTINUED if continued else 0, NO_GRANULE, lacing, bytes(body)))
                    lacing, body, continued = [], bytearray(), True
                take = min(255, len(packet) - written)
                lacing.append(take)
                body += packet[written : written + take]
                written += take
                if take < 255:
                    break
        pages.append((CONTINUED if continued else 0, granule, lacing, bytes(body)))
        lacing, body, continued = [], bytearray(), False

    for index, (flags, granule, page_lacing, page_body) in enumerate(pages):
        if index == 0:
            flags |= BOS
        if index + 1 == len(pages):
            flags |= EOS
        out += raw_page(flags, granule, serial, sequence, page_lacing, page_body)
        sequence += 1
    return bytes(out)


def le32(n):
    return struct.pack("<I", n)


def comment_body(vendor, items):
    """A Vorbis comment: a vendor string, a count, then that many `NAME=value` items."""
    out = le32(len(vendor)) + vendor + le32(len(items))
    for item in items:
        out += le32(len(item)) + item
    return out


def vorbis_comment_packet(vendor, items):
    return b"\x03vorbis" + comment_body(vendor, items) + b"\x01"


def opus_tags_packet(vendor, items, padding=b""):
    return b"OpusTags" + comment_body(vendor, items) + padding


def flac_block(kind, payload, last=False):
    return bytes((kind | (0x80 if last else 0),)) + struct.pack(">I", len(payload))[1:] + payload


def flac_mapping_packet(headers):
    return b"\x7fFLAC\x01\x00" + struct.pack(">H", headers) + b"fLaC" + FLAC_STREAMINFO_BLOCK


def vorbis_file(vendor, items, serial=0x5A17_C0DE):
    return paginate(
        serial,
        [
            (0, [VORBIS_ID]),
            (0, [vorbis_comment_packet(vendor, items), VORBIS_SETUP]),
            (VORBIS_GRANULE, VORBIS_PACKETS),
        ],
    )


def opus_file(vendor, items, padding=b"", serial=0x09_05_11_5E):
    return paginate(
        serial,
        [
            (0, [OPUS_HEAD]),
            (0, [opus_tags_packet(vendor, items, padding)]),
            (OPUS_GRANULE, OPUS_PACKETS),
        ],
    )


def flac_file(blocks, serial=0x0F_1AC_05, headers=None):
    """`blocks` is a list of (type, payload); the last one gets the last-block flag."""
    packets = [
        flac_block(kind, payload, last=index + 1 == len(blocks))
        for index, (kind, payload) in enumerate(blocks)
    ]
    count = len(blocks) if headers is None else headers
    return paginate(
        serial,
        [
            (0, [flac_mapping_packet(count)]),
            (0, packets),
            (FLAC_GRANULE, FLAC_PACKETS),
        ],
    )


# The comment sets. Every value is a marker, and the field names are the ones real taggers write.
VORBIS_VENDOR = b"Xiph.Org libVorbis SYNTHETIC-VENDOR-0001"
VORBIS_ITEMS = [
    b"ARTIST=SYNTHETIC-ARTIST-0002",
    b"ALBUMARTIST=SYNTHETIC-ARTIST-0003",
    b"TITLE=SYNTHETIC-TITLE-0004",
    b"DATE=2026-09-03T11:22:33Z",
    b"LOCATION=51.5074,-0.1278 SYNTHETIC-PLACE-0005",
    b"ENCODED-BY=SYNTHETIC-OPERATOR-0006",
    b"ENCODER=SYNTHETIC-ENCODER-0007",
    b"MUSICBRAINZ_TRACKID=SYNTHETIC-MBID-0008",
    b"ISRC=SYNTHETIC-ISRC-0009",
    b"COMMENT=SYNTHETIC-COMMENT-0010",
    b"COPYRIGHT=SYNTHETIC-HOLDER-0011",
    b"REPLAYGAIN_TRACK_GAIN=-7.35 dB",
]
OPUS_VENDOR = b"libopus 1.5.2 SYNTHETIC-VENDOR-0012"
OPUS_ITEMS = [
    b"ARTIST=SYNTHETIC-ARTIST-0013",
    b"TITLE=SYNTHETIC-TITLE-0014",
    b"DATE=2026-09-03",
    b"ENCODER=opusenc SYNTHETIC-ENCODER-0015",
    b"GPS=51.5074/-0.1278 SYNTHETIC-FIX-0016",
]


def picture_payload(marker):
    """A FLAC picture block (§8.7): a type, a media type, a description, geometry, and an image."""
    media, description = b"image/png", marker
    image = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
    return (
        struct.pack(">I", 3)
        + struct.pack(">I", len(media))
        + media
        + struct.pack(">I", len(description))
        + description
        + struct.pack(">IIII", 16, 16, 8, 0)
        + struct.pack(">I", len(image))
        + image
    )


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT)}  {len(data)} bytes")


def main():
    print("Ogg fixtures:")

    # A stream whose comment header is already empty. Not byte-identical after a strip: the serial
    # number is rewritten, which is the one thing this group's other handlers do not do (ADR-0041).
    write(OUT / "clean-vorbis.ogg", vorbis_file(b"", []))
    write(OUT / "vorbis.ogg", vorbis_file(VORBIS_VENDOR, VORBIS_ITEMS))

    # Cover art base64-encoded into a comment, which is how taggers put a picture in a Vorbis or
    # Opus stream. It runs past one page's lacing table, so it exercises the spanning path.
    art = base64.b64encode(picture_payload(b"SYNTHETIC-PICTURE-0017")) * 700
    write(
        OUT / "vorbis-cover-art.ogg",
        vorbis_file(VORBIS_VENDOR, [b"METADATA_BLOCK_PICTURE=" + art]),
    )
    write(
        OUT / "vorbis-many-comments.ogg",
        vorbis_file(
            VORBIS_VENDOR,
            [b"CUSTOM%03d=SYNTHETIC-BULK-%04d" % (n, n) for n in range(400)],
        ),
    )

    write(OUT / "clean-opus.opus", opus_file(b"", []))
    write(OUT / "opus.opus", opus_file(OPUS_VENDOR, OPUS_ITEMS))
    # RFC 7845 §5.2 allows padding after the comment list, and a tagger can leave anything in it.
    write(
        OUT / "opus-padding.opus",
        opus_file(OPUS_VENDOR, OPUS_ITEMS, padding=b"SYNTHETIC-IN-PADDING-0018" + b"\x00" * 64),
    )

    write(OUT / "clean-ogg-flac.oga", flac_file([(4, comment_body(b"", []))]))
    write(
        OUT / "ogg-flac.oga",
        flac_file([(4, comment_body(VORBIS_VENDOR, VORBIS_ITEMS))]),
    )
    # Every block type at once: a comment, a picture, padding with something in it, an application
    # block, a cuesheet carrying a catalogue number, and a seek table that must survive.
    write(
        OUT / "ogg-flac-blocks.oga",
        flac_file(
            [
                (4, comment_body(VORBIS_VENDOR, VORBIS_ITEMS)),
                (6, picture_payload(b"SYNTHETIC-PICTURE-0019")),
                (1, b"\x00" * 8 + b"SYNTHETIC-IN-PADDING-0020" + b"\x00" * 8),
                (2, b"riffSYNTHETIC-APPLICATION-0021"),
                (5, b"012345678SYNTHETIC-CATALOGUE-0022".ljust(128, b"\x00") + b"\x00" * 8),
                (3, b"\x11" * 18),
                (42, b"SYNTHETIC-RESERVED-0023"),
            ]
        ),
    )

    print("Malformed Ogg fixtures:")
    good = vorbis_file(VORBIS_VENDOR, VORBIS_ITEMS)

    write(MALFORMED / "truncated.ogg", good[: len(good) // 2])

    # A page whose CRC does not match. It is the evidence the walk is on a real header, and every
    # decoder drops the page anyway.
    broken = bytearray(good)
    broken[-1] ^= 0xFF
    write(MALFORMED / "bad-crc.ogg", bytes(broken))

    # A page version RFC 3533 does not define.
    version = bytearray(good)
    version[4] = 1
    write(MALFORMED / "unknown-page-version.ogg", _restamp(bytes(version), 0))

    theora = paginate(0x7E_04A, [(0, [b"\x80theora" + b"\x00" * 32]), (100, [b"\x81theora"])])
    write(MALFORMED / "theora.ogv", theora)
    write(
        MALFORMED / "speex.spx",
        paginate(0x59_EE, [(0, [b"Speex   " + b"\x00" * 72]), (100, [b"AUDIO"])]),
    )
    write(
        MALFORMED / "skeleton.ogg",
        paginate(0x5E_1E, [(0, [b"fishead\x00" + b"\x00" * 56]), (100, [b"\x00" * 8])]),
    )

    # Two logical bitstreams side by side, which is what an `.ogv` really is. Refused rather than
    # half-cleaned: the second stream has a comment header this handler never read.
    write(MALFORMED / "multiplexed.ogg", _interleave(good, theora))
    # Two complete streams one after the other.
    write(MALFORMED / "chained.ogg", good + vorbis_file(b"SECOND-SYNTHETIC-0024", []))

    write(MALFORMED / "leading-bytes.ogg", b"SYNTHETIC-HIDDEN-0025" + good)
    write(MALFORMED / "trailing-bytes.ogg", good + b"SYNTHETIC-HIDDEN-0026")

    # The second packet is not the comment header the mapping requires.
    write(
        MALFORMED / "no-comment-header.ogg",
        paginate(
            0x1234,
            [
                (0, [VORBIS_ID]),
                (0, [b"SYNTHETIC-NOT-A-HEADER-0027", VORBIS_SETUP]),
                (VORBIS_GRANULE, VORBIS_PACKETS),
            ],
        ),
    )

    # Headers and nothing else: it would otherwise strip to a file with no payload, reported as a
    # success.
    write(
        MALFORMED / "headers-only.ogg",
        paginate(
            0x1234,
            [
                (0, [VORBIS_ID]),
                (0, [vorbis_comment_packet(VORBIS_VENDOR, VORBIS_ITEMS), VORBIS_SETUP]),
            ],
        ),
    )

    # A page that finishes no packet must say so with a −1 granule; a real one there is a timestamp
    # for nothing.
    long_packet = b"\x03vorbis" + comment_body(b"SYNTHETIC-SPAN-0028", []) + b"\x01"
    long_packet += b"\x00" * (255 * 300 - len(long_packet))
    spanning = paginate(0x1234, [(0, [VORBIS_ID]), (0, [long_packet]), (VORBIS_GRANULE, VORBIS_PACKETS)])
    write(MALFORMED / "granule-on-carrier-page.ogg", _stamp_granule(spanning, 1, 4096))

    # One FLAC metadata block per packet, so a block that does not fill its packet hides bytes
    # behind it.
    short = flac_block(1, b"\x00" * 8, last=True) + b"SYNTHETIC-BEHIND-THE-BLOCK-0029"
    write(
        MALFORMED / "flac-block-overrun.oga",
        paginate(
            0x1234,
            [
                (0, [flac_mapping_packet(2)]),
                (0, [flac_block(4, comment_body(b"v", []), last=False), short]),
                (FLAC_GRANULE, FLAC_PACKETS),
            ],
        ),
    )
    # The mapping header's declared count and the last-block flag disagree.
    write(
        MALFORMED / "flac-header-count-mismatch.oga",
        flac_file([(4, comment_body(b"v", []))], headers=7),
    )


def _page_end(data, at=0):
    """Where the page starting at `at` ends."""
    segments = data[at + 26]
    return at + 27 + segments + sum(data[at + 27 : at + 27 + segments])


def _pages(data):
    at = 0
    while at < len(data):
        end = _page_end(data, at)
        yield at, end
        at = end


def _interleave(first, second):
    """Both streams' first pages at the front, which is how a multiplexed file is laid out."""
    a = list(_pages(first))
    b = list(_pages(second))
    out = first[a[0][0] : a[0][1]] + second[b[0][0] : b[0][1]]
    out += first[a[1][0] :] + second[b[1][0] :]
    return out


def _restamp(data, index):
    """Recompute the CRC of one page, after editing its header by hand."""
    out = bytearray(data)
    at = list(_pages(data))[index][0]
    out[at + 22 : at + 26] = b"\x00\x00\x00\x00"
    end = _page_end(bytes(out), at)
    out[at + 22 : at + 26] = struct.pack("<I", crc(bytes(out[at:end])))
    return bytes(out)


def _stamp_granule(data, index, granule):
    """Overwrite one page's granule position and re-stamp its CRC."""
    out = bytearray(data)
    at = list(_pages(data))[index][0]
    out[at + 6 : at + 14] = struct.pack("<Q", granule)
    return _restamp(bytes(out), index)


if __name__ == "__main__":
    sys.exit(main())
