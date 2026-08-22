#!/usr/bin/env python3
"""Replace the real personal data in the fetched real-producer corpus with synthetic values.

WHY THIS EXISTS
---------------
`docs/TESTING_STRATEGY.md` §3: "No file may contain real personal data. Fixtures are committed
publicly and forever; a corpus that leaks someone's location is an unusually humiliating
failure for this project in particular."

The fetched corpus carries real named people, a real camera serial, and live GPS coordinates
accurate to well under 100 metres. Those files are publicly available upstream, but committing
them here would make strypt an independent *publisher* of that data, permanently — git history
survives the upstream deleting a file.

So the values are replaced and the structure is kept. Structure is the entire point of a
real-producer fixture: a Canon's maker-note layout, LaTeX's object numbering, a phone's
APP1 ordering. Regenerating those synthetically would not reproduce the quirks the corpus
exists to test against.

WHAT IS DELIBERATELY *NOT* SANITISED
------------------------------------
Software producer strings — `Creator=TeX`, `LaTeX with hyperref`, `Writer`. Those name an
application, not a person, and they are exactly the fingerprint the fixtures test. Removing
them would defeat the purpose.

TWO METHODS, AND WHY THE CHOICE MATTERS
---------------------------------------
`exiftool` (JPEG, PNG)
    Rewrites the metadata block in place. Verified to leave no stale copy of the old value and
    to preserve the Canon maker note.

Byte substitution (PDF)
    `exiftool` MUST NOT be used to sanitise a PDF. It writes an incremental update and leaves
    the superseded object intact, so the original name stays in the file while `exiftool -Author`
    cheerfully reports the new one. That was verified on GeoTopo-komprimiert.pdf: after writing
    `Author=STRYPT TEST`, `Martin Thoma` was still present in the bytes. It is the precise
    failure mode strypt exists to catch, and it would have shipped a corpus that looked clean.

    Instead each string is overwritten in place with a replacement of *identical length*, so
    every byte offset and the whole cross-reference table stay valid. `qpdf --check` confirms it.

Run `--verify` alone to re-check an already-sanitised corpus without modifying it.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import struct
import subprocess
import sys
import zlib

CORPUS = pathlib.Path(__file__).parent / "real-corpus"

# A synthetic coordinate that is obviously artificial: 1°01'01" N, 1°01'01" E, in the Gulf of
# Guinea. Chosen over deleting the tag because a GPS-bearing fixture is the point — a fixture
# with no GPS tests nothing about GPS removal.
SYNTHETIC_LAT = "1.0169444"
SYNTHETIC_LON = "1.0169444"

# JPEG and PNG: (path, [exiftool assignments]). Rewritten in place by exiftool.
TAG_REWRITES: list[tuple[str, list[str]]] = [
    ("jpeg/canon/Canon_DIGITAL_IXUS_400.jpg", ["-Canon:OwnerName=STRYPT TEST OWNER"]),
    ("jpeg/canon/Canon_PowerShot_S40.jpg", ["-Canon:OwnerName=STRYPT TEST OWNER"]),
    ("jpeg/canon/canon-ixus.jpg", ["-Canon:OwnerName=STRYPT TEST OWNER"]),
    # Despite the "sony" directory this is a Canon PowerShot A5, and its owner name lives in a
    # CIFF block rather than the ordinary Canon maker note. `-Canon:OwnerName` silently succeeds
    # and changes nothing; the group has to be named explicitly.
    ("jpeg/sony/sony-powershota5.jpg", ["-CIFF:OwnerName=STRYPT TEST OWNER"]),
    ("png/browser/wm_upload_wikimedia_org_a23d1e831e128dff.png", ["-XMP-dc:Creator=STRYPT TEST CREATOR"]),
    ("png/windows/wm_upload_wikimedia_org_a23d1e831e128dff.png", ["-XMP-dc:Creator=STRYPT TEST CREATOR"]),
    ("png/macos/shirt_transparent.png", ["-XMP-aux:SerialNumber=0000000"]),
]

# PNG same-length substitutions, applied chunk-aware so the CRC can be recomputed.
#
# `exif:SerialNumber` inside an XMP packet is not writable by exiftool — it warns "doesn't exist
# or isn't writable" and exits 0, so a tag rewrite here fails silently. Substituting the bytes
# is the reliable route, but a PNG chunk carries a CRC32 over its type and data, so the bytes
# cannot simply be patched in place the way a PDF's can.
PNG_BYTE_REWRITES: list[tuple[str, bytes, bytes]] = [
    ("png/macos/shirt_transparent.png", b"6047708", b"0000000"),
]

GPS_REWRITES: list[str] = [
    "jpeg/android/HMD_Nokia_8.3_5G.jpg",
    "jpeg/android/HMD_Nokia_8.3_5G_hdr.jpg",
    "jpeg/iphone/IMG_5250.jpeg",
    "jpeg/iphone/iphone_hdr_NO.jpg",
    "jpeg/iphone/iphone_hdr_YES.jpg",
]

# PDF: exact same-length byte substitutions. Lengths are asserted at run time — a mismatch
# would shift every offset after it and silently corrupt the cross-reference table.
BYTE_REWRITES: list[tuple[str, bytes, bytes]] = [
    ("pdf/latex/GeoTopo.pdf", b"Martin Thoma", b"STRYPT TEST1"),
    ("pdf/latex/GeoTopo-komprimiert.pdf", b"Martin Thoma", b"STRYPT TEST1"),
    ("pdf/acrobat/024-annotations.pdf", b"Martin Thoma", b"STRYPT TEST1"),
    ("pdf/acrobat/020-xmp.pdf", b"Martin Thoma", b"STRYPT TEST1"),
    ("pdf/acrobat/020-xmp.pdf", b"John Doe", b"TESTUSER"),
]

# Any of these surviving anywhere in the corpus is a sanitisation failure.
FORBIDDEN = [
    b"Martin Thoma",
    b"John Doe",
    b"Guido Hegasy",
    b"Andreas Huggel",
    b"Chris Smith",
    b"Jean-Pierre Grignon",
    b"Tom Rowan",
    b"Sarah Clifton",
    b"6047708",
]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def rewrite_png_chunk(path: pathlib.Path, old: bytes, new: bytes) -> int:
    """Substitute inside PNG chunks, recomputing each modified chunk's CRC32.

    Same-length only, so the chunk length field and every later offset stay correct; only the
    checksum has to be rebuilt. Returns the number of chunks changed.
    """
    data = path.read_bytes()
    out = bytearray(data[:8])  # signature
    offset, changed = 8, 0
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        ctype = data[offset + 4 : offset + 8]
        body = data[offset + 8 : offset + 8 + length]
        if old in body:
            body = body.replace(old, new)
            changed += 1
        out += struct.pack(">I", len(body)) + ctype + body
        out += struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)
        offset += 12 + length
    if changed:
        path.write_bytes(bytes(out))
    return changed


def sanitise() -> int:
    if not shutil.which("exiftool"):
        print("error: exiftool not found; install it before sanitising", file=sys.stderr)
        return 2

    for rel, assignments in TAG_REWRITES:
        path = CORPUS / rel
        if not path.exists():
            print(f"skip (absent): {rel}")
            continue
        result = run(["exiftool", "-q", "-overwrite_original", *assignments, str(path)])
        if result.returncode != 0:
            print(f"error: exiftool failed on {rel}: {result.stderr.strip()}", file=sys.stderr)
            return 1
        print(f"tags   {rel}")

    for rel in GPS_REWRITES:
        path = CORPUS / rel
        if not path.exists():
            print(f"skip (absent): {rel}")
            continue
        result = run([
            "exiftool", "-q", "-overwrite_original",
            f"-GPSLatitude={SYNTHETIC_LAT}", "-GPSLatitudeRef=N",
            f"-GPSLongitude={SYNTHETIC_LON}", "-GPSLongitudeRef=E",
            str(path),
        ])
        if result.returncode != 0:
            print(f"error: exiftool failed on {rel}: {result.stderr.strip()}", file=sys.stderr)
            return 1
        print(f"gps    {rel}")

    for rel, old, new in PNG_BYTE_REWRITES:
        path = CORPUS / rel
        if not path.exists():
            print(f"skip (absent): {rel}")
            continue
        if len(old) != len(new):
            print(f"error: {old!r} and {new!r} differ in length", file=sys.stderr)
            return 1
        changed = rewrite_png_chunk(path, old, new)
        print(f"png    {rel}: {old.decode()} -> {new.decode()} ({changed} chunk(s))")

    for rel, old, new in BYTE_REWRITES:
        path = CORPUS / rel
        if not path.exists():
            print(f"skip (absent): {rel}")
            continue
        # A length change would shift every subsequent offset and invalidate the xref table.
        if len(old) != len(new):
            print(f"error: {old!r} and {new!r} differ in length", file=sys.stderr)
            return 1
        data = path.read_bytes()
        if old not in data:
            print(f"bytes  {rel}: {old.decode()} already absent")
            continue
        path.write_bytes(data.replace(old, new))
        print(f"bytes  {rel}: {old.decode()} -> {new.decode()}")

    return 0


def verify() -> int:
    """Fail loudly if any real personal value survived, or if a PDF was structurally broken."""
    failures = 0

    for path in sorted(CORPUS.rglob("*")):
        if not path.is_file() or path.suffix in {".md", ".csv"}:
            continue
        data = path.read_bytes()
        for needle in FORBIDDEN:
            if needle in data:
                print(f"LEAK  {path.relative_to(CORPUS)}: {needle.decode()}", file=sys.stderr)
                failures += 1

    # GPS is binary in Exif, so a byte scan cannot see it. Ask exiftool instead.
    result = run([
        "exiftool", "-r", "-q", "-n", "-if", "$gpslatitude",
        "-p", "$Directory/$FileName $gpslatitude $gpslongitude", str(CORPUS),
    ])
    for line in result.stdout.splitlines():
        parts = line.rsplit(maxsplit=2)
        if len(parts) != 3:
            continue
        name, lat, lon = parts
        if (lat, lon) != (SYNTHETIC_LAT, SYNTHETIC_LON):
            print(f"LEAK  {name}: real GPS {lat},{lon}", file=sys.stderr)
            failures += 1

    # Byte substitution keeps offsets valid only if the replacement was the same length, so the
    # PDFs this script edits are structure-checked.
    #
    # ONLY those. Checking every PDF in the corpus reports failures this script did not cause:
    # `generated/pdf/minimal-xref-table.pdf` is a deliberately minimal file and
    # `pdf/word/005-libreoffice-writer-password.pdf` is encrypted, and qpdf exits 2 on both
    # before anything here touches them. A verifier that cries wolf about untouched files
    # teaches the reader to ignore it.
    if shutil.which("qpdf"):
        for rel in sorted({rel for rel, _, _ in BYTE_REWRITES}):
            path = CORPUS / rel
            if not path.exists():
                continue
            result = run(["qpdf", "--check", str(path)])
            # 3 is warnings on a file that was already imperfect upstream; 2 is a hard error.
            if result.returncode == 2:
                print(f"BROKE {rel}: {result.stdout.strip()[:200]}", file=sys.stderr)
                failures += 1
    else:
        print("warning: qpdf not found; PDF structure not verified", file=sys.stderr)

    if failures:
        print(f"\n{failures} problem(s) found", file=sys.stderr)
        return 1
    print("\nverified: no real personal data, no PDF structurally broken")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="only re-check, do not modify")
    args = parser.parse_args()

    if args.verify:
        return verify()
    code = sanitise()
    if code:
        return code
    print()
    return verify()


if __name__ == "__main__":
    sys.exit(main())
