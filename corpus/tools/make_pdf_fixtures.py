#!/usr/bin/env python3
"""Generate the PDF test fixtures in ``corpus/pdf``.

Fixtures are generated rather than collected. ``docs/TESTING_STRATEGY.md`` §3 forbids real
personal data in the corpus, and the corpus is committed publicly and permanently — a
generator makes that rule structural instead of a habit someone has to remember. Every value
below is obviously synthetic, and several are deliberately unmistakable strings so that a
test can assert they are absent from output.

Run from the repository root:

    python3 corpus/tools/make_pdf_fixtures.py

The output is deterministic: running it twice produces byte-identical files, so a fixture
changing in ``git diff`` means someone changed this script.
"""

from __future__ import annotations

import pathlib

OUT = pathlib.Path(__file__).resolve().parents[1] / "pdf"

# A one-page document's worth of content, used by every fixture so that they differ only in
# their metadata.
CONTENT = b"BT /F1 12 Tf 20 100 Td (strypt fixture) Tj ET"


def build(objects: dict[int, bytes], trailer_extra: bytes, version: bytes = b"1.7") -> bytes:
    """Serialise ``objects`` into a PDF with a correct classic cross-reference table."""
    out = bytearray()
    out += b"%PDF-" + version + b"\n"
    # The binary comment tells transfer software the file is not text. Real producers emit it.
    out += b"%\xe2\xe3\xcf\xd3\n"

    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"

    startxref = len(out)
    highest = max(objects) + 1
    out += b"xref\n0 %d\n" % highest
    out += b"0000000000 65535 f \n"
    for num in range(1, highest):
        if num in offsets:
            out += b"%010d 00000 n \n" % offsets[num]
        else:
            out += b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d " % highest + trailer_extra + b" >>\n"
    out += b"startxref\n%d\n%%%%EOF\n" % startxref
    return bytes(out)


def page_objects(extra_page_keys: bytes = b"", annots: bytes = b"") -> dict[int, bytes]:
    """The catalogue, page tree, one page, and its content stream."""
    return {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> "
            + extra_page_keys
            + annots
            + b" >>"
        ),
        4: b"<< /Length %d >>\nstream\n" % len(CONTENT) + CONTENT + b"\nendstream",
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }


def write(name: str, data: bytes) -> None:
    path = OUT / name
    path.write_bytes(data)
    print(f"{path.relative_to(pathlib.Path.cwd())}  {len(data)} bytes")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    # 1. A document whose only metadata is the Information Dictionary. The baseline case, and
    #    the one every other metadata tool also handles.
    objs = page_objects()
    objs[6] = (
        b"<< /Author (SYNTHETIC-AUTHOR-0001) /Creator (Fixture Generator 1.0) "
        b"/Producer (strypt fixture generator) /Title (Quarterly Fixture) "
        b"/Subject (testing) /Keywords (synthetic, fixture) "
        b"/CreationDate (D:20200101000000Z) /ModDate (D:20200102000000Z) "
        b"/CustomVendorField (SYNTHETIC-CUSTOM-0002) >>"
    )
    write(
        "info-dictionary.pdf",
        build(objs, b"/Root 1 0 R /Info 6 0 R /ID [<0123456789ABCDEF> <0123456789ABCDEF>]"),
    )

    # 2. An uncompressed XMP packet, which is where a document's fuller record usually lives —
    #    including xmpMM:History, a log of every save with its tool and timestamp.
    xmp = (
        b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        b'<rdf:Description rdf:about=""\n'
        b'  xmlns:dc="http://purl.org/dc/elements/1.1/"\n'
        b'  xmlns:xmp="http://ns.adobe.com/xap/1.0/"\n'
        b'  xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"\n'
        b'  xmlns:pdf="http://ns.adobe.com/pdf/1.3/">\n'
        b"  <dc:creator><rdf:Seq><rdf:li>SYNTHETIC-XMP-AUTHOR-0003</rdf:li></rdf:Seq></dc:creator>\n"
        b"  <xmp:CreatorTool>Fixture Generator 1.0</xmp:CreatorTool>\n"
        b"  <xmp:CreateDate>2020-01-01T00:00:00Z</xmp:CreateDate>\n"
        b"  <xmp:ModifyDate>2020-01-02T00:00:00Z</xmp:ModifyDate>\n"
        b"  <xmpMM:DocumentID>uuid:00000000-0000-4000-8000-000000000003</xmpMM:DocumentID>\n"
        b"  <xmpMM:InstanceID>uuid:00000000-0000-4000-8000-000000000004</xmpMM:InstanceID>\n"
        b"  <pdf:Producer>strypt fixture generator</pdf:Producer>\n"
        b"</rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"w\"?>\n"
    )
    objs = page_objects()
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>"
    objs[6] = b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xmp) + xmp + b"\nendstream"
    write("xmp-packet.pdf", build(objs, b"/Root 1 0 R"))

    # 3. THE fixture that justifies the full-rewrite decision (ADR-0020). The document is saved
    #    twice: the second save supersedes the Info dictionary, and the first one's author is
    #    still sitting in the file, unreferenced and perfectly readable in a hex editor. A tool
    #    that patches instead of rewriting leaves SYNTHETIC-ORPHANED-AUTHOR-0005 in place while
    #    reporting the file clean.
    objs = page_objects()
    objs[6] = b"<< /Author (SYNTHETIC-ORPHANED-AUTHOR-0005) /Producer (first pass) >>"
    base = build(objs, b"/Root 1 0 R /Info 6 0 R")
    prev_startxref = int(base.split(b"startxref\n")[-1].split(b"\n")[0])

    update = bytearray(base)
    new_info_offset = len(update)
    update += b"7 0 obj\n<< /Author (SYNTHETIC-SECOND-PASS-0006) /Producer (second pass) >>\nendobj\n"
    xref_at = len(update)
    update += b"xref\n0 1\n0000000000 65535 f \n7 1\n%010d 00000 n \n" % new_info_offset
    update += (
        b"trailer\n<< /Size 8 /Root 1 0 R /Info 7 0 R /Prev %d >>\n" % prev_startxref
    )
    update += b"startxref\n%d\n%%%%EOF\n" % xref_at
    write("incremental-update.pdf", bytes(update))

    # 4. A markup annotation. /T here is the person who wrote the comment.
    annot = (
        b"<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] "
        b"/T (SYNTHETIC-REVIEWER-0007) /Contents (a review comment) "
        b"/M (D:20200103000000Z) /CreationDate (D:20200103000000Z) "
        b"/NM (annot-0001) >>"
    )
    objs = page_objects(annots=b"/Annots [6 0 R]")
    objs[6] = annot
    write("annotation-author.pdf", build(objs, b"/Root 1 0 R"))

    # 5. A form field. /T here is the field's *name*, which the form's logic and its saved data
    #    depend on. Removing it would break the document — this fixture exists to prove strypt
    #    does not (see MARKUP_ANNOTATION_SUBTYPES in formats/pdf.rs).
    widget = (
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /Rect [10 10 100 30] "
        b"/T (applicant_surname) /V (         ) >>"
    )
    objs = page_objects(annots=b"/Annots [6 0 R]")
    objs[6] = widget
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>"
    write("form-field.pdf", build(objs, b"/Root 1 0 R"))

    # 6. Private application scratch data. What an application stores here is entirely up to it.
    objs = page_objects(
        extra_page_keys=b"/PieceInfo << /FixtureApp << /Private (SYNTHETIC-PIECEINFO-0008) >> >> "
        b"/LastModified (D:20200104000000Z)"
    )
    write("piece-info.pdf", build(objs, b"/Root 1 0 R"))

    # 7. An embedded attachment, whose own metadata strypt reports but does not recurse into.
    payload = b"attached file contents"
    objs = page_objects()
    objs[6] = (
        b"<< /Type /Filespec /F (attachment.txt) /Desc (SYNTHETIC-DESC-0009) "
        b"/EF << /F 7 0 R >> >>"
    )
    objs[7] = (
        b"<< /Type /EmbeddedFile /Length %d /Params << /CreationDate (D:20200105000000Z) "
        b"/ModDate (D:20200106000000Z) /Size %d >> >>\nstream\n" % (len(payload), len(payload))
        + payload
        + b"\nendstream"
    )
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(attachment) 6 0 R] >> >> >>"
    write("embedded-file.pdf", build(objs, b"/Root 1 0 R"))

    # 8. A document with no metadata at all. Strip must be a well-formed no-op, and `show` must
    #    report nothing — a tool that invents findings on a clean file trains users to ignore it.
    write("clean.pdf", build(page_objects(), b"/Root 1 0 R"))


if __name__ == "__main__":
    main()
