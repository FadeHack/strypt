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
import zlib

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
    path.parent.mkdir(parents=True, exist_ok=True)
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

    # 9. A cross-reference table whose entries are 19 bytes rather than the 20 that
    #    ISO 32000-1 §7.5.4 requires. The spec is explicit that each entry is exactly 20
    #    bytes, ending in a two-character sequence (SP CR, SP LF, or CR LF); this fixture
    #    drops the padding space so each entry ends "n\n" instead of "n \n".
    #
    #    Real producers emit this. It was found in the wild during the Phase 1 real-producer
    #    corpus sweep (`pdf/scanner/019-grayscale-image.pdf`, from py-pdf/sample-files), where
    #    qpdf --check reports no syntax errors and mat2 strips the file successfully, but
    #    lopdf 0.44 — the parser strypt uses — rejects the trailer outright.
    #
    #    strypt therefore refuses a file that other tools accept. That is a capability gap,
    #    not a safety failure: refusing is the correct fail-closed behaviour (CLAUDE.md §3.6),
    #    and the accompanying test pins it as a *typed* refusal so that the day lopdf gains
    #    tolerance here, the change is noticed rather than absorbed silently.
    strict = build(page_objects(), b"/Root 1 0 R")
    write("malformed/xref-19-byte-entries.pdf", strict.replace(b" n \n", b" n\n").replace(b" f \n", b" f\n"))

    # 10. A negative zero in a MediaBox. This file is perfectly valid — it lives here rather
    #     than in malformed/ for that reason — and it broke byte-identical idempotence.
    #
    #     lopdf writes Real(-0.0) as "-0", without the decimal point that made it a real.
    #     Re-parsing "-0" therefore yields Integer(0), which writes as "0", so stripping once
    #     and stripping twice produced different bytes. Found by the pdf fuzz target at 6985s
    #     of a two-hour run; the handler now collapses negative zero before writing.
    #
    #     ISO 32000-1 §7.3.3 gives PDF numbers no signed zero, so this rewrite changes no
    #     meaning — which is what makes normalising defensible in a handler that otherwise
    #     refuses rather than repairs.
    #     Both a bare value and one nested in an array are covered, using real page keys so
    #     they stay reachable — an unreferenced object would be pruned before the handler ever
    #     walked it, and the test would pass without exercising anything.
    #
    #     The trailer copy is not redundant. The first fix walked only the object graph and
    #     passed every test here; CI's fuzz run then moved a negative zero into the trailer,
    #     which lopdf keeps outside `objects`, and the assertion fired again within minutes on a
    #     document whose objects were entirely clean.
    write(
        "negative-zero-real.pdf",
        build(
            page_objects(b"/UserUnit -0. /CropBox [-0. 0. -0.0 10] "),
            b"/Root 1 0 R /StrypteTestBox [-0. 0. -0.0 10] ",
        ),
    )

    # 11. A trailer with no /Root. ISO 32000-1 §7.5.5 requires it: it names the document
    #     catalogue, the single root every other object hangs off. Here the key is /t instead,
    #     so the file has no defined entry point and no viewer opens it.
    #
    #     strypt used to accept this, and accepting was worse than refusing. The rewrite walks
    #     reachable objects from the root and drops the rest (ADR-0020); with no root, which
    #     objects survive is not stable between runs. The pdf fuzz target found it at 2832s —
    #     stripping once gave 609 bytes, stripping again gave 485, because the second pass
    #     dropped an annotation object the page still referenced via /Annots. Renumbering then
    #     put the catalogue in that slot, so the page's annotation array pointed at the
    #     catalogue: corruption strypt introduced itself, while reporting success both times.
    #
    #     Refusing costs nothing real — a PDF this broken cannot be published either way.
    write("malformed/no-root-trailer.pdf", build(page_objects(), b"/t 1 0 R"))

    # 12. A photograph placed on the page and as its thumbnail. A DCTDecode stream is a JPEG file
    #     byte for byte, so the camera's Exif rides along; 0.1.0 reported this file clean (ADR-0056).
    jpeg = (OUT.parent / "jpeg" / "exif-gps.jpg").read_bytes()
    image = b"<< /Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceRGB "
    image += b"/BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n" % len(jpeg)
    image += jpeg + b"\nendstream"
    draw = b"q 16 0 0 16 0 0 cm /Im0 Do Q"
    objs = page_objects(b"/Thumb 7 0 R ")
    objs[3] = objs[3].replace(b"/Font << /F1 5 0 R >>", b"/Font << /F1 5 0 R >> /XObject << /Im0 6 0 R >>")
    objs[4] = b"<< /Length %d >>\nstream\n" % (len(CONTENT) + len(draw) + 1) + CONTENT + b"\n" + draw + b"\nendstream"
    objs[6] = image
    objs[7] = image.replace(b"/Type /XObject /Subtype /Image ", b"")
    write("embedded-jpeg.pdf", build(objs, b"/Root 1 0 R"))

    # 13. Images strypt cannot reach without a JPEG 2000 parser or inflating first. Copied, with a
    #     note that says so.
    # A bare codestream: the JP2 signature box contains CR LF, which the checkout test forbids.
    jpx = b"\xff\x4f\xff\x51SYNTHETIC-JPX-0013"
    objs = page_objects()
    objs[3] = objs[3].replace(b"/Font << /F1 5 0 R >>", b"/Font << /F1 5 0 R >> /XObject << /Im0 6 0 R /Im1 7 0 R >>")
    objs[6] = (
        b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /JPXDecode /Length %d >>\nstream\n"
        % len(jpx) + jpx + b"\nendstream"
    )
    wrapped = zlib.compress(b"\xff\xd8\xff\xfeSYNTHETIC-COMMENT-0014\xff\xd9", 9)
    objs[7] = (
        b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 "
        b"/Filter [/FlateDecode /DCTDecode] /Length %d >>\nstream\n" % len(wrapped) + wrapped + b"\nendstream"
    )
    write("unexamined-images.pdf", build(objs, b"/Root 1 0 R"))


if __name__ == "__main__":
    main()
