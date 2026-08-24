#!/usr/bin/env python3
"""Generate the OpenDocument fixtures in ``corpus/odf``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with LibreOffice installed is a corpus nobody regenerates.

Every fixture is a **structurally real OpenDocument package**: a ``mimetype`` entry written first
and stored (ODF 1.3 Part 2 section 3.3), a ``META-INF/manifest.xml`` listing every part
(section 2.2.1), and the parts it lists. They are minimal rather than rich — a fixture exists to
exercise one decision in the handler, and a fixture carrying a whole document's worth of
unrelated markup makes it harder to see which byte the test is actually about.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report —
a handler that forgot to remove something would still cheerfully report having removed it.

Values that must **survive** are prefixed ``PRESERVED-`` so the sweep for surviving ``SYNTHETIC``
markers does not trip over them: the words of a tracked change, the text of a comment, and the
document's body. Removing those would change what the document says, which ``docs/PRD.md``
section 8.1 forbids (ADR-0031).
"""

import pathlib
import struct
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "odf"
MALFORMED = OUT / "malformed"

# A fixed MS-DOS timestamp for every entry. The generator must not put the current time into a
# fixture — that would make the corpus non-deterministic, and it would put the build machine's
# clock into a file committed to a public repository.
FIXED_DATE = (2020, 1, 1, 0, 0, 0)

TEXT = "application/vnd.oasis.opendocument.text"
SPREADSHEET = "application/vnd.oasis.opendocument.spreadsheet"
PRESENTATION = "application/vnd.oasis.opendocument.presentation"
GRAPHICS = "application/vnd.oasis.opendocument.graphics"

XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>\n'

NS = (
    ' xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"'
    ' xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"'
    ' xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"'
    ' xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"'
    ' xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"'
    ' xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
    ' xmlns:xlink="http://www.w3.org/1999/xlink"'
)

MANIFEST_NS = ' xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"'
CONFIG_NS = ' xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0"'


def manifest(media_type, parts, encrypted=None):
    """``META-INF/manifest.xml`` listing the package root and every part in it."""
    lines = [
        XML_DECL,
        f'<manifest:manifest{MANIFEST_NS} manifest:version="1.3">',
        f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{media_type}"'
        ' manifest:version="1.3"/>',
    ]
    for name in parts:
        if name in ("mimetype", "META-INF/manifest.xml"):
            continue
        kind = "text/xml" if name.endswith(".xml") else media_of(name)
        if name == encrypted:
            # An entry whose data is encrypted by ODF itself rather than by ZIP. The ZIP layer
            # cannot see this — it is not the general-purpose encryption bit — so the handler has
            # to refuse on the manifest, or a package of ciphertext gets reported clean.
            lines.append(
                f'<manifest:file-entry manifest:full-path="{name}" manifest:media-type="{kind}"'
                ' manifest:size="4096"><manifest:encryption-data'
                ' manifest:checksum-type="SHA1/1K" manifest:checksum="c3ludGhldGlj">'
                "</manifest:encryption-data></manifest:file-entry>"
            )
            continue
        lines.append(
            f'<manifest:file-entry manifest:full-path="{name}" manifest:media-type="{kind}"/>'
        )
    lines.append("</manifest:manifest>")
    return "".join(lines)


def media_of(name):
    if name.endswith(".png"):
        return "image/png"
    if name.endswith(".jpg") or name.endswith(".jpeg"):
        return "image/jpeg"
    return "application/octet-stream"


def content(body="<text:p>PRESERVED-BODY-TEXT</text:p>", extra=""):
    return (
        XML_DECL
        + f'<office:document-content{NS} office:version="1.3">'
        + extra
        + f"<office:body><office:text>{body}</office:text></office:body>"
        "</office:document-content>"
    )


def styles(body=""):
    return (
        XML_DECL
        + f'<office:document-styles{NS} office:version="1.3">'
        f"<office:styles>{body}</office:styles>"
        "</office:document-styles>"
    )


# The metadata part. `meta:editing-cycles` and `meta:editing-duration` are the pair with no
# Office Open XML counterpart worth calling equivalent: `TotalTime` is cumulative minutes, and
# this is an ISO 8601 duration written to the second.
META_XML = (
    XML_DECL
    + f'<office:document-meta{NS} office:version="1.3"><office:meta>'
    "<meta:initial-creator>SYNTHETIC-INITIALCREATOR-0001</meta:initial-creator>"
    "<dc:creator>SYNTHETIC-LASTSAVEDBY-0002</dc:creator>"
    "<meta:creation-date>2021-03-04T05:06:07</meta:creation-date>"
    "<dc:date>2021-03-04T08:09:10</dc:date>"
    "<meta:printed-by>SYNTHETIC-PRINTEDBY-0003</meta:printed-by>"
    "<meta:print-date>2021-03-05T09:10:11</meta:print-date>"
    "<meta:editing-cycles>37</meta:editing-cycles>"
    "<meta:editing-duration>PT4H32M17S</meta:editing-duration>"
    "<meta:generator>SYNTHETIC-GENERATOR-0004</meta:generator>"
    "<dc:title>SYNTHETIC-TITLE-0005</dc:title>"
    "<dc:subject>SYNTHETIC-SUBJECT-0006</dc:subject>"
    "<dc:description>SYNTHETIC-DESCRIPTION-0007</dc:description>"
    '<meta:keyword>SYNTHETIC-KEYWORD-0008</meta:keyword>'
    '<meta:user-defined meta:name="MatterNumber">SYNTHETIC-MATTER-0009</meta:user-defined>'
    '<meta:template xlink:href="file:///home/SYNTHETIC-USER-0010/Templates/report.ott"'
    ' xlink:title="SYNTHETIC-TEMPLATE-0011" meta:date="2021-01-01T00:00:00"/>'
    '<meta:document-statistic meta:table-count="1" meta:image-count="0"'
    ' meta:page-count="3" meta:paragraph-count="12" meta:word-count="412"'
    ' meta:character-count="2317"/>'
    "</office:meta></office:document-meta>"
)

# The settings part. Its printer name and base64 setup blob are why it is removed whole rather
# than scrubbed: the rest of it is several hundred window-geometry integers and a per-release set
# of configuration keys that fingerprints the producing build.
SETTINGS_XML = (
    XML_DECL
    + f'<office:document-settings{NS}{CONFIG_NS} office:version="1.3"><office:settings>'
    '<config:config-item-set config:name="ooo:view-settings">'
    '<config:config-item config:name="ViewAreaTop" config:type="int">0</config:config-item>'
    "</config:config-item-set>"
    '<config:config-item-set config:name="ooo:configuration-settings">'
    '<config:config-item config:name="PrinterName" config:type="string">'
    "SYNTHETIC-PRINTER-0012</config:config-item>"
    '<config:config-item config:name="PrinterSetup" config:type="base64Binary">'
    "SYNTHETIC-PRINTERSETUP-0013</config:config-item>"
    '<config:config-item config:name="BuildId" config:type="string">'
    "SYNTHETIC-BUILDID-0014</config:config-item>"
    "</config:config-item-set>"
    "</office:settings></office:document-settings>"
)


def build(path, parts, mimetype=TEXT, store_mimetype=True, mimetype_first=True):
    """Write an OpenDocument package deterministically.

    ``store_mimetype`` and ``mimetype_first`` exist so one fixture can be a *nonconforming*
    package — Part 2 section 3.3 requires the entry to be first and uncompressed, and the handler
    has to produce a conforming package out of one that is not.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        def write(name, data, stored=False):
            if isinstance(data, str):
                data = data.encode("utf-8")
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            # Deflate everything else, which is what a real producer does — a corpus of
            # stored-only archives would never exercise the inflate path at all.
            info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            archive.writestr(info, data)

        if mimetype is not None and mimetype_first:
            write("mimetype", mimetype, stored=store_mimetype)
        for name, data in parts.items():
            write(name, data)
        if mimetype is not None and not mimetype_first:
            write("mimetype", mimetype, stored=store_mimetype)


def package(media_type, extra=None, body=None, styles_body="", manifest_override=None):
    """The parts every package needs, plus whatever the fixture adds."""
    parts = {
        "content.xml": content(body) if body else content(),
        "styles.xml": styles(styles_body),
    }
    parts.update(extra or {})
    names = ["mimetype", *parts.keys()]
    parts = {
        "META-INF/manifest.xml": manifest_override or manifest(media_type, names),
        **parts,
    }
    return parts


def jpeg_fixture():
    """The geotagged JPEG fixture, reused as an embedded picture.

    Reused rather than regenerated: the point of the embedded-image fixture is that the *same*
    handler runs on a picture inside a document as on a loose one (ADR-0029), and using a
    different JPEG would let the two drift apart without a test noticing.
    """
    source = ROOT / "jpeg" / "exif-gps.jpg"
    if not source.exists():
        sys.exit(
            f"missing {source}; run corpus/tools/make_jpeg_fixtures.py first — the embedded "
            "picture is deliberately the same file the JPEG handler is tested against"
        )
    return source.read_bytes()


def png_fixture():
    """A PNG carrying text chunks, used as the package thumbnail."""
    source = ROOT / "png" / "text-chunks.png"
    if not source.exists():
        sys.exit(f"missing {source}; run corpus/tools/make_png_fixtures.py first")
    return source.read_bytes()


ANNOTATION = (
    "<text:p><office:annotation>"
    "<dc:creator>SYNTHETIC-COMMENTER-0015</dc:creator>"
    "<dc:date>2021-03-04T05:06:09</dc:date>"
    "<meta:date-string>SYNTHETIC-DATESTRING-0016</meta:date-string>"
    "<text:p>PRESERVED-COMMENT-TEXT</text:p>"
    "</office:annotation>PRESERVED-BODY-TEXT</text:p>"
)

TRACKED_CHANGES = (
    "<text:tracked-changes>"
    '<text:changed-region xml:id="ct1" text:id="ct1"><text:insertion>'
    "<office:change-info><dc:creator>SYNTHETIC-INSERTER-0017</dc:creator>"
    "<dc:date>2021-03-04T05:06:07</dc:date></office:change-info>"
    "</text:insertion></text:changed-region>"
    '<text:changed-region xml:id="ct2" text:id="ct2"><text:deletion>'
    "<office:change-info><dc:creator>SYNTHETIC-DELETER-0018</dc:creator>"
    "<dc:date>2021-03-04T05:06:08</dc:date></office:change-info>"
    "<text:p>PRESERVED-DELETED-TEXT</text:p>"
    "</text:deletion></text:changed-region>"
    "</text:tracked-changes>"
    '<text:p><text:change-start text:change-id="ct1"/>PRESERVED-INSERTED-TEXT'
    '<text:change-end text:change-id="ct1"/></text:p>'
)

# Fields whose text is a *cached copy* of what `meta.xml` holds. The application filled these in;
# the author did not type them. Leaving them would print the name strypt just reported removing.
AUTHOR_FIELDS = (
    "<text:p>By <text:creator>SYNTHETIC-FIELDCREATOR-0019</text:creator>"
    " (<text:initial-creator>SYNTHETIC-FIELDINITIAL-0020</text:initial-creator>,"
    " <text:author-name>SYNTHETIC-FIELDAUTHOR-0021</text:author-name>,"
    " <text:author-initials>SYNTHETIC-FIELDINITIALS-0022</text:author-initials>)</text:p>"
    "<text:p>Saved <text:editing-cycles>37</text:editing-cycles> times over"
    " <text:editing-duration>PT4H32M17S</text:editing-duration></text:p>"
    # A date the author chose to display. It stays, and the report says it is there.
    "<text:p>Created <text:creation-date>2021-03-04</text:creation-date></text:p>"
)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)

    # A package with nothing to remove. A tool that invents findings teaches users to ignore it.
    build(OUT / "clean.odt", package(TEXT))

    build(OUT / "meta.odt", package(TEXT, extra={"meta.xml": META_XML}))
    build(OUT / "settings.odt", package(TEXT, extra={"settings.xml": SETTINGS_XML}))

    # A rendered preview of the first page (Part 2 section 3.8). It survives every kind of
    # redaction applied to the text, in the same way an Exif thumbnail survives cropping.
    build(
        OUT / "thumbnail.odt",
        package(TEXT, extra={"Thumbnails/thumbnail.png": png_fixture()}),
    )

    # The producer's saved user-interface configuration.
    build(
        OUT / "configurations.odt",
        package(
            TEXT,
            extra={
                "Configurations2/accelerator/current.xml": XML_DECL
                + "<config>SYNTHETIC-ACCELERATOR-0023</config>",
                "layout-cache": b"\x00\x01SYNTHETIC-LAYOUTCACHE-0024\x00",
            },
        ),
    )

    build(OUT / "comments.odt", package(TEXT, body=ANNOTATION))
    build(OUT / "tracked-changes.odt", package(TEXT, body=TRACKED_CHANGES))

    # The one place this handler edits what a reader sees, and the fixture that pins why.
    build(
        OUT / "author-fields.odt",
        package(
            TEXT,
            body=AUTHOR_FIELDS,
            styles_body="<style:header><text:p>"
            "<text:creator>SYNTHETIC-HEADERCREATOR-0025</text:creator>"
            "</text:p></style:header>",
        ),
    )

    # The fixture for ADR-0029: a photograph inside a document, carrying its own GPS.
    build(
        OUT / "embedded-image.odt",
        package(TEXT, extra={"Pictures/image1.jpg": jpeg_fixture()}),
    )

    # An embedded chart. ODF stores one as ordinary entries in the same archive rather than as a
    # nested archive, so its own author metadata is reachable in the same pass — the opposite
    # outcome from the equivalent Office document, which is refused (docs/THREAT_MODEL.md 7.6).
    build(
        OUT / "embedded-object.ods",
        package(
            SPREADSHEET,
            extra={
                "Object 1/content.xml": content("<text:p>PRESERVED-CHART-TEXT</text:p>"),
                "Object 1/meta.xml": META_XML.replace(
                    "SYNTHETIC-INITIALCREATOR-0001", "SYNTHETIC-CHARTAUTHOR-0026"
                ),
                "Object 1/settings.xml": SETTINGS_XML,
            },
        ),
        mimetype=SPREADSHEET,
    )

    build(
        OUT / "spreadsheet.ods",
        package(SPREADSHEET, extra={"meta.xml": META_XML}, body=ANNOTATION),
        mimetype=SPREADSHEET,
    )
    build(
        OUT / "presentation.odp",
        package(PRESENTATION, extra={"meta.xml": META_XML}),
        mimetype=PRESENTATION,
    )

    # A package whose `mimetype` entry is neither first nor stored, which Part 2 section 3.3
    # forbids. Real readers accept it; strypt's output has to be conforming regardless.
    build(
        OUT / "nonconforming-mimetype.odt",
        package(TEXT, extra={"meta.xml": META_XML}),
        store_mimetype=False,
        mimetype_first=False,
    )

    # Everything at once, which is what a real document looks like.
    build(
        OUT / "everything.odt",
        package(
            TEXT,
            extra={
                "meta.xml": META_XML,
                "settings.xml": SETTINGS_XML,
                "Thumbnails/thumbnail.png": png_fixture(),
                "Pictures/image1.jpg": jpeg_fixture(),
                "Configurations2/accelerator/current.xml": XML_DECL
                + "<config>SYNTHETIC-ACCELERATOR-0023</config>",
            },
            body=ANNOTATION + TRACKED_CHANGES + AUTHOR_FIELDS,
        ),
    )

    write_malformed()
    print(f"wrote fixtures to {OUT}")


def write_malformed():
    """Files that must be refused, each refused for a different reason."""
    data = (OUT / "everything.odt").read_bytes()

    # Truncated mid-archive: the central directory is gone entirely.
    (MALFORMED / "truncated.odt").write_bytes(data[: len(data) // 2])

    # No manifest. Part 2 section 2.2.1 requires it; without one there is no package, only a ZIP
    # of loose XML, and treating it as a document would mean guessing.
    build(
        MALFORMED / "no-manifest.odt",
        {"content.xml": content(), "styles.xml": styles()},
    )

    # An ODF-encrypted package. **The ZIP layer cannot see this**: ODF does not set the ZIP
    # encryption bit, it encrypts the entry data and records the fact in the manifest. Without the
    # manifest check, `content.xml` is ciphertext, no rule matches it, and the document is
    # reported clean — docs/THREAT_MODEL.md section 5.4 exactly.
    parts = package(TEXT)
    parts["META-INF/manifest.xml"] = manifest(
        TEXT,
        ["mimetype", "content.xml", "styles.xml"],
        encrypted="content.xml",
    )
    parts["content.xml"] = bytes(range(256)) * 4
    build(MALFORMED / "encrypted.odt", parts)

    # A package that gives two different answers to "what am I". Different readers would disagree
    # about what they are opening, and picking a winner would mean strypt deciding for them.
    parts = package(TEXT)
    parts["META-INF/manifest.xml"] = manifest(
        SPREADSHEET, ["mimetype", "content.xml", "styles.xml"]
    )
    build(MALFORMED / "mimetype-mismatch.odt", parts)

    # An OpenDocument drawing: understood, named in the refusal, and not in this format group.
    build(MALFORMED / "drawing.odg", package(GRAPHICS), mimetype=GRAPHICS)

    # A document containing another document. ADR-0029 fixes the descent at one level, so this is
    # refused rather than partially cleaned.
    build(
        MALFORMED / "nested-archive.odt",
        package(TEXT, extra={"inner.odt": (OUT / "clean.odt").read_bytes()}),
    )

    # An OLE compound file — the shape of an OLE object embedded from another application.
    build(
        MALFORMED / "ole-object.odt",
        package(
            TEXT,
            extra={
                "Object 1": bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
                + b"\x00" * 512
            },
        ),
    )

    # An entry that claims to inflate to far more than its compressed size permits. The ratio
    # check has to bite before the memory is committed.
    bomb = bytearray((OUT / "clean.odt").read_bytes())
    cursor = bomb.find(b"PK\x01\x02")
    # Uncompressed size sits 24 bytes into a central directory header.
    struct.pack_into("<I", bomb, cursor + 24, 0x0FFF_FFFF)
    (MALFORMED / "declared-expansion-bomb.odt").write_bytes(bytes(bomb))


if __name__ == "__main__":
    main()
