#!/usr/bin/env python3
"""Generate the Office Open XML fixtures in ``corpus/ooxml``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with Word or LibreOffice installed is a corpus nobody regenerates.

Every fixture is a **structurally real OOXML package**: a ZIP archive with a
``[Content_Types].xml`` that declares a main part, a ``_rels/.rels`` that points at it, and the
main part itself. They are minimal rather than rich — a fixture exists to exercise one decision
in the handler, and a fixture carrying a whole document's worth of unrelated markup makes it
harder to see which byte the test is actually about.

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report —
a handler that forgot to remove something would still cheerfully report having removed it.

Two fixtures deliberately carry values that must **survive**, prefixed ``PRESERVED-`` so the
sweep for surviving ``SYNTHETIC`` markers does not trip over them: the words of a tracked
change and the text of a comment. Removing those would change what the document says, which
``docs/PRD.md`` section 8.1 forbids (ADR-0030).
"""

import pathlib
import struct
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "ooxml"
MALFORMED = OUT / "malformed"

# A fixed MS-DOS timestamp for every entry. The generator must not put the current time into a
# fixture — that would make the corpus non-deterministic, and it would put the build machine's
# clock into a file committed to a public repository.
FIXED_DATE = (2020, 1, 1, 0, 0, 0)

CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

MAIN_TYPES = {
    "docx": (
        "/word/document.xml",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    ),
    "xlsx": (
        "/xl/workbook.xml",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    ),
    "pptx": (
        "/ppt/presentation.xml",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
    ),
}

CORE_TYPE = "application/vnd.openxmlformats-package.core-properties+xml"
APP_TYPE = "application/vnd.openxmlformats-officedocument.extended-properties+xml"
CUSTOM_TYPE = "application/vnd.openxmlformats-officedocument.custom-properties+xml"
# Real producers declare an Override for every part they write. Declaring `word/settings.xml`
# only through the generic `Default Extension="xml"` would make the fixture less like a real
# document than it needs to be — and mat2, which keys on the declared content type, refuses such
# a package outright, which would silently remove those fixtures from the differential.
SETTINGS_TYPE = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"
)

XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def content_types(kind, overrides=(), defaults=()):
    """``[Content_Types].xml`` declaring the main part plus whatever a fixture adds."""
    part, main_type = MAIN_TYPES[kind]
    lines = [XML_DECL, f'<Types xmlns="{CT_NS}">']
    lines.append(
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    )
    lines.append('<Default Extension="xml" ContentType="application/xml"/>')
    for ext, kind_ in defaults:
        lines.append(f'<Default Extension="{ext}" ContentType="{kind_}"/>')
    lines.append(f'<Override PartName="{part}" ContentType="{main_type}"/>')
    for name, kind_ in overrides:
        lines.append(f'<Override PartName="{name}" ContentType="{kind_}"/>')
    lines.append("</Types>")
    return "".join(lines)


def root_rels(kind, extra=()):
    """``_rels/.rels``, which is where the properties parts are referenced from."""
    target = MAIN_TYPES[kind][0].lstrip("/")
    lines = [XML_DECL, f'<Relationships xmlns="{REL_NS}">']
    lines.append(
        f'<Relationship Id="rId1" Type="{OFFICE_REL}/officeDocument" Target="{target}"/>'
    )
    for index, (rel_type, rel_target) in enumerate(extra, start=2):
        lines.append(
            f'<Relationship Id="rId{index}" Type="{rel_type}" Target="{rel_target}"/>'
        )
    lines.append("</Relationships>")
    return "".join(lines)


def word_document(body):
    return (
        XML_DECL
        + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
        ' xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml">'
        f"<w:body>{body}</w:body></w:document>"
    )


CORE_XML = (
    XML_DECL
    + '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
    ' xmlns:dcterms="http://purl.org/dc/terms/">'
    "<dc:title>SYNTHETIC-TITLE-0001</dc:title>"
    "<dc:creator>SYNTHETIC-CREATOR-0002</dc:creator>"
    "<cp:lastModifiedBy>SYNTHETIC-LASTMODIFIEDBY-0003</cp:lastModifiedBy>"
    "<cp:revision>SYNTHETIC-REVISION-0004</cp:revision>"
    "<dcterms:created>2021-03-04T05:06:07Z</dcterms:created>"
    "<dcterms:modified>2021-03-04T08:09:10Z</dcterms:modified>"
    "<cp:keywords>SYNTHETIC-KEYWORDS-0005</cp:keywords>"
    "</cp:coreProperties>"
)

APP_XML = (
    XML_DECL
    + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    "<Application>SYNTHETIC-APPLICATION-0006</Application>"
    "<AppVersion>SYNTHETIC-APPVERSION-0007</AppVersion>"
    "<Company>SYNTHETIC-COMPANY-0008</Company>"
    "<Manager>SYNTHETIC-MANAGER-0009</Manager>"
    "<TotalTime>SYNTHETIC-TOTALTIME-0010</TotalTime>"
    "<Template>SYNTHETIC-TEMPLATE-0011</Template>"
    "</Properties>"
)

CUSTOM_XML = (
    XML_DECL
    + '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"'
    ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="MatterNumber">'
    "<vt:lpwstr>SYNTHETIC-MATTER-0012</vt:lpwstr></property>"
    "</Properties>"
)


def build(path, parts):
    """Write a ZIP archive with the given ``name -> bytes`` mapping, deterministically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in parts.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            # Deflate for the XML parts, which is what a real producer does — a corpus of
            # stored-only archives would never exercise the inflate path at all.
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def base_parts(kind, overrides=(), defaults=(), extra_rels=(), main_body=None):
    """The three parts every package needs, plus whatever the fixture overrides."""
    part = MAIN_TYPES[kind][0].lstrip("/")
    if main_body is None:
        main_body = {
            "docx": word_document("<w:p><w:r><w:t>PRESERVED-BODY-TEXT</w:t></w:r></w:p>"),
            "xlsx": XML_DECL
            + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheets><sheet name="Sheet1" sheetId="1"/></sheets></workbook>',
            "pptx": XML_DECL
            + '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>',
        }[kind]
    return {
        "[Content_Types].xml": content_types(kind, overrides, defaults),
        "_rels/.rels": root_rels(kind, extra_rels),
        part: main_body,
    }


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


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    MALFORMED.mkdir(parents=True, exist_ok=True)

    # A package with nothing to remove. A tool that invents findings teaches users to ignore it.
    build(OUT / "clean.docx", base_parts("docx"))

    build(
        OUT / "core-properties.docx",
        base_parts(
            "docx",
            overrides=[("/docProps/core.xml", CORE_TYPE)],
            extra_rels=[(f"{PKG_REL}/metadata/core-properties", "docProps/core.xml")],
        )
        | {"docProps/core.xml": CORE_XML},
    )

    build(
        OUT / "app-properties.docx",
        base_parts(
            "docx",
            overrides=[("/docProps/app.xml", APP_TYPE)],
            extra_rels=[(f"{OFFICE_REL}/extended-properties", "docProps/app.xml")],
        )
        | {"docProps/app.xml": APP_XML},
    )

    build(
        OUT / "custom-properties.docx",
        base_parts(
            "docx",
            overrides=[("/docProps/custom.xml", CUSTOM_TYPE)],
            extra_rels=[(f"{OFFICE_REL}/custom-properties", "docProps/custom.xml")],
        )
        | {"docProps/custom.xml": CUSTOM_XML},
    )

    # A rendered preview of the first page. It survives every kind of redaction applied to the
    # text, in the same way an Exif thumbnail survives cropping — and it has no content-type
    # override, so it can only be found through its relationship.
    build(
        OUT / "thumbnail.docx",
        base_parts(
            "docx",
            defaults=[("jpeg", "image/jpeg")],
            extra_rels=[(f"{PKG_REL}/metadata/thumbnail", "docProps/thumbnail.jpeg")],
        )
        | {"docProps/thumbnail.jpeg": jpeg_fixture()},
    )

    # Revision-save identifiers: the metadata nobody looks for. Two documents carrying the same
    # rsid were edited in the same session on the same machine.
    rsid_body = word_document(
        '<w:p w:rsidR="00A1B2C3" w:rsidRDefault="00A1B2C3" w:rsidP="00D4E5F6"'
        ' w14:paraId="1A2B3C4D" w14:textId="5E6F7A8B">'
        "<w:r><w:t>PRESERVED-BODY-TEXT</w:t></w:r></w:p>"
    )
    settings = (
        XML_DECL
        + '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:zoom w:percent="100"/>'
        '<w:rsids><w:rsidRoot w:val="00A1B2C3"/><w:rsid w:val="00A1B2C3"/>'
        '<w:rsid w:val="00D4E5F6"/></w:rsids>'
        "</w:settings>"
    )
    build(
        OUT / "revision-identifiers.docx",
        base_parts(
            "docx",
            overrides=[("/word/settings.xml", SETTINGS_TYPE)],
            main_body=rsid_body,
        )
        | {
            "word/settings.xml": settings,
            "word/_rels/document.xml.rels": XML_DECL
            + f'<Relationships xmlns="{REL_NS}">'
            f'<Relationship Id="rId1" Type="{OFFICE_REL}/settings" Target="settings.xml"/>'
            "</Relationships>",
        },
    )

    # The fixture behind ADR-0030's hardest call: the author of a revision goes, the words of it
    # stay. A tool that silently accepted every pending change would hand a journalist a
    # document that says something different from the one they reviewed.
    tracked = word_document(
        '<w:p><w:ins w:id="1" w:author="SYNTHETIC-INSERTER-0013"'
        ' w:date="2021-03-04T05:06:07Z"><w:r><w:t>PRESERVED-INSERTED-TEXT</w:t></w:r></w:ins>'
        '<w:del w:id="2" w:author="SYNTHETIC-DELETER-0014" w:date="2021-03-04T05:06:08Z">'
        "<w:r><w:delText>PRESERVED-DELETED-TEXT</w:delText></w:r></w:del></w:p>"
    )
    build(OUT / "tracked-changes.docx", base_parts("docx", main_body=tracked))

    comments = (
        XML_DECL
        + '<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:comment w:id="1" w:author="SYNTHETIC-COMMENTER-0015" w:initials="SC"'
        ' w:date="2021-03-04T05:06:09Z">'
        "<w:p><w:r><w:t>PRESERVED-COMMENT-TEXT</w:t></w:r></w:p></w:comment>"
        "</w:comments>"
    )
    build(
        OUT / "comments.docx",
        base_parts(
            "docx",
            overrides=[
                (
                    "/word/comments.xml",
                    "application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.comments+xml",
                )
            ],
        )
        | {"word/comments.xml": comments},
    )

    # The fixture for ADR-0029: a photograph inside a document, carrying its own GPS.
    build(
        OUT / "embedded-image.docx",
        base_parts("docx", defaults=[("jpg", "image/jpeg")])
        | {"word/media/image1.jpg": jpeg_fixture()},
    )

    # An external relationship whose target names a person through their home directory. Reported
    # rather than removed: cutting it would leave the r:id that refers to it dangling.
    build(
        OUT / "external-template.docx",
        base_parts("docx", overrides=[("/word/settings.xml", SETTINGS_TYPE)])
        | {
            "word/settings.xml": XML_DECL
            + '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
            ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<w:attachedTemplate r:id="rId1"/></w:settings>',
            "word/_rels/settings.xml.rels": XML_DECL
            + f'<Relationships xmlns="{REL_NS}">'
            f'<Relationship Id="rId1" Type="{OFFICE_REL}/attachedTemplate"'
            ' Target="file:///Users/SYNTHETIC-USER-0016/Templates/report.dotx"'
            ' TargetMode="External"/></Relationships>',
        },
    )

    # Everything at once, which is what a real document looks like.
    build(
        OUT / "everything.docx",
        base_parts(
            "docx",
            overrides=[
                ("/docProps/core.xml", CORE_TYPE),
                ("/docProps/app.xml", APP_TYPE),
                ("/docProps/custom.xml", CUSTOM_TYPE),
                ("/word/settings.xml", SETTINGS_TYPE),
            ],
            defaults=[("jpg", "image/jpeg"), ("jpeg", "image/jpeg")],
            extra_rels=[
                (f"{PKG_REL}/metadata/core-properties", "docProps/core.xml"),
                (f"{OFFICE_REL}/extended-properties", "docProps/app.xml"),
                (f"{OFFICE_REL}/custom-properties", "docProps/custom.xml"),
                (f"{PKG_REL}/metadata/thumbnail", "docProps/thumbnail.jpeg"),
            ],
            main_body=rsid_body,
        )
        | {
            "docProps/core.xml": CORE_XML,
            "docProps/app.xml": APP_XML,
            "docProps/custom.xml": CUSTOM_XML,
            "docProps/thumbnail.jpeg": jpeg_fixture(),
            "word/settings.xml": settings,
            "word/media/image1.jpg": jpeg_fixture(),
        },
    )

    # SpreadsheetML: the author list is positional, so its entries are emptied rather than
    # removed — deleting one would silently reattribute every comment after it.
    xl_comments = (
        XML_DECL
        + '<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<authors><author>SYNTHETIC-XLAUTHOR-0017</author>"
        "<author>SYNTHETIC-XLAUTHOR-0018</author></authors>"
        '<commentList><comment ref="A1" authorId="1">'
        "<text><t>PRESERVED-XL-COMMENT</t></text></comment></commentList></comments>"
    )
    build(
        OUT / "workbook.xlsx",
        base_parts(
            "xlsx",
            overrides=[
                ("/docProps/core.xml", CORE_TYPE),
                (
                    "/xl/comments1.xml",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml",
                ),
            ],
            extra_rels=[(f"{PKG_REL}/metadata/core-properties", "docProps/core.xml")],
        )
        | {"docProps/core.xml": CORE_XML, "xl/comments1.xml": xl_comments},
    )

    # PresentationML: the comment-author list keys on `id`, so the id stays and the name goes.
    cm_authors = (
        XML_DECL
        + '<p:cmAuthorLst xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cmAuthor id="1" name="SYNTHETIC-PPTAUTHOR-0019" initials="SP" lastIdx="1"/>'
        "</p:cmAuthorLst>"
    )
    build(
        OUT / "presentation.pptx",
        base_parts(
            "pptx",
            overrides=[
                ("/docProps/core.xml", CORE_TYPE),
                (
                    "/ppt/commentAuthors.xml",
                    "application/vnd.openxmlformats-officedocument."
                    "presentationml.commentAuthors+xml",
                ),
            ],
            extra_rels=[(f"{PKG_REL}/metadata/core-properties", "docProps/core.xml")],
        )
        | {"docProps/core.xml": CORE_XML, "ppt/commentAuthors.xml": cm_authors},
    )

    write_malformed()
    print(f"wrote fixtures to {OUT}")


def write_malformed():
    """Files that must be refused, each refused for a different reason."""
    good = OUT / "everything.docx"
    data = good.read_bytes()

    # Truncated mid-archive: the central directory is gone entirely.
    (MALFORMED / "truncated.docx").write_bytes(data[: len(data) // 2])

    # A package with no `[Content_Types].xml`, which is what makes a ZIP an OOXML package. It
    # must be refused rather than treated as an archive of loose XML.
    build(
        MALFORMED / "no-content-types.docx",
        {"_rels/.rels": root_rels("docx"), "word/document.xml": word_document("")},
    )

    # A document containing another document. ADR-0029 fixes the descent at one level, so this
    # is refused rather than partially cleaned.
    build(
        MALFORMED / "nested-archive.docx",
        base_parts("docx", defaults=[("bin", "application/octet-stream")])
        | {"word/embeddings/inner.bin": (OUT / "core-properties.docx").read_bytes()},
    )

    # An OLE compound file — the shape of `vbaProject.bin` and of every embedded OLE object.
    # strypt cannot read its directory, so a document carrying one is refused.
    build(
        MALFORMED / "ole-object.docx",
        base_parts("docx", defaults=[("bin", "application/octet-stream")])
        | {
            "word/embeddings/oleObject1.bin": bytes(
                [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
            )
            + b"\x00" * 512
        },
    )

    # A macro-enabled document, refused at detection so the message can say why.
    macro_types = content_types("docx").replace(
        "wordprocessingml.document.main+xml",
        "wordprocessingml.document.macroEnabled.main+xml",
    )
    build(
        MALFORMED / "macro-enabled.docm",
        {
            "[Content_Types].xml": macro_types,
            "_rels/.rels": root_rels("docx"),
            "word/document.xml": word_document(""),
            "word/vbaProject.bin": bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        },
    )

    # An entry flagged as encrypted. strypt cannot inspect what it cannot read, and reporting a
    # document clean on the strength of parts nobody examined is the failure this whole project
    # exists to prevent (docs/THREAT_MODEL.md section 5.4).
    encrypted = bytearray((OUT / "clean.docx").read_bytes())
    cursor = encrypted.find(b"PK\x01\x02")
    while cursor != -1:
        # General-purpose flags sit eight bytes into a central directory header.
        encrypted[cursor + 8] |= 1
        cursor = encrypted.find(b"PK\x01\x02", cursor + 1)
    (MALFORMED / "encrypted-entry.docx").write_bytes(bytes(encrypted))

    # An entry that claims to inflate to far more than its compressed size permits. The ratio
    # check has to bite before the memory is committed.
    bomb = bytearray((OUT / "clean.docx").read_bytes())
    cursor = bomb.find(b"PK\x01\x02")
    # Uncompressed size sits 24 bytes into a central directory header.
    struct.pack_into("<I", bomb, cursor + 24, 0x0FFF_FFFF)
    (MALFORMED / "declared-expansion-bomb.docx").write_bytes(bytes(bomb))


if __name__ == "__main__":
    main()
