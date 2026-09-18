# Test corpus manifest

Every fixture is documented here: where it came from, what metadata it carries, and what it
is testing. An undocumented fixture is a file nobody dares change.

## Rules

- **No file may contain real personal data.** Fixtures are committed publicly and
  permanently. A corpus that leaks someone's location would be an unusually humiliating
  failure for this project in particular (`docs/TESTING_STRATEGY.md` §3).
- Fixtures are **generated**, not collected, wherever that is possible — it makes the rule
  above structural rather than a habit someone has to remember.
- Marker strings are deliberately unmistakable (`SYNTHETIC-…-000N`) so that a test can assert
  on the *bytes of the output* rather than on strypt's own report. A handler that forgot to
  remove something would still report having removed it.
- Fixtures stay small. Large ones belong in a fetched-on-demand corpus, not in git forever.

## Regenerating

```
python3 corpus/tools/make_pdf_fixtures.py
python3 corpus/tools/make_jpeg_fixtures.py
python3 corpus/tools/make_png_fixtures.py
python3 corpus/tools/make_webp_fixtures.py
python3 corpus/tools/make_tiff_fixtures.py
python3 corpus/tools/make_gif_fixtures.py
python3 corpus/tools/make_heif_fixtures.py
python3 corpus/tools/make_svg_fixtures.py
python3 corpus/tools/make_jxl_fixtures.py
python3 corpus/tools/make_flac_fixtures.py
python3 corpus/tools/make_wav_fixtures.py
python3 corpus/tools/make_mp3_fixtures.py
python3 corpus/tools/make_ogg_fixtures.py
python3 corpus/tools/make_mp4_fixtures.py
python3 corpus/tools/make_ooxml_fixtures.py   # requires the JPEG fixtures: it embeds one
python3 corpus/tools/make_odf_fixtures.py     # requires the JPEG and PNG fixtures: it embeds both
```

Deterministic: two runs produce byte-identical files, so a fixture appearing in `git diff`
means the generator changed.

## PDF

| Fixture | Carries | Tests |
|---|---|---|
| `info-dictionary.pdf` | Author, Creator, Producer, Title, Subject, Keywords, CreationDate, ModDate, a non-standard `CustomVendorField`, and a trailer `/ID` | The baseline case, plus that vendor-invented keys are not walked past |
| `xmp-packet.pdf` | An uncompressed XMP packet: `dc:creator`, `xmp:CreatorTool`, `xmp:CreateDate`, `xmp:ModifyDate`, `xmpMM:DocumentID`, `xmpMM:InstanceID`, `pdf:Producer` | That XMP is found, broken down by property, and removed |
| `incremental-update.pdf` | Two saves. The first save's author (`SYNTHETIC-ORPHANED-AUTHOR-0005`) is still in the file, referenced by nothing | **The fixture that justifies ADR-0020.** A tool that patches rather than rewrites leaves the orphaned author in place and reports the file clean |
| `annotation-author.pdf` | A `/Text` markup annotation with `/T`, `/M`, `/CreationDate`, `/NM`, and a comment | That the annotator's name goes and the comment stays — strypt removes metadata, not content |
| `form-field.pdf` | A `/Widget` annotation whose `/T` is the field name `applicant_surname` | That `/T` is **not** removed here. On a widget it is the field name the form's logic and saved data depend on; removing it breaks the document |
| `piece-info.pdf` | `/PieceInfo` private application scratch data and `/LastModified` | That application-private storage is removed |
| `embedded-file.pdf` | A `/Filespec` attachment with `/Desc` and `/Params` dates | That attachment metadata is removed, the attachment itself is preserved, and the report says plainly that strypt did not open it |
| `clean.pdf` | Nothing | That a clean file produces no findings. A tool that invents findings teaches users to ignore it |
| `embedded-jpeg.pdf` | `jpeg/exif-gps.jpg` placed on the page and used as its `/Thumb` | **A regression test for a real leak** (ADR-0056). 0.1.0 reported this file clean while both images kept their GPS, serial and artist |
| `unexamined-images.pdf` | A bare JPEG 2000 codestream, and a JPEG behind `/FlateDecode` | That images strypt cannot open are copied and named in the report, not passed silently |
| `negative-zero-real.pdf` | A `/UserUnit` and a `/CropBox` holding negative zero — a valid document, which is why it is not under `malformed/` | **A regression test for a real bug.** lopdf wrote `Real(-0.0)` as `-0`, which re-parsed as `Integer(0)` and wrote as `0`, so one strip differed from two. Both a bare value and one nested in an array are covered, on reachable page keys so pruning cannot quietly remove them before the handler walks them |
| `malformed/xref-start-overflow.pdf` | An xref subsection header mutated so the parser computes a start index that overflows | **A regression test for a real bug**, and the fixture that pins ADR-0024. lopdf 0.44.0 panics on it; strypt contains the panic and refuses the file rather than crashing. The bytes are the fuzzer's, kept verbatim |
| `malformed/xref-19-byte-entries.pdf` | A correct document whose xref entries are 19 bytes, not the 20 ISO 32000-1 §7.5.4 requires — the padding space before each newline is dropped | That strypt refuses it as a *typed* `Malformed` error rather than panicking or reporting success on a file it never processed. A known capability gap: qpdf and mat2 both accept these bytes (`docs/THREAT_MODEL.md` §7.5) |
| `malformed/stream-length-mismatch.pdf` | A content stream declaring `/Length 45.` — a malformed real where §7.3.8.2 requires an integer. lopdf parses the document without error but stores empty stream content | **A regression test for a real bug.** strypt used to rewrite this and report a clean copy while silently discarding the page's content and emitting a PDF qpdf calls corrupt. Now refused |
| `malformed/no-root-trailer.pdf` | A trailer whose `/Root` key is spelled `/t`, so the document has no catalogue — ISO 32000-1 §7.5.5 requires the entry | **A regression test for a real bug.** With no root to walk from, the reachability rewrite (ADR-0020) dropped a different set of objects on the second pass than the first, renumbering the catalogue into a slot a page's `/Annots` still pointed at. strypt reported success both times. Now refused |

`malformed/stream-length-mismatch.pdf` is the one fixture in this corpus not produced by a
generator: it is a minimised `pdf` fuzz artifact, kept as the exact input that triggered the
bug (`CONTRIBUTING.md`). It is a mutation of `xmp-packet.pdf`, so it carries only the
synthetic markers that fixture carries.

### Not yet represented

Recorded so the gaps are visible rather than forgotten. The fixtures above are synthetic, so
they test strypt against the specification rather than against what real software emits — and
real software is where the quirks live.

The fetch-on-demand corpus in `real-producer-corpus/` now covers several of these locally
(24 PDFs from LaTeX, LibreOffice, Google Docs, Acrobat and ImageMagick). It is **not**
committed — its files carry real names and coordinates, which `docs/TESTING_STRATEGY.md` §3
forbids here. So these remain gaps in *this* corpus, which is the one CI runs against:

- Files from actual producers, as committed fixtures.
- Linearised ("fast web view") files — absent from both corpora.
- Object streams and cross-reference streams (PDF 1.5+), which most modern producers emit and
  which none of the fixtures above use. Exercised via the fetched corpus (`GeoTopo.pdf` carries
  34 object streams and strips cleanly), but not pinned by a committed fixture.
- Encrypted documents. Refused by design (`crates/strypt-core/src/formats/pdf.rs`), and the
  refusal is confirmed against a real password-protected LibreOffice file in the fetched
  corpus, but it is not yet covered by a committed fixture.

## JPEG

Every JPEG fixture is a **real, decodable image**: the same 16×16 greyscale gradient with
different metadata spliced around it. That shared base image is what makes the pixel-identity
test possible — after stripping, all of them must have byte-identical entropy-coded data, and
any difference means something re-encoded a picture.

| Fixture | Carries | Tests |
|---|---|---|
| `exif-gps.jpg` | Exif: `Make`, `Model`, `Software`, `Artist`, `DateTime`, `DateTimeOriginal`, `BodySerialNumber`, `UserComment`, and a GPS directory with latitude and longitude | The baseline case, and that Exif is reported tag by tag rather than as one lump |
| `exif-thumbnail.jpg` | An Exif `IFD1` thumbnail: a second, complete JPEG carrying its own marker string | That the thumbnail's **bytes** are gone, not merely that `IFD1` is. A thumbnail predates cropping and survives redaction of the main image |
| `xmp-packet.jpg` | An `APP1` XMP packet: `dc:creator`, `xmp:CreatorTool`, `xmpMM:DocumentID` | That XMP is found, broken down by property, and removed |
| `comment.jpg` | A `COM` segment | Free text written by a person into a slot nothing displays |
| `photoshop-iptc.jpg` | `APP13` Photoshop image resources with IPTC by-line and city | That press-photo credit fields go |
| `icc-profile.jpg` | `APP2` ICC profile naming a vendor and a device | That colour profiles are removed even though removing them changes rendering (ADR-0021) |
| `jfif-thumbnail.jpg` | `APP0` JFIF header with a 3×3 embedded RGB thumbnail | **A rewrite, not a removal.** The header survives — it carries the pixel aspect ratio — with the thumbnail gone and its dimensions zeroed |
| `adobe-marker.jpg` | `APP14` Adobe colour-transform marker | That it is **kept**, and that the report declares it as kept rather than leaving it to be discovered |
| `trailing-data.jpg` | A whole second image after the `EOI` marker | Where a phone's multi-picture extension hides a full-resolution frame. No viewer shows it; every forensic tool finds it |
| `clean.jpg` | Nothing | That a clean file produces no findings and is returned byte-identical |

### `corpus/jpeg/malformed/`

Deliberately broken files: a length running past the end of the file, a length below the two
bytes the length field itself occupies, an Exif directory pointing at itself, a tag claiming
four billion components, a file with no `EOI`, a long run of fill bytes, and an Exif block
whose TIFF header is not one. They are fuzz seeds and are asserted on directly: nothing may
panic, and anything reported as a success must really be clean. A seed corpus of nothing but
valid files teaches the fuzzer that files are valid.

### Not yet represented

- Photographs from real cameras and phones — multiple makes, with real maker notes. The maker
  note is vendor-private with no public schema and is where the surprises live; synthetic
  fixtures cannot stand in for it.
- Progressive JPEGs with several scans, and files using restart intervals in anger.
- CMYK and YCCK images, which are what makes the `APP14` retention matter.

## PNG

Every PNG fixture is a **real, decodable image**: the same 16×16 greyscale gradient with
different metadata chunks spliced around it. That shared base is what makes the image-identity
test possible — after stripping, all of them must have byte-identical `IDAT` data.

The compressed chunks are built with **stored (uncompressed) deflate blocks**. That is a legal
zlib stream, so every fixture stays decodable, and it means the text inside a `zTXt` or a
compressed `iTXt` is visible in the file's raw bytes — which lets a test assert that strypt's
*output* does not contain it, rather than trusting strypt's report. It also makes the
generator independent of any compressor's version-to-version output, which is what determinism
needs.

| Fixture | Carries | Tests |
|---|---|---|
| `text-chunks.png` | `tEXt`: `Author`, `Software`, `Comment` | The baseline case, and that keywords are classified rather than all filed as "text" |
| `thumbnail-uri.png` | `tEXt`: `Thumb::URI` holding a full `file:///home/...` path, and `Thumb::MTime` | That a thumbnailer's record of where the original lived is ranked as identifying. A home directory names a person |
| `compressed-text.png` | `zTXt` with keyword `Comment` | **The fixture that justifies ADR-0022.** The keyword is readable, the payload is not read, and the chunk goes whole — with no decompressor anywhere in the tree |
| `xmp-packet.png` | `iTXt` `XML:com.adobe.xmp`, uncompressed: `dc:creator`, `xmp:CreatorTool`, `xmpMM:DocumentID` | That an uncompressed packet is broken down property by property |
| `xmp-compressed.png` | The same packet, with the compression flag set | The documented cost of carrying no decompressor: removed identically, reported as one item |
| `exif-gps.png` | An `eXIf` chunk: `Make`, `Model`, `DateTime`, and a GPS directory | That the `eXIf` chunk goes through the same Exif reader a JPEG's `APP1` does |
| `icc-profile.png` | `iCCP` with a vendor-named profile | That the profile name — which is *not* compressed — is what the report names |
| `timestamp.png` | `tIME` | That the modification time is removed, and that its value is withheld unless the caller asks |
| `raw-profile.png` | `tEXt` with keyword `Raw profile type exif` holding a hex-encoded Exif block | `ImageMagick`'s habit. A tool that only looks at `eXIf` chunks walks straight past a camera's GPS coordinates |
| `unknown-chunks.png` | A private ancillary chunk (`prVW`) and an unknown critical one (`VeND`) | That the ancillary one goes and the critical one is **kept and declared**. Its marker is prefixed `PRESERVED-`, not `SYNTHETIC-`, so the "no marker survives" test does not sweep it up. **This fixture is deliberately not renderable**: a conforming decoder must refuse an unrecognised critical chunk, and macOS `sips` duly does. Do not "fix" it |
| `rendering-chunks.png` | `gAMA`, `sRGB`, `pHYs`, `bKGD`, plus a `tEXt` | That chunks affecting how the image renders survive, and that `pHYs` is declared in the report's `retained` list rather than left to be discovered |
| `trailing-data.png` | A whole second PNG after `IEND` | Where an uncropped copy of a cropped picture fits comfortably. Nothing reads past `IEND` |
| `clean.png` | Nothing | That a clean file produces no findings and is returned **byte-identical** |

### `corpus/png/malformed/`

Deliberately broken files: a chunk length running past the end of the file, a length with the
high bit the specification reserves, a file ending before `IEND`, a chunk type that is not
four letters, a file whose first chunk is not `IHDR`, and a text chunk with no NUL separator.
They are fuzz seeds and are asserted on directly: nothing may panic, and anything reported as
a success must really be clean. The last of them should still strip rather than be refused —
it is malformed and on its way out regardless.

### Not yet represented

- PNGs from real producers: screenshot tools, phone screenshots, Photoshop, GIMP, scanners.
  Screenshot metadata is where this format's real-world risk concentrates.
- APNG animations. The animation chunks are kept by design and no fixture yet proves it.
- Interlaced images, 16-bit depths, and palette images with `PLTE` plus `tRNS`.

## WebP

Generated by `corpus/tools/make_webp_fixtures.py`. Deterministic: two runs produce
byte-identical files.

Every WebP fixture is a **real, decodable image**. Two base bitstreams — one lossless, one
lossy — were produced once with `cwebp 1.6.0` from the same 16×16 picture the PNG fixtures use
and are committed as literals in the generator, so regenerating the corpus never depends on an
encoder being installed or on its version-to-version output. The fixtures are those bitstreams
with container chunks arranged around them; nothing is re-encoded, which is also what strypt
itself refuses to do.

The lossless base has a 25-byte payload — an odd length, so it carries the RIFF padding byte
(RFC 9649 §2.3). That is deliberate: a handler that dropped the pad when copying a chunk
through would shift every chunk after it by one byte, and no fixture with an even payload would
ever catch it.

| Fixture | Carries | Tests |
|---|---|---|
| `exif-gps.webp` | `EXIF`: `Make`, `Model`, `DateTime`, and a GPS directory | The ordinary photograph case, and that the chunk goes through the same Exif reader a JPEG's `APP1` does |
| `xmp-packet.webp` | `XMP `: `dc:creator`, `xmp:CreatorTool`, `xmpMM:DocumentID` | That a packet is broken down property by property |
| `icc-profile.webp` | `ICCP` | That the profile is removed and ranked as a colour profile. strypt does not read inside it |
| `all-metadata.webp` | `ICCP`, `EXIF`, and `XMP `, with the alpha bit also set in `VP8X` | **The fixture that justifies ADR-0023.** All three flag bits must be cleared and the alpha bit must survive — the header has to describe the file it is actually in |
| `unknown-chunk.webp` | A `PRVW` chunk | That an unknown chunk is removed, which is a deliberate departure from §2.7.1.6's "writers SHOULD preserve them" |
| `animated.webp` | `ANIM`, two `ANMF` frames, and an `EXIF` chunk | That an animation keeps both frames and loses its metadata — a handler that dropped `ANMF` would silently turn an animation into a still |
| `animation-frame-chunk.webp` | A `JUNK` chunk *inside* an `ANMF` frame | §2.7.1.1 allows unknown chunks inside a frame, which makes it a hiding place with the specification's blessing. A handler that filtered only the top level would walk straight past this |
| `unparsable-frame.webp` | An `ANMF` whose sub-chunk length runs past the end of the frame | That the frame is **kept and declared unexamined** rather than half-parsed or the file refused. Its marker is prefixed `PRESERVED-`, not `SYNTHETIC-`, so the "no marker survives" test does not sweep it up |
| `trailing-data.webp` | A whole second WebP after the declared RIFF size | Where an uncropped copy of a cropped picture fits comfortably. Nothing reads past that boundary |
| `stale-flags.webp` | A `VP8X` claiming ICC, Exif, and XMP that the file does not have | That the flags are corrected even when there is nothing to remove — so `show` reports nothing and `strip` still changes the file |
| `exif-introducer.webp` | An `EXIF` chunk beginning with JPEG's `Exif\0\0` introducer | §2.7.1.5 puts no introducer here, but a producer copying a JPEG `APP1` payload across brings one. Those six bytes shift every offset inside the TIFF block |
| `clean-lossless.webp` | Nothing — simple format, `VP8L` | That a file with no `VP8X` is returned **byte-identical**. Not merely "nothing was found": §2.7 requires the extended header before any metadata chunk, so a simple file has nowhere to put any |
| `clean-lossy.webp` | Nothing — simple format, `VP8 ` | The same guarantee for the lossy bitstream |
| `clean-extended.webp` | Nothing — `VP8X` with no flags set | That a `VP8X` needing no correction is copied rather than rewritten |

### `corpus/webp/malformed/`

Deliberately broken files: a RIFF size running past the end of the file, a chunk size running
past the RIFF extent, a file with no bitstream and no animation frame, a four-character code
that is not ASCII, a file ending mid-chunk, a `VP8X` that is not the ten bytes §2.7 fixes it
at, and a file whose first chunk is metadata rather than a header or a bitstream. They are fuzz
seeds and are asserted on directly: nothing may panic, and anything reported as a success must
really be clean.

`no-picture-chunk.webp` is the one worth naming. It would otherwise strip to a valid-looking
container with no image in it, reported as a success — the failure mode in
`docs/THREAT_MODEL.md` §5.4 — so the handler refuses it instead.

### Not yet represented

- WebPs from real producers: phone cameras that write WebP directly, browser "save image as",
  Photoshop's WebP export, and the conversion pipelines that turn a JPEG into a WebP and carry
  its Exif block across.
- A real `ALPH` chunk with an actual alpha channel. The alpha bit is exercised in
  `all-metadata.webp`, but no fixture yet carries the chunk itself.
- Lossless files using the full range of VP8L transforms, and animations with more than two
  frames or with per-frame disposal and blending set.

## Office Open XML

Generated by `corpus/tools/make_ooxml_fixtures.py`. Every fixture is a structurally real package
— a ZIP archive with a `[Content_Types].xml` declaring a main part, a `_rels/.rels` pointing at
it, and the main part itself — built with `zipfile` and deflate, so the inflate path is
exercised rather than bypassed. They are minimal on purpose: a fixture exists to exercise one
decision, and a whole document's worth of unrelated markup makes it harder to see which byte the
test is about.

The `PRESERVED-…` markers are as load-bearing as the `SYNTHETIC-…` ones and pull in the opposite
direction. They are the document's own words, and a test suite that only checked for absence
would pass just as happily on a handler that deleted the document's contents (ADR-0030).

| Fixture | Carries | Tests |
|---|---|---|
| `clean.docx` | Nothing beyond entry timestamps | That a clean document produces no invented findings. A tool that invents findings teaches users to ignore it |
| `core-properties.docx` | `dc:title`, `dc:creator`, `cp:lastModifiedBy`, `cp:revision`, `dcterms:created`, `dcterms:modified`, `cp:keywords` | The baseline case, and that the part is removed *and* de-referenced from both index parts |
| `app-properties.docx` | `Application`, `AppVersion`, `Company`, `Manager`, `TotalTime`, `Template` | That the extended properties go, including `TotalTime` — cumulative editing minutes |
| `custom-properties.docx` | A `MatterNumber` custom property | That document-management-system properties are removed. Matched by content type, not by path |
| `thumbnail.docx` | A `docProps/thumbnail.jpeg` referenced only from `_rels/.rels` | **The fixture that justifies matching by relationship type.** The thumbnail has no content-type override, so a path- or type-only rule misses it entirely |
| `revision-identifiers.docx` | `w:rsidR`, `w:rsidRDefault`, `w:rsidP`, `w14:paraId`, `w14:textId`, and a `w:rsids` table in `settings.xml` | That editing-session identifiers go and `PRESERVED-BODY-TEXT` and `<w:zoom>` stay — removing the rsid table must not take the rest of `settings.xml` with it |
| `tracked-changes.docx` | A `w:ins` and a `w:del`, each with `w:author` and `w:date` | **The hardest call in ADR-0030.** That the attribution goes and `PRESERVED-INSERTED-TEXT` and `PRESERVED-DELETED-TEXT` both remain |
| `comments.docx` | A `w:comment` with author, initials, and date | That the commenter's name goes, `PRESERVED-COMMENT-TEXT` stays, and a `Note` says the comment content is still there |
| `embedded-image.docx` | The `corpus/jpeg/exif-gps.jpg` fixture at `word/media/image1.jpg` | **The fixture that justifies ADR-0029.** That a photograph inside a document is stripped by the *same* handler a loose one goes through — asserted by byte-comparing the two outputs |
| `external-template.docx` | An attached template at `file:///Users/SYNTHETIC-USER-0016/…` | That the relationship *and* the `w:attachedTemplate` that referred to it are both removed. Removing one end alone leaves a dangling reference and a repair prompt |
| `everything.docx` | All of the above at once | What a real document looks like, and the input for the truncation sweep |
| `workbook.xlsx` | Core properties, plus `xl/comments1.xml` with a positional `<authors>` list | That author entries are **emptied, not deleted** — `authorId` is an index, and shortening the list would silently reattribute every comment after it |
| `presentation.pptx` | Core properties, plus a `p:cmAuthor` with `name` and `initials` | That the name goes and `id` stays, since comments refer to it. Also the one fixture **mat2 refuses outright** (`docs/THREAT_MODEL.md` §7.6) |

### Malformed — every one must be refused

| Fixture | Why it must be refused |
|---|---|
| `truncated.docx` | The central directory is gone; there is no entry list to parse and guessing would mean inventing one |
| `no-content-types.docx` | Without `[Content_Types].xml` it is a ZIP of loose XML, not an OOXML package |
| `nested-archive.docx` | A document inside a document. ADR-0029 fixes the descent at one level, so this is refused rather than partly cleaned |
| `ole-object.docx` | An OLE compound file — its own container, with its own metadata streams strypt cannot read |
| `macro-enabled.docm` | Refused at *detection*, so the message can say why rather than calling it a generic ZIP |
| `encrypted-entry.docx` | strypt cannot inspect what it cannot read, and a document reported clean on the strength of parts nobody examined is the failure this project exists to prevent |
| `declared-expansion-bomb.docx` | An entry declaring far more inflated output than its compressed size permits. The ratio check must bite *before* the memory is committed |

## OpenDocument

Generated by `corpus/tools/make_odf_fixtures.py`. Every fixture is a structurally real package —
a `mimetype` entry written **first and stored** (ODF 1.3 Part 2 §3.3), a `META-INF/manifest.xml`
listing every part (§2.2.1), and the parts it lists — built with `zipfile` and deflate for
everything else, so the inflate path is exercised rather than bypassed.

The `PRESERVED-…` markers pull in the opposite direction from the `SYNTHETIC-…` ones, as for
OOXML: they are the document's own words, and a suite that only checked for absence would pass
just as happily on a handler that deleted the document's contents (ADR-0031).

| Fixture | Carries | Tests |
|---|---|---|
| `clean.odt` | Nothing beyond entry timestamps | That a clean document produces no invented findings |
| `meta.odt` | A full `meta.xml`: initial creator, last-saved-by, creation/modification/print dates, `meta:editing-cycles`, `meta:editing-duration`, `meta:generator`, a user-defined property, a `meta:template` path, and `meta:document-statistic` | **The fixture the format group exists for.** `meta:editing-duration` is an ISO 8601 duration to the second, with no Office equivalent worth calling equivalent, and the statistics are **attributes**, which the Office reporting path would walk straight past |
| `settings.odt` | A `settings.xml` with `PrinterName`, `PrinterSetup`, and `BuildId` | That the part is removed whole *and* that the report names the printer, rather than saying "a settings part was removed" and leaving the user none the wiser |
| `thumbnail.odt` | `Thumbnails/thumbnail.png` — the `corpus/png/text-chunks.png` fixture | That the rendered preview of the first page goes, and is reported as a thumbnail rather than as an anonymous part |
| `configurations.odt` | `Configurations2/accelerator/current.xml` and a `layout-cache` | That the producer's saved user-interface configuration and its layout cache are removed as subtrees |
| `comments.odt` | An `office:annotation` with `dc:creator`, `dc:date`, and `meta:date-string` | **The fixture that justifies tracking context.** `dc:creator` is the element name for a comment's author, a revision's author, *and* the document's own, so the rule cannot key on the name alone. `PRESERVED-COMMENT-TEXT` and the `PRESERVED-BODY-TEXT` outside the annotation both stay |
| `tracked-changes.odt` | `text:tracked-changes` with two `office:change-info` blocks | That attribution goes and `PRESERVED-INSERTED-TEXT` and `PRESERVED-DELETED-TEXT` both remain |
| `author-fields.odt` | `text:creator`, `text:initial-creator`, `text:author-name`, `text:author-initials`, `text:editing-cycles`, `text:editing-duration` in the body, one more in a `styles.xml` header, and a `text:creation-date` | **The one place strypt edits what a reader sees.** The cached author fields are emptied — the application filled them in from `meta.xml`, so leaving them would print the name strypt reported removing — and the displayed date is *kept* and reported |
| `embedded-image.odt` | The `corpus/jpeg/exif-gps.jpg` fixture at `Pictures/image1.jpg` | ADR-0029, from the ODF side. Asserted by byte-comparing against the same picture stripped loose, which also proves both package handlers share one descent |
| `embedded-object.ods` | An `Object 1/` chart with its own `content.xml`, `meta.xml`, and `settings.xml` | **The fixture that shows ODF is not OOXML with different names.** The equivalent `.docx` holds a whole `.xlsx` inside itself and is refused; here the chart's metadata is reachable in the same pass with no recursion, so the document is cleaned. Also the one fixture **mat2 refuses outright** (`docs/THREAT_MODEL.md` §7.7) |
| `nonconforming-mimetype.odt` | A `mimetype` entry written last and deflated | That output is a conforming package regardless: the entry is moved first and re-stored, and idempotence proves the move settles rather than oscillating |
| `spreadsheet.ods` / `presentation.odp` | `meta.xml`, plus an annotation in the spreadsheet | That all three document types are detected by the media type they declare and handled identically |
| `everything.odt` | All of the above at once | What a real document looks like, and the input for the truncation and bit-flip sweeps |

### Malformed — every one must be refused

| Fixture | Why it must be refused |
|---|---|
| `truncated.odt` | The central directory is gone; there is no entry list to parse and guessing would mean inventing one |
| `no-manifest.odt` | Part 2 §2.2.1 requires `META-INF/manifest.xml`. Without one it is a ZIP of loose XML, not a package |
| `encrypted.odt` | **The most dangerous case in this format.** ODF does not set ZIP's encryption bit — it encrypts entry data itself and records it in the manifest (§3.4) — so without a manifest check `content.xml` is ciphertext, nothing matches it, and the package is reported clean having been read by nobody |
| `mimetype-mismatch.odt` | The `mimetype` entry and the manifest root give different answers about what the document is. Different readers would disagree about what they are opening, and picking a winner would mean strypt deciding for them |
| `drawing.odg` | An `OpenDocument` type outside this format group. Refused at *detection* and named, so the message says "understood and declined" rather than "not recognised" |
| `nested-archive.odt` | A package inside a package. ADR-0029 fixes the descent at one level |
| `ole-object.odt` | An OLE compound file — its own container, with its own metadata streams strypt cannot read |
| `declared-expansion-bomb.odt` | An entry declaring far more inflated output than its compressed size permits. The ratio check must bite *before* the memory is committed |

## TIFF

Generated by `corpus/tools/make_tiff_fixtures.py`. Every fixture's pixel payload is the marker
`PRESERVED-TIFF-PIXELS`, so a test can assert the image crossed the rebuild byte for byte —
which for this format is the claim that matters, because strypt writes a new file rather than
editing the one it was given (ADR-0033).

| Fixture | Carries | Tests |
|---|---|---|
| `clean.tiff` | Nothing identifying | That a clean file still rebuilds into a valid TIFF, and that the rebuild is a fixed point of its own reader |
| `identifying-tags.tiff` | `Make`, `Model`, `Software`, `Artist`, `DateTime`, `HostComputer`, `Copyright`, `ImageDescription`, `DocumentName` | The ordinary camera-and-scanner case, and that each is reported by name rather than as an opaque block |
| `unknown-vendor-tag.tiff` | Two private tags (`0xC5D9`, `0xFDE8`) no tag table knows | **The fixture that justifies the allow-list running in the direction it does.** Under a deny-list these survive precisely because nothing recognises them |
| `exif-and-gps.tiff` | An Exif IFD with `CameraOwnerName`, `BodySerialNumber`, `DateTimeOriginal`, `UserComment`; a GPS IFD with coordinates | That metadata reached through a pointer is found, and that a serial number one level down is reported |
| `packets.tiff` | XMP, IPTC, and an ICC profile carried as tag values | That three whole metadata containers go, including the ICC profile whose removal is a deliberate colour-fidelity trade |
| `reduced-resolution-thumbnail.tiff` | A second directory flagged `NewSubfileType = 1`, with its own artist and its own pixels | That the embedded second image is dropped, not merely stripped — it survives every crop and redaction applied to the first |
| `multi-page.tiff` | Three pages, each with its own `Artist` | The scanned-dossier case: every page survives and every page's metadata does not |
| `multi-strip.tiff` | Three strips, plus `Software` | The writer's out-of-line geometry path, and that strips keep their order |
| `palette.tiff` | A 48-entry `ColorMap`, plus `Artist` | The *other* direction of the allow-list's risk: a structural value wrongly dropped breaks the picture. Also the writer's out-of-line path for a kept tag |
| `big-endian.tiff` | `Artist`, in `MM` byte order | That every offset and length is read and written in the declared order, and that the output keeps it |

### Malformed

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/bigtiff.tiff` | Magic number 43, eight-byte offsets | Refused by name, not parsed as the TIFF it is not (ADR-0033) |
| `malformed/directory-cycle.tiff` | A directory whose "next" pointer is itself | Refused as a cyclic reference rather than walked forever |
| `malformed/strip-out-of-range.tiff` | A strip offset past the end of the file | Refused — the image data cannot be copied, so no output |
| `malformed/truncated-directory.tiff` | Ends part-way through the first directory | Refused rather than completed |
| `malformed/entry-count-lies.tiff` | A directory claiming 65535 entries | Refused; the count is not trusted against the bytes present |
| `malformed/no-dimensions.tiff` | No `ImageWidth` or `ImageLength` | Refused: a directory that cannot describe an image |

## GIF

Generated by `corpus/tools/make_gif_fixtures.py`, which carries **its own LZW encoder** so that
every fixture is a real, decodable GIF. That matters more here than the extra code costs: mat2's
GIF path re-renders the image through GdkPixbuf, so a fixture it cannot open makes the
differential comparison say nothing at all — the mistake the WebP comparison made for two days
(`docs/THREAT_MODEL.md` §7.4).

The pixel payload cannot carry a `PRESERVED-` marker the way TIFF's does, because it is
LZW-compressed. The "the picture crossed intact" claim is owned instead by
`crates/strypt-core/tests/gif.rs`, which walks the blocks with its own parser and compares them
byte for byte.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.gif` | Nothing identifying | That a clean file comes back **byte-identical** — a promise a block-list format can make and TIFF cannot |
| `comment.gif` | A comment extension | The ordinary case, and the one ExifTool files under `[File] Comment` rather than `[GIF]` |
| `long-comment.gif` | A 600-byte comment plus a second one | The sub-block chain walk, where a length field gets mishandled |
| `xmp.gif` | An XMP packet in the raw-plus-magic-trailer layout the XMP specification defines for GIF | That the packet is found and itemised by property, and that a walk lands on the trailer and terminates |
| `application-blocks.gif` | `ICCRGBG1012`, `MGK8BIM0000`, and `MGKIPTC0000` — what `ImageMagick` and Photoshop write | That whole ICC, 8BIM, and IPTC blocks go, and that the IPTC by-line is ranked as naming a person |
| `unknown-application.gif` | A vendor identifier no table knows | **The fixture that justifies the allow-list running in the direction it does.** Under a deny-list this survives precisely because nothing recognises it |
| `animated-loop.gif` | A `NETSCAPE2.0` loop count, three frames, three graphic control blocks, and a comment | That the animation still loops and keeps every frame, and that the loop block is declared as retained rather than kept silently |
| `animated-no-loop.gif` | Two frames and no loop block | That the handler keeps what was there rather than deciding an animation ought to loop |
| `transparency.gif` | A graphic control block with a transparent index and a 50-tick delay | That rendering instructions cross untouched — dropping them would change how the image looks |
| `plain-text.gif` | A plain-text extension with a graphic control block in front of it | That the pair is removed **together**: §23 makes that block apply to the next graphic, so leaving it would retime the following image |
| `interlaced-local-table.gif` | An interlaced image with its own local colour table | Two structural flags on a code path that is easy to skip past by accident |
| `unknown-extension.gif` | An extension under label `0x42`, which the format does not define | That a block nobody can name is removed rather than copied through |
| `trailing-data.gif` | Bytes after the trailer | That data nothing reads is removed, and reported |
| `gif87a.gif` | A comment, in a file spelling `GIF87a` | That the older signature is handled rather than refused on a version string no decoder enforces |

### Malformed

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/truncated-header.gif` | Ends inside the logical screen descriptor | Refused rather than guessed at |
| `malformed/no-trailer.gif` | The block sequence simply stops | Refused rather than completed — a repaired copy is not the file the user handed over |
| `malformed/sub-block-past-end.gif` | A sub-block claiming more bytes than the file holds | Refused, not clamped |
| `malformed/unterminated-sub-blocks.gif` | A chain whose terminating zero never arrives | Refused |
| `malformed/bad-introducer.gif` | A byte where only an extension, an image, or the trailer is permitted | Refused: the walk is no longer where it thinks it is |
| `malformed/colour-table-past-end.gif` | A global colour table the file is too short to contain | Refused |

---

## HEIF and AVIF

Generated by `corpus/tools/make_heif_fixtures.py`. It embeds **one recorded AV1 codestream and one
recorded HEVC codestream**, extracted once from a real encoder, and builds every container by hand
around them — so the tool is deterministic and needs no third-party library at generation time,
while every fixture is still a **real, decodable image** that libheif and ImageMagick both open.
The reasoning is §7.9's: mat2 re-renders these formats, and a comparison it cannot run says
nothing (`docs/THREAT_MODEL.md` §7.4).

`thumbnail.heic` carries its marker inside the thumbnail item's own bytes, and that is deliberate:
**no third-party tool on this machine enumerates a HEIF thumbnail item** — ExifTool does not report
it, `magick identify` shows one frame, and `heif-info` prints `thumbnail: 0x0` — so without a
marker there the differential would have no way to tell whether it survived.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.avif`, `clean.heic` | Nothing identifying | The baseline rebuild, one per codec. Output is **not** byte-identical — a rebuild reorders the file — but stripping it again is |
| `exif.avif`, `exif.heic` | An `Exif` item bound by a `cdsc` reference | The ordinary case, in both codecs: the block an iPhone photograph's GPS and serial numbers live in |
| `xmp.heic` | A `mime` item of type `application/rdf+xml` | XMP stored the way the HEIF specification says to store it |
| `exif-and-xmp.avif` | Both, with two `cdsc` references | That removing one item does not strand the other — the case the offset rebuild exists for |
| `uuid-xmp.heic` | A top-level `uuid` box with the XMP identifier | XMP stored the way Adobe actually stores it. **The fixture that justifies the allow-list's direction**: `uuid` is the format's official extension point |
| `thumbnail.heic` | A second coded image bound by a `thmb` reference | That the thumbnail goes and the picture stays. **The reference runs thumbnail → master**, and reading it backwards deletes the photograph |
| `icc-profile.avif` | A `colr` property of type `prof` | That the ICC profile goes, checked with ImageMagick because ExifTool reports no profile for these formats |
| `nclx-colour.avif` | A `colr` property of type `nclx` | That numeric colour signalling is **kept and declared as retained** — it names a colour space, not a device |
| `unknown-item.avif` | An item under a vendor type no table knows | That an unrecognised item cannot survive by going unrecognised |
| `unknown-property.heic` | A `udes` description and a vendor `XPRP` property | The same, one directory down, plus free text naming the image |
| `named-item.avif` | An `infe` with a non-empty `item_name` | That a structural field which cannot be dropped is written **empty** rather than copied |
| `idat-item.heic` | An item using `iloc` construction method 1 | That `idat` data is resolved and rewritten into `mdat` as method 0, so `idat` never appears in output |
| `meta-xml.avif` | An `xml ` box inside `meta` | A metadata box outside the `meta` allow-list |
| `free-space.avif` | `free` and `skip` boxes between `meta` and `mdat` | That padding boxes go, and that the offsets of everything after them are recomputed rather than carried |
| `trailing-data.heic` | Bytes after the last box | That data nothing reads is removed and reported. mat2 declines this file in both modes, because ExifTool refuses to write it |

### Malformed — every one must be refused

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/truncated.avif` | Ends inside `meta` | Refused rather than guessed at |
| `malformed/box-size-below-header.avif` | A box inside `meta` whose size is smaller than its own header | Refused — the non-termination case a walker must not loop on |
| `malformed/iloc-out-of-range.avif` | An item extent reaching past the end of the file | Refused, not clamped |
| `malformed/primary-is-metadata.avif` | `pitm` naming the Exif item instead of an image | Refused: the file does not have a picture where it claims to |
| `malformed/construction-method-2.heic` | `iloc` offsets expressed relative to another item | Refused by name — relocating it would mean resolving an item graph |
| `malformed/live-photo.heic` | A `moov` box | Refused **as a motion HEIF or Live Photo**, not as a malformed file. Video is Group 4 |
| `malformed/infe-version-1.avif` | An `infe` below version 2 | Refused rather than parsed under a layout that does not apply |
| `malformed/external-data-reference.avif` | A non-zero `data_reference_index` | Refused: the item's data is in another file, and no network or filesystem access is permitted to fetch it (ADR-0004) |

## SVG

Generated by `corpus/tools/make_svg_fixtures.py`. **Every fixture is a real, renderable SVG**, for
§7.9's reason turned up a notch: mat2's SVG path loads the document through Rsvg and re-renders it,
so a fixture Rsvg cannot open makes the comparison say nothing (`docs/THREAT_MODEL.md` §7.4).

Unlike every other corpus here, these carry a marker **in the drawing itself** —
`id="PRESERVED-SHAPE"` on a rectangle every fixture shares. SVG is the one format where the picture
is text, so "the payload crossed intact" is checkable by looking for a string. A marker spelled
`SYNTHETIC-…-KEPT-…` is one strypt deliberately does not remove and declares as retained.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.svg` | Nothing identifying | The baseline. Must come back **byte-identical** — deletion, not rebuild (ADR-0035 §1) |
| `metadata-rdf.svg` | RDF, Dublin Core and a Creative Commons licence in `<metadata>` | The element SVG 1.1 §5.10 says is not rendered. The creator is nested as `<dc:creator><cc:Agent><dc:title>`, so the leaf is called `title` and only its ancestor says it is a person |
| `inkscape.svg` | `sodipodi:docname`, `inkscape:version`, a `<sodipodi:namedview>` | The most common real dirty SVG there is: the file's name on the author's disk, and their window geometry and current layer |
| `illustrator.svg` | A generator comment, `<i:pgf>`, `<x:xmpmeta>` | `<i:pgf>` is a compressed copy of the original AI document hidden inside the export |
| `xmp-packet.svg` | An XMP packet in Adobe's `<?xpacket?>` wrapper, its fields in **attributes** | Two things the scanner used to step over: a processing instruction, and metadata that is not element text |
| `unknown-namespace.svg` | A vendor prefix no table knows | **The fixture that justifies the allow-list's direction**: under a deny-list this survives precisely because nothing recognises it |
| `embedded-image.svg`, `embedded-image-xlink.svg` | A PNG with a `tEXt` chunk in a `data:` URI | ADR-0029's one-level descent, through both `href` and `xlink:href`. The picture stays and its metadata goes |
| `accessibility-text.svg` | `<title>` and `<desc>`, marked `-KEPT-` | That both **survive and are declared as retained** (ADR-0035 §5). mat2 removes them |
| `external-references.svg` | A local path and a remote `url()`, one marked `-KEPT-`, plus `url(#internal)` | That an external reference is **kept and reported without its target ever being named**, and that a fragment is not treated as a leak |
| `stylesheet.svg` | A CSS comment, and `/* … */` inside a quoted string marked `-KEPT-` | That stylesheet comments go and the quoted false positive does not — cutting there would corrupt the rule around it |
| `doctype.svg` | A `PUBLIC` doctype and a comment | That the format's boilerplate stays and the comment goes |
| `comments.svg` | Comments before the root, in the body, inside `<metadata>`, and after the last element | That position is irrelevant to removal |
| `kitchen-sink.svg` | One of nearly everything | That the rules compose, and that an outer element's removal subsumes the attribute edits inside it |

### Malformed — every one must be refused

Five of these are refused on a **rule** rather than on damage, and mat2 accepts four of them: it
re-renders, which drops the script along with everything else. **mat2 is the better recommendation
for a scripted SVG**, and `docs/THREAT_MODEL.md` §7.11 says so.

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/script-element.svg` | A `<script>` that reads the document and calls out | Refused by name, not partly cleaned (ADR-0035 §2) |
| `malformed/event-handler.svg` | `onload` on the root | The same, via the attribute rule: SVG defines no attribute beginning `on` that is not a handler |
| `malformed/event-handler-nested.svg` | `onclick` on a child | That the rule is not scoped to the root element |
| `malformed/foreign-object.svg` | A `<foreignObject>` holding XHTML | Refused: its contents are another language strypt does not read |
| `malformed/javascript-href.svg` | `href="javascript:…"` | Refused — a script does not have to be in a `<script>` |
| `malformed/entity-subset.svg` | A doctype internal subset declaring an entity | Refused: an expansion vector, and removing it would leave `&who;` pointing at nothing (ADR-0035 §8). mat2 refuses it too |
| `malformed/data-uri-pdf.svg` | A PDF in a `data:` URI | Refused: a nested container carries metadata one pass cannot reach (ADR-0029) |
| `malformed/data-uri-svg.svg` | An SVG in a `data:` URI | The same, and what keeps the descent one level deep by construction |
| `malformed/utf16.svg` | A UTF-16 document | Refused rather than scanned as UTF-8, which would find no tags and report a clean file |

## JPEG XL

Generated by `corpus/tools/make_jxl_fixtures.py`.

**The codestream in these fixtures is a header, not a picture**, and that is a deliberate break
with every other image corpus here. The others carry decodable images because mat2 reaches those
formats through a decoder. mat2's `JXLParser` is an `ExiftoolParser` running
`_lightweight_cleanup()` — it reads the box layer and decodes nothing, and neither does strypt
(ADR-0036) — so the stub is a valid ISO/IEC 18181-1 §9.1 signature, `SizeHeader` and all-default
`ImageMetadata`, enough that ExifTool reports an 8x8 JXL, and nothing after it.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.jxl` | Nothing | The baseline. Must come back **byte-identical** — deletion, not rebuild (ADR-0036 §3) |
| `bare-codestream.jxl` | No box layer at all | The format's other spelling: **accepted, reported clean, returned unchanged**, with the codestream declared as not entered (ADR-0036 §2). mat2 refuses this file in both modes |
| `exif.jxl` | An `Exif` box: description, make, model, software, artist, timestamp | That the four-byte TIFF-header offset §5.3 puts at the front of the payload is stepped over — a scan that missed it would parse the wrong bytes and still look plausible |
| `xmp.jxl` | An `xml ` box holding an XMP packet | `dc:creator`, `xmp:CreatorTool` and `xmp:CreateDate`, broken down by property |
| `jumbf.jxl` | A `jumb` box: a C2PA manifest label and claim generator | **The fixture that shows the gap running the other way.** ExifTool reads this box and leaves it, so it survives mat2 and not strypt |
| `brotli-compressed.jxl` | A `brob` box naming `Exif` and holding bytes that are **not valid Brotli** | That the box is removed on its four-byte inner type alone, without anything inflating it (ADR-0036 §4). Its payload's invalidity is the point |
| `jpeg-reconstruction.jxl` | A `jbrd` box holding a JPEG `COM` and an `APP14` segment, beside an `Exif` box | That the original JPEG's marker segments go, and that the report declares what removing them costs (ADR-0036 §5) |
| `frame-index.jxl` | A `jxli` box | That an optional seek index into a file being edited is removed rather than trusted |
| `padding.jxl` | `free` and `skip` boxes carrying markers | Padding is ignorable by definition, which is what makes it a place to keep something |
| `level-and-partial-codestream.jxl` | A `jxll` level box, a codestream split across two `jxlp` boxes, an `Exif` box between them | That kept boxes are copied byte for byte and that removal from *between* two of them changes neither |
| `size-zero-final.jxl` | A final `jxlc` declaring size 0 — "runs to the end of the file" (§4.2) | That deletion preserves that meaning. A rebuild would have had to recompute it |
| `metadata-after-codestream.jxl` | `Exif` and `xml ` **after** the codestream | Where a tool that appended metadata to a finished file puts it |
| `kitchen-sink.jxl` | One of everything | That the rules compose, and that only `JXL `, `ftyp`, `jxll` and `jxlc` come out |

### Malformed — every one refused but the last

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/unknown-box.jxl` | A top-level `vndr` box | **The fixture that justifies the allow-list's direction**: under a deny-list this survives precisely because nothing recognises it (ADR-0036 §7) |
| `malformed/no-signature.jxl` | An `ftyp` with no signature box before it | Refused. It reaches detection as a bare ISO base-media file, which is what it is |
| `malformed/wrong-brand.jxl` | An `ftyp` branding the file `jpeg` | Refused rather than processed as the JPEG XL it claims not to be |
| `malformed/signature-wrong-length.jxl` | A signature box of 13 bytes | Refused at detection: §5.2 fixes the whole box, not just its type |
| `malformed/box-overruns-file.jxl` | A final box declaring more bytes than remain | **The one that matters most here.** Its remnant would otherwise be read as trailing junk and dropped, leaving a container with no codestream and a success message on it |
| `malformed/box-size-below-header.jxl` | A box declaring size 4 | The non-termination case: a walk that clamped rather than refused would loop on one offset forever |
| `malformed/trailing-data.jxl` | Bytes after the last box | Refused. JPEG XL has no terminator, so unlike GIF (§27) there is no defined place for them |
| `malformed/no-codestream.jxl` | A container holding only an `Exif` box | Refused: no codestream is no image |
| `malformed/exif-offset-past-end.jxl` | An `Exif` box whose TIFF-header offset points past its own payload | Reported as an Exif box and removed whole — a block that does not parse is still a block that is going |

## FLAC

Generated by `corpus/tools/make_flac_fixtures.py`.

**These are real, decodable FLAC files**, unlike the JPEG XL stubs above: mat2 reaches FLAC through
mutagen, which will not open a file whose frames do not parse, and a differential against a tool
that refused the input would prove nothing. The audio is one 4096-sample frame of digital silence —
a constant subframe with a correct CRC-8 header and CRC-16 footer (RFC 9639 §9) — and `STREAMINFO`'s
MD5 is the real MD5 of those samples.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.flac` | Nothing but zeroed padding | The baseline. Must come back **byte-identical** — block surgery, not rebuild (ADR-0038) |
| `vorbis-comment.flac` | Artist, album, date, comment, encoder, settings, MusicBrainz id, location, organisation | That the block is itemised field by field rather than reported as one blob |
| `cover-art.flac` | A `PICTURE` block holding a PNG that carries its **own** `tEXt` | That the picture goes whole, so nothing has to descend into it (ADR-0029 does not extend to this group) |
| `cuesheet.flac` | A `CUESHEET`: media catalogue number, one track's ISRC, the lead-out | That it is removed **and** that the report says the file can no longer be split into tracks |
| `seektable.flac` | A `SEEKTABLE` beside a Vorbis comment | **The fixture that proves the tranche's premise**: §8.5 measures a seek point from the first frame header, so removal moves no offset and the table survives untouched |
| `application.flac` | An `APPLICATION` block with a registered id | That it is removed and named by its id. ExifTool reports nothing for it, so only the marker sweep and the block walk see this one |
| `padding-with-data.flac` | `PADDING` holding a marker rather than zeros | That the block **keeps its length and loses its contents** (ADR-0038) |
| `reserved-block.flac` | A block of type 20 | **The fixture that justifies the allow-list's direction**: under a deny-list this survives precisely because nothing recognises it |
| `no-audio-md5.flac` | An all-zero `STREAMINFO` MD5, which §8.2 defines as "unknown" | That there is then no fingerprint to declare — the retained list is empty |
| `id3-prefixed.flac` | An ID3v2 tag glued in front of the stream marker | That it is read and removed rather than refused. Non-standard but common, and left in place it would sit in front of blocks strypt had cleaned (ADR-0040 lifts ADR-0038 decision 7) |
| `appended-tags.flac` | An ID3v2 tag in front **and** an ID3v1 tag past the last frame | That both ends are peeled. The trailing tag used to survive silently under the "the frames are not decoded" note |
| `kitchen-sink.flac` | One of everything, two pictures | That the rules compose, and that only `STREAMINFO`, `SEEKTABLE` and `PADDING` come out |

### Malformed — every one refused

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/wrong-marker.flac` | `fLaD` | Refused at detection |
| `malformed/no-streaminfo.flac` | A Vorbis comment as the first block | Refused: §8.2 makes `STREAMINFO` mandatory and first |
| `malformed/streaminfo-wrong-length.flac` | A `STREAMINFO` of 30 bytes | Refused: the block is a fixed 34 |
| `malformed/second-streaminfo.flac` | Two `STREAMINFO` blocks | Refused rather than one of them being picked |
| `malformed/forbidden-block-type.flac` | Type 127 | Refused. §8.1 forbids it so a block header can never look like a frame sync |
| `malformed/block-overruns-file.flac` | A block declaring more bytes than remain | Refused rather than clamped |
| `malformed/no-frame-sync.flac` | Blocks that end where no frame sync begins | **The one that matters most here.** A lying length that does not overrun would otherwise be accepted and the audio copied from the wrong offset |

## WAV

Generated by `corpus/tools/make_wav_fixtures.py`.

**These are real, playable WAV files** — 16-bit mono PCM at 8 kHz, a quarter-second of a 440 Hz
tone — because the differential drives mat2 and ffmpeg over them, and a comparison against a tool
that refused the input would prove nothing.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.wav` | `fmt ` and `data`, nothing else | The baseline. Must come back **byte-identical** — chunk surgery, not rebuild (ADR-0039) |
| `info-list.wav` | A `LIST`/`INFO` of eighteen tags: artist, engineer, technician, commissioner, copyright, archival location, dates, software | That the list is itemised tag by tag rather than reported as one blob |
| `adtl-list.wav` | A `LIST`/`adtl` of cue labels and notes | That an associated-data list goes with the rest, and that an unknown `LIST` form would too |
| `broadcast-extension.wav` | A `bext`: originator, originator reference, UMID, origination date and time, coding history | The richest identifying chunk in the format — the desk, the operator and every processing step |
| `cart.wav` | A `cart`: title, artist, cut and client ids, producer app and version, a URL | Fixed-offset field extraction across a 2 KB chunk |
| `ixml.wav` | An `iXML` document with device serial and scene/take | A field recorder's document, reported as device identity |
| `xmp.wav` | An `_PMX` chunk | That the shared XMP scanner is reached from this handler too |
| `id3.wav` | An `id3 ` chunk holding an ID3v2 tag | That it is **dropped unread** — no ID3 reader enters the tree before tranche 3 (ADR-0039) |
| `sampler.wav` | An `smpl` chunk with loop points | That it is removed **and** that the report says the file can no longer be looped by a sampler |
| `padding.wav` | A `JUNK` chunk holding a marker rather than zeros | That the chunk **keeps its length and loses its contents**, as FLAC's padding does |
| `cue-points.wav` | A `cue ` chunk beside `fmt ` and `data` | **The fixture that proves the tranche's premise**: `cue `'s offsets index the wave-list data section, not the file, so removal moves nothing and the chunk survives untouched — byte-identical output |
| `unknown-chunk.wav` | A private `PrVw` chunk | **The fixture that justifies the allow-list's direction**: under a deny-list this survives precisely because nothing recognises it |
| `trailing.wav` | Bytes past the declared RIFF extent | That they are dropped rather than copied along |
| `kitchen-sink.wav` | One of everything above | That the rules compose, and that only `fmt `, `data`, `cue ` and a zeroed `JUNK` come out |

### Malformed — every one refused

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/truncated.wav` | The file ends mid-`data` | Refused rather than partly cleaned |
| `malformed/riff-size-past-end.wav` | A RIFF size larger than the file | Refused rather than clamped to the file's length |
| `malformed/chunk-past-extent.wav` | A chunk length running past the RIFF extent | Refused. A lying length that was clamped would copy the wrong bytes |
| `malformed/non-ascii-code.wav` | A four-character code outside printable ASCII | Refused: a code that cannot be named cannot be reported |
| `malformed/no-data.wav` | No `data` chunk | Refused: there is no audio to preserve |
| `malformed/no-fmt.wav` | No `fmt ` chunk | Refused: nothing describes the audio |
| `malformed/short-fmt.wav` | A `fmt ` of 12 bytes | Refused: the chunk is at least 16 |
| `malformed/wave-list.wav` | A `LIST`/`wavl` in place of `data` | Refused **by name**. There the `cue ` offsets index a structure the handler would be editing — the shape ADR-0034 found in HEIF |
| `malformed/rf64.wav` | An `RF64` header | Refused **by name**, not treated as a large WAV: its real sizes live in a `ds64` chunk and the RIFF fields hold a `-1` placeholder |
| `malformed/avi.wav` | A RIFF of form `AVI ` | Refused **by name** as another RIFF form, so the message is useful rather than "unrecognised" |

## MP3

Generated by `corpus/tools/make_mp3_fixtures.py`.

**These are real, playable MP3 files**: mat2 reaches MP3 through mutagen and ExifTool reads the
frame header directly, and a differential against a tool that refused the input would prove nothing.
The audio is four MPEG-1 Layer III frames at 128 kbps, 44.1 kHz mono — 417 bytes each — whose main
data is zeroed, which decodes as silence.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.mp3` | Frames and nothing else | The baseline. Must come back **byte-identical** — deletion at the ends, never a rewrite (ADR-0040) |
| `id3v2-4.mp3` | An ID3v2.4 tag of thirteen frames: artist, composer, tagger, encoder, four timestamps, copyright, ISRC, comment, user text, location | That the tag is itemised frame by frame and ranked, rather than reported as one blob |
| `id3v2-3.mp3` | ID3v2.3, whose frame sizes are plain integers and whose dates are split across `TYER`/`TDAT`/`TIME` | That the size encoding is read per version rather than guessed |
| `id3v2-2.mp3` | ID3v2.2, whose frame identifiers are three characters | That the older spelling is itemised too |
| `unsynchronised.mp3` | A v2.3 tag with §6.1's unsynchronisation flag set and an `FF 00` escape in a value | That the escape is undone before frame sizes are read — a reader that skips the step lands nowhere |
| `extended-header.mp3` | §3.2's extended header | That the frames are found past it |
| `footer.mp3` | §3.1's footer, ten bytes the size field does not count | That the span reaches to the end of the footer |
| `stacked-tags.mp3` | Two ID3v2 tags, one in front of the other | That both are peeled. Taggers really do this |
| `id3v1.mp3` | A 128-byte `TAG` block at the very end | That the tail is walked at all |
| `id3v1-extended.mp3` | A 227-byte `TAG+` block in front of the `TAG` block | **The fixture that shows the differential's direction**: mat2 0.15.0 deletes the `TAG` block and leaves `TAG+` behind |
| `ape.mp3` | An APEv2 tag with header and footer: artist, tool, comment, ISRC | That free-form items are itemised by key |
| `ape-no-header.mp3` | The same tag with only a footer | That the flag at bit 31 is what decides the span, not an assumption |
| `lyrics3v2.mp3` | `LYRICSBEGIN`, a `LYR` field, six size digits, `LYRICS200` | **The clearest gap in the differential**: a Lyrics3 tag alone on a file survives mat2 and does not survive strypt |
| `lyrics3v1.mp3` | The sizeless v1 spelling | That it is found by a bounded backwards search rather than a size field |
| `cover-art.mp3` | An `APIC` frame holding a PNG signature | That the picture goes whole, carrying whatever its own container holds |
| `embedded-object.mp3` | A `GEOB` frame: any file at all under a name the tagger chose | That an arbitrary payload is removed unread |
| `private-frame.mp3` | A `PRIV` frame with an owner identifier | That a vendor's private frame is removed and ranked as an identifier |
| `unknown-frame.mp3` | A `ZZZZ` frame | **The fixture that shows the frame table is a ranking and never a filter**: it goes either way, and it is still reported |
| `vbr-xing.mp3` | A `Xing` header frame with a `LAME3.100` extension | **The declared keep**: a real frame inside the encoded stream, kept because removal would break VBR seeking, and named in the report |
| `vbr-info.mp3` | The `Info` spelling, which a CBR encoder writes | The same, under the other marker |
| `vbr-vbri.mp3` | Fraunhofer's `VBRI`, at a fixed offset rather than behind the side information | That the third spelling is found at its own offset |
| `leading-padding.mp3` | 512 zero bytes between the tag and the first frame | That they are dropped **and** that the report accounts for the size change |
| `kitchen-sink.mp3` | A tag of everything above, a `Xing` frame, then Lyrics3, APE and `TAG+`/ID3v1 | That the rules compose, and that only the frames come out |

### Malformed — every one refused

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/truncated.mp3` | The file ends inside the ID3v2 tag | Refused rather than partly cleaned |
| `malformed/tag-size-past-end.mp3` | A tag size larger than the file | Refused rather than clamped: that number is the boundary between metadata and audio |
| `malformed/non-syncsafe-size.mp3` | A high bit set in the size field | Refused: §6.2 makes it syncsafe, so the writer's length is not this reader's |
| `malformed/unknown-major-version.mp3` | ID3v2.5 | Refused: §3.1 promises a later version keeps the header but not the body |
| `malformed/ape-header-missing.mp3` | An APE footer whose flag claims a header that is not there | Refused: the file lied about where the audio ends |
| `malformed/tail-tag-below-floor.mp3` | An APE size reaching below the head tags | **The fail-closed worst case**: without the floor this strips to nothing and reports success |
| `malformed/no-audio.mp3` | Tags and no frames | Refused for the same reason |
| `malformed/hidden-before-audio.mp3` | Arbitrary bytes between the tag and the first frame | Refused: that is exactly where something would be hidden from a tool that skipped ahead to the first sync |
| `malformed/layer-two.mp3` | MPEG-1 Layer II | Refused **by name** as MPEG audio that is not Layer III, not as "unrecognised" |
| `malformed/reserved-version.mp3` | `01` in the version field | Refused: where the audio begins would be a guess |
| `malformed/forbidden-bitrate.mp3` | `1111` in the bitrate index | Refused for the same reason |

## MP4 and M4A

Generated by `corpus/tools/make_mp4_fixtures.py`.

**These are real, decodable files**: mat2 reaches MP4 through ffmpeg and the differential decodes
with ffmpeg, so a fixture no decoder accepts would prove nothing. A codec configuration is not
something to hand-write, so one 0.4 s H.264 video (16x16, black) and one 0.2 s AAC recording
(440 Hz, mono) were produced once with **ffmpeg 9.0.1** — `-fflags +bitexact -map_metadata -1` — and
are embedded as base64. Every box, every offset and every marker around them is the generator's own
work, and its `clean.mp4` / `clean.m4a` baselines are derived here rather than from strypt's output:
a fixture compared against the tool's own answer proves nothing (`docs/TESTING_STRATEGY.md` §2.2).

ffmpeg's own layout is what the fixtures inherit — `ftyp`, `free`, `mdat`, then `moov` — so dropping
the leading `free` moves the media by eight bytes and every fixture exercises the relocation table.

| Fixture | Carries | Tests |
|---|---|---|
| `clean.mp4` | Nothing removable | The baseline, and a **fixed point**: it strips to itself byte for byte |
| `clean.m4a` | Nothing removable | The audio baseline, same property |
| `video-tags.mp4` | `moov/udta` with a GPS coordinate, title, date, encoder, make and model, plus a handler name and an encoder name in the sample entry | That the atoms every phone writes are itemised and ranked, and that `compressorname` goes |
| `itunes-tags.m4a` | `moov/udta/meta/ilst` with title, artist, encoder, comment, cover art, and a `----` mean/name/data triple | That the other place the same material lives is itemised too, and that cover art goes unread |
| `xmp-uuid.mp4` | A top-level `uuid` box with XMP's fixed extended type, carrying `dc:creator` and `xmp:CreatorTool` | That the packet is scanned before it goes, so the report names what went |
| `free-space.mp4` | A `free` after `ftyp` and a `skip` later, both with something in them | That free space is where a producer parks a deleted atom, and that removing two of them relocates correctly |
| `faststart.mp4` | `moov` in front of `mdat`, with a title | The streaming layout, where removing anything really does move the media |
| `sixty-four-bit-mdat.mp4` | A `mdat` using §4.2's 64-bit size escape | That the header form survives the copy — rewriting it short would move the payload without moving the offsets |
| `timestamps.mp4` | Real dates in `mvhd`, `tkhd` and `mdhd`, a language of `eng`, and a populated `pre_defined` block | The four fields edited in place rather than removed |
| `unknown-boxes.mp4` | Microsoft's `Xtra` under `trak` and an `iods` under `moov` | The drop-and-report path, reached by a box on no list and with no named rule |

### Malformed — every one refused

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/fragmented.mp4` | A `moof` box | Refused **by name**: sample offsets live in track fragment runs strypt does not rewrite |
| `malformed/movie-extends.mp4` | A `mvex` inside `moov`, which declares fragments to follow | Refused by name for the same reason |
| `malformed/fragmented-brand.mp4` | A `dash` brand and no fragment box | Refused by name: the brand is the claim, and a file making it is not one to partly clean |
| `malformed/encrypted-sample-entry.mp4` | An `encv` sample entry | Refused by name: the samples are ciphertext |
| `malformed/protection-system.mp4` | A `pssh` box | Refused by name |
| `malformed/protected.m4a` | The `M4P ` brand | Refused by name |
| `malformed/chunk-offset-into-free.mp4` | A chunk offset pointing into a `free` box that is about to be deleted | **The fail-closed offset case**: refused rather than nudged by a delta nobody verified |
| `malformed/chunk-offset-past-end.mp4` | A chunk offset past the end of the file | Refused for the same reason |
| `malformed/external-data-reference.mp4` | A `dref` entry with §8.7.2's self-contained flag clear | Refused: the samples are in another file, so the `mdat` strypt relocates into is not where they are |
| `malformed/no-movie-box.mp4` | No `moov` | Refused: a file with no index |
| `malformed/two-movie-boxes.mp4` | Two `moov` boxes | Refused: which one a player picks is not a guess to make on a user's behalf |
| `malformed/no-track.mp4` | A `moov` with no `trak` | Refused: it would otherwise strip to a file nobody can play, reported as a success |
| `malformed/truncated.mp4` | A box declaring more bytes than the file has | Refused rather than partly cleaned |
| `malformed/quicktime.mov` | The `qt  ` brand | Refused by name: a different vocabulary sharing the same box grammar |
| `malformed/three-gpp.mp4` | The `3gp4` brand | Refused by name |

---

## Ogg

Generated by `corpus/tools/make_ogg_fixtures.py`.

**These are real, decodable Ogg files**: mat2 reaches Ogg through mutagen and the differential
decodes with ffmpeg, so a fixture no decoder accepts would prove nothing. A Vorbis setup header is a
codebook table nobody can hand-write, so the identification, setup and audio packets were produced
once with ffmpeg 9.0.1 and are embedded as base64 — the pagination, the CRCs and every comment are
the generator's own work. The Ogg-FLAC `STREAMINFO` carries a synthetic non-zero audio MD5, because
ffmpeg leaves that field zero when it writes the header into a non-seekable stream and RFC 9639 §8.2
spells zero as "unknown" — with it left zero, no fixture exercises the declared retention.

| Fixture | Carries | Tests |
|---|---|---|
| `clean-vorbis.ogg` | An empty comment header and nothing else | The baseline. **Not** byte-identical after a strip: the serial number is rewritten (ADR-0041), which is what makes this handler unlike FLAC's, WAV's and MP3's |
| `vorbis.ogg` | Twelve comments — artist, album artist, title, date, location, encoded-by, encoder, MusicBrainz and ISRC identifiers, a comment, copyright, replay gain — behind the vendor string | That the comment header is itemised field by field and ranked |
| `vorbis-cover-art.ogg` | A `METADATA_BLOCK_PICTURE` comment large enough to run past one page's lacing table | That cover art goes whole, and **that a packet spanning pages is reassembled and re-emitted** |
| `vorbis-many-comments.ogg` | 400 comments under keys nothing recognises | That an unknown key is removed unread, and that the itemisation ceiling holds |
| `clean-opus.opus` | An empty `OpusTags` packet | The Opus baseline, whose header count is two rather than Vorbis's three |
| `opus.opus` | Six comments behind `libopus`'s vendor string, one of them a GPS fix | That the Opus mapping is itemised the same way |
| `opus-padding.opus` | RFC 7845 §5.2 padding after the comment list, with something in it | That the padding a tagger can hide in goes with the packet |
| `clean-ogg-flac.oga` | The `\x7fFLAC` mapping, an empty comment block, and audio | The Ogg-FLAC baseline, whose headers are FLAC metadata blocks one to a packet |
| `ogg-flac.oga` | The same twelve comments, in a FLAC `VORBIS_COMMENT` block | That the shared comment reader is reached through the other mapping too |
| `ogg-flac-blocks.oga` | Every block type at once: comment, picture, padding with something in it, an `APPLICATION` block, a cuesheet with a catalogue number, a seek table, and reserved type 42 | That removed blocks become zero-length padding so the declared header count holds, that the **seek table survives**, and that the **audio MD5 is kept and declared** |

### Malformed — every one refused

| Fixture | Defect | Expected |
|---|---|---|
| `malformed/truncated.ogg` | The file ends mid-stream | Refused rather than partly cleaned |
| `malformed/bad-crc.ogg` | A page whose declared CRC does not match its bytes | Refused: the CRC is the evidence the walk is on a real header, and every decoder drops the page anyway |
| `malformed/unknown-page-version.ogg` | A page version RFC 3533 does not define | Refused: a later version's header layout is not this reader's |
| `malformed/theora.ogv` | An Ogg carrying Theora video | Refused **by name**, not as "unrecognised" |
| `malformed/speex.spx` | An Ogg carrying Speex | Refused by name |
| `malformed/skeleton.ogg` | A Skeleton (`fishead`) stream | Refused by name |
| `malformed/multiplexed.ogg` | Two logical bitstreams side by side, which is what an `.ogv` really is | Refused rather than half-cleaned: the second stream has a comment header this handler never read |
| `malformed/chained.ogg` | Two complete streams one after the other | Refused for the same reason |
| `malformed/leading-bytes.ogg` | Bytes before the first page | Refused: that is where something would be hidden from a walk that scanned for the first `OggS` |
| `malformed/trailing-bytes.ogg` | Bytes after the last page | Refused for the same reason |
| `malformed/no-comment-header.ogg` | A second packet that is not the comment header the mapping requires | Refused: the packet strypt would have emptied is not there |
| `malformed/headers-only.ogg` | Headers and no audio packets | Refused: it would otherwise strip to a file with no payload, reported as a success |
| `malformed/granule-on-carrier-page.ogg` | A page that finishes no packet, carrying a granule position other than −1 | **The fail-closed timing case**: a real granule there is a timestamp for nothing, and carrying it forward would move a timing |
| `malformed/flac-block-overrun.oga` | An Ogg-FLAC metadata block that does not fill its packet | Refused: the bytes behind it are exactly where something would hide |
| `malformed/flac-header-count-mismatch.oga` | A mapping header whose declared count disagrees with the last-block flag | Refused: which packet the audio starts at would be a guess |
