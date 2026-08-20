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
| `negative-zero-real.pdf` | A `/UserUnit` and a `/CropBox` holding negative zero — a valid document, which is why it is not under `malformed/` | **A regression test for a real bug.** lopdf wrote `Real(-0.0)` as `-0`, which re-parsed as `Integer(0)` and wrote as `0`, so one strip differed from two. Both a bare value and one nested in an array are covered, on reachable page keys so pruning cannot quietly remove them before the handler walks them |
| `malformed/xref-19-byte-entries.pdf` | A correct document whose xref entries are 19 bytes, not the 20 ISO 32000-1 §7.5.4 requires — the padding space before each newline is dropped | That strypt refuses it as a *typed* `Malformed` error rather than panicking or reporting success on a file it never processed. A known capability gap: qpdf and mat2 both accept these bytes (`docs/THREAT_MODEL.md` §7.5) |
| `malformed/stream-length-mismatch.pdf` | A content stream declaring `/Length 45.` — a malformed real where §7.3.8.2 requires an integer. lopdf parses the document without error but stores empty stream content | **A regression test for a real bug.** strypt used to rewrite this and report a clean copy while silently discarding the page's content and emitting a PDF qpdf calls corrupt. Now refused |

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
