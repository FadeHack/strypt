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

### Not yet represented

Recorded so the gaps are visible rather than forgotten. These need real-world producers and
are the corpus's main weakness today:

- Files from actual producers: LaTeX, Word, Acrobat, LibreOffice, scanners, browser
  print-to-PDF. The fixtures above are synthetic, so they test strypt against the
  specification rather than against what real software emits — and real software is where the
  quirks live.
- Linearised ("fast web view") files.
- Object streams and cross-reference streams (PDF 1.5+), which most modern producers emit and
  which none of the fixtures above use.
- Encrypted documents. Refused by design (`crates/strypt-core/src/formats/pdf.rs`), but the
  refusal is not yet covered by a fixture.

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

## PNG, WebP

Not yet present — those handlers have not landed.
