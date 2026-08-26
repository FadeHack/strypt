# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog 2.0.0](https://keepachangelog.com/en/2.0.0/) (released
2026-06-07; verified 2026-08-19), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Project-specific conventions:**

- Security fixes go under `Security` and **must state which versions and formats were
  affected**, so users can determine whether files they already published need re-checking.
  For a metadata-removal tool this is the primary purpose of the entry — see
  [`SECURITY.md`](SECURITY.md).
- Any change to what a format handler removes goes under `Changed` or `Fixed`, never buried
  in a refactor entry. Users make publication decisions based on this.
- Entries are written for users, not for maintainers. "Fixed EXIF thumbnail surviving in
  progressive JPEGs" — not "refactor jpeg.rs".

## [Unreleased]

### Added

- **TIFF support — `.tif`, `.tiff`, including the multi-page files scanners produce.** `strypt
  show` and `strypt strip` now process TIFF images. This is the first tranche of Phase 2's third
  format group (ADR-0032, ADR-0033).

  **This format is handled differently from every other image, and the difference is worth
  understanding before relying on it.** A JPEG or PNG keeps its metadata in a delimited block
  strypt can drop whole. A TIFF does not: its metadata sits in the same directory as the tags
  needed to decode the picture, and everything in the file is addressed by absolute offsets. So
  strypt does not edit a TIFF — it **writes a new one**, copying the image data across untouched
  and writing only the tags an image cannot be decoded without.

  What comes out: the camera or scanner's make and model, the software that wrote the file, the
  artist, copyright, description, document and page names, the date and time, the host computer's
  name, the GPS coordinates and the camera owner's name and body serial number in the Exif and
  GPS directories, and the XMP, IPTC, and ICC profile packets — the last of which routinely names
  a device. **Embedded thumbnails go entirely**: a reduced-resolution copy of the image is a
  complete second picture that survives any crop or redaction applied to the first.

  **A private tag strypt has never seen does not survive by being unrecognised.** Tags are
  written from a list of what the image needs, so anything else — a vendor maker note, a
  scanner's proprietary field holding a serial number — is absent from the output because it was
  never written.

  **The pixels are bit-identical.** Strips and tiles are moved, never decoded and never
  recompressed.

  **Three limitations to read before relying on this.** The output is **never byte-identical to
  the input**, even for a file that carried no metadata, because a rebuild reorders the file;
  stripping an already-stripped file *is* byte-identical. Metadata concealed inside the
  compressed image data is out of reach — **mat2's default TIFF path re-renders the image and
  does reach that, so where that is your concern mat2 is the better tool**, at the cost of
  rewriting your pixels. And a file using a feature strypt cannot reproduce faithfully is
  refused rather than approximated: BigTIFF, an inconsistent strip geometry, or a directory
  without dimensions.

  Checked against **mat2 0.15.0 and ExifTool 13.55**: nothing survives strypt that does not also
  survive mat2, across all ten fixtures.

- **The TIFF and detection parsers survived 24 CPU-hours of hostile input.** Twelve hours each,
  in parallel, on 2026-08-26: **zero crashes, zero hangs, zero out-of-memory failures**. The TIFF
  parser alone was fed **1.4 billion** malformed inputs and the detector 3.0 billion. Detection
  was included because it changed in the same work — it now routes TIFF to a handler and refuses
  BigTIFF by name.

- **OpenDocument support — `.odt`, `.ods`, and `.odp`.** `strypt show` and `strypt strip` now
  process LibreOffice and OpenOffice text documents, spreadsheets, and presentations. This is the
  second format group of Phase 2 (ADR-0027, ADR-0031).

  What comes out: `meta.xml` entire — the initial creator and the last person to save the
  document, the creation, modification and print dates, who printed it, the **editing-cycle count
  and the total editing duration** (an ISO 8601 duration recorded to the second, which with the
  dates beside it says when somebody sat down, how long they worked, and when they stopped), the
  generator string (which names the operating system, not just the application), the page and
  word statistics, arbitrary user-defined properties, and a template reference that frequently
  points at a file under the author's home directory. Also `settings.xml` entire — which holds
  the **printer's name and its setup blob**, the last cursor position, and a set of configuration
  keys that fingerprints the producing build; the page thumbnail; the producer's saved
  user-interface configuration and layout cache; the author names and dates on comments and
  tracked changes; the cached author-name fields printed inside the document; and per-part ZIP
  timestamps and host fields.

  **Photographs inside a document are stripped too**, by the same JPEG, PNG, and WebP handlers a
  loose file goes through — one level deep, images only (ADR-0029). **An embedded chart's own
  metadata is removed as well**, without any recursion: OpenDocument stores an embedded object as
  ordinary entries in the same package, so its author and printer details are reachable in the
  same pass.

  Refused rather than half-processed: a package with no manifest, a package whose manifest
  declares encryption — which ZIP's own encryption flag does not reveal, so this refusal is what
  stops an encrypted document being reported clean — a package that gives two different answers
  about what it is, and a package containing a nested archive, an embedded PDF, or an OLE object.

  **One limitation to read before relying on this.** The *text* of comments and tracked changes
  is kept and reported, with only its attribution removed; **for a document whose comments must
  not be published, mat2 removes them outright and is the better tool.**

- **A new refusal for OpenDocument types outside this group** — drawings, formulas, charts,
  databases, and the `-template` variants — named specifically rather than reported as a generic
  ZIP container, so the message says the file was understood and declined rather than not
  recognised.

- **Office Open XML support — `.docx`, `.xlsx`, and `.pptx`.** `strypt show` and `strypt strip`
  now process Word documents, Excel workbooks, and PowerPoint presentations. This is the first
  format group of Phase 2, which opened on 2026-08-23 (ADR-0027).

  What comes out: the core, extended, and custom properties parts (author, last-modified-by,
  company, manager, cumulative editing time, revision count, and any custom property a document
  management system left behind); the package thumbnail, which is a rendered preview of the
  first page and survives every redaction applied to the text; revision-save identifiers
  (`w:rsid*` and the `w:rsids` table), which link two documents edited in the same session on
  the same machine; per-paragraph identifiers (`w14:paraId`, `w14:textId`), which are stable
  across copies; the author names, initials, and dates on comments and tracked changes; per-part
  ZIP timestamps and host fields such as Unix UID/GID; and external relationships whose target is
  a local or network path, such as an attached template under someone's home directory.

  **Photographs inside a document are stripped too**, by the same JPEG, PNG, and WebP handlers a
  loose file goes through — one level deep, images only (ADR-0029). A geotagged photo pasted into
  a report is the leak most likely to reach publication, because nothing in the document's own
  properties hints that it is there.

- **A new refusal for macro-enabled documents** (`.docm`, `.xlsm`, `.pptm`), named specifically
  rather than reported as a generic ZIP. Their `vbaProject.bin` is a container strypt cannot
  read, and a document reported clean while part of it went unexamined is the outcome this tool
  must never produce.

- **Stripped OpenDocument files are now verified to still open in LibreOffice.** A new check,
  `scripts/odf-libreoffice-validation.sh`, strips each document, loads it with LibreOffice, and
  compares the document body before and after — so a file that opens but quietly lost content
  fails as loudly as one that will not open at all. Run against **LibreOffice 26.2.5.2**: all 14
  fixtures and 2 real LibreOffice-authored documents pass.

  This closes a gap that was recorded rather than hidden: until now nothing strypt produced for
  this format had ever been opened in the application that writes it. Seven of the stripped files
  were also opened by hand in the LibreOffice interface, and **none prompted to repair the
  file** — a separate check, because that dialog is a GUI prompt no automated import can trigger.

- **The OpenDocument, ZIP, Office and PDF parsers survived 48 CPU-hours of hostile input.**
  Twelve hours each, in parallel, on 2026-08-25: **zero crashes, zero hangs, zero out-of-memory
  failures**. The OpenDocument parser alone was fed 382 million malformed inputs. PDF was
  included because its two most recent fixes had had only a short run.

  Malformed input is expected input for this tool — a file that crashes the stripper is a file
  the user may then publish uncleaned. What this does *not* mean: three of the four parsers were
  still reaching new code at the twelve-hour mark, so longer runs remain worthwhile and the
  project's own hardening target (Phase 3) is not met.

### Fixed

- **A PDF that cannot be rewritten faithfully is now refused instead of written.** For some
  damaged documents the rewrite produced a file that did not read back as what was written: an
  object whose keys came from mangled bytes was written in a form the parser could not read
  again, so it disappeared when the file was reopened. Where that object was the document's only
  page, strypt wrote a file whose page tree pointed at an object that was no longer there — and
  reported success. Stripping that output again produced a further truncated file with a
  dangling page reference, reporting success a second time.

  strypt now reads its own output back before returning it and refuses the file if the document
  did not survive the round trip, so nothing is written and the refusal says so. **No metadata
  survived either write** — the failure was structural damage reported as success, not a leak —
  but a user acts on a success report by publishing, which is why this is treated as the more
  serious of the two PDF fixes in this release. Found by the PDF fuzz target; regression test
  and fixture committed.

- **A PDF whose page tree refers to itself no longer strips to different bytes on the second
  pass.** Stripping such a document once and stripping it twice produced two files of the same
  length and content whose object numbering differed — objects 2 and 3 traded identities.
  Nothing was left unstripped and no metadata survived either pass, so this was a reproducibility
  failure rather than a leak, but a user who strips a file twice must get the same file. The
  renumbering step now runs until the numbering stops changing before anything is written, and a
  document that will not settle is refused instead of written. Found by the PDF fuzz target;
  regression test and fixture committed.

### Changed

- **The sustained fuzzing runner knows about `tiff`.** `scripts/fuzz-sustained.sh` had the same
  gap for the TIFF target that it had for `ooxml` and `zip` below — it rejected the name as
  unknown, so the new parser could not have been included in a sustained run at all. It is now
  in the default set, with its malformed seed directory wired up the way WebP's is. **Any run
  recorded before 2026-08-25 covered eight targets regardless of how it was invoked.**

- **The sustained fuzzing runner covers all seven targets.** `scripts/fuzz-sustained.sh` knew
  only the five Phase 1 targets and rejected `ooxml` and `zip` as unknown, so the two parsers
  added by Phase 2's first format group could not be included in a sustained run at all. They
  are now in the default set. Any run recorded before 2026-08-23 covered five targets regardless
  of how it was invoked.
- **A live status viewer for a run in progress**, `scripts/fuzz-status.sh`. The runner prints
  nothing until every target finishes, which makes a twelve-hour run indistinguishable from a
  hung one. The viewer reads the per-target logs and refreshes a coverage and crash table. It
  decides nothing — the run's own `summary.md` and exit code remain what answer the exit
  criterion.
- **What `strypt show` reports for a document is broken down per part**, so a finding reads
  `word/media/image2.jpeg → APP1 (Exif) GPS IFD /GPSLatitude` rather than being attributed to
  the document as a whole.

### Known limitations (new)

- **The text of comments and tracked changes is not removed** — only their author names,
  initials, and dates. Removing a tracked insertion means deciding whether the document accepts
  or rejects it, which changes what the document says. A note in the report says the content is
  still there. **If the comments themselves must not be published, use mat2**, which removes
  those parts outright.
- **A document containing a nested archive, an embedded PDF, or an OLE object is refused**
  rather than partly cleaned. This includes the cached workbook Word embeds behind a chart, which
  is common in real documents. The refusal is deliberate: that workbook carries its own author
  names, and strypt does not descend a second level.
- **A stripped document is not byte-identical to a clean input**, because a rewritten part is
  stored rather than re-compressed and entry timestamps are normalised. Stripping an
  already-stripped document *is* byte-identical.
- **A damaged Office document is reported as an unsupported ZIP container**, not as a damaged
  document, because identifying it requires reading a part that a damaged package may not have.

### Added

- **strypt is installable: `cargo install strypt`.** `strypt` and `strypt-core` are published
  to crates.io at `0.0.1`, ahead of the Phase 4 work they belong to, so the names are held by
  this project rather than by whoever registers them first. Names are not reservable on
  crates.io and a stub crate that only holds one violates its policy, so the crates carry the
  real code.

  **This is not a release.** `0.0.1` means what it says: Phase 3 hardening has not happened,
  there has been no external audit, and the limits in the README apply unchanged. What changed
  is that the install path stopped being hypothetical — for anything that matters, mat2 and
  ExifTool remain the right recommendation.

### Changed

- **The CLI crate is now `strypt`, renamed from `strypt-cli` (ADR-0026).** The binary was
  always called `strypt`, so `cargo install strypt` is the command people will type — and
  leaving that name unregistered meant the most guessable install path for a metadata-removal
  tool could later resolve to a stranger's code under the name this project's own
  documentation prints. The built binary is unchanged.

  `strypt-cli` `0.0.1` is published and **yanked**. Yanking keeps the name registered here, so
  it cannot be used to impersonate the tool, while stopping anyone installing a version that
  will never be updated. If you installed `strypt-cli`, replace it with `strypt`; it is the
  same program.

- **The WebP comparison against mat2 now runs, and passes.** It had been recorded since
  2026-08-19 as *not run* rather than as a pass — mat2 reaches WebP through GdkPixbuf, and
  without a WebP pixbuf loader it failed on the original files too, so the comparison said
  nothing about strypt. With the loader installed, `scripts/webp-differential.sh` finds no tag
  that mat2 removes surviving in strypt's output, across the 14 synthetic fixtures and 30 files
  from real producers. The script refuses to run when the loader is missing, because a sweep
  both tools failed identically looks like evidence and is not.

  It also records two differences that are **not** faults in either tool. mat2 decodes and
  re-encodes, so it returns an animated WebP as a single still frame; strypt keeps every frame.
  The reverse of that trade is that re-encoding removes the encoder's fingerprint, which strypt
  deliberately leaves alone. If you need the fingerprint gone more than you need the animation,
  mat2 is the better tool for that file.

- **Two WebP coverage gaps closed.** The corpus had nothing testing metadata that survives a
  change of file format, and nothing written by an actual browser. Both now exist: a
  JPEG→WebP conversion carrying real Canon Exif across — **including the embedded thumbnail,
  which is a small copy of the original photograph** — and a WebP encoded by Chrome's own
  encoder. strypt strips both clean; the conversion file goes from 92 readable tags to none.

- **Measured performance numbers in `docs/PRD.md` §9, replacing estimates.** Startup is 2.5 ms,
  a 3.3 MB JPEG strips in 10.9 ms, and a 3000-file batch peaks at 3.0 MB of memory against
  2.4 MB for 200 files — fifteen times the work for 0.6 MB more, so memory tracks the largest
  single file rather than the batch. `scripts/measure-performance.sh` reproduces them, and
  refuses to run against a debug binary. One machine only; Linux and Windows are unmeasured,
  and none of it is a commitment.

- **A sustained-fuzzing runner, `scripts/fuzz-sustained.sh`.** The fuzzing commands documented
  until now were 300-second smoke tests — enough to prove a target still runs, not enough to
  stand behind. The runner runs any set of targets in parallel for a chosen duration and
  records, per target, a coverage curve against elapsed time, whether coverage had stopped
  climbing by the end of the run, and any crash artefact. It exits non-zero if a target
  crashed. This is measurement infrastructure for a release criterion, not a new tool feature:
  the curves are what will replace ADR-0014's provisional 100-CPU-hours-per-handler figure,
  which was written before any parser existed and which that ADR already flags as a hypothesis
  to revise against real data.

  Its run summary now reports CPU-hours **budgeted** and CPU-hours **delivered** separately.
  The two differ whenever a target stops early on a crash: the first 8-hour five-target run
  was budgeted 40.00 CPU-hours but delivered 37.79, because the PDF target stopped at 5h47m on
  a genuine finding. Since ADR-0014 states its exit criterion in CPU-hours, reporting the
  budget as though it were delivered would credit a run with time it never spent — and the
  number is going to be read later, by someone deciding whether a release criterion was met.

- **`strypt show` and `strypt strip` now work on JPEG images.** They report and remove Exif
  — including GPS coordinates, camera make and model, body and lens serial numbers, the
  maker note, timestamps, and the embedded thumbnail — along with XMP packets, Photoshop and
  IPTC blocks, ICC colour profiles, the multi-picture and FlashPix segments, vendor blocks in
  `APP12`, comments, and any data hidden after the file's end-of-image marker. Exif is
  reported **tag by tag**, so you can see that it was `GPSLatitude` and `BodySerialNumber`
  that came out, not just that "an Exif block" did.
- **Your photograph is not re-encoded.** strypt edits the file's metadata segments and copies
  the image data through byte for byte, so the picture that comes out is bit-identical to the
  one that went in. Tools that strip a JPEG by decoding and re-saving it lose a little quality
  every time (ADR-0021).
- **Two JPEG segments are kept on purpose, and the report says so.** The JFIF header, which
  carries the pixel aspect ratio, and the Adobe marker, which declares the colour transform —
  without it, CMYK images render with wrong colours. Neither names a person, a place, or a
  device. Any thumbnail inside the JFIF header is still removed.
- **`strypt show` and `strypt strip` now work on PNG images.** They report and remove text
  chunks (`tEXt`, `zTXt`, `iTXt`), the `tIME` modification timestamp, the `eXIf` block, the
  `iCCP` colour profile, suggested palettes, ancillary chunks strypt does not recognise, and
  any data hidden after the file's end chunk. Text chunks are reported by keyword, so you can
  see that a thumbnailer had recorded the original file's full path — `Thumb::URI` names your
  home directory — or that a converter had stashed a whole Exif block as hex text under a
  `Raw profile type` keyword, where a tool looking only for Exif would miss it.
- **Your PNG is not re-encoded, and a file with nothing to remove comes back byte-identical.**
  Chunks that stay are copied through exactly as they were, CRCs included. PNG is a lossless
  format; a tool that re-saved it would be undoing the reason you chose it.
- **strypt reads PNG's compressed text chunks without decompressing them** (ADR-0022). The
  keyword that says what a chunk is sits outside the compression, and the chunk is removed
  whole either way — so strypt ships no decompressor and never feeds one an untrusted file.
  The cost, stated plainly: a compressed XMP packet is reported as one item rather than
  broken down property by property. An uncompressed one is still itemised.
- **Two PNG behaviours are deliberate and reported rather than silent.** Chunks that affect
  how the image renders are kept, and the physical-dimensions chunk (`pHYs`) is listed in the
  strip report as kept on purpose. A chunk strypt does not recognise is also kept if the file
  marks it as *critical* — meaning whatever wrote the file said it is needed to interpret the
  image — and the report says plainly that its bytes went through unexamined.
- **`strypt show` and `strypt strip` now work on WebP images.** They report and remove the
  `EXIF` block, the `XMP ` packet, the `ICCP` colour profile, and any chunk strypt does not
  recognise — including chunks hidden *inside* an animation frame, which the WebP
  specification explicitly permits and which a handler looking only at the top level would
  walk straight past. Data after the length the file's header declares is removed too.
- **strypt corrects the header that says what a WebP contains.** An extended WebP opens with a
  `VP8X` chunk whose flags declare that the file has an ICC profile, Exif, or XMP. Remove
  those and leave the flags set and the file lies about itself — some viewers warn, some
  refuse to open it. strypt clears exactly those three bits and copies every other byte of the
  chunk through, so the alpha channel, the animation, and the canvas dimensions are untouched
  (ADR-0023). A side effect worth knowing: a file whose header was *already* claiming metadata
  it did not have will be changed by `strip` even though `show` reported nothing to remove.
- **A WebP with no metadata header comes back byte-identical.** A simple-format WebP cannot
  carry Exif, XMP, or an ICC profile at all — the format requires the extended header first —
  so stripping one is a guaranteed pass-through rather than a file that happened to be clean.
  An animation whose frames need nothing removed passes through unchanged too.
- **A WebP animation keeps every frame.** The frames are the picture; a handler that treated
  them as container chrome would silently hand back a still image.
- **`strypt show` and `strypt strip` now work on PDF files.** They report and remove the
  Document Information Dictionary (including vendor-invented keys), XMP metadata packets,
  the document identifier, private application data in `/PieceInfo`, page modification
  times, markup-annotation authorship and dates, and embedded-file parameter metadata.
- **Earlier revisions of a PDF no longer survive stripping.** A PDF that has been saved more
  than once carries every previous version inside it, recoverable with a hex editor. strypt
  rebuilds the document from what the catalogue can actually reach, so superseded revisions
  are not written out at all (ADR-0020). The report also tells you when a file had earlier
  revisions in it, whether or not you were expecting that.
- **Output is checked before it is written.** Every strip is re-inspected, and if metadata
  survived, the operation fails and nothing is written. strypt would rather refuse than hand
  you a file it cannot vouch for.
- Unsupported and unrecognised formats are reported as such, with the format named where it
  can be identified. They are never copied through or reported as success.
- CLI: batch processing, `--recursive`, `--in-place`, `--output-dir`, `--force`, `--json`
  with a stable schema, `--show-values`, `--max-bytes`, and documented exit codes.
- Fuzz targets for the PDF, JPEG, PNG, and WebP handlers and for format detection, with seed
  corpora that include deliberately malformed files. They assert invariants — that stripped
  output re-inspects clean and that stripping is idempotent — not merely that nothing
  crashed.
- Test corpus with a manifest and a deterministic generator (`corpus/tools/`). No fixture
  contains real personal data, by construction.

- **Phase 1 is complete.** `strypt show` and `strypt strip` handle PDF, JPEG, PNG and WebP;
  every other format is reported as unsupported and never passed through untouched. All seven
  exit criteria are met, including a 12-hour fuzz run of the PDF parser with no crashes, hangs
  or memory exhaustion, and a green build and test run on Linux, macOS and Windows.

  What that does **not** mean: no tool can guarantee total metadata removal, and the documented
  limitations still apply — strypt keeps the JPEG `APP14` colour-transform marker that mat2
  removes, and refuses a PDF with 19-byte cross-reference entries that mat2 strips, where mat2
  is the better recommendation for that file. Performance figures come from one machine.

- **The real-producer test corpus no longer carries anyone's real personal data.** The files it
  fetches from public sample repositories held four real names in Canon owner-name fields, two
  more in PDF author fields, a camera serial number, and live GPS coordinates for five
  photographs — Helsinki, Hämeenlinna, Kansas City and Madrid. `sanitise_corpus.py` now replaces
  every one with a synthetic value on each build, keeping the producer's file structure intact
  so the fixtures still test what they were collected to test. The build refuses to write its
  manifests if verification finds anything real surviving.

  This never affected anyone using strypt — the corpus is a development-only, fetch-on-demand
  set that ships in no release and was never committed. It matters because those files were a
  step away from being committed, and a metadata-removal tool publishing a stranger's home
  coordinates is the exact failure it exists to prevent.

### Fixed

- **A malicious PDF could crash strypt instead of being refused.** A flaw in the underlying PDF
  library made it overflow an integer while reading a damaged cross-reference table, and strypt
  stopped with a Rust stack trace and exit code 101. Such files are now refused normally: "the
  parser failed on this file and it was not processed".

  **Nothing was leaked and no bad file was ever written** — strypt crashed before writing
  anything, so it never produced a half-cleaned document or reported success on a file it had
  not processed. The harm was a crash on hostile input and an error message that looked like a
  bug in strypt. Affects PDFs only. Found by the `pdf` fuzz target during an eight-hour run and
  reported upstream; strypt contains the failure rather than fixing the library (ADR-0024).

- **A PDF with no document catalogue is now refused instead of being rewritten into a corrupt
  file that strypt called clean.** ISO 32000-1 requires the file trailer to name a `/Root`, the
  catalogue every other object hangs off. When it was missing, strypt had no root to walk from,
  so its rewrite kept a different set of objects each time it ran: stripping such a file twice
  produced two different documents, and the second one had a page whose annotation list pointed
  at the catalogue object. strypt reported success both times. It now refuses the file — "the
  parser failed on this file and it was not processed".

  **This corrupted the output rather than leaking anything**: the metadata strypt is asked to
  remove was still removed on every pass. If you stripped such a file with an earlier build,
  the result may not open in a viewer — but the input could not open in a viewer either, since
  a PDF without a catalogue has no entry point. Affects PDFs only. Found by the `pdf` fuzz
  target; `corpus/pdf/malformed/no-root-trailer.pdf` is the regression test.

- **Error messages no longer print `None` where a position is unknown.** A refusal with no known
  byte offset read "malformed PDF at byte offset None" — debug syntax shown to someone deciding
  whether a document is safe to publish. It now simply omits the position.

- **Stripping a PDF containing a negative zero twice gave a different file than stripping it
  once.** The underlying PDF library writes the real number `-0.0` as `-0`, without the decimal
  point that made it a real; read back, `-0` becomes the integer `0` and is written as `0`. So a
  second strip changed one byte, and the value quietly changed type. strypt now writes negative
  zero as zero, which the PDF specification treats as the same number — no page, no coordinate,
  and no rendered output changes.

  **Nothing was leaked or damaged by this**, and a file stripped with an earlier build is fine:
  both passes removed everything they should. What broke was strypt's promise that stripping is
  repeatable, which is the property differential testing and future verification work rest on.
  Affected any PDF carrying a negative zero — legal, and ordinary enough in page geometry.
  Found by the `pdf` fuzz target during a two-hour run, and a second time by CI when the first
  fix turned out to miss negative zeros in the file trailer.

- **A PDF whose content stream declared a malformed length was rewritten with that stream's
  contents silently discarded, and reported as a clean copy.** The specification requires a
  stream's `/Length` to be an integer; a file writing `45.` instead of `45` parses without
  complaint in the underlying PDF library, which then hands strypt the stream with its bytes
  already dropped. strypt rewrote the document, wrote out a file whose `/Length` still claimed
  45 bytes over an empty stream — structurally invalid, and missing the page's content — and
  told the user "nothing to remove; wrote a clean copy". Such files are now refused.

  **No metadata was leaked by this**, so a file you stripped with an earlier build has not
  had anything exposed. What could happen is the reverse: an affected document would come back
  damaged, with content missing, while reporting success. Only PDFs with a malformed stream
  length were affected — no file in the synthetic corpus or in the 23 real-producer PDFs
  (pdfLaTeX, LibreOffice, Google Docs, Acrobat, ImageMagick) triggers it. Found by the `pdf`
  fuzz target, which noticed that stripping such a file twice gave two different results.

- The `binary` rule for PDF fixtures now covers subdirectories (`corpus/pdf/**/*.pdf`, not
  `corpus/pdf/*.pdf`). The narrower pattern matched no fixture in `corpus/pdf/malformed/`, so
  the first one added there would have been silently corrupted on a Windows checkout by the
  same CRLF rewriting described below — the fix was in place but did not reach where it was
  next needed.

- `real-producer-corpus/build_real_corpus.py` now rebuilds reproducibly. ImageMagick stamps
  the wall clock into generated PNGs in two places — the `date:*` text chunks and the `tIME`
  chunk — so every rebuild produced different bytes and invalidated every checksum in the
  manifest. It also prunes files it no longer produces; a renamed fixture had been left
  behind as an unlisted duplicate, inflating the corpus counts. Its `minimal-object-stream.pdf`
  contained no object stream and pointed `startxref` at the wrong offset, so it failed for a
  reason unrelated to its name; it is replaced by `minimal-xref-table.pdf`, built from
  computed offsets.

- PDF test fixtures are marked `binary` in `.gitattributes`. Without it, Git classified them
  as text — they are mostly printable ASCII — and rewrote every LF to CRLF when checking out
  on Windows, which shifts every offset in a PDF's cross-reference table and stops the file
  parsing at all. Caught by CI as fifteen failures on `windows-latest` and none elsewhere.
  A test now checks fixture integrity directly, so this cannot recur silently on any platform.

### Known limitations in this release

Read these before relying on the tool. They are limitations, not bugs, and each is deliberate:

- **All four Phase 1 formats are handled: PDF, JPEG, PNG, and WebP.** Everything else is
  reported as unsupported rather than processed.
- **Stripping a JPEG can change how it displays.** Two of the things removed affect
  rendering: Exif `Orientation`, so an image that relied on it may appear rotated, and the ICC
  colour profile, so a wide-gamut image is afterwards interpreted as sRGB. Both are also
  identifying — a per-device colour profile is a fingerprint, and its description usually
  names the vendor — so both are removed and the consequence is stated here rather than
  hidden. Check a stripped image before publishing it.
- **A JPEG that ends without its end-of-image marker is refused.** strypt will not repair a
  damaged file and hand it back as a clean one.
- **The Adobe `APP14` marker is kept, where mat2 removes it.** It is two bytes of colour-space
  declaration and it names nothing; removing it would change how CMYK files look. This is a
  deliberate, documented difference (ADR-0021).
- **A JPEG's encoder fingerprint survives.** Quantisation tables, Huffman tables, and chroma
  subsampling identify the software and often the device that produced a file. Removing them
  would mean re-encoding the picture, which strypt will not do.
- **A compressed PNG text chunk is reported less finely than an uncompressed one.** strypt
  carries no decompressor, so a compressed XMP packet is reported as a single item rather than
  property by property. It is removed either way (ADR-0022).
- **A PNG chunk strypt does not recognise is kept if it is critical.** strypt cannot know
  what it holds or what depends on it, so it copies the bytes through unexamined and the
  report says so. If you have a file with an unusual critical chunk, read the notes before
  publishing it — and note that such a file was already unreadable to ordinary viewers before
  strypt saw it.
- **A malformed PNG is refused, not repaired.** A file whose first chunk is not `IHDR`, that
  ends before `IEND`, or whose chunk lengths do not agree with its size, is rejected rather
  than cleaned up and handed back.
- **An extended WebP is not returned byte-identical.** Two fields change beyond the removals:
  the header's flags byte, and the container's own size. A simple-format WebP, and an extended
  one whose flags describe only the picture, are unchanged.
- **strypt does not read inside a WebP's ICC profile.** The chunk is removed whole and
  reported as a colour profile, without naming the device manufacturer or model recorded in
  it. Parsing an ICC profile would mean another format parser running on untrusted bytes for
  no change to what is removed.
- **A WebP animation frame strypt cannot parse is kept, not refused.** The report says plainly
  that its bytes went through unexamined, so anything hidden in that frame is still there.
- **A WebP with no picture in it is refused.** A file consisting of only a header and a
  metadata chunk would otherwise strip to a valid-looking container with no image, reported as
  a success.
- **A WebP's encoder fingerprint survives.** The bitstream carries its encoder's choices and
  the chunk order carries its muxer's. Removing them would mean re-encoding, which for a lossy
  WebP also means degrading the picture a second time.
- **strypt has not been compared against mat2 on WebP.** mat2 supports the format, but its
  WebP path needs a GdkPixbuf WebP loader that was not present on the machine used for
  verification, so the comparison was not run — for WebP only. ExifTool finds nothing but
  structural image properties in strypt's output.
- **Encrypted PDFs are refused.** strypt will not emit a decrypted copy of your document, so
  a password-protected file cannot be stripped at present.
- **Some PDFs are refused that other tools accept, because of how their cross-reference table
  is written.** The PDF specification fixes each entry in that table at exactly 20 bytes, and
  some producers write 19 by leaving out a padding space. strypt's PDF parser rejects those
  files; `qpdf` reports no errors on them and **mat2 strips them successfully**. If strypt
  tells you a PDF is malformed but other tools open it happily, this is the likely reason —
  **use mat2 for that file.** strypt refuses rather than guessing, so you are never handed a
  file it did not actually process, but this is a gap on strypt's side rather than a problem
  with your document. Found against real files during Phase 1 corpus work
  (`docs/THREAT_MODEL.md` §7.5).
- **Annotation contents are preserved.** strypt removes the annotator's name and dates, not
  the comment they wrote. It removes metadata, not information — a reviewer's remarks are
  content, and something visible in a document is not something this tool deletes.
- **Embedded attachments are not opened.** Their parameter metadata is removed and the
  attachment itself is left intact; if it carries its own metadata, strypt has not touched it.
  The report says so.
- **strypt does not redact.** Text under a black rectangle in a PDF is still in the file.
- Testing so far uses generated fixtures. Files from real producers — LaTeX, Word, Acrobat,
  scanners, browser print-to-PDF — are not yet in the corpus, and real producers are where
  the quirks live.

### Added — foundation

- Phase 0 foundation documents: PRD, architecture, roadmap, threat model, decision log,
  and testing strategy.
- Contribution, security, and code of conduct policies.
- Dual MIT / Apache-2.0 licensing.
- `.claude/` tooling configuration, including hooks intended to catch violations of the
  no-network and `unsafe` constraints early.
- Cargo workspace scaffolding: `strypt-core` (no logic yet) and `strypt-cli` (stub binary),
  with `unsafe_code = "forbid"` workspace-wide and panic-freedom lints scoped to the core
  crate per ADR-0006.
- `rust-toolchain.toml` pinning the compiler explicitly, so release builds never depend on
  whichever toolchain a machine happens to have.
- `scripts/check-no-network.sh`, the authoritative ADR-0004 gate: walks the fully resolved
  dependency graph across all features and fails on any networking crate, transitive ones
  included. Verified to fire on a deliberate violation.
- CI workflows (build/test on Linux, macOS, and Windows; fmt; clippy; MSRV; no-network;
  cargo-deny) and a `.githooks/pre-commit` gate covering edits made outside Claude Code.
- `deny.toml` supply-chain policy: allowed licences, banned networking crates, crates.io as
  the only permitted source.
- README status banner stating exactly what is built, fuzzed, and audited versus what is
  not, tracked against the phase definitions in `docs/ROADMAP.md`.
- CONTRIBUTING.md disclosure that development uses an AI coding agent under defined
  constraints, including a direct statement of what those safeguards do *not* establish.

### Fixed

- The MSRV CI job would have silently built with the pinned toolchain rather than the MSRV,
  because `rust-toolchain.toml` outranks a default-setting toolchain action in rustup's
  precedence order. It now sets `RUSTUP_TOOLCHAIN` explicitly and asserts the version in use.
  Recorded as ADR-0015.
- `cargo-deny` reported success while its `bans` check was failing, because the job was
  advisory-only. The deterministic checks (`bans`, `licenses`, `sources`) are now hard gates;
  `advisories` stays advisory until Phase 3. Recorded as ADR-0016.
- `strypt-cli` declared `strypt-core` by path with no version — a wildcard dependency, and
  unpublishable to crates.io. Now versioned explicitly.
- Bumped `actions/checkout` to v5; v4 targets a deprecated Node runtime.

### Notes

- No software has been released. There is nothing installable yet, and no version has been
  tagged. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for what Phase 1 will contain.

[Unreleased]: https://github.com/FadeHack/strypt/commits/main
