# strypt

> ## Status: Phase 2 in progress — no audit, no release, no hardening phase yet
>
> **PDF, JPEG, PNG, WebP, TIFF, GIF, HEIF/AVIF (`.heic`, `.heif`, `.avif`), SVG, JPEG XL, FLAC, WAV, Office Open XML
> (`.docx`, `.xlsx`, `.pptx`), and OpenDocument (`.odt`, `.ods`, `.odp`) are implemented.**
> Everything else is recognised and reported as unsupported; it is not processed. All seven Phase 1 exit criteria are met: the handlers were
> swept over 102 files from real producers — real camera maker notes included — the mat2
> differential covers all four formats, performance is measured, CI is green on Linux, macOS and
> Windows, and 80 CPU-hours of fuzzing across five targets found four real PDF defects, each
> fixed with a regression test, ending in a 12-hour PDF run with no crashes, hangs or OOMs.
>
> **Office Open XML landed 2026-08-23 and OpenDocument on 2026-08-24**, the first two of Phase
> 2's four format groups (ADR-0027). A photograph pasted into a document is stripped by the same
> image handler a loose file goes through. Limitations recorded rather than glossed: the *text*
> of comments and tracked changes stays in both formats (only its attribution is removed, and
> **mat2 is the better tool if the comments themselves must go**); an Office document containing
> a nested archive, an embedded PDF, or an OLE object is refused rather than partly cleaned.
> The `odf`, `zip`, `ooxml` and `pdf` fuzz targets have each run 12 hours in parallel — 48
> CPU-hours, zero crashes, hangs or OOMs — and every stripped OpenDocument file opens in
> LibreOffice 26.2.5.2, with 16 documents imported and body-compared automatically and seven
> also opened by hand with no repair prompt.
>
> **TIFF is done (2026-08-26).** It is the first of five
> tranches the additional-image group was split into (ADR-0032). TIFF is the one format strypt
> **rebuilds rather than edits** — its metadata is its file structure, so there is nothing to
> excise — writing only the tags an image cannot be decoded without and copying the pixels
> across bit-identically (ADR-0033). Its differential against mat2 0.15.0 and ExifTool 13.55 is
> clean over all 10 fixtures, and the `tiff` and `detect` fuzz targets have each run 12 hours —
> 24 CPU-hours, 4.4 billion inputs, zero crashes, hangs or OOMs — so **the tranche is complete as
> of 2026-08-26**. Recorded limitations:
> output is never byte-identical to input even for a clean file, because a rebuild reorders it;
> metadata hidden inside the compressed image data is out of reach, and **mat2's re-rendering
> default is the better tool where that is the concern**.
>
> **GIF is finished as of 2026-08-27.** Comments, XMP, the ICC,
> 8BIM and IPTC blocks `ImageMagick` writes, plain text, and anything hidden after the trailer are
> removed; the animation's loop count is **kept on purpose** and declared, because it identifies
> nobody and removing it would stop a looping animation from looping. The pixels are never
> decoded, and a clean GIF comes back byte-identical. Its differential against mat2 0.15.0 and
> ExifTool 13.55 is clean over all 14 fixtures — on one of them strypt removes more than mat2
> does. Its sustained fuzz run came back clean over a full twelve hours and 1.07 billion inputs,
> so it now meets the same bar every other shipped format has met.
>
> **HEIF and AVIF are finished as of 2026-08-27.** The Exif block with its GPS and serial
> numbers, XMP in both the places it hides, the ICC profile, item names, and **embedded thumbnails** all come out, and a
> vendor item or property strypt has never seen does not survive by going unrecognised. Like TIFF,
> the file is **rebuilt rather than edited**: its metadata is addressed by absolute file offsets, so
> removing any of it moves everything after (ADR-0034). The picture is copied across without being
> re-encoded, and the differential against mat2 0.15.0 and ExifTool 13.55 is clean over all 17
> fixtures with zero differing pixels, and the `heif`, `bmff` and `detect` fuzz targets have each
> run 12 hours — 36 CPU-hours, 5.6 billion inputs, zero crashes, hangs or OOMs — so **the tranche
> is complete**. Recorded limitations: output is never byte-identical to input even for a clean file; metadata
> inside the compressed image data is out of reach, where **mat2's re-rendering default is the
> better tool**; and a **motion HEIF is refused, which means Apple Live Photos are refused** rather
> than partly cleaned, because video is a later group.
>
> One finding worth repeating outside the threat model: **a hidden thumbnail in a HEIC or AVIF is
> not something the usual tools will show you.** ExifTool does not report it, ImageMagick shows a
> single frame, and libheif prints `thumbnail: 0x0` (measured 2026-08-27).
>
> **SVG is finished as of 2026-08-29.** It is the one format here where strypt removes *less* than mat2 and says so: mat2
> re-renders the document through Rsvg, which removes more — the accessibility text and the script
> strypt refuses to touch — but destroys ids, grouping, animation and the author's editable
> structure. strypt edits by deletion, so a clean drawing comes back byte-identical, and a name
> reaches the output only if its namespace prefix is one the picture cannot be drawn without —
> an editor nobody here has tested cannot survive by going unrecognised. Recorded limitations:
> `<title>`, `<desc>` and an external reference's path are **kept and declared** because each can
> identify an author and removing any of them changes what the file does; and a document containing
> a script, an event handler, a `foreignObject` or a `javascript:` reference is **refused rather
> than partly cleaned**, where **mat2 is the better tool**. `.svgz`, non-UTF-8 documents and a
> doctype declaring its own entities are refused too. The differential against mat2 0.15.0 and
> ExifTool 13.55 is clean over 14 fixtures, and the `svg` and `detect` fuzz targets have each run
> 12 hours — 24 CPU-hours, 4.1 billion inputs, zero crashes, hangs or OOMs.
>
> **JPEG XL is finished as of 2026-08-30, and with it Phase 2's image group.** Both spellings are handled: the
> container, and the bare codestream, which has no metadata layer at all and is returned unchanged
> with its scope stated rather than being called clean without qualification. Boxes reach the output
> through an allow-list, so a box strypt has never seen refuses the file. It is the format where
> strypt removes the most relative to the alternative, and that was measured rather than assumed:
> ExifTool removes the Exif, XMP and Brotli boxes and leaves the rest, so **a C2PA manifest naming
> the capture device and the signing identity survives mat2 and does not survive strypt** (2026-08-29).
> Recorded limitations: the codestream is never entered, so an **ICC profile and a preview frame are
> out of reach** — for ExifTool and mat2 as much as for strypt — and removing the JPEG
> reconstruction box **ends bit-exact JPEG round-tripping**, which every affected report says. The
> `jxl` and `detect` fuzz targets have each run 12 hours — 24 CPU-hours, 3.4 billion inputs, zero
> crashes, hangs or OOMs.
>
> **FLAC is finished as of 2026-09-01 — the first of Phase 2's five audio/video tranches.** It is
> edited by block surgery, so a clean file comes back byte-identical: RFC 9639
> measures a seek point from the first audio frame rather than from the start of the file, so
> removing metadata moves nothing. Blocks reach the output through an allow-list, so a block type
> strypt has never seen is removed unread. Measured on 2026-09-01, mat2 reaches FLAC through
> mutagen and knows only the Vorbis comment and the picture block, so **a vendor `APPLICATION`
> block, a cuesheet carrying a disc catalogue number and per-track ISRCs, and a reserved block type
> all survive mat2 and do not survive strypt**. Recorded limitations: the audio is never decoded, so
> anything hidden in a frame or appended past the last one is out of reach; the **MD5 of the
> unencoded audio is kept and declared**, because whoever holds the file can recompute it from the
> audio it still carries; removing the cuesheet **ends splitting the file back into tracks**; and a
> FLAC with an ID3v2 tag glued to the front is refused by name.
>
> The `flac` and `detect` fuzz targets have each run 12 hours — 24 CPU-hours, 3.5 billion inputs,
> zero crashes, hangs or OOMs.
>
> **WAV landed 2026-09-01 — the second audio tranche — and its sustained fuzz run is still owed.**
> Short runs are clean, but until a 12-hour run over `wav`, `riff` and `webp` is recorded, this
> handler has not met the same bar as the ones above it, and MP3 does not start. It is edited by
> chunk surgery, so a clean file comes back byte-identical, and only four chunks are copied through
> — everything else, named or private, is removed unread. Its walker is now shared with WebP.
> Measured on 2026-09-01 against mat2 0.15.0: no gaps in either direction. **The interesting result
> is one that did not go strypt's way and is recorded anyway**: mat2 rebuilds a WAV through ffmpeg,
> which looked like it should reach data hidden in the samples where chunk surgery cannot — it does
> not, because for 16-bit PCM the rebuild reproduces the audio byte for byte. So **neither tool
> reaches anything hidden inside a WAV's sample values**, and every report says so. Also recorded:
> `cue ` is kept although ExifTool calls it metadata; an embedded ID3v2 tag is dropped unread rather
> than parsed; removing the sampler chunk **ends looping the file in a sampler**; and RF64/BW64
> files are refused by name rather than treated as large WAVs.
>
> MP3, Ogg and MP4 are **not started**.
>
> **What "Phase 1 done" does not mean.** There has been no external audit and no release. No
> tool can guarantee total metadata removal and strypt does not claim to. Hardening is Phase 3
> and has not started, so the 100-CPU-hour-per-handler fuzzing budget is *not* met — PDF was
> still finding new code paths at hour 12. Two limitations are documented rather than fixed: the
> JPEG `APP14` marker mat2 removes, and a PDF with 19-byte cross-reference entries that strypt
> refuses and mat2 handles. Performance is one machine; Linux and Windows are unmeasured.
>
> | Phase | Status |
> |---|---|
> | 0 — Foundation: docs, workspace, CI gates | ✅ Done |
> | 1 — Core engine + CLI (JPEG, PNG, WebP, PDF) | ✅ Done 2026-08-22 — all seven exit criteria met; see the caveats above |
> | 2 — Expanded formats | 🔶 In progress — OOXML 2026-08-23, OpenDocument 2026-08-24, TIFF 2026-08-26, GIF and HEIF/AVIF 2026-08-27, SVG 2026-08-29, JPEG XL 2026-08-30, FLAC 2026-09-01 done; WAV landed 2026-09-01 with its sustained fuzz run still owed; MP3, Ogg, MP4 not started |
> | 3 — Hardening · 4 — Distribution | ⬜ Not started |
> | 5 — GUI · 6 — File-manager integration · 7 — Community | ⬜ Not started |
>
> Full phase definitions and exit criteria: [`docs/ROADMAP.md`](docs/ROADMAP.md).
>
> **For anything other than the formats listed above, and for anything that matters, use
> [mat2](https://github.com/jvoisin/mat2) or [ExifTool](https://exiftool.org/)** — both
> mature, actively maintained, and covering far more formats.
> [`docs/PRD.md`](docs/PRD.md) §4 explains where strypt intends to differ.
>
> Development is AI-assisted under defined constraints — see
> [Development process](CONTRIBUTING.md#development-process-ai-assisted-under-constraints).

---

**Remove hidden metadata from files before you share them.**

Photos carry GPS coordinates and camera serial numbers. PDFs carry author names, organisation
names, and editing timestamps. Word documents carry all of that plus the editing sessions they
were written in — and the photographs pasted into them arrive with their own GPS still attached.
None of it is visible in a normal viewer, and all of it survives to publication. strypt finds it
and strips it out.

A single self-contained binary. Memory-safe Rust. **No network access in any code path.**

<!-- Badge placeholders — activate in Phase 4 -->
<!-- [![CI](…)](…) [![crates.io](…)](…) [![License](…)](…) -->

---

## Trying it

```sh
cargo run -p strypt -- show corpus/pdf/info-dictionary.pdf
cargo run -p strypt -- show corpus/jpeg/exif-gps.jpg
cargo run -p strypt -- show corpus/ooxml/everything.docx
cargo run -p strypt -- show corpus/odf/everything.odt
cargo run -p strypt -- strip corpus/jpeg/exif-gps.jpg
```

`show` never writes. `strip` writes a copy beside the input and leaves the original alone
unless you ask for `--in-place`. Full command reference and exit codes:
[`INSTRUCTIONS.md`](INSTRUCTIONS.md).

## Scope

| Format | What gets removed |
|---|---|
| JPEG | Exif (incl. GPS and MakerNote), XMP, IPTC, ICC profile, comments, embedded thumbnails, and data hidden after the end-of-image marker. The picture is never re-encoded |
| PNG | Text chunks (`tEXt`, `zTXt`, `iTXt`), timestamps, ICC profile, the `eXIf` chunk, unknown ancillary chunks, and data hidden after the end chunk. Image data is copied through byte for byte |
| WebP | The `EXIF`, `XMP `, and `ICCP` chunks, unknown chunks at the top level and inside animation frames, and data hidden past the container's declared length. The header's flags are corrected so the file stops claiming metadata it no longer has. The bitstream is copied through byte for byte |
| PDF | Document info dictionary, XMP metadata streams, document IDs, annotation and embedded-file metadata |
| TIFF | Everything except the tags an image cannot be decoded without — camera and scanner identity, artist, copyright, description, timestamps, GPS and Exif sub-directories, XMP, IPTC, the ICC profile, embedded thumbnails, and **any vendor tag strypt has never seen**. The file is rebuilt rather than edited, and the pixels are copied across bit-identically |
| GIF | Comments, XMP, the ICC, 8BIM and IPTC blocks `ImageMagick` and Photoshop write as application extensions, plain text, extensions under undefined labels, **any vendor application block**, and data hidden after the trailer. The animation's loop count, frame delays and transparency are kept and declared. The LZW data is never decoded, and a clean file comes back byte-identical |
| HEIF / AVIF | The Exif block with its GPS coordinates and serial numbers, XMP as an item or in a top-level `uuid` box, the ICC profile, item names, embedded thumbnails, and **any item type or property strypt has never seen**. Numeric colour signalling is kept and declared. The file is rebuilt rather than edited, and the coded picture is copied across byte for byte. A motion HEIF — an Apple Live Photo — is refused rather than partly cleaned |
| SVG | `<metadata>` with its Dublin Core author, licence and XMP; Inkscape's and Illustrator's private namespaces, which carry the file's name on the author's disk, an absolute export path, window geometry, and a compressed copy of the original Illustrator document; XML comments and processing instructions; stylesheet comments; and **any namespace prefix strypt has never seen**. `<title>`, `<desc>` and external references are kept and declared. A photograph pasted in as a `data:` URI is stripped by the image handlers above. Edited by deletion, so a clean drawing comes back byte-identical |
| JPEG XL | The Exif block with its GPS coordinates and serial numbers, XMP, **C2PA provenance** naming the capture device and the signing identity, Brotli-compressed metadata — removed without being decompressed — the frame index, and padding. **Any top-level box strypt has never seen refuses the file.** The codestream is never entered, so its ICC profile and any preview frame are out of reach, which every report says. Removing the JPEG reconstruction box ends bit-exact JPEG round-tripping. A bare codestream is returned unchanged. Edited by deletion, so a clean file comes back byte-identical |
| FLAC | The Vorbis comment, itemised field by field — artist, album, date, location, organisation, the ripping software and its settings; **cover art, removed whole, so the metadata inside that image goes with it**; the cuesheet, which carries the disc's catalogue number and each track's ISRC; vendor `APPLICATION` blocks; and any reserved block type, removed unread. Padding keeps its length and loses its contents. The audio is never decoded, so anything inside a frame is out of reach, which every report says. **The MD5 of the unencoded audio is kept and declared** — whoever holds the file can recompute it. Removing the cuesheet ends splitting the file back into tracks. Edited by block surgery, so a clean file comes back byte-identical |
| WAV | The `INFO` list — artist, engineer, technician, commissioner, copyright holder, archival location, dates; the **broadcast extension**, whose originator, originator reference, UMID and coding history name the desk, the operator and every processing step; field-recorder documents in `iXML` and `aXML`; XMP; **an embedded ID3v2 tag, dropped unread**; radio traffic metadata; cue labels; display text, playlists and instrument settings; and **any chunk strypt has never seen, removed unread**. Padding keeps its length and loses its contents. The cue-point chunk is kept and declared — it names nobody, and removing metadata cannot move its offsets. Removing the sampler chunk ends looping the file in a sampler. The audio is never decoded, so anything hidden in the sample values is out of reach, which every report says. RF64 and BW64 are refused by name. Edited by chunk surgery, so a clean file comes back byte-identical |
| `.docx` `.xlsx` `.pptx` | The core, extended, and custom properties (author, company, manager, cumulative editing time, revision count), the page thumbnail, revision-save and paragraph identifiers, the author names and dates on comments and tracked changes, per-part timestamps and host fields, and external relationships pointing at a local path. **Photographs inside the document are stripped by the image handlers above.** The *text* of comments and tracked changes is kept and reported — see the limitations below |

| `.odt` `.ods` `.odp` | `meta.xml` entire — author, last-saved-by, creation/modification/print dates, the editing-cycle count and the total editing duration, the generator (which names the operating system), page and word statistics, user-defined properties, and a template path — plus `settings.xml` entire, which holds the **printer name and setup blob**; the page thumbnail; the saved user-interface configuration and layout cache; the author names and dates on comments and tracked changes; the cached author-name fields printed in the document; and per-part timestamps and host fields. **Photographs inside the document are stripped by the image handlers above, and an embedded chart's own metadata goes too.** The *text* of comments and tracked changes is kept and reported — see the limitations below |

Still to come in Phase 2: audio and video. See
[`docs/ROADMAP.md`](docs/ROADMAP.md).

**Where mat2 is the better tool, this says so.** For a document whose comments must not be
published at all, use mat2 — it removes those parts, and strypt deliberately keeps their text
because removing a tracked change alters what the document says. That difference is sharpest for
OpenDocument, where mat2 removes annotations and tracked changes outright. For a PDF with
19-byte cross-reference entries, mat2 handles it and strypt refuses.

## Planned usage

```sh
strypt show photo.jpg              # report what metadata is present; changes nothing
strypt strip photo.jpg             # write a sanitised copy
strypt strip --in-place *.pdf      # overwrite originals (opt-in, never the default)
strypt show --json ./docs          # machine-readable output for scripting
strypt strip report.docx           # Office documents too, pictures inside them included
strypt strip report.odt            # and OpenDocument, charts inside them included
```

## Design commitments

- **No network access, ever.** No update checks, no telemetry, no crash reporting. Enforced
  by a CI gate, not by a promise.
- **Your image data is not re-encoded.** Removing metadata is a container operation. Stripped
  photos stay pixel-identical.
- **Safe by default.** Copy-out rather than in-place. Loud failures rather than silent ones.
- **No `unsafe` code**, and no panics on malformed input.
- **Honest about limits.** See below.

## What strypt will *not* do

This matters as much as the feature list.

- It does not redact. A PDF with a black box drawn over text still contains that text.
- It does not change what your document *says*, or anonymise your writing style.
- It does not clean filenames, and `budget_final_jsmith_home.pdf` identifies you regardless.
- It does not protect against metadata a platform adds after you upload.
- It cannot defeat fingerprinting — encoder quirks and camera sensor noise can identify a
  device from pixel data alone, with no metadata present at all.
- **No tool can guarantee complete metadata removal from complex formats.** strypt will never
  claim otherwise.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on this tool for anything
that matters.

## Installation

```sh
cargo install strypt    # requires a Rust toolchain
```

**That is the only install path, and `0.0.1` is not a release.** The crate was published early
to hold the name, not because the project is ready to be depended on — Phase 3 hardening has
not started and there has been no external audit. Prebuilt binaries, checksums, signing,
reproducible builds, and a Homebrew formula are Phase 4 and do not exist yet. See
[`docs/ROADMAP.md`](docs/ROADMAP.md).

`strypt-cli` on crates.io is the same tool under its original name, published and then yanked
on 2026-08-23 (ADR-0026). It is not a separate project and it will not be updated; if you have
it installed, replace it with `strypt`.

## Documentation

| Document | Contents |
|---|---|
| [`docs/PRD.md`](docs/PRD.md) | Problem, users, requirements, competitive landscape |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, dependencies, security architecture |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phases, deliverables, exit criteria |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Adversaries, protections, and limits |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Architecture decision records |
| [`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) | How correctness is verified |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute |
| [`SECURITY.md`](SECURITY.md) | Reporting vulnerabilities |
| [`INSTRUCTIONS.md`](INSTRUCTIONS.md) | Build, test, and lint commands |

## Prior art

strypt owes its problem framing to [mat2](https://github.com/jvoisin/mat2) by Julien Voisin,
built with support from the Tails project, and uses [ExifTool](https://exiftool.org/) as a
verification reference. Both are excellent and actively maintained; strypt is a
differently-engineered option, not a replacement for either.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Contributions are accepted under the same dual licence, per the Apache-2.0 contribution
clause, unless you state otherwise.
