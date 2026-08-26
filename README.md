# strypt

> ## Status: Phase 2 in progress — no audit, no release, no hardening phase yet
>
> **PDF, JPEG, PNG, WebP, TIFF, GIF, Office Open XML (`.docx`, `.xlsx`, `.pptx`), and
> OpenDocument (`.odt`, `.ods`, `.odp`) are implemented.**
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
> **The GIF handler landed 2026-08-26 and its tranche is not finished.** Comments, XMP, the ICC,
> 8BIM and IPTC blocks `ImageMagick` writes, plain text, and anything hidden after the trailer are
> removed; the animation's loop count is **kept on purpose** and declared, because it identifies
> nobody and removing it would stop a looping animation from looping. The pixels are never
> decoded, and a clean GIF comes back byte-identical. Its differential against mat2 0.15.0 and
> ExifTool 13.55 is clean over all 14 fixtures — on one of them strypt removes more than mat2
> does. **It has had a 3-minute fuzz smoke run and not a sustained one, so it does not yet meet
> the bar every other shipped format has met.** HEIF/AVIF, SVG, JPEG XL, and audio/video are
> **not started**.
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
> | 2 — Expanded formats | 🔶 In progress — OOXML 2026-08-23, OpenDocument 2026-08-24, TIFF 2026-08-26 done; GIF landed and owes its fuzz run; HEIF/AVIF, SVG, JPEG XL and A/V not started |
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
| `.docx` `.xlsx` `.pptx` | The core, extended, and custom properties (author, company, manager, cumulative editing time, revision count), the page thumbnail, revision-save and paragraph identifiers, the author names and dates on comments and tracked changes, per-part timestamps and host fields, and external relationships pointing at a local path. **Photographs inside the document are stripped by the image handlers above.** The *text* of comments and tracked changes is kept and reported — see the limitations below |

| `.odt` `.ods` `.odp` | `meta.xml` entire — author, last-saved-by, creation/modification/print dates, the editing-cycle count and the total editing duration, the generator (which names the operating system), page and word statistics, user-defined properties, and a template path — plus `settings.xml` entire, which holds the **printer name and setup blob**; the page thumbnail; the saved user-interface configuration and layout cache; the author names and dates on comments and tracked changes; the cached author-name fields printed in the document; and per-part timestamps and host fields. **Photographs inside the document are stripped by the image handlers above, and an embedded chart's own metadata goes too.** The *text* of comments and tracked changes is kept and reported — see the limitations below |

Still to come in Phase 2: HEIF/AVIF, SVG, JPEG XL, audio, and video. See
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
