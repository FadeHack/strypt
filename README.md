# strypt

**Remove hidden metadata from files before you share them.**

Photos carry GPS coordinates and camera serial numbers. PDFs carry author names, organisation
names, and editing timestamps. Word documents carry all of that plus the editing sessions they
were written in — and the photographs pasted into them arrive with their own GPS still attached.
None of it is visible in a normal viewer, and all of it survives to publication. strypt finds it
and strips it out.

A single self-contained binary. Memory-safe Rust. **No network access in any code path.**

> **Status: `0.0.1`, not a release. No external audit.** Read
> [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) before relying on strypt.
> Phases 0–3 are complete; prebuilt binaries and signing are Phase 4 ([`docs/ROADMAP.md`](docs/ROADMAP.md)).

<!-- Badge placeholders — activate in Phase 4 -->
<!-- [![CI](…)](…) [![crates.io](…)](…) [![License](…)](…) -->

## Formats

| Kind | Formats |
|---|---|
| Images | JPEG, PNG, WebP, TIFF, GIF, HEIF/AVIF (`.heic`, `.heif`, `.avif`), SVG, JPEG XL |
| Documents | PDF; Office Open XML (`.docx`, `.xlsx`, `.pptx`); OpenDocument (`.odt`, `.ods`, `.odp`) |
| Audio and video | FLAC, WAV, MP3, Ogg (`.ogg`, `.opus`, `.oga`), MP4/M4A (`.mp4`, `.m4v`, `.m4a`, `.m4b`) |

Photographs inside a document are stripped by the image handlers. Every other format is reported
as unsupported and never passed through. What each handler removes, keeps, and refuses:
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §7.

**For other formats, use [mat2](https://github.com/jvoisin/mat2) or
[ExifTool](https://exiftool.org/)** — both mature, actively maintained, and covering far more
formats. Where mat2 is the better tool for a file strypt does support,
[`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md#where-mat2-is-the-better-choice) says so.

## What strypt will *not* do

- It does not redact. A PDF with a black box drawn over text still contains that text.
- It does not change what your document *says*, or anonymise your writing style.
- It does not clean filenames, and `budget_final_jsmith_home.pdf` identifies you regardless.
- It does not protect against metadata a platform adds after you upload.
- It cannot defeat fingerprinting — encoder quirks and camera sensor noise can identify a
  device from pixel data alone, with no metadata present at all.
- **No tool can guarantee complete metadata removal from complex formats.** strypt will never
  claim otherwise.

## Install

```sh
cargo install strypt    # requires a Rust toolchain
```

That is the only install path until Phase 4. `strypt-cli` on crates.io is the same tool under
its original name, yanked on 2026-08-23 (ADR-0026); replace it with `strypt`.

## Usage

```sh
strypt show photo.jpg                  # report what metadata is present; changes nothing
strypt strip photo.jpg                 # write a sanitised copy beside the original
strypt strip --output-dir out/ *.pdf   # write copies elsewhere
strypt strip --in-place report.docx    # overwrite the original (opt-in, never the default)
strypt show --json --recursive ./docs  # machine-readable output for scripting
```

A failure is loud: a file strypt cannot fully process produces no output. Commands and exit
codes: [`INSTRUCTIONS.md`](INSTRUCTIONS.md).

## Documentation

| Document | Contents |
|---|---|
| [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) | What strypt keeps, cannot see, and refuses, per format |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Adversaries, protections, and limits |
| [`docs/PRD.md`](docs/PRD.md) | Problem, users, requirements, and where strypt differs from mat2 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, dependencies, security architecture |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phases, deliverables, exit criteria |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Architecture decision records |
| [`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) | How correctness is verified |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute, and how development is [AI-assisted under constraints](CONTRIBUTING.md#development-process-ai-assisted-under-constraints) |
| [`SECURITY.md`](SECURITY.md) | Reporting vulnerabilities |
| [`INSTRUCTIONS.md`](INSTRUCTIONS.md) | Build, test, and lint commands |

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Contributions are accepted under the same dual licence, per the Apache-2.0 contribution clause,
unless you state otherwise.
