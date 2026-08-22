# strypt

> ## Status: Phase 1 done (2026-08-22) — no audit, no release, no hardening phase yet
>
> **PDF, JPEG, PNG, and WebP are implemented.** Everything else is recognised and reported as
> unsupported; it is not processed. All seven Phase 1 exit criteria are met: the handlers were
> swept over 102 files from real producers — real camera maker notes included — the mat2
> differential covers all four formats, performance is measured, CI is green on Linux, macOS and
> Windows, and 80 CPU-hours of fuzzing across five targets found four real PDF defects, each
> fixed with a regression test, ending in a 12-hour PDF run with no crashes, hangs or OOMs.
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
> | 2 — Expanded formats · 3 — Hardening · 4 — Distribution | ⬜ Not started |
> | 5 — GUI · 6 — File-manager integration · 7 — Community | ⬜ Not started |
>
> Full phase definitions and exit criteria: [`docs/ROADMAP.md`](docs/ROADMAP.md).
>
> **For anything other than PDF, JPEG, PNG, and WebP, and for anything that matters, use
> [mat2](https://github.com/jvoisin/mat2) or [ExifTool](https://exiftool.org/)** — both
> mature, actively maintained, and covering far more formats.
> [`docs/PRD.md`](docs/PRD.md) §4 explains where strypt intends to differ.
>
> Development is AI-assisted under defined constraints — see
> [Development process](CONTRIBUTING.md#development-process-ai-assisted-under-constraints).

---

**Remove hidden metadata from files before you share them.**

Photos carry GPS coordinates and camera serial numbers. PDFs carry author names, organisation
names, and editing timestamps. None of it is visible in a normal viewer, and all of it
survives to publication. strypt finds it and strips it out.

A single self-contained binary. Memory-safe Rust. **No network access in any code path.**

<!-- Badge placeholders — activate in Phase 4 -->
<!-- [![CI](…)](…) [![crates.io](…)](…) [![License](…)](…) -->

---

## Trying it

```sh
cargo run -p strypt -- show corpus/pdf/info-dictionary.pdf
cargo run -p strypt -- show corpus/jpeg/exif-gps.jpg
cargo run -p strypt -- strip corpus/jpeg/exif-gps.jpg
```

`show` never writes. `strip` writes a copy beside the input and leaves the original alone
unless you ask for `--in-place`. Full command reference and exit codes:
[`INSTRUCTIONS.md`](INSTRUCTIONS.md).

## Scope (Phase 1)

| Format | What gets removed |
|---|---|
| JPEG | Exif (incl. GPS and MakerNote), XMP, IPTC, ICC profile, comments, embedded thumbnails, and data hidden after the end-of-image marker. The picture is never re-encoded |
| PNG | Text chunks (`tEXt`, `zTXt`, `iTXt`), timestamps, ICC profile, the `eXIf` chunk, unknown ancillary chunks, and data hidden after the end chunk. Image data is copied through byte for byte |
| WebP | The `EXIF`, `XMP `, and `ICCP` chunks, unknown chunks at the top level and inside animation frames, and data hidden past the container's declared length. The header's flags are corrected so the file stops claiming metadata it no longer has. The bitstream is copied through byte for byte |
| PDF | Document info dictionary, XMP metadata streams, document IDs, annotation and embedded-file metadata |

More formats — Office documents, audio, video — are Phase 2. See
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## Planned usage

```sh
strypt show photo.jpg              # report what metadata is present; changes nothing
strypt strip photo.jpg             # write a sanitised copy
strypt strip --in-place *.pdf      # overwrite originals (opt-in, never the default)
strypt show --json ./docs          # machine-readable output for scripting
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
