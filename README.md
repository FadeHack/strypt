# strypt

> ## Status: Phase 0 (Foundation) complete — Phase 1 not started
>
> **Do not use strypt to protect anything that matters. It cannot yet: no file format is
> implemented.** `strypt strip` is a stub that prints a notice and exits 2.
>
> What exists today is the foundation: design documents, threat model, decision log, a Cargo
> workspace, and the enforcement gates described below. What does not exist is the part that
> removes metadata.
>
> Phases are defined in [`docs/ROADMAP.md`](docs/ROADMAP.md), with exit criteria per phase.
> This table tracks against those definitions:
>
> | Phase | Status |
> |---|---|
> | 0 — Foundation: docs, workspace, CI gates | ✅ Complete, all exit criteria met |
> | 1 — Core engine + CLI (JPEG, PNG, WebP, PDF) | ⬜ Not started |
> | 2 — Expanded formats (Office, audio/video) | ⬜ Not started |
> | 3 — Hardening: sustained fuzzing, live-OS validation | ⬜ Not started |
> | 4 — Distribution: binaries, checksums, packaging | ⬜ Not started |
> | 5 — GUI · 6 — File-manager integration · 7 — Community | ⬜ Not started |
>
> **Specifically, as of Phase 0:**
>
> - **Built and verified:** a two-crate workspace; `unsafe` forbidden crate-wide and enforced
>   by the compiler; panic-capable lints denied in the parsing crate; CI on Linux, macOS, and
>   Windows; a dependency-graph gate that fails the build on any networking crate, including
>   transitive ones, tested by deliberate violation; `cargo-deny` bans/licenses/sources as
>   hard gates.
> - **Not built:** every format handler, metadata detection, the CLI itself.
> - **Not fuzzed:** nothing. There is no parser to fuzz. Fuzzing is Phase 1 (per-handler
>   harnesses) and Phase 3 (sustained budgets).
> - **Not audited:** no external security review has taken place, and none is scheduled. The
>   threat model in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is self-assessed.
> - **Not validated on Tails or Qubes-Whonix.** Compatibility is an explicit assumption
>   throughout the docs, converted to fact in Phase 3.
>
> **If you need to strip metadata today, use [mat2](https://github.com/jvoisin/mat2) or
> [ExifTool](https://exiftool.org/).** Both are mature and actively maintained; mat2 supports
> roughly six times as many formats and is already packaged in most Linux distributions.
> [`docs/PRD.md`](docs/PRD.md) §4 sets out where strypt intends to differ, and §0 records a
> correction to this project's own founding premise.
>
> Development uses an AI coding agent under a defined process — see
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

## Planned scope (Phase 1)

| Format | What gets removed |
|---|---|
| JPEG | EXIF (incl. GPS and MakerNote), XMP, IPTC, ICC profile, comments, embedded thumbnails |
| PNG | Text chunks, timestamps, ICC profile, EXIF chunk, other ancillary chunks |
| WebP | EXIF, XMP, and ICC chunks |
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

Not available yet — Phase 4. Prebuilt binaries, checksums, crates.io, and a Homebrew formula
are planned. See [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
