# strypt

**Remove hidden metadata from files before you share them.**

Photos carry GPS coordinates and camera serial numbers. PDFs carry author names, organisation
names, and editing timestamps. None of it is visible in a normal viewer, and all of it
survives to publication. strypt finds it and strips it out.

A single self-contained binary. Memory-safe Rust. **No network access in any code path.**

---

> ### ⚠️ Status: Phase 0 — Foundation
>
> **strypt is not usable yet.** There is no code — this repository currently contains the
> design documents, the threat model, and the decision log that Phase 1 will be built
> against. There is nothing to install.
>
> **If you need to strip metadata today, use [mat2](https://github.com/jvoisin/mat2)** or
> [ExifTool](https://exiftool.org/). mat2 is actively maintained, supports far more formats,
> and is already packaged in most Linux distributions. See [`docs/PRD.md`](docs/PRD.md) §4
> for an honest account of where strypt intends to differ.

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
