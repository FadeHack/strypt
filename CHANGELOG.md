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
- Fuzz targets for the PDF handler, the JPEG handler, and format detection, with seed
  corpora that include deliberately malformed files. They assert invariants — that stripped
  output re-inspects clean and that stripping is idempotent — not merely that nothing
  crashed.
- Test corpus with a manifest and a deterministic generator (`corpus/tools/`). No fixture
  contains real personal data, by construction.

### Fixed

- PDF test fixtures are marked `binary` in `.gitattributes`. Without it, Git classified them
  as text — they are mostly printable ASCII — and rewrote every LF to CRLF when checking out
  on Windows, which shifts every offset in a PDF's cross-reference table and stops the file
  parsing at all. Caught by CI as fifteen failures on `windows-latest` and none elsewhere.
  A test now checks fixture integrity directly, so this cannot recur silently on any platform.

### Known limitations in this release

Read these before relying on the tool. They are limitations, not bugs, and each is deliberate:

- **Only PDF and JPEG are handled so far.** PNG and WebP are in progress; until they land,
  those files are reported as unsupported rather than processed.
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
- **Encrypted PDFs are refused.** strypt will not emit a decrypted copy of your document, so
  a password-protected file cannot be stripped at present.
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
