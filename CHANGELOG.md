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

- **A sustained-fuzzing runner, `scripts/fuzz-sustained.sh`.** The fuzzing commands documented
  until now were 300-second smoke tests — enough to prove a target still runs, not enough to
  stand behind. The runner runs any set of targets in parallel for a chosen duration and
  records, per target, a coverage curve against elapsed time, whether coverage had stopped
  climbing by the end of the run, and any crash artefact. It exits non-zero if a target
  crashed. This is measurement infrastructure for a release criterion, not a new tool feature:
  the curves are what will replace ADR-0014's provisional 100-CPU-hours-per-handler figure,
  which was written before any parser existed and which that ADR already flags as a hypothesis
  to revise against real data.

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

### Fixed

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
