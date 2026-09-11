# strypt — Testing Strategy

**Status:** Phase 1 complete (2026-08-22) · **Last updated:** 2026-08-23

For strypt, testing is not quality assurance — it is the evidence for the product's central
claim. A metadata scrubber nobody can verify is a metadata scrubber nobody should use.

---

## 1. The invariants everything tests against

Five properties. Every layer below exists to check some subset of them.

1. **Correctness.** Metadata the handler claims to remove is gone from the output.
2. **Preservation.** The payload is unchanged. For images this means pixel-identical after
   decoding; for PDFs, visually and textually equivalent.
3. **Idempotence.** `strip(strip(x))` is byte-identical to `strip(x)`.
4. **Determinism.** The same input and the same version yield byte-identical output, on every
   platform.
5. **Robustness.** No panic, crash, hang, unbounded allocation, or stack overflow on any
   input, including deliberately hostile input.

Note that 3 and 4 are what make differential testing and the Phase 5 GUI byte-identity check
possible. They are not stylistic preferences.

---

## 2. Layers

### 2.1 Unit tests — per module, in `strypt-core`

Segment and chunk walking against hand-constructed byte sequences; boundary conditions
(zero-length, truncated at every offset, length fields exceeding the file); error paths, which
are the ones production will actually exercise on hostile input.

Every unit test that constructs a byte sequence should say in a comment what real-world
structure it represents. A test asserting on an opaque byte array teaches a future reader
nothing when it fails.

### 2.2 Integration tests — CLI and library end to end

Full `show` and `strip` flows over the corpus. CLI contract: exit codes, JSON schema
stability, stdout/stderr separation. Safety behaviours specifically:

- Input is not modified without `--in-place`.
- An existing file is not overwritten without `--force`.
- Interrupting an in-place strip never leaves a truncated or half-stripped file where the
  original was.
- An unsupported format is reported as unsupported — never silently copied, never reported
  as success.

That last one deserves a dedicated test per release. It is the failure mode from
`docs/THREAT_MODEL.md` §5.4 and it is the one a refactor is most likely to reintroduce.

### 2.3 Property-based tests — planned, **not adopted in Phase 1**

> **`proptest` is not a dependency and no property tests exist.** This section is the Phase 0
> plan, kept because the reasoning still applies if the layer is added later. Do not read it
> as describing tests that run.
>
> **Invariants 3 and 4 are covered anyway**, by two other layers: every handler's integration
> tests assert byte-identical idempotence and determinism across the whole committed corpus
> (`stripping_is_idempotent_byte_for_byte`, `stripping_is_deterministic_for_every_fixture`),
> and the fuzz targets assert idempotence on *arbitrary* input, which is a stronger generator
> than a `proptest` strategy hand-written to produce valid files. What is genuinely missing is
> the structural exploration below — generated metadata of arbitrary size, encoding, and
> nesting. That gap is real and is a Phase 3 candidate, not a Phase 1 hole to backfill.

The plan, if this layer is added. Best suited to invariants 3 and 4, and to
generated-structure exploration:

- Idempotence and determinism across generated valid files.
- Round-trip: parse → serialise without stripping produces an equivalent file.
- Generated metadata of arbitrary size, encoding, and nesting is removed regardless of shape
  — including empty values, very long values, non-UTF-8 bytes, and deeply nested structures.

Where `proptest` and fuzzing overlap, prefer fuzzing for adversarial input and `proptest`
for structural invariants over *valid* inputs. They answer different questions.

### 2.4 Fuzzing — `cargo-fuzz` 0.13.2 (verified 2026-08-19, MIT OR Apache-2.0)

The primary evidence for invariant 5, and non-optional for any handler.

**Constraints to design CI around:** `cargo-fuzz` requires a nightly toolchain and supports
x86-64 and aarch64 on Unix-like systems only — **not Windows** (verified 2026-08-19). Fuzzing
therefore runs on Linux (and optionally macOS) while Windows is covered by the other layers.

**Requirements.**
- One target per format handler, minimum. Targets for `detect` and for any shared container
  layer (the ZIP layer in Phase 2) as well — a shared parser reached by several handlers is a
  shared risk.
- Targets exercise both `inspect` and `strip`, and assert the invariants: strip output must
  re-inspect clean, and strip must be idempotent. **A target that only checks "did not crash"
  is leaving most of its value unclaimed** — assertion-carrying targets turn the fuzzer into
  a correctness checker, not just a crash finder.
- Seed corpora committed to `corpus/`, containing valid files from diverse producers and
  deliberately malformed variants (truncated, bit-flipped, lying length fields, cyclic
  references).
- Structure-aware fuzzing via the `Arbitrary` trait for object-graph formats such as PDF,
  where random bytes rarely reach deep code paths.
- **Hangs, OOMs, and slow units are findings**, ranked with crashes. For safe Rust these are
  the realistic vulnerability class (`docs/THREAT_MODEL.md` §5.1), so a policy that only
  counts crashes measures the wrong thing.

**Budget — ADR-0044, measured from 80 coverage curves.** A handler certifies on **one run of at
least 24 CPU-hours** since its last substantive change, shared modules included, whose curve
classifies **saturated** under `scripts/fuzz-plateau.py`: six equal windows, and no window after
the first both gaining over 1% of final coverage and doubling its predecessor. `scripts/fuzz-tally.py`
decides certification, from the most recent qualifying run.

ADR-0014's earlier bar — 100 CPU-hours plus "no new edge in the final 25%" — is superseded, and so
is the `plateau` column in any `summary.md` predating 2026-09-11. A flat curve is *not* sufficient
evidence of saturation: `ogg` went flat for 24 hours and then found 140 edges in one window.

**Continuous fuzzing.** Local batches, not CI (ADR-0046). After a handler change, re-fuzz
whatever `scripts/fuzz-tally.py` shows has lost certification. OSS-Fuzz is declined until strypt has users.

### 2.5 Differential testing — against mat2 and ExifTool

The strongest available correctness signal, because it compares against implementations with
years of accumulated format knowledge.

For every corpus file: run strypt, then ask ExifTool and mat2 what remains in strypt's
output. Any field ExifTool still reports is either a bug or a documented limitation — and the
decision between those two must be explicit, recorded, and never made by silence.

Also run the reverse comparison: metadata mat2 removes that strypt does not. That gap list is
the Phase 2 backlog and the seed of the known-limitations page.

Practical note: ExifTool and mat2 are external tools, so this suite runs in a dedicated CI job
that may be allowed to lag rather than gating every commit. It must run before every release.
It reads output files only — **it never becomes a runtime dependency** (ADR-0004, ADR-0008).

### 2.6 Regression tests — mandatory, no exceptions

**Every bug found by fuzzing, differential testing, or a user report gets a regression test
committed before the fix is accepted.** The offending input goes into the corpus. This is the
single testing policy with no discretion attached: a fixed bug without a regression test is
an unfixed bug with a delay.

---

### 2.7 Filesystem-constraints matrix — Phase 3, ADR-0043

Everything above feeds bytes to a parser. This layer feeds a **hostile filesystem** to the write
path, which is the other place a fail-closed promise can break — and the place where breaking it
leaves a half-written file on a journalist's USB stick rather than a metadata leak.

Cases, each run against the real CLI binary on Linux in CI: a read-only destination directory; a
full volume, so `ENOSPC` lands mid-write; removable-media filesystems with no Unix permission
model (`vfat`, `exfat`); a destination on a different mount from `TMPDIR`; and an unwritable
directory holding a writable file. Built from `tmpfs` and loopback images; mounting needs sudo,
which CI runners grant. `scripts/fs-matrix.sh` runs it.

**Each case asserts the contract, not the absence of a panic:** the destination is replaced in
full or left untouched, no `.strypt-*.tmp` survives, and no success is reported for a file that
was not written. Like every other gate here, the matrix must be **proven to fail** when that
contract is deliberately broken: `scripts/prove-fs-matrix.sh` plants five `io.rs` mutants and
requires each to be caught by its own case.

**This replaces booting Tails and Qubes-Whonix** (ADR-0043), and it does not test those
distributions — a green matrix is never "validated on Tails".

---

## 3. The corpus

`corpus/` holds the test fixtures. Its quality bounds the value of everything above.

**Required diversity for Phase 1:**
- JPEG: multiple camera makes, multiple phone makes, scanner output, images processed through
  Lightroom/GIMP/Photoshop, images already stripped by other tools, images with MakerNote
  data (the most vendor-specific and least standardised region), images with embedded
  thumbnails that differ from the main image.
- PNG: with and without text chunks, ICC profiles, `eXIf` chunks, interlaced and not.
- WebP: lossy, lossless, animated, with and without EXIF/XMP/ICC chunks.
- PDF: LaTeX, Word, LibreOffice, Acrobat, scanner output, browser print-to-PDF, files with
  incremental updates, linearised files, files with embedded attachments and annotations.

**Rules.**
- **No file may contain real personal data.** Fixtures are committed publicly and forever;
  a corpus that leaks someone's location is an unusually humiliating failure for this project
  in particular. Generate fixtures or use files with deliberately synthetic metadata.
- Every fixture is documented in a manifest: origin, what metadata it carries, what it tests.
- Fixtures from bug reports are sanitised before committing, and if a reporter's file cannot
  be sanitised, reproduce the structure synthetically instead.
- Keep binaries small. Large fixtures belong in a fetched-on-demand corpus, not in git
  history forever.

**Sanitising a real-producer file, in practice.** `real-producer-corpus/sanitise_corpus.py`
runs on every corpus build and replaces real names, the camera serial, and live GPS with
synthetic values while preserving the producer's structure — a Canon's maker-note layout,
LaTeX's object numbering. Structure is the entire reason to keep a real-producer fixture; a
regenerated file would not carry the quirks it exists to test. Two findings from writing it are
worth knowing before sanitising anything else:

- **Never use `exiftool` to sanitise a PDF.** It writes an incremental update and leaves the
  superseded object in place, so the original value stays in the bytes while `exiftool` reports
  the new one. Verified on `GeoTopo-komprimiert.pdf`: after setting `Author`, `Martin Thoma` was
  still present. This is exactly the defect class strypt exists to catch, and it would have
  shipped a corpus that looked clean. Same-length byte substitution is used instead, which keeps
  every offset and the cross-reference table valid; `qpdf --check` confirms it.
- **A silent no-op looks like success.** `-Canon:OwnerName` on a CIFF-format file and
  `-XMP-exif:SerialNumber` on a PNG both exit 0 and change nothing. Any sanitiser needs an
  independent verification pass that re-reads the bytes; do not trust the writing tool's exit
  code.

---

## 4. CI

| Job | Platforms | Gate |
|---|---|---|
| `cargo fmt --check` | Linux | hard |
| `cargo clippy -- -D warnings` | Linux | hard |
| `cargo test` | Linux, macOS, Windows | hard |
| `cargo-deny` (advisories, licenses, bans, sources) | Linux | hard — all four from 2026-09-11 (ADR-0045) |
| No-network dependency-graph check | Linux | **hard from Phase 0** |
| Gate proof — each gate fails on a planted violation (`scripts/prove-gates.sh`) | Linux | hard from Phase 3 |
| MSRV build | Linux | hard |
| Fuzz smoke (short run per target) | Linux | hard from Phase 1 |
| Continuous fuzzing (long run) | local only | declined in CI (ADR-0046) |
| Filesystem-constraints matrix (§2.7) | Linux | hard from Phase 3 |
| Differential vs mat2/ExifTool | Linux | scheduled + pre-release |

Two notes. The no-network check is hard from the very beginning because retrofitting an
invariant after a violation lands is much harder than holding it from the start. And every
gate must be **proven to fail** when deliberately violated — an untested gate provides
confidence without providing protection, which is worse than having none. For the supply-chain
gates that proof is automated and runs on every push; the filesystem matrix (§2.7) owes the same.

---

## 5. Coverage

Line coverage is tracked but not targeted. High coverage of happy paths in a parser means
very little; what matters is whether error paths and boundary conditions are exercised, and
fuzzing edge-coverage is a better measure of that than a line-coverage percentage. Do not set
a coverage number as an exit criterion — it optimises for the wrong behaviour and would be
satisfied by tests that assert nothing about the invariants in §1.

---

## 6. Definition of done for a format handler

1. Unit tests for parsing, boundaries, and error paths.
2. Integration tests through the CLI.
3. Idempotence and determinism asserted byte-for-byte over every corpus fixture, **and**
   idempotence asserted on arbitrary input by the handler's fuzz target. (The Phase 0 plan
   put this on `proptest`; §2.3 records why it is not used and what that does and does not
   cost.)
4. A fuzz target with assertions plus a committed seed corpus.
5. Differential comparison against mat2 and ExifTool, with every gap either fixed or
   documented as a known limitation.
6. Pixel-identity (images) or content-equivalence (documents) verification.
7. `docs/THREAT_MODEL.md` updated for the format.
8. Known limitations documented.
9. Zero open crash, hang, or OOM findings.
