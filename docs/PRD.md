# strypt — Product Requirements Document

**Status:** Phase 1 complete (2026-08-22) · **Last updated:** 2026-08-23
**Owner:** project owner (see `CLAUDE.md`)

---

## 0. A correction to the founding premise — read this first

strypt was conceived on the premise that `mat2` is archived and unmaintained, leaving
privacy-focused operating systems without a maintained metadata-removal tool. **That premise
is partly wrong, and this document is written on corrected footing.** Verified 2026-08-19:

| Claim | Reality as verified |
|---|---|
| mat2 is archived | The *old* home, `0xacab.org/jvoisin/mat2`, is archived and read-only. Development **moved to GitHub**. |
| mat2 is unmaintained | `github.com/jvoisin/mat2` is **active**: last push 2026-08-18, `archived: false`, 4 open issues. |
| mat2 is stale | **v0.15.0 released 2026-08-04** (added AVIF and JPEG XL support, Nemo file-manager integration, `pyproject.toml` migration). v0.14.0 was 2025-10-23. |

**What this means.** "The incumbent is dead" is not an available justification for strypt.
Anyone evaluating this project will check the mat2 repository in about thirty seconds and
find an actively developed tool that supports roughly six times as many formats. A PRD that
opens with a false obituary would destroy the project's credibility with exactly the
security-literate audience it needs.

The justification below is therefore built on differences that are true and checkable *while
mat2 is healthy*. The project owner should decide, before Phase 1 begins, whether those
differences justify the effort. They are real, but they are a narrower claim than the
original premise, and this is the single most important thing to review in this document.

---

## 1. Problem statement

Files carry identifying information their authors never see and rarely intend to share.

- A JPEG from a phone or DSLR typically embeds GPS coordinates, capture timestamp, camera
  make and model, lens, and often a camera body serial number that links every photo that
  device ever took.
- A PDF embeds an author name, an organisation, the producing software and version, and
  creation/modification timestamps — frequently the real name of someone who believed they
  were publishing anonymously.
- Editing and export pipelines add their own layers: XMP records, ICC profiles carrying
  installation-specific strings, and thumbnail images that can survive cropping and
  redaction of the visible image.

The consequences are not hypothetical or minor. Metadata in published files has located
sources, unmasked anonymous authors, and revealed the physical locations of people who were
hiding from someone dangerous. The information is invisible in every normal viewer, which is
precisely why it survives to publication.

Tools to remove it exist. What is thin is the intersection of: actively maintained, safe by
default, auditable, and deployable as a single self-contained binary with no interpreter and
no C-library dependency chain. That intersection — not the absence of any tool — is strypt's
opening.

---

## 2. What strypt is

A fast, memory-safe, single-binary tool that detects and removes hidden identifying metadata
from files so they are safer to publish or share. A Rust core library (`strypt-core`) with a
CLI front-end (`strypt-cli`), no network access in any code path, and a deliberately small
audited dependency tree.

## 3. What strypt is not

Not an encryption tool. Not a secure-deletion tool. Not a general-purpose forensics suite.
Not a steganography detector. Not an anonymity system. Scope is metadata detection and
removal, and requests that widen it get refused by default. See `docs/THREAT_MODEL.md` for
the security-relevant version of these limits.

---

## 4. Why strypt, given that mat2 is alive

These are the differentiators that survive the correction in §0. Each is independently
checkable.

**1. Deployment shape.** mat2 requires Python 3.11+ plus Poppler, Cairo, GdkPixbuf, librsvg,
`mutagen`, and ExifTool as a fallback for some formats (verified from its README,
2026-08-19). strypt targets a single statically-linked binary. This matters concretely for
air-gapped machines, live/amnesic systems, minimal containers, and any environment where
installing a Python and GObject stack is friction or an audit burden.

**2. Memory safety of the parsing path.** mat2's actual file parsing happens largely in C
libraries reached through GObject introspection. Those libraries are mature but they are the
historical home of image and PDF parser CVEs, and they are being handed adversarially
crafted files by design. strypt's parsing is safe Rust with `#![forbid(unsafe_code)]`
(ADR-0007) and a no-panic rule (ADR-0006). This is a genuine, structural difference in
attack surface — arguably the strongest single argument for the project.

**3. Licensing.** mat2 is LGPL-3.0-or-later. strypt is `MIT OR Apache-2.0` (ADR-0002),
which permits static linking into permissively-licensed tools and embedding as a library.
This widens who can build on it.

**4. Bus factor and process.** mat2 is essentially one maintainer. That is not a criticism —
it is a structural risk for software that privacy-focused operating systems depend on, and
the 0xacab-to-GitHub migration is a reminder that single-maintainer projects move and
occasionally stop. A second, independently-maintained implementation with a different
technology stack is a resilience argument, not a replacement argument.

**5. Verification rigour as a product feature.** Sustained fuzzing per format handler with
published budgets, a per-format documented-limitations page derived from actual findings, and
supply-chain gates in CI (Phase 3). The goal is that strypt's claims about what it removes
are *demonstrable*, not asserted.

**Honest counterpoint, to be stated in the README rather than hidden:** mat2 supports far
more formats, has years of field use, and is already packaged in Debian, Kali, and the
privacy-focused distributions. For most users today, mat2 is the correct recommendation.
strypt earns its place by being better on the axes above, not by mat2 being worse.

---

## 5. Target users

### 5.1 Amara — freelance photojournalist

Shoots on a DSLR and a phone, files to several outlets, sometimes from countries where
being identified as a journalist is dangerous. Handles hundreds of images per assignment.

- **Needs:** batch processing of whole directories; GPS and camera serial removal she can
  *verify*, not just trust; a preview mode showing exactly what will be removed before
  anything is written; image quality preserved, because a re-encoded JPEG is an unusable
  deliverable.
- **Distrusts:** any tool that silently re-encodes her images; any tool that says "done"
  without showing what it did; anything that touches the network while she is working.

### 5.2 Devi — source preparing a disclosure

Using Tails on a borrowed machine. Has a set of internal PDFs and photographs. Limited
technical depth, extremely high stakes, no second chance if the tool leaks something.

- **Needs:** to work fully offline with no configuration; safe defaults with no dangerous
  options to get wrong; clear, unambiguous output about what remains; honesty about limits,
  because "clean" that means "mostly clean" could identify her.
- **Distrusts:** anything that makes an outbound connection; anything that claims perfection;
  anything requiring an install process she cannot complete or verify on an amnesic system.

### 5.3 Marcus — legal aid caseworker

Processes client intake documents — scanned PDFs, phone photos of injuries and documents —
before filing or sharing with partner organisations. Not technical. Works under time
pressure with a queue of cases.

- **Needs:** obvious right-click or one-command operation; originals never destroyed by
  default; unambiguous success/failure so a mistake is never silent; reliability across a
  managed Windows fleet he does not administer.
- **Distrusts:** a tool that overwrites originals; a CLI that fails quietly; anything his IT
  department would flag as unapproved network software.

### 5.4 Sam — technical lead at a domestic violence support organisation

Automates intake sanitisation. Wants metadata scrubbing wired into a pipeline so caseworkers
cannot forget it. Small budget, no security team, personally accountable if a survivor's
location leaks through a photograph.

- **Needs:** machine-readable output (JSON) and reliable non-zero exit codes for scripting;
  a library or stable CLI contract that will not break under him; deterministic behaviour;
  an auditable dependency tree he can justify to a board.
- **Distrusts:** unstable interfaces, unpinnable versions, opaque dependency trees, and any
  tool whose failure mode is "silently did nothing and returned success."

---

## 6. Goals — v1 (Phase 1)

1. Reliably remove metadata from JPEG, PNG, WebP, and PDF. Scope locked per ADR-0005.
2. A `show` / dry-run mode reporting what metadata is present without modifying anything.
3. Safe defaults: copy-out to a new file rather than in-place mutation, unless in-place is
   explicitly requested.
4. Batch processing over multiple files and directories with accurate per-file status.
5. Machine-readable (JSON) output mode and meaningful, documented exit codes.
6. Zero network access in any code path, structurally enforced (ADR-0004).
7. No panics on any input, including deliberately malformed input, demonstrated by fuzzing.
8. A single self-contained binary on Linux, macOS, and Windows.

## 7. Non-goals — v1

Office formats (docx/xlsx/pptx/ODF), audio/video containers, archives, SVG, EPUB — all
Phase 2. GUI — Phase 5. File-manager integration — Phase 6. Encryption, secure deletion,
steganography detection, content redaction, writing-style anonymisation, and any form of
network functionality — permanently out of scope.

---

## 8. Functional requirements

### 8.1 Format coverage (Phase 1 — locked, ADR-0005)

| Format | Metadata targeted |
|---|---|
| JPEG | EXIF (incl. GPS IFD, MakerNote), XMP, IPTC/IIM, ICC profile, JFIF/COM comment segments, embedded thumbnails |
| PNG | Textual chunks (`tEXt`, `zTXt`, `iTXt`), timestamp (`tIME`), ICC profile (`iCCP`), EXIF (`eXIf`), other non-critical ancillary chunks |
| WebP | RIFF `EXIF`, `XMP `, and `ICCP` chunks, unknown chunks at the top level and inside `ANMF` animation frames, and data past the declared RIFF length. The `VP8X` header's ICC, Exif, and XMP flag bits are cleared to match (ADR-0023) |
| PDF | Document Information Dictionary (Author, Creator, Producer, Title, Subject, Keywords, CreationDate, ModDate), XMP metadata streams (document and object level), document ID, embedded-file and annotation metadata, orphaned/incremental-update remnants |

Two requirements that apply to every handler:

- **Preserve image data.** Removing an EXIF segment must not re-encode pixels. This is a
  hard requirement, from Amara's persona — a lossy round-trip is an unacceptable outcome
  and is a meaningful behavioural difference from mat2's default (non-`-L`) mode.
- **Fail closed.** If a handler cannot confidently strip a file, it reports failure and
  leaves no partially-sanitised output that could be mistaken for clean.

### 8.2 CLI behaviour

- `strypt show <files...>` — report metadata found; never write. Exits non-zero if metadata
  is found, so it composes in scripts and pre-commit checks.
- `strypt strip <files...>` — write sanitised output. Default is copy-out to a new file;
  `--in-place` is opt-in and never the default.
- `--json` — machine-readable output on stdout, diagnostics on stderr, stable schema.
- Batch: accept multiple paths and directories; `--recursive` opt-in; continue past
  individual failures while reporting them, and reflect any failure in the exit code.
- Unknown or unsupported formats are an explicit, clearly-reported outcome — never a silent
  pass-through, and never a silent copy of the original.
- Exit codes: `0` success/clean · `1` metadata found (`show`) or one or more files failed
  (`strip`) · `2` usage error · distinct codes for I/O and unsupported-format conditions,
  documented in `INSTRUCTIONS.md` and stable across releases.
- Output must state what was removed, not merely that something was.

### 8.3 Safety behaviours

- Never modify the input file unless `--in-place` is given.
- In-place writes go through a temporary file and atomic rename, so an interruption cannot
  leave a truncated or half-stripped file where the original was.
- Never write output over an existing file without `--force`.
- Preserve neither source timestamps nor permissions onto output by default where doing so
  would itself leak information — this needs an explicit decision and an ADR in Phase 1.

---

## 9. Non-functional requirements

- **No network access.** Hard constraint, ADR-0004. Enforced by CI gate, not documentation.
- **Platforms.** Linux is primary (target-user gravity and the live-OS story). macOS and
  Windows are supported and CI-tested from Phase 1. Note that `cargo-fuzz` does not support
  Windows (verified 2026-08-19), so fuzzing is a Linux/macOS CI activity.
- **Performance. Measured 2026-08-20**, replacing the order-of-magnitude intentions this
  section previously carried. Reproduce with `./scripts/measure-performance.sh`.

  | Case | Measured | Prior intention |
  |---|---|---|
  | Startup (`--version`) | **2.5 ms** | under ~50 ms |
  | `strip` a 3.3 MB JPEG | **10.9 ms** | 5 MB "well under a second" |
  | `strip` a 4.1 MB PNG | **9.1 ms** | — |
  | `strip` a 1.1 MB WebP | **7.8 ms** | — |
  | `show` a 3.3 MB JPEG | **4.7 ms** | — |
  | Batch of 3000 JPEGs | **10.4 s** (3.5 ms/file) | thousands of files |
  | Peak RSS, 3000-file batch | **3.0 MB** | no unbounded growth |

  Every intention is met with substantial margin. The memory claim is the one that needed
  volume to demonstrate rather than assert: peak RSS was 2.4 MB over 200 files and 3.0 MB over
  3000 — fifteen times the work for 0.6 MB more memory, so cost tracks the largest single file
  rather than the batch.

  **Read these as a floor, not a specification.** They are one machine (Apple Silicon, macOS,
  11 cores), taken while a fuzzing run occupied three of those cores, so they understate rather
  than flatter. Median of 15 runs; the script reports the best run too. Linux and Windows are
  unmeasured. Nothing here is a commitment — no supported workload has a stated time budget,
  and correctness outranks speed everywhere the two conflict.

- **Binary size.** Aim for a release binary in the low tens of megabytes or below;
  a size regression is a signal that dependency footprint has drifted (ADR-0008).
  **Measured 2026-08-20: 1.26 MB** release binary, macOS arm64 — comfortably inside the aim,
  and a useful baseline for noticing drift.
- **Determinism.** Same input plus same version yields byte-identical output. This makes
  differential testing and the Phase 5 GUI-parity check possible, and it means stripped
  output does not itself carry a random nonce.
- **Live-OS compatibility.** Must run correctly under Tails and Qubes-Whonix constraints:
  read-only system filesystem, limited writable space, no network. **Flagged for explicit
  validation in Phase 3 — assumed, not verified, as of this writing.**

---

## 10. Success metrics

Not a commercial product; metrics are about trustworthiness and reach.

**Correctness and rigour (primary):**
- Zero open crash/hang findings from fuzzing at every release tag.
- A published minimum fuzzing budget met per format handler before v1.0 (Phase 3 sets the
  concrete number).
- A per-format known-limitations page derived from real findings, not written speculatively.
- Differential testing against mat2 and ExifTool on a shared corpus: for the four Phase 1
  formats, strypt should remove at least what mat2 removes. Any field where it removes less
  is either a bug or a documented limitation — never silently ignored.

**Reach (secondary):**
- crates.io downloads and GitHub stars, tracked but not optimised for.
- Packaged in at least one mainstream Linux distribution (Phase 4).
- **Stretch:** substantive engagement with Tails and/or Qubes-Whonix maintainers about
  inclusion (Phase 7). Note this is a *conversation* metric, not an inclusion promise — and
  given mat2's active maintenance, inclusion as an *addition* is more plausible than
  inclusion as a *replacement*.

---

## 11. Competitive and adjacent landscape

All verified 2026-08-19; re-verify before quoting.

**mat2** — Python 3.11+, LGPL-3.0-or-later, actively maintained on GitHub (last push
2026-08-18; v0.15.0 on 2026-08-04). Supports approximately: avi, bmp, css, epub/ncx, flac,
gif, jpeg, m4a/mp2/mp3, mp4, ODF family, opus/oga/spx, pdf, png, ppm, OOXML family, svg,
tar family, tiff, torrent, wav, wmv, zip, webp, avif, jxl. Depends on Poppler, Cairo,
GdkPixbuf, librsvg, mutagen, and ExifTool as a fallback. Ships Nautilus, Dolphin, and (as of
0.15.0) Nemo file-manager extensions. Offers a lightweight mode (`-L`) that preserves file
data at the cost of removing less. **Two points worth internalising:** its README explicitly
states that showing no metadata does not mean a file is clean — intellectual honesty strypt
should inherit rather than try to out-market; and it *removed* bubblewrap sandboxing in
0.14.0, which is directly relevant to strypt's Phase 3 sandboxing investigation.

**ExifTool** — Perl, extraordinarily broad format and tag coverage, actively maintained, the
de-facto reference implementation for metadata. Oriented at power users; a general-purpose
read/write tool rather than a safe-by-default scrubber, and its flexibility is a liability
for non-expert users who can easily believe they removed more than they did. Not a
competitor so much as the yardstick strypt tests against.

**Metadata Cleaner** — GTK GUI over mat2. Inherits mat2's format coverage and dependency
chain. Evidence that the GUI need is real (relevant to Phase 5) and that a GUI wrapping a
solid core is a viable shape.

**ExifCleaner / ExifEraser** — Electron desktop and Android tools respectively, image-focused,
convenience-oriented, with maintenance activity that should be re-verified before citing.
Neither targets the auditability bar strypt is aiming at.

**The gap strypt fills:** a maintained, permissively-licensed, memory-safe, single-binary
scrubber with safe defaults and demonstrable verification rigour. Each existing tool has
some of these; none has all of them.

---

## 12. Risks

**The premise risk (highest).** mat2 is alive and healthy, so strypt must compete on merit
rather than fill a vacuum. *Mitigation:* compete on the five differentiators in §4, state
them honestly, and recommend mat2 where it is genuinely the better answer. If the owner
concludes those differentiators do not justify the effort, that conclusion is best reached
now, in Phase 0 — this is the decision this document exists to inform.

**Overclaiming.** No tool can guarantee complete metadata removal from complex formats.
Overclaiming here is not marketing puffery; it can get someone hurt. *Mitigation:* inherit
mat2's honesty. Never use "guaranteed", "complete", or "100%" in user-facing text.
`docs/THREAT_MODEL.md` states the limits explicitly and the README links it prominently.

**Scope creep on formats.** Format requests will be constant and each looks small.
*Mitigation:* ADR-0005 locks Phase 1; expansion requires a superseding ADR.

**PDF is genuinely hard.** Incremental updates, object streams, cross-reference streams,
encryption, linearisation, and metadata in half a dozen places. A naive strip leaves data in
orphaned objects. *Mitigation:* treat PDF as the hardest Phase 1 deliverable, budget
accordingly, fuzz hardest, and document limitations honestly rather than claiming coverage.

**Rust ecosystem gaps.** Some formats mat2 supports have no mature pure-Rust parser.
*Mitigation:* accept slower format expansion rather than pulling in C dependencies, which
would forfeit the memory-safety differentiator that is strypt's strongest argument.

**Under-investment in fuzzing.** The easiest corner to cut under release pressure, and
cutting it removes the main evidence for strypt's central claim. *Mitigation:* Phase 3 exit
criteria are explicit that this phase is not compressible.

**Single-maintainer risk applies to strypt too.** The bus-factor criticism of mat2 in §4 is
one strypt must not simply repeat. *Mitigation:* Phase 7's contribution-pipeline work, and
documentation good enough for someone else to take over.
