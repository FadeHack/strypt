# CLAUDE.md — working agreement for strypt

Read this fully before doing anything in this repository.

---

## 1. What strypt is

strypt is a metadata removal tool: a Rust library (`strypt-core`) plus a CLI (`strypt`, the
crate at `crates/strypt/`; it was called `strypt-cli` until ADR-0026)
that detects and strips hidden identifying metadata — GPS coordinates, device serial numbers,
author names, timestamps, editing history — from files so they are safer to publish. Its
users include journalists protecting sources, whistleblowers, domestic violence survivors,
and human rights investigators. For some of them, a leak through this tool is a physical
safety event, not an inconvenience.

strypt is **not** an encryption tool, a secure-deletion tool, a forensics suite, a redaction
tool, or a steganography detector. Requests to widen scope in those directions are declined
by default.

## 2. Current phase: **Phase 2 in progress — OOXML, OpenDocument and TIFF done; the GIF handler has landed and owes its fuzz run (2026-08-26)**

**Phases 0 and 1 are complete. Phase 2 opened 2026-08-23 (ADR-0027) and its first two format
groups have landed.** `strypt show` and `strypt strip` process PDF, JPEG, PNG, WebP, TIFF, GIF, `.docx`,
`.xlsx`, `.pptx`, `.odt`, `.ods`, and `.odp`; every other format is reported as unsupported and
never passed through untouched. Landed: bounded ingest,
content-sniffing detection, the handler registry and trait, the post-strip verification pass,
structured reports, typed errors, the atomic write path, the full CLI, the four Phase 1 handlers
with shared Exif and XMP readers, five fuzz targets, a generated fixture corpus for all four
formats, and — as of 2026-08-20 — a fetch-on-demand real-producer corpus of 102 files that all
four handlers have been swept over (`docs/THREAT_MODEL.md` §7.5).

**Phase 1 closed on 2026-08-22.** All seven numbered exit criteria are met, and the last
non-numbered item — committed real-producer fixtures — is resolved by ADR-0025, which decided
*not* to commit them.

**Phase 2 opened 2026-08-23 by ADR-0027**, which supersedes ADR-0005's scope lock and replaces
it with a narrower one. **The scope is still locked**: the phase covers exactly the four format
groups in `docs/ROADMAP.md` Phase 2, they land one at a time in that order, and a group is not
started until the previous one meets the Phase 1 bar in full. "Phase 2 is open" is not "scope is
open" — adding a format outside those groups still needs a superseding ADR.

**Group 1 — Office Open XML — is done (2026-08-23).** Landed: a hand-written ZIP container layer
under `container/zip.rs` (ADR-0028 — *not* a dependency, and not a general-purpose ZIP
implementation), a one-level descent into embedded images (ADR-0029), the handler and its XML
scanner (ADR-0030), `ooxml` and `zip` fuzz targets, 20 fixtures, 26 integration tests, a clean
mat2/ExifTool differential, and `docs/THREAT_MODEL.md` §7.6.

**Group 2 — OpenDocument — is done (2026-08-24).** `.odt`, `.ods`, `.odp`. Landed: the handler
and its rules (ADR-0031), an `odf` fuzz target, 14 fixtures plus 8 malformed ones, 33 integration
tests, a clean mat2/ExifTool differential, and `docs/THREAT_MODEL.md` §7.7. Two internal
boundaries moved so the two package formats share rather than duplicate: the XML scanner is now
`formats/xml.rs` (rules per format beside each handler), and the ZIP-package machinery is now
`container/package.rs` — which is what keeps ADR-0029's one-level descent existing exactly once.

**Group 3 — additional images — is in progress, split into five tranches by ADR-0032**: TIFF,
GIF, HEIF+AVIF, SVG, JPEG XL, in that order, each meeting the Phase 1 bar before the next opens.
The split exists because this group, unlike the first two, has no shared container — six formats
with nothing in common — and one lump would hold a finished handler hostage to the hardest member.

**Tranche 1 — TIFF — is done (2026-08-26).** Landed: the
handler, its allow-list of structural tags, a `tiff` fuzz target, 10 fixtures plus 6 malformed
with their generator, 17 integration tests, 14 unit tests, `docs/THREAT_MODEL.md` §7.8.
**ADR-0033 is required reading before touching it**: TIFF is the one format strypt *rebuilds*
rather than edits, because its metadata is its file structure and there is no block to drop.
Tags reach the output only from an allow-list of what the image cannot be decoded without, so an
unknown vendor tag cannot survive by going unrecognised — the inverse of the deletion rule that
governs OOXML and OpenDocument, and deliberately so.

The mat2/ExifTool differential landed with the handler and is clean (`scripts/tiff-differential.sh`,
10 fixtures, zero tags surviving either tool, verified able to fail).

**Its sustained-fuzzing debt is cleared as of 2026-08-26**: `tiff` and `detect` ran twelve hours
each in parallel — **24.00 CPU-hours budgeted, 24.00 delivered, both clean**, `tiff` at
1,417,537,939 inputs and `detect` at 2,991,380,340. **Both plateaued** — `tiff`'s last gain at
17,217s of 43,203s, `detect`'s at one second — which is ADR-0014 **Phase 3** evidence and **not**
a Phase 1 gate. It is the first plateau evidence at the opposite end from PDF, and it still does
not license superseding ADR-0014; do not conflate the two bars.

Deliberate limitations, already recorded: output
is never byte-identical to input even for a clean file (idempotence is, and is tested); metadata
inside the compressed image data is out of reach, where **mat2's re-rendering default is the
better recommendation**; ICC profiles are removed, trading colour fidelity; BigTIFF and
inconsistent strip geometry are refused.

**Tranche 2 — GIF — landed 2026-08-26, and is NOT complete.** Landed: the handler, a `gif` fuzz
target, 14 fixtures plus 6 malformed with their generator (which carries its own LZW encoder, so
every fixture really decodes and mat2 can open it), 22 integration tests, 20 unit tests, a clean
mat2/ExifTool differential, and `docs/THREAT_MODEL.md` §7.9. GIF is a flat block list, so removal
is deletion and **a clean file comes back byte-identical** — the only format in the tree that can
promise that of a whole file.

**The one judgement call is the loop count, and it is settled: `NETSCAPE2.0` and `ANIMEXTS1.0` are
kept.** They carry an animation's loop count and nothing else — no person, device, place, or time,
and byte-identical between any two looping files — while every *other* application extension is
removed on an allow-list, unknown vendor identifiers included. Removing them would turn a user's
looping animation into a one-shot, which is a change to what the file does. They are declared in
the report's `retained` list, and `scripts/gif-differential.sh` asserts the loop count survives
rather than merely excluding it from the comparison. A plain-text extension is removed *together
with* the graphic control block in front of it, because that block would otherwise retime the next
image.

**Its sustained fuzzing debt is OWED, and the tranche does not meet the Phase 1 bar until it is
paid.** `gif` has had a 3-minute smoke run only (9,215,373 inputs, clean). The run to make is
`./scripts/fuzz-sustained.sh -d 43200 gif detect` — `detect` because its parser changed in the
same work. **Until it comes back clean, ADR-0032 does not permit tranche 3 to open.**

**Tranches 3–5 and Group 4 are NOT started.** SVG owes its own ADR before its tranche opens. The
"check before referencing a later-phase artefact" rule now applies *within* this phase too.

**Qualifications on the two landed groups, which are real:**

- **OOXML's sustained-run debt is cleared** — `ooxml` and `zip` each ran a clean 12 hours on
  2026-08-24. **OpenDocument's is cleared too, as of 2026-08-25**: `odf`, `zip`, `ooxml` and `pdf`
  ran 12 hours each in parallel — **48.00 CPU-hours budgeted, 48.00 delivered, all four clean**,
  zero crashes, hangs or OOMs. `odf` executed 382M inputs; `pdf` was included because its two most
  recent fixes had had only a smoke run. Three of the four had **not plateaued** at twelve hours,
  which is ADR-0014 Phase 3 evidence and **not** a Phase 1 gate — do not conflate them.
- **The text of comments and tracked changes is deliberately kept**, with only its attribution
  removed. **mat2 is the better recommendation for a document whose comments must not be
  published**, and ADR-0012 requires saying so. This is sharper for ODF than for Office: mat2
  removes ODF annotations and tracked changes outright.
- **An OOXML document containing a nested archive, an embedded PDF, or an OLE object is
  refused**, not partly cleaned. This refuses real documents — a chart's cached workbook is
  common — and that cost is accepted deliberately. **ODF is different and it is not a
  double standard**: it stores an embedded chart as ordinary entries in the same archive, so
  that document is cleaned rather than refused, with no recursion involved (ADR-0031).
- **Output is not byte-identical for a clean input** (rewritten parts are stored, entry
  timestamps normalised, and an ODF `mimetype` entry may be moved and re-stored). Idempotence
  *is* byte-identical and is tested.
- **Stripped ODF packages now import into LibreOffice 26.2.5.2** — 14 fixtures and 2 real
  LibreOffice-authored documents, stripped, loaded and body-compared by
  `scripts/odf-libreoffice-validation.sh` on 2026-08-24, no failures. The GUI repair-prompt check
  was done by hand the same day — seven stripped files opened in the interface, none prompting
  for repair. **These are two claims, not one**: headless import cannot raise a dialog, so the
  script covers all 16 documents and the manual pass covers seven.
  `docs/THREAT_MODEL.md` §7.7 keeps them separate, and a handler change re-owes the manual pass.

**Closed does not mean unqualified.** Read these before repeating "Phase 1 is done" anywhere
user-facing — each is a real limit, not a formality:

- No single fuzz run has had all four targets clean simultaneously; criterion 2 rests on a
  12h PDF-only run plus standing evidence for the other three.
- No committed real-producer fixture exists, and JPEG real-producer coverage depends on
  `ianare/exif-samples`, which is archived and has no licence, so it cannot be mirrored.
- The recorded limitations stand: the JPEG `APP14` marker mat2 removes, and the 19-byte-xref
  PDF that strypt refuses and mat2 strips.
- Performance is measured on one machine. Linux and Windows are unmeasured.

Status of the items that were outstanding, kept because the detail matters:

- ~~**Sustained fuzzing**~~ — ✅ **exit criterion 2 met 2026-08-22.** Three runs via
  `scripts/fuzz-sustained.sh`: **37.79 CPU-hours** (08-20), **30.42** (08-21), **12.00** (08-22),
  **80.21 total**. They found four real PDF defects, all fixed with regression tests. The third
  run was PDF alone and came back **clean — zero crashes, hangs or OOMs over a full 12.00
  delivered CPU-hours**, the first sustained run in which PDF did not die partway.

  **Know which bar you are measuring against.** Criterion 2 is *"zero panics, crashes, hangs,
  or OOMs across all four fuzz targets after a sustained run"* — no CPU-hour figure, no plateau.
  ADR-0014's 100 CPU-hours plus plateau is a **Phase 3** deliverable.
  `scripts/fuzz-sustained.sh` serves both and its header used to conflate them; do not
  re-import that error by citing ADR-0014 as a Phase 1 gate.

  One caveat is recorded in `docs/ROADMAP.md`: no single run has yet had all four targets clean
  at once. The 08-22 run rests on standing evidence for JPEG, PNG, WebP and detect, which have
  zero artefacts across both earlier runs and unchanged handlers since. Assessed as met; a
  five-target clean run would remove the interpretation and is not a blocker.

  **Phase 3 evidence, not a Phase 1 gate:** JPEG, PNG and WebP plateaued inside 8h; **PDF did
  not plateau in 12h** (last gain 40919s of 43203s, 4324 → 4366 edges). That argues ADR-0014's
  flat 100 should become per-handler numbers — but PDF still owes a run long enough to flatten,
  so do not supersede the ADR on this data alone.
- **The real-producer corpus is deliberately not committed**: its files carry real names, a
  device serial, and live GPS coordinates (`docs/TESTING_STRATEGY.md` §3). The build script and
  manifests are committed and rebuild it. Both WebP coverage gaps closed 2026-08-21 — a
  `cwebp -metadata all` JPEG→WebP conversion carrying real Canon Exif and its IFD1 thumbnail
  across, and a Chrome 151 `canvas.toDataURL` export. The browser file is built only under
  `build_real_corpus.py --with-browser`, since browsers auto-update and its bytes would
  otherwise churn the committed manifest.

The mat2 WebP differential — recorded as never run from 2026-08-19 — **ran on 2026-08-21 and
passes**, after installing `webp-pixbuf-loader`. `scripts/webp-differential.sh` covers the 14
synthetic fixtures and 30 real-producer WebPs with no gaps, and refuses to run without the
loader rather than reporting a meaningless clean sweep (`docs/THREAT_MODEL.md` §7.4).

One known capability gap is recorded and deliberate: a PDF with 19-byte cross-reference
entries is refused by `lopdf`, where mat2 strips it. Refusing is correct fail-closed
behaviour, and mat2 is the better recommendation for that file (`docs/THREAT_MODEL.md` §7.5).

**Panics inside `lopdf` are contained, not eliminated (ADR-0024).** Fuzzing reached an integer
overflow in `lopdf` 0.44.0's xref parser that panicked the shipped binary. Calls into `lopdf`
now go through `strypt_core::panic_guard`, which turns an unwinding panic into an ordinary
typed refusal. Read that module's header before trusting it: it cannot catch a stack overflow
or an abort, it needs unwinding panics (so **do not set `panic = "abort"`**), and it says
nothing about a dependency returning a wrong answer quietly. Containment is a floor, not a
fix — the defect is being reported upstream.

**Measured performance numbers** are in `docs/PRD.md` §9 as of 2026-08-20, produced by
`scripts/measure-performance.sh`. One machine only; Linux and Windows are unmeasured.

Read `docs/ROADMAP.md` for the full exit criteria before treating any of this as settled, and
**check before referencing a later-phase artefact** — nothing beyond Phase 2's second format
group exists.

**Premise correction — settled, and binding (ADR-0012).** The project's founding premise
was that mat2 is archived and unmaintained. That is wrong: mat2 is actively maintained (last
push 2026-08-18, v0.15.0 on 2026-08-04), and only its former GitLab home is archived. The
owner signed off on 2026-08-19 to proceed on corrected footing.

**strypt is an additional option with different engineering trade-offs — never a
"replacement", "successor", or "maintained alternative" to mat2.** That framing is fixed and
must not drift back in any document, release note, issue reply, or outreach message, in this
phase or any later one — not even once strypt reaches feature parity. Never describe mat2 as
dead, archived, or abandoned. Where mat2 is genuinely the better recommendation for a user,
say so. The approved case rests on five differentiators: single-binary deployment versus a
Python-plus-C-library chain, memory-safe parsing where the CVEs actually live, permissive
versus LGPL-3.0 licensing, bus-factor resilience, and verification rigour. Read ADR-0012
before writing anything that positions strypt against mat2.

## 3. Hard constraints — never violate these

These are invariants, not defaults. Each has an ADR in `docs/DECISIONS.md`.

1. **No network access at runtime, ever, in any code path.** No update checks, no telemetry,
   no crash reporting, no remote config, no CDN or remote fonts in any future GUI. No
   dependency that opens a socket may appear anywhere in the tree, including transitively.
   (ADR-0004)
2. **No `unsafe`.** Crates declare `#![forbid(unsafe_code)]`. Introducing `unsafe` requires a
   `// SAFETY:` comment stating the invariants relied on *and* a new ADR in
   `docs/DECISIONS.md` in the same commit. (ADR-0007)
3. **Parsing must never panic.** No `unwrap()`, `expect()`, `panic!()`, `todo!()`,
   `unimplemented!()`, direct slice indexing, or unchecked arithmetic in any code reachable
   from untrusted bytes. Failures are typed `Result` values. Malformed input is *expected*
   input. (ADR-0006)
4. **Every format parser must be fuzz-testable in isolation** and ships with a fuzz target
   and seed corpus in the same pull request as the handler.
5. **All logic lives in `strypt-core`.** It has zero CLI dependencies: no `clap`, no
   `println!`, no `process::exit`, no human-formatted strings. It returns structured data;
   front-ends render it. (ADR-0003)
6. **Fail closed.** Never emit partially-sanitised output. Never report success for a file
   that was not actually processed. An unsupported format is reported as unsupported, never
   silently passed through. This is the most dangerous bug class in the project — a user acts
   on a success message by publishing.
7. **Never overclaim.** "Complete", "guaranteed", and "100%" are banned from user-facing
   text. No tool can guarantee total metadata removal; pretending otherwise can get someone
   hurt.
8. **Never log or print metadata values** above trace level. A log file is a durable copy of
   the secret the user just removed. Log field names and counts, not contents.

## 4. Standing instruction: verify, do not recall

**For any dependency, version number, MSRV, tool capability, or claim about an external
project (mat2, ExifTool, Tails, Qubes-Whonix, crates.io, Tauri, a crate's maintenance status)
that is not already verified in this repository's docs — perform a web search before writing
code or documentation that depends on it. Do not assume training data is current.**

This is not boilerplate. In this session, training-data assumptions about mat2's status were
wrong in a way that would have poisoned the project's founding document, and a search
surfaced the correct answer in under a minute. Crate ecosystems move fast; a stale version
number in a security tool's docs undermines its credibility with exactly the audience that
matters.

Facts already verified in these docs carry the date they were checked. Treat any such fact
older than a few months as a starting point for a search, not as current.

## 5. When you MUST read another document

These are referenced by plain link, not `@path` import, so they load on demand rather than
consuming context every session (ADR-0010). **That makes these triggers load-bearing.** If
you skip them, you will work without knowing the phase scope or the threat model.

| Trigger | Read |
|---|---|
| Starting a new phase, or any task not already scoped in this session | [`docs/ROADMAP.md`](docs/ROADMAP.md) **in full** — confirm which phase the work belongs to and its exit criteria |
| Adding or modifying a format handler | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §3 and §5, and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) in full |
| Adding, removing, or upgrading any dependency | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §4 and §6, then add an ADR to [`docs/DECISIONS.md`](docs/DECISIONS.md) |
| Being asked to add a format, flag, or feature | [`docs/PRD.md`](docs/PRD.md) §6–8 and [`docs/DECISIONS.md`](docs/DECISIONS.md) ADR-0005 — Phase 1 scope is locked |
| Writing any test, fuzz target, or corpus file | [`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) |
| Anything touching security posture, sandboxing, or a reported leak | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`SECURITY.md`](SECURITY.md) |
| Running any build, test, or lint command | [`INSTRUCTIONS.md`](INSTRUCTIONS.md) — the source of truth for exact commands |
| Wondering why something is the way it is | [`docs/DECISIONS.md`](docs/DECISIONS.md) before proposing a change to it |

## 6. Enforcement limits — read this honestly

**Everything in this file is guidance followed by whichever session reads it. None of it is
mechanically enforced.** A future session, or a rushed moment in this one, can violate any
rule above simply by not internalising it. This is a real limitation, not a disclaimer.

For the constraints where a violation would be genuinely serious — network access, an
unreviewed `unsafe` block, a panic path in parsing — do not rely on this file:

- `.claude/settings.json` configures `PreToolUse` hooks as an **early local warning**. Their
  real limits are documented in `.claude/HOOKS.md`; they are best-effort, not a guarantee.
- **CI is the real gate.** The no-network dependency-graph check and `cargo-deny` run on
  every push and cannot be bypassed by a contributor who has not read the docs — which, over
  a project's lifetime, is most contributors.
- Every gate must be **proven to fail** when deliberately violated. An untested gate provides
  confidence without protection.

If you find yourself about to violate a hard constraint because it is inconvenient: stop and
raise it with the owner. Adding a network call "just for an update check" is precisely how
this class of tool loses the trust it exists to hold.

## 7. How to work here

Exact commands live in [`INSTRUCTIONS.md`](INSTRUCTIONS.md) — **it is the source of truth,
and it must be updated in the same commit whenever a command changes.** The loop is roughly
`cargo build` / `cargo test` / `cargo clippy --all-targets -- -D warnings` / `cargo fmt`, plus
`./scripts/check-no-network.sh`, and a fuzz run for the target whose handler you touched. All
of them work today — so run them, and **never invent output for a command you have not run.**

## 8. Coding standards

- **Edition 2024.** Stable since Rust 1.85 (February 2025). Verified 2026-08-19.
- **MSRV: current stable minus two releases**, tested in CI. This tracks the ecosystem
  closely enough to use current crates — `clap` 4.6.6 already requires 1.85 — while leaving
  distribution packagers a small window. Re-evaluate if a target distribution's Rust proves
  older; state the MSRV explicitly in `Cargo.toml` via `rust-version`.
  Verified 2026-08-19: stable is **1.97.1** (released 2026-07-16), so **the MSRV is
  currently 1.95**. Policy recorded in ADR-0013 — it is this project's house policy, *not* a
  claimed industry standard, and must not be cited as one.
- **CI pins the toolchain explicitly** via `rust-toolchain.toml`; it never relies on whatever
  version a contributor's machine happens to have.
- **`rustfmt` and `clippy` are required gates**, not suggestions. Clippy runs with
  `-D warnings`. `strypt-core` additionally denies the panic-capable lints (ADR-0006);
  scope those denials to the parsing path rather than applying them blanket and then
  sprinkling `allow`s, which defeats the purpose.
- **`formats/` is organised by file format, not by dependency.** Someone looking for WebP
  handling opens `formats/webp.rs`. If the underlying crate changes, the module boundary
  absorbs it. Never name a module after the crate it wraps.
- **Errors are typed.** `thiserror` in `strypt-core`; **never `anyhow` there** — callers must
  distinguish "unsupported format" from "corrupt file" from "I/O error", and `anyhow` erases
  exactly that. `anyhow` is acceptable in the `strypt` CLI crate.
- **Comments explain why, not what.** In parser code specifically, cite the spec section or
  the real-world quirk being handled. A future contributor cannot re-derive "this vendor
  writes a malformed length field here" from the code.

## 9. Definition of done — any task in this repo

1. Tests pass on all supported platforms.
2. `cargo clippy -- -D warnings` and `cargo fmt --check` are clean.
3. If a parser changed: fuzz target still builds, seed corpus updated, a short fuzz run is
   clean.
4. If a bug was fixed: a regression test exists and the triggering input is in the corpus.
   **No exceptions** — a fixed bug without a regression test is an unfixed bug with a delay.
5. `CHANGELOG.md` updated under `[Unreleased]`.
6. No new `unsafe` without an ADR in `docs/DECISIONS.md` in the same commit.
7. No new dependency without an ADR.
8. `docs/THREAT_MODEL.md` updated if a format handler was added or changed.
9. `INSTRUCTIONS.md` updated if any command changed.
