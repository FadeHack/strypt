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

## 2. Current phase: **Phase 2 complete; Phase 3 not opened**

Phases 0, 1 and 2 are complete. **Phase 2 opened 2026-08-23 (ADR-0027) and closed 2026-09-05**, all
four groups landed and all four exit criteria met.

`strypt show` and `strypt strip` process PDF, JPEG, PNG, WebP, TIFF, GIF, HEIF, AVIF, SVG, JPEG XL,
FLAC, WAV, MP3, Ogg, MP4, M4A, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, and `.odp`. Every other
format is reported as unsupported and never passed through untouched.

**The scope is still locked.** ADR-0027's list is finished, not widened — a format outside it needs
a superseding ADR, and closing a phase is not an invitation to add one. Phase 3 is hardening
(`docs/ROADMAP.md`), not more formats, and it has not started: nothing in it exists.

**Where things stand — read `docs/ROADMAP.md` for the detail, which is not repeated here:**

| | Status |
|---|---|
| Group 1 — Office Open XML | ✅ 2026-08-23 |
| Group 2 — OpenDocument | ✅ 2026-08-24 |
| Group 3 — TIFF / GIF / HEIF+AVIF | ✅ 2026-08-26, 08-27, 08-27 |
| Group 3 — SVG | ✅ 2026-08-29 |
| Group 3 — JPEG XL | ✅ 2026-08-30 |
| Group 4 — FLAC | ✅ 2026-09-01 |
| Group 4 — WAV | ✅ 2026-09-02 |
| Group 4 — MP3 | ✅ 2026-09-03 |
| Group 4 — Ogg | ✅ 2026-09-04 |
| Group 4 — MP4 | ✅ 2026-09-05 |

**Check before referencing a later-phase artefact.** Nothing beyond the above exists. That rule
applies *within* this phase as well as across phases.

### Required reading before touching a handler

- **ADR-0033 (TIFF)** — the one format strypt *rebuilds* rather than edits, because its metadata is
  its file structure. Tags reach the output from an allow-list, so an unknown vendor tag cannot
  survive by going unrecognised — the inverse of the deletion rule governing OOXML and ODF.
- **ADR-0034 (HEIF+AVIF)** — **corrects ADR-0033's guess** that an ISO-BMFF box tree could be
  edited by deletion. The tree can; the metadata is not in the tree. Exif and XMP are *items*
  addressed by absolute file offsets, so HEIF is rebuilt with every offset recomputed.
- **ADR-0035 (SVG)** — not a container of encoded pixels. Edited by deletion, allow-listed on
  namespace prefix, and the one format where strypt removes *less* than mat2 and says so.
- **ADR-0036 (JPEG XL)** — HEIF's box grammar, ADR-0034's conclusion reversed: nothing is addressed
  by file offset, so it is edited by deletion. Two spellings, one handler; the bare codestream is a
  declared no-op; `brob` is deleted without inflating, so no Brotli decompressor enters the tree.
- **ADR-0038 (FLAC)** — the first audio format, and the group's hazard is absent: RFC 9639 §8.5
  measures a seek offset from the first audio frame, so removal moves nothing and the file is edited
  by block surgery. Two decisions to know before changing it: padding is zeroed at its length rather
  than dropped, and the `STREAMINFO` audio MD5 is **kept and declared** because the file's holder can
  recompute it.
- **ADR-0039 (WAV + RIFF)** — answers ADR-0037's open question: the RIFF walk now lives in
  `container/riff.rs` and is shared with WebP, so **a change there changes WebP too**. WAV is edited
  by chunk surgery because `cue `'s offsets index the wave list's data section, not the file. Two
  things to know: `cue ` is kept although ExifTool calls it metadata, and `id3 ` is dropped unread —
  no ID3 reader enters the tree before tranche 3.
- **ADR-0040 (MP3 + tags)** — the one format that is **not a container**: no header, no index, just
  frames with tags glued to each end. Edited by deletion at both ends; there is no allow-list because
  the frames are the payload, so the *boundary* is the whole safety argument — a tag length is refused
  rather than clamped. The ID3 reader is hand-written and lives in `formats/tags.rs`, **shared with
  FLAC, so a change there changes FLAC too**. Three things to know: it lifts ADR-0038 decision 7 (an
  ID3-prefixed FLAC is now cleaned, and a FLAC's trailing tags are peeled), the `Xing`/`VBRI` frame is
  kept and declared because it is real audio, and `check-no-network.sh` cannot see a dependency's
  optional features — read decision 1 before trusting a green run on a new crate.

- **ADR-0041 (Ogg)** — pages are CRC-checked, so it is **rebuilt**, and the serial number is rewritten
  to zero: the one handler that cannot promise a byte-identical clean file. Granules are per-page, so
  page grouping is preserved. The Vorbis comment reader is `formats/vorbis.rs`, **shared with FLAC**.

- **ADR-0042 (MP4)** — `stco` indexes the file, and **ADR-0034's conclusion reverses**: MP4's metadata
  is outside `mdat`, so it is edited by deletion with every chunk offset remapped through a table of
  `mdat` extents. An offset resolving inside none of them **refuses the file** — that check, not the
  allow-lists, is the safety argument. `container/bmff.rs` is **shared with HEIF**, so a change there
  changes HEIF too.

- **ADR-0029** — the descent into embedded images is one level, images only. It exists exactly once,
  in `container/package.rs`.

### Two mistakes this project has already made once

- **Know which fuzzing bar you are measuring against.** Phase 1 exit criterion 2 is *"zero panics,
  crashes, hangs, or OOMs across all four fuzz targets after a sustained run"* — no CPU-hour figure,
  no plateau. ADR-0014's 100 CPU-hours plus plateau is a **Phase 3** deliverable.
  `scripts/fuzz-sustained.sh` serves both. Do not cite ADR-0014 as a Phase 1 gate.
- **A per-format invariant in a pipeline-wide fuzz target must be guarded by a format check.** These
  targets drive the whole pipeline, so a mutation reaching another format's magic is dispatched to
  that format's handler. An unguarded "stripping never grows a file" assertion killed a twelve-hour
  run at 144.5M inputs on 2026-08-26. Carry the guard into every future handler's target.

### Closed does not mean unqualified

Read these before repeating "Phase 1 is done" anywhere user-facing. Each is a real limit:

- No committed real-producer fixture exists (ADR-0025 decided that deliberately; the build script
  and manifests are committed and rebuild the corpus). JPEG real-producer coverage depends on
  `ianare/exif-samples`, which is archived and unlicensed, so it cannot be mirrored.
- Recorded capability gaps stand: the JPEG `APP14` marker mat2 removes, and the 19-byte-xref PDF
  strypt refuses and mat2 strips. Refusing is correct fail-closed behaviour, and **mat2 is the
  better recommendation for that file**.
- Performance is measured on one machine. Linux and Windows are unmeasured.
- **Panics inside `lopdf` are contained, not eliminated (ADR-0024).** Calls go through
  `strypt_core::panic_guard`. Read that module's header before trusting it: it cannot catch a stack
  overflow or an abort, it needs unwinding panics (so **do not set `panic = "abort"`**), and it says
  nothing about a dependency returning a wrong answer quietly.

Every handler carries deliberate limitations of its own — what is out of reach, what is refused,
what is kept on purpose. They live in `docs/THREAT_MODEL.md` §7, one subsection per format, and
that is the document to read before making a claim about what strypt removes.

### Premise correction — settled, and binding (ADR-0012)

The project's founding premise was that mat2 is archived and unmaintained. That is wrong: mat2 is
actively maintained, and only its former GitLab home is archived. The owner signed off on
2026-08-19 to proceed on corrected footing.

**strypt is an additional option with different engineering trade-offs — never a "replacement",
"successor", or "maintained alternative" to mat2.** That framing is fixed and must not drift back
into any document, release note, issue reply, or outreach message, in this phase or any later one,
not even at feature parity. Never describe mat2 as dead, archived, or abandoned. **Where mat2 is
genuinely the better recommendation for a user, say so.** The approved case rests on five
differentiators: single-binary deployment, memory-safe parsing, permissive licensing, bus-factor
resilience, and verification rigour. Read ADR-0012 before positioning strypt against mat2.

## 3. Hard constraints — never violate these

These are invariants, not defaults. Constraints 1–8 each have an ADR in `docs/DECISIONS.md`;
constraint 9 is the owner's standing instruction.

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
9. **Do not write verbose comments or verbose docs.** A comment earns its place by saying
   something the code cannot: the spec section, the vendor quirk, the reason a rule runs in an
   unexpected direction. One or two lines. Not a paragraph, not an essay, not a restatement of
   the line below it. The same applies to every document here — CLAUDE.md, CHANGELOG.md,
   README.md and the docs — which are already dense; **matching that density overshoots.** Do
   not repeat in one file what another file already says: link to it. Long-form reasoning
   belongs in `docs/DECISIONS.md`, once, as an ADR.

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
| Being asked to add a format, flag, or feature | [`docs/PRD.md`](docs/PRD.md) §6–8 and [`docs/DECISIONS.md`](docs/DECISIONS.md) ADR-0027 and ADR-0032 — the phase scope is locked |
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
`cargo build` / `cargo test` / `cargo clippy --all-targets --all-features -- -D warnings` / `cargo fmt`, plus
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
2. `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check` are clean.
   **`--all-features` is not optional** — it is what compiles the feature-gated `fuzzing` module,
   and CI runs that form. Dropping it hides a whole module from the lint.
3. If a parser changed: fuzz target still builds, seed corpus updated, a short fuzz run is
   clean.
4. If a bug was fixed: a regression test exists and the triggering input is in the corpus.
   **No exceptions** — a fixed bug without a regression test is an unfixed bug with a delay.
5. `CHANGELOG.md` updated under `[Unreleased]`.
6. No new `unsafe` without an ADR in `docs/DECISIONS.md` in the same commit.
7. No new dependency without an ADR.
8. `docs/THREAT_MODEL.md` updated if a format handler was added or changed.
9. `INSTRUCTIONS.md` updated if any command changed.
