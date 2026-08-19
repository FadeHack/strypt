# CLAUDE.md — working agreement for strypt

Read this fully before doing anything in this repository.

---

## 1. What strypt is

strypt is a metadata removal tool: a Rust library (`strypt-core`) plus a CLI (`strypt-cli`)
that detects and strips hidden identifying metadata — GPS coordinates, device serial numbers,
author names, timestamps, editing history — from files so they are safer to publish. Its
users include journalists protecting sources, whistleblowers, domestic violence survivors,
and human rights investigators. For some of them, a leak through this tool is a physical
safety event, not an inconvenience.

strypt is **not** an encryption tool, a secure-deletion tool, a forensics suite, a redaction
tool, or a steganography detector. Requests to widen scope in those directions are declined
by default.

## 2. Current phase: **Phase 1 — Core engine + CLI**

**Phase 0 is complete. All four Phase 1 handlers exist and work — but the phase does not end
there.** `strypt show` and `strypt strip` process PDF, JPEG, PNG, and WebP; every other format
is reported as unsupported and never passed through untouched. Landed: bounded ingest,
content-sniffing detection, the handler registry and trait, the post-strip verification pass,
structured reports, typed errors, the atomic write path, the full CLI, four handlers with
shared Exif and XMP readers, five fuzz targets, and a generated fixture corpus for all four
formats.

**Do not read "all four handlers exist" as "Phase 1 is nearly done".** Three exit criteria are
outstanding and none of them is a handler:

- **Real-producer corpus** — every fixture is synthetic, so the tool has been tested against
  specifications, not against what real software emits. This is the largest gap and the one
  most likely to surface a genuine bug.
- **Sustained fuzzing** — the runs so far are smoke tests of seconds to minutes, against
  ADR-0014's bar of 100 CPU-hours per handler plus a coverage plateau.
- **Measured performance numbers** — `docs/PRD.md` §9 still carries estimates labelled as
  such. Nothing has been measured.

One differential-testing gap is also open and must not be reported as a pass: the mat2
comparison for WebP has never run, because mat2's WebP path needs a GdkPixbuf WebP loader the
verification machine lacks (`docs/THREAT_MODEL.md` §7.4).

Read `docs/ROADMAP.md` for the full exit criteria before treating any of this as settled, and
**check before referencing a later-phase artefact** — nothing beyond Phase 1 exists.

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
  exactly that. `anyhow` is acceptable in `strypt-cli`.
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
