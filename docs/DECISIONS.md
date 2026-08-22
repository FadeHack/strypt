# Architecture Decision Records

This is the decision log for strypt. Every architecturally significant choice — anything
that would make a future contributor ask "why is it like this?" — gets an entry here.

**Format.** Lightweight ADRs in the Nygard style: Context, Decision, Consequences, Status.
Entries are append-only and numbered sequentially. Do not edit a decided ADR to change its
meaning; supersede it with a new ADR and mark the old one `Superseded by ADR-NNNN`.

**Status values:** `Proposed` · `Accepted` · `Superseded by ADR-NNNN` · `Rejected`

**When you MUST add an entry:**

- Adding, removing, or swapping any third-party dependency.
- Introducing an `unsafe` block (this is a hard gate — see `CLAUDE.md`).
- Any change to the format-handler trait or dispatch architecture.
- Any change that touches the no-network constraint, even indirectly (e.g. adding a
  dependency that transitively pulls in a TLS or HTTP stack).
- Any decision to accept a known limitation in metadata removal for a format.

---

## ADR-0001 — Rust as the implementation language

**Status:** Accepted (2026-08-19)

**Context.** strypt parses untrusted, potentially adversarially-crafted binary files supplied
by people whose physical safety may depend on the tool not being exploitable. The dominant
prior art in this space (`mat2`) is Python and delegates parsing to C libraries (Poppler,
Cairo, GdkPixbuf, librsvg) — a large memory-unsafe attack surface reached through a dynamic
runtime.

**Decision.** Implement in Rust, edition 2024, with a hard preference for pure-Rust
dependencies over `-sys` bindings to C libraries.

**Consequences.**

- Memory-safety class bugs (buffer overflow, use-after-free, double-free) are ruled out by
  construction in safe Rust, which is the single largest category of parser CVEs.
- Panics remain possible and become the dominant availability risk; this is why the
  no-panic-in-parsing rule (ADR-0006) exists.
- Single statically-linked binary with no runtime interpreter, which matters for the
  distribution and live-OS stories (see `docs/ROADMAP.md` Phase 4).
- Cost: the Rust format-parsing ecosystem is thinner than Python's. Some formats mat2
  supports will be harder to reach. Accepted deliberately — see ADR-0005.

---

## ADR-0002 — Dual MIT OR Apache-2.0 licensing

**Status:** Accepted (2026-08-19)

**Context.** strypt should be embeddable by anyone, including in privacy-focused operating
systems and in downstream tools. The predecessor `mat2` is LGPL-3.0-or-later (verified on
its GitHub repository, 2026-08-19), which constrains static linking into non-(L)GPL
binaries — a real friction point for a Rust project that wants to ship as a single static
binary and expose a reusable library crate.

**Decision.** Dual-license under `MIT OR Apache-2.0`, the Rust ecosystem default. Expressed
in `Cargo.toml` as the SPDX expression `license = "MIT OR Apache-2.0"`, with canonical
`LICENSE-MIT` and `LICENSE-APACHE` files at the repository root.

**Consequences.**

- Apache-2.0 supplies an explicit patent grant and contribution clause; MIT supplies GPLv2
  compatibility. This is precisely why the Rust project itself uses the pair.
- We cannot vendor or link LGPL/GPL code (including mat2 itself) into `strypt-core`. Any
  proposal to do so requires a new ADR and would likely be rejected.
- Dependencies must be license-compatible; this is mechanically enforced by `cargo-deny`'s
  license check in CI (see ADR-0008).
- `LICENSE-APACHE` is the unmodified canonical text from apache.org (downloaded and diffed
  2026-08-19). Do not hand-edit it.

---

## ADR-0003 — Cargo workspace: library core, thin CLI

**Status:** Accepted (2026-08-19)

**Context.** The roadmap anticipates at least three consumers of the same stripping logic: a
CLI (Phase 1), a Tauri GUI (Phase 5), and file-manager integrations (Phase 6). Any
architecture that lets stripping logic live in the CLI guarantees behavioural drift between
front-ends — and in a security tool, drift between front-ends means one of them is silently
less safe than the other.

**Decision.** A Cargo workspace. `strypt-core` holds all detection, inspection, and
stripping logic and takes zero CLI dependencies (no `clap`, no terminal formatting, no
`println!`, no process exit codes). `strypt-cli` is a thin binary crate that does argument
parsing, I/O orchestration, and presentation only. Future members `strypt-gui` and
`strypt-ffi` are named now but not created until their phases.

**Consequences.**

- `strypt-core` must expose structured result types (not formatted strings) so every
  front-end renders them itself.
- Phase 5's exit criterion — GUI output byte-identical to CLI output for the same input —
  is only meaningful because of this split.
- Slight up-front friction: even Phase 1 pays the cost of a two-crate workspace for a
  single-front-end tool. Accepted; retrofitting this split later is far more expensive.

---

## ADR-0004 — No network access at runtime, in any code path, ever

**Status:** Accepted (2026-08-19)

**Context.** strypt's users include people for whom an outbound connection at the moment
they sanitise a document is itself a disclosure — it reveals that sanitisation happened,
when, and from which IP. A telemetry ping, an update check, a crash reporter, or a font/CDN
fetch in a future GUI would all break the tool's core promise. Note that mat2 removed its
bubblewrap sandboxing in 0.14.0 (verified 2026-08-19), which shows how security properties
erode when they are not treated as invariants.

**Decision.** `strypt-core` and `strypt-cli` make no network calls. No update checks, no
telemetry, no crash reporting, no remote configuration, no license/version phone-home. This
extends to dependencies: no crate that opens sockets may appear anywhere in the dependency
tree, including transitively. This is a project invariant, not a default that can be
overridden by a flag.

**Consequences.**

- Enforced at three layers, deliberately redundant (see `.claude/settings.json` notes):
  1. A `PreToolUse` hook giving early local warning on edits that look like they add a
     networking dependency.
  2. A CI job that greps the resolved dependency graph for known networking crates and
     fails the build — this is the real gate.
  3. `cargo-deny`'s `bans` section listing networking crates as denied.
- Phase 5 (Tauri GUI) must additionally prove absence of network *capability*, since Tauri
  can grant it via its permissions system. That is an explicit Phase 5 exit criterion.
- Consequence accepted: no auto-update. Distribution must therefore make manual updates
  easy and verifiable (Phase 4).

---

## ADR-0005 — Phase 1 format scope fixed at images (JPEG/PNG/WebP) + PDF

**Status:** Accepted (2026-08-19)

**Context.** mat2 supports roughly two dozen formats. Matching that list in a first release
is achievable only by making every handler shallow. For this tool, a shallow handler is
worse than no handler: it produces a file the user believes is clean.

**Decision.** Phase 1 ships exactly four formats — JPEG, PNG, WebP (EXIF / XMP / ICC and
container-level ancillary metadata), and PDF (document information dictionary, XMP metadata
stream, and related structures). No Office formats, no audio/video, no archives in Phase 1.
The scope is locked for the duration of the phase.

**Rationale for these four specifically.**

- They carry the highest real-world risk for strypt's target users: GPS coordinates, camera
  serial numbers, and device identifiers in images; author names, organisation names,
  producing-software strings, and revision data in PDFs.
- They are the formats where correctness can be verified most rigorously within one phase,
  by fuzzing and by byte-level differential inspection.
- JPEG, PNG, and WebP share a container-inspection idiom (segment/chunk/RIFF walking) that
  one well-tested dependency covers, so the marginal cost of the third format is low.

**Consequences.**

- strypt is not a mat2 replacement at the end of Phase 1 and documentation must not imply
  it is. Feature parity is a Phase 2 goal.
- The handler trait must be designed for extension from day one even though only four
  formats use it (see `docs/ARCHITECTURE.md`).
- Anyone tempted to add a fifth format during Phase 1 should read this ADR and the Phase 1
  exit criteria first. Expanding scope requires a superseding ADR.

---

## ADR-0006 — Parsing code may not panic; errors are values

**Status:** Accepted (2026-08-19)

**Context.** In Rust, the residual availability risk after memory safety is the panic:
slice index out of range, integer overflow in debug, `unwrap()` on malformed input. For a
batch-processing CLI a panic is a denial of service; in a future GUI or library embedding it
can take down the host process. Adversarial input is the *expected* input for this tool.

**Decision.** No `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unimplemented!()`, direct
slice indexing, or arithmetic that can overflow in any code reachable from parsing untrusted
bytes. All failure modes return `Result` with a typed error. Enforced by `clippy` lints
denied at the crate level in `strypt-core`, not merely warned.

**Consequences.**

- `strypt-core` code is more verbose: `get(..).ok_or(..)?` instead of `[..]`, checked
  arithmetic instead of bare operators.
- `expect()` remains permissible in tests, in build scripts, and in `strypt-cli` startup
  paths that do not touch file content — the lint configuration should reflect that
  boundary precisely rather than being blanket-applied and then blanket-`allow`ed.
- Every panic discovered by fuzzing is a bug with a regression test, per
  `docs/TESTING_STRATEGY.md`.

---

## ADR-0007 — `unsafe` requires an ADR

**Status:** Accepted (2026-08-19)

**Context.** The memory-safety argument for choosing Rust (ADR-0001) is void in any
`unsafe` block. In a tool whose value proposition is trustworthiness, unreviewed `unsafe` is
a direct contradiction of the pitch.

**Decision.** `strypt-core` and `strypt-cli` declare `#![forbid(unsafe_code)]` by default.
Introducing `unsafe` requires (a) removing `forbid` in favour of `deny` with a targeted
`allow`, (b) a `// SAFETY:` comment stating the invariants relied upon and why they hold,
and (c) a new ADR in this file, in the same commit.

**Consequences.**

- `forbid(unsafe_code)` cannot be locally overridden, so the change is necessarily visible
  in review rather than buried in a module.
- Dependencies may contain `unsafe` — this rule governs strypt's own code. Dependency
  `unsafe` is managed by preferring pure-Rust, widely-audited crates and by keeping the
  dependency count low (ADR-0008).

---

## ADR-0008 — Minimal dependency footprint, mechanically audited

**Status:** Accepted (2026-08-19)

**Context.** Every transitive dependency is code that runs with the user's privileges on the
user's most sensitive documents. The supply chain is a realistic attack path against a tool
that at-risk users rely on, and it is the attack path least visible to those users.

**Decision.** Prefer crates with few transitive dependencies. Justify each direct dependency
in `docs/ARCHITECTURE.md` with the version and date verified. Run `cargo-deny` in CI as a
hard merge gate covering advisories, licenses, banned crates (including all networking
crates per ADR-0004), and duplicate versions. Generate an SBOM at release time.

**Consequences.**

- Some convenience crates will be rejected on dependency-count grounds even when they are
  the ergonomic choice.
- CI will occasionally break on a newly-published RustSec advisory affecting a transitive
  dependency. That is the gate working, not a nuisance to be downgraded to a warning.
- Version numbers recorded in the docs go stale. They are timestamped and marked
  "verify at implementation time" rather than presented as evergreen.

---

## ADR-0009 — CLI-first, GUI deferred

**Status:** Accepted (2026-08-19)

**Context.** The user base spans scripting-comfortable technical users and non-technical
field workers. Building both front-ends at once would mean shipping neither well, and would
mean designing the core library's API against a moving GUI target.

**Decision.** Phase 1 ships a CLI only. The GUI (Tauri) is Phase 5, after the core is
hardened (Phase 3) and distributable (Phase 4).

**Consequences.**

- Non-technical users are not served until Phase 5. Acknowledged as a real gap, not a
  reason to rush the GUI: a GUI over an unhardened core would give exactly the false
  confidence this project exists to avoid.
- The core API gets to stabilise against one consumer before a second is added.

---

## ADR-0010 — Documentation lives in `docs/`, `CLAUDE.md` at the root

**Status:** Accepted (2026-08-19)

**Context.** Claude Code loads `CLAUDE.md` from the project root automatically. The other
foundational documents are large; loading all of them into every session would consume
context on documents most sessions do not need.

**Decision.** `CLAUDE.md` at the repository root. PRD, architecture, roadmap, threat model,
decisions, and testing strategy in `docs/`, referenced from `CLAUDE.md` by plain relative
Markdown link rather than by `@path` import, so they load on demand.

**Consequences.**

- Context stays cheap, but the read-trigger table in `CLAUDE.md` is doing real work: it is
  the only thing that gets the right document in front of the right session. It must be
  written as concrete trigger conditions, not descriptions.
- A session that ignores the triggers will operate without knowing the phase scope or the
  threat model. This is a known, accepted weakness of instruction-based guidance and is why
  the genuinely serious constraints also have CI gates (ADR-0004, ADR-0007).

---

## ADR-0011 — No third-party plugin loading

**Status:** Accepted (2026-08-19)

**Context.** A plugin system for external format handlers is a natural-seeming extension of
the trait-based handler architecture, and mat2-adjacent tools often grow one.

**Decision.** Format handlers are compiled in, via the in-tree `MetadataHandler` trait. No
dynamic loading of third-party handlers (`dlopen`, WASM plugin registries, script hooks) in
any planned phase.

**Consequences.**

- Extensibility for contributors is preserved: adding a format means adding a module and
  registering it, no core dispatch changes.
- The trust model stays intact. A loaded plugin would run with full privileges over the
  user's most sensitive files, and no user could reasonably audit it — this is precisely
  the compromise strypt exists to avoid.
- If in-process sandboxing of *our own* parsers is adopted (a Phase 3 investigation), that
  is a hardening measure and does not reopen this decision.

---

## ADR-0012 — Positioning: an additional option, never a replacement for mat2

**Status:** Accepted (2026-08-19) · **Owner-approved**

**Context.** strypt was conceived on the premise that mat2 was archived and unmaintained.
Verification on 2026-08-19 showed that premise is wrong: only mat2's former GitLab home
(`0xacab.org`) is archived, development having moved to GitHub, where it is active — last
push 2026-08-18, v0.15.0 released 2026-08-04. See `docs/PRD.md` §0 for the full correction.

**Decision.** strypt positions itself as an **additional, independently-implemented option
with different engineering trade-offs — never as a replacement for, or successor to, mat2.**
This applies to every document, release note, README, issue reply, conference talk, and
outreach message, in this phase and all future phases.

The approved case for strypt rests on five differentiators, all of which hold true *while
mat2 is healthy*:

1. **Deployment shape** — a single static binary versus a Python 3.11+ runtime plus Poppler,
   Cairo, GdkPixbuf, librsvg, mutagen, and an ExifTool fallback.
2. **Memory-safe parsing** — safe Rust with `#![forbid(unsafe_code)]`, where mat2's parsing
   is delegated to C libraries that are the historical home of image and PDF parser CVEs.
   This is the strongest single argument.
3. **Permissive licensing** — `MIT OR Apache-2.0` versus LGPL-3.0-or-later, enabling static
   linking and embedding.
4. **Bus-factor resilience** — a second independent implementation on a different technology
   stack, which is a resilience argument rather than a criticism of mat2's maintainer.
5. **Verification rigour** — published fuzzing budgets, findings-derived limitation
   documentation, and supply-chain gates in CI.

**Consequences.**

- Language such as "successor to mat2", "replacement for mat2", "mat2 is dead/archived/
  abandoned", or "the maintained alternative" is **prohibited** in project materials. Where
  mat2 is genuinely the better recommendation for a user, say so.
- Phase 7 outreach to Tails and Qubes-Whonix pitches strypt as an addition, not a
  substitution. Pitching a replacement to maintainers who know the landscape better than we
  do would be both inaccurate and a poor first impression.
- This framing must not drift back over time as the project gains capability. Feature parity
  with mat2 would still not make strypt its replacement — it would make it a peer.
- If mat2's status ever genuinely changes, that is a new ADR superseding this one, made on
  fresh verification rather than on assumption.

---

## ADR-0013 — MSRV policy: current stable minus two releases

**Status:** Accepted (2026-08-19) · **Owner-approved**

**Context.** A security tool intended for distribution packaging has to balance two pressures:
tracking stable closely enough to use current crates (`clap` 4.6.6 already requires Rust
1.85), and leaving distribution packagers — particularly Debian-derived systems such as Tails
and Qubes-Whonix — a window in which their toolchain can build it.

**Decision.** strypt supports **the current stable Rust release and the two before it**,
declared explicitly via `rust-version` in `Cargo.toml` and tested by a dedicated CI job.

As of 2026-08-19, stable is 1.97.1 (released 2026-07-16), so **the MSRV is 1.95**.

**This is adopted as this project's house policy. It has NOT been verified as community
consensus or industry best practice, and must never be cited as though it were.** It is a
judgement call balancing the two pressures above. If a target distribution turns out to ship
an older Rust, revisit it — that would be evidence, and evidence supersedes a house rule.

**Consequences.**

- A CI job builds against the MSRV; raising the MSRV is a deliberate act with a `CHANGELOG.md`
  entry, not an accident of using a new language feature.
- Roughly a 12-to-18-week support window, given Rust's six-week release cadence.
- Point releases (like 1.97.1) count as their minor version for this purpose; the policy is
  expressed in minor versions.

---

## ADR-0014 — Fuzzing budget: 100 CPU-hours per handler plus a coverage plateau

**Status:** **Proposed — provisional starting target, not a commitment** · Owner-approved as
a starting point (2026-08-19)

**Context.** "Fuzz it for a while" is not an exit criterion — it cannot be met or missed. A
number is needed so Phase 3 can be assessed. But no coverage data exists yet, because no
parser exists yet, so any number chosen today is an estimate rather than a measurement.

**Decision (provisional).** A handler meets the Phase 3 fuzzing bar when **both** hold:

1. **≥ 100 CPU-hours** of fuzzing since its last substantive change; **and**
2. **Edge coverage has plateaued** — no new coverage in the final 25% of the run.

Both conditions are required because either alone is gameable. CPU-hours alone can be burned
on a target that stopped exploring hours ago; a plateau alone can be reached in minutes by a
harness too narrow to find anything.

**This number is explicitly provisional and is to be revised with real coverage data once
Phase 3 actually begins.** It is a starting target, not a figure the project is locked into.
Revision in either direction — including substantially upward, if early data shows 100 hours
barely scratches the PDF handler — is the expected outcome, not a failure of planning.
Whoever runs Phase 3 should treat this ADR as a hypothesis to test.

**Consequences.**

- Phase 3 must record actual CPU-hours and coverage curves per handler, so the revision is
  driven by data rather than by another estimate.
- Formats will differ substantially. PDF's object graph is far larger than PNG's chunk list;
  a single flat number across all handlers is likely wrong and should be expected to split
  into per-format targets.
- Hangs, OOMs, and slow units count as findings alongside crashes, per
  `docs/TESTING_STRATEGY.md` §2.4. A budget met while ignoring hangs has not been met.
- Supersede this ADR with the measured policy at the end of Phase 3; do not silently edit
  the numbers here.

---

## ADR-0015 — Toolchain pinning, and why the MSRV job must override it explicitly

**Status:** Accepted (2026-08-19)

**Context.** `rust-toolchain.toml` pins the compiler to an exact version so that a release
binary never depends on whichever toolchain happened to be installed on the building machine.
The compiler is part of this tool's trusted computing base: Rust 1.97.1 was itself a point
release fixing an LLVM miscompilation, and a miscompiled parser handling hostile input is
exactly the failure this project cannot afford.

The pin creates a trap for the MSRV job, which must build against a *different* version by
design. Measured locally on 2026-08-19, rustup's precedence is:

```
+toolchain  >  RUSTUP_TOOLCHAIN  >  directory override  >  rust-toolchain.toml  >  default
```

A CI action that installs a toolchain and sets it as the **default** is therefore outranked
by `rust-toolchain.toml`. The MSRV job as first written used exactly such an action, so it
would have built with the pinned 1.97.1 while reporting success — testing nothing, while
looking like a passing gate. This is the failure mode `docs/ROADMAP.md` warns about
generally: a gate that provides confidence without protection.

**Decision.** `rust-toolchain.toml` pins the build toolchain. Any job that must deviate sets
`RUSTUP_TOOLCHAIN` explicitly (or uses `cargo +version`), never a default-setting action.
Every such job includes a `rustc --version` step whose output must be checked to confirm the
intended toolchain is actually in use.

**Consequences.**

- Verified 2026-08-19: the workspace builds cleanly on the MSRV, 1.95.0.
- Bumping the pin or the MSRV is a deliberate act with a `CHANGELOG.md` entry, and the two
  move independently — the pin tracks current stable, the MSRV follows ADR-0013.
- Generalises beyond MSRV: any future job needing a different toolchain (nightly for
  `cargo-fuzz`, for instance) faces the same trap and must use the same explicit mechanism.
  Phase 1 will hit this with the fuzzing jobs.

---

## ADR-0016 — Split supply-chain gates by determinism

**Status:** Accepted (2026-08-19)

**Context.** `cargo-deny` was wired as a single advisory (`continue-on-error`) job, to be
made hard in Phase 3, on the reasoning that a newly-published RustSec advisory can break the
build with no change to this repository — which is disruptive before the project has capacity
to service it.

On the very first CI run, that advisory-only setting **hid a genuine failure**: `bans FAILED`,
because `strypt-cli` declared `strypt-core` by path with no version, which `cargo-deny`
correctly reports as a wildcard dependency. The job showed green. Nothing was broken by it,
but the mechanism that was supposed to report it stayed silent — precisely the "confidence
without protection" failure this project warns about elsewhere.

**Decision.** Split the checks by whether they can fail for reasons outside this repository:

- **`bans`, `licenses`, `sources` — hard gates, from now.** These depend only on this
  repository's contents. They can only fail because someone changed something here, so
  failing the build is correct and actionable immediately.
- **`advisories` — advisory until Phase 3**, then hard. This depends on the RustSec database
  and can begin failing with no commit at all. Keeping it non-blocking for now is a capacity
  decision, not a statement that advisories matter less.

**Consequences.**

- The wildcard was fixed by giving the path dependency an explicit `version`, which is also
  required for the Phase 4 crates.io publish — a bare path dependency cannot be published.
- The general rule this establishes: **prefer a narrow hard gate to a broad advisory one.**
  An advisory gate reports into a log nobody reads. Where a check is deterministic and under
  our control, it should block.
- The `cargo-deny` action runs in a musl container that could not resolve the pinned
  toolchain, emitting a rustup error into the log. Its `rust-version` input is now pinned to
  match `rust-toolchain.toml`, because log noise is how real failures get overlooked.

---

## ADR-0017 — Handlers take a byte slice and return a buffer

**Status:** Accepted (2026-08-19)

**Context.** `docs/ARCHITECTURE.md` §3 sketched `MetadataHandler` over `&mut dyn ReadSeek`
for input and `&mut dyn Write` for output. That sketch predates any implementation, and Phase
1 is where it meets the two things it has to support: a verification pass, and lints that
forbid panicking on hostile input.

**Decision.** Handlers take `&[u8]` and return `Stripped { bytes: Vec<u8>, report }`.

**Consequences.**

- **The verification pass becomes possible.** `docs/ARCHITECTURE.md` §1 stage 5 re-inspects
  the handler's output and fails if metadata survived. If a handler streamed straight to the
  destination, unverified — possibly partially-sanitised — bytes would already be on disk by
  the time that check ran. Holding the output in memory means nothing reaches the user's
  filesystem until it has passed. That is the fail-closed rule made structural rather than
  aspirational.
- **The panic-freedom lints become enforceable.** Seek-driven parsing spreads bounds checking
  across every read site. A slice concentrates it in `crate::bytes::Reader`, which is the one
  place `indexing_slicing` and `arithmetic_side_effects` have to be satisfied — and it is
  unit-tested against overflow and truncation directly (ADR-0006).
- **The cost is memory.** A file is held whole, and a PDF rewrite holds the parsed object
  graph as well, so peak usage is a multiple of the input size. This is why `io::Limits`
  bounds ingest *before* a handler is reached, and why the default ceiling is 512 MiB rather
  than "as much as will fit" — the constrained, RAM-only systems this tool targets are
  exactly where that distinction matters.
- Streaming remains possible later for formats that genuinely need it, but it would have to
  come with an answer for how the output gets verified before it is committed.

---

## ADR-0018 — Phase 1 dependencies

**Status:** Accepted (2026-08-19)

**Context.** ADR-0008 requires an ADR per dependency and treats "it is convenient" as
insufficient. Phase 1 needs four. All versions were re-verified against crates.io on
2026-08-19, at the start of this phase, rather than carried over from the Phase 0 snapshot in
`docs/ARCHITECTURE.md` §4 — which, as it happens, they matched.

**Decision.**

| Crate | Version | Licence | Where | Why |
|---|---|---|---|---|
| `thiserror` | 2.0.20 | MIT OR Apache-2.0 | `strypt-core` | Typed errors. `anyhow` stays banned here: callers must distinguish "unsupported format" from "corrupt file" from "I/O error", and a boxed error erases exactly that |
| `lopdf` | 0.44.0 | MIT | `strypt-core` | PDF object model. Pure Rust, the longest maintenance record of the candidates, and it exposes the object-graph access a full rewrite needs |
| `clap` | 4.6.6 | MIT OR Apache-2.0 | `strypt-cli` | Argument parsing |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 | `strypt-cli` | JSON output. Hand-rolling a serialiser to avoid a dependency means hand-rolling string escaping, and a metadata value is precisely the attacker-influenced text that finds the bugs in a hand-rolled escaper |

`lopdf` is taken with `default-features = false`, which drops `rayon` and `chrono-clock`.
Parallel object processing would put deterministic output at risk — invariant 4 in
`docs/TESTING_STRATEGY.md` §1, which the idempotence and byte-identity checks all rest on —
and a metadata scrubber has no business reading the wall clock.

**Consequences.**

- **`lopdf` is a parser sitting on hostile input, and it is not covered by this project's
  no-panic rule.** `#![forbid(unsafe_code)]` protects strypt's own code; it says nothing
  about whether a dependency panics on a malformed file. This is the largest single piece of
  untrusted-input surface in the tree and it is not ours. Mitigation is the fuzz target,
  which exercises `lopdf` through strypt on every run, and the honest statement here that a
  panic originating in it is a real possibility rather than a theoretical one. Phase 3's
  sandboxing investigation should weigh this specifically: containing a dependency is one of
  the few things sandboxing genuinely buys a safe-Rust parser.
- `lopdf` brings a substantial transitive tree even with defaults off — `aes`, `sha2`,
  `md-5`, `flate2`, `nom`, `encoding_rs`, `getrandom`, `rand`, and others. That is a real
  cost against ADR-0008 and it is accepted rather than waved away: writing a PDF parser from
  scratch for Phase 1 is not a credible alternative, and the alternative crate
  (`oxidize-pdf`) is younger and moving through major versions quickly.
- The no-network gate (`scripts/check-no-network.sh`) was run against the resolved graph with
  `lopdf` in it and passes. `tokio` is behind the non-default `async` feature and is not in
  the tree.
- `getrandom` and `rand` are present for `lopdf`'s encryption support. They are a determinism
  risk if any write path ever reaches them; the fixture-wide determinism test exists partly to
  catch that, and it passes.

---

## ADR-0019 — Output carries a fresh timestamp and owner-only permissions

**Status:** Accepted (2026-08-19)

**Context.** `docs/PRD.md` §8.3 flagged this as requiring an explicit decision. When strypt
writes a sanitised copy, it can preserve the source file's modification time and permission
bits, or it can not.

**Decision.** Neither is copied. Output gets the current time and `0600` on Unix.

**Consequences.**

- **Modification time is metadata.** Preserving it hands back a fact the user believed they
  had just removed — it can reveal when a photograph was taken or when a document was
  prepared, long after the EXIF or Info dictionary is gone. Copying it through would be a leak
  performed by the tool whose job is to prevent leaks.
- **The stripped file is the more sensitive artefact of the pair, not the less.** It is the
  one about to be published. A world-readable copy sitting in a shared directory in the
  meantime is avoidable exposure, so the default is owner-only. The temporary file is created
  with the same mode at open time rather than tightened afterwards, which closes the window in
  which it exists at the umask's permissions.
- **Costs, stated plainly.** Batch output all shares one timestamp, so file-manager sorting by
  date is lost. Users copying output somewhere another local account must read — a web
  server's directory, a shared `/srv` — will need `chmod`. For the personas in
  `docs/PRD.md` §5, working on their own machine and then uploading or emailing, neither costs
  anything: their own viewer, browser, and mail client read `0600` fine, and USB drives are
  usually FAT/exFAT, which has no Unix permission bits at all.
- **Windows is weaker and this is a known limitation, not an oversight.** There is no umask
  equivalent; a new file inherits the parent directory's ACL, and strypt does not currently
  narrow it. `Permissions::OwnerOnly` therefore means less there than on Unix. Phase 3's
  platform validation is where this gets addressed.
- If the timestamp loss proves genuinely annoying in practice, a `--preserve-times` flag is
  the right shape for the fix — opt-in, named for what it does, with the leak stated in its
  help text. It is not the default.

---

## ADR-0020 — PDF is rewritten in full, never patched incrementally

**Status:** Accepted (2026-08-19)

**Context.** A PDF can be edited by appending: the original bytes stay where they are, and a
new cross-reference section at the end declares which objects supersede which. Removing the
Info dictionary this way is easy, fast, and preserves the rest of the file almost perfectly.

The alternative is to parse the document into its object graph, scrub it, drop everything the
catalogue can no longer reach, and serialise a new file.

**Decision.** Full rewrite. Incremental patching is not offered, not even as a flag.

**Consequences.**

- **This is the whole reason the decision matters.** A patch leaves every superseded
  revision physically in the file. A document saved three times carries all three authors,
  and the first two are recoverable with a hex editor by anyone who thinks to look. Patching
  and reporting success would be a silent failure of the exact kind
  `docs/THREAT_MODEL.md` §5.4 identifies as the most dangerous bug class here: the user is
  told the file is clean and publishes it. `corpus/pdf/incremental-update.pdf` exists to hold
  this to account, and asserts on the output's *bytes* rather than on strypt's report.
- **Output is not byte-comparable with input**, object numbers change, and file size moves in
  both directions. Objects are renumbered deliberately so that output depends on the object
  graph rather than on whatever numbering the input happened to use — without which two
  documents that scrub to identical content would serialise differently, breaking the
  determinism invariant for no reason.
- **Files the rewrite cannot faithfully reproduce are refused, not mangled.** Encrypted
  documents are refused outright: `lopdf` can open one protected by an empty owner password,
  and emitting a decrypted copy would silently strip the user's protection along with their
  metadata — a change to their document's security they did not ask for and might not notice.
- **The residual risk is fidelity.** A rewrite touches every object, so a bug damages the
  document rather than merely failing. This is why the fixture set checks that content
  survives — an annotation's comment, a form field's name, an attachment's bytes — and not
  only that metadata does not. Real-producer files (LaTeX, Word, Acrobat, scanners) are the
  gap in that coverage today and are recorded as such in `corpus/MANIFEST.md`.
- Annotation `/T` is removed only on markup annotation subtypes. On a `/Widget` it is the
  form field's name, which the form's logic and its saved data depend on; removing it would
  break the document. Breaking a user's file to protect them is not a trade this tool makes
  silently.

---

## ADR-0021 — JPEG is edited by segment surgery, and two segments are kept on purpose

**Status:** Accepted (2026-08-19)

**Context.** A JPEG is a list of marker segments wrapped around entropy-coded scan data. All
of the identifying material — Exif, XMP, IPTC, ICC, comments, thumbnails — is in the `APPn`
and `COM` segments; none of it is in the scan data. Two implementation strategies exist:
decode the image and re-encode it without metadata, which is what most tooling does and what
mat2 does through Pillow, or walk the segment list and copy the scan data through untouched.

**Decision.** Segment surgery. The handler never decodes an image and never re-encodes one.
Within that, `APP0` (JFIF) and `APP14` (Adobe) are copied through and reported in the strip
report's `retained` list; Exif `Orientation` and the `APP2` ICC profile are removed despite
both affecting how the image renders.

**Consequences.**

- **The photograph is bit-identical afterwards.** Verified, not assumed: every fixture in
  `corpus/jpeg` is the same base image with different metadata around it, and
  `tests/jpeg.rs` asserts that all of them have byte-identical entropy-coded data after
  stripping. Measured against mat2 0.15.0 on 2026-08-19, over `corpus/jpeg/exif-gps.jpg`:
  strypt's output differs from the input by zero pixels (ImageMagick `compare -metric AE`),
  mat2's by a non-zero amount, because its JPEG path re-encodes. That is a deliberate
  trade-off on their side and a real one — re-encoding is robust against structures the
  parser does not understand — but for a photojournalist whose picture is the evidence,
  generation loss is damage (`docs/PRD.md` §8.1).
- **`APP0` (JFIF) is kept, minus any thumbnail inside it.** It carries the pixel aspect
  ratio, and dropping it changes how a non-square-pixel image displays. It is a fixed-shape
  structure naming no person, place, or device.
- **`APP14` (Adobe) is kept.** It declares the colour transform; a CMYK or YCCK file whose
  `APP14` was removed renders with wrong colours in many decoders. This is a **documented gap
  against mat2**, which removes it: strypt keeps two bytes of "this file is YCCK" and says so
  in the report rather than silently altering how the image looks.
- **Exif `Orientation` and the ICC profile go anyway**, and this is the opposite trade to the
  one above, so the line is worth stating: both are identifying — an ICC profile routinely
  names the device or vendor it was made for, and a per-device profile is a fingerprint —
  whereas neither `APP0` nor `APP14` names anything. The cost is that an image that relied on
  `Orientation` may display rotated, and a wide-gamut image is afterwards interpreted as
  sRGB. Both are in `CHANGELOG.md` under known limitations.
- **Everything after the `EOI` marker is removed.** No decoder reads it and few users know it
  is there; in practice it is where a phone's multi-picture extension keeps a second
  full-resolution frame — an unredacted copy of the picture, past the end of the picture.
- **A file that ends without an `EOI` is refused, not completed.** Emitting a repaired copy of
  a damaged file would hand the user something that is not what they gave us, presented as a
  clean version of it.
- **Exif is removed whole, never edited tag by tag.** A TIFF block is a graph of absolute
  offsets, so removing one tag means rewriting every offset after it, and an error there
  produces a file that still parses while pointing at the wrong bytes. `formats/exif.rs`
  therefore only reads — it exists to name what was in the block, because "GPSLatitude,
  BodySerialNumber, DateTimeOriginal" is what lets someone judge a file they already
  published, and "a 12 KB Exif block" is not.

---

## ADR-0022 — PNG is edited by chunk surgery, and compressed text is never inflated

**Status:** Accepted (2026-08-19)

**Context.** A PNG is a signature followed by a flat list of chunks, each carrying its own
length, type, payload, and CRC. Everything identifying lives in ancillary chunks — `tEXt`,
`zTXt`, `iTXt`, `tIME`, `eXIf`, `iCCP` — and the picture lives in `IDAT`. So the structural
question that ADR-0021 settled for JPEG barely arises here: chunk surgery is obviously right,
and re-encoding would be indefensible for a format whose whole point is losslessness.

The question that did need deciding is compression. `zTXt` is compressed by definition and
`iTXt` is compressed when its compression flag is set, so the natural assumption is that this
handler needs a zlib decompressor, and therefore a new dependency and this ADR.

That assumption is wrong, and checking it is the reason this ADR exists. Per the PNG
specification (W3C PNG Third Edition, §11.3.3.3 `zTXt` and §11.3.3.4 `iTXt`, checked
2026-08-19), the keyword, the compression flag, the language tag, and the translated keyword
are **all uncompressed**; only the text itself is compressed. `iCCP`'s profile name — the part
that names a device or a vendor — is uncompressed too, and `eXIf` is a raw TIFF block that the
existing reader in `formats/exif.rs` handles directly.

Every chunk in that list is removed **whole**. Nothing that decides what is removed is behind
the compression, and no inflated byte could ever reach the output file. Decompression would
change one thing only: how finely the *report* names what was in a compressed chunk.

**Decision.** Chunk surgery, with no decompressor. `strypt-core` gains no dependency for PNG.
Compressed text is reported by its keyword — which is enough to say what the chunk was — and
the chunk is removed either way.

The kept-versus-removed line follows ADR-0021's test, "does it name a person, a place, or a
device": `IHDR`, `PLTE`, `IDAT`, `IEND` and the rendering chunks (`tRNS`, `gAMA`, `cHRM`,
`sRGB`, `sBIT`, `pHYs`, `bKGD`, `hIST`, `cICP`, `mDCV`, `cLLI`, and the APNG chunks `acTL`,
`fcTL`, `fdAT`) are copied through byte for byte. `pHYs` is additionally declared in the strip
report's `retained` list, because it is the chunk a careful user is most likely to expect to
have gone.

**Consequences.**

- **This is the same trade the PDF handler already made, in the same direction.** A
  `FlateDecode`d XMP stream is reported as one item rather than itemised by property
  (`formats/pdf.rs`, and `docs/THREAT_MODEL.md` §7.1). Inflating for PNG while refusing to
  inflate for PDF would have left the project holding two positions on one question. The
  rejected option was `miniz_oxide` — pure Rust, `#![forbid(unsafe_code)]`, already in the
  tree transitively via `lopdf` → `flate2`, and with `decompress_to_vec_zlib_with_limit` it
  offers exactly the bounded primitive `ParseLimits::max_expanded_bytes` was shaped for. It
  was still declined: the gain is report granularity on a minority of chunks, and the cost is
  a decompression-bomb surface, a direct dependency (ADR-0008), and a pin to the `0.8` line
  that `flate2 1.1.9` requires while `0.9.1` is current — taking `0.9` instead would put two
  inflate implementations in one binary.
- **The report is less detailed for compressed chunks, and this is the honest cost.** An XMP
  packet in an uncompressed `iTXt` is broken down by property; the same packet compressed is
  one finding. ImageMagick's `Raw profile type exif` and `Raw profile type iptc` chunks are
  reported by keyword and classified by what that keyword means the chunk is, not by reading
  inside it. Recorded in `docs/THREAT_MODEL.md` §7.3 rather than left for a user to discover.
- **`ParseLimits::max_expanded_bytes` and `ResourceLimit::ExpandedSize` stay in the API with
  no caller.** WebP brings no zlib either, so nothing in Phase 1 will use them. They are
  marked as reserved where they are defined rather than quietly left looking enforced. Phase
  2's ZIP-container formats are what they were built for.
- **CRCs are copied, never recomputed, and never checked.** A chunk's CRC covers only its own
  type and data, and this handler never alters a chunk it keeps — so a kept chunk's CRC is
  still correct by construction, and no CRC implementation is needed anywhere in the tree.
  Validating them was declined separately: strypt is not a decoder, and refusing a file whose
  CRC a previous tool left stale would help nobody. A corrupt file is a decoder's problem;
  a file that lies about its *lengths* is ours, and those are checked on every chunk.
- **A clean PNG strips to a byte-identical copy of itself**, because kept chunks are copied
  as raw bytes rather than re-serialised. That is a stronger property than the JPEG handler's
  and it makes idempotence a consequence of the design rather than a test result.
- **Unknown chunks split by the ancillary bit** (bit 5 of the first byte of the type, §5.4).
  An unknown *ancillary* chunk is removed and reported: a private chunk can hold anything, and
  a scrubber that copies through what it does not understand is not scrubbing. An unknown
  *critical* chunk is kept, with a `Note::UnparsedRegion` saying its bytes were preserved and
  anything inside them was not removed. Critical means whoever wrote the file marked that
  chunk as required in order to interpret the image, and strypt cannot know what it holds or
  what depends on it — so it copies it through and says so, rather than deciding on the user's
  behalf that it was disposable. Note the honest consequence: a conforming decoder already
  refuses such a file, so keeping the chunk keeps the file exactly as unreadable as it
  arrived. Silently dropping it to make the file open would be strypt changing what the
  document *is*, which is a larger decision than the one the user asked for.
- **`sPLT` is removed** despite being a standard rendering chunk, which is the one place this
  handler departs from "keep what affects rendering". Its palette-name field is arbitrary
  text, so it is a text carrier; it is advisory data used only by decoders that cannot display
  the full image, so removing it changes nothing a modern viewer does.
- **Everything after `IEND` is removed**, for the reason `EOI` trailing data is removed from a
  JPEG: no decoder reads it, few users know it can be there, and it is a convenient place for
  a second copy of something.

---

## ADR-0023 — WebP is edited by chunk surgery, and `VP8X`'s flags are corrected rather than left lying

**Status:** Accepted (2026-08-19)

**Context.** A WebP file is a RIFF container: an eight-byte header, the `WEBP` form type, and
a flat list of chunks with no checksums anywhere (RFC 9649 §2.3, checked 2026-08-19 — RFC 9649
is now the container's authoritative specification, superseding the Google developer page as a
citable source). Structurally it is the closest thing in this crate to PNG, and the structural
question ADR-0021 settled for JPEG and ADR-0022 settled for PNG barely arises: chunk surgery is
obviously right, kept chunks copy through byte for byte, and there is not even a CRC to
preserve. All the metadata lives in exactly three chunks — `ICCP`, `EXIF`, and `XMP ` — plus
whatever a producer left in an unknown one.

The question that did need deciding is what happens to `VP8X`. An extended-format file opens
with that chunk, and its flags byte declares which optional parts the file has: an ICC profile,
an alpha channel, Exif metadata, XMP metadata, an animation (§2.7). Remove the `EXIF` chunk and
leave its bit set and the file now lies about itself — some decoders warn, some refuse. So
unlike PNG, **stripping a WebP requires mutating a chunk that is kept**. Three options were on
the table: clear the flag bits, drop `VP8X` entirely once no flags remain, or refuse extended
files outright.

**Decision.** Clear the three metadata flag bits in `VP8X` and copy every other byte of the
chunk through unchanged. The alpha and animation bits, the reserved bits, and the canvas
dimensions are untouched. A `VP8X` whose metadata bits are already clear is copied verbatim, so
the rewrite happens only where it changes something.

**Rationale, and why the other two were declined.**

- **Dropping `VP8X` when no flags remain** produces a smaller file but rewrites the container's
  shape, and it is only safe if the header's canvas dimensions agree with the bitstream's own.
  Verifying that means parsing a VP8 or VP8L bitstream — a decoder, on attacker-controlled
  bytes, inside a tool whose whole design avoids exactly that — for a cosmetic gain.
- **Refusing extended files** is safe and close to useless: §2.7 requires the extended header
  before any metadata chunk, so every WebP that carries metadata is an extended file. That
  option succeeds only on the files that needed nothing done.
- **Precedent already runs in this direction.** The JPEG handler rewrites `APP0` to zero a
  thumbnail's dimensions (ADR-0021). A kept structure being corrected to match what was removed
  is an established position in this project, not a new one.

**Consequences.**

- **An extended file is no longer a pure byte-for-byte copy of its kept chunks.** One byte
  changes, plus the RIFF size field, which has to be recomputed once any chunk is gone. A
  *simple*-format file — one with no `VP8X` — cannot carry metadata at all, so it is a
  guaranteed byte-identical pass-through, and `tests/webp.rs` asserts that rather than leaving
  it implicit. So is an extended file whose flags describe only the picture.
- **A file can be modified with nothing reported as removed.** A header claiming an Exif chunk
  the file does not have is corrected on strip, while `show` reports no findings — the flags
  are not metadata. This is a real inconsistency between the two commands and it is the honest
  one: the alternative is either inventing a finding for a byte that names nobody, or leaving a
  file that lies.
- **No decompressor, again.** Nothing WebP puts metadata in is compressed at the container
  level, so `strypt-core` gains no dependency and no inflate path (as ADR-0022 anticipated when
  it left `ParseLimits::max_expanded_bytes` reserved with no caller).
- **Unknown chunks are removed, which is a deliberate departure from the specification.**
  §2.7.1.6 tells readers to ignore unknown chunks and writers to preserve them. strypt does the
  first and not the second: it is not a general WebP writer, and an unknown chunk is precisely
  where something goes that its producer would rather a metadata tool did not look at. Because
  the same section makes them ignorable to readers, dropping one cannot break a decoder — which
  is why this handler has no equivalent of PNG's unknown-critical-chunk dilemma.
- **Animation frames are filtered, not merely copied.** §2.7.1.1 allows an `ANMF` frame to
  carry an optional list of unknown chunks alongside its alpha and bitstream sub-chunks, which
  makes the inside of a frame a hiding place with the specification's blessing. So the
  sub-chunk area is walked and filtered the same way the top level is, and the sixteen-byte
  frame header is copied verbatim — nothing in it depends on which sub-chunks follow. A frame
  whose sub-chunk area does not parse is kept exactly as it arrived, with a
  `Note::UnparsedRegion` saying so; a frame that needed nothing dropped is copied rather than
  reassembled, so an ordinary animation still passes through byte-identically.
- **The file is refused if it would strip to a container with no picture in it.** A file whose
  only chunks are `VP8X` and `EXIF` would otherwise produce a valid-looking WebP with no image,
  reported as a success. So is a file that does not open with `VP8X`, `VP8 `, or `VP8L`, one
  whose `VP8X` is not exactly ten bytes, one whose RIFF or chunk size runs past what is
  available, and one whose four-character code is not ASCII.
- **A `EXIF` chunk beginning with JPEG's `Exif\0\0` introducer is tolerated.** §2.7.1.5 puts no
  introducer here, but a producer copying a JPEG `APP1` payload across brings one, and feeding
  those six bytes to the shared TIFF reader shifts every offset inside the block and yields a
  confident parse of the wrong bytes. The chunk is removed either way; this only decides
  whether the report is right about what was in it.
- **Everything past the declared RIFF size is removed**, for the reason trailing data is
  removed from a JPEG and a PNG: no decoder reads it, few users know it can be there, and it is
  a convenient place for a second copy of something.

---

## ADR-0024 — A panic inside a third-party parser is contained and reported as a refusal

**Status:** Accepted (2026-08-21)

**Context.** ADR-0006 requires strypt's own parsing code never to panic: malformed input is
expected input, and failures are typed `Result` values. ADR-0018 accepted `lopdf` as the PDF
parser and recorded plainly that this rule does not extend inside it —
`docs/THREAT_MODEL.md` §5.1 names a panic in a dependency as one of the residual risks that
`forbid(unsafe_code)` does not address, precisely because memory safety and panic-freedom are
different properties.

On 2026-08-21 that stopped being theoretical. A sustained fuzz run reached an integer overflow
in `lopdf` 0.44.0's cross-reference parser — `parser/mod.rs:516`, computing `start + index`
where `start` is read from the file. `Cargo.toml` deliberately enables `overflow-checks` in
release so that an overflow while parsing an attacker-controlled field aborts rather than
wrapping into a nonsensical offset, so the **shipped binary** panicked: exit code 101 and a
Rust stack trace, on a file a user might plausibly be handed by someone hostile. 0.44.0 was
already the newest release, so there was no upgrade to take.

**Decision.** Calls into `lopdf` that touch untrusted bytes — parsing and serialisation — are
wrapped by `strypt_core::panic_guard::guard`, which converts an unwinding panic into
`Malformed { detail: DependencyPanic }`. The user gets an ordinary refusal, and nothing is
written. The defect is reported upstream separately; containment is not a fix.

**Alternatives considered.**

*Report upstream and wait.* Correct, and being done, but it leaves strypt crashing on hostile
input for however long a third party's release cycle takes. Not acceptable on its own for a
tool whose users are handed files by people who may wish them harm.

*Validate the cross-reference table before handing bytes to `lopdf`.* Rejected. It puts more
of our own code in the most security-sensitive path in the project to work around someone
else's bug, and ADR-0018 argues specifically against pre-processing untrusted bytes ahead of
the parser. It would also only address the overflow we happen to know about.

*Accept the panic as fail-closed behaviour.* It is genuinely fail-closed — the process dies
before writing anything, so no partially-sanitised file escapes and no success is reported.
But a crash is still a denial of service, it is indistinguishable to the user from a bug in
strypt itself, and Phase 1 exit criterion 2 requires zero panics across the fuzz targets. A
criterion satisfied by redefining the failure as acceptable is not satisfied.

**Consequences.**

- A dependency panic reaches the user as "the parser failed on this file and it was not
  processed", with a distinct `DependencyPanic` detail so the occurrence stays findable in the
  wild rather than being folded into ordinary refusals.
- **This depends on unwinding panics.** Building with `panic = "abort"` defeats it entirely.
  strypt does not set `panic = "abort"`, and this ADR is a reason not to.
- It cannot catch what does not unwind: stack overflow from deep recursion, an abort, or a
  signal. Bounded recursion via `ParseLimits` remains the control for the first.
- **It says nothing about correctness.** A dependency that panics may equally return a wrong
  answer quietly, which no guard detects. This is a floor, not a guarantee, and it must not be
  cited as evidence that dependency defects are handled.
- The panic message is suppressed for guarded calls only, via a thread-local flag, because a
  parser's panic message can quote the bytes it was parsing — which are the user's document,
  and CLAUDE.md §3.8 forbids printing metadata values.
- It is a general mechanism rather than a PDF one. Any future handler wrapping a third-party
  parser should use it, and Phase 2's ZIP-container work is the obvious next candidate.

---

## ADR-0025 — The real-producer corpus stays fetched, not committed

**Status:** Accepted (2026-08-22)

**Context.** Phase 1 carried an outstanding item reading *"committed fixtures for real
producers, since the fetched files cannot serve that role — they carry real names, a device
serial and live GPS coordinates."* It was the last thing standing between the phase and done,
and the question of how to close it kept recurring, so it is settled here rather than in a
`.gitignore` comment.

Two things changed since it was written. `sanitise_corpus.py` (2026-08-22) now replaces every
real name, the camera serial, and the live GPS with synthetic values on every build, verified,
with the build aborting rather than writing a manifest if anything real survives — so the
item's own stated reason no longer holds. And the upstream licences were checked properly
rather than assumed:

| Upstream | Files | Licence |
|---|---|---|
| py-pdf/sample-files | 22 PDFs, 7.6 MB | CC BY-SA 4.0 — determinate, copyleft |
| codec-corpus/image-rs | 9 PNG/WebP, 96 KB | MIT |
| codec-corpus/{png-conformance, imageflow, webp-conformance} | 20 files | "Various" — undetermined |
| ianare/exif-samples | 20 JPEGs, 19 MB | **no LICENSE file exists**; archived 2025-04-22 |

**Decision.** The real-producer corpus is **not** committed. `build_real_corpus.py`,
`sanitise_corpus.py`, `MANIFEST.csv` and `MANIFEST.md` are committed and reproduce it on
demand. What lands in `corpus/` is what it always has been: synthetic fixtures, and small
synthetic reproductions of anything the real corpus finds.

**Why not commit a licence-clean subset.** It was proposed and rejected, because the value is
inverted. The files at real risk of vanishing are exactly the ones that cannot be committed —
`exif-samples` is archived and carries no licence at all. The files that *could* be committed
come from active repositories at low risk of disappearing. Committing would take on licensing
obligations and permanent git weight for the fixtures that need it least, while doing nothing
for the fragile ones.

The discovery-to-fixture workflow also already works without redistribution, and
`docs/TESTING_STRATEGY.md` §3 already prescribes it: *"if a reporter's file cannot be
sanitised, reproduce the structure synthetically instead."* `corpus/pdf/malformed/xref-19-byte-entries.pdf`
exists because the real corpus hit that limitation against a real scanner PDF and a synthetic
reproduction was committed; `stream-length-mismatch.pdf` came the same way. Those synthetic
files are what the regression tests actually run against. No third-party file needed to enter
git history for any of it.

Committing would also breach §3's own size rule — large fixtures belong in a fetched-on-demand
corpus — at 32 MB, or 2.5 MB even for the licence-clean subset.

**Consequences.**

- Phase 1 exit criteria are met and the phase closes on this decision.
- **`exif-samples` being archived is an unmitigated risk, stated plainly.** JPEG real-producer
  coverage depends on a repository nobody maintains, and it cannot be reconstituted if it
  disappears, because there is no licence under which to keep a copy. The available mitigation
  is first-party photographs, whose licence is the project's own; none exist yet.
- **There is no offline real-producer sweep.** Running one requires a fetch. This is the single
  concrete thing committing would have bought, and it is given up knowingly.
- Anything the real corpus finds must still be reproduced synthetically and committed, per
  §3. A finding that lives only in the fetched corpus is a finding that will be lost.
- If a future phase does commit real-producer files, the licence table above is the starting
  point, and `exif-samples` is not an option without an upstream grant.

---

## ADR-0026 — The CLI crate is named `strypt`, not `strypt-cli`

**Status:** Accepted (2026-08-23)

**Context.** `strypt-core` and `strypt-cli` were published to crates.io at `0.0.1` on
2026-08-23, ahead of Phase 4, because crates.io names are not reservable in advance and a
stub crate that only holds one violates the registry's policy against a crate that "exists
only to reserve a name ... without having any genuine functionality". Publishing the working
code was the only policy-compliant way to keep the names.

That left `strypt` unregistered, and the first assessment was to leave it that way on the
grounds that registering a name with no crate behind it is exactly the squatting the policy
targets. That assessment missed the consequence that matters:

**The binary is named `strypt`.** Every usage example, every line of `--help`, and the output
of `--version` print that word. The command a user will type unprompted is `cargo install
strypt`. While the name is unregistered that command fails harmlessly; once someone else takes
it, the most guessable install path for a metadata-removal tool silently resolves to a
stranger's code, under the exact name this project's documentation tells people to use.

For a tool whose users include people for whom a metadata leak is a physical safety event,
that is an impersonation vector, not a packaging inconvenience — and it is the kind that is
cheap to close now and impossible to close later.

**Decision.** The CLI crate is named `strypt`. The package was renamed `strypt-cli` →
`strypt` and its directory moved `crates/strypt-cli/` → `crates/strypt/`; the `[[bin]]` target
was already `strypt`, so the built binary is unchanged. `cargo install strypt` installs it.

`strypt-cli` `0.0.1` is **yanked, not abandoned**. Yanking keeps the name registered to this
project — so it cannot be taken and used to impersonate the tool — while preventing anyone
from installing a version that will never receive a fix. A never-updated `0.0.1` of a security
tool sitting installable on crates.io indefinitely is the worse outcome of the two.

This is not squatting in either direction. `strypt` carries the actual CLI; `strypt-cli`
carries a real published version of the same program under its former name.

**Consequences.**

- Both `strypt` and `strypt-core` are held by real code. `strypt-cli` is held by a yanked
  real version. All three names are out of reach of a squatter.
- `cargo install strypt-cli` no longer resolves. This is intended. The README says where the
  name went and that it is the same tool, so the failure is explicable rather than a
  dead end.
- The rename cost one publish and a documentation sweep, done the same day the crates went up
  and while they had no users. The same change after adoption would have broken dependents.
- Historical ADRs and completed-phase records still say `strypt-cli`, and are deliberately
  left alone — they record what was true when written. Living documents (`README.md`,
  `INSTRUCTIONS.md`, `ARCHITECTURE.md`, `SECURITY.md`, `CLAUDE.md`) were updated.
- Publishing early does not advance Phase 4 and does not imply Phase 3 happened. `0.0.1`
  means what it says; `docs/ROADMAP.md` Phase 4 records the deliverable as partly done and
  states what it does not cover.
