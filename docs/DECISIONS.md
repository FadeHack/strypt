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

**Status:** Accepted (2026-08-19) · scope lock superseded by ADR-0027 (2026-08-23). The
reasoning below — why these four, and why a shallow handler is worse than no handler — stands
and is inherited by Phase 2.

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
  narrow it. `Permissions::OwnerOnly` therefore means less there than on Unix. **Recorded as
  permanent by ADR-0047.**
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

---

## ADR-0027 — Phase 2 opens, and its format scope is fixed at OOXML first

**Status:** Accepted (2026-08-23)

**Supersedes ADR-0005** for the purpose of the scope lock only. ADR-0005's rationale for
*why* the Phase 1 four were chosen, and its rule that a shallow handler is worse than no
handler, both stand unchanged and are inherited by this phase.

**Context.** ADR-0005 locked the supported-format list to JPEG, PNG, WebP, and PDF "for the
duration of the phase", and required a superseding ADR rather than a judgement call to widen
it. Phase 1 closed on 2026-08-22 with all seven exit criteria met, so that lock has served
its purpose and now blocks the work it was written to sequence.

`docs/ROADMAP.md` Phase 2 lists four deliverable groups in priority order — OOXML,
OpenDocument, additional images, then audio and video containers — ordered by user risk
rather than by implementation ease. Nothing about closing Phase 1 changes that ordering, and
this ADR does not revisit it.

**Decision.** Phase 2 is open. The scope lock moves rather than disappearing:

- **The phase's format list is exactly the four groups in `docs/ROADMAP.md` Phase 2.** Adding
  a format outside them still requires a superseding ADR. "Phase 2 is open" is not "scope is
  open".
- **Formats land one group at a time, in the roadmap's order**, and a group is not started
  until the previous one meets Phase 1's per-format bar in full. Phase 2 exit criterion 1
  forbids provisional handlers, and the cheapest way to honour that is to never have more
  than one incomplete handler in the tree.
- **Office Open XML — `.docx`, `.xlsx`, `.pptx` — is the group in progress.** OpenDocument,
  the additional image formats, and the audio/video containers are not started, and the same
  "check before referencing a later artefact" rule that applied across phases now applies
  within this one.

**The Phase 1 bar is restated here in full, because "meets the Phase 1 bar" is the load-
bearing phrase in Phase 2's exit criteria** and a reader should not have to reconstruct it:
handler, fuzz target and seed corpus landing in the same change as the handler, integration
tests including byte-identical idempotence, differential comparison against mat2 and
ExifTool, a `docs/THREAT_MODEL.md` section recording what was actually learned about the
format, and a `CHANGELOG.md` entry.

**Consequences.**

- ADR-0005 is superseded on scope and retained on reasoning. Its warning about the fifth
  format during Phase 1 now reads as the warning about the fifth *group* during Phase 2.
- The detection module's Phase 1 comment — that a hand-written magic-number matcher is
  adequate until "the supported-format count grows and the container types get genuinely
  ambiguous" — has come due. OOXML and ODF are both ZIP, so the ZIP signature alone can no
  longer route a file; detection has to look inside the container. That is handled in
  ADR-0028 rather than by taking the magic-table dependency the comment anticipated, because
  the ambiguity is not between many formats but between two, and both are resolved by
  reading an entry name.
- **The positioning rule in ADR-0012 gets harder to hold in this phase, not easier.** Phase 2
  is explicitly about moving toward mat2's format list, and every format shipped narrows a
  gap. That is exactly when "successor" and "replacement" language creeps into a changelog
  entry. It remains banned, at parity and beyond.
- Nothing here advances Phase 3. Sustained fuzzing budgets, the known-limitations page, the
  sandboxing decision, and live-OS validation are all still ahead, and a shipped OOXML
  handler does not imply any of them.

---

## ADR-0028 — The ZIP container layer is written here, not taken as a dependency

**Status:** Accepted (2026-08-23)

**Context.** Every format in Phase 2's first two groups — OOXML and OpenDocument — is a ZIP
archive with an agreed directory layout inside it. Reaching their metadata means parsing ZIP:
the end-of-central-directory record, the central directory, local file headers, ZIP64
extensions, and the data descriptors that streaming writers leave behind. This is a full
hostile-input parser, and `docs/ROADMAP.md` Phase 2 names it as such — "treat the ZIP layer
as a hostile parser in its own right, with its own fuzz target".

Three options were evaluated on 2026-08-23, with versions checked against crates.io the same
day rather than recalled:

| Option | Version | Licence | Assessment |
|---|---|---|---|
| `zip` | 9.0.0-pre3 (2026-08-11) | MIT | The ecosystem default and the most exposed to real-world archive quirks. Two costs: it is a pre-release, and its default feature set turns on `aes-crypto`, `bzip2`, `lzma`, `zstd`, `ppmd`, and `xz`. Several of those are bindings to C libraries. They can be switched off, but a security tool whose central technical claim is memory-safe parsing (`docs/PRD.md` §4) should not be one accidental feature-unification away from linking a C decompressor |
| `rawzip` | 0.5.1 (2026-07-13) | MIT | Zero dependencies, no `unsafe`, edition 2024, ~355k downloads. Genuinely the closest fit of the two crates. Still young at 0.x, and it would sit directly on hostile input under someone else's panic policy |
| Hand-written | — | — | Roughly 600–800 lines against APPNOTE.TXT, under this crate's own no-panic lints, fuzzed as ours |

**Decision.** The ZIP container layer is written in `strypt-core`, as
`crates/strypt-core/src/container/zip.rs`, reading through `crate::bytes::Reader` like every
other parser here. It has its own fuzz target, independent of any format handler that sits on
top of it.

**Rationale, and the honest version of it.** The decisive argument is not "we can write it
better". It is that **the panic-freedom rule in ADR-0006 is the project's actual safety
property, and it does not extend across a dependency boundary.** ADR-0018 accepted that gap
for `lopdf` because writing a PDF parser was not a credible alternative — and then every
single defect the sustained fuzzing found in Phase 1 was in the PDF path, one of them a panic
inside `lopdf` itself that reached the shipped binary and had to be contained by
`panic_guard` (ADR-0024). ZIP's central directory is a far smaller specification than PDF's
object graph. The alternative that was not credible for PDF is credible here, and taking it
means the largest new hostile-input surface in Phase 2 is covered by the rule rather than
excepted from it.

Two things are **not** claimed. First, this is not a general-purpose ZIP implementation and
must never be described as one: it reads the subset that OOXML and ODF actually use and
refuses the rest — see the refusal list below. Second, hand-written does not mean bug-free.
It means the bugs are ours to find with our own fuzz target and to fix without waiting on an
upstream, which is a different property from correctness.

**What it refuses rather than handles.** Each of these is a deliberate fail-closed refusal,
not a gap to be quietly tolerated:

- **Encrypted entries** (general-purpose bit 0), including the AES extensions. strypt cannot
  inspect what it cannot read, and a "cleaned" encrypted document would be a success message
  about a file whose metadata was never examined.
- **Any compression method other than stored (0) and deflate (8).** These are the two OOXML
  and ODF use. Refusing the rest keeps bzip2, LZMA, zstd, XZ, and PPMd — the exact decoders
  that made the `zip` crate's default features a problem — out of the tree entirely.
- **Multi-disk and spanned archives.**
- **Entry names that are absolute, contain a `..` component, or contain a backslash.** No
  entry is ever written to the filesystem by name, so path traversal is not directly
  exploitable here; the names are refused anyway, because a document containing one is not a
  document and treating it as ordinary is how the assumption "we never write these out"
  silently stops being true in a later phase.

**Consequences.**

- **`flate2` becomes a direct dependency of `strypt-core`, for decompression only**, pinned
  to `default-features = false, features = ["rust_backend"]` so the backend is `miniz_oxide`
  and never a C zlib. It is already in the resolved graph at 1.1.9 by way of `lopdf`, so this
  adds no new crate — it promotes an existing transitive one to declared, which ADR-0008
  prefers on the grounds that an audited dependency should be visible in the manifest.
  `crc32fast` 1.5.0 is promoted the same way, for the CRC-32 every ZIP entry header carries.
  The residual risk is feature unification: if any future dependency enables `flate2`'s
  `zlib` feature, the whole graph gets the C backend regardless of what is declared here.
  `scripts/check-no-network.sh` does not see that, so it is called out here and belongs in the
  `deny.toml` bans list when Phase 3 makes `cargo-deny` a hard gate.
- **strypt gains an inflate path for the first time**, which makes
  `ParseLimits::max_expanded_bytes` load-bearing rather than reserved. `formats/mod.rs`
  documented it as reserved specifically against this moment. Decompression is bounded by
  that ceiling *and* by a per-entry expansion-ratio check, because a limit expressed only in
  absolute bytes still lets a 1 KB archive cost 256 MB of work.
- **Nothing is compressed on the way out.** Entries strypt does not modify are copied through
  with their original compressed bytes, header, and CRC verbatim, so an unmodified entry is
  byte-identical by construction. Entries strypt rewrites are re-emitted **stored**,
  uncompressed. This is deliberate: deflate output is implementation-defined, so compressing
  on output would make byte-identical idempotence depend on a compressor's internal choices
  staying stable across versions — a property no compressor promises. The cost is a slightly
  larger output file for the rewritten parts, which is recorded rather than hidden. It also
  means no deflate *encoder* is needed at all, only the decoder.
- The ZIP layer lives under `container/`, not `formats/`, because it is not a format anyone
  hands to strypt on its own — it is machinery two format groups share, in the same way
  `formats/exif.rs` and `formats/xmp.rs` are shared readers. A bare `.zip` file remains
  unsupported and is refused as such.

---

## ADR-0029 — strypt descends exactly one level, and only into images

**Status:** Accepted (2026-08-23)

This ADR satisfies Phase 2 exit criterion 4, which requires the recursion decision to be
recorded rather than defaulted.

**Context.** A `.docx` is a container of other files. Among them are the photographs the
author pasted in, in `word/media/`, arriving with whatever their camera wrote — GPS
coordinates, a body serial number, an embedded thumbnail of the uncropped original. The
document's own `docProps/core.xml` is the obvious target and it is not the dangerous one: a
user who strips a report and publishes it has published every geotag in every picture inside
it, while holding a success message that said the document was cleaned.

That is the failure in `CLAUDE.md` §3 rule 6 and `docs/THREAT_MODEL.md` §5.4, arriving by a
new route. But the opposite extreme is a different hazard: a container that recurses into
containers without limit is a zip bomb and a stack-exhaustion target, and stack exhaustion
aborts the process rather than raising a catchable error.

**Decision.** strypt descends **exactly one level**, into **image formats only**.

- An entry inside a ZIP container that content-sniffs as JPEG, PNG, or WebP is routed to that
  format's existing handler. Its findings are reported with the entry path as their location,
  so a report says `word/media/image2.jpeg → APP1 (Exif)` rather than attributing the leak to
  the document as a whole.
- An entry that sniffs as **any container format — ZIP, or PDF —** is **not** descended into.
  A nested archive is refused outright, and the file it was found in is refused with it: a
  `.docx` containing a `.docx` is not something to partially clean.
- Recursion depth is fixed at 1 in the type system rather than in a counter. The function
  that processes an embedded entry cannot call itself, and image handlers do not open
  containers, so a second level is unreachable by construction. A depth counter that could be
  raised later would be an invitation to raise it.

**Why PDF is excluded from the descent even though a handler exists.** A PDF inside a `.docx`
goes through `lopdf`, which is the one parser in the tree outside the no-panic rule and the
one that produced every fuzz defect in Phase 1 (ADR-0018, ADR-0024). Reaching it through a
decompressed, attacker-chosen ZIP entry composes the project's weakest parser with its newest
one. That may become reasonable later, with evidence; it is not the thing to do in the change
that introduces the ZIP layer. Embedded PDFs are reported as `Note::OutOfScopeContent` and the
document is refused, so the user learns the file is there rather than publishing over it.

**Bounds, all of which refuse rather than truncate.**

- Entry count per archive, against `ParseLimits::max_items`.
- Total decompressed bytes across the archive, against `ParseLimits::max_expanded_bytes`.
- Per-entry expansion ratio, because an absolute byte ceiling alone still permits a tiny
  archive to demand the whole ceiling's worth of work.
- Decompressed output is bounded *as it is produced*, not checked after the fact. A limit
  tested after inflating is not a limit.

**Consequences.**

- **This is the honest position, not the comfortable one.** A one-level descent means a
  photograph inside a document is cleaned, and it means strypt refuses documents that a less
  careful tool would report as cleaned. The refusals are visible and the leaks would not have
  been, which is the correct direction for the trade.
- The embedded image is stripped by the *same* handler code the CLI uses on a loose file, so
  it inherits Phase 1's verification pass, its byte-identical idempotence, and its recorded
  limitations. There is no second, weaker implementation of JPEG stripping for the embedded
  case, which would be exactly the divergence ADR-0003 exists to prevent.
- The container handler's `inspect` must see embedded image metadata, because the pipeline's
  verification pass re-inspects the output and fails on any residual finding. Descending in
  `strip` but not in `inspect` would make every document with a photograph in it fail
  verification. They share one pass, as the WebP handler already does.
- Extending the descent — to PDF, to a second level, to nested archives — requires a
  superseding ADR with fuzzing evidence behind it. It is not a configuration flag, and there
  is deliberately no CLI option to raise the depth.

---

## ADR-0030 — Office Open XML is edited by part surgery, and three parts are rewritten

**Status:** Accepted (2026-08-23)

**Context.** An OOXML document is a ZIP archive of XML parts described by
`[Content_Types].xml` and wired together by relationship parts under `_rels/`. Its metadata
is not in one place:

- `docProps/core.xml` — Dublin Core: `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`,
  `dcterms:modified`, `cp:revision`, `cp:category`, `cp:keywords`.
- `docProps/app.xml` — the producing application and its version, `Company`, `Manager`,
  `TotalTime` (cumulative editing minutes), page and word counts, and the document's heading
  and title structure.
- `docProps/custom.xml` — arbitrary named properties, frequently written by document
  management systems and frequently carrying an internal matter number or a username.
- `docProps/thumbnail.*` — a rendered preview of the first page, which survives every kind of
  redaction applied to the text.
- Revision-save identifiers (`w:rsid` and the `settings.xml` `w:rsids` table) which
  correlate editing sessions across documents, tracked changes, and comments, each of which
  names its author inline in the document body.

Removing a part from a ZIP is not enough. `[Content_Types].xml` still declares its type and
`_rels/.rels` still points at it, and a document referencing parts that are not there is
invalid — Word repairs it with a prompt, which is a worse outcome for a user trying not to
draw attention to a file than a slightly larger one.

**Decision.** The handler removes parts and rewrites exactly the parts that referred to them.

**Removed entirely:** `docProps/core.xml`, `docProps/app.xml`, `docProps/custom.xml`,
`docProps/thumbnail.*`, and any part whose content type is a Core Properties, Extended
Properties, Custom Properties, or Thumbnail type — matched **by content type, not by path**,
because the path is a convention and the content type is the contract.

**Rewritten:** `[Content_Types].xml` loses the `Override` entries for the removed parts;
`_rels/.rels` loses the `Relationship` entries whose `Target` was a removed part; the main
document part and `word/settings.xml` (and their spreadsheet and presentation equivalents)
lose revision-save identifiers. Rewritten parts are re-emitted **stored**, per ADR-0028.

**Kept, and declared as kept:** the document body, its styles, its numbering, its embedded
fonts, and every relationship to a part that still exists. Comments and tracked changes are
**out of scope for this change and reported, not removed** — see below.

**Comments and tracked changes are reported as `OutOfScopeContent`, not stripped.** Removing
a tracked insertion means choosing whether the document accepts or rejects it, and that
changes the document's *text*. `docs/PRD.md` §8.1 and the Phase 1 risk register both say the
payload wins where thoroughness and payload conflict, and the visible words of a document are
its payload in the most direct sense available. A tool that silently accepted every pending
revision would hand a journalist a document that says something different from the one they
reviewed. The user is told the content is there and left to decide, which is the same position
strypt takes on text under a redaction rectangle (`docs/THREAT_MODEL.md` §4.3).

**This is a recorded limitation and mat2 is the better recommendation for a document whose
comments must go.** ADR-0012 requires saying so where it is true, and it is true here.

**Consequences.**

- A stripped `.docx` opens in Word, LibreOffice, and Google Docs without a repair prompt.
  That is a test, not an aspiration, and it is in the integration suite as a structural
  validity check plus a manual open recorded in `docs/THREAT_MODEL.md`.
- **Output is not byte-identical to input even for a clean document**, because
  `[Content_Types].xml` is re-emitted stored where it arrived deflated. Idempotence still
  holds byte-identically — `strip(strip(x)) == strip(x)` — because the second pass finds
  nothing to remove and copies every entry through verbatim. The Phase 1 handlers can promise
  the stronger property for a clean file and this one cannot, which is stated rather than
  glossed.
- ZIP entry order and the archive's internal offsets change. Nothing in OOXML depends on
  entry order except that `mimetype` conventions apply to ODF rather than here, so this is
  safe for this format group and must be re-checked when ODF lands — ODF *does* require
  `mimetype` first and stored.
- Every timestamp in every ZIP entry header is a metadata field of its own, recording when
  each part was last written. They are normalised to a fixed value rather than preserved,
  consistent with ADR-0019's treatment of output timestamps.

---

## ADR-0031 — OpenDocument is edited by name, and `meta.xml` is not `docProps` in another spelling

**Status:** Accepted (2026-08-24)

**Context.** OpenDocument — `.odt`, `.ods`, `.odp` — is Phase 2's second format group
(ADR-0027), and it arrives on machinery Group 1 already built: the ZIP container layer
(ADR-0028) and the one-level, images-only descent into embedded pictures (ADR-0029) are used
unchanged. The tempting conclusion is that the handler is OOXML with different part names.

It is not, and the differences are the reason this ADR exists. Four of them changed the design:

1. **There is no content type to match on.** ADR-0030 finds Office property parts by their
   declared content type, deliberately, "because the path is a convention and the content type
   is the contract". ODF inverts that. `meta.xml`, `settings.xml`, and `META-INF/manifest.xml`
   are *named* by ODF 1.3 Part 2 §3.1, and the manifest gives `meta.xml` the media type
   `text/xml` — indistinguishable from every other XML part in the package. The rule that is
   right for one format cannot be applied to the other at all.
2. **Authorship is element text, not an attribute.** `<w:ins w:author="A Name">` against
   `<office:change-info><dc:creator>A Name</dc:creator></office:change-info>`. An attribute is
   removable on the strength of its name wherever it occurs; `<dc:creator>` is the document's
   author in `meta.xml`, a comment's author inside `<office:annotation>`, and a revision's
   author inside `<office:change-info>`. The scanner therefore has to know which element it is
   inside, where the Office rules never did.
3. **An encrypted package does not look encrypted to ZIP.** ODF encrypts entry data itself and
   records it in `META-INF/manifest.xml` (Part 2 §3.4) without setting ZIP's general-purpose
   encryption bit. The refusal in `container/zip.rs` that catches an encrypted `.docx`
   therefore passes an encrypted `.odt` straight through — whereupon `content.xml` is
   ciphertext, no rule matches it, and the package is reported clean having been read by
   nobody. That is `docs/THREAT_MODEL.md` §5.4 reached by a route the Group 1 work did not
   have.
4. **An embedded object is not a nested container.** A `.docx` stores a chart's cached
   workbook as a whole `.xlsx` inside itself, which ADR-0029 refuses. ODF stores the same
   thing as ordinary entries in the same archive — `Object 1/content.xml`,
   `Object 1/meta.xml` — so the chart's own author metadata is reachable in the same pass,
   with no recursion at all.

**The pair the roadmap named**, and the reason it named them: `meta:editing-cycles` counts
saves as `cp:revision` does, but `meta:editing-duration` is an ISO 8601 duration written to
the second — `PT4H32M17S` — where Office's `TotalTime` is cumulative whole minutes. Beside
`meta:creation-date` and `dc:date`, that is enough to say when somebody sat down, how long
they worked, and when they stopped. `meta:generator` is likewise stronger than its Office
counterpart: `LibreOffice/7.4.2$Linux_X86_64` names the operating system, where `Application`
and `AppVersion` do not. And `meta:document-statistic` keeps its page and word counts in
**attributes**, so the Office reporting path — which walks elements containing text — sees
nothing there at all.

**Decision.**

**Removed whole, matched by name** (leaf name, so an embedded object's own copies go by the
same rule): `meta.xml`, `settings.xml`, `layout-cache`, and everything under `Thumbnails/` and
`Configurations2/`. Their contents are itemised in the report before they go, because "this
document names an author and records four and a half hours of editing across 37 saves" is
actionable where "a metadata part was removed" is not.

`settings.xml` goes whole rather than being scrubbed, which is worth justifying: it holds the
printer's name and a base64 setup blob that carries the driver and often a network path, and
the rest of it is window geometry, the last cursor position, and a per-release set of
configuration keys that fingerprints the producing build. None of that is payload, and no
application shows any of it. mat2 removes the same part for the same reason.

`layout-cache` is a producer-written binary cache of text layout with an undocumented format.
Unlike an unrecognised part — which may be load-bearing, and which strypt copies with a note
(§7.6) — nothing refers to it and it holds nothing the document needs, so there is nothing to
weigh against removing it.

**Rewritten:** `META-INF/manifest.xml` loses the `manifest:file-entry` elements naming parts
that went. `content.xml`, `styles.xml`, and any other XML part lose the text of `dc:creator`,
`dc:date`, and `meta:date-string` *inside* an `office:annotation` or an `office:change-info`,
and the cached values of the author fields below. As in ADR-0030, editing is by deleting byte
ranges, never by re-serialising.

**Kept, and declared as kept:** the words of comments and tracked changes, for the reason
ADR-0030 gives and `docs/PRD.md` §8.1 requires — removing a tracked insertion means deciding
whether the document accepts or rejects it, which changes what the document *says*. **mat2 is
the better recommendation for a document whose comments must not be published**, and it is a
sharper difference here than for Office: mat2 removes ODF annotations and tracked changes
outright. ADR-0012 requires saying so where it is true.

**One narrow exception to "the visible text is the payload", made deliberately.** The cached
values of `text:creator`, `text:initial-creator`, `text:author-name`, `text:author-initials`,
`text:printed-by`, `text:editing-cycles`, and `text:editing-duration` are emptied. These are
*fields*: the application inserted them and filled them in from `meta.xml`, so their content is
a second copy of what this handler is removing. Leaving them would mean strypt reporting the
author removed while the same name is printed in the document's header — a §5.4 failure wearing
the costume of payload preservation. The field element itself stays, so the structure is
untouched and an application refills it from whatever metadata exists.

Date and time *fields* the document displays — `text:creation-date` and its siblings — are
**not** touched. A date printed in a letter is a date the author chose to show. Their presence
is reported as a `Note` instead, so a user who asked for timestamps to go is told one is still
on the page.

**`mimetype` is emitted first and stored.** Part 2 §3.3 requires the entry to be the first in
the archive, uncompressed, and without an extra field, and readers use it to identify the
format. Input order is otherwise preserved exactly; this is the only entry this project's
handlers ever move. A package that arrived with it deflated or elsewhere is repaired rather
than refused — the user has an ordinary document their producer wrote badly, and emitting a
package that violates the identifying clause would be the worse answer.

**Refused rather than half-processed:** a package with no manifest (Part 2 §2.2.1 requires
one); a package whose manifest declares `manifest:encryption-data`; a package whose `mimetype`
entry and manifest root give *different* answers about what it is, since different readers
would then disagree about what they are opening and picking a winner would mean strypt
deciding which of two documents the user has; and — inherited from ADR-0029 — a nested archive,
an embedded PDF, or an OLE object. An OpenDocument type outside this group (a drawing, a
formula, a chart, a database, any `-template`) is refused at detection and **named**, because
"understood and declined" and "not recognised" are different things to tell a user.

**Consequences.**

- **Two internal boundaries moved, and neither is a new decision so much as the consequence of
  having two package formats instead of one.** The XML scanner is now `formats/xml.rs`, shared,
  with the per-format rules in `formats/ooxml/rules.rs` and `formats/odf/rules.rs`; and the
  parts of a ZIP package both handlers treat identically — decompression against a shared
  budget, the nested-container refusal, the embedded-image descent, and the entry-header
  findings — are now `container/package.rs`. **The descent of ADR-0029 existing exactly once is
  the point of the second move**: a copy of it in this handler would have been a second place
  for the depth to grow, and that ADR fixes the depth in the type system precisely so it cannot.
  The OOXML behaviour is unchanged, which its 26 integration tests and a fresh short fuzz run
  are the evidence for.
- **Output is not byte-identical to input even for a clean document**, as for OOXML: rewritten
  parts are re-emitted stored (ADR-0028), entry timestamps are normalised, and `mimetype` may
  move. Idempotence *is* byte-identical and is tested over every fixture — which for this format
  is also what proves the `mimetype` reordering settles rather than oscillating.
- **strypt processes at least one document mat2 refuses.** mat2's part patterns are anchored at
  the package root, so `Object 1/settings.xml` — an embedded chart's settings, which real
  documents contain — matches neither its keep list nor its omit list and it stops with an
  error. This is recorded as an observation, not a claim of superiority: the differential's
  purpose is to find what strypt misses, and on that question it found nothing.
- **No claim is made that a stripped package opens without a repair prompt in LibreOffice**,
  because no LibreOffice was available on the machine this was built on. The structural checks
  that *are* run — an independent reader parses every output, the manifest is checked against
  the entries actually present, and `mimetype` is checked against §3.3 — are stated in
  `docs/THREAT_MODEL.md` §7.7 for what they are, and the manual open is owed.
- Extending the group — to `.odg`, to the template variants, to flat ODF (`.fodt`, which is a
  single XML file and is refused as XML today) — requires a superseding ADR, not a judgement
  call. ADR-0027's scope lock is unchanged.

---

## ADR-0032 — Phase 2's third group is five tranches, not one deliverable

**Status:** Accepted (2026-08-25)

**Context.** `docs/ROADMAP.md` Phase 2 deliverable 3 is a single line — "Additional images —
TIFF, GIF, AVIF, HEIF, JPEG XL, SVG" — and ADR-0027 locks it as the next group to land now that
OpenDocument has met the Phase 1 bar in full (fuzzing debt cleared 2026-08-25, LibreOffice import
closed 2026-08-24).

That line is written as though the six formats were a family. They are not, and this is the
respect in which Group 3 differs from both groups that came before it. Groups 1 and 2 were each
three formats sharing one container: OOXML and OpenDocument are ZIP packages of XML, which is why
`container/package.rs` and `formats/xml.rs` exist and why the second group cost far less than the
first. Group 3 has no such centre. It spans a tag-and-offset graph (TIFF), a small chunk list
(GIF), an ISO base-media box tree (HEIF, AVIF), an XML text format with a script-execution threat
model (SVG), and a format with two mutually exclusive container spellings (JPEG XL).

Landing them as one deliverable has a specific failure mode, and it is not merely that the pull
request would be large. A group is "done" only when its hardest member is done, so a finished and
verified TIFF handler would sit unshipped behind JPEG XL — the member with the thinnest tooling
and the least settled answer. Phase 2's exit criterion 1 forbids provisional handlers; the way to
honour that without holding finished work hostage is to make the unit of completion smaller than
the group.

**Decision.**

1. **Group 3 lands as five sub-tranches, in this fixed order**, each meeting the Phase 1 per-format
   bar in full before the next is started — the discipline ADR-0027 applies *between* groups,
   applied *within* this one:

   | # | Tranche | Why here |
   |---|---|---|
   | 1 | **TIFF** | Reuses `formats/exif.rs`, whose header already names this case. Settles the offset-rewriting question below, which nothing after it needs but which nothing before it has faced. |
   | 2 | **GIF** | A short chunk list with two metadata-bearing extension blocks. The cheapest handler in the project, and useful as a control on the tranche machinery. |
   | 3 | **HEIF + AVIF** | One ISO-BMFF box walker serving two formats — the only genuine sharing in this group, and the reason they are one tranche rather than two. |
   | 4 | **SVG** | Deferred behind the raster formats because its threat model is different in kind, not degree. See point 3. |
   | 5 | **JPEG XL** | Last deliberately: two container forms (bare codestream and BMFF), the newest ecosystem, and the weakest answer today. Placing it last means an unresolved JPEG XL delays nothing else. |

   A tranche that proves harder than expected may be deferred out of Phase 2 by a superseding ADR.
   It may **not** be landed provisionally, and it may not be reordered ahead of an unfinished
   predecessor.

2. **The default is a hand-written walker; a dependency requires its own ADR.** This is not a new
   position, it is the one the codebase already holds: ADR-0028 wrote the ZIP layer rather than
   importing one, `formats/xml.rs` states at its head why there is no XML parser behind it, and
   `formats/exif.rs` is a hand-written IFD reader. The common thread is that strypt never needs a
   document model — it needs to name byte ranges and delete some of them, which is a scanner.

   Candidates were surveyed on 2026-08-25 and none displaces that default:

   - **`avif-parse` 2.1.0** (released 2026-03-27, ~58k recent downloads,
     `github.com/kornelski/avif-parse`) is a safe-Rust ISO-BMFF/MIAF parser forked from Mozilla's
     Firefox MP4 parser, which is real pedigree against hostile input. It is **MPL-2.0**, and that
     is the finding that matters: `docs/PRD.md` §4 and ADR-0012 rest part of strypt's case on
     permissive versus LGPL-3.0 licensing. MPL-2.0 is weak, file-scoped copyleft and would not
     endanger the dual MIT/Apache-2.0 licence of strypt's own code, but it *complicates a sentence
     the project uses to distinguish itself*, and it decodes far more of the format than a
     metadata pass needs. Not adopted without a dedicated ADR arguing it earns that.
   - **`jxl-oxide` 0.12.6** (released 2026-05-29, `github.com/tirr-c/jxl-oxide`) is a full JPEG XL
     **pixel decoder**. Decoding an image to remove its metadata is the wrong shape of tool, and
     admits an entire codec as attack surface for a job that touches container boxes.
   - **`nom-exif`** parses metadata across many of these formats but is, like `formats/exif.rs`, a
     *reader*. Group 3's work is removal, and reading is the part strypt already has.

3. **SVG gets its own ADR before its tranche opens.** It stays in Phase 2 and keeps its place in
   the order, but it is not decided by this one. SVG is the only member of the group where the
   question "what is metadata?" has no obvious answer: `<metadata>`, `<title>`, `<desc>` and
   editor-namespaced attributes (`inkscape:`, `sodipodi:`, Adobe's `i:`) are the easy part, while
   scripts, external references that phone home when the file is opened, embedded raster images in
   `data:` URIs, and comments carrying author names are each a separate judgement. It can reuse
   `formats/xml.rs`, but reuse of the scanner is not reuse of the rules, and treating it as one
   more image handler is how the script surface gets under-thought.

4. **The TIFF tranche must settle offset rewriting, and this ADR does not pre-empt it.**
   `formats/exif.rs` is read-only by an explicit and well-argued design decision recorded in its
   header: a TIFF is a graph of absolute file offsets, so editing tags out of one means rewriting
   every offset that follows, and an error there yields a file that still parses while pointing at
   the wrong bytes. Every image handler shipped so far sidesteps this by dropping the *entire*
   container the Exif block sits in — a removal that cannot half-succeed.

   **A standalone TIFF has no such container to drop.** Its metadata is its file structure. The
   tranche therefore has to choose between rewriting the IFD graph with offset fixup — new
   machinery, on the failure mode `exif.rs` was written to avoid — and refusing TIFF as
   unsupported, which is fail-closed and honest but ships nothing. That choice is the tranche's
   first task and is recorded in its own ADR, informed by what the format actually requires rather
   than settled here in advance.

**Consequences.**

- **Group 3 is not "done" until all five tranches are done**, and the roadmap's exit criterion 1
  still governs each of them individually. Splitting the unit of delivery changes when work ships,
  never what bar it ships against.
- **`docs/ROADMAP.md` Phase 2 deliverable 3 is now read through this ADR**, in the same way
  deliverables 1 and 2 are read through ADR-0030 and ADR-0031. The roadmap line is not rewritten;
  the ordering and the completion unit live here.
- **Three further ADRs are owed inside this group** — one for TIFF's offset decision, one for SVG,
  and one for any dependency a tranche concludes it needs. This is more decision records than
  either previous group required, which is a consequence of the group being five problems rather
  than one.
- **ADR-0012's licensing differentiator now has a documented edge case.** MPL-2.0 sits between
  "permissive" and "LGPL-3.0" and the survey above found it on the most credible candidate in the
  group. If a later ADR adopts an MPL-2.0 dependency, the positioning language in `docs/PRD.md` §4
  must be revisited in the same commit rather than left to imply a purity the tree no longer has.
- **Nothing here changes ADR-0027's scope lock.** Group 3 remains exactly the six formats the
  roadmap names. Adding a seventh — TIFF-based raw formats such as CR2, NEF or DNG are the
  obvious temptation, since the IFD machinery would already be there — still requires a
  superseding ADR, and the temptation should be resisted on the ground that a raw file's maker
  notes are a vendor-specific format in their own right.

---

## ADR-0033 — A stripped TIFF is rebuilt from an allow-list, not edited in place

**Status:** Accepted (2026-08-25)

**Context.** TIFF is the first tranche of Phase 2's third group (ADR-0032), and it arrives with a
problem no format shipped so far has had.

Every image handler in the tree removes metadata the same way: drop the *entire* container the
metadata block sits in. A JPEG `APP1` segment, a PNG `eXIf` chunk, a WebP `EXIF` chunk — each is a
delimited region that can be excised whole, and `formats/exif.rs` says in its own header why it
therefore only ever reads:

> a TIFF is a graph of absolute file offsets, so editing tags out of one means rewriting every
> offset that followed them, and a mistake there produces a file that still parses while pointing
> at the wrong bytes. Dropping the block whole cannot half-succeed.

**A standalone TIFF has no block to drop.** Its metadata *is* its file structure. IFD0 holds the
identifying tags and the structural ones in one directory, values longer than four bytes live at
arbitrary offsets elsewhere in the file, and the image data is addressed by `StripOffsets` or
`TileOffsets` — absolute file positions that any edit before them invalidates. The removal
strategy every other handler relies on does not exist here, and the failure mode `exif.rs` warns
about is precisely the one an in-place editor would walk into: a file that still parses, with an
offset pointing at the wrong bytes, reported as successfully stripped.

**Decision.** strypt does not edit a TIFF. It **writes a new one**, from an allow-list, and copies
the image data across unmodified.

1. **Construct, never patch.** The output is authored from an empty buffer: a fresh header, then
   each retained directory, then the values, then the image data — with every offset computed at
   the moment it is written, against the buffer being built. **No offset from the input is ever
   carried into the output.** This is what makes the class of bug `exif.rs` names unreachable
   rather than merely unlikely: there is no stale offset to be wrong, because there is no
   preserved offset at all.

2. **An allow-list of structural tags, and nothing else.** A tag is written to the output only if
   it appears on a list of tags required to decode the image — dimensions, bit depth, compression,
   photometric interpretation, the strip or tile geometry and its byte counts, samples per pixel,
   planar configuration, colour map, predictor, sample format, extra samples, fill order,
   resolution and its unit, and `JPEGTables` for JPEG-compressed strips. Everything else is
   absent from the output because it was never written.

   **The direction of the default is the whole point.** A deny-list carries an unknown tag through,
   and the tags that matter most here are exactly the ones a tag table has not heard of: vendor
   maker notes, a scanner's private tags, a proprietary field holding a device serial. Under an
   allow-list an unrecognised tag cannot survive by going unrecognised. This inverts the rule that
   governs the two ZIP-package handlers — ADR-0030 and ADR-0031 edit by deletion and keep every
   byte they had no reason to change — and the inversion is deliberate: those formats can be
   edited in place and this one cannot, so the conservative choice moves from "keep unless known
   bad" to "drop unless known necessary".

3. **The image data is copied verbatim, byte for byte.** Strips and tiles are moved, not decoded,
   not recompressed, not re-rendered. The output's pixels are bit-identical to the input's.

   This is where strypt and mat2 differ concretely, and it is a trade-off rather than a verdict.
   mat2's default TIFF path loads the image through GdkPixbuf and re-renders it, which is
   thorough — it cannot leave behind a metadata carrier it failed to parse — but it rewrites the
   image data, which is why mat2 offers `-L` for users who need the pixels untouched. strypt's
   approach keeps the pixels by construction and accepts the corresponding risk: metadata hidden
   *inside* the compressed image data is not something a container rebuild can reach. Where a
   user's threat model includes that, mat2's default is the better recommendation and
   `docs/THREAT_MODEL.md` must say so (ADR-0012).

4. **Reduced-resolution images are dropped; pages are kept.** A TIFF's IFDs form a chain, and a
   chained directory can be either another page of a multi-page document — a scanned dossier, the
   case that matters for this project's users — or a reduced-resolution copy of the image before
   it, flagged by bit 0 of `NewSubfileType` (TIFF 6.0 §8, tag `0x00FE`). Pages are
   retained, each rebuilt on its own terms. Reduced-resolution directories and the thumbnails
   reached through `SubIFDs` (`0x014A`) are **not written to the output at all**, on the same
   reasoning as `docs/THREAT_MODEL.md` §3: a thumbnail is a complete second image that survives
   any redaction painted over the first.

5. **Anything the writer cannot reproduce faithfully is refused, not approximated.** BigTIFF
   (header magic 43, with 8-byte offsets) is refused by name in this tranche rather than parsed
   badly. So is a file whose strip or tile geometry is inconsistent — offsets and byte counts of
   differing lengths, a strip running past the end of the file, overlapping strips — and one whose
   structural tags are absent or contradictory. This is hard constraint 6: a partly-understood
   TIFF is reported as unsupported, never written out and reported clean.

**Consequences.**

- **The output is not byte-identical to the input, ever, including for a TIFF with no metadata at
  all.** A rebuild reorders the file by construction. This is a stronger statement than the
  OOXML and OpenDocument caveat, which only concerns rewritten parts, and it belongs in
  `CHANGELOG.md` and `docs/THREAT_MODEL.md` in those terms. **Idempotence remains byte-identical
  and must be tested**: stripping an already-stripped TIFF must reproduce it exactly, which for
  a rebuild is also the proof that the writer's output is a fixed point of its own reader.
- **A TIFF using a feature outside the allow-list is refused rather than degraded**, and some of
  those refusals will be real files. This is the same cost ADR-0029's nested-container refusal
  accepted, taken deliberately for the same reason.
- **`formats/exif.rs` stays read-only and its header stays true.** The writer is new code in
  `formats/tiff.rs`; the shared reader is not extended into an editor, because it is shared with
  three handlers that must not acquire a rewriting path they have no use for.

  What *is* shared is the reader's **tag table** — `describe` and `render`, widened to
  `pub(crate)` — so a tag is named identically whether it was found in a JPEG's `APP1` segment or
  in a standalone TIFF, and there is one place to correct a wrong name. The TIFF handler walks the
  directories itself, because it has to walk them anyway to rebuild them; reusing the reader's
  walk instead would mean two passes over hostile bytes where one will do. Naming what was
  removed and deciding what to keep therefore stay separate concerns sharing one vocabulary, and
  the output does not depend on the report.
- **The allow-list is a correctness surface and will need revision.** A tag wrongly omitted breaks
  an image; the mitigation is the differential against mat2 and ExifTool that every format ships,
  plus a decode check on every fixture's output. A tag wrongly *included* leaks, which is the more
  serious direction and is why the list is enumerated in code with a comment per tag citing why
  the image cannot be decoded without it.
- **This ADR governs TIFF only.** It is not a precedent for the tranches after it: GIF's chunk list
  and the ISO-BMFF box tree can both be edited by deletion, and reaching for a rebuild there —
  where the format does not force it — would discard the "every byte that had no reason to change
  does not change" property for nothing.

---

## ADR-0034 — A stripped HEIF is rebuilt from three allow-lists, and its item offsets are recomputed, never carried

**Status:** Accepted (2026-08-27)

**Context.** HEIF and AVIF are the third tranche of Phase 2's third group (ADR-0032), taken as one
tranche because they share a single ISO-BMFF box walker — the only genuine sharing in that group.

**ADR-0033 predicted the wrong answer for this format, and the correction is the substance of this
ADR.** Its closing bullet said the TIFF rebuild "is not a precedent for the tranches after it:
GIF's chunk list and the ISO-BMFF box tree can both be edited by deletion". GIF's half was right
(§7.9). The BMFF half was not, and probing a real AVIF and HEIC rather than reasoning from the box
tree is what showed it:

```
ftyp  meta[ hdlr iloc iinf iref pitm iprp[ ipco[ av1C ispe pixi ] ipma ] ]  mdat
```

The box tree really can be edited by deletion. **The metadata is not in the box tree.** Exif and
XMP are *items*: declared in `iinf`, bound to the picture through `iref`, and located by `iloc` as
**absolute file offsets** into `mdat`, where their bytes sit beside the coded image with no
delimiter between them. Deleting an item means deleting a range from the middle of `mdat`, which
shifts every surviving item's offset, which means rewriting `iloc`. That is the offset-patching
failure `formats/exif.rs` was written to avoid and that ADR-0033 rejected for TIFF, arriving in a
format whose box tree superficially looks like PNG's chunk list. HEIF is structurally nearer to
TIFF than to GIF, and ADR-0033's guess to the contrary should be read as superseded on this point.

**Decision.** strypt does not edit a HEIF. It **writes a new one**, from allow-lists, and copies
each retained item's data across unmodified.

1. **Construct, never patch.** Output is authored from an empty buffer — a fresh `ftyp`, a fresh
   `meta` holding only retained boxes, then a fresh `mdat`. Every `iloc` offset is computed against
   the buffer being built. **No offset from the input reaches the output.**

   This has a wrinkle TIFF did not: `meta` precedes `mdat`, so the offsets written *into* `meta`
   depend on how long `meta` turns out to be. It is resolved by making the encoded length
   independent of the values encoded — `iloc`'s `offset_size` and `length_size` are written as a
   fixed 4 bytes each rather than narrowed to fit — so `meta` is written once with a placeholder
   base to learn its length, then once for real. **The two lengths are asserted equal and a
   mismatch is a refusal, not a fix-up**: a second pass that changed length would mean every
   offset in the file was computed against the wrong base, and that is precisely the failure this
   design exists to make unreachable.

2. **Three allow-lists, all running in the same direction as ADR-0033's.** A box, an item, or a
   property reaches the output only by being named as something the image cannot be decoded or
   rendered without: two box types at the top level, seven inside `meta`, fifteen properties, and
   eight item types. Everything else is absent because it was never written.

   **`uuid` is why the direction matters more here than anywhere else.** It is the format's blessed
   extension point — the box type a producer is *supposed* to invent in — and it is where Adobe
   writes XMP. A deny-list would carry an unrecognised `uuid` through for the exact reason it needs
   dropping. It cannot survive here by going unrecognised, because nothing survives by going
   unrecognised.

3. **Every name a producer could write is emitted empty rather than copied.** `hdlr`'s trailing
   name string and each `infe`'s `item_name` are free text that some encoders fill with a product
   string and some with nothing. They are structural fields that cannot be dropped, so they are
   written as empty strings, and item IDs are renumbered from 1 so that gaps left by removed items
   do not themselves record how many items the original had.

4. **Refused rather than approximated**, each by name:
   - **A `moov`, `moof`, `mfra` or `mvex` box** — a motion HEIF, which is what an Apple Live Photo
     is. Video is Group 4. **This refuses a common real iPhone file and that cost is accepted
     deliberately**, the same trade ADR-0029 made for OOXML embedded objects; the refusal names
     Live Photos specifically so the user knows what happened rather than reading "malformed".
   - An image **sequence** brand (`msf1`, `hevc`), for the same reason.
   - `iloc` `construction_method` 2 — offsets into another item — which cannot be relocated without
     resolving an item graph. Method 1 (`idat`) *is* handled, by resolving it and writing the data
     into `mdat` as method 0, which is why `idat` does not appear in any output.
   - An `infe` below version 2, a non-zero `data_reference_index` (item data living in another
     file), an `ipro` protection box, an `iloc` field width outside {0, 4, 8}, and a file with no
     `meta`, no `pitm`, or a primary item whose extents fall outside it.

5. **The ICC profile goes and numeric colour signalling stays.** A `colr` box is answered by its
   payload rather than its type: `prof` and `rICC` carry an ICC profile, which is removed on the
   same reasoning as TIFF §7.8 and JPEG §7.2, at a documented cost in colour fidelity; `nclx` is
   four numeric fields naming a colour space and no device, and is kept. It is declared in the
   report's `retained` list rather than passed over in silence, as GIF's loop count is.

6. **Thumbnail items go.** An item reached by a `thmb` reference is a complete second copy of the
   picture, and §3's argument applies unchanged: it survives cropping and anything painted over the
   first. **The reference runs from the thumbnail to the master, not the other way**, which is
   worth stating in an ADR because reading it backwards deletes the photograph and keeps the
   thumbnail — a bug this work made and caught only because a fixture existed for it.

**Consequences.**

- **The output is not byte-identical to the input, ever, including for a HEIF with no metadata at
  all** — the same consequence ADR-0033 records, and stronger than the OOXML and OpenDocument
  caveat. **Idempotence remains byte-identical and is tested.**
- **`container/bmff.rs` holds no HEIF semantics**, on the precedent `container/zip.rs` set for
  `formats/ooxml.rs` rather than on a new one: ADR-0032 names MP4 (Group 4) and JPEG XL (tranche 5)
  as later callers, so the walker goes where a second caller can reach it. It ships its own fuzz
  target for the reason ADR-0028 required one for ZIP — reaching a container only through a handler
  does not fuzz the container, because every input has to look like a plausible HEIF first.
- **The coded picture is copied byte for byte and never re-encoded**, so metadata hidden *inside*
  the compressed image data is out of reach. Where a user's threat model includes that, mat2's
  re-rendering default is the better recommendation and §7.10 says so (ADR-0012).
- **The allow-lists are a correctness surface and will need revision.** A property wrongly omitted
  breaks an image; the mitigation is the differential and a decode check on every fixture's output.
  A property wrongly included leaks, which is the more serious direction, and is why each list is
  enumerated in `formats/heif/boxes.rs` with the reason the image needs it.
- **No new dependency.** The walker is hand-written, which is ADR-0032's default. `avif-parse` was
  surveyed there and its MPL-2.0 licence complicates a sentence `docs/PRD.md` §4 uses; adopting it
  would need its own ADR and is not proposed.

---

## ADR-0035 — SVG is edited by deletion, and the four things that are not metadata decide the handler

**Status:** Accepted (2026-08-28)

**Context.** SVG is the fourth tranche of Phase 2's third group. ADR-0032 §3 held it back behind the
raster formats and required it to have this ADR before the tranche opened, on the ground that its
threat model "differs in kind, not degree" — and that treating it as one more image handler "is how
the script surface gets under-thought". This ADR is that thinking.

**The scanner is reusable and the rules are not.** `formats/xml.rs` already names byte ranges and
cuts them, which is exactly the shape of edit SVG needs, and it is shared with Office Open XML and
`OpenDocument` for the same reason. What does not transfer is any of the rules: those two formats
keep their metadata in named parts of a package, and an SVG is one document where the metadata,
the picture, the accessibility text, and — if the author wanted — an executable program all sit in
the same element tree.

**mat2 is the opposite tool here, and this is the one format where that is true.** For every raster
format in this project, mat2 re-renders the pixels and strypt does not, so mat2 reaches metadata
hidden inside the compressed image data and strypt records that as a limitation (§7.8, §7.9,
§7.10). SVG inverts it: `SVGParser.remove_all` loads the document through **Rsvg** and re-renders
it onto a blank **Cairo** SVG surface (verified against mat2's `libmat2/images.py`, 2026-08-28).
That removes everything, including things this ADR decides to keep — and it also rewrites the
entire document, so identifiers, classes, grouping, animation, interactivity, and the author's
editable structure do not survive. **Neither behaviour is a defect.** They are different products,
and §7.11 must say which is the better recommendation for which user rather than implying strypt
wins.

**Four questions have no obvious answer, and they are what this ADR exists to settle.** Everything
else about SVG — `<metadata>`, editor namespaces, comments — is bookkeeping.

**Decision.**

1. **An SVG is edited by deletion, never re-serialised, and a clean one comes back byte-identical.**
   The property GIF has (§7.9) and that TIFF and HEIF cannot promise at all: output is the input's
   bytes with some ranges cut out. Namespace declarations keep their order, attribute quoting keeps
   its style, whitespace keeps its shape, and a diff of input against output shows exactly what
   strypt did and nothing else. This is `formats/xml.rs`'s existing commitment applied to a format
   that is a single part rather than a package.

2. **A file that can execute code is refused by name, not partly cleaned.** A `<script>` element, an
   `on*` event-handler attribute, or a `<foreignObject>` — all three make the refusal, reported as
   `UnsupportedKind::ScriptedSvg`.

   The reasoning is `UnsupportedKind::MacroEnabledOffice`'s, which is the exact analogue: a document
   carrying executable code that strypt cannot read. A script is a container whose contents strypt
   has no parser for, and which is free to hold a name, an absolute path, a credential, or a base64
   copy of anything at all. The three available answers are to remove it, to keep it, or to refuse:

   - *Removing it* makes strypt a sanitiser rather than a metadata remover. It changes what the
     file does, which `docs/PRD.md` §8.1 reserves for the user, and it takes on the obligation to
     find every execution vector across SVG, CSS, and SMIL animation — a moving target, and one
     where being 95% right produces a file the user believes is inert.
   - *Keeping it* means reporting success on a file that runs arbitrary code the moment a reader
     opens it, having examined none of it. That is `docs/THREAT_MODEL.md` §5.4 in its plainest
     form: the user acts on the success message by publishing.
   - *Refusing* tells the user what is in their file and leaves the decision where it belongs. It
     is the same trade ADR-0029 made for OOXML OLE objects and ADR-0034 made for Live Photos.

   **This refuses real files** — interactive web graphics, and anything Illustrator exported with
   an event handler on it. The cost is accepted deliberately, and **mat2 is the better
   recommendation for that user**: its re-render flattens the script away along with everything
   else, which is a coherent answer to the same problem and one strypt is not trying to give.

3. **A reference to anything outside the document is reported and never removed.** A remote URL in
   an `href`, a relative path to a file on the author's machine, and a `url()` inside a `<style>`
   are all the same shape: a pointer to a picture the file does not contain.

   Both halves of that are deliberate. It is **reported** because a remote reference is a beacon
   that fires when any reader opens the published file, and because a local path is itself
   identifying — `../../Users/aname/Desktop/leak.png` names a person as surely as an Exif author
   field does. It is **never removed** because a file that draws a linked logo would silently
   become a file that draws nothing, and `docs/PRD.md` §8.1 puts that decision with the user.

   It reaches the report as a `Retained` entry and a `Note`, **not as a `Finding`** — a finding
   would make the verification pass reject strypt's own output, since verification requires the
   result to re-inspect clean. The note names the element and the attribute and **never the value**
   (`docs/THREAT_MODEL.md` §5.5): a note saying which path was leaked would be a durable copy of it.

4. **A raster image embedded as a `data:` URI is descended into exactly once, and only when it is an
   image.** This is ADR-0029's rule applied unchanged — one level, images only, through the *same*
   handler the CLI uses on a loose file, so the embedded picture inherits the verification pass and
   the recorded limitations of its own format rather than getting a second, weaker implementation.

   The case is common rather than exotic: Inkscape embeds pasted photographs this way as a matter
   of routine, and the result is a JPEG with its GPS coordinates, its body serial number, and its
   own thumbnail sitting base64-encoded inside an attribute of a file the user thinks of as a
   drawing. Reporting that and leaving it would be strypt declining to do the one job it exists for
   on a photograph it can already strip.

   Consequences of descending, all of them accepted:
   - **Base64 is decoded and re-encoded by hand**, in `formats/svg/data_uri.rs`. No dependency: it
     is forty lines of table lookup, which ADR-0008 would not admit a crate for.
   - **Decoding is charged against `ParseLimits::max_expanded_bytes`**, shared across the whole
     document as the ZIP layer shares it across an archive (ADR-0028), because base64 in an
     attribute is an expansion vector like any other.
   - **The re-encoding is canonical**, so a document whose embedded image changed is not
     byte-identical in that attribute even where the original encoding was merely unusual. A
     document with nothing to remove is untouched.
   - **A `data:` URI that decodes to a nested container — a PDF, an archive, an OLE compound file —
     refuses the whole document**, on `container/package.rs`'s existing rule rather than a new one.
     A `data:` URI that decodes to anything else (a font, an audio clip) is reported as unexamined
     and left.

5. **`<title>` and `<desc>` are kept, and declared.** They are the format's accessibility text: a
   screen reader announces `<title>`, and a browser shows it as a tooltip. They are content a person
   typed and a reader receives, which makes them payload under §8.1 and puts them exactly where
   ADR-0031 put an `OpenDocument` comment's words — kept, with the report saying they are there.

   **A `<desc>` can absolutely name its author**, and a user who needs them gone should be told so
   rather than left to assume strypt handled it. They are declared as `Retained` and noted, and
   §7.11 says plainly that **mat2 removes them** and is the better recommendation for that user.
   This is the same shape of honesty ADR-0031 requires about ODF annotations.

6. **A prefixed name survives only if its prefix is one the picture cannot be drawn without.** An
   allow-list, in the direction ADR-0033 and ADR-0034 established: `xlink:` and `xml:` reach the
   output, together with every unprefixed name, which is the SVG namespace itself. **Every other
   prefixed element and attribute is removed, and so is the `xmlns:` declaration that bound the
   prefix.**

   The direction is the whole point, and SVG makes the argument better than HEIF's `uuid` does. A
   deny-list of `inkscape:`, `sodipodi:`, and Adobe's `i:` would be a list of the three editors
   whose output someone happened to test, and every other editor's private data would survive by
   being unrecognised. What goes under this rule includes `<sodipodi:namedview>` — which records
   the author's window geometry, screen zoom, and current layer — `inkscape:version`,
   `sodipodi:docname`, **which is the file's name on the author's disk**, and Illustrator's
   `<i:pgf>`, which is a compressed copy of the original AI document hidden inside the exported
   SVG.

7. **`<metadata>` is removed whole.** SVG 1.1 §5.10 states that its contents are not rendered, so
   there is nothing to weigh: it is where RDF, Dublin Core, Creative Commons licensing, and XMP go,
   and it is the one element in the format that is unambiguously metadata by definition.

8. **Comments and processing instructions are removed; a doctype with an internal subset is
   refused.** A comment is where Adobe writes `<!-- Generator: Adobe Illustrator 25.0 -->` and where
   a hand-editing author writes a name. A processing instruction is where an XMP packet's
   `<?xpacket?>` wrapper lives. Neither renders.

   **CSS comments inside `<style>` go with them**, which is the one place this handler reads a
   second grammar. It is bounded and quote-aware, and it is there because a stylesheet comment is a
   producer fingerprint in exactly the way an XML comment is — mat2's own `CSSParser` removes them
   for the same reason.

   A doctype is kept when it is the format's boilerplate and **refused when it carries an internal
   subset**. Removing a subset that declares entities would leave `&name;` references pointing at
   nothing, and keeping it means keeping declarations that are both an expansion vector and, if
   external, a network reference — neither of which a document that merely draws a picture needs.

9. **Non-UTF-8 input is refused**, rather than scanned as bytes on a guess about its encoding. XML
   permits UTF-16, and a scanner that treated it as UTF-8 would find no tags at all and report a
   clean file, which is §5.4 again.

10. **`.svgz` is refused by name.** A gzipped SVG is recognised at detection so the message can say
    what it is and tell the user to decompress it first, rather than calling a common spelling of a
    supported format "unrecognised". Handling it would mean inflating and re-deflating, which puts
    a compressor in the output path for no metadata gain.

**Consequences.**

- **`container/package.rs`'s embedded-image descent now covers every image format the registry has
  a handler for**, rather than the three that happened to exist in Phase 1. ADR-0029's rule was
  always "one level, images only" and never "one level, three formats"; the narrower list was an
  artefact of when it was written. This is a **behaviour change for Office Open XML and
  `OpenDocument` as well as for SVG** — a `.docx` with a TIFF or a HEIC pasted into it now has that
  picture stripped instead of copied through unexamined — and it is recorded here rather than
  slipped in, because it changes what those two handlers remove.
- **`formats/xml.rs` grows a way to see what it currently skips.** The scanner deliberately steps
  over comments, CDATA, processing instructions, and doctypes because neither package format has
  ever needed to touch one. SVG needs their byte ranges, so they are now reported alongside
  elements. Element scanning is unchanged, which is what keeps the two shipped handlers' output
  byte-for-byte what it was.
- **Two things strypt keeps could still identify their author**: accessibility text, and the path
  in an external reference. Both are declared in every report and both are in §7.11. An empty
  `retained` list is a claim (`crate::report`), so this handler making two entries is the design
  working rather than a shortfall.
- **The refusals will meet real files.** A scripted SVG, a document with an entity subset, and a
  `.svgz` are each refused rather than partly cleaned. Fail-closed is the correct behaviour and it
  is not free; §7.11 names each refusal and what to do about it.
- **No new dependency.** The scanner, the base64 codec, and the CSS comment pass are all
  hand-written, which is ADR-0032's default. Nothing surveyed there applies to SVG, and an XML
  parser is the category `formats/xml.rs` already argues against at its head.

---

## ADR-0036 — JPEG XL is edited by deletion at the box layer, and the codestream is never entered

**Status:** Accepted (2026-08-29)

**Context.** JPEG XL is the fifth and last tranche of Phase 2's third group. ADR-0032 §1 put it
here deliberately — "two container forms (bare codestream and BMFF), the newest ecosystem, and the
weakest answer today" — so that an unresolved JPEG XL would delay nothing else. Four tranches later
the answer is no longer weak, and the reason is that the format keeps its metadata somewhere the
other four do not: in a flat list of top-level boxes that nothing else in the file points at.

**This is the case ADR-0034 said it was not.** That ADR corrected ADR-0033's guess that an ISO-BMFF
box tree could be edited by deletion, and the correction was specific: the tree can, but HEIF's
metadata is not in the tree — Exif and XMP are *items* located by `iloc` as absolute file offsets
into `mdat`, so removing one moves every surviving one and the file has to be rebuilt. JPEG XL
spells the same container and reaches the opposite conclusion, because ISO/IEC 18181-2 puts Exif,
XMP and JUMBF in top-level boxes of their own. There is no item table, no `iloc`, and no box whose
contents are addressed by a file offset. Deleting a box moves the ones after it and breaks nothing.

**Surveyed dependencies, re-verified 2026-08-29.** `jxl-oxide` is at **0.12.6** (2026-05-29), still
a full pixel decoder, so ADR-0032 §2's finding stands unchanged: decoding an image to remove its
metadata is the wrong shape of tool. A Brotli crate would be the new temptation, for the `brob`
box; decision 4 removes the need for one.

**Decision.**

1. **Both spellings are detected, one handler serves them, and `Format::Jxl` is one format.** A
   container file begins with the 12-byte signature box `0x0000000C 4A584C20 0D0A870A`; a bare
   codestream begins with `0xFF0A`. The report names which spelling was found, because it decides
   what strypt could look at.

2. **A bare codestream is accepted, reported clean, and returned byte-identical.** It has no box
   layer, so the metadata layer is not merely empty — it cannot exist. This is the clean-PNG case
   rather than a refusal, and refusing would tell a user their file may be dirty when the only
   container-level metadata it could hold provably is not there.

   **What that verdict does not cover is stated in every report and in §7.12.** strypt reads the
   signature and does not decode: the codestream's own `ImageMetadata` carries an ICC profile —
   whose description and manufacturer fields name a device or an application — and may carry a
   preview frame, and both are entropy-coded inside the image data. Reaching them means a decoder,
   which is decision 3's answer to a different question and the same answer here. **ExifTool, and
   therefore mat2, does not reach them either**; this is a limit of the approach, not of strypt.

3. **A container file is edited by deletion, and a clean one comes back byte-identical.** Output is
   the input's bytes with whole boxes cut out — SVG's property (§7.11) and GIF's (§7.9), which TIFF
   and HEIF cannot promise at all. Nothing is re-serialised, no size field is recomputed, and the
   codestream is copied without being parsed. A final box declaring size 0 — "extends to end of
   file" — keeps that meaning under deletion, since nothing is ever inserted after it.

4. **Five box types are deleted, and `brob` is deleted without being decompressed.**

   | Box | Why it goes |
   |---|---|
   | `Exif` | The Exif block, unchanged from the JPEG and TIFF cases. |
   | `xml ` | XMP, and anything else an author put in an XML box. |
   | `jumb` | JUMBF (ISO/IEC 19566-5), which is where C2PA provenance — capture device, edit history, signing identity — arrives. |
   | `brob` | Brotli-compressed metadata. Its first four bytes name the box it wraps; that name is reported and the box is dropped whole. |
   | `jbrd` | JPEG bitstream reconstruction data. See decision 5. |
   | `free`, `skip` | Padding by definition, and free to hold anything. Nothing depends on them. |

   **`brob` is the reason no Brotli decompressor enters the tree.** Removal does not need to read
   what is being removed — the same argument ADR-0022 made for PNG's compressed text chunks, and
   the PDF handler's for a filtered metadata stream. Inflating attacker-controlled Brotli to decide
   whether to delete bytes that are being deleted either way would buy a decompression-bomb surface
   for nothing.

   **Where strypt removes more than the alternative is measured, not assumed.** mat2's
   `JXLParser` is an `ExiftoolParser` running `_lightweight_cleanup()` (verified against
   `libmat2/images.py`, 2026-08-29), so it shells out to ExifTool rather than re-rendering, and
   the two tools are being asked the same question. Run over this corpus on 2026-08-29, ExifTool
   removes `Exif`, `xml ` and `brob`, and **leaves `jumb`, `jbrd`, `jxli`, `free` and `skip`** —
   so a C2PA manifest naming the capture device and the signing identity survives mat2 and does
   not survive strypt. `scripts/jxl-differential.sh` checks both directions over the fixture set,
   as every other differential in this project does, and §7.12 states the gap in each direction.

5. **`jbrd` is deleted, and the report says what that costs.** The box exists to rebuild the
   original JPEG bit-exactly, and libjxl's `JPEGData` keeps `app_data`, `com_data` and
   `inter_marker_data` — the original file's APPn and COM marker segments, verbatim (verified
   against `lib/jxl/jpeg/jpeg_data.h`, 2026-08-29). It is a copy of the headers of the file the
   user converted, which is exactly the thing this project removes.

   Deleting it changes what the file *does*: the picture decodes identically, and bit-exact JPEG
   reconstruction stops working. That is declared in the report rather than done quietly, and it is
   coherent with deleting the `Exif` box that the same reconstruction depends on. Half-cleaning it
   — parsing the box and stripping only its marker segments — is the failure mode this project
   refuses everywhere else.

6. **`jxli` is deleted rather than trusted.** A frame index is an optional seek accelerator for an
   animation; libjxl's own overview says it "is not needed to display the animation". It is the one
   retained-candidate box that indexes positions in a file this handler is editing, and deleting it
   settles the question without needing to establish what its offsets are relative to.

7. **Everything else refuses the file, and the allow-list runs on the retained side.** `JXL `,
   `ftyp`, `jxll`, `jxlc` and `jxlp` reach the output; any other type is `UnsupportedKind` by name.
   The direction is ADR-0033's and ADR-0035's: a deny-list of the box types someone happened to
   test lets an unknown one survive by going unrecognised, and an unknown top-level box in a
   metadata format is more likely to be metadata than not.

   A file whose first box is not the signature box, or whose second is not an `ftyp` with the
   `jxl ` brand, is refused as malformed rather than scanned for boxes on a guess.

**Consequences.**

- **`container/bmff.rs` gets the second caller its header predicted**, unchanged. The walker is
  generic and this handler supplies the meaning, exactly as `formats/heif.rs` does. Only top-level
  boxes are walked: JPEG XL has no nesting strypt needs to enter, and `jumb` — the one box with
  internal structure — is deleted whole.
- **Group 3 is complete when this tranche meets the bar**, and Phase 2 has one group left.
- **Two limits are declared in every report**, and neither is a shortfall: the codestream interior
  is not entered, and a deleted `jbrd` costs JPEG reconstruction. §7.12 names both.
- **No new dependency**, and ADR-0032's default holds for the fifth time in five tranches.

---

## ADR-0037 — Phase 2's fourth group is five tranches, and the video one is last

**Status:** Accepted (2026-09-01)

**Context.** `docs/ROADMAP.md` Phase 2 deliverable 4 is one line — "Audio and video containers —
FLAC, MP3/M4A, Opus/Ogg, MP4, WAV" — and ADR-0032's fifth tranche closed Group 3 on 2026-08-30
with no outstanding debt, so ADR-0027's gate permits this group to open.

That line names five things that are not five formats. M4A and MP4 are one container with two
extensions. FLAC appears twice — once as its own file, once as a codec inside Ogg — and those are
different parsing problems with the same tag format inside them. What the line actually spans is
four unrelated containers: a flat metadata block list (FLAC), RIFF (WAV), a bare frame stream with
tags bolted to both ends (MP3), Ogg's CRC-checked page stream, and an ISO base-media box tree
(MP4/M4A).

ADR-0032's argument therefore applies again, and the failure mode is the same: a group is "done"
only when its hardest member is done, and Phase 2 exit criterion 1 forbids landing the others
provisionally to get there.

**What is new in this group, and it is not merely more formats.** Every format shipped so far
holds a still image, and metadata sits beside the payload. Here the payload is a timed stream and
the container carries an *index into it*. MP4's `stco`/`co64` address `mdat` by absolute file
offset, so removing a box ahead of the media silently invalidates every sample offset — ADR-0034's
finding a second time, in a format where getting it wrong yields a file that still opens and plays
the wrong bytes. Ogg's metadata is a packet inside pages that carry their own CRC, so it cannot be
deleted in place at all. Neither problem has an analogue in Groups 1 to 3.

**Decision.**

1. **Group 4 lands as five tranches, in this fixed order**, each meeting the Phase 1 per-format bar
   in full before the next is started:

   | # | Tranche | Why here |
   |---|---|---|
   | 1 | **FLAC** (native) | A flat list of typed metadata blocks, removed by deletion, so a clean file comes back byte-identical. Its seek points are offsets from the first audio frame rather than from the file, so nothing needs rewriting. The cheapest handler in the group and a control on the tranche machinery, as GIF was for Group 3 — and it settles the VorbisComment vocabulary that tranche 4 reuses. |
   | 2 | **WAV** | RIFF chunk surgery, the nearest neighbour of shipped work: `formats/webp.rs` already walks RIFF. Its metadata — `LIST`/`INFO`, `bext` with its originator and coding history, `iXML`, `id3 ` — is dropped whole, so it needs no ID3 reader, which is the same move every image handler makes on an Exif block. |
   | 3 | **MP3** | Not a container: an ID3v2 block at the head, ID3v1 or APE at the tail, frames between. Deletion at both ends, and it settles ID3 itself — unsynchronisation, the extended header, the footer — which is the part tranche 2 deliberately avoided. |
   | 4 | **Ogg** — Opus, Vorbis, FLAC-in-Ogg | One page walker serving several codecs: the only genuine sharing in this group, and the reason these are one tranche rather than three. Not a deletion, unlike everything before it — the comment header is a packet inside CRC-checked pages, so pages are rebuilt and CRCs recomputed. |
   | 5 | **MP4 + M4A** | Last, deliberately. It reuses `container/bmff.rs` but must answer the offset question again and possibly differently from ADR-0034, and it is the largest surface in the group. Placing it last means an unresolved MP4 delays nothing else. |

   ADR-0032's rules carry over unchanged: a tranche that proves harder than expected may be
   deferred out of Phase 2 by a superseding ADR, may **not** be landed provisionally, and may not
   be reordered ahead of an unfinished predecessor.

2. **The default is still a hand-written walker — but the survey is closer this time, and saying
   otherwise would be dishonest.** Candidates checked 2026-09-01:

   - **`lofty` 0.25.1** (2026-08-15, `github.com/Serial-ATA/lofty-rs`, ~321k recent downloads) is
     **MIT OR Apache-2.0** and is a metadata library rather than a decoder. It therefore loses on
     neither of the two grounds that disqualified Group 3's candidates, and it must not be waved
     away with the sentence written for `avif-parse`. What still argues against it is shape: it is
     a tag *model* that reads, converts and writes, where strypt needs to name byte ranges and
     delete them, and adopting it puts a general tag-writing implementation between the user's
     bytes and the output — the fail-closed surface this project owns. It also has no notion of
     refusing a file over a chunk it does not recognise, which is the rule ADR-0033 and ADR-0036
     both turn on. A tranche that concludes it earns adoption writes that ADR; **it does not
     inherit a rejection from this one.**
   - **`symphonia` 0.6.1** (2026-08-13, MPL-2.0) is a container-and-decode library. Wrong shape for
     the same reason `jxl-oxide` was: decoding a file to remove its metadata admits a codec as
     attack surface for a job that touches headers.
   - **`mp4parse` 0.17.0** (MPL-2.0, last released 2023-05-29) carries ADR-0032's MPL-2.0 note and
     adds staleness to it.
   - **`id3` 1.17.1** (2026-07-29, MIT) is a reader-writer for one tag format, and is the example of
     why any such ADR runs `scripts/check-no-network.sh` over the **resolved graph** before
     arguing anything else: it offers optional async via Tokio.

3. **Cover art is removed with its tag, and ADR-0029's descent does not extend to this group.**
   All five formats embed a picture inside a metadata block — FLAC `PICTURE`, ID3 `APIC`, Ogg's
   `METADATA_BLOCK_PICTURE`, MP4 `covr`. Deleting the block deletes the image and whatever Exif was
   inside it, so no descent machinery is needed. ADR-0029 exists for package formats, where an
   embedded image is a member the user expects to survive; here it is the metadata. Removal is
   declared per file in the report, because a user may not expect their album art to vanish.

4. **Motion HEIF stays refused, and tranche 5 does not quietly adopt it.** ADR-0034 refused it —
   and with it Apple Live Photos — on the ground that video is Group 4. That is a decision about
   the HEIF handler, not about MP4, and shipping tranche 5 does not reopen it: moving a format
   between handlers changes what `detect` routes where, and needs its own ADR.

5. **Three questions are named and left to their tranches**, as ADR-0032 left TIFF's and SVG's:
   MP4's sample-offset handling (tranche 5's first task), Ogg's repagination and CRC recomputation
   (tranche 4), and whether the RIFF walk moves out of `formats/webp.rs` into `container/riff.rs`
   (tranche 2). Each is decided against what the format requires, not settled here in advance.

**Consequences.**

- **Group 4 is not done until all five tranches are**, against the same per-format bar. As with
  ADR-0032, splitting the unit of delivery changes when work ships, never what it ships against.
- **`docs/ROADMAP.md` deliverable 4 is read through this ADR**, as deliverable 3 is through
  ADR-0032. The roadmap line is not rewritten; the ordering and the completion unit live here.
- **At least three further ADRs are owed inside this group**, plus one for any dependency a tranche
  adopts — and the `lofty` finding makes that last one likelier here than in any previous group.
- **Phase 2's remaining exit criteria come due when this group closes**, and they are phase-wide
  rather than group-wide: criterion 2 covers every fuzz target in the tree, old and new, and
  criterion 3 covers every shipped format. That is a sweep to budget for, not to discover.
- **The encoded audio is never entered**, on Phase 1's preserve-payload rule — the same trade the
  image handlers make for pixels, with the same cost, which is that metadata hidden inside the
  compressed stream is out of reach and the threat-model section says so.
- **The scope lock is unchanged.** Matroska and WebM, AAC in ADTS, AIFF, and the raw camera video
  formats are the obvious temptations once a page walker and a box walker are both in the tree.
  Each still needs a superseding ADR (ADR-0027).

---

## ADR-0038 — FLAC is edited by block surgery, and the audio MD5 stays

**Status:** Accepted (2026-09-01)

**Context.** ADR-0037's first tranche. A FLAC is a four-byte marker, a list of typed metadata
blocks, then audio frames to the end of the file (RFC 9639 §8). The identifying material is all in
the block list: a Vorbis comment naming the artist, the ripping software and the machine that ran
it; cover art that is an ordinary image with its own Exif inside it; a cuesheet carrying the
catalogue number of the disc.

The group's distinguishing hazard — a container index into a timed payload (ADR-0037) — **is not
present here**, and one sentence of the spec is why: a seek point's offset is measured "from the
first byte of the first frame header" (§8.5), not from the start of the file. Removing metadata
therefore moves nothing. That makes the choice available which ADR-0034 could not make for HEIF.

**Decision.**

1. **Edited by deletion, never re-encoded.** Blocks are dropped whole, kept blocks are copied as
   raw bytes, and the audio is appended verbatim, so a clean file comes back **byte-identical** —
   GIF's and JPEG XL's property (ADR-0036), which TIFF and HEIF cannot offer. The only field
   rewritten anywhere is the last-metadata-block flag (§8.1), which has to move when the block
   after it goes.

2. **`STREAMINFO`, `SEEKTABLE` and `PADDING` are kept; everything else goes.** An allow-list on
   the output side, as ADR-0033 and ADR-0036 use: a reserved type (7–126) is removed unread rather
   than surviving by being unrecognised. `APPLICATION` and `CUESHEET` go too — see below.

3. **Padding keeps its length and loses its contents.** §8.2 defines padding as *n* zero bits, so
   the bytes are replaced with the zeros the spec calls for rather than the block being dropped. A
   compliant file is unchanged, a file hiding data in its padding is scrubbed and told about, and
   the several kilobytes a later tagger writes in place are still there. Dropping the block would
   have been the more aggressive choice and would have cost the user a real capability for nothing.

4. **The audio MD5 in `STREAMINFO` is kept, and declared.** Its last sixteen bytes are an MD5 of
   the *unencoded* audio (§8.2) — a fingerprint, and one that links this file to any other copy of
   the same recording. It stays because it is **computed from the payload the file still carries**:
   anyone holding the file can recompute it, so removing it hides nothing from them while breaking
   every verifier that checks it. It is reported rather than passed over in silence, which is what
   `RetentionReason::DerivedFromPayload` exists for. An all-zero field means "unknown" and there is
   then nothing to declare.

5. **`CUESHEET` is removed, and what that costs is stated.** It carries the disc's media catalogue
   number and each track's ISRC, which identify a purchase and a pressing. Removing it means the
   file can no longer be split back into tracks, so the report says so — ADR-0036's treatment of
   `jbrd`, applied again.

6. **A frame sync must follow the last block, or the file is refused.** §9.1.1's 14-bit sync is the
   only thing that confirms the walk ended where the file says it did; without the check, a lying
   length would be silently accepted and the "audio" copied from the wrong offset.

7. **A FLAC with a prepended ID3v2 tag is refused by name** (`UnsupportedKind::Id3PrefixedFlac`).
   Non-standard but common. Reading the tag is tranche 3's job; cleaning the blocks and leaving an
   unread tag in front of them would be a success message about a file strypt had not finished.

8. **Cover art is removed with its block, so nothing descends into it.** ADR-0029's one-level
   descent into embedded images does not extend to this group, as ADR-0037 already recorded: a
   picture that is deleted does not have to be parsed first.

**Consequences.**

- **strypt removes more than mat2 here, in both directions of a real measurement.** mat2's
  `FLACParser` uses mutagen, which knows the Vorbis comment and the picture block; measured
  2026-09-01, it keeps `APPLICATION`, `CUESHEET` and reserved block types. That is recorded in
  `docs/THREAT_MODEL.md` §7.13 with the numbers, not claimed here.
- **The encoded audio is never entered**, so anything inside a frame's reserved bits or appended
  past the last frame is out of reach. Every report carries that note, clean files included.
- **No dependency was added.** The walker is about two hundred lines against a spec that fits on a
  page, which is ADR-0037's default holding for one more tranche. `lofty` remains un-rejected.
- **Decision 4 is the one to revisit** if a later tranche meets a payload-derived fingerprint that
  is *not* recomputable by the holder — the reasoning above does not transfer to that case.

---

## ADR-0039 — The RIFF walk moves into `container/riff.rs`, and WAV is edited by chunk surgery

**Status:** Accepted (2026-09-01)

**Context.** ADR-0037's second tranche, and the tranche its decision 5 named: *whether the RIFF walk
moves out of `formats/webp.rs` into `container/riff.rs`*. A WAV is a RIFF file — a `RIFF` header, a
`WAVE` form type, then a flat list of length-prefixed chunks, odd lengths padded to even
(RIFFMCI.RTF, "Multimedia Programming Interface and Data Specifications 1.0"). WebP is the same
container with a different form type, and strypt has walked it since Phase 1.

The identifying material is all in the chunk list: an `INFO` list naming artist, engineer and
copyright holder; a `bext` broadcast extension whose `Originator`, `OriginatorReference`, `UMID` and
`CodingHistory` name the desk, the operator and every processing step; `iXML` and `aXML` documents
from field recorders; XMP in `_PMX`; a whole ID3v2 tag in `id3 `; `cart` radio traffic fields down
to a URL.

The group's hazard — a container index into a timed payload (ADR-0037) — **is absent again**, and
one sentence is why: the `cue ` chunk's `dwChunkStart` and `dwBlockStart` are each "a byte offset
relative to the start of the data section of the 'wavl' LIST chunk" (verified 2026-09-01), never
into the file. Removing chunks moves nothing, exactly as RFC 9639 §8.5 gave FLAC (ADR-0038).

**Decision.**

1. **Extract `container/riff.rs`, shared by WebP and WAV.** Two real consumers now exist;
   `container/bmff.rs` was extracted on the strength of an *expected* one. What moves is the part
   that is identical and dangerous: length arithmetic on attacker-chosen fields — the chunk size,
   the odd-length pad byte, the tiling against the declared extent. A duplicated copy of that is a
   fail-closed hazard, because a fix lands in one copy and not the other. The module refuses rather
   than clamps, as `zip.rs` and `bmff.rs` do, and carries a format-agnostic `WalkError` each handler
   converts into its own `StryptError`.

2. **WebP keeps everything that is about WebP.** The form type, `VP8X`'s fixed-length rule,
   `validate_shape`, the flag correction, and the `ANMF` sub-chunk rewrite all stay in
   `formats/webp.rs`. The extraction is behaviour-preserving with one deliberate change: the `ANMF`
   sub-chunk walk had no item budget and now gets one. A `riff` fuzz target lands with the module —
   the `zip`/`bmff` precedent — and `webp` re-runs in the sustained run, because a shipped, heavily
   fuzzed handler was touched.

3. **WAV is edited by chunk surgery, never re-encoded.** Chunks are dropped whole, kept chunks are
   copied as raw bytes, and the `data` payload crosses byte for byte, so a clean file comes back
   **byte-identical** and the `RIFF` size is the only recomputed field in the file.

4. **`fmt `, `data`, `fact` and `cue ` are copied; everything else goes.** An allow-list on the
   output side (ADR-0033, ADR-0036, ADR-0038): an unknown chunk is removed unread rather than
   surviving by being unrecognised. `cue ` is a deliberate keep — it names nobody, it is playback
   structure, and per the context above nothing this handler removes can move its offsets.

5. **`JUNK`, `PAD ` and `FLLR` keep their length and lose their contents**, ADR-0038 decision 3
   carried across: a compliant file is unchanged, a file hiding data in its padding is scrubbed and
   told about, and the space a later tagger writes in place is still there.

6. **`id3 ` is dropped whole, and no ID3 reader enters the tree.** Reading it is tranche 3's job;
   deleting a chunk does not require parsing it — ADR-0036's treatment of `brob`, applied again.
   The same holds for `smpl`, whose removal costs the file its sampler loop points and is therefore
   declared, and for `cart`, `DISP`, `CSET`, `inst`, `plst` and every unknown `LIST` form.

7. **Three shapes are refused by name rather than as "unrecognised".** A file with no `fmt ` or no
   `data`, or a `fmt ` under sixteen bytes, is malformed. `RF64` and `BW64` (EBU Tech 3306, ITU-R
   BS.2088) are a **different container**, not a large WAV: their sizes live in a `ds64` chunk and
   the RIFF fields hold a `-1` placeholder, so walking them as RIFF would read the wrong lengths. A
   WAV whose audio is a `wavl` wave list is refused because *there* the `cue ` offsets index a
   structure the handler would be editing — which is exactly what ADR-0034 found in HEIF.

8. **mat2 is the contrast here, not the target — and the expected contrast did not appear.** Its
   `WAVParser` is an `AbstractFFmpegParser`, so it rebuilds the file through ffmpeg rather than
   editing it, and the reasonable prediction was that re-encoding would reach data hidden in the
   samples where chunk surgery cannot. **Measured on 2026-09-01, it does not**: for 16-bit PCM the
   re-encode reproduces the `data` payload byte for byte across all fourteen fixtures. The
   difference between the two tools on this format is in the container, not the audio. The
   prediction was worth testing and the measurement is what is recorded —
   `scripts/wav-differential.sh` compares the payload on every file for exactly this reason.

**Consequences.**

- **Neither tool reaches data hidden inside the sample values of a PCM WAV**, and
  `docs/THREAT_MODEL.md` §7.14 states that as a measured limit shared with mat2, not as a trade
  strypt makes alone.
- **A second handler now depends on `container/riff.rs`**, so a change there is a change to WebP.
  Both handlers' fuzz targets and the module's own must run before one lands.
- **The uninspected audio is declared on every file**, clean ones included: the samples are copied
  without being decoded.
- **No dependency was added.** `lofty` remains un-rejected (ADR-0037 decision 2).
- **Decision 7's `wavl` refusal is the one to revisit** if a real-producer file turns up using it;
  today it is a spec shape without a producer, and refusing costs nothing.

## ADR-0040 — MP3 is edited by deletion at both ends, and the ID3 reader is hand-written

**Status:** Accepted (2026-09-02)

**Context.** ADR-0037's third tranche. MP3 is the one format in this project that is **not a
container**: there is no header describing the file and no index. An MP3 is a run of self-describing
MPEG audio frames (ISO/IEC 11172-3 §2.4.2.3), and every piece of metadata it carries was glued to
one end or the other by a tagger — ID3v2 at the head; ID3v1, its `TAG+` extension, APEv1/v2 and
Lyrics3 v1/v2 at the tail.

The group's hazard — a container index into a timed payload (ADR-0037) — is absent for the third
time, and for a stronger reason than FLAC's or WAV's: **nothing in an MP3 points at anything else**.
There is no offset, length or flag anywhere that removing a tag could invalidate.

The open question the tranche inherited was the reader. ID3v2 is not a trivial format: three major
versions with different frame-identifier widths and size encodings, syncsafe integers, an optional
extended header counted differently in v2.3 and v2.4, an optional footer, and §6.1's
unsynchronisation.

**Decision.**

1. **The ID3 reader is hand-written, in `formats/tags.rs`.** The `id3` crate (1.17.1, MIT, edition
   2024, `rust-version` 1.85 — checked 2026-09-02) was evaluated and declined on two grounds. The
   first is shape: it models a tag as something to read, convert and **write back**, where strypt
   needs a byte range to delete and a reason to refuse a structure it cannot account for, which that
   API has no notion of. The second is the optional `tokio` dependency, and it is worth recording
   what the check actually proved: trial-adding the crate and running `scripts/check-no-network.sh`
   **passed**, and `cargo metadata --all-features` showed no `tokio` — because `--all-features`
   applies to workspace members, not to dependencies. So the gate neither opened the door nor
   flagged it. That is a finding about the gate as much as about the crate (ADR-0004, CLAUDE.md §6),
   and it is the reason the decision did not rest on a green run.

2. **`formats/tags.rs` is shared by `mp3` and `flac`,** as `formats/xmp.rs` is shared by the image
   handlers and for the same reason: the tag is the same wherever it is stuck, and two handlers have
   no business disagreeing about what is in one. It names byte ranges and never rewrites one.

3. **Itemising is best-effort; removal is not.** A tag whose insides do not add up is reported in
   one line and deleted whole — ADR-0038's treatment of a Vorbis comment. The split keeps the
   fail-closed surface small: a mis-parsed frame costs a line of a report, while a mis-parsed tag
   *length* would cost the boundary between metadata and audio.

4. **A tag length is refused, never clamped.** A size field that is not the syncsafe integer §6.2
   requires, a span running past the end of the file, a major version whose header this code has
   never read, an APE footer claiming a header that is not there — each refuses the file. Lyrics3 v1
   is the one exception and it goes the other way: it carries no size at all, so a `LYRICSEND` that
   is really audio yields "no tag" rather than a refusal, because there is no number to have lied.

5. **The tail scan has a floor.** Tail tags are peeled down to where the head tags stopped and no
   further. Without it a lying tail-tag size would swallow the audio, and the file would strip to
   nothing while reporting success — the fail-closed rule's worst case.

6. **The handler demands a real frame header where the tags stop.** It is the format's only
   structural check and it carries the whole safety argument: there is no allow-list here because
   the frames *are* the payload and everything that is not a frame goes. A bounded run of **zeros**
   between the tags and the first frame is dropped and reported; anything else there refuses the
   file, because a run of arbitrary bytes in front of the audio is exactly where something would be
   hidden from a tool that skipped ahead to the first sync.

7. **A VBR header frame — `Xing`, `Info` or `VBRI` — is kept and declared.** It is a real MPEG frame
   that decoders play as silence, and the LAME extension inside it names the encoder and its
   settings. It is *inside the encoded stream*, which ADR-0037 commits this group to never entering,
   and removing it would break VBR seeking and gapless playback. mat2 leaves it too. A keep nobody
   is told about is a leak with a clean report, so it is in the report.

8. **Layers I and II are refused by name.** The same frame grammar, a different format, and Phase
   2's scope is MP3 (ADR-0027). "Unrecognised" would be untrue for a file most tools would call
   MPEG audio.

9. **ADR-0038 decision 7 is lifted: an ID3-prefixed FLAC is no longer refused.** That refusal stood
   only because there was no ID3 reader in the tree, and there is one now. Symmetrically, a trailing
   ID3v1, APE or Lyrics3 tag on a FLAC is peeled too — it used to survive silently under the generic
   "the frames are not decoded" note. mat2's `FLACParser` already did both, so this closes a place
   where mat2 was the better recommendation. `flac` and `detect` therefore re-run in the sustained
   fuzz run alongside the two new targets.

10. **mat2 is the contrast here, and the difference is measurable in both directions.** Its
    `MP3Parser` deletes the ID3 tag through mutagen; neither tool re-encodes, so this is the closest
    comparison in the project so far. Measured 2026-09-02 against mat2 0.15.0: a Lyrics3 tag that is
    the only tag on a file survives mat2 and does not survive strypt. In the other direction, strypt
    **refuses** files mat2 will still clean — an `.mp2`, or a file with arbitrary bytes in front of
    the audio — and for those files mat2 is the better recommendation (ADR-0012).

**Consequences.**

- **A file with no tags comes back byte-identical**, GIF's, JPEG XL's, FLAC's and WAV's property.
- **Nothing in the encoded stream is reachable by either tool**, and `docs/THREAT_MODEL.md` §7.15
  states that as a limit shared with mat2 rather than a trade strypt makes alone.
- **A second module is now shared between handlers**, so a change to `formats/tags.rs` is a change to
  FLAC as well as MP3. Both handler targets and the `tags` target must run before one lands.
- **No dependency was added.** `lofty` remains un-rejected (ADR-0037 decision 2), and `id3` is now
  declined with a reason.
- **`scripts/check-no-network.sh` does not see a dependency's optional features.** Recorded here
  because the next person to evaluate a crate with an optional networking feature will get the same
  clean result, and it means less than it looks like.

---

## ADR-0041 — Ogg is rebuilt page by page, and the stream serial number is rewritten

**Status:** Accepted (2026-09-03)

**Context.** ADR-0037's fourth tranche, and the first format in this project that is a container for
*somebody else's* format. An Ogg file is nothing but pages (RFC 3533 §6): a capture pattern, a
granule position, a serial number naming the logical bitstream, a page sequence number, a CRC over
the whole page, and a lacing table chopping packets into segments. What those packets mean is
decided by a codec mapping, and the metadata lives in a mapping-defined header packet.

Three mappings are in scope for this tranche: Vorbis I §4.2, Opus (RFC 7845), and the Ogg FLAC
mapping. All three carry their identifying material in a Vorbis comment — the same structure FLAC
already reads (ADR-0038) — and Ogg FLAC carries a whole FLAC metadata block list on top of it.

Two things make Ogg unlike the three tranches before it. Each page carries a CRC, so no byte can be
changed without recomputing something. And the granule position is per *page*, not per packet: it
timestamps the last packet that finishes on that page, and there is no way to recover a per-packet
timestamp without decoding.

**Decision.**

1. **Ogg is rebuilt, page by page, with every CRC recomputed.** Editing in place is not available at
   any granularity: emptying the comment packet changes its length, which changes its page's lacing
   table, which changes that page's size and CRC, and every page after it renumbers. Packet payloads
   are copied verbatim; only the pages around them are new.

2. **Input CRCs are verified, and a mismatch refuses the file.** The CRC is the evidence that the
   walk is where it thinks it is — FLAC's frame-sync check by another name (ADR-0038) — and every
   decoder drops a bad page anyway, so accepting one would mean cleaning bytes no player reads.

3. **Granule positions are carried verbatim.** RFC 3533 §3 makes a granule position a codec-defined
   sample count, not a file offset, so removal moves nothing: the group's hazard (ADR-0037) is
   absent for the fourth time running. But because a granule belongs to a page rather than a packet,
   **the input's page grouping cannot be discarded.** The rebuild keeps, for each input page, the
   packets that completed on it, so every granule stays attached to the packet it timestamps. A page
   that completes no packet is dropped, and one carrying a granule other than −1 there — which RFC
   3533 §6 does not allow — refuses the file rather than losing a number nobody can recompute.

4. **Page sequence numbers are renumbered from zero.** Removal can change how many pages there are,
   and a decoder reads the sequence to detect a hole in the stream.

5. **The serial number is rewritten to zero.** It is an identifier in its own right: 32 bits chosen
   by the encoder, not derived from the audio, and libogg's own example seeds it from `time(NULL)`,
   so it can carry the wall-clock time of the encode and links every copy of a file to itself. It is
   the case ADR-0038's consequence reserved — a payload-adjacent fingerprint the holder of the file
   *cannot* recompute — and the answer there is the opposite of the answer for FLAC's audio MD5.
   Zero rather than a random value because nothing in this crate may be non-deterministic.

6. **Exactly one logical bitstream.** A multiplexed file (a Vorbis stream beside a Theora one) or a
   chained one is refused by name, not partly cleaned: a second stream is a second mapping, with a
   second comment header this handler has not read. It also keeps the rebuild a single linear pass.
   Bytes before the first page or after the last are refused for the same reason MP3 refuses a run
   of non-zero bytes in front of its audio (ADR-0040 decision 6).

7. **Vorbis, Opus and FLAC-in-Ogg land; Theora, Speex, Skeleton and anything unrecognised are
   refused by name.** Theora is video and is Phase 2's fifth tranche at the earliest. Speex is
   deprecated by its own authors and has no fixtures anyone can generate without adding an encoder.
   Skeleton only ever appears alongside another stream, which decision 6 already refuses. Naming
   them beats "unrecognised" for a file every player calls an Ogg.

8. **The comment header is emptied, not deleted.** All three mappings require the packet to be
   present — it is the second header packet, and a decoder that does not find it there stops — so
   the FLAC treatment of dropping the block whole is not available. What is written back is an empty
   vendor string and a zero comment count, plus Vorbis I's framing bit, which Opus does not have.

9. **FLAC-in-Ogg keeps its packet count.** Each metadata block after the mapping header is its own
   packet, and the header declares how many there are. A removed block therefore becomes a
   zero-length `PADDING` block rather than a dropped packet, so neither the declared count nor the
   last-metadata-block flag has to be rewritten. `STREAMINFO` is kept, and its MD5 of the unencoded
   audio is kept and declared, exactly as ADR-0038 decision 4 has it.

10. **The Vorbis comment reader is shared, as `formats/vorbis.rs`.** It is lifted out of `flac.rs`
    unchanged, on ADR-0040 decision 2's reasoning: the structure is the same wherever it is stuck,
    and two handlers have no business disagreeing about what is in one. **`flac` therefore re-runs
    in the sustained fuzz run**, as it did for the tranche before. It gets no target of its own — it
    is a reader like `formats/xmp.rs`, not a container, and both handler targets reach it with
    arbitrary bytes.

11. **Two new fuzz targets, split as ADR-0028 splits `zip` from `ooxml`.** `oggpage` drives
    `container/ogg.rs` through `fuzzing.rs`: the page walk, the CRC, packet assembly and the page
    writer, reached without having to look like any codec first. `ogg` drives the handler.

12. **mat2 is the closest comparison in the project so far, and the differences go both ways.** Its
    `OggParser` goes through mutagen, which rewrites the comment header and repaginates — so neither
    tool re-encodes and both empty the same packet. Measured by `scripts/ogg-differential.sh` on
    2026-09-03 against **mat2 0.15.0**, no gaps across the ten well-formed fixtures: mat2 **keeps the
    vendor string** on every fixture that has one and **leaves the serial number alone**, and strypt
    clears both. In the other direction, strypt refuses multiplexed, chained and Theora files that
    mat2 will still process, and **for those files mat2 is the better recommendation** (ADR-0012).

**Consequences.**

- **A clean Ogg does not come back byte-identical**, and this is the first handler in group 4 that
  cannot promise it. Decision 5 is the whole reason: a file whose serial is already zero and whose
  pages already end at packet boundaries does round-trip unchanged, and no real encoder writes one.
  What is promised instead, and tested: **the packets cross byte for byte**, and stripping twice is
  byte-exact.
- **Page boundaries can move.** A packet that spanned pages in the input is emitted whole on the page
  it completed on, so a file paginated mid-packet comes back with a different page layout and the
  same packets, granules and timings.
- **A third module is now shared between handlers.** A change to `formats/vorbis.rs` is a change to
  FLAC; a change to `container/ogg.rs` is a change to all three Ogg spellings.
- **No dependency was added.** `lofty` remains un-rejected (ADR-0037 decision 2), and no Ogg,
  Vorbis, Opus or CRC crate entered the tree — the CRC is eight lines of `wrapping_shl`.
- **Group 4 has one tranche left**, and it is the one the hazard is actually in (ADR-0037).

---

## ADR-0042 — MP4 is edited by deletion, and every chunk offset is remapped through a verified table

**Status:** Accepted (2026-09-04)

**Context.** ADR-0037's fifth and last tranche, and the one the group was ordered around: MP4 is
where the offset hazard actually lives. `stco` (ISO/IEC 14496-12 §8.7.5) holds a table of **absolute
file offsets** to the chunks of media inside `mdat`, and `co64` is the same table with 64-bit
entries. Remove a box in front of the `mdat` and every one of those numbers is wrong. Nothing warns:
the file still opens, and the decoder reads whatever now sits where the chunk used to be.

ADR-0034 met the same sentence in HEIF and concluded that the file had to be rebuilt. This tranche
has to answer whether that conclusion carries.

It does not, and the reason is structural rather than stylistic. In HEIF the metadata is *inside*
`mdat`: Exif and XMP are items whose bytes are interleaved with the coded picture and addressed by
`iloc`. Removing one punches a hole in the payload region, and every surviving item after it moves
by a different amount, so there is no single delta to apply. In MP4 the metadata is entirely
*outside* `mdat` — `moov/udta`, `moov/meta`, a top-level `uuid`, `free` — and the media data is one
opaque run of bytes nobody edits. Each `mdat` therefore **translates rigidly**: every chunk inside it
moves by the same number of bytes, which is the number of bytes removed ahead of it.

**Decision.**

1. **MP4 is edited by deletion, not rebuilt. ADR-0034's conclusion reverses.** The tree is filtered
   against allow-lists and re-emitted; `ftyp` and every `mdat` cross verbatim, header bytes included,
   so a 64-bit `mdat` header stays a 64-bit header. What is written fresh is `moov` and the boxes
   under it, because that is where the removals are.

2. **When a box ahead of an `mdat` is removed, every chunk offset is rewritten through a relocation
   table, and an offset that does not resolve refuses the file.** The table holds one entry per input
   `mdat`: its old payload extent and its new start. Each `stco`/`co64` entry must fall **inside a
   known input `mdat` extent**; its replacement is that entry's position within the extent, measured
   from the new start. An offset landing in no `mdat` — in a `free` box that was deleted, in `moov`,
   past the end of the file — is `BrokenIndex` and nothing is written. It is deliberately **not**
   adjusted by a blind delta: a blind delta on an offset nobody located produces a file that plays
   the wrong bytes, which is the failure ADR-0039 refused a wave list to avoid.

   The file only ever shrinks, so a 32-bit `stco` cannot overflow into needing `co64`; the conversion
   is checked anyway and refuses rather than truncating.

3. **The rewrite is two-pass, and a size disagreement between the passes is a refusal.** `moov`'s
   size decides where the `mdat`s land, and the offsets written into `moov` depend on where they
   land. The loop is cut by the fact that the *widths* never change — a `stco` stays a `stco` with
   the same entry count — so the first pass writes the tree with placeholder offsets purely to
   measure it, the layout is computed, and the second pass writes it for real. The second pass's
   `moov` must be exactly as long as the first's; if it is not, the assumption is broken and the file
   is refused as `NotRoundTrippable` rather than written with offsets pointing at nothing.

4. **`container/bmff.rs` is shared, and extended by two things.** A `Box` now records its header
   length, and `bmff::raw` hands back a box's original bytes. Both exist for decision 1: verbatim
   re-emission is only verbatim if the header form is preserved, and `write_box` deliberately only
   ever writes 32-bit sizes. Nothing MP4-specific enters the module. **`heif` and `bmff` therefore
   re-run in the sustained fuzz run**, as `webp` did for ADR-0039 and `flac` for ADR-0040 and
   ADR-0041.

5. **Brands that land:** `isom`, `iso2`, `iso4`, `iso5`, `iso6`, `mp41`, `mp42`, `mmp4`, `avc1` and
   `M4V ` route to `Format::Mp4`; `M4A ` and `M4B ` route to `Format::M4a`. Two formats, one
   `Mp4Handler`, as HEIF and AVIF share one (ADR-0034). They are separate formats because they are
   separate things to a user and get separate output extensions, not because the code differs.

6. **Fragmented MP4 is refused by name.** A `moof`, `mfra`, `mvex`, `styp` or `sidx` box, or a
   `dash`, `msdh`, `msix`, `cmfc` or `cmfl` brand, refuses the file. `tfhd`'s `base_data_offset` and
   every `tfra` entry are absolute file offsets again, in structures spread across fragments that
   this handler does not read — decision 2's table cannot be built for them, and a fragmented file
   edited as though it were progressive plays silence.

7. **DRM is refused by name.** A `pssh` box anywhere, or a sample entry of type `encv`, `enca`,
   `encs`, `enct`, `drms` or `drmi`, or the `M4P ` brand. Common Encryption puts the real sample
   entry inside `sinf/frma` and leaves ciphertext behind; strypt has no rule that matches ciphertext,
   so a protected file reported clean would have been examined by nobody — the ODF and HEIF
   `ipro` refusals by another name (§7.7, ADR-0034). The signal is the sample entry type, the
   `pssh`, and the brand; strypt does not attempt to find a `sinf` inside a sample entry it does not
   parse, and says so in `docs/THREAT_MODEL.md` §7.17.

   QuickTime (`qt  `) and the 3GPP brands are refused as out of scope: ADR-0037's tranche is MP4 and
   M4A, and `.mov` carries QuickTime-only atoms with their own rules.

8. **Removals.** `udta` at every level, which is where `©nam`, `©ART`, `©day`, `©too`, iTunes `----`
   free-form tags, `covr` cover art and — the one that matters most — `©xyz`, the ISO-6709 GPS string
   every iPhone and most Android phones write into every video they record. Also `meta`/`ilst`/`keys`
   wherever they appear, `uuid` including the Adobe XMP one, `free`/`skip`/`wide`, `pnot`/`PICT`,
   `iods`, `ctab`, and Microsoft's `Xtra`.

9. **Five fields are edited in place rather than removed**, because the boxes holding them are
   mandatory: `creation_time` and `modification_time` are zeroed in `mvhd`, `tkhd` and `mdhd`;
   `hdlr`'s trailing name string is emptied (encoders write their own product name there); `mdhd`'s
   language is set to `und`; `mvhd`'s 24-byte `pre_defined` block — poster time, preview and
   selection windows, current time — is zeroed, which §8.2.2 says it should have been; and
   **`compressorname` in a video sample entry is zeroed**. The last is the one exception to decision
   10's rule that this handler does not read inside a sample entry, and it is narrow on purpose:
   §12.1.3 fixes the field's offset in a `VisualSampleEntry`, the track's `hdlr` type says the entry
   is one, nothing decodes it, and ffmpeg writes `Lavc libx264` into it — a software fingerprint of
   exactly the class `©too` is. Audio entries have no such field and are left alone rather than
   read at a guessed offset. The language is the field with a cost: in a file carrying several
   language tracks, a player can no longer auto-select one. It is removed rather than kept because
   it is a per-file editorial fact about who the file was made for, and mat2 normalises it the same
   way.

10. **Unknown boxes are dropped and reported rather than refused, and decision 2 is why that is
    safe.** ADR-0036 refuses an unknown top-level JPEG XL box because in that format a box is where
    metadata lives and nothing else can be inferred. Here the safety argument is stronger and does not
    need the refusal: media data is only reachable through a chunk offset, and every chunk offset
    must resolve inside an `mdat` that was kept. A dropped box that something pointed into refuses
    the file automatically, at the offset check, without a list having to anticipate its name.

11. **One new fuzz target, `mp4`.** No container-level target is added: `bmff` already exists and
    already drives the walker and the writer through `fuzzing.rs`, and it is in this tranche's
    sustained run for decision 4's reason. The target asserts the size invariant — deletion cannot
    grow a file — **guarded by a `detect` check**, per the 2026-08-26 lesson.

12. **mat2 handles MP4 very differently, and the end state is close.** Its `MP4Parser` subclasses
    `AbstractFFmpegParser` and **remuxes the file through ffmpeg** with `-map 0 -codec copy
    -map_metadata -1 -map_chapters -1 -disposition 0` and the `bitexact` flags, then checks what
    survived against an allow-list that expects the `mvhd`/`tkhd`/`mdhd` dates to be present and
    **zeroed** rather than absent — the same end state decision 9 reaches by patching six fields in
    place. Measured by `scripts/mp4-differential.sh` on 2026-09-04 against **mat2 0.15.0, ExifTool
    13.55 and ffmpeg 9.0.1**. Two differences worth stating: mat2 rewrites the whole container, so
    its output is a different file that plays the same media, where strypt's `mdat` is the input's
    `mdat` byte for byte; and **mat2 0.15.0 does not claim `.m4a` at all** — its MP4 parser registers
    `video/mp4` only — so for an audio-only file in this container there is no mat2 comparison to
    make. In the other direction mat2 will process a fragmented or QuickTime file that strypt
    refuses, and **for those files mat2 is the better recommendation** (ADR-0012). Measured result:
    **no gaps** — mat2 keeps `HandlerDescription`, `HandlerVendorID` and an empty `free` box on every
    fixture, all three of which strypt removes.

**Consequences.**

- **A clean MP4 comes back byte-identical.** Group 4's other rebuilt format could not promise that
  (ADR-0041), and this one can: nothing is renumbered, nothing is repaginated, and a file whose
  timestamps are already zero and whose tree is already on the allow-list re-emits to the same bytes.
  Stripping twice is byte-exact regardless.
- **`container/bmff.rs` now has two callers, and a change to it is a change to HEIF and AVIF.** That
  is the third shared module in group 4, after `formats/tags.rs` and `formats/vorbis.rs`.
- **The offset table is the whole safety argument**, in the way the tag boundary was for MP3
  (ADR-0040). Every future change to what MP4 drops has to keep asking whether anything pointed into
  it, and the answer is enforced by decision 2 rather than by remembering.
- **No dependency was added.** `lofty` ends the group as it started it: not rejected, not adopted
  (ADR-0037 decision 2).
- **Group 4 is closed, and with it the four format groups ADR-0027 scoped for Phase 2.** Anything
  further — Matroska, WebM, AAC in ADTS, AIFF, fragmented MP4, QuickTime — needs a superseding ADR.

---

## ADR-0043 — Phase 3 opens, and live-OS validation becomes a filesystem-constraints matrix

**Status:** Accepted (2026-09-05)

**Revises `docs/ROADMAP.md` Phase 3** — its deliverable list and its exit criteria. It does not
touch ADR-0014, which is revised on its own schedule by decision 5 below.

**Context.** Phase 2 closed on 2026-09-05 with all four groups landed and all four exit criteria
met, so ADR-0027's gate permits the next phase to open. Phase 3's deliverables were written in
Phase 0, before a single parser existed, and two of the six have been overtaken — one by what the
tree turned out to be, one by what hardware exists.

**The live-OS deliverable is the one that does not survive contact.** It asks for Tails and
Qubes-Whonix "actually booted and tested", covering read-only filesystem behaviour, temp-file
placement, and constrained writable space. Verified 2026-09-05: **Tails is x86-64 only** and
states that it does not run on ARM; **Qubes OS requires bare-metal Xen with VT-d/IOMMU** and
disables nested virtualisation deliberately, because of the attack surface it adds. This
project's machine is an Apple M3 Pro. Tails therefore runs only under whole-machine emulation,
and Qubes-Whonix does not run at all.

**The hardware is the smaller problem.** The deliverable's premise is weaker than it looked when
it was written. The two failure modes it exists to catch are already designed out and tested:
`crates/strypt-core/src/io.rs` creates the temporary **in the destination's own directory, never
in `TMPDIR`** — its module header gives `rename` being atomic only within a filesystem as the
reason — and `the_temporary_sits_beside_the_destination_not_in_tmpdir` asserts it. So `EXDEV` on
the rename and a large temporary filling a RAM-backed `tmpfs` are both closed by construction.

What is left is **filesystem shape, not distribution identity**: a read-only destination
directory, `ENOSPC` on a small volume, removable media with no Unix permission model, a
destination on a different mount. Every one of those reproduces on a plain Linux VM with a
loopback image — natively on aarch64, at full speed — and reproduces *in CI*, where a manual boot
is a point-in-time anecdote that rots the next time the write path changes.

**Decision.**

1. **Phase 3 is open**, and its scope is exactly the nine deliverables in `docs/ROADMAP.md`
   Phase 3 as revised by this ADR. ADR-0027's rule carries over verbatim: **"Phase 3 is open" is
   not "scope is open"**. The format list stays locked where ADR-0042 left it, and Phase 3 adds no
   formats.

2. **Live-OS validation is replaced by a filesystem-constraints matrix**, run in CI on Linux
   against the real CLI binary. It covers, at minimum: a **read-only destination directory**; a
   **full volume**, so `ENOSPC` lands mid-write; **removable-media filesystems without a Unix
   permission model** (`vfat`, `exfat`); a **destination on a different mount** from `TMPDIR`; and
   a **destination directory the user cannot write but whose file is writable**. Each case asserts
   the fail-closed contract, not merely the absence of a panic: the destination is either replaced
   in full or untouched, no `.strypt-*.tmp` survives, and no success is reported for a file that
   was not written.

3. **Tails becomes an optional confirmatory boot; Qubes-Whonix is deferred**, with the hardware
   reason recorded here rather than left as an unmet criterion nobody can meet. Exit criterion 6
   is rewritten to ask for the matrix. **The claims this invalidates are corrected in the same
   change as this ADR** — `docs/PRD.md` §8 and `docs/ARCHITECTURE.md` §8 both currently say live-OS
   behaviour is assumed and that Phase 3 will test it on real systems, and both must say what is
   actually being tested instead.

4. **ADR-0019's Windows permission debt becomes an explicit deliverable.** `io.rs` says in a
   comment that `Permissions::OwnerOnly` is weaker on Windows because the new file inherits the
   parent directory's ACL, and that **"Phase 3's platform validation is where it gets addressed"**.
   The roadmap never listed it. It is listed now, and its outcome may be either narrowing the ACL
   or recording the gap as permanent — but not silence.

5. **ADR-0014 is revised, not superseded**, and not yet. `docs/ROADMAP.md` already carries the
   accumulated plateau evidence and its own reading of it: one target saturates in 39 seconds while
   `pdf` has not flattened across three consecutive twelve-hour runs, so a flat 100 CPU-hours per
   target is the wrong shape.

   **The measured policy needs a curve per handler, not a curve for `pdf`.** Superseding needs the
   budget **and** the plateau, and on the evidence to date only `bmff`, `detect`, `zip` and `tiff`
   have ever plateaued — four of twenty-two. `pdf` is the loudest case, not the only one, and seven
   targets (`jpeg`, `png`, `gif`, `mp3`, `tags`, `oggpage`, `riff`) have no plateau measurement
   recorded at all.

   **The first step is a tally, not a run.** Twenty-eight run directories under
   `target/fuzz-runs/` already hold a `summary.md` and per-target `cov-*.tsv`. Per-handler
   cumulative CPU-hours since last substantive change, and last-gain time per run, are computable
   from them for free. That tally decides who owes hours, who owes only a plateau, and who is
   already done — and it is what stops the phase burning days of CPU on targets that saturated
   weeks ago.

   **Runs are then batched to the core count.** The runner starts one process per target in
   parallel, so selecting more targets than cores oversubscribes them and corrupts coverage
   against wall-time, which is the measurement. Batch below the core count rather than running
   twenty-two at once.

6. **Deliverable order.** The fuzzing work starts first because it is gated by wall-clock rather
   than by attention, and everything else proceeds beside it. Nothing in this phase gates anything
   else in it, with one exception: **`docs/THREAT_MODEL.md`'s revision is last**, because it is
   supposed to record what hardening taught us, and writing it early would make it a plan rather
   than a finding.

**Consequences.**

- **Exit criterion 6 becomes meetable on hardware this project has.** The old one could not be met
  at all, and an unmeetable criterion is not a high bar — it is an invitation to quietly redefine
  the bar later, which is the failure mode this phase exists to prevent.
- **The matrix is stronger evidence than the boot it replaces**, and this is the actual argument,
  not a consolation. It is repeatable, it runs on every push, and it fails when someone changes the
  write path in two years. A one-off manual boot proves the binary worked once on one image.
- **What is given up, stated rather than glossed:** nothing now exercises Tails's real squashfs and
  Persistent Storage layout, or Qubes's inter-VM file copy and volatile root. If a bug lives
  specifically in those, this phase will not find it. That is a real reduction in coverage, taken
  because the alternative was an unmeetable criterion rather than because the risk is zero.
- **One specific hypothesis the matrix should settle.** `io.rs`'s `commit` re-asserts permissions
  **after** the rename has already succeeded and propagates the error. On a `vfat`/`exfat` stick —
  a borrowed machine with files on a USB key, which is `docs/PRD.md` §5's Tails persona exactly —
  `chmod` typically fails with `EPERM`, which would make `commit` return an error for a file it
  wrote correctly and put in place. This is a **hypothesis, not a measured defect**: it has not
  been run on `vfat`. It fails in the safe direction if real — a false failure, not a false success
  — so constraint 6 holds either way, but it is a real defect for that persona.
- **Phase 4's `.deb` reasoning loses a support it had not yet earned.** `docs/ROADMAP.md` Phase 4
  picks `.deb` partly because Tails and Qubes-Whonix are Debian-based. That argument stands on the
  distributions being Debian-derived; it does not stand on validation that has not happened, and
  Phase 4 must not cite this phase as having confirmed it.
- **ADR-0012 still binds, and gets no easier here.** Hardening is where "audited", "proven" and
  "hardened" start sounding like available words. A passing matrix is evidence about specific
  filesystem behaviours, and nothing in this phase licenses a claim about total metadata removal.

---

## ADR-0044 — The fuzzing plateau is a curve shape, not an absence of new edges

**Status:** Accepted (2026-09-10)

**Supersedes ADR-0014's plateau definition and its 100 CPU-hour budget.** ADR-0014's other
content — that a handler's clock resets when its sources change, shared modules included — is
retained and is now enforced by `scripts/fuzz-tally.py`. Discharges ADR-0043 decision 5.

**Context.** ADR-0014 set a provisional bar: 100 CPU-hours per handler since its last substantive
change, **plus** a plateau, defined as no new edge in the final 25% of the run. It was written in
Phase 0 with no measurements. Phase 3 deliverable 1 is to replace it with a measured policy, and
there are now **80 recorded coverage curves across 22 targets**, including three batches run for
this purpose at 12, 24 and 48 hours.

**The measurements falsify the definition in both directions, which is why it is superseded
rather than retuned.**

`pdf`'s 48-hour run reached 5,944 edges with per-window gains of 3955, 235, 40, 13, 1, 4. It has
been flat since the 12-hour mark. It found one edge at 47h07m, and ADR-0014 therefore records
**"NO — still climbing"** for the most obviously saturated curve in the set. A single late edge
on a five-thousand-edge corpus is noise, and a rule that a coin-flip can fail is not a gate.

`ogg`'s 48-hour run gives the opposite failure. Its windows are 77, 9, 5, 2, **140**, 42: flat from hour 8
to hour 32 — 16 edges across three windows — and then a 140-edge breakthrough in the fifth.
**Any rule evaluated at 24 hours would have passed it**, and it would then have found 184 more
edges. Flatness is not
evidence of saturation; it is also what being stuck behind a hard constraint looks like, which for
Ogg is the per-page CRC that ADR-0041 documents.

**A rate-based rule fixes neither.** Measuring gain in the final quarter as a fraction of total
coverage was the obvious repair, and `webp` shows why it fails: 1.12% at 24 hours, 0.00% at 48
hours, same code. The number reports where the run was cut, not what the handler did.

**The finding that decided the shape of the rule: "still climbing" does not exist.** Classifying
all 80 curves puts **zero** of them in a slow-steady-slope bucket. Every curve is either a decaying
one — large first window, monotone-ish decay after — or a punctuated one, flat with breakthroughs.
ADR-0014 was measuring a state this project's fuzzing does not enter.

**Decision.**

1. **A plateau is a windowed curve shape.** Split the run into six equal windows. Window 1 is
   initial exploration and is never tested. A run is **punctuated** if any later window's gain both
   exceeds 1% of final coverage and at least doubles its predecessor. Otherwise it is **saturated**
   if the final window's gain is under 1% of final coverage. `scripts/fuzz-plateau.py` is the test;
   the rule is not to be applied by eye.

2. **The 1% floor is load-bearing and is not a tuning knob.** Without it the doubling test fires on
   noise, because a window that gained zero doubles to anything. It is what keeps `webp`'s +21 on a
   2,229-edge corpus from reading as a breakthrough.

3. **The budget is 24 CPU-hours per handler per run, not 100.** Every handler that punctuated at 12
   hours had settled by 24 except `ogg`, `jxl` and `png`. Duration is doing the work the hour count
   was supposed to do: a breakthrough needs long enough to occur *and decay* inside the same run.
   `pdf` — the largest state space in the tree — was flat from hour 12 of 48.

4. **A handler certifies on one run of at least 24 hours that classifies saturated.** On the
   evidence to date that certifies twelve: `flac gif heif jpeg mp3 mp4 odf ooxml pdf svg wav webp`.

5. **Three handlers are recurrently punctuated and do not certify: `ogg`, `jxl`, `png`.** `ogg` is
   the serious case — punctuated at 12, 24 *and* 48 hours, and `oggpage` punctuated on its only run,
   which is the same `container/ogg.rs` seen through a second target. **More hours are not the
   remedy and this ADR does not prescribe them.** 84 CPU-hours have not made `ogg` converge, and the
   140-edge window shows the fuzzer spending most of a run failing to construct a valid page
   checksum. The intervention is structure-aware input — a dictionary of page headers, or a
   CRC-fixing mutator — and it is a Phase 3 task in its own right, entered on `docs/ROADMAP.md`
   under deliverable 1.

6. **Seven targets have no run of 24 hours or longer**: `bmff detect riff tags tiff zip oggpage`.
   They owe one run each at the new budget. This is a known scheduled cost of about **one batch**,
   not a gap being quietly dropped.

**Consequences.**

- **The outstanding fuzzing debt falls from roughly 1,401 CPU-hours to roughly 170.** That is the
  practical result of the phase's first deliverable, and it comes from measuring rather than from
  lowering a bar: `bmff` saturates in 39 seconds and would have burnt 100 hours proving it.
- **The policy can now fail a handler for a reason.** ADR-0014 failed 22 of 22, including targets
  that cannot gain another edge, so it carried no information. This one certifies 12 and fails 3,
  and the 3 are the 3 with a diagnosable cause.
- **`ogg`'s exception must not decay into an exemption.** It is a handler where this project's
  fuzzing is known to be weak, on a format that is rebuilt rather than edited. It stays on the
  roadmap until the structure-aware work happens, and `docs/THREAT_MODEL.md` §7's Ogg subsection
  records it when deliverable 9 is written.
- **The rule is falsifiable and cheap to re-run**, which matters more than its exact constants. Any
  future contributor can re-run `fuzz-plateau.py` over the whole archive and see whether the
  classification still holds, including against these numbers.
- **What this does not license.** A certified handler means its coverage curve stopped producing new
  edges under this corpus and this harness. It is not a statement that the handler is correct, that
  its format is fully explored, or that metadata removal is complete — ADR-0012 and constraint 7
  bind here exactly as elsewhere.

---

## ADR-0045 — Every supply-chain check is a hard gate, and CI proves each one fails

**Status:** Accepted (2026-09-11)

**Completes ADR-0016**, which kept `advisories` non-blocking until Phase 3, and **brings
`deny.toml` into line with ADR-0008**, which named duplicate versions as part of the hard gate
while the config only warned on them. Discharges Phase 3 deliverable 4.

**Context.** Three of `cargo-deny`'s four checks were already hard. Two things were missing.
`advisories` still ran with `continue-on-error`, and **`cargo-deny` had never been shown
failing at all.** The no-network gate had, once, by hand, on 2026-08-19 (the procedure was in
`INSTRUCTIONS.md`). Exit criterion 2 asks for both gates to be proven to fail, and a manual
procedure has the same flaw ADR-0043 found in the Tails boot: it proves the gate worked on the
day someone remembered to run it.

Verified 2026-09-11: cargo-deny **0.20.2** is current, and `cargo-deny-action@v2` bundles it. The
advisories `version` field is no longer used, and `unsound` defaults to workspace crates only.

**The stricter config caught something on its first run.** With `yanked = "deny"`, the tree
failed on `chacha20 0.10.1`, pulled in through `lopdf` → `rand`. Both 0.10.0 and 0.10.1 are
yanked without a message, and no RustSec advisory names either. It is bumped to 0.10.2, a patch
release in the same semver range. That is a lockfile change, not a new dependency, so ARCHITECTURE
§6 does not ask for its own ADR; it is recorded here.

**Decision.**

1. **`advisories` is a hard gate.** `continue-on-error` is removed. A scheduled run that goes red
   with no commit here is a finding. Fix it, or add an `ignore` entry with a reason and a revisit
   date. Never restore the non-blocking job.
2. **`yanked = "deny"`, `unmaintained = "all"`, `unsound = "all"`, set explicitly.** Defaults have
   moved between releases. `unsound` at its default would ignore a soundness advisory against
   `lopdf`, the crate that parses hostile PDFs.
3. **`multiple-versions = "deny"`.** The tree has no duplicates today, so this costs nothing yet.
   When an upgrade makes one unavoidable, the answer is a `skip` entry with a reason, not a
   return to `warn`.
4. **The licence allow-list names only licences the tree uses.** `ISC`, `BSD-2-Clause` and
   `Apache-2.0 WITH LLVM-exception` matched nothing, and `BSD-2-Clause` was there for a crate
   never adopted. A new dependency already needs an ADR, so its licence gets added at that
   point, deliberately.
5. **`scripts/prove-gates.sh` runs in CI.** It copies the tree, plants one violation per check,
   and requires that check's own diagnostic rather than just a non-zero exit. The cases are: a
   banned networking crate (which must also trip `check-no-network.sh`), a duplicate version, a
   wildcard, a copyleft licence, a git source, a known vulnerability, and a yanked crate.
   **The script was itself shown failing**: with `yanked` and `multiple-versions` set back to
   `warn`, it named both cases and exited 1.

**Consequences.**

- **Exit criterion 2 can now be met, and is met locally.** It will not be met in CI until the
  workflow has run there. Do not record it as met before then.
- **A PR can be blocked by an advisory published overnight.** ADR-0008 accepted this in
  advance: "That is the gate working, not a nuisance to be downgraded to a warning."
- **The proof depends on external state:** RUSTSEC-2021-0003 staying published (it is fixed
  upstream, so it has no reason to be withdrawn), `chacha20 0.10.1` staying yanked, and GitHub
  serving `dtolnay/itoa`. If any of these changes, the proof fails when the gate has not got
  weaker. That false alarm errs toward caution, and the script says which assumption to check
  first.
- **`multiple-versions = "deny"` will cause friction on upgrades.** Duplicate `windows-sys`
  versions are common in Rust trees. The friction is intended: every duplicate is extra code
  running on the user's documents, and a `skip` entry with a reason documents that it was
  looked at.
- **What this does not claim.** `cargo-deny` reads metadata and advisory databases. It does not
  audit code. A passing gate means no *known* problem is declared against the tree, not that the
  tree is safe.

---

## ADR-0046 — No scheduled CI fuzzing job, and OSS-Fuzz is declined for now

**Status:** Accepted (2026-09-11)

Discharges Phase 3 deliverable 2 by declining it. No exit criterion depends on it.

**Context.** Verified 2026-09-11: GitHub-hosted jobs stop at 6 hours; this repository is private,
so its Linux runners have 2 vCPU and the account has 2,000 free minutes a month. ADR-0044 certifies
on one run of at least 24 hours, which no CI job can produce. A full 24-hour sweep would cost
about 15,800 runner-minutes. A weekly 10-minute-per-target job fits the budget but is under 1% of
that bar.

**Decision.**

1. **No `fuzz-long.yml`.** Local batches stay the continuous-fuzzing method, and
   `scripts/fuzz-tally.py` stays the authority on which handlers are certified.
2. **After any handler change, run `fuzz-tally.py` and re-fuzz every target that lost
   certification.** This replaces the scheduled job.
3. **OSS-Fuzz is declined.** It accepts open-source projects "with a significant user base and/or
   critical to the global IT infrastructure"; a private, pre-release project is neither. Revisit
   after Phase 4. ClusterFuzzLite is declined with it: it needs a Docker build and adds nothing
   cargo-fuzz lacks here.

**Consequences.**

- **Only `pdf` and `detect` are fuzzed on push** (the smoke job). A crash introduced in any other
  handler goes unseen until the next local batch.
- **Making the repository public would change the cost side, not the 6-hour cap:** Actions become
  free on 4-vCPU runners, and an all-targets smoke job becomes affordable. Revisit this ADR then.

---

## ADR-0047 — Windows output keeps its inherited ACL, permanently

**Status:** Accepted (2026-09-11)

Resolves ADR-0019's Windows bullet and discharges Phase 3 deliverable 7 by recording the gap.

**Context.** Verified 2026-09-11:

- Rust's `std::os::windows::fs::OpenOptionsExt` takes no security descriptor. Setting a DACL means
  calling Win32 directly.
- A file created without a descriptor gets its DACL from the parent's inheritable ACEs ([Microsoft
  Learn, "DACL for a New Object"](https://learn.microsoft.com/en-us/windows/win32/secauthz/dacl-for-a-new-object)).
- A same-volume rename keeps the file's ACL. The temporary is beside the destination, so the output
  carries the destination directory's inheritable ACEs, like any file the user saves there.
- Under `C:\Users\<name>` those ACEs are SYSTEM, Administrators and the user. That is the Windows
  counterpart of `0600`, allowing for administrators, just as root can read `0600`.
- The safe wrappers, `windows-acl` 0.3.0 and `windows-permissions` 0.2.4, were both last released
  in 2021.

**Decision.** strypt does not narrow the ACL. `Permissions::OwnerOnly` is a no-op on Windows, and
this is permanent unless a later ADR admits `unsafe` for it.

**Consequences.**

- **Narrowing would add the project's first `unsafe`** (ADR-0007), or an unmaintained wrapper around
  the Win32 security API, to protect a case the default profile ACL already covers.
- **The exposure is output written outside the profile**, such as `C:\Users\Public`, a shared folder,
  or a directory whose ACL grants Users or Everyone. There the output can be read by whoever can
  read that directory.
- **FAT and exFAT have no ACLs at all**, so no narrowing would help on a USB stick. That matches the
  Unix finding in deliverable 6.
- **Carried into the known-limitations page (deliverable 5)** in one line: on Windows the output has
  the permissions of the folder it is written to.

---

## ADR-0048 — Parser sandboxing is deferred

**Status:** Accepted (2026-09-11)

Discharges Phase 3 deliverable 8 and meets exit criterion 4. Answers ARCHITECTURE §5.3.

**Context.** The three inputs deliverable 8 requires:

1. **mat2's experience.** mat2 0.14.0 (2025-10-23) removed bubblewrap because it "was a significant
   source of issues over the years, was annoying to test in the continuous integration suite, didn't
   provide significant security improvement besides mitigating possible command injections in
   exiftool, and was best-effort anyway" ([release notes](https://dustri.org/b/mat2-0140.html)).
   strypt spawns no subprocess, so the one gain mat2 names does not exist here.
2. **What it buys a `forbid(unsafe_code)` parser.** Measured 2026-09-11 against the lockfile:
   - `lopdf`, the largest hostile-input parser in the tree, has **no `unsafe`**.
   - The `unsafe` that remains sits in foundational crates such as `hashbrown`, `memchr`,
     `encoding_rs` and `aes`.
   - Resource exhaustion already fails closed: an OOM or a hang writes nothing and reports nothing.
   - The real gain is **containing a compromised dependency**. The no-network gate matches crate
     names, so it cannot see a dependency calling `std::net` directly. A sandbox can.
   - But a compromised parser's most dangerous act is **returning uncleaned or watermarked output**,
     and a sandbox has to pass the output through.
3. **Cross-platform cost.** Verified 2026-09-11:
   - **Linux** has safe crates. The `landlock` crate (0.4.5) restricts filesystem access, but its
     network rules need kernel 6.7 or later (Tails 7 ships 6.12) and cover **TCP only**. Blocking UDP
     needs seccomp as well.
   - **macOS** has only the deprecated `sandbox_init`/`sandbox-exec`, which needs FFI.
   - **Windows** AppContainer needs FFI.
   - Both FFI routes mean `unsafe`, which ADR-0047 has just declined for a smaller gain.

**Decision.** No sandbox. strypt stays a single process with no privilege separation.

**Consequences.**

- **A compromised dependency runs with the user's full access** (THREAT_MODEL §5.2). Mitigations
  remain dependency minimisation, the lockfile, `cargo-deny` and the no-network gate.
- **The no-network gate's `std::net` blind spot is recorded here** and goes into THREAT_MODEL with
  deliverable 9.
- **Revisit when any of these happens:**
  - a RustSec vulnerability or `unsound` advisory against a crate that parses untrusted bytes here;
  - a dependency that spawns processes;
  - Phase 5's GUI, where a UI/worker split is natural.
- **If adopted, start with** Landlock plus seccomp on Linux, applied in-process once the input and
  the temporary file are open. Treat it as defence for one platform and do not describe it as
  cross-platform.

---

## ADR-0049 — Phase 4 opens, and the repository goes public on its existing history

**Status:** Accepted (2026-09-12)

Settles `docs/ROADMAP.md` Phase 4's three opening-ADR inputs. **Amends ADR-0046**'s smoke-job scope.

**Context.** Phase 3 closed 2026-09-12. Release downloads, a Homebrew tap and private vulnerability
reporting (PVR) all need a public repository, so its prerequisites come first. Every commit and every
blob, binaries included, was audited on 2026-09-12:

- **Commit metadata** carries the owner's personal address and a fixed UTC offset. The owner accepts
  both as public.
- **The local account name** appears once in `real-producer-corpus/real-corpus/MANIFEST.csv`.
  `build_real_corpus.py` copies `identify`'s raw output, and that output quotes an absolute path. The
  name also appears in a since-deleted `.codex/hooks.json`.
- **Origin** holds only `refs/heads/main`, with no pull-request refs, so going public exposes nothing
  beyond `main`.

Verified 2026-09-12:

- Changing visibility leaves commits, branches and tags unchanged.
- Private forks are detached and stay private.
- PVR is available on public repositories only.
- Standard runners are free and unlimited on public repositories, with 4 vCPU on Linux x64 and arm64.
  The 6-hour job cap and the Free plan's 20 concurrent jobs still apply.
- homebrew-core requires a stable tagged release, and a notability bar that is higher for
  self-submitted software ([Homebrew/brew#21923](https://github.com/Homebrew/brew/pull/21923),
  merged 2026-04-05).

**Decision.**

1. **Phase 4 is open**, and its deliverables and exit criteria stand as written. As under ADR-0043,
   "a phase is open" is not "scope is open": no formats are added.
2. **History is not rewritten** (input 1). The existing repository's visibility is flipped.
   - `build_real_corpus.py` writes paths relative to the corpus root, and `MANIFEST.csv` is
     regenerated.
   - The account name stays in history, by the owner's decision.
   - No CI gate checks for local paths. Review is the defence.
3. **`SECURITY.md`** (input 2):
   - PVR is enabled at the flip and becomes the preferred channel. Email stays as the fallback for
     reporters without a GitHub account.
   - Before the flip, the owner sends the address a test report from an unrelated account and confirms
     it arrived and did not land in spam.
   - The "not available" limit is rewritten in the flip commit.
4. **ADR-0046** (input 3):
   - After the flip, the fuzz smoke job covers all 22 targets, as a 60-second matrix.
   - ADR-0046 is otherwise unchanged. No job can run ADR-0044's 24 hours, so certification stays local.
   - OSS-Fuzz stays declined until Phase 4 closes, because being public does not meet its criteria.
5. **Deliverable order:**
   1. manifest path fix and email drill (2, 3);
   2. README banner and `strypt show` demo, before the flip so first visitors see them. The demo is a
      static image rendered by a script from the real binary on synthetic fixtures, so it can be
      regenerated when the output changes. Both images have a neutral prompt and are stripped by
      strypt before commit;
   3. flip to public, with PVR and the wider smoke job (3, 4);
   4. reproducible builds with provenance, in their own ADR, before any binary ships — traceability
      cannot be retrofitted onto a release;
   5. signing, in its own ADR, alongside 4, because its outcome shapes the README's verification steps;
   6. GitHub Releases for the five targets, with SHA256 checksums;
   7. Homebrew, as a project tap, since homebrew-core's notability bar excludes a new repository;
   8. `.deb`, opening with ROADMAP's own question of whether it reaches Tails and Qubes-Whonix users
      (ADR-0043's `.deb` caveat binds);
   9. README and `INSTRUCTIONS.md` finalised with install paths and checksum verification;
   10. clean-machine install tests (exit criterion 4), last, because they test 9.

**Consequences.**

- **Anyone who reads the history sees the commit address, the UTC offset and the account name.**
  These were accepted on 2026-09-12. Once the repository is public, a later rewrite cannot unpublish
  them.
- **Nothing mechanical stops the next absolute path.** The manifest fix removes one source, but any
  tool that quotes a path into a committed file can repeat it.
- **Commit IDs are unchanged**, so the SHAs cited in the docs and in `target/fuzz-runs/` stay valid.

---

## ADR-0050 — Release binaries are built reproducibly, by one script, never on a personal machine

**Status:** Accepted (2026-09-13)

Discharges ADR-0049 decision 5 item 4 and ROADMAP Phase 4's reproducible-builds deliverable.

**Context.** Measured 2026-09-13 on macOS arm64 with the pinned 1.97.1:

- **A release build embeds its build machine's paths.** `target/release/strypt` holds 82 absolute
  paths naming the local account. They come from panic locations in `~/.cargo/registry` and
  `~/.rustup`, and `strip = true` does not remove them.
- **Three settings make the bytes independent of the machine:**
  - `--remap-path-prefix` for `CARGO_HOME`;
  - `--remap-path-prefix` for std's source. With rust-src installed, std's paths resolve into the
    toolchain, so they are mapped to the `/rustc/<commit>` that a machine without rust-src embeds;
  - `-Wl,-oso_prefix,<checkout>/`, because Apple's `ld` hashes object-file paths into `LC_UUID`.
    `man ld` documents this as helping "build servers generate identical binaries".
- **Measured with those settings.** `scripts/build-release.sh` produced identical `aarch64-apple-darwin`
  binaries from two checkouts that also differed in `CARGO_HOME` and `RUSTUP_HOME`, one toolchain
  with rust-src and one without. It also produced identical `x86_64-apple-darwin` binaries,
  cross-built from arm64. Dropping the `CARGO_HOME` remap leaked 61 registry paths and broke the
  match. Cargo already passes workspace paths as relative ones. Linux and Windows are unmeasured,
  since no Docker or Windows host is available here.

Verified 2026-09-13:

- Cargo's `trim-paths` is still unstable ([cargo#12137](https://github.com/rust-lang/cargo/issues/12137)),
  so rustc's `--remap-path-prefix` is the stable route.
- ~~rustc passes `/Brepro` to the MSVC linker when `SOURCE_DATE_EPOCH` is set.~~ **Wrong,
  corrected 2026-09-13:** only rustc's bootstrap passes it, and the first gate run failed on the PE
  timestamp. The script passes `/Brepro` itself.
- `actions/attest` v4 writes a Sigstore-signed SLSA v1 provenance attestation, free on public
  repositories; `gh attestation verify` checks it. `attest-build-provenance` is now a wrapper around it.
- GitHub has announced the end of x86_64 macOS runners in August 2027. `ubuntu-24.04-arm` is free on
  public repositories.
- Tails 7 is based on Debian 13.
- `dist` (formerly cargo-dist) is maintained, at 0.32.0 (2026-05-21).

**Decision.**

1. **Byte-reproducible, not only traceable.** Every release artefact is built by
   `scripts/build-release.sh <target>`, which both CI and anyone verifying run. It sets:
   - `--locked`, with the toolchain from `rust-toolchain.toml`;
   - `SOURCE_DATE_EPOCH` to the commit time;
   - path remaps: `CARGO_HOME` to `/cargo`, std's source to `/rustc/<commit>`, and the checkout to
     `/strypt` for any build-script output;
   - on macOS, `-oso_prefix` for the checkout; on Windows, `/Brepro`.
2. **Five targets.**
   - `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`: static, so they run on Tails and
     older Debian whatever their glibc, each built on its native runner.
   - `aarch64-apple-darwin`, plus `x86_64-apple-darwin` cross-built on the same arm64 runner, so
     losing Intel runners changes nothing.
   - `x86_64-pc-windows-msvc`.

   musl's allocator is slow under thread contention, and strypt runs on one thread. Take
   `measure-performance.sh` on the musl build before the first release; mimalloc is declined because
   it would add a C dependency.
3. **A reproducibility gate.** The release job builds each target twice and publishes nothing if any
   pair differs. The second build uses another checkout, with its own `CARGO_HOME` and `RUSTUP_HOME`.
   Running the workflow with `prove` drops the `CARGO_HOME` remap, and the gate must then fail. It
   proves the build does not depend on paths, home directories or build time on one runner image. It
   says nothing across operating-system images or linker versions, and is described no more broadly.
4. **Provenance for every artefact.** `actions/attest` signs each binary and `SHA256SUMS`. That
   meets exit criterion 2 even for a target that stops being byte-reproducible. Actions on the
   release path are pinned by commit SHA.
5. **No release binary is built on a personal machine.** The 82 paths are why. Local
   `cargo build --release` is unchanged.
6. **`dist` is declined.** Its value is generated workflows and installer scripts. strypt needs
   neither, and every action it adds is supply-chain surface on the release path.

**Consequences.**

- **A toolchain bump changes every hash.** It is recorded in `CHANGELOG.md`, and a verifier must
  use the release's own `rust-toolchain.toml`.
- **Signing will change the bytes.** An embedded Authenticode or Developer ID signature alters the
  binary, so ADR-0051 must say what a verifier compares.
- **The gate first ran green on 2026-09-13**, at `b710b8d`: all five targets
  ([run 34719784195](https://github.com/FadeHack/strypt/actions/runs/34719784195)). The prove run
  ([34719785986](https://github.com/FadeHack/strypt/actions/runs/34719785986)) found the planted path
  in all five. The four non-Windows hashes matched a run of the previous commit on other runners.
  Windows needed `/Brepro` first.
- **A verifier needs the release's toolchain, not only its commit.** A local build on macOS 26 with ld-1230
  differed from CI's ld-1167 build: every section had the same size, but the data was laid out in a
  different order. Each release must name its runner image and linker version.
- **musl measured no slower than glibc** (2026-09-13,
  [perf run 34720383086](https://github.com/FadeHack/strypt/actions/runs/34720383086)). On both
  Linux runners, alternating with a glibc build of the same commit, musl matched or beat it in every
  case. A 3.3 MB JPEG was stripped in 8.7–9.8 ms against 9.6–10.9 ms. A 1,000-file batch peaked at
  1.1–1.3 MB RSS against 2.5–3.0 MB. mimalloc stays declined.

---

## ADR-0051 — No Apple Developer ID; Windows signing through SignPath after the first release

**Status:** Accepted (2026-09-13)

Discharges ADR-0049 decision 5 item 5, ROADMAP Phase 4's signing deliverable, and its "signing
identity versus maintainer privacy" risk.

**Context.** Verified 2026-09-13:

- **Apple.** The Developer Program costs $99 a year, and enrolment needs your legal name. A Developer
  ID certificate is named `Developer ID Application: <name> (<Team ID>)`, and `codesign` reads that
  name from every binary signed with it.
- **Gatekeeper checks quarantined files only.** `curl` does not quarantine a download, and Homebrew
  formula installs are not affected. A browser download is quarantined. Since macOS 15, the
  Control-click override is gone, and the user must approve the file in System Settings → Privacy &
  Security.
- **Azure Artifact Signing** costs $9.99 a month. Individual public-trust identities are limited to
  the US and Canada.
- **SignPath Foundation** signs free for OSI-licensed projects with no proprietary parts. The
  certificate is issued to SignPath Foundation, which is named as the publisher. The project must
  already be released in the form to be signed, built verifiably from source.

**Decision.**

1. **No Apple Developer ID.** A legal name in every binary conflicts with a pseudonymous
   maintainer, and the fee recurs. macOS binaries carry only the linker's ad-hoc signature, which
   Apple Silicon requires and which ADR-0050 reproduces byte for byte. The finalised README (ADR-0049
   item 9) recommends Homebrew or `curl`, and describes the System Settings step for a browser
   download. It must not tell anyone to turn Gatekeeper off.
2. **Windows ships unsigned in the first release, then SignPath is applied for.** If SignPath
   accepts, an amendment here settles what a verifier compares, because an embedded Authenticode
   signature changes the bytes ADR-0050 reproduces. Azure is declined because of its identity
   requirement and its region limit.
3. **Verification rests on provenance and checksums on every platform** (ADR-0050 decision 4). The
   README makes `gh attestation verify` and `SHA256SUMS` prominent, which is ROADMAP's mitigation for
   an unsigned download.

**Consequences.**

- **Windows SmartScreen may warn about the unsigned binary**, at least until SignPath signs it.
- **A macOS browser download needs one extra approval step.** The README must explain it without
  weakening the user's defaults.
- **Revisitable.** A Developer ID can be added later without affecting earlier releases, if the
  maintainer's situation changes.

---

## ADR-0052 — No `.deb`: the static binary is the Tails and Whonix path, and Debian waits for Phase 7

**Status:** Accepted (2026-09-13)

Discharges ADR-0049 decision 5 item 8. **Revises** `docs/ROADMAP.md` Phase 4's native-package
deliverable and `docs/PRD.md` §10's distribution metric.

**Context.** ROADMAP chose `.deb` because Tails and Qubes-Whonix are Debian-based, and asked
whether that transfers to their real install paths. Verified 2026-09-13:

- **Tails** keeps software across reboots only through Additional Software. Its docs cover packages
  installed with APT from Debian's repositories, after setting an admin password at the Welcome
  Screen. They describe no way to keep a downloaded `.deb`, and warn that extra APT repositories
  "might break the security built into Tails".
- **Tails ships mat2 and Metadata Cleaner** by default.
- **Whonix** prefers a third-party APT repository, then Flatpak, then a verified standalone binary
  in the home folder. In Qubes-Whonix, APT in an app qube lasts one session. Persistent packages go
  in the template.
- A `.deb` without an APT repository gets no updates. A repository needs a signing key to hold and
  rotate.

**Decision.**

1. **No `.deb` is built.** A downloaded `.deb` reaches neither system: Tails does not keep it, and
   Whonix ranks it below a binary. It would wrap the same musl binary that ADR-0050 already ships.
2. **The static musl binary is the documented path** for both. It needs no root and no package
   manager, and on Qubes-Whonix it persists in the app qube's home without touching the template.
   The README (item 9) says mat2 ships with Tails, as ADR-0012 requires.
3. **No APT repository.** A signing key is a long-lived secret and hosting is a permanent
   obligation, for Whonix's top-ranked route alone.
4. **Debian proper moves to Phase 7**, beside the Tails and Qubes-Whonix outreach. Inclusion is
   the only route by which Tails's Additional Software would keep strypt. The PRD's "packaged in a
   mainstream distribution" metric moves with it.

**Consequences.**

- **Phase 4's exit criteria are unchanged.** Criterion 1 never needed a `.deb`.
- **Unverified: running the binary from Tails 7's Persistent Storage.** The only evidence is
  Electrum's Tails 4 guide. If Persistent Storage is `noexec`, the README's Tails steps change.
  ADR-0043 binds: nothing here has been run on Tails.
- **Debian and Ubuntu desktop users get no `/usr/bin` install or clean uninstall.** They use the
  binary, Homebrew on Linux, or `cargo install`.
- **Revisitable** if strypt enters Debian, or a target community asks for a `.deb`.

---

## ADR-0053 — Install steps tested on fresh runners, and Phase 4 closes

**Status:** Accepted (2026-09-14)

Discharges ADR-0049 decision 5 item 10 and ROADMAP Phase 4 exit criterion 4, and settles ADR-0052's
open question on Tails's Persistent Storage.

**Context.** No clean machine is available. `install.yml`, a manual workflow, reads README's install
steps from README at the commit under test and runs them:

| Path | Where | Image |
|---|---|---|
| Homebrew | macOS 15 arm64 and Intel; `debian:13` on Linux x86_64 and aarch64 | macos-15-arm64 20260907.0337.1; macos-15 20260824.0482.1; ubuntu24 20260907.300.1; ubuntu24-arm64 20260907.118.1 |
| `curl`, `sha256sum`, `gh attestation verify` | the same four | as above |
| `Get-FileHash`, `gh attestation verify` | Windows Server 2025, Windows PowerShell 5.1 | win25-vs2026 20260907.229.1 |
| `cargo install strypt` | `debian:13` on Linux x86_64 | as above |

The Linux containers start with nothing but Debian. Only the documented prerequisites are installed:
`curl`, Homebrew's own list, `gh` from cli.github.com, and Rust from rustup.rs. The macOS and
Windows images are fresh virtual machines but not clean: Homebrew, `gh` and other taps come preinstalled, and the Intel image's
hashicorp tap printed an import error during `brew install`. Nothing was downloaded in a browser, so
Gatekeeper and SmartScreen are untested.

**Findings.** [Run 34779376160](https://github.com/FadeHack/strypt/actions/runs/34779376160) ran
README as of `a1029ec`, and three steps failed as written:

- `shasum` is not in `debian:13`, since it ships with the full `perl` package. `sha256sum` is present
  on every Linux and on macOS 15 and later, and handles `--ignore-missing`.
- `gh attestation verify` exits 4 until `gh` is signed in, on every platform
  ([cli/cli#11803](https://github.com/cli/cli/issues/11803), open). Debian 13's own `gh` is 2.46,
  and the command arrived in 2.49.
- On Windows, `Get-FileHash` prints the hash in capitals and `SHA256SUMS` in lower case.

[Run 34781311172](https://github.com/FadeHack/strypt/actions/runs/34781311172), which added cargo,
found a fourth: Debian 13's `cargo` is 1.85.1, and refuses strypt's `rust-version` of 1.95. Through
rustup, `cargo install strypt` built and ran.

Two passed but proved less than they appeared to. A fresh Linux Homebrew install was 7.0.1, while
README said "Homebrew 6". Signed in, `gh attestation verify` printed nothing without a terminal, so
the workflow prints the commit it verified. `52fab40` and this ADR's commit fixed README. Run
34781311172 ran `1be9f5d` and passed every job; the later rewording changes no command. Each
binary's attestation named `c2f4403`, v0.1.0's commit.

**Tails 7.12.** Its ISO, checked against tails.net's SHA256, was unpacked and read. `tps/device.py`
mounts the Persistent Storage partition with `mount -o acl`. `tps/configuration/binding.py`
binds the Persistent folder, then remounts it `nosymfollow` and `x-gvfs-hide`, a file-manager hint.
No `noexec` appears in `tps`, `/etc`, any systemd unit, `/usr/local` or live-boot. The workflow
mounts an ext4 image the same way (`rw,relatime,nosymfollow`), and the x86_64 binary ran and
stripped a file from it.

**Decision.**

1. **Fresh GitHub runners stand in for clean machines**, with Linux in `debian:13`. This ADR says so,
   and README and KNOWN_LIMITATIONS do not say "clean machine".
2. **README is corrected as above.** Linux and macOS use `sha256sum`, and `shasum` stays as a
   fallback for older macOS. The attestation step names `gh auth login` and `gh` 2.49, and the
   cargo line names Rust 1.95.
3. **Tails's Persistent Storage allows running the binary**, as far as code and a reproduction on
   Linux can show. ADR-0043 binds: it has not been run on Tails.
4. **`install.yml` is re-run for each release** (`INSTRUCTIONS.md`). It is not a gate.
5. **Phase 4 closes.** Its exit criteria:
   1. Met. Homebrew and the release download need no Rust. They are two channels for one artefact, so
      a bad release breaks both.
   2. Met. Every binary is attested to its commit, and byte-reproducible on its runner image
      (ADR-0050).
   3. Met. `SHA256SUMS` covers all five binaries, and is itself attested. Whether a non-expert can
      follow the steps is untested.
   4. Met on fresh runners, within decision 1's limits.

**Consequences.**

- **Browser downloads, Gatekeeper and SmartScreen are untested**, as is anyone's own machine.
- **Verifying provenance needs a GitHub account** until cli/cli#11803 lands. Checksums need none.
- **ADR-0049 decision 4's OSS-Fuzz deferral ends with the phase.** It is not decided here.
- **SignPath (ADR-0051 decision 2) is still owed**, and does not hold the phase open.

---

## ADR-0054 — A CycloneDX SBOM per release binary, from `cargo-cyclonedx`

**Status:** Accepted (2026-09-14)

Settles ARCHITECTURE §6's "pick one in Phase 4". Not a Phase 4 exit criterion, so ADR-0053 stands.

**Context.** Verified 2026-09-14: `cargo-cyclonedx` 0.5.9 (2026-03-19) honours `SOURCE_DATE_EPOCH`,
dropping the clock time and the random serial number. `cargo-sbom` 0.10.0 (2025-06-17) writes the
current time. `actions/attest` v4 takes an `sbom-path`.

Measured the same day with 0.5.9: an SBOM names each workspace crate by its checkout's absolute path,
percent-encoded, so two checkouts differ. With those paths mapped to `/strypt`, two checkouts at
different paths wrote identical bytes. One macOS host wrote every target's SBOM, since it reads
`Cargo.lock` through `cargo metadata` and builds nothing. The Windows SBOM lists 71 components against
68 elsewhere, the three extra being `windows-sys` and its kin.

**Decision.**

1. **`cargo-cyclonedx`, CycloneDX 1.5 JSON, one SBOM per target**, named `<binary>.cdx.json`.
   Build dependencies are left out. Proc-macro crates stay in: they run at build time and are not in
   the binary, and a scanner may flag them anyway.
2. **`scripts/sbom.sh` writes them**, in `release.yml`'s release job, with `cargo-cyclonedx` pinned
   by version and `--locked`. It maps checkout paths to `/strypt` and fails if any other local path
   remains. Deleting the mapping was shown to fail it.
3. **Provenance through `SHA256SUMS`**, which lists the SBOMs and is already attested. No
   `sbom-path` attestation: it would add a signing step per binary and prove nothing the checksum
   does not.
4. **First shipped with the next release.** 0.1.0 is not retrofitted.

**Consequences.**

- **The SBOM is `Cargo.lock` restated**, per target and in a standard format. It adds nothing a
  verifier with the commit could not derive, and is described no more broadly.
- **It is not compared across two runs** as the binaries are. Determinism rests on
  `SOURCE_DATE_EPOCH` and the path check.
- **First run green on 2026-09-14**, at `3b55416`
  ([run 34818678470](https://github.com/FadeHack/strypt/actions/runs/34818678470)). All five SBOMs
  were byte-identical to ones written on macOS arm64 from the same commit, checked by hand once.

---

## ADR-0055 — SignPath declines, and four Phase 7 deliverables come before Phase 5

**Status:** Accepted (2026-09-18)

Settles ADR-0051 decision 2. Opens no phase.

**Context.** SignPath Foundation declined strypt by email on 2026-09-16: the
project is too new to have community attention, and could be reconsidered once it has. Every other
route to a trusted signature needs the maintainer's legal name (ADR-0051).

Checked 2026-09-18: Windows 11's Smart App Control, where enabled, blocks an unsigned app without
reputation outright, not with SmartScreen's click-through. A command at the top level of the
Windows 11 Explorer menu must come from a package signed by a CA-trusted certificate; unsigned
registry verbs appear only under "Show more options". A macOS browser download that is not
notarised needs approval in System Settings.

So Phase 5's GUI and Phase 6's Explorer integration can be built unsigned, but exit criterion 3 of
Phase 5, usable by someone who has never opened a terminal, is at risk on Windows and macOS. Linux,
including Tails and Whonix, is unaffected. There is no evidence yet of anyone using strypt outside
the project, which Phase 5's criterion 3 and all of Phase 7 need.

**Decision.**

1. **Windows stays unsigned.** SignPath is applied to again once there is traction to show.
   ADR-0051 decision 1 is unchanged.
2. **Four Phase 7 deliverables are done now:** the contribution pipeline (templates, response
   norms, curated good-first issues), a security-triage process exercised by a drill, one public
   announcement framed per ADR-0012, and applications for an independent audit or funding.
3. **Phase 7 is not opened.** Outreach to Tails and Qubes-Whonix waits for outside users and
   ideally an audit, since mat2 already ships in Tails and a first impression cannot be retaken.
   Debian packaging and the localisation ADR wait with it.
4. **Phase 5 does not wait for traction**, which has no end condition. Its opening ADR must say how
   Windows and macOS are distributed unsigned, or scope them out.

**Consequences.**

- **Choosing between signing and pseudonymity is the maintainer's to make**, and would unblock
  Windows and macOS sooner than traction.
- **Phase 7's exit criteria are not met by this work** except where it happens to meet them; the
  phase is judged when it opens.

---

## ADR-0056 — A PDF's JPEGs go through the JPEG handler

**Status:** Accepted (2026-09-18)

Extends ADR-0029's one-level, images-only descent from ZIP packages to PDF. It does not descend
*into* a PDF, which ADR-0029 still refuses.

**Context.** Found 2026-09-18, from a question on a public announcement: 0.1.0 reported a PDF clean
while the photo on its page kept its GPS, body serial and artist. A `DCTDecode` stream is a JPEG file
byte for byte (ISO 32000-1 §7.4.8), and producers such as pdfLaTeX embed a camera's JPEG unchanged;
`real-producer-corpus/…/003-pdflatex-image.pdf` carries a camera make, model and capture date that
way. The handler read only dictionaries, and ADR-0029 covered only ZIP packages.

Every check missed it. ExifTool reads a PDF's embedded images only with `-ee`, and no differential
passed it. mat2 re-renders a PDF's pages, so its output had nothing to compare against.

**Decision.**

1. **A stream whose only filter is `DCTDecode` and whose bytes sniff as JPEG goes through
   `package::strip_embedded_image`**, the handler a loose JPEG uses. Keyed on the filter, not on
   `/Subtype /Image`, so page thumbnails (§12.3.4) are covered.
2. **Nothing is inflated.** JPEG 2000, and filter chains ending in a JPEG, are copied with a note.
   Refusing would refuse every such PDF; a note is how OOXML treats a part it cannot read.
3. **A JPEG the handler refuses refuses the PDF.**
4. **Inline images are not reached**, because content streams are not parsed. Recorded in
   KNOWN_LIMITATIONS.
5. **The PDF differential runs ExifTool with `-ee`** (`INSTRUCTIONS.md`).

**Consequences.**

- **A security fix for 0.1.0**, disclosed under `Security` in CHANGELOG.
- **Rendering is unchanged as far as Poppler shows:** `pdftoppm` renders all 124 pages of three
  affected PDFs with no differing pixel, one of them losing its JPEGs' ICC profiles. The image
  dictionary, not the JPEG, sets a PDF image's colour space and placement.
- **Fuzzing:** a five-minute `pdf` run was clean, with the new fixtures as seeds. ADR-0044's 24-hour
  run is owed again before `pdf` is described as certified.
- **Found on the way:** 0.1.0 refuses `003-pdflatex-image.pdf` as not round-trippable, although the
  Phase 1 sweep (THREAT_MODEL §7.5) processed it. A refusal leaks nothing; it is a capability gap
  introduced after that sweep, not fixed here.

---

## ADR-0057 — Renumbering that would shrink a PDF refuses it

**Status:** Accepted (2026-09-20)

**Context.** The `pdf` fuzz target's idempotence assertion fired at 64213s of a 24-hour run on
2026-09-20. `lopdf::renumber_objects` permutes page objects so that page order matches ascending
ids before numbering them sequentially (0.44.0 `src/processor.rs`). A page tree that names the same
object more than once — `/Kids [2 0 R 2 0 R 2 0 R]`, with object 2 itself a `/Page` — maps two old
ids onto one new one, and the object that loses is gone from the document.

0.1.1 wrote such a file, without its only real page, and reported success. `verify_round_trip` did
not see it: the loss happens before serialising, so the written and reloaded documents agree. The
visible symptom was the second strip dropping the orphan the first had left.

**Decision.** `renumber_stably` compares the object count across each round and refuses the document
as `NotRoundTrippable` if it fell. Counting is enough — renumbering is a bijection or it is a bug —
and it costs one comparison per round.

**Consequences.**

- **A file already stripped by 0.1.1 or earlier may be missing a page.** Nothing leaked, so this is
  not a metadata disclosure; a user whose only copy is the stripped one has lost content. Under
  `Fixed` in CHANGELOG, not `Security`.
- **Documents of this shape are refused, not repaired.** Consistent with ADR-0018, and a viewer
  cannot resolve a page tree that lists one page three times either.
- **Fuzzing:** ADR-0044's 24-hour run is owed again for `pdf`; the run that found this ended at
  17.8 of its 24 hours.
- `malformed/duplicate-kids.pdf` carries the case, in the corpus and in the `pdf` fuzz seeds.

---
