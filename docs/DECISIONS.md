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
