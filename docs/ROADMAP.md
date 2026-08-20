# strypt — Roadmap

**Status:** Phase 1 in progress · **Last updated:** 2026-08-21

Every phase below states **Goal**, **Deliverables**, **Exit criteria**, and **Risks**. A
phase is done when its exit criteria are met — not when its deliverables have been attempted.

**Standing rule for every phase:** all tool, crate, and framework references in this document
are snapshots taken on 2026-08-19. **Re-verify them at the start of the phase, not at the
start of the project.** Phase 3 and later may be executed months from now, and a version
number cited here should be treated as a starting point for a search, never as current fact.

**No dates.** This is a correctness-driven project without a delivery commitment. Phases are
ordered by dependency, and a phase that needs longer gets longer.

---

## Phase 0 — Foundation *(complete)*

**Goal.** Someone cloning this repository — human or AI — can determine what strypt is, why
it exists, how it is built, what phase it is in, and what to do next, without asking anyone.

**Deliverables.**
- The four core documents: `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`,
  `CLAUDE.md`. ✅
- Supporting docs: `docs/THREAT_MODEL.md`, `docs/DECISIONS.md`, `docs/TESTING_STRATEGY.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `README.md`,
  `INSTRUCTIONS.md`. ✅
- Dual licence files, canonical text. ✅
- `.claude/` tooling: `settings.json` with enforcement hooks, `commands/` and `skills/`
  stubs. ✅
- Owner sign-off on the `docs/PRD.md` §0 premise correction, with positioning fixed as
  "additional option, never a replacement" (ADR-0012). ✅ **Signed off 2026-08-19.**
- MSRV policy adopted as house policy (ADR-0013). ✅
- crates.io name availability confirmed: `strypt`, `strypt-cli`, and `strypt-core` are all
  unregistered as of 2026-08-19. ✅
- Cargo workspace: `Cargo.toml`, `crates/strypt-core`, `crates/strypt-cli`, shared lint
  configuration, panic-freedom lints scoped to the core crate. ✅
- `rust-toolchain.toml` pinning 1.97.1, honoured by CI. ✅
- CI skeleton: `ci.yml` (build/test on three platforms, fmt, clippy, MSRV), `no-network.yml`
  (hard gate), `deny.yml` (advisory until Phase 3). ✅
- `scripts/check-no-network.sh` — the authoritative ADR-0004 gate, walking the fully
  resolved graph across all features. ✅
- `deny.toml` and a `.githooks/pre-commit` gate for non-Claude edits. ✅
- CI verified green on real pushes to `github.com/FadeHack/strypt` (2026-08-19): build and
  test on Linux, macOS, and Windows; fmt; clippy; MSRV; no-network; cargo-deny. ✅

**Exit criteria.**
1. ✅ **Met 2026-08-19.** `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, and
   `cargo fmt --check` all pass on the scaffolded workspace.
2. ✅ **Met 2026-08-19.** CI runs those four gates plus `cargo-deny` and the no-network
   check on every push, on Linux, macOS, and Windows — all green on a real push.
3. The no-network gate is **proven to work** by a deliberate test. ✅ **Locally verified
   2026-08-19:** adding `ureq` to `strypt-core` made the gate exit 1, flagging `ureq`, its
   declaration, *and* `rustls` pulled in transitively — the transitive case being precisely
   what the Claude Code hooks structurally cannot see. Change reverted; gate re-verified
   clean. Confirmed running green in GitHub Actions 2026-08-19.
4. ✅ **Met 2026-08-19.** `INSTRUCTIONS.md` contains real, copy-pasteable commands that
   actually run. The last of them — the fuzz, `cargo-deny`, and CLI commands — could only be
   verified once Phase 1 produced something to run them against, and now have been.
5. ✅ **Met 2026-08-19.** The owner reviewed `docs/PRD.md` §0 and confirmed the project
   proceeds on the corrected footing recorded in ADR-0012.
6. ✅ **Met 2026-08-19.** `rust-toolchain.toml` pins an explicit version and CI demonstrably
   uses it. Confirmed against real CI logs, including the MSRV job — which was silently
   building with the pinned toolchain instead of the MSRV until ADR-0015 fixed it, and now
   logs `rustc 1.95.0` as proof.

**Risks.**
- *Documentation drifting from reality the moment code appears.* Mitigation: `INSTRUCTIONS.md`
  is the single source of truth for commands, and updating it is in the definition of done.
- *The premise correction changes the project's rationale.* This is exactly why exit
  criterion 5 exists — better resolved now than after Phase 1's effort is spent.

---

## Phase 1 — Core engine + CLI (JPEG, PNG, WebP, PDF) *(in progress)*

**Goal.** A person can strip metadata from the four highest-risk formats with a tool that is
correct, honest about what it did, and demonstrably does not crash on hostile input.

**Scope is locked** to JPEG, PNG, WebP, PDF by ADR-0005. Expanding it requires a superseding
ADR, not a judgement call mid-phase.

**Progress so far (2026-08-19).** All four handlers are done to the per-format bar. Landed:
bounded ingest, content-sniffing detection, the handler registry and trait, the verification
pass, structured reports, typed errors, the atomic write path, the full CLI, the PDF handler,
the JPEG handler with its shared Exif and XMP readers, the PNG handler reusing both, the WebP
handler reusing both again, fuzz targets for PDF, JPEG, PNG, WebP, and detection, and a
generated fixture corpus for all four formats. Differential testing against ExifTool 13.55 and
mat2 0.15.0 over that corpus shows nothing surviving in strypt's output, with two recorded and
deliberate gaps: strypt keeps the JPEG `APP14` Adobe colour-transform marker, which mat2
removes (ADR-0021), and the **mat2 comparison for WebP was not run at all** — mat2's WebP path
needs a GdkPixbuf WebP loader that the verification machine does not have, so mat2 fails on the
original fixtures too and the comparison says nothing (`docs/THREAT_MODEL.md` §7.4). It must be
run before release on a machine with the loader.

Exit criterion 4 is met for JPEG and by a stronger check than it asks for — the entropy-coded
data is byte-identical after stripping, and ImageMagick reports zero differing pixels where
mat2's re-encoding path reports some. PNG needed no new dependency: its compressed text chunks
are removed without being inflated, because everything that decides what goes is outside the
compression (ADR-0022), and its `IDAT` is byte-identical to the input's where mat2's Pillow
path re-encodes (`docs/THREAT_MODEL.md` §7.3). WebP needed no new dependency either, and for a
simpler reason — nothing it puts metadata in is compressed at the container level. Its one
structural decision was `VP8X`, whose flags declare which metadata chunks a file has: strypt
clears the ICC, Exif, and XMP bits and copies the rest of the chunk verbatim, so the file stops
claiming metadata it no longer has (ADR-0023). The cost, recorded rather than glossed: an
extended WebP is not returned byte-identical, though a simple-format one is guaranteed to be.

**Remaining in this phase — none of it is a handler:**

- **Real-producer corpus.** *Substantially addressed 2026-08-20; two gaps remain.* A
  fetch-on-demand corpus of 101 files now exists in `real-producer-corpus/`, assembled by
  `build_real_corpus.py` from three public sample sets: 23 camera and phone JPEGs with real
  maker notes (Canon, Nikon, Sony, Samsung, HMD, Jolla, Apple), 23 PDFs (pdfLaTeX,
  LibreOffice, Google Docs, Acrobat, ImageMagick), 27 PNGs and 28 WebPs. All four handlers
  were run over the set — no panic, no hang, no silent pass-through; results in
  `docs/THREAT_MODEL.md` §7.5.

  **It is deliberately not committed.** Its files carry four real names in Canon MakerNote
  owner fields, two more in PDF author fields, a device serial number, and live GPS
  coordinates for five photographs — which `docs/TESTING_STRATEGY.md` §3 forbids in a corpus
  that is public and permanent, and which this tool of all tools should not republish. The
  build script and manifests are committed instead, and a rebuild reproduces every fixture
  byte-identically, so the sweep is repeatable.

  It did what it was meant to do: it found the 19-byte-xref limitation against a real scanner
  PDF (§7.5), and refreshing the fuzz seeds from the enlarged corpus surfaced a genuine bug —
  a malformed stream length caused strypt to discard a page's contents and report a clean
  copy. Both are now fixed or documented, with regression tests.

  **Still missing:** WebPs written by a browser, and WebPs from a JPEG→WebP conversion
  pipeline that carries an Exif block across — the path where metadata survives a format
  conversion is still untested against real output. Committed fixtures for real producers
  also remain absent, since the fetched files cannot serve that role.
- **Sustained fuzzing (exit criterion 2).** Under way, not met. The first sustained run
  (2026-08-20, `scripts/fuzz-sustained.sh`) delivered **37.79 CPU-hours** — eight hours each on
  JPEG, PNG, WebP and detect, and 5h47m on PDF, which stopped early on a genuine finding. It
  earned its keep: three real PDF defects, all fixed with regression tests — negative zero
  breaking byte-identical idempotence in the object graph and again in the trailer, and an
  integer-overflow panic inside `lopdf` that reached the shipped binary as exit 101.

  **The coverage data now exists, and it says the run was too short.** Only `detect` plateaued,
  and legitimately so: 96 edges found in 3 seconds, then nothing in eight hours at 86k exec/s.
  The four format handlers were all still finding new edges inside the final quarter — PNG
  gained five in its last 1000 seconds, after 7.7 hours. So this run establishes a floor, not
  a number. Superseding ADR-0014 needs at least one handler driven to an actual plateau;
  replacing a provisional 100 with a figure extrapolated from curves that never flattened
  would swap one guess for another.

  PDF additionally owes a re-run, having lost its last 2h13m to the crash.
- **Performance numbers.** ✅ Done. `docs/PRD.md` §9 now carries measurements from
  `scripts/measure-performance.sh`, which refuses to run against a debug binary. One machine
  only — Linux and Windows are unmeasured, and none of it is a commitment.
- **The mat2 differential for WebP**, on a machine with a GdkPixbuf WebP loader.
- **CI green on all three platforms.**

**Deliverables.**
- `strypt-core`: bounded ingest, content-sniffing format detection, handler registry, the
  `MetadataHandler` trait, four handlers, the post-strip verification pass, structured
  report types, typed errors.
- `strypt-cli`: `show` and `strip` subcommands, batch and `--recursive`, `--in-place`
  (opt-in), `--json`, `--force`, documented and stable exit codes.
- Atomic write path (temp file + rename) with the platform differences in
  `docs/ARCHITECTURE.md` §8 actually handled, not assumed.
- A **meaningful** fuzz harness per handler — four targets, each with a real seed corpus of
  valid and deliberately malformed files. A target that only ever sees valid input is
  theatre.
- Test corpus of real-world files: photos from multiple camera and phone makes, PDFs from
  multiple producers (LaTeX, Word, Acrobat, scanners, browser print-to-PDF).
- Differential testing against mat2 and ExifTool over that corpus.
- Measured performance numbers replacing the estimates in `docs/PRD.md` §9.
- ADRs for the decisions this phase forces: PDF full-rewrite versus incremental patching;
  timestamp and permission handling on output; the exact clippy lint set and where the
  no-panic boundary sits.

**Exit criteria.**
1. All four handlers pass unit, integration, and property tests, including idempotence
   (`strip(strip(x)) == strip(x)`, byte-identical) and `inspect(strip(x))` reporting nothing
   removable.
2. **Zero panics, crashes, hangs, or OOMs** across all four fuzz targets after a sustained
   run — no known-failing input set aside as "not worth fixing".
3. Differential testing shows strypt removes at least what mat2 removes for these four
   formats, or every gap is recorded as a documented limitation with a rationale.
4. Image handlers provably do not re-encode pixel data: verified by comparing decoded pixel
   output before and after stripping.
5. `strypt show` on already-stripped output is clean for every file in the corpus.
6. CI green on Linux, macOS, and Windows.
7. `docs/THREAT_MODEL.md` updated with what was actually learned about each format.

**Risks.**
- *PDF is the whole phase's schedule risk.* Incremental updates, object streams, orphaned
  objects, encryption, linearisation. Mitigation: start PDF first, not last; be willing to
  ship a narrower but honest PDF handler with documented limitations rather than a broad one
  that quietly misses orphaned objects.
- *Preserve-payload versus thoroughness.* Some metadata is entangled with encoded data.
  Where they conflict, preserve the payload and document the limitation — do not silently
  re-encode, which would break a core promise to the photojournalist persona.
- *Fuzzing deferred to "when it works".* Mitigation: fuzz targets land with their handlers,
  in the same pull request, not afterwards.
- *Scope creep.* "SVG is basically XML, it's easy." Read ADR-0005.

---

## Phase 2 — Expanded format coverage

**Goal.** Move meaningfully toward mat2's format list without lowering the Phase 1 bar for
any individual format.

**Deliverables.** In priority order, driven by user risk rather than by implementation ease:
1. Office Open XML — `.docx`, `.xlsx`, `.pptx` (ZIP containers; `docProps/core.xml`,
   `app.xml`, custom properties, revision identifiers, comments, tracked changes,
   embedded thumbnails).
2. OpenDocument — `.odt`, `.ods`, `.odp` (`meta.xml`, editing-cycle and duration statistics).
3. Additional images — TIFF, GIF, AVIF, HEIF, JPEG XL, SVG.
4. Audio and video containers — FLAC, MP3/M4A, Opus/Ogg, MP4, WAV.

Each format ships with: handler, fuzz target and seed corpus, integration tests, differential
comparison against mat2/ExifTool, a `docs/THREAT_MODEL.md` update, and a `CHANGELOG.md` entry.

**Exit criteria.**
1. Every format shipped in this phase meets Phase 1's per-format bar in full. No exceptions
   and no "provisional" handlers.
2. Zero open crash/hang findings across all fuzz targets, old and new.
3. The known-limitations page covers every shipped format.
4. Archive/container formats (ZIP-based OOXML) have documented handling of nested files —
   including the decision, recorded as an ADR, on whether strypt recurses into embedded
   files at all. Unbounded recursion into nested archives is a zip-bomb vector and needs an
   explicit depth and expansion limit.

**Risks.**
- *ZIP-container formats reintroduce whole classes of parser risk* — zip bombs, path
  traversal in entry names, nested archives. Treat the ZIP layer as a hostile parser in its
  own right, with its own fuzz target.
- *Pure-Rust gaps.* Some formats may lack a mature safe parser. Accept slower expansion
  rather than pulling in C dependencies — that trade would forfeit the memory-safety
  argument that is strypt's strongest differentiator (`docs/PRD.md` §4).
- *Coverage measured by format count rather than by trustworthiness.* The count is a vanity
  metric; per-format rigour is the product.

---

## Phase 3 — Hardening

**Goal.** strypt is defensible under adversarial scrutiny before it is ever pointed at real
at-risk users' files. Not "it works" but "we can show why you should believe it works."

**Deliverables.**
- **A sustained fuzzing budget, stated as a number.** Recorded as **ADR-0014, status
  Proposed**: a minimum of **100 CPU-hours per format handler** since its last substantive
  change, **plus** a coverage plateau (no new edge coverage in the final 25% of the run) —
  because CPU-hours alone can be burned on a target that stopped exploring long ago. Both
  conditions must hold.

  **This number is provisional and is to be revised with real coverage data once this phase
  actually starts.** It was set before any parser existed, so it is a hypothesis, not a
  commitment — the project is not locked into it, and revising it upward (PDF's object graph
  is far larger than PNG's chunk list) is an expected outcome rather than a planning failure.
  Record actual CPU-hours and coverage curves per handler so the revision is driven by
  measurement, then supersede ADR-0014 with the measured policy. Continuous fuzzing
  infrastructure (a scheduled CI job, or OSS-Fuzz if strypt qualifies at that point —
  investigate) rather than one-off manual runs.
- Every crash, hang, OOM, and assertion failure triaged to zero, each with a regression test.
- `cargo-deny` wired into CI as a **hard merge gate**, not advisory: `advisories`,
  `licenses`, `bans` (including the networking-crate list), `sources`. Verify current
  recommended `deny.toml` configuration at phase start.
- A per-format **known-limitations page**, written *from* the fuzzing and differential-testing
  findings, never speculatively. This document is a safety feature: it is what stops a user
  over-trusting the tool.
- **A decision on parser sandboxing, recorded as an ADR.** Investigate — do not assume.
  Required inputs to that decision: (a) why mat2 removed bubblewrap sandboxing in v0.14.0,
  which is the most relevant prior experience available and costs nothing to look up;
  (b) what sandboxing actually buys for a `forbid(unsafe_code)` Rust parser, honestly
  assessed — realistically resource-exhaustion bounding and supply-chain-compromise
  containment, not memory-safety;  (c) the cross-platform maintenance cost. "Deferred, with
  reasons" is a legitimate outcome.
- **Live-OS validation on real systems:** Tails and Qubes-Whonix, actually booted and tested,
  covering read-only filesystem behaviour, temp-file placement, and constrained writable
  space. Currently an assumption everywhere in these docs; this phase converts it to fact.

**Exit criteria.**
1. Zero open crash/panic/hang findings from fuzzing across every handler.
2. Both CI gates (`cargo-deny`, no-network) passing on a clean run, both proven to fail when
   deliberately violated.
3. Known-limitations page complete for every shipped format and linked from the README.
4. Sandboxing ADR recorded — adopted or deferred, with reasoning either way.
5. `docs/THREAT_MODEL.md` revised to reflect what hardening actually taught us. If nothing
   changed, that is itself suspicious and worth re-examining.
6. Tails and Qubes-Whonix validation complete, with findings documented.

**Risks.**
- *This phase is the one that gets compressed under release pressure, and compressing it
  removes the evidence for strypt's central claim.* It should not be shortened to hit a
  release date. If something must give, cut format coverage from Phase 2 instead — fewer
  formats done properly is a coherent product; more formats done shallowly is the failure
  mode this project was created to avoid.
- *Fuzzing plateaus give false comfort.* Coverage-guided fuzzing finds what the seed corpus
  and target structure let it reach. Rotate seeds, add structure-aware fuzzing via
  `Arbitrary` for the object-graph formats, and treat a plateau as a prompt to improve the
  harness rather than as a passing grade.

---

## Phase 4 — Distribution

**Goal.** A person can install and run strypt without a Rust toolchain, through channels that
do not themselves undermine the trust model.

**Deliverables.**
- `strypt-cli` (and `strypt-core`) published to crates.io. **Name availability confirmed
  2026-08-19: `strypt`, `strypt-cli`, and `strypt-core` were all unregistered.** Names are
  not reservable in advance, so re-check at publish time and consider publishing placeholder
  versions once the project goes public, to avoid losing the names.
- GitHub Releases with prebuilt binaries: Linux x86_64 and aarch64, macOS Intel and Apple
  Silicon, Windows x86_64.
- **SHA256 checksums for every artefact**, published alongside the release.
- **Binary signing** investigated and adopted if a reasonably low-friction option exists at
  phase start — verify current status, cost, and requirements rather than assuming any
  particular service. macOS notarisation and Windows Authenticode have real cost and
  identity requirements that may conflict with a pseudonymous maintainer; if signing is not
  adopted, document why and make checksum verification prominent instead.
- **Reproducible builds**: every published binary traceable to the exact source commit, ideally
  byte-reproducible. For a tool asking to be trusted by at-risk users, "you can verify this
  binary came from this source" is a core feature, not packaging polish.
- A Homebrew formula.
- At least one native Linux package format. **`.deb` is the leading candidate** because both
  Tails and Qubes-Whonix are Debian-based — but confirm at phase start that this transfers
  cleanly to the actual distribution path (Debian proper has its own packaging process and
  timelines, and inclusion in a derivative is not automatic).

**Exit criteria.**
1. A person with no Rust toolchain can go from never having heard of strypt to running it via
   **at least two independent install paths**.
2. Every published binary is traceable to its exact source commit.
3. Checksums published for every artefact, with verification instructions in the README that
   a non-expert can follow.
4. Install instructions in `README.md` and `INSTRUCTIONS.md` tested on a clean machine per
   platform — not assumed to work.

**Risks.**
- *Packaging-format completionism.* Every additional package format is a permanent
  maintenance obligation. Prioritise ruthlessly by where target users actually are.
- *Signing identity versus maintainer privacy.* A project for at-risk users may have
  maintainers with their own safety considerations, and code-signing generally requires
  verified legal identity. This tension is real; resolve it deliberately and document the
  outcome rather than letting it stall the phase.
- *An unsigned binary download is itself a supply-chain risk for exactly this user base.*
  Mitigation: make checksum and provenance verification easy and prominent.

---

## Phase 5 — GUI

**Goal.** Non-technical users — Marcus and Devi from `docs/PRD.md` §5 — get the same
protection CLI users have, with no lower-trust code path.

**Framework:** Tauri v2. Verified 2026-08-19: stable at v2.10.1 (2026-03-04), independently
audited by Radically Open Security during its beta/RC cycle, dual MIT/Apache-2.0 — which
aligns with strypt's own licensing. **Re-verify all of this at phase start**; this is many
phases away and the security posture of the framework is load-bearing.

**Deliverables.**
- `strypt-gui` calling **directly into `strypt-core`**. It must not re-implement stripping
  logic and must not shell out to the CLI binary as a subprocess. Call the library.
- Drag-and-drop file input, batch support.
- **A visible before/after metadata diff**, so the user sees exactly what is being removed.
  This is a trust feature first and a usability feature second: a user who can see what came
  out has grounds to believe the tool, and a user who sees an empty diff on a file they
  expected to be dirty has learned something important.
- Safe defaults matching the CLI: copy-out, never in-place without explicit action.
- **Verified absence of network capability.** Tauri grants capabilities explicitly through
  its permissions system, so this is auditable — and must be audited, not assumed.

**Exit criteria.**
1. GUI produces **byte-identical** output to the CLI for every file in the test corpus.
   This is the proof that no logic was duplicated or has drifted (ADR-0003).
2. A capability and permissions audit confirms **zero** network access, with the audit method
   documented so it can be repeated each release.
3. The GUI is usable by someone who has never opened a terminal — validated with an actual
   non-technical person, not assumed by the developer.
4. No new `unsafe` and no new dependency without an ADR.

**Risks.**
- *"Nice to have" network features* — update checks, telemetry, crash reporting, remote
  fonts — are exactly the scope creep that would break ADR-0004. Any such proposal is an ADR
  discussion, never a quick addition. A web-technology GUI makes accidental network access
  unusually easy: a single remote font or CDN stylesheet reference would violate the
  invariant silently.
- *Front-end divergence.* Mitigated structurally by exit criterion 1, which is why it is a
  byte-identity check rather than a spot check.
- *GUI framework churn* over the long gap between now and this phase. Re-evaluate rather than
  assuming Tauri is still the right answer.

---

## Phase 6 — File-manager integration

**Goal.** Match the reach mat2 achieved through file-manager extensions, which is how much of
this tool's audience actually encounters and uses it.

**Deliverables.**
- Right-click "strip metadata" for GNOME Files (Nautilus), KDE Dolphin, and Windows Explorer.
  mat2 also added Cinnamon Nemo support in v0.15.0 — worth considering.
- Each integration calls `strypt-core` or the CLI binary; no third implementation of
  stripping logic.
- Verify the **current** recommended extension mechanism for each desktop environment at
  phase start. These APIs shift more than anything else in this roadmap.

**Exit criteria.**
1. Each integration installs and works independently of the others — a Linux user needs
   nothing Windows-specific present, and vice versa.
2. Each is tested against the **current stable release** of its target desktop environment.
3. Each surfaces failures visibly. A silent no-op in a right-click menu is worse than no
   integration, because the user believes the file was cleaned.

**Risks.**
- *Desktop extension APIs are the most volatile surface in this project* — budget extra time
  for platform-specific breakage and expect ongoing maintenance, not a one-time delivery.
- *Error reporting through a file-manager context menu is genuinely hard.* Design the failure
  path first, not last.

---

## Phase 7 — Community and adoption

**Goal.** strypt becomes a credible, trusted option in the communities that would actually
rely on it — rather than a well-built tool nobody uses.

**Deliverables.**
- Contribution pipeline maturity: issue and pull-request templates, an actively curated
  "good first issue" label, and documented response-time norms in `CONTRIBUTING.md`.
- A **documented, working security-triage process** with more behind it than "the maintainer
  will get to it" — a named backup contact at minimum.
- **Concrete outreach to Tails and Qubes-Whonix maintainers**, as a real deliverable with
  drafted messages, an owner, and a target window. Framed accurately given `docs/PRD.md` §0:
  mat2 is actively maintained, so the credible pitch is strypt as an **additional,
  independently-implemented option** with different trade-offs — memory-safe parsing, no
  interpreter or C-library chain, permissive licensing — not as a replacement for a tool
  that is not in fact dead. Pitching it as a replacement would be both inaccurate and a poor
  first impression with maintainers who know the landscape better than we do.
- A deliberate **decision on localisation**, made rather than defaulted, given an
  international user base. Record it as an ADR either way.

**Exit criteria.**
1. Outreach to at least one privacy-focused OS project has **actually happened** — sent, not
   planned.
2. A documented security-triage process exists and has been exercised at least once, even if
   only on a drill.
3. At least one substantive external contribution has been reviewed and merged, proving the
   pipeline works end to end.
4. The localisation decision is recorded in `docs/DECISIONS.md`.

**Risks.**
- *This phase drifts indefinitely without dates.* The outreach deliverable specifically needs
  a named owner and a rough target window once the project reaches this point.
- *Community growth outpacing review capacity* is a security risk in a project where parsing
  changes carry real consequences. `CONTRIBUTING.md` is explicit that parsing-logic changes
  get extra scrutiny; that must hold under volume, and slower merges are the correct trade.
