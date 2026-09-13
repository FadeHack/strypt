# strypt — Roadmap

**Status:** Phases 0–3 complete; **Phase 4 open** (ADR-0049) · **Last updated:** 2026-09-13

Every open phase states **Goal**, **Deliverables**, **Exit criteria**, and **Risks**. A phase is
done when its exit criteria are met — not when its deliverables have been attempted. Closed phases
are summarised; the evidence is in [`DECISIONS.md`](DECISIONS.md) (ADR numbers below),
[`THREAT_MODEL.md`](THREAT_MODEL.md) §7, and [`CHANGELOG.md`](../CHANGELOG.md).

**Standing rule for every phase:** all tool, crate, and framework references in this document
are snapshots taken on 2026-08-19. **Re-verify them at the start of the phase, not at the
start of the project.** A version number cited here is a starting point for a search, never
current fact.

**No dates.** This is a correctness-driven project without a delivery commitment. Phases are
ordered by dependency, and a phase that needs longer gets longer.

---

## Phase 0 — Foundation *(complete 2026-08-19)*

Core and supporting docs, dual licence, `.claude/` hooks, Cargo workspace, `rust-toolchain.toml`,
CI (`ci.yml`, `no-network.yml`, `deny.yml`), `scripts/check-no-network.sh`. Positioning signed off
as "additional option, never a replacement" (ADR-0012); MSRV policy (ADR-0013).

**Exit criteria — all six met 2026-08-19:** build/test/clippy/fmt pass; CI runs them plus
`cargo-deny` and no-network on Linux, macOS and Windows; the no-network gate proven to fail (adding
`ureq` flagged it and the transitive `rustls`); `INSTRUCTIONS.md` commands run; the owner signed off
the PRD §0 premise correction; CI demonstrably uses the pinned toolchain (ADR-0015).

---

## Phase 1 — Core engine + CLI (JPEG, PNG, WebP, PDF) *(complete 2026-08-22)*

Scope locked by ADR-0005. The engine, CLI, four handlers and their fuzz targets; decisions in
ADR-0017 to ADR-0025.

**Exit criteria — all seven met:**
1. ✅ Unit, integration and property tests, including byte-identical idempotence and
   `inspect(strip(x))` clean.
2. ✅ Zero panics, crashes, hangs or OOMs across all four fuzz targets after a sustained run. Three
   runs, 80.21 CPU-hours, found four PDF defects, each fixed with a regression test (THREAT_MODEL
   §7.1, §7.5); met by a clean 12-hour PDF run on 2026-08-22, and by all four clean in one run on
   2026-08-27.
3. ✅ Every gap against mat2 is recorded: the JPEG `APP14` marker (ADR-0021) and the 19-byte-xref
   PDF strypt refuses (THREAT_MODEL §7.5).
4. ✅ Image handlers do not re-encode pixel data.
5. ✅ `strypt show` on stripped output is clean across the corpus.
6. ✅ CI green on Linux, macOS and Windows, on `99feed2`.
7. ✅ THREAT_MODEL §7.1–7.5 written from what was learned.

Also delivered: a 102-file real-producer sweep (THREAT_MODEL §7.5; fetched, not committed —
ADR-0025) and performance measured on one machine (PRD §9).

---

## Phase 2 — Expanded format coverage *(complete; opened 2026-08-23, closed 2026-09-05)*

Opened by ADR-0027, which fixed the format list at four groups landing in order:

| Group | Formats | Done | ADRs |
|---|---|---|---|
| 1 | Office Open XML | 2026-08-23 | 0028, 0029, 0030 |
| 2 | OpenDocument | 2026-08-24 | 0031 |
| 3 | TIFF · GIF · HEIF/AVIF · SVG · JPEG XL | 08-26 · 08-27 · 08-27 · 08-29 · 08-30 | 0032, 0033, 0034, 0035, 0036 |
| 4 | FLAC · WAV · MP3 · Ogg · MP4/M4A | 09-01 · 09-02 · 09-03 · 09-04 · 09-05 | 0037, 0038, 0039, 0040, 0041, 0042 |

**Exit criteria — all four met 2026-09-05:** every format meets the Phase 1 per-format bar, with a
differential verified able to fail; zero open crash/hang findings across all 22 fuzz targets; one
THREAT_MODEL subsection per format (§7.6–7.17); nested-file handling decided by ADR-0029 — one
level, images only, in `container/package.rs`.

The first GIF run, 2026-08-26, aborted on a harness fault rather than a handler defect: an
unguarded "never grows a file" assertion met a TIFF (`target/fuzz-runs/20260826-135442-aborted/`).
Every target now guards per-format invariants with a `detect()` check.

---

## Phase 3 — Hardening *(complete; opened 2026-09-05, closed 2026-09-12)*

Opened and rescoped by ADR-0043: live-OS validation became a filesystem-constraints matrix, the
Windows permission debt was added, and no formats were added.

| # | Deliverable | Outcome |
|---|---|---|
| 1 | Fuzzing budget as a number | ADR-0044: 24 CPU-hours per handler, plateau as a windowed curve shape. 20 of 22 targets certify (`scripts/fuzz-tally.py`); `jxl` and `png` stay punctuated. `ogg`/`oggpage` certified 2026-09-12 after a CRC-fixing mutator |
| 2 | Continuous fuzzing | Declined, ADR-0046 |
| 3 | Findings triaged to zero | 2026-09-11: six failures, all fixed with regression tests |
| 4 | `cargo-deny` as a hard gate | ADR-0045; `scripts/prove-gates.sh` runs in CI, green on `9bbfd41` |
| 5 | Known-limitations page | [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md). A handler change owes an edit there as well as in THREAT_MODEL §7 |
| 6 | Filesystem-constraints matrix | `scripts/fs-matrix.sh`, 14 cases, proven to fail, green in CI on `a490adb`. Tails optional, Qubes-Whonix deferred (ADR-0043) |
| 7 | Windows permission gap | Permanent, ADR-0047 |
| 8 | Parser sandboxing | Deferred, ADR-0048 |
| 9 | THREAT_MODEL revised | 2026-09-12 |

A plateau at one corpus size is not one at the next: `jpeg` and `png` plateaued inside eight hours
in 2026-08, then climbed again on larger corpora. That, and PDF flat from hour 12 of a 48-hour run
while the old rule called it climbing, is why ADR-0044 replaced ADR-0014.

**Exit criteria — all seven met.** Zero open fuzzing findings; both CI gates pass and are proven to
fail; known-limitations page complete and linked from the README; sandboxing ADR recorded; threat
model revised; filesystem matrix passes in CI and is proven to fail; Windows gap documented as
permanent. Criteria 1, 2 and 6 stay met only while the next batch and those CI jobs stay clean.

---

## Phase 4 — Distribution *(open; opened 2026-09-12)*

Opened by ADR-0049, which settles the three inputs below and sets the deliverable order: the public
repository first, reproducible builds before any binary ships.

**Goal.** A person can install and run strypt without a Rust toolchain, through channels that
do not themselves undermine the trust model.

**Deliverables.**
- ~~`strypt-cli` (and `strypt-core`) published to crates.io.~~ **Partly done ahead of this
  phase, 2026-08-23: `strypt` and `strypt-core` published at `0.0.1`.** Names are not
  reservable in advance, and crates.io policy prohibits a crate that "exists only to reserve a
  name... without having any genuine functionality" — so the choice was to publish the real
  code early or risk the names. The real code went up.

  All three names are held. The CLI crate was renamed `strypt-cli` → `strypt` the same day
  (ADR-0026) so that `cargo install strypt` — the command matching the binary, and the one a
  user will guess — resolves to this project rather than to whoever registered it first.
  `strypt-cli` `0.0.1` is published and yanked: yanking keeps the name and stops anyone
  installing a version that will never be updated.

  **Publishing is not releasing, and the version says so.** A `0.0.1` on crates.io does not
  mean this phase's remaining deliverables — binaries, checksums, signing, reproducible
  builds — are met, and it does not mean Phase 3 happened. What it does mean is that
  `cargo install strypt` now works, so the honesty of the README's status block is load-
  bearing in a way it was not while the project was unpublished. Re-verify it before every
  subsequent version bump.

  *Both crates published at `0.1.0` with the release, 2026-09-13.*
- GitHub Releases with prebuilt binaries: Linux x86_64 and aarch64, macOS Intel and Apple
  Silicon, Windows x86_64.
  *Done: [0.1.0](https://github.com/FadeHack/strypt/releases/tag/v0.1.0), 2026-09-13, drafted from a tag by `release.yml`.*
- **SHA256 checksums for every artefact**, published alongside the release. *Done in 0.1.0; README
  verification steps are item 9.*
- **Binary signing** investigated and adopted if a reasonably low-friction option exists at
  phase start — verify current status, cost, and requirements rather than assuming any
  particular service. macOS notarisation and Windows Authenticode have real cost and
  identity requirements that may conflict with a pseudonymous maintainer; if signing is not
  adopted, document why and make checksum verification prominent instead.
  *Settled by ADR-0051: no Apple Developer ID; Windows through SignPath after the first release.*
- **Reproducible builds**: every published binary traceable to the exact source commit, ideally
  byte-reproducible. For a tool asking to be trusted by at-risk users, "you can verify this
  binary came from this source" is a core feature, not packaging polish.
  *Done in 0.1.0 (ADR-0050): each binary attested, and byte-identical across two builds on its
  runner image.*
- A Homebrew formula.
  *Done: [FadeHack/homebrew-strypt](https://github.com/FadeHack/homebrew-strypt), 2026-09-13, a
  project tap (ADR-0049) installing the 0.1.0 release binaries. `brew install` and `brew test`
  passed on macOS arm64. Intel macOS and both Linux targets resolve to the right binary and hash, but
  are uninstalled until item 10.*
- At least one native Linux package format. **`.deb` is the leading candidate** because both
  Tails and Qubes-Whonix are Debian-based — but confirm at phase start that this transfers
  cleanly to the actual distribution path (Debian proper has its own packaging process and
  timelines, and inclusion in a derivative is not automatic).
  *Declined by ADR-0052: Tails keeps only packages from Debian's repositories, so the static musl
  binary is the Tails and Whonix path, and Debian proper moves to Phase 7.*
- **The README finalised for a public audience** — install paths, checksum verification, and the
  status line brought up to date with what this phase delivers. Add a banner and a `strypt show`
  demo made from synthetic fixtures, both stripped by strypt before committing.
  *Install and verification steps written 2026-09-13, and run only on macOS arm64. Item 10 tests
  them on clean machines, and Tails's Persistent Storage is unverified (ADR-0052).*
- **The repository made public.**

**Inputs to the Phase 4 opening ADR** — all three settled by ADR-0049.
- A privacy check of git history and commit author emails before the repository goes public.
- `SECURITY.md`'s reporting channel — confirm it works for a public repository.
- Revisiting ADR-0046: an all-targets CI fuzz job becomes affordable once the repository is public.

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
- **Debian packaging explored** (ADR-0052): the only route by which Tails's Additional Software
  would keep strypt.
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
