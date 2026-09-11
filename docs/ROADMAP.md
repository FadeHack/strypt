# strypt — Roadmap

**Status:** Phase 1 complete (2026-08-22); Phase 2 complete (2026-09-05); **Phase 3 open
(opened 2026-09-05, ADR-0043)** · **Last updated:** 2026-09-05

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

## Phase 1 — Core engine + CLI (JPEG, PNG, WebP, PDF) *(complete 2026-08-22)*

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
removes (ADR-0021), and the mat2 comparison for WebP, which **was not run at all until
2026-08-21** — mat2's WebP path needs a GdkPixbuf WebP loader the verification machine did not
have, so mat2 failed on the original fixtures too and the comparison said nothing. Installing
`webp-pixbuf-loader` 0.2.7 closed that; `scripts/webp-differential.sh` now passes with no gaps
over both fixture sets (`docs/THREAT_MODEL.md` §7.4). One recorded gap therefore remains: the
`APP14` marker.

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
  fetch-on-demand corpus of 102 files now exists in `real-producer-corpus/`, assembled by
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

  **Both WebP gaps closed 2026-08-21** (`docs/THREAT_MODEL.md` §7.5): a `cwebp -metadata all`
  JPEG→WebP conversion carrying real Canon Exif — IFD1 thumbnail included — across a change of
  container, and a Chrome 151 `canvas.toDataURL('image/webp')` export. Both strip clean; the
  conversion fixture goes from 92 ExifTool tags to none. The browser fixture is opt-in via
  `build_real_corpus.py --with-browser`, because a browser's bytes change on every auto-update
  and would otherwise churn the committed manifest.

  ~~**Still missing:** committed fixtures for real producers, since the fetched files cannot
  serve that role — they carry real names, a device serial and live GPS coordinates.~~
  ✅ **Resolved 2026-08-22 by ADR-0025 — deciding *not* to commit them.** The stated reason for
  this item was the personal data, and `sanitise_corpus.py` now replaces all of it on every
  build. A licence-clean subset was proposed and rejected: the files at real risk of vanishing
  (`ianare/exif-samples`, archived, **no LICENSE file at all**) are exactly the ones that cannot
  be committed, while the ones that could be come from healthy repositories. The
  discovery-to-synthetic-reproduction workflow already covers this without redistributing
  anything — see `corpus/pdf/malformed/xref-19-byte-entries.pdf`. Two costs recorded in the
  ADR rather than glossed: JPEG real-producer coverage depends on an unmaintained upstream that
  cannot be mirrored, and there is no offline real-producer sweep.
- **Sustained fuzzing (exit criterion 2).** ✅ **Met 2026-08-22**, on the third sustained run.
  Three runs via `scripts/fuzz-sustained.sh` have delivered **80.21 CPU-hours** in total.

  The first (2026-08-20) delivered **37.79 CPU-hours** — eight hours each on JPEG, PNG, WebP
  and detect, and 5h47m on PDF, which stopped early on a genuine finding. It earned its keep:
  three real PDF defects, all fixed with regression tests — negative zero breaking
  byte-identical idempotence in the object graph and again in the trailer, and an
  integer-overflow panic inside `lopdf` that reached the shipped binary as exit 101. Only
  `detect` plateaued in that run, so it established a floor rather than a number.

  The second (2026-08-21) budgeted 60 CPU-hours and **delivered 30.42**, stopped by hand before
  its 12-hour target. It found a fourth PDF defect: a document with no `/Root` that strypt
  rewrote into corruption while reporting success twice over, now refused (`THREAT_MODEL` §7.1).
  PDF lost the run to that crash at 47 minutes.

  **What this criterion asks for is a sustained run with no crash artefact — nothing more.**
  It states no CPU-hour figure and requires no coverage plateau. ADR-0014's 100 CPU-hours plus
  plateau is a **Phase 3** deliverable and must not be applied here; `scripts/fuzz-sustained.sh`
  serves both bars and its header used to conflate them, which caused Phase 1 to be assessed
  against a Phase 3 number.

  The third (2026-08-22) is the one that met it: **PDF alone, 12.00 CPU-hours budgeted and
  12.00 delivered — zero crashes, zero hangs, zero OOMs**, 3100 corpus files at 7590 exec/s.
  Budget and delivered matching is itself the headline: it is the first sustained run in which
  PDF did not die partway.

  **PDF was the only handler that ever failed this criterion**, and it no longer does. JPEG,
  PNG, WebP and detect recorded zero artefacts across both earlier runs and are unchanged
  since. The four defects that ended the earlier runs — negative zero in the object graph and
  again in the trailer, the `lopdf` xref overflow, and the `/Root` corruption — are each fixed
  with a regression test, and none recurred.

  ~~**One caveat, recorded rather than glossed.**~~ **Closed 2026-08-27.** The caveat was that
  the criterion says "across all four fuzz targets after *a* sustained run", and no single run
  had yet had all four clean at once — the 08-22 run was PDF alone, resting on standing evidence
  for the other three. **The run of 2026-08-26/27 removes the interpretation by measurement.**
  `pdf`, `jpeg`, `png` and `webp` were all in it, all ran the full twelve hours, and all came
  back clean, alongside `gif` and `detect`: **72.00 CPU-hours budgeted, 72.01 delivered, six
  targets, zero crashes, hangs or OOMs.** PDF executed 250,357,511 inputs, JPEG 580,596,344,
  PNG 969,850,801, WebP 898,387,838. **Criterion 2 now rests on one run rather than on one run
  plus an argument**, which is the state it was written to describe.

  **Coverage data is kept for Phase 3, and it already says ADR-0014's flat number is the wrong
  shape.** JPEG, PNG and WebP each plateaued inside eight hours (last gains at 13845s, 16044s
  and 19442s of 26673s). **PDF did not plateau in twelve** — its last gain came at 40919s of
  43203s, deep inside the final quarter, climbing 4324 → 4366 edges over the run. So after
  roughly 29 cumulative CPU-hours PDF is still exploring while three handlers stopped at eight.
  That is the measurement ADR-0014 asked for, and it argues for per-handler numbers rather than
  one flat 100. Do not supersede ADR-0014 on this alone — PDF still owes a run long enough to
  actually flatten — but this is the evidence that revision should start from.

  **Updated 2026-08-27, and the picture got more complicated rather than less.** In the six-target
  run only `detect` plateaued by the runner's strict rule (last gain at 2s of 43,203s). JPEG, PNG
  and WebP, which had flattened inside eight hours in the earlier run, all recorded late gains
  this time on larger corpora — so **a plateau at one corpus size is not a plateau at the next**,
  and ADR-0014's revision cannot be built from a single observation per handler. **PDF has now
  failed to flatten across three consecutive twelve-hour runs** (last gain 39,092s of 43,204s).
  Two curves are nearly flat without passing the test: `gif` gained **one edge in its last six and
  a half hours** (1321 at 19,633s → 1322 at 38,315s) and `pdf` **two in its last three and a half**
  (4609 at 26,534s → 4611 at 39,092s). The strict last-gain rule is the wrong instrument for that
  shape, and a revision of ADR-0014 should probably define the plateau as a rate rather than as an
  absence. Still Phase 3 evidence; still not a Phase 1 gate.

  **Updated again 2026-08-27 by the HEIF run, which stretches the range at both ends.** `bmff`
  flattened after **39 seconds** and then absorbed 2.39 billion further inputs without one new
  edge — the fastest plateau this project has measured, and unambiguous rather than borderline:
  it is what a small module with a tiny input grammar looks like when genuinely saturated. `heif`
  did the opposite, still climbing at **40,374s of 43,211s** and reaching 3140 edges, more than
  any handler except PDF. **One target saturates in 39 seconds while PDF has not flattened in
  three consecutive twelve-hour runs**, which is about as direct a refutation of a single flat
  per-target budget as this data can produce. It reinforces both prior conclusions — per-handler
  numbers, and a plateau defined as a rate — without supplying the long PDF run that a supersession
  of ADR-0014 still requires.
- **Performance numbers.** ✅ Done. `docs/PRD.md` §9 now carries measurements from
  `scripts/measure-performance.sh`, which refuses to run against a debug binary. One machine
  only — Linux and Windows are unmeasured, and none of it is a commitment.
- ~~**The mat2 differential for WebP**, on a machine with a GdkPixbuf WebP loader.~~ ✅ Done
  2026-08-21: `webp-pixbuf-loader` 0.2.7 installed, `scripts/webp-differential.sh` run over the
  14 synthetic fixtures and 30 real-producer WebPs, no gaps. Exit criterion 3 is met for WebP.
- **CI green on all three platforms.** ✅ Done 2026-08-22 on `99feed2`: all seven jobs green —
  `test (ubuntu-latest)`, `test (macos-latest)`, `test (windows-latest)`, clippy, rustfmt, fuzz
  smoke, and MSRV (ADR-0013). Exit criterion 6 is met for the current tree, not merely for an
  older commit.

**Phase 1 is complete as of 2026-08-22.** All seven numbered exit criteria are met — criterion 2
by a clean 12.00-CPU-hour PDF fuzz run and criterion 6 by all seven CI jobs green on `99feed2`
— and the last non-numbered item is resolved by ADR-0025. What is *not* claimed: no tool
guarantees total metadata removal, the recorded limitations stand (the JPEG `APP14` marker, the
19-byte-xref refusal), performance is measured on one machine, and the caveats above about
fuzz-run composition and real-producer coverage are real rather than decorative.

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

## Phase 2 — Expanded format coverage *(complete; opened 2026-08-23, closed 2026-09-05)*

**Goal.** Move meaningfully toward mat2's format list without lowering the Phase 1 bar for
any individual format.

**Opened by ADR-0027**, which supersedes ADR-0005's scope lock and replaces it with a narrower
one: the phase's format list is exactly the four groups below, they land one group at a time in
this order, and a group is not started until the previous one meets the Phase 1 bar in full.
"Phase 2 is open" is not "scope is open".

**Progress.** Each entry records what landed, the ADR that governs it, and its fuzzing. The
per-format limitations, the differential results and what each handler removes are **not repeated
here** — they live in `docs/THREAT_MODEL.md` §7, one subsection per format, which is the document
to read before making a claim about what strypt removes.

- ✅ **Group 1 — Office Open XML, done 2026-08-23.** `.docx`, `.xlsx`, `.pptx`. Landed: the ZIP
  container layer written rather than imported (ADR-0028), the one-level descent into embedded
  images (ADR-0029), the handler and its XML scanner (ADR-0030), `ooxml` and `zip` fuzz targets —
  the latter through a feature-gated entry point, so the container is fuzzed independently of any
  handler — 13 fixtures plus 7 malformed, 26 integration tests, `scripts/ooxml-differential.sh`,
  and §7.6.

  Fuzzing cleared 2026-08-24: `ooxml` and `zip`, twelve hours each, zero artefacts.

- ✅ **Group 2 — OpenDocument, done 2026-08-24.** `.odt`, `.ods`, `.odp`. Landed: the handler and
  its rules (ADR-0031), an `odf` fuzz target, 14 fixtures plus 8 malformed, 33 integration tests,
  `scripts/odf-differential.sh`, and §7.7. Two internal boundaries moved so the two package formats
  share rather than duplicate: the XML scanner became `formats/xml.rs` with per-format rules beside
  each handler, and the ZIP-package machinery became `container/package.rs` — which is what keeps
  ADR-0029's one-level descent existing exactly once.

  **A stripped package really opens in LibreOffice**, which was an open hole until 2026-08-24.
  `scripts/odf-libreoffice-validation.sh` strips, imports and body-compares every fixture against
  **LibreOffice 26.2.5.2** — 14 fixtures plus 2 real LibreOffice-authored documents, no failures.
  The GUI repair-prompt check was done separately by hand the same day, seven files, no prompts;
  the two are recorded as separate claims because headless import cannot raise a dialog.

  Fuzzing cleared 2026-08-25: `odf`, `zip`, `ooxml` and `pdf` in parallel, 48.00 CPU-hours
  budgeted and delivered, zero crashes across all four. `pdf` was included because its two most
  recent fixes had had only a smoke run. Budget matching delivery is the headline: a target that
  crashes stops early, so a run that spends every hour it budgeted is one in which nothing died.

- ✅ **Group 3 — additional images — complete 2026-08-30, five tranches of five.** **ADR-0032
  splits it into five tranches** — TIFF, GIF, HEIF+AVIF, SVG, JPEG XL — landing in that order, each
  meeting the Phase 1 bar in full before the next opens. Six formats with no shared container,
  unlike Groups 1 and 2; holding a finished handler hostage to the hardest member of the list is
  what the split avoids. The default remains a hand-written walker, and ADR-0032's 2026-08-25
  survey found no dependency that earns its own ADR.

  - ✅ **Tranche 1 — TIFF — complete 2026-08-26.** `.tif`/`.tiff`, multi-page scans included.
    Landed: ADR-0033, the handler and its allow-list of structural tags, a `tiff` fuzz target, 10
    fixtures plus 6 malformed with their generator, 17 integration tests, 14 unit tests, a clean
    differential verified able to fail, and §7.8.

    **ADR-0033 records why TIFF is rebuilt rather than edited:** its metadata *is* its file
    structure, so there is no block to drop and no way to edit in place without rewriting every
    offset. Tags reach the output from an allow-list, so an unknown vendor tag cannot survive by
    going unrecognised. A clean file is therefore **never byte-identical**; idempotence is, and is
    tested.

    Fuzzing cleared 2026-08-26: `tiff` and `detect`, 24.00 CPU-hours, 4,408,918,279 inputs, zero
    crashes. `detect` was included because its parser changed in the same work.

  - ✅ **Tranche 2 — GIF — complete 2026-08-27.** `.gif`, animated included. Landed: the handler, a
    `gif` fuzz target, 14 fixtures plus 6 malformed with their generator, 22 integration tests, 20
    unit tests, a clean differential, and §7.9.

    GIF is the shape ADR-0032 predicted — a short block list, removal by deletion, no rebuild — and
    it was the first format in the tree to return a **byte-identical** copy of a clean file. One
    judgement call is recorded rather than assumed: `NETSCAPE2.0` and `ANIMEXTS1.0` are **kept**
    because they carry an animation's loop count and nothing else, declared in the report, with the
    differential asserting the loop count survives rather than filtering it out of the comparison.

    Fuzzing cleared 2026-08-27: `gif` alongside `pdf`, `jpeg`, `png`, `webp` and `detect`, 72.01
    CPU-hours delivered, all six clean. That run also closed exit criterion 2's standing caveat —
    the four formats the criterion names were clean in a single run for the first time.

    **The first attempt was aborted, and the reason is recorded rather than glossed.** `gif` died
    at 144,505,581 inputs on 2026-08-26 against a TIFF-shaped input, on the fuzz target's own
    assertion that stripping never grows a file — true of every handler until TIFF landed that
    morning, and these targets drive the whole pipeline rather than one handler. The fault was in
    the harness, not the handler; `png` and `webp` carried the same unguarded assertion. All three
    now check `detect` first, and the triggering input is kept as a seed
    (`target/fuzz-runs/20260826-135442-aborted/ABORTED.md`). **Carry that guard into every future
    handler's target.**

  - ✅ **Tranche 3 — HEIF+AVIF — complete 2026-08-27.** `.heic`, `.heif`, `.avif`, taken as one
    tranche because they share one ISO-BMFF box walker. Landed: the walker under
    `container/bmff.rs` — generic, no HEIF semantics, on the precedent `container/zip.rs` set —
    the handler and its three allow-lists, `heif` and `bmff` fuzz targets, 17 fixtures plus 8
    malformed with their generator, 24 integration tests, 27 unit tests, a differential that
    verifies itself able to fail on every run, and §7.10.

    **ADR-0034 is required reading, and it corrects ADR-0033**, which predicted an ISO-BMFF box
    tree could be edited by deletion. The tree can; the metadata is not in the tree. Exif and XMP
    are *items* addressed by absolute file offsets in `iloc`, so removing one shifts every
    surviving item — HEIF is structurally nearer to TIFF than to GIF, and is rebuilt for the same
    reason. **Motion HEIF is refused, which refuses Apple Live Photos** — a common real iPhone
    file, and a cost taken deliberately because video is Group 4.

    Fuzzing cleared 2026-08-27: `heif`, `bmff` and `detect`, 36.01 CPU-hours, 5,615,172,697
    inputs, all three clean, each running the full 43,201s and exiting through libFuzzer's own
    `Done` line.

  - ✅ **Tranche 4 — SVG — complete 2026-08-29.** Landed: ADR-0035, the handler and its rules, a
    `data:` URI codec, an `svg` fuzz target, 14 fixtures plus 9 malformed with their generator, 21
    integration tests, 33 unit tests, a clean differential verified able to fail, and §7.11.

    **ADR-0035 is required reading.** SVG is not a container of encoded pixels: the picture is
    text, and the metadata, the accessibility text and — if the author wanted — an executable
    program all sit in the same element tree. Edited by deletion, so a clean drawing comes back
    byte-identical; names reach the output only through a prefix allow-list, so an editor nobody
    here has tested cannot survive by going unrecognised.

    **SVG inverts the mat2 comparison every other format here makes.** mat2 re-renders through
    Rsvg, so it removes strictly *more* — the accessibility text and the script strypt refuses to
    touch — while destroying ids, grouping, animation and the author's editable structure. This is
    the one format where strypt removes less and says so, and where **mat2 is the better
    recommendation** for a scripted file (§7.11).

    Fuzzing cleared 2026-08-29: `svg` and `detect`, 4.14 billion inputs, zero crashes.

  - ✅ **Tranche 5 — JPEG XL — complete 2026-08-30.** Landed: ADR-0036, the handler, a `jxl` fuzz
    target with seeds, 13 fixtures plus 9 malformed with their generator, 17 integration tests, 15
    unit tests, a clean differential verified able to fail, and §7.12.

    **ADR-0036 is required reading, and it is the ADR-0034 exception.** JPEG XL spells HEIF's box
    grammar but addresses nothing by file offset, so it is edited by deletion and a clean file
    comes back byte-identical. Both spellings are handled: the container, and the bare `FF 0A`
    codestream, which has no box layer and is returned unchanged with its scope declared. `brob` is
    deleted without being decompressed, so **no Brotli decompressor enters the tree**.

    **strypt removes more here, measured rather than assumed:** a **C2PA manifest naming the
    capture device and the signing identity survives mat2 and does not survive strypt** (§7.12).

    Fuzzing cleared 2026-08-30: `jxl` and `detect`, 3.42 billion inputs, zero crashes, both exiting
    through libFuzzer's own `Done` line.

    With that, **group 3 closed** — five tranches, five handlers, no outstanding debt.

- ✅ **Group 4 — audio and video containers — complete 2026-09-05, five tranches of five.**
  **ADR-0037 splits it into five tranches** — FLAC, WAV, MP3, Ogg, MP4+M4A — landing in that order
  under ADR-0032's rules. What makes this group unlike the three before it: the payload is a timed
  stream and the container indexes into it, so MP4's `stco`/`co64` invalidate silently when a box
  ahead of the media is removed, and Ogg's metadata sits in CRC-checked pages that cannot be edited
  in place. **The group's distinguishing hazard turned out to be absent in three of the five** —
  the reason is recorded per tranche, because it is different each time.

  - ✅ **Tranche 1 — FLAC — complete 2026-09-01.** Landed: ADR-0038, the handler, a `flac` fuzz
    target with seeds, 10 fixtures plus 8 malformed with their generator, 19 integration tests, 26
    unit tests, a clean differential verified able to fail, and §7.13.

    **ADR-0038 is required reading.** The group's hazard is absent: RFC 9639 §8.5 measures a seek
    point from the first frame header rather than from the start of the file, so removing metadata
    moves no offset. Edited by block surgery, and a clean file comes back byte-identical. Two
    decisions to know: padding is zeroed at its original length rather than dropped, and the
    **`STREAMINFO` audio MD5 is kept and declared**, because the file's holder can recompute it and
    removing it would break verifiers while hiding nothing.

    **strypt removes more here, measured rather than assumed:** an `APPLICATION` block, a
    `CUESHEET` carrying a catalogue number and ISRCs, and a reserved block type all survive mat2
    and do not survive strypt (§7.13).

    Fuzzing cleared 2026-09-01: `flac` and `detect`, 3.47 billion inputs, zero crashes. `flac`'s
    peak RSS of 1,267MB was the highest of any target to that point, at 62% of libFuzzer's 2GB
    default.

  - ✅ **Tranche 2 — WAV — complete 2026-09-02.** Landed: ADR-0039, `container/riff.rs`, the
    handler, `wav` and `riff` fuzz targets with seeds, 14 fixtures plus 10 malformed with their
    generator, 16 integration tests, 33 unit tests, a clean differential verified able to fail, and
    §7.14.

    **ADR-0039 is required reading**, and it answers ADR-0037's second open question: **the RIFF
    walk moved out of `formats/webp.rs` into `container/riff.rs`**, because two real consumers now
    exist and the shared part is attacker-driven length arithmetic, where a duplicated copy is a
    fail-closed hazard. **A change there changes WebP too.** The hazard is absent for a second
    tranche: `cue `'s offsets are measured into the data section of a `wavl` list rather than into
    the file (verified 2026-09-01), so WAV is edited by chunk surgery and a clean file comes back
    byte-identical.

    **A prediction that did not hold, recorded as measured rather than argued.** mat2's `WAVParser`
    rebuilds through ffmpeg, which looked like it should reach data hidden in the samples where
    chunk surgery cannot. It does not: for 16-bit PCM the rebuild reproduces the `data` payload
    byte for byte on every fixture.

    Fuzzing cleared 2026-09-02: `wav`, `riff`, `webp` and `detect`, 8.10 billion inputs, zero
    crashes, all four exiting through libFuzzer's own `Done` line. `webp` was there because
    ADR-0039 moved code out of it — the re-run explored paths the first had not, found nothing, and
    is why it was required rather than optional. **A later change to `container/riff.rs` owes the
    same.**

  - ✅ **Tranche 3 — MP3 — complete 2026-09-03.** Landed: ADR-0040, `formats/tags.rs`, the handler,
    `mp3` and `tags` fuzz targets with seeds, 23 fixtures plus 11 malformed with their generator,
    16 integration tests, 33 unit tests, a clean differential verified able to fail, and §7.15.

    **ADR-0040 is required reading**, and it answers ADR-0037's third open question: **the ID3
    reader is hand-written** rather than taken from the `id3` crate — on shape (that crate models a
    tag as something to read, convert and write back, where strypt needs a byte range to delete and
    a reason to refuse) and on its optional `tokio`. That second point produced a finding worth
    more than the tranche: **`scripts/check-no-network.sh` passes and proves less than it looks
    like** — `--all-features` reaches workspace members, not dependencies. Read ADR-0040 decision 1
    before trusting a green run on a new crate.

    **MP3 is not a container at all**, so the hazard is absent a third time and for a stronger
    reason: nothing in the file points at anything else. Edited by deletion at both ends, and a
    file with no tags comes back byte-identical. There is no allow-list because there is nothing to
    allow-list — the frames are the payload — which makes the **boundary the whole safety
    argument**, so a tag length is refused rather than clamped.

    **ADR-0038 decision 7 is lifted.** An ID3-prefixed FLAC is now read and cleaned rather than
    refused, and a trailing tag on a FLAC — which used to survive a strip in silence — is peeled
    too. `formats/tags.rs` is **shared with FLAC**, so a change there changes FLAC too.

    Fuzzing cleared 2026-09-03: `mp3`, `tags`, `flac` and `detect`, 48.00 CPU-hours,
    7,273,768,346 inputs, zero crashes — the two new targets' debt and the two re-owed by ADR-0040
    cleared together.

  - ✅ **Tranche 4 — Ogg — complete 2026-09-04.** Vorbis, Opus and FLAC-in-Ogg in one handler.
    Landed: ADR-0041, `container/ogg.rs`, `formats/vorbis.rs`, `ogg` and `oggpage` fuzz targets
    with seeds, 10 fixtures plus 15 malformed with their generator, 17 integration tests, 35 unit
    tests, a clean differential verified able to fail, and §7.16.

    **ADR-0041 is required reading.** Ogg is the first format in this group that is **rebuilt**:
    pages carry a CRC over their own bytes and a sequence number, so emptying a comment header
    invalidates the page holding it and renumbers everything after it. Granule positions are
    per-page, so the input's page grouping is preserved rather than repaginated freely.

    **The stream serial number is rewritten to zero**, which makes this the one handler that cannot
    promise a byte-identical clean file — it is an identifier, and nobody can recompute a file's
    original one. What is promised instead, and tested: the packets cross byte for byte, and
    stripping twice is byte-exact. `formats/vorbis.rs` is **shared with FLAC**.

    Fuzzing cleared 2026-09-04: `ogg`, `oggpage`, `flac` and `detect`, 48.00 CPU-hours,
    4,377,342,181 inputs, zero crashes.

  - ✅ **Tranche 5 — MP4 / M4A — complete 2026-09-05.** Landed: ADR-0042, `formats/mp4.rs` and
    `formats/mp4/boxes.rs`, the handler across both brand families (`.mp4`/`.m4v` and
    `.m4a`/`.m4b`), an `mp4` fuzz target with seeds, 10 fixtures plus 15 malformed with their
    generator, 18 integration tests, unit tests in the handler and the box tables, a clean
    differential verified able to fail, and §7.17.

    **ADR-0042 is required reading, and it reverses ADR-0034.** `stco` and `co64` hold absolute
    file offsets, so removing a box in front of the media moves every chunk — the same sentence
    HEIF met. HEIF answered it by rebuilding, because its metadata is *inside* `mdat`. MP4's
    metadata is entirely outside it, so each `mdat` moves as one rigid block and the file is
    **edited by deletion**, with **every chunk offset remapped through a table of `mdat` extents**.
    An offset resolving inside none of them **refuses the file** rather than being nudged by a delta
    nobody verified — **that check, not the allow-lists, is the safety argument.** A clean MP4 comes
    back byte-identical, which the group's other rebuilt format could not promise.

    **`container/bmff.rs` is shared with HEIF and was extended**, so a change there changes HEIF
    too. Four families are refused by name: fragmented MP4, encrypted media (CENC and FairPlay),
    QuickTime `.mov`, and 3GPP/3GPP2.

    Fuzzing cleared 2026-09-05: `mp4`, `bmff`, `heif` and `detect`, 48.02 CPU-hours delivered,
    5,457,344,752 inputs, zero crashes, peak RSS 1,050MB on `mp4`. `bmff` and `heif` were re-owed
    because the shared box walk changed.

    With that, **group 4 closed**, and with it Phase 2's format list.

**ADR-0014 plateau evidence — Phase 3 input, not a Phase 1 gate.** Exit criterion 2 asks for a
sustained run with no crash artefact, which every run above answers. ADR-0014's *separate* bar —
100 CPU-hours **and** a plateau — is a Phase 3 deliverable, and this is the accumulated evidence
for revising it. Last coverage gain, against a 43,200s run:

| Target | Last gain | Read as |
|---|---|---|
| `bmff` | 39s, later 15s | Saturated. The fastest plateau measured here — a small module with a tiny input grammar. |
| `detect` | 1–3s most runs, 3,488s once | Saturated in every run since 2026-08-26. |
| `zip` | 6,519s | Plateaued. |
| `tiff` | 17,217s | Plateaued — 17 new edges across 1.4 billion inputs, nothing in the final 60%. |
| `ooxml` · `pdf` | 36,544s · 36,961s | Still climbing. |
| `odf` · `flac` · `ogg` | 39,934s · 39,896s · 39,178s | Still climbing. |
| `heif` | 40,374s, later 40,136s | Still climbing, on more edges than any handler except PDF. |
| `jxl` · `webp` · `svg` | 41,175s · 41,349s · 41,365s | Still climbing. |
| `wav` · `mp4` | 42,672s · 42,908s | Still climbing — the latest gains measured. |

Two conclusions. **A flat 100 CPU-hours for every target is the wrong shape** when one saturates in
39 seconds and PDF has not flattened in three consecutive twelve-hour runs. And **that argues for
revising ADR-0014, not for superseding it** — superseding needs the budget *and* the plateau, and
most targets here have neither. PDF still owes a run long enough to actually flatten.

**Superseded 2026-09-10 by ADR-0044, and the "Read as" column above is wrong.** PDF got that
longer run — 48 hours — and was flat from hour 12, yet this table's rule still calls it "still
climbing" on one edge at 47h07m. The rule, not the handler, was the problem: measuring *last gain*
answers where the final edge landed, not whether the curve had stopped. Every "still climbing" row
above should be read as unclassified. See ADR-0044 for the replacement and
`scripts/fuzz-plateau.py` for the test; the batch results are recorded under deliverable 1.

**Deliverables.** In priority order, driven by user risk rather than by implementation ease:
1. ✅ Office Open XML — `.docx`, `.xlsx`, `.pptx` (ZIP containers; `docProps/core.xml`,
   `app.xml`, custom properties, revision identifiers, comments, tracked changes,
   embedded thumbnails).
2. ✅ OpenDocument — `.odt`, `.ods`, `.odp` (`meta.xml`, editing-cycle and duration statistics,
   `settings.xml`, thumbnails, and the authorship that ODF keeps in element text rather than in
   attributes).
3. ✅ Additional images — TIFF, GIF, AVIF, HEIF, JPEG XL, SVG. Split into five tranches by
   ADR-0032; TIFF (2026-08-26), GIF (2026-08-27), HEIF+AVIF (2026-08-27) and SVG (2026-08-29) are
   complete, and JPEG XL on 2026-08-30. **Group 3 is closed**; group 4 may open.
4. ✅ Audio and video containers — FLAC, MP3/M4A, Opus/Ogg, MP4, WAV. Split into five tranches by
   ADR-0037; FLAC complete 2026-09-01, WAV 2026-09-02, MP3 2026-09-03, Ogg 2026-09-04, MP4/M4A
   2026-09-05. **Group 4 is closed.**

**Exit-criterion progress — all four met 2026-09-05.**

1. **Met.** Every format shipped in this phase carries a handler, a fuzz target with seeds,
   fixtures and their generator, integration tests with an independent parser, a differential
   against mat2/ExifTool verified able to fail, and a `docs/THREAT_MODEL.md` subsection. No
   handler shipped provisionally.
2. **Met.** All twenty-two fuzz targets stand on a clean sustained run, the last four
   (`mp4`, `bmff`, `heif`, `detect`) on 2026-09-05. No finding is open, and none was set aside as
   not worth fixing; the five historic `pdf` reproducers from 2026-08-24 were replayed on
   2026-09-05 and none reproduces.
3. **Met.** `docs/THREAT_MODEL.md` §7 has one subsection per shipped format, §7.1 through §7.17.
4. **Met by ADR-0029.** The descent is fixed at one level and at image formats only, enforced in
   the type system rather than by a counter, with an archive-wide decompression budget, a
   per-entry expansion-ratio ceiling, and an entry-count ceiling. It covers both package formats,
   since the descent is shared code — `container/package.rs` — rather than a rule each handler
   implements for itself.

**Phase 3 opened 2026-09-05 (ADR-0043), rescoped from what Phase 0 wrote.** Nothing in it is
delivered yet.

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

## Phase 3 — Hardening *(open; opened 2026-09-05)*

**Goal.** strypt is defensible under adversarial scrutiny before it is ever pointed at real
at-risk users' files. Not "it works" but "we can show why you should believe it works."

**Opened and rescoped by ADR-0043**, which revises the deliverables and exit criteria below.
Two of the six original deliverables were written in Phase 0, before a parser existed, and did
not survive contact: live-OS validation is replaced by a filesystem-constraints matrix
(deliverable 6), and ADR-0019's Windows permission debt is added (deliverable 7) because the
code already assigns it to this phase and the roadmap never listed it. **ADR-0027's rule
carries over: "Phase 3 is open" is not "scope is open", and this phase adds no formats.**

**Deliverables.** Nine, fixed by ADR-0043. Deliverable 1 starts first because it is gated by
wall-clock rather than by attention; deliverable 8 is last by construction. Nothing else here
gates anything else here.

1. ✅ **A sustained fuzzing budget, stated as a number** — **2026-09-10, ADR-0044**, which
   supersedes ADR-0014's plateau definition and its 100 CPU-hour figure. Three measured batches
   (24h ×9, 24h ×5, 48h ×3; 480 CPU-hours, zero crashes) brought the archive to **80 coverage
   curves across 22 targets**, and both halves of the old bar failed on them:

   | Curve | What the old rule said | What the curve shows |
   |---|---|---|
   | `pdf` 48h — 3955, 235, 40, 13, 1, 4 | "still climbing" | Flat since hour 12; failed on one edge at 47h07m |
   | `ogg` 48h — 77, 9, 5, 2, **140**, 42 | would have passed at 24h | Flat 24 hours, then a 140-edge breakthrough |
   | `webp` 24h → 48h | final-quarter rate 1.12% → 0.00% | Same code; the rate reports where the run was cut |

   **The finding that set the new rule: "still climbing" does not exist.** Classifying all 80
   curves puts zero in a slow-slope bucket — every one is decaying or punctuated. So a plateau is
   now a **windowed curve shape**, tested by `scripts/fuzz-plateau.py`, and the budget is **24
   CPU-hours per handler per run**, not 100. That certifies twelve handlers and cuts outstanding
   debt from ~1,401 CPU-hours to ~170. `scripts/fuzz-tally.py` tracks who owes what.

   **The debt batch ran 2026-09-10** — `bmff detect riff tags tiff zip oggpage` at 24h, 168
   CPU-hours, zero crashes. Six certified. **`oggpage` did not**: windows 3, 17, 0, 0, 0, 0,
   punctuated in window 2. It first read as saturated because `fuzz-plateau.py` skipped testing
   window 2, which ADR-0044's text never allowed; the script was corrected to the ADR, and no
   verdict ADR-0044 itself cites changed. **18 of 22 now certify** (`fuzz-tally.py`), and no
   target owes hours.

   **One item remains open under this deliverable and is not closed by the ADR:**

   - **`ogg` is recurrently punctuated at 12, 24 and 48 hours**, and `oggpage` on both its runs —
     the same `container/ogg.rs` through a second target. `jxl` and `png` punctuate too, less
     severely. **More hours are not the remedy**: 84 CPU-hours have not made `ogg` converge, and
     the fuzzer is visibly spending most of a run failing to construct a valid page CRC
     (ADR-0041). The work is structure-aware input — a page-header dictionary or a CRC-fixing
     mutator — and it stays listed here until it happens.
2. ✅ **Continuous fuzzing infrastructure — declined, 2026-09-11, ADR-0046.** No CI job can
   run ADR-0044's 24 hours, and a private repo cannot afford one. Local batches plus
   `fuzz-tally.py` stay the method. OSS-Fuzz is declined until strypt has users.
3. Every crash, hang, OOM, and assertion failure triaged to zero, each with a regression test.
4. ✅ **`cargo-deny` as a hard merge gate** — **2026-09-11, ADR-0045**, confirmed in CI the
   same day on `9bbfd41`. All four checks block; `advisories` lost its `continue-on-error`, `yanked`,
   `unmaintained` and `unsound` are set explicitly, duplicates are denied as ADR-0008 always
   required, and the licence allow-list names only what the tree uses. Schema verified against
   cargo-deny 0.20.2. **The stricter config caught a yanked `chacha20 0.10.1` under `lopdf` on
   its first run**; it was bumped to 0.10.2. `scripts/prove-gates.sh` plants seven violations
   and requires each gate's own diagnostic — including the no-network gate's — and runs in CI.
   It was itself shown failing when two gates were weakened.
5. A per-format **known-limitations page**, written *from* the fuzzing and differential-testing
   findings, never speculatively. This document is a safety feature: it is what stops a user
   over-trusting the tool.
6. **A filesystem-constraints matrix** — **built 2026-09-11; not yet run in CI.** `scripts/fs-matrix.sh`,
   14 cases, all green on Linux 6.12 (Docker, aarch64); `scripts/prove-fs-matrix.sh` catches all five planted
   `io.rs` mutants. **ADR-0043's `vfat` hypothesis is false there**: `chmod` succeeds and does
   nothing, so no false failure. **The real finding is a limitation, carried into deliverable 5**:
   on `vfat`/`exfat` the output takes the mount's mode (0755 by default), so ADR-0019's owner-only
   permissions do not apply on a USB stick. As specified: run in CI on Linux against the real CLI binary.
   **Replaces the "boot Tails and Qubes-Whonix" deliverable** — see ADR-0043 for why, and for
   what that gives up. Minimum cases: a read-only destination directory; a full volume, so
   `ENOSPC` lands mid-write; removable-media filesystems with no Unix permission model
   (`vfat`, `exfat`); a destination on a different mount from `TMPDIR`; and an unwritable
   destination directory holding a writable file. Each case asserts the **fail-closed
   contract**, not merely the absence of a panic: the destination is replaced in full or left
   untouched, no `.strypt-*.tmp` survives, and no success is reported for a file that was not
   written. Tails is an **optional confirmatory boot**; **Qubes-Whonix is deferred**, because
   it needs bare-metal x86-64 with IOMMU that this project does not have.
7. **ADR-0019's Windows permission gap resolved either way.** `crates/strypt-core/src/io.rs`
   says in a comment that `Permissions::OwnerOnly` is weaker on Windows — the new file
   inherits the parent directory's ACL — and that Phase 3's platform validation is where it
   gets addressed. Outcome is narrowing the ACL **or** recording the gap as permanent in the
   known-limitations page. Not silence.
8. **A decision on parser sandboxing, recorded as an ADR.** Investigate — do not assume.
   Required inputs to that decision: (a) why mat2 removed bubblewrap sandboxing in v0.14.0,
   which is the most relevant prior experience available and costs nothing to look up;
   (b) what sandboxing actually buys for a `forbid(unsafe_code)` Rust parser, honestly
   assessed — realistically resource-exhaustion bounding and supply-chain-compromise
   containment, not memory-safety;  (c) the cross-platform maintenance cost. "Deferred, with
   reasons" is a legitimate outcome.
9. **`docs/THREAT_MODEL.md` revised** to record what hardening actually taught us. **Last, by
   ADR-0043 decision 6** — written early it would be a plan rather than a finding.

   **Carried into this deliverable, deliberately not fixed early:** §7's per-format fuzzing notes
   still read a plateau off ADR-0014's superseded rule — "had not plateaued at twelve hours" and
   similar, in the `zip`, `odf`, `tiff` and group-4 subsections. They are wrong now (ADR-0044) and
   are corrected here rather than in a drive-by pass, because §7 also has to absorb what the
   `ogg` result means for that handler's confidence.

**Exit criteria.**
1. Zero open crash/panic/hang findings from fuzzing across every handler.
2. ✅ Both CI gates (`cargo-deny`, no-network) passing on a clean run, both proven to fail when
   deliberately violated. **Met 2026-09-11**: CI run on `9bbfd41` passed both gates and
   `prove-gates.sh` caught all seven planted violations on Ubuntu, eight checks in all. It stays met only while that
   job stays green.
3. Known-limitations page complete for every shipped format and linked from the README.
4. Sandboxing ADR recorded — adopted or deferred, with reasoning either way.
5. `docs/THREAT_MODEL.md` revised to reflect what hardening actually taught us. If nothing
   changed, that is itself suspicious and worth re-examining.
6. **The filesystem-constraints matrix passes in CI on Linux, and is proven to fail** when the
   fail-closed contract is deliberately broken. Tails and Qubes-Whonix boots are **not**
   required by this criterion; ADR-0043 records what that forgoes.
7. The Windows permission gap is closed or documented as permanent — deliverable 7 resolved,
   not carried forward silently a second time.

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
- *The constraints matrix tests filesystem shape, not the distributions themselves.* It is the
  better instrument for the failure modes we know about, and it is silent on anything specific
  to Tails's squashfs and Persistent Storage layout or to Qubes's volatile root and inter-VM
  copy. Do not let a green matrix become "validated on Tails" in any user-facing text.

---

## Phase 4 — Distribution

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
