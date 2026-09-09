# strypt — Architecture

**Status:** Phase 1 built to this design; Phase 2's first format group extends it ·
**Last updated:** 2026-08-23

Phase 1 is implemented and follows the structure below: the pipeline in §1, the layout in §2,
the `MetadataHandler` trait in §3, and the handlers behind it. Later work should follow this
design or amend it via a new ADR in `docs/DECISIONS.md` — it should not silently diverge.

**Phase 2's OOXML group added one thing this design did not anticipate: a `container/` layer.**
A ZIP archive is not a format anyone hands to strypt on its own; it is machinery that two format
groups share, in the way `formats/exif.rs` is a shared reader rather than a format. It sits
below `formats/` and implements no trait (ADR-0028). The `MetadataHandler` trait itself did not
change, which was the point of designing it for extension from day one (ADR-0005).

**Two parts of this document are Phase 0 evaluations, not descriptions of the code, and are
kept for the reasoning rather than the conclusions. Do not read them as current:**

- **§4's dependency tables** recommend crates that were *not* adopted. `img-parts` and
  `file-format` were both rejected — JPEG, PNG and WebP are parsed in-tree and detection is
  hand-written, so the only parsing dependency is `lopdf`. No logging crate was taken, so
  `tracing` is not a dependency either. **`docs/DECISIONS.md` ADR-0018 is the authority on
  what is actually depended on and why**; the tables record what was considered at the time.
- **§3's trait** is described below as a sketch. The implemented signatures are in
  `crates/strypt-core/src/formats/mod.rs`, which is the authority; the invariants stated here
  did survive.

Anything else that says "Phase 1 will" is a Phase 0 statement about work now finished — read
`docs/ROADMAP.md` for what is actually done.

---

## 1. System overview

```
                          ┌──────────────────────────────────────┐
                          │  front-ends (thin, interchangeable)  │
                          │    strypt   │ strypt-gui │ strypt-ffi│
                          │   (P1)      │   (P5)     │  (later)  │
                          └────────────────┬─────────────────────┘
                                           │  structured types only
                                           │  (never formatted strings)
  ════════════════════════════════════════ │ ══════════════════════════ crate boundary
                                           ▼
                          ┌──────────────────────────────────────┐
                          │             strypt-core              │
                          │                                      │
                          │  ┌────────────────────────────────┐  │
   file bytes ──────────▶ │  │ 1. Ingest (bounded reader)     │  │
                          │  └───────────────┬────────────────┘  │
                          │                  ▼                   │
                          │  ┌────────────────────────────────┐  │
                          │  │ 2. Format detection            │  │
                          │  │    content sniffing only —     │  │
                          │  │    file extension is a hint,   │  │
                          │  │    never authoritative         │  │
                          │  └───────────────┬────────────────┘  │
                          │                  ▼                   │
                          │  ┌────────────────────────────────┐  │
                          │  │ 3. Handler registry            │  │
                          │  │    dispatch to MetadataHandler │  │
                          │  └───────────────┬────────────────┘  │
                          │                  ▼                   │
                          │  ┌────────────────────────────────┐  │
                          │  │ 4. Handler: inspect / strip    │  │
                          │  │    jpeg │ png │ webp │ pdf     │  │
                          │  │    (hostile-input boundary)    │  │
                          │  └───────────────┬────────────────┘  │
                          │                  ▼                   │
                          │  ┌────────────────────────────────┐  │
                          │  │ 5. Verification pass           │  │
                          │  │    re-inspect own output;      │  │
                          │  │    residual metadata = failure │  │
                          │  └───────────────┬────────────────┘  │
                          │                  ▼                   │
                          │  ┌────────────────────────────────┐  │
                          │  │ 6. Output writer               │  │
                          │  │    temp file + atomic rename   │  │
                          │  └────────────────────────────────┘  │
                          └──────────────────────────────────────┘
```

Two stages deserve emphasis because they are easy to omit and expensive to retrofit:

**Stage 2 sniffs content, never trusts extensions.** A `.jpg` that is actually a PDF must be
handled as a PDF or rejected — never handed to the JPEG handler, which would "succeed"
while stripping nothing. Silent mis-dispatch is one of the most dangerous failure modes
available to this tool, because it produces a confident success message about a file that is
untouched.

**Stage 5 is a self-check, not decoration.** After stripping, `strypt-core` re-runs its own
inspection over the *output*. If inspection still finds metadata the handler claimed to
remove, the operation fails and the output is discarded. This converts an entire class of
silent handler bugs into loud, safe failures. It cannot detect metadata the inspector does
not know about — that limitation is stated in `docs/THREAT_MODEL.md` — but it makes the
tool's claims internally consistent.

---

## 2. Workspace layout

```
strypt/
├── Cargo.toml                  # workspace root; shared lints, shared dep versions
├── crates/
│   ├── strypt-core/            # ALL logic. Zero CLI/UI/network dependencies.
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── detect.rs       # content sniffing → Format
│   │   │   ├── registry.rs     # Format → &dyn MetadataHandler
│   │   │   ├── pipeline.rs     # ingest → detect → dispatch → verify → write
│   │   │   ├── report.rs       # structured result/report types
│   │   │   ├── error.rs        # typed errors, no panics
│   │   │   ├── bytes.rs        # checked reads over untrusted buffers (ADR-0006)
│   │   │   ├── panic_guard.rs  # contains unwinding panics from `lopdf` (ADR-0024)
│   │   │   ├── io.rs           # bounded reads, atomic writes
│   │   │   ├── fuzzing.rs      # feature-gated, non-public: lets `zip` be fuzzed on its own
│   │   │   ├── container/      # NOT formats: machinery that formats sit on top of
│   │   │   │   ├── mod.rs
│   │   │   │   ├── zip.rs      # hand-written ZIP reader/writer (ADR-0028)
│   │   │   │   └── package.rs  # what OOXML and ODF do the same way: shared decompression
│   │   │   │                   # budget, nested-container refusal, and the one-level
│   │   │   │                   # descent into embedded images — which exists here so that
│   │   │   │                   # it exists exactly once (ADR-0029)
│   │   │   └── formats/
│   │   │       ├── mod.rs      # MetadataHandler trait
│   │   │       ├── exif.rs     # shared Exif reader (JPEG, PNG, WebP)
│   │   │       ├── xmp.rs      # shared XMP reader
│   │   │       ├── xml.rs      # shared tag scanner (OOXML, ODF); edits by deleting byte
│   │   │       │               # ranges, never by re-serialising
│   │   │       ├── jpeg.rs
│   │   │       ├── png.rs
│   │   │       ├── webp.rs
│   │   │       ├── pdf.rs
│   │   │       ├── ooxml.rs    # .docx/.xlsx/.pptx: part classification (ADR-0030)
│   │   │       ├── ooxml/
│   │   │       │   └── rules.rs  # which Office attributes are identifying
│   │   │       ├── odf.rs      # .odt/.ods/.odp: parts found by name, not by declared
│   │   │       │               # type — the inversion of ADR-0030 (ADR-0031)
│   │   │       └── odf/
│   │   │           └── rules.rs  # which ODF elements are identifying, and in what context
│   │   ├── tests/              # integration tests + corpus-driven tests
│   │   └── fuzz/               # cargo-fuzz targets: one per handler, plus `detect` and `zip`
│   └── strypt/                 # thin: args, orchestration, presentation, exit codes
├── corpus/                     # committed synthetic fixtures (see TESTING_STRATEGY.md §3)
├── real-producer-corpus/       # build script + manifests; the files themselves are fetched
│                               # on demand and never committed (ADR-0025)
├── scripts/                    # gates and measurement: no-network, fuzz, differentials
└── docs/
```

Future workspace members, named now so the boundaries are designed for and *not* built now:
`strypt-gui` (Phase 5, Tauri) and `strypt-ffi` (C ABI / language bindings, unscheduled).

**The rule that makes this worth the overhead (ADR-0003):** `strypt-core` never formats
output for humans, never reads argv, never calls `std::process::exit`, never prints. It
returns data. Every front-end renders that data itself. Violating this is how the GUI ends up
subtly different from the CLI, and in a security tool "subtly different" means one of them is
quietly less safe.

`formats/` is organised **by file format, not by dependency**. A reader looking for how WebP
is handled opens `formats/webp.rs`. If the underlying crate is swapped later, the module
boundary absorbs it and nothing else in the tree moves.

`container/` is the one thing under `strypt-core/src/` that is deliberately *not* a format. It
holds parsers for things that stand between strypt and what the user asked to have cleaned, and
its code exists to get through them safely rather than to implement them faithfully. Nothing in
it implements `MetadataHandler`, and a bare `.zip` handed to strypt is still refused as
unsupported.

---

## 3. The `MetadataHandler` trait

> **The implemented trait is in `crates/strypt-core/src/formats/mod.rs`**, which is the
> authority on signatures. The sketch below is the Phase 0 design; the invariants it states
> survived Phase 1, the exact signatures did not survive unchanged.

Sketch — the shape and the invariants matter more than the exact signatures:

```rust
pub trait MetadataHandler: Send + Sync {
    /// Stable identifier, e.g. "jpeg". Used in reports and JSON output.
    fn name(&self) -> &'static str;

    /// Can this handler process this format? Called after detection.
    fn handles(&self, format: Format) -> bool;

    /// Report metadata present. MUST NOT modify anything.
    /// MUST NOT return Err merely because the file is unusual — an unparseable
    /// region is a finding to report, not necessarily a failure.
    fn inspect(&self, input: &mut dyn ReadSeek) -> Result<MetadataReport, StrypError>;

    /// Write a sanitised copy to `out`. MUST NOT modify the input.
    /// MUST fail rather than emit partially-sanitised output.
    fn strip(&self, input: &mut dyn ReadSeek, out: &mut dyn Write)
        -> Result<StripReport, StrypError>;
}
```

Invariants every implementation must uphold:

1. **`inspect` is pure.** No writes, no temp files, no mutation of input.
2. **No panics.** Every failure is a typed `Err` (ADR-0006). Malformed input is expected
   input, not an exceptional condition.
3. **Fail closed.** Partial success is failure. Never emit output that might be mistaken for
   sanitised.
4. **Bounded resources.** No unbounded allocation driven by an attacker-controlled length
   field, and no unbounded recursion — a hostile file must not be able to exhaust memory or
   the stack. This is the most common real vulnerability class in format parsers written in
   safe Rust, precisely because memory safety does not prevent it.
5. **Preserve payload.** Removing metadata must not re-encode image data (PRD §8.1).
6. **Self-verifiable.** Whatever `strip` claims to remove, `inspect` must be able to detect,
   so stage 5's verification pass is meaningful.

Adding a format means: implement the trait, register it, add fuzz target, add corpus,
update `docs/THREAT_MODEL.md`. Core dispatch is untouched. No dynamic plugin loading, ever
(ADR-0011).

---

## 4. Dependency choices

> **Superseded — this section is the Phase 0 evaluation, not the dependency list.** Several
> crates recommended below were rejected once Phase 1 measured them: `img-parts` and
> `file-format` were both dropped (image parsing and detection are in-tree), and no logging
> crate was adopted. The actual direct dependencies are `thiserror` and `lopdf` in
> `strypt-core`, `clap` and `serde_json` in `strypt`. **See `docs/DECISIONS.md` ADR-0018.**
> Kept because the alternatives considered are worth having on record.

**Every version below was verified on crates.io on 2026-08-19 and every one of them must be
re-verified at implementation time.** Crate health changes; a version number in a document is
a snapshot, not a commitment. Where the recommendation is close, the alternative is named so
the Phase 1 implementer can re-run the comparison rather than re-derive the options.

Toolchain note (verified 2026-08-19 against the authoritative rustup channel manifest at
`static.rust-lang.org/dist/channel-rust-stable.toml`): stable is **1.97.1**, released
2026-07-16, with rustc build date 2026-07-14. Under ADR-0013's `stable - 2` policy the **MSRV
is currently 1.95**. Note that `releases.rs` served stale data (stable 1.96.0) on the same
day — use the channel manifest or `rust-lang/rust` release tags instead.

1.97.1 is a point release fixing an LLVM miscompilation. That is worth remembering here: for
a tool whose parsers process hostile input, a compiler bug is part of the trusted computing
base, which is why CI pins an explicit toolchain via `rust-toolchain.toml` rather than
tracking whatever `stable` resolves to on a given day.

### Format detection

| Candidate | Version (verified 2026-08-19) | License | Notes |
|---|---|---|---|
| **`file-format`** *(recommended)* | 0.29.0 (2026-03-27) | MIT OR Apache-2.0 | Broad magic-number coverage, optional deeper readers for PDF/ZIP/MP4, feature-gated so unneeded readers can be compiled out. |
| `infer` | 0.22.0 (2026-07-15) | MIT | Smaller and simpler, zero dependencies. Good fallback if `file-format`'s footprint proves excessive. |

Recommend `file-format`, with its optional readers disabled unless needed, because
discriminating container subtypes (RIFF-WebP vs other RIFF payloads) matters here. Detection
must be treated as a hostile-input parser like any other — it sees every byte of every file.

### Image containers (JPEG / PNG / WebP)

| Candidate | Version (verified 2026-08-19) | License | Notes |
|---|---|---|---|
| **`img-parts`** *(recommended)* | 0.4.0 (2025-08-08) | MIT OR Apache-2.0 | Low-level JPEG/PNG/RIFF *container* manipulation with direct EXIF and ICC access. Covers all three Phase 1 image formats with one dependency, and — critically — allows removing segments/chunks **without touching encoded pixel data**, satisfying PRD §8.1. |
| `kamadak-exif` | 0.6.1 (2024-11-06) | BSD-2-Clause | Excellent EXIF *reader*, useful for `inspect` and for cross-checking. Read-oriented; last release is over eighteen months old. |
| `little_exif` | 0.6.23 (2026-01-13) | MIT OR Apache-2.0 | Read *and* write EXIF across PNG/JPEG/WebP/HEIF/JXL, actively developed. Worth re-evaluating at Phase 1 start, and the stronger option if Phase 2 adds HEIF/JXL. |

Recommendation: `img-parts` as the structural workhorse, optionally `kamadak-exif` for
richer `inspect` reporting. **Note the licence:** `kamadak-exif` is BSD-2-Clause — permissive
and compatible with `MIT OR Apache-2.0` distribution, but it is a third licence in the tree
and must be declared in `cargo-deny`'s allow-list.

**Deliberate non-choice:** the `image` crate. It decodes to pixels and re-encodes, which
violates the preserve-payload requirement. Metadata stripping is a container operation, not
an imaging operation — this distinction should be stated in code comments, because reaching
for `image` is the obvious wrong turn.

### PDF

| Candidate | Version (verified 2026-08-19) | License | Notes |
|---|---|---|---|
| **`lopdf`** *(recommended)* | 0.44.0 (2026-07-10) | MIT | Long-established, actively released, pure Rust, object-level document model. Can read the trailer/Info dictionary and metadata streams, remove entries, and re-serialise. ~15.7M downloads. |
| `oxidize-pdf` | 4.5.0 (2026-08-18) | MIT | Very actively developed pure Rust, no C deps. Oriented toward AI/RAG extraction; broader than needed and moving fast (major version churn). Re-evaluate at Phase 1. |

Recommend `lopdf`: the object-model access strypt needs is exactly what it provides, and its
maintenance record is the longest. **Expect this to be the hardest handler.** The Info
dictionary is the easy part; XMP metadata streams, per-object metadata, document IDs, and —
above all — data left reachable through incremental updates and orphaned objects are where
real leaks hide. Full document rewrite (rather than incremental patching) is likely necessary
to drop orphaned objects, and that decision needs its own ADR in Phase 1 once the trade-offs
against file fidelity are measured.

### CLI, errors, logging

| Purpose | Recommendation | Version (verified 2026-08-19) | License | Alternative |
|---|---|---|---|---|
| Argument parsing | **`clap`** (derive) | 4.6.6 (2026-08-06), MSRV 1.85 | MIT OR Apache-2.0 | `lexopt` — far smaller, if binary size or dep count becomes a problem |
| Error types | **`thiserror`** | 2.0.20 (2026-08-08) | MIT OR Apache-2.0 | hand-written enums (no dependency) |
| Logging | **`tracing`** | 0.1.44 (2025-12-18) | MIT | `log` — simpler; `tracing` is likely more than Phase 1 needs |

`clap` and `tracing` belong to `strypt-cli` only. `strypt-core` takes `thiserror` and the
format crates — nothing else. **`anyhow` must not appear in `strypt-core`:** callers need to
match on typed errors to distinguish "unsupported format" from "corrupt file" from "I/O
failure", and `anyhow` erases exactly that.

**Logging carries a privacy obligation.** Log output can itself leak the metadata being
removed, and a log file is a durable copy of the secret the user just deleted. Never log
metadata *values* above trace level; log field names and counts. This should be a code-review
checklist item, not a good intention.

### Testing and verification

| Purpose | Recommendation | Version (verified 2026-08-19) | License |
|---|---|---|---|
| Fuzzing | `cargo-fuzz` + `libfuzzer-sys` | cargo-fuzz 0.13.2 (2026-06-09) | MIT OR Apache-2.0 |
| Property testing | `proptest` | 1.11.0 (2026-03-24) | MIT OR Apache-2.0 |

`cargo-fuzz` requires a nightly toolchain and supports x86-64 and aarch64 on Unix-like
systems only — **not Windows** (verified 2026-08-19). CI must therefore run fuzzing on
Linux/macOS while still testing Windows normally. Details in `docs/TESTING_STRATEGY.md`.

---

## 5. Security architecture

This section is the reason the project exists. It is not a footnote to the design; it *is*
the design.

### 5.1 Every input is hostile

strypt's threat model assumes files may be crafted specifically to exploit it — a document
sent to a journalist by someone who would like to know where that journalist is. Concretely:

- **No trust in declared lengths.** Every length, offset, and count read from a file is
  attacker-controlled. Validate against actual remaining bytes before allocating or seeking.
  `Vec::with_capacity(n_from_file)` is a memory-exhaustion bug.
- **Bounded reads.** Handlers read through a reader that enforces a maximum, so a
  small file claiming an enormous structure cannot drive unbounded allocation.
- **Recursion limits.** PDF object graphs can be cyclic and deeply nested. Every recursive
  descent needs an explicit depth cap and cycle detection. Stack overflow is not a catchable
  panic — it aborts the process, so this cannot be handled after the fact.
- **No panics.** ADR-0006, enforced by denied clippy lints, verified by fuzzing.
- **No `unsafe`.** `#![forbid(unsafe_code)]`; exceptions require an ADR (ADR-0007).
- **Timeouts.** A handler that takes unbounded time on a crafted file is a denial of service
  against batch users. Fuzzing must treat hangs as findings, equal in severity to crashes.

### 5.2 No network, enforced in depth

ADR-0004 is the project's most important invariant, and documentation alone will not hold it
across years and contributors. Three layers, from weakest to strongest:

1. **`PreToolUse` hook** (`.claude/settings.json`) — early local warning when an edit looks
   like it adds a networking dependency. Best-effort; see that file's notes for its real
   limits.
2. **CI dependency-graph check** — parses the fully-resolved dependency tree and fails the
   build if any known networking crate (`reqwest`, `hyper`, `tokio` with net features,
   `curl`, `ureq`, `rustls`, `native-tls`, `socket2`, …) appears anywhere, including
   transitively. **This is the real gate.**
3. **`cargo-deny` `bans`** — the same list expressed as policy, so violations are reported
   with an explanation rather than a bare grep failure.

The CI gate is authoritative because it is the only layer that cannot be bypassed by a
contributor who has not read the docs — which, over a project's life, is most contributors.

### 5.3 Parser isolation — a Phase 3 investigation, not a v1 feature

Running each format handler in a restricted subprocess (seccomp/Landlock on Linux, sandbox
profiles on macOS) or a WASM sandbox would contain a parser compromise. It is explicitly
**not** v1 scope, and Phase 3 must *investigate* rather than assume the answer.

Relevant data point: mat2 **removed** its bubblewrap sandboxing in v0.14.0 (verified
2026-08-19). Phase 3 should find out why before repeating the experiment — the reasons a
comparable project abandoned this exact mechanism are the highest-value evidence available,
and they are free.

Honest framing: for safe Rust with no `unsafe`, sandboxing buys much less than it does for
C parsers. The realistic gains are bounding resource exhaustion and containing a
supply-chain compromise in a dependency. Those are real but modest, and must be weighed
against complexity, platform-specific code, and the cross-platform testing burden. Decision
recorded as an ADR either way.

### 5.4 Handling metadata-leak reports

A bug where strypt reports a file clean while metadata remains is a **security
vulnerability**, not a normal defect, because users act on that report. Such reports follow
the private disclosure process in `SECURITY.md`, are triaged at highest severity, get a
regression test before the fix is accepted, and are disclosed in `CHANGELOG.md` under
`Security` with a clear statement of which versions and formats were affected — so users can
work out whether files they already published need re-checking.

---

## 6. Supply-chain security

- **`cargo-deny` in CI as a hard merge gate** covering `advisories`, `licenses`, `bans`
  (including the networking-crate list from §5.2), and `sources`. `cargo-deny` subsumes
  `cargo-audit`'s advisory checking; running both is optional redundancy, not a requirement.
- **Minimise dependencies** (ADR-0008). Each direct dependency is justified in §4. A new one
  needs an ADR, and "it is convenient" is not sufficient.
- **`Cargo.lock` is committed.** strypt ships binaries; reproducibility beats float.
- **SBOM at release time** via `cargo-cyclonedx` (CycloneDX; sources from both `Cargo.lock`
  and `cargo metadata`, so it can honour feature selections and record per-component
  licences) or `cargo-sbom` (emits both SPDX and CycloneDX). Verified as the current standard
  options 2026-08-19; pick one in Phase 4 and record it as an ADR.
- **Release artefacts** carry SHA256 checksums and are traceable to the exact source commit
  (Phase 4 exit criterion).

---

## 7. Testing

Summarised here; the authority is `docs/TESTING_STRATEGY.md`.

Unit tests per handler; integration tests over a corpus of real files; property tests
(`proptest`) for round-trip and idempotence invariants; fuzzing (`cargo-fuzz`) per handler
with committed seed corpora; differential testing against mat2 and ExifTool. Every
fuzz-discovered bug gets a regression test before it is marked fixed.

The invariant worth stating here because it is architectural: **`strip` is idempotent**
(stripping twice equals stripping once, byte for byte) and **`inspect(strip(x))` reports no
removable metadata**. These are the properties stage 5's verification pass depends on.

---

## 8. Cross-platform considerations

- **Paths.** Use `Path`/`OsStr` throughout; never assume UTF-8 filenames. Filenames are
  attacker-influenced too, and a filename can itself carry identifying information — worth
  a warning in `show` output, since a scrubbed file named `IMG_survivor_address.jpg` is not
  scrubbed in any meaningful sense.
- **Atomic replace.** `rename` semantics differ across platforms, particularly on Windows
  where an open handle can block replacement. In-place mode must handle this explicitly
  rather than assuming POSIX behaviour.
- **Permissions and ownership.** Output must not be created world-readable. Copy-out mode
  should create files with restrictive permissions by default; on Windows the ACL model
  differs and needs its own handling.
- **Live/amnesic systems (Tails, Qubes-Whonix).** Read-only system filesystem, limited
  writable space, no network. **Temp-file placement deliberately ignores `TMPDIR`** and writes
  beside the destination instead — `rename` is atomic only within a filesystem, and a temp copy
  of a sensitive file landing on an unexpected mount would be a serious leak in itself. Both
  distributions are Debian-based, which informs Phase 4 packaging priorities. **Validated in
  Phase 3 by a filesystem-constraints matrix, not by booting either system** (ADR-0043); the
  distributions themselves remain untested, and the matrix must not be reported as if they
  were.
- **Case-insensitive filesystems** (default macOS, Windows) can collide `photo.jpg` and
  `Photo.JPG` in batch output. Detect and refuse rather than silently overwrite.

---

## 9. Explicitly out of scope for the architecture right now

- Any networking stack, in any form, in any phase (ADR-0004).
- GUI framework specifics beyond naming Tauri v2 as the Phase 5 direction (verified stable at
  v2.10.1, 2026-03-04; independently audited by Radically Open Security during its beta/RC
  cycle; MIT/Apache-2.0 — all to be re-verified at Phase 5 start, which is a long way off).
- Third-party plugin loading (ADR-0011).
- Content-level transformation: OCR, redaction of visible content, image re-encoding,
  writing-style anonymisation. strypt removes metadata; it does not alter the payload.
- Multi-threading. Batch parallelism is an obvious later win, but Phase 1 should be correct
  and deterministic first. Any parallelism must preserve deterministic output ordering.
