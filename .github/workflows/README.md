# CI workflows

**Empty stub — Phase 0 deliverable, not yet built.** See `docs/ROADMAP.md` Phase 0.

CI is the project's real enforcement layer (`.claude/HOOKS.md`), so this directory being
empty is currently the largest gap between strypt's stated guarantees and its actual ones.

## Required before Phase 0 is complete

| Workflow | Gate | Platforms |
|---|---|---|
| `ci.yml` — fmt, clippy `-D warnings`, test | hard | Linux, macOS, Windows |
| `ci.yml` — MSRV build | hard | Linux |
| `no-network.yml` — resolved dependency-graph check | **hard, from day one** | Linux |
| `deny.yml` — `cargo deny check` | advisory now, hard from Phase 3 | Linux |
| `fuzz-smoke.yml` — short run per target | hard, from Phase 1 | Linux |
| `fuzz-long.yml` — sustained run | declined (ADR-0046) | — |
| `differential.yml` — vs mat2 and ExifTool | scheduled + pre-release | Linux |

## Toolchain pinning — required

CI **must** use the version pinned in `rust-toolchain.toml` (a Phase 0 deliverable), never a
floating `stable`. Rust 1.97.1 was a point release fixing an LLVM miscompilation; for a tool
whose parsers process hostile input, the compiler is part of the trusted computing base, and
a release binary must never depend on which toolchain happened to be installed on the
building machine. The MSRV job is the deliberate exception — it pins the MSRV from ADR-0013
(currently 1.95).

Phase 0 exit criterion 6 requires proving CI actually honours the pin, by confirming the
build log reports the pinned version rather than a floating one.

Notes that will save time later:

- **The no-network check must walk the fully resolved graph** (`cargo metadata --format-version 1`
  over all targets and features), not just the manifests. Catching only direct dependencies
  would miss the realistic case, which is a networking crate arriving transitively.
- **`cargo-fuzz` requires nightly and does not support Windows** (verified 2026-08-19). Fuzz
  jobs are Linux/macOS; Windows is covered by the other layers.
- **Every gate must be proven to fail** when deliberately violated — Phase 0 exit criterion 3.
  The procedure is in `INSTRUCTIONS.md`.
