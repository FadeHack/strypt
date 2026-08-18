# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog 2.0.0](https://keepachangelog.com/en/2.0.0/) (released
2026-06-07; verified 2026-08-19), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Project-specific conventions:**

- Security fixes go under `Security` and **must state which versions and formats were
  affected**, so users can determine whether files they already published need re-checking.
  For a metadata-removal tool this is the primary purpose of the entry — see
  [`SECURITY.md`](SECURITY.md).
- Any change to what a format handler removes goes under `Changed` or `Fixed`, never buried
  in a refactor entry. Users make publication decisions based on this.
- Entries are written for users, not for maintainers. "Fixed EXIF thumbnail surviving in
  progressive JPEGs" — not "refactor jpeg.rs".

## [Unreleased]

### Added

- Phase 0 foundation documents: PRD, architecture, roadmap, threat model, decision log,
  and testing strategy.
- Contribution, security, and code of conduct policies.
- Dual MIT / Apache-2.0 licensing.
- `.claude/` tooling configuration, including hooks intended to catch violations of the
  no-network and `unsafe` constraints early.
- Cargo workspace scaffolding: `strypt-core` (no logic yet) and `strypt-cli` (stub binary),
  with `unsafe_code = "forbid"` workspace-wide and panic-freedom lints scoped to the core
  crate per ADR-0006.
- `rust-toolchain.toml` pinning the compiler explicitly, so release builds never depend on
  whichever toolchain a machine happens to have.
- `scripts/check-no-network.sh`, the authoritative ADR-0004 gate: walks the fully resolved
  dependency graph across all features and fails on any networking crate, transitive ones
  included. Verified to fire on a deliberate violation.
- CI workflows (build/test on Linux, macOS, and Windows; fmt; clippy; MSRV; no-network;
  cargo-deny) and a `.githooks/pre-commit` gate covering edits made outside Claude Code.
- `deny.toml` supply-chain policy: allowed licences, banned networking crates, crates.io as
  the only permitted source.

### Fixed

- The MSRV CI job would have silently built with the pinned toolchain rather than the MSRV,
  because `rust-toolchain.toml` outranks a default-setting toolchain action in rustup's
  precedence order. It now sets `RUSTUP_TOOLCHAIN` explicitly and asserts the version in use.
  Recorded as ADR-0015.
- `cargo-deny` reported success while its `bans` check was failing, because the job was
  advisory-only. The deterministic checks (`bans`, `licenses`, `sources`) are now hard gates;
  `advisories` stays advisory until Phase 3. Recorded as ADR-0016.
- `strypt-cli` declared `strypt-core` by path with no version — a wildcard dependency, and
  unpublishable to crates.io. Now versioned explicitly.
- Bumped `actions/checkout` to v5; v4 targets a deprecated Node runtime.

### Notes

- No software has been released. There is nothing installable yet, and no version has been
  tagged. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for what Phase 1 will contain.

[Unreleased]: https://github.com/FadeHack/strypt/commits/main
