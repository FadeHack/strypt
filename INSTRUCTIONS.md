# INSTRUCTIONS.md — build, test, and lint

**This file is the source of truth for commands.** [`CLAUDE.md`](CLAUDE.md) points here
rather than duplicating commands, so they cannot drift apart. **Update this file in the same
commit as any change to the build, test, or lint workflow.**

---

> ## ⚠️ Phase 0 — the workspace exists, but there is no functionality
>
> The Cargo workspace is scaffolded and **every command below was executed and verified on
> 2026-08-19**. But `strypt-core` contains no logic and `strypt-cli` is a stub that prints a
> notice and exits 2, so `cargo run` does nothing useful yet.
>
> Commands referencing fuzz targets, `cargo-deny`, or real CLI subcommands are recorded in
> advance and are **not** yet runnable — `cargo-fuzz` and `cargo-deny` are not installed
> locally, and no fuzz targets exist. They are marked below.

## Prerequisites

| Tool | Purpose | Notes |
|---|---|---|
| Rust stable | build, test, lint | Edition 2024. Stable was **1.97.1** (released 2026-07-16) as of 2026-08-19. |
| Rust nightly | fuzzing only | `cargo-fuzz` requires nightly. |
| `cargo-fuzz` | fuzzing | `cargo install cargo-fuzz` — **Linux/macOS only**, x86-64 and aarch64. Not supported on Windows. |
| `cargo-deny` | supply-chain gate | `cargo install cargo-deny` |
| ExifTool, mat2 | differential testing | Optional locally, required for release verification. **Never runtime dependencies.** |

Check your toolchain:

```sh
rustc --version          # expect a current stable, edition 2024 capable
cargo --version
rustup show              # confirm the active toolchain is what you think it is
```

> **Toolchain versions (verified 2026-08-19 against `static.rust-lang.org/dist/channel-rust-stable.toml`,
> the authoritative rustup channel manifest):** stable is **1.97.1**, released 2026-07-16
> (rustc build dated 2026-07-14). 1.97.0 shipped 2026-07-09; 1.97.1 is a point release fixing
> an LLVM miscompilation. Under the MSRV policy in ADR-0013 (`stable - 2`), **the MSRV is
> currently 1.95**.
>
> Note that `releases.rs` reported stale data (stable 1.96.0) when checked on the same day.
> Prefer the channel manifest or `rust-lang/rust` release tags as the authoritative source.
>
> **CI must not trust whatever toolchain happens to be on a developer's machine.** A
> `rust-toolchain.toml` pinning an explicit rustup-managed version is a Phase 0 deliverable —
> see `docs/ROADMAP.md`. The 1.97.1 point release is a concrete illustration of why: a
> compiler miscompilation reaching a release build of a parser that handles hostile input is
> exactly the class of problem an unpinned toolchain lets through silently.

## Build

```sh
cargo build                      # debug build, whole workspace
cargo build --release            # optimised
cargo build -p strypt-core       # library only
cargo build -p strypt-cli        # CLI only
```

## Test

```sh
cargo test                       # whole workspace
cargo test -p strypt-core        # library only
cargo test -- --nocapture        # show output from passing tests
cargo test jpeg                  # run tests matching a name
```

## Lint and format

Both are **required gates** — CI runs them with the same flags.

```sh
cargo fmt                        # apply formatting
cargo fmt --check                # verify without changing (what CI runs)
cargo clippy --all-targets --all-features -- -D warnings
```

## Fuzzing

**Not yet runnable — Phase 1.** No fuzz targets exist and `cargo-fuzz` is not
installed locally. Requires nightly and a Unix-like platform.

```sh
cargo +nightly fuzz list                          # list available targets
cargo +nightly fuzz run jpeg                      # run until stopped
cargo +nightly fuzz run jpeg -- -max_total_time=300   # 5-minute smoke run
cargo +nightly fuzz run jpeg -- -runs=100000          # bounded by iterations
cargo +nightly fuzz cmin jpeg                     # minimise the corpus
```

A crash writes its input to `fuzz/artifacts/<target>/`. Reproduce with:

```sh
cargo +nightly fuzz run jpeg fuzz/artifacts/jpeg/crash-<hash>
```

**Every crash, hang, or OOM requires a regression test and the offending input added to the
corpus before the fix is accepted** ([`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md)
§2.6). Hangs and OOMs count as findings, ranked equally with crashes.

## Supply-chain checks

**`cargo-deny` is not installed locally** (`cargo install cargo-deny`). CI runs it via the
cargo-deny action; `deny.toml` is already configured.

```sh
cargo deny check                 # all checks
cargo deny check advisories      # RustSec advisories only
cargo deny check licenses        # licence compatibility
cargo deny check bans            # banned crates, including all networking crates
```

## The no-network gate

The project's most important check (ADR-0004), and the one piece of enforcement that is
already real:

```sh
./scripts/check-no-network.sh
```

It walks the fully resolved dependency graph across all features and fails on any networking
crate, including transitive ones. To inspect the graph manually:

```sh
cargo tree                                    # full resolved tree
cargo tree -i reqwest                         # who pulls in a given crate (expect: nothing)
cargo tree --prefix none --format '{p}' | sort -u
```

**To verify the gate itself still works**, deliberately break it on a throwaway branch:

```sh
git switch -c test/network-gate
cargo add ureq -p strypt-core
./scripts/check-no-network.sh    # must exit 1
git checkout crates/strypt-core/Cargo.toml && rm -f Cargo.lock
git switch - && git branch -D test/network-gate
```

Verified 2026-08-19: this flagged `ureq`, its declaration, and `rustls` pulled in
transitively — then passed cleanly again after reverting. If it ever does not fail, the gate
is broken and that is a priority-one bug.

An untested gate provides confidence without protection. Re-run this check whenever the CI
configuration changes.

## Enabling the local git hooks

Once per clone. Catches edits made outside Claude Code, which the `.claude/` hooks cannot see:

```sh
git config core.hooksPath .githooks
```

## Running strypt locally

**Phase 0: the binary is a stub that prints a notice and exits 2.** These are the Phase 1
commands:

```sh
cargo run -p strypt-cli -- show test.jpg
cargo run -p strypt-cli -- strip test.jpg
cargo run -p strypt-cli -- --help
```

## Full pre-commit check

What CI runs, in order:

```sh
cargo fmt --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test && \
./scripts/check-no-network.sh && \
cargo deny check          # once cargo-deny is installed
```

Plus, if a parser changed:

```sh
cargo +nightly fuzz run <target> -- -max_total_time=300
```

See [`CLAUDE.md`](CLAUDE.md) §9 for the full definition of done.
