# INSTRUCTIONS.md — build, test, and lint

**This file is the source of truth for commands.** [`CLAUDE.md`](CLAUDE.md) points here
rather than duplicating commands, so they cannot drift apart. **Update this file in the same
commit as any change to the build, test, or lint workflow.**

---

> ## ⚠️ Phase 1 — PDF works; the image handlers do not exist yet
>
> **Every command below was executed and verified on 2026-08-19.** `strypt show` and
> `strypt strip` work on PDF files. JPEG, PNG, and WebP are detected and reported as
> unsupported — they are not processed and are never passed through untouched.

## Prerequisites

| Tool | Purpose | Notes |
|---|---|---|
| Rust stable | build, test, lint | Edition 2024. Stable was **1.97.1** (released 2026-07-16) as of 2026-08-19. |
| Rust nightly | fuzzing only | `cargo-fuzz` requires nightly. |
| `cargo-fuzz` | fuzzing | `cargo install cargo-fuzz` — **Linux/macOS only**, x86-64 and aarch64. Not supported on Windows. |
| `cargo-deny` | supply-chain gate | `cargo install cargo-deny` |
| ExifTool, mat2 | differential testing | Optional locally, required for release verification. **Never runtime dependencies.** Verified working 2026-08-19 with ExifTool 13.55 and mat2 0.15.0. |
| `qpdf` | fixture validation | Optional. `qpdf --check` confirms a generated PDF fixture is structurally sound. |
| Python 3 | fixture generation | Optional. Only needed to regenerate `corpus/`. |

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

## Running strypt

```sh
cargo run -p strypt-cli -- show corpus/pdf/info-dictionary.pdf
cargo run -p strypt-cli -- strip corpus/pdf/info-dictionary.pdf
./target/debug/strypt --help
```

`show` reports what is in a file and never writes. `strip` writes a sanitised copy beside the
input as `<name>.stripped.<ext>`; the original is untouched unless you pass `--in-place`.

```sh
strypt show FILE...                    # report metadata; exits 1 if any is found
strypt show --show-values FILE...      # include the values, not only the field names
strypt show --json FILE...             # machine-readable, stable schema
strypt strip FILE...                   # write sanitised copies
strypt strip --in-place FILE...        # replace the originals
strypt strip --output-dir OUT FILE...  # write copies into OUT
strypt strip --force FILE...           # overwrite an existing output file
strypt strip --recursive DIR           # descend into a directory
strypt strip --max-bytes 1048576 FILE  # refuse inputs above this size
```

### Exit codes

**Stable across releases** — scripts and pre-commit hooks depend on them.

| Code | Meaning |
|---|---|
| 0 | Success, and `show` found nothing removable |
| 1 | `show` found metadata, or `strip` had at least one file fail |
| 2 | Usage error |
| 3 | A file could not be read or written |
| 4 | A file's format has no handler in this release |
| 5 | Output failed post-strip verification and was discarded — strypt does not trust its own result. Treat this as a bug report, not as a bad file |

When a batch hits several of these, the most serious one wins.

## Fuzzing

Requires nightly and a Unix-like platform. Run from the fuzz crate, which is its own
workspace:

```sh
cd crates/strypt-core/fuzz
mkdir -p corpus/pdf corpus/detect               # libFuzzer's working corpus; git-ignored
cargo +nightly fuzz list                                          # pdf, detect
cargo +nightly fuzz run pdf corpus/pdf seeds/pdf                  # run until stopped
cargo +nightly fuzz run pdf corpus/pdf seeds/pdf -- -max_total_time=300
cargo +nightly fuzz run detect corpus/detect seeds/detect -- -runs=100000
cargo +nightly fuzz cmin pdf corpus/pdf                           # minimise the corpus
```

Two directories, deliberately. **`seeds/<target>/` is the curated corpus and is committed**;
`corpus/<target>/` is where libFuzzer writes what it discovers, reaches thousands of
machine-generated files within minutes, and is git-ignored. libFuzzer writes to the first
directory given and reads the rest.

The PDF seeds are copies of `corpus/pdf/`; refresh them after regenerating the fixtures.

A crash writes its input to `crates/strypt-core/fuzz/artifacts/<target>/`. Reproduce with:

```sh
cargo +nightly fuzz run pdf artifacts/pdf/crash-<hash>
```

## Test fixtures

```sh
python3 corpus/tools/make_pdf_fixtures.py        # regenerate; deterministic
qpdf --check corpus/pdf/info-dictionary.pdf      # confirm a fixture is structurally sound
```

Fixtures are generated rather than collected so that the "no real personal data" rule in
`docs/TESTING_STRATEGY.md` §3 is structural. Every fixture is documented in
`corpus/MANIFEST.md`.

## Differential testing

Compares strypt against implementations with years of accumulated format knowledge. Run
before every release; not a per-commit gate.

```sh
mkdir -p /tmp/strypt-diff && cp corpus/pdf/*.pdf /tmp/strypt-diff/
./target/debug/strypt strip /tmp/strypt-diff/*.pdf

# What ExifTool still sees in strypt's output. [File] and [ExifTool] tags are filesystem
# facts about the copy, not metadata inside it.
exiftool -s -G /tmp/strypt-diff/*.stripped.pdf | grep -vE '^\[(File|ExifTool)\]'

# What mat2 still sees.
mat2 --show /tmp/strypt-diff/*.stripped.pdf
```

Anything either tool still reports is **either a bug or a documented limitation**, and that
decision must be explicit and recorded — never made by silence.

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
