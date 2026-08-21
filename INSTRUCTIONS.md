# INSTRUCTIONS.md — build, test, and lint

**This file is the source of truth for commands.** [`CLAUDE.md`](CLAUDE.md) points here
rather than duplicating commands, so they cannot drift apart. **Update this file in the same
commit as any change to the build, test, or lint workflow.**

---

> ## ⚠️ Phase 1 — all four handlers work; the phase is not finished
>
> **Every command below was executed and verified on 2026-08-19.** `strypt show` and
> `strypt strip` work on PDF, JPEG, PNG, and WebP files. Every other format is detected and
> reported as unsupported — never processed, and never passed through untouched. What remains
> in the phase is corpus, fuzzing, and performance work, not handlers; see
> [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Prerequisites

| Tool | Purpose | Notes |
|---|---|---|
| Rust stable | build, test, lint | Edition 2024. Stable was **1.97.1** (released 2026-07-16) as of 2026-08-19. |
| Rust nightly | fuzzing only | `cargo-fuzz` requires nightly. |
| `cargo-fuzz` | fuzzing | `cargo install cargo-fuzz` — **Linux/macOS only**, x86-64 and aarch64. Not supported on Windows. |
| `cargo-deny` | supply-chain gate | `cargo install cargo-deny` |
| ExifTool, mat2 | differential testing | Optional locally, required for release verification. **Never runtime dependencies.** Verified working 2026-08-19 with ExifTool 13.55 and mat2 0.15.0. |
| `webp-pixbuf-loader`, `webpinfo` | WebP differential | Required for `scripts/webp-differential.sh`. Without the pixbuf loader mat2 cannot read WebP and the comparison is meaningless; the script refuses to run. Verified 2026-08-21 with loader 0.2.7 and libwebp 1.6.0. |
| Chrome or Chromium | optional corpus fixture | Only for `build_real_corpus.py --with-browser`. Verified 2026-08-21 with Chrome 151. |
| `qpdf` | fixture validation | Optional. `qpdf --check` confirms a generated PDF fixture is structurally sound. |
| ImageMagick | fixture validation | Optional. `magick identify` confirms a JPEG, PNG, or WebP fixture still decodes; `magick compare -metric AE` confirms stripping changed no pixels. |
| Python 3 | fixture generation | Optional. Only needed to regenerate `corpus/`. |
| `cwebp` | WebP base bitstreams | **Not needed.** The two base bitstreams are committed as literals inside `make_webp_fixtures.py`; `cwebp 1.6.0` produced them once. Only needed to replace them. |

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
mkdir -p corpus/pdf corpus/jpeg corpus/png corpus/webp corpus/detect  # libFuzzer's working corpus; git-ignored
cargo +nightly fuzz list                                          # pdf, jpeg, png, webp, detect
cargo +nightly fuzz run pdf corpus/pdf seeds/pdf                  # run until stopped
cargo +nightly fuzz run pdf corpus/pdf seeds/pdf -- -max_total_time=300
cargo +nightly fuzz run jpeg corpus/jpeg seeds/jpeg -- -max_total_time=300
cargo +nightly fuzz run png corpus/png seeds/png -- -max_total_time=300
cargo +nightly fuzz run webp corpus/webp seeds/webp seeds/webp/malformed -- -max_total_time=300
cargo +nightly fuzz run detect corpus/detect seeds/detect -- -runs=100000
cargo +nightly fuzz cmin pdf corpus/pdf                           # minimise the corpus
```

Two directories, deliberately. **`seeds/<target>/` is the curated corpus and is committed**;
`corpus/<target>/` is where libFuzzer writes what it discovers, reaches thousands of
machine-generated files within minutes, and is git-ignored. libFuzzer writes to the first
directory given and reads the rest.

The PDF, JPEG, PNG, and WebP seeds are copies of `corpus/pdf/`, `corpus/jpeg/`, `corpus/png/`,
and `corpus/webp/` (including their `malformed/` subdirectories); refresh them after
regenerating the fixtures.

A crash writes its input to `crates/strypt-core/fuzz/artifacts/<target>/`. Reproduce with:

```sh
cargo +nightly fuzz run pdf artifacts/pdf/crash-<hash>
```

### Sustained runs

**The commands above are smoke tests, not the Phase 1 exit criterion.** They prove a target
still builds and runs. Exit criterion 2 in `docs/ROADMAP.md` asks for a sustained run, and
ADR-0014 asks for two conditions together: a per-handler CPU-hour budget **and** a coverage
plateau — no new edge coverage in the final 25% of the run. Use the runner, from the
repository root:

```sh
./scripts/fuzz-sustained.sh                       # all five targets, 2h each, in parallel
./scripts/fuzz-sustained.sh -d 300                # short; exercises the same analysis path
./scripts/fuzz-sustained.sh -d 28800 pdf          # 8h on PDF alone
./scripts/fuzz-sustained.sh -d 14400 png webp     # 4h each, in parallel
./scripts/fuzz-sustained.sh -h                    # options
```

Targets run **in parallel, one process each**, so wall time is the `-d` value no matter how
many targets are selected — but CPU-hours are `-d × targets`, and the script prints that
**budget** before it starts. It exits non-zero if any target produced a crash artefact.

The summary reports CPU-hours **budgeted** and **delivered** separately, and you want the
second one. They diverge whenever a target stops early — on a crash, or because you stopped the
run by hand. The first sustained run was budgeted 40.00 and delivered 37.79, because PDF stopped
at 5h47m; the second was budgeted 60.00 and delivered **30.42**, because it was ended early and
PDF had already died at 47 minutes. ADR-0014's criterion is stated in CPU-hours, so quote
delivered when arguing that a run met it, and never quote the budget.

Each run writes to `target/fuzz-runs/<timestamp>/` (git-ignored):

| File | Contents |
|---|---|
| `summary.md` | Per-target `cov`, `ft`, corpus size, exec/s, when coverage last increased, whether ADR-0014's plateau condition holds, and crash count |
| `cov-<target>.tsv` | The coverage curve — `elapsed_seconds<TAB>cov`, one row per increase |
| `<target>.log` | Full libFuzzer output, every line prefixed with elapsed seconds |

**The curves are the deliverable, not the duration.** ADR-0014's 100 CPU-hours per handler was
set before any parser existed and the ADR says so explicitly: it is a hypothesis to be replaced
by measurement. A target reporting `NO — still climbing` has not failed — it has not yet run
long enough for its number to be set.

Stopping a run early is safe. libFuzzer writes each discovery to `corpus/<target>/` as it finds
it, so the next run resumes from what has been found rather than starting over.

## Performance measurement

Produces the numbers in `docs/PRD.md` §9. Needs a **release** binary — the script refuses a
debug one, because debug Rust is slow enough to understate the tool by an order of magnitude.

```sh
cargo build --release
./scripts/measure-performance.sh                  # 10 reps per case, 1000-file batch
REPS=15 BATCH=3000 ./scripts/measure-performance.sh
```

Requires ImageMagick, which it uses to synthesise realistically-sized inputs; the fixtures in
`corpus/` are deliberately tiny and would measure little but process startup. The script warns
when machine load is high relative to core count — numbers taken under load are pessimistic,
which is the direction nobody thinks to double-check.

## Test fixtures

```sh
python3 corpus/tools/make_pdf_fixtures.py        # regenerate; deterministic
python3 corpus/tools/make_jpeg_fixtures.py       # regenerate; deterministic
python3 corpus/tools/make_png_fixtures.py        # regenerate; reuses the JPEG tool's TIFF builder
python3 corpus/tools/make_webp_fixtures.py       # regenerate; reuses the JPEG tool's TIFF builder
qpdf --check corpus/pdf/info-dictionary.pdf      # confirm a fixture is structurally sound
magick identify corpus/jpeg/exif-gps.jpg         # confirm a JPEG fixture still decodes
magick identify corpus/png/exif-gps.png          # confirm a PNG fixture still decodes
magick identify corpus/webp/all-metadata.webp    # confirm a WebP fixture still decodes
exiftool corpus/jpeg/exif-gps.jpg                # confirm it carries what the manifest says
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

### WebP differential

**mat2's WebP path needs a GdkPixbuf WebP loader**, absent on many machines. Where it is
missing, mat2 fails on the *original* fixtures as well as on strypt's output, so the comparison
says nothing and must be recorded as not run rather than as a pass. That was the state from
2026-08-19 until 2026-08-21.

```sh
brew install webp-pixbuf-loader          # macOS; Debian/Ubuntu: apt install webp-pixbuf
gdk-pixbuf-query-loaders | grep -i webp  # must print a line, or mat2 cannot read WebP

./scripts/webp-differential.sh                     # the 14 synthetic fixtures
./scripts/webp-differential.sh /path/to/other/dir  # any directory of .webp files
```

The script exits 2 without running if the loader is missing — a clean sweep that both tools
failed identically is worse than no result, because it looks like evidence. Exit 0 means no tag
mat2 removes survives in strypt's output; exit 1 lists the gaps.

Two expected notes in its output are **not** strypt findings: mat2 re-encodes through GdkPixbuf,
so it flattens animations to a single frame, and it can expose `ALPH` bitstream parameters the
input did not have. Both are recorded in `docs/THREAT_MODEL.md` §7.4.

### Real-producer corpus

Files from real cameras, converters and producers, kept **out of this repository** because they
carry real names, a device serial and live GPS coordinates
([`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) §3). The build script and manifests are
committed; the files are fetched on demand.

```sh
cd real-producer-corpus
python3 build_real_corpus.py                  # 102 fixtures; clones upstreams into .cache/ once
python3 build_real_corpus.py --with-browser   # + a WebP encoded by the local browser (103)
```

The first run needs network to clone three public repositories; later runs are offline, since
`acquire()` only clones what is absent. **This is corpus tooling, not strypt** — ADR-0004's
no-network rule constrains the shipped dependency graph, not a developer script that fetches
test data.

`--with-browser` is opt-in on purpose. It drives headless Chrome through
`canvas.toDataURL('image/webp')` to get a genuinely browser-encoded file, but browsers
auto-update, so its bytes would otherwise churn the committed `MANIFEST.csv` on every
contributor's machine. Without a browser installed it prints `SKIP` and carries on. `prune()`
never deletes the result, because regenerating it needs a browser the next machine may lack.

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
