# INSTRUCTIONS.md - build, test, and lint

The source of truth for commands. Update it in the same commit as any change to a command.
Why a rule exists lives in [`docs/DECISIONS.md`](docs/DECISIONS.md); results live in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §7.

## Prerequisites

| Tool                                                              | Needed for                                                                                                                                          |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| rustup                                                            | everything. `rust-toolchain.toml` pins the compiler and rustup installs it on first use; the MSRV is `rust-version` in `Cargo.toml` (ADR-0013) |
| Rust nightly, `cargo install cargo-fuzz`                         | fuzzing. Linux and macOS only                                                                                                                       |
| `cargo install cargo-deny --locked --version 0.20.2`            | supply-chain checks; the version CI runs                                                                                                            |
| Python 3                                                          | fixtures, fuzz analysis, README images                                                                                                              |
| mat2, ExifTool                                                    | differential testing. **Never runtime dependencies**                                                                                           |
| ffmpeg, libheif, `webpinfo`, `webp-pixbuf-loader`, LibreOffice | individual differentials; see [Differential testing](#differential-testing)                                                                           |
| ImageMagick, `qpdf`                                              | performance measurement and fixture checks                                                                                                          |

## Build, test, lint

```sh
cargo build                      # whole workspace
cargo build --release
cargo test --all-features        # what CI runs, on Linux, macOS and Windows
cargo test -p strypt             # CLI contract tests only
cargo test jpeg                  # tests matching a name
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

`--all-features` compiles the `fuzzing` module; without it clippy and the tests skip a module.

## Running strypt

Installing a release without Rust: [README](README.md#install).

```sh
cargo run -p strypt -- show corpus/pdf/info-dictionary.pdf
strypt show FILE...                    # report metadata; never writes
strypt show --show-values FILE...      # include values, not only field names
strypt show --json FILE...             # machine-readable
strypt strip FILE...                   # write FILE.stripped.EXT beside each input
strypt strip --in-place FILE...        # replace the originals
strypt strip --output-dir OUT FILE...  # write copies into OUT
strypt strip --force FILE...           # overwrite an existing output
strypt strip --recursive DIR           # descend into a directory; symlinks are not followed
strypt strip --max-bytes 1048576 FILE  # refuse larger inputs
```

### Exit codes

Stable across releases; scripts depend on them. When a batch hits several, the most serious wins.

| Code | Meaning                                                                       |
| ---- | ----------------------------------------------------------------------------- |
| 0    | Success, and `show` found nothing removable                                  |
| 1    | `show` found metadata, or `strip` had a file fail                         |
| 2    | Usage error                                                                   |
| 3    | A file could not be read or written                                           |
| 4    | A file's format has no handler                                                |
| 5    | Output failed post-strip verification and was discarded — report it as a bug |

## Full pre-commit check

What CI runs:

```sh
cargo fmt --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --all-features && \
./scripts/check-no-network.sh && \
cargo deny check && \
./scripts/prove-gates.sh
```

CI also builds at the MSRV (`rustup toolchain install 1.95`, then `cargo +1.95 build --all-features`), runs the [filesystem matrix](#filesystem-constraints-matrix) on Linux, and
fuzzes every target for 60 seconds. Enable the local pre-commit hook once per clone:

```sh
git config core.hooksPath .githooks
```

## Fuzzing

From the fuzz crate, which is its own workspace:

```sh
cd crates/strypt-core/fuzz
cargo +nightly fuzz list
T=pdf; mkdir -p corpus/$T && cargo +nightly fuzz run $T corpus/$T seeds/$T -- -max_total_time=300
cargo +nightly fuzz run $T artifacts/$T/crash-<hash>   # reproduce a crash
cargo +nightly fuzz cmin $T corpus/$T                   # minimise
```

**Give `corpus/<target>` first, never `seeds/`.** libFuzzer writes discoveries into the first
directory; `seeds/` is the committed corpus ([`seeds/README.md`](crates/strypt-core/fuzz/seeds/README.md)),
`corpus/` is git-ignored. Crash inputs land in `artifacts/<target>/`.

### Sustained runs

The certification bar is ADR-0044's: 24 CPU-hours per handler and a saturated coverage curve.
From the repository root:

```sh
./scripts/fuzz-sustained.sh -h                    # options; default is every target, 2h each
./scripts/fuzz-sustained.sh -d 86400 pdf jpeg     # 24h each, in parallel
nohup caffeinate -ims ./scripts/fuzz-sustained.sh -d 86400 pdf > /tmp/strypt-fuzz.out 2>&1 &
./scripts/fuzz-status.sh                          # live view; Ctrl-C stops the viewer, not the run
python3 scripts/fuzz-tally.py                     # which handlers certify, which owe a run
python3 scripts/fuzz-plateau.py [target...]       # saturated or PUNCTUATED, per curve
```

- On macOS, `caffeinate -ims` on AC power, lid open — a sleeping machine delivers a fraction of
  the budget silently. If `ELAPSED` in `fuzz-status.sh` stops advancing, the run is void.
- Quote CPU-hours **delivered**, never budgeted. They differ when a target stops early.
- Read a `summary.md` from before 2026-09-11 with `fuzz-plateau.py`; its `plateau` column uses
  ADR-0014's superseded rule.
- The runner's target list must include every target in `fuzz list`; check after adding one.

Each run writes `summary.md`, `cov-<target>.tsv` and `<target>.log` to `target/fuzz-runs/<timestamp>/`.
Stopping early is safe: discoveries are already in `corpus/`.

## Test fixtures

Generated, so no fixture carries real personal data ([`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) §3).
Each is documented in [`corpus/MANIFEST.md`](corpus/MANIFEST.md). Refresh the matching `seeds/`
copies after regenerating.

```sh
for t in pdf jpeg png webp tiff gif heif svg jxl flac wav mp3 ogg mp4 ooxml odf; do
  python3 corpus/tools/make_${t}_fixtures.py
done                                             # ooxml and odf embed JPEG and PNG fixtures, so they run last
qpdf --check corpus/pdf/info-dictionary.pdf      # structurally sound
magick identify corpus/gif/animated-loop.gif     # still decodes
heif-convert corpus/heif/clean.avif /tmp/x.png   # decodes through libheif
exiftool corpus/jpeg/exif-gps.jpg                # carries what the manifest says
unzip -l corpus/odf/everything.odt               # first entry must be a stored `mimetype`
```

### Real-producer corpus

Real files carrying real names and live GPS, kept out of the repository; only the build script
and manifests are committed.

```sh
cd real-producer-corpus
python3 build_real_corpus.py                  # 102 fixtures; the first run clones three upstreams
python3 build_real_corpus.py --with-browser   # + one Chrome-encoded WebP; opt-in, browsers churn
```

Every crash, hang or OOM needs a regression test and its input in the corpus before the fix is
accepted ([`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) §2.6).

## Differential testing

Before every release, not per commit. Build `--release` first; every script defaults to
`target/release/strypt` (override with `STRYPT=`), refuses to run without its tools, and reports
what survives each tool's output — a gap is a bug or a documented limitation, never silence.

| Script                                                                                                                         | Also needs                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `ooxml-differential.sh`, `odf-differential.sh`, `tiff-differential.sh`, `gif-differential.sh`, `svg-differential.sh` | —                                                                           |
| `jxl-differential.sh`                                                                                                        | python3                                                                      |
| `heif-differential.sh`                                                                                                       | libheif's `heif-convert`                                                    |
| `flac-differential.sh`, `wav-differential.sh`, `mp3-differential.sh`, `ogg-differential.sh`, `mp4-differential.sh`   | ffmpeg, python3                                                              |
| `webp-differential.sh [DIR]`                                                                                                 | `webpinfo`, and `webp-pixbuf-loader` — without it mat2 cannot read WebP |

```sh
cargo build --release && ./scripts/mp4-differential.sh
```

PDF, JPEG and PNG have no script:

```sh
mkdir -p /tmp/strypt-diff && cp corpus/pdf/*.pdf /tmp/strypt-diff/
./target/release/strypt strip /tmp/strypt-diff/*.pdf
exiftool -s -G /tmp/strypt-diff/*.stripped.pdf | grep -vE '^\[(File|ExifTool)\]'
mat2 --show /tmp/strypt-diff/*.stripped.pdf
```

### LibreOffice import validation

```sh
cargo build --release && ./scripts/odf-libreoffice-validation.sh
CORPUS=/path/to/odf/files ./scripts/odf-libreoffice-validation.sh
```

Needs `soffice` on PATH. It checks that stripped packages still import, not that no repair
prompt appears; opening a few by hand is re-owed whenever the handler changes.

## Supply-chain checks

Hard merge gates (ADR-0045):

```sh
cargo deny check                 # advisories, licenses, bans, sources
cargo deny check advisories      # or one at a time
./scripts/check-no-network.sh    # ADR-0004: fails on any networking crate, transitive included
cargo tree -i reqwest            # who pulls a crate in (expect: nothing)
```

A red `advisories` run with no change here is a new advisory or yank: fix it, or add a reasoned
`ignore` to `deny.toml`.

### Proving the gates fail

```sh
./scripts/prove-gates.sh         # ~20s; needs network
```

Plants one violation per check in a throwaway copy — a networking crate, a duplicate, a
wildcard, a copyleft licence, a git source, a vulnerability, a yanked crate — and requires each
gate to fail with its own diagnostic. CI runs it. If a case fails untouched, check its external
assumption first: the yank case needs `chacha20 0.10.1` still yanked.

## Filesystem-constraints matrix

Linux, non-root with passwordless sudo, `dosfstools` and `exfatprogs`. Cases:
[`docs/TESTING_STRATEGY.md`](docs/TESTING_STRATEGY.md) §2.7.

```sh
cargo build -p strypt && ./scripts/fs-matrix.sh [BINARY]
./scripts/prove-fs-matrix.sh     # five io.rs mutants; each must be caught
```

On macOS, in Docker:

```sh
docker build -t strypt-fsm - <<'EOF'
FROM rust:1-bookworm
RUN apt-get update -qq && apt-get install -y -qq sudo dosfstools exfatprogs python3 git \
 && chmod -R a+w /usr/local/rustup /usr/local/cargo && useradd -m u \
 && echo 'u ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/u && git config --system --add safe.directory '*'
USER u
EOF
docker run --rm --privileged -v "$PWD":/src:ro -w /src -e CARGO_TARGET_DIR=/tmp/t strypt-fsm \
  sh -c 'cargo build -q -p strypt && scripts/fs-matrix.sh /tmp/t/debug/strypt && scripts/prove-fs-matrix.sh'
```

## Release builds

ADR-0050. Release binaries come only from CI's `release` workflow, which builds each target twice
and fails unless the two match. A local release build embeds your home directory's paths.

```sh
scripts/build-release.sh aarch64-apple-darwin   # -> target/release-artifacts/strypt-<version>-<target>
gh workflow run release.yml                      # the gate on all five targets; publishes nothing
gh workflow run release.yml -f prove=true        # drops a remap; each job passes only if the gate catches it
scripts/sbom.sh out x86_64-unknown-linux-musl    # -> out/strypt-<version>-<target>.cdx.json (ADR-0054)
```

`sbom.sh` needs `cargo install cargo-cyclonedx --version 0.5.9 --locked`, the version `release.yml` pins.

Cutting a release:

1. Bump `version` in `Cargo.toml` and the `strypt-core` requirement in `crates/strypt/Cargo.toml`,
   refresh both `Cargo.lock`s (the fuzz crate has its own), date CHANGELOG's `[Unreleased]`, and
   update the version in README's install section.
2. Push the tag `v<version>`. `release.yml` drafts the release; review it, then publish it.
3. `cargo publish -p strypt-core`, then `cargo publish -p strypt`.
4. In [homebrew-strypt](https://github.com/FadeHack/homebrew-strypt), set the four URLs and SHA256s
   in `Formula/strypt.rb` from `SHA256SUMS`, push, then:

```sh
brew update && brew upgrade fadehack/strypt/strypt && brew test fadehack/strypt/strypt
brew audit --strict --online fadehack/strypt/strypt
```

5. `gh workflow run install.yml` runs README's install steps on fresh runners. Update the file
   names and `BUILT_FROM` in it first.

## Performance measurement

The numbers in [`docs/PRD.md`](docs/PRD.md) §9. Needs a release binary and ImageMagick.

```sh
cargo build --release && ./scripts/measure-performance.sh
REPS=15 BATCH=3000 ./scripts/measure-performance.sh
BIN=path/to/strypt ./scripts/measure-performance.sh   # any other build
gh workflow run perf.yml                              # musl against glibc on Linux (ADR-0050)
```

## README images

Re-run after any change to CLI output; it renders `docs/assets/demo.svg` from the release binary
and strips both README images with strypt.

```sh
python3 scripts/render-demo.py
```
