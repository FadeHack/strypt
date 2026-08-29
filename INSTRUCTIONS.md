# INSTRUCTIONS.md — build, test, and lint

**This file is the source of truth for commands.** [`CLAUDE.md`](CLAUDE.md) points here
rather than duplicating commands, so they cannot drift apart. **Update this file in the same
commit as any change to the build, test, or lint workflow.**

---

> ## ⚠️ Phase 1 complete (2026-08-22) · Phase 2 in progress
>
> **Every command below was executed and verified**, the Phase 1 ones on 2026-08-19, the
> Office Open XML ones on 2026-08-23, the OpenDocument ones on 2026-08-24, the TIFF ones on
> 2026-08-26, and the GIF ones the same day. `strypt show` and `strypt strip` work on PDF, JPEG,
> PNG, WebP, TIFF, GIF, HEIF, AVIF, SVG, JPEG XL, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, and `.odp`. Every
> other format is detected and reported as unsupported — never processed, and never passed through
> untouched.
>
> Phase 2 opened 2026-08-23 (ADR-0027). OOXML and OpenDocument are its first two format groups;
> the third is five image tranches (ADR-0032), of which TIFF, GIF, HEIF+AVIF and SVG are complete,
> each with a clean sustained fuzz run. JPEG XL has landed and owes that run; audio/video is not
> started. See
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
| ImageMagick | fixture validation | Optional. `magick identify` confirms a JPEG, PNG, WebP, or GIF fixture still decodes; `magick compare -metric AE` confirms stripping changed no pixels. |
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
cargo build -p strypt        # CLI only
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
cargo run -p strypt -- show corpus/pdf/info-dictionary.pdf
cargo run -p strypt -- strip corpus/pdf/info-dictionary.pdf
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
mkdir -p corpus/pdf corpus/jpeg corpus/png corpus/webp corpus/tiff corpus/gif corpus/heif corpus/bmff corpus/svg corpus/jxl corpus/detect corpus/ooxml corpus/odf corpus/zip
cargo +nightly fuzz list                                          # pdf, jpeg, png, webp, tiff, gif, heif, svg, jxl, bmff, detect, ooxml, odf, zip
cargo +nightly fuzz run pdf corpus/pdf seeds/pdf                  # run until stopped
cargo +nightly fuzz run pdf corpus/pdf seeds/pdf -- -max_total_time=300
cargo +nightly fuzz run jpeg corpus/jpeg seeds/jpeg -- -max_total_time=300
cargo +nightly fuzz run png corpus/png seeds/png -- -max_total_time=300
cargo +nightly fuzz run webp corpus/webp seeds/webp seeds/webp/malformed -- -max_total_time=300
cargo +nightly fuzz run tiff corpus/tiff seeds/tiff seeds/tiff/malformed -- -max_total_time=300
cargo +nightly fuzz run gif corpus/gif seeds/gif seeds/gif/malformed -- -max_total_time=300
cargo +nightly fuzz run heif corpus/heif seeds/heif seeds/heif/malformed -- -max_total_time=300
cargo +nightly fuzz run svg corpus/svg seeds/svg seeds/svg/malformed -- -max_total_time=300
cargo +nightly fuzz run jxl corpus/jxl seeds/jxl seeds/jxl/malformed -- -max_total_time=300
cargo +nightly fuzz run bmff corpus/bmff seeds/bmff -- -max_total_time=300
cargo +nightly fuzz run detect corpus/detect seeds/detect -- -runs=100000
cargo +nightly fuzz run ooxml corpus/ooxml seeds/ooxml -- -max_total_time=300
cargo +nightly fuzz run odf corpus/odf seeds/odf -- -max_total_time=300
cargo +nightly fuzz run zip corpus/zip seeds/zip -- -max_total_time=300
cargo +nightly fuzz cmin pdf corpus/pdf                           # minimise the corpus
```

Two directories, deliberately. **`seeds/<target>/` is the curated corpus and is committed**;
`corpus/<target>/` is where libFuzzer writes what it discovers, reaches thousands of
machine-generated files within minutes, and is git-ignored. libFuzzer writes to the first
directory given and reads the rest.

The PDF, JPEG, PNG, WebP, TIFF, GIF, HEIF, OOXML, and ODF seeds are copies of `corpus/pdf/`,
`corpus/jpeg/`, `corpus/png/`, `corpus/webp/`, `corpus/tiff/`, `corpus/gif/`, `corpus/heif/`,
`corpus/ooxml/`, and `corpus/odf/` (including their `malformed/` subdirectories); refresh them
after regenerating the fixtures.

**Give `corpus/<target>/` first and never `seeds/` first.** libFuzzer writes its discoveries into
whichever directory it is handed first, so reversing them fills the committed corpus with hundreds
of hash-named machine-generated files. That happened on 2026-08-27 to `seeds/heif/`, `seeds/bmff/`
and `seeds/detect/`, and had to be undone by hand.

`seeds/zip/` holds the same packages as `seeds/ooxml/` and `seeds/odf/`, deliberately. The `zip`
target exercises the container layer on its own (ADR-0028), and its job is to explore *outward*
from a real archive into malformed ones — a container fuzzer seeded only with hand-written stubs
never reaches the structures a real producer writes. The ODF packages earn their place there
beyond variety: they are the only seeds whose first entry is stored and whose others are
deflated, which is a shape no OOXML package has.

**The `zip` target needs the `fuzzing` feature**, which is why `fuzz/Cargo.toml` enables it. It
opens a hidden, non-public entry point to the internal ZIP parser (`src/fuzzing.rs`); no
front-end may use it.

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
./scripts/fuzz-sustained.sh                       # all ten targets, 2h each, in parallel
./scripts/fuzz-sustained.sh -d 300                # short; exercises the same analysis path
./scripts/fuzz-sustained.sh -d 28800 pdf          # 8h on PDF alone
./scripts/fuzz-sustained.sh -d 14400 png webp     # 4h each, in parallel
./scripts/fuzz-sustained.sh -d 43200 ooxml zip    # 12h each on the Phase 2 container targets
./scripts/fuzz-sustained.sh -d 43200 tiff detect  # 12h each; group 3 tranche 1's debt, cleared 2026-08-26
./scripts/fuzz-sustained.sh -d 43200 gif detect   # 12h each; group 3 tranche 2's debt, cleared 2026-08-27
./scripts/fuzz-sustained.sh -d 43200 heif bmff detect  # 12h each; group 3 tranche 3's debt, cleared 2026-08-27
./scripts/fuzz-sustained.sh -h                    # options

# Detached, so it survives closing the terminal, with the machine held awake:
nohup caffeinate -ims ./scripts/fuzz-sustained.sh -d 43200 pdf jpeg png webp \
  > /tmp/strypt-fuzz.out 2>&1 &
./scripts/fuzz-status.sh                          # watch it; Ctrl-C exits the viewer only
```

The default target list is **all twelve** — `pdf jpeg png webp tiff gif heif bmff ooxml odf zip
detect`. The runner has now failed to know about a new target three times, so check it before
trusting a run to have covered what you asked for: `ooxml` and `zip` were added on 2026-08-23,
`odf` with Phase 2 group 2, `tiff` on 2026-08-25, `gif` on 2026-08-26, and `heif` and `bmff` on
2026-08-27. Each was rejected as an unknown name until it was added,
so **a run predating a target's addition covered fewer targets than its command line suggests**,
silently.

**On macOS, wrap a long run in `caffeinate -ims`** or the machine will sleep partway through and
deliver a fraction of the budgeted CPU-hours without saying so — which is the one thing that
makes a sustained run's headline number a lie, since budget matching delivery is what says
nothing died (`docs/THREAT_MODEL.md` §7.7). Check `pmset -g`: a default laptop sleeps after a
minute or two idle, so this is not a corner case. `-i` covers idle sleep, `-m` disk idle sleep,
and `-s` system sleep — the last **only on AC power**, so keep it plugged in. Passing the script
to `caffeinate` as its child, as above, ties the assertion to the run's lifetime and releases it
when the run ends.

**`caffeinate` does not survive closing the lid.** Clamshell sleep overrides it unless the
machine is on AC with an external display. Leave the lid open, and sanity-check `ELAPSED` in
`fuzz-status.sh` a minute in: if it is not advancing, the machine slept and the run is void.

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

### Watching a run in progress

The runner redirects each target to its own log and prints nothing until every target finishes,
so a twelve-hour run and a hung one look identical from the outside. From a second terminal:

```sh
./scripts/fuzz-status.sh                          # most recent run, refresh every 10s
./scripts/fuzz-status.sh -n 30                    # gentler refresh
./scripts/fuzz-status.sh target/fuzz-runs/<name>  # a specific run
tail -F target/fuzz-runs/<name>/pdf.log           # raw libFuzzer output for one target
```

It is a viewer only: Ctrl-C stops watching, not the run, and the run's `summary.md` and exit
code — not this table — are what answer the exit criterion. Its artefact column counts only
files newer than the run's `.started` marker, because `artifacts/` still holds triaged findings
from August 2026 and counting those would flag a long-fixed crash on every run.

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
python3 corpus/tools/make_tiff_fixtures.py       # regenerate; deterministic
python3 corpus/tools/make_gif_fixtures.py        # regenerate; carries its own LZW encoder, so every fixture really decodes
python3 corpus/tools/make_heif_fixtures.py       # regenerate; embeds one recorded AV1 and one recorded HEVC codestream, so every fixture really decodes
python3 corpus/tools/make_svg_fixtures.py        # regenerate; every fixture is a real SVG that Rsvg can open
python3 corpus/tools/make_jxl_fixtures.py        # regenerate; the codestream is a hand-written header stub — no encoder is needed
python3 corpus/tools/make_ooxml_fixtures.py      # regenerate; embeds corpus/jpeg/exif-gps.jpg, so run that tool first
python3 corpus/tools/make_odf_fixtures.py        # regenerate; embeds the JPEG and PNG fixtures, so run those tools first
qpdf --check corpus/pdf/info-dictionary.pdf      # confirm a fixture is structurally sound
magick identify corpus/jpeg/exif-gps.jpg         # confirm a JPEG fixture still decodes
magick identify corpus/png/exif-gps.png          # confirm a PNG fixture still decodes
magick identify corpus/webp/all-metadata.webp    # confirm a WebP fixture still decodes
magick identify corpus/gif/animated-loop.gif     # confirm a GIF fixture still decodes, frames and all
heif-convert corpus/heif/clean.avif /tmp/x.png   # confirm a HEIF fixture decodes through libheif, not only ImageMagick
exiftool corpus/jpeg/exif-gps.jpg                # confirm it carries what the manifest says
unzip -l corpus/ooxml/everything.docx            # confirm an OOXML fixture is a readable package
unzip -l corpus/odf/everything.odt               # first entry must be a stored `mimetype` (ODF Part 2 §3.3)
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

### Office Open XML differential

```sh
cargo build --release                    # the script refuses to run against a debug binary path
./scripts/ooxml-differential.sh
```

Compares **what metadata survives in each tool's output**, not whether the two produce the same
file. They do not and should not: mat2 rebuilds an OOXML package from a whitelist of parts it
recognises, while strypt copies through every part it had no reason to change. A byte comparison
would report a difference on every file and tell you nothing.

Both sides are read with **mat2's own reader**, which takes strypt's report out of the loop
entirely — a handler that forgot to remove something cannot pass by claiming it did. ExifTool is
the second opinion and the one that reads into the embedded pictures.

Two fields are excluded from the comparison, each for a stated reason rather than because it was
inconvenient, and both are values *both* tools normalise to a constant: `date_time` (the ZIP
entry timestamp) and `create_system` (the host byte — mat2 recognises only 2 and 3, and reports
strypt's constant 0, which is what Word writes, as "Weird").

Expect one file to be skipped: **mat2 refuses `presentation.pptx`**, because
`ppt/commentAuthors.xml` is not on its content-type whitelist. That is recorded rather than
silently passed over (`docs/THREAT_MODEL.md` §7.6).

Last run 2026-08-23 against mat2 0.15.0 and ExifTool 13.55: no gaps across 13 fixtures.

### OpenDocument differential

```sh
cargo build --release                    # the script refuses to run against a debug binary path
./scripts/odf-differential.sh
```

The same shape as the OOXML one and the same two exclusions, against `corpus/odf`. mat2's
OpenDocument path removes more than its Office one — `meta.xml`, `settings.xml`, `Thumbnails/`,
`Configurations2/`, `ObjectReplacements/`, and annotations and tracked changes outright — so this
is the stricter of the two comparisons.

Expect one file to be skipped: **mat2 refuses `embedded-object.ods`**, because its part patterns
are anchored at the package root and an embedded chart's `Object 1/settings.xml` matches neither
its keep list nor its omit list. Recorded rather than silently passed over
(`docs/THREAT_MODEL.md` §7.7).

Last run 2026-08-24 against mat2 0.15.0 and ExifTool 13.55: no gaps across 14 fixtures.

### TIFF differential

```sh
cargo build --release
./scripts/tiff-differential.sh
```

A different shape from the package-format differentials, because TIFF is the one format strypt
**rebuilds rather than edits** (ADR-0033). mat2's default TIFF path re-renders the pixels through
GdkPixbuf while strypt copies the compressed data across, so the two outputs cannot resemble each
other and a byte comparison would say nothing. What is compared is what metadata survives in each,
read by ExifTool.

**`-u` is load-bearing** and the script passes it: ExifTool omits tags it does not recognise
unless asked, and an unrecognised vendor tag is exactly the case the handler's allow-list exists
to catch. The script also greps the output bytes for the fixtures' `SYNTHETIC` markers and for
the `PRESERVED-` payload, so a clean result does not depend on either tool's reader alone.

Last run 2026-08-25 against mat2 0.15.0 and ExifTool 13.55: no gaps across 10 fixtures — zero
tags surviving on either side. Verified able to fail: the same filter over the *unstripped*
fixtures reports 9, 6, 2, and 1 surviving tags and names the leaked values.

### GIF differential

```sh
cargo build --release
./scripts/gif-differential.sh
```

mat2's GIF path re-renders the image through GdkPixbuf where strypt removes whole blocks and
copies the rest through, so as with TIFF the outputs cannot resemble each other and what is
compared is what metadata survives in each.

**Two things in that script are decisions rather than bookkeeping, and both are written into it.**
The `[File]` group is filtered tag by tag rather than as a whole, because ExifTool files a GIF's
comment under `[File] Comment` — the blanket exclusion the TIFF script uses would hide this
format's most common leak. And `AnimationIterations` is excluded because strypt keeps the loop
count on purpose; the script pairs that exclusion with a check asserting the loop count really
does survive, so it is a declared choice rather than a softened sweep.

Last run 2026-08-26 against mat2 0.15.0 and ExifTool 13.55: no gaps across 14 fixtures, zero tags
surviving strypt. On `plain-text.gif` **strypt removes more than mat2 does** — ExifTool still
reports the plain-text block in mat2's output. Verified able to fail: the same filter over the
*unstripped* fixtures reports surviving tags on 8 of the 14, including 3 on `xmp.gif`.

### HEIF and AVIF differential

```sh
cargo build --release
./scripts/heif-differential.sh
```

Three things in that script are decisions rather than bookkeeping, and all three are written into
it. **mat2's default mode declines HEIC** — "HEIC files can't be thoroughly cleaned. Use lightweight
mode instead." — so the script falls back to `mat2 -L` and prints which mode ran; comparing against
a refusal would be comparing against nothing. **`PERL_HASH_SEED` is pinned**, because ExifTool walks
atoms in Perl hash order and on some fixtures that order decides whether it refuses to write at all,
making the same bytes pass or fail run to run. And **the ICC check asks ImageMagick, not ExifTool**,
which reports no ICC profile for either format.

The script runs its own able-to-fail check on every invocation, against the unstripped fixtures,
and refuses to report a sweep if they do not light the filter up.

Last run 2026-08-27 against mat2 0.15.0 and ExifTool 13.55: no gaps across all 17 fixtures, zero
tags surviving strypt, every output still decoding through libheif, and **0 differing pixels** on
every one.

### SVG differential

```sh
cargo build --release
./scripts/svg-differential.sh
```

**SVG inverts the comparison every other format here makes.** mat2 re-renders the document through
Rsvg, so it removes strictly more — the accessibility text and the script strypt will not touch —
while destroying ids, grouping, animation and the author's editable structure. The script therefore
checks both directions: nothing survives strypt that does not survive mat2, and the drawing itself
crossed strypt byte for byte.

One exclusion in it is a decision rather than bookkeeping: `Title` and `Desc` are filtered out
because strypt keeps the accessibility text and mat2 removes it, and the exclusion is paired with a
check asserting both really do survive.

Last run 2026-08-28 against mat2 0.15.0 and ExifTool 13.55: no gaps across 14 fixtures, zero tags
surviving strypt, `PRESERVED-SHAPE` intact in every output. Verified able to fail: against a
pass-through binary it reports 19 gaps.

### JPEG XL differential

```sh
cargo build --release
./scripts/jxl-differential.sh
```

Both tools edit the container here rather than re-rendering — mat2's `JXLParser` shells out to
ExifTool — so the comparison is fair in both directions, and **the reverse direction is the one
worth reading**. The script walks top-level boxes with its own Python walker, because ExifTool
names nothing at all for a `jbrd`, a `free`, a `skip` or a `jxli`, and a box that survives one tool
and not the other would otherwise be invisible.

**No JPEG XL decoder is used or needed**: strypt never enters the codestream, ExifTool does not
either, and the fixtures' codestream is a header stub. The "still the same image" check is
therefore structural — the output must still identify as JXL at the dimensions it went in with.

Last run 2026-08-29 against mat2 0.15.0 and ExifTool 13.55: no gaps across 13 fixtures, and
ExifTool leaving `jumb`, `jbrd`, `jxli`, `free` and `skip` where strypt removes them. Verified able
to fail: against a pass-through binary it reports 28 gaps.

### OpenDocument LibreOffice import validation

```sh
brew install --cask libreoffice          # macOS; any install putting soffice on PATH will do
cargo build --release
./scripts/odf-libreoffice-validation.sh
```

Answers a different question from the differential. The differential asks *what metadata
survives*; this asks *does the stripped package still open in the application that writes this
format* — the check `docs/THREAT_MODEL.md` §7.7 recorded as owed. Each fixture is stripped,
loaded by LibreOffice, and re-exported to flat XML, which forces a full import of every part
rather than a header sniff; then the document bodies of the original and the stripped copy are
compared, to catch a file that opens cleanly but lost content.

**`soffice` exits 0 even when the import fails**, so the script gates on whether an output file
appeared, never on the exit status. Verified against `corpus/odf/malformed/truncated.odt`.

Point it at other files with `CORPUS=`, which is how the real-producer LibreOffice documents were
covered:

```sh
CORPUS=/path/to/odf/files ./scripts/odf-libreoffice-validation.sh
```

`EXPECT_BODY_DIFF` in the script lists the fixtures whose body is *supposed* to change, each with
its reason. An unexpected difference fails, and so does an unexpected match — a fixture that
stopped changing means strypt stopped removing something.

**This is not the GUI repair-prompt check.** Headless import cannot raise a dialog, so opening a
few stripped files by hand in LibreOffice is a separate, manual step — and it is **re-owed
whenever the handler changes**, since the script cannot cover it. Last done 2026-08-24: seven
stripped files opened in LibreOffice 26.2.5.2, none prompting for repair
(`docs/THREAT_MODEL.md` §7.7).

Last run 2026-08-24 against LibreOffice 26.2.5.2 on macOS/arm64: 14 fixtures and 2 real-producer
documents, no failures.

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
