<img src="https://github.com/FadeHack/strypt/raw/HEAD/docs/assets/banner.svg?sanitize=true" alt="strypt: remove hidden metadata from files before you share them" width="100%">

Photos carry GPS coordinates and camera serial numbers. PDFs carry author names, organisation
names, and editing timestamps. Word documents carry all of that plus the editing sessions they
were written in, and the photographs pasted into them arrive with their own GPS still attached.
None of it is visible in a normal viewer, and all of it survives to publication. strypt finds it
and strips it out.

A single self-contained binary. Memory-safe Rust. **No network access in any code path.**

> **Status: `0.1.0`, the first release. No external audit.** Read
> [`docs/KNOWN_LIMITATIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/KNOWN_LIMITATIONS.md) before relying on strypt.
> Phases 0–3 are complete. Phase 4 ships binaries and a Homebrew tap; install tests on clean
> machines are still to come ([`docs/ROADMAP.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/ROADMAP.md)).

[![CI](https://github.com/FadeHack/strypt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/FadeHack/strypt/actions/workflows/ci.yml)
[![no-network](https://github.com/FadeHack/strypt/actions/workflows/no-network.yml/badge.svg?branch=main)](https://github.com/FadeHack/strypt/actions/workflows/no-network.yml)
[![cargo-deny](https://github.com/FadeHack/strypt/actions/workflows/deny.yml/badge.svg?branch=main)](https://github.com/FadeHack/strypt/actions/workflows/deny.yml)
[![licence](https://img.shields.io/badge/licence-MIT_OR_Apache--2.0-blue)](#licence)

<img src="https://github.com/FadeHack/strypt/raw/HEAD/docs/assets/demo.svg?sanitize=true" alt="strypt strip removes a photo's GPS, serial number and author, and strypt show then finds nothing">

<sub>A synthetic test photo from <code>corpus/</code>; its GPS, serial number and author are invented.</sub>

## Formats

| Kind | Formats |
|---|---|
| Images | JPEG, PNG, WebP, TIFF, GIF, HEIF/AVIF (`.heic`, `.heif`, `.avif`), SVG, JPEG XL |
| Documents | PDF; Office Open XML (`.docx`, `.xlsx`, `.pptx`); OpenDocument (`.odt`, `.ods`, `.odp`) |
| Audio and video | FLAC, WAV, MP3, Ogg (`.ogg`, `.opus`, `.oga`), MP4/M4A (`.mp4`, `.m4v`, `.m4a`, `.m4b`) |

Photographs inside a document are stripped by the image handlers. Every other format is reported
as unsupported and never passed through. What each handler removes, keeps, and refuses:
[`docs/THREAT_MODEL.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/THREAT_MODEL.md) §7.

**For other formats, use [mat2](https://github.com/jvoisin/mat2) or
[ExifTool](https://exiftool.org/)**: both mature, actively maintained, and covering far more
formats. Where mat2 is the better tool for a file strypt does support,
[`docs/KNOWN_LIMITATIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/KNOWN_LIMITATIONS.md#where-mat2-is-the-better-choice) says so.

## Why trust the output

Evidence, not an audit: each point links to where it is checked.

- **It fails closed.** A file strypt cannot fully process produces no output, and an unsupported
  format is reported as unsupported, never passed through.
- **It re-reads its own output.** Every stripped file is detected and inspected afresh, and
  discarded (exit 5) if anything the handler recognises survived. That proves consistency, not
  omniscience ([`docs/THREAT_MODEL.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/THREAT_MODEL.md) §4.8).
- **It cannot phone home.** CI rejects any dependency that can open a network connection,
  transitive ones included, and [proves that check fails](https://github.com/FadeHack/strypt/blob/HEAD/INSTRUCTIONS.md#proving-the-gates-fail)
  on every push (ADR-0004).
- **No `unsafe` in strypt's own code**, enforced by the compiler; dependencies are checked
  against RustSec advisories on every push and weekly.
- **Every parser is fuzzed.** 20 of 22 fuzz targets meet the bar of 24 CPU-hours with saturated
  coverage (ADR-0044); `jxl` and `png` do not yet. All 22 run for a minute on every push.
- **Every format is compared against mat2 and ExifTool**, and each difference is recorded as a
  bug or a deliberate choice ([`docs/THREAT_MODEL.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/THREAT_MODEL.md) §7).

## What strypt will *not* do

- It does not redact. A PDF with a black box drawn over text still contains that text.
- It does not change what your document *says*, or anonymise your writing style.
- It does not clean filenames, and `budget_final_jsmith_home.pdf` identifies you regardless.
- It does not protect against metadata a platform adds after you upload.
- It cannot defeat fingerprinting. Encoder quirks and camera sensor noise can identify a
  device from pixel data alone, with no metadata present at all.
- **No tool can guarantee complete metadata removal from complex formats.** strypt will never
  claim otherwise.

## Before you publish

1. **Rename the file.** strypt keeps the name you gave it, plus `.stripped`.
2. **Look at what is visible**: faces, screens, reflections, street signs, and the text itself.
3. **Check the stripped copy** with `strypt show`, and read what `strip` said it kept.
4. **Upload only the stripped copy.** A platform may store the file you send even when it shows a
   re-encoded one.

**If strypt calls a file clean and it still carries metadata, that is a security vulnerability.**
Report it privately through [`SECURITY.md`](https://github.com/FadeHack/strypt/blob/HEAD/SECURITY.md), not in a public issue.

## Install

**Homebrew**, on macOS or Linux:

```sh
brew install fadehack/strypt/strypt
```

Naming the formula in full is how Homebrew 6 and later trust a third-party tap. The
[formula](https://github.com/FadeHack/homebrew-strypt/blob/main/Formula/strypt.rb) installs the
release binary below, checked against its SHA256.

**Or download the binary.** It is one file, with nothing else to install.

| Platform | File |
|---|---|
| Linux x86_64 (static) | `strypt-0.1.0-x86_64-unknown-linux-musl` |
| Linux arm64 (static) | `strypt-0.1.0-aarch64-unknown-linux-musl` |
| macOS, Apple Silicon | `strypt-0.1.0-aarch64-apple-darwin` |
| macOS, Intel | `strypt-0.1.0-x86_64-apple-darwin` |
| Windows x86_64 | `strypt-0.1.0-x86_64-pc-windows-msvc.exe` |

```sh
F=strypt-0.1.0-x86_64-unknown-linux-musl    # your file from the table
curl -LO https://github.com/FadeHack/strypt/releases/download/v0.1.0/$F
curl -LO https://github.com/FadeHack/strypt/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing     # must print "<file>: OK"; older macOS: shasum -a 256 -c
chmod +x $F && ./$F --version                # then rename it strypt, in a directory on your PATH
```

The checksum catches a damaged download, but it comes from the same page as the binary. To check
that the binary was built by this repository's CI from a public commit, sign in to the
[GitHub CLI](https://cli.github.com/) with `gh auth login`, then run
`gh attestation verify $F -R FadeHack/strypt`. It needs a GitHub account and `gh` 2.49 or later;
Debian's own `gh` package is older.

On Windows, compare `Get-FileHash strypt-0.1.0-x86_64-pc-windows-msvc.exe` in PowerShell with its
line in `SHA256SUMS`. PowerShell prints the hash in capitals, which does not matter.

The binaries are not code-signed ([ADR-0051](https://github.com/FadeHack/strypt/blob/HEAD/docs/DECISIONS.md)). Windows may show a SmartScreen
warning. On macOS, a file downloaded in a browser must be allowed once in System Settings →
Privacy & Security; one fetched with `curl` does not. Never turn Gatekeeper off to run it.

**Tails and Qubes-Whonix**: use the static Linux x86_64 binary. There is no `.deb`, because Tails
keeps only packages from Debian (ADR-0052). On Qubes-Whonix, keep the binary in the app qube's home
folder. On Tails, keep it in the Persistent folder: Tails 7 mounts it without `noexec`, which was
read from Tails's code and reproduced on Linux, not tried on Tails itself. Tails already includes
mat2 and Metadata Cleaner, which cover more formats than strypt.

With a Rust toolchain, `cargo install strypt` builds it instead. `strypt-cli` on crates.io is the
same tool under its original name, yanked on 2026-08-23 (ADR-0026); replace it with `strypt`.

Tested in CI on Linux, macOS and Windows. On Windows, output takes the permissions of the folder
it is written to ([`docs/KNOWN_LIMITATIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/KNOWN_LIMITATIONS.md#everywhere)).

## Usage

```sh
strypt show photo.jpg                  # report what metadata is present; changes nothing
strypt strip photo.jpg                 # write a sanitised copy beside the original
strypt strip --output-dir out/ *.pdf   # write copies elsewhere
strypt strip --in-place report.docx    # overwrite the original (opt-in, never the default)
strypt show --json --recursive ./docs  # machine-readable output for scripting
```

A failure is loud: a file strypt cannot fully process produces no output. Commands and exit
codes: [`INSTRUCTIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/INSTRUCTIONS.md).

`show` exits non-zero when anything is left to deal with, so a publishing script or CI job can
refuse to ship metadata:

```sh
strypt show --recursive public/images > /dev/null   # 1: metadata found; 4: a file strypt cannot check
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/KNOWN_LIMITATIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/KNOWN_LIMITATIONS.md) | What strypt keeps, cannot see, and refuses, per format |
| [`docs/THREAT_MODEL.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/THREAT_MODEL.md) | Adversaries, protections, and limits |
| [`docs/PRD.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/PRD.md) | Problem, users, requirements, and where strypt differs from mat2 |
| [`docs/ARCHITECTURE.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/ARCHITECTURE.md) | System design, dependencies, security architecture |
| [`docs/ROADMAP.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/ROADMAP.md) | Phases, deliverables, exit criteria |
| [`docs/DECISIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/DECISIONS.md) | Architecture decision records |
| [`docs/TESTING_STRATEGY.md`](https://github.com/FadeHack/strypt/blob/HEAD/docs/TESTING_STRATEGY.md) | How correctness is verified |
| [`CONTRIBUTING.md`](https://github.com/FadeHack/strypt/blob/HEAD/CONTRIBUTING.md) | How to contribute, and [how strypt is developed](https://github.com/FadeHack/strypt/blob/HEAD/CONTRIBUTING.md#how-strypt-is-developed) |
| [`SECURITY.md`](https://github.com/FadeHack/strypt/blob/HEAD/SECURITY.md) | Reporting vulnerabilities |
| [`INSTRUCTIONS.md`](https://github.com/FadeHack/strypt/blob/HEAD/INSTRUCTIONS.md) | Build, test, and lint commands |

## Licence

Dual-licensed under [MIT](https://github.com/FadeHack/strypt/blob/HEAD/LICENSE-MIT) or [Apache-2.0](https://github.com/FadeHack/strypt/blob/HEAD/LICENSE-APACHE), at your option.
Contributions are accepted under the same dual licence, per the Apache-2.0 contribution clause,
unless you state otherwise.
