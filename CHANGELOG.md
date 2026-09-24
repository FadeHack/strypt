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

## [0.2.0] - 2026-09-24

### Fixed

- `--recursive` skipped an unreadable entry inside a folder without saying so, so any files in it
  went unmentioned. It is now reported, and the run exits 3. A named pipe in the tree was read,
  which waits forever; it is now skipped and reported (ADR-0061).
- `strypt strip` gave FLAC's kept audio MD5 as "reason not recognised by this version of the CLI". It
  now says it is kept because anyone holding the file can recompute it (ADR-0038). The CLI's and the
  GUI's wording now come from one file (ADR-0060).
- The no-network check read the features `tokio` defines rather than those enabled, so it refused
  any `tokio`, even one that cannot open a socket. It now refuses `tokio` only with `net`, `full`,
  `io-std` or `process` enabled, as ARCHITECTURE §5.2 says, and `prove-gates.sh` proves both sides.

### Changed

- **strypt has a desktop app**, for dropping files onto a window: a `.dmg` for macOS, an AppImage
  for Linux and a portable `.exe` for Windows, all unsigned. It is built on egui rather than Tauri,
  which resolves an HTTP client into the dependency graph and needs WebKit2GTK on Linux, so it fails
  strypt's no-network gate (ADR-0058). Phase 5 is complete (ADR-0063).
- **The no-network check is now per crate.** The library and CLI still admit no networking-capable
  crate at all; only the GUI may carry the Linux accessibility and Wayland event loops, and only
  by those routes (ADR-0058 decision 3).

### Added

- `scripts/build-release.sh --gui` builds `strypt-gui` reproducibly, the first step to shipping it as
  a `.dmg`, an AppImage and a portable `.exe`, unsigned (ADR-0062). The release workflow gates it on
  five targets, Linux on glibc. macOS builds now link with
  `-Wl,-S`, because a toolchain path in the linker's debug map made the GUI's `LC_UUID` differ
  between machines. This changes the macOS CLI binaries' hashes too.
- Clippy runs in CI on macOS and Windows as well as Linux, since platform-gated code is linted only
  where it compiles. It found one warning in Windows-only code.
- `scripts/package-macos.sh` makes one universal `strypt.app`, signed ad-hoc as a whole and verified,
  inside a `.dmg`. The release workflow packages it twice and compares the two apps (ADR-0062).
- `scripts/package-linux.sh` makes an AppImage for each Linux architecture with `appimagetool` 1.9.1
  and runtime 20251108, both checked against pinned SHA-256s. It embeds no update URL. The release
  workflow packages each twice and fails unless they are byte-identical, which they are (ADR-0062).
- The Linux GUI is built inside Ubuntu 22.04, so it runs on Ubuntu 22.04, Debian 12, Mint 21 and
  newer. Built on Ubuntu 24.04 it needed glibc 2.39 and did nothing when opened on 22.04 (ADR-0062).
- `strypt-mark`, an unpublished crate that draws the mark and writes it as ICO, ICNS or PNG, so no
  icon file is committed.
- Releases carry the GUI: the `.dmg`, both AppImages and the Windows `.exe`, each with its own SBOM,
  listed in `SHA256SUMS` and attested like the CLI binaries. The `.dmg`'s SBOM covers both Mac
  architectures (ADR-0054). `KNOWN_LIMITATIONS.md` lists what the app cannot do, among them Linux
  older than glibc 2.35 and the Open files dialog's possible entry in recent files, and what was
  tried with a screen reader: VoiceOver on macOS reads the app, and no other screen reader was tried.
  A screen reader now meets the app's content before its two caveats, and hears how sensitive each
  removed detail is rather than its `!!` mark.
- `strypt-gui.exe` shows strypt's mark in Explorer, drawn at build time from the code that draws
  the window icon, through `winresource` on a Windows host (ADR-0062).
- `strypt-gui` opens without a console window on Windows, and if its window cannot open, it says so
  in a dialog rather than on a stderr nobody sees.
- `strypt-gui` takes dropped folders. It says how many files and folders it found and where copies
  will go, and writes nothing until asked. Each file gets a row, as does every link, special file
  or unreadable entry it skipped, and a folder's unsupported files share one card that lists them.
- `--recursive` names each symbolic link or special file it skips on stderr, and with `--json` as
  an entry with the new status `"skipped"`. The exit code is unchanged for these.
- `strypt_core::walk`: the folder walk, moved out of the CLI so every front-end shares it.
- `strypt-gui` shows, under each cleaned file, what was found, what was removed and what was kept and
  why, by field name only, with the CLI's `!!`/`!` sensitivity marks and every note. An empty result
  says so, and every file carries the caveats that filenames and visible content are untouched, and
  that finding nothing does not mean a file is clean.
- `strypt-gui` has its own look: a wordmark and icon drawn in code, a paper-and-ink palette in light
  and dark, and a large drop area that lights up while files are held over it. Each file gets a card
  listing what was removed in plain words ("Where it was made", "Who made it"), struck through one
  kind at a time, with the CLI's field-level list under Technical details. It follows the system's
  light or dark setting on macOS and Windows; on Linux it starts light, because the X11 backend it
  prefers reports no theme. Fonts are egui's bundled ones only.
- `strypt-gui` can save cleaned copies into a chosen folder instead of beside each original.
- `strypt_core::strip_bytes_to_file`, so a front-end that inspects a file first reads it once.
- An Open files button in `strypt-gui`, beside drag-and-drop, through the `rfd` crate. On Linux the
  GUI starts on X11 when it can, because file drops do not arrive under Wayland (ADR-0059).
- `strypt-gui`: drop any number of files, and each gets a row
  saying cleaned, not cleaned, or unsupported, with the CLI's reason. Stripping runs off the window's
  thread. A test holds that only a written file is shown as cleaned; another holds the files it
  writes identical to the CLI's in bytes, name and permissions.
- `strypt_core::stripped_path`: the `*.stripped.*` naming, moved out of the CLI so every
  front-end shares it. The CLI's output names are unchanged.

## [0.1.2] - 2026-09-21

### Fixed

- **PDF: a document whose page tree names one object more than once is now refused.** Rewriting
  such a file dropped an object — in the file that found this, its only page — and strypt reported
  success. Affects every release up to and including `0.1.1`. A refused file is unchanged, so no
  output was ever wrong; the risk was a saved copy missing a page (ADR-0057).

## [0.1.1] - 2026-09-18

### Added

- **Homebrew tap**: `brew install fadehack/strypt/strypt` installs the 0.1.0 release binary on
  macOS and Linux ([FadeHack/homebrew-strypt](https://github.com/FadeHack/homebrew-strypt)).
- **An SBOM for each release binary**, `<file>.cdx.json` in CycloneDX: every crate built into it,
  with version and licence, and a checksum for each from crates.io, so a scanner can check a binary against advisories published
  after its release. Listed in `SHA256SUMS`; from the next release (ADR-0054).
- **Issue forms and a pull request template.** A leak or a crash still goes to private reporting;
  a report of running strypt on your own machine now has its own form.
- **The maintainer's steps for a security report**, linked from `SECURITY.md` and tried once on a
  drill.

### Changed

- **Phase 4 — distribution — is complete (ADR-0053; opened 2026-09-12, closed 2026-09-14).** No
  change to what strypt removes. The install steps were tested on fresh CI runners, not on anyone's
  own machine: browser downloads, Gatekeeper and SmartScreen are untested.
- **Windows binaries stay unsigned.** SignPath declined the project as too new (ADR-0055). README now
  says Smart App Control may block them, not only warn.

### Fixed

- **README install steps**, run on fresh machines: the checksum command works where `shasum` is
  absent, and the steps name what `gh attestation verify` and `cargo install` need.
- **SECURITY.md's supported versions** still said there had been no release.

### Security

- **PDF: photos kept their Exif while strypt reported the file clean.** A JPEG placed in a PDF, or
  used as a page thumbnail, kept its GPS position, camera serial number, author and capture time;
  `show` found nothing and `strip` said "nothing to remove". **Affects 0.1.0.** If you published a
  PDF containing photos after stripping it with strypt, check it with `exiftool -ee`. Those JPEGs are
  now cleaned; JPEG 2000 images and JPEGs inside another compression are named in the report as not
  opened (ADR-0056).

## [0.1.0] - 2026-09-13

### Added

- **Prebuilt binaries**: Linux x86_64 and aarch64 (static, musl), macOS Apple Silicon and Intel, and
  Windows x86_64, on the GitHub release page with `SHA256SUMS` and a signed provenance record
  (ADR-0050). CI builds each binary twice and releases none unless every pair is byte-identical; the
  release notes name the runner image and linker needed to rebuild one. No binary is code-signed
  (ADR-0051): no Apple Developer ID, and Windows signing through SignPath Foundation is applied for
  after this release.

- **MP4 and M4A support — `.mp4`, `.m4v`, `.m4a`, `.m4b`.** The fifth and last tranche of Phase 2's
  fourth format group (ADR-0037), decided in ADR-0042.

  What comes out: the **GPS coordinate** every phone writes into every video it records; the whole
  **iTunes atom list** — title, artist, album, composer, comment, description, lyrics, dates,
  encoder, and vendor key/value triples — itemised atom by atom; **camera make and model**; **cover
  art**, removed whole, so metadata inside the image goes with it; an **XMP packet** in a top-level
  `uuid` box, scanned first so the report names what went; Microsoft's `Xtra`; free space; and the
  **encoding software** wherever it hides, including `compressorname` inside a video sample entry,
  where ffmpeg writes `Lavc libx264`. A box strypt has never seen goes too, rather than surviving by
  being unrecognised. The samples are copied without ever being decoded.

  What is edited rather than removed, because the boxes are mandatory: creation and modification
  times in `mvhd`, `tkhd` and `mdhd` are zeroed, the handler name is emptied, the media language
  becomes `und`, and `mvhd`'s poster/preview/selection block is zeroed.

- **A clean MP4 comes back byte-identical.** `ftyp` and every `mdat` are copied byte for byte and
  only the movie box is rewritten, so nothing is re-encoded and the media is the media that went in.

- **A chunk offset that cannot be relocated refuses the file.** `stco` and `co64` hold absolute file
  offsets, so removing a box in front of the media moves every chunk. Each offset is remapped through
  a table of `mdat` extents; one resolving inside none of them is a refusal, never a guess. The
  alternative — shifting everything by the number of bytes removed — produces a playable-looking file
  whose chunks are wrong.

- **Four families are refused by name** rather than as "unrecognised": **fragmented MP4**,
  **encrypted media** (Common Encryption and FairPlay), **QuickTime `.mov`**, and **3GPP/3GPP2**. So
  is a track whose samples live in another file.

- **Measured against mat2 0.15.0 on 2026-09-04: no gaps on the MP4 corpus, and the media decodes
  identically.** mat2 remuxes through ffmpeg where strypt edits the box tree; it keeps
  `HandlerDescription`, `HandlerVendorID` and an empty `free` box, which strypt removes. In the other
  direction mat2 does not claim `.m4a` at all, and it will still process a fragmented or QuickTime
  file that strypt refuses — **for those files mat2 is the better recommendation**.

- **The MP4 handler has had a clean twelve-hour fuzz run** — `mp4`, `bmff`, `heif` and `detect` in
  parallel, 48 CPU-hours, 5.5 billion inputs, zero crashes, hangs or OOMs. `bmff` and `heif` are in
  that list because MP4 extended the ISO-BMFF box walk the HEIF handler already used. With it,
  **Phase 2's format list is complete** and every one of the twenty-two fuzz targets stands on a
  clean sustained run.

- **Ogg support — `.ogg`, `.opus`, `.oga`.** Vorbis, Opus and FLAC-in-Ogg: the fourth tranche of
  Phase 2's fourth format group (ADR-0037), decided in ADR-0041.

  What comes out: the **Vorbis comment header**, itemised field by field — artist, performer,
  composer, conductor, copyright holder, the person who encoded it, a contact address, recording and
  tagging timestamps, a place and a set of coordinates, the encoder, the disc and recording
  identifiers, and comments; **cover art**, removed whole, whether it is a `METADATA_BLOCK_PICTURE`
  comment or an Ogg-FLAC picture block, so metadata inside the image goes with it; and the **vendor
  string** naming the library that wrote the file. A comment key strypt has never seen goes too,
  rather than surviving by being unrecognised. The audio packets are copied without ever being
  decoded.

- **The stream serial number is rewritten to zero.** It is an identifier in its own right — libogg's
  own example seeds it from the clock — and no tool can recompute a file's original serial. Page
  sequence numbers are renumbered with it. This is the one format where a file with nothing to
  remove does **not** come back byte-for-byte identical; what does hold, and is tested, is that the
  audio packets cross byte for byte and that stripping twice gives the same bytes.

- **An Ogg carrying more than one logical bitstream is refused** — multiplexed or chained — rather
  than partly cleaned, and so is a page whose CRC does not match its bytes, a stream with bytes
  before its first page or after its last, and a stream that ends mid-packet.

- **Theora, Speex and Skeleton streams are refused by name** rather than as "unrecognised". They are
  Ogg files, and they are not formats strypt handles.

- **Measured against mat2 0.15.0 on 2026-09-03: no gaps on the Ogg corpus, and the audio decodes
  identically.** Neither tool re-encodes, so this is the closest comparison in the project so far.
  Two differences are worth knowing: **mat2 keeps the vendor string and the stream serial number**,
  and strypt clears both; and **strypt refuses files mat2 will still clean** — a multiplexed or
  chained stream, and a Theora video in an Ogg. Refusing is the correct behaviour for a file strypt
  cannot fully account for, and **for those files mat2 is the better recommendation**.

- **The Ogg handler has had a clean twelve-hour fuzz run** — `ogg`, `oggpage`, `flac` and `detect`
  in parallel, 48 CPU-hours, 4.4 billion inputs, zero crashes, hangs or OOMs. `flac` is in that list
  because the Vorbis comment reader is now shared between the two handlers.

- **MP3 support — `.mp3`.** The third tranche of Phase 2's fourth format group (ADR-0037), decided
  in ADR-0040.

  What comes out: the **ID3v2 tag**, itemised frame by frame across all three major versions —
  artist, composer, conductor, publisher, copyright holder, the tagging software, recording and
  encoding timestamps, the disc and recording identifiers, comments and lyrics, and a place where
  the geotagging convention was used; **cover art and any embedded file**, removed whole, so
  metadata inside them goes with it; a vendor's private frames; the **ID3v1 tag and its `TAG+`
  extension**; **APE tags**, itemised by key; and **Lyrics3 tags**, v1 and v2. Any frame strypt has
  never seen goes too, rather than surviving by being unrecognised. A file with nothing to remove
  comes back byte-identical, and the audio frames are copied without ever being decoded.

- **What an MP3 keeps, and why you are told:** the `Xing`, `Info` or `VBRI` header frame stays,
  because it is a real audio frame and removing it would break variable-bitrate seeking and gapless
  playback. The encoder that made the file — its name and its settings — is named in there, so the
  report says the frame was kept on every file that has one. **mat2 leaves it too.**

- **An MP3 with anything other than zeros between its tags and its first audio frame is refused.**
  That is exactly where something would be hidden from a tool that skipped ahead to the first frame.
  So is a tag whose declared length runs past the end of the file, and a file that is nothing but
  tags — which would otherwise strip to an empty file reported as a success.

- **`.mp1` and `.mp2` files are refused by name rather than as "unrecognised".** They share MP3's
  frame grammar and are a different format.

- **A FLAC with an ID3v2 tag in front of it is now cleaned rather than refused**, and an ID3v1, APE
  or Lyrics3 tag appended past a FLAC's last frame is now removed. The tag reader that arrived with
  MP3 made both possible; the appended case previously survived a strip in silence.

- **Measured against mat2 0.15.0 on 2026-09-02: no gaps on the MP3 corpus, and the frames come
  through byte for byte.** Neither tool re-encodes, so the two are close here. Two differences are
  worth knowing: a **Lyrics3 tag alone on a file survives mat2** and does not survive strypt; and
  **strypt refuses files mat2 will still clean** — an `.mp2`, or a file with arbitrary bytes in
  front of the audio. Refusing is the correct behaviour for a file strypt cannot fully account for,
  and **for those files mat2 is the better recommendation**.

- **The MP3 handler has had a clean twelve-hour fuzz run** — 1.8 billion inputs, zero crashes,
  hangs or OOMs — alongside the shared tag reader's 2.3 billion, FLAC's 590 million and the
  format-detection target's 2.6 billion. FLAC and detection were re-run because reading ID3
  changed both.

- **WAV support — `.wav`.** The second tranche of Phase 2's fourth format group (ADR-0037),
  decided in ADR-0039.

  What comes out: the `INFO` list — artist, engineer, technician, commissioner, copyright holder,
  archival location, dates; the **broadcast extension**, whose originator, originator reference,
  UMID and coding history name the desk, the operator and every processing step applied; field
  recorder documents in `iXML` and `aXML`; XMP; **a whole ID3v2 tag**, dropped unread; radio
  traffic metadata in `cart`; cue and region labels; display text, playlists and instrument
  settings; and any private chunk, removed unread rather than surviving by being unrecognised.
  Only the format, audio, sample-count and cue-point chunks are copied through. A file with
  nothing to remove comes back byte-identical, and the audio is never decoded or re-encoded.

- **A WAV's padding is emptied rather than dropped**, as a FLAC's is: it keeps its original length
  and loses whatever had been left in it.

- **Removing a WAV's sampler chunk means the file can no longer be looped by a sampler at the
  points it recorded**, and the report says so on every file that had one.

- **RF64 and BW64 files are refused by name rather than treated as large WAVs.** They are a
  different container — their real sizes live in a chunk strypt does not read — and editing one as
  a WAV would read the wrong lengths.

- **Measured against mat2 0.15.0 on 2026-09-01: no gaps in either direction on the WAV corpus.**
  mat2 rebuilds a WAV through ffmpeg where strypt edits its chunk list, and the measurement found
  that this does *not* change the audio: for 16-bit PCM the rebuild reproduces the samples byte
  for byte. So **neither tool reaches anything hidden inside the sample values of a WAV**, and
  strypt's report says so on every file.

- **The WAV handler has had a clean twelve-hour fuzz run** — 1.4 billion inputs, zero crashes,
  hangs or OOMs — alongside the shared chunk walker's 3.2 billion, WebP's 824 million and the
  format-detection target's 2.7 billion. WebP was re-run because its chunk walk is now shared.

- **FLAC support — `.flac`.** The first tranche of Phase 2's fourth format group (ADR-0037).

  What comes out: the Vorbis comment, itemised field by field — artist, album, date, location,
  organisation, the ripping software and its settings; **cover art**, removed whole, so metadata
  inside the embedded image goes with it; the **cuesheet**, which carries the disc's catalogue
  number and each track's ISRC; vendor `APPLICATION` blocks; and any reserved block type, removed
  unread rather than surviving by being unrecognised. A file with nothing to remove comes back
  byte-identical, and the audio is never decoded or re-encoded.

- **A FLAC's padding is emptied rather than dropped.** It keeps its original length, so a later
  tagger still has the space it was written for, and loses whatever had been left in it.

- **The MD5 of the unencoded audio in a FLAC's `STREAMINFO` is kept, and the report says so.** It
  is a fingerprint that links the file to other copies of the same recording — but it is computed
  from audio the file still carries, so anyone holding the file can recompute it, and removing it
  would break verification while hiding nothing.

- **Removing a FLAC's cuesheet means the file can no longer be split back into tracks**, and the
  report says so on every file that had one.

- **Measured against mat2 0.15.0 on 2026-09-01: an `APPLICATION` block, a cuesheet carrying a
  catalogue number and ISRCs, and a reserved block type all survive mat2's FLAC cleanup and do not
  survive strypt.** mat2 reaches FLAC through mutagen, which knows the Vorbis comment and the
  picture block.

- **A FLAC with an ID3v2 tag glued to the front is refused by name.** Non-standard but common;
  reading that tag is a later tranche's work, and cleaning the blocks around it would report
  success on a file that was not finished.

- **The FLAC handler has had a clean twelve-hour fuzz run** — 364 million inputs, zero crashes,
  hangs or OOMs — alongside the format-detection target's 3.1 billion.

- **JPEG XL support — `.jxl`, in both of its spellings.** The fifth tranche of Phase 2's third
  format group (ADR-0032).

  What comes out of a container: the Exif block with its GPS coordinates, serial numbers and
  capture timestamps; XMP; **C2PA provenance**, which names the capture device, the editing history
  and the signing identity; Brotli-compressed metadata, removed without being decompressed; the
  frame index; and padding, which is free to hold anything. A box strypt does not recognise causes
  the file to be **refused**, rather than being copied through unexamined. A file with nothing to
  remove comes back byte-identical.

- **A JPEG XL that is a bare codestream is reported clean and returned unchanged**, and every JPEG
  XL report — clean files included — says what was not examined: the codestream's ICC profile,
  whose fields can name a device or an application, and a preview frame, both coded inside the
  image data and out of reach without a decoder. mat2 refuses a bare codestream instead.

- **Removing a JPEG XL's `jbrd` box ends bit-exact JPEG reconstruction**, and the report says so on
  every file that had one. The box holds a verbatim copy of the source JPEG's headers, which is a
  producer fingerprint; the picture still decodes identically without it.

- **Measured against ExifTool on 2026-08-29: a C2PA manifest naming the capture device and the
  signing identity survives mat2's JPEG XL cleanup and does not survive strypt.** ExifTool removes
  the Exif, XMP and Brotli boxes and leaves the JUMBF, reconstruction, index and padding boxes.

- **JPEG XL's sustained fuzz run is clean.** On 2026-08-30 the `jxl` and `detect` targets each ran
  twelve hours — **24.01 CPU-hours, 3.42 billion inputs, zero crashes, hangs or out-of-memory
  conditions**. `jxl` was still reaching new code at the twelve-hour mark, so longer runs remain
  worthwhile and the Phase 3 hardening target is still not met.

- **SVG support — `.svg`.** The fourth tranche of Phase 2's third format group (ADR-0032).

  What comes out: `<metadata>` with its Dublin Core author, licence and XMP; Inkscape's and
  Illustrator's private namespaces, which carry the file's name on the author's disk, an absolute
  export path, their window geometry, and a compressed copy of the original Illustrator document;
  XML comments and processing instructions; comments inside `<style>`; and the metadata of a
  photograph pasted in as a `data:` URI. A namespace strypt has never seen is removed too — a name
  reaches the output only if the picture cannot be drawn without it.

  A drawing with nothing to remove comes back byte-identical. One that had something removed keeps
  every other byte: its ids, grouping, attribute quoting and whitespace.

- **Two things strypt keeps in an SVG could still identify their author**, and both are declared in
  the report: `<title>` and `<desc>`, which a screen reader announces, and a reference to a file
  outside the document, whose path can name a directory on the author's machine. Removing either
  would change what the file does. The report never repeats the path itself.

- **An SVG containing a `<script>`, an `on*` handler, a `<foreignObject>` or a `javascript:`
  reference is refused rather than partly cleaned**, as are `.svgz`, non-UTF-8 documents, and a
  doctype declaring its own entities. **mat2 is the better recommendation for a scripted SVG**: it
  re-renders through Rsvg, dropping the script along with the drawing's ids, grouping, animation
  and editable structure.

- **SVG's sustained fuzz run is clean.** On 2026-08-29 the `svg` and `detect` targets each ran
  twelve hours — **24.00 CPU-hours, 4.14 billion inputs, zero crashes, hangs or out-of-memory
  conditions**. `svg` was still reaching new code at the twelve-hour mark, so longer runs remain
  worthwhile and the Phase 3 hardening target is still not met.

- **HEIF and AVIF support — `.heic`, `.heif`, `.avif`.** `strypt show` and `strypt strip` now
  process the format an iPhone photograph arrives in. This is the third tranche of Phase 2's third
  format group (ADR-0032), and the two formats land together because they are the same container.

  What comes out: the Exif block, with its GPS coordinates, body and lens serial numbers, and
  capture timestamps; XMP, whether it is stored as an item or in the top-level `uuid` box Adobe
  uses; the ICC profile; item names, which some encoders fill with a product string; and
  **embedded thumbnails**, which are a complete second copy of the picture and survive any cropping
  or redaction applied to the first.

  **An item type or property strypt has never seen does not survive by being unrecognised.** The
  handler writes a new file containing only what the image cannot be decoded or rendered without —
  codec configuration, dimensions, bit depth, rotation, mirroring, cropping — so a vendor extension
  is absent because it was never written. `uuid` boxes make this matter more than usual: `uuid` is
  the format's official extension point, so a deny-list would carry exactly the wrong thing
  through.

  Numeric colour signalling (an `nclx` colour box) is **kept and declared in the report**. It names
  a colour space and no device, and removing it would change how the picture looks.

  **The picture itself is never re-encoded** — the coded image data is copied across byte for byte,
  and every fixture's output decodes to pixels identical to its input's.

- **A hidden HEIF thumbnail is hard to check for with anything else.** ExifTool does not report it,
  `magick identify` shows a single frame, and libheif's `heif-info` prints `thumbnail: 0x0`
  (measured 2026-08-27). If you have published HEIC or AVIF files that were cropped before
  publication, the uncropped version may still be inside them and the usual tools will not say so.

- **GIF support — `.gif`, animated ones included.** `strypt show` and `strypt strip` now process
  GIF images. This is the second tranche of Phase 2's third format group (ADR-0032).

  What comes out: comment extensions, which hold whatever the producing tool felt like putting
  there and in real files routinely hold a filename or a person; XMP packets; the whole 8BIM,
  IPTC, and ICC profile blocks `ImageMagick` and Photoshop write as application extensions — the
  IPTC one carries a by-line, which is somebody's name; plain-text extensions; extensions under
  labels the format does not define; and anything hidden after the file's trailer byte, which
  nothing reads and which is a convenient place to keep a second copy of an image whose visible
  version was cropped.

  **An application block strypt has never seen does not survive by being unrecognised.** Only two
  are kept, and neither is metadata: `NETSCAPE2.0` and `ANIMEXTS1.0` carry the animation's loop
  count. They name no person, device, place, or time, and they are identical in every looping GIF
  ever written — but removing them would turn a looping animation into a one-shot, which is a
  change to what the file *does*. strypt keeps them and says so in its report rather than staying
  silent.

  **The pixels are bit-identical, and a clean file comes back byte-identical.** The
  LZW-compressed image data is never decoded, frame delays and transparency are copied across
  untouched, and a GIF that carried no metadata is returned exactly as it arrived.

  **One deliberate removal is worth knowing about**: a plain-text extension is removed along with
  the graphic control block in front of it. That block sets the *next* graphic's delay and
  transparency, so leaving it behind would retime the following image.

  Checked against **mat2 0.15.0 and ExifTool 13.55**: nothing survives strypt that does not also
  survive mat2, across all 14 fixtures. On one of them strypt removes more — mat2 leaves the
  plain-text extension in place.

- **TIFF support — `.tif`, `.tiff`, including the multi-page files scanners produce.** `strypt
  show` and `strypt strip` now process TIFF images. This is the first tranche of Phase 2's third
  format group (ADR-0032, ADR-0033).

  **This format is handled differently from every other image, and the difference is worth
  understanding before relying on it.** A JPEG or PNG keeps its metadata in a delimited block
  strypt can drop whole. A TIFF does not: its metadata sits in the same directory as the tags
  needed to decode the picture, and everything in the file is addressed by absolute offsets. So
  strypt does not edit a TIFF — it **writes a new one**, copying the image data across untouched
  and writing only the tags an image cannot be decoded without.

  What comes out: the camera or scanner's make and model, the software that wrote the file, the
  artist, copyright, description, document and page names, the date and time, the host computer's
  name, the GPS coordinates and the camera owner's name and body serial number in the Exif and
  GPS directories, and the XMP, IPTC, and ICC profile packets — the last of which routinely names
  a device. **Embedded thumbnails go entirely**: a reduced-resolution copy of the image is a
  complete second picture that survives any crop or redaction applied to the first.

  **A private tag strypt has never seen does not survive by being unrecognised.** Tags are
  written from a list of what the image needs, so anything else — a vendor maker note, a
  scanner's proprietary field holding a serial number — is absent from the output because it was
  never written.

  **The pixels are bit-identical.** Strips and tiles are moved, never decoded and never
  recompressed.

  **Three limitations to read before relying on this.** The output is **never byte-identical to
  the input**, even for a file that carried no metadata, because a rebuild reorders the file;
  stripping an already-stripped file *is* byte-identical. Metadata concealed inside the
  compressed image data is out of reach — **mat2's default TIFF path re-renders the image and
  does reach that, so where that is your concern mat2 is the better tool**, at the cost of
  rewriting your pixels. And a file using a feature strypt cannot reproduce faithfully is
  refused rather than approximated: BigTIFF, an inconsistent strip geometry, or a directory
  without dimensions.

  Checked against **mat2 0.15.0 and ExifTool 13.55**: nothing survives strypt that does not also
  survive mat2, across all ten fixtures.

- **The TIFF and detection parsers survived 24 CPU-hours of hostile input.** Twelve hours each,
  in parallel, on 2026-08-26: **zero crashes, zero hangs, zero out-of-memory failures**. The TIFF
  parser alone was fed **1.4 billion** malformed inputs and the detector 3.0 billion. Detection
  was included because it changed in the same work — it now routes TIFF to a handler and refuses
  BigTIFF by name.

- **OpenDocument support — `.odt`, `.ods`, and `.odp`.** `strypt show` and `strypt strip` now
  process LibreOffice and OpenOffice text documents, spreadsheets, and presentations. This is the
  second format group of Phase 2 (ADR-0027, ADR-0031).

  What comes out: `meta.xml` entire — the initial creator and the last person to save the
  document, the creation, modification and print dates, who printed it, the **editing-cycle count
  and the total editing duration** (an ISO 8601 duration recorded to the second, which with the
  dates beside it says when somebody sat down, how long they worked, and when they stopped), the
  generator string (which names the operating system, not just the application), the page and
  word statistics, arbitrary user-defined properties, and a template reference that frequently
  points at a file under the author's home directory. Also `settings.xml` entire — which holds
  the **printer's name and its setup blob**, the last cursor position, and a set of configuration
  keys that fingerprints the producing build; the page thumbnail; the producer's saved
  user-interface configuration and layout cache; the author names and dates on comments and
  tracked changes; the cached author-name fields printed inside the document; and per-part ZIP
  timestamps and host fields.

  **Photographs inside a document are stripped too**, by the same JPEG, PNG, and WebP handlers a
  loose file goes through — one level deep, images only (ADR-0029). **An embedded chart's own
  metadata is removed as well**, without any recursion: OpenDocument stores an embedded object as
  ordinary entries in the same package, so its author and printer details are reachable in the
  same pass.

  Refused rather than half-processed: a package with no manifest, a package whose manifest
  declares encryption — which ZIP's own encryption flag does not reveal, so this refusal is what
  stops an encrypted document being reported clean — a package that gives two different answers
  about what it is, and a package containing a nested archive, an embedded PDF, or an OLE object.

  **One limitation to read before relying on this.** The *text* of comments and tracked changes
  is kept and reported, with only its attribution removed; **for a document whose comments must
  not be published, mat2 removes them outright and is the better tool.**

- **A new refusal for OpenDocument types outside this group** — drawings, formulas, charts,
  databases, and the `-template` variants — named specifically rather than reported as a generic
  ZIP container, so the message says the file was understood and declined rather than not
  recognised.

- **Office Open XML support — `.docx`, `.xlsx`, and `.pptx`.** `strypt show` and `strypt strip`
  now process Word documents, Excel workbooks, and PowerPoint presentations. This is the first
  format group of Phase 2, which opened on 2026-08-23 (ADR-0027).

  What comes out: the core, extended, and custom properties parts (author, last-modified-by,
  company, manager, cumulative editing time, revision count, and any custom property a document
  management system left behind); the package thumbnail, which is a rendered preview of the
  first page and survives every redaction applied to the text; revision-save identifiers
  (`w:rsid*` and the `w:rsids` table), which link two documents edited in the same session on
  the same machine; per-paragraph identifiers (`w14:paraId`, `w14:textId`), which are stable
  across copies; the author names, initials, and dates on comments and tracked changes; per-part
  ZIP timestamps and host fields such as Unix UID/GID; and external relationships whose target is
  a local or network path, such as an attached template under someone's home directory.

  **Photographs inside a document are stripped too**, by the same JPEG, PNG, and WebP handlers a
  loose file goes through — one level deep, images only (ADR-0029). A geotagged photo pasted into
  a report is the leak most likely to reach publication, because nothing in the document's own
  properties hints that it is there.

- **A new refusal for macro-enabled documents** (`.docm`, `.xlsm`, `.pptm`), named specifically
  rather than reported as a generic ZIP. Their `vbaProject.bin` is a container strypt cannot
  read, and a document reported clean while part of it went unexamined is the outcome this tool
  must never produce.

- **Stripped OpenDocument files are now verified to still open in LibreOffice.** A new check,
  `scripts/odf-libreoffice-validation.sh`, strips each document, loads it with LibreOffice, and
  compares the document body before and after — so a file that opens but quietly lost content
  fails as loudly as one that will not open at all. Run against **LibreOffice 26.2.5.2**: all 14
  fixtures and 2 real LibreOffice-authored documents pass.

  This closes a gap that was recorded rather than hidden: until now nothing strypt produced for
  this format had ever been opened in the application that writes it. Seven of the stripped files
  were also opened by hand in the LibreOffice interface, and **none prompted to repair the
  file** — a separate check, because that dialog is a GUI prompt no automated import can trigger.

- **The OpenDocument, ZIP, Office and PDF parsers survived 48 CPU-hours of hostile input.**
  Twelve hours each, in parallel, on 2026-08-25: **zero crashes, zero hangs, zero out-of-memory
  failures**. The OpenDocument parser alone was fed 382 million malformed inputs. PDF was
  included because its two most recent fixes had had only a short run.

  Malformed input is expected input for this tool — a file that crashes the stripper is a file
  the user may then publish uncleaned. What this does *not* mean: three of the four parsers were
  still reaching new code at the twelve-hour mark, so longer runs remain worthwhile and the
  project's own hardening target (Phase 3) is not met.

### Changed

- **Phase 4 — distribution — is open (ADR-0049).** No change to what strypt removes. The
  repository goes public first, with GitHub's private vulnerability reporting as the preferred
  security channel; prebuilt binaries follow once builds are reproducible.

- **The reminder that filenames, folder names and visible content are not touched now follows
  every `show` and `strip`.** It used to appear only when `show` found metadata, so a clean
  result, the one that leads to publishing, came without it. JSON output is unchanged.

- **Security reports now go through GitHub's private vulnerability reporting**, with email kept for
  reporters without a GitHub account ([`SECURITY.md`](SECURITY.md)).

- **Every format handler is now fuzzed on every push (ADR-0049).** No change to what strypt removes.
  CI runs each of the 22 fuzz targets for a minute; before this, only PDF and format detection.

- **The README opens with a banner and a demo of `strypt strip` and `strypt show`.** The demo is the
  real binary's output on a synthetic test photo, regenerated by `scripts/render-demo.py`. A "Why
  trust the output" section links each safety claim to where it is checked, and CI badges are live.
  It also gains a before-you-publish checklist, how to report a missed field, the platforms CI
  tests, and a scripting example built on `show`'s exit code.

- **`INSTRUCTIONS.md` rewritten as a command reference**, 841 lines to about 250. It had fallen
  three phases behind, still cited ADR-0014's superseded fuzzing rule, and omitted CI's
  `--all-features` test run and MSRV build. Differential results live in THREAT_MODEL §7.

- **The CLI's contract is tested end to end** (TESTING_STRATEGY §2.2): exit codes, the JSON schema,
  stdout and stderr, and that strypt never changes an input, overwrites without `--force`, follows a
  symlink, or prints values unasked. 21 tests, each safety test shown to fail against a planted bug.

- **Phase 3 — hardening — is complete (ADR-0043; opened 2026-09-05, closed 2026-09-12).** No change to what
  strypt removes: this phase adds no formats. What changed for users is what the project promises
  to verify. **The planned "boot Tails and Qubes-Whonix" validation is replaced by a
  filesystem-constraints matrix in CI** — a read-only destination, a full volume, `vfat`/`exfat`
  media, a destination on a different mount — because those distributions' constraints are
  filesystem shapes, and reproducing them in CI catches a regression where a one-off boot cannot.
  **Neither distribution will itself be tested**: Tails is x86-64 only and Qubes needs bare-metal
  IOMMU hardware this project does not have, so Tails becomes an optional confirmatory boot and
  Qubes-Whonix is deferred. **If you run strypt on Tails or Qubes, nothing here validates that** —
  `docs/PRD.md` and `docs/ARCHITECTURE.md` previously implied such validation was coming and have
  been corrected.

- **Every supply-chain check now blocks a merge, and CI proves each one works (ADR-0045).** No
  change to what strypt removes. Known security advisories, yanked crates, duplicate dependency
  versions, unexpected licences and non-crates.io sources all fail the build now; before this,
  advisories only warned. On every push, a script plants one violation of each kind in a
  throwaway copy of the tree and checks that the right gate catches it, so a gate that has been
  quietly weakened fails as well.

  The stricter check found one real issue on its first run: `chacha20 0.10.1`, pulled in through
  the PDF library, had been **yanked by its publisher**. It is now 0.10.2. No security advisory
  names 0.10.1 and the yank gave no reason, so this is **not a known vulnerability**, and nothing
  suggests files you have already cleaned need checking again.

- **CI now tests writing to hostile filesystems (ADR-0043).** No change to what strypt removes.
  A read-only volume, a full volume, FAT and exFAT sticks, and a locked directory are each checked
  to leave either a complete file or the original untouched. **On a FAT or exFAT drive, the
  stripped file is not owner-only**: those filesystems have no Unix permissions, so anyone who can
  read the drive can read it.

- **A known-limitations page: [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md).** It lists,
  format by format, what strypt keeps, cannot see and refuses, and which files mat2 handles better.
  It is linked from the top of the README.

- **Corrected: mat2 does not reach data hidden in HEIF or AVIF pixels either.** Earlier docs
  recommended mat2 for that; mat2 0.15.0 cleans those formats through ExifTool without re-rendering.

- **No open fuzzing findings.** No change in behaviour. Every crash fuzzing has ever found is
  fixed, and each has a regression test.

- **No parser sandbox, for now (ADR-0048).** No change in behaviour. strypt runs as one process
  with your permissions, so a compromised dependency would have them too. The ADR says what would
  change this.

- **On Windows, the stripped file has the permissions of the folder it is written to (ADR-0047).**
  No change in behaviour; this is now permanent rather than pending. Inside your user folder that
  means you, administrators and SYSTEM. In a shared or public folder, anyone who can read the
  folder can read the file.

- **No scheduled CI fuzzing, and no OSS-Fuzz for now (ADR-0046).** No change to what strypt
  removes. Long fuzzing runs stay local, because CI jobs cannot run the required 24 hours.

- **How much fuzzing counts as enough is now measured rather than guessed (ADR-0044).** No change
  to what strypt removes. The project's own bar for testing a format handler was set before any
  parser existed — 100 CPU-hours plus "no new coverage in the last quarter of the run" — and 480
  CPU-hours of measurement across 80 coverage curves showed it failing in both directions: it
  called the most thoroughly-saturated handler "still climbing" over a single late edge, and it
  would have passed Ogg 24 hours before Ogg found another 184. The bar is now 24 CPU-hours plus a
  curve-shape test (`scripts/fuzz-plateau.py`), which eighteen of the twenty-two fuzz targets
  meet after a further 168 CPU-hours.

  **What this says honestly: Ogg is the weakest-tested handler in the tree** — both the handler
  and its page-level target fail the test — and PNG and JPEG XL are behind the rest. Ogg's fuzzing keeps finding new code paths after 84 CPU-hours because the
  fuzzer struggles to construct the per-page checksums the format requires, so it explores less
  of the handler per hour than the numbers suggest. That is recorded rather than smoothed over,
  and the fix — feeding the fuzzer valid page structures — is outstanding work, not done work.
  All 648 CPU-hours found zero crashes.

  That fix is now in: the Ogg fuzz targets repair page checksums after each mutation, and both
  met the bar on their next 24-hour run, with no crashes. PNG and JPEG XL still do not.

- **WebP and WAV now share one chunk walker (ADR-0039).** WebP's behaviour is unchanged, with one
  exception that only makes it stricter: the per-frame sub-chunks of an animation are now subject
  to the same item limit as the rest of the file. WebP's fuzz target was re-run against the change,
  and the shared walker has a fuzz target of its own.

- **`.heic`, `.heif` and `.avif` are no longer reported as unsupported.** They were refused as
  "an ISO base-media file" before; they are now detected by their `ftyp` brand and handled. MP4 and
  M4A still report as unsupported, and an **image sequence or motion HEIF — which is what an Apple
  Live Photo is — is refused by name** rather than partly cleaned. Video containers are a later
  group; the refusal says so instead of reporting a malformed file.

- **A stripped HEIF or AVIF is not byte-identical to its input, even when the input carried no
  metadata at all.** The file is rebuilt rather than edited, because its metadata is addressed by
  absolute file offsets and removing any of it moves everything after (ADR-0034). Stripping an
  already-stripped file *is* byte-identical.

### Verification

- **The HEIF and AVIF parsers survived 36 CPU-hours of hostile input.** Twelve hours each on the
  `heif`, `bmff` and `detect` targets, in parallel on 2026-08-27: **5.6 billion generated inputs,
  zero crashes, zero hangs, zero out-of-memory failures**, nothing set aside as not worth fixing.
  Detection was included because it changed in the same work — these formats now route to a
  handler by their `ftyp` brand instead of being reported as unsupported.

  Malformed input is expected input for this tool: a file that crashes the stripper is a file the
  user may then publish uncleaned. What this does *not* mean — the HEIF parser was still reaching
  new code at the twelve-hour mark, so longer runs remain worthwhile and the project's own
  hardening target (Phase 3) is not met.

- **Every format strypt ships has now had a clean sustained fuzz run.** GIF was the last one
  outstanding. On 2026-08-27 the `gif`, `pdf`, `jpeg`, `png`, `webp` and `detect` targets each ran
  twelve hours in parallel — **72.01 CPU-hours delivered, zero crashes, zero hangs, zero
  out-of-memory conditions**, nothing set aside as not worth fixing. GIF alone processed
  1,073,948,408 generated inputs.

  This also settles something that had been carrying a footnote since 2026-08-22. The project's
  own bar asks for four fuzz targets clean after a single sustained run, and until now no one run
  had managed all four at once — the claim rested on one clean run plus an argument that the other
  three were unchanged since theirs. All four were in this run and all four came back clean, so
  the argument is no longer load-bearing.

  No tool can guarantee total metadata removal, and this does not change that. The documented
  per-format limitations in `docs/THREAT_MODEL.md` still stand and are still worth reading.

### Fixed

- **`strip` now says when its output file already exists.** It refused correctly, exit 3, but said
  "i/o failure while creating a temporary file". It now names the file and suggests `--force`;
  `strypt-core` reports the refusal as `StryptError::OutputExists`.

- **A test-only size check that could report a false failure for TIFF files.** No user-facing
  behaviour changed and no file was ever stripped incorrectly — this is a fault in the fuzzing
  harness, recorded because the harness is what the project's safety claims rest on. The GIF,
  PNG, and WebP fuzz targets each drive the whole pipeline, so an input the fuzzer mutates onto
  another format's magic bytes is dispatched to that format's handler. Each target then asserted
  that stripping never makes a file bigger — true for every handler until TIFF landed on
  2026-08-26, which is rebuilt rather than edited and can legitimately grow (ADR-0033). The GIF
  target hit the resulting false alarm on a TIFF-shaped input after 144.5 million executions.
  The three assertions now apply only when the input really is the format the target is about,
  and the triggering input is kept as a seed.

- **A PDF that cannot be rewritten faithfully is now refused instead of written.** For some
  damaged documents the rewrite produced a file that did not read back as what was written: an
  object whose keys came from mangled bytes was written in a form the parser could not read
  again, so it disappeared when the file was reopened. Where that object was the document's only
  page, strypt wrote a file whose page tree pointed at an object that was no longer there — and
  reported success. Stripping that output again produced a further truncated file with a
  dangling page reference, reporting success a second time.

  strypt now reads its own output back before returning it and refuses the file if the document
  did not survive the round trip, so nothing is written and the refusal says so. **No metadata
  survived either write** — the failure was structural damage reported as success, not a leak —
  but a user acts on a success report by publishing, which is why this is treated as the more
  serious of the two PDF fixes in this release. Found by the PDF fuzz target; regression test
  and fixture committed.

- **A PDF whose page tree refers to itself no longer strips to different bytes on the second
  pass.** Stripping such a document once and stripping it twice produced two files of the same
  length and content whose object numbering differed — objects 2 and 3 traded identities.
  Nothing was left unstripped and no metadata survived either pass, so this was a reproducibility
  failure rather than a leak, but a user who strips a file twice must get the same file. The
  renumbering step now runs until the numbering stops changing before anything is written, and a
  document that will not settle is refused instead of written. Found by the PDF fuzz target;
  regression test and fixture committed.

### Changed

- **The sustained fuzzing runner knows about `tiff`.** `scripts/fuzz-sustained.sh` had the same
  gap for the TIFF target that it had for `ooxml` and `zip` below — it rejected the name as
  unknown, so the new parser could not have been included in a sustained run at all. It is now
  in the default set, with its malformed seed directory wired up the way WebP's is. **Any run
  recorded before 2026-08-25 covered eight targets regardless of how it was invoked.**

- **The sustained fuzzing runner covers all seven targets.** `scripts/fuzz-sustained.sh` knew
  only the five Phase 1 targets and rejected `ooxml` and `zip` as unknown, so the two parsers
  added by Phase 2's first format group could not be included in a sustained run at all. They
  are now in the default set. Any run recorded before 2026-08-23 covered five targets regardless
  of how it was invoked.
- **A live status viewer for a run in progress**, `scripts/fuzz-status.sh`. The runner prints
  nothing until every target finishes, which makes a twelve-hour run indistinguishable from a
  hung one. The viewer reads the per-target logs and refreshes a coverage and crash table. It
  decides nothing — the run's own `summary.md` and exit code remain what answer the exit
  criterion.
- **What `strypt show` reports for a document is broken down per part**, so a finding reads
  `word/media/image2.jpeg → APP1 (Exif) GPS IFD /GPSLatitude` rather than being attributed to
  the document as a whole.

### Known limitations (new)

- **The text of comments and tracked changes is not removed** — only their author names,
  initials, and dates. Removing a tracked insertion means deciding whether the document accepts
  or rejects it, which changes what the document says. A note in the report says the content is
  still there. **If the comments themselves must not be published, use mat2**, which removes
  those parts outright.
- **A document containing a nested archive, an embedded PDF, or an OLE object is refused**
  rather than partly cleaned. This includes the cached workbook Word embeds behind a chart, which
  is common in real documents. The refusal is deliberate: that workbook carries its own author
  names, and strypt does not descend a second level.
- **A stripped document is not byte-identical to a clean input**, because a rewritten part is
  stored rather than re-compressed and entry timestamps are normalised. Stripping an
  already-stripped document *is* byte-identical.
- **A damaged Office document is reported as an unsupported ZIP container**, not as a damaged
  document, because identifying it requires reading a part that a damaged package may not have.

### Added

- **strypt is installable: `cargo install strypt`.** `strypt` and `strypt-core` are published
  to crates.io at `0.0.1`, ahead of the Phase 4 work they belong to, so the names are held by
  this project rather than by whoever registers them first. Names are not reservable on
  crates.io and a stub crate that only holds one violates its policy, so the crates carry the
  real code.

  **This is not a release.** `0.0.1` means what it says: Phase 3 hardening has not happened,
  there has been no external audit, and the limits in the README apply unchanged. What changed
  is that the install path stopped being hypothetical — for anything that matters, mat2 and
  ExifTool remain the right recommendation.

### Changed

- **The CLI crate is now `strypt`, renamed from `strypt-cli` (ADR-0026).** The binary was
  always called `strypt`, so `cargo install strypt` is the command people will type — and
  leaving that name unregistered meant the most guessable install path for a metadata-removal
  tool could later resolve to a stranger's code under the name this project's own
  documentation prints. The built binary is unchanged.

  `strypt-cli` `0.0.1` is published and **yanked**. Yanking keeps the name registered here, so
  it cannot be used to impersonate the tool, while stopping anyone installing a version that
  will never be updated. If you installed `strypt-cli`, replace it with `strypt`; it is the
  same program.

- **The WebP comparison against mat2 now runs, and passes.** It had been recorded since
  2026-08-19 as *not run* rather than as a pass — mat2 reaches WebP through GdkPixbuf, and
  without a WebP pixbuf loader it failed on the original files too, so the comparison said
  nothing about strypt. With the loader installed, `scripts/webp-differential.sh` finds no tag
  that mat2 removes surviving in strypt's output, across the 14 synthetic fixtures and 30 files
  from real producers. The script refuses to run when the loader is missing, because a sweep
  both tools failed identically looks like evidence and is not.

  It also records two differences that are **not** faults in either tool. mat2 decodes and
  re-encodes, so it returns an animated WebP as a single still frame; strypt keeps every frame.
  The reverse of that trade is that re-encoding removes the encoder's fingerprint, which strypt
  deliberately leaves alone. If you need the fingerprint gone more than you need the animation,
  mat2 is the better tool for that file.

- **Two WebP coverage gaps closed.** The corpus had nothing testing metadata that survives a
  change of file format, and nothing written by an actual browser. Both now exist: a
  JPEG→WebP conversion carrying real Canon Exif across — **including the embedded thumbnail,
  which is a small copy of the original photograph** — and a WebP encoded by Chrome's own
  encoder. strypt strips both clean; the conversion file goes from 92 readable tags to none.

- **Measured performance numbers in `docs/PRD.md` §9, replacing estimates.** Startup is 2.5 ms,
  a 3.3 MB JPEG strips in 10.9 ms, and a 3000-file batch peaks at 3.0 MB of memory against
  2.4 MB for 200 files — fifteen times the work for 0.6 MB more, so memory tracks the largest
  single file rather than the batch. `scripts/measure-performance.sh` reproduces them, and
  refuses to run against a debug binary. One machine only; Linux and Windows are unmeasured,
  and none of it is a commitment.

- **A sustained-fuzzing runner, `scripts/fuzz-sustained.sh`.** The fuzzing commands documented
  until now were 300-second smoke tests — enough to prove a target still runs, not enough to
  stand behind. The runner runs any set of targets in parallel for a chosen duration and
  records, per target, a coverage curve against elapsed time, whether coverage had stopped
  climbing by the end of the run, and any crash artefact. It exits non-zero if a target
  crashed. This is measurement infrastructure for a release criterion, not a new tool feature:
  the curves are what will replace ADR-0014's provisional 100-CPU-hours-per-handler figure,
  which was written before any parser existed and which that ADR already flags as a hypothesis
  to revise against real data.

  Its run summary now reports CPU-hours **budgeted** and CPU-hours **delivered** separately.
  The two differ whenever a target stops early on a crash: the first 8-hour five-target run
  was budgeted 40.00 CPU-hours but delivered 37.79, because the PDF target stopped at 5h47m on
  a genuine finding. Since ADR-0014 states its exit criterion in CPU-hours, reporting the
  budget as though it were delivered would credit a run with time it never spent — and the
  number is going to be read later, by someone deciding whether a release criterion was met.

- **`strypt show` and `strypt strip` now work on JPEG images.** They report and remove Exif
  — including GPS coordinates, camera make and model, body and lens serial numbers, the
  maker note, timestamps, and the embedded thumbnail — along with XMP packets, Photoshop and
  IPTC blocks, ICC colour profiles, the multi-picture and FlashPix segments, vendor blocks in
  `APP12`, comments, and any data hidden after the file's end-of-image marker. Exif is
  reported **tag by tag**, so you can see that it was `GPSLatitude` and `BodySerialNumber`
  that came out, not just that "an Exif block" did.
- **Your photograph is not re-encoded.** strypt edits the file's metadata segments and copies
  the image data through byte for byte, so the picture that comes out is bit-identical to the
  one that went in. Tools that strip a JPEG by decoding and re-saving it lose a little quality
  every time (ADR-0021).
- **Two JPEG segments are kept on purpose, and the report says so.** The JFIF header, which
  carries the pixel aspect ratio, and the Adobe marker, which declares the colour transform —
  without it, CMYK images render with wrong colours. Neither names a person, a place, or a
  device. Any thumbnail inside the JFIF header is still removed.
- **`strypt show` and `strypt strip` now work on PNG images.** They report and remove text
  chunks (`tEXt`, `zTXt`, `iTXt`), the `tIME` modification timestamp, the `eXIf` block, the
  `iCCP` colour profile, suggested palettes, ancillary chunks strypt does not recognise, and
  any data hidden after the file's end chunk. Text chunks are reported by keyword, so you can
  see that a thumbnailer had recorded the original file's full path — `Thumb::URI` names your
  home directory — or that a converter had stashed a whole Exif block as hex text under a
  `Raw profile type` keyword, where a tool looking only for Exif would miss it.
- **Your PNG is not re-encoded, and a file with nothing to remove comes back byte-identical.**
  Chunks that stay are copied through exactly as they were, CRCs included. PNG is a lossless
  format; a tool that re-saved it would be undoing the reason you chose it.
- **strypt reads PNG's compressed text chunks without decompressing them** (ADR-0022). The
  keyword that says what a chunk is sits outside the compression, and the chunk is removed
  whole either way — so strypt ships no decompressor and never feeds one an untrusted file.
  The cost, stated plainly: a compressed XMP packet is reported as one item rather than
  broken down property by property. An uncompressed one is still itemised.
- **Two PNG behaviours are deliberate and reported rather than silent.** Chunks that affect
  how the image renders are kept, and the physical-dimensions chunk (`pHYs`) is listed in the
  strip report as kept on purpose. A chunk strypt does not recognise is also kept if the file
  marks it as *critical* — meaning whatever wrote the file said it is needed to interpret the
  image — and the report says plainly that its bytes went through unexamined.
- **`strypt show` and `strypt strip` now work on WebP images.** They report and remove the
  `EXIF` block, the `XMP ` packet, the `ICCP` colour profile, and any chunk strypt does not
  recognise — including chunks hidden *inside* an animation frame, which the WebP
  specification explicitly permits and which a handler looking only at the top level would
  walk straight past. Data after the length the file's header declares is removed too.
- **strypt corrects the header that says what a WebP contains.** An extended WebP opens with a
  `VP8X` chunk whose flags declare that the file has an ICC profile, Exif, or XMP. Remove
  those and leave the flags set and the file lies about itself — some viewers warn, some
  refuse to open it. strypt clears exactly those three bits and copies every other byte of the
  chunk through, so the alpha channel, the animation, and the canvas dimensions are untouched
  (ADR-0023). A side effect worth knowing: a file whose header was *already* claiming metadata
  it did not have will be changed by `strip` even though `show` reported nothing to remove.
- **A WebP with no metadata header comes back byte-identical.** A simple-format WebP cannot
  carry Exif, XMP, or an ICC profile at all — the format requires the extended header first —
  so stripping one is a guaranteed pass-through rather than a file that happened to be clean.
  An animation whose frames need nothing removed passes through unchanged too.
- **A WebP animation keeps every frame.** The frames are the picture; a handler that treated
  them as container chrome would silently hand back a still image.
- **`strypt show` and `strypt strip` now work on PDF files.** They report and remove the
  Document Information Dictionary (including vendor-invented keys), XMP metadata packets,
  the document identifier, private application data in `/PieceInfo`, page modification
  times, markup-annotation authorship and dates, and embedded-file parameter metadata.
- **Earlier revisions of a PDF no longer survive stripping.** A PDF that has been saved more
  than once carries every previous version inside it, recoverable with a hex editor. strypt
  rebuilds the document from what the catalogue can actually reach, so superseded revisions
  are not written out at all (ADR-0020). The report also tells you when a file had earlier
  revisions in it, whether or not you were expecting that.
- **Output is checked before it is written.** Every strip is re-inspected, and if metadata
  survived, the operation fails and nothing is written. strypt would rather refuse than hand
  you a file it cannot vouch for.
- Unsupported and unrecognised formats are reported as such, with the format named where it
  can be identified. They are never copied through or reported as success.
- CLI: batch processing, `--recursive`, `--in-place`, `--output-dir`, `--force`, `--json`
  with a stable schema, `--show-values`, `--max-bytes`, and documented exit codes.
- Fuzz targets for the PDF, JPEG, PNG, and WebP handlers and for format detection, with seed
  corpora that include deliberately malformed files. They assert invariants — that stripped
  output re-inspects clean and that stripping is idempotent — not merely that nothing
  crashed.
- Test corpus with a manifest and a deterministic generator (`corpus/tools/`). No fixture
  contains real personal data, by construction.

- **Phase 1 is complete.** `strypt show` and `strypt strip` handle PDF, JPEG, PNG and WebP;
  every other format is reported as unsupported and never passed through untouched. All seven
  exit criteria are met, including a 12-hour fuzz run of the PDF parser with no crashes, hangs
  or memory exhaustion, and a green build and test run on Linux, macOS and Windows.

  What that does **not** mean: no tool can guarantee total metadata removal, and the documented
  limitations still apply — strypt keeps the JPEG `APP14` colour-transform marker that mat2
  removes, and refuses a PDF with 19-byte cross-reference entries that mat2 strips, where mat2
  is the better recommendation for that file. Performance figures come from one machine.

- **The real-producer test corpus no longer carries anyone's real personal data.** The files it
  fetches from public sample repositories held four real names in Canon owner-name fields, two
  more in PDF author fields, a camera serial number, and live GPS coordinates for five
  photographs — Helsinki, Hämeenlinna, Kansas City and Madrid. `sanitise_corpus.py` now replaces
  every one with a synthetic value on each build, keeping the producer's file structure intact
  so the fixtures still test what they were collected to test. The build refuses to write its
  manifests if verification finds anything real surviving.

  This never affected anyone using strypt — the corpus is a development-only, fetch-on-demand
  set that ships in no release and was never committed. It matters because those files were a
  step away from being committed, and a metadata-removal tool publishing a stranger's home
  coordinates is the exact failure it exists to prevent.

### Fixed

- **A malicious PDF could crash strypt instead of being refused.** A flaw in the underlying PDF
  library made it overflow an integer while reading a damaged cross-reference table, and strypt
  stopped with a Rust stack trace and exit code 101. Such files are now refused normally: "the
  parser failed on this file and it was not processed".

  **Nothing was leaked and no bad file was ever written** — strypt crashed before writing
  anything, so it never produced a half-cleaned document or reported success on a file it had
  not processed. The harm was a crash on hostile input and an error message that looked like a
  bug in strypt. Affects PDFs only. Found by the `pdf` fuzz target during an eight-hour run and
  reported upstream; strypt contains the failure rather than fixing the library (ADR-0024).

- **A PDF with no document catalogue is now refused instead of being rewritten into a corrupt
  file that strypt called clean.** ISO 32000-1 requires the file trailer to name a `/Root`, the
  catalogue every other object hangs off. When it was missing, strypt had no root to walk from,
  so its rewrite kept a different set of objects each time it ran: stripping such a file twice
  produced two different documents, and the second one had a page whose annotation list pointed
  at the catalogue object. strypt reported success both times. It now refuses the file — "the
  parser failed on this file and it was not processed".

  **This corrupted the output rather than leaking anything**: the metadata strypt is asked to
  remove was still removed on every pass. If you stripped such a file with an earlier build,
  the result may not open in a viewer — but the input could not open in a viewer either, since
  a PDF without a catalogue has no entry point. Affects PDFs only. Found by the `pdf` fuzz
  target; `corpus/pdf/malformed/no-root-trailer.pdf` is the regression test.

- **Error messages no longer print `None` where a position is unknown.** A refusal with no known
  byte offset read "malformed PDF at byte offset None" — debug syntax shown to someone deciding
  whether a document is safe to publish. It now simply omits the position.

- **Stripping a PDF containing a negative zero twice gave a different file than stripping it
  once.** The underlying PDF library writes the real number `-0.0` as `-0`, without the decimal
  point that made it a real; read back, `-0` becomes the integer `0` and is written as `0`. So a
  second strip changed one byte, and the value quietly changed type. strypt now writes negative
  zero as zero, which the PDF specification treats as the same number — no page, no coordinate,
  and no rendered output changes.

  **Nothing was leaked or damaged by this**, and a file stripped with an earlier build is fine:
  both passes removed everything they should. What broke was strypt's promise that stripping is
  repeatable, which is the property differential testing and future verification work rest on.
  Affected any PDF carrying a negative zero — legal, and ordinary enough in page geometry.
  Found by the `pdf` fuzz target during a two-hour run, and a second time by CI when the first
  fix turned out to miss negative zeros in the file trailer.

- **A PDF whose content stream declared a malformed length was rewritten with that stream's
  contents silently discarded, and reported as a clean copy.** The specification requires a
  stream's `/Length` to be an integer; a file writing `45.` instead of `45` parses without
  complaint in the underlying PDF library, which then hands strypt the stream with its bytes
  already dropped. strypt rewrote the document, wrote out a file whose `/Length` still claimed
  45 bytes over an empty stream — structurally invalid, and missing the page's content — and
  told the user "nothing to remove; wrote a clean copy". Such files are now refused.

  **No metadata was leaked by this**, so a file you stripped with an earlier build has not
  had anything exposed. What could happen is the reverse: an affected document would come back
  damaged, with content missing, while reporting success. Only PDFs with a malformed stream
  length were affected — no file in the synthetic corpus or in the 23 real-producer PDFs
  (pdfLaTeX, LibreOffice, Google Docs, Acrobat, ImageMagick) triggers it. Found by the `pdf`
  fuzz target, which noticed that stripping such a file twice gave two different results.

- The `binary` rule for PDF fixtures now covers subdirectories (`corpus/pdf/**/*.pdf`, not
  `corpus/pdf/*.pdf`). The narrower pattern matched no fixture in `corpus/pdf/malformed/`, so
  the first one added there would have been silently corrupted on a Windows checkout by the
  same CRLF rewriting described below — the fix was in place but did not reach where it was
  next needed.

- `real-producer-corpus/build_real_corpus.py` now rebuilds reproducibly. ImageMagick stamps
  the wall clock into generated PNGs in two places — the `date:*` text chunks and the `tIME`
  chunk — so every rebuild produced different bytes and invalidated every checksum in the
  manifest. It also prunes files it no longer produces; a renamed fixture had been left
  behind as an unlisted duplicate, inflating the corpus counts. Its `minimal-object-stream.pdf`
  contained no object stream and pointed `startxref` at the wrong offset, so it failed for a
  reason unrelated to its name; it is replaced by `minimal-xref-table.pdf`, built from
  computed offsets.

- PDF test fixtures are marked `binary` in `.gitattributes`. Without it, Git classified them
  as text — they are mostly printable ASCII — and rewrote every LF to CRLF when checking out
  on Windows, which shifts every offset in a PDF's cross-reference table and stops the file
  parsing at all. Caught by CI as fifteen failures on `windows-latest` and none elsewhere.
  A test now checks fixture integrity directly, so this cannot recur silently on any platform.

### Known limitations in this release

Read these before relying on the tool. They are limitations, not bugs, and each is deliberate:

- **All four Phase 1 formats are handled: PDF, JPEG, PNG, and WebP.** Everything else is
  reported as unsupported rather than processed.
- **Stripping a JPEG can change how it displays.** Two of the things removed affect
  rendering: Exif `Orientation`, so an image that relied on it may appear rotated, and the ICC
  colour profile, so a wide-gamut image is afterwards interpreted as sRGB. Both are also
  identifying — a per-device colour profile is a fingerprint, and its description usually
  names the vendor — so both are removed and the consequence is stated here rather than
  hidden. Check a stripped image before publishing it.
- **A JPEG that ends without its end-of-image marker is refused.** strypt will not repair a
  damaged file and hand it back as a clean one.
- **The Adobe `APP14` marker is kept, where mat2 removes it.** It is two bytes of colour-space
  declaration and it names nothing; removing it would change how CMYK files look. This is a
  deliberate, documented difference (ADR-0021).
- **A JPEG's encoder fingerprint survives.** Quantisation tables, Huffman tables, and chroma
  subsampling identify the software and often the device that produced a file. Removing them
  would mean re-encoding the picture, which strypt will not do.
- **A compressed PNG text chunk is reported less finely than an uncompressed one.** strypt
  carries no decompressor, so a compressed XMP packet is reported as a single item rather than
  property by property. It is removed either way (ADR-0022).
- **A PNG chunk strypt does not recognise is kept if it is critical.** strypt cannot know
  what it holds or what depends on it, so it copies the bytes through unexamined and the
  report says so. If you have a file with an unusual critical chunk, read the notes before
  publishing it — and note that such a file was already unreadable to ordinary viewers before
  strypt saw it.
- **A malformed PNG is refused, not repaired.** A file whose first chunk is not `IHDR`, that
  ends before `IEND`, or whose chunk lengths do not agree with its size, is rejected rather
  than cleaned up and handed back.
- **An extended WebP is not returned byte-identical.** Two fields change beyond the removals:
  the header's flags byte, and the container's own size. A simple-format WebP, and an extended
  one whose flags describe only the picture, are unchanged.
- **strypt does not read inside a WebP's ICC profile.** The chunk is removed whole and
  reported as a colour profile, without naming the device manufacturer or model recorded in
  it. Parsing an ICC profile would mean another format parser running on untrusted bytes for
  no change to what is removed.
- **A WebP animation frame strypt cannot parse is kept, not refused.** The report says plainly
  that its bytes went through unexamined, so anything hidden in that frame is still there.
- **A WebP with no picture in it is refused.** A file consisting of only a header and a
  metadata chunk would otherwise strip to a valid-looking container with no image, reported as
  a success.
- **A WebP's encoder fingerprint survives.** The bitstream carries its encoder's choices and
  the chunk order carries its muxer's. Removing them would mean re-encoding, which for a lossy
  WebP also means degrading the picture a second time.
- **strypt has not been compared against mat2 on WebP.** mat2 supports the format, but its
  WebP path needs a GdkPixbuf WebP loader that was not present on the machine used for
  verification, so the comparison was not run — for WebP only. ExifTool finds nothing but
  structural image properties in strypt's output.
- **Encrypted PDFs are refused.** strypt will not emit a decrypted copy of your document, so
  a password-protected file cannot be stripped at present.
- **Some PDFs are refused that other tools accept, because of how their cross-reference table
  is written.** The PDF specification fixes each entry in that table at exactly 20 bytes, and
  some producers write 19 by leaving out a padding space. strypt's PDF parser rejects those
  files; `qpdf` reports no errors on them and **mat2 strips them successfully**. If strypt
  tells you a PDF is malformed but other tools open it happily, this is the likely reason —
  **use mat2 for that file.** strypt refuses rather than guessing, so you are never handed a
  file it did not actually process, but this is a gap on strypt's side rather than a problem
  with your document. Found against real files during Phase 1 corpus work
  (`docs/THREAT_MODEL.md` §7.5).
- **Annotation contents are preserved.** strypt removes the annotator's name and dates, not
  the comment they wrote. It removes metadata, not information — a reviewer's remarks are
  content, and something visible in a document is not something this tool deletes.
- **Embedded attachments are not opened.** Their parameter metadata is removed and the
  attachment itself is left intact; if it carries its own metadata, strypt has not touched it.
  The report says so.
- **strypt does not redact.** Text under a black rectangle in a PDF is still in the file.
- Testing so far uses generated fixtures. Files from real producers — LaTeX, Word, Acrobat,
  scanners, browser print-to-PDF — are not yet in the corpus, and real producers are where
  the quirks live.

### Added — foundation

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
- README status banner stating exactly what is built, fuzzed, and audited versus what is
  not, tracked against the phase definitions in `docs/ROADMAP.md`.
- CONTRIBUTING.md disclosure that development uses an AI coding agent under defined
  constraints, including a direct statement of what those safeguards do *not* establish.

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

[Unreleased]: https://github.com/FadeHack/strypt/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/FadeHack/strypt/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/FadeHack/strypt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/FadeHack/strypt/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/FadeHack/strypt/releases/tag/v0.1.0
