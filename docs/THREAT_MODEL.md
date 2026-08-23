# strypt — Threat Model

**Status:** Phase 1 complete (2026-08-22) · **Last updated:** 2026-08-23

**This document must be revisited every time a format handler is added or substantially
changed.** A new format brings new places for data to hide, and a threat model that lags the
code is worse than none — it describes protection the tool no longer provides.

---

## 1. What we are protecting

The identity, location, affiliations, devices, and activity patterns of the person who
created or handled a file — all of which can be inferred from metadata that no ordinary
viewer displays.

## 2. Who we are protecting them from

Adversaries are listed by capability. strypt's protection is meaningful against all of them
for the metadata it removes; what differs is how much the residue matters and how much
effort the adversary will spend on it.

**A. The casual recipient.** Anyone who opens a file's properties dialog or drags it into an
online EXIF viewer. Sees author name, GPS, timestamps. No special skill or intent.
*strypt is highly effective here.*

**B. The motivated individual.** A harasser, a stalker, an abusive ex-partner. Will use
ExifTool, will read forum guides, will spend hours. This adversary is the reason the
domestic-violence-support persona exists in `docs/PRD.md`, and often the most dangerous in
practice because they already know who the target is and need only *where*.
*strypt is effective, and the residue that matters most is what strypt does not touch — see §4.*

**C. The organisational adversary.** A corporate legal or security team, or a newsroom's
opponent, investigating a leak. Has forensic tooling, has the original documents to compare
against, and can correlate across many files. Can exploit *differences* between documents,
not just their contents.
*strypt helps, but correlation attacks (§4.7) become significant.*

**D. The state-level actor.** Full forensic capability, access to intermediary infrastructure,
ability to compel third parties, patience, and the ability to combine metadata with signals
strypt never sees. May also target strypt itself — the binary, its distribution channel, or
its dependencies.
*strypt is one control among many and must not be treated as sufficient. Anyone facing this
adversary needs operational security advice far beyond a metadata scrubber.*

We also assume the **file itself may be hostile** (§5): a document sent to a journalist
specifically to exploit whatever tool they run it through.

---

## 3. What strypt protects against

Within its supported formats, strypt removes:

- **Location data** — EXIF GPS coordinates, altitude, direction, and timestamps that
  correlate with location.
- **Device identity** — camera make, model, lens, and body serial numbers. Serial numbers are
  particularly dangerous: they link every photograph a device ever produced, so a single
  un-stripped image can retroactively deanonymise an entire archive.
- **Personal identity** — author, creator, and last-modified-by names; organisation names;
  registered software owner strings.
- **Software fingerprints** — producing application and version. Rarely identifying alone,
  frequently identifying in combination (§4.7).
- **Timestamps** — creation and modification times, which reveal working patterns, time zones,
  and whether a document was prepared before or after a claimed event.
- **Embedded thumbnails and previews** — which can survive cropping and visual redaction of
  the main image, meaning a "redacted" photograph may carry an unredacted copy of itself.
- **Editing traces** — where the format exposes them: revision identifiers, editing-cycle
  counts, total editing time.

---

## 4. What strypt does NOT protect against

This section matters more than §3. A user who over-trusts the tool is in a worse position
than one who understands its limits, because they will take risks based on a guarantee that
was never made. **Nothing here should be softened for marketing reasons.**

**4.1 Content.** strypt does not read what your document says. A name in the body text, a
recognisable street in a photograph, a reflection in a window, a visible badge or screen — all
untouched. strypt removes metadata, not information.

**4.2 Writing style.** Stylometry can attribute authorship from text alone. strypt does
nothing about this, and no metadata tool can.

**4.3 Redaction.** strypt does not redact. A PDF with a black rectangle drawn over text still
contains that text and strypt will not remove it. This is a distinct and frequently-fatal
mistake, and the README should say so plainly.

**4.4 Metadata added after strypt runs.** Uploading a file to any platform hands it to a
pipeline you do not control. Servers re-encode images, add their own identifiers, and record
upload time and source IP. strypt cleans the file you have; it cannot clean what a service
does afterwards.

**4.5 Network and traffic analysis.** strypt makes no network connections (ADR-0004) and
therefore reveals nothing itself — but it also protects nothing about how you transmit the
file. Who you sent it to, when, and from where are outside its scope entirely.

**4.6 Filesystem and out-of-band metadata.** Filenames (`budget_final_jsmith_home.pdf`),
directory structure, filesystem timestamps, extended attributes, macOS resource forks,
Windows alternate data streams, and cloud-sync sidecar files all carry information. strypt
operates on file *contents*. Phase 1 should warn about identifying filenames in `show`
output, but the user remains responsible.

**4.7 Correlation and fingerprinting.** Even fully stripped files carry a fingerprint. JPEG
quantisation tables and encoder quirks identify the producing software. PDF object ordering
and structure identify the generator. Sensor pattern noise (PRNU) can identify an individual
camera *from pixel data alone*, with no metadata whatsoever. A cluster of individually
innocuous traits — "produced by this LaTeX version, on this platform, with these fonts" —
can narrow authorship dramatically. **strypt cannot defeat this class of attack**, and
against adversary C or D it may be the attack that matters.

**4.8 Unknown-unknowns within supported formats.** Complex formats hide data in places no
implementation enumerates completely. mat2's own README is explicit that seeing no metadata
does not mean a file is clean. strypt inherits that honesty (`docs/PRD.md` §12). The
post-strip verification pass (`docs/ARCHITECTURE.md` §1) catches only what the *inspector*
knows to look for — it makes the tool internally consistent, not omniscient.

**4.9 A compromised machine.** If the endpoint is compromised, the original file was already
readable before strypt ran. Metadata removal is irrelevant at that point.

**4.10 The user's own mistakes.** Sending the original by accident. Forgetting one file in a
batch. Keeping an un-stripped backup in the same directory. Safe defaults (copy-out, explicit
opt-in for destructive operations, loud failures) mitigate this, but design cannot eliminate
it.

---

## 5. Threats against strypt itself

**5.1 Malicious input files.** The primary technical threat: a file crafted to exploit
strypt's parsers. Handled by the adversarial-input architecture in
`docs/ARCHITECTURE.md` §5.1 — safe Rust with `forbid(unsafe_code)`, no panics, bounded
allocation, recursion limits, and per-handler fuzzing. Memory-safety exploitation is ruled
out by construction; **resource exhaustion and non-termination are the realistic residual
risks**, which is why fuzzing must treat hangs and OOMs as findings equal in severity to
crashes.

**5.2 Supply-chain compromise.** A malicious or compromised dependency runs with full access
to the user's most sensitive documents, and is the attack path least visible to users.
Mitigated by minimal dependencies (ADR-0008), `cargo-deny` as a hard CI gate, a committed
`Cargo.lock`, and release SBOMs. Not eliminated.

**5.3 A malicious build or distribution channel.** A tampered binary could exfiltrate
everything it touches. Mitigated by reproducible builds, published checksums, and provenance
back to a source commit (Phase 4). This is why Phase 4 treats verifiable provenance as a
feature rather than packaging polish.

**5.4 Silent failure — the most dangerous bug class in this project.** A bug where strypt
reports success while leaving metadata in place is worse than a crash, because the user acts
on the report and publishes. Treated as a security vulnerability, not a defect
(`docs/ARCHITECTURE.md` §5.4). Mitigations: the verification pass, fail-closed handlers,
differential testing against mat2 and ExifTool, and an explicit rule that unsupported
formats are reported as unsupported and never silently passed through.

**5.5 Leakage through strypt's own outputs.** Log files, error messages, JSON output, and
temp files can each contain the metadata the user just removed — a durable copy of the
secret. Hence: never log metadata values above trace level; temp files go alongside the
destination with restrictive permissions and are removed on failure; error messages name
fields, not values.

**5.6 Over-trust induced by the tool's own confidence.** If strypt's output reads as an
unqualified guarantee, users will take risks they would not otherwise take. This is a threat
created by *documentation and UI*, not by code, and it is the reason for the ban on
"complete", "guaranteed", and "100%" in user-facing text.

---

## 6. Assumptions

Stated so they can be challenged; each is a place the model could be wrong.

1. The user's machine is not already compromised (§4.9).
2. The user obtained an authentic strypt binary (§5.3).
3. The user understands strypt handles file contents only, not filenames or transmission.
4. Supported-format handlers are more thorough than a naive manual attempt — validated by
   differential testing, not assumed.
5. Removing metadata does not itself create a distinguishing signal. **This assumption is
   weak.** A stripped file may be conspicuous precisely because it is unusually clean, and in
   a small population of documents "the one with no metadata" can itself be a lead. strypt
   cannot resolve this; users in that situation need to consider whether a plausible-looking
   file is safer than a clean one.

---

## 7. Per-format findings

Added as each handler lands, from what implementing and testing it actually taught us — not
from what the specification says ought to be true. §4's general limitations still apply on top
of everything here.

### 7.1 PDF (Phase 1)

**What strypt removes.** The Document Information Dictionary, including keys no specification
ever defined — applications invent their own freely, and a custom key is no less identifying
for being non-standard. XMP metadata packets at document and object level. The trailer `/ID`.
`/PieceInfo`, which is a scratch area where an application may store whatever private state
it likes between editing sessions. `/LastModified`. Markup-annotation authorship (`/T`),
dates, and identifiers. Embedded-file parameter dates and checksums.

**Objects left behind by incremental updates are the finding that shaped the design.** A PDF
saved more than once contains every earlier version of itself: the old bytes stay, and a new
cross-reference section declares what supersedes what. Nothing in a normal reader shows this,
and neither ExifTool nor mat2 reported the superseded author in our own test fixture — but it
sits in the file in plain text. strypt rebuilds the document from what the catalogue can
reach, so those objects are never written out (ADR-0020). Any tool that patches a PDF in place
rather than rewriting it leaves them there while reporting the file clean.

**What remains, and why.**

- **Annotation contents.** The comment text a reviewer wrote is preserved; only their name and
  the dates are removed. This is §4.1 applied deliberately — content is not strypt's to
  delete. It is a real difference from tools that re-render the page, which lose the comment
  along with its author.
- **Form field names.** `/T` on a `/Widget` annotation is the field name that the form's logic
  and its saved data depend on, not a person's name. It is kept. Breaking a user's document to
  protect them is not a trade this tool makes silently.
- **Embedded attachments are not opened.** Their parameter metadata goes; whatever is inside
  them is untouched, and the report says so. Recursing into nested files is a zip-bomb-shaped
  problem that Phase 2 has to decide about explicitly, with a depth and expansion limit.
- **Compressed XMP packets are removed but not itemised.** ISO 32000-1 §14.3.2 recommends
  metadata streams be left uncompressed, and in practice they nearly always are. Inflating the
  rare compressed one to produce a more detailed report would mean accepting a decompression
  bomb in exchange for a nicer listing. The packet is still found and still removed.
- **Structural fingerprints.** Object ordering, the producer's layout conventions, font
  subsetting, and compression choices all survive and can identify the generating software.
  This is §4.7 and strypt does not address it. A full rewrite changes the fingerprint to
  strypt's own rather than erasing the notion of one — which, per assumption 6.5, may itself be
  distinguishing in a small population of documents.

**What strypt refuses.** Encrypted documents. `lopdf` can open one protected by an empty owner
password, and emitting a decrypted copy would strip the user's protection along with their
metadata — a change to their document's security they did not ask for and might not notice.

A trailer with no `/Root` is also refused, by both `show` and `strip`. ISO 32000-1 §7.5.5 makes
the entry required: it names the document catalogue, the single root every other object hangs
off, so without it the file has no defined entry point and no viewer opens it. strypt used to
accept such a file, and accepting was worse than refusing. The rewrite walks reachable objects
from the root and drops the rest (ADR-0020); with no root, which objects survive is not stable
between runs. The `pdf` fuzz target found it: one strip produced 609 bytes and a second produced
485, because the second pass dropped an annotation object a page still referenced through
`/Annots`, and renumbering then put the catalogue in that slot — so the page's annotation array
pointed at the document catalogue. That is corruption strypt introduced itself while reporting
success both times, which is §6 fail-closed inverted. Refusing costs the user nothing real: a
PDF this broken cannot be published either way. `corpus/pdf/malformed/no-root-trailer.pdf` pins
the behaviour, and both the triggering shapes are in the `pdf` seed corpus.

**A panic inside `lopdf` reached the shipped binary, and is now contained.** A sustained fuzz
run found an integer overflow in `lopdf` 0.44.0's cross-reference parser (`parser/mod.rs:516`,
computing `start + index` where `start` is read from the file). Because `Cargo.toml`
deliberately enables `overflow-checks` in release — an overflow parsing an attacker-controlled
field should abort rather than wrap into a nonsensical offset (ADR-0006) — the release binary
panicked with exit 101 and a stack trace, not merely the debug build. 0.44.0 was already the
newest release.

Calls into `lopdf` that touch untrusted bytes are now wrapped so an unwinding panic becomes a
typed `DependencyPanic` refusal (ADR-0024). What that is worth stating precisely: the panic was
already *fail-closed* — the process died before writing anything, so no partially-sanitised file
escaped and no success was reported on an unprocessed file. What containment buys is that the
user gets an intelligible refusal instead of a crash indistinguishable from a bug in strypt, and
that exit criterion 2 is met by fixing the behaviour rather than by redefining it as acceptable.
It buys nothing at all against a dependency that returns a *wrong answer* quietly, which no
guard detects.

**New attack surface this handler introduces.** `lopdf` is a third-party PDF parser processing
attacker-controlled bytes, and this project's no-panic rule does not extend to it (ADR-0018).
`#![forbid(unsafe_code)]` rules out memory-corruption exploitation; it does not rule out a
panic, a hang, or unbounded allocation originating inside the dependency. This is the largest
piece of untrusted-input surface in the tree and it is not code we control. It is why the PDF
fuzz target exists, and it is a specific input to Phase 3's sandboxing decision — containing a
compromised or merely fragile dependency is one of the few things sandboxing genuinely buys a
safe-Rust parser.

**One value is rewritten rather than copied: negative zero.** `lopdf` writes `Real(-0.0)` as
`-0`, dropping the decimal point that made it a real; reading `-0` back therefore yields
`Integer(0)`, which writes as `0`. Stripping once and stripping twice produced different bytes,
breaking the byte-identical idempotence invariant, and the value's *type* changed silently as
well. The handler now collapses negative zero to zero before writing.

Rewriting a number in someone's document deserves justifying in a handler that elsewhere
refuses rather than repairs. ISO 32000-1 §7.3.3 gives PDF numbers no signed zero: `-0` and `0`
denote the same value, no operator distinguishes them, and no renderer can. The rejected
alternative was refusing the file — which would have cost a user their entirely valid document
to preserve a distinction the format does not make. This is the opposite trade from the
19-byte-xref gap in §7.5, and deliberately so: there, accepting would have meant rewriting
untrusted bytes *ahead of the parser* to widen what strypt accepts; here, the document has
already parsed and the change provably preserves meaning.

The first version of this fix walked only the object graph and passed every test locally. CI's
fuzz smoke run then moved a negative zero into the *trailer* — which lopdf keeps outside
`objects` — and the assertion fired again within minutes, on a document whose object graph was
entirely clean. Both are now walked. The lesson generalises past this bug: a normalisation pass
is only as complete as its traversal, and "all the objects" was not all the document.

Found by the PDF fuzz target 6985 seconds into a two-hour run, through the harness's
idempotence assertion — the second real PDF defect that one assertion has caught, after the
stream-length bug in §7.5. Both were invisible to the verification pass, which searches output
for residual metadata and so cannot see a defect that leaves no metadata behind. The trigger
was a valid file: negative zero in a `/CropBox` is legal, and nothing about such a document
would strike a user as unusual.

### 7.2 JPEG (Phase 1)

**What strypt removes.** Every `APPn` segment except the two named below, and every `COM`
comment. That covers Exif — including the GPS directory, the maker note, and the thumbnail
directory — XMP packets and their extension segments, Photoshop image resources and the IPTC
block inside them, ICC colour profiles, the FlashPix and multi-picture segments, and the
vendor blocks several camera makers put in `APP12`. Exif is reported tag by tag rather than as
one lump, because "GPSLatitude, BodySerialNumber, DateTimeOriginal" is what lets someone judge
a file they already published.

**Data after the end-of-image marker is the finding worth knowing about.** A JPEG ends at its
`EOI` marker and nothing stops a file continuing past it. In practice that is where a phone's
multi-picture extension keeps a second, full-resolution frame: a viewer shows the picture that
was cropped, and the file contains the one that was not. strypt drops everything after `EOI`
and reports it. It is worth checking what a tool you rely on does with those bytes.

**A body serial number is the tag with the longest reach.** It links every photograph a camera
ever took. One image published with it intact retroactively attributes an entire archive that
was otherwise clean — which is why the report names it rather than counting it.

**What remains, and why.**

- **`APP0` (JFIF) and `APP14` (Adobe).** Both are kept deliberately and both appear in the
  strip report's `retained` list, so a reader sees them rather than discovers them. `APP0`
  carries the pixel aspect ratio; `APP14` declares the colour transform, and a CMYK or YCCK
  file without it renders with wrong colours. Neither names a person, a place, or a device.
  Keeping `APP14` is a **documented gap against mat2**, which removes it (ADR-0021).
- **The encoder's fingerprint.** Quantisation tables, Huffman tables, chroma subsampling, and
  scan structure all survive, and together they identify the software and often the device
  that produced the file. This is §4.7, it is not addressed, and it cannot be addressed
  without re-encoding — which would destroy the picture to hide the camera. A tool that
  re-encodes replaces the camera's fingerprint with its own rather than removing the notion of
  one (assumption 6.5).
- **The picture itself.** strypt never decodes or re-encodes an image, so anything visible in
  the frame — a face, a street sign, a screen — is exactly as it was. §4.3 applies: visual
  content is the user's to redact, and metadata removal is not redaction.

**What strypt refuses.** A file that ends without an `EOI` marker, or whose segment lengths do
not agree with its size. Completing a damaged file would hand the user something that is not
what they gave us, presented as a clean version of it.

**What is removed even though it changes how the file renders.** Exif `Orientation` and the
ICC profile. An image that relied on `Orientation` may afterwards display rotated, and a
wide-gamut image is interpreted as sRGB. Both are identifying — a per-device ICC profile is a
fingerprint and its description tag routinely names the vendor — so both go, and the
consequence is documented rather than hidden.

**New attack surface this handler introduces.** None from dependencies: the JPEG segment
walker and the Exif reader are written in this repository, under the crate's panic-freedom
lints, over the shared checked-reading primitive. The residual risks are the ones safe Rust
still has — a hang or unbounded allocation on a hostile file — which is what the `jpeg` fuzz
target exists to find. A five-minute run over the seed corpus on 2026-08-19 executed 6.8
million inputs with no crash, hang, or timeout; that is a smoke test, not the Phase 3 budget
(ADR-0014).

### 7.3 PNG (Phase 1)

**What strypt removes.** Every text chunk — `tEXt`, `zTXt`, and `iTXt` — the `tIME`
modification timestamp, the `eXIf` block, the `iCCP` colour profile, `sPLT`, every ancillary
chunk strypt does not recognise, and anything after `IEND`.

**PNG's text chunks are a general-purpose store, and that is the finding.** Unlike Exif, there
is no fixed field list: a keyword is any Latin-1 string up to 79 characters, and applications
use that freely. In practice the contents are worse than the format's reputation suggests.
Freedesktop thumbnailers write `Thumb::URI`, which is the **full path of the original file** —
it names a home directory, and a home directory names a person. `ImageMagick` stores entire
Exif and IPTC blocks as hex text under `Raw profile type` keywords, so a PNG converted from a
JPEG can carry the camera's GPS coordinates in a chunk that a tool looking only at `eXIf`
walks straight past. Screenshot and editing tools write their own names. strypt classifies by
keyword so that the report ranks these the way this document does, rather than filing
everything under "text".

**Measured against other tools on 2026-08-19.** ExifTool 13.55 finds nothing but structural
image properties — dimensions, bit depth, colour type — in strypt's output for every fixture in
`corpus/png`. Against mat2 0.15.0 over `corpus/png/text-chunks.png`: both remove the text
chunks, and the difference is what happens to the image. strypt's `IDAT` is byte-identical to
the input's; mat2's PNG path re-encodes through Pillow, which rewrote the 8-bit greyscale image
as 8-bit RGB — colour type 0 to colour type 2, tripling the pixel data — and dropped `gAMA`,
`sRGB`, and `pHYs` while adding a `bKGD` chunk of its own. ImageMagick reports zero differing
pixels, so nothing *visible* changed; the file did. That is a deliberate trade on their side
and a real one — re-encoding is robust against structures a parser does not understand — but
it means the output is no longer the file the user had, and it replaces the original encoder's
fingerprint with Pillow's rather than removing the notion of one (assumption 6.5). mat2 also
refuses `corpus/png/unknown-chunks.png` outright, which is a reasonable outcome for the same
reason any conforming decoder refuses it.

**What remains, and why.**

- **Compressed text is removed but not itemised.** `zTXt` is compressed by definition, and
  `iTXt` is when its flag says so. strypt carries no decompressor (ADR-0022) and does not need
  one: the keyword, the compression flag, the language tag, the translated keyword, and
  `iCCP`'s profile name are all outside the compression, and the chunk is removed whole
  regardless. What is lost is granularity — an XMP packet in an uncompressed `iTXt` is broken
  down by property, and the same packet compressed is one finding. This is the same trade
  §7.1 records for a `FlateDecode`d PDF metadata stream, made for the same reason: a
  decompression bomb is a real cost and a nicer listing is not worth it.
- **Rendering chunks survive.** `gAMA`, `cHRM`, `sRGB`, `sBIT`, `tRNS`, `bKGD`, `hIST`, the
  HDR chunks, and the APNG animation chunks are all copied through. None of them names a
  person, a place, or a device, and several change how the image looks if they go. `pHYs` —
  the pixel dimensions and DPI — is additionally declared in the strip report's `retained`
  list, because it is the chunk a careful user is most likely to expect to have gone.
- **An unknown critical chunk is kept, and the report says it was not examined.** Critical
  means the producer marked it as required in order to interpret the image, so strypt cannot
  know what it holds or what depends on it. It is copied through and reported as an unparsed
  region, so the user is told plainly that some bytes went by unexamined. The honest
  consequence: a conforming decoder already refuses such a file, so keeping the chunk leaves
  it exactly as unreadable as it arrived — `corpus/png/unknown-chunks.png` is deliberately
  one of those files. Dropping the chunk to make the file open would be strypt deciding what
  the document is, which is a bigger decision than the user asked for. An unknown *ancillary*
  chunk is removed: a private chunk can hold anything, and copying through what you do not
  understand is not scrubbing.
- **The encoder's fingerprint.** Filter choices per scanline, the deflate implementation's
  output, chunk ordering, and interlacing all survive and together identify the producing
  software. This is §4.7 and it is not addressed; addressing it would mean re-encoding the
  image, which for a lossless format is exactly what a user chose PNG to avoid.
- **The picture itself.** strypt never decodes or re-encodes an image, so anything visible in
  the frame — a face, a screen, a filename in a screenshot's title bar — is exactly as it was.
  §4.3 applies, and for PNG it applies hardest: a screenshot is *made of* content that a
  metadata tool cannot help with.

**What strypt refuses.** A file whose first chunk is not `IHDR`, one that ends before `IEND`,
one whose chunk length runs past the end of the file or sets the high bit the specification
reserves, and one whose chunk type is not four letters. Each of those means the walk is not
where it thinks it is, and a "cleaned" copy would be a guess presented as a fact.

**New attack surface this handler introduces.** None from dependencies, and this is where the
decision in ADR-0022 pays: the obvious implementation of PNG text handling pulls in a zlib
decompressor and feeds it attacker-controlled bytes, and strypt's does not. The chunk walker
is written in this repository, under the crate's panic-freedom lints, over the shared
checked-reading primitive. CRCs are copied rather than recomputed, so there is no checksum
code either. The residual risks are the ones safe Rust still has — a hang or unbounded
allocation on a hostile file — which is what the `png` fuzz target exists to find. A
90-second run over the seed corpus on 2026-08-19 executed 4.46 million inputs with no crash,
hang, or timeout; that is a smoke test, not the Phase 3 budget (ADR-0014).

---

### 7.4 WebP (Phase 1)

**What strypt removes.** The `ICCP` colour profile, the `EXIF` block, the `XMP ` packet, every
chunk strypt does not recognise — at the top level and inside an animation frame alike — and
anything after the length the RIFF header declares. The `VP8X` header's ICC, Exif, and XMP
flag bits are cleared so that the file stops claiming metadata it no longer has (ADR-0023).

**WebP concentrates its metadata in three chunks, and that is the good news.** Unlike PNG's
open-ended text-chunk store, there is no general-purpose key-value area a producer can invent
fields in: RFC 9649 §2.7.1.5 gives Exif and XMP one chunk each, and colour management one more.
The corresponding bad news is §2.7.1.6, which asks writers to *preserve* chunks they do not
recognise, and §2.7.1.1, which explicitly allows unknown chunks inside an animation frame. Both
are hiding places with the specification's blessing, and both are places a conforming WebP
writer will carry data through untouched. strypt removes them in both positions. It cannot
break a decoder by doing so, because the same section that asks writers to keep unknown chunks
tells readers to ignore them.

**Measured against other tools on 2026-08-19.** ExifTool 13.55 finds nothing but structural
image properties — dimensions, flags, animation timing — in strypt's output for every fixture
in `corpus/webp`.

**The mat2 differential for WebP is now run, and it passes.** From 2026-08-19 to 2026-08-21
this section recorded it as *not run*: mat2 0.15.0 lists `image/webp` as supported but reaches
it through GdkPixbuf, and the verification machine had no WebP pixbuf loader, so mat2 failed
identically on the *original* fixtures and the comparison said nothing about strypt.
Installing `webp-pixbuf-loader` 0.2.7 resolved it. On **2026-08-21**,
`scripts/webp-differential.sh` compared strypt against mat2 0.15.0 across all 14 fixtures in
`corpus/webp` and all 30 WebPs in the real-producer corpus: **no tag that mat2 removes survives
in strypt's output**, in either set. The script refuses to run when the loader is absent, rather
than reporting a clean sweep that would prove nothing.

Two results are worth recording, neither of them a strypt finding:

- **mat2 flattens an animation.** Its WebP path decodes and re-encodes through GdkPixbuf, so a
  two-frame `animated.webp` returns as a single still `VP8` chunk with no `ANIM`, no `ANMF` and
  no frame timing; a six-frame real-producer file likewise. strypt keeps every frame and removes
  only the `EXIF` chunk. This is the other face of "the encoder's fingerprint" below:
  re-encoding destroys the fingerprint strypt deliberately leaves alone, and destroys the
  animation with it. **Neither behaviour is wrong** — they are different answers to whether a
  metadata tool may alter the picture. A user who needs the encoder fingerprint gone, and does
  not need the animation, is better served by mat2.
- **Re-encoding can expose properties the input did not.** On `1_webp_ll.webp`, mat2's output
  carries `ALPH` parameters absent from the input. These are bitstream encoding choices, not
  metadata, and leak nothing the user had — noted because a differential that merely counts
  tags would misread it as mat2 *adding* metadata.

**What remains, and why.**

- **An extended file is not returned byte-identical.** Two fields change beyond the removals:
  the `VP8X` flags byte, and the RIFF chunk's own size. A *simple*-format file — no `VP8X` — is
  a guaranteed byte-identical pass-through, because §2.7 requires the extended header before
  any metadata chunk, so such a file has nowhere to put any. So is an extended file whose flags
  describe only the picture. This is a weaker property than PNG's and it is the price of the
  flags decision in ADR-0023; the alternative was leaving a file that lies about itself.
- **A file can change with nothing reported as removed.** A header claiming an Exif chunk that
  the file does not contain is corrected on strip, while `show` reports nothing — the flags
  byte names nobody, so it is not a finding. The two commands genuinely disagree here, and
  `corpus/webp/stale-flags.webp` is the case.
- **An animation frame that does not parse is kept, and the report says it was not examined.**
  strypt does not re-serialise a frame it only partly understands, and it does not refuse the
  whole file over one. It copies the frame through and emits a `Note::UnparsedRegion`, so the
  user is told plainly that some bytes went by unread rather than left to assume the frame was
  scrubbed. `corpus/webp/unparsable-frame.webp` is deliberately such a file.
- **The ICC profile is removed but never read.** A profile's internal tags carry the device
  manufacturer, the model, and a creation date, and strypt reports the chunk without naming
  any of them: parsing an ICC profile means another format parser on attacker-controlled
  bytes, for report granularity on a chunk that is going regardless. Same trade as compressed
  text in §7.3.
- **The encoder's fingerprint.** The VP8 or VP8L bitstream carries its encoder's choices —
  quantisation, partitioning, prediction modes, the lossless transforms selected — and chunk
  ordering carries the muxer's. Together they identify the producing software. This is §4.7 and
  it is not addressed; addressing it would mean re-encoding, which for a lossy format also
  means degrading the picture a second time.
- **The picture itself.** strypt never decodes or re-encodes an image, so anything visible in
  the frame is exactly as it was. §4.3 applies.

**What strypt refuses.** A file that is not RIFF, or is RIFF but not `WEBP`; one whose declared
RIFF size or chunk size runs past what is available; one that does not open with `VP8X`,
`VP8 `, or `VP8L`; one whose `VP8X` is not the ten bytes §2.7 fixes it at; one whose
four-character code is not ASCII; and — the one worth naming separately — **one that contains
no bitstream and no animation frame**, which would otherwise strip to a valid-looking container
with no picture in it and be reported as a success. That is the failure mode in §5.4, reached
by a file consisting of nothing but a header and an `EXIF` chunk.

**New attack surface this handler introduces.** None from dependencies. The chunk walker is
written in this repository, under the crate's panic-freedom lints, over the shared
checked-reading primitive, and it shares the Exif and XMP readers with the JPEG and PNG
handlers rather than adding parsers of its own. WebP carries no checksums at all, so unlike PNG
there is not even a CRC field to reason about. The residual risks are the ones safe Rust still
has — a hang or unbounded allocation on a hostile file — which is what the `webp` fuzz target
exists to find. A 180-second run over the seed corpus on 2026-08-19 executed 6.99 million inputs with no
crash, hang, or timeout; that is a smoke test, not the Phase 3 budget (ADR-0014).

### 7.5 What real producers showed (Phase 1)

The findings in §7.1–7.4 were reached against synthetic fixtures — files built to the
specification. On 2026-08-20 all four handlers were run over the fetch-on-demand corpus in
`real-producer-corpus/`: 102 files, comprising 23 camera and phone JPEGs (Canon, Nikon, Sony,
Samsung, HMD, Jolla, Apple), 23 PDFs (pdfLaTeX, LibreOffice, Google Docs, Acrobat,
ImageMagick), 27 PNGs and 28 WebPs. Each was put through `show`, then `strip`, then `show`
again on the output.

**No panic, no hang, and no silent pass-through occurred.** Ninety-six files processed and
re-inspected clean. Five were refused, four of them correctly: three deliberately truncated
generated files, and one password-protected LibreOffice document, which exercised the
encryption refusal in §7.1 against a real file for the first time. Real Canon, Nikon and Sony
MakerNote blocks — the least standardised region in Exif, and the one §7.2 calls out as the
most likely to hide a parser bug — were handled without incident.

**Refreshing the PDF fuzz seeds found a real bug, and it is worth reading as a lesson about
where the verification pass does not reach.** ISO 32000-1 §7.3.8.2 requires a stream's
`/Length` to be an integer. Given `45.` instead, `lopdf` 0.44 parses the document, reports no
error, keeps the malformed value, and stores *empty* stream content because it cannot locate
the stream's end. strypt accepted that document, rewrote it, and emitted a PDF whose `/Length`
still claimed 45 bytes over an empty stream — structurally invalid by qpdf's reading, with the
page's content gone — while reporting "nothing to remove; wrote a clean copy". That is a §5.4
failure: a success message about a file that was not correctly processed.

**The verification pass did not catch it, and could not have.** It searches the output for
residual metadata, and a stream that has been emptied has none — the check and the defect were
looking at different properties. What caught it was the fuzz target's byte-for-byte
idempotence assertion, because a second strip produced different bytes again. This is the
argument for keeping invariants in the fuzz targets that duplicate no production check.

`load()` now refuses any document with a stream whose declared length disagrees with its
parsed content. The refusal costs nothing on real files: across the synthetic corpus and all
23 parseable real-producer PDFs, not one stream disagrees.

**One genuine gap surfaced, and it is a capability gap rather than a safety failure.**
`019-grayscale-image.pdf` writes cross-reference entries of 19 bytes instead of the 20 that
ISO 32000-1 §7.5.4 fixes them at, dropping the padding space before each newline. `qpdf
--check` reports no syntax errors on that file and **mat2 strips it successfully**, but
`lopdf` 0.44 — the parser strypt uses (ADR-0018), and already the newest release — rejects
the trailer, so strypt refuses a document that the tool it is most often compared with
handles. Padding the entries to 20 bytes makes it parse, confirming the cause.

This is recorded as a known gap rather than worked around. Normalising a cross-reference
table before parsing would mean rewriting untrusted bytes ahead of the parser, in the most
security-sensitive path in the project, to widen what strypt accepts — the wrong trade for
this tool. Refusing is the correct fail-closed behaviour (§5.4): the user is told the file was
not processed and can reach for another tool, which is the outcome that keeps them safe.
Where mat2 handles a file strypt cannot, mat2 is the better recommendation, and this is such a
case.

`corpus/pdf/malformed/xref-19-byte-entries.pdf` reproduces the structure synthetically — the
upstream file carries a real person's name, which §3 of `docs/TESTING_STRATEGY.md` keeps out
of the committed corpus. The accompanying test pins the refusal as a *typed* `Malformed`
error, so that if a future `lopdf` becomes tolerant here, the change is noticed rather than
absorbed silently.

**Both WebP coverage gaps were closed on 2026-08-21**, and both passed.

- **The format-conversion path** — metadata surviving a change of container — is now exercised
  by `generated/webp/from-jpeg-exif.webp`, produced by `cwebp -metadata all` from the real
  `Canon_40D.jpg` already in the corpus. It carries 2468 bytes of genuine Canon Exif and a
  3144-byte ICC profile across into WebP, **including the IFD1 thumbnail — a small picture of
  the original scene**, which is the most under-appreciated leak in this class. strypt removes
  all of it: 92 ExifTool tags before, none after, and the output holds only `VP8X` with an
  empty flags byte and `VP8`. Every other WebP in the corpus was born a WebP, so nothing else
  tested this.
- **A genuinely browser-encoded WebP** is now `webp/browser/chrome-canvas.webp`, produced by
  Chrome 151's own encoder via `canvas.toDataURL('image/webp')`. Chrome writes an extended file
  with an `ICCP` chunk; the profile is a generic sRGB one stamped `1998:02:09` and naming no
  device, which is Chrome declining to fingerprint the display rather than an oversight.
  strypt removes it and clears the flag. This file is built only under
  `build_real_corpus.py --with-browser`, because browsers auto-update and its bytes would
  otherwise churn the committed manifest on every contributor's machine.

**What this sweep still does not establish.** Every category directory beneath
`real-producer-corpus/real-corpus/` is a coverage bucket, not a verified producer claim — the
`chrome/`, `firefox/` and `android/` WebP directories hold reference-encoder conformance files,
and the manifest says so per row. 29 of the files are marked `LOW` provenance, and the file
above is one of them: its "scanner" bucket is unverified. `chrome-canvas.webp` is the corpus's
only WebP with a `HIGH`-confidence producer claim, and even it exercises a canvas export rather
than a browser re-encoding a photograph that arrived with Exif.

The corpus is **not committed** (`.gitignore`), because its files carry real names, a device
serial number, and live GPS coordinates, which §3 of `docs/TESTING_STRATEGY.md` keeps out of
this repository. `build_real_corpus.py` and the manifests are committed, and a rebuild
reproduces all 102 fixtures byte-identically, so this sweep is repeatable by anyone.

### 7.6 Office Open XML — `.docx`, `.xlsx`, `.pptx` (Phase 2)

*Written 2026-08-23, from what the handler, the fuzz targets, and the mat2/ExifTool differential
actually showed — not from the specification.*

**The structural difference from every Phase 1 format.** A JPEG is one file with metadata
segments in it. An OOXML document is a ZIP archive of XML parts, and one class of part is *whole
files with their own metadata* — the photographs the author pasted in, arriving with whatever
their cameras wrote. Phase 1's mental model, "walk the container and drop the metadata regions",
covers about half of what this format needs.

**The leak that matters most here is the one that is not in the document's own metadata.** A
user strips a report, publishes it, and has published every geotag in every picture inside it,
while holding a success message saying the document was cleaned. That is the failure in §5.4
arriving by a new route, and it is why ADR-0029 descends one level into embedded images rather
than stopping at `docProps/`.

**Where the metadata was, in the order a user would be surprised by it:**

| Location | What it carries |
|---|---|
| `word/media/*`, `xl/media/*`, `ppt/media/*` | Whole JPEG/PNG/WebP files with GPS, camera serial numbers, and Exif thumbnails of the uncropped original |
| `docProps/core.xml` | `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`, `dcterms:modified`, `cp:revision` |
| `docProps/app.xml` | `Application`, `AppVersion`, `Company`, `Manager`, and `TotalTime` — cumulative editing minutes |
| `docProps/custom.xml` | Arbitrary named properties; document management systems write internal matter numbers and usernames here |
| `docProps/thumbnail.*` | A rendered preview of the first page, which survives every redaction applied to the text |
| `w:rsid*` attributes, `w:rsids` in `settings.xml` | Revision-save identifiers. Two documents sharing one were edited in the same session on the same machine |
| `w14:paraId`, `w14:textId` | Per-paragraph identifiers, stable across saves *and across copies* |
| `w:ins`, `w:del`, `w:comment`, `p:cmAuthor`, `xl` `<author>` | Author names, initials, and timestamps sitting inline in the body |
| ZIP entry headers | A modification time per part — a record of the author's working hours that no application displays |
| ZIP extra fields | Unix UID/GID (0x7875), NTFS times (0x000A), extended timestamps (0x5455) |
| External relationships | `file:` and UNC targets. An attached template under someone's home directory names that person |

**What was learned that the specification does not say.**

- **Removing a part is not enough, and the failure is loud.** `[Content_Types].xml` and
  `_rels/.rels` still refer to what went, and Word offers to *repair* the result. For a user
  trying not to draw attention to a document, a repair prompt is a worse outcome than a slightly
  larger file. Both index parts are rewritten (ADR-0030).
- **Writing an index part twice is silently tolerated.** An early version of the handler emitted
  `[Content_Types].xml` in the entry loop *and* again in a post-pass. Every reader tried —
  Python's `zipfile` included — accepted the duplicate without complaint, preferring one copy
  arbitrarily. Nothing caught it except the byte-identical idempotence check. This is recorded
  because it generalises: **a ZIP reader's tolerance hides writer bugs**, so a container handler
  needs an invariant that does not depend on a reader noticing.
- **The package's own declaration is the only reliable way to tell these formats apart.** `.docx`,
  `.xlsx`, `.pptx` and every OpenDocument file share one magic number. Searching the raw bytes
  for `word/document.xml` would work until it did not: the string appears verbatim in any archive
  that merely *contains* a Word document, and an attacker can put it in a comment. Detection
  opens the container and reads the declared main-part content type (ADR-0027).
- **The `create_system` byte is a producer fingerprint that no one thinks about.** strypt writes
  a constant 0 (MS-DOS/FAT), which is what Word writes. mat2 normalises the same field to 3,
  which says "made on Linux". Neither leaks the real host; the difference is which constant
  blends in.

**What is deliberately kept, and why.**

- **The words of comments and tracked changes.** Removing a tracked insertion means deciding
  whether the document accepts or rejects it, and that changes what the document *says*.
  `docs/PRD.md` §8.1 gives the payload priority, and a tool that silently accepted every pending
  revision would hand a journalist a document different from the one they reviewed. Their author
  names, initials, and dates are removed — those are metadata sitting on content, and removing
  them changes no words. A `Note` reports that the revision content remains.
- **Any part strypt does not recognise**, copied through with a `Note::UnparsedRegion` naming it.
  Unlike WebP's unknown chunks (ADR-0023), an unrecognised OOXML part may be load-bearing —
  dropping a theme or a font table breaks the document — so the honest move is to copy it and
  say plainly that nobody looked inside.

**What is refused rather than half-processed.** Each of these produces no output file at all:

- A **macro-enabled** document (`.docm`, `.xlsm`, `.pptm`). Its `vbaProject.bin` is an OLE
  compound file with its own directory and its own metadata streams that strypt cannot read.
- A document containing a **nested archive, an embedded PDF, or an OLE object**. ADR-0029 fixes
  the descent at one level; a `.docx` inside a `.docx` is not something to partially clean. This
  refuses real documents — a chart's cached workbook at `word/embeddings/*.xlsx` is common — and
  that cost is accepted, because such a workbook carries its own author names.
- An **encrypted entry**, any **compression method other than stored or deflate**, a
  **multi-disk archive**, and an entry name that is absolute or contains `..`.

**Known limitations, stated plainly.**

1. **Comments and tracked changes remain in the document.** Their attribution is removed; their
   text is not. **For a document whose comments must not be published, mat2 is the better
   recommendation** — it removes the parts outright. ADR-0012 requires saying so where it is
   true, and it is true here.
2. **Output is not byte-identical to input even for a clean document.** A rewritten part is
   re-emitted stored where it arrived deflated (ADR-0028), and entry timestamps are normalised.
   Idempotence *is* byte-identical, and is tested. The Phase 1 image handlers can promise the
   stronger property for a clean file and this one cannot.
3. **A damaged OOXML package is reported as an unsupported ZIP container, not as a damaged
   document.** Detection has to read `[Content_Types].xml` to know what the file is; if that part
   cannot be read, there is nothing to distinguish the file from any other archive. The refusal
   is correct and fail-closed, but its wording is less useful than it could be.
4. **`vbaProject.bin`, OLE objects, fonts, and audio are not inspected.** They are refused
   (containers) or copied with a note (fonts, media strypt has no handler for).
5. **XML is scanned, not parsed.** Entities are not resolved and nesting is not validated. An
   attribute is removed on the strength of its name, and a name cannot be spelled with an entity
   reference — but a producer doing something genuinely unusual with XML could in principle
   defeat the scanner, in which case the part is copied through unchanged rather than edited on
   a guess.

**Differential result (2026-08-23).** `scripts/ooxml-differential.sh` over all 13 fixtures,
against mat2 0.15.0 and ExifTool 13.55: **no gaps** — nothing survives strypt that does not also
survive mat2, and ExifTool finds no GPS, serial, artist, or owner tag in any output. One finding
in the other direction, recorded because it is interesting rather than because it flatters:
**mat2 refuses `presentation.pptx` outright**, because `ppt/commentAuthors.xml` is not on its
content-type whitelist, and strypt processes it. Two comparison exclusions (`date_time`,
`create_system`) are justified in the script's own comments; both are values *both* tools
normalise to a constant.

**Fuzzing (2026-08-23).** Short runs only, and stated as such: 3.53M executions on the `ooxml`
target and 9.05M on the `zip` target, both clean, no artefacts. That is the definition-of-done
smoke bar, **not** a sustained run and not Phase 1 exit criterion 2's bar. A sustained run
covering the two new targets is owed before this format group can be called done.

---

## 8. Review triggers

Update this document when:

- A format handler is added or substantially changed — **mandatory**.
- Fuzzing or differential testing reveals a new class of hidden data.
- A dependency handling untrusted input is added or swapped.
- A new front-end (GUI, file-manager integration, FFI) creates a new trust boundary.
- Any metadata-leak vulnerability is reported, whatever the outcome.
- At each phase transition, as a scheduled review even absent a specific trigger.
