# strypt — Threat Model

**Status:** Draft, Phase 0 · **Last updated:** 2026-08-19

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

**New attack surface this handler introduces.** `lopdf` is a third-party PDF parser processing
attacker-controlled bytes, and this project's no-panic rule does not extend to it (ADR-0018).
`#![forbid(unsafe_code)]` rules out memory-corruption exploitation; it does not rule out a
panic, a hang, or unbounded allocation originating inside the dependency. This is the largest
piece of untrusted-input surface in the tree and it is not code we control. It is why the PDF
fuzz target exists, and it is a specific input to Phase 3's sandboxing decision — containing a
compromised or merely fragile dependency is one of the few things sandboxing genuinely buys a
safe-Rust parser.

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

---

## 8. Review triggers

Update this document when:

- A format handler is added or substantially changed — **mandatory**.
- Fuzzing or differential testing reveals a new class of hidden data.
- A dependency handling untrusted input is added or swapped.
- A new front-end (GUI, file-manager integration, FFI) creates a new trust boundary.
- Any metadata-leak vulnerability is reported, whatever the outcome.
- At each phase transition, as a scheduled review even absent a specific trigger.
