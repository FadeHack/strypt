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

## 7. Review triggers

Update this document when:

- A format handler is added or substantially changed — **mandatory**.
- Fuzzing or differential testing reveals a new class of hidden data.
- A dependency handling untrusted input is added or swapped.
- A new front-end (GUI, file-manager integration, FFI) creates a new trust boundary.
- Any metadata-leak vulnerability is reported, whatever the outcome.
- At each phase transition, as a scheduled review even absent a specific trigger.
