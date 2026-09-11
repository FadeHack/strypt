# Known limitations

What strypt leaves in a file, what it cannot see, and what it refuses. Everything here comes from
testing — fuzzing, the mat2/ExifTool differentials, the filesystem matrix — not from the
specifications. The detail and the evidence are in [`THREAT_MODEL.md`](THREAT_MODEL.md) §7, one
subsection per format.

**A report saying nothing was found does not mean a file is clean.** It means strypt found nothing
it knows to look for. No tool can promise more.

## Everywhere

- **Content is untouched.** Names in the text, faces and street signs in a photo, black boxes drawn
  over text: strypt removes metadata, not information, and does not redact
  ([THREAT_MODEL §4](THREAT_MODEL.md#4-what-strypt-does-not-protect-against)).
- **Encoded data is never decoded.** Anything hidden inside compressed pixels, audio frames or video
  samples is out of reach in every format. Audio, video and JPEG XL reports say so on every file.
- **Encoder fingerprints survive.** Compression tables, chunk ordering and track layout can identify
  the software, and sometimes the device, that made the file.
- **Filenames, filesystem timestamps, extended attributes and Windows alternate data streams are not
  touched.** Output gets a fresh modification time.
- **Output permissions depend on where you write.** On Unix the output is owner-only (`0600`), except
  on **FAT or exFAT drives**, where it takes the mount's mode, which is `0755` by default on Linux, so
  anyone who can read the drive can read it. On **Windows** the output has the permissions of the
  folder it is written to (ADR-0047).
- **No sandbox.** strypt runs with your permissions, and so would a compromised dependency
  (ADR-0048).
- **A refused file produces no output.** strypt refuses rather than partly cleans. Where mat2 handles
  a refused file, the table below says so.
- **Less fuzzing confidence for JPEG XL, Ogg and PNG.** No crash has been found, but those targets
  were still finding new code paths late in their 24-hour runs (ADR-0044).
- **Testing on real files is uneven.** The Phase 1 formats (JPEG, PNG, WebP, PDF) were checked
  against 102 files from real cameras and applications. The later formats were checked mostly
  against generated test files.
- **No external audit and no release.** Performance has been measured on one macOS machine.

## Where mat2 is the better choice

| Your file | Why |
|---|---|
| A `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods` or `.odp` whose comments or tracked changes must not be published | strypt keeps their text and removes only who wrote them and when. mat2 removes them outright |
| A PDF with 19-byte cross-reference entries | strypt refuses it; mat2 strips it |
| A TIFF or GIF where data may be hidden in the pixels | mat2 re-renders the image by default, which reaches the pixels |
| A WebP whose encoder fingerprint matters more than its animation | mat2 re-encodes the image and flattens any animation to one frame |
| An SVG with a script, event handler, `foreignObject` or `javascript:` link, or whose `<title>` and `<desc>` must go | strypt refuses the first and keeps the second. mat2 re-renders the drawing and loses its editable structure |
| An `.mp2`, or an MP3 with other data before the audio | strypt refuses it |
| A multiplexed or chained Ogg, or Theora video | strypt refuses it |
| A fragmented MP4 or a QuickTime `.mov` | strypt refuses it |
| A JPEG whose `APP14` (Adobe colour) segment must go | strypt keeps it, because CMYK images render wrongly without it. It names no one |

## By format

Kept items are listed in each strip report as retained, so you can see them.

**PDF**
- Kept: comment text (not its author or date), and form field names.
- Not opened: embedded attachments. Their dates go, but their contents stay as they are.
- Refused: encrypted documents, and files with no document root.
- Every run rewrites the file, so its layout carries strypt's fingerprint instead of the original
  producer's.

**JPEG**
- Kept: `APP0` (JFIF) and `APP14` (Adobe).
- Removed, which changes how the image looks: orientation (a rotated photo may display sideways) and
  the ICC profile (colours are read as sRGB).
- Refused: files with no end marker, or whose segment lengths disagree with the file's size.

**PNG**
- Kept: rendering chunks such as gamma, transparency and pixel density.
- An unknown *critical* chunk is copied and reported as unexamined. Decoders refuse such files
  anyway.

**WebP**
- An animation frame that doesn't parse is copied and reported as unexamined.
- The ICC profile is removed without being read.

**Office Open XML — `.docx`, `.xlsx`, `.pptx`**
- Kept: comment and tracked-change text.
- Copied with a note: unrecognised parts, and fonts and media strypt has no handler for.
- Refused: macro-enabled files, and documents with a nested archive, embedded PDF or OLE object.
  That includes the common Word chart that carries its own workbook.
- XML is scanned rather than parsed. A part the scanner can't follow is copied unchanged, with a
  note.

**OpenDocument — `.odt`, `.ods`, `.odp`**
- Kept: comment and tracked-change text, and dates printed in the document.
- Copied: `ObjectReplacements/` previews and fonts, unexamined. mat2 drops the previews.
- Refused: encrypted packages, and drawings, formulas, charts, databases and templates.
- Flat XML files (`.fodt`, `.fods`, `.fodp`) are refused as plain XML.

**TIFF**
- Data in the pixels is out of reach, and the ICC profile is removed.
- Refused: BigTIFF, and inconsistent strip geometry.

**GIF**
- Kept: the loop count, frame delays and transparency.
- Data in the pixels is out of reach.

**HEIF / AVIF**
- Kept: numeric colour signalling.
- Data in the pixels is out of reach, and the ICC profile is removed.
- **Apple Live Photos are refused.** Hidden thumbnails are removed, and ExifTool, ImageMagick and
  libheif don't show them.

**SVG**
- Kept: `<title>`, `<desc>` and external references. Each can identify an author.
- Refused: scripts, event handlers, `foreignObject`, `javascript:` links, doctype entities, `.svgz`,
  and non-UTF-8 files.

**JPEG XL**
- The codestream is never entered, so its ICC profile and any preview frame stay. The same is true
  for ExifTool and mat2.
- A bare codestream is returned unchanged.
- An unknown box refuses the file.
- Removing the JPEG reconstruction box ends exact JPEG round-tripping.

**FLAC**
- Kept: the audio MD5, which anyone holding the file can recompute.
- Removing the cuesheet ends splitting the file into tracks.

**WAV**
- Kept: cue points.
- Sample values are out of reach; mat2's rebuild doesn't reach them either.
- Removing the sampler chunk ends sampler looping.
- Refused: RF64 and BW64.

**MP3**
- Kept: the `Xing`/`Info`/`VBRI` frame, which names the encoder. mat2 keeps it too.
- Refused: tag lengths that don't add up.

**Ogg — Vorbis, Opus, FLAC-in-Ogg**
- The stream serial number is rewritten to zero, so a clean file does not come back byte-identical.
- Kept: the audio MD5 in Ogg-FLAC.
- Refused: Speex and Skeleton, along with the files in the table above.

**MP4 / M4A**
- Kept: the codec configuration.
- Zeroed rather than removed: creation times.
- The encoder's options inside H.264 video data (x264 writes them there) are out of reach, for mat2
  as well.
- Track count, durations and resolution survive.
- Refused: encrypted media and 3GPP. An encryption box inside an otherwise plain sample entry is not
  detected.
