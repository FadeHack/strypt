# Test corpus manifest

Every fixture is documented here: where it came from, what metadata it carries, and what it
is testing. An undocumented fixture is a file nobody dares change.

## Rules

- **No file may contain real personal data.** Fixtures are committed publicly and
  permanently. A corpus that leaks someone's location would be an unusually humiliating
  failure for this project in particular (`docs/TESTING_STRATEGY.md` §3).
- Fixtures are **generated**, not collected, wherever that is possible — it makes the rule
  above structural rather than a habit someone has to remember.
- Marker strings are deliberately unmistakable (`SYNTHETIC-…-000N`) so that a test can assert
  on the *bytes of the output* rather than on strypt's own report. A handler that forgot to
  remove something would still report having removed it.
- Fixtures stay small. Large ones belong in a fetched-on-demand corpus, not in git forever.

## Regenerating

```
python3 corpus/tools/make_pdf_fixtures.py
```

Deterministic: two runs produce byte-identical files, so a fixture appearing in `git diff`
means the generator changed.

## PDF

| Fixture | Carries | Tests |
|---|---|---|
| `info-dictionary.pdf` | Author, Creator, Producer, Title, Subject, Keywords, CreationDate, ModDate, a non-standard `CustomVendorField`, and a trailer `/ID` | The baseline case, plus that vendor-invented keys are not walked past |
| `xmp-packet.pdf` | An uncompressed XMP packet: `dc:creator`, `xmp:CreatorTool`, `xmp:CreateDate`, `xmp:ModifyDate`, `xmpMM:DocumentID`, `xmpMM:InstanceID`, `pdf:Producer` | That XMP is found, broken down by property, and removed |
| `incremental-update.pdf` | Two saves. The first save's author (`SYNTHETIC-ORPHANED-AUTHOR-0005`) is still in the file, referenced by nothing | **The fixture that justifies ADR-0020.** A tool that patches rather than rewrites leaves the orphaned author in place and reports the file clean |
| `annotation-author.pdf` | A `/Text` markup annotation with `/T`, `/M`, `/CreationDate`, `/NM`, and a comment | That the annotator's name goes and the comment stays — strypt removes metadata, not content |
| `form-field.pdf` | A `/Widget` annotation whose `/T` is the field name `applicant_surname` | That `/T` is **not** removed here. On a widget it is the field name the form's logic and saved data depend on; removing it breaks the document |
| `piece-info.pdf` | `/PieceInfo` private application scratch data and `/LastModified` | That application-private storage is removed |
| `embedded-file.pdf` | A `/Filespec` attachment with `/Desc` and `/Params` dates | That attachment metadata is removed, the attachment itself is preserved, and the report says plainly that strypt did not open it |
| `clean.pdf` | Nothing | That a clean file produces no findings. A tool that invents findings teaches users to ignore it |

### Not yet represented

Recorded so the gaps are visible rather than forgotten. These need real-world producers and
are the corpus's main weakness today:

- Files from actual producers: LaTeX, Word, Acrobat, LibreOffice, scanners, browser
  print-to-PDF. The fixtures above are synthetic, so they test strypt against the
  specification rather than against what real software emits — and real software is where the
  quirks live.
- Linearised ("fast web view") files.
- Object streams and cross-reference streams (PDF 1.5+), which most modern producers emit and
  which none of the fixtures above use.
- Encrypted documents. Refused by design (`crates/strypt-core/src/formats/pdf.rs`), but the
  refusal is not yet covered by a fixture.

## JPEG, PNG, WebP

Not yet present — those handlers have not landed.
