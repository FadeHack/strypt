//! PDF.
//!
//! The hardest of the Phase 1 formats, and the one where hidden data is least likely to be
//! where you look for it. The Document Information Dictionary is the easy part and the part
//! every tutorial covers; the leaks that matter live in XMP packets, per-object metadata,
//! annotation authorship, and — above all — in objects left behind by incremental updates,
//! which are physically present in the file and reachable with a hex editor long after the
//! "current" version of the document stopped referring to them.
//!
//! # Full rewrite, not incremental patching (ADR-0020)
//!
//! A PDF can be edited by appending: the original bytes stay, and a new cross-reference
//! section at the end says which objects supersede which. Nulling the Info dictionary with
//! another such append is easy, fast, and preserves the file almost perfectly — and it leaves
//! every previous author name exactly where it was, four kilobytes up the file. For this
//! tool that is not a lesser fix, it is a silent failure: the user is told the document is
//! clean and publishes it.
//!
//! So the document is parsed into its object graph, scrubbed, pruned to what the catalogue
//! can actually reach, renumbered, and written out fresh. Everything unreachable — every
//! superseded revision — is gone because it is never written, not because it was overwritten.
//!
//! The cost is honest and worth stating: the output is not byte-comparable with the input,
//! object numbering changes, and files using features the rewrite cannot faithfully reproduce
//! are refused rather than mangled. Refusing is the correct half of that trade.

use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::xmp::name_of;
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, StripReport,
};

/// Removal of metadata from PDF documents.
#[derive(Debug, Clone, Copy, Default)]
pub struct PdfHandler;

impl MetadataHandler for PdfHandler {
    fn name(&self) -> &'static str {
        Format::Pdf.id()
    }

    fn format(&self) -> Format {
        Format::Pdf
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection loads its own copy of the document and runs the *same* scrub that
        // stripping does, then throws the result away. That is deliberate: it makes
        // "everything `strip` removes is something `inspect` can see" true by construction
        // rather than by two code paths agreeing to stay in step. The verification pass in
        // `crate::pipeline` is only meaningful if that holds (`docs/ARCHITECTURE.md` §3).
        let limits = ParseLimits::default();
        let mut doc = load(input, &limits)?;
        let scrubbed = scrub(&mut doc, input, options, &limits)?;
        Ok(MetadataReport {
            format: Format::Pdf,
            findings: scrubbed.findings,
            notes: scrubbed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let mut doc = load(input, &options.limits)?;
        let mut scrubbed = scrub(&mut doc, input, &options.inspect, &options.limits)?;

        // Drop every object the catalogue can no longer reach. This is the step that removes
        // superseded revisions, and it has to come after scrubbing so that objects orphaned
        // *by* the scrub — the Info dictionary, XMP streams — go with them.
        let pruned = doc.prune_objects();
        if !pruned.is_empty() {
            scrubbed.notes.push(Note::OrphanedObjectsRemoved {
                objects: pruned.len(),
            });
        }

        // Renumber so that output depends only on the object graph, not on the numbering the
        // input happened to use. Without this, two documents that scrub to the same content
        // serialise differently, and the determinism invariant
        // (`docs/TESTING_STRATEGY.md` §1) fails for no good reason.
        doc.renumber_objects();

        // Collapse negative zero to zero for the same reason renumbering exists above: without
        // it the output is not stable under a second strip. lopdf writes `Real(-0.0)` as `-0`,
        // dropping the decimal point; re-parsing `-0` yields `Integer(0)`, which writes as `0`.
        // So one strip of a file containing `-0.` differs from two, breaking the idempotence
        // invariant (`docs/TESTING_STRATEGY.md` §1, invariant 3).
        //
        // Rewriting a number in the user's document needs justifying, since this handler
        // otherwise refuses rather than repairs (ADR-0018). It is sound here because ISO
        // 32000-1 §7.3.3 gives PDF numbers no signed zero: `-0` and `0` denote the same value,
        // there is no operator that can distinguish them, and no renderer can. The alternative
        // — refusing a valid file over a lost minus sign that changes nothing — costs the user
        // their document to protect a distinction the format does not make.
        normalise_negative_zero(&mut doc, &options.limits)?;

        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).map_err(|source| StryptError::Io {
            action: crate::error::IoAction::WritingOutput,
            source,
        })?;

        Ok(Stripped {
            report: StripReport {
                format: Format::Pdf,
                removed: scrubbed.findings,
                retained: Vec::new(),
                notes: scrubbed.notes,
                input_bytes: as_u64(input.len()),
                output_bytes: as_u64(bytes.len()),
            },
            bytes,
        })
    }
}

/// Findings and caveats from one pass over a document.
struct Scrubbed {
    findings: Vec<Finding>,
    notes: Vec<Note>,
}

/// Parse `input`, refusing documents this handler must not rewrite.
fn load(input: &[u8], limits: &ParseLimits) -> Result<Document> {
    let doc = Document::load_mem(input).map_err(|e| map_parse_error(&e))?;

    // Encrypted documents are refused rather than rewritten. lopdf can open one protected by
    // an empty owner password, and it would be technically easy to emit a decrypted copy —
    // but that hands the user a file with its protection quietly removed, which is a change
    // to their document's security they did not ask for and would not necessarily notice.
    // Fail closed and say so.
    if doc.is_encrypted() || doc.was_encrypted() {
        return Err(StryptError::Malformed {
            format: Format::Pdf,
            offset: None,
            detail: MalformedDetail::UnsupportedFeature,
        });
    }

    let too_many = u32::try_from(doc.objects.len()).map_or(true, |count| count > limits.max_items);
    if too_many {
        return Err(StryptError::LimitExceeded {
            format: Format::Pdf,
            limit: ResourceLimit::ItemCount,
        });
    }

    // Every stream's declared /Length must be an integer that matches the content actually
    // parsed out of it.
    //
    // ISO 32000-1 §7.3.8.2 requires /Length to be an integer giving the exact byte count
    // between "stream" and "endstream". When it is not — a fuzz case reached here by writing
    // "/Length 45." instead of "/Length 45" — lopdf 0.44 parses the object, keeps the
    // malformed value in the dictionary, and stores *empty* content, because it cannot locate
    // the stream's end. It reports no error while doing so.
    //
    // Left unchecked, the document reaches the rewriter with the stream's bytes already gone.
    // strypt then writes a file whose /Length still claims 45 bytes over an empty stream, and
    // reports "nothing to remove; wrote a clean copy" — a structurally invalid PDF, missing
    // the user's page content, presented as a success. That is the §5.4 failure the whole
    // design is arranged to avoid, and the reason it went unnoticed is that the verification
    // pass looks for residual *metadata*, which an emptied stream has none of.
    //
    // Refusing costs nothing on real documents: across the synthetic corpus and all 23
    // parseable PDFs of the real-producer corpus — pdfLaTeX, LibreOffice, Google Docs,
    // Acrobat and ImageMagick output, compressed streams included — not one stream disagrees
    // with its declared length.
    for object in doc.objects.values() {
        let Ok(stream) = object.as_stream() else {
            continue;
        };
        let declared = stream
            .dict
            .get(b"Length")
            .ok()
            .and_then(|length| length.as_i64().ok())
            .and_then(|length| usize::try_from(length).ok());
        if declared != Some(stream.content.len()) {
            return Err(StryptError::Malformed {
                format: Format::Pdf,
                offset: None,
                detail: MalformedDetail::LengthOutOfRange,
            });
        }
    }

    Ok(doc)
}

/// Translate a parser failure into something a user can act on.
///
/// The mapping is coarse on purpose. "Your file is truncated" and "your file is not really a
/// PDF" lead to different actions; which of thirty-four internal variants fired does not.
fn map_parse_error(error: &lopdf::Error) -> StryptError {
    use lopdf::Error as E;
    let detail = match *error {
        E::Parse(_) | E::Syntax(_) | E::IndirectObject { .. } | E::ObjectIdMismatch => {
            MalformedDetail::UnexpectedMarker
        }
        E::Xref(_) | E::MissingXrefEntry | E::InvalidObjectStream(_) => {
            MalformedDetail::BrokenIndex
        }
        E::InvalidOffset(_) | E::ObjectNotFound(_) | E::NumericCast(_) | E::TryFromInt(_) => {
            MalformedDetail::LengthOutOfRange
        }
        E::ReferenceCycle(_) | E::ReferenceLimit => MalformedDetail::CyclicReference,
        E::IO(_) => MalformedDetail::Truncated,
        E::Decryption(_)
        | E::InvalidPassword
        | E::AlreadyEncrypted
        | E::UnsupportedSecurityHandler(_)
        | E::Unimplemented(_) => MalformedDetail::UnsupportedFeature,
        _ => MalformedDetail::MissingMarker,
    };
    let offset = match *error {
        E::InvalidOffset(at) | E::IndirectObject { offset: at } => u64::try_from(at).ok(),
        _ => None,
    };
    StryptError::Malformed {
        format: Format::Pdf,
        offset,
        detail,
    }
}

/// Keys in the Document Information Dictionary, and what each one exposes.
///
/// `/Creator` names the application the document was *authored* in and `/Producer` the one
/// that wrote the PDF — so a LaTeX paper typically confesses both its editor and its
/// toolchain version here. Neither identifies a person alone; together with a timestamp and
/// a font list they narrow the field a great deal (`docs/THREAT_MODEL.md` §4.7).
const INFO_KEYS: &[(&[u8], MetadataKind)] = &[
    (b"Author", MetadataKind::PersonalIdentity),
    (b"Creator", MetadataKind::SoftwareFingerprint),
    (b"Producer", MetadataKind::SoftwareFingerprint),
    (b"CreationDate", MetadataKind::Timestamp),
    (b"ModDate", MetadataKind::Timestamp),
    (b"Title", MetadataKind::Comment),
    (b"Subject", MetadataKind::Comment),
    (b"Keywords", MetadataKind::Comment),
    (b"Trapped", MetadataKind::Other),
];

/// Keys removed from *any* dictionary in the document, wherever they appear.
///
/// These are safe to remove anywhere because the PDF specification gives them one meaning
/// each and nothing renders differently without them. `/PieceInfo` is the interesting one:
/// it is a scratch area where an application may store whatever private state it likes
/// between editing sessions, and what ends up in it is entirely up to that application.
const GLOBAL_KEYS: &[(&[u8], MetadataKind)] = &[
    (b"Metadata", MetadataKind::Other),
    (b"PieceInfo", MetadataKind::EditingHistory),
    (b"LastModified", MetadataKind::Timestamp),
];

/// Annotation subtypes whose `/T` entry is the annotating person's name.
///
/// This distinction matters. On a markup annotation `/T` is the author — exactly what we are
/// here to remove. On a `/Widget`, which is how every interactive form field is drawn, `/T`
/// is the *field name* that the form's logic and its saved data refer to. Stripping it would
/// silently break the document, and breaking a user's file to protect them is not a trade
/// this tool gets to make on their behalf without saying so.
const MARKUP_ANNOTATION_SUBTYPES: &[&[u8]] = &[
    b"Text",
    b"FreeText",
    b"Line",
    b"Square",
    b"Circle",
    b"Polygon",
    b"PolyLine",
    b"Highlight",
    b"Underline",
    b"Squiggly",
    b"StrikeOut",
    b"Stamp",
    b"Caret",
    b"Ink",
    b"FileAttachment",
    b"Sound",
    b"Movie",
    b"Redact",
];

/// Walk the document, recording what is there and removing it.
fn scrub(
    doc: &mut Document,
    raw: &[u8],
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Scrubbed> {
    let mut findings = Vec::new();
    let mut notes = Vec::new();

    let info_id = trailer_reference(doc, b"Info");

    // Phase one reads. Every object is examined, not merely the ones the catalogue can reach:
    // an orphan from a superseded revision is exactly the thing worth telling the user about,
    // and it is invisible to a walk that starts at the root.
    let object_ids: Vec<ObjectId> = doc.objects.keys().copied().collect();
    for id in &object_ids {
        let Some(object) = doc.objects.get(id) else {
            continue;
        };
        examine_object(object, *id, info_id, options, limits, 0, &mut findings)?;
    }
    if doc.trailer.has(b"ID") {
        // The file identifier is a pair of strings that stays stable across saves of the same
        // document. It identifies nobody by itself and links every copy and every revision of
        // the document to each other, which for a leaked draft is the whole question.
        findings.push(Finding::new(
            MetadataKind::DocumentIdentifier,
            "trailer /ID",
            0,
        ));
    }

    // A PDF that has been saved more than once ends with more than one %%EOF. Counting them
    // is cruder than walking the cross-reference chain and tells the user the thing that
    // actually matters: earlier versions of this document were sitting inside it.
    let revisions = count_revisions(raw);
    if revisions > 1 {
        notes.push(Note::IncrementalHistory {
            revisions: revisions.saturating_sub(1),
        });
    }

    // Phase two writes.
    doc.trailer.remove(b"Info");
    doc.trailer.remove(b"ID");
    for id in &object_ids {
        if let Some(object) = doc.objects.get_mut(id) {
            remove_from_object(object, *id, info_id, limits, 0)?;
        }
    }

    if object_ids
        .iter()
        .filter_map(|id| doc.objects.get(id))
        .any(is_embedded_file_holder)
    {
        // strypt does not open embedded files. Recursing into them means recursing into
        // arbitrary nested content, which is a zip-bomb-shaped problem that Phase 2 has to
        // decide about explicitly. Until then the user is told, because an attachment
        // carrying its own metadata inside a document reported as clean is precisely the
        // over-trust this tool must not create (`docs/THREAT_MODEL.md` §5.6).
        notes.push(Note::OutOfScopeContent {
            location: "embedded file attachment".into(),
        });
    }

    Ok(Scrubbed { findings, notes })
}

/// Resolve a reference held in the trailer, if it is one.
fn trailer_reference(doc: &Document, key: &[u8]) -> Option<ObjectId> {
    doc.trailer
        .get(key)
        .ok()
        .and_then(|o| o.as_reference().ok())
}

/// Count `%%EOF` markers, each of which terminates one revision of the document.
fn count_revisions(raw: &[u8]) -> usize {
    const EOF: &[u8] = b"%%EOF";
    raw.windows(EOF.len()).filter(|w| *w == EOF).count()
}

/// Record everything identifying inside one object.
fn examine_object(
    object: &Object,
    id: ObjectId,
    info_id: Option<ObjectId>,
    options: &InspectOptions,
    limits: &ParseLimits,
    depth: u32,
    out: &mut Vec<Finding>,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(StryptError::LimitExceeded {
            format: Format::Pdf,
            limit: ResourceLimit::Depth,
        });
    }
    match object {
        Object::Dictionary(dict) => {
            if Some(id) == info_id {
                examine_info(dict, options, out);
            }
            examine_dictionary(dict, id, info_id, options, limits, depth, out)?;
        }
        Object::Stream(stream) => {
            if is_metadata_stream(&stream.dict) {
                examine_xmp(stream, options, out);
            }
            examine_dictionary(&stream.dict, id, info_id, options, limits, depth, out)?;
        }
        Object::Array(items) => {
            for item in items {
                examine_object(
                    item,
                    id,
                    info_id,
                    options,
                    limits,
                    depth.saturating_add(1),
                    out,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Record the Document Information Dictionary, including keys the specification never
/// defined — applications add their own freely, and a custom key is no less identifying for
/// being non-standard.
fn examine_info(dict: &Dictionary, options: &InspectOptions, out: &mut Vec<Finding>) {
    for (key, value) in dict {
        let kind = INFO_KEYS
            .iter()
            .find(|(name, _)| *name == key.as_slice())
            .map_or(MetadataKind::Other, |(_, kind)| *kind);
        out.push(
            Finding::new(kind, "/Info", value_size(value))
                .with_field(name_of(key))
                .with_value(options, || describe(value)),
        );
    }
}

/// Record the globally-removable keys, and annotation authorship.
fn examine_dictionary(
    dict: &Dictionary,
    id: ObjectId,
    info_id: Option<ObjectId>,
    options: &InspectOptions,
    limits: &ParseLimits,
    depth: u32,
    out: &mut Vec<Finding>,
) -> Result<()> {
    for (name, kind) in GLOBAL_KEYS {
        if let Ok(value) = dict.get(name) {
            out.push(
                Finding::new(*kind, format!("/{}", name_of(name)), value_size(value))
                    .with_field(name_of(name)),
            );
        }
    }
    if is_markup_annotation(dict) {
        for (name, kind) in [
            (&b"T"[..], MetadataKind::PersonalIdentity),
            (&b"M"[..], MetadataKind::Timestamp),
            (&b"CreationDate"[..], MetadataKind::Timestamp),
            (&b"NM"[..], MetadataKind::DocumentIdentifier),
        ] {
            if let Ok(value) = dict.get(name) {
                out.push(
                    Finding::new(kind, "annotation", value_size(value))
                        .with_field(name_of(name))
                        .with_value(options, || describe(value)),
                );
            }
        }
    }
    // Embedded-file parameters carry their own creation and modification dates, which survive
    // every scrub aimed only at the containing document.
    if let Ok(Object::Dictionary(params)) = dict.get(b"Params") {
        for name in [&b"CreationDate"[..], &b"ModDate"[..], &b"CheckSum"[..]] {
            if let Ok(value) = params.get(name) {
                out.push(
                    Finding::new(MetadataKind::Timestamp, "/Params", value_size(value))
                        .with_field(name_of(name)),
                );
            }
        }
    }
    for (_, value) in dict {
        examine_object(
            value,
            id,
            info_id,
            options,
            limits,
            depth.saturating_add(1),
            out,
        )?;
    }
    Ok(())
}

/// Scan an XMP packet for the properties worth naming.
///
/// Only unfiltered packets are scanned. ISO 32000-1 §14.3.2 recommends that a metadata stream
/// be left uncompressed precisely so it can be read without parsing the whole document, and
/// in practice they almost always are. Refusing to inflate the rare compressed one avoids
/// handing an attacker a decompression bomb in exchange for a slightly more detailed report —
/// the packet is still found, still reported, and still removed either way.
fn examine_xmp(stream: &lopdf::Stream, options: &InspectOptions, out: &mut Vec<Finding>) {
    if stream.dict.has(b"Filter") {
        out.push(
            Finding::new(
                MetadataKind::Other,
                "XMP packet",
                as_u64(stream.content.len()),
            )
            .with_field("Metadata (encoded)"),
        );
        return;
    }
    out.extend(xmp::scan(&stream.content, "XMP packet", options));
}

/// Remove everything [`examine_object`] reports, from one object.
fn remove_from_object(
    object: &mut Object,
    id: ObjectId,
    info_id: Option<ObjectId>,
    limits: &ParseLimits,
    depth: u32,
) -> Result<()> {
    if depth > limits.max_depth {
        return Err(StryptError::LimitExceeded {
            format: Format::Pdf,
            limit: ResourceLimit::Depth,
        });
    }
    match object {
        Object::Dictionary(dict) => {
            if Some(id) == info_id {
                // The Info dictionary is emptied as well as unlinked. Unlinking alone would
                // be enough for a correct pruner, and relying on that would make this
                // handler's correctness depend on the pruner's — a dependency worth not
                // having in the one place where being wrong means a name survives.
                *dict = Dictionary::new();
                return Ok(());
            }
            remove_from_dictionary(dict, id, info_id, limits, depth)?;
        }
        Object::Stream(stream) => {
            remove_from_dictionary(&mut stream.dict, id, info_id, limits, depth)?;
        }
        Object::Array(items) => {
            for item in items {
                remove_from_object(item, id, info_id, limits, depth.saturating_add(1))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Rewrite every `Real(-0.0)` in the document as `Real(0.0)`.
///
/// See the call site for why this is done at all. Note the deliberate use of `is_sign_negative`
/// rather than `== -0.0`: in IEEE 754 `-0.0 == 0.0` is true, so the obvious comparison matches
/// positive zero as well and would rewrite values that were never a problem.
fn normalise_negative_zero(doc: &mut Document, limits: &ParseLimits) -> Result<()> {
    for object in doc.objects.values_mut() {
        normalise_object(object, limits, 0)?;
    }
    // The trailer is not in `objects` and is reached only by walking it explicitly. Missing it
    // is how the first version of this fix passed every local test and still failed: CI's fuzz
    // run moved a negative zero into the trailer within minutes, and the assertion fired again
    // on a document whose object graph was entirely clean.
    for (_, value) in &mut doc.trailer {
        normalise_object(value, limits, 0)?;
    }
    Ok(())
}

/// Walk one object, collapsing negative zeros wherever they nest.
fn normalise_object(object: &mut Object, limits: &ParseLimits, depth: u32) -> Result<()> {
    if depth > limits.max_depth {
        return Err(StryptError::LimitExceeded {
            format: Format::Pdf,
            limit: ResourceLimit::Depth,
        });
    }
    match object {
        Object::Real(value) if value.is_sign_negative() && *value == 0.0 => {
            *value = 0.0;
        }
        Object::Dictionary(dict) => {
            for (_, value) in dict.iter_mut() {
                normalise_object(value, limits, depth.saturating_add(1))?;
            }
        }
        Object::Stream(stream) => {
            for (_, value) in &mut stream.dict {
                normalise_object(value, limits, depth.saturating_add(1))?;
            }
        }
        Object::Array(items) => {
            for item in items {
                normalise_object(item, limits, depth.saturating_add(1))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Remove identifying keys from one dictionary and everything nested inside it.
fn remove_from_dictionary(
    dict: &mut Dictionary,
    id: ObjectId,
    info_id: Option<ObjectId>,
    limits: &ParseLimits,
    depth: u32,
) -> Result<()> {
    for (name, _) in GLOBAL_KEYS {
        dict.remove(name);
    }
    if is_markup_annotation(dict) {
        dict.remove(b"T");
        dict.remove(b"M");
        dict.remove(b"CreationDate");
        dict.remove(b"NM");
    }
    if let Ok(Object::Dictionary(params)) = dict.get_mut(b"Params") {
        params.remove(b"CreationDate");
        params.remove(b"ModDate");
        params.remove(b"CheckSum");
    }
    for (_, value) in &mut *dict {
        remove_from_object(value, id, info_id, limits, depth.saturating_add(1))?;
    }
    Ok(())
}

/// True for a stream that is an XMP metadata packet.
fn is_metadata_stream(dict: &Dictionary) -> bool {
    dict.get_type().is_ok_and(|t| t == b"Metadata")
        || dict
            .get(b"Subtype")
            .and_then(Object::as_name)
            .is_ok_and(|s| s == b"XML")
}

/// True for an annotation whose `/T` names a person rather than a form field.
fn is_markup_annotation(dict: &Dictionary) -> bool {
    let Ok(subtype) = dict.get(b"Subtype").and_then(Object::as_name) else {
        return false;
    };
    MARKUP_ANNOTATION_SUBTYPES.contains(&subtype)
}

/// True for a file-specification dictionary, which is how a PDF carries an attachment.
fn is_embedded_file_holder(object: &Object) -> bool {
    let dict = match object {
        Object::Dictionary(dict) => dict,
        Object::Stream(stream) => &stream.dict,
        _ => return false,
    };
    dict.has_type(b"Filespec") || dict.has(b"EmbeddedFiles")
}

/// The size of a value in bytes, where it has a meaningful one.
fn value_size(object: &Object) -> u64 {
    match object {
        Object::String(bytes, _) | Object::Name(bytes) => as_u64(bytes.len()),
        Object::Stream(stream) => as_u64(stream.content.len()),
        _ => 0,
    }
}

/// Render a value, for the callers that opted into seeing values.
fn describe(object: &Object) -> MetadataValue {
    match object {
        Object::String(bytes, _) | Object::Name(bytes) => MetadataValue::Text(name_of(bytes)),
        Object::Integer(n) => MetadataValue::Text(n.to_string()),
        Object::Boolean(b) => MetadataValue::Text(b.to_string()),
        other => MetadataValue::Opaque {
            bytes: value_size(other),
        },
    }
}

/// Widen a length for reporting. Saturating rather than fallible: a report field is not worth
/// failing an otherwise-successful strip over.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
