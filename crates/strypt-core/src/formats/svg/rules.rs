//! What in an SVG is identifying, what is the picture, and what makes strypt refuse the file.
//!
//! The scanning and the cutting are [`crate::formats::xml`], shared with the two package formats.
//! What is here is only SVG's half, and none of it transfers from theirs: Office Open XML and
//! `OpenDocument` keep their metadata in *named parts of a package*, while an SVG is one document
//! in which the metadata, the picture, the accessibility text, and — if the author wanted — an
//! executable program all sit in the same element tree.
//!
//! ADR-0035 is required reading. Its four decisions are the four things in this module that a
//! reader would otherwise ask about:
//!
//! 1. A file that can run code is **refused**, not partly cleaned ([`SCRIPT_ELEMENTS`]).
//! 2. A reference to something outside the document is **reported and never removed**, because
//!    removing it would silently turn a file that draws a linked logo into one that draws nothing.
//! 3. A raster image in a `data:` URI is **descended into exactly once**, through the same handler
//!    the CLI uses on a loose file (ADR-0029 unchanged).
//! 4. `<title>` and `<desc>` are **kept and declared**, because they are what a screen reader
//!    announces — the same call ADR-0031 made about an `OpenDocument` comment's words.
//!
//! # The allow-list runs on namespace prefixes
//!
//! A name reaches the output only if its prefix is one the picture cannot be drawn without —
//! `xlink:`, `xml:`, or no prefix at all, which is the SVG namespace itself. Everything else goes,
//! **including prefixes strypt has never seen**. This is ADR-0033's direction, and SVG makes the
//! argument better than HEIF's `uuid` box does: a deny-list of `inkscape:`, `sodipodi:` and
//! Adobe's `i:` would be a list of the three editors somebody happened to test, and every other
//! editor's private data would survive precisely by going unrecognised.

use crate::detect::{self, Format};
use crate::error::{MalformedDetail, Result, StryptError, UnsupportedKind};
use crate::formats::ParseLimits;
use crate::formats::xml::{self, Kind, NonElementKind, Tag};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataValue, Note, Retained, RetentionReason,
};

use super::data_uri;

/// Elements whose presence refuses the document (ADR-0035 §2).
///
/// `handler` is SVG Tiny 1.2's spelling of the same thing and is listed so that the smaller
/// profile is not a way round the rule.
const SCRIPT_ELEMENTS: [&str; 3] = ["script", "foreignObject", "handler"];

/// Namespace prefixes whose names reach the output.
///
/// `xlink` carries `href`, which is how an SVG refers to anything at all, and `xml` carries
/// `xml:space` and `xml:lang`, which change how text is laid out and read aloud.
const RENDERING_PREFIXES: [&str; 2] = ["xlink", "xml"];

/// The element whose contents SVG 1.1 §5.10 states are not rendered.
///
/// The one element in the format that is unambiguously metadata by definition: RDF, Dublin Core,
/// Creative Commons licensing, and XMP all go here.
const METADATA_ELEMENT: &str = "metadata";

/// The accessibility text, kept and declared (ADR-0035 §5).
const ACCESSIBILITY_ELEMENTS: [&str; 2] = ["title", "desc"];

/// The element holding a stylesheet, which is the one place this handler reads a second grammar.
const STYLE_ELEMENT: &str = "style";

/// Attributes whose entire value is a reference to a resource.
///
/// A value containing `url(` is treated as one too, wherever it appears, which is how `fill`,
/// `filter`, `clip-path`, `mask` and a `style` attribute are covered without enumerating the
/// presentation attributes — a list that grows with the specification.
const REFERENCE_ATTRIBUTES: [&str; 3] = ["href", "xlink:href", "src"];

/// Local names whose value names a person or a moment, whatever namespace they arrive in.
///
/// Matched on the local name because the same field appears under several prefixes: Dublin Core
/// `dc:creator`, Inkscape's `sodipodi:docname`, and Illustrator's own spellings. Anything
/// prefixed and not on this list is still removed — this table only decides how the report
/// *describes* it.
const PERSONAL_LOCAL_NAMES: [&str; 8] = [
    "creator",
    "contributor",
    "publisher",
    "docname",
    "docbase",
    "export-filename",
    "absref",
    "sourcefile",
];

/// Local names whose value is a date or a time.
///
/// Names *ending* in `date` or `time` count too, because XMP spells them `xmp:CreateDate`,
/// `xmp:ModifyDate`, `xmp:MetadataDate` and `exif:DateTimeOriginal` — a fixed list would be a
/// list of the ones somebody remembered.
const TIME_LOCAL_NAMES: [&str; 3] = ["modified", "created", "timestamp"];

/// One change to make to the source.
///
/// A replacement rather than only a cut, because a `data:` URI whose embedded image was stripped
/// is rewritten in place rather than removed — the picture stays and its metadata goes.
struct Edit {
    start: usize,
    end: usize,
    replacement: Option<String>,
}

/// Everything one pass over a document produced.
#[derive(Debug)]
pub(super) struct Outcome {
    /// The rewritten document, or [`None`] when nothing changed and the input's bytes stand.
    pub(super) output: Option<Vec<u8>>,
    pub(super) findings: Vec<Finding>,
    pub(super) retained: Vec<Retained>,
    pub(super) notes: Vec<Note>,
}

/// The state carried through one pass, so that the walk itself stays readable.
struct Pass<'a> {
    src: &'a str,
    options: &'a InspectOptions,
    limits: &'a ParseLimits,
    /// The shared decompression allowance, spent by `data:` URI decoding as the ZIP layer spends
    /// it across an archive (ADR-0028): a hundred small embedded images must not collectively
    /// exceed what one large one may.
    budget: u64,
    edits: Vec<Edit>,
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    /// How many external references were seen, so the report says "four" rather than repeating
    /// one line four hundred times for a document that links a sprite sheet.
    external: usize,
}

/// Walk a document once, producing both the report and the sanitised bytes.
///
/// # Errors
///
/// Refuses a document that can execute code, one whose doctype declares entities, one whose
/// `data:` URI holds a container rather than a picture, and one with more elements than
/// [`ParseLimits::max_items`] allows.
pub(super) fn process(
    src: &str,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Outcome> {
    let scan = xml::scan(src);
    if scan.tags.len() > limits.max_items as usize {
        return Err(StryptError::LimitExceeded {
            format: Format::Svg,
            limit: crate::error::ResourceLimit::ItemCount,
        });
    }

    let mut pass = Pass {
        src,
        options,
        limits,
        budget: limits.max_expanded_bytes,
        edits: Vec::new(),
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
        external: 0,
    };

    pass.walk_non_elements(&scan.others)?;
    pass.walk_elements(&scan.tags)?;
    pass.summarise_external();

    Ok(Outcome {
        output: pass.apply(),
        findings: pass.findings,
        retained: pass.retained,
        notes: pass.notes,
    })
}

impl<'a> Pass<'a> {
    /// Comments, processing instructions, and the doctype.
    fn walk_non_elements(&mut self, others: &[xml::NonElement]) -> Result<()> {
        for other in others {
            let text = self.src.get(other.start..other.end).unwrap_or_default();
            match other.kind {
                // Where Adobe writes `<!-- Generator: Adobe Illustrator 25.0 -->` and where a
                // hand-editing author writes a name. Nothing in a comment renders.
                NonElementKind::Comment => {
                    self.cut(other.start, other.end);
                    self.find(
                        MetadataKind::Comment,
                        "<!-- -->",
                        None,
                        other.end.saturating_sub(other.start),
                        text,
                    );
                }
                // Removed, except the XML declaration — which is not a processing instruction at
                // all in the specification's terms, and whose `encoding` is load-bearing. What
                // goes includes an XMP packet's `<?xpacket?>` wrapper and `<?xml-stylesheet?>`,
                // which is an external reference dressed as markup.
                NonElementKind::ProcessingInstruction => {
                    if is_xml_declaration(text) {
                        continue;
                    }
                    self.cut(other.start, other.end);
                    self.find(
                        MetadataKind::SoftwareFingerprint,
                        "<? ?>",
                        None,
                        other.end.saturating_sub(other.start),
                        text,
                    );
                }
                // A doctype naming a public identifier is the format's boilerplate and stays. An
                // internal subset is refused: removing it would leave `&name;` references
                // pointing at nothing, and keeping it means keeping entity declarations, which
                // are an expansion vector and, when external, a network reference (ADR-0035 §8).
                NonElementKind::Doctype => {
                    if text.contains('[') {
                        return Err(StryptError::Malformed {
                            format: Format::Svg,
                            offset: Some(crate::container::package::as_u64(other.start)),
                            detail: MalformedDetail::UnsupportedFeature,
                        });
                    }
                }
                NonElementKind::Cdata => {}
            }
        }
        Ok(())
    }

    /// Elements and their attributes.
    fn walk_elements(&mut self, tags: &[Tag<'a>]) -> Result<()> {
        // Everything inside an element that is being removed whole is already gone, so the walk
        // steps over it rather than reporting its contents a second time.
        let mut skip_until = 0usize;

        for (index, tag) in tags.iter().enumerate() {
            if tag.start < skip_until || tag.kind == Kind::Close {
                continue;
            }
            let name = tag.name;

            if SCRIPT_ELEMENTS.contains(&name) {
                return Err(scripted());
            }

            if let Some(prefix) = prefix_of(name) {
                if !RENDERING_PREFIXES.contains(&prefix) {
                    // An editor's private element: `<sodipodi:namedview>`, which records the
                    // author's window geometry and current layer, or Illustrator's `<i:pgf>`,
                    // which is a compressed copy of the original AI document.
                    if let Some(span) = xml::element_span(tags, index) {
                        skip_until = span.end;
                        self.cut(span.start, span.end);
                        self.find(
                            kind_for(name),
                            format!("<{name}>"),
                            None,
                            span.len(),
                            self.src.get(span.start..span.end).unwrap_or_default(),
                        );
                        continue;
                    }
                }
            } else if name == METADATA_ELEMENT {
                if let Some(span) = xml::element_span(tags, index) {
                    skip_until = span.end;
                    self.cut(span.start, span.end);
                    self.report_metadata(span.start, span.end);
                    continue;
                }
            } else if ACCESSIBILITY_ELEMENTS.contains(&name) {
                self.keep_accessibility_text(tags, index, name);
            } else if name == STYLE_ELEMENT {
                self.scrub_stylesheet(tags, index);
            }

            self.walk_attributes(tag)?;
        }
        Ok(())
    }

    /// One element's attributes.
    fn walk_attributes(&mut self, tag: &Tag<'a>) -> Result<()> {
        let base = tag.start;
        for attribute in xml::attributes(tag.raw) {
            let name = attribute.name;
            let start = base.saturating_add(attribute.start);
            let end = base.saturating_add(attribute.end);

            // Any attribute whose name begins `on` is an event handler: SVG defines no other.
            if is_event_handler(name) {
                return Err(scripted());
            }

            if let Some(bound) = name.strip_prefix("xmlns:") {
                // The declaration that bound a prefix goes with the names that used it, because
                // `xmlns:inkscape` names the editor whether or not anything still refers to it.
                if !RENDERING_PREFIXES.contains(&bound) {
                    self.cut(start, end);
                    self.find(
                        MetadataKind::SoftwareFingerprint,
                        format!("<{} {name}>", tag.name),
                        Some(name.to_owned()),
                        end.saturating_sub(start),
                        attribute.value,
                    );
                }
                continue;
            }

            if let Some(prefix) = prefix_of(name)
                && !RENDERING_PREFIXES.contains(&prefix)
            {
                self.cut(start, end);
                self.find(
                    kind_for(name),
                    format!("<{} {name}>", tag.name),
                    Some(name.to_owned()),
                    end.saturating_sub(start),
                    attribute.value,
                );
                continue;
            }

            self.examine_reference(tag, name, attribute.value, start, end)?;
        }
        Ok(())
    }

    /// Look at what an attribute's value points at.
    fn examine_reference(
        &mut self,
        tag: &Tag<'a>,
        name: &str,
        value: &'a str,
        start: usize,
        end: usize,
    ) -> Result<()> {
        let whole = REFERENCE_ATTRIBUTES.contains(&name);
        if !whole && !value.contains("url(") {
            return Ok(());
        }

        if whole {
            if is_javascript(value) {
                return Err(scripted());
            }
            if let Some(uri) = data_uri::parse(value) {
                return self.descend(tag, name, &uri, start, end);
            }
            if is_external(value) {
                self.external = self.external.saturating_add(1);
                self.retain_reference(tag.name, name);
            }
            return Ok(());
        }

        // `url(...)` inside a presentation attribute or an inline `style`. A fragment is an
        // internal reference to another element of the same file and is not a leak.
        for target in url_targets(value) {
            if is_javascript(target) {
                return Err(scripted());
            }
            if is_external(target) {
                self.external = self.external.saturating_add(1);
                self.retain_reference(tag.name, name);
            }
        }
        Ok(())
    }

    /// Strip an image carried in a `data:` URI, one level and images only (ADR-0029).
    fn descend(
        &mut self,
        tag: &Tag<'a>,
        name: &str,
        uri: &data_uri::DataUri<'_>,
        start: usize,
        end: usize,
    ) -> Result<()> {
        let location = format!("<{} {name}> (data: URI)", tag.name);

        // A percent-encoded payload is a legal `data:` URI and vanishingly rare for an image.
        // Declared rather than decoded on a guess.
        let Some(bytes) = uri
            .base64
            .then(|| data_uri::decode(uri.payload, &mut self.budget))
            .flatten()
        else {
            self.notes.push(Note::UnparsedRegion {
                location,
                bytes: crate::container::package::as_u64(uri.payload.len()),
            });
            return Ok(());
        };

        // What it is comes from the bytes, never from the declared media type — the same rule
        // that stops a `.jpg` full of PDF reaching the JPEG handler.
        let Some(format) = crate::container::package::embedded_image_format(&bytes) else {
            // A nested container carries its own metadata that one pass cannot reach, so the
            // document is refused rather than reported clean. An SVG inside an SVG lands here
            // too, which is also what keeps the descent one level deep by construction.
            if is_nested_container(&bytes) {
                self.notes.push(Note::OutOfScopeContent {
                    location: format!("{location} (a container, not a picture)"),
                });
                return Err(StryptError::Malformed {
                    format: Format::Svg,
                    offset: Some(crate::container::package::as_u64(start)),
                    detail: MalformedDetail::UnsupportedFeature,
                });
            }
            self.notes.push(Note::UnparsedRegion {
                location,
                bytes: crate::container::package::as_u64(bytes.len()),
            });
            return Ok(());
        };

        match crate::container::package::strip_embedded_image(
            format,
            &bytes,
            &location,
            self.options,
            self.limits,
        )? {
            crate::container::package::Embedded::Unchanged => {}
            crate::container::package::Embedded::Stripped {
                bytes: cleaned,
                findings,
                notes,
            } => {
                let encoded = data_uri::encode(&uri.media_type, &cleaned);
                // The quoting character is whatever the document used, so a value written with
                // single quotes stays written with single quotes.
                let quote = quote_of(self.src.get(start..end).unwrap_or_default()).unwrap_or('"');
                self.edits.push(Edit {
                    start,
                    end,
                    replacement: Some(format!(" {name}={quote}{encoded}{quote}")),
                });
                self.findings.extend(findings);
                self.notes.extend(notes);
            }
        }
        Ok(())
    }

    /// Report what `<metadata>` held, before it goes.
    ///
    /// The element goes whole either way, and naming its fields is what makes `strypt show` worth
    /// running before a decision to publish — "this drawing names an author and a licence" is
    /// actionable where "a metadata element was removed" is not.
    fn report_metadata(&mut self, start: usize, end: usize) {
        let inner = self.src.get(start..end).unwrap_or_default();
        let tags = xml::tags(inner);
        let mut ancestors: Vec<&str> = Vec::new();
        let mut named = false;

        for (index, tag) in tags.iter().enumerate() {
            if tag.kind == Kind::Close {
                // Popping on a mismatch would shift every later element's context.
                if ancestors.last() == Some(&tag.name) {
                    ancestors.pop();
                }
                continue;
            }

            // Adobe writes XMP as attributes — `<rdf:Description xmp:CreatorTool="..."/>` — so
            // itemising only text would call a whole packet "other metadata".
            for attribute in xml::attributes(tag.raw) {
                if attribute.name.starts_with("xmlns") || attribute.value.trim().is_empty() {
                    continue;
                }
                named = true;
                self.find(
                    kind_for(attribute.name),
                    "<metadata>",
                    Some(format!("{} {}", tag.name, attribute.name)),
                    attribute.value.len(),
                    attribute.value,
                );
            }

            if let Some(text) = xml::element_text(&tags, index, inner)
                && !text.value.trim().is_empty()
            {
                named = true;
                self.find(
                    kind_in_context(&ancestors, tag.name),
                    "<metadata>",
                    Some(tag.name.to_owned()),
                    text.value.len(),
                    text.value,
                );
            }

            if tag.kind == Kind::Open {
                ancestors.push(tag.name);
            }
        }
        if !named {
            // An element whose contents this pass could not itemise is still an element that
            // should not be published, and a report saying nothing about it would be a report
            // claiming there was nothing there.
            self.find(
                MetadataKind::Other,
                "<metadata>",
                None,
                end.saturating_sub(start),
                inner,
            );
        }
    }

    /// Declare accessibility text that is being kept.
    fn keep_accessibility_text(&mut self, tags: &[Tag<'a>], index: usize, name: &str) {
        let Some(text) = xml::element_text(tags, index, self.src) else {
            return;
        };
        if text.value.trim().is_empty() {
            return;
        }
        // A `Retained` rather than a `Finding`: a finding would make the verification pass reject
        // strypt's own output, which requires the result to re-inspect clean.
        self.retained.push(Retained {
            location: format!("<{name}>"),
            reason: RetentionReason::RemovalWouldAlterPayload,
        });
        self.notes.push(Note::OutOfScopeContent {
            location: format!("<{name}> (accessibility text, which can name its author)"),
        });
    }

    /// Remove comments from a stylesheet and look at what it references.
    fn scrub_stylesheet(&mut self, tags: &[Tag<'a>], index: usize) {
        let Some(text) = xml::element_text(tags, index, self.src) else {
            return;
        };
        for span in css_comments(text.value) {
            let start = text.range.start.saturating_add(span.0);
            let end = text.range.start.saturating_add(span.1);
            self.cut(start, end);
            self.find(
                MetadataKind::Comment,
                "<style> (/* */)",
                None,
                end.saturating_sub(start),
                self.src.get(start..end).unwrap_or_default(),
            );
        }
        for target in url_targets(text.value) {
            if is_external(target) {
                self.external = self.external.saturating_add(1);
                self.retain_reference("style", "url()");
            }
        }
    }

    /// Declare one external reference, without ever naming what it points at.
    ///
    /// The path is the leak — `../../Users/aname/Desktop/photo.png` names a person — so it must
    /// not appear in a report that lands in scrollback or a pasted issue
    /// (`docs/THREAT_MODEL.md` §5.5). The element and the attribute are enough to find it.
    fn retain_reference(&mut self, element: &str, attribute: &str) {
        let location = format!("<{element} {attribute}> (a reference outside this document)");
        if self.retained.iter().any(|r| r.location == location) {
            return;
        }
        self.retained.push(Retained {
            location,
            reason: RetentionReason::RemovalWouldAlterPayload,
        });
    }

    /// One note for however many external references there were.
    fn summarise_external(&mut self) {
        if self.external == 0 {
            return;
        }
        self.notes.push(Note::OutOfScopeContent {
            // A bare noun phrase, because the CLI wraps a note in "contains {location}, which
            // strypt does not open — check it separately". Why they are kept is the `Retained`
            // entry's reason, not this line's job.
            location: format!(
                "{} reference(s) to files outside this document",
                self.external
            ),
        });
    }

    /// Record a range to remove.
    fn cut(&mut self, start: usize, end: usize) {
        if start < end {
            self.edits.push(Edit {
                start,
                end,
                replacement: None,
            });
        }
    }

    /// Record one finding.
    fn find(
        &mut self,
        kind: MetadataKind,
        location: impl Into<String>,
        field: Option<String>,
        bytes: usize,
        value: &str,
    ) {
        let mut finding = Finding::new(kind, location, crate::container::package::as_u64(bytes));
        if let Some(field) = field {
            finding = finding.with_field(field);
        }
        self.findings.push(finding.with_value(self.options, || {
            MetadataValue::Text(value.trim().to_owned())
        }));
    }

    /// Build the output, or [`None`] when there was nothing to do.
    ///
    /// Overlapping edits are resolved by taking the outermost: an element removal is recorded
    /// before the attribute edits inside it, and sorting the wider range first means the inner
    /// ones are skipped rather than applied to bytes that are already gone.
    fn apply(&mut self) -> Option<Vec<u8>> {
        if self.edits.is_empty() {
            return None;
        }
        self.edits
            .sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

        let mut out = String::with_capacity(self.src.len());
        let mut copied = 0usize;
        for edit in &self.edits {
            if edit.start < copied {
                continue;
            }
            out.push_str(self.src.get(copied..edit.start)?);
            if let Some(replacement) = &edit.replacement {
                out.push_str(replacement);
            }
            copied = edit.end;
        }
        out.push_str(self.src.get(copied..)?);
        Some(out.into_bytes())
    }
}

/// The refusal for a document that can execute code.
const fn scripted() -> StryptError {
    StryptError::UnsupportedFormat {
        format: UnsupportedKind::ScriptedSvg,
    }
}

/// A name's namespace prefix, or [`None`] when it has none.
fn prefix_of(name: &str) -> Option<&str> {
    name.split_once(':').map(|(prefix, _)| prefix)
}

/// A name's local part, which is the whole name when it is unprefixed.
fn local_of(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, local)| local)
}

/// How the report should describe a name that is being removed.
///
/// Only the description: what is removed is decided by the prefix allow-list, so a name absent
/// from every table here is still removed, and is merely called a software fingerprint.
fn kind_for(name: &str) -> MetadataKind {
    let local = local_of(name).to_ascii_lowercase();
    if PERSONAL_LOCAL_NAMES.contains(&local.as_str()) {
        return MetadataKind::PersonalIdentity;
    }
    if TIME_LOCAL_NAMES.contains(&local.as_str())
        || local.ends_with("date")
        || local.ends_with("time")
    {
        return MetadataKind::Timestamp;
    }
    match local.as_str() {
        "title" | "description" | "subject" | "rights" | "license" => MetadataKind::Comment,
        _ => MetadataKind::SoftwareFingerprint,
    }
}

/// How to describe a name, upgraded by the elements it sits inside.
///
/// RDF nests the value: a person arrives as `<dc:creator><cc:Agent><dc:title>A Name</dc:title>`,
/// where only the ancestor says the leaf is a person.
fn kind_in_context(ancestors: &[&str], name: &str) -> MetadataKind {
    let personal = |candidate: &str| {
        PERSONAL_LOCAL_NAMES.contains(&local_of(candidate).to_ascii_lowercase().as_str())
    };
    if ancestors.iter().copied().any(personal) {
        return MetadataKind::PersonalIdentity;
    }
    kind_for(name)
}

/// True when a processing instruction is the XML declaration.
///
/// Not a processing instruction at all in the specification's terms, and its `encoding` decides
/// how the rest of the file is read — so it stays where every other one goes.
fn is_xml_declaration(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("<?") else {
        return false;
    };
    let target = rest
        .split(|c: char| c.is_whitespace() || c == '?')
        .next()
        .unwrap_or_default();
    target == "xml"
}

/// True when an attribute name is an event handler.
///
/// SVG defines no attribute beginning `on` that is not one, which makes this the allow-list's
/// shape rather than a list of the handlers somebody remembered: `onload`, `onclick`, `onbegin`,
/// `onrepeat`, and whatever a future specification adds are all caught by the same rule.
fn is_event_handler(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("on") else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// True when a reference value invokes script rather than naming a resource.
fn is_javascript(value: &str) -> bool {
    let trimmed = value.trim_start();
    trimmed
        .get(..11)
        .is_some_and(|head| head.eq_ignore_ascii_case("javascript:"))
}

/// True when a reference points outside the document.
///
/// A fragment names another element of the same file and is not a leak. Everything else is —
/// whether it is a URL that fires when a reader opens the published file, or a relative path that
/// names a directory on the author's machine.
fn is_external(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && !trimmed.starts_with('#') && data_uri::parse(trimmed).is_none()
}

/// True when decoded bytes are a container carrying its own metadata rather than a picture.
fn is_nested_container(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        || matches!(detect::detect(bytes), Ok(Format::Pdf | Format::Svg))
}

/// The quoting character an attribute was written with.
fn quote_of(raw: &str) -> Option<char> {
    raw.split_once('=')
        .and_then(|(_, value)| value.trim_start().chars().next())
        .filter(|c| *c == '"' || *c == '\'')
}

/// Every `url(...)` target in a value, unquoted.
fn url_targets(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(at) = rest.find("url(") {
        let Some(after) = rest.get(at.saturating_add(4)..) else {
            break;
        };
        let Some(close) = after.find(')') else {
            break;
        };
        let target = after.get(..close).unwrap_or_default().trim();
        out.push(target.trim_matches(['"', '\'']));
        rest = after.get(close.saturating_add(1)..).unwrap_or_default();
    }
    out
}

/// The byte ranges of every CSS comment in a stylesheet.
///
/// Quote-aware, because `/*` inside a string is not a comment and cutting there would corrupt
/// the rule around it. This is the one place this handler reads a grammar other than XML, and it
/// is here because a stylesheet comment is a producer fingerprint in exactly the way an XML
/// comment is — mat2's own `CSSParser` removes them for the same reason.
fn css_comments(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut quote: Option<u8> = None;
    let mut i = 0usize;

    while let Some(&byte) = bytes.get(i) {
        match quote {
            Some(q) => {
                // A backslash escapes the next character, quote included.
                if byte == b'\\' {
                    i = i.saturating_add(2);
                    continue;
                }
                if byte == q {
                    quote = None;
                }
            }
            None => {
                if byte == b'"' || byte == b'\'' {
                    quote = Some(byte);
                } else if byte == b'/' && bytes.get(i.saturating_add(1)) == Some(&b'*') {
                    let from = i.saturating_add(2);
                    // An unterminated comment runs to the end, which is what a CSS parser does
                    // with one; cutting to the end is therefore not a guess.
                    let end = text
                        .get(from..)
                        .and_then(|rest| rest.find("*/"))
                        .map_or(text.len(), |n| from.saturating_add(n).saturating_add(2));
                    out.push((i, end));
                    i = end;
                    continue;
                }
            }
        }
        i = i.saturating_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn run(src: &str) -> Outcome {
        process(src, &InspectOptions::names_only(), &ParseLimits::default()).unwrap()
    }

    fn output(src: &str) -> String {
        String::from_utf8(run(src).output.unwrap()).unwrap()
    }

    #[test]
    fn a_clean_drawing_is_returned_untouched() {
        // The property GIF has and TIFF and HEIF cannot promise: editing is deletion, so a file
        // with nothing to remove is not rewritten at all.
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 10 10\">\
                   <rect width=\"10\" height=\"10\" fill=\"#123456\"/></svg>";
        let outcome = run(src);
        assert!(outcome.output.is_none());
        assert!(outcome.findings.is_empty());
    }

    #[test]
    fn an_editors_private_namespace_goes_whole_and_so_does_its_declaration() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\" \
                   xmlns:sodipodi=\"http://sodipodi.sf.net/\" \
                   xmlns:inkscape=\"http://inkscape.org/\" \
                   sodipodi:docname=\"leak-from-my-desktop.svg\" inkscape:version=\"1.1\">\
                   <sodipodi:namedview inkscape:current-layer=\"layer1\" inkscape:zoom=\"3.7\"/>\
                   <rect width=\"1\" height=\"1\"/></svg>";
        let out = output(src);
        assert!(!out.contains("sodipodi"), "{out}");
        assert!(!out.contains("inkscape"), "{out}");
        assert!(out.contains("<rect width=\"1\" height=\"1\"/>"));
        assert!(out.contains("xmlns=\"http://www.w3.org/2000/svg\""));
    }

    #[test]
    fn an_unknown_editors_namespace_goes_for_the_same_reason() {
        // The direction the allow-list runs in. A deny-list would carry this through precisely
        // because nothing recognised it (ADR-0035 §6).
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\" \
                   xmlns:notatoolweveheardof=\"http://example.invalid/\">\
                   <notatoolweveheardof:private author=\"A Name\"/><rect/></svg>";
        let out = output(src);
        assert!(!out.contains("A Name"));
        assert!(!out.contains("notatoolweveheardof"));
        assert!(out.contains("<rect/>"));
    }

    #[test]
    fn xlink_and_xml_survive_because_the_picture_needs_them() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\" \
                   xmlns:xlink=\"http://www.w3.org/1999/xlink\">\
                   <text xml:space=\"preserve\">x</text>\
                   <use xlink:href=\"#shape\"/></svg>";
        assert!(run(src).output.is_none(), "nothing here is removable");
    }

    #[test]
    fn the_metadata_element_goes_and_its_fields_are_named() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\"><metadata><rdf:RDF>\
                   <dc:creator>A Name</dc:creator><dc:date>2021-03-04</dc:date>\
                   </rdf:RDF></metadata><rect/></svg>";
        let outcome = run(src);
        let out = String::from_utf8(outcome.output.clone().unwrap()).unwrap();
        assert!(!out.contains("A Name"));
        assert!(out.contains("<rect/>"));
        let fields: Vec<&str> = outcome
            .findings
            .iter()
            .filter_map(|f| f.field.as_deref())
            .collect();
        assert!(fields.contains(&"dc:creator"), "{fields:?}");
        assert!(
            outcome
                .findings
                .iter()
                .any(|f| f.kind == MetadataKind::PersonalIdentity)
        );
    }

    #[test]
    fn a_name_rdf_nested_under_an_agent_is_still_reported_as_a_person() {
        // What Inkscape actually writes. The leaf is called `title`, and only its ancestor says
        // it holds a person — a report calling that a comment understates it.
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\"><metadata><rdf:RDF><cc:Work>\
                   <dc:creator><cc:Agent><dc:title>A Name</dc:title></cc:Agent></dc:creator>\
                   <dc:title>A Drawing</dc:title></cc:Work></rdf:RDF></metadata></svg>";
        let outcome = run(src);
        let person = outcome
            .findings
            .iter()
            .find(|f| f.kind == MetadataKind::PersonalIdentity)
            .expect("the nested name must be reported as a person");
        assert_eq!(person.field.as_deref(), Some("dc:title"));
        // The drawing's own title sits outside `<dc:creator>` and must not be upgraded with it.
        assert!(
            outcome
                .findings
                .iter()
                .any(|f| f.kind == MetadataKind::Comment)
        );
    }

    #[test]
    fn xmp_written_as_attributes_is_itemised_rather_than_lumped_together() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\"><metadata><rdf:RDF>\
                   <rdf:Description xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" \
                   xmp:CreatorTool=\"Some Editor 3.1\" xmp:CreateDate=\"2021-03-04\"/>\
                   </rdf:RDF></metadata></svg>";
        let outcome = run(src);
        let fields: Vec<&str> = outcome
            .findings
            .iter()
            .filter_map(|f| f.field.as_deref())
            .collect();
        assert!(
            fields.contains(&"rdf:Description xmp:CreatorTool"),
            "{fields:?}"
        );
        assert!(
            outcome
                .findings
                .iter()
                .any(|f| f.kind == MetadataKind::Timestamp),
            "`xmp:CreateDate` is a timestamp"
        );
        // The namespace declaration is bookkeeping, not a field of the packet.
        assert!(!fields.iter().any(|f| f.contains("xmlns")), "{fields:?}");
    }

    #[test]
    fn comments_go_and_the_xml_declaration_stays() {
        let src = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                   <!-- Generator: Adobe Illustrator 25.0, SVG Export Plug-In -->\
                   <?xpacket begin=\"\" id=\"W5M0Mp\"?>\
                   <svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>";
        let out = output(src);
        assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(!out.contains("Adobe Illustrator"));
        assert!(!out.contains("xpacket"));
    }

    #[test]
    fn a_script_or_an_event_handler_refuses_the_document() {
        // ADR-0035 §2. Removing it would make strypt a sanitiser; keeping it would mean
        // reporting success on a file that runs unexamined code when a reader opens it.
        for src in [
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"><rect/></svg>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect onclick=\"x()\"/></svg>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><foreignObject><p/></foreignObject></svg>",
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><a href=\"javascript:x()\"/></svg>",
        ] {
            let e = process(src, &InspectOptions::names_only(), &ParseLimits::default())
                .expect_err("a document that can execute code must be refused");
            assert!(
                matches!(
                    e,
                    StryptError::UnsupportedFormat {
                        format: UnsupportedKind::ScriptedSvg
                    }
                ),
                "{src} gave {e:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_attribute_beginning_on_is_not_mistaken_for_a_handler() {
        assert!(is_event_handler("onload"));
        assert!(is_event_handler("onmouseover"));
        assert!(!is_event_handler("on"));
        assert!(!is_event_handler("once-upon"));
        assert!(!is_event_handler("opacity"));
    }

    #[test]
    fn accessibility_text_is_kept_and_declared() {
        // ADR-0035 §5: a screen reader announces it, so it is payload — and it can name its
        // author, so the user has to be told it is still there.
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\">\
                   <title>A photograph by A Name</title><desc>Taken at home</desc>\
                   <rect/></svg>";
        let outcome = run(src);
        assert!(outcome.output.is_none(), "the text stays");
        assert!(
            outcome.retained.iter().any(|r| r.location == "<title>"),
            "an empty retained list is a claim: it has to say what was kept"
        );
        assert!(outcome.retained.iter().any(|r| r.location == "<desc>"));
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| matches!(n, Note::OutOfScopeContent { .. }))
        );
    }

    #[test]
    fn an_external_reference_is_reported_and_never_removed() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\">\
                   <image href=\"../../Users/aname/Desktop/photo.png\"/>\
                   <rect fill=\"url(https://tracker.invalid/p.png)\"/>\
                   <circle fill=\"url(#gradient)\"/></svg>";
        let outcome = run(src);
        assert!(outcome.output.is_none(), "removing it would break the file");
        assert_eq!(outcome.retained.len(), 2, "{:?}", outcome.retained);
        // The path is the leak, so it must not reach a report that lands in scrollback.
        for retained in &outcome.retained {
            assert!(!retained.location.contains("aname"));
            assert!(!retained.location.contains("tracker"));
        }
        assert!(
            outcome.findings.is_empty(),
            "a kept reference must not be a finding, or verification would reject our own output"
        );
    }

    #[test]
    fn a_fragment_reference_is_not_a_leak() {
        assert!(!is_external("#gradient"));
        assert!(!is_external(""));
        assert!(is_external("photo.png"));
        assert!(is_external("https://example.invalid/x.png"));
        assert!(!is_external("data:image/png;base64,AA=="));
    }

    #[test]
    fn a_stylesheet_loses_its_comments_and_keeps_its_rules() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\"><style>\
                   /* Generator: A Tool 1.2 by A Name */\
                   .a{fill:red;content:\"/* not a comment */\"}</style><rect class=\"a\"/></svg>";
        let out = output(src);
        assert!(!out.contains("A Name"));
        assert!(out.contains(".a{fill:red"));
        assert!(
            out.contains("/* not a comment */"),
            "a quoted string is not a comment: {out}"
        );
    }

    #[test]
    fn a_doctype_stays_and_an_entity_subset_refuses() {
        let plain = "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \
                     \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\
                     <svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>";
        assert!(run(plain).output.is_none());

        let subset = "<!DOCTYPE svg [<!ENTITY who \"A Name\">]>\
                      <svg xmlns=\"http://www.w3.org/2000/svg\"><text>&who;</text></svg>";
        assert!(
            process(
                subset,
                &InspectOptions::names_only(),
                &ParseLimits::default()
            )
            .is_err(),
            "removing the subset would leave &who; pointing at nothing"
        );
    }

    #[test]
    fn scrubbing_is_idempotent() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:i=\"http://ns.adobe.com/\" \
                   i:extraneous=\"self\"><!-- Generator --><metadata><dc:creator>A</dc:creator>\
                   </metadata><rect/></svg>";
        let once = output(src);
        assert!(
            run(&once).output.is_none(),
            "a second pass must find nothing, or verification would never converge"
        );
    }

    #[test]
    fn overlapping_edits_take_the_outermost() {
        // An attribute inside an element that is itself being removed must not be applied to
        // bytes that are already gone.
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\">\
                   <sodipodi:namedview inkscape:zoom=\"1\" xmlns:x=\"y\"/><rect/></svg>";
        let out = output(src);
        assert!(!out.contains("namedview"));
        assert!(out.contains("<rect/>"));
    }

    #[test]
    fn arbitrary_text_does_not_panic_the_rules() {
        let cases = [
            "",
            "<",
            "<svg",
            "<svg>",
            "<!--",
            "<?",
            "<![CDATA[",
            "<!DOCTYPE [",
            "<svg xmlns:=\"\"/>",
            "<svg :name=\"x\"/>",
            "<metadata>",
            "<style>/*",
            "<style>\"",
            "<image href=\"data:\"/>",
            "<image href=\"data:image/png;base64,====\"/>",
            "<rect fill=\"url(\"/>",
            "<<<<>>>>",
        ];
        for case in cases {
            let _ = process(
                case,
                &InspectOptions::with_values(),
                &ParseLimits::default(),
            );
        }
    }

    #[test]
    fn every_prefix_of_a_real_drawing_is_survivable() {
        let src = "<?xml version=\"1.0\"?><!-- gen --><svg xmlns=\"http://www.w3.org/2000/svg\" \
                   xmlns:inkscape=\"http://inkscape.org/\"><metadata><dc:creator>A</dc:creator>\
                   </metadata><title>T</title><style>/* c */.a{fill:red}</style>\
                   <image href=\"data:image/png;base64,iVBORw==\"/><rect/></svg>";
        for n in 0..=src.len() {
            let prefix = src.get(0..n).unwrap_or_default();
            let _ = process(
                prefix,
                &InspectOptions::names_only(),
                &ParseLimits::default(),
            );
        }
    }
}
