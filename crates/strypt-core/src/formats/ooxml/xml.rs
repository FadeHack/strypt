//! Just enough XML to find and delete the identifying parts of an OOXML document.
//!
//! # Why there is no XML parser here
//!
//! ADR-0008 requires a dependency to earn its place, and an XML parser is a large, historically
//! CVE-dense category to admit for a job that never needs a document tree. Everything this
//! handler does is: name the elements and attributes present, and delete the byte ranges of
//! some of them. That is a scanner, not a parser.
//!
//! **Editing is by deletion, never by re-serialisation.** A rewritten part is the original
//! bytes with some ranges cut out, so every byte that had no reason to change does not change:
//! namespace declarations keep their order, attribute quoting keeps its style, whitespace keeps
//! its shape. Re-serialising through a document model would rewrite the whole part and make it
//! impossible to see, in a diff, what strypt actually did.
//!
//! # What this scanner does not do
//!
//! It does not resolve entities, does not validate, does not check that elements nest, and does
//! not decode character references. It does not need to: an attribute is removed on the
//! strength of its *name*, and a name cannot be spelled with an entity reference in XML. Where
//! the scanner cannot make sense of the text it stops and the part is copied through untouched
//! with a note saying so, rather than being edited on a guess.

use std::collections::BTreeSet;

use crate::report::{Finding, InspectOptions, MetadataKind, MetadataValue, Note};

/// Revision-save identifiers. Each marks one editing session, and two documents carrying the
/// same one were edited in the same session on the same machine — which is why they are a
/// correlation risk far out of proportion to how obscure they are.
const RSID_ATTRIBUTES: [&str; 8] = [
    "w:rsidR",
    "w:rsidRDefault",
    "w:rsidP",
    "w:rsidRPr",
    "w:rsidTr",
    "w:rsidSect",
    "w:rsidDel",
    "w:rsidRProp",
];

/// Per-paragraph identifiers, stable across saves and across copies of a document. Two documents
/// sharing a `paraId` share a paragraph's history.
const PARAGRAPH_ID_ATTRIBUTES: [&str; 2] = ["w14:paraId", "w14:textId"];

/// Author, initials, and timestamp on a tracked change or a comment.
///
/// Removing these changes no words of the document — see the module note in the parent on why
/// the *content* of a revision stays and its attribution does not.
const AUTHORSHIP_ATTRIBUTES: [&str; 3] = ["w:author", "w:initials", "w:date"];

/// Attributes removed only on `p:cmAuthor`, the `PresentationML` comment-author list.
///
/// Scoped to that element because `name` is far too common an attribute to remove wherever it
/// appears — on `w:style` or `a:latin` it is structural, and dropping it would break the
/// document.
const COMMENT_AUTHOR_ELEMENT: &str = "p:cmAuthor";
const COMMENT_AUTHOR_ATTRIBUTES: [&str; 2] = ["name", "initials"];

/// The `SpreadsheetML` comment-author list: `<authors><author>A Name</author></authors>`.
///
/// The names are element text rather than attributes, and the list is indexed by position —
/// `<comment authorId="0">` refers to the first entry — so the entries are emptied rather than
/// removed, which keeps every index pointing where it did.
const AUTHOR_TEXT_ELEMENT: &str = "author";

/// The element holding the whole revision-save-identifier table in `settings.xml`. Removed
/// entire, since nothing outside it refers into it.
const RSID_TABLE_ELEMENT: &str = "w:rsids";

/// Report names for the two ends of an external-relationship removal.
const RELATIONSHIP_ELEMENT: &str = "Relationship (external local path)";
const RELATIONSHIP_REFERENCE: &str = "r:id (to an external local path)";

/// How a tag closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// `<name ...>`
    Open,
    /// `</name>`
    Close,
    /// `<name ... />`
    Empty,
}

/// One element tag, located in the source.
#[derive(Debug, Clone)]
pub(super) struct Tag<'a> {
    /// The element's name, exactly as written, prefix included.
    pub(super) name: &'a str,
    /// How it closes.
    pub(super) kind: Kind,
    /// Byte offset of the opening `<`.
    pub(super) start: usize,
    /// Byte offset one past the closing `>`.
    pub(super) end: usize,
    /// The whole tag text, `<` and `>` included.
    raw: &'a str,
}

impl<'a> Tag<'a> {
    /// The value of `name`, or [`None`] if the attribute is absent.
    pub(super) fn attribute(&self, name: &str) -> Option<&'a str> {
        attributes(self.raw)
            .into_iter()
            .find(|attr| attr.name == name)
            .map(|attr| attr.value)
    }
}

/// One attribute, located within its tag's text.
struct Attribute<'a> {
    name: &'a str,
    value: &'a str,
    /// Byte offset within the tag of the whitespace preceding the attribute, so that removing
    /// the range leaves no double space behind.
    start: usize,
    /// Byte offset within the tag one past the closing quote.
    end: usize,
}

/// Every element tag in `src`, in document order.
///
/// Comments, CDATA sections, processing instructions, and doctype declarations are skipped
/// rather than reported: nothing this handler removes lives in one, and treating their contents
/// as markup is how a scanner starts editing text it has misread.
pub(super) fn tags(src: &str) -> Vec<Tag<'_>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(open) = find_from(bytes, i, b'<') else {
            break;
        };
        let rest = src.get(open..).unwrap_or_default();

        // Skip the constructs whose contents are not markup. Each returns the offset just past
        // its terminator; an unterminated one ends the scan, because everything after it is
        // inside a construct that never closed.
        if let Some(skipped) = skip_non_element(rest, open) {
            i = skipped;
            continue;
        }

        let Some(close) = find_tag_end(bytes, open) else {
            break;
        };
        let end = close.saturating_add(1);
        let raw = src.get(open..end).unwrap_or_default();
        if let Some(tag) = parse_tag(raw, open, end) {
            out.push(tag);
        }
        i = end;
    }
    out
}

/// Skip a comment, CDATA section, processing instruction, or doctype, returning the offset past
/// it. [`None`] when `rest` begins an ordinary element tag.
fn skip_non_element(rest: &str, at: usize) -> Option<usize> {
    let (prefix, terminator): (&str, &str) = if rest.starts_with("<!--") {
        ("<!--", "-->")
    } else if rest.starts_with("<![CDATA[") {
        ("<![CDATA[", "]]>")
    } else if rest.starts_with("<?") {
        ("<?", "?>")
    } else if rest.starts_with("<!") {
        ("<!", ">")
    } else {
        return None;
    };
    let after_prefix = rest.get(prefix.len()..).unwrap_or_default();
    let found = after_prefix.find(terminator);
    // An unterminated construct: return the end of the input so the scan stops here rather than
    // resuming inside it.
    let offset = found.map_or(rest.len(), |n| {
        prefix
            .len()
            .saturating_add(n)
            .saturating_add(terminator.len())
    });
    Some(at.saturating_add(offset))
}

/// Find the `>` closing the tag that starts at `open`, ignoring any inside a quoted value.
///
/// Quoting matters: an attribute value may legitimately contain `>`, and a scanner that stopped
/// at the first one would split a tag in half and then read its remainder as text.
fn find_tag_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut i = open.checked_add(1)?;
    let mut quote: Option<u8> = None;
    while let Some(&b) = bytes.get(i) {
        // Inside a quoted value nothing is structural; outside one, a quote opens a value and
        // `>` ends the tag.
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'>' => return Some(i),
                _ => {}
            },
        }
        i = i.checked_add(1)?;
    }
    None
}

/// Split a tag's text into its name and how it closes.
fn parse_tag(raw: &str, start: usize, end: usize) -> Option<Tag<'_>> {
    let inner = raw.strip_prefix('<')?.strip_suffix('>')?;
    let (kind, body) = match inner.strip_prefix('/') {
        Some(rest) => (Kind::Close, rest),
        None => match inner.strip_suffix('/') {
            Some(rest) => (Kind::Empty, rest),
            None => (Kind::Open, inner),
        },
    };
    let name_end = body
        .find(|c: char| c.is_whitespace() || c == '/')
        .unwrap_or(body.len());
    let name = body.get(0..name_end)?;
    if name.is_empty() {
        return None;
    }
    Some(Tag {
        name,
        kind,
        start,
        end,
        raw,
    })
}

/// Every attribute of a tag, with the byte ranges that removing one would have to cut.
fn attributes(raw: &str) -> Vec<Attribute<'_>> {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    // Step past `<` and the element name.
    let Some(mut i) = raw.find(|c: char| c.is_whitespace()) else {
        return out;
    };

    while i < bytes.len() {
        let span_start = i;
        // Leading whitespace belongs to the attribute for removal purposes, so that cutting one
        // out does not leave a double space behind.
        while matches!(bytes.get(i), Some(b) if b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        let name_start = i;
        while matches!(bytes.get(i), Some(b) if !b.is_ascii_whitespace() && *b != b'=' && *b != b'>' && *b != b'/')
        {
            i = i.saturating_add(1);
        }
        let Some(name) = raw.get(name_start..i) else {
            break;
        };
        if name.is_empty() {
            break;
        }
        while matches!(bytes.get(i), Some(b) if b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        if bytes.get(i) != Some(&b'=') {
            // A bare attribute name, which XML does not permit. Stop rather than guess where
            // the next one begins.
            break;
        }
        i = i.saturating_add(1);
        while matches!(bytes.get(i), Some(b) if b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        let Some(&quote) = bytes.get(i) else { break };
        if quote != b'"' && quote != b'\'' {
            break;
        }
        i = i.saturating_add(1);
        let value_start = i;
        while matches!(bytes.get(i), Some(b) if *b != quote) {
            i = i.saturating_add(1);
        }
        let Some(value) = raw.get(value_start..i) else {
            break;
        };
        if bytes.get(i) != Some(&quote) {
            break;
        }
        i = i.saturating_add(1);
        out.push(Attribute {
            name,
            value,
            start: span_start,
            end: i,
        });
    }
    out
}

/// A byte range to cut from the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cut {
    start: usize,
    end: usize,
}

impl Cut {
    /// True when the range covers nothing, so that an already-empty element is not "rewritten"
    /// into an identical part.
    const fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

/// Build the output by copying `src` minus `cuts`.
///
/// Overlapping ranges are merged rather than double-cut, which is what makes it safe for an
/// element removal and an attribute removal inside it to be collected independently.
fn apply(src: &str, mut cuts: Vec<Cut>) -> Option<String> {
    if cuts.is_empty() {
        return None;
    }
    cuts.sort_unstable();

    let mut out = String::with_capacity(src.len());
    let mut copied = 0usize;
    for cut in cuts {
        if cut.start < copied {
            // Already inside a range that was cut.
            continue;
        }
        out.push_str(src.get(copied..cut.start)?);
        copied = cut.end;
    }
    out.push_str(src.get(copied..)?);
    Some(out)
}

/// Find the offset of `needle` in `bytes` at or after `from`.
fn find_from(bytes: &[u8], from: usize, needle: u8) -> Option<usize> {
    let rest = bytes.get(from..)?;
    rest.iter()
        .position(|b| *b == needle)
        .and_then(|n| from.checked_add(n))
}

/// The result of scrubbing one part.
pub(super) struct Scrubbed {
    /// The rewritten part, or [`None`] when nothing changed and the original bytes stand.
    pub(super) output: Option<String>,
    pub(super) findings: Vec<Finding>,
    pub(super) notes: Vec<Note>,
}

/// Remove identifying attributes and tables from one XML part.
///
/// `dead_rel_ids` names relationships this package has decided to remove — see
/// [`external_local_relationships`]. In a `.rels` part they identify the `Relationship` elements
/// to cut; in any other part they identify the elements that referred to them, which have to go
/// with them or be left pointing at nothing.
#[expect(
    clippy::too_many_lines,
    reason = "the removal rules are a single ordered walk over one part's tags; splitting it \
              into a rule per function would hide the ordering, and the ordering is what stops \
              an element removal and an attribute removal inside it from being collected twice"
)]
pub(super) fn scrub(
    src: &str,
    part: &str,
    dead_rel_ids: &BTreeSet<String>,
    options: &InspectOptions,
) -> Scrubbed {
    let tags = tags(src);
    let mut cuts: Vec<Cut> = Vec::new();
    // Aggregated per attribute name: thousands of rsids in one document should be one line in a
    // report, not thousands.
    let mut removed: Vec<(&str, MetadataKind, u64, Option<String>)> = Vec::new();
    let mut notes = Vec::new();

    let is_spreadsheet_comments = part.contains("comments");

    let mut i = 0usize;
    while let Some(tag) = tags.get(i) {
        i = i.saturating_add(1);

        // The whole revision-save-identifier table.
        if tag.name == RSID_TABLE_ELEMENT && matches!(tag.kind, Kind::Open | Kind::Empty) {
            if let Some(cut) = element_span(&tags, i.saturating_sub(1)) {
                cuts.push(cut);
                record(
                    &mut removed,
                    RSID_TABLE_ELEMENT,
                    MetadataKind::EditingHistory,
                    cut.end.saturating_sub(cut.start),
                    None,
                );
            }
            continue;
        }

        // SpreadsheetML's positional author list: emptied, not removed, so `authorId` indexes
        // keep pointing at the entries they pointed at.
        if is_spreadsheet_comments && tag.name == AUTHOR_TEXT_ELEMENT && tag.kind == Kind::Open {
            if let Some(text) = element_text(&tags, i.saturating_sub(1), src)
                && !text.range.is_empty()
            {
                cuts.push(text.range);
                record(
                    &mut removed,
                    AUTHOR_TEXT_ELEMENT,
                    MetadataKind::PersonalIdentity,
                    text.range.end.saturating_sub(text.range.start),
                    options.include_values.then(|| text.value.to_owned()),
                );
            }
            continue;
        }

        if tag.kind == Kind::Close {
            continue;
        }

        for attribute in attributes(tag.raw) {
            let Some(kind) = attribute_kind(tag.name, attribute.name) else {
                continue;
            };
            let Some(start) = tag.start.checked_add(attribute.start) else {
                continue;
            };
            let Some(end) = tag.start.checked_add(attribute.end) else {
                continue;
            };
            cuts.push(Cut { start, end });
            record(
                &mut removed,
                attribute.name,
                kind,
                end.saturating_sub(start),
                options.include_values.then(|| attribute.value.to_owned()),
            );
        }

        // A relationship pointing at a local or network path. An attached template on
        // somebody's desktop names that person in its path, and a UNC target names their file
        // server. Both ends go: the relationship here, and — in the part that referred to it —
        // whatever carried the `r:id`, since a reference to a relationship that is not there is
        // the repair prompt this handler exists to avoid.
        if tag.name == "Relationship"
            && tag
                .attribute("Id")
                .is_some_and(|id| dead_rel_ids.contains(id))
        {
            cuts.push(Cut {
                start: tag.start,
                end: tag.end,
            });
            record(
                &mut removed,
                RELATIONSHIP_ELEMENT,
                MetadataKind::PersonalIdentity,
                tag.end.saturating_sub(tag.start),
                options
                    .include_values
                    .then(|| tag.attribute("Target").unwrap_or_default().to_owned()),
            );
            continue;
        }

        // The other end of the same removal.
        if let Some(id) = tag.attribute("r:id")
            && dead_rel_ids.contains(id)
        {
            if tag.kind == Kind::Empty {
                // An empty element exists only for the reference it carries — `w:attachedTemplate`
                // is the case this was written for — so it goes entire.
                cuts.push(Cut {
                    start: tag.start,
                    end: tag.end,
                });
            } else if let Some(attribute) =
                attributes(tag.raw).into_iter().find(|a| a.name == "r:id")
            {
                // An element with content keeps its content and loses only the reference: a
                // hyperlink to a local file stops being a link and goes on saying what it said.
                if let (Some(start), Some(end)) = (
                    tag.start.checked_add(attribute.start),
                    tag.start.checked_add(attribute.end),
                ) {
                    cuts.push(Cut { start, end });
                }
            }
            record(
                &mut removed,
                RELATIONSHIP_REFERENCE,
                MetadataKind::PersonalIdentity,
                tag.end.saturating_sub(tag.start),
                None,
            );
        }
    }

    notes.extend(revision_notes(src, part));

    let findings = removed
        .into_iter()
        .map(|(name, kind, bytes, value)| {
            Finding::new(kind, part.to_owned(), bytes)
                .with_field(name.to_owned())
                .with_value(options, || MetadataValue::Text(value.unwrap_or_default()))
        })
        .collect();

    Scrubbed {
        output: apply(src, cuts),
        findings,
        notes,
    }
}

/// Which category an attribute falls into, or [`None`] if it is structural and stays.
fn attribute_kind(element: &str, attribute: &str) -> Option<MetadataKind> {
    if RSID_ATTRIBUTES.contains(&attribute) {
        return Some(MetadataKind::EditingHistory);
    }
    if PARAGRAPH_ID_ATTRIBUTES.contains(&attribute) {
        return Some(MetadataKind::DocumentIdentifier);
    }
    if AUTHORSHIP_ATTRIBUTES.contains(&attribute) {
        return Some(if attribute == "w:date" {
            MetadataKind::Timestamp
        } else {
            MetadataKind::PersonalIdentity
        });
    }
    if element == COMMENT_AUTHOR_ELEMENT && COMMENT_AUTHOR_ATTRIBUTES.contains(&attribute) {
        return Some(MetadataKind::PersonalIdentity);
    }
    None
}

/// Note the presence of content this handler deliberately does not remove.
fn revision_notes(src: &str, part: &str) -> Vec<Note> {
    let mut notes = Vec::new();
    if src.contains("<w:ins ") || src.contains("<w:del ") {
        notes.push(Note::OutOfScopeContent {
            location: format!("{part} (tracked changes; their authors and dates were removed)"),
        });
    }
    if part.ends_with("comments.xml") {
        notes.push(Note::OutOfScopeContent {
            location: format!("{part} (comment text; its authors and dates were removed)"),
        });
    }
    notes
}

/// Accumulate one removal under its attribute or element name.
fn record(
    removed: &mut Vec<(&'static str, MetadataKind, u64, Option<String>)>,
    name: &str,
    kind: MetadataKind,
    bytes: usize,
    value: Option<String>,
) {
    // The names are all drawn from the fixed tables above, so this maps back to a `'static`
    // string rather than allocating one per occurrence.
    let Some(stable) = stable_name(name) else {
        return;
    };
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    if let Some(existing) = removed.iter_mut().find(|(n, _, _, _)| *n == stable) {
        existing.2 = existing.2.saturating_add(bytes);
        return;
    }
    removed.push((stable, kind, bytes, value));
}

/// Map a scanned name back to the `'static` spelling from the tables above.
fn stable_name(name: &str) -> Option<&'static str> {
    RSID_ATTRIBUTES
        .into_iter()
        .chain(PARAGRAPH_ID_ATTRIBUTES)
        .chain(AUTHORSHIP_ATTRIBUTES)
        .chain(COMMENT_AUTHOR_ATTRIBUTES)
        .chain([
            RSID_TABLE_ELEMENT,
            AUTHOR_TEXT_ELEMENT,
            RELATIONSHIP_ELEMENT,
            RELATIONSHIP_REFERENCE,
        ])
        .find(|candidate| *candidate == name)
}

/// The full byte span of the element whose start tag is at `index`, including its end tag.
///
/// Depth-counted, so a nested element of the same name does not end the span early. [`None`]
/// when the element never closes, in which case nothing is removed and the part stands.
fn element_span(tags: &[Tag<'_>], index: usize) -> Option<Cut> {
    let start = tags.get(index)?;
    if start.kind == Kind::Empty {
        return Some(Cut {
            start: start.start,
            end: start.end,
        });
    }
    let mut depth = 1usize;
    let mut i = index.checked_add(1)?;
    while let Some(tag) = tags.get(i) {
        if tag.name == start.name {
            match tag.kind {
                Kind::Open => depth = depth.saturating_add(1),
                Kind::Close => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(Cut {
                            start: start.start,
                            end: tag.end,
                        });
                    }
                }
                Kind::Empty => {}
            }
        }
        i = i.checked_add(1)?;
    }
    None
}

/// The text between an element's start and end tags.
struct ElementText<'a> {
    range: Cut,
    value: &'a str,
}

/// Locate the text content of the element whose start tag is at `index`.
///
/// Only meaningful for an element with no child elements, which is what the author lists are.
fn element_text<'a>(tags: &[Tag<'a>], index: usize, src: &'a str) -> Option<ElementText<'a>> {
    let start = tags.get(index)?;
    let next = tags.get(index.checked_add(1)?)?;
    if next.kind != Kind::Close || next.name != start.name {
        return None;
    }
    let range = Cut {
        start: start.end,
        end: next.start,
    };
    Some(ElementText {
        range,
        value: src.get(range.start..range.end)?,
    })
}

/// Remove `Override` and `Relationship` entries pointing at parts that are no longer there.
///
/// Returns [`None`] when nothing referred to a removed part, so an index that did not need
/// changing keeps its original compressed bytes.
pub(super) fn drop_references(src: &str, dropped: &BTreeSet<String>) -> Option<String> {
    let mut cuts = Vec::new();
    for tag in tags(src) {
        let target = match tag.name {
            "Override" => tag.attribute("PartName"),
            "Relationship" => tag.attribute("Target"),
            _ => None,
        };
        let Some(target) = target else { continue };
        let normalised = target.strip_prefix('/').unwrap_or(target);
        if dropped.contains(normalised) {
            cuts.push(Cut {
                start: tag.start,
                end: tag.end,
            });
        }
    }
    apply(src, cuts)
}

/// Relationship ids in `src` whose target is a local filesystem or network path.
///
/// A `file:` URL or a UNC path in an external relationship is a direct personal identifier — an
/// attached template under someone's home directory names that person, and a UNC target names
/// their employer's file server. `http` targets are deliberately not matched: a hyperlink to a
/// public page is content the author put there on purpose.
pub(super) fn external_local_relationships(src: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for tag in tags(src) {
        if tag.name != "Relationship" || tag.attribute("TargetMode") != Some("External") {
            continue;
        }
        let Some(target) = tag.attribute("Target") else {
            continue;
        };
        let local = target.starts_with("file:")
            || target.starts_with("\\\\")
            // A bare drive-letter path, which some producers write unprefixed.
            || matches!(target.as_bytes().get(1), Some(b':'));
        if local && let Some(id) = tag.attribute("Id") {
            ids.insert(id.to_owned());
        }
    }
    ids
}

/// One element and its text, for reporting the contents of a properties part.
pub(super) struct TextElement<'a> {
    pub(super) name: &'a str,
    pub(super) text: &'a str,
}

/// Every element in `src` that directly contains text.
pub(super) fn elements_with_text(src: &str) -> Vec<TextElement<'_>> {
    let tags = tags(src);
    let mut out = Vec::new();
    for (index, tag) in tags.iter().enumerate() {
        if tag.kind != Kind::Open {
            continue;
        }
        if let Some(text) = element_text(&tags, index, src)
            && !text.value.is_empty()
        {
            out.push(TextElement {
                name: tag.name,
                text: text.value,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn a_quoted_angle_bracket_does_not_split_a_tag() {
        // An attribute value may legitimately contain `>`. A scanner that stopped at the first
        // one would read the rest of the tag as text and then edit the wrong bytes.
        let found = tags(r#"<w:p w:rsidR="a>b" other="x"/>"#);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "w:p");
        assert_eq!(found[0].attribute("w:rsidR"), Some("a>b"));
        assert_eq!(found[0].attribute("other"), Some("x"));
    }

    #[test]
    fn comments_and_cdata_are_not_read_as_markup() {
        let src = r"<a><!-- <w:p w:rsidR='1'/> --><![CDATA[<b/>]]><c/></a>";
        let names: Vec<&str> = tags(src).iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["a", "c", "a"]);
    }

    #[test]
    fn an_unterminated_comment_stops_the_scan_rather_than_resuming_inside_it() {
        let found = tags("<a/><!-- <b/>");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "a");
    }

    #[test]
    fn rsid_attributes_are_removed_and_everything_else_is_byte_identical() {
        let src = r#"<w:p w:rsidR="00A1" w:rsidRDefault="00A1" w14:paraId="12345678"><w:r><w:t>text</w:t></w:r></w:p>"#;
        let scrubbed = scrub(
            src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        );
        let out = scrubbed.output.unwrap();
        assert_eq!(out, "<w:p><w:r><w:t>text</w:t></w:r></w:p>");
    }

    #[test]
    fn a_part_with_nothing_to_remove_is_left_alone() {
        // `None` here is what keeps a clean document's entries byte-identical to their
        // originals: an unchanged part is copied with its original compressed bytes.
        let src = r"<w:p><w:r><w:t>ordinary text</w:t></w:r></w:p>";
        let scrubbed = scrub(
            src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        );
        assert!(scrubbed.output.is_none());
        assert!(scrubbed.findings.is_empty());
    }

    #[test]
    fn a_tracked_change_keeps_its_words_and_loses_its_author() {
        let src = r#"<w:ins w:id="1" w:author="A Name" w:date="2026-01-01T00:00:00Z"><w:r><w:t>inserted</w:t></w:r></w:ins>"#;
        let scrubbed = scrub(
            src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        );
        let out = scrubbed.output.unwrap();
        assert_eq!(
            out,
            r#"<w:ins w:id="1"><w:r><w:t>inserted</w:t></w:r></w:ins>"#
        );
        assert!(
            out.contains("inserted"),
            "the document's words are its payload and must survive (PRD §8.1)"
        );
        assert!(
            scrubbed
                .notes
                .iter()
                .any(|n| matches!(n, Note::OutOfScopeContent { .. })),
            "the revision that remains has to be declared, not left silent"
        );
    }

    #[test]
    fn the_rsid_table_is_removed_whole() {
        let src = "<w:settings><w:rsids><w:rsidRoot w:val=\"00A1\"/><w:rsid w:val=\"00B2\"/></w:rsids><w:zoom w:percent=\"100\"/></w:settings>";
        let out = scrub(
            src,
            "word/settings.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        assert_eq!(
            out, "<w:settings><w:zoom w:percent=\"100\"/></w:settings>",
            "nothing outside the table refers into it, so it goes entire"
        );
    }

    #[test]
    fn a_presentation_comment_author_loses_its_name_but_keeps_its_index() {
        let src = r#"<p:cmAuthorLst><p:cmAuthor id="1" name="A Name" initials="AN" lastIdx="2"/></p:cmAuthorLst>"#;
        let out = scrub(
            src,
            "ppt/commentAuthors.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        assert!(!out.contains("A Name"));
        assert!(
            out.contains(r#"id="1""#),
            "the id is what comments refer to and must not move"
        );
    }

    #[test]
    fn a_spreadsheet_author_entry_is_emptied_rather_than_removed() {
        // `authorId` is a positional index into this list, so deleting an entry would silently
        // reattribute every comment after it.
        let src = "<authors><author>A Name</author><author>B Name</author></authors>";
        let out = scrub(
            src,
            "xl/comments1.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        assert_eq!(out, "<authors><author></author><author></author></authors>");
    }

    #[test]
    fn a_name_attribute_is_only_removed_on_the_element_that_owns_authors() {
        // `name` is structural nearly everywhere it appears; removing it wholesale would break
        // the document.
        let src = r#"<w:style w:styleId="Normal"><w:name w:val="Normal"/></w:style>"#;
        assert!(
            scrub(
                src,
                "word/styles.xml",
                &BTreeSet::new(),
                &InspectOptions::names_only()
            )
            .output
            .is_none()
        );
    }

    #[test]
    fn values_are_withheld_unless_the_caller_asks() {
        let src = r#"<w:ins w:author="A Name"/>"#;
        let names_only = scrub(
            src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        );
        assert!(names_only.findings.iter().all(|f| f.value.is_none()));

        let with_values = scrub(
            src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::with_values(),
        );
        assert_eq!(
            with_values
                .findings
                .iter()
                .find(|f| f.field.as_deref() == Some("w:author"))
                .and_then(|f| f.value.clone()),
            Some(MetadataValue::Text("A Name".to_owned()))
        );
    }

    #[test]
    fn thousands_of_rsids_aggregate_to_one_finding() {
        // A report is for a person deciding whether to publish. One line saying "revision
        // identifiers, 40 KB" is usable; four thousand lines are not.
        let mut src = String::from("<w:body>");
        for _ in 0..500 {
            src.push_str(r#"<w:p w:rsidR="00A1"/>"#);
        }
        src.push_str("</w:body>");
        let scrubbed = scrub(
            &src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        );
        assert_eq!(scrubbed.findings.len(), 1);
        assert_eq!(scrubbed.findings[0].field.as_deref(), Some("w:rsidR"));
    }

    #[test]
    fn scrubbing_is_idempotent() {
        let src = r#"<w:p w:rsidR="00A1" w14:paraId="1"><w:ins w:author="X"/></w:p>"#;
        let once = scrub(
            src,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        let twice = scrub(
            &once,
            "word/document.xml",
            &BTreeSet::new(),
            &InspectOptions::names_only(),
        );
        assert!(
            twice.output.is_none(),
            "a second pass must find nothing, or verification would never converge"
        );
    }

    #[test]
    fn dropped_parts_lose_their_index_entries() {
        let src = r#"<Types><Override PartName="/docProps/core.xml" ContentType="x"/><Override PartName="/word/document.xml" ContentType="y"/></Types>"#;
        let dropped: BTreeSet<String> = ["docProps/core.xml".to_owned()].into_iter().collect();
        let out = drop_references(src, &dropped).unwrap();
        assert!(!out.contains("core.xml"));
        assert!(out.contains("word/document.xml"));
    }

    #[test]
    fn an_index_that_needed_no_change_is_reported_as_unchanged() {
        let src = r#"<Types><Override PartName="/word/document.xml" ContentType="y"/></Types>"#;
        assert!(drop_references(src, &BTreeSet::new()).is_none());
    }

    #[test]
    fn an_external_relationship_to_a_local_path_is_removed_at_both_ends() {
        // A `file:` target under somebody's home directory names that person, so both ends go:
        // the relationship, and whatever referred to it. Removing only one end would leave a
        // reference pointing at nothing, which is the repair prompt this handler avoids.
        let rels = r#"<Relationships><Relationship Id="rId1" Type="t" Target="file:///Users/SYNTHETIC-USER-0016/Templates/report.dotx" TargetMode="External"/><Relationship Id="rId2" Type="t" Target="https://example.org/page" TargetMode="External"/></Relationships>"#;
        let dead = external_local_relationships(rels);
        assert_eq!(
            dead.iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["rId1"],
            "an http hyperlink is content the author put there on purpose and stays"
        );

        let rewritten = scrub(
            rels,
            "word/_rels/settings.xml.rels",
            &dead,
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        assert!(!rewritten.contains("SYNTHETIC-USER-0016"));
        assert!(rewritten.contains("rId2"));

        let settings = r#"<w:settings><w:attachedTemplate r:id="rId1"/><w:zoom w:percent="100"/></w:settings>"#;
        let cleaned = scrub(
            settings,
            "word/settings.xml",
            &dead,
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        assert_eq!(
            cleaned, r#"<w:settings><w:zoom w:percent="100"/></w:settings>"#,
            "an element that exists only to carry the reference goes entire"
        );
    }

    #[test]
    fn an_element_with_content_keeps_its_content_and_loses_only_the_reference() {
        // A hyperlink to a local file stops being a link and goes on saying what it said.
        // Deleting the whole element would delete the author's words with it.
        let dead: BTreeSet<String> = ["rId9".to_owned()].into_iter().collect();
        let src =
            r#"<w:hyperlink r:id="rId9"><w:r><w:t>PRESERVED-LINK-TEXT</w:t></w:r></w:hyperlink>"#;
        let out = scrub(
            src,
            "word/document.xml",
            &dead,
            &InspectOptions::names_only(),
        )
        .output
        .unwrap();
        assert_eq!(
            out,
            r"<w:hyperlink><w:r><w:t>PRESERVED-LINK-TEXT</w:t></w:r></w:hyperlink>"
        );
    }

    #[test]
    fn arbitrary_text_does_not_panic_the_scanner() {
        // The scanner sits on attacker-controlled bytes like every parser in this crate.
        let cases = [
            "<",
            "<a",
            "<a=",
            "</",
            "<!",
            "<!--",
            "<![CDATA[",
            "<?",
            "<a b=",
            "<a b='",
            "<a b='c",
            "<<<<>>>>",
            "<a/><//>",
            "<w:rsids>",
            "<author>",
        ];
        for case in cases {
            let _ = scrub(
                case,
                "word/document.xml",
                &BTreeSet::new(),
                &InspectOptions::names_only(),
            );
            let _ = elements_with_text(case);
            let _ = drop_references(case, &BTreeSet::new());
        }
    }

    #[test]
    fn every_prefix_of_a_real_part_is_survivable() {
        let src = r#"<?xml version="1.0"?><w:document xmlns:w="ns"><w:body><w:p w:rsidR="00A1"><w:r><w:t>x</w:t></w:r></w:p></w:body></w:document>"#;
        for n in 0..=src.len() {
            let prefix = src.get(0..n).unwrap_or_default();
            let _ = scrub(
                prefix,
                "word/document.xml",
                &BTreeSet::new(),
                &InspectOptions::names_only(),
            );
        }
    }
}
