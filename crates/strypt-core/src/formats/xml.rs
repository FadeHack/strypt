//! Just enough XML to find and delete the identifying parts of a document.
//!
//! Shared by the two ZIP-package format groups — Office Open XML and `OpenDocument` — in the same
//! way [`super::exif`] and [`super::xmp`] are shared by the image handlers. **The rules about
//! which elements and attributes are identifying live with their format**, in
//! `ooxml/xml.rs` and `odf/xml.rs`; what lives here is the scanning and the cutting, which is
//! the part that sits on hostile bytes and the part neither format should have its own copy of.
//!
//! # Why there is no XML parser here
//!
//! ADR-0008 requires a dependency to earn its place, and an XML parser is a large, historically
//! CVE-dense category to admit for a job that never needs a document tree. Everything the
//! handlers do is: name the elements and attributes present, and delete the byte ranges of some
//! of them. That is a scanner, not a parser.
//!
//! **Editing is by deletion, never by re-serialisation.** A rewritten part is the original bytes
//! with some ranges cut out, so every byte that had no reason to change does not change:
//! namespace declarations keep their order, attribute quoting keeps its style, whitespace keeps
//! its shape. Re-serialising through a document model would rewrite the whole part and make it
//! impossible to see, in a diff, what strypt actually did.
//!
//! # What this scanner does not do
//!
//! It does not resolve entities, does not validate, does not check that elements nest, and does
//! not decode character references. It does not need to: an attribute is removed on the strength
//! of its *name*, and a name cannot be spelled with an entity reference in XML. Where the scanner
//! cannot make sense of the text it stops and the part is copied through untouched with a note
//! saying so, rather than being edited on a guess.

/// How a tag closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) enum Kind {
    /// `<name ...>`
    Open,
    /// `</name>`
    Close,
    /// `<name ... />`
    Empty,
}

/// One element tag, located in the source.
#[derive(Debug, Clone)]
pub(in crate::formats) struct Tag<'a> {
    /// The element's name, exactly as written, prefix included.
    pub(in crate::formats) name: &'a str,
    /// How it closes.
    pub(in crate::formats) kind: Kind,
    /// Byte offset of the opening `<`.
    pub(in crate::formats) start: usize,
    /// Byte offset one past the closing `>`.
    pub(in crate::formats) end: usize,
    /// The whole tag text, `<` and `>` included.
    pub(in crate::formats) raw: &'a str,
}

impl<'a> Tag<'a> {
    /// The value of `name`, or [`None`] if the attribute is absent.
    pub(in crate::formats) fn attribute(&self, name: &str) -> Option<&'a str> {
        attributes(self.raw)
            .into_iter()
            .find(|attr| attr.name == name)
            .map(|attr| attr.value)
    }
}

/// One attribute, located within its tag's text.
pub(in crate::formats) struct Attribute<'a> {
    pub(in crate::formats) name: &'a str,
    pub(in crate::formats) value: &'a str,
    /// Byte offset within the tag of the whitespace preceding the attribute, so that removing
    /// the range leaves no double space behind.
    pub(in crate::formats) start: usize,
    /// Byte offset within the tag one past the closing quote.
    pub(in crate::formats) end: usize,
}

/// A construct that is not an element tag.
///
/// The scanner has always stepped over these. It now says where they were, because SVG removes
/// two of them — a comment is where Adobe writes its generator string, and a processing
/// instruction is where an XMP packet's wrapper lives (ADR-0035). Neither package format needs
/// them, so both keep getting the tag list alone and their output is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) enum NonElementKind {
    /// `<!-- ... -->`
    Comment,
    /// `<![CDATA[ ... ]]>`
    Cdata,
    /// `<? ... ?>`
    ProcessingInstruction,
    /// `<!DOCTYPE ...>`, and any other `<!` declaration.
    Doctype,
}

/// One non-element construct, located in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::formats) struct NonElement {
    pub(in crate::formats) kind: NonElementKind,
    /// Byte offset of the opening `<`.
    pub(in crate::formats) start: usize,
    /// Byte offset one past the terminator, or the end of the input when it never closed.
    pub(in crate::formats) end: usize,
}

/// Everything one pass over the source found.
pub(in crate::formats) struct Scan<'a> {
    pub(in crate::formats) tags: Vec<Tag<'a>>,
    pub(in crate::formats) others: Vec<NonElement>,
}

/// Every element tag in `src`, in document order.
///
/// Comments, CDATA sections, processing instructions, and doctype declarations are skipped
/// rather than reported: nothing the package handlers remove lives in one, and treating their
/// contents as markup is how a scanner starts editing text it has misread. A caller that needs
/// their positions asks [`scan`] instead.
pub(in crate::formats) fn tags(src: &str) -> Vec<Tag<'_>> {
    scan(src).tags
}

/// Every element tag and every non-element construct in `src`, in document order.
pub(in crate::formats) fn scan(src: &str) -> Scan<'_> {
    let bytes = src.as_bytes();
    let mut tags = Vec::new();
    let mut others = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(open) = find_from(bytes, i, b'<') else {
            break;
        };
        let rest = src.get(open..).unwrap_or_default();

        // Step over the constructs whose contents are not markup. Each reports the offset just
        // past its terminator; an unterminated one ends the scan, because everything after it is
        // inside a construct that never closed.
        if let Some((kind, skipped)) = skip_non_element(rest, open) {
            others.push(NonElement {
                kind,
                start: open,
                end: skipped,
            });
            i = skipped;
            continue;
        }

        let Some(close) = find_tag_end(bytes, open) else {
            break;
        };
        let end = close.saturating_add(1);
        let raw = src.get(open..end).unwrap_or_default();
        if let Some(tag) = parse_tag(raw, open, end) {
            tags.push(tag);
        }
        i = end;
    }
    Scan { tags, others }
}

/// Step over a comment, CDATA section, processing instruction, or doctype, reporting what it was
/// and the offset past it. [`None`] when `rest` begins an ordinary element tag.
fn skip_non_element(rest: &str, at: usize) -> Option<(NonElementKind, usize)> {
    let (kind, prefix, terminator): (NonElementKind, &str, &str) = if rest.starts_with("<!--") {
        (NonElementKind::Comment, "<!--", "-->")
    } else if rest.starts_with("<![CDATA[") {
        (NonElementKind::Cdata, "<![CDATA[", "]]>")
    } else if rest.starts_with("<?") {
        (NonElementKind::ProcessingInstruction, "<?", "?>")
    } else if rest.starts_with("<!") {
        (NonElementKind::Doctype, "<!", ">")
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
    Some((kind, at.saturating_add(offset)))
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
pub(in crate::formats) fn attributes(raw: &str) -> Vec<Attribute<'_>> {
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
pub(in crate::formats) struct Cut {
    pub(in crate::formats) start: usize,
    pub(in crate::formats) end: usize,
}

impl Cut {
    /// True when the range covers nothing, so that an already-empty element is not "rewritten"
    /// into an identical part.
    pub(in crate::formats) const fn is_empty(self) -> bool {
        self.start >= self.end
    }

    /// How many bytes the range covers.
    pub(in crate::formats) const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

/// Build the output by copying `src` minus `cuts`.
///
/// Overlapping ranges are merged rather than double-cut, which is what makes it safe for an
/// element removal and an attribute removal inside it to be collected independently.
pub(in crate::formats) fn apply(src: &str, mut cuts: Vec<Cut>) -> Option<String> {
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

/// The full byte span of the element whose start tag is at `index`, including its end tag.
///
/// Depth-counted, so a nested element of the same name does not end the span early. [`None`]
/// when the element never closes, in which case nothing is removed and the part stands.
pub(in crate::formats) fn element_span(tags: &[Tag<'_>], index: usize) -> Option<Cut> {
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
pub(in crate::formats) struct ElementText<'a> {
    pub(in crate::formats) range: Cut,
    pub(in crate::formats) value: &'a str,
}

/// Locate the text content of the element whose start tag is at `index`.
///
/// Only meaningful for an element with no child elements, which is what a metadata field is.
pub(in crate::formats) fn element_text<'a>(
    tags: &[Tag<'a>],
    index: usize,
    src: &'a str,
) -> Option<ElementText<'a>> {
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

/// One element and its text, for reporting the contents of a metadata part.
pub(in crate::formats) struct TextElement<'a> {
    pub(in crate::formats) name: &'a str,
    pub(in crate::formats) text: &'a str,
}

/// Every element in `src` that directly contains text.
pub(in crate::formats) fn elements_with_text(src: &str) -> Vec<TextElement<'_>> {
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

/// Remove every tag for which `should_drop` answers true.
///
/// Used by both package formats to make an index part stop referring to a part that is no longer
/// there — `[Content_Types].xml` and `_rels/.rels` in OOXML, `META-INF/manifest.xml` in ODF.
/// Returns [`None`] when nothing matched, so an index that did not need changing keeps its
/// original compressed bytes.
pub(in crate::formats) fn drop_tags(
    src: &str,
    should_drop: impl Fn(&Tag<'_>) -> bool,
) -> Option<String> {
    let mut cuts = Vec::new();
    for tag in tags(src) {
        if should_drop(&tag) {
            cuts.push(Cut {
                start: tag.start,
                end: tag.end,
            });
        }
    }
    apply(src, cuts)
}

/// Tracks which elements the scan is currently inside.
///
/// The scanner is linear rather than a tree, but some rules are only correct in context: in ODF
/// a `<dc:creator>` inside an `<office:annotation>` is a comment's author and a `<dc:creator>`
/// in `meta.xml` is the document's, and neither format's rules should fire on the other's
/// element. Maintaining the open-element names as the scan passes them is enough to express
/// that, and costs one push per tag.
pub(in crate::formats) struct OpenElements<'a> {
    stack: Vec<&'a str>,
}

/// The deepest nesting the scanner will track before giving up on a part.
///
/// Not a stack-overflow guard — nothing here recurses — but a bound on how much a hostile part
/// can make strypt remember. Real documents nest to tens of levels; a part that goes past this
/// is not one whose rules are worth applying on a guess, and the caller copies it through.
const MAX_ELEMENT_DEPTH: usize = 256;

impl<'a> OpenElements<'a> {
    pub(in crate::formats) const fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Record a tag, returning `false` when the part nests deeper than this will follow.
    pub(in crate::formats) fn observe(&mut self, tag: &Tag<'a>) -> bool {
        match tag.kind {
            Kind::Open => {
                if self.stack.len() >= MAX_ELEMENT_DEPTH {
                    return false;
                }
                self.stack.push(tag.name);
            }
            Kind::Close => {
                // A close tag that matches nothing open is malformed markup. Popping the
                // innermost element anyway would make the scanner's idea of context drift for
                // the rest of the part, so the mismatch ends the tracking instead.
                if self.stack.last() != Some(&tag.name) {
                    return false;
                }
                self.stack.pop();
            }
            Kind::Empty => {}
        }
        true
    }

    /// True when the scan is inside an element named `name`.
    pub(in crate::formats) fn inside(&self, name: &str) -> bool {
        self.stack.contains(&name)
    }
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
    fn open_elements_tracks_context_and_gives_up_on_mismatched_markup() {
        let src = "<office:annotation><dc:creator>x</dc:creator></office:annotation>";
        let mut open = OpenElements::new();
        let mut seen_inside = false;
        for tag in tags(src) {
            if tag.name == "dc:creator" && tag.kind == Kind::Open {
                seen_inside = open.inside("office:annotation");
            }
            assert!(open.observe(&tag));
        }
        assert!(seen_inside, "context must be visible to the rule");

        // A close tag matching nothing open ends the tracking rather than letting the scanner's
        // idea of where it is drift for the rest of the part.
        let mut open = OpenElements::new();
        let mismatched = tags("<a></b>");
        assert!(open.observe(&mismatched[0]));
        assert!(!open.observe(&mismatched[1]));
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
            let found = tags(case);
            for (index, tag) in found.iter().enumerate() {
                let _ = attributes(tag.raw);
                let _ = element_span(&found, index);
                let _ = element_text(&found, index, case);
            }
            let _ = elements_with_text(case);
            let _ = drop_tags(case, |_| true);
        }
    }
}
