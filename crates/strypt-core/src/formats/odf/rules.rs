//! Which elements of an `OpenDocument` part are identifying, and what happens to each.
//!
//! The scanning and the cutting are [`crate::formats::xml`], shared with Office Open XML. What
//! is here is only the `OpenDocument`-specific half — and it is a genuinely different half, which
//! is the finding ADR-0031 was written around:
//!
//! **In Office Open XML, authorship is an attribute; in `OpenDocument` it is element text.**
//! `<w:ins w:author="A Name">` against
//! `<office:change-info><dc:creator>A Name</dc:creator></office:change-info>`. An attribute can
//! be removed on the strength of its name alone, wherever it appears. `<dc:creator>` cannot: the
//! same element name is the document's author in `meta.xml`, a comment's author inside an
//! `<office:annotation>`, and a revision's author inside an `<office:change-info>`. So this
//! module tracks which elements the scan is inside, where the Office rules never had to.

use std::collections::BTreeSet;

use crate::formats::xml::{self, Cut, Kind, Tag};
use crate::report::{Finding, InspectOptions, MetadataKind, MetadataValue, Note};

/// The two elements that wrap an attribution in the document body.
///
/// `<office:annotation>` is a comment; `<office:change-info>` is the author and date of one
/// tracked change. Both are ODF 1.3 Part 3 §14.3 and §5.5.
const ANNOTATION_ELEMENT: &str = "office:annotation";
const CHANGE_INFO_ELEMENT: &str = "office:change-info";

/// The children of those two whose text names a person or a moment.
///
/// Emptied rather than removed with their container: the comment's own words stay, for the
/// reason in the parent module's header, and an annotation with no `<dc:creator>` at all is
/// still a valid annotation.
const ATTRIBUTION_ELEMENTS: [(&str, MetadataKind); 3] = [
    ("dc:creator", MetadataKind::PersonalIdentity),
    ("dc:date", MetadataKind::Timestamp),
    // The human-readable form of the same date, which LibreOffice writes beside it.
    ("meta:date-string", MetadataKind::Timestamp),
];

/// Fields in the document body whose text is a *cached copy* of something in `meta.xml`.
///
/// These are the one place this handler edits what a reader sees, and it is deliberate. A
/// `<text:creator>` field is not words the author typed: the application inserted it and filled
/// it in from the document's own metadata, so its content is a second copy of the name in
/// `meta.xml`. Leaving it would mean strypt removing the author from the metadata and reporting
/// so while the same name is printed in the document's header — which is the shape of the
/// failure in `docs/THREAT_MODEL.md` §5.4, not a preservation of payload.
///
/// The field element itself stays, so the document's structure is untouched and an application
/// refills it from whatever metadata exists next time. What goes is the cached value.
const CACHED_METADATA_FIELDS: [(&str, MetadataKind); 7] = [
    ("text:creator", MetadataKind::PersonalIdentity),
    ("text:initial-creator", MetadataKind::PersonalIdentity),
    ("text:author-name", MetadataKind::PersonalIdentity),
    ("text:author-initials", MetadataKind::PersonalIdentity),
    ("text:printed-by", MetadataKind::PersonalIdentity),
    ("text:editing-cycles", MetadataKind::EditingHistory),
    ("text:editing-duration", MetadataKind::EditingHistory),
];

/// Date and time fields that are left exactly as they are, and reported.
///
/// A date printed in a letter's header is a date the author chose to show. Blanking it would be
/// strypt editing the document's visible content, which `docs/PRD.md` §8.1 reserves for the
/// user — but a user who asked for timestamps to be removed should be told that one is still on
/// the page, so its presence is a note.
const DISPLAYED_TIME_FIELDS: [&str; 6] = [
    "text:creation-date",
    "text:creation-time",
    "text:modification-date",
    "text:modification-time",
    "text:print-date",
    "text:print-time",
];

/// Elements of `<office:meta>`, and what each of them exposes.
///
/// `meta:editing-cycles` and `meta:editing-duration` have no Office Open XML counterpart worth
/// calling equivalent. `cp:revision` counts saves as ODF's editing-cycles does, but `TotalTime`
/// is cumulative *minutes* while `meta:editing-duration` is an ISO 8601 duration written to the
/// second — `PT4H32M17S`. Together with `meta:creation-date` and `dc:date` that is enough to
/// reconstruct when somebody sat down, how long they worked, and when they stopped.
const META_ELEMENTS: [(&str, MetadataKind); 12] = [
    ("meta:initial-creator", MetadataKind::PersonalIdentity),
    // In ODF `dc:creator` inside `office:meta` is the *last* person to save the document, which
    // is the opposite way round from the name a reader would guess.
    ("dc:creator", MetadataKind::PersonalIdentity),
    ("meta:printed-by", MetadataKind::PersonalIdentity),
    ("meta:creation-date", MetadataKind::Timestamp),
    ("dc:date", MetadataKind::Timestamp),
    ("meta:print-date", MetadataKind::Timestamp),
    ("meta:editing-cycles", MetadataKind::EditingHistory),
    ("meta:editing-duration", MetadataKind::EditingHistory),
    // Names the application, its version, *and its operating system*:
    // `LibreOffice/7.4.2$Linux_X86_64 LibreOffice_project/…`. The Office equivalents,
    // `Application` and `AppVersion`, do not name the platform.
    ("meta:generator", MetadataKind::SoftwareFingerprint),
    ("dc:title", MetadataKind::Comment),
    ("dc:description", MetadataKind::Comment),
    ("dc:subject", MetadataKind::Comment),
];

/// `<meta:user-defined meta:name="…">` — arbitrary named properties, the ODF counterpart of
/// `docProps/custom.xml`, and the same place a document management system leaves a matter number
/// or a username.
const USER_DEFINED_ELEMENT: &str = "meta:user-defined";

/// `<meta:document-statistic>`, whose counts are **attributes rather than text**.
///
/// Worth stating because it is exactly where the Office reporting path does not transfer: that
/// one walks elements that contain text, and this element contains none. A page and word count
/// is not identifying by itself and it correlates a published excerpt with an unpublished
/// original very well.
const STATISTIC_ELEMENT: &str = "meta:document-statistic";

/// `<meta:template xlink:href="…">`, which frequently points at a file on the author's machine.
const TEMPLATE_ELEMENT: &str = "meta:template";

/// Configuration items in `settings.xml` that name something outside the document.
///
/// `settings.xml` is removed whole regardless (ADR-0031); this list is what lets the report say
/// *which* of its several hundred items were worth removing, rather than "a settings part was
/// removed", which tells a user deciding whether to publish nothing at all.
const SENSITIVE_SETTINGS: [(&str, MetadataKind); 6] = [
    ("PrinterName", MetadataKind::DeviceIdentity),
    // A base64 blob holding the printer's name, its driver, and its port — often a network path
    // that names an employer's print server.
    ("PrinterSetup", MetadataKind::DeviceIdentity),
    ("CurrentDatabaseDataSource", MetadataKind::PersonalIdentity),
    ("CurrentDatabaseCommand", MetadataKind::PersonalIdentity),
    ("BuildId", MetadataKind::SoftwareFingerprint),
    ("ColorPalettes", MetadataKind::SoftwareFingerprint),
];

/// The result of scrubbing one part.
pub(super) struct Scrubbed {
    /// The rewritten part, or [`None`] when nothing changed and the original bytes stand.
    pub(super) output: Option<String>,
    pub(super) findings: Vec<Finding>,
    pub(super) notes: Vec<Note>,
}

/// Remove identifying text from one XML part of the document body.
pub(super) fn scrub(src: &str, part: &str, options: &InspectOptions) -> Scrubbed {
    let tags = xml::tags(src);
    let mut cuts: Vec<Cut> = Vec::new();
    // Aggregated per element name: a document with four hundred tracked changes in it should be
    // one line in a report, not four hundred.
    let mut removed: Vec<(&'static str, MetadataKind, u64, Option<String>)> = Vec::new();
    let mut notes = Vec::new();
    let mut open = xml::OpenElements::new();

    for (index, tag) in tags.iter().enumerate() {
        if tag.kind == Kind::Open {
            // Context is read before this tag is pushed, so a rule asks about its *parents*.
            let attribution = open.inside(ANNOTATION_ELEMENT) || open.inside(CHANGE_INFO_ELEMENT);
            let rule = if attribution {
                lookup(&ATTRIBUTION_ELEMENTS, tag.name)
            } else {
                None
            }
            .or_else(|| lookup(&CACHED_METADATA_FIELDS, tag.name));

            if let Some((name, kind)) = rule
                && let Some((cut, value)) = value_span(&tags, index, src)
                && !cut.is_empty()
            {
                cuts.push(cut);
                record(
                    &mut removed,
                    name,
                    kind,
                    cut.len(),
                    options.include_values.then(|| value.to_owned()),
                );
            }
        }

        if !open.observe(tag) {
            // The part nests deeper than the scanner will follow, or its tags do not match. It
            // is copied through untouched rather than edited on a guess about where the scan
            // is — and the note says so, because bytes nobody could examine is exactly what a
            // user deciding whether to publish needs told.
            return Scrubbed {
                output: None,
                findings: Vec::new(),
                notes: vec![Note::UnparsedRegion {
                    location: format!("{part} (markup the scanner could not follow)"),
                    bytes: u64::try_from(src.len()).unwrap_or(u64::MAX),
                }],
            };
        }
    }

    notes.extend(content_notes(src, part));

    let findings = removed
        .into_iter()
        .map(|(name, kind, bytes, value)| {
            Finding::new(kind, part.to_owned(), bytes)
                .with_field(name.to_owned())
                .with_value(options, || MetadataValue::Text(value.unwrap_or_default()))
        })
        .collect();

    Scrubbed {
        output: xml::apply(src, cuts),
        findings,
        notes,
    }
}

/// The range holding an element's value, and the value itself.
///
/// Ordinarily that is the text between the start and end tags, which is what every one of these
/// elements holds in a document any application wrote. When the element has children instead —
/// which the schema does not permit and a hostile file is free to do — the *whole element* is
/// cut rather than left alone. Leaving it would mean a name surviving in a document strypt
/// reported as cleaned, which is the one outcome worth changing the shape of the edit for.
fn value_span<'a>(tags: &[Tag<'a>], index: usize, src: &'a str) -> Option<(Cut, &'a str)> {
    if let Some(text) = xml::element_text(tags, index, src) {
        return Some((text.range, text.value));
    }
    let span = xml::element_span(tags, index)?;
    Some((span, src.get(span.start..span.end).unwrap_or_default()))
}

/// Note the presence of content this handler deliberately does not remove.
fn content_notes(src: &str, part: &str) -> Vec<Note> {
    let mut notes = Vec::new();
    if src.contains("<text:tracked-changes") || src.contains("<table:tracked-changes") {
        notes.push(Note::OutOfScopeContent {
            location: format!("{part} (tracked changes; their authors and dates were removed)"),
        });
    }
    if src.contains("<office:annotation") {
        notes.push(Note::OutOfScopeContent {
            location: format!("{part} (comment text; its authors and dates were removed)"),
        });
    }
    if DISPLAYED_TIME_FIELDS
        .iter()
        .any(|field| src.contains(&format!("<{field}")))
    {
        notes.push(Note::OutOfScopeContent {
            location: format!("{part} (a date or time field the document displays)"),
        });
    }
    notes
}

/// Find `name` in a table of rules.
fn lookup(
    table: &[(&'static str, MetadataKind)],
    name: &str,
) -> Option<(&'static str, MetadataKind)> {
    table
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .copied()
}

/// Accumulate one removal under its element name.
fn record(
    removed: &mut Vec<(&'static str, MetadataKind, u64, Option<String>)>,
    name: &'static str,
    kind: MetadataKind,
    bytes: usize,
    value: Option<String>,
) {
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    if let Some(existing) = removed.iter_mut().find(|(n, _, _, _)| *n == name) {
        existing.2 = existing.2.saturating_add(bytes);
        return;
    }
    removed.push((name, kind, bytes, value));
}

/// Report what `meta.xml` held, before the part is dropped.
///
/// The part goes whole either way. Naming its fields is what makes `strypt show` useful — "this
/// document names an author and records four and a half hours of editing across 37 saves" is
/// actionable, where "a metadata part was removed" is not.
pub(super) fn meta_findings(src: &str, part: &str, options: &InspectOptions) -> Vec<Finding> {
    let tags = xml::tags(src);
    let mut findings = Vec::new();

    for (index, tag) in tags.iter().enumerate() {
        if tag.kind == Kind::Close {
            continue;
        }
        match tag.name {
            // Attributes rather than text, which is why the Office reporting path does not
            // transfer: it walks elements that contain text, and this element contains none.
            STATISTIC_ELEMENT => {
                for attribute in xml::attributes(tag.raw) {
                    findings.push(
                        Finding::new(
                            MetadataKind::Other,
                            part.to_owned(),
                            u64::try_from(attribute.value.len()).unwrap_or(u64::MAX),
                        )
                        .with_field(attribute.name.to_owned())
                        .with_value(options, || MetadataValue::Text(attribute.value.to_owned())),
                    );
                }
            }
            // A template reference whose target is frequently a path on the author's machine —
            // the same leak as an Office attached template, in a different spelling.
            TEMPLATE_ELEMENT => {
                if let Some(href) = tag.attribute("xlink:href") {
                    findings.push(
                        Finding::new(
                            MetadataKind::PersonalIdentity,
                            part.to_owned(),
                            u64::try_from(href.len()).unwrap_or(u64::MAX),
                        )
                        .with_field("meta:template xlink:href".to_owned())
                        .with_value(options, || MetadataValue::Text(href.to_owned())),
                    );
                }
            }
            USER_DEFINED_ELEMENT => {
                let name = tag.attribute("meta:name").unwrap_or("meta:user-defined");
                let text = xml::element_text(&tags, index, src);
                findings.push(
                    Finding::new(
                        MetadataKind::PersonalIdentity,
                        part.to_owned(),
                        text.as_ref()
                            .map_or(0, |t| u64::try_from(t.value.len()).unwrap_or(u64::MAX)),
                    )
                    .with_field(format!("meta:user-defined ({name})"))
                    .with_value(options, || {
                        MetadataValue::Text(
                            text.as_ref()
                                .map(|t| t.value)
                                .unwrap_or_default()
                                .to_owned(),
                        )
                    }),
                );
            }
            name => {
                let Some((_, kind)) = lookup(&META_ELEMENTS, name) else {
                    continue;
                };
                let Some(text) = xml::element_text(&tags, index, src) else {
                    continue;
                };
                if text.value.trim().is_empty() {
                    continue;
                }
                findings.push(
                    Finding::new(
                        kind,
                        part.to_owned(),
                        u64::try_from(text.value.len()).unwrap_or(u64::MAX),
                    )
                    .with_field(name.to_owned())
                    .with_value(options, || MetadataValue::Text(text.value.to_owned())),
                );
            }
        }
    }
    findings
}

/// Report what `settings.xml` held, before the part is dropped.
///
/// One line per item that names something outside the document, plus one for the part as a
/// whole. Every real `settings.xml` holds several hundred items, nearly all of them window
/// geometry and integers, so listing them all would bury the two that matter.
pub(super) fn settings_findings(src: &str, part: &str, options: &InspectOptions) -> Vec<Finding> {
    let tags = xml::tags(src);
    let mut findings = Vec::new();
    let mut items = 0usize;

    for (index, tag) in tags.iter().enumerate() {
        if tag.name != "config:config-item" || tag.kind == Kind::Close {
            continue;
        }
        items = items.saturating_add(1);
        let Some(name) = tag.attribute("config:name") else {
            continue;
        };
        let Some((_, kind)) = lookup(&SENSITIVE_SETTINGS, name) else {
            continue;
        };
        let text = xml::element_text(&tags, index, src);
        findings.push(
            Finding::new(
                kind,
                part.to_owned(),
                text.as_ref()
                    .map_or(0, |t| u64::try_from(t.value.len()).unwrap_or(u64::MAX)),
            )
            .with_field(format!("config:config-item ({name})"))
            .with_value(options, || {
                MetadataValue::Text(
                    text.as_ref()
                        .map(|t| t.value)
                        .unwrap_or_default()
                        .to_owned(),
                )
            }),
        );
    }

    // The part goes whether or not any of its items is on the list above, so the report has to
    // say so whether or not any of them was.
    findings.push(
        Finding::new(
            MetadataKind::SoftwareFingerprint,
            part.to_owned(),
            u64::try_from(items).unwrap_or(u64::MAX),
        )
        .with_field("config:config-item".to_owned()),
    );
    findings
}

/// Remove `manifest:file-entry` elements pointing at parts that are no longer there.
///
/// Returns [`None`] when nothing referred to a removed part, so a manifest that did not need
/// changing keeps its original compressed bytes.
pub(super) fn drop_manifest_entries(src: &str, dropped: &BTreeSet<String>) -> Option<String> {
    xml::drop_tags(src, |tag: &Tag<'_>| {
        tag.name == "manifest:file-entry"
            && tag
                .attribute("manifest:full-path")
                .is_some_and(|path| dropped.contains(path.strip_prefix('/').unwrap_or(path)))
    })
}

/// Whether a manifest declares any entry as encrypted.
///
/// **The ZIP layer cannot see this.** An `OpenDocument` package does not use ZIP's own encryption
/// bit: it deflates an entry, encrypts the result, and records the fact in the manifest
/// (ODF 1.3 Part 2 §3.4). So the general-purpose-bit refusal in [`crate::container::zip`] —
/// which catches an encrypted Office document — passes an encrypted `OpenDocument` straight
/// through, whereupon `content.xml` is ciphertext, no rule matches it, and the document is
/// reported clean. That is `docs/THREAT_MODEL.md` §5.4 exactly, and this check is what stops it.
pub(super) fn declares_encryption(src: &str) -> bool {
    xml::tags(src)
        .iter()
        .any(|tag| tag.name == "manifest:encryption-data")
}

/// The media type a manifest declares for the package as a whole.
pub(super) fn root_media_type(src: &str) -> Option<String> {
    xml::tags(src).into_iter().find_map(|tag| {
        (tag.name == "manifest:file-entry" && tag.attribute("manifest:full-path") == Some("/"))
            .then(|| tag.attribute("manifest:media-type").map(str::to_owned))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn a_comment_loses_its_author_and_keeps_its_words() {
        let src = "<office:annotation><dc:creator>A Name</dc:creator>\
                   <dc:date>2021-03-04T05:06:07</dc:date>\
                   <text:p>PRESERVED-COMMENT-TEXT</text:p></office:annotation>";
        let scrubbed = scrub(src, "content.xml", &InspectOptions::names_only());
        let out = scrubbed.output.unwrap();
        assert!(!out.contains("A Name"));
        assert!(!out.contains("2021-03-04"));
        assert!(
            out.contains("PRESERVED-COMMENT-TEXT"),
            "the comment's words are the document's payload (PRD §8.1)"
        );
        assert!(
            out.contains("<dc:creator></dc:creator>"),
            "the element stays; only its value goes"
        );
        assert!(
            scrubbed
                .notes
                .iter()
                .any(|n| matches!(n, Note::OutOfScopeContent { .. })),
            "the comment that remains has to be declared, not left silent"
        );
    }

    #[test]
    fn a_tracked_change_loses_its_author_and_keeps_its_words() {
        let src = "<text:tracked-changes><text:changed-region><text:insertion>\
                   <office:change-info><dc:creator>A Name</dc:creator>\
                   <dc:date>2021-03-04T05:06:07</dc:date></office:change-info>\
                   </text:insertion></text:changed-region></text:tracked-changes>\
                   <text:p>PRESERVED-INSERTED-TEXT</text:p>";
        let out = scrub(src, "content.xml", &InspectOptions::names_only())
            .output
            .unwrap();
        assert!(!out.contains("A Name"));
        assert!(out.contains("PRESERVED-INSERTED-TEXT"));
        assert!(
            out.contains("<text:insertion>"),
            "the revision itself stays; only its attribution goes"
        );
    }

    #[test]
    fn dc_creator_outside_an_attribution_is_left_alone() {
        // The rule that made this module different from the Office one. `dc:creator` is the
        // element name ODF uses for a comment's author, a revision's author, *and* the document's
        // own — so a rule keyed on the name alone would fire on markup it has no business
        // touching.
        let src = "<text:p><dc:creator>NOT-AN-ATTRIBUTION</dc:creator></text:p>";
        assert!(
            scrub(src, "content.xml", &InspectOptions::names_only())
                .output
                .is_none()
        );
    }

    #[test]
    fn a_cached_author_field_loses_its_value_and_keeps_its_element() {
        // A `text:creator` field is not words the author typed — the application filled it in
        // from `meta.xml`. Leaving it would print the name strypt just reported removing.
        let src = "<text:p>By <text:creator>A Name</text:creator></text:p>";
        let out = scrub(src, "content.xml", &InspectOptions::names_only())
            .output
            .unwrap();
        assert_eq!(out, "<text:p>By <text:creator></text:creator></text:p>");
    }

    #[test]
    fn an_attribution_with_children_is_removed_entire_rather_than_left() {
        // The schema does not permit this and a hostile file is free to write it. Leaving the
        // element alone would mean a name surviving in a document reported as cleaned.
        let src = "<office:annotation><dc:creator><a>A Name</a></dc:creator></office:annotation>";
        let out = scrub(src, "content.xml", &InspectOptions::names_only())
            .output
            .unwrap();
        assert!(!out.contains("A Name"));
    }

    #[test]
    fn a_displayed_date_field_is_reported_rather_than_blanked() {
        // A date printed in a letter's header is a date the author chose to show.
        let src = "<text:p><text:creation-date>2021-03-04</text:creation-date></text:p>";
        let scrubbed = scrub(src, "content.xml", &InspectOptions::names_only());
        assert!(scrubbed.output.is_none(), "the visible date stays");
        assert!(
            scrubbed
                .notes
                .iter()
                .any(|n| matches!(n, Note::OutOfScopeContent { .. })),
            "and the user is told it is there"
        );
    }

    #[test]
    fn scrubbing_is_idempotent() {
        let src = "<office:annotation><dc:creator>A Name</dc:creator>\
                   <text:p>text</text:p></office:annotation>";
        let once = scrub(src, "content.xml", &InspectOptions::names_only())
            .output
            .unwrap();
        assert!(
            scrub(&once, "content.xml", &InspectOptions::names_only())
                .output
                .is_none(),
            "a second pass must find nothing, or verification would never converge"
        );
    }

    #[test]
    fn meta_reports_the_editing_statistics_odf_keeps_and_office_does_not() {
        let src = "<office:document-meta><office:meta>\
                   <meta:initial-creator>A Name</meta:initial-creator>\
                   <meta:editing-cycles>37</meta:editing-cycles>\
                   <meta:editing-duration>PT4H32M17S</meta:editing-duration>\
                   <meta:generator>LibreOffice/7.4$Linux_X86_64</meta:generator>\
                   <meta:document-statistic meta:page-count=\"3\" meta:word-count=\"412\"/>\
                   <meta:user-defined meta:name=\"MatterNumber\">A-1234</meta:user-defined>\
                   <meta:template xlink:href=\"file:///home/aname/t.ott\"/>\
                   </office:meta></office:document-meta>";
        let findings = meta_findings(src, "meta.xml", &InspectOptions::names_only());
        let fields: Vec<&str> = findings.iter().filter_map(|f| f.field.as_deref()).collect();
        for expected in [
            "meta:initial-creator",
            "meta:editing-cycles",
            "meta:editing-duration",
            "meta:generator",
            "meta:page-count",
            "meta:word-count",
            "meta:template xlink:href",
        ] {
            assert!(fields.contains(&expected), "{expected} was not reported");
        }
        assert!(
            fields.iter().any(|f| f.starts_with("meta:user-defined (")),
            "a user-defined property must be named, not counted"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == MetadataKind::EditingHistory),
            "editing-cycles and editing-duration are the pair ODF records and Office does not"
        );
    }

    #[test]
    fn settings_names_the_printer_and_counts_the_rest() {
        let src = "<office:settings><config:config-item-set config:name=\"ooo:view-settings\">\
                   <config:config-item config:name=\"PrinterName\" config:type=\"string\">\
                   A Printer</config:config-item>\
                   <config:config-item config:name=\"ViewAreaTop\" config:type=\"int\">0\
                   </config:config-item></config:config-item-set></office:settings>";
        let findings = settings_findings(src, "settings.xml", &InspectOptions::names_only());
        assert!(findings.iter().any(|f| f.field.as_deref()
            == Some("config:config-item (PrinterName)")
            && f.kind == MetadataKind::DeviceIdentity));
        assert!(
            findings
                .iter()
                .any(|f| f.field.as_deref() == Some("config:config-item")),
            "the part goes whole, so the report has to account for it whole"
        );
    }

    #[test]
    fn values_are_withheld_unless_the_caller_asks() {
        let src = "<office:meta><dc:creator>A Name</dc:creator></office:meta>";
        assert!(
            meta_findings(src, "meta.xml", &InspectOptions::names_only())
                .iter()
                .all(|f| f.value.is_none())
        );
        assert_eq!(
            meta_findings(src, "meta.xml", &InspectOptions::with_values())
                .iter()
                .find(|f| f.field.as_deref() == Some("dc:creator"))
                .and_then(|f| f.value.clone()),
            Some(MetadataValue::Text("A Name".to_owned()))
        );
    }

    #[test]
    fn an_encrypted_package_is_visible_in_the_manifest_where_zip_cannot_see_it() {
        let src = "<manifest:manifest><manifest:file-entry manifest:full-path=\"content.xml\">\
                   <manifest:encryption-data manifest:checksum=\"x\"/></manifest:file-entry>\
                   </manifest:manifest>";
        assert!(declares_encryption(src));
        assert!(!declares_encryption(
            "<manifest:manifest><manifest:file-entry manifest:full-path=\"content.xml\"/>\
             </manifest:manifest>"
        ));
    }

    #[test]
    fn the_manifest_names_the_package_and_loses_entries_for_removed_parts() {
        let src = "<manifest:manifest>\
                   <manifest:file-entry manifest:full-path=\"/\" \
                   manifest:media-type=\"application/vnd.oasis.opendocument.text\"/>\
                   <manifest:file-entry manifest:full-path=\"meta.xml\" \
                   manifest:media-type=\"text/xml\"/>\
                   <manifest:file-entry manifest:full-path=\"content.xml\" \
                   manifest:media-type=\"text/xml\"/></manifest:manifest>";
        assert_eq!(
            root_media_type(src).as_deref(),
            Some("application/vnd.oasis.opendocument.text")
        );
        let dropped: BTreeSet<String> = ["meta.xml".to_owned()].into_iter().collect();
        let out = drop_manifest_entries(src, &dropped).unwrap();
        assert!(!out.contains("meta.xml"));
        assert!(out.contains("content.xml"));
        assert!(drop_manifest_entries(src, &BTreeSet::new()).is_none());
    }

    #[test]
    fn arbitrary_text_does_not_panic_the_rules() {
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
            "<office:annotation>",
            "<dc:creator>",
            "<office:change-info><dc:creator>",
            "<meta:document-statistic",
            "</office:annotation>",
            "<<<<>>>>",
        ];
        for case in cases {
            let _ = scrub(case, "content.xml", &InspectOptions::names_only());
            let _ = meta_findings(case, "meta.xml", &InspectOptions::with_values());
            let _ = settings_findings(case, "settings.xml", &InspectOptions::with_values());
            let _ = drop_manifest_entries(case, &BTreeSet::new());
            let _ = declares_encryption(case);
            let _ = root_media_type(case);
        }
    }

    #[test]
    fn every_prefix_of_a_real_part_is_survivable() {
        let src = "<?xml version=\"1.0\"?><office:document-content>\
                   <office:body><text:p><office:annotation><dc:creator>A</dc:creator>\
                   <text:p>x</text:p></office:annotation></text:p></office:body>\
                   </office:document-content>";
        for n in 0..=src.len() {
            let prefix = src.get(0..n).unwrap_or_default();
            let _ = scrub(prefix, "content.xml", &InspectOptions::names_only());
        }
    }
}
