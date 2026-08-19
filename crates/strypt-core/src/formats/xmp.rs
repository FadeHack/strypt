//! XMP packets, wherever they are embedded.
//!
//! XMP is an RDF/XML document that Adobe's tooling — and by now most other tooling — writes
//! into PDFs, JPEGs, PNGs, and WebP files alike. It routinely carries a fuller record than the
//! format's own metadata slot does: `xmpMM:History` is a log of every save, with the tool and
//! timestamp for each, and `xmpMM:DocumentID` links every copy and every revision of one
//! document to each other.
//!
//! Shared by every handler, because the packet is the same wherever it is found and there is
//! no reason for two handlers to disagree about what is in one.
//!
//! # Why this is a substring scan rather than an XML parse
//!
//! The packet is removed whole, so nothing here decides what goes — this only decides how the
//! report reads. A real XML parser would buy slightly better field names in exchange for a new
//! dependency with an entity-expansion attack surface, on data supplied by the file, for no
//! gain in what is removed. That trade is not worth making (ADR-0008); the packet is found,
//! reported, and removed identically either way.

use crate::report::{Finding, InspectOptions, MetadataKind, MetadataValue};

/// XMP properties worth naming individually in a report.
pub(crate) const PROPERTIES: &[(&[u8], MetadataKind)] = &[
    (b"dc:creator", MetadataKind::PersonalIdentity),
    (b"dc:title", MetadataKind::Comment),
    (b"dc:description", MetadataKind::Comment),
    (b"dc:subject", MetadataKind::Comment),
    (b"xmp:CreatorTool", MetadataKind::SoftwareFingerprint),
    (b"xmp:CreateDate", MetadataKind::Timestamp),
    (b"xmp:ModifyDate", MetadataKind::Timestamp),
    (b"xmp:MetadataDate", MetadataKind::Timestamp),
    (b"xmpMM:DocumentID", MetadataKind::DocumentIdentifier),
    (b"xmpMM:InstanceID", MetadataKind::DocumentIdentifier),
    (
        b"xmpMM:OriginalDocumentID",
        MetadataKind::DocumentIdentifier,
    ),
    (b"xmpMM:History", MetadataKind::EditingHistory),
    (b"pdf:Producer", MetadataKind::SoftwareFingerprint),
    (b"photoshop:", MetadataKind::SoftwareFingerprint),
    (b"exif:GPS", MetadataKind::Location),
    (b"tiff:Make", MetadataKind::DeviceIdentity),
    (b"tiff:Model", MetadataKind::DeviceIdentity),
];

/// Name the properties in `packet`, reporting them under `location`.
///
/// A packet in which nothing recognisable appears still yields one finding: something is
/// there, it is going, and the user is told so. Silence would read as "no metadata here".
pub(crate) fn scan(packet: &[u8], location: &str, options: &InspectOptions) -> Vec<Finding> {
    let mut out = Vec::new();
    for (property, kind) in PROPERTIES {
        if contains(packet, property) {
            out.push(
                Finding::new(*kind, location.to_owned(), 0)
                    .with_field(name_of(property))
                    .with_value(options, || MetadataValue::Opaque {
                        bytes: as_u64(property.len()),
                    }),
            );
        }
    }
    if out.is_empty() {
        out.push(
            Finding::new(
                MetadataKind::Other,
                location.to_owned(),
                as_u64(packet.len()),
            )
            .with_field("Metadata"),
        );
    }
    out
}

/// True when `haystack` contains `needle`.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A property name as text, with anything non-UTF-8 or control replaced.
///
/// Lossy on purpose: the name is shown to a user, and nothing here should be able to emit a
/// control sequence into a terminal.
pub(crate) fn name_of(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_control())
        .collect()
}

/// Widen a length for reporting. Saturating: a report field is not worth failing a strip over.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn known_properties_are_named_individually() {
        let packet = br#"<x:xmpmeta><rdf:RDF><rdf:Description
            xmpMM:DocumentID="uuid:0001" xmp:CreatorTool="SYNTHETIC"/></rdf:RDF></x:xmpmeta>"#;
        let found = scan(packet, "APP1 (XMP)", &InspectOptions::names_only());
        let fields: Vec<_> = found.iter().filter_map(|f| f.field.as_deref()).collect();
        assert!(fields.contains(&"xmpMM:DocumentID"));
        assert!(fields.contains(&"xmp:CreatorTool"));
    }

    #[test]
    fn an_unrecognised_packet_is_still_reported() {
        let found = scan(
            b"<x:xmpmeta><rdf:RDF/></x:xmpmeta>",
            "XMP packet",
            &InspectOptions::names_only(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, MetadataKind::Other);
    }
}
