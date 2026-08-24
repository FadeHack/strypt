//! Container formats that other formats are stored inside.
//!
//! Not a format handler and never reached by dispatch: nothing here implements
//! [`crate::formats::MetadataHandler`], and a bare `.zip` handed to strypt is still refused as
//! unsupported. These modules are machinery that format handlers share, in the same way
//! [`crate::formats::exif`] and [`crate::formats::xmp`] are shared readers rather than formats
//! in their own right.
//!
//! The distinction matters for one reason: a container is *not* a thing the user asked to have
//! cleaned. It is a thing standing between strypt and what the user asked to have cleaned, and
//! the code here exists to get through it safely rather than to be a faithful implementation of
//! it (ADR-0028).

pub(crate) mod package;
pub(crate) mod zip;
