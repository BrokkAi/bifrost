//! Bifrost-curated semantic-pack distribution support.
//!
//! Generic pack artifacts and analyzer integration remain in
//! `brokk-bifrost-analysis`. Release-only bundle tooling is opt-in so ordinary
//! analyzer consumers do not compile packaging dependencies.

#[cfg(feature = "release-tooling")]
pub mod release_bundle;
