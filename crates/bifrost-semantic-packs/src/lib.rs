//! Distribution lifecycle for externally released semantic packs.
//!
//! Generic pack artifacts, catalogs, activation, and analyzer overlays remain in
//! `brokk-bifrost-analysis`. This downstream crate owns acquisition, release
//! bundle installation, and authoring tooling. The engine ships no pack content
//! (#4438); hosts install a released packs bundle.

#[cfg(feature = "download")]
pub mod download;
#[cfg(any(feature = "release-tooling", feature = "download"))]
pub mod release_bundle;
#[cfg(feature = "release-tooling")]
pub mod summary_foundry;

#[cfg(test)]
use brokk_bifrost_tools as _;
#[cfg(any(feature = "download", feature = "release-tooling"))]
use std::fmt::{self, Formatter};

#[cfg(any(feature = "download", feature = "release-tooling"))]
pub(crate) fn fmt_string_error(message: &str, formatter: &mut Formatter<'_>) -> fmt::Result {
    formatter.write_str(message)
}

#[cfg(test)]
#[path = "../../../test-support/zip.rs"]
mod zip_test_support;
