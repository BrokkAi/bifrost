use crate::analyzer::{ProjectFile, Range};
use std::env;

#[doc(hidden)]
pub fn file(name: &str) -> ProjectFile {
    ProjectFile::new(env::temp_dir().join("bifrost-signature-help"), name)
}

#[doc(hidden)]
pub fn byte_range(source: &str, needle: &str) -> Range {
    crate::analyzer::usages::test_support::byte_range(source, needle)
}
