//! npm version semantics, independent of dependency acquisition and query syntax.
//!
//! Parse a range once per request and apply it to each recorded exact version.
//! Package, source, locator and owner selection belong to the existing evidence
//! consumer. A manifest range is never evidence of a resolved exact version.

use std::fmt;

/// Maximum range input in bytes, bounding parser work and retained request data.
pub const MAX_NPM_RANGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmVersionError {
    RangeTooLong,
    InvalidRange(js_semver::SemverError),
    InvalidExactVersion(js_semver::SemverError),
}

impl fmt::Display for NpmVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RangeTooLong => write!(f, "npm range exceeds {MAX_NPM_RANGE_BYTES} bytes"),
            Self::InvalidRange(error) => write!(f, "unsupported or invalid npm range: {error}"),
            Self::InvalidExactVersion(error) => write!(f, "invalid exact npm version: {error}"),
        }
    }
}

impl std::error::Error for NpmVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RangeTooLong => None,
            Self::InvalidRange(error) | Self::InvalidExactVersion(error) => Some(error),
        }
    }
}

/// Request-scoped npm comparator sets with npm's default prerelease exclusion.
///
/// The maintained parser owns comparator, union, caret, tilde, partial, wildcard
/// and hyphen syntax, including its supported whitespace and `v` normalization.
/// Tags, aliases and source references are not resolved or coerced here.
#[derive(Debug, Clone)]
pub struct NpmVersionRange(js_semver::Range);

impl NpmVersionRange {
    pub fn parse(requirement: &str) -> Result<Self, NpmVersionError> {
        if requirement.len() > MAX_NPM_RANGE_BYTES {
            return Err(NpmVersionError::RangeTooLong);
        }
        js_semver::Range::parse(requirement)
            .map(Self)
            .map_err(NpmVersionError::InvalidRange)
    }

    /// Compare a full recorded version. Partial versions and arbitrary references
    /// fail parsing; they are never padded or converted into semver versions.
    pub fn matches_exact(&self, version: &str) -> Result<bool, NpmVersionError> {
        let version =
            js_semver::Version::parse(version).map_err(NpmVersionError::InvalidExactVersion)?;
        Ok(self.0.satisfies(&version))
    }
}

/// Normalize only full versions accepted by the maintained npm parser.
/// Prerelease and build metadata survive normalization; source references do not.
pub fn normalize_exact_npm_version(version: &str) -> Result<String, NpmVersionError> {
    js_semver::Version::parse(version)
        .map(|version| version.to_string())
        .map_err(NpmVersionError::InvalidExactVersion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_comparator_and_prerelease_contract() {
        let range = NpmVersionRange::parse(">=1.2.3 <1.3.0 || ^2.0.0").unwrap();
        assert!(range.matches_exact("v1.2.4").unwrap());
        assert!(!range.matches_exact("1.3.0").unwrap());
        assert!(!range.matches_exact("2.1.0-beta.1").unwrap());
        assert!(range.matches_exact("2.1.0+build.1").unwrap());
        assert!(range.matches_exact("workspace:1.2.4").is_err());
        assert!(NpmVersionRange::parse("^1.2.3 || latest").is_err());
    }
}
