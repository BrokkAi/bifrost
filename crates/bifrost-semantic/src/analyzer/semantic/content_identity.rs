use crate::analyzer::semantic::ids::StableDigest;
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use std::fmt;

/// The content identity of one analyzed-file scope.
///
/// This type is public only because [`crate::analyzer::IAnalyzer`] is an
/// extension boundary; it is an opaque comparison token with no accessible
/// structure beyond its digest.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceContentIdentity {
    #[doc(hidden)]
    pub digest: StableDigest,
}

impl WorkspaceContentIdentity {
    #[doc(hidden)]
    pub const fn from_digest(digest: StableDigest) -> Self {
        Self { digest }
    }

    #[doc(hidden)]
    pub const fn digest(self) -> StableDigest {
        self.digest
    }

    /// Stable digest bytes for an exact derived-value persistence key.
    #[doc(hidden)]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }

    /// The stand-in identity used when a cache has to name an artifact whose
    /// content identity the analyzer could not state.
    ///
    /// It is a digest of a fixed domain string, so it names "no evidence" and
    /// can never be produced by an analyzed file set. It exists only so that
    /// `InvalidationReason::ContentIdentityEvidenceMissing`
    /// can carry a well-formed artifact identity; nothing is ever keyed by it.
    #[doc(hidden)]
    pub fn unattested() -> Self {
        Self::from_digest(StableDigest::sha256(
            b"bifrost-workspace-content:unattested:v1",
        ))
    }

    /// A synthetic identity for tests that exercise cache mechanics without an
    /// analyzer behind them.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn for_test(seed: u64) -> Self {
        let mut hasher = CanonicalHasher::new(b"bifrost-workspace-content:test:v1");
        hasher.value(&seed.to_be_bytes());
        Self::from_digest(StableDigest::from_array(hasher.finish()))
    }
}

impl fmt::Display for WorkspaceContentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.digest.fmt(formatter)
    }
}
