use std::fmt;

use serde::{Serialize, Serializer};

use crate::analyzer::canonical_hash::{hash_domain_bytes, write_lower_hex};

const TYPESTATE_PROTOCOL_DOMAIN: &[u8] = b"bifrost-typestate-protocol/v1";

/// Canonical identity of one compiled internal finite-state protocol.
///
/// The digest excludes policy presentation, language, selected program
/// bindings, and run-local dense IDs.  It is safe to use in downstream
/// protocol-summary and policy-projection keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypestateProtocolHash([u8; 32]);

impl TypestateProtocolHash {
    /// Wrap a digest already produced by the owning protocol compiler.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hash canonical protocol bytes under the schema-version-1 domain.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(hash_domain_bytes(TYPESTATE_PROTOCOL_DOMAIN, bytes))
    }
}

impl fmt::Display for TypestateProtocolHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, formatter)
    }
}

impl Serialize for TypestateProtocolHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}
