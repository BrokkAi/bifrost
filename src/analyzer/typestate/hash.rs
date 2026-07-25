use std::fmt;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

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
        let mut hasher = Sha256::new();
        update_value(&mut hasher, TYPESTATE_PROTOCOL_DOMAIN);
        update_value(&mut hasher, bytes);
        Self(hasher.finalize().into())
    }
}

fn update_value(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("usize fits u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

impl fmt::Display for TypestateProtocolHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
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
