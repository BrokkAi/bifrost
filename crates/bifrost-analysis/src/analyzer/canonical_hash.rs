//! Shared deterministic hashing primitives for analyzer-owned identities.

use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) struct CanonicalHasher(Sha256);

impl CanonicalHasher {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.value(domain);
        hasher
    }

    pub(crate) fn field(&mut self, name: &str, value: &[u8]) {
        self.value(name.as_bytes());
        self.value(value);
    }

    pub(crate) fn value(&mut self, value: &[u8]) {
        let length = u64::try_from(value.len()).expect("usize fits u64 on supported targets");
        self.0.update(length.to_be_bytes());
        self.0.update(value);
    }

    pub(crate) fn sequence<T>(
        &mut self,
        name: &str,
        values: &[T],
        mut update: impl FnMut(&mut Self, &T),
    ) {
        self.value(name.as_bytes());
        self.value(
            &u64::try_from(values.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for value in values {
            update(self, value);
        }
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

pub(crate) fn hash_domain_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    hasher.value(bytes);
    hasher.finish()
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn lower_hex_string(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn write_lower_hex(bytes: &[u8; 32], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
