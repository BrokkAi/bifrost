//! Shared deterministic hashing primitives for analyzer-owned identities.

use sha2::{Digest, Sha256};
use std::fmt;

pub struct CanonicalHasher(Sha256);

impl CanonicalHasher {
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.value(domain);
        hasher
    }

    pub fn field(&mut self, name: &str, value: &[u8]) {
        self.value(name.as_bytes());
        self.value(value);
    }

    pub fn value(&mut self, value: &[u8]) {
        let length = u64::try_from(value.len()).expect("usize fits u64 on supported targets");
        self.0.update(length.to_be_bytes());
        self.0.update(value);
    }

    pub fn sequence<T>(&mut self, name: &str, values: &[T], mut update: impl FnMut(&mut Self, &T)) {
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

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

pub fn hash_domain_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    hasher.value(bytes);
    hasher.finish()
}

pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn lower_hex_string(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn parse_lower_sha256(value: &str) -> Option<[u8; 32]> {
    if !is_lower_sha256(value) {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    Some(digest)
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn write_lower_hex(bytes: &[u8; 32], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
