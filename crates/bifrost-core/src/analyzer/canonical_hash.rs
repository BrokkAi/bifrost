//! Shared deterministic hashing primitives for analyzer-owned identities.

use sha2::{Digest, Sha256};
use std::fmt;

pub struct CanonicalHasher(Sha256);

pub fn finish_sha256(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

/// Append a byte slice as a big-endian `u64` length followed by its bytes.
pub fn write_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("usize fits u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

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
        write_length_prefixed(&mut self.0, value);
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
        finish_sha256(self.0)
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
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = (lower_hex_nibble(pair[0])? << 4) | lower_hex_nibble(pair[1])?;
    }
    Some(digest)
}

pub fn lower_hex_nibble(byte: u8) -> Option<u8> {
    if byte.is_ascii_uppercase() {
        None
    } else {
        crate::path_utils::hex_value(byte)
    }
}

pub fn write_lower_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod canonical_hash_properties {
    use super::*;
    use proptest::prelude::*;

    /// Renders bytes through `write_lower_hex` via a `Display` wrapper.
    struct LowerHex<'a>(&'a [u8]);

    impl fmt::Display for LowerHex<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_lower_hex(self.0, formatter)
        }
    }

    /// Independent reference rendering: a lookup table, no `format!`.
    fn reference_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::new();
        for byte in bytes {
            output.push(DIGITS[usize::from(byte >> 4)] as char);
            output.push(DIGITS[usize::from(byte & 0x0f)] as char);
        }
        output
    }

    /// Independent reference for the documented framing: every value is a
    /// big-endian `u64` byte length followed by the bytes, a field is its name
    /// then its value, and a sequence is its name, then the 8-byte big-endian
    /// item count, then its items. Built on raw `Sha256`, not on
    /// `CanonicalHasher` or `write_length_prefixed`.
    fn reference_framed_digest(
        domain: &[u8],
        fields: &[(String, Vec<u8>)],
        sequence_name: &str,
        items: &[Vec<u8>],
        trailing_value: &[u8],
    ) -> [u8; 32] {
        fn framed(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        let mut hasher = Sha256::new();
        framed(&mut hasher, domain);
        for (name, value) in fields {
            framed(&mut hasher, name.as_bytes());
            framed(&mut hasher, value);
        }
        framed(&mut hasher, sequence_name.as_bytes());
        framed(&mut hasher, &(items.len() as u64).to_be_bytes());
        for item in items {
            framed(&mut hasher, item);
        }
        framed(&mut hasher, trailing_value);
        hasher.finalize().into()
    }

    fn canonical_digest(
        domain: &[u8],
        fields: &[(String, Vec<u8>)],
        sequence_name: &str,
        items: &[Vec<u8>],
        trailing_value: &[u8],
    ) -> [u8; 32] {
        let mut hasher = CanonicalHasher::new(domain);
        for (name, value) in fields {
            hasher.field(name, value);
        }
        hasher.sequence(sequence_name, items, |hasher, item| hasher.value(item));
        hasher.value(trailing_value);
        hasher.finish()
    }

    /// Canonical digests become persisted identities, so the framing is
    /// pinned to fixed values. The literal digests were computed outside
    /// Rust (Python `hashlib.sha256` over the same framing); a change here
    /// rotates every stored identity and needs a version bump instead.
    #[test]
    fn canonical_hasher_matches_known_answer_vectors() {
        assert_eq!(
            lower_hex_string(&hash_domain_bytes(b"d", b"v")),
            "d34124f6f9e01758257731fd687ee99a80c419e3a995a3da132b042f322712c3"
        );

        let fields = [("name".to_string(), b"val".to_vec())];
        let items = [b"x".to_vec(), b"yz".to_vec()];
        let expected = "4367b2d497c6f7ed63e26e6224021fe611e886457321916d2aa25f79f85169e6";
        assert_eq!(
            lower_hex_string(&reference_framed_digest(
                b"dom", &fields, "items", &items, b""
            )),
            expected
        );
        assert_eq!(
            lower_hex_string(&canonical_digest(b"dom", &fields, "items", &items, b"")),
            expected
        );
    }

    #[test]
    fn sha256_bytes_matches_fips_180_vectors() {
        assert_eq!(
            lower_hex_string(&sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            lower_hex_string(&sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            lower_hex_string(&sha256_bytes(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn is_lower_sha256_rejects_tricky_shapes() {
        let valid = "0123456789abcdef".repeat(4);
        assert!(is_lower_sha256(&valid));
        assert!(!is_lower_sha256(&valid.to_uppercase()));
        // Mixed case: one uppercase digit in an otherwise valid string.
        assert!(!is_lower_sha256(&format!("A{}", &valid[1..])));
        assert!(!is_lower_sha256(&valid[1..]));
        assert!(!is_lower_sha256(&format!("{valid}0")));
        assert!(!is_lower_sha256(""));
        // 'g' is the first character past 'f'; '`' and '/' flank the ranges.
        for bad in ['g', '`', '/', ':', '@', ' ', '-'] {
            assert!(!is_lower_sha256(&format!("{bad}{}", &valid[1..])), "{bad}");
        }
        // Two-byte UTF-8 characters: 32 of them are 64 bytes long.
        let multibyte = "\u{e9}".repeat(32);
        assert_eq!(multibyte.len(), 64);
        assert!(!is_lower_sha256(&multibyte));
        assert_eq!(parse_lower_sha256(&multibyte), None);
    }

    #[test]
    fn lower_hex_nibble_accepts_exactly_lowercase_hex_digits() {
        for byte in 0..=u8::MAX {
            let expected = match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            assert_eq!(lower_hex_nibble(byte), expected, "byte {byte:#04x}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn sha256_bytes_matches_chunked_digest(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            split in 0_usize..512,
        ) {
            let split = split.min(bytes.len());
            let mut hasher = Sha256::new();
            hasher.update(&bytes[..split]);
            hasher.update(&bytes[split..]);
            prop_assert_eq!(sha256_bytes(&bytes), finish_sha256(hasher));
        }

        #[test]
        fn canonical_hasher_matches_reference_framing(
            domain in proptest::collection::vec(any::<u8>(), 0..24),
            fields in proptest::collection::vec(
                ("[a-z_]{0,8}", proptest::collection::vec(any::<u8>(), 0..24)),
                0..4,
            ),
            sequence_name in "[a-z_]{0,8}",
            items in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..12), 0..4),
            trailing_value in proptest::collection::vec(any::<u8>(), 0..12),
        ) {
            prop_assert_eq!(
                canonical_digest(&domain, &fields, &sequence_name, &items, &trailing_value),
                reference_framed_digest(&domain, &fields, &sequence_name, &items, &trailing_value)
            );
        }

        #[test]
        fn write_lower_hex_matches_table_rendering(
            bytes in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let rendered = LowerHex(&bytes).to_string();
            prop_assert_eq!(rendered.len(), bytes.len() * 2);
            prop_assert_eq!(rendered, reference_hex(&bytes));
        }

        #[test]
        fn parse_inverts_write_lower_hex(bytes in any::<[u8; 32]>()) {
            let rendered = LowerHex(&bytes).to_string();
            prop_assert!(is_lower_sha256(&rendered));
            prop_assert_eq!(parse_lower_sha256(&rendered), Some(bytes));
            prop_assert_eq!(rendered, lower_hex_string(&bytes));
        }

        #[test]
        fn is_lower_sha256_agrees_with_brute_force_shape(value in "\\PC{0,70}") {
            let expected = value.chars().count() == 64
                && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
            prop_assert_eq!(is_lower_sha256(&value), expected);
            prop_assert_eq!(parse_lower_sha256(&value).is_some(), expected);
        }

        #[test]
        fn parse_lower_sha256_accepts_every_lowercase_hex_string(
            value in "[0-9a-f]{64}",
        ) {
            let digest = parse_lower_sha256(&value).expect("64 lowercase hex chars parse");
            prop_assert_eq!(reference_hex(&digest), value);
        }

        #[test]
        fn parse_lower_sha256_rejects_single_corrupted_position(
            bytes in any::<[u8; 32]>(),
            position in 0_usize..64,
            replacement in prop_oneof![
                Just(b'A'), Just(b'F'), Just(b'g'), Just(b'z'), Just(b' '), Just(b'-'),
            ],
        ) {
            let mut rendered = lower_hex_string(&bytes).into_bytes();
            rendered[position] = replacement;
            let corrupted = String::from_utf8(rendered).expect("ASCII");
            prop_assert_eq!(parse_lower_sha256(&corrupted), None);
        }
    }
}
