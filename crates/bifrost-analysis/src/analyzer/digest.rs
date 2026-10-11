use sha2::{Digest, Sha256};

pub(crate) fn new_length_delimited_sha256(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    update_length_delimited_sha256(&mut hasher, domain);
    hasher
}

pub(crate) fn update_length_delimited_sha256(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("length-delimited digest input fits in u64");
    hasher.update(length.to_le_bytes());
    hasher.update(value);
}
