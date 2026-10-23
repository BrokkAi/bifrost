use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;
pub use brokk_bifrost_semantic::analyzer::semantic::read_ledger::*;
const READ_SET_DOMAIN: &[u8] = b"bifrost-read-ledger:set:v1";
/// The digest of one complete read set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadSetDigest(StableDigest);
impl ReadSetDigest {
    pub const fn from_digest(digest: StableDigest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> StableDigest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
impl std::fmt::Display for ReadSetDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
/// The digest of one read set held as a slice rather than as a live ledger.
///
/// A verifier holds a published unit's keys, not the ledger that recorded
/// them, and still has to name the unit by what it read; a persisted row does
/// the same. Sorting here rather than trusting the caller's order is what
/// makes the two digests equal.
pub fn read_set_digest(keys: &[ReadKey]) -> ReadSetDigest {
    let mut sorted = keys.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut hasher = CanonicalHasher::new(READ_SET_DOMAIN);
    hasher.value(
        &u64::try_from(sorted.len())
            .expect("usize fits u64 on supported targets")
            .to_be_bytes(),
    );
    for key in &sorted {
        key.push_canonical(&mut hasher);
    }
    ReadSetDigest::from_digest(StableDigest::from_array(hasher.finish()))
}
