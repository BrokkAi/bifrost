//! Fast hash collections for repository-local analysis data.
//!
//! Bifrost analyzes trusted local repositories, not attacker-controlled request
//! keys, so the standard library's SipHash-based default is the wrong tradeoff
//! for hot analyzer indexes. Use these aliases for internal maps and sets.
//! Hash iteration order is intentionally unspecified; deterministic output must
//! be produced with `BTree*` collections or explicit sorting at boundaries.

pub type HashMap<K, V> = std::collections::HashMap<K, V, rustc_hash::FxBuildHasher>;
pub type HashSet<T> = std::collections::HashSet<T, rustc_hash::FxBuildHasher>;
