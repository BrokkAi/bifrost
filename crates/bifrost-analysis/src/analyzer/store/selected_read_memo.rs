//! Query- or stage-scoped storage for exact relational read answers.
//!
//! The caller owns the memo lifetime and supplies every bound query parameter
//! as the key. This helper adds no cache policy or lifetime of its own.

use std::hash::Hash;

use crate::hash::HashMap;

pub(crate) struct ExactReadMemo<K: Eq + Hash, V> {
    entries: HashMap<K, V>,
}

impl<K: Eq + Hash, V> Default for ExactReadMemo<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

impl<K: Eq + Hash, V> ExactReadMemo<K, V> {
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.entries.insert(key, value)
    }
}
