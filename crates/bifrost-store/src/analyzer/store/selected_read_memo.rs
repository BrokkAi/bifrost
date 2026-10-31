//! Query- or stage-scoped storage for exact relational read answers.
//!
//! The caller owns the memo lifetime and supplies every bound query parameter
//! as the key. This helper adds no cache policy or lifetime of its own.

use std::hash::Hash;

use crate::hash::HashMap;

pub(crate) struct ExactReadMemo<K: Eq + Hash, V> {
    entries: HashMap<K, V>,
    #[cfg(any(test, feature = "test-support"))]
    bounded_fills: usize,
    #[cfg(any(test, feature = "test-support"))]
    refused_admissions: usize,
}

impl<K: Eq + Hash, V> Default for ExactReadMemo<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
            #[cfg(any(test, feature = "test-support"))]
            bounded_fills: 0,
            #[cfg(any(test, feature = "test-support"))]
            refused_admissions: 0,
        }
    }
}

impl<K: Eq + Hash, V> ExactReadMemo<K, V> {
    pub(crate) fn insert_bounded(&mut self, key: K, value: V) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        {
            self.bounded_fills += 1;
        }
        if self.entries.len() >= 8192 {
            #[cfg(any(test, feature = "test-support"))]
            {
                self.refused_admissions += 1;
            }
            return false;
        }
        self.entries.insert(key, value);
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn bounded_counts(&self) -> (usize, usize) {
        (self.bounded_fills, self.refused_admissions)
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.entries.insert(key, value)
    }
}

/// The one insert-stop bound for disposable request caches, including
/// placement_access's memos. Past it, reads continue uncached.
pub(crate) const REQUEST_READ_CACHE_ENTRY_CAP: usize = 65_536;

/// Disposable rows for one selected request. Refusing admission never refuses
/// a read: callers return the computed value and reread SQL on the next miss.
/// Authoritative preparations must continue to use ExactReadMemo instead.
pub(crate) struct RequestReadCache<K: Eq + Hash, V> {
    entries: HashMap<K, V>,
}

impl<K: Eq + Hash, V> Default for RequestReadCache<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

impl<K: Eq + Hash, V> RequestReadCache<K, V> {
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.entries.len() >= REQUEST_READ_CACHE_ENTRY_CAP {
            return None;
        }
        self.entries.insert(key, value)
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::ExactReadMemo;

    #[test]
    fn bounded_admission_preserves_old_rows_and_counts_refusals() {
        let mut memo = ExactReadMemo::default();
        for key in 0..8192 {
            assert!(memo.insert_bounded(key, key));
        }
        assert!(!memo.insert_bounded(8192, 8192));
        assert_eq!(memo.get(&0), Some(&0));
        assert_eq!(memo.get(&8192), None);
        assert_eq!(memo.bounded_counts(), (8193, 1));
    }
}
