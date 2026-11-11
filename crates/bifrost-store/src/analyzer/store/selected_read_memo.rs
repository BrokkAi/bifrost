//! Query- or stage-scoped storage for exact relational read answers.
//!
//! The caller owns the memo lifetime and supplies every bound query parameter
//! as the key. This helper adds no cache policy or lifetime of its own.

use std::hash::Hash;

use crate::hash::HashMap;

/// Bounded admission stops at this many entries or at this many estimated
/// bytes, whichever comes first. Past either bound, reads continue uncached.
const EXACT_READ_MEMO_ENTRY_CAP: usize = 8192;
const EXACT_READ_MEMO_BYTE_CAP: usize = 16 * 1024 * 1024;

/// Shared weighed admission for request-lifetime exact read memos.
pub(crate) struct ExactReadByteBudget {
    cap: usize,
    used: usize,
}

impl Default for ExactReadByteBudget {
    fn default() -> Self {
        Self::new(EXACT_READ_MEMO_BYTE_CAP)
    }
}

impl ExactReadByteBudget {
    fn new(cap: usize) -> Self {
        Self { cap, used: 0 }
    }

    pub(crate) fn admit(&mut self, bytes: usize) -> bool {
        if self.used.saturating_add(bytes) > self.cap {
            return false;
        }
        self.used += bytes;
        true
    }

    pub(crate) fn clear(&mut self) {
        self.used = 0;
    }

    pub(crate) fn release(&mut self, bytes: usize) {
        assert!(bytes <= self.used, "removed entry exceeds admitted bytes");
        self.used -= bytes;
    }
}

pub(crate) struct ExactReadMemo<K: Eq + Hash, V> {
    entries: HashMap<K, V>,
    entry_cap: usize,
    budget: ExactReadByteBudget,
    #[cfg(any(test, feature = "test-support"))]
    bounded_fills: usize,
    #[cfg(any(test, feature = "test-support"))]
    refused_admissions: usize,
}

impl<K: Eq + Hash, V> Default for ExactReadMemo<K, V> {
    fn default() -> Self {
        Self::with_caps(EXACT_READ_MEMO_ENTRY_CAP, EXACT_READ_MEMO_BYTE_CAP)
    }
}

impl<K: Eq + Hash, V> ExactReadMemo<K, V> {
    /// A memo whose bounded admission stops at the given caps instead of the
    /// shared defaults.
    pub(crate) fn with_caps(entry_cap: usize, byte_cap: usize) -> Self {
        Self {
            entries: HashMap::default(),
            entry_cap,
            budget: ExactReadByteBudget::new(byte_cap),
            #[cfg(any(test, feature = "test-support"))]
            bounded_fills: 0,
            #[cfg(any(test, feature = "test-support"))]
            refused_admissions: 0,
        }
    }

    /// An empty memo with this memo's caps, for values staged to join it.
    pub(crate) fn empty_with_same_caps(&self) -> Self {
        Self::with_caps(self.entry_cap, self.budget.cap)
    }

    pub(crate) fn insert_bounded(&mut self, key: K, value: V) -> bool {
        self.insert_bounded_weighed(key, value, 0)
    }

    /// `insert_bounded` for values whose size varies widely: `bytes` is the
    /// caller's estimate of the value's heap size, charged against the byte cap.
    pub(crate) fn insert_bounded_weighed(&mut self, key: K, value: V, bytes: usize) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        {
            self.bounded_fills += 1;
        }
        if self.entries.len() >= self.entry_cap || !self.budget.admit(bytes) {
            #[cfg(any(test, feature = "test-support"))]
            {
                self.refused_admissions += 1;
            }
            return false;
        }
        self.entries.insert(key, value);
        true
    }

    /// Remove an entry admitted by `insert_bounded_weighed`, returning its
    /// `bytes` charge to the byte cap. The caller passes the same estimate it
    /// charged at admission.
    pub(crate) fn remove_weighed(&mut self, key: &K, bytes: usize) -> Option<V> {
        let value = self.entries.remove(key)?;
        self.budget.release(bytes);
        Some(value)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn weighed_bytes(&self) -> usize {
        self.budget.used
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

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter()
    }

    pub(crate) fn into_entries(self) -> impl Iterator<Item = (K, V)> {
        self.entries.into_iter()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
