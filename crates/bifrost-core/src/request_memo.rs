//! Private request memos under an existing retention owner.
use crate::retention_budget::{BudgetRegion, BudgetedValue, RetainedBytes, RetentionBudget};
use std::{cell::Cell, hash::Hash};

/// P-class memo: refusal returns the complete request-owned answer; eviction
/// permits recomputation. Each instance has a fresh namespace and releases its
/// residents on every exit, including unwinding.
pub struct RequestMemo<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    region: BudgetRegion<K, V>,
    filled: Cell<bool>,
}
impl<K, V> std::fmt::Debug for RequestMemo<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestMemo")
            .field("name", &self.region.name())
            .finish()
    }
}
impl<K, V> RequestMemo<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    pub fn new(owner: &RetentionBudget, name: &'static str) -> Self {
        Self {
            region: owner.region(name, None),
            filled: Cell::new(false),
        }
    }
    /// Whether no insertion has been attempted, even if entries were refused.
    pub fn is_unused(&self) -> bool {
        !self.filled.get()
    }
    pub fn get(&self, key: &K) -> Option<BudgetedValue<V>> {
        self.region.get(key).map(BudgetedValue::Retained)
    }
    pub fn insert(&self, key: K, value: V) -> BudgetedValue<V> {
        self.filled.set(true);
        self.region.insert(key, value)
    }
    pub fn get_or_insert_with(&self, key: K, build: impl FnOnce() -> V) -> BudgetedValue<V> {
        self.get(&key).unwrap_or_else(|| self.insert(key, build()))
    }
}
impl<K, V> Drop for RequestMemo<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + RetainedBytes + 'static,
    V: Send + Sync + RetainedBytes + 'static,
{
    fn drop(&mut self) {
        self.region.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_memo_reuses_or_recomputes_complete_values() {
        for (capacity, expected_builds) in [(1_000_000, 1), (1, 2)] {
            let owner = RetentionBudget::for_test_capacity(capacity);
            let builds = Cell::new(0);
            {
                let memo = RequestMemo::new(&owner, "test.request_memo");
                for _ in 0..2 {
                    let answer = memo.get_or_insert_with(7_u64, || {
                        builds.set(builds.get() + 1);
                        "complete answer".to_owned()
                    });
                    assert_eq!(&**answer, "complete answer");
                }
                assert_eq!(builds.get(), expected_builds);
            }
            assert_eq!(owner.accounted_bytes(), 0);
        }
    }

    #[test]
    fn request_memo_unwind_releases_charge() {
        let owner = RetentionBudget::for_test_capacity(1_000_000);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let memo = RequestMemo::new(&owner, "test.request_memo.unwind");
            drop(memo.insert(7_u64, "complete answer".to_owned()));
            assert!(owner.accounted_bytes() > 0);
            panic!("request failed");
        }));
        assert!(result.is_err());
        assert_eq!(owner.accounted_bytes(), 0);
    }
}
