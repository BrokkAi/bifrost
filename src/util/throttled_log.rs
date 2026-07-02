use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(crate) struct ThrottledLog<K> {
    last: Mutex<HashMap<K, Instant>>,
    window: Duration,
    max_entries: usize,
}

impl<K> ThrottledLog<K>
where
    K: Eq + Hash,
{
    pub(crate) fn new(window: Duration, max_entries: usize) -> Self {
        assert!(max_entries > 0, "throttled log max_entries must be nonzero");
        Self {
            last: Mutex::new(HashMap::new()),
            window,
            max_entries,
        }
    }

    pub(crate) fn should_log<Q>(&self, key: &Q, now: Instant) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ToOwned<Owned = K> + ?Sized,
    {
        let mut last = self.last.lock().expect("throttled log poisoned");
        let recent = last
            .get(key)
            .map(|previous| now.duration_since(*previous) < self.window)
            .unwrap_or(false);
        if recent {
            return false;
        }

        if last.len() >= self.max_entries {
            last.retain(|_, previous| now.duration_since(*previous) < self.window);
            if last.len() >= self.max_entries {
                last.clear();
            }
        }
        last.insert(key.to_owned(), now);
        true
    }

    pub(crate) fn clear(&self) {
        self.last.lock().expect("throttled log poisoned").clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_log_throttles_by_key() {
        let log: ThrottledLog<String> = ThrottledLog::new(Duration::from_secs(10), 8);
        let now = Instant::now();

        assert!(log.should_log("a", now));
        assert!(!log.should_log("a", now + Duration::from_secs(9)));
        assert!(log.should_log("a", now + Duration::from_secs(10)));
    }

    #[test]
    fn should_log_prunes_stale_entries_and_bounds_recent_entries() {
        let log: ThrottledLog<String> = ThrottledLog::new(Duration::from_secs(10), 2);
        let now = Instant::now();

        assert!(log.should_log("stale_a", now));
        assert!(log.should_log("stale_b", now + Duration::from_secs(1)));
        assert!(log.should_log("after_prune", now + Duration::from_secs(12)));

        let entries_after_prune = log.last.lock().expect("lock").len();
        assert_eq!(
            entries_after_prune, 1,
            "stale entries should be pruned before recording the new key"
        );

        assert!(log.should_log("recent_a", now + Duration::from_secs(13)));
        assert!(log.should_log("after_clear", now + Duration::from_secs(14)));

        let entries_after_clear = log.last.lock().expect("lock").len();
        assert_eq!(
            entries_after_clear, 1,
            "recent entries should be cleared wholesale when the log stays full"
        );
    }
}
