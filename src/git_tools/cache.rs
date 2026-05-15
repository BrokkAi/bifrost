// Process-global LRU for `search_git_commit_messages`. The key includes
// the canonical repo root and the HEAD oid so that any new commit
// transparently produces a fresh cache key — explicit invalidation is
// unnecessary. Bounded at 64 entries; LRU eviction reclaims the rest.

use moka::sync::Cache;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Clone, Hash, Eq, PartialEq)]
pub(super) struct CommitSearchKey {
    pub root: PathBuf,
    pub head: String,
    pub pattern: String,
    pub limit: usize,
}

pub(super) fn commit_search_cache() -> &'static Cache<CommitSearchKey, String> {
    static CACHE: OnceLock<Cache<CommitSearchKey, String>> = OnceLock::new();
    // 64 entries is plenty for interactive use; LRU eviction reclaims older
    // patterns automatically. moka's sync Cache is Arc-backed so the static
    // reference is shared cheaply across calls.
    CACHE.get_or_init(|| Cache::builder().max_capacity(64).build())
}
