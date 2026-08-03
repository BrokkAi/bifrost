//! Compatibility facade for shared Git blob/cache plumbing.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use git2::Repository;
use growable_bloom_filter::GrowableBloom;

type Result<T> = std::result::Result<T, String>;

pub fn discover(root: &Path) -> Option<Repository> {
    brokk_bifrost_analysis::gitblob::discover(root)
}

pub fn is_git_repo(root: &Path) -> bool {
    brokk_bifrost_analysis::gitblob::is_git_repo(root)
}

pub fn working_tree_oids(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    brokk_bifrost_analysis::gitblob::working_tree_oids(repo, rel_paths)
}

pub fn working_tree_oids_targeted(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    brokk_bifrost_analysis::gitblob::working_tree_oids(repo, rel_paths)
}

pub fn read_blob(repo: &Repository, oid_hex: &str) -> Result<Vec<u8>> {
    brokk_bifrost_analysis::gitblob::read_blob(repo, oid_hex)
}

pub fn reachable_bloom(repo: &Repository) -> Result<GrowableBloom> {
    brokk_bifrost_analysis::gitblob::reachable_bloom(repo)
}

pub fn worktree_roots(repo: &Repository) -> Result<Vec<PathBuf>> {
    brokk_bifrost_analysis::gitblob::worktree_roots(repo)
}

pub fn uncommitted_oids(root: &Path) -> Result<HashSet<String>> {
    brokk_bifrost_analysis::gitblob::uncommitted_oids(root)
}
