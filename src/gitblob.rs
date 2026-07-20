//! Shared git blob-OID plumbing for content-addressed caches.
//!
//! Files are hashed from the bytes visible in the working tree, using Git's
//! blob hashing, so analyzer cache keys line up with the exact byte stream used
//! for tree-sitter ranges and LSP positions. On LF checkouts this matches the
//! index OID for clean files; on CRLF checkouts it intentionally differs.

use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use git2::{IndexEntry, ObjectType, Oid, Repository, Status, StatusOptions};
use growable_bloom_filter::GrowableBloom;

pub type Result<T> = std::result::Result<T, String>;

pub const CACHE_DIR_NAME: &str = ".brokk";
pub const CACHE_DIR_ENV: &str = "BIFROST_CACHE_DIR";

/// Discover the repository containing `root`, if any.
pub fn discover(root: &Path) -> Option<Repository> {
    Repository::discover(root)
        .ok()
        .filter(|repo| !repo.is_bare())
}

/// Whether `root` is inside a non-bare git repository.
pub fn is_git_repo(root: &Path) -> bool {
    discover(root).is_some()
}

/// Resolve the primary repository root. Linked worktrees collapse to the
/// checkout that owns the common object database.
pub fn primary_repo_root(repo: &Repository) -> Option<PathBuf> {
    if repo.is_bare() {
        return None;
    }
    if repo.is_worktree() {
        return repo.commondir().parent().map(Path::to_path_buf);
    }
    repo.workdir().map(Path::to_path_buf)
}

/// Resolve the unified cache database path under `.brokk` at the primary repo
/// root. Non-git roots fall back to the provided workspace root.
pub fn cache_db_path(workspace_root: &Path) -> PathBuf {
    if let Some(cache_dir) = std::env::var_os(CACHE_DIR_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(cache_dir).join(crate::cache_db::CACHE_DB_FILE_NAME);
    }
    let primary_root = discover(workspace_root)
        .as_ref()
        .and_then(primary_repo_root)
        .unwrap_or_else(|| workspace_root.to_path_buf());
    primary_root
        .join(CACHE_DIR_NAME)
        .join(crate::cache_db::CACHE_DB_FILE_NAME)
}

/// Working-tree blob OID (hex) for each of `rel_paths`.
pub fn working_tree_oids(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|e| e.to_string())?;

    let mut out = HashMap::with_capacity(rel_paths.len());
    for rel in rel_paths {
        let oid = resolve_path_oid(workdir, &index, rel)?;
        out.insert(rel.clone(), oid.to_string());
    }
    Ok(out)
}

/// Like [`working_tree_oids`] but kept as the explicit incremental-update API.
pub fn working_tree_oids_targeted(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    working_tree_oids(repo, rel_paths)
}

/// Resolve every path in the index to the blob OID for its current working-tree
/// bytes.
pub fn working_tree_oids_full(repo: &Repository) -> Result<HashMap<String, String>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let mut out = HashMap::with_capacity(index.len());
    for entry in index.iter() {
        let rel = index_path_to_string(&entry)?;
        let oid = resolve_index_entry_oid(workdir, &entry)?;
        out.insert(rel, oid.to_string());
    }
    Ok(out)
}

/// Resolve one path to the OID of its current working-tree bytes. Returns
/// `Ok(None)` for a missing file.
pub fn working_tree_oid_for_path(repo: &Repository, rel_path: &Path) -> Result<Option<Oid>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let Some(rel) = rel_path.to_str() else {
        return Err(format!("non-UTF-8 git path: {}", rel_path.display()));
    };
    if !workdir.join(rel_path).is_file() {
        return Ok(None);
    }
    Ok(Some(resolve_path_oid(workdir, &index, rel)?))
}

/// Whether a path's working-tree content differs from the index entry.
pub fn is_path_dirty(repo: &Repository, rel_path: &Path) -> Result<bool> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let Some(entry) = index.get_path(rel_path, 0) else {
        return Ok(workdir.join(rel_path).is_file());
    };
    Ok(!entry_stat_matches(&workdir.join(rel_path), &entry))
}

/// Read a blob's bytes by OID.
pub fn read_blob(repo: &Repository, oid_hex: &str) -> Result<Vec<u8>> {
    let oid = Oid::from_str(oid_hex).map_err(|e| e.to_string())?;
    let blob = repo.find_blob(oid).map_err(|e| e.to_string())?;
    Ok(blob.content().to_vec())
}

/// Target false-positive rate for the GC reachability filter. There are no
/// false negatives, so GC never drops a reachable blob.
const GC_BLOOM_FP_RATE: f64 = 0.05;
const GC_BLOOM_EST_OIDS: usize = 1 << 19;

/// A Bloom filter of every OID reachable from any ref or linked worktree HEAD,
/// built by streaming `git rev-list --objects --all <worktree-heads...>`.
pub fn reachable_bloom(repo: &Repository) -> Result<GrowableBloom> {
    let workdir = workdir(repo)?;
    let mut args = vec![
        "rev-list".to_string(),
        "--objects".to_string(),
        "--all".to_string(),
    ];
    args.extend(worktree_heads(repo)?);
    let mut child = Command::new("git")
        .current_dir(workdir)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("git rev-list failed to spawn: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git rev-list produced no stdout".to_string())?;

    let mut bloom = GrowableBloom::new(GC_BLOOM_FP_RATE, GC_BLOOM_EST_OIDS);
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("reading git rev-list output: {e}"))?;
        let oid = line.split(' ').next().unwrap_or("");
        if oid.len() >= 40 {
            bloom.insert(oid);
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("git rev-list wait failed: {e}"))?;
    if !status.success() {
        return Err("git rev-list --objects --all failed".to_string());
    }
    Ok(bloom)
}

/// Commit OIDs checked out by every linked worktree, including detached HEADs
/// that are not otherwise reachable from refs.
pub fn worktree_heads(repo: &Repository) -> Result<Vec<String>> {
    let text = worktree_porcelain(repo)?;
    let mut heads = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        if let Some(head) = line.strip_prefix("HEAD ")
            && let Ok(oid) = Oid::from_str(head)
            && !oid.is_zero()
            && seen.insert(head.to_string())
        {
            heads.push(head.to_string());
        }
    }
    Ok(heads)
}

/// Roots of every linked worktree of this repo, including the main worktree.
pub fn worktree_roots(repo: &Repository) -> Result<Vec<PathBuf>> {
    let text = worktree_porcelain(repo)?;
    let mut roots = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            roots.push(PathBuf::from(path));
        }
    }
    Ok(roots)
}

fn worktree_porcelain(repo: &Repository) -> Result<String> {
    let workdir = workdir(repo)?;
    let output = Command::new("git")
        .current_dir(workdir)
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|e| format!("git worktree list failed to spawn: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git worktree list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Blob OIDs (hex) of dirty/untracked files in `root`'s working tree.
pub fn uncommitted_oids(root: &Path) -> Result<HashSet<String>> {
    let Some(repo) = discover(root) else {
        return Ok(HashSet::new());
    };
    let workdir = workdir(&repo)?.to_path_buf();
    let mut out = HashSet::new();
    for rel in dirty_paths(&repo)? {
        if let Ok(oid) = hash_working_file(&workdir, &rel) {
            out.insert(oid.to_string());
        }
    }
    Ok(out)
}

/// Blob OIDs (hex) for every existing tracked file and every untracked file in
/// `root`'s working tree.
///
/// GC must retain the bytes analyzers actually parsed, even when Git considers
/// those bytes clean after line-ending conversion. Missing tracked files and
/// files that cannot be hashed are skipped because they cannot back an active
/// working-tree analysis.
pub fn existing_working_tree_oids(root: &Path) -> Result<HashSet<String>> {
    let Some(repo) = discover(root) else {
        return Ok(HashSet::new());
    };
    let workdir = workdir(&repo)?.to_path_buf();
    let index = repo.index().map_err(|e| e.to_string())?;
    let mut tracked_paths = HashSet::with_capacity(index.len());
    let mut out = HashSet::with_capacity(index.len());

    for entry in index.iter() {
        let Ok(rel) = index_path_to_string(&entry) else {
            continue;
        };
        tracked_paths.insert(rel.clone());
        if workdir.join(&rel).is_file()
            && let Ok(oid) = hash_working_file(&workdir, &rel)
        {
            out.insert(oid.to_string());
        }
    }

    for rel in dirty_paths(&repo)? {
        if !tracked_paths.contains(&rel)
            && workdir.join(&rel).is_file()
            && let Ok(oid) = hash_working_file(&workdir, &rel)
        {
            out.insert(oid.to_string());
        }
    }
    Ok(out)
}

fn workdir(repo: &Repository) -> Result<&Path> {
    repo.workdir()
        .ok_or_else(|| "repository has no working directory".to_string())
}

fn resolve_path_oid(workdir: &Path, index: &git2::Index, rel: &str) -> Result<Oid> {
    let path = Path::new(rel);
    match index.get_path(path, 0) {
        Some(entry) => resolve_index_entry_oid(workdir, &entry),
        None => hash_working_file(workdir, rel),
    }
}

pub(crate) fn resolve_index_entry_oid(workdir: &Path, entry: &IndexEntry) -> Result<Oid> {
    let rel = index_path_to_string(entry)?;
    hash_working_file(workdir, &rel)
}

pub(crate) fn index_path_to_string(entry: &IndexEntry) -> Result<String> {
    String::from_utf8(entry.path.clone()).map_err(|err| format!("non-UTF-8 git index path: {err}"))
}

pub(crate) fn entry_stat_matches(path: &Path, entry: &IndexEntry) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata_matches_index(&metadata, entry)
}

#[cfg(unix)]
fn metadata_matches_index(metadata: &Metadata, entry: &IndexEntry) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.dev() as u32 == entry.dev
        && metadata.ino() as u32 == entry.ino
        && metadata.mode() == entry.mode
        && metadata.uid() == entry.uid
        && metadata.gid() == entry.gid
        && metadata.size() as u32 == entry.file_size
        && metadata.mtime() as i32 == entry.mtime.seconds()
        && metadata.mtime_nsec() as u32 == entry.mtime.nanoseconds()
}

#[cfg(not(unix))]
fn metadata_matches_index(metadata: &Metadata, entry: &IndexEntry) -> bool {
    use std::time::UNIX_EPOCH;

    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(duration) = modified.duration_since(UNIX_EPOCH) else {
        return false;
    };
    metadata.len() as u32 == entry.file_size
        && duration.as_secs() as i32 == entry.mtime.seconds()
        && duration.subsec_nanos() == entry.mtime.nanoseconds()
}

fn dirty_paths(repo: &Repository) -> Result<HashSet<String>> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_unmodified(false)
        .exclude_submodules(true);
    let statuses = repo.statuses(Some(&mut opts)).map_err(|e| e.to_string())?;
    let mut dirty = HashSet::new();
    let changed = dirty_flags();
    for entry in statuses.iter() {
        if entry.status().intersects(changed)
            && let Some(path) = entry.path()
        {
            dirty.insert(path.to_string());
        }
    }
    Ok(dirty)
}

fn dirty_flags() -> Status {
    Status::WT_MODIFIED
        | Status::WT_NEW
        | Status::WT_TYPECHANGE
        | Status::WT_RENAMED
        | Status::INDEX_MODIFIED
        | Status::INDEX_NEW
        | Status::INDEX_TYPECHANGE
        | Status::INDEX_RENAMED
}

fn hash_working_file(workdir: &Path, rel: &str) -> Result<Oid> {
    Oid::hash_file(ObjectType::Blob, workdir.join(rel)).map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use git2::{IndexAddOption, Signature};

    pub(crate) fn init_repo(dir: &Path) -> Repository {
        let repo = Repository::init(dir).unwrap();
        {
            let mut config = repo.config().unwrap();
            config.set_str("user.email", "t@example.com").unwrap();
            config.set_str("user.name", "T").unwrap();
        }
        repo
    }

    pub(crate) fn commit_all(repo: &Repository, message: &str) -> Oid {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("T", "t@example.com").unwrap();
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        match parent {
            Some(parent) => repo
                .commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])
                .unwrap(),
            None => repo
                .commit(Some("HEAD"), &sig, &sig, message, &tree, &[])
                .unwrap(),
        }
    }

    #[test]
    fn clean_file_oid_matches_git_hash_object() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        let oids = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        assert_eq!(
            oids["a.txt"],
            Oid::hash_object(ObjectType::Blob, b"hello\n")
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn dirty_file_oid_reflects_working_tree() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("a.txt"), "changed\n").unwrap();

        let oids = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        assert_eq!(
            oids["a.txt"],
            Oid::hash_object(ObjectType::Blob, b"changed\n")
                .unwrap()
                .to_string()
        );

        let uncommitted = uncommitted_oids(temp.path()).unwrap();
        assert!(uncommitted.contains(&oids["a.txt"]));
    }

    #[test]
    fn targeted_matches_bulk_for_clean_dirty_and_untracked() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("clean.txt"), "clean\n").unwrap();
        std::fs::write(temp.path().join("dirty.txt"), "committed\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("dirty.txt"), "working\n").unwrap();
        std::fs::write(temp.path().join("new.txt"), "fresh\n").unwrap();

        let paths = vec![
            "clean.txt".to_string(),
            "dirty.txt".to_string(),
            "new.txt".to_string(),
        ];
        let bulk = working_tree_oids(&repo, &paths).unwrap();
        let targeted = working_tree_oids_targeted(&repo, &paths).unwrap();
        assert_eq!(bulk, targeted);
        assert_eq!(
            targeted["clean.txt"],
            Oid::hash_object(ObjectType::Blob, b"clean\n")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            targeted["dirty.txt"],
            Oid::hash_object(ObjectType::Blob, b"working\n")
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn gc_oids_include_existing_tracked_and_untracked_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("clean.txt"), "clean\n").unwrap();
        std::fs::write(temp.path().join("changed.txt"), "committed\n").unwrap();
        std::fs::write(temp.path().join("deleted.txt"), "deleted\n").unwrap();
        commit_all(&repo, "init");

        std::fs::write(temp.path().join("changed.txt"), "working\r\n").unwrap();
        std::fs::remove_file(temp.path().join("deleted.txt")).unwrap();
        std::fs::write(temp.path().join("untracked.txt"), "untracked\n").unwrap();

        let oids = existing_working_tree_oids(temp.path()).unwrap();
        for bytes in [
            b"clean\n".as_slice(),
            b"working\r\n".as_slice(),
            b"untracked\n".as_slice(),
        ] {
            let oid = Oid::hash_object(ObjectType::Blob, bytes)
                .unwrap()
                .to_string();
            assert!(oids.contains(&oid), "missing working-tree OID {oid}");
        }
        let deleted_oid = Oid::hash_object(ObjectType::Blob, b"deleted\n")
            .unwrap()
            .to_string();
        assert!(!oids.contains(&deleted_oid));
    }
}
