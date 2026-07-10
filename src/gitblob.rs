//! Shared Git blob-OID plumbing for content-addressed caches.
//!
//! Live files are hashed from the bytes visible in the working tree, using
//! Git's blob hashing. On LF checkouts this matches the index OID for clean
//! files; on CRLF checkouts it intentionally differs so cache identity stays
//! aligned with the bytes consumed by analyzers and semantic indexing.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use git2::{IndexEntry, ObjectType, Oid, Repository, Status, StatusOptions};
use growable_bloom_filter::GrowableBloom;

use crate::path_normalization::NormalizePath;

pub(crate) type Result<T> = std::result::Result<T, String>;

pub(crate) const CACHE_DIR_NAME: &str = ".brokk";

/// Discover the non-bare repository containing `root`, if any.
pub(crate) fn discover(root: &Path) -> Option<Repository> {
    Repository::discover(root)
        .ok()
        .filter(|repo| !repo.is_bare())
}

/// Whether `root` is inside a non-bare Git repository.
pub(crate) fn is_git_repo(root: &Path) -> bool {
    discover(root).is_some()
}

/// Resolve the primary repository root. Linked worktrees collapse to the
/// checkout that owns the common object database.
pub(crate) fn primary_repo_root(repo: &Repository) -> Option<PathBuf> {
    if repo.is_bare() {
        return None;
    }
    let root = if repo.is_worktree() {
        repo.commondir().parent().map(Path::to_path_buf)
    } else {
        repo.workdir().map(Path::to_path_buf)
    }?;
    Some(root.normalize())
}

/// Resolve the unified cache path under the primary repository's `.brokk`
/// directory. Non-Git roots fall back to the provided workspace root.
pub(crate) fn cache_db_path(workspace_root: &Path) -> PathBuf {
    let primary_root = discover(workspace_root)
        .as_ref()
        .and_then(primary_repo_root)
        .unwrap_or_else(|| workspace_root.to_path_buf().normalize());
    primary_root
        .join(CACHE_DIR_NAME)
        .join(crate::cache_db::CACHE_DB_FILE_NAME)
}

/// Working-tree blob OID (hex) for each project-relative path.
pub(crate) fn working_tree_oids(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|err| err.to_string())?;
    let mut out = HashMap::with_capacity(rel_paths.len());
    for rel in rel_paths {
        let oid = resolve_path_oid(workdir, &index, rel)?;
        out.insert(rel.clone(), oid.to_string());
    }
    Ok(out)
}

/// Resolve every indexed path to the OID of its current working-tree bytes.
pub(crate) fn working_tree_oids_full(repo: &Repository) -> Result<HashMap<String, String>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|err| err.to_string())?;
    let mut out = HashMap::with_capacity(index.len());
    for entry in index.iter() {
        let rel = index_path_to_string(&entry)?;
        if !workdir.join(&rel).is_file() {
            continue;
        }
        let oid = resolve_index_entry_oid(workdir, &entry)?;
        out.insert(rel, oid.to_string());
    }
    Ok(out)
}

/// Resolve one path to the OID of its current working-tree bytes. Missing
/// files return `Ok(None)`.
pub(crate) fn working_tree_oid_for_path(repo: &Repository, rel_path: &Path) -> Result<Option<Oid>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|err| err.to_string())?;
    let Some(rel) = rel_path.to_str() else {
        return Err(format!("non-UTF-8 git path: {}", rel_path.display()));
    };
    if !workdir.join(rel_path).is_file() {
        return Ok(None);
    }
    Ok(Some(resolve_path_oid(workdir, &index, rel)?))
}

/// Read a Git blob's bytes by hexadecimal OID.
pub(crate) fn read_blob(repo: &Repository, oid_hex: &str) -> Result<Vec<u8>> {
    let oid = Oid::from_str(oid_hex).map_err(|err| err.to_string())?;
    let blob = repo.find_blob(oid).map_err(|err| err.to_string())?;
    Ok(blob.content().to_vec())
}

const GC_BLOOM_FP_RATE: f64 = 0.05;
const GC_BLOOM_EST_OIDS: usize = 1 << 19;

/// Build a Bloom filter containing every object reachable from refs or a
/// linked-worktree HEAD, including detached HEADs not named by a ref.
pub(crate) fn reachable_bloom(repo: &Repository) -> Result<GrowableBloom> {
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
        .map_err(|err| format!("git rev-list failed to spawn: {err}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git rev-list produced no stdout".to_string())?;

    let mut bloom = GrowableBloom::new(GC_BLOOM_FP_RATE, GC_BLOOM_EST_OIDS);
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|err| format!("reading git rev-list output: {err}"))?;
        let oid = line.split(' ').next().unwrap_or("");
        if oid.len() >= 40 {
            bloom.insert(oid);
        }
    }
    let status = child
        .wait()
        .map_err(|err| format!("git rev-list wait failed: {err}"))?;
    if !status.success() {
        return Err("git rev-list --objects --all failed".to_string());
    }
    Ok(bloom)
}

/// Commit OIDs checked out by every linked worktree.
pub(crate) fn worktree_heads(repo: &Repository) -> Result<Vec<String>> {
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

/// Roots of every linked worktree, including the primary checkout.
pub(crate) fn worktree_roots(repo: &Repository) -> Result<Vec<PathBuf>> {
    let text = worktree_porcelain(repo)?;
    let mut roots = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            let path = PathBuf::from(path);
            roots.push(
                path.canonicalize()
                    .map(NormalizePath::normalize)
                    .unwrap_or_else(|_| path.normalize()),
            );
        }
    }
    Ok(roots)
}

/// Exact-byte OIDs held by every worktree: all present indexed files plus
/// untracked files. This is the shared working-tree liveness root for caches.
pub(crate) fn worktree_live_oids(repo: &Repository) -> Result<HashSet<String>> {
    let mut oids = HashSet::new();
    for root in worktree_roots(repo)? {
        let worktree_repo = Repository::open(&root)
            .map_err(|err| format!("opening worktree {}: {err}", root.display()))?;
        oids.extend(working_tree_oids_full(&worktree_repo)?.into_values());
        oids.extend(uncommitted_oids(&root)?);
    }
    Ok(oids)
}

fn worktree_porcelain(repo: &Repository) -> Result<String> {
    let workdir = workdir(repo)?;
    let output = Command::new("git")
        .current_dir(workdir)
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|err| format!("git worktree list failed to spawn: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git worktree list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Blob OIDs of dirty or untracked files in one worktree.
pub(crate) fn uncommitted_oids(root: &Path) -> Result<HashSet<String>> {
    let Some(repo) = discover(root) else {
        return Ok(HashSet::new());
    };
    let workdir = workdir(&repo)?.to_path_buf();
    let mut out = HashSet::new();
    for rel in dirty_paths(&repo)? {
        let path = workdir.join(&rel);
        if !path.is_file() {
            continue;
        }
        let oid = hash_working_file(&workdir, &rel)?;
        out.insert(oid.to_string());
    }
    Ok(out)
}

fn workdir(repo: &Repository) -> Result<&Path> {
    repo.workdir()
        .ok_or_else(|| "repository has no working directory".to_string())
}

fn resolve_path_oid(workdir: &Path, index: &git2::Index, rel: &str) -> Result<Oid> {
    match index.get_path(Path::new(rel), 0) {
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

fn dirty_paths(repo: &Repository) -> Result<HashSet<String>> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_unmodified(false)
        .exclude_submodules(true);
    let statuses = repo
        .statuses(Some(&mut opts))
        .map_err(|err| err.to_string())?;
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
    Oid::hash_file(ObjectType::Blob, workdir.join(rel)).map_err(|err| err.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use git2::{IndexAddOption, Signature};

    pub(crate) fn init_repo(dir: &Path) -> Repository {
        let repo = Repository::init(dir).unwrap();
        let mut config = repo.config().unwrap();
        config.set_str("user.email", "t@example.com").unwrap();
        config.set_str("user.name", "T").unwrap();
        drop(config);
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

    fn run_git(dir: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn clean_file_oid_matches_working_tree_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        let expected = Oid::hash_object(ObjectType::Blob, b"hello\n").unwrap();
        let paths = vec!["a.txt".to_string()];
        assert_eq!(
            working_tree_oids(&repo, &paths).unwrap()["a.txt"],
            expected.to_string()
        );
        assert_eq!(
            working_tree_oids_full(&repo).unwrap()["a.txt"],
            expected.to_string()
        );
        assert_eq!(
            working_tree_oid_for_path(&repo, Path::new("a.txt")).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn clean_crlf_checkout_uses_working_tree_not_index_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        repo.config()
            .unwrap()
            .set_str("core.autocrlf", "true")
            .unwrap();
        std::fs::write(temp.path().join("a.txt"), b"hello\r\n").unwrap();
        run_git(temp.path(), &["add", "a.txt"]);
        run_git(temp.path(), &["commit", "-m", "init"]);

        let index_oid = repo
            .index()
            .unwrap()
            .get_path(Path::new("a.txt"), 0)
            .unwrap()
            .id;
        let lf_oid = Oid::hash_object(ObjectType::Blob, b"hello\n").unwrap();
        let crlf_oid = Oid::hash_object(ObjectType::Blob, b"hello\r\n").unwrap();
        assert_eq!(index_oid, lf_oid);
        assert_ne!(index_oid, crlf_oid);
        let paths = vec!["a.txt".to_string()];
        assert_eq!(
            working_tree_oids(&repo, &paths).unwrap()["a.txt"],
            crlf_oid.to_string()
        );
        assert_eq!(
            working_tree_oids_full(&repo).unwrap()["a.txt"],
            crlf_oid.to_string()
        );
        assert_eq!(
            working_tree_oid_for_path(&repo, Path::new("a.txt")).unwrap(),
            Some(crlf_oid)
        );
    }

    #[test]
    fn dirty_and_untracked_files_reflect_working_tree_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("dirty.txt"), "committed\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("dirty.txt"), "working\n").unwrap();
        std::fs::write(temp.path().join("new.txt"), "fresh\n").unwrap();

        let paths = vec!["dirty.txt".to_string(), "new.txt".to_string()];
        let bulk = working_tree_oids(&repo, &paths).unwrap();
        let full = working_tree_oids_full(&repo).unwrap();
        assert_eq!(full["dirty.txt"], bulk["dirty.txt"]);
        assert_eq!(
            working_tree_oid_for_path(&repo, Path::new("dirty.txt")).unwrap(),
            Some(Oid::from_str(&bulk["dirty.txt"]).unwrap())
        );
        assert_eq!(
            working_tree_oid_for_path(&repo, Path::new("new.txt")).unwrap(),
            Some(Oid::from_str(&bulk["new.txt"]).unwrap())
        );
        assert_eq!(
            bulk["dirty.txt"],
            Oid::hash_object(ObjectType::Blob, b"working\n")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            bulk["new.txt"],
            Oid::hash_object(ObjectType::Blob, b"fresh\n")
                .unwrap()
                .to_string()
        );
        let uncommitted = uncommitted_oids(temp.path()).unwrap();
        assert!(uncommitted.contains(&bulk["dirty.txt"]));
        assert!(uncommitted.contains(&bulk["new.txt"]));
    }

    #[test]
    fn linked_worktrees_share_cache_path_and_are_enumerated() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        std::fs::create_dir(&repo_root).unwrap();
        let repo = init_repo(&repo_root);
        std::fs::write(repo_root.join("a.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        let linked = temp.path().join("linked");
        run_git(
            &repo_root,
            &[
                "worktree",
                "add",
                "--detach",
                linked.to_str().unwrap(),
                "HEAD",
            ],
        );

        assert_eq!(cache_db_path(&repo_root), cache_db_path(&linked));
        let roots = worktree_roots(&repo).unwrap();
        assert!(roots.contains(&repo_root.canonicalize().unwrap().normalize()));
        assert!(roots.contains(&linked.canonicalize().unwrap().normalize()));
        assert_eq!(worktree_heads(&repo).unwrap().len(), 1);
        assert!(
            worktree_live_oids(&repo).unwrap().contains(
                &Oid::hash_object(ObjectType::Blob, b"hello\n")
                    .unwrap()
                    .to_string()
            )
        );
    }

    #[cfg(windows)]
    #[test]
    fn cache_root_normalizes_verbatim_disk_and_unc_paths() {
        assert_eq!(
            cache_db_path(Path::new(r"C:\Users\runner\repo")),
            cache_db_path(Path::new(r"\\?\C:\Users\runner\repo"))
        );
        assert_eq!(
            cache_db_path(Path::new(r"\\server\share\repo")),
            cache_db_path(Path::new(r"\\?\UNC\server\share\repo"))
        );
    }
}
