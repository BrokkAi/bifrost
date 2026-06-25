//! Git plumbing for the content-addressed semantic cache.
//!
//! The cache is keyed by git blob OID. Clean files take their OID straight from
//! the index (free, no read); dirty/untracked files are hashed with the same
//! algorithm git would use (`Oid::hash_file`), so the key space is uniform. GC
//! liveness is "reachable from any ref" ∪ "checked out but uncommitted".

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use git2::{ObjectType, Oid, Repository, Status, StatusOptions};

type Result<T> = std::result::Result<T, String>;

/// Discover the repository containing `root`, if any. Semantic search is gated on
/// this being `Some` (non-git workspaces are unsupported).
pub fn discover(root: &Path) -> Option<Repository> {
    Repository::discover(root)
        .ok()
        .filter(|repo| !repo.is_bare())
}

/// Whether `root` is inside a (non-bare) git repository.
pub fn is_git_repo(root: &Path) -> bool {
    discover(root).is_some()
}

/// Working-tree blob OID (hex) for each of `rel_paths`. Clean files use the index
/// entry's OID; modified/untracked files are hashed from disk so the OID reflects
/// the actual working-tree content the user is searching.
pub fn working_tree_oids(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?
        .to_path_buf();

    let index = repo.index().map_err(|e| e.to_string())?;
    let mut index_oids: HashMap<String, Oid> = HashMap::new();
    for entry in index.iter() {
        let path = String::from_utf8_lossy(&entry.path).into_owned();
        index_oids.insert(path, entry.id);
    }

    let dirty = dirty_paths(repo)?;

    let mut out = HashMap::with_capacity(rel_paths.len());
    for rel in rel_paths {
        let oid = if !dirty.contains(rel) {
            if let Some(oid) = index_oids.get(rel) {
                *oid
            } else {
                hash_working_file(&workdir, rel)?
            }
        } else {
            hash_working_file(&workdir, rel)?
        };
        out.insert(rel.clone(), oid.to_string());
    }
    Ok(out)
}

/// Like `working_tree_oids` but O(changed): the incremental-update resolver.
/// Resolves each path with point lookups — `status_file` for dirtiness, the index
/// for a clean OID, `hash_file` for dirty/untracked — instead of building a
/// whole-repo index map and walking the entire working tree. Only the one-time
/// `repo.index()` load is repo-sized (and unavoidable); everything else is per-path.
pub fn working_tree_oids_targeted(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?
        .to_path_buf();
    let index = repo.index().map_err(|e| e.to_string())?;

    let mut out = HashMap::with_capacity(rel_paths.len());
    for rel in rel_paths {
        let path = Path::new(rel);
        // status_file errors on paths git refuses to stat (e.g. ignored); treat
        // anything we can't prove clean as dirty and hash it from disk.
        let clean =
            matches!(repo.status_file(path), Ok(status) if !status.intersects(dirty_flags()));
        let oid = if clean {
            match index.get_path(path, 0) {
                Some(entry) => entry.id,
                None => hash_working_file(&workdir, rel)?,
            }
        } else {
            hash_working_file(&workdir, rel)?
        };
        out.insert(rel.clone(), oid.to_string());
    }
    Ok(out)
}

/// Read a blob's bytes by OID (used only to re-materialize a non-checked-out blob).
pub fn read_blob(repo: &Repository, oid_hex: &str) -> Result<Vec<u8>> {
    let oid = Oid::from_str(oid_hex).map_err(|e| e.to_string())?;
    let blob = repo.find_blob(oid).map_err(|e| e.to_string())?;
    Ok(blob.content().to_vec())
}

/// The subset of `candidates` reachable from any ref (incl. per-worktree HEADs).
///
/// Streams `git rev-list --objects --all` and keeps only OIDs already in `candidates`,
/// so peak memory is O(|candidates|) — the bounded cache OID set — rather than O(all
/// objects ever). The full reachable set on a large monorepo is millions of objects and
/// buffering it OOMs (see git history for the removed `reachable_oids`); intersecting on
/// the fly against what the cache actually holds avoids that while keeping the exact
/// "reachable from any ref" liveness. The history walk itself is still O(history) in time
/// (a candidate for incremental GC later), but it no longer balloons memory.
pub fn reachable_among(
    repo: &Repository,
    candidates: &HashSet<String>,
) -> Result<HashSet<String>> {
    if candidates.is_empty() {
        return Ok(HashSet::new());
    }
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?;
    let mut child = Command::new("git")
        .current_dir(workdir)
        .args(["rev-list", "--objects", "--all"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("git rev-list failed to spawn: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git rev-list produced no stdout".to_string())?;

    let mut live = HashSet::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("reading git rev-list output: {e}"))?;
        // Each line is "<oid>" or "<oid> <path>"; the OID is the first token.
        let oid = line.split(' ').next().unwrap_or("");
        if oid.len() >= 40 && candidates.contains(oid) {
            live.insert(oid.to_string());
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("git rev-list wait failed: {e}"))?;
    if !status.success() {
        return Err("git rev-list --objects --all failed".to_string());
    }
    Ok(live)
}

/// Roots of every linked worktree of this repo (incl. the main worktree).
pub fn worktree_roots(repo: &Repository) -> Result<Vec<PathBuf>> {
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?;
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
    let text = String::from_utf8_lossy(&output.stdout);
    let mut roots = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            roots.push(PathBuf::from(path));
        }
    }
    Ok(roots)
}

/// Blob OIDs (hex) of dirty/untracked files in `root`'s working tree — GC roots
/// for content not reachable from any committed tree.
pub fn uncommitted_oids(root: &Path) -> Result<HashSet<String>> {
    let Some(repo) = discover(root) else {
        return Ok(HashSet::new());
    };
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?
        .to_path_buf();
    let mut out = HashSet::new();
    for rel in dirty_paths(&repo)? {
        if let Ok(oid) = hash_working_file(&workdir, &rel) {
            out.insert(oid.to_string());
        }
    }
    Ok(out)
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

/// Status bits that mean a path's working-tree content differs from HEAD/index,
/// so its OID must be hashed from disk rather than read from the index.
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
mod tests {
    use super::*;
    use std::process::Command;

    fn run_git<const N: usize>(dir: &Path, args: [&str; N]) {
        let status = Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_repo(dir: &Path) {
        run_git(dir, ["init"]);
        run_git(dir, ["config", "user.email", "t@example.com"]);
        run_git(dir, ["config", "user.name", "T"]);
    }

    #[test]
    fn clean_file_oid_matches_git_hash_object() {
        let temp = tempfile::TempDir::new().unwrap();
        init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        run_git(temp.path(), ["add", "a.txt"]);
        run_git(temp.path(), ["commit", "-m", "init"]);

        let repo = discover(temp.path()).unwrap();
        let oids = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        // git hash-object of "hello\n"
        assert_eq!(oids["a.txt"], "ce013625030ba8dba906f756967f9e9ca394464a");
    }

    #[test]
    fn dirty_file_oid_reflects_working_tree() {
        let temp = tempfile::TempDir::new().unwrap();
        init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        run_git(temp.path(), ["add", "a.txt"]);
        run_git(temp.path(), ["commit", "-m", "init"]);
        std::fs::write(temp.path().join("a.txt"), "changed\n").unwrap();

        let repo = discover(temp.path()).unwrap();
        let oids = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        assert_ne!(oids["a.txt"], "ce013625030ba8dba906f756967f9e9ca394464a");

        // reachable_among returns only the candidates reachable from a ref: the committed
        // "hello\n" blob is (it's in HEAD), the dirty working-tree blob is not.
        let committed = "ce013625030ba8dba906f756967f9e9ca394464a".to_string();
        let candidates: HashSet<String> =
            [committed.clone(), oids["a.txt"].clone()].into_iter().collect();
        let reachable = reachable_among(&repo, &candidates).unwrap();
        assert!(reachable.contains(&committed));
        assert!(!reachable.contains(&oids["a.txt"]));
        // ...but the dirty working-tree blob is held live by the uncommitted set.
        let uncommitted = uncommitted_oids(temp.path()).unwrap();
        assert!(uncommitted.contains(&oids["a.txt"]));
    }

    #[test]
    fn targeted_matches_bulk_for_clean_and_dirty() {
        let temp = tempfile::TempDir::new().unwrap();
        init_repo(temp.path());
        std::fs::write(temp.path().join("clean.txt"), "clean\n").unwrap();
        std::fs::write(temp.path().join("dirty.txt"), "committed\n").unwrap();
        run_git(temp.path(), ["add", "clean.txt", "dirty.txt"]);
        run_git(temp.path(), ["commit", "-m", "init"]);
        // Make dirty.txt differ from HEAD; add an untracked file too.
        std::fs::write(temp.path().join("dirty.txt"), "working\n").unwrap();
        std::fs::write(temp.path().join("new.txt"), "fresh\n").unwrap();

        let repo = discover(temp.path()).unwrap();
        let paths = vec![
            "clean.txt".to_string(),
            "dirty.txt".to_string(),
            "new.txt".to_string(),
        ];
        let bulk = working_tree_oids(&repo, &paths).unwrap();
        let targeted = working_tree_oids_targeted(&repo, &paths).unwrap();
        assert_eq!(bulk, targeted, "targeted resolver must match bulk per path");
        // clean uses the committed OID; dirty/untracked reflect working bytes.
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
}
