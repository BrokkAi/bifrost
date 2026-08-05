//! Git plumbing for the semantic content cache.
//!
//! The analyzer cache identifies the exact bytes that tree-sitter parsed. The
//! semantic cache has a different contract: clean tracked files use the Git
//! index OID without a content read. Dirty and untracked files use the OID of
//! their working bytes. Paths with a content-changing Git attribute also use
//! their working bytes, even when Git reports them as clean.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use git2::{AttrCheckFlags, AttrValue, DiffOptions, Index, ObjectType, Oid, Repository};
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
    let started = Instant::now();
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?;
    let mut index = repo.index().map_err(|err| err.to_string())?;
    // Bifrost keeps this repository open while another process can run Git.
    // Reload the index so newly staged content gets its current index OID.
    index.read(true).map_err(|err| err.to_string())?;
    let dirty = dirty_worktree_paths(repo, &index, None)?;
    let index_oids: HashMap<String, Oid> = index
        .iter()
        .map(|entry| {
            let path = String::from_utf8(entry.path).map_err(|err| {
                format!("non-UTF-8 git index path while building semantic cache: {err}")
            })?;
            Ok((path, entry.id))
        })
        .collect::<Result<_>>()?;
    let mut out = HashMap::with_capacity(rel_paths.len());
    let mut hashed = 0usize;
    for rel in rel_paths {
        let use_worktree = dirty.contains(rel)
            || !index_oids.contains_key(rel)
            || has_content_transform(repo, Path::new(rel))?;
        let oid = if use_worktree {
            hashed += 1;
            hash_working_file(workdir, rel)?
        } else {
            *index_oids
                .get(rel)
                .expect("tracked clean semantic path has an index OID")
        };
        out.insert(rel.clone(), oid.to_string());
    }
    eprintln!(
        "bifrost semantic identities: files={}; index={}; hashed={hashed}; time={:?}",
        rel_paths.len(),
        rel_paths.len() - hashed,
        started.elapsed()
    );
    Ok(out)
}

pub fn working_tree_oids_targeted(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    let started = Instant::now();
    let workdir = repo
        .workdir()
        .ok_or_else(|| "repository has no working directory".to_string())?;
    let mut index = repo.index().map_err(|err| err.to_string())?;
    // Watcher updates also run after external Git commands on a long-lived repo.
    index.read(true).map_err(|err| err.to_string())?;
    let dirty = dirty_worktree_paths(repo, &index, Some(rel_paths))?;
    let mut out = HashMap::with_capacity(rel_paths.len());
    let mut hashed = 0usize;
    for rel in rel_paths {
        let path = Path::new(rel);
        let entry = index.get_path(path, 0);
        let use_worktree =
            dirty.contains(rel) || entry.is_none() || has_content_transform(repo, path)?;
        let oid = if use_worktree {
            hashed += 1;
            hash_working_file(workdir, rel)?
        } else {
            entry
                .expect("tracked clean semantic path has an index OID")
                .id
        };
        out.insert(rel.clone(), oid.to_string());
    }
    eprintln!(
        "bifrost semantic watcher identities: files={}; index={}; hashed={hashed}; time={:?}",
        rel_paths.len(),
        rel_paths.len() - hashed,
        started.elapsed()
    );
    Ok(out)
}

fn dirty_worktree_paths(
    repo: &Repository,
    index: &Index,
    rel_paths: Option<&[String]>,
) -> Result<HashSet<String>> {
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true)
        .ignore_submodules(true)
        .skip_binary_check(true);
    if let Some(paths) = rel_paths {
        options.disable_pathspec_match(true);
        for path in paths {
            options.pathspec(path);
        }
    }

    let diff = repo
        .diff_index_to_workdir(Some(index), Some(&mut options))
        .map_err(|err| err.to_string())?;
    let mut dirty = HashSet::new();
    for delta in diff.deltas() {
        if let Some(path) = delta.old_file().path() {
            dirty.insert(path.to_string_lossy().into_owned());
        }
        if let Some(path) = delta.new_file().path() {
            dirty.insert(path.to_string_lossy().into_owned());
        }
    }
    Ok(dirty)
}

fn has_content_transform(repo: &Repository, path: &Path) -> Result<bool> {
    for name in ["filter", "ident", "working-tree-encoding"] {
        let value = repo
            .get_attr(path, name, AttrCheckFlags::FILE_THEN_INDEX)
            .map_err(|err| format!("reading Git attribute {name} for {}: {err}", path.display()))?;
        if !matches!(
            AttrValue::from_string(value),
            AttrValue::False | AttrValue::Unspecified
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hash_working_file(workdir: &Path, rel: &str) -> Result<Oid> {
    Oid::hash_file(ObjectType::Blob, workdir.join(rel)).map_err(|err| err.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn run_git<const N: usize>(root: &Path, args: [&str; N]) {
        let status = Command::new("git")
            .current_dir(root)
            .args(["-c", "commit.gpgSign=false"])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_repo() -> (tempfile::TempDir, Repository) {
        let temp = tempfile::tempdir().unwrap();
        run_git(temp.path(), ["init"]);
        run_git(temp.path(), ["config", "user.email", "test@example.com"]);
        run_git(temp.path(), ["config", "user.name", "Test"]);
        std::fs::write(temp.path().join("tracked.rs"), "fn first() {}\n").unwrap();
        run_git(temp.path(), ["add", "tracked.rs"]);
        run_git(temp.path(), ["commit", "-m", "initial"]);
        let repo = Repository::open(temp.path()).unwrap();
        (temp, repo)
    }

    #[test]
    fn clean_and_staged_files_use_the_current_index_oid() {
        let (temp, repo) = init_repo();
        let path = "tracked.rs".to_string();
        let index_oid = repo
            .index()
            .unwrap()
            .get_path(Path::new(&path), 0)
            .unwrap()
            .id;
        assert_eq!(
            working_tree_oids(&repo, std::slice::from_ref(&path)).unwrap()[&path],
            index_oid.to_string()
        );

        std::fs::write(temp.path().join(&path), "fn staged() {}\n").unwrap();
        run_git(temp.path(), ["add", "tracked.rs"]);
        let mut index = repo.index().unwrap();
        index.read(true).unwrap();
        let staged_oid = index.get_path(Path::new(&path), 0).unwrap().id;
        assert_eq!(
            working_tree_oids_targeted(&repo, std::slice::from_ref(&path)).unwrap()[&path],
            staged_oid.to_string()
        );
    }

    #[test]
    fn dirty_and_untracked_files_use_working_byte_oids() {
        let (temp, repo) = init_repo();
        std::fs::write(temp.path().join("tracked.rs"), "fn dirty() {}\n").unwrap();
        std::fs::write(temp.path().join("new.rs"), "fn new_file() {}\n").unwrap();
        let paths = ["tracked.rs".to_string(), "new.rs".to_string()];
        let resolved = working_tree_oids(&repo, &paths).unwrap();

        for path in paths {
            assert_eq!(
                resolved[&path],
                Oid::hash_file(ObjectType::Blob, temp.path().join(path))
                    .unwrap()
                    .to_string()
            );
        }
    }

    #[test]
    fn ident_attributes_use_the_transformed_working_bytes() {
        let (temp, repo) = init_repo();
        std::fs::write(temp.path().join(".gitattributes"), "ident.txt ident\n").unwrap();
        std::fs::write(temp.path().join("ident.txt"), "$Id$\n").unwrap();
        run_git(temp.path(), ["add", ".gitattributes", "ident.txt"]);
        run_git(temp.path(), ["commit", "-m", "ident"]);
        std::fs::remove_file(temp.path().join("ident.txt")).unwrap();
        run_git(temp.path(), ["checkout", "--", "ident.txt"]);

        let path = "ident.txt".to_string();
        let index_oid = repo
            .index()
            .unwrap()
            .get_path(Path::new(&path), 0)
            .unwrap()
            .id;
        let working_oid = Oid::hash_file(ObjectType::Blob, temp.path().join(&path)).unwrap();
        assert_ne!(working_oid, index_oid);
        assert_eq!(
            working_tree_oids(&repo, std::slice::from_ref(&path)).unwrap()[&path],
            working_oid.to_string()
        );
    }
}
