use git2::{ObjectType, Repository};
use std::path::{Component, Path, PathBuf};

pub fn parse_rev_path(input: &str) -> Option<(&str, &str)> {
    let (rev, path) = input.split_once(':')?;
    if rev.is_empty() || path.is_empty() {
        return None;
    }
    if is_windows_absolute_path_split(rev, path) {
        return None;
    }
    Some((rev, path))
}

fn is_windows_absolute_path_split(rev: &str, path: &str) -> bool {
    rev.len() == 1
        && rev.as_bytes()[0].is_ascii_alphabetic()
        && matches!(path.as_bytes().first(), Some(b'/' | b'\\'))
}

pub fn resolve_git_file_path(path: &str, workspace_root: &Path) -> PathBuf {
    let path = path.trim();
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return normalize_path_lexically(PathBuf::from(home).join(rest));
    }

    let raw = Path::new(path);
    if raw.is_absolute() {
        normalize_path_lexically(raw.to_path_buf())
    } else {
        normalize_path_lexically(workspace_root.join(raw))
    }
}

/// Discovers the git repository containing `abs_path` and computes the
/// repository-relative path used to look it up inside a revision tree. Shared
/// by [`read_git_file`] and [`git_history_path_is_file`] so both consult the
/// same repo-discovery/canonicalization rules.
fn discover_history_repo_relative_path(abs_path: &Path) -> Result<(Repository, PathBuf), String> {
    if !abs_path.is_absolute() {
        return Err(format!(
            "git history path must be absolute after resolution: {}",
            abs_path.display()
        ));
    }

    let discover_from = nearest_existing_ancestor(abs_path).ok_or_else(|| {
        format!(
            "path is not in any git repository because no existing ancestor could be found: {}",
            abs_path.display()
        )
    })?;
    let repo = Repository::discover(&discover_from).map_err(|err| {
        format!(
            "path is not in any git repository: {} ({err})",
            abs_path.display()
        )
    })?;
    let workdir = repo.workdir().ok_or_else(|| {
        format!(
            "git repository has no working tree: {}",
            repo.path().display()
        )
    })?;

    let canonical_workdir = workdir.canonicalize().map_err(|err| {
        format!(
            "unable to canonicalize git workdir {}: {err}",
            workdir.display()
        )
    })?;
    let canonical_abs = canonicalize_allow_missing(abs_path)?;
    let repo_rel = canonical_abs
        .strip_prefix(&canonical_workdir)
        .map_err(|_| {
            format!(
                "path is outside discovered git workdir: {} (workdir: {})",
                abs_path.display(),
                canonical_workdir.display()
            )
        })?
        .to_path_buf();
    Ok((repo, repo_rel))
}

/// Structured existence probe for the `#`-split boundary search in
/// `split_git_history_source_selector` (bifrost#1216): a committed filename
/// may itself contain `#` (e.g. `Foo.VerifyGeneratedCode#01.verified.cs`), so
/// the CLI selector parser walks candidate anchors and needs to know which
/// ones actually name a blob at `rev`. Unlike [`read_git_file`] this never
/// reads blob content and never errors — any failure to discover the repo,
/// resolve the revision, or find the path simply means "not a file", which is
/// exactly what the caller needs to move on to the next candidate.
pub fn git_history_path_is_file(rev: &str, abs_path: &Path) -> bool {
    let Ok((repo, repo_rel)) = discover_history_repo_relative_path(abs_path) else {
        return false;
    };
    let Ok(object) = repo.revparse_single(rev) else {
        return false;
    };
    let Ok(commit) = object.peel_to_commit() else {
        return false;
    };
    let Ok(tree) = commit.tree() else {
        return false;
    };
    matches!(
        tree.get_path(&repo_rel).ok().and_then(|entry| entry.kind()),
        Some(ObjectType::Blob)
    )
}

pub fn read_git_file(rev: &str, abs_path: &Path) -> Result<String, String> {
    let (repo, repo_rel) = discover_history_repo_relative_path(abs_path)?;

    let object = repo
        .revparse_single(rev)
        .map_err(|err| format!("bad git revision `{rev}`: {err}"))?;
    let commit = object
        .peel_to_commit()
        .map_err(|err| format!("git revision `{rev}` is not a commit: {err}"))?;
    let tree = commit
        .tree()
        .map_err(|err| format!("unable to read tree for git revision `{rev}`: {err}"))?;
    let entry = tree.get_path(&repo_rel).map_err(|err| {
        format!(
            "path `{}` is absent at git revision `{rev}`: {err}",
            repo_rel.display()
        )
    })?;
    if entry.kind() != Some(ObjectType::Blob) {
        return Err(format!(
            "path `{}` at git revision `{rev}` is not a file blob",
            repo_rel.display()
        ));
    }
    let blob = repo.find_blob(entry.id()).map_err(|err| {
        format!(
            "unable to read blob `{}` at git revision `{rev}`: {err}",
            repo_rel.display()
        )
    })?;
    if blob.is_binary() {
        return Err(format!(
            "path `{}` at git revision `{rev}` is binary and cannot be returned as text",
            repo_rel.display()
        ));
    }
    // Non-UTF8 text (legacy encodings like Windows-1252/GBK) passes the binary
    // check above; convert lossily so pinned-revision reads tolerate the same
    // files a live session does instead of failing session startup.
    Ok(String::from_utf8_lossy(blob.content()).into_owned())
}

pub fn list_git_files_at_revision(
    workspace_root: &Path,
    rev: &str,
) -> Result<Vec<PathBuf>, String> {
    let canonical_root = workspace_root.canonicalize().map_err(|err| {
        format!(
            "unable to canonicalize workspace root {}: {err}",
            workspace_root.display()
        )
    })?;
    let repo = Repository::discover(&canonical_root).map_err(|err| {
        format!(
            "workspace root is not in any git repository: {} ({err})",
            workspace_root.display()
        )
    })?;
    let workdir = repo.workdir().ok_or_else(|| {
        format!(
            "git repository has no working tree: {}",
            repo.path().display()
        )
    })?;
    let canonical_workdir = workdir.canonicalize().map_err(|err| {
        format!(
            "unable to canonicalize git workdir {}: {err}",
            workdir.display()
        )
    })?;
    let workspace_repo_rel = canonical_root
        .strip_prefix(&canonical_workdir)
        .map_err(|_| {
            format!(
                "workspace root is outside discovered git workdir: {} (workdir: {})",
                workspace_root.display(),
                canonical_workdir.display()
            )
        })?;

    let object = repo
        .revparse_single(rev)
        .map_err(|err| format!("bad git revision `{rev}`: {err}"))?;
    let commit = object
        .peel_to_commit()
        .map_err(|err| format!("git revision `{rev}` is not a commit: {err}"))?;
    let tree = commit
        .tree()
        .map_err(|err| format!("unable to read tree for git revision `{rev}`: {err}"))?;

    let root_tree = if workspace_repo_rel.as_os_str().is_empty() {
        tree
    } else {
        let entry = tree.get_path(workspace_repo_rel).map_err(|err| {
            format!(
                "workspace root `{}` is absent at git revision `{rev}`: {err}",
                workspace_repo_rel.display()
            )
        })?;
        if entry.kind() != Some(ObjectType::Tree) {
            return Err(format!(
                "workspace root `{}` at git revision `{rev}` is not a tree",
                workspace_repo_rel.display()
            ));
        }
        repo.find_tree(entry.id()).map_err(|err| {
            format!(
                "unable to read workspace tree `{}` at git revision `{rev}`: {err}",
                workspace_repo_rel.display()
            )
        })?
    };

    let mut files = Vec::new();
    let mut stack = vec![(PathBuf::new(), root_tree)];
    while let Some((prefix, tree)) = stack.pop() {
        for entry in &tree {
            let Some(name) = entry.name() else {
                continue;
            };
            let rel = prefix.join(name);
            match entry.kind() {
                Some(ObjectType::Blob) => files.push(rel),
                Some(ObjectType::Tree) => {
                    let child = repo.find_tree(entry.id()).map_err(|err| {
                        format!(
                            "unable to read tree `{}` at git revision `{rev}`: {err}",
                            rel.display()
                        )
                    })?;
                    stack.push((rel, child));
                }
                _ => {}
            }
        }
    }
    files.sort();
    Ok(files)
}

fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    start
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .map(Path::to_path_buf)
}

fn canonicalize_allow_missing(path: &Path) -> Result<PathBuf, String> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }

    let existing = nearest_existing_ancestor(path).ok_or_else(|| {
        format!(
            "unable to canonicalize {} because no existing ancestor could be found",
            path.display()
        )
    })?;
    let canonical_existing = existing
        .canonicalize()
        .map_err(|err| format!("unable to canonicalize {}: {err}", existing.display()))?;
    let suffix = path.strip_prefix(&existing).map_err(|_| {
        format!(
            "unable to compute missing suffix for {} from {}",
            path.display(),
            existing.display()
        )
    })?;
    Ok(normalize_path_lexically(canonical_existing.join(suffix)))
}

fn normalize_path_lexically(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
}
