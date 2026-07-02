use git2::{ObjectType, Repository};
use std::path::{Component, Path, PathBuf};

pub(crate) fn parse_rev_path(input: &str) -> Option<(&str, &str)> {
    let (rev, path) = input.split_once(':')?;
    if rev.is_empty() || path.is_empty() {
        return None;
    }
    Some((rev, path))
}

pub(crate) fn resolve_git_file_path(path: &str, workspace_root: &Path) -> PathBuf {
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

pub(crate) fn read_git_file(rev: &str, abs_path: &Path) -> Result<String, String> {
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
    let entry = tree.get_path(repo_rel).map_err(|err| {
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
    std::str::from_utf8(blob.content())
        .map(str::to_owned)
        .map_err(|err| {
            format!(
                "path `{}` at git revision `{rev}` is not valid UTF-8: {err}",
                repo_rel.display()
            )
        })
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
