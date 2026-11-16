//! The one relation between a batch of changed workspace paths and a path a
//! derived product depends on (#12435).
//!
//! A change event can name a directory instead of the files below it: a
//! directory deletion or replacement may name only the directory (see
//! `resolve_update_paths_with_refresh`). So a changed path `c` touches a
//! protected path `p` when `c` equals `p`, when `c` is an ancestor of `p`, or
//! when `c` lies inside `p`. Both comparisons are component-wise `Path`
//! relations, never string prefixes: `.bifrost2` does not touch `.bifrost`.
//!
//! The relation fails closed on spelling. A changed spelling is certified
//! only when it is a member of the exact post-update workspace listing. Any
//! other spelling (a deleted path, a directory, an ignored or omitted entry,
//! or an alias) is compared a second time with case folded, and a spelling
//! whose existing ancestors include a symlink touches every protected path,
//! because the project cannot say which file the link reached.

use super::model::ProjectFile;
use super::project::Project;
use std::collections::{BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct ChangedPaths {
    /// Every changed spelling, sorted by `Path` order, which is component-wise.
    exact: Vec<PathBuf>,
    /// The case-folded uncertified spellings, sorted the same way.
    folded: Vec<PathBuf>,
    /// An uncertified spelling reached through a symlink or an unreadable entry.
    unprovable: bool,
}

impl ChangedPaths {
    /// Compare every spelling exactly and with case folded. For a consumer
    /// that has no project view to certify spellings against, and whose
    /// protected paths are canonical constants: no spelling is certified, so a
    /// case alias of a protected path counts as touching it.
    pub fn literal<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Self {
        let exact = sorted_unique(paths.into_iter().map(Path::to_path_buf).collect());
        let folded = sorted_unique(exact.iter().map(|path| fold_case(path)).collect());
        Self {
            exact,
            folded,
            unprovable: false,
        }
    }

    /// Certify each changed spelling against the exact post-update `listed`
    /// membership of `project`, and refuse any spelling it cannot certify.
    pub fn certified_against<'a>(
        project: &dyn Project,
        listed: &BTreeSet<ProjectFile>,
        changed: impl IntoIterator<Item = &'a ProjectFile>,
    ) -> Self {
        let mut exact = Vec::new();
        let mut folded = Vec::new();
        let mut unprovable = false;
        let mut real_directories = HashSet::new();
        for file in changed {
            exact.push(file.rel_path().to_path_buf());
            if listed.contains(file) {
                continue;
            }
            folded.push(fold_case(file.rel_path()));
            unprovable |=
                !reaches_no_symlink(project.root(), file.rel_path(), &mut real_directories);
        }
        Self {
            exact: sorted_unique(exact),
            folded: sorted_unique(folded),
            unprovable,
        }
    }

    /// Whether `protected` equals, contains or lies inside a changed path, or
    /// an uncertified spelling could name it.
    pub fn touches(&self, protected: &Path) -> bool {
        self.unprovable
            || related(&self.exact, protected)
            || (!self.folded.is_empty() && related(&self.folded, &fold_case(protected)))
    }
}

fn sorted_unique(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort_unstable();
    paths.dedup();
    paths
}

/// `Path` order is component-wise, so every path inside `protected` follows it
/// contiguously, and every ancestor is found by exact search.
fn related(sorted: &[PathBuf], protected: &Path) -> bool {
    let first_not_before = sorted.partition_point(|changed| changed.as_path() < protected);
    sorted
        .get(first_not_before)
        .is_some_and(|changed| changed.starts_with(protected))
        || protected
            .ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty())
            .any(|ancestor| {
                sorted
                    .binary_search_by(|changed| changed.as_path().cmp(ancestor))
                    .is_ok()
            })
}

fn fold_case(path: &Path) -> PathBuf {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => PathBuf::from(name.to_string_lossy().to_lowercase()),
            other => PathBuf::from(other.as_os_str()),
        })
        .collect()
}

/// True when no existing ancestor-or-self of `rel_path` is a symlink and every
/// existing entry could be inspected. The walk stops at the first missing
/// component: nothing below it exists to alias another path.
fn reaches_no_symlink(root: &Path, rel_path: &Path, clean: &mut HashSet<PathBuf>) -> bool {
    let mut prefix = PathBuf::new();
    for component in rel_path.components() {
        prefix.push(component);
        if clean.contains(&prefix) {
            continue;
        }
        match std::fs::symlink_metadata(root.join(&prefix)) {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {
                clean.insert(prefix.clone());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return true;
            }
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_is_component_wise_in_both_directions() {
        let changed = ChangedPaths::literal(
            [Path::new("docs"), Path::new("src/a/B.java")]
                .iter()
                .copied(),
        );
        // A changed directory contains the protected path; a changed file is the protected path.
        assert!(changed.touches(Path::new("docs/guide/x.md")));
        assert!(changed.touches(Path::new("src/a/B.java")));
        // A changed path inside a protected directory.
        assert!(changed.touches(Path::new("src")));
        assert!(changed.touches(Path::new("src/a")));
        // A shared string prefix is not a shared component.
        assert!(!changed.touches(Path::new("doc")));
        assert!(!changed.touches(Path::new("docs2/x")));
        assert!(!changed.touches(Path::new("src/a/B.java.orig")));
        assert!(!changed.touches(Path::new("src/c")));
    }
}
