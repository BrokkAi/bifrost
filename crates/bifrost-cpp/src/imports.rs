//! `#include` parsing and the workspace-wide include-target index.
//!
//! `analyzer/cpp/imports.rs` in `brokk-bifrost-analysis` keeps the
//! `ImportAnalysisProvider` / `TestDetectionProvider` impls and the `OnceLock` /
//! `PoolSafeMemo` cells that memoize [`IncludeTargetIndex`] and the reverse
//! include map on the analyzer; every decision they make is a function here.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Workspace-wide resolution table for `#include` targets: every analyzable file
/// keyed both by its full workspace-relative path and by its bare file name.
///
/// Built once per analyzer generation from `all_files()` and consulted by every
/// include-visibility walk, so a header's dependents resolve without a
/// filesystem probe per include line.
pub struct IncludeTargetIndex {
    by_rel_path: HashMap<PathBuf, Vec<ProjectFile>>,
    by_file_name: HashMap<String, Vec<ProjectFile>>,
}

impl IncludeTargetIndex {
    pub fn build<'a>(files: impl IntoIterator<Item = &'a ProjectFile>) -> Self {
        let mut by_rel_path: HashMap<PathBuf, Vec<ProjectFile>> = HashMap::default();
        let mut by_file_name: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for file in files {
            by_rel_path
                .entry(file.rel_path().to_path_buf())
                .or_default()
                .push(file.clone());
            if let Some(file_name) = file.rel_path().file_name().and_then(|value| value.to_str()) {
                by_file_name
                    .entry(file_name.to_string())
                    .or_default()
                    .push(file.clone());
            }
        }
        Self {
            by_rel_path,
            by_file_name,
        }
    }

    pub fn resolve_indexed(&self, include: &str) -> Vec<ProjectFile> {
        let include_path = Path::new(include);
        let mut matched = HashSet::default();
        let mut resolved = Vec::new();
        if let Some(targets) = self.by_rel_path.get(include_path) {
            for target in targets {
                if matched.insert(target.clone()) {
                    resolved.push(target.clone());
                }
            }
        }
        for suffix in string_suffixes(include) {
            if let Some(targets) = self.by_file_name.get(suffix) {
                for target in targets {
                    if matched.insert(target.clone()) {
                        resolved.push(target.clone());
                    }
                }
            }
        }
        resolved
    }

    fn resolve_direct(&self, source_file: &ProjectFile, include: &str) -> Vec<ProjectFile> {
        let include_path = Path::new(include);
        let mut matched = HashSet::default();
        let mut resolved = Vec::new();
        if include_path.is_absolute() {
            if let Some(rel_path) = project_relative_include_path(source_file.root(), include_path)
            {
                self.extend_rel_path(&rel_path, &mut matched, &mut resolved);
            }
            return resolved;
        }

        let source_relative = ProjectFile::new(
            source_file.root().to_path_buf(),
            source_file.parent().join(include_path),
        );
        self.extend_rel_path(source_relative.rel_path(), &mut matched, &mut resolved);

        let project_relative =
            ProjectFile::new(source_file.root().to_path_buf(), include_path.to_path_buf());
        self.extend_rel_path(project_relative.rel_path(), &mut matched, &mut resolved);
        resolved
    }

    fn extend_rel_path(
        &self,
        rel_path: &Path,
        matched: &mut HashSet<ProjectFile>,
        out: &mut Vec<ProjectFile>,
    ) {
        if let Some(targets) = self.by_rel_path.get(rel_path) {
            for target in targets {
                if matched.insert(target.clone()) {
                    out.push(target.clone());
                }
            }
        }
    }

    fn resolve_unique_fallback(&self, include: &str) -> Vec<ProjectFile> {
        let include_path = Path::new(include);
        let matches: Vec<_> = self
            .resolve_indexed(include)
            .into_iter()
            .filter(|file| {
                if include_path.components().count() > 1 {
                    file.rel_path().ends_with(include_path)
                } else {
                    file.rel_path()
                        .file_name()
                        .is_some_and(|name| name == include_path)
                }
            })
            .collect();
        if matches.len() == 1 {
            matches
        } else {
            Vec::new()
        }
    }
}

fn string_suffixes(value: &str) -> impl Iterator<Item = &str> {
    value.char_indices().map(|(index, _)| &value[index..])
}

pub fn parse_quoted_include(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let quote_start = trimmed.find('"')?;
    let quote_end = trimmed[quote_start + 1..].find('"')?;
    Some(trimmed[quote_start + 1..quote_start + 1 + quote_end].to_string())
}

pub fn parse_include_path(line: &str) -> Option<String> {
    if let Some(path) = parse_quoted_include(line) {
        return Some(path);
    }
    let trimmed = line.trim();
    let angle_start = trimmed.find('<')?;
    let angle_end = trimmed[angle_start + 1..].find('>')?;
    Some(trimmed[angle_start + 1..angle_start + 1 + angle_end].to_string())
}

pub fn resolve_include_targets(
    project: &dyn Project,
    source_file: &ProjectFile,
    include: &str,
) -> Vec<ProjectFile> {
    let mut candidates = Vec::new();
    let include_path = Path::new(include);
    let source_root = project.root().to_path_buf();
    let relative_path = if include_path.is_absolute() {
        match project_relative_include_path(project.root(), include_path) {
            Some(path) => path,
            None => return candidates,
        }
    } else {
        source_file.parent().join(include_path)
    };
    let relative_file = ProjectFile::new(source_root.clone(), relative_path);
    if relative_file.exists() {
        candidates.push(relative_file);
    }
    if !include_path.is_absolute() {
        let project_relative_file = ProjectFile::new(source_root.clone(), include_path);
        if project_relative_file.exists() {
            candidates.push(project_relative_file);
        }
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

pub fn resolve_include_targets_with_index(
    source_file: &ProjectFile,
    include: &str,
    include_targets: &IncludeTargetIndex,
) -> Vec<ProjectFile> {
    let mut candidates = include_targets.resolve_direct(source_file, include);
    if !candidates.is_empty() {
        return candidates;
    }
    if Path::new(include).is_absolute() {
        return candidates;
    }
    candidates.extend(include_targets.resolve_unique_fallback(include));
    candidates
}

pub fn resolve_direct_include_targets_with_index(
    source_file: &ProjectFile,
    include: &str,
    include_targets: &IncludeTargetIndex,
) -> Vec<ProjectFile> {
    include_targets.resolve_direct(source_file, include)
}

fn project_relative_include_path(project_root: &Path, include_path: &Path) -> Option<PathBuf> {
    let canonical_root = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    let canonical_include = include_path
        .canonicalize()
        .unwrap_or_else(|_| include_path.to_path_buf());
    canonical_include
        .strip_prefix(&canonical_root)
        .map(Path::to_path_buf)
        .or_else(|_| {
            include_path
                .strip_prefix(project_root)
                .map(Path::to_path_buf)
        })
        .ok()
        .or_else(|| lexical_project_relative_include_path(&canonical_root, &canonical_include))
        .or_else(|| lexical_project_relative_include_path(project_root, include_path))
}

/// The claim edges `sources` contribute: for each source file, the workspace
/// files it pulls in by quoted `#include` that no language's extension registry
/// claims (#1837).
///
/// `sources` pairs each already-analyzed C++ file with the `ImportInfo` rows
/// recorded for it; `claimable` is the caller's set of workspace files with an
/// extension no language owns. `abseil`'s `.inc` translation-unit fragments are
/// the motivating case: nothing indexes them today, so every declaration they
/// hold is invisible in both directions.
///
/// Only quoted includes participate. An angled include names a search path the
/// analyzer does not model, so resolving one against workspace file names would
/// claim files the compiler would never reach.
///
/// Edges rather than a flat set, because the caller both closes the relation
/// transitively and drops a claim when the last `#include` naming it goes away;
/// both need to know which source contributed which target. A source with no
/// claimable include contributes no entry.
///
/// The result depends only on `sources`, `claimable` and the resolution rules
/// in this module -- never on the order either collection arrives in.
pub fn included_claimable_files(
    sources: &[(ProjectFile, Vec<ImportInfo>)],
    claimable: &BTreeSet<ProjectFile>,
) -> HashMap<ProjectFile, BTreeSet<ProjectFile>> {
    let mut edges: HashMap<ProjectFile, BTreeSet<ProjectFile>> = HashMap::default();
    if claimable.is_empty() || sources.is_empty() {
        return edges;
    }
    let index = IncludeTargetIndex::build(claimable.iter());
    for (source_file, imports) in sources {
        let mut targets = BTreeSet::new();
        for include in imports
            .iter()
            .filter_map(|import| parse_quoted_include(&import.raw_snippet))
        {
            targets.extend(resolve_include_targets_with_index(
                source_file,
                &include,
                &index,
            ));
        }
        if !targets.is_empty() {
            edges.insert(source_file.clone(), targets);
        }
    }
    edges
}

pub fn quoted_include_paths(parsed: &[String]) -> Vec<String> {
    parsed
        .iter()
        .filter_map(|line| parse_quoted_include(line))
        .collect()
}

pub fn include_paths(parsed: &[String]) -> Vec<String> {
    parsed
        .iter()
        .filter_map(|line| parse_include_path(line))
        .collect()
}

/// The capitalized identifiers a C++ source mentions, used to decide which of a
/// declaration's `#include` lines are relevant to it.
///
/// Deliberately lexical, and the only place in this crate that is: the input is
/// a rendered source excerpt whose enclosing translation unit is not available
/// to parse, and the output feeds a *filter* over already-resolved includes, so
/// an over-broad token set costs recall on the filter rather than inventing a
/// declaration. Every fleet language has this same shape
/// (`brokk_bifrost_python::graph_support::extract_type_identifiers` is the
/// closest sibling).
pub fn extract_type_identifiers(source: &str) -> BTreeSet<String> {
    static IDENT_RE: OnceLock<Regex> = OnceLock::new();
    let regex =
        IDENT_RE.get_or_init(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_:<>]*").expect("valid regex"));
    regex
        .find_iter(source)
        .map(|m| m.as_str())
        .filter(|token| {
            token
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_uppercase())
        })
        .map(|token| token.trim_matches(':').to_string())
        .collect()
}

/// Whether the structural receiver queries apply to `file`.
///
/// `Language::Cpp` also covers plain `.c`, which has no member-call receivers
/// for those queries to resolve, so the route is gated on the extension.
pub fn receiver_query_supported(file: &ProjectFile) -> bool {
    file.rel_path()
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("c")
}

fn lexical_project_relative_include_path(
    project_root: &Path,
    include_path: &Path,
) -> Option<PathBuf> {
    let root = slash_path(project_root);
    let include = slash_path(include_path);
    strip_slash_prefix(&include, &root).map(PathBuf::from)
}

fn slash_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let raw = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    raw.replace('\\', "/").trim_end_matches('/').to_string()
}

#[cfg(windows)]
fn strip_slash_prefix<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if path.eq_ignore_ascii_case(root) {
        return Some("");
    }
    if path.len() > root.len()
        && path.as_bytes().get(root.len()) == Some(&b'/')
        && path[..root.len()].eq_ignore_ascii_case(root)
    {
        return Some(&path[root.len() + 1..]);
    }
    None
}

#[cfg(not(windows))]
fn strip_slash_prefix<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if path == root {
        return Some("");
    }
    path.strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_file(root: &Path, rel: &str) -> ProjectFile {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("test file has parent")).unwrap();
        fs::write(&path, "").unwrap();
        ProjectFile::new(root.to_path_buf(), rel)
    }

    #[test]
    fn indexed_include_resolution_uses_unique_suffix_fallback() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = write_file(&root, "src/lib.c");
        let target = write_file(&root, "include/git2/sys/credential.h");
        let duplicate = write_file(&root, "vendor/credential.h");
        let index = IncludeTargetIndex::build([&source, &target, &duplicate]);

        let resolved = resolve_include_targets_with_index(&source, "git2/sys/credential.h", &index);
        assert_eq!(resolved, vec![target]);

        let ambiguous = resolve_include_targets_with_index(&source, "credential.h", &index);
        assert!(ambiguous.is_empty());
    }
}
