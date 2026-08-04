//! Go import resolution: how an `import "path"` line binds to workspace files
//! and to a local package name.
//!
//! The `ImportAnalysisProvider` impl itself stays in `brokk-bifrost-analysis`
//! because it is memoized on `GoMemoCaches` (moka, deliberately kept out of
//! this crate and out of core). Everything it memoizes is computed here from a
//! [`CodeUnitIndex`], a [`GoWorkspacePathIndex`], and an explicit file list.

use crate::packages::{GoWorkspacePathIndex, canonical_go_package_name};
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use regex::Regex;
use std::sync::{Arc, LazyLock};

static VERSION_SUFFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.v\d+$").expect("valid Go module version suffix regex"));

/// The local name an unaliased Go import binds to: the path's last component,
/// with a `.vN` module-version suffix stripped.
pub fn default_go_import_local_name(import_path_or_identifier: &str) -> String {
    let tail = import_path_or_identifier
        .rsplit('/')
        .next()
        .unwrap_or(import_path_or_identifier);
    VERSION_SUFFIX_RE.replace(tail, "").to_string()
}

/// The quoted import path out of a raw `import ...` snippet.
pub fn extract_go_import_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim();
    trimmed
        .split_whitespace()
        .next_back()
        .map(|path| {
            path.trim_matches('"')
                .trim_matches('`')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|path| !path.is_empty())
}

/// Legacy directory-suffix import match, used only as a fallback when no
/// declaration's canonical package equals the import path (module-less or
/// vendored layouts).
pub fn dir_suffix_matches(candidate: &ProjectFile, path: &str) -> bool {
    let parent = parent_path_key(candidate);
    parent == path || path.ends_with(&format!("/{parent}")) || parent.ends_with(&format!("/{path}"))
}

pub fn parent_path_key(file: &ProjectFile) -> String {
    file.parent().to_string_lossy().replace('\\', "/")
}

pub fn path_suffixes(path: &str) -> impl Iterator<Item = &str> {
    let mut suffixes = Vec::new();
    suffixes.push(path);
    suffixes.extend(
        path.match_indices('/')
            .map(|(index, _)| &path[index + 1..])
            .filter(|suffix| !suffix.is_empty()),
    );
    suffixes.into_iter()
}

/// Canonical package identity (import path) of a file, taken from any of its
/// declarations. `None` for files with no top-level declarations.
pub fn go_package_of(index: &dyn CodeUnitIndex, file: &ProjectFile) -> Option<String> {
    index
        .top_level_declarations(file)
        .into_iter()
        .next()
        .map(|unit| unit.package_name().to_string())
}

/// Files grouped by their canonical Go package (import path).
pub fn build_go_package_files(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
) -> HashMap<String, Arc<Vec<ProjectFile>>> {
    let mut files_by_package: HashMap<String, Vec<ProjectFile>> = HashMap::default();
    for file in files {
        if let Some(package) = go_package_of(index, file) {
            files_by_package
                .entry(package)
                .or_default()
                .push(file.clone());
        }
    }
    files_by_package
        .into_iter()
        .map(|(package, files)| (package, Arc::new(files)))
        .collect()
}

/// Go files grouped by their parent directory path.
pub fn build_go_dir_parent_files(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
) -> HashMap<String, Arc<Vec<ProjectFile>>> {
    let mut files_by_parent: HashMap<String, Vec<ProjectFile>> = HashMap::default();
    for file in files {
        if go_package_of(index, file).is_none() {
            continue;
        }
        files_by_parent
            .entry(parent_path_key(file))
            .or_default()
            .push(file.clone());
    }
    files_by_parent
        .into_iter()
        .map(|(parent, files)| (parent, Arc::new(files)))
        .collect()
}

/// Go files grouped by every path suffix of their parent directory.
pub fn build_go_dir_parent_suffix_files(
    index: &dyn CodeUnitIndex,
    files: &[ProjectFile],
) -> HashMap<String, Arc<Vec<ProjectFile>>> {
    let mut files_by_suffix: HashMap<String, Vec<ProjectFile>> = HashMap::default();
    for file in files {
        if go_package_of(index, file).is_none() {
            continue;
        }
        for suffix in path_suffixes(&parent_path_key(file)) {
            files_by_suffix
                .entry(suffix.to_string())
                .or_default()
                .push(file.clone());
        }
    }
    files_by_suffix
        .into_iter()
        .map(|(suffix, files)| (suffix, Arc::new(files)))
        .collect()
}

/// The prebuilt import-resolution tables an `ImportAnalysisProvider` memoizes.
///
/// Grouping the three maps keeps the free functions below from taking the same
/// three arguments each; every field is data the caller already owns.
pub struct GoImportTables<'a> {
    pub package_files: &'a HashMap<String, Arc<Vec<ProjectFile>>>,
    pub dir_parent_files: &'a HashMap<String, Arc<Vec<ProjectFile>>>,
    pub dir_parent_suffix_files: &'a HashMap<String, Arc<Vec<ProjectFile>>>,
}

/// Files that `import_path` resolves to from `source_file`.
///
/// Prefers exact canonical-package identity: with a `go.mod` present a
/// package's `package_name` is its import path, so this is unambiguous. Falls
/// back to the directory-suffix heuristic only when no canonical package
/// matches (module-less or vendored layouts).
pub fn go_matching_import_files(
    tables: &GoImportTables<'_>,
    source_file: &ProjectFile,
    import_path: &str,
) -> Vec<ProjectFile> {
    if let Some(files) = tables.package_files.get(import_path) {
        let exact: Vec<_> = files
            .iter()
            .filter(|candidate| *candidate != source_file)
            .cloned()
            .collect();
        if !exact.is_empty() {
            return exact;
        }
    }

    let mut seen = HashSet::default();
    let mut matching = Vec::new();
    for suffix in path_suffixes(import_path) {
        if let Some(files) = tables.dir_parent_files.get(suffix) {
            for candidate in files.iter() {
                if candidate != source_file && seen.insert(candidate.clone()) {
                    matching.push(candidate.clone());
                }
            }
        }
    }
    if let Some(files) = tables.dir_parent_suffix_files.get(import_path) {
        for candidate in files.iter() {
            if candidate != source_file && seen.insert(candidate.clone()) {
                matching.push(candidate.clone());
            }
        }
    }
    matching
}

/// The fallback behind [`go_matching_import_files`]: every file sharing a
/// directory with a workspace-path hit. Callers reach for this only when the
/// package and suffix tables both come back empty, so `files` -- the whole
/// analyzed file list -- stays off the common path.
pub fn go_directory_sibling_import_files(
    workspace_paths: &GoWorkspacePathIndex,
    files: &[ProjectFile],
    source_file: &ProjectFile,
    import_path: &str,
) -> Vec<ProjectFile> {
    let directories: HashSet<_> = workspace_paths
        .import_files(source_file, import_path)
        .into_iter()
        .map(|file| file.parent())
        .collect();
    files
        .iter()
        .filter(|file| *file != source_file && directories.contains(&file.parent()))
        .cloned()
        .collect()
}

/// Every non-module top-level declaration `file`'s imports bring into scope.
pub fn go_imported_code_units_of(
    index: &dyn CodeUnitIndex,
    tables: &GoImportTables<'_>,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<CodeUnit> {
    let mut resolved = HashSet::default();
    for import in imports {
        if import.alias.as_deref() == Some("_") {
            continue;
        }
        let Some(path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        for target_file in go_matching_import_files(tables, file, &path) {
            resolved.extend(
                index
                    .top_level_declarations(&target_file)
                    .into_iter()
                    .filter(|code_unit| !code_unit.is_module()),
            );
        }
    }
    resolved
}

/// The subset of `imports` whose bound token appears in `source`, plus every
/// dot import (which binds names the source never spells with a qualifier).
pub fn go_relevant_imports_for(source: &str, imports: &[ImportInfo]) -> HashSet<String> {
    let mut relevant = HashSet::default();
    for import in imports {
        if import.alias.as_deref() == Some("_") {
            continue;
        }

        let token = import
            .alias
            .as_ref()
            .filter(|alias| alias.as_str() != ".")
            .cloned()
            .or_else(|| import.identifier.clone())
            .unwrap_or_default();
        if token.is_empty() || source.contains(&token) || import.alias.as_deref() == Some(".") {
            relevant.insert(import.raw_snippet.clone());
        }
    }
    relevant
}

/// Resolve only `file`'s namespace from persisted import and package facts.
///
/// This deliberately avoids the whole-workspace package graph used by bulk
/// usage analysis. `package_clause_of` reports a file's declared `package`
/// clause, which only the persisting analyzer can answer, so it arrives as a
/// caller-supplied lookup rather than through a trait.
pub fn go_definition_import_namespaces(
    index: &dyn CodeUnitIndex,
    workspace_paths: &GoWorkspacePathIndex,
    package_clause_of: impl Fn(&ProjectFile) -> Option<String>,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> (HashMap<String, Vec<String>>, Vec<String>) {
    let mut by_alias: HashMap<String, Vec<String>> = HashMap::default();
    let mut dot_imports = Vec::new();
    for import in imports {
        let alias = import.alias.as_deref();
        if alias == Some("_") {
            continue;
        }
        let Some(path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        let vendor_suffix = format!("/vendor/{path}");
        let mut packages: Vec<String> = workspace_paths
            .import_files(file, &path)
            .into_iter()
            .filter(|target| index.is_analyzed(target))
            .filter_map(|target| {
                let declared = package_clause_of(&target)?;
                Some(canonical_go_package_name(&target, &declared))
            })
            .filter(|package| package == &path || package.ends_with(&vendor_suffix))
            .collect();
        packages.sort();
        packages.dedup();
        if packages.is_empty() {
            // Preserve the source import path for packages outside the
            // indexed workspace so callers can report an import boundary.
            packages.push(path.clone());
        }
        match alias {
            Some(".") => dot_imports.extend(packages),
            Some(explicit) => by_alias
                .entry(explicit.to_string())
                .or_default()
                .extend(packages),
            None => {
                let local = workspace_paths
                    .import_files(file, &path)
                    .into_iter()
                    .filter(|candidate| index.is_analyzed(candidate))
                    .find_map(|candidate| package_clause_of(&candidate))
                    .filter(|package| !package.is_empty())
                    .or_else(|| import.identifier.clone())
                    .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(&path).to_string());
                by_alias.entry(local).or_default().extend(packages);
            }
        }
    }
    for packages in by_alias.values_mut() {
        packages.sort();
        packages.dedup();
    }
    dot_imports.sort();
    dot_imports.dedup();
    (by_alias, dot_imports)
}
