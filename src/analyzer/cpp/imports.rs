use super::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

impl TestDetectionProvider for CppAnalyzer {}

impl ImportAnalysisProvider for CppAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let mut resolved = HashSet::default();
        for path in quoted_include_paths(self.inner.import_statements(file)) {
            for target in resolve_include_targets(self.inner.project(), file, &path) {
                resolved.extend(self.inner.top_level_declarations(&target).cloned());
            }
        }

        self.imported_code_units
            .insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }

        let file_name = file.rel_path().file_name().and_then(|value| value.to_str());
        let mut references = HashSet::default();
        for candidate in self.inner.all_files() {
            if candidate == file {
                continue;
            }
            if quoted_include_paths(self.inner.import_statements(candidate))
                .iter()
                .any(|include| {
                    file.rel_path() == Path::new(include)
                        || file_name.is_some_and(|name| include.ends_with(name))
                })
            {
                references.insert(candidate.clone());
            }
        }

        self.referencing_files
            .insert(file.clone(), Arc::new(references.clone()));
        references
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        let source = code_unit.source();
        let identifiers = self
            .extract_type_identifiers(&self.inner.get_source(code_unit, true).unwrap_or_default());
        self.inner
            .import_statements(source)
            .iter()
            .filter(|line| {
                parse_quoted_include(line).is_some_and(|path| {
                    let stem = Path::new(&path)
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("");
                    identifiers.contains(stem)
                })
            })
            .cloned()
            .collect()
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let target_name = target
            .rel_path()
            .file_name()
            .and_then(|value| value.to_str());
        imports.iter().any(|import| {
            parse_quoted_include(&import.raw_snippet).is_some_and(|include| {
                target.rel_path() == Path::new(&include)
                    || target_name.is_some_and(|name| include.ends_with(name))
                    || source_file.parent().join(&include) == target.rel_path()
            })
        })
    }
}

pub(crate) fn parse_quoted_include(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let quote_start = trimmed.find('"')?;
    let quote_end = trimmed[quote_start + 1..].find('"')?;
    Some(trimmed[quote_start + 1..quote_start + 1 + quote_end].to_string())
}

pub(crate) fn resolve_include_targets(
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

    candidates.sort();
    candidates.dedup();
    candidates
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

pub(crate) fn quoted_include_paths(parsed: &[String]) -> Vec<String> {
    parsed
        .iter()
        .filter_map(|line| parse_quoted_include(line))
        .collect()
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
