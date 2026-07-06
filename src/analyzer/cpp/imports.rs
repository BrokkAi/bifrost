use super::*;
use crate::analyzer::build_reverse_file_index;
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

        let references = self
            .reverse_include_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();

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

impl CppAnalyzer {
    fn reverse_include_index(&self) -> &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        self.reverse_include_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            let mut by_rel_path: HashMap<PathBuf, Vec<ProjectFile>> = HashMap::default();
            let mut by_file_name: HashMap<String, Vec<ProjectFile>> = HashMap::default();
            for file in &files {
                by_rel_path
                    .entry(file.rel_path().to_path_buf())
                    .or_default()
                    .push(file.clone());
                if let Some(file_name) =
                    file.rel_path().file_name().and_then(|value| value.to_str())
                {
                    by_file_name
                        .entry(file_name.to_string())
                        .or_default()
                        .push(file.clone());
                }
            }

            build_reverse_file_index(&files, |candidate| {
                let mut matched_targets = HashSet::default();
                let mut resolved_targets = Vec::new();
                for include in quoted_include_paths(self.inner.import_statements(candidate)) {
                    if let Some(path_targets) = by_rel_path.get(Path::new(&include)) {
                        for target in path_targets {
                            if matched_targets.insert(target.clone()) {
                                resolved_targets.push(target.clone());
                            }
                        }
                    }
                    for suffix in string_suffixes(&include) {
                        if let Some(name_targets) = by_file_name.get(suffix) {
                            for target in name_targets {
                                if matched_targets.insert(target.clone()) {
                                    resolved_targets.push(target.clone());
                                }
                            }
                        }
                    }
                }
                resolved_targets
            })
        })
    }
}

fn string_suffixes(value: &str) -> impl Iterator<Item = &str> {
    value.char_indices().map(|(index, _)| &value[index..])
}

pub(crate) fn parse_quoted_include(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let quote_start = trimmed.find('"')?;
    let quote_end = trimmed[quote_start + 1..].find('"')?;
    Some(trimmed[quote_start + 1..quote_start + 1 + quote_end].to_string())
}

pub(crate) fn parse_include_path(line: &str) -> Option<String> {
    if let Some(path) = parse_quoted_include(line) {
        return Some(path);
    }
    let trimmed = line.trim();
    let angle_start = trimmed.find('<')?;
    let angle_end = trimmed[angle_start + 1..].find('>')?;
    Some(trimmed[angle_start + 1..angle_start + 1 + angle_end].to_string())
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

pub(crate) fn resolve_include_targets_with_unique_fallback(
    project: &dyn Project,
    source_file: &ProjectFile,
    include: &str,
) -> Vec<ProjectFile> {
    let mut candidates = resolve_include_targets(project, source_file, include);
    if !candidates.is_empty() {
        return candidates;
    }
    let include_path = Path::new(include);
    if include_path.is_absolute() {
        return candidates;
    }
    if let Ok(files) = project.all_files() {
        let matches: Vec<_> = files
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
            candidates.extend(matches);
        }
    }
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

pub(crate) fn include_paths(parsed: &[String]) -> Vec<String> {
    parsed
        .iter()
        .filter_map(|line| parse_include_path(line))
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
