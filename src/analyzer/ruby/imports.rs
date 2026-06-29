use super::*;
use crate::analyzer::ImportInfo;
use rayon::prelude::*;
use std::path::{Component, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

/// Parses a `require`/`require_relative`/`load`/`autoload` call into an
/// [`ImportInfo`]. The required path string is stored in `identifier`; the kind
/// is recoverable from `raw_snippet`.
pub(super) fn parse_ruby_require_call(node: Node<'_>, source: &str) -> Option<ImportInfo> {
    let raw_snippet = super::declarations::ruby_node_text(node, source)
        .trim()
        .to_string();
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let path = arguments
        .named_children(&mut cursor)
        .find_map(|arg| string_literal_value(arg, source))?;

    Some(ImportInfo {
        raw_snippet,
        is_wildcard: false,
        identifier: Some(path),
        alias: None,
    })
}

/// Extracts the contents of a string literal node (`"foo"` -> `foo`).
fn string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = super::declarations::ruby_node_text(node, source).trim();
    let trimmed = text.trim_matches(['"', '\'']);
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolves the in-project file path of a supported Ruby require target.
///
/// `require_relative` is resolved relative to the requiring file's directory.
/// Bare `require` is resolved as a project-root-relative load path only when a
/// matching project file exists.
fn resolve_required_file(file: &ProjectFile, import: &ImportInfo) -> Option<ProjectFile> {
    let raw_path = import.identifier.as_deref()?;
    if import.raw_snippet.starts_with("require_relative") {
        let base = file.rel_path().parent().unwrap_or_else(|| Path::new(""));
        return resolve_relative_required_file(file, &base.join(raw_path));
    }
    if import.raw_snippet.starts_with("require") {
        return resolve_project_required_file(file, Path::new(raw_path));
    }
    None
}

fn resolve_relative_required_file(file: &ProjectFile, path: &Path) -> Option<ProjectFile> {
    resolve_candidate(file, path, false)
}

fn resolve_project_required_file(file: &ProjectFile, path: &Path) -> Option<ProjectFile> {
    if path.is_absolute() {
        return None;
    }
    resolve_required_path_candidates(file, path)
}

fn resolve_required_path_candidates(file: &ProjectFile, path: &Path) -> Option<ProjectFile> {
    resolve_candidate(file, path, false).or_else(|| {
        path.extension()
            .is_none()
            .then(|| resolve_candidate(file, path, true))
            .flatten()
    })
}

fn resolve_candidate(
    file: &ProjectFile,
    path: &Path,
    directory_index: bool,
) -> Option<ProjectFile> {
    let mut candidate = normalize_relative(path)?;
    if directory_index {
        candidate.push("index");
    }
    if candidate.extension().is_none() {
        candidate.set_extension("rb");
    }
    let project_file = ProjectFile::new(file.root().to_path_buf(), candidate);
    project_file.exists().then_some(project_file)
}

/// Resolves `.`/`..` components without touching the filesystem. Returns `None`
/// if the path escapes the project root.
fn normalize_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(part) => out.push(part),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

impl RubyAnalyzer {
    /// Project files this file pulls in via supported Ruby require forms.
    pub(crate) fn required_files(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        self.inner
            .import_info_of(file)
            .iter()
            .filter_map(|import| resolve_required_file(file, import))
            .collect()
    }

    pub(super) fn build_reverse_import_index(
        &self,
    ) -> &HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        self.reverse_import_index.get_or_init(|| {
            let files: Vec<_> = self.inner.all_files().cloned().collect();
            let edges: Vec<_> = files
                .par_iter()
                .flat_map(|file| {
                    self.required_files(file)
                        .into_iter()
                        .filter(|required| required != file)
                        .map(|required| (required, file.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            let mut reverse: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
            for (required, importer) in edges {
                reverse.entry(required).or_default().insert(importer);
            }
            reverse
                .into_iter()
                .map(|(file, refs)| (file, Arc::new(refs)))
                .collect()
        })
    }

    fn transitive_referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let reverse_index = self.build_reverse_import_index();
        let mut referencing = HashSet::default();
        let mut visited = HashSet::default();
        visited.insert(file.clone());
        let mut stack: Vec<ProjectFile> = reverse_index
            .get(file)
            .map(|files| files.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(next) = stack.pop() {
            if !visited.insert(next.clone()) {
                continue;
            }
            referencing.insert(next.clone());
            if let Some(parents) = reverse_index.get(&next) {
                stack.extend(parents.iter().cloned());
            }
        }
        referencing
    }
}

impl ImportAnalysisProvider for RubyAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let mut units = HashSet::default();
        for required in self.required_files(file) {
            for code_unit in self.inner.top_level_declarations(&required) {
                units.insert(code_unit.clone());
            }
        }
        self.imported_code_units
            .insert(file.clone(), Arc::new(units.clone()));
        units
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        let referencing = self.transitive_referencing_files_of(file);
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }
}
