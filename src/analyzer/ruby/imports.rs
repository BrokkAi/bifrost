use super::*;
use crate::analyzer::ImportInfo;
use crate::analyzer::build_reverse_import_index;
use std::path::{Component, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

/// Parses a `require`/`require_relative`/`load`/`autoload` call into an
/// [`ImportInfo`]. The required path string is stored in `identifier`; the kind
/// is recoverable from `raw_snippet` (only `require_relative` resolves to an
/// in-project file).
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

/// Resolves the in-project file path of a `require_relative` target, relative to
/// the requiring file's directory and adding the implicit `.rb` extension. Bare
/// `require` targets (stdlib/gems) are not resolvable and yield `None`.
fn resolve_required_file(file: &ProjectFile, import: &ImportInfo) -> Option<ProjectFile> {
    if !import.raw_snippet.starts_with("require_relative") {
        return None;
    }
    let raw_path = import.identifier.as_deref()?;
    let base = file.rel_path().parent().unwrap_or_else(|| Path::new(""));
    let mut joined = base.join(raw_path);
    if joined.extension().is_none() {
        joined.set_extension("rb");
    }
    let normalized = normalize_relative(&joined)?;
    Some(ProjectFile::new(file.root().to_path_buf(), normalized))
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
    /// Project files this file pulls in via `require_relative`.
    pub(super) fn required_files(&self, file: &ProjectFile) -> Vec<ProjectFile> {
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
            build_reverse_import_index(&files, |file| self.imported_code_units_of(file))
        })
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
        let referencing = self
            .build_reverse_import_index()
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }
}
