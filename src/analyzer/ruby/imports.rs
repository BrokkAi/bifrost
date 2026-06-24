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

/// Candidate in-project relative paths a require could resolve to, normalized
/// and `.rb`-suffixed. `require_relative "x"` resolves against the requiring
/// file's directory; project-local `require "a/b/c"` (and `load`/`autoload`)
/// resolves against the project root and a conventional `lib/` root. The caller
/// keeps only candidates that name an analyzed file, so stdlib/gem requires
/// (no matching project file) stay unresolved.
fn candidate_required_paths(file: &ProjectFile, import: &ImportInfo) -> Vec<PathBuf> {
    let Some(raw_path) = import.identifier.as_deref() else {
        return Vec::new();
    };

    if import.raw_snippet.starts_with("require_relative") {
        let base = file.rel_path().parent().unwrap_or_else(|| Path::new(""));
        return normalize_relative(&with_rb_extension(base.join(raw_path)))
            .into_iter()
            .collect();
    }

    ["", "lib"]
        .iter()
        .filter_map(|root| normalize_relative(&with_rb_extension(Path::new(root).join(raw_path))))
        .collect()
}

/// Adds the implicit `.rb` extension when the require path carries none.
fn with_rb_extension(mut path: PathBuf) -> PathBuf {
    if path.extension().is_none() {
        path.set_extension("rb");
    }
    path
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
    /// Project files this file pulls in via `require`/`require_relative`/`load`.
    /// A require resolves only when a candidate path names an analyzed project
    /// file, so external (stdlib/gem) requires never fabricate an edge.
    pub(super) fn required_files(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let analyzed: HashSet<PathBuf> = self
            .inner
            .all_files()
            .map(|f| f.rel_path().to_path_buf())
            .collect();
        let root = file.root().to_path_buf();

        let mut required = Vec::new();
        for import in self.inner.import_info_of(file) {
            if let Some(resolved) = candidate_required_paths(file, import)
                .into_iter()
                .find(|candidate| analyzed.contains(candidate))
            {
                required.push(ProjectFile::new(root.clone(), resolved));
            }
        }
        required
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
        // Transitive closure over the direct reverse-require edges: if A requires
        // B and B requires C, A is a candidate when scanning usages of C.
        let index = self.build_reverse_import_index();
        let mut referencing = HashSet::default();
        let mut frontier: Vec<ProjectFile> = index
            .get(file)
            .map(|files| files.iter().cloned().collect())
            .unwrap_or_default();
        while let Some(referrer) = frontier.pop() {
            if !referencing.insert(referrer.clone()) {
                continue;
            }
            if let Some(indirect) = index.get(&referrer) {
                frontier.extend(indirect.iter().cloned());
            }
        }
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }
}
