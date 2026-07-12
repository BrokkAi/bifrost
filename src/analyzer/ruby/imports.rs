use super::*;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{ImportInfo, Language};
use std::ffi::OsStr;
use std::path::{Component, PathBuf};
use std::sync::Arc;
use tree_sitter::Node;

const ZEITWERK_AUTOLOAD_EXCLUDED_APP_DIRS: &[&str] = &["assets", "javascript", "views"];

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

fn symbol_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "simple_symbol" {
        return None;
    }
    let text = super::declarations::ruby_node_text(node, source).trim();
    let stripped = text.strip_prefix(':').unwrap_or(text);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

/// Resolves the in-project file path of a supported Ruby require target.
///
/// `require_relative` is resolved relative to the requiring file's directory.
/// Bare `require` is resolved as a project-root-relative load path only when a
/// matching project file exists.
fn resolve_required_file(file: &ProjectFile, import: &ImportInfo) -> Option<ProjectFile> {
    let raw_path = import.identifier.as_deref()?;
    if import.raw_snippet.starts_with("autoload") {
        return resolve_project_required_file(file, Path::new(raw_path));
    }
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
        .or_else(|| resolve_required_path_candidates(file, &Path::new("lib").join(path)))
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

    pub(crate) fn autoload_visible_files_for_constant(
        &self,
        constant: &str,
    ) -> HashSet<ProjectFile> {
        self.autoload_constant_files()
            .get(constant)
            .cloned()
            .unwrap_or_default()
    }

    fn autoload_constant_files(&self) -> &HashMap<String, HashSet<ProjectFile>> {
        self.autoload_constant_files.get_or_init(|| {
            let mut index: HashMap<String, HashSet<ProjectFile>> = HashMap::default();
            for file in self.inner.all_files() {
                let Ok(source) = self.inner.project().read_source(&file) else {
                    continue;
                };
                let Some(tree) = parse_ruby_tree(&source) else {
                    continue;
                };
                collect_ruby_autoload_edges(&file, &source, tree.root_node(), &mut index);
            }
            index
        })
    }

    fn has_zeitwerk_autoload_conventions(&self) -> bool {
        *self.zeitwerk_project.get_or_init(|| {
            self.project_file_contents("Gemfile")
                .as_deref()
                .is_some_and(gemfile_declares_zeitwerk_autoloading)
                || self
                    .project_file_contents("Gemfile.lock")
                    .as_deref()
                    .is_some_and(gemfile_lock_declares_zeitwerk_autoloading)
        })
    }

    fn project_file_contents(&self, rel_path: &str) -> Option<String> {
        let file = ProjectFile::new(self.inner.project().root().to_path_buf(), rel_path);
        self.inner.project().read_source(&file).ok()
    }

    pub(crate) fn zeitwerk_autoload_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_autoload_files.get_or_init(|| {
            if !self.has_zeitwerk_autoload_conventions() {
                return HashSet::default();
            }
            self.inner
                .project()
                .analyzable_files(Language::Ruby)
                .map(|files| {
                    files
                        .into_iter()
                        .filter(is_zeitwerk_autoload_file)
                        .collect()
                })
                .unwrap_or_default()
        })
    }

    fn zeitwerk_consumer_files(&self) -> &HashSet<ProjectFile> {
        self.zeitwerk_consumer_files.get_or_init(|| {
            if !self.has_zeitwerk_autoload_conventions() {
                return HashSet::default();
            }
            self.inner
                .project()
                .analyzable_files(Language::Ruby)
                .map(|files| files.into_iter().collect())
                .unwrap_or_default()
        })
    }

    fn zeitwerk_autoload_code_units(&self) -> &HashSet<CodeUnit> {
        self.zeitwerk_autoload_code_units.get_or_init(|| {
            let mut units = HashSet::default();
            for file in self.zeitwerk_autoload_files() {
                for code_unit in self.inner.top_level_declarations(file) {
                    units.insert(code_unit.clone());
                }
            }
            units
        })
    }

    pub(crate) fn zeitwerk_reference_files_for_identifier(
        &self,
        identifier: &str,
    ) -> HashSet<ProjectFile> {
        if identifier.is_empty() {
            return HashSet::default();
        }
        self.zeitwerk_reference_files()
            .get(identifier)
            .into_iter()
            .flat_map(|files| files.iter().cloned())
            .collect()
    }

    pub(crate) fn zeitwerk_visible_files_for(
        &self,
        file: &ProjectFile,
    ) -> Option<&HashSet<ProjectFile>> {
        self.zeitwerk_consumer_files()
            .contains(file)
            .then(|| self.zeitwerk_autoload_files())
    }

    fn zeitwerk_reference_files(&self) -> &HashMap<String, HashSet<ProjectFile>> {
        self.zeitwerk_reference_files.get_or_init(|| {
            let mut references: HashMap<String, HashSet<ProjectFile>> = HashMap::default();
            for file in self.zeitwerk_consumer_files() {
                let Ok(source) = self.inner.project().read_source(file) else {
                    continue;
                };
                let Some(tree) = parse_ruby_tree(&source) else {
                    continue;
                };
                collect_ruby_reference_identifiers(&source, tree.root_node(), |identifier| {
                    references
                        .entry(identifier.to_string())
                        .or_default()
                        .insert(file.clone());
                });
            }
            references
        })
    }

    fn effective_imported_code_units(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        let mut units = HashSet::default();
        for required in self.required_files(file) {
            for code_unit in self.inner.top_level_declarations(&required) {
                units.insert(code_unit.clone());
            }
        }
        if self.zeitwerk_consumer_files().contains(file) {
            units.extend(
                self.zeitwerk_autoload_code_units()
                    .iter()
                    .filter(|code_unit| code_unit.source() != file)
                    .cloned(),
            );
        }
        units
    }

    pub(super) fn build_reverse_import_index(
        &self,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        crate::analyzer::memoized_reverse_file_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |file| self.required_files(file),
        )
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

fn collect_ruby_autoload_edges(
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    index: &mut HashMap<String, HashSet<ProjectFile>>,
) {
    enum Exit {
        Lexical(usize),
    }

    let mut stack = vec![(root, false)];
    let mut lexical_stack: Vec<String> = Vec::new();
    let mut exits: Vec<Exit> = Vec::new();
    while let Some((node, exiting)) = stack.pop() {
        if exiting {
            if let Some(Exit::Lexical(len)) = exits.pop() {
                lexical_stack.truncate(len);
            }
            continue;
        }

        let mut pushed_exit = false;
        if matches!(node.kind(), "class" | "module")
            && let Some(name) = node.child_by_field_name("name")
        {
            let previous_len = lexical_stack.len();
            let mut segments = lexical_stack.clone();
            segments.extend(super::declarations::extract_name_segments(name, source));
            if !segments.is_empty() {
                lexical_stack = segments;
                exits.push(Exit::Lexical(previous_len));
                stack.push((node, true));
                pushed_exit = true;
            }
        }

        if node.kind() == "call"
            && let Some((constant, path)) = parse_ruby_autoload_call(node, source)
        {
            let mut segments = lexical_stack.clone();
            segments.push(constant);
            let key = segments.join("$");
            let files = index.entry(key).or_default();
            files.insert(file.clone());
            let import = ImportInfo {
                raw_snippet: super::declarations::ruby_node_text(node, source)
                    .trim()
                    .to_string(),
                is_wildcard: false,
                identifier: Some(path),
                alias: None,
            };
            if let Some(required) = resolve_required_file(file, &import) {
                files.insert(required);
            }
        }

        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push((child, false));
        }
        if !pushed_exit {
            continue;
        }
    }
}

pub(crate) fn parse_ruby_autoload_call(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let method = node.child_by_field_name("method")?;
    if super::declarations::ruby_node_text(method, source).trim() != "autoload" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut args = arguments.named_children(&mut cursor);
    let constant = symbol_name(args.next()?, source)?;
    let path = args.find_map(|arg| string_literal_value(arg, source))?;
    Some((constant, path))
}

pub(crate) fn is_ruby_autoload_symbol_argument(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "simple_symbol" {
        return false;
    }
    let Some(arguments) = node.parent() else {
        return false;
    };
    if arguments.kind() != "argument_list" {
        return false;
    }
    let mut cursor = arguments.walk();
    if arguments.named_children(&mut cursor).next() != Some(node) {
        return false;
    }
    let Some(call) = arguments.parent() else {
        return false;
    };
    call.kind() == "call" && parse_ruby_autoload_call(call, source).is_some()
}

pub(crate) fn ruby_symbol_name(node: Node<'_>, source: &str) -> Option<String> {
    symbol_name(node, source)
}

impl ImportAnalysisProvider for RubyAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }
        let units = self.effective_imported_code_units(file);
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

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_files_from_infos(
        &self,
        file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<ProjectFile>> {
        Some(
            imports
                .iter()
                .filter_map(|import| resolve_required_file(file, import))
                .collect(),
        )
    }
}

fn gemfile_declares_zeitwerk_autoloading(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line
            .split_once('#')
            .map_or(line, |(before, _)| before)
            .trim();
        let Some(after_gem) = line.strip_prefix("gem") else {
            return false;
        };
        if !after_gem
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_whitespace() || ch == '(')
        {
            return false;
        }
        let args = after_gem
            .trim_start()
            .strip_prefix('(')
            .unwrap_or(after_gem);
        gem_args_name(args.trim_start()).is_some_and(is_zeitwerk_autoload_gem)
    })
}

fn gemfile_lock_declares_zeitwerk_autoloading(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim_start();
        let Some((gem, rest)) = gemfile_lock_gem_line(trimmed) else {
            return false;
        };
        is_zeitwerk_autoload_gem(gem) && rest.trim_start().starts_with('(')
    })
}

fn gem_args_name(args: &str) -> Option<&str> {
    let quote = args.chars().next()?;
    if !matches!(quote, '"' | '\'') {
        return None;
    }
    let rest = &args[quote.len_utf8()..];
    rest.find(quote).map(|end| &rest[..end])
}

fn gemfile_lock_gem_line(line: &str) -> Option<(&str, &str)> {
    let name_len = line
        .char_indices()
        .find_map(|(index, ch)| (ch.is_ascii_whitespace() || ch == '(').then_some(index))
        .unwrap_or(line.len());
    if name_len == 0 {
        return None;
    }
    Some((&line[..name_len], &line[name_len..]))
}

fn is_zeitwerk_autoload_gem(gem: &str) -> bool {
    matches!(gem, "rails" | "zeitwerk")
}

fn is_zeitwerk_autoload_file(file: &ProjectFile) -> bool {
    if file.rel_path().extension() != Some(OsStr::new("rb")) {
        return false;
    }
    let mut components = file.rel_path().components();
    if components.next() != Some(Component::Normal(OsStr::new("app"))) {
        return false;
    }
    let Some(Component::Normal(app_dir)) = components.next() else {
        return false;
    };
    let Some(app_dir) = app_dir.to_str() else {
        return false;
    };
    !ZEITWERK_AUTOLOAD_EXCLUDED_APP_DIRS.contains(&app_dir)
}

fn collect_ruby_reference_identifiers<'a>(
    source: &'a str,
    root: Node<'_>,
    mut sink: impl FnMut(&'a str),
) {
    walk_named_tree_preorder(root, true, |node| {
        if let Some(method) = method_call_identifier(node, source) {
            sink(method);
        }
        if let Some(constant) = constant_reference_identifier(node, source) {
            sink(constant);
        }
        WalkControl::Continue
    });
}

fn method_call_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "call" {
        return None;
    }
    let method = node.child_by_field_name("method")?;
    Some(ruby_node_text(method, source))
}

fn constant_reference_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "constant" {
        return None;
    }
    if let Some(parent) = node.parent()
        && matches!(parent.kind(), "class" | "module")
    {
        return None;
    }
    Some(ruby_node_text(node, source))
}

fn ruby_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim()
}
