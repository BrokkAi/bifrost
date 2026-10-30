//! Ruby's load-path knowledge: `require`/`require_relative`/`load`/`autoload`
//! parsing and resolution, the `autoload` constant edge collector, and the
//! Gemfile-driven Zeitwerk conventions.
//!
//! The memoized products these build -- the autoload constant index, the
//! Zeitwerk convention/visibility cells, and the reverse import index -- stay on `RubyAnalyzer` in
//! `brokk-bifrost-analysis`; only the decisions that fill them live here.

use crate::declarations::ruby_node_text as node_text;
use crate::graph_support::RubySource;
use crate::structural::RUBY_STRUCTURAL_SPEC;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::ruby_facts::{RubyLoadInfo, RubyLoadKind};
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use tree_sitter::Node;

pub const ZEITWERK_AUTOLOAD_EXCLUDED_APP_DIRS: &[&str] = &["assets", "javascript", "views"];

pub(crate) struct RubyLoadSyntax<'tree> {
    pub import: ImportInfo,
    pub kind: RubyLoadKind,
    pub has_receiver: bool,
    pub constant: Option<String>,
    pub target: Node<'tree>,
}

/// Interpret one load-call node while its primary AST is live.
pub(crate) fn parse_ruby_load_syntax<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<RubyLoadSyntax<'tree>> {
    if node.kind() != "call" {
        return None;
    }
    let method = node.child_by_field_name("method")?;
    let kind = match node_text(method, source).trim() {
        "require" => RubyLoadKind::Require,
        "require_relative" => RubyLoadKind::RequireRelative,
        "load" => RubyLoadKind::Load,
        "autoload" => RubyLoadKind::Autoload,
        _ => return None,
    };
    let arguments = crate::syntax::ruby_call_arguments(node);
    let path_index = usize::from(kind == RubyLoadKind::Autoload);
    let argument = *arguments.get(path_index)?;
    let path = string_literal_value(argument, source)?;
    let constant = if kind == RubyLoadKind::Autoload {
        literal_constant_name(*arguments.first()?, source)
    } else {
        None
    };
    let target = crate::syntax::single_static_string_content_node(argument).unwrap_or(argument);
    Some(RubyLoadSyntax {
        import: ImportInfo {
            raw_snippet: node_text(node, source).trim().to_owned(),
            is_wildcard: false,
            is_global: false,
            identifier: Some(path),
            alias: None,
            path: None,
            binder_span: None,
        },
        kind,
        has_receiver: node.child_by_field_name("receiver").is_some(),
        constant,
        target,
    })
}

/// Extracts the contents of a string literal node (`"foo"` -> `foo`).
fn string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    RUBY_STRUCTURAL_SPEC
        .string_literal_value(node, source)
        .filter(|value| !value.is_empty())
}

fn symbol_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "simple_symbol" {
        return None;
    }
    let text = node_text(node, source).trim();
    let stripped = text.strip_prefix(':').unwrap_or(text);
    (!stripped.is_empty()).then(|| stripped.to_string())
}

/// Resolves the in-project file path of a supported Ruby require target.
///
/// `require_relative` is resolved relative to the requiring file's directory.
/// Bare `require` is resolved as a project-root-relative load path only when a
/// matching project file exists.
pub fn resolve_required_file(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    load: &RubyLoadInfo,
) -> Option<ProjectFile> {
    let raw_path = load.import.identifier.as_deref()?;
    if load.has_receiver {
        return None;
    }
    match load.kind {
        RubyLoadKind::RequireRelative => {
            let base = file.rel_path().parent().unwrap_or_else(|| Path::new(""));
            resolve_relative_required_file(ruby, file, &base.join(raw_path))
        }
        RubyLoadKind::Require | RubyLoadKind::Autoload => {
            resolve_project_required_file(ruby, file, Path::new(raw_path))
        }
        RubyLoadKind::Load => None,
    }
}

fn resolve_generic_load(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    load: &RubyLoadInfo,
) -> Option<ProjectFile> {
    load.generic
        .then(|| resolve_required_file(ruby, file, load))
        .flatten()
}

fn resolve_relative_required_file(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    path: &Path,
) -> Option<ProjectFile> {
    resolve_candidate(ruby, file, path, false)
}

fn resolve_project_required_file(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    path: &Path,
) -> Option<ProjectFile> {
    if path.is_absolute() {
        return None;
    }
    resolve_required_path_candidates(ruby, file, path)
        .or_else(|| resolve_required_path_candidates(ruby, file, &Path::new("lib").join(path)))
}

fn resolve_required_path_candidates(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    path: &Path,
) -> Option<ProjectFile> {
    resolve_candidate(ruby, file, path, false).or_else(|| {
        path.extension()
            .is_none()
            .then(|| resolve_candidate(ruby, file, path, true))
            .flatten()
    })
}

fn resolve_candidate(
    ruby: &dyn RubySource,
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
    ruby.required_file_exists(&project_file)
        .then_some(project_file)
}

/// Resolves `.`/`..` components without touching the filesystem. Returns `None`
/// if the path escapes the project root.
fn normalize_relative(path: &Path) -> Option<PathBuf> {
    let normalized =
        brokk_bifrost_core::path_utils::normalize_relative_path_from(Path::new(""), path)?;
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

pub fn parse_ruby_autoload_call(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let method = node.child_by_field_name("method")?;
    if node_text(method, source).trim() != "autoload" {
        return None;
    }
    let args = crate::syntax::ruby_call_arguments(node);
    let constant = literal_constant_name(*args.first()?, source)?;
    let path = string_literal_value(*args.get(1)?, source)?;
    Some((constant, path))
}

pub fn is_ruby_autoload_symbol_argument(node: Node<'_>, source: &str) -> bool {
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

pub fn ruby_symbol_name(node: Node<'_>, source: &str) -> Option<String> {
    symbol_name(node, source)
}

fn literal_constant_name(node: Node<'_>, source: &str) -> Option<String> {
    symbol_name(node, source).or_else(|| string_literal_value(node, source))
}

pub fn gemfile_declares_zeitwerk_autoloading(contents: &str) -> bool {
    let Some(tree) = crate::declarations::parse_ruby_tree(contents) else {
        return false;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call"
            && node.child_by_field_name("receiver").is_none()
            && node
                .child_by_field_name("method")
                .is_some_and(|method| node_text(method, contents) == "gem")
            && crate::syntax::ruby_first_call_argument(node)
                .and_then(|arg| string_literal_value(arg, contents))
                .is_some_and(|name| is_zeitwerk_autoload_gem(&name))
        {
            return true;
        }
        brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed_as(
            node,
            &mut stack,
            |child| child,
        );
    }
    false
}

pub fn gemfile_lock_declares_zeitwerk_autoloading(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim_start();
        let Some((gem, rest)) = gemfile_lock_gem_line(trimmed) else {
            return false;
        };
        is_zeitwerk_autoload_gem(gem) && rest.trim_start().starts_with('(')
    })
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

pub fn is_zeitwerk_autoload_file(file: &ProjectFile) -> bool {
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

/// Project files this file pulls in via supported Ruby require forms.
pub fn ruby_required_files(
    ruby: &dyn RubySource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Vec<ProjectFile> {
    ruby_required_files_checked(ruby, token, file).unwrap_or_default()
}

pub fn ruby_required_files_checked(
    ruby: &dyn RubySource,
    _token: QueryToken<'_>,
    file: &ProjectFile,
) -> Option<Vec<ProjectFile>> {
    Some(
        ruby.source_facts(file)?
            .loads
            .iter()
            .filter_map(|load| resolve_generic_load(ruby, file, load))
            .collect(),
    )
}

pub fn ruby_autoload_visible_files_for_constant(
    ruby: &dyn RubySource,
    constant: &str,
) -> Option<HashSet<ProjectFile>> {
    Some(
        ruby.autoload_constant_files()?
            .get(constant)
            .cloned()
            .unwrap_or_default(),
    )
}

pub fn build_autoload_constant_files(
    ruby: &dyn RubySource,
) -> Option<HashMap<String, HashSet<ProjectFile>>> {
    let mut index: HashMap<String, HashSet<ProjectFile>> = HashMap::default();
    for file in ruby.source_files()? {
        for load in ruby.source_facts(&file)?.loads {
            let Some(constant) = &load.autoload_constant else {
                continue;
            };
            let files = index.entry(constant.join("$")).or_default();
            files.insert(file.clone());
            if let Some(required) = resolve_required_file(ruby, &file, &load) {
                files.insert(required);
            }
        }
    }
    Some(index)
}

pub fn detect_zeitwerk_autoload_conventions(ruby: &dyn RubySource) -> bool {
    ruby_project_file_contents(ruby, "Gemfile")
        .as_deref()
        .is_some_and(gemfile_declares_zeitwerk_autoloading)
        || ruby_project_file_contents(ruby, "Gemfile.lock")
            .as_deref()
            .is_some_and(gemfile_lock_declares_zeitwerk_autoloading)
}

fn ruby_project_file_contents(ruby: &dyn RubySource, rel_path: &str) -> Option<String> {
    let file = ProjectFile::new(ruby.project().root().to_path_buf(), rel_path);
    ruby.project().read_source(&file).ok()
}

fn zeitwerk_consumer_files(ruby: &dyn RubySource) -> BTreeSet<ProjectFile> {
    if !ruby.has_zeitwerk_autoload_conventions() {
        return BTreeSet::default();
    }
    ruby.project()
        .analyzable_files(Language::Ruby)
        .unwrap_or_default()
}

pub fn build_zeitwerk_autoload_files(ruby: &dyn RubySource) -> HashSet<ProjectFile> {
    zeitwerk_consumer_files(ruby)
        .into_iter()
        .filter(is_zeitwerk_autoload_file)
        .collect()
}

pub fn build_zeitwerk_consumer_files(ruby: &dyn RubySource) -> HashSet<ProjectFile> {
    zeitwerk_consumer_files(ruby).into_iter().collect()
}

pub fn build_zeitwerk_autoload_code_units(ruby: &dyn RubySource) -> HashSet<CodeUnit> {
    let mut units = HashSet::default();
    for file in ruby.zeitwerk_autoload_files().iter() {
        for code_unit in ruby.top_level_declarations(file) {
            units.insert(code_unit.clone());
        }
    }
    units
}

pub fn ruby_zeitwerk_visible_files_for(
    ruby: &dyn RubySource,
    file: &ProjectFile,
) -> Option<std::sync::Arc<HashSet<ProjectFile>>> {
    ruby.zeitwerk_consumer_files()
        .contains(file)
        .then(|| ruby.zeitwerk_autoload_files())
}

pub fn ruby_effective_imported_code_units(
    ruby: &dyn RubySource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> HashSet<CodeUnit> {
    let mut units = HashSet::default();
    for required in ruby_required_files(ruby, token, file) {
        for code_unit in ruby.top_level_declarations(&required) {
            units.insert(code_unit.clone());
        }
    }
    if ruby.zeitwerk_consumer_files().contains(file) {
        units.extend(
            ruby.zeitwerk_autoload_code_units()
                .iter()
                .filter(|code_unit| code_unit.source() != file)
                .cloned(),
        );
    }
    units
}

pub fn ruby_transitive_referencing_files_of(
    ruby: &dyn RubySource,
    file: &ProjectFile,
) -> HashSet<ProjectFile> {
    let reverse_index = ruby.reverse_import_index();
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

pub fn ruby_imported_files_from_infos(
    ruby: &dyn RubySource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Option<HashSet<ProjectFile>> {
    let loads = ruby.source_facts(file)?.loads;
    Some(
        loads
            .iter()
            .filter(|load| imports.contains(&load.import))
            .filter_map(|load| resolve_generic_load(ruby, file, load))
            .collect(),
    )
}

#[cfg(test)]
mod load_syntax_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "826c41013fe0: quicksilver round 10 on brokk-bifrost-ruby: string autoload names were mistaken for paths"
    )]
    fn ruby_load_argument_grammar() {
        for source in [
            "autoload :Widget, 'widget'",
            "autoload \"Widget\", \"widget\"",
        ] {
            let tree = crate::declarations::parse_ruby_tree(source).unwrap();
            let call = tree.root_node().named_child(0).unwrap();
            let load = parse_ruby_load_syntax(call, source).unwrap();
            assert_eq!(load.constant.as_deref(), Some("Widget"));
            assert_eq!(load.import.identifier.as_deref(), Some("widget"));
            assert_eq!(
                parse_ruby_autoload_call(call, source),
                Some(("Widget".into(), "widget".into()))
            );
        }
    }

    #[test]
    #[hardwon(
        "826c41013fe0: quicksilver round 10 on brokk-bifrost-ruby: Gemfile line scanning missed multiline calls and admitted heredoc text"
    )]
    fn ruby_gemfile_call_grammar() {
        for (source, expected) in [
            ("gem(\n \"zeitwerk\"\n)\n", true),
            ("group :default do\n gem 'rails'\nend", true),
            ("gem ENV.fetch(\"GEM\")", false),
            ("gem 'rack'", false),
            ("# gem 'zeitwerk'", false),
            ("text = <<~TEXT\ngem \"zeitwerk\"\nTEXT\n", false),
            ("other.gem 'zeitwerk'", false),
        ] {
            assert_eq!(
                gemfile_declares_zeitwerk_autoloading(source),
                expected,
                "{source}"
            );
        }
    }
}
