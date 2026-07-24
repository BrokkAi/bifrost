use crate::analyzer::js_ts::tsconfig::AliasResolver;
use crate::analyzer::{ImportInfo, Language, ProjectFile};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tree_sitter::Node;

pub(crate) fn parse_es_import_infos_from_node(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    if node.kind() != "import_statement" {
        return Vec::new();
    }
    let raw = node_text(node, source).trim().to_string();
    let Some(source_node) = node.child_by_field_name("source") else {
        return Vec::new();
    };
    if node_text(source_node, source).trim().is_empty() {
        return Vec::new();
    }

    let Some(import_clause) = named_child_of_kind(node, "import_clause") else {
        return vec![ImportInfo {
            raw_snippet: raw,
            is_wildcard: false,
            identifier: None,
            alias: None,
            path: None,
        }];
    };

    let mut imports = Vec::new();
    let mut cursor = import_clause.walk();
    for child in import_clause.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let identifier = node_text(child, source).trim();
                if !identifier.is_empty() {
                    imports.push(ImportInfo {
                        raw_snippet: raw.clone(),
                        is_wildcard: false,
                        identifier: Some(identifier.to_string()),
                        alias: None,
                        path: None,
                    });
                }
            }
            "namespace_import" => {
                if let Some(alias) = first_identifier_child(child, source) {
                    imports.push(ImportInfo {
                        raw_snippet: raw.clone(),
                        is_wildcard: true,
                        identifier: None,
                        alias: Some(alias),
                        path: None,
                    });
                }
            }
            "named_imports" => collect_named_es_imports(child, source, &raw, &mut imports),
            _ => {}
        }
    }
    imports
}

pub(crate) fn parse_commonjs_require_import_infos_from_node(
    node: Node<'_>,
    source: &str,
) -> Vec<ImportInfo> {
    if matches!(node.kind(), "lexical_declaration" | "variable_declaration") {
        return parse_commonjs_require_bindings_from_node(node, source)
            .into_iter()
            .map(|binding| ImportInfo {
                raw_snippet: binding.raw_snippet,
                is_wildcard: false,
                identifier: Some(binding.imported_name),
                alias: binding.alias,
                path: None,
            })
            .collect();
    }

    if node.kind() == "expression_statement" {
        let raw = node_text(node, source).trim();
        if raw.is_empty() || !direct_require_expression(node, source) {
            return Vec::new();
        }
        return vec![ImportInfo {
            raw_snippet: raw.to_string(),
            is_wildcard: false,
            identifier: None,
            alias: None,
            path: None,
        }];
    }

    Vec::new()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommonJsRequireBinding {
    pub(crate) raw_snippet: String,
    pub(crate) module_specifier: String,
    pub(crate) local_name: String,
    pub(crate) imported_name: String,
    pub(crate) alias: Option<String>,
    pub(crate) kind: CommonJsRequireBindingKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommonJsRequireBindingKind {
    ModuleObject,
    Named,
}

pub(crate) fn parse_commonjs_require_bindings_from_node(
    node: Node<'_>,
    source: &str,
) -> Vec<CommonJsRequireBinding> {
    if !matches!(node.kind(), "lexical_declaration" | "variable_declaration") {
        return Vec::new();
    }
    let raw = node_text(node, source).trim().to_string();
    if raw.is_empty() {
        return Vec::new();
    }

    let mut bindings = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            bindings.extend(commonjs_require_bindings_from_declarator(
                child, &raw, source,
            ));
        }
    }
    bindings
}

fn commonjs_require_bindings_from_declarator(
    declarator: Node<'_>,
    raw: &str,
    source: &str,
) -> Vec<CommonJsRequireBinding> {
    let Some(module_specifier) =
        commonjs_require_module_specifier_from_declarator(declarator, source)
    else {
        return Vec::new();
    };
    let Some(name) = declarator.child_by_field_name("name") else {
        return Vec::new();
    };
    commonjs_require_bindings_from_name(name, raw, &module_specifier, source)
}

fn commonjs_require_bindings_from_name(
    node: Node<'_>,
    raw: &str,
    module_specifier: &str,
    source: &str,
) -> Vec<CommonJsRequireBinding> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let identifier = node_text(node, source).trim();
            if identifier.is_empty() {
                Vec::new()
            } else {
                vec![CommonJsRequireBinding {
                    raw_snippet: raw.to_string(),
                    module_specifier: module_specifier.to_string(),
                    local_name: identifier.to_string(),
                    imported_name: identifier.to_string(),
                    alias: None,
                    kind: CommonJsRequireBindingKind::ModuleObject,
                }]
            }
        }
        "object_pattern" => {
            let mut bindings = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "shorthand_property_identifier_pattern" => {
                        let identifier = node_text(child, source).trim();
                        if !identifier.is_empty() {
                            bindings.push(CommonJsRequireBinding {
                                raw_snippet: raw.to_string(),
                                module_specifier: module_specifier.to_string(),
                                local_name: identifier.to_string(),
                                imported_name: identifier.to_string(),
                                alias: None,
                                kind: CommonJsRequireBindingKind::Named,
                            });
                        }
                    }
                    "pair_pattern" => {
                        let identifier = child
                            .child_by_field_name("key")
                            .or_else(|| first_child_of_kind(child, "property_identifier"))
                            .map(|key| node_text(key, source).trim().to_string())
                            .filter(|text| !text.is_empty());
                        let alias = child
                            .child_by_field_name("value")
                            .and_then(|value| commonjs_pattern_local_name(value, source))
                            .filter(|text| !text.is_empty());
                        if let Some(identifier) = identifier {
                            let local_name = alias.clone().unwrap_or_else(|| identifier.clone());
                            bindings.push(CommonJsRequireBinding {
                                raw_snippet: raw.to_string(),
                                module_specifier: module_specifier.to_string(),
                                local_name,
                                imported_name: identifier,
                                alias,
                                kind: CommonJsRequireBindingKind::Named,
                            });
                        }
                    }
                    _ => {}
                }
            }
            bindings
        }
        _ => Vec::new(),
    }
}

pub(crate) fn commonjs_require_module_specifier_from_declarator(
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let value = declarator.child_by_field_name("value")?;
    require_call_module_specifier(value, source)
}

pub(crate) fn require_call_module_specifier(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "identifier" || node_text(function, source).trim() != "require" {
        return None;
    }

    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let first_argument = arguments.named_children(&mut cursor).next()?;
    if !matches!(first_argument.kind(), "string" | "string_fragment") {
        return None;
    }
    Some(unquote(node_text(first_argument, source)))
}

fn commonjs_pattern_local_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "type_identifier" | "shorthand_property_identifier_pattern" => {
            let text = node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "assignment_pattern" => node
            .child_by_field_name("left")
            .and_then(|left| commonjs_pattern_local_name(left, source)),
        _ => None,
    }
}

fn first_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn direct_require_expression(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| is_require_call(child, source))
}

fn is_require_call(node: Node<'_>, source: &str) -> bool {
    require_call_module_specifier(node, source).is_some()
}

fn collect_named_es_imports(
    node: Node<'_>,
    source: &str,
    raw: &str,
    imports: &mut Vec<ImportInfo>,
) {
    let mut cursor = node.walk();
    for spec in node.named_children(&mut cursor) {
        if spec.kind() != "import_specifier" {
            continue;
        }
        let identifier = spec
            .child_by_field_name("name")
            .map(|name| node_text(name, source).trim().to_string());
        let alias = spec
            .child_by_field_name("alias")
            .map(|alias| node_text(alias, source).trim().to_string());
        if identifier.as_deref().is_none_or(str::is_empty) {
            continue;
        }
        imports.push(ImportInfo {
            raw_snippet: raw.to_string(),
            is_wildcard: false,
            identifier,
            alias,
            path: None,
        });
    }
}

fn named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn first_identifier_child(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "identifier" | "type_identifier"))
        .map(|child| node_text(child, source).trim().to_string())
        .filter(|text| !text.is_empty())
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    let stripped = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        });
    stripped.unwrap_or(trimmed).to_string()
}

pub(crate) fn resolve_js_ts_import_paths(
    source_file: &ProjectFile,
    raw_import: &str,
    language: Language,
    aliases: Option<&AliasResolver>,
) -> Vec<ProjectFile> {
    let Some(module_path) = extract_import_module_path(raw_import) else {
        return Vec::new();
    };
    resolve_js_ts_module_specifier(source_file, &module_path, language, aliases)
}

/// Resolve a module specifier to project files. Relative specifiers (`"./foo"`) resolve
/// against the importing file's directory; non-relative specifiers are matched against
/// the importing file's governing `tsconfig.json`/`jsconfig.json` path aliases via
/// `aliases` (when supplied). Bare package specifiers that match no alias are still
/// ignored — `package.json` `exports`/`main` resolution remains out of scope. Shared with
/// the JS/TS export-usage graph so both resolvers stay in lock-step.
pub(crate) fn resolve_js_ts_module_specifier(
    source_file: &ProjectFile,
    module_specifier: &str,
    language: Language,
    aliases: Option<&AliasResolver>,
) -> Vec<ProjectFile> {
    let exts = language.extensions();
    if !module_specifier.starts_with('.') {
        // Non-relative: try tsconfig path aliases. Each candidate base is tried in TS
        // precedence order; the first that resolves to a real file wins.
        let Some(aliases) = aliases else {
            return Vec::new();
        };
        for base in aliases.candidate_bases(source_file, module_specifier) {
            let mut candidates = Vec::new();
            collect_candidate_paths(source_file.root(), &base, language, exts, &mut candidates);
            if !candidates.is_empty() {
                candidates.sort();
                candidates.dedup();
                return candidates;
            }
        }
        return Vec::new();
    }
    let base = source_file.parent().join(module_specifier);
    let mut candidates = Vec::new();
    collect_candidate_paths(source_file.root(), &base, language, exts, &mut candidates);
    candidates.sort();
    candidates.dedup();
    candidates
}

fn extract_import_module_path(raw_import: &str) -> Option<String> {
    let trimmed = raw_import.trim().trim_end_matches(';').trim();
    if trimmed.starts_with("import ") {
        if let Some((_, path)) = trimmed.trim_end_matches(';').rsplit_once(" from ") {
            return Some(path.trim().trim_matches('\'').trim_matches('"').to_string());
        }
        let path = trimmed.split_whitespace().nth(1)?;
        return Some(path.trim().trim_matches('\'').trim_matches('"').to_string());
    }
    let require = trimmed.split_once("require(")?.1;
    let path = require
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_end_matches(';')
        .trim();
    Some(path.trim_matches('\'').trim_matches('"').to_string())
}

fn collect_candidate_paths(
    root: &Path,
    module_path: &Path,
    language: Language,
    extensions: &[&str],
    out: &mut Vec<ProjectFile>,
) {
    if module_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| extensions.contains(&ext))
    {
        let file = ProjectFile::new(root.to_path_buf(), module_path.to_path_buf());
        if file.exists() {
            out.push(file);
        }
        return;
    }
    if let Some(source_extensions) =
        ts_source_extensions_for_runtime_specifier(module_path, language)
    {
        for source_extension in source_extensions {
            let source_path = module_path.with_extension(source_extension);
            let file = ProjectFile::new(root.to_path_buf(), source_path);
            if file.exists() {
                out.push(file);
            }
        }
        if !out.is_empty() {
            return;
        }
    }
    for extension in extensions {
        let with_ext = PathBuf::from(format!("{}.{}", module_path.to_string_lossy(), extension));
        let direct = ProjectFile::new(root.to_path_buf(), with_ext);
        if direct.exists() {
            out.push(direct);
        }
        let index = module_path.join(format!("index.{extension}"));
        let index_file = ProjectFile::new(root.to_path_buf(), index);
        if index_file.exists() {
            out.push(index_file);
        }
    }
}

fn ts_source_extensions_for_runtime_specifier(
    module_path: &Path,
    language: Language,
) -> Option<&'static [&'static str]> {
    if language != Language::TypeScript {
        return None;
    }
    match module_path.extension().and_then(|ext| ext.to_str()) {
        Some("js") => Some(&["ts", "tsx"]),
        Some("jsx") => Some(&["tsx", "ts"]),
        Some("mjs") => Some(&["mts", "ts"]),
        Some("cjs") => Some(&["cts", "ts"]),
        _ => None,
    }
}

pub(crate) fn import_info_tokens(import: &ImportInfo) -> BTreeSet<String> {
    import
        .local_name()
        .map(str::to_string)
        .into_iter()
        .collect()
}

pub(crate) fn extract_js_ts_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed);
    let (receiver, method) = before_args.rsplit_once('.')?;
    if receiver.is_empty() || method.is_empty() {
        return None;
    }
    Some(receiver.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_es_import_infos_from_node;
    use tree_sitter::Parser;

    fn parse_typescript_import_infos(source: &str) -> Vec<crate::analyzer::ImportInfo> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let import_node = root
            .named_children(&mut root.walk())
            .find(|child| child.kind() == "import_statement")
            .unwrap();
        parse_es_import_infos_from_node(import_node, source)
    }

    #[test]
    fn parses_typescript_type_only_named_imports() {
        let imports = parse_typescript_import_infos("import type { BubbleState } from '../types';");
        assert_eq!(1, imports.len());
        assert_eq!(Some("BubbleState"), imports[0].identifier.as_deref());
        assert_eq!(None, imports[0].alias.as_deref());
    }

    #[test]
    fn parses_mixed_typescript_named_imports_with_inline_type_modifiers() {
        let imports = parse_typescript_import_infos(
            "import { type BubbleState, SummaryState } from '../types';",
        );
        let identifiers = imports
            .into_iter()
            .map(|import| import.identifier.unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(vec!["BubbleState", "SummaryState"], identifiers);
    }
}
