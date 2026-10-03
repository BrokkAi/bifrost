use crate::access_chain::{ImportMemberChainOwner, JsTsImportedMemberChain};
use crate::providers::JsTsSource;
use crate::syntax::JsTsImportBinder;
use crate::tsconfig::AliasResolver;
use crate::type_text::{jsts_type_space_candidates, jsts_value_space_candidates};
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportPath};
use brokk_bifrost_core::analyzer::usages::model::ImportBinding;
use brokk_bifrost_core::analyzer::usages::model::ImportKind;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome,
};
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, Language, ProjectFile, Range,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tree_sitter::Node;

/// Syntax view of one parser-derived JS/TS import row.
///
/// `ImportInfo` is the durable projection used by analyzer consumers. These
/// nodes are retained only while the primary parser owns its tree, allowing
/// consumers to intern exact declaration and binder identities without
/// matching ranges or reparsing `raw_snippet`.
#[derive(Clone)]
pub struct JsTsImportSyntax<'tree> {
    pub import: ImportInfo,
    pub declaration: Node<'tree>,
    pub target: Option<Node<'tree>>,
    pub name: Option<Node<'tree>>,
    pub alias: Option<Node<'tree>>,
    pub kind: Option<ImportKind>,
    pub is_static: bool,
}

pub fn parse_es_import_infos_from_node(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    parse_es_import_syntaxes_from_node(node, source)
        .into_iter()
        .map(|syntax| syntax.import)
        .collect()
}

/// Parse one ESM import statement while retaining its source nodes.
pub fn parse_es_import_syntaxes_from_node<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Vec<JsTsImportSyntax<'tree>> {
    if node.kind() != "import_statement" {
        return Vec::new();
    }
    let raw = node_text(node, source).trim().to_string();
    let Some(source_node) = node.child_by_field_name("source") else {
        return Vec::new();
    };
    let module_specifier = unquote(node_text(source_node, source));
    if module_specifier.is_empty() {
        return Vec::new();
    }
    let path = structured_module_path(&module_specifier, node.start_byte());

    let Some(import_clause) = named_child_of_kind(node, "import_clause") else {
        return vec![JsTsImportSyntax {
            import: ImportInfo {
                raw_snippet: raw,
                is_wildcard: false,
                is_global: false,
                identifier: None,
                alias: None,
                path: Some(path),
                binder_span: None,
            },
            declaration: node,
            target: Some(source_node),
            name: None,
            alias: None,
            kind: None,
            is_static: false,
        }];
    };

    let mut imports = Vec::new();
    let mut cursor = import_clause.walk();
    for child in import_clause.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                let identifier = node_text(child, source).trim();
                if !identifier.is_empty() {
                    imports.push(JsTsImportSyntax {
                        import: ImportInfo {
                            raw_snippet: raw.clone(),
                            is_wildcard: false,
                            is_global: false,
                            identifier: Some(identifier.to_string()),
                            alias: None,
                            path: Some(path.clone()),
                            binder_span: Some(brokk_bifrost_core::analyzer::common::node_span(
                                child,
                            )),
                        },
                        declaration: node,
                        target: Some(source_node),
                        name: Some(child),
                        alias: None,
                        kind: Some(ImportKind::Default),
                        is_static: true,
                    });
                }
            }
            "namespace_import" => {
                if let Some(alias_node) = first_identifier_child_node(child) {
                    let alias = node_text(alias_node, source).trim().to_string();
                    if !alias.is_empty() {
                        imports.push(JsTsImportSyntax {
                            import: ImportInfo {
                                raw_snippet: raw.clone(),
                                is_wildcard: true,
                                is_global: false,
                                identifier: None,
                                alias: Some(alias),
                                path: Some(path.clone()),
                                // A namespace import binds one name: its alias token.
                                binder_span: Some(brokk_bifrost_core::analyzer::common::node_span(
                                    alias_node,
                                )),
                            },
                            declaration: node,
                            target: Some(source_node),
                            name: None,
                            alias: Some(alias_node),
                            kind: Some(ImportKind::Namespace),
                            is_static: true,
                        });
                    }
                }
            }
            "named_imports" => collect_named_es_import_syntaxes(
                child,
                source,
                &raw,
                source_node,
                node,
                &mut imports,
            ),
            _ => {}
        }
    }
    for syntax in &mut imports {
        syntax.import.path = Some(path.clone());
    }
    imports
}

pub fn parse_commonjs_require_import_infos_from_node(
    node: Node<'_>,
    source: &str,
) -> Vec<ImportInfo> {
    parse_commonjs_require_import_syntaxes_from_node(node, source)
        .into_iter()
        .map(|syntax| syntax.import)
        .collect()
}

/// Parse CommonJS `require` imports while retaining their source nodes.
pub fn parse_commonjs_require_import_syntaxes_from_node<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Vec<JsTsImportSyntax<'tree>> {
    if matches!(node.kind(), "lexical_declaration" | "variable_declaration") {
        return commonjs_require_import_syntaxes_from_declaration(node, source);
    }

    if node.kind() == "expression_statement" {
        let raw = node_text(node, source).trim();
        if raw.is_empty() || !direct_require_expression(node, source) {
            return Vec::new();
        }
        let Some(module_specifier) = direct_require_module_specifier(node, source) else {
            return Vec::new();
        };
        return vec![JsTsImportSyntax {
            import: ImportInfo {
                raw_snippet: raw.to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: None,
                alias: None,
                path: Some(structured_module_path(&module_specifier, node.start_byte())),
                binder_span: None,
            },
            declaration: node,
            target: direct_require_call(node, source).and_then(require_call_target_node),
            name: None,
            alias: None,
            // A side-effect require has no local binder. Keep its import leaf
            // for source identity, but do not make graph consumers invent a
            // binding for it.
            kind: None,
            is_static: false,
        }];
    }

    Vec::new()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonJsRequireBinding {
    pub raw_snippet: String,
    pub module_specifier: String,
    pub local_name: String,
    pub imported_name: String,
    pub alias: Option<String>,
    pub kind: CommonJsRequireBindingKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonJsRequireBindingKind {
    ModuleObject,
    Named,
}

fn commonjs_require_import_syntaxes_from_declaration<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Vec<JsTsImportSyntax<'tree>> {
    let raw = node_text(node, source).trim().to_string();
    if raw.is_empty() {
        return Vec::new();
    }

    let mut imports = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(module_specifier) =
            commonjs_require_module_specifier_from_declarator(child, source)
        else {
            continue;
        };
        let Some(name) = child.child_by_field_name("name") else {
            continue;
        };
        let target = child
            .child_by_field_name("value")
            .and_then(require_call_target_node);
        imports.extend(commonjs_require_import_syntaxes_from_name(
            name,
            node,
            target,
            &raw,
            &module_specifier,
            source,
        ));
    }
    imports
}

fn commonjs_require_import_syntaxes_from_name<'tree>(
    node: Node<'tree>,
    declaration: Node<'tree>,
    target: Option<Node<'tree>>,
    raw: &str,
    module_specifier: &str,
    source: &str,
) -> Vec<JsTsImportSyntax<'tree>> {
    let path = Some(structured_module_path(
        module_specifier,
        declaration.start_byte(),
    ));
    let import_info = |identifier: String, alias: Option<String>, binder_span| ImportInfo {
        raw_snippet: raw.to_string(),
        is_wildcard: false,
        is_global: false,
        identifier: Some(identifier),
        alias,
        path: path.clone(),
        binder_span,
    };

    match node.kind() {
        "identifier" | "type_identifier" => {
            let identifier = node_text(node, source).trim();
            if identifier.is_empty() {
                Vec::new()
            } else {
                vec![JsTsImportSyntax {
                    import: import_info(
                        identifier.to_string(),
                        None,
                        Some(brokk_bifrost_core::analyzer::common::node_span(node)),
                    ),
                    declaration,
                    target,
                    name: Some(node),
                    alias: None,
                    kind: Some(ImportKind::CommonJsRequire),
                    is_static: false,
                }]
            }
        }
        "object_pattern" => {
            let mut imports = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                match child.kind() {
                    "shorthand_property_identifier_pattern" => {
                        let identifier = node_text(child, source).trim();
                        if !identifier.is_empty() {
                            imports.push(JsTsImportSyntax {
                                import: import_info(
                                    identifier.to_string(),
                                    None,
                                    Some(brokk_bifrost_core::analyzer::common::node_span(child)),
                                ),
                                declaration,
                                target,
                                name: Some(child),
                                alias: None,
                                kind: Some(ImportKind::Named),
                                is_static: false,
                            });
                        }
                    }
                    "pair_pattern" => {
                        let name = child
                            .child_by_field_name("key")
                            .or_else(|| first_child_of_kind(child, "property_identifier"));
                        let Some(name) = name else {
                            continue;
                        };
                        let identifier = node_text(name, source).trim();
                        if identifier.is_empty() {
                            continue;
                        }
                        let alias = child
                            .child_by_field_name("value")
                            .and_then(|value| commonjs_pattern_local_name_node(value, source));
                        let alias_text =
                            alias.map(|node| node_text(node, source).trim().to_string());
                        imports.push(JsTsImportSyntax {
                            import: import_info(
                                identifier.to_string(),
                                alias_text,
                                Some(brokk_bifrost_core::analyzer::common::node_span(
                                    alias.unwrap_or(name),
                                )),
                            ),
                            declaration,
                            target,
                            name: Some(name),
                            alias,
                            kind: Some(ImportKind::Named),
                            is_static: false,
                        });
                    }
                    _ => {}
                }
            }
            imports
        }
        _ => Vec::new(),
    }
}

pub fn parse_commonjs_require_bindings_from_node(
    node: Node<'_>,
    source: &str,
) -> Vec<CommonJsRequireBinding> {
    parse_commonjs_require_import_syntaxes_from_node(node, source)
        .into_iter()
        .filter_map(|syntax| {
            let module_specifier = syntax
                .import
                .path
                .as_ref()
                .map(|path| path.render_segments("/"))
                .filter(|path| !path.is_empty())?;
            let local_name = syntax.import.local_name()?.to_owned();
            let kind = match syntax.kind? {
                ImportKind::CommonJsRequire => CommonJsRequireBindingKind::ModuleObject,
                ImportKind::Named => CommonJsRequireBindingKind::Named,
                _ => return None,
            };
            let imported_name = syntax.import.identifier.clone()?;
            Some(CommonJsRequireBinding {
                raw_snippet: syntax.import.raw_snippet,
                module_specifier,
                local_name,
                imported_name,
                alias: syntax.import.alias,
                kind,
            })
        })
        .collect()
}

pub fn commonjs_require_module_specifier_from_declarator(
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let value = declarator.child_by_field_name("value")?;
    require_call_module_specifier(value, source)
}

pub fn require_call_module_specifier(node: Node<'_>, source: &str) -> Option<String> {
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

fn commonjs_pattern_local_name_node<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    match node.kind() {
        "identifier" | "type_identifier" | "shorthand_property_identifier_pattern" => {
            (!node_text(node, source).trim().is_empty()).then_some(node)
        }
        "assignment_pattern" => node
            .child_by_field_name("left")
            .and_then(|left| commonjs_pattern_local_name_node(left, source)),
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

fn direct_require_call<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| is_require_call(*child, source))
}

fn is_require_call(node: Node<'_>, source: &str) -> bool {
    require_call_module_specifier(node, source).is_some()
}

fn direct_require_module_specifier(node: Node<'_>, source: &str) -> Option<String> {
    direct_require_call(node, source).and_then(|call| require_call_module_specifier(call, source))
}

fn require_call_target_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "call_expression" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let argument = arguments.named_children(&mut cursor).next()?;
    matches!(argument.kind(), "string" | "string_fragment").then_some(argument)
}

fn structured_module_path(
    module_specifier: &str,
    declaration_start_byte: usize,
) -> StructuredImportPath {
    StructuredImportPath {
        // JS/TS module specifiers are AST string-literal values. Keep the
        // complete specifier as one segment; diff expansion interprets it via
        // `Path` components instead of reparsing raw source text.
        segments: vec![module_specifier.to_string()],
        kind: None,
        lexical_prefixes: Vec::new(),
        lexical_scopes: Vec::new(),
        declaration_start_byte,
    }
}

fn collect_named_es_import_syntaxes<'tree>(
    node: Node<'tree>,
    source: &str,
    raw: &str,
    target: Node<'tree>,
    declaration: Node<'tree>,
    imports: &mut Vec<JsTsImportSyntax<'tree>>,
) {
    let mut cursor = node.walk();
    for spec in node.named_children(&mut cursor) {
        if spec.kind() != "import_specifier" {
            continue;
        }
        let name_node = spec.child_by_field_name("name");
        let alias_node = spec.child_by_field_name("alias");
        let identifier = name_node.map(|name| node_text(name, source).trim().to_string());
        let alias = alias_node.map(|alias| node_text(alias, source).trim().to_string());
        if identifier.as_deref().is_none_or(str::is_empty) {
            continue;
        }
        // The bound name is spelled by the alias token when renamed, and by
        // the imported name's own token otherwise.
        let binder_span = alias_node
            .filter(|_| alias.as_deref().is_some_and(|alias| !alias.is_empty()))
            .or(name_node)
            .map(brokk_bifrost_core::analyzer::common::node_span);
        imports.push(JsTsImportSyntax {
            import: ImportInfo {
                raw_snippet: raw.to_string(),
                is_wildcard: false,
                is_global: false,
                identifier,
                alias,
                path: None,
                binder_span,
            },
            declaration,
            target: Some(target),
            name: name_node,
            alias: alias_node,
            kind: Some(ImportKind::Named),
            is_static: true,
        });
    }
}

fn named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn first_identifier_child_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "identifier" | "type_identifier"))
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
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

/// Resolve one parser-derived import to project files.
///
/// This is the canonical consumer path: the module specifier comes from the
/// structured import path captured by the parser. If the parser could not
/// provide that path, resolution stops instead of trying to recover it from
/// the display snippet.
pub fn resolve_js_ts_import_info_paths(
    source_file: &ProjectFile,
    import: &ImportInfo,
    language: Language,
    aliases: Option<&AliasResolver>,
) -> Vec<ProjectFile> {
    let Some(path) = import.path.as_ref() else {
        return Vec::new();
    };
    let module_specifier = path.render_segments("/");
    if module_specifier.is_empty() {
        return Vec::new();
    }
    resolve_js_ts_module_specifier(source_file, &module_specifier, language, aliases)
}

/// Resolve an explicitly supplied raw import snippet.
///
/// This compatibility SPI remains available for callers that intentionally
/// provide raw source. Analyzer consumers with [`ImportInfo`] must use
/// [`resolve_js_ts_import_info_paths`] so stale display text cannot override
/// the parser-captured path.
pub fn resolve_js_ts_import_paths(
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
/// against the importing file's directory. A non-relative specifier is matched first
/// against the importing file's governing `tsconfig.json`/`jsconfig.json` path aliases,
/// then, when no alias resolves it, against the names the workspace's own npm packages
/// declare in their `package.json` — so `@tanstack/react-query` inside the TanStack
/// monorepo reaches `packages/react-query/src/index.ts`. A bare specifier that names no
/// workspace package is an external dependency and still resolves to nothing. Shared
/// with the JS/TS export-usage graph so both resolvers stay in lock-step.
pub fn resolve_js_ts_module_specifier(
    source_file: &ProjectFile,
    module_specifier: &str,
    language: Language,
    aliases: Option<&AliasResolver>,
) -> Vec<ProjectFile> {
    let exts = language.extensions();
    if !module_specifier.starts_with('.') {
        // Non-relative: try tsconfig path aliases, then workspace package names.
        // Aliases keep precedence — a repository that spells an alias for a
        // package name means the alias — and each candidate base is tried in
        // order, so the first that resolves to a real file wins. A matching
        // alias that resolves to nothing falls through to the package map, the
        // way an unresolved `paths` entry falls through to node resolution.
        let Some(aliases) = aliases else {
            return Vec::new();
        };
        let bases = aliases
            .candidate_bases(source_file, module_specifier)
            .into_iter()
            .chain(aliases.workspace_package_bases(module_specifier));
        for base in bases {
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

/// The scheme Node's module resolution puts in front of a builtin module name.
///
/// `node:fs` and `fs` load the same builtin, so the scheme is spelling, not
/// identity.
const NODE_BUILTIN_SCHEME: &str = "node:";

/// The module a JS/TS specifier addresses, in the one spelling every consumer
/// must key on.
///
/// The three fields answer the three questions callers actually ask: what
/// module is this (`specifier`), which package or builtin owns it (`package`),
/// and what does it select inside that package (`subpath`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsTsModuleIdentity<'a> {
    /// The whole specifier with the `node:` scheme folded away: `fs`,
    /// `fs/promises`, `left-pad/dist/index`, `@scope/pkg/deep`. This is the
    /// owner a module-object binding mints, so `import fs from 'node:fs'` and
    /// `import fs from 'fs'` mint exactly one owner.
    pub specifier: &'a str,
    /// The package or builtin root: `fs`, `left-pad`, `@scope/pkg`.
    pub package: &'a str,
    /// What the specifier selects below the root, when it selects anything.
    pub subpath: Option<&'a str>,
}

/// Classify a JS/TS module specifier into the identity every consumer keys on.
///
/// A relative or absolute specifier (`./util`, `../util`, `/abs/util`)
/// addresses a workspace file rather than a package, and yields `None`. Every
/// other specifier yields its canonical identity:
///
///   * `node:fs` and `fs` -> both `fs`, package `fs`, no subpath. Node's module
///     resolution defines `node:` as a scheme on the specifier that selects the
///     builtin the bare name already selects, so the two spellings are one
///     module and must mint one owner (#2609);
///   * `node:fs/promises` -> `fs/promises`, package `fs`, subpath `promises`,
///     exactly as `fs/promises` splits;
///   * `left-pad/dist/index` -> package `left-pad`, subpath `dist/index`;
///   * `@scope/pkg/deep` -> package `@scope/pkg`, subpath `deep`.
///
/// The specifier is the whole structure here: the AST hands it over as one
/// string-literal value and has nothing below it. Recognizing the literal
/// `node:` prefix and the scope/name/subpath slashes is reading the specifier
/// grammar that Node and npm define, not a text search standing in for
/// structure a parser could have supplied. Discovery records exactly these
/// package and module identities (see `js_ts::external::declaration_entries`),
/// so callers that match retained evidence must split the same way.
pub fn js_ts_module_identity(specifier: &str) -> Option<JsTsModuleIdentity<'_>> {
    let specifier = specifier
        .strip_prefix(NODE_BUILTIN_SCHEME)
        .unwrap_or(specifier);
    if specifier.is_empty() || specifier.starts_with('.') || specifier.starts_with('/') {
        return None;
    }
    let boundary = if specifier.starts_with('@') {
        // A scoped package is `@scope/name`: the package ends at the second slash.
        let scope_end = specifier.find('/')?;
        specifier[scope_end + 1..]
            .find('/')
            .map(|offset| scope_end + 1 + offset)
    } else {
        specifier.find('/')
    };
    let Some(offset) = boundary else {
        return Some(JsTsModuleIdentity {
            specifier,
            package: specifier,
            subpath: None,
        });
    };
    let package = &specifier[..offset];
    let subpath = specifier[offset + 1..].trim_start_matches('/');
    // A trailing slash names the package itself, so the identity is the package.
    Some(JsTsModuleIdentity {
        specifier: if subpath.is_empty() {
            package
        } else {
            specifier
        },
        package,
        subpath: (!subpath.is_empty()).then_some(subpath),
    })
}

/// The npm package a bare module specifier addresses, and the subpath below it.
///
/// The `(package, subpath)` half of [`js_ts_module_identity`], for callers that
/// key on the package rather than on the whole module.
pub fn npm_package_of_module_specifier(specifier: &str) -> Option<(&str, Option<&str>)> {
    js_ts_module_identity(specifier).map(|identity| (identity.package, identity.subpath))
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

/// The paths one module path could name, grouped in the order the resolver
/// consults them: an explicit source extension alone; then, for a TypeScript
/// runtime specifier, the source extensions it stands for; then every
/// extension as both a sibling file and a directory index.
///
/// The grouping is what [`collect_candidate_paths`] stops on -- the first
/// group that yields a file wins -- and it is also what a specifier that
/// resolves to nothing has stat'ed in full, which is why the enumeration is
/// stated once here and read by both the resolver and
/// [`js_ts_module_specifier_probed_paths`]. A second enumeration would be a
/// second set of paths, and a read set that named paths the resolver never
/// probed would invalidate on files the resolver would never have found.
fn candidate_path_groups(
    root: &Path,
    module_path: &Path,
    language: Language,
    extensions: &[&str],
) -> Vec<Vec<ProjectFile>> {
    if module_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| extensions.contains(&ext))
    {
        return vec![vec![ProjectFile::new(
            root.to_path_buf(),
            module_path.to_path_buf(),
        )]];
    }
    let mut groups = Vec::new();
    if let Some(source_extensions) =
        ts_source_extensions_for_runtime_specifier(module_path, language)
    {
        groups.push(
            source_extensions
                .iter()
                .map(|source_extension| {
                    ProjectFile::new(
                        root.to_path_buf(),
                        module_path.with_extension(source_extension),
                    )
                })
                .collect(),
        );
    }
    let mut by_extension = Vec::with_capacity(extensions.len() * 2);
    for extension in extensions {
        by_extension.push(ProjectFile::new(
            root.to_path_buf(),
            PathBuf::from(format!("{}.{}", module_path.to_string_lossy(), extension)),
        ));
        by_extension.push(ProjectFile::new(
            root.to_path_buf(),
            module_path.join(format!("index.{extension}")),
        ));
    }
    groups.push(by_extension);
    groups
}

fn collect_candidate_paths(
    root: &Path,
    module_path: &Path,
    language: Language,
    extensions: &[&str],
    out: &mut Vec<ProjectFile>,
) {
    for group in candidate_path_groups(root, module_path, language, extensions) {
        out.extend(group.into_iter().filter(ProjectFile::exists));
        if !out.is_empty() {
            return;
        }
    }
}

/// Every path [`resolve_js_ts_module_specifier`] stats for a specifier that
/// resolves to no file at all.
///
/// The negative answer "no workspace file answers this specifier" is exactly
/// the absence of these paths, so a reader that recorded nothing when the
/// specifier resolved to nothing would be reusable in a workspace where it
/// now resolves. Only defined for the empty case: a specifier that resolved
/// stops at the group that answered it, and the reader names the file it
/// found instead.
pub fn js_ts_module_specifier_probed_paths(
    source_file: &ProjectFile,
    module_specifier: &str,
    language: Language,
    aliases: Option<&AliasResolver>,
) -> Vec<ProjectFile> {
    debug_assert!(
        resolve_js_ts_module_specifier(source_file, module_specifier, language, aliases).is_empty(),
        "the probed-path set is the stat list of a specifier that resolved to nothing"
    );
    let exts = language.extensions();
    let bases: Vec<PathBuf> = if module_specifier.starts_with('.') {
        vec![source_file.parent().join(module_specifier)]
    } else {
        let Some(aliases) = aliases else {
            return Vec::new();
        };
        aliases
            .candidate_bases(source_file, module_specifier)
            .into_iter()
            .chain(aliases.workspace_package_bases(module_specifier))
            .collect()
    };
    let mut probed = bases
        .iter()
        .flat_map(|base| candidate_path_groups(source_file.root(), base, language, exts))
        .flatten()
        .collect::<Vec<_>>();
    probed.sort();
    probed.dedup();
    probed
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

pub fn import_info_tokens(import: &ImportInfo) -> BTreeSet<String> {
    import
        .local_name()
        .map(str::to_string)
        .into_iter()
        .collect()
}

pub fn extract_js_ts_call_receiver(reference: &str) -> Option<String> {
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

#[allow(clippy::too_many_arguments)]
pub fn resolve_js_ts_module_binding_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    language: Language,
    file: &ProjectFile,
    module: &str,
    exported_name: &str,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> Vec<CodeUnit> {
    let files = crate::imports::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        return Vec::new();
    }

    let mut candidates =
        jsts_module_export_candidates(host, support, &files, exported_name, value_position);
    if value_position {
        candidates = jsts_value_space_candidates(host, candidates);
    } else {
        candidates = jsts_type_space_candidates(host, candidates);
    }
    if candidates.is_empty() && exported_name == "default" {
        for file in &files {
            candidates.extend(
                host.declarations(file)
                    .into_iter()
                    .filter(|unit| unit.identifier() == "default"),
            );
        }
        sort_units(&mut candidates);
        candidates.dedup();
        if value_position {
            candidates = jsts_value_space_candidates(host, candidates);
        } else {
            candidates = jsts_type_space_candidates(host, candidates);
        }
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_js_ts_direct_import_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    language: Language,
    file: &ProjectFile,
    imports: &JsTsImportBinder,
    name: &str,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> Option<Vec<CodeUnit>> {
    let mut saw_direct_import = false;
    let mut candidates = Vec::new();
    for binding in imports.resolvable_direct_bindings_for(name) {
        saw_direct_import = true;
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(name),
            ImportKind::Default => "default",
            _ => unreachable!("direct bindings contain only named/default imports"),
        };
        candidates.extend(resolve_js_ts_module_binding_candidates(
            host,
            support,
            language,
            file,
            &binding.module_specifier,
            exported_name,
            aliases,
            value_position,
        ));
    }
    if !saw_direct_import {
        return None;
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates)
}

/// One exact imported member endpoint. The declaration identity and the source
/// endpoint travel together so navigation and inverse usage extraction cannot
/// substitute an owner token for a descendant member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsTsResolvedImportedMember {
    pub declaration: CodeUnit,
    pub endpoint_range: Range,
}

/// Resolve a structured member chain from an already proven import binding.
///
/// This function deliberately accepts the binder's selected `ImportBinding`
/// instead of looking up a name itself. Binding selection is source-position
/// sensitive and belongs to `JsTsImportBinder`; module/export/member traversal
/// belongs here. Every branch remains in `ReceiverAnalysisOutcome`, and a
/// terminal is precise only when one declaration survives every segment.
#[allow(clippy::too_many_arguments)]
pub fn resolve_js_ts_imported_member_chain(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    language: Language,
    file: &ProjectFile,
    binding: &ImportBinding,
    chain: &JsTsImportedMemberChain<'_>,
    aliases: Option<&AliasResolver>,
    value_position: bool,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<JsTsResolvedImportedMember> {
    let (exported_name, remaining) = match binding.kind {
        ImportKind::Namespace | ImportKind::CommonJsRequire => {
            let Some((exported, remaining)) = chain.members.split_first() else {
                return ReceiverAnalysisOutcome::Unknown;
            };
            (exported.name.as_str(), remaining)
        }
        ImportKind::Named => {
            let Some(imported_name) = binding.imported_name.as_deref() else {
                return ReceiverAnalysisOutcome::Unknown;
            };
            (imported_name, chain.members.as_slice())
        }
        ImportKind::Default => ("default", chain.members.as_slice()),
        ImportKind::Glob => {
            return ReceiverAnalysisOutcome::Unsupported {
                reason: "glob_import_member_chain",
            };
        }
    };

    let resolved_files =
        resolve_js_ts_module_specifier(file, &binding.module_specifier, language, aliases);
    if resolved_files.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    if resolved_files.len() != 1 {
        return ReceiverAnalysisOutcome::Ambiguous(Vec::new());
    }

    let owners = resolve_js_ts_module_binding_candidates(
        host,
        support,
        language,
        file,
        &binding.module_specifier,
        exported_name,
        aliases,
        value_position,
    );
    let mut outcome = ReceiverAnalysisOutcome::single_precise_or_ambiguous(owners, budget);
    for member in remaining {
        outcome = resolve_imported_member_step(support, outcome, member, value_position, budget);
    }

    let Some(endpoint) = chain.endpoint() else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    match outcome {
        ReceiverAnalysisOutcome::Precise(declarations) => ReceiverAnalysisOutcome::Precise(
            declarations
                .into_iter()
                .map(|declaration| JsTsResolvedImportedMember {
                    declaration,
                    endpoint_range: endpoint.range,
                })
                .collect(),
        ),
        ReceiverAnalysisOutcome::Ambiguous(declarations) => ReceiverAnalysisOutcome::Ambiguous(
            declarations
                .into_iter()
                .map(|declaration| JsTsResolvedImportedMember {
                    declaration,
                    endpoint_range: endpoint.range,
                })
                .collect(),
        ),
        ReceiverAnalysisOutcome::Unknown => ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            ReceiverAnalysisOutcome::Unsupported { reason }
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ReceiverAnalysisOutcome::ExceededBudget { limit }
        }
    }
}

fn resolve_imported_member_step(
    support: &dyn BoundedDefinitionLookup,
    owners: ReceiverAnalysisOutcome<CodeUnit>,
    member: &ImportMemberChainOwner<'_>,
    value_position: bool,
    budget: ReceiverAnalysisBudget,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let (owners, inherited_ambiguity) = match owners {
        ReceiverAnalysisOutcome::Precise(owners) => (owners, false),
        ReceiverAnalysisOutcome::Ambiguous(owners) => (owners, true),
        ReceiverAnalysisOutcome::Unknown => return ReceiverAnalysisOutcome::Unknown,
        ReceiverAnalysisOutcome::Unsupported { reason } => {
            return ReceiverAnalysisOutcome::Unsupported { reason };
        }
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            return ReceiverAnalysisOutcome::ExceededBudget { limit };
        }
    };
    let branches = owners.into_iter().map(|owner| {
        let members_named = |name: &str| {
            support
                .members_for_owner(&owner, name)
                .into_iter()
                .filter(|candidate| candidate.source() == owner.source())
                .filter(|candidate| candidate.fq().parent().as_ref() == Some(owner.fq()))
                .collect::<Vec<_>>()
        };
        let mut candidates = members_named(&member.name);
        if value_position && owner.is_class() {
            let static_candidates = members_named(&format!("{}$static", member.name));
            if !static_candidates.is_empty() {
                candidates = static_candidates;
            }
        }
        ReceiverAnalysisOutcome::single_precise_or_ambiguous(candidates, budget)
    });
    let merged = ReceiverAnalysisOutcome::merge_branch_outcomes(branches, budget);
    if inherited_ambiguity {
        match merged {
            ReceiverAnalysisOutcome::Precise(values)
            | ReceiverAnalysisOutcome::Ambiguous(values) => {
                ReceiverAnalysisOutcome::Ambiguous(values)
            }
            other => other,
        }
    } else {
        merged
    }
}

fn jsts_module_export_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    files: &[ProjectFile],
    exported_name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let Some(index) = host.usage_index(None) else {
        return Vec::new();
    };

    let bindings = index.local_bindings_for_exported_name(files, exported_name);
    let mut candidates = Vec::new();
    for (file, local_name) in bindings {
        // An export names one exact local binding. Prefer its exact FQN before
        // the broad file-identifier index, which also returns same-terminal
        // class members such as `Store.getPreferences` for an exported
        // top-level `getPreferences` function.
        let mut file_candidates: Vec<_> = support
            .fqn(&local_name)
            .into_iter()
            .filter(|candidate| candidate.source() == &file)
            .collect();
        if file_candidates.is_empty() {
            file_candidates = support.file_identifier_in_files(&[file], &local_name);
        }
        candidates.extend(file_candidates);
    }

    if value_position {
        jsts_value_space_candidates(host, candidates)
    } else {
        jsts_type_space_candidates(host, candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        node_text, parse_commonjs_require_bindings_from_node,
        parse_commonjs_require_import_infos_from_node,
        parse_commonjs_require_import_syntaxes_from_node, parse_es_import_infos_from_node,
        parse_es_import_syntaxes_from_node, resolve_js_ts_import_info_paths,
    };
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::model::ImportInfo;
    use std::path::PathBuf;
    use tree_sitter::Parser;

    fn parse_typescript_import_infos(
        source: &str,
    ) -> Vec<brokk_bifrost_core::analyzer::model::ImportInfo> {
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
        assert_eq!(
            Some(&vec!["../types".to_string()]),
            imports[0].path.as_ref().map(|path| &path.segments)
        );
    }

    #[test]
    fn retains_exact_esm_import_nodes_and_kind() {
        let source = "import { original as current } from './module';";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let statement = root
            .named_children(&mut root.walk())
            .find(|child| child.kind() == "import_statement")
            .unwrap();
        let syntax = parse_es_import_syntaxes_from_node(statement, source);
        assert_eq!(1, syntax.len());
        let syntax = &syntax[0];
        assert_eq!(
            Some("original"),
            syntax.name.map(|node| node_text(node, source))
        );
        assert_eq!(
            Some("current"),
            syntax.alias.map(|node| node_text(node, source))
        );
        assert_eq!(
            Some("'./module'"),
            syntax.target.map(|node| node_text(node, source))
        );
        assert_eq!(Some(super::ImportKind::Named), syntax.kind);
        assert!(syntax.is_static);
        assert_eq!(statement, syntax.declaration);
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

    #[test]
    fn parses_typescript_commonjs_import_path_from_the_ast_literal() {
        let source = "const { makeThing } = require('./other');";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let declaration = root
            .named_children(&mut root.walk())
            .find(|child| child.kind() == "lexical_declaration")
            .unwrap();
        let imports = parse_commonjs_require_import_infos_from_node(declaration, source);

        assert_eq!(1, imports.len());
        assert_eq!(
            Some(&vec!["./other".to_string()]),
            imports[0].path.as_ref().map(|path| &path.segments)
        );
    }

    #[test]
    fn retains_commonjs_require_target_and_named_binding_nodes() {
        let source = "const { makeThing: localThing } = require('./other');";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let declaration = root
            .named_children(&mut root.walk())
            .find(|child| child.kind() == "lexical_declaration")
            .unwrap();
        let syntax = parse_commonjs_require_import_syntaxes_from_node(declaration, source);
        assert_eq!(1, syntax.len());
        let syntax = &syntax[0];
        assert_eq!(
            Some("makeThing"),
            syntax.name.map(|node| node_text(node, source))
        );
        assert_eq!(
            Some("localThing"),
            syntax.alias.map(|node| node_text(node, source))
        );
        assert_eq!(
            Some("'./other'"),
            syntax.target.map(|node| node_text(node, source))
        );
        assert_eq!(Some(super::ImportKind::Named), syntax.kind);
        assert!(!syntax.is_static);
    }

    #[test]
    fn side_effect_require_has_no_local_binding_kind() {
        let source = "require('./side-effect');";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let statement = tree.root_node().named_child(0).unwrap();

        let syntax = parse_commonjs_require_import_syntaxes_from_node(statement, source);
        assert_eq!(1, syntax.len());
        assert_eq!(None, syntax[0].kind);
        assert_eq!(
            Some("'./side-effect'"),
            syntax[0].target.map(|node| node_text(node, source))
        );
        assert!(parse_commonjs_require_bindings_from_node(statement, source).is_empty());
    }

    #[test]
    fn canonical_import_resolution_ignores_stale_raw_snippet() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/main.ts"), "").unwrap();
        std::fs::write(root.path().join("src/captured.ts"), "").unwrap();
        std::fs::write(root.path().join("src/stale.ts"), "").unwrap();
        let source_file = brokk_bifrost_core::analyzer::ProjectFile::new(
            root.path().to_path_buf(),
            PathBuf::from("src/main.ts"),
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();
        let tree = parser
            .parse("import value from './captured';", None)
            .unwrap();
        let root_node = tree.root_node();
        let statement = root_node
            .named_children(&mut root_node.walk())
            .next()
            .unwrap();
        let mut import =
            parse_es_import_infos_from_node(statement, "import value from './captured';")
                .pop()
                .unwrap();
        import.raw_snippet = "import value from './stale';".to_string();
        let resolved =
            resolve_js_ts_import_info_paths(&source_file, &import, Language::TypeScript, None);
        assert_eq!(
            vec![brokk_bifrost_core::analyzer::ProjectFile::new(
                root.path().to_path_buf(),
                PathBuf::from("src/captured.ts"),
            )],
            resolved
        );
    }

    #[test]
    fn canonical_import_resolution_reports_unavailable_structured_path() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/main.ts"), "").unwrap();
        std::fs::write(root.path().join("src/stale.ts"), "").unwrap();
        let source_file = brokk_bifrost_core::analyzer::ProjectFile::new(
            root.path().to_path_buf(),
            PathBuf::from("src/main.ts"),
        );
        let import = ImportInfo {
            raw_snippet: "import value from './stale';".to_string(),
            is_wildcard: false,
            is_global: false,
            identifier: Some("value".to_string()),
            alias: None,
            path: None,
            binder_span: None,
        };
        assert!(
            resolve_js_ts_import_info_paths(&source_file, &import, Language::TypeScript, None)
                .is_empty()
        );
    }

    #[test]
    fn splits_bare_specifiers_into_their_npm_package_and_subpath() {
        use super::npm_package_of_module_specifier as split;

        assert_eq!(Some(("left-pad", None)), split("left-pad"));
        assert_eq!(Some(("left-pad", Some("dist"))), split("left-pad/dist"));
        assert_eq!(
            Some(("left-pad", Some("dist/index"))),
            split("left-pad/dist/index")
        );
        assert_eq!(Some(("@scope/pkg", None)), split("@scope/pkg"));
        assert_eq!(Some(("@scope/pkg", Some("deep"))), split("@scope/pkg/deep"));
        assert_eq!(
            Some(("@scope/pkg", Some("deep/deeper"))),
            split("@scope/pkg/deep/deeper")
        );
        // A trailing slash names the package itself, not an empty subpath.
        assert_eq!(Some(("left-pad", None)), split("left-pad/"));
    }

    #[test]
    fn refuses_specifiers_that_do_not_address_a_package() {
        use super::npm_package_of_module_specifier as split;

        assert_eq!(None, split(""));
        assert_eq!(None, split("./local"));
        assert_eq!(None, split("../sibling"));
        assert_eq!(None, split("/absolute"));
        // A scope with no package name is not an npm coordinate.
        assert_eq!(None, split("@scope"));
    }

    #[test]
    fn folds_the_node_scheme_into_the_bare_builtin_identity() {
        use super::js_ts_module_identity as classify;

        let bare = classify("fs").expect("a bare builtin names a module");
        let scheme = classify("node:fs").expect("a node: builtin names a module");
        assert_eq!(bare, scheme, "one module, one identity");
        assert_eq!("fs", scheme.specifier);
        assert_eq!("fs", scheme.package);
        assert_eq!(None, scheme.subpath);

        // A builtin subpath keeps its bare root and splits like any other.
        let bare_subpath = classify("fs/promises").expect("a builtin subpath names a module");
        let scheme_subpath =
            classify("node:fs/promises").expect("a node: builtin subpath names a module");
        assert_eq!(bare_subpath, scheme_subpath);
        assert_eq!("fs/promises", scheme_subpath.specifier);
        assert_eq!("fs", scheme_subpath.package);
        assert_eq!(Some("promises"), scheme_subpath.subpath);
    }

    #[test]
    fn classifies_packages_subpaths_and_workspace_paths() {
        use super::js_ts_module_identity as classify;

        let scoped = classify("@scope/pkg").expect("a scoped package names a module");
        assert_eq!("@scope/pkg", scoped.specifier);
        assert_eq!("@scope/pkg", scoped.package);
        assert_eq!(None, scoped.subpath);

        let subpath = classify("pkg/sub").expect("a package subpath names a module");
        assert_eq!("pkg/sub", subpath.specifier);
        assert_eq!("pkg", subpath.package);
        assert_eq!(Some("sub"), subpath.subpath);

        // A trailing slash names the package itself, not an empty subpath.
        let trailing = classify("pkg/").expect("a trailing slash still names the package");
        assert_eq!("pkg", trailing.specifier);
        assert_eq!("pkg", trailing.package);
        assert_eq!(None, trailing.subpath);

        assert_eq!(None, classify("./rel"));
        assert_eq!(None, classify("/abs"));
    }
}
