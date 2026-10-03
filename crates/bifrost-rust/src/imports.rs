use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::common::node_span;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind, StructuredImportScope,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::rust_facts::RustImportSourceOccurrences;
use brokk_bifrost_core::analyzer::source_facts::SourceImportId;
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use std::borrow::Cow;
use tree_sitter::Node;

use crate::declarations::{rust_node_text, rust_package_name};
use crate::graph_support::{ReferenceContextResult, RustSource, resolve_module_package};
use crate::lexical_scope::{RustCfgCondition, rust_cfg_condition};
use crate::syntax::{outer_attributes, unwrap_attributes};

/// Re-exported from core, where the persisted Rust usage facts that carry it
/// live. It stays spelled `crate::imports::RustVisibility` for every Rust
/// caller, because visibility arithmetic is this module's subject.
pub use brokk_bifrost_core::analyzer::rust_facts::RustVisibility;

/// The semantic binding introduced by one Rust import leaf.
///
/// Rust's `use path as _` deliberately imports the target without introducing
/// a referenceable local name. That is distinct from a glob, which imports the
/// target module's public names into the importing scope. The distinction is
/// kept here, beside the parser-owned [`ImportInfo`] projection, so consumers
/// do not infer it from rendered snippets or use `_` as a sentinel name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustImportBindingName<'a> {
    Named(Cow<'a, str>),
    Unnamed,
    Glob,
}

impl<'a> RustImportBindingName<'a> {
    pub fn named(&self) -> Option<&str> {
        match self {
            Self::Named(name) => Some(name.as_ref()),
            Self::Unnamed | Self::Glob => None,
        }
    }

    pub fn is_glob(&self) -> bool {
        matches!(self, Self::Glob)
    }
}

/// Classify the local binding represented by parser-derived import fields.
///
/// `ImportInfo::local_name` already implements the parser field precedence
/// (`alias`, `identifier`, then the structured path tail). Reusing that
/// projection keeps all Rust import consumers on the same structured source of
/// truth while giving underscore imports their semantic no-name state.
pub fn rust_import_binding_name<'a>(import: &'a ImportInfo) -> RustImportBindingName<'a> {
    if import.is_wildcard {
        return RustImportBindingName::Glob;
    }
    if import.alias.as_deref() == Some("_") {
        return RustImportBindingName::Unnamed;
    }
    let name = import
        .local_name()
        .expect("non-glob Rust import must have a parser-derived local name");
    RustImportBindingName::Named(Cow::Borrowed(name))
}

#[derive(Debug, Clone)]
pub struct RustImportInfo {
    pub info: ImportInfo,
    pub visibility: RustVisibility,
    /// Whether an `extern crate` declaration carries a blanket `#[macro_use]`
    /// attribute and imports the dependency's exported macros.
    pub is_macro_use: bool,
    /// The exact token naming the imported entity before any `as` alias.
    /// Wildcard imports have no single target token.
    pub target_span: Option<Span>,
    /// The leaf is `self` in a grouped import (`use a::m::{self}`). It names
    /// the module the prefix reaches and binds only the type namespace: a
    /// value or macro spelled like the module's last segment is not imported
    /// (Rust Reference, "Use declarations", `self` imports). Its target token
    /// is the `self` keyword itself.
    pub module_self: bool,
}

/// Exact primary-tree syntax handles used to attach canonical source ids.
/// These handles are transient and never leave the live parse tree.
#[derive(Clone)]
pub(crate) struct RustImportSourceNodes<'tree> {
    pub(crate) declaration: Node<'tree>,
    pub(crate) target: Option<Node<'tree>>,
    pub(crate) alias: Option<Node<'tree>>,
    pub(crate) lexical_scopes: Vec<Node<'tree>>,
    pub(crate) owner_scope: Option<Node<'tree>>,
    pub(crate) local_scope: Option<Node<'tree>>,
}

impl RustImportInfo {
    /// The parser-owned path for this Rust import. Every projected Rust
    /// import carries one; keeping the accessor checked prevents consumers
    /// from silently falling back to the display snippet.
    pub fn path(&self) -> &[String] {
        self.info
            .path
            .as_ref()
            .expect("Rust import projection must carry a structured path")
            .segments
            .as_slice()
    }

    /// Whether this event is an `extern crate` declaration. The distinction
    /// is part of the structured path kind, not a second Rust-only flag.
    pub fn is_extern_crate(&self) -> bool {
        self.info
            .path
            .as_ref()
            .expect("Rust import projection must carry a structured path")
            .kind
            == Some(StructuredImportPathKind::ExternCrate)
    }

    pub fn binding_name(&self) -> RustImportBindingName<'_> {
        rust_import_binding_name(&self.info)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustImportOwner {
    Module {
        module: String,
        start: usize,
        end: usize,
    },
    LocalOnly {
        module: String,
        module_start: usize,
        module_end: usize,
        start: usize,
        end: usize,
    },
}

#[derive(Clone)]
struct RustImportOwnerProjection<'tree> {
    owner_scope: Option<Node<'tree>>,
    local_scope: Option<Node<'tree>>,
    owner: RustImportOwner,
}

#[derive(Debug, Clone)]
pub struct RustProjectedImport {
    pub import: RustImportInfo,
    pub owner: RustImportOwner,
    pub cfg_condition: RustCfgCondition,
    /// The coordinated producer's per-leaf identity. Standalone legacy
    /// projection helpers leave this unset because they have no source arena.
    pub source_import_id: Option<SourceImportId>,
    /// Set only after a primary coordinated event interns the exact syntax
    /// handles through its shared source collector.
    pub source_occurrences: Option<RustImportSourceOccurrences>,
}

pub(crate) fn rust_import_projection_with_source_nodes<'tree>(
    root: Node<'tree>,
    source: &str,
    base_module: &str,
) -> Vec<(RustProjectedImport, RustImportSourceNodes<'tree>)> {
    let mut projected = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        let declaration = unwrap_attributes(node);
        if declaration.kind() == "extern_crate_declaration" {
            if let Some((import, source_nodes)) =
                rust_external_crate_import(node, source, base_module)
            {
                projected.push((import, source_nodes));
            }
            continue;
        }
        if declaration.kind() == "use_declaration" {
            let owner = rust_import_owner(declaration, source, base_module);
            let cfg_condition = rust_cfg_condition(node, source);
            projected.extend(
                rust_imports_with_visibility_from_use_declaration_with_sources(declaration, source)
                    .into_iter()
                    .map(|leaf| {
                        let source_nodes = RustImportSourceNodes {
                            declaration: node,
                            target: leaf.target,
                            alias: leaf.alias,
                            lexical_scopes: leaf.lexical_scopes,
                            owner_scope: owner.owner_scope,
                            local_scope: owner.local_scope,
                        };
                        (
                            RustProjectedImport {
                                import: leaf.import,
                                owner: owner.owner.clone(),
                                cfg_condition: cfg_condition.clone(),
                                source_import_id: None,
                                source_occurrences: None,
                            },
                            source_nodes,
                        )
                    }),
            );
            continue;
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }
    projected
}

pub fn rust_import_projection<'tree>(
    root: Node<'tree>,
    source: &str,
    base_module: &str,
) -> Vec<RustProjectedImport> {
    rust_import_projection_with_source_nodes(root, source, base_module)
        .into_iter()
        .map(|(projected, _)| projected)
        .collect()
}

fn rust_external_crate_import<'tree>(
    node: Node<'tree>,
    source: &str,
    base_module: &str,
) -> Option<(RustProjectedImport, RustImportSourceNodes<'tree>)> {
    let declaration = unwrap_attributes(node);
    let name_node = declaration.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let alias_node = declaration.child_by_field_name("alias");
    let alias = alias_node
        .map(|node| rust_node_text(node, source).trim().to_string())
        .filter(|alias| !alias.is_empty());
    let binder_node = alias_node.unwrap_or(name_node);
    let import = RustImportInfo {
        info: ImportInfo {
            raw_snippet: rust_node_text(declaration, source).to_string(),
            is_wildcard: false,
            is_global: false,
            identifier: Some(name.to_string()),
            alias,
            path: Some(StructuredImportPath {
                segments: vec![name.to_string()],
                kind: Some(StructuredImportPathKind::ExternCrate),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: declaration.start_byte(),
            }),
            binder_span: Some(node_span(binder_node)),
        },
        visibility: rust_item_visibility(declaration, source),
        is_macro_use: rust_item_attribute(node, source, "macro_use")
            .is_some_and(|attribute| attribute.child_by_field_name("arguments").is_none()),
        target_span: Some(node_span(name_node)),
        module_self: false,
    };
    let owner = rust_import_owner(declaration, source, base_module);
    let source_nodes = RustImportSourceNodes {
        declaration,
        target: Some(name_node),
        alias: alias_node,
        lexical_scopes: Vec::new(),
        owner_scope: owner.owner_scope,
        local_scope: owner.local_scope,
    };
    Some((
        RustProjectedImport {
            import,
            owner: owner.owner,
            cfg_condition: rust_cfg_condition(node, source),
            source_import_id: None,
            source_occurrences: None,
        },
        source_nodes,
    ))
}

/// Whether an item carries a preceding outer attribute with the exact path.
///
/// Tree-sitter-rust represents outer attributes as preceding siblings rather
/// than children of the item. Walking the contiguous attribute run preserves
/// that structure without interpreting the item's rendered source text.
pub(crate) fn rust_item_has_attribute(node: Node<'_>, source: &str, expected: &str) -> bool {
    rust_item_attribute(node, source, expected).is_some()
}

fn rust_item_attribute<'tree>(
    node: Node<'tree>,
    source: &str,
    expected: &str,
) -> Option<Node<'tree>> {
    for attribute_item in outer_attributes(node) {
        if matches!(attribute_item.kind(), "line_comment" | "block_comment") {
            continue;
        }
        if attribute_item.kind() != "attribute_item" {
            break;
        }
        let Some(attribute) = attribute_item.named_child(0) else {
            break;
        };
        let Some(path) = attribute.named_child(0) else {
            break;
        };
        if source.get(path.start_byte()..path.end_byte()) == Some(expected) {
            return Some(attribute);
        }
    }
    None
}

pub fn rust_module_extents(
    root: Node<'_>,
    source: &str,
    base_module: &str,
) -> Vec<(String, usize, usize)> {
    let mut extents = vec![(base_module.to_string(), root.start_byte(), root.end_byte())];
    let mut pending = vec![(root, base_module.to_string())];
    while let Some((node, owner)) = pending.pop() {
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            let declaration = unwrap_attributes(child);
            if declaration.kind() == "mod_item"
                && let Some(name) = declaration
                    .child_by_field_name("name")
                    .and_then(|name| simple_segment(name, source))
                && let Some(body) = declaration.child_by_field_name("body")
            {
                let module = if owner.is_empty() {
                    name
                } else {
                    format!("{owner}.{name}")
                };
                extents.push((module.clone(), body.start_byte(), body.end_byte()));
                pending.push((body, module));
            } else {
                pending.push((child, owner.clone()));
            }
        }
    }
    extents
}

fn rust_import_owner<'tree>(
    node: Node<'tree>,
    source: &str,
    base_module: &str,
) -> RustImportOwnerProjection<'tree> {
    let mut modules = Vec::new();
    let mut module_extent = None;
    let mut local_extent = None;
    let mut owner_scope = None;
    let mut local_scope = None;
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "block" | "function_item" | "closure_expression" | "async_block" => {
                if local_extent.is_none() {
                    local_extent = Some((ancestor.start_byte(), ancestor.end_byte()));
                    local_scope = Some(ancestor);
                }
            }
            "mod_item" => {
                if let Some(name) = ancestor
                    .child_by_field_name("name")
                    .and_then(|name| simple_segment(name, source))
                {
                    modules.push(name);
                    if module_extent.is_none() {
                        let body = ancestor.child_by_field_name("body").unwrap_or(ancestor);
                        module_extent = Some((body.start_byte(), body.end_byte()));
                        owner_scope = Some(body);
                    }
                }
            }
            _ => {}
        }
        current = ancestor.parent();
    }
    modules.reverse();
    let mut owner = base_module.to_string();
    for module in modules {
        if !owner.is_empty() {
            owner.push('.');
        }
        owner.push_str(&module);
    }
    let module_extent = module_extent.unwrap_or((0, source.len()));
    let owner = if let Some((start, end)) = local_extent {
        RustImportOwner::LocalOnly {
            module: owner,
            module_start: module_extent.0,
            module_end: module_extent.1,
            start,
            end,
        }
    } else {
        RustImportOwner::Module {
            module: owner,
            start: module_extent.0,
            end: module_extent.1,
        }
    };
    RustImportOwnerProjection {
        owner_scope,
        local_scope,
        owner,
    }
}

fn simple_segment(node: Node<'_>, source: &str) -> Option<String> {
    let text = rust_node_text(node, source).trim();
    (!text.is_empty()).then(|| text.to_string())
}

pub struct RustFocusedUsePath<'tree> {
    pub full_path: String,
    pub segments: Vec<String>,
    pub root: Node<'tree>,
}

pub fn rust_focused_use_path<'tree>(
    focused: Node<'tree>,
    source: &str,
) -> Option<RustFocusedUsePath<'tree>> {
    let mut prefix = focused;
    while let Some(parent) = prefix.parent() {
        if !matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) {
            break;
        }
        if parent
            .child_by_field_name("name")
            .is_some_and(|name| node_contains(name, focused))
        {
            if focused.kind() == "self" {
                prefix = parent.child_by_field_name("path")?;
                break;
            }
            prefix = parent;
            continue;
        }
        break;
    }

    let mut path_nodes = vec![prefix];
    let mut current = prefix;
    let mut found_use = false;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "scoped_use_list" => {
                if parent
                    .child_by_field_name("list")
                    .is_some_and(|list| node_contains(list, current))
                    && let Some(path) = parent.child_by_field_name("path")
                {
                    path_nodes.push(path);
                }
            }
            "use_declaration" => {
                found_use = true;
                break;
            }
            _ => {}
        }
        current = parent;
    }
    if !found_use {
        return None;
    }

    path_nodes.reverse();
    let root = rust_use_path_root(*path_nodes.first()?);
    let mut segments = Vec::new();
    let path_node_count = path_nodes.len();
    for node in path_nodes {
        if node.kind() == "self" && path_node_count > 1 {
            continue;
        }
        segments.extend(rust_use_path_segments(node, source));
    }
    (!segments.is_empty()).then(|| RustFocusedUsePath {
        full_path: segments.join("::"),
        segments,
        root,
    })
}

fn node_contains(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

fn rust_use_path_root(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        let Some(path) = node.child_by_field_name("path") else {
            break;
        };
        node = path;
    }
    node
}

/// The declarations a file's `use` items name, resolved through the store. The
/// caller owns the memo; this is the miss path.
pub fn rust_imported_code_units(
    index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> HashSet<CodeUnit> {
    let package = rust_package_name(file);
    let mut resolved = HashSet::default();
    for import in imports {
        if let Some(target_fq_name) = resolve_rust_import_fq_name(file, &package, import) {
            resolved.extend(index.definitions(&target_fq_name));
        }
    }
    resolved
}

pub fn rust_could_import_file(
    index: &dyn CodeUnitIndex,
    source_file: &ProjectFile,
    imports: &[ImportInfo],
    target: &ProjectFile,
) -> bool {
    let package = rust_package_name(source_file);
    imports.iter().any(|import| {
        resolve_rust_import_fq_name(source_file, &package, import)
            .into_iter()
            .any(|fq_name| {
                index
                    .definitions(&fq_name)
                    .any(|code_unit| code_unit.source() == target)
            })
    })
}

pub fn rust_imports_from_use_declaration(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    rust_imports_with_visibility_from_use_declaration(node, source)
        .into_iter()
        .map(|import| import.info)
        .collect()
}

pub fn rust_imports_with_visibility_from_use_declaration(
    node: Node<'_>,
    source: &str,
) -> Vec<RustImportInfo> {
    rust_imports_with_visibility_from_use_declaration_with_sources(node, source)
        .into_iter()
        .map(|leaf| leaf.import)
        .collect()
}

pub(crate) struct RustImportProjectionLeaf<'tree> {
    pub(crate) import: RustImportInfo,
    pub(crate) target: Option<Node<'tree>>,
    pub(crate) alias: Option<Node<'tree>>,
    pub(crate) lexical_scopes: Vec<Node<'tree>>,
}

pub(crate) fn rust_imports_with_visibility_from_use_declaration_with_sources<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Vec<RustImportProjectionLeaf<'tree>> {
    if node.kind() != "use_declaration" {
        return Vec::new();
    }
    let Some(argument) = node.child_by_field_name("argument") else {
        return Vec::new();
    };
    let lexical_scope_nodes = rust_import_lexical_scope_nodes(node);
    let declaration = RustUseDeclaration {
        visibility: rust_item_visibility(node, source),
        lexical_scopes: lexical_scope_nodes
            .iter()
            .map(|scope| StructuredImportScope {
                start_byte: scope.start_byte(),
                end_byte: scope.end_byte(),
            })
            .collect(),
        lexical_scope_nodes,
        declaration_start_byte: node.start_byte(),
    };
    let mut imports = Vec::new();
    collect_rust_use_tree(argument, source, &declaration, &mut imports);
    imports
}

pub(crate) fn rust_import_lexical_scope_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut scopes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "declaration_list" | "block") {
            scopes.push(parent);
        }
        current = parent.parent();
    }
    scopes.reverse();
    scopes
}

fn collect_rust_use_tree<'tree>(
    node: Node<'tree>,
    source: &str,
    declaration: &RustUseDeclaration<'tree>,
    out: &mut Vec<RustImportProjectionLeaf<'tree>>,
) {
    let mut pending = vec![(node, Vec::<RustUsePathSegment<'tree>>::new(), false)];
    while let Some((node, prefix, leading_absolute)) = pending.pop() {
        match node.kind() {
            "scoped_use_list" => {
                let mut scoped_prefix = prefix;
                let mut scoped_absolute = leading_absolute;
                if let Some(path) = node.child_by_field_name("path") {
                    let path_is_absolute = rust_use_path_is_absolute(path);
                    if path_is_absolute {
                        scoped_prefix.clear();
                    }
                    scoped_prefix.extend(rust_use_path_segments_with_spans(path, source));
                    scoped_absolute |= path_is_absolute;
                }
                if let Some(list) = node.child_by_field_name("list") {
                    pending.push((list, scoped_prefix, scoped_absolute));
                }
            }
            "use_list" => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                pending.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|child| (child, prefix.clone(), leading_absolute)),
                );
            }
            "use_as_clause" => {
                let Some(path_node) = node.child_by_field_name("path") else {
                    continue;
                };
                let Some(alias_node) = node.child_by_field_name("alias") else {
                    continue;
                };
                let alias = rust_node_text(alias_node, source).trim();
                if alias.is_empty() {
                    continue;
                }
                let path_is_absolute = rust_use_path_is_absolute(path_node);
                let mut path = if path_is_absolute { Vec::new() } else { prefix };
                // In a grouped import, `self` denotes the entity named by the
                // prefix rather than a literal trailing path component:
                // `use crate::service::{self as svc}` binds `svc` to
                // `crate::service`, not to `crate::service::self`.
                let module_self = path_node.kind() == "self" && !path.is_empty();
                if !module_self {
                    path.extend(rust_use_path_segments_with_spans(path_node, source));
                }
                let Some(identifier) = path.last().map(|segment| segment.name.clone()) else {
                    continue;
                };
                let target_node = if module_self {
                    Some(path_node)
                } else {
                    path.last().map(|segment| segment.node)
                };
                out.push(declaration.leaf(
                    path,
                    false,
                    Some(identifier),
                    Some(alias.to_string()),
                    Some(node_span(alias_node)),
                    target_node,
                    Some(alias_node),
                    leading_absolute || path_is_absolute,
                    module_self,
                ));
            }
            "use_wildcard" => {
                let path_node = first_named_child(node);
                let path_is_absolute = path_node.is_some_and(rust_use_path_is_absolute);
                let mut path = if path_is_absolute { Vec::new() } else { prefix };
                if let Some(path_node) = path_node {
                    path.extend(rust_use_path_segments_with_spans(path_node, source));
                }
                if !path.is_empty() {
                    out.push(declaration.leaf(
                        path,
                        true,
                        None,
                        None,
                        None,
                        None,
                        None,
                        leading_absolute || path_is_absolute,
                        false,
                    ));
                }
            }
            "crate" | "identifier" | "metavariable" | "scoped_identifier" | "self" | "super" => {
                let path_is_absolute = rust_use_path_is_absolute(node);
                let mut path = if path_is_absolute { Vec::new() } else { prefix };
                let prefix_was_empty = path.is_empty();
                let module_self = node.kind() == "self" && !prefix_was_empty;
                if !module_self {
                    path.extend(rust_use_path_segments_with_spans(node, source));
                }
                let Some(identifier) = path.last().map(|segment| segment.name.clone()) else {
                    continue;
                };
                let binder_span = rust_use_leaf_binder_node(node, prefix_was_empty).map(node_span);
                let target_node = if module_self {
                    Some(node)
                } else {
                    path.last().map(|segment| segment.node)
                };
                out.push(declaration.leaf(
                    path,
                    false,
                    Some(identifier),
                    None,
                    binder_span,
                    target_node,
                    None,
                    leading_absolute || path_is_absolute,
                    module_self,
                ));
            }
            _ => {}
        }
    }
}

#[derive(Clone)]
struct RustUsePathSegment<'tree> {
    name: String,
    span: Span,
    node: Node<'tree>,
}

fn rust_use_path_segments(node: Node<'_>, source: &str) -> Vec<String> {
    rust_use_path_segments_with_spans(node, source)
        .into_iter()
        .map(|segment| segment.name)
        .collect()
}

fn rust_use_path_segments_with_spans<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Vec<RustUsePathSegment<'tree>> {
    let mut segments = Vec::new();
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(name) = node.child_by_field_name("name") {
                    pending.push(name);
                }
                if let Some(path) = node.child_by_field_name("path") {
                    pending.push(path);
                }
            }
            "crate" | "identifier" | "type_identifier" | "metavariable" | "self" | "super" => {
                let segment = rust_node_text(node, source).trim();
                if !segment.is_empty() {
                    segments.push(RustUsePathSegment {
                        name: segment.to_string(),
                        span: node_span(node),
                        node,
                    });
                }
            }
            _ => {}
        }
    }
    segments
}

/// Whether a structured Rust use path starts with the grammar's root `::`
/// anchor. A scoped identifier with no `path` field is exactly the tree-sitter
/// representation of `::name`; walking its `path` fields reaches that root
/// without inspecting source text.
fn rust_use_path_is_absolute(mut node: Node<'_>) -> bool {
    while node.kind() == "scoped_identifier" {
        let Some(path) = node.child_by_field_name("path") else {
            return true;
        };
        node = path;
    }
    false
}

pub fn rust_item_visibility(node: Node<'_>, source: &str) -> RustVisibility {
    // Trait members and enum variant fields are accessible through their
    // owner. Access to that owner is checked independently through its route.
    if node
        .parent()
        .and_then(|body| body.parent())
        .is_some_and(|owner| matches!(owner.kind(), "trait_item" | "enum_variant"))
    {
        return RustVisibility::Public;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "visibility_modifier")
        .map(|visibility| rust_visibility_from_modifier(visibility, source))
        .unwrap_or(RustVisibility::Private)
}

pub fn rust_visibility_from_modifier(node: Node<'_>, source: &str) -> RustVisibility {
    if node.kind() == "crate" {
        return RustVisibility::Crate;
    }
    let mut cursor = node.walk();
    let Some(scope) = node.named_children(&mut cursor).next() else {
        return RustVisibility::Public;
    };
    match scope.kind() {
        "crate" => RustVisibility::Crate,
        "self" => RustVisibility::SelfModule,
        "super" => RustVisibility::SuperModule,
        _ => {
            let segments = rust_use_path_segments(scope, source);
            if segments.is_empty() {
                RustVisibility::Private
            } else {
                RustVisibility::InPath(segments)
            }
        }
    }
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

/// The facts every leaf of one `use` tree shares: the declaration's
/// visibility, the lexical scopes it sits in, and its start byte. One value is
/// built per `use_declaration`, and every [`RustImportInfo`] the tree walk
/// emits reads from it, so a leaf constructor only names what varies per leaf.
struct RustUseDeclaration<'tree> {
    visibility: RustVisibility,
    lexical_scopes: Vec<StructuredImportScope>,
    lexical_scope_nodes: Vec<Node<'tree>>,
    declaration_start_byte: usize,
}

impl<'tree> RustUseDeclaration<'tree> {
    /// One import this declaration introduces: `path` is the leaf's full
    /// segment list, and `binder_span` is the token spelling the bound name
    /// where the leaf has one.
    #[expect(
        clippy::too_many_arguments,
        reason = "each leaf carries the independent AST and spelling projections"
    )]
    fn leaf(
        &self,
        path: Vec<RustUsePathSegment<'tree>>,
        is_wildcard: bool,
        identifier: Option<String>,
        alias: Option<String>,
        binder_span: Option<Span>,
        target_node: Option<Node<'tree>>,
        alias_node: Option<Node<'tree>>,
        leading_absolute: bool,
        module_self: bool,
    ) -> RustImportProjectionLeaf<'tree> {
        assert_eq!(is_wildcard, target_node.is_none());
        // The span keeps naming the imported entity by its path, so a
        // `{self}` leaf spells its module's last prefix segment here while its
        // target occurrence is the `self` token.
        let target_span = if is_wildcard {
            None
        } else {
            path.last().map(|segment| segment.span)
        };
        let path = path
            .into_iter()
            .map(|segment| segment.name)
            .collect::<Vec<_>>();
        let rendered_path = path.join("::");
        let prefix = self.rendered_use_prefix();
        let anchor = if leading_absolute { "::" } else { "" };
        let raw_snippet = if is_wildcard {
            format!("{prefix}{anchor}{rendered_path}::*;")
        } else if let Some(alias) = &alias {
            format!("{prefix}{anchor}{rendered_path} as {alias};")
        } else {
            format!("{prefix}{anchor}{rendered_path};")
        };
        RustImportProjectionLeaf {
            import: RustImportInfo {
                info: ImportInfo {
                    raw_snippet,
                    is_wildcard,
                    is_global: leading_absolute,
                    identifier,
                    alias,
                    path: Some(StructuredImportPath {
                        segments: path,
                        kind: Some(StructuredImportPathKind::Namespace),
                        lexical_prefixes: Vec::new(),
                        lexical_scopes: self.lexical_scopes.clone(),
                        declaration_start_byte: self.declaration_start_byte,
                    }),
                    binder_span,
                },
                visibility: self.visibility.clone(),
                is_macro_use: false,
                target_span,
                module_self,
            },
            target: target_node,
            alias: alias_node,
            lexical_scopes: self.lexical_scope_nodes.clone(),
        }
    }

    /// The canonical `use` keyword with this declaration's visibility
    /// qualifier, ready to prepend to a rendered path.
    fn rendered_use_prefix(&self) -> Cow<'static, str> {
        match &self.visibility {
            RustVisibility::Private => Cow::Borrowed("use "),
            RustVisibility::Public => Cow::Borrowed("pub use "),
            RustVisibility::Crate => Cow::Borrowed("pub(crate) use "),
            RustVisibility::SelfModule => Cow::Borrowed("pub(self) use "),
            RustVisibility::SuperModule => Cow::Borrowed("pub(super) use "),
            RustVisibility::InPath(scope) => {
                Cow::Owned(format!("pub(in {}) use ", scope.join("::")))
            }
        }
    }
}

/// The token that spells the name a plain (un-aliased) use-tree leaf binds:
/// a scoped path's final `name` segment, or the leaf identifier itself.
/// `None` for `{self}` with a group prefix -- the bound name is then spelled
/// by the prefix's last segment, which sits outside this leaf node.
fn rust_use_leaf_binder_node(node: Node<'_>, prefix_was_empty: bool) -> Option<Node<'_>> {
    match node.kind() {
        "scoped_identifier" => node.child_by_field_name("name"),
        "identifier" | "metavariable" | "crate" | "super" => Some(node),
        "self" if prefix_was_empty => Some(node),
        _ => None,
    }
}

#[cfg(test)]
mod macro_use_tests {
    use super::*;
    use tree_sitter::Parser;

    #[test]
    fn selective_macro_use_is_not_a_blanket_macro_import() {
        let source = "#[macro_use]\n// Preserve the attribute across comments.\nextern crate all;\n#[macro_use(a, b)]\nextern crate selected;\nextern crate ordinary;\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let imports = rust_import_projection(tree.root_node(), source, "");
        let flags: Vec<_> = imports
            .iter()
            .map(|binding| {
                (
                    binding.import.info.identifier.as_deref().unwrap(),
                    binding.import.is_macro_use,
                )
            })
            .collect();
        assert_eq!(
            flags,
            vec![("all", true), ("selected", false), ("ordinary", false)]
        );
    }

    #[test]
    fn import_binding_name_distinguishes_unnamed_named_and_glob() {
        let source = "use crate::Trait as _;\nuse crate::Named;\nuse crate::module::*;\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("load Rust grammar");
        let tree = parser.parse(source, None).expect("parse Rust imports");
        let mut cursor = tree.root_node().walk();
        let imports: Vec<_> = tree
            .root_node()
            .named_children(&mut cursor)
            .filter(|node| node.kind() == "use_declaration")
            .flat_map(|node| rust_imports_with_visibility_from_use_declaration(node, source))
            .collect();

        assert_eq!(imports[0].binding_name(), RustImportBindingName::Unnamed);
        assert_eq!(imports[0].info.alias.as_deref(), Some("_"));
        assert_eq!(
            imports[0]
                .path()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["crate", "Trait"]
        );
        assert_eq!(
            imports[1].binding_name(),
            RustImportBindingName::Named(Cow::Borrowed("Named"))
        );
        assert_eq!(imports[2].binding_name(), RustImportBindingName::Glob);
    }
}

pub fn rust_import_body(raw_import: &str) -> Option<&str> {
    let trimmed = raw_import.trim().trim_end_matches(';').trim();
    if let Some(body) = trimmed.strip_prefix("use ") {
        return Some(body.trim());
    }
    if let Some(body) = trimmed.strip_prefix("pub use ") {
        return Some(body.trim());
    }
    let (visibility, body) = trimmed.split_once(" use ")?;
    let visibility = visibility.trim();
    (visibility.starts_with("pub(") || visibility == "crate").then_some(body.trim())
}

pub fn split_rust_import_module_and_name(raw_import: &str) -> Option<(String, String)> {
    let body = rust_import_body(raw_import)?;
    let path = body
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(body)
        .trim();
    if path.ends_with("::*") {
        return None;
    }

    let (module_specifier, imported_name) = path.rsplit_once("::")?;
    Some((module_specifier.to_string(), imported_name.to_string()))
}

pub fn resolve_rust_module_path_with_crate(
    package: &str,
    crate_package: &str,
    module_specifier: &str,
) -> Option<String> {
    let trimmed = module_specifier.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "crate" {
        return Some(crate_package.to_string());
    }

    let segments: Vec<_> = trimmed
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    resolve_rust_module_segments_with_crate(package, crate_package, &segments)
}

/// Resolve an import's module specifier against the lexical module containing
/// the import. In particular, `self` and `super` must start from an inline
/// module's package rather than the package inferred from the backing file.
pub fn resolve_rust_import_package_scoped(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    module_specifier: &str,
) -> ReferenceContextResult<Option<String>> {
    let segments = parse_symbol_path(Language::Rust, module_specifier);
    if !matches!(segments.first().map(String::as_str), Some("self" | "super")) {
        return resolve_module_package(rust, token, file, module_specifier);
    }
    let file_package = rust_package_name(file);
    let lexical_package =
        crate::lexical_scope::lexical_package_at(&file_package, source, scope_start);
    resolve_rust_import_package_in_lexical_package(
        rust,
        token,
        file,
        &lexical_package,
        module_specifier,
    )
}

/// Resolve an import using an already established lexical module identity.
/// Both live query syntax and canonical declaration contexts use this route.
pub fn resolve_rust_import_package_in_lexical_package(
    rust: &dyn RustSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    lexical_package: &str,
    module_specifier: &str,
) -> ReferenceContextResult<Option<String>> {
    let segments = parse_symbol_path(Language::Rust, module_specifier);
    let Some(first) = segments.first().map(String::as_str) else {
        return Ok(None);
    };
    if !matches!(first, "self" | "super") {
        return resolve_module_package(rust, token, file, module_specifier);
    }
    let crate_package = rust_crate_root_package(file);
    Ok(resolve_rust_module_segments_with_crate(
        lexical_package,
        &crate_package,
        &segments,
    ))
}

/// Where a module specifier's resolved package is anchored, for persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustModuleAnchor {
    /// `crate::...` -- anchored at the file's crate root.
    Crate,
    /// `self::...` / `super::...` / a bare local path -- anchored at the file's
    /// own package, popped `pop` components.
    OwnModule { pop: u8 },
    /// A path rooted in another crate; its package is not placeable from this
    /// file's path at all.
    External,
}

/// Whether a module specifier is rooted at the crate rather than at a module.
pub fn rust_module_specifier_is_crate_rooted(module_specifier: &str) -> bool {
    module_specifier
        .trim()
        .split("::")
        .find(|segment| !segment.is_empty())
        == Some("crate")
}

/// Classify a package that [`resolve_rust_module_path_with_crate`] already
/// produced, by comparing it against the package of the file it is persisted
/// under.
///
/// The anchor is derived from the RESOLVED package rather than from the
/// specifier's `super` count: a specifier resolves at the import's lexical
/// scope, while the anchor has to describe the package that actually gets
/// stored. Counting `super`s only agrees with that package while the two scopes
/// coincide; comparing the resolved package is correct either way.
///
/// `crate_rooted` wins over the component relationships below. A crate root and
/// an own-module ancestor can coincide in the extracting mount and diverge in
/// another, so a `crate::` route has to keep its own anchor.
pub fn rust_anchor_for_resolved_package(
    resolved_package: &str,
    file_package: &str,
    crate_rooted: bool,
) -> RustModuleAnchor {
    fn components(package: &str) -> Vec<&str> {
        package
            .split('.')
            .filter(|component| !component.is_empty())
            .collect()
    }
    if crate_rooted {
        return RustModuleAnchor::Crate;
    }
    // Compare components, not raw strings: `a.bc` must not read as living
    // under `a.b`.
    let resolved = components(resolved_package);
    let file = components(file_package);
    if file.starts_with(&resolved) {
        // An ancestor of this file's own module -- pop back up to it. Equality
        // lands here with a pop of zero, as does an empty resolved package.
        match u8::try_from(file.len() - resolved.len()) {
            Ok(pop) => RustModuleAnchor::OwnModule { pop },
            Err(_) => RustModuleAnchor::External,
        }
    } else if resolved.starts_with(&file) {
        // A module below this file's own: those extra components are written in
        // the source, so they ride in the persisted tail past the anchor.
        RustModuleAnchor::OwnModule { pop: 0 }
    } else {
        RustModuleAnchor::External
    }
}

pub fn resolve_rust_module_segments_with_crate<S: AsRef<str>>(
    package: &str,
    crate_package: &str,
    segments: &[S],
) -> Option<String> {
    if segments.is_empty() {
        return None;
    }

    let first = segments[0].as_ref();
    let resolved = match first {
        "crate" => crate_package
            .split('.')
            .filter(|segment| !segment.is_empty())
            .chain(segments[1..].iter().map(|segment| segment.as_ref()))
            .collect::<Vec<_>>()
            .join("."),
        "self" | "super" => {
            let mut package_parts: Vec<_> = package
                .split('.')
                .filter(|segment| !segment.is_empty())
                .collect();
            let mut index = 0usize;
            while segments
                .get(index)
                .is_some_and(|segment| matches!(segment.as_ref(), "self" | "super"))
            {
                if segments[index].as_ref() == "super" {
                    package_parts.pop()?;
                }
                index += 1;
            }
            package_parts
                .into_iter()
                .chain(segments[index..].iter().map(|segment| segment.as_ref()))
                .collect::<Vec<_>>()
                .join(".")
        }
        _ => segments
            .iter()
            .map(|segment| segment.as_ref())
            .collect::<Vec<_>>()
            .join("."),
    };

    Some(resolved)
}

pub fn resolve_rust_import_fq_name(
    source_file: &ProjectFile,
    package: &str,
    import: &ImportInfo,
) -> Option<String> {
    let path = import
        .path
        .as_ref()
        .expect("Rust import resolution requires a structured path");
    assert!(
        !path.segments.is_empty(),
        "Rust import structured path must contain at least one segment"
    );
    if path.kind == Some(StructuredImportPathKind::ExternCrate) {
        return None;
    }

    let crate_package = rust_crate_root_package(source_file);
    resolve_rust_module_segments_with_crate(package, &crate_package, &path.segments)
}

pub fn rust_external_module_route(path: &str) -> Option<(&str, Option<String>)> {
    let mut segments = path.split("::").filter(|segment| !segment.is_empty());
    let root = segments.next()?;
    if matches!(root, "crate" | "self" | "super") {
        return None;
    }
    let nested = segments.collect::<Vec<_>>().join(".");
    Some((root, (!nested.is_empty()).then_some(nested)))
}

pub fn rust_external_module_segments(segments: &[String]) -> Option<(&str, Option<String>)> {
    let root = segments.first()?.as_str();
    if matches!(root, "crate" | "self" | "super") {
        return None;
    }
    let nested = segments[1..]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(".");
    Some((root, (!nested.is_empty()).then_some(nested)))
}

/// Kind-level root (`C.tests`, `C.benches`, `C.examples`) for a file that sits
/// at its own target root, i.e. the package prefix under which the modules
/// shared between sibling targets live. `None` when the file has no separate
/// kind root, so callers only pay for the target-directory case.
///
/// A target root file owns its `crate::` root (sibling benches must not see
/// each other's items), so a name that misses under that root may still be one
/// of the shared modules beside it -- `mod common;` in `benches/a.rs` and in
/// `benches/b.rs` both name the single `benches/common/mod.rs` identity.
pub fn rust_target_kind_root_package(file: &ProjectFile) -> Option<String> {
    crate::crate_naming::rust_target_kind_root(file).map(|root| root.join("."))
}

/// Re-spell a package resolved under a Cargo target's private `crate::` root
/// under the kind root shared by its sibling targets.
///
/// `package` is an analyzer package produced by the structured Rust module
/// resolver, not source text. A direct target such as `tests/left.rs` resolves
/// `crate::common` first as `C.tests.left.common`; this returns
/// `C.tests.common`, where Cargo's physically shared `tests/common/mod.rs`
/// lives. Callers still decide whether that alternative has an indexed,
/// reachable backing file and must keep the private-root answer first.
pub fn rust_target_kind_root_alternative(file: &ProjectFile, package: &str) -> Option<String> {
    let kind_root = rust_target_kind_root_package(file)?;
    let own_root = rust_crate_root_package(file);
    let suffix = package.strip_prefix(&own_root)?;
    if !suffix.is_empty() && !suffix.starts_with('.') {
        return None;
    }
    Some(format!("{kind_root}{suffix}"))
}

/// Package that `crate::` resolves to from `file`: crate-anchored when a
/// `Cargo.toml` governs the file, otherwise the legacy path-derived root.
pub fn rust_crate_root_package(file: &ProjectFile) -> String {
    if let Some(paths) = crate::crate_naming::rust_crate_paths(file) {
        return paths.crate_root.join(".");
    }
    crate::crate_naming::path_derived_crate_root_components(file.rel_path()).join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    #[test]
    fn grouped_use_projection_retains_target_and_alias_spans() {
        let source = "use crate::service::{self as svc, run as execute, *};\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser.parse(source, None).expect("parse grouped use");
        let imports = rust_import_projection(tree.root_node(), source, "");

        let svc = imports
            .iter()
            .find(|import| import.import.info.local_name() == Some("svc"))
            .expect("self alias projection");
        assert_eq!(svc.import.path(), ["crate", "service"]);
        assert_eq!(
            svc.import.target_span.map(|span| span.text(source)),
            Some("service")
        );
        assert_eq!(
            svc.import.info.binder_span.map(|span| span.text(source)),
            Some("svc")
        );

        let execute = imports
            .iter()
            .find(|import| import.import.info.local_name() == Some("execute"))
            .expect("named alias projection");
        assert_eq!(execute.import.path(), ["crate", "service", "run"]);
        assert_eq!(
            execute.import.target_span.map(|span| span.text(source)),
            Some("run")
        );
        assert_eq!(
            execute
                .import
                .info
                .binder_span
                .map(|span| span.text(source)),
            Some("execute")
        );

        let glob = imports
            .iter()
            .find(|import| import.import.info.is_wildcard)
            .expect("glob projection");
        assert_eq!(glob.import.path(), ["crate", "service"]);
        assert_eq!(glob.import.target_span, None);
        assert_eq!(glob.import.info.binder_span, None);
    }

    #[test]
    fn leading_absolute_is_recorded_per_grouped_leaf() {
        let source = "use {::root::absolute, local::relative};\nuse ::root::group::{one, two};\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("set Rust grammar");
        let tree = parser
            .parse(source, None)
            .expect("parse grouped absolute use");
        let imports = rust_import_projection(tree.root_node(), source, "");

        let described = imports
            .iter()
            .map(|import| {
                (
                    import.import.path().join("::"),
                    import.import.info.is_global,
                    import.import.info.raw_snippet.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            described,
            vec![
                (
                    "root::absolute".to_string(),
                    true,
                    "use ::root::absolute;".to_string(),
                ),
                (
                    "local::relative".to_string(),
                    false,
                    "use local::relative;".to_string(),
                ),
                (
                    "root::group::one".to_string(),
                    true,
                    "use ::root::group::one;".to_string(),
                ),
                (
                    "root::group::two".to_string(),
                    true,
                    "use ::root::group::two;".to_string(),
                ),
            ]
        );
    }

    fn structured_import(
        raw_snippet: &str,
        segments: &[&str],
        kind: StructuredImportPathKind,
        is_wildcard: bool,
    ) -> ImportInfo {
        ImportInfo {
            raw_snippet: raw_snippet.to_string(),
            is_wildcard,
            is_global: false,
            identifier: None,
            alias: None,
            path: Some(StructuredImportPath {
                segments: segments
                    .iter()
                    .map(|segment| (*segment).to_string())
                    .collect(),
                kind: Some(kind),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
                declaration_start_byte: 0,
            }),
            binder_span: None,
        }
    }

    #[test]
    fn import_resolution_uses_structured_path_not_display_text() {
        let temp = tempfile::tempdir().expect("temporary workspace root");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("absolute workspace root"),
            "src/lib.rs",
        );
        let import = structured_import(
            "use crate::display_text_is_not_authority::Wrong;",
            &["crate", "actual", "Item"],
            StructuredImportPathKind::Namespace,
            false,
        );

        assert_eq!(
            resolve_rust_import_fq_name(&file, "", &import),
            Some("actual.Item".to_string())
        );
    }

    #[test]
    fn import_resolution_handles_roots_aliases_wildcards_and_extern_crates() {
        let temp = tempfile::tempdir().expect("temporary workspace root");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("absolute workspace root"),
            "src/lib.rs",
        );
        let cases = [
            (
                structured_import(
                    "use crate::model::Item as Renamed;",
                    &["crate", "model", "Item"],
                    StructuredImportPathKind::Namespace,
                    false,
                ),
                "app.inner",
                Some("model.Item"),
            ),
            (
                structured_import(
                    "use self::model::*;",
                    &["self", "model"],
                    StructuredImportPathKind::Namespace,
                    true,
                ),
                "app.inner",
                Some("app.inner.model"),
            ),
            (
                structured_import(
                    "use super::model::Item;",
                    &["super", "model", "Item"],
                    StructuredImportPathKind::Namespace,
                    false,
                ),
                "app.inner",
                Some("app.model.Item"),
            ),
            (
                structured_import(
                    "extern crate model;",
                    &["model"],
                    StructuredImportPathKind::ExternCrate,
                    false,
                ),
                "app.inner",
                None,
            ),
        ];

        for (import, package, expected) in cases {
            assert_eq!(
                resolve_rust_import_fq_name(&file, package, &import),
                expected.map(str::to_string),
                "structured import path {:?}",
                import.path.as_ref().expect("test import path").segments
            );
        }
    }
}
