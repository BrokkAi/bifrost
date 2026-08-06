use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::common::node_span;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind, StructuredImportScope,
};
use brokk_bifrost_core::analyzer::structural::facts::Span;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
use brokk_bifrost_core::analyzer::{CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use std::borrow::Cow;
use tree_sitter::Node;

use crate::declarations::{rust_node_text, rust_package_name};
use crate::graph_support::{RustSource, resolve_module_package};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustVisibility {
    Private,
    Public,
    Crate,
    SelfModule,
    SuperModule,
    InPath(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct RustImportInfo {
    pub info: ImportInfo,
    pub visibility: RustVisibility,
    pub path: Vec<String>,
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

#[derive(Debug, Clone)]
pub struct RustProjectedImport {
    pub import: RustImportInfo,
    pub owner: RustImportOwner,
}

pub fn rust_import_projection(
    root: Node<'_>,
    source: &str,
    base_module: &str,
) -> Vec<RustProjectedImport> {
    let mut projected = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "use_declaration" {
            let owner = rust_import_owner(node, source, base_module);
            projected.extend(
                rust_imports_with_visibility_from_use_declaration(node, source)
                    .into_iter()
                    .map(|import| RustProjectedImport {
                        import,
                        owner: owner.clone(),
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
            if child.kind() == "mod_item"
                && let Some(name) = child
                    .child_by_field_name("name")
                    .and_then(|name| simple_segment(name, source))
                && let Some(body) = child.child_by_field_name("body")
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

fn rust_import_owner(node: Node<'_>, source: &str, base_module: &str) -> RustImportOwner {
    let mut modules = Vec::new();
    let mut module_extent = None;
    let mut local_extent = None;
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "block" | "function_item" | "closure_expression" | "async_block" => {
                local_extent.get_or_insert((ancestor.start_byte(), ancestor.end_byte()));
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
    if let Some((start, end)) = local_extent {
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
        if let Some(target_fq_name) =
            resolve_rust_import_fq_name(file, &package, &import.raw_snippet)
        {
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
        resolve_rust_import_fq_name(source_file, &package, &import.raw_snippet)
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
    if node.kind() != "use_declaration" {
        return Vec::new();
    }
    let Some(argument) = node.child_by_field_name("argument") else {
        return Vec::new();
    };
    let declaration = RustUseDeclaration {
        visibility: import_visibility(node, source),
        lexical_scopes: rust_import_lexical_scopes(node),
        declaration_start_byte: node.start_byte(),
    };
    let mut imports = Vec::new();
    collect_rust_use_tree(argument, source, &declaration, &mut imports);
    imports
}

fn rust_import_lexical_scopes(node: Node<'_>) -> Vec<StructuredImportScope> {
    let mut scopes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "declaration_list" | "block") {
            scopes.push(StructuredImportScope {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
            });
        }
        current = parent.parent();
    }
    scopes.reverse();
    scopes
}

fn collect_rust_use_tree(
    node: Node<'_>,
    source: &str,
    declaration: &RustUseDeclaration,
    out: &mut Vec<RustImportInfo>,
) {
    let mut pending = vec![(node, Vec::<String>::new())];
    while let Some((node, prefix)) = pending.pop() {
        match node.kind() {
            "scoped_use_list" => {
                let mut scoped_prefix = prefix;
                if let Some(path) = node.child_by_field_name("path") {
                    scoped_prefix.extend(rust_use_path_segments(path, source));
                }
                if let Some(list) = node.child_by_field_name("list") {
                    pending.push((list, scoped_prefix));
                }
            }
            "use_list" => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                pending.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|child| (child, prefix.clone())),
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
                let mut path = prefix;
                // In a grouped import, `self` denotes the entity named by the
                // prefix rather than a literal trailing path component:
                // `use crate::service::{self as svc}` binds `svc` to
                // `crate::service`, not to `crate::service::self`.
                if path_node.kind() != "self" || path.is_empty() {
                    path.extend(rust_use_path_segments(path_node, source));
                }
                let Some(identifier) = path.last().cloned() else {
                    continue;
                };
                out.push(declaration.leaf(
                    path,
                    false,
                    Some(identifier),
                    Some(alias.to_string()),
                    Some(node_span(alias_node)),
                ));
            }
            "use_wildcard" => {
                let mut path = prefix;
                if let Some(path_node) = first_named_child(node) {
                    path.extend(rust_use_path_segments(path_node, source));
                }
                if !path.is_empty() {
                    out.push(declaration.leaf(path, true, None, None, None));
                }
            }
            "crate" | "identifier" | "metavariable" | "scoped_identifier" | "self" | "super" => {
                let mut path = prefix;
                let prefix_was_empty = path.is_empty();
                if node.kind() != "self" || prefix_was_empty {
                    path.extend(rust_use_path_segments(node, source));
                }
                let Some(identifier) = path.last().cloned() else {
                    continue;
                };
                let binder_span = rust_use_leaf_binder_node(node, prefix_was_empty).map(node_span);
                out.push(declaration.leaf(path, false, Some(identifier), None, binder_span));
            }
            _ => {}
        }
    }
}

fn rust_use_path_segments(node: Node<'_>, source: &str) -> Vec<String> {
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
                    segments.push(segment.to_string());
                }
            }
            _ => {}
        }
    }
    segments
}

fn import_visibility(node: Node<'_>, source: &str) -> RustVisibility {
    let mut cursor = node.walk();
    let visibility = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "visibility_modifier");
    visibility
        .map(|visibility| rust_visibility_from_modifier(visibility, source))
        .unwrap_or(RustVisibility::Private)
}

pub fn rust_item_visibility(node: Node<'_>, source: &str) -> RustVisibility {
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
struct RustUseDeclaration {
    visibility: RustVisibility,
    lexical_scopes: Vec<StructuredImportScope>,
    declaration_start_byte: usize,
}

impl RustUseDeclaration {
    /// One import this declaration introduces: `path` is the leaf's full
    /// segment list, and `binder_span` is the token spelling the bound name
    /// where the leaf has one.
    fn leaf(
        &self,
        path: Vec<String>,
        is_wildcard: bool,
        identifier: Option<String>,
        alias: Option<String>,
        binder_span: Option<Span>,
    ) -> RustImportInfo {
        let rendered_path = path.join("::");
        let prefix = self.rendered_use_prefix();
        let raw_snippet = if is_wildcard {
            format!("{prefix}{rendered_path}::*;")
        } else if let Some(alias) = &alias {
            format!("{prefix}{rendered_path} as {alias};")
        } else {
            format!("{prefix}{rendered_path};")
        };
        RustImportInfo {
            info: ImportInfo {
                raw_snippet,
                is_wildcard,
                identifier,
                alias,
                path: Some(StructuredImportPath {
                    segments: path.clone(),
                    kind: Some(StructuredImportPathKind::Namespace),
                    lexical_prefixes: Vec::new(),
                    lexical_scopes: self.lexical_scopes.clone(),
                    declaration_start_byte: self.declaration_start_byte,
                }),
                binder_span,
            },
            visibility: self.visibility.clone(),
            path,
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
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    module_specifier: &str,
) -> Option<String> {
    let segments = parse_symbol_path(Language::Rust, module_specifier);
    let first = segments.first().map(String::as_str)?;
    if !matches!(first, "self" | "super") {
        return resolve_module_package(rust, file, module_specifier);
    }
    let file_package = rust_package_name(file);
    let lexical_package =
        crate::lexical_scope::lexical_package_at(&file_package, source, scope_start);
    let crate_package = rust_crate_root_package(file);
    resolve_rust_module_segments_with_crate(&lexical_package, &crate_package, &segments)
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
    raw_import: &str,
) -> Option<String> {
    let body = rust_import_body(raw_import)?;
    let path = body
        .rsplit_once(" as ")
        .map(|(path, _)| path)
        .unwrap_or(body)
        .trim_end_matches("::*")
        .trim();
    let segments: Vec<_> = path
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }

    let crate_package = rust_crate_root_package(source_file);
    resolve_rust_module_path_with_crate(package, &crate_package, path)
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

/// Package that `crate::` resolves to from `file`: crate-anchored when a
/// `Cargo.toml` governs the file, otherwise the legacy path-derived root.
pub fn rust_crate_root_package(file: &ProjectFile) -> String {
    if let Some(paths) = crate::crate_naming::rust_crate_paths(file) {
        return paths.crate_root.join(".");
    }
    rust_path_derived_crate_root_package(file)
}

/// Directory-derived crate root, kept verbatim for manifest-less trees.
fn rust_path_derived_crate_root_package(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();
    let Some(src_index) = components.iter().rposition(|component| component == "src") else {
        return rust_package_name(file);
    };
    if src_index == 0 {
        return String::new();
    }
    components.truncate(src_index + 1);
    components.join(".")
}
