use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::HashSet;
use std::sync::Arc;
use tree_sitter::Node;

use super::RustAnalyzer;
use super::declarations::{rust_node_text, rust_package_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RustVisibility {
    Private,
    Public,
    Crate,
    SelfModule,
    SuperModule,
    InPath(Vec<String>),
}

#[derive(Debug, Clone)]
pub(super) struct RustImportInfo {
    pub(super) info: ImportInfo,
    pub(super) visibility: RustVisibility,
    pub(super) path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RustImportOwner {
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
pub(super) struct RustProjectedImport {
    pub(super) import: RustImportInfo,
    pub(super) owner: RustImportOwner,
}

pub(super) fn rust_import_projection(
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

pub(super) fn rust_module_extents(
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

pub(crate) struct RustFocusedUsePath<'tree> {
    pub(crate) full_path: String,
    pub(crate) root: Node<'tree>,
}

pub(crate) fn rust_focused_use_path<'tree>(
    focused: Node<'tree>,
    source: &str,
) -> Option<RustFocusedUsePath<'tree>> {
    let mut prefix = focused;
    while let Some(parent) = prefix.parent() {
        if parent.kind() != "scoped_identifier" {
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
    let mut full_path = String::new();
    let path_node_count = path_nodes.len();
    for node in path_nodes {
        if node.kind() == "self" && path_node_count > 1 {
            continue;
        }
        let part = rust_use_path_text(node, source)?;
        if !full_path.is_empty() {
            full_path.push_str("::");
        }
        full_path.push_str(&part);
    }
    (!full_path.is_empty()).then_some(RustFocusedUsePath { full_path, root })
}

fn node_contains(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

fn rust_use_path_root(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "scoped_identifier" {
        let Some(path) = node.child_by_field_name("path") else {
            break;
        };
        node = path;
    }
    node
}

impl ImportAnalysisProvider for RustAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        if let Some(cached) = self.imported_code_units.get(file) {
            return (*cached).clone();
        }

        let package = rust_package_name(file);
        let mut resolved = HashSet::default();
        for import in self.inner.import_info_of(file) {
            if let Some(target_fq_name) =
                resolve_rust_import_fq_name(file, &package, &import.raw_snippet)
            {
                resolved.extend(self.inner.definitions(&target_fq_name));
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

        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let referencing = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        self.referencing_files
            .insert(file.clone(), Arc::new(referencing.clone()));
        referencing
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        let package = rust_package_name(source_file);
        imports.iter().any(|import| {
            resolve_rust_import_fq_name(source_file, &package, &import.raw_snippet)
                .into_iter()
                .any(|fq_name| {
                    self.inner
                        .definitions(&fq_name)
                        .any(|code_unit| code_unit.source() == target)
                })
        })
    }
}

pub(super) fn rust_imports_from_use_declaration(node: Node<'_>, source: &str) -> Vec<ImportInfo> {
    rust_imports_with_visibility_from_use_declaration(node, source)
        .into_iter()
        .map(|import| import.info)
        .collect()
}

pub(super) fn rust_imports_with_visibility_from_use_declaration(
    node: Node<'_>,
    source: &str,
) -> Vec<RustImportInfo> {
    if node.kind() != "use_declaration" {
        return Vec::new();
    }
    let Some(argument) = node.child_by_field_name("argument") else {
        return Vec::new();
    };
    let visibility = import_visibility(node, source);
    let mut imports = Vec::new();
    collect_rust_use_tree(argument, source, visibility, &mut imports);
    imports
}

fn collect_rust_use_tree(
    node: Node<'_>,
    source: &str,
    visibility: RustVisibility,
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
                let rendered_path = path.join("::");
                out.push(RustImportInfo {
                    visibility: visibility.clone(),
                    info: rust_import_info(
                        visibility.clone(),
                        &rendered_path,
                        false,
                        Some(identifier),
                        Some(alias.to_string()),
                    ),
                    path,
                });
            }
            "use_wildcard" => {
                let mut path = prefix;
                if let Some(path_node) = first_named_child(node) {
                    path.extend(rust_use_path_segments(path_node, source));
                }
                if !path.is_empty() {
                    let rendered_path = path.join("::");
                    out.push(RustImportInfo {
                        info: rust_import_info(
                            visibility.clone(),
                            &rendered_path,
                            true,
                            None,
                            None,
                        ),
                        visibility: visibility.clone(),
                        path,
                    });
                }
            }
            "crate" | "identifier" | "metavariable" | "scoped_identifier" | "self" | "super" => {
                let mut path = prefix;
                if node.kind() != "self" || path.is_empty() {
                    path.extend(rust_use_path_segments(node, source));
                }
                let Some(identifier) = path.last().cloned() else {
                    continue;
                };
                let rendered_path = path.join("::");
                out.push(RustImportInfo {
                    info: rust_import_info(
                        visibility.clone(),
                        &rendered_path,
                        false,
                        Some(identifier),
                        None,
                    ),
                    visibility: visibility.clone(),
                    path,
                });
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
            "scoped_identifier" => {
                if let Some(name) = node.child_by_field_name("name") {
                    pending.push(name);
                }
                if let Some(path) = node.child_by_field_name("path") {
                    pending.push(path);
                }
            }
            "crate" | "identifier" | "metavariable" | "self" | "super" => {
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

pub(super) fn rust_item_visibility(node: Node<'_>, source: &str) -> RustVisibility {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "visibility_modifier")
        .map(|visibility| rust_visibility_from_modifier(visibility, source))
        .unwrap_or(RustVisibility::Private)
}

fn rust_visibility_from_modifier(node: Node<'_>, source: &str) -> RustVisibility {
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

fn rust_use_path_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "crate" | "identifier" | "metavariable" | "self" | "super" => {
            let text = rust_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "scoped_identifier" => {
            let path = node
                .child_by_field_name("path")
                .and_then(|child| rust_use_path_text(child, source));
            let name = node
                .child_by_field_name("name")
                .and_then(|child| rust_use_path_text(child, source))?;
            Some(join_rust_path(path.as_deref(), &name))
        }
        _ => None,
    }
}

fn join_rust_path(prefix: Option<&str>, path: &str) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() && !path.is_empty() => format!("{prefix}::{path}"),
        Some(prefix) if !prefix.is_empty() => prefix.to_string(),
        _ => path.to_string(),
    }
}

fn rust_import_info(
    visibility: RustVisibility,
    path: &str,
    is_wildcard: bool,
    identifier: Option<String>,
    alias: Option<String>,
) -> ImportInfo {
    let prefix = match visibility {
        RustVisibility::Private => "use ",
        RustVisibility::Public => "pub use ",
        RustVisibility::Crate => {
            return restricted_rust_import_info("pub(crate)", path, is_wildcard, identifier, alias);
        }
        RustVisibility::SelfModule => {
            return restricted_rust_import_info("pub(self)", path, is_wildcard, identifier, alias);
        }
        RustVisibility::SuperModule => {
            return restricted_rust_import_info("pub(super)", path, is_wildcard, identifier, alias);
        }
        RustVisibility::InPath(ref scope) => {
            return restricted_rust_import_info(
                &format!("pub(in {})", scope.join("::")),
                path,
                is_wildcard,
                identifier,
                alias,
            );
        }
    };
    let raw_snippet = if is_wildcard {
        format!("{prefix}{path}::*;")
    } else if let Some(alias) = &alias {
        format!("{prefix}{path} as {alias};")
    } else {
        format!("{prefix}{path};")
    };

    ImportInfo {
        raw_snippet,
        is_wildcard,
        identifier,
        alias,
    }
}

fn restricted_rust_import_info(
    visibility: &str,
    path: &str,
    is_wildcard: bool,
    identifier: Option<String>,
    alias: Option<String>,
) -> ImportInfo {
    let raw_snippet = if is_wildcard {
        format!("{visibility} use {path}::*;")
    } else if let Some(alias) = &alias {
        format!("{visibility} use {path} as {alias};")
    } else {
        format!("{visibility} use {path};")
    };

    ImportInfo {
        raw_snippet,
        is_wildcard,
        identifier,
        alias,
    }
}

pub(super) fn rust_import_body(raw_import: &str) -> Option<&str> {
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

pub(super) fn split_rust_import_module_and_name(raw_import: &str) -> Option<(String, String)> {
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

pub(super) fn resolve_rust_module_path_with_crate(
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

pub(super) fn resolve_rust_module_segments_with_crate<S: AsRef<str>>(
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

pub(super) fn resolve_rust_import_fq_name(
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

pub(super) fn rust_external_module_route(path: &str) -> Option<(&str, Option<String>)> {
    let mut segments = path.split("::").filter(|segment| !segment.is_empty());
    let root = segments.next()?;
    if matches!(root, "crate" | "self" | "super") {
        return None;
    }
    let nested = segments.collect::<Vec<_>>().join(".");
    Some((root, (!nested.is_empty()).then_some(nested)))
}

pub(super) fn rust_external_module_segments(segments: &[String]) -> Option<(&str, Option<String>)> {
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

pub(super) fn rust_crate_root_package(file: &ProjectFile) -> String {
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
