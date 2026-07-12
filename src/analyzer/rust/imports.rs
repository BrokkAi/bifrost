use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, ProjectFile};
use crate::hash::HashSet;
use std::sync::Arc;
use tree_sitter::Node;

use super::RustAnalyzer;
use super::declarations::{rust_node_text, rust_package_name};

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
    if node.kind() != "use_declaration" {
        return Vec::new();
    }
    let Some(argument) = node.child_by_field_name("argument") else {
        return Vec::new();
    };
    let visibility = import_visibility(node, source);
    let mut imports = Vec::new();
    collect_rust_use_tree(argument, source, None, visibility, &mut imports);
    imports
}

fn collect_rust_use_tree(
    node: Node<'_>,
    source: &str,
    prefix: Option<&str>,
    visibility: ImportVisibility,
    out: &mut Vec<ImportInfo>,
) {
    match node.kind() {
        "scoped_use_list" => {
            let scoped_prefix = node
                .child_by_field_name("path")
                .and_then(|path| rust_use_path_text(path, source))
                .map(|path| join_rust_path(prefix, &path))
                .or_else(|| prefix.map(str::to_string));
            if let Some(list) = node.child_by_field_name("list") {
                collect_rust_use_tree(list, source, scoped_prefix.as_deref(), visibility, out);
            }
        }
        "use_list" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_rust_use_tree(child, source, prefix, visibility.clone(), out);
            }
        }
        "use_as_clause" => {
            let Some(path_node) = node.child_by_field_name("path") else {
                return;
            };
            let Some(path) = rust_use_path_text(path_node, source) else {
                return;
            };
            let Some(alias_node) = node.child_by_field_name("alias") else {
                return;
            };
            let alias = rust_node_text(alias_node, source).trim();
            if alias.is_empty() {
                return;
            }
            let full_path = join_rust_path(prefix, &path);
            let Some(identifier) = rust_use_path_leaf(path_node, source) else {
                return;
            };
            out.push(rust_import_info(
                visibility,
                &full_path,
                false,
                Some(identifier),
                Some(alias.to_string()),
            ));
        }
        "use_wildcard" => {
            let wildcard_path = first_named_child(node)
                .and_then(|path| rust_use_path_text(path, source))
                .map(|path| join_rust_path(prefix, &path))
                .or_else(|| prefix.map(str::to_string));
            if let Some(path) = wildcard_path
                && !path.is_empty()
            {
                out.push(rust_import_info(visibility, &path, true, None, None));
            }
        }
        "crate" | "identifier" | "metavariable" | "scoped_identifier" | "self" | "super" => {
            let Some(path) = rust_use_path_text(node, source) else {
                return;
            };
            let full_path = if node.kind() == "self" {
                prefix.map(str::to_string).unwrap_or(path)
            } else {
                join_rust_path(prefix, &path)
            };
            let identifier = if node.kind() == "self" {
                rust_path_leaf(&full_path)
            } else {
                rust_use_path_leaf(node, source)
            };
            let Some(identifier) = identifier else { return };
            out.push(rust_import_info(
                visibility,
                &full_path,
                false,
                Some(identifier),
                None,
            ));
        }
        _ => {}
    }
}

#[derive(Clone)]
enum ImportVisibility {
    Private,
    Public,
    Restricted(String),
}

fn import_visibility(node: Node<'_>, source: &str) -> ImportVisibility {
    let mut cursor = node.walk();
    let visibility = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "visibility_modifier")
        .map(|child| rust_node_text(child, source).trim());
    match visibility {
        Some("pub") => ImportVisibility::Public,
        Some(text) if !text.is_empty() => ImportVisibility::Restricted(text.to_string()),
        _ => ImportVisibility::Private,
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

fn rust_use_path_leaf(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "scoped_identifier" => node
            .child_by_field_name("name")
            .and_then(|child| rust_use_path_leaf(child, source)),
        "crate" | "identifier" | "metavariable" | "self" | "super" => {
            let text = rust_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => None,
    }
}

fn rust_path_leaf(path: &str) -> Option<String> {
    path.rsplit("::")
        .next()
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
}

fn join_rust_path(prefix: Option<&str>, path: &str) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() && !path.is_empty() => format!("{prefix}::{path}"),
        Some(prefix) if !prefix.is_empty() => prefix.to_string(),
        _ => path.to_string(),
    }
}

fn rust_import_info(
    visibility: ImportVisibility,
    path: &str,
    is_wildcard: bool,
    identifier: Option<String>,
    alias: Option<String>,
) -> ImportInfo {
    let prefix = match visibility {
        ImportVisibility::Private => "use ",
        ImportVisibility::Public => "pub use ",
        ImportVisibility::Restricted(ref visibility) => {
            return restricted_rust_import_info(visibility, path, is_wildcard, identifier, alias);
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
    if segments.is_empty() {
        return None;
    }

    let resolved = match segments[0] {
        "crate" => crate_package
            .split('.')
            .filter(|segment| !segment.is_empty())
            .chain(segments[1..].iter().copied())
            .collect::<Vec<_>>()
            .join("."),
        "self" | "super" => {
            let mut package_parts: Vec<_> = package
                .split('.')
                .filter(|segment| !segment.is_empty())
                .collect();
            let mut index = 0usize;
            while matches!(segments.get(index), Some(&"self" | &"super")) {
                if segments[index] == "super" {
                    package_parts.pop()?;
                }
                index += 1;
            }
            package_parts
                .into_iter()
                .chain(segments[index..].iter().copied())
                .collect::<Vec<_>>()
                .join(".")
        }
        _ => segments.join("."),
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
