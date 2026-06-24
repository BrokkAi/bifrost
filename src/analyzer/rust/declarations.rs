use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::HashSet;
use std::path::Path;
use tree_sitter::{Node, Tree};

use super::imports::rust_imports_from_use_declaration;

pub(super) fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(super) fn parse_rust_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let mut parsed = ParsedFile::new(rust_package_name(file));
    let root = tree.root_node();
    collect_rust_type_identifiers(root, source, &mut parsed.type_identifiers);

    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        match child.kind() {
            "use_declaration" => {
                let imports = rust_imports_from_use_declaration(child, source);
                parsed
                    .import_statements
                    .extend(imports.iter().map(|import| import.raw_snippet.clone()));
                parsed.imports.extend(imports);
            }
            "struct_item" | "enum_item" | "trait_item" => {
                visit_rust_class_like(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "mod_item" => {
                visit_rust_module(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "function_item" => {
                visit_rust_function(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "const_item" | "static_item" => {
                visit_rust_field(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "macro_definition" => {
                visit_rust_macro(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "type_item" => {
                visit_rust_alias(
                    file,
                    source,
                    child,
                    None,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            "impl_item" => {
                visit_rust_impl(
                    file,
                    source,
                    child,
                    &parsed.package_name.clone(),
                    &mut parsed,
                );
            }
            _ => {}
        }
    }

    parsed
}

pub(super) fn rust_package_name(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();

    if components.first().map(|component| component.as_str()) == Some("src") {
        components.remove(0);
    }
    if components.is_empty() {
        return String::new();
    }

    let file_name = components.pop().unwrap_or_default();
    let stem = Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if stem == "lib" || stem == "main" || stem == "mod" {
        components.join(".")
    } else if rel.starts_with("src") {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        components.join(".")
    }
}

fn visit_rust_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_type_signature(node, source, package_name.is_empty()),
    );

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "field_declaration" | "enum_variant" | "const_item" => {
                    visit_rust_field(file, source, child, Some(&code_unit), package_name, parsed);
                }
                "function_signature_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_rust_module(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Module,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit.clone(), format!("mod {name} {{"));

    if let Some(body) = node.child_by_field_name("body") {
        for index in 0..body.named_child_count() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            match child.kind() {
                "function_item" => {
                    visit_rust_function(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "struct_item" | "enum_item" | "trait_item" => {
                    visit_rust_class_like(
                        file,
                        source,
                        child,
                        Some(&code_unit),
                        package_name,
                        parsed,
                    );
                }
                "mod_item" => {
                    visit_rust_module(file, source, child, Some(&code_unit), package_name, parsed);
                }
                "macro_definition" => {
                    visit_rust_macro(file, source, child, Some(&code_unit), package_name, parsed);
                }
                _ => {}
            }
        }
    }

    Some(code_unit)
}

fn visit_rust_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| rust_node_text(parameters, source).trim().to_string());
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature,
        false,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(code_unit.clone(), rust_function_signature(node, source));
    Some(code_unit)
}

fn visit_rust_macro(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Macro,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(code_unit.clone(), rust_macro_signature(node, source));
    Some(code_unit)
}

fn visit_rust_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = rust_node_text(name_node, source)
        .trim()
        .trim_end_matches(',')
        .to_string();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| format!("_module_.{name}"));
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_node_text(node, source)
            .trim()
            .trim_end_matches(',')
            .to_string(),
    );
    Some(code_unit)
}

fn visit_rust_alias(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        short_name,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    parsed.add_signature(
        code_unit.clone(),
        rust_node_text(node, source).trim().to_string(),
    );
    parsed.mark_type_alias(code_unit.clone());
    Some(code_unit)
}

fn visit_rust_impl(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(target_name) = extract_rust_impl_target_name(type_node, source) else {
        return;
    };
    let parent = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Class,
        package_name.to_string(),
        target_name,
    );
    if !parsed.declarations.contains(&parent) {
        let top_level = parent.clone();
        parsed.add_code_unit(parent.clone(), node, source, None, Some(top_level));
    }

    let Some(body) = node.child_by_field_name("body") else {
        return;
    };
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "function_item" => {
                visit_rust_function(file, source, child, Some(&parent), package_name, parsed);
            }
            "const_item" => {
                visit_rust_field(file, source, child, Some(&parent), package_name, parsed);
            }
            "type_item" => {
                visit_rust_alias(file, source, child, Some(&parent), package_name, parsed);
            }
            _ => {}
        }
    }
}

fn rust_type_signature(node: Node<'_>, source: &str, _top_level: bool) -> String {
    let header = rust_node_text(node, source)
        .split('{')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .split(';')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .trim();
    format!("{header} {{")
}

fn rust_function_signature(node: Node<'_>, source: &str) -> String {
    let header = rust_node_text(node, source)
        .split('{')
        .next()
        .unwrap_or_else(|| rust_node_text(node, source))
        .trim()
        .trim_end_matches(';')
        .to_string();
    if node.kind() == "function_signature_item" {
        header
    } else {
        format!("{header} {{ ... }}")
    }
}

fn rust_macro_signature(node: Node<'_>, source: &str) -> String {
    rust_node_text(node, source)
        .lines()
        .find(|line| line.contains("macro_rules!"))
        .map(str::trim)
        .unwrap_or("macro_rules!")
        .to_string()
}

pub(super) fn collect_rust_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => {
            let text = rust_node_text(node, source).trim();
            if !text.is_empty() {
                identifiers.insert(text.to_string());
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_rust_type_identifiers(child, source, identifiers);
    }
}

fn extract_rust_impl_target_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => {
            let text = rust_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "scoped_type_identifier" => node
            .child_by_field_name("name")
            .and_then(|name| extract_rust_impl_target_name(name, source))
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find_map(|child| extract_rust_impl_target_name(child, source))
            }),
        "generic_type" | "reference_type" | "pointer_type" | "array_type" | "slice_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_rust_impl_target_name(child, source))
        }
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_rust_impl_target_name(child, source))
        }
    }
}
