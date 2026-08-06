//! TypeScript's declaration walk.
//!
//! The whole free-function band of `analyzer/typescript/mod.rs`: the top-level
//! parse driver, ambient and global-module handling, the class-like/function/
//! value visitors, type-alias member expansion, the shape-preservation analysis
//! and the signature renderers. Everything here takes plain syntax and core
//! types, so none of it ever named `TypescriptAnalyzer`.
//!
//! `brokk-bifrost-analysis` keeps the shim: the `TypescriptAnalyzer` struct with
//! its `JsTsMemoCaches` bucket and `AliasResolver`, the `CodeUnitIndex` and
//! `IAnalyzer` impls, the `TypescriptAdapter` forwarding shell whose
//! `parse_file` calls [`parse_typescript_file`], and the SPI registration.

use crate::hierarchy::extract_ts_supertypes;
use crate::imports::{
    parse_commonjs_require_import_infos_from_node, parse_es_import_infos_from_node,
};
use crate::model::*;
use crate::providers::JsTsSource;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind};
use brokk_bifrost_core::analyzer::model::{CodeUnit, SignatureMetadata};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::{Node, Tree};

/// The TypeScript half of `LanguageAdapter::parse_file`: walk `tree`'s top level
/// and record every declaration, import statement and export the file spells,
/// including ambient and `declare global` bodies.
pub fn parse_typescript_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let root = tree.root_node();
    let mut parsed = ParsedFile::new(String::new());
    let module = module_code_unit(file);
    let mut module_has_imports = false;
    let exported_roots = ts_es_named_exported_roots(root, source);

    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        match child.kind() {
            "import_statement" => {
                let raw = node_text(child, source).trim().to_string();
                module_has_imports = true;
                parsed.import_statements.push(raw.clone());
                parsed
                    .imports
                    .extend(parse_es_import_infos_from_node(child, source));
            }
            "expression_statement" => {
                let imports = parse_commonjs_require_import_infos_from_node(child, source);
                if !imports.is_empty() {
                    let raw = node_text(child, source).trim().to_string();
                    module_has_imports = true;
                    parsed.import_statements.push(raw);
                    parsed.imports.extend(imports);
                }
            }
            "export_statement" => {
                visit_ts_export(file, source, child, None, &mut parsed, &exported_roots)
            }
            "ambient_declaration" => {
                visit_ts_ambient_declarations(file, source, child, None, &mut parsed, false);
            }
            "internal_module" if ts_is_global_internal_module(child, source) => {
                visit_ts_ambient_declarations(file, source, child, None, &mut parsed, false);
            }
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "internal_module" => {
                visit_ts_class_like(file, source, child, None, &mut parsed, false);
            }
            "function_declaration" | "function_signature" => {
                visit_ts_function(file, source, child, None, &mut parsed, false);
            }
            "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
                if matches!(child.kind(), "lexical_declaration" | "variable_declaration") {
                    let imports = parse_commonjs_require_import_infos_from_node(child, source);
                    if !imports.is_empty() {
                        let raw = node_text(child, source).trim().to_string();
                        module_has_imports = true;
                        parsed.import_statements.push(raw);
                        parsed.imports.extend(imports);
                    }
                }
                visit_ts_value(
                    file,
                    source,
                    child,
                    None,
                    &mut parsed,
                    false,
                    &exported_roots,
                );
            }
            _ => {}
        }
    }

    if module_has_imports {
        parsed.add_code_unit(module, root, source, None, None);
    }

    parsed
}

/// A type alias renders as its own signature line. TypeScript-only: no other
/// dialect in this family has the form.
pub fn ts_type_alias_skeleton(host: &dyn JsTsSource, code_unit: &CodeUnit) -> Option<String> {
    host.is_type_alias(code_unit)
        .then(|| host.raw_signatures(code_unit).first().cloned())
        .flatten()
}

fn visit_ts_ambient_declarations(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    exported: bool,
) {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    match definition.kind() {
        "ambient_declaration" | "statement_block" => {
            let mut cursor = definition.walk();
            for child in definition.named_children(&mut cursor) {
                visit_ts_ambient_declarations(file, source, child, parent, parsed, exported);
            }
        }
        "internal_module" if ts_is_global_internal_module(definition, source) => {
            if let Some(body) = definition.child_by_field_name("body") {
                let mut cursor = body.walk();
                for child in body.named_children(&mut cursor) {
                    visit_ts_ambient_declarations(file, source, child, parent, parsed, false);
                }
            }
        }
        "class_declaration"
        | "abstract_class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "internal_module" => {
            visit_ts_class_like(file, source, definition, parent, parsed, exported);
        }
        "function_declaration" | "function_signature" => {
            visit_ts_function(file, source, definition, parent, parsed, exported);
        }
        "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
            visit_ts_value(
                file,
                source,
                definition,
                parent,
                parsed,
                exported,
                &HashSet::default(),
            );
        }
        _ => {}
    }
}

pub fn ts_is_global_internal_module(node: Node<'_>, source: &str) -> bool {
    node.kind() == "internal_module"
        && node
            .child_by_field_name("name")
            .is_some_and(|name| trim_statement(node_text(name, source)) == "global")
}

fn visit_ts_export(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    exported_roots: &HashSet<String>,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "ambient_declaration" => {
                visit_ts_ambient_declarations(file, source, declaration, parent, parsed, true);
            }
            "internal_module" if ts_is_global_internal_module(declaration, source) => {
                visit_ts_ambient_declarations(file, source, declaration, parent, parsed, true);
            }
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "internal_module" => {
                if matches!(
                    declaration.kind(),
                    "class_declaration" | "abstract_class_declaration"
                ) && declaration.child_by_field_name("name").is_none()
                    && ts_export_is_default(node, source)
                    && parent.is_none()
                {
                    visit_ts_default_export_class(file, source, node, declaration, parsed);
                } else {
                    if parent.is_none() {
                        record_named_export(
                            source,
                            node,
                            declaration,
                            ts_export_is_default(node, source),
                            parsed,
                        );
                    }
                    visit_ts_class_like(file, source, node, parent, parsed, true);
                }
            }
            "function_declaration" | "function_signature" => {
                if declaration.kind() == "function_declaration"
                    && declaration.child_by_field_name("name").is_none()
                    && ts_export_is_default(node, source)
                    && parent.is_none()
                {
                    visit_ts_default_export_function(file, source, node, declaration, parsed);
                } else {
                    if parent.is_none() {
                        record_named_export(
                            source,
                            node,
                            declaration,
                            ts_export_is_default(node, source),
                            parsed,
                        );
                    }
                    visit_ts_function(file, source, node, parent, parsed, true);
                }
            }
            "lexical_declaration" | "variable_declaration" | "type_alias_declaration" => {
                if parent.is_none() {
                    if declaration.kind() == "type_alias_declaration" {
                        record_named_export(source, node, declaration, false, parsed);
                    } else {
                        record_named_declarator_exports(source, node, declaration, parsed);
                    }
                }
                visit_ts_value(file, source, node, parent, parsed, true, exported_roots);
            }
            _ => {}
        }
    } else if parent.is_none()
        && let Some(value) = node.child_by_field_name("value")
    {
        visit_ts_default_export_value(file, source, node, value, parsed);
    }
}

fn ts_export_is_default(node: Node<'_>, source: &str) -> bool {
    (0..node.child_count()).any(|index| {
        node.child(index)
            .is_some_and(|child| child.kind() == "default" || node_text(child, source) == "default")
    })
}

fn visit_ts_default_export_value(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    value: Node<'_>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    match value.kind() {
        "arrow_function" | "function_expression" | "generator_function" => {
            visit_ts_default_export_function(file, source, export, value, parsed);
        }
        "class" => {
            visit_ts_default_export_class(file, source, export, value, parsed);
        }
        "object" => {
            let code_unit = add_default_export_unit(
                file,
                source,
                export,
                brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
                parsed,
            );
            parsed.add_signature(code_unit.clone(), trim_statement(node_text(export, source)));
            visit_ts_object_literal_properties(file, source, value, &code_unit, &code_unit, parsed);
        }
        // `export default name` points at an existing binding; indexing `default`
        // here would duplicate that declaration instead of describing new code.
        // The export declaration itself is still recorded.
        _ => record_default_reexport(export, parsed),
    }
}

fn visit_ts_default_export_function(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    function: Node<'_>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) -> CodeUnit {
    let code_unit = add_default_export_unit(
        file,
        source,
        export,
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        parsed,
    );
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(
            ts_default_export_function_signature(function, source),
            ts_parameter_labels(function, source),
        ),
    );
    visit_ts_return_object_literal_properties(
        file, source, function, &code_unit, &code_unit, parsed,
    );
    code_unit
}

fn visit_ts_default_export_class(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    class: Node<'_>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) -> CodeUnit {
    let code_unit = add_default_export_unit(
        file,
        source,
        export,
        brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
        parsed,
    );
    parsed.add_signature(
        code_unit.clone(),
        ts_default_export_class_signature(export, source),
    );
    let supertypes = extract_ts_supertypes(class, source);
    if !supertypes.is_empty() {
        parsed.set_raw_supertypes(code_unit.clone(), supertypes);
    }
    let _nested = visit_ts_class_like_body(file, source, class, &code_unit, &code_unit, parsed);
    code_unit
}

fn visit_ts_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    exported: bool,
) -> Option<CodeUnit> {
    let mut first = None;
    let mut stack = vec![(node, parent.cloned(), exported)];
    while let Some((node, parent, exported)) = stack.pop() {
        let definition = if node.kind() == "export_statement" {
            node.child_by_field_name("declaration").unwrap_or(node)
        } else {
            node
        };
        let Some(name_node) = definition.child_by_field_name("name") else {
            continue;
        };
        let name = trim_statement(node_text(name_node, source));
        if name.is_empty() {
            continue;
        }
        let short_name = parent
            .as_ref()
            .map(|parent| format!("{}.{}", parent.short_name(), name))
            .unwrap_or(name.clone());
        let fq = match &parent {
            Some(parent) => parent
                .fq()
                .clone()
                .with_pushed(js_ts_segment(&name, SegmentKind::Type)),
            None => FqName::new().with_pushed(js_ts_segment(&name, SegmentKind::Type)),
        };
        let code_unit = CodeUnit::new_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
            "",
            short_name,
            fq,
        );
        if first.is_none() {
            first = Some(code_unit.clone());
        }
        let top_level = parent.clone().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.clone(),
            Some(top_level.clone()),
        );
        parsed.add_signature(
            code_unit.clone(),
            ts_class_signature(node, source, exported),
        );
        let supertypes = extract_ts_supertypes(definition, source);
        if !supertypes.is_empty() {
            parsed.set_raw_supertypes(code_unit.clone(), supertypes);
        }

        if definition.kind() == "enum_declaration" {
            if let Some(body) = definition.child_by_field_name("body") {
                for index in 0..body.named_child_count() {
                    let Some(child) = body.named_child(index) else {
                        continue;
                    };
                    if child.kind() == "enum_assignment"
                        || child.kind() == "property_identifier"
                        || child.kind() == "identifier"
                    {
                        visit_ts_enum_member(file, source, child, &code_unit, &top_level, parsed);
                    }
                }
            }
            continue;
        }

        let nested_class_like =
            visit_ts_class_like_body(file, source, definition, &code_unit, &top_level, parsed);
        stack.extend(
            nested_class_like
                .into_iter()
                .rev()
                .map(|child| (child, Some(code_unit.clone()), false)),
        );
    }
    first
}

fn visit_ts_class_like_body<'tree>(
    file: &ProjectFile,
    source: &str,
    class_like: Node<'tree>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) -> Vec<Node<'tree>> {
    let Some(body) = class_like.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut nested_class_like = Vec::new();
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "method_definition" | "method_signature" | "abstract_method_signature" => {
                visit_ts_method(file, source, child, parent, top_level, parsed);
            }
            "public_field_definition" | "property_signature" | "index_signature" => {
                visit_ts_field(file, source, child, parent, top_level, parsed);
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "internal_module" => {
                nested_class_like.push(child);
            }
            _ => {}
        }
    }
    nested_class_like
}

fn visit_ts_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    exported: bool,
) {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let Some(name_node) = definition.child_by_field_name("name") else {
        return;
    };
    let name = trim_statement(node_text(name_node, source));
    if name.is_empty() {
        return;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.clone());
    let fq = match parent {
        Some(parent) => parent
            .fq()
            .clone()
            .with_pushed(js_ts_segment(&name, SegmentKind::Member)),
        None => FqName::new().with_pushed(js_ts_segment(&name, SegmentKind::Member)),
    };
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        "",
        short_name,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        parent.cloned(),
        Some(top_level.clone()),
    );
    let signature = ts_function_signature(node, source, exported);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(
            signature,
            ts_parameter_labels(definition, source),
        ),
    );
    visit_ts_return_object_literal_properties(
        file, source, definition, &code_unit, &top_level, parsed,
    );
}

fn visit_ts_value(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    exported: bool,
    exported_roots: &HashSet<String>,
) {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };

    if definition.kind() == "type_alias_declaration" {
        let Some(name_node) = definition.child_by_field_name("name") else {
            return;
        };
        let name = trim_statement(node_text(name_node, source));
        let short_name = parent
            .map(|parent| format!("{}.{}", parent.short_name(), name))
            .unwrap_or_else(|| {
                format!(
                    "{}.{}",
                    file.rel_path()
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("module"),
                    name
                )
            });
        // Mirrors `short_name` above: a nested type alias is a plain `Member`
        // off the parent's `fq`; a top-level one is qualified by the same
        // file-name `Path` prefix as `file_scoped_field_name` (built by hand
        // above rather than via the shared helper, but structurally identical).
        let fq = match parent {
            Some(parent) => parent
                .fq()
                .clone()
                .with_pushed(js_ts_segment(&name, SegmentKind::Member)),
            None => file_scoped_field_fq(file, &name),
        };
        let code_unit = CodeUnit::new_fq(
            file.clone(),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
            "",
            short_name,
            fq,
        );
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.cloned(),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit.clone(), trim_statement(node_text(node, source)));
        parsed.mark_type_alias(code_unit.clone());
        visit_ts_type_alias_members(file, source, definition, &code_unit, &top_level, parsed);
        return;
    }

    for index in 0..definition.named_child_count() {
        let Some(child) = definition.named_child(index) else {
            continue;
        };
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if matches!(name_node.kind(), "object_pattern" | "array_pattern") {
            let signature = ts_variable_signature(definition, child, source, exported);
            let range_node = if exported { node } else { definition };
            add_destructured_binder_units(
                file, source, name_node, range_node, parent, &signature, parsed,
            );
            continue;
        }
        let name = trim_statement(node_text(name_node, source));
        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
            .unwrap_or(false);
        let module_surface = parent.is_none()
            && (exported || exported_roots.contains(&name))
            && value.is_some_and(|value| {
                ts_exported_surface_object_literal_value(child, value, source).is_some()
            });
        let kind = if is_function {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function
        } else {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field
        };
        let short_name = if kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Field {
            if let Some(parent) = parent {
                format!("{}.{}", parent.short_name(), name)
            } else {
                file_scoped_field_name(file, &name)
            }
        } else {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| name.clone())
        };
        // Mirrors `short_name` above segment-for-segment (see the analogous
        // javascript `visit_js_variable_statement`).
        let fq = if kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Field {
            match parent {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(js_ts_segment(&name, SegmentKind::Member)),
                None => file_scoped_field_fq(file, &name),
            }
        } else {
            match parent {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(js_ts_segment(&name, SegmentKind::Member)),
                None => FqName::new().with_pushed(js_ts_segment(&name, SegmentKind::Member)),
            }
        };
        let code_unit = CodeUnit::new_fq(file.clone(), kind, "", short_name, fq);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            parent.cloned(),
            Some(top_level.clone()),
        );
        let variable_signature = if is_function {
            let signature = ts_variable_function_signature(definition, child, source, exported);
            if let Some(value) = value {
                parsed.add_signature_with_metadata(
                    code_unit.clone(),
                    SignatureMetadata::with_parameter_labels(
                        signature.clone(),
                        ts_parameter_labels(value, source),
                    ),
                );
                visit_ts_return_object_literal_properties(
                    file, source, value, &code_unit, &top_level, parsed,
                );
            } else {
                parsed.add_signature(code_unit.clone(), signature.clone());
            }
            signature
        } else {
            let signature = ts_variable_signature(definition, child, source, exported);
            parsed.add_signature(code_unit.clone(), signature.clone());
            signature
        };
        let indexable_object = if !is_function {
            value.and_then(|value| {
                if module_surface {
                    ts_exported_surface_object_literal_value(child, value, source)
                } else {
                    ts_indexable_object_literal_value(child, value, source)
                }
            })
        } else {
            None
        };
        if let Some(object) = indexable_object {
            visit_ts_object_literal_properties(
                file, source, object, &code_unit, &top_level, parsed,
            );
        }
        if module_surface
            && kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Field
            && parent.is_none()
        {
            let surface_fq = FqName::new().with_pushed(js_ts_segment(&name, SegmentKind::Member));
            let surface_code_unit = CodeUnit::new_fq(
                file.clone(),
                brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
                "",
                name,
                surface_fq,
            );
            parsed.add_code_unit(
                surface_code_unit.clone(),
                range_node,
                source,
                None,
                Some(surface_code_unit.clone()),
            );
            parsed.add_signature(surface_code_unit.clone(), variable_signature);
            if let Some(object) = indexable_object {
                visit_ts_object_literal_properties(
                    file,
                    source,
                    object,
                    &surface_code_unit,
                    &surface_code_unit,
                    parsed,
                );
            }
        }
    }
}

fn visit_ts_type_alias_members(
    file: &ProjectFile,
    source: &str,
    definition: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let Some(value) = definition.child_by_field_name("value") else {
        return;
    };
    let container = value.child_by_field_name("body").unwrap_or(value);
    for index in 0..container.named_child_count() {
        let Some(child) = container.named_child(index) else {
            continue;
        };
        match child.kind() {
            "method_signature" | "abstract_method_signature" => {
                visit_ts_method(file, source, child, parent, top_level, parsed);
            }
            "property_signature" | "index_signature" => {
                visit_ts_field(file, source, child, parent, top_level, parsed);
            }
            _ => {}
        }
    }
}

fn ts_indexable_object_literal_value<'tree>(
    declarator: Node<'tree>,
    value: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    ts_object_literal_value(value).or_else(|| {
        (value.kind() == "call_expression")
            .then(|| ts_shape_preserving_call_object_argument(declarator, value, source))
            .flatten()
    })
}

fn ts_exported_surface_object_literal_value<'tree>(
    declarator: Node<'tree>,
    value: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    ts_object_literal_value(value).or_else(|| {
        (value.kind() == "call_expression")
            .then(|| ts_surface_call_object_argument(declarator, value, source))
            .flatten()
    })
}

fn ts_object_literal_value(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "object" => return Some(node),
            "parenthesized_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion" => {
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn ts_shape_preserving_call_object_argument<'tree>(
    anchor: Node<'tree>,
    call: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = ts_object_literal_value(argument)?;
            ts_call_preserves_object_argument_shape(anchor, call, source, index).then_some(object)
        })
}

fn ts_call_preserves_object_argument_shape(
    anchor: Node<'_>,
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> bool {
    if argument_index == 0 && call_is_schema_object_builder(call, source) {
        return true;
    }
    ts_call_object_argument_shape_preservation(anchor, call, source, argument_index)
        == TsShapePreservation::Preserves
}

fn ts_source_function_preserves_parameter_shape(
    anchor: Node<'_>,
    source: &str,
    function_name: &str,
    parameter_index: usize,
) -> TsShapePreservation {
    let root = root_node(anchor);
    let mut functions = Vec::new();
    collect_function_nodes(root, source, function_name, &mut functions);
    if functions.is_empty() {
        return TsShapePreservation::Unknown;
    }
    if functions.into_iter().any(|function| {
        ts_function_node_preserves_parameter_shape(function, source, parameter_index)
    }) {
        TsShapePreservation::Preserves
    } else {
        TsShapePreservation::DoesNotPreserve
    }
}

fn ts_surface_call_object_argument<'tree>(
    anchor: Node<'tree>,
    call: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = ts_object_literal_value(argument)?;
            ts_surface_call_preserves_object_argument_shape(anchor, call, source, index)
                .then_some(object)
        })
}

fn ts_surface_call_preserves_object_argument_shape(
    anchor: Node<'_>,
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> bool {
    if argument_index == 0 && call_is_schema_object_builder(call, source) {
        return true;
    }
    match ts_call_object_argument_shape_preservation(anchor, call, source, argument_index) {
        TsShapePreservation::Preserves => true,
        TsShapePreservation::DoesNotPreserve => false,
        TsShapePreservation::Unknown => call_has_likely_surface_factory_name(call, source),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsShapePreservation {
    Preserves,
    DoesNotPreserve,
    Unknown,
}

fn ts_call_object_argument_shape_preservation(
    anchor: Node<'_>,
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> TsShapePreservation {
    let Some(callee_name) = call_identifier_name(call, source) else {
        return TsShapePreservation::Unknown;
    };
    ts_source_function_preserves_parameter_shape(anchor, source, &callee_name, argument_index)
}

fn ts_function_node_preserves_parameter_shape(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> bool {
    let Some(parameter_name) = ts_function_parameter_name(function, source, parameter_index) else {
        return false;
    };
    if function.kind() == "arrow_function"
        && let Some(body) = function.child_by_field_name("body")
        && ts_expression_preserves_parameter_shape(body, source, &parameter_name)
    {
        return true;
    }
    ts_function_returns_parameter_shape(function, function.id(), source, &parameter_name)
}

fn ts_function_parameter_name(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(ts_parameter_name_node)
        .nth(parameter_index)
        .map(|name| node_text(name, source).trim().to_string())
        .filter(|name| !name.is_empty())
}

fn ts_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "required_parameter" | "optional_parameter" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        _ => None,
    }
}

fn ts_parameter_labels(function: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(ts_parameter_name_node)
        .filter_map(|name| {
            let label = node_text(name, source).trim();
            (!label.is_empty()).then(|| label.to_string())
        })
        .collect()
}

fn ts_function_returns_parameter_shape(
    node: Node<'_>,
    root_id: usize,
    source: &str,
    parameter_name: &str,
) -> bool {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "abstract_class_declaration"
                    | "interface_declaration"
            )
        {
            continue;
        }
        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if node
                .named_children(&mut cursor)
                .next()
                .is_some_and(|expression| {
                    ts_expression_preserves_parameter_shape(expression, source, parameter_name)
                })
            {
                return true;
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    false
}

fn ts_expression_preserves_parameter_shape(
    expression: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    let Some(expression) = ts_object_shape_expression(expression) else {
        return false;
    };
    if matches!(expression.kind(), "identifier" | "property_identifier")
        && node_text(expression, source).trim() == parameter_name
    {
        return true;
    }
    if expression.kind() != "object" {
        return false;
    }
    let mut cursor = expression.walk();
    expression.named_children(&mut cursor).any(|child| {
        child.kind() == "spread_element"
            && child
                .named_child(0)
                .and_then(ts_object_shape_expression)
                .is_some_and(|spread| node_text(spread, source).trim() == parameter_name)
    })
}

fn ts_object_shape_expression(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "as_expression" | "satisfies_expression" | "type_assertion" => {
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            _ => return Some(node),
        }
    }
    None
}

fn visit_ts_return_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let mut objects = Vec::new();
    collect_ts_return_object_literals(function, function.id(), &mut objects);
    for object in objects {
        visit_ts_object_literal_properties(file, source, object, parent, top_level, parsed);
    }
}

fn collect_ts_return_object_literals<'tree>(
    node: Node<'tree>,
    root_id: usize,
    out: &mut Vec<Node<'tree>>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "abstract_class_declaration"
                    | "interface_declaration"
            )
        {
            continue;
        }

        if node.kind() == "return_statement" {
            let mut cursor = node.walk();
            if let Some(object) = node
                .named_children(&mut cursor)
                .find_map(ts_object_literal_value)
            {
                out.push(object);
            }
            continue;
        }

        if node.kind() == "arrow_function"
            && let Some(body) = node.child_by_field_name("body")
            && let Some(object) = ts_object_literal_value(body)
        {
            out.push(object);
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn visit_ts_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    for index in 0..object.named_child_count() {
        let Some(child) = object.named_child(index) else {
            continue;
        };
        let Some(name) = ts_object_literal_property_name(child, source) else {
            continue;
        };
        let kind = if ts_object_literal_property_is_function(child) {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function
        } else {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field
        };
        let fq = parent
            .fq()
            .clone()
            .with_pushed(js_ts_segment(&name, SegmentKind::Member));
        let code_unit = CodeUnit::with_signature_and_fq(
            file.clone(),
            kind,
            "",
            format!("{}.{}", parent.short_name(), name),
            None,
            true,
            fq,
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, trim_statement(node_text(child, source)));
    }
}

pub fn ts_object_literal_property_name(node: Node<'_>, source: &str) -> Option<String> {
    let key = match node.kind() {
        "pair" => node
            .child_by_field_name("key")
            .or_else(|| node.named_child(0))?,
        "shorthand_property_identifier" => node,
        "method_definition" => node.child_by_field_name("name")?,
        _ => return None,
    };
    if key.kind() == "computed_property_name" {
        return None;
    }
    let name = trim_statement(node_text(key, source))
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    (!name.is_empty()).then_some(name)
}

fn ts_object_literal_property_is_function(node: Node<'_>) -> bool {
    node.kind() == "method_definition"
        || node
            .child_by_field_name("value")
            .is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
}

fn ts_es_named_exported_roots(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut roots = HashSet::default();
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if child.kind() != "export_statement" || child.child_by_field_name("source").is_some() {
            continue;
        }
        let mut cursor = child.walk();
        for export_child in child.named_children(&mut cursor) {
            collect_ts_export_clause_roots(export_child, source, &mut roots);
        }
    }
    roots
}

fn collect_ts_export_clause_roots(node: Node<'_>, source: &str, roots: &mut HashSet<String>) {
    match node.kind() {
        "export_clause" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_ts_export_clause_roots(child, source, roots);
            }
        }
        "export_specifier" => {
            let name = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0));
            if let Some(name) = name {
                collect_ts_export_identifier(name, source, roots);
            }
        }
        _ => {}
    }
}

fn collect_ts_export_identifier(node: Node<'_>, source: &str, roots: &mut HashSet<String>) {
    if matches!(
        node.kind(),
        "identifier" | "property_identifier" | "shorthand_property_identifier" | "type_identifier"
    ) {
        let name = node_text(node, source).trim();
        if !name.is_empty() {
            roots.insert(name.to_string());
        }
    }
}

fn visit_ts_method(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = trim_statement(node_text(name_node, source))
        .trim_matches('"')
        .to_string();
    let member_name = if is_static_ts_member(node, source) {
        format!("{name}$static")
    } else {
        name
    };
    // `member_name` already embeds the `$static` suffix (if any) as part of
    // its own text, so pushing it as a single Member segment reproduces the
    // legacy `.{member_name}` join exactly with no new segment kind.
    let fq = parent
        .fq()
        .clone()
        .with_pushed(js_ts_segment(&member_name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        "",
        format!("{}.{}", parent.short_name(), member_name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    let signature = match node.kind() {
        "method_definition" => format!(
            "{} {{ ... }}",
            trim_statement(node_text(node, source).split('{').next().unwrap_or(""))
        ),
        _ => trim_statement(node_text(node, source).split('{').next().unwrap_or("")),
    };
    parsed.add_signature_with_metadata(
        code_unit,
        SignatureMetadata::with_parameter_labels(signature, ts_parameter_labels(node, source)),
    );
    if member_name == "constructor" {
        visit_ts_constructor_assigned_fields(file, source, node, parent, top_level, parsed);
    }
}

/// Index constructor-assigned instance properties (`this.x = ...`) as Field
/// units, mirroring the JavaScript analyzer: pre-class-field style codebases
/// (and any constructor that assigns properties) otherwise have instance
/// fields that scan_usages resolves but search_symbols cannot find.
fn visit_ts_constructor_assigned_fields(
    file: &ProjectFile,
    source: &str,
    constructor: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let mut stack = vec![constructor];
    while let Some(node) = stack.pop() {
        if node.id() != constructor.id()
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "function"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        {
            continue;
        }
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && let Some(property) = this_member_property(left, source)
        {
            let Some(name) = property_name_text(property, source) else {
                continue;
            };
            let fq = parent
                .fq()
                .clone()
                .with_pushed(js_ts_segment(&name, SegmentKind::Member));
            let code_unit = CodeUnit::new_fq(
                file.clone(),
                brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
                "",
                format!("{}.{}", parent.short_name(), name),
                fq,
            );
            parsed.add_code_unit(
                code_unit.clone(),
                property,
                source,
                Some(parent.clone()),
                Some(top_level.clone()),
            );
            parsed.add_signature(code_unit, trim_statement(node_text(node, source)));
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn visit_ts_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let name_node = node.child_by_field_name("name").unwrap_or(node);
    let name = trim_statement(node_text(name_node, source))
        .trim_matches('"')
        .to_string();
    let member_name = if is_static_ts_member(node, source) {
        format!("{name}$static")
    } else {
        name
    };
    let fq = parent
        .fq()
        .clone()
        .with_pushed(js_ts_segment(&member_name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), member_name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, ts_field_signature(node, source));
}

fn visit_ts_enum_member(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
) {
    let name = if node.kind() == "enum_assignment" {
        node.child_by_field_name("name")
            .map(|name| trim_statement(node_text(name, source)))
            .unwrap_or_default()
    } else {
        trim_statement(node_text(node, source))
    };
    if name.is_empty() {
        return;
    }
    let fq = parent
        .fq()
        .clone()
        .with_pushed(js_ts_segment(&name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
        "",
        format!("{}.{}", parent.short_name(), name),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    let raw = trim_statement(node_text(node, source));
    let suffix = source
        .get(node.end_byte()..)
        .map(str::trim_start)
        .filter(|tail| tail.starts_with(','))
        .map(|_| ",")
        .unwrap_or("");
    parsed.add_signature(code_unit, format!("{raw}{suffix}"));
}

fn ts_class_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let text = if node.kind() == "export_statement" {
        node_text(node, source)
    } else {
        node_text(definition, source)
    };
    let head = trim_statement(text.split('{').next().unwrap_or(text));
    if definition.kind() == "enum_declaration" {
        let open = format!(
            "{} {{",
            if exported && !head.starts_with("export ") {
                format!("export {head}")
            } else {
                head
            }
        );
        return open;
    }
    format!(
        "{} {{",
        if exported && !head.starts_with("export ") {
            format!("export {head}")
        } else {
            head
        }
    )
}

fn ts_default_export_class_signature(export: Node<'_>, source: &str) -> String {
    let text = node_text(export, source);
    let head = trim_statement(text.split('{').next().unwrap_or(text));
    format!("{head} {{")
}

fn ts_function_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let head = trim_statement(
        if node.kind() == "export_statement" {
            node_text(node, source)
        } else {
            node_text(definition, source)
        }
        .split('{')
        .next()
        .unwrap_or(node_text(definition, source)),
    );
    let head = if exported && !head.starts_with("export ") {
        format!("export {head}")
    } else {
        head
    };
    if definition.kind() == "function_signature" {
        head
    } else {
        format!("{head} {{ ... }}")
    }
}

fn ts_default_export_function_signature(function: Node<'_>, source: &str) -> String {
    let text = node_text(function, source);
    let async_prefix = if text.trim_start().starts_with("async ") {
        "async "
    } else {
        ""
    };
    let params = function
        .child_by_field_name("parameters")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_else(|| "()".to_string());
    let return_type = function
        .child_by_field_name("return_type")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let return_suffix = if return_type.is_empty() {
        String::new()
    } else {
        format!(": {}", return_type.trim_start_matches(':').trim())
    };
    match function.kind() {
        "function_declaration" | "function_expression" => {
            format!("export default {async_prefix}function{params}{return_suffix} {{ ... }}")
        }
        "generator_function" => {
            format!("export default {async_prefix}function*{params}{return_suffix} {{ ... }}")
        }
        _ => format!("export default {async_prefix}{params}{return_suffix} => {{ ... }}"),
    }
}

fn ts_variable_function_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let kind = statement
        .child(0)
        .map(|node| node_text(node, source).trim().to_string())
        .unwrap_or_else(|| "const".to_string());
    let name = declarator
        .child_by_field_name("name")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let value = declarator
        .child_by_field_name("value")
        .unwrap_or(declarator);
    let params = value
        .child_by_field_name("parameters")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_else(|| "()".to_string());
    let return_type = value
        .child_by_field_name("return_type")
        .map(|node| trim_statement(node_text(node, source)))
        .unwrap_or_default();
    let export_prefix = if exported { "export " } else { "" };
    let return_suffix = if return_type.is_empty() {
        String::new()
    } else {
        format!(": {}", return_type.trim_start_matches(':').trim())
    };
    format!("{export_prefix}{kind} {name} = {params}{return_suffix} => {{ ... }}")
}

fn ts_variable_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let header = variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_ts_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn ts_field_signature(node: Node<'_>, source: &str) -> String {
    if matches!(node.kind(), "property_signature" | "index_signature") {
        return trim_statement(node_text(node, source));
    }

    let raw = trim_statement(node_text(node, source));
    if let Some(value) = node.child_by_field_name("value")
        && !is_simple_ts_initializer(value)
    {
        return raw
            .split('=')
            .next()
            .map(trim_statement)
            .filter(|header| !header.is_empty())
            .unwrap_or(raw);
    }
    raw
}

fn is_simple_ts_initializer(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string"
            | "number"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "regex"
            | "template_string"
            | "unary_expression"
            | "binary_expression"
            | "identifier"
            | "member_expression"
    )
}

fn is_static_ts_member(node: Node<'_>, source: &str) -> bool {
    let head = node_text(node, source)
        .split(['{', ';'])
        .next()
        .unwrap_or("");
    head.split_whitespace().any(|token| token == "static")
}
