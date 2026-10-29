//! JavaScript's declaration walk.
//!
//! The whole free-function band of `analyzer/javascript/mod.rs`: the top-level
//! parse driver, the export/class/function/field visitors, the CommonJS and ESM
//! export analysis, the assignment-declaration state machine and the signature
//! renderers. Everything here takes plain syntax and core types, so none of it
//! ever named `JavascriptAnalyzer`.
//!
//! `brokk-bifrost-analysis` keeps the shim: the `JavascriptAnalyzer` struct with
//! its `JsTsMemoCaches` bucket and `AliasResolver`, the `CodeUnitIndex` and
//! `IAnalyzer` impls, the `JavascriptAdapter` forwarding shell whose
//! `parse_file` calls [`parse_javascript_file`], and the SPI registration.

use crate::hierarchy::extract_js_supertypes;
use crate::identifiers::{extract_js_ts_type_identifiers, trimmed_identifier_text};
use crate::imports::{
    parse_commonjs_require_import_syntaxes_from_node, parse_es_import_syntaxes_from_node,
};
use crate::model::*;
use crate::parse::flow_dialect_blocks_extraction;
use crate::primary::{JsTsParsedFile, StructuralOwnerClaim};
use crate::syntax::{
    expression_preserves_parameter_shape, function_returns_parameter_shape,
    js_program_is_external_module, parameter_name_at_index,
};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ParameterMetadata, SignatureMetadata};
use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
use brokk_bifrost_core::analyzer::structural::materialization::{
    ExportForm, MaterializationRecord,
};
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::analyzer::tree_walk::{WalkControl, walk_named_tree_preorder};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
#[cfg(test)]
use tree_sitter::Parser;
use tree_sitter::{Node, Tree};

/// The JavaScript half of `LanguageAdapter::parse_file`: walk `tree`'s top level
/// and record every declaration, import statement and export the file spells.
pub fn parse_javascript_file(file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
    let root = tree.root_node();
    let blocked = flow_dialect_blocks_extraction(file, root, source);
    let module = module_code_unit(file);
    let top_level_field_identity = if js_program_is_external_module(root, source) {
        file_scoped_field_identity
    } else {
        program_scoped_field_identity
    };
    let mut module_has_imports = false;
    let lexical_bindings = crate::syntax::JsTsLexicalBindingIndex::build(root, source);
    let mut assignment_state = JsAssignmentDeclarations::new(root, source, &lexical_bindings);
    let exported_roots = js_exported_binding_roots(root, source, &assignment_state.state.commonjs);
    crate::primary::parse_primary_with_lexical_bindings(
        source,
        tree,
        &crate::structural::JAVASCRIPT_STRUCTURAL_SPEC,
        lexical_bindings,
        assignment_state.commonjs().clone(),
        |parsed, event| {
            if blocked {
                return;
            }
            match event {
                crate::primary::PrimaryEvent::Enter {
                    node: child,
                    parent_kind,
                    depth,
                } => {
                    if depth == 1 {
                        match child.kind() {
                            "import_statement" => {
                                module_has_imports = true;
                                parsed.add_import_syntaxes(parse_es_import_syntaxes_from_node(
                                    child, source,
                                ));
                            }
                            "expression_statement" => {
                                let imports =
                                    parse_commonjs_require_import_syntaxes_from_node(child, source);
                                if !imports.is_empty() {
                                    module_has_imports = true;
                                    parsed.add_import_syntaxes(imports);
                                }
                            }
                            "export_statement" => {
                                visit_js_export(file, source, child, parsed);
                            }
                            "class_declaration" => {
                                visit_js_class(file, source, child, parsed, false);
                            }
                            "function_declaration" => {
                                visit_js_function(file, source, child, None, parsed, false);
                            }
                            "lexical_declaration" | "variable_declaration" => {
                                let imports =
                                    parse_commonjs_require_import_syntaxes_from_node(child, source);
                                if !imports.is_empty() {
                                    module_has_imports = true;
                                    parsed.add_import_syntaxes(imports);
                                }
                                visit_js_variable_statement(
                                    file,
                                    source,
                                    child,
                                    None,
                                    parsed,
                                    false,
                                    &exported_roots,
                                    top_level_field_identity,
                                );
                            }
                            _ => {}
                        }
                    }
                    assignment_state.enter(file, source, child, parent_kind, parsed);
                }
                crate::primary::PrimaryEvent::Exit { node } => {
                    assignment_state.exit(node);
                    if node.id() == root.id() && module_has_imports {
                        parsed.add_code_unit(module.clone(), root, source, None, None);
                    }
                }
            }
        },
    )
}

fn visit_js_export(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
) {
    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "class_declaration" => {
                if declaration.child_by_field_name("name").is_none()
                    && export_is_default(node, source)
                {
                    visit_js_default_export_class(file, source, node, declaration, parsed);
                } else {
                    record_named_export(
                        source,
                        node,
                        declaration,
                        export_is_default(node, source),
                        parsed,
                    );
                    visit_js_class(file, source, node, parsed, true);
                }
            }
            "function_declaration" => {
                if declaration.child_by_field_name("name").is_none()
                    && export_is_default(node, source)
                {
                    visit_js_default_export_function(file, source, node, declaration, parsed);
                } else {
                    record_named_export(
                        source,
                        node,
                        declaration,
                        export_is_default(node, source),
                        parsed,
                    );
                    visit_js_function(file, source, node, None, parsed, true);
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                record_named_declarator_exports(source, node, declaration, parsed);
                visit_js_variable_statement(
                    file,
                    source,
                    node,
                    None,
                    parsed,
                    true,
                    &HashSet::default(),
                    file_scoped_field_identity,
                );
            }
            _ => {}
        }
    } else if let Some(value) = node.child_by_field_name("value") {
        visit_js_default_export_value(file, source, node, value, parsed);
    }
}

fn visit_js_default_export_value(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    value: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
) {
    visit_default_export_value(
        file,
        source,
        export,
        value,
        parsed,
        |file, source, export, function, parsed| {
            visit_js_default_export_function(file, source, export, function, parsed);
        },
        |file, source, export, class, parsed| {
            visit_js_default_export_class(file, source, export, class, parsed);
        },
        visit_js_object_literal_properties,
    );
}

fn visit_js_default_export_function(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    function: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
) -> CodeUnit {
    let code_unit = add_default_export_unit(
        file,
        source,
        export,
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
        parsed,
    );
    let (signature, parameter_text) = js_default_export_function_signature(function, source);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        js_signature_metadata(signature, function, source, &parameter_text),
    );
    visit_js_return_object_literal_properties(
        file, source, function, &code_unit, &code_unit, parsed,
    );
    code_unit
}

fn visit_js_default_export_class(
    file: &ProjectFile,
    source: &str,
    export: Node<'_>,
    class: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
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
        js_default_export_class_signature(export, source),
    );
    let supertypes = extract_js_supertypes(class, source);
    if !supertypes.is_empty() {
        parsed.set_raw_supertypes(code_unit.clone(), supertypes);
    }
    visit_js_class_body(file, source, class, &code_unit, &code_unit, parsed);
    code_unit
}

fn visit_js_class(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
    exported: bool,
) -> Option<CodeUnit> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let name_node = definition.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = name.to_string();
    let fq = FqName::new().with_pushed(segment_interner().intern(name, SegmentKind::Type));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
        "",
        short_name,
        fq,
    );
    let top_level = code_unit.clone();
    let range_node = if exported { node } else { definition };
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        None,
        Some(top_level.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        js_class_signature(node, source, exported),
    );
    let supertypes = extract_js_supertypes(definition, source);
    if !supertypes.is_empty() {
        parsed.set_raw_supertypes(code_unit.clone(), supertypes);
    }

    visit_js_class_body(file, source, definition, &code_unit, &top_level, parsed);

    Some(code_unit)
}

fn visit_js_class_body(
    file: &ProjectFile,
    source: &str,
    class: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) {
    let Some(body) = class.child_by_field_name("body") else {
        return;
    };
    for index in 0..body.named_child_count() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        match child.kind() {
            "method_definition" => visit_js_method(file, source, child, parent, top_level, parsed),
            "field_definition" | "public_field_definition" => {
                visit_js_field(file, source, child, parent, top_level, parsed);
            }
            _ => {}
        }
    }
}

fn visit_js_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut JsTsParsedFile<'_>,
    exported: bool,
) -> Option<CodeUnit> {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let name_node = definition.child_by_field_name("name")?;
    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    let fq = match parent {
        Some(parent) => parent
            .fq()
            .clone()
            .with_pushed(segment_interner().intern(name, SegmentKind::Member)),
        None => FqName::new().with_pushed(segment_interner().intern(name, SegmentKind::Member)),
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
    let (signature, parameter_text) = js_function_signature(definition, source, name, exported);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        js_signature_metadata(signature, definition, source, &parameter_text),
    );
    visit_js_return_object_literal_properties(
        file, source, definition, &code_unit, &top_level, parsed,
    );
    Some(code_unit)
}

fn visit_js_method(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, source).trim_matches('"').trim();
    if name.is_empty() {
        return;
    }

    let fq = parent
        .fq()
        .clone()
        .with_pushed(segment_interner().intern(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function,
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
    let (signature, parameter_text) = js_method_signature(node, source);
    parsed.add_signature_with_metadata(
        code_unit,
        js_signature_metadata(signature, node, source, &parameter_text),
    );
    if name == "constructor" {
        visit_js_constructor_assigned_fields(file, source, node, parent, top_level, parsed);
    }
}

fn visit_js_constructor_assigned_fields(
    file: &ProjectFile,
    source: &str,
    constructor: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) {
    crate::primary::visit_constructor_assigned_fields(
        file,
        source,
        constructor,
        parent,
        top_level,
        parsed,
        |kind| {
            matches!(
                kind,
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        },
    );
}

fn visit_js_field(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) {
    // `field_definition` names its property through `property`; the TSX
    // grammar's `public_field_definition`, which reads every `.jsx` file
    // (#3322), names it through `name`.
    let Some(name_node) = node
        .child_by_field_name("property")
        .or_else(|| node.child_by_field_name("name"))
    else {
        return;
    };
    let name = node_text(name_node, source).trim_matches('"').trim();
    if name.is_empty() {
        return;
    }
    let code_unit =
        crate::primary::add_field_member_unit(file, source, node, name, parent, top_level, parsed);
    parsed.add_signature(code_unit, trim_statement(node_text(node, source)));
}

#[allow(clippy::too_many_arguments)]
fn visit_js_variable_statement(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    parsed: &mut JsTsParsedFile<'_>,
    exported: bool,
    exported_roots: &HashSet<String>,
    top_level_field_identity: TopLevelFieldIdentity,
) {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
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
            let signature = js_variable_signature(definition, child, source, exported);
            let range_node = if exported { node } else { definition };
            add_destructured_binder_units(
                file,
                source,
                name_node,
                range_node,
                parent,
                &signature,
                parsed,
                top_level_field_identity,
            );
            continue;
        }
        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let value = child.child_by_field_name("value");
        let is_function = value
            .map(|value| matches!(value.kind(), "arrow_function" | "function_expression"))
            .unwrap_or(false);
        let module_surface = parent.is_none()
            && (exported || exported_roots.contains(name))
            && value.is_some_and(|value| js_initializer_has_surface_shape(value, source));
        let kind = if is_function {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Function
        } else {
            brokk_bifrost_core::analyzer::model::CodeUnitType::Field
        };
        let short_name = if kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Field {
            if let Some(parent) = parent {
                format!("{}.{}", parent.short_name(), name)
            } else {
                top_level_field_identity(file, name).0
            }
        } else {
            parent
                .map(|parent| format!("{}.{}", parent.short_name(), name))
                .unwrap_or_else(|| name.to_string())
        };
        // Mirrors `short_name` above segment-for-segment. A top-level script
        // Field uses the shared program identity. A module Field uses its file
        // identity. Nested fields stay below their structural parent.
        let fq = if kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Field {
            match parent {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(segment_interner().intern(name, SegmentKind::Member)),
                None => top_level_field_identity(file, name).1,
            }
        } else {
            match parent {
                Some(parent) => parent
                    .fq()
                    .clone()
                    .with_pushed(segment_interner().intern(name, SegmentKind::Member)),
                None => {
                    FqName::new().with_pushed(segment_interner().intern(name, SegmentKind::Member))
                }
            }
        };
        let code_unit = CodeUnit::new_fq(file.clone(), kind, "", short_name, fq);
        let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
        let range_node = if exported { node } else { definition };
        parsed.add_named_code_unit(
            code_unit.clone(),
            range_node,
            name_node,
            source,
            parent.cloned(),
            Some(top_level.clone()),
        );
        let variable_signature = if is_function {
            let (signature, parameter_text) =
                js_variable_function_signature(definition, child, source, name, exported);
            if let Some(value) = value {
                parsed.add_signature_with_metadata(
                    code_unit.clone(),
                    js_signature_metadata(signature.clone(), value, source, &parameter_text),
                );
            } else {
                parsed.add_signature(code_unit.clone(), signature.clone());
            }
            if let Some(value) = value {
                visit_js_return_object_literal_properties(
                    file, source, value, &code_unit, &top_level, parsed,
                );
            }
            signature
        } else {
            let signature = js_variable_signature(definition, child, source, exported);
            parsed.add_signature(code_unit.clone(), signature.clone());
            signature
        };
        let indexable_object = if !is_function {
            value.and_then(|value| js_indexable_object_literal_value(value, source, module_surface))
        } else {
            None
        };
        if let Some(object) = indexable_object {
            visit_js_object_literal_properties(
                file, source, object, &code_unit, &top_level, parsed,
            );
        }
        if module_surface
            && kind == brokk_bifrost_core::analyzer::model::CodeUnitType::Field
            && parent.is_none()
        {
            let surface_fq =
                FqName::new().with_pushed(segment_interner().intern(name, SegmentKind::Member));
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
                visit_js_object_literal_properties_for_surface(
                    file,
                    source,
                    object,
                    &surface_code_unit,
                    &surface_code_unit,
                    parsed,
                    JsAssignmentSymbolSurface::DefinitionLookupOnly,
                );
            }
        }
    }
}

fn visit_js_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) {
    visit_js_object_literal_properties_for_surface(
        file,
        source,
        object,
        parent,
        top_level,
        parsed,
        JsAssignmentSymbolSurface::Declaration,
    );
}

fn visit_js_object_literal_properties_for_surface(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
    surface: JsAssignmentSymbolSurface,
) {
    let mut pending = vec![(object, parent.clone())];
    while let Some((object, parent)) = pending.pop() {
        for index in 0..object.named_child_count() {
            let Some(child) = object.named_child(index) else {
                continue;
            };
            let Some(name) = js_object_literal_property_name(child, source) else {
                continue;
            };
            let kind = object_literal_property_kind(child);
            let fq = parent
                .fq()
                .clone()
                .with_pushed(segment_interner().intern(&name, SegmentKind::Member));
            let short_name = fq.display_native(file.language(), segment_interner());
            let code_unit = CodeUnit::new_fq(file.clone(), kind, "", short_name, fq);
            match surface {
                JsAssignmentSymbolSurface::Declaration => {
                    parsed.add_code_unit(
                        code_unit.clone(),
                        child,
                        source,
                        Some(parent.clone()),
                        Some(top_level.clone()),
                    );
                }
                JsAssignmentSymbolSurface::DefinitionLookupOnly => {
                    parsed.add_definition_lookup_unit(code_unit.clone(), child, source);
                }
            }
            if child.kind() == "pair"
                && let Some(nested) = child
                    .child_by_field_name("value")
                    .and_then(crate::syntax::js_ts_object_literal_value)
            {
                pending.push((nested, code_unit.clone()));
            }
            parsed.add_signature(code_unit, trim_statement(node_text(child, source)));
        }
    }
}

fn visit_js_module_exports_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
) {
    for index in 0..object.named_child_count() {
        let Some(child) = object.named_child(index) else {
            continue;
        };
        let Some(name) = js_object_literal_property_name(child, source) else {
            continue;
        };
        if js_module_exports_property_is_reference(child) {
            // A reference property re-exports an existing local declaration;
            // it is an export row but materializes no declaration of its own.
            parsed.record_materialization(MaterializationRecord::Export {
                range: brokk_bifrost_core::analyzer::tree_walk::node_range(child),
                form: ExportForm::CommonJsMember,
                exported_name: name,
                target: None,
            });
            continue;
        }
        let kind = object_literal_property_kind(child);
        let fq = FqName::new().with_pushed(segment_interner().intern(&name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(file.clone(), kind, "", name.clone(), fq);
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            None,
            Some(code_unit.clone()),
        );
        parsed.record_materialization(MaterializationRecord::Export {
            range: brokk_bifrost_core::analyzer::tree_walk::node_range(child),
            form: ExportForm::CommonJsMember,
            exported_name: name,
            target: Some(code_unit.clone()),
        });
        parsed.add_signature(code_unit, trim_statement(node_text(child, source)));
    }
}

/// Whether a `module.exports = { ... }` property re-exports an existing local
/// declaration (shorthand `{ makeWidget }` or `{ name: localBinding }`) rather
/// than defining a value in place. Reference properties must not become
/// declarations of their own: the export index already maps them to the real
/// local declaration, and a duplicate top-level CodeUnit at the export site
/// makes definition lookup for the exported name ambiguous.
fn js_module_exports_property_is_reference(node: Node<'_>) -> bool {
    match node.kind() {
        "shorthand_property_identifier" => true,
        "pair" => node
            .child_by_field_name("value")
            .is_some_and(|value| matches!(value.kind(), "identifier" | "member_expression")),
        _ => false,
    }
}

fn js_object_literal_property_name(node: Node<'_>, source: &str) -> Option<String> {
    crate::typescript::ts_object_literal_property_name(node, source)
}

fn js_exported_binding_roots(
    root: Node<'_>,
    source: &str,
    commonjs: &crate::commonjs::CommonJsObjects,
) -> HashSet<String> {
    let mut roots = js_commonjs_exported_roots(root, source, commonjs);
    roots.extend(crate::identifiers::es_named_exported_roots(root, source));
    roots
}

fn js_indexable_object_literal_value<'tree>(
    value: Node<'tree>,
    source: &str,
    include_factory_call: bool,
) -> Option<Node<'tree>> {
    crate::syntax::js_ts_object_literal_value(value)
        .or_else(|| js_surface_call_object_argument(value, source, include_factory_call))
}

fn js_initializer_has_surface_shape(value: Node<'_>, source: &str) -> bool {
    js_indexable_object_literal_value(value, source, true).is_some()
}

fn js_surface_call_object_argument<'tree>(
    call: Node<'tree>,
    source: &str,
    include_factory_call: bool,
) -> Option<Node<'tree>> {
    if call.kind() != "call_expression" {
        return None;
    }
    crate::syntax::first_preserved_object_literal_call_argument(call, |index| {
        // The schema-builder shortcut (e.g. zod's `z.object({...})`) applies
        // regardless of export/surface status. The broader factory-name
        // heuristic remains surface-gated.
        (index == 0 && call_is_schema_object_builder(call, source))
            || (include_factory_call
                && js_call_preserves_object_argument_shape(call, source, index))
    })
}

fn js_call_preserves_object_argument_shape(
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> bool {
    surface_call_preserves_object_argument_shape(
        call,
        source,
        argument_index,
        js_call_object_argument_shape_preservation(call, source, argument_index),
    )
}

fn js_call_object_argument_shape_preservation(
    call: Node<'_>,
    source: &str,
    argument_index: usize,
) -> ShapePreservation {
    let Some(callee_name) = call_identifier_name(call, source) else {
        return ShapePreservation::Unknown;
    };
    js_source_function_preserves_parameter_shape(call, source, &callee_name, argument_index)
}

fn js_source_function_preserves_parameter_shape(
    anchor: Node<'_>,
    source: &str,
    function_name: &str,
    parameter_index: usize,
) -> ShapePreservation {
    source_function_shape_preservation(anchor, source, function_name, |function| {
        js_function_node_preserves_parameter_shape(function, source, parameter_index)
    })
}

fn js_function_node_preserves_parameter_shape(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> bool {
    let Some(parameter_name) = js_function_parameter_name(function, source, parameter_index) else {
        return false;
    };
    if function.kind() == "arrow_function"
        && let Some(body) = function.child_by_field_name("body")
        && js_expression_preserves_parameter_shape(body, source, &parameter_name)
    {
        return true;
    }
    js_function_returns_parameter_shape(function, function.id(), source, &parameter_name)
}

fn js_function_parameter_name(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    parameter_name_at_index(function, source, parameter_index, js_parameter_label_node)
}

fn js_function_returns_parameter_shape(
    node: Node<'_>,
    root_id: usize,
    source: &str,
    parameter_name: &str,
) -> bool {
    function_returns_parameter_shape(
        node,
        root_id,
        |kind| {
            matches!(
                kind,
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        },
        |expression| js_expression_preserves_parameter_shape(expression, source, parameter_name),
    )
}

fn js_expression_preserves_parameter_shape(
    expression: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    expression_preserves_parameter_shape(expression, parameter_name, Some, |node, name| {
        node_text(node, source).trim() == name
    })
}

fn visit_js_return_object_literal_properties(
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut JsTsParsedFile<'_>,
) {
    let mut objects = Vec::new();
    collect_js_return_object_literals(function, function.id(), &mut objects);
    for object in objects {
        visit_js_object_literal_properties(file, source, object, parent, top_level, parsed);
    }
}

fn collect_js_return_object_literals<'tree>(
    node: Node<'tree>,
    root_id: usize,
    out: &mut Vec<Node<'tree>>,
) {
    collect_return_object_literals(
        node,
        root_id,
        out,
        |node| {
            matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "class"
            )
        },
        crate::syntax::js_ts_object_literal_value,
    );
}

fn js_signature_metadata(
    signature: String,
    function: Node<'_>,
    source: &str,
    parameter_text: &str,
) -> SignatureMetadata {
    let (is_static, is_constructor) = js_callable_modifiers(function, source);
    let with_modifiers = |metadata: SignatureMetadata| {
        metadata.with_callable_modifiers(is_static, is_constructor, DeclaredVisibility::Unknown)
    };
    let parameters = ParameterMetadata::from_signature_labels(
        &signature,
        parameter_text,
        js_parameter_label_nodes(function)
            .into_iter()
            .map(|node| node_text(node, source).trim()),
    );
    with_modifiers(SignatureMetadata::new(signature, parameters))
}

/// The `(is_static, is_constructor)` pair this callable declares, read from its
/// own syntax nodes (#2597).
///
/// Recording the pair is what makes a JavaScript declaration keyable for
/// procedure-summary binding: `receiver_contract_of` refuses to answer for a
/// callable whose adapter never inspected modifiers, so before this every
/// JavaScript summary matched nothing.
///
/// Only a `method_definition` can bind a class receiver. Every other node this
/// walk hands over -- `function_declaration`, `function_expression`,
/// `arrow_function`, `generator_function` -- is reached through its own binding
/// rather than through an instance, so it is static in the sense the receiver
/// contract asks about: nothing has to be bound in receiver position.
///
/// `static` and the `static get` compound are anonymous tokens of
/// `method_definition`, so the check reads the node's children rather than its
/// rendered header. `constructor` is a static-free member name: a member named
/// `constructor` under `static` is an ordinary static method, and the language
/// only reserves the name for the instance-construction path.
fn js_callable_modifiers(function: Node<'_>, source: &str) -> (bool, bool) {
    if function.kind() != "method_definition" {
        return (true, false);
    }
    let mut cursor = function.walk();
    let is_static = function
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "static" | "static get"));
    let is_constructor = !is_static
        && function
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source).trim_matches('"').trim() == "constructor");
    (is_static, is_constructor)
}

fn js_rendered_parameter_text(function: Node<'_>, source: &str) -> String {
    if let Some(parameters) = function.child_by_field_name("parameters") {
        return node_text(parameters, source).trim().to_string();
    }
    function
        .child_by_field_name("parameter")
        .map(|parameter| format!("({})", node_text(parameter, source).trim()))
        .unwrap_or_else(|| "()".to_string())
}

fn js_parameter_label_nodes(function: Node<'_>) -> Vec<Node<'_>> {
    if let Some(parameters) = function.child_by_field_name("parameters") {
        let mut cursor = parameters.walk();
        return parameters
            .named_children(&mut cursor)
            .filter_map(js_parameter_label_node)
            .collect();
    }
    function
        .child_by_field_name("parameter")
        .and_then(js_parameter_label_node)
        .into_iter()
        .collect()
}

fn js_parameter_label_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "assignment_pattern" => parameter.child_by_field_name("left"),
        "rest_pattern" => parameter.named_child(0).or(Some(parameter)),
        "object_pattern" | "array_pattern" => Some(parameter),
        // The TSX grammar, which reads every `.jsx` file (#3322), wraps each
        // parameter in `required_parameter`/`optional_parameter` and states
        // the binding under `pattern`. A default value is the wrapper's
        // `value` field rather than an `assignment_pattern`, so the binding
        // under `pattern` is already the label in both spellings.
        "required_parameter" | "optional_parameter" => parameter
            .child_by_field_name("pattern")
            .and_then(js_parameter_label_node),
        _ => None,
    }
}

/// The shared JS/TS member-assignment and local-object extraction walk.
pub(crate) struct JsAssignmentDeclarations {
    state: JsAssignmentDeclarationState,
}

impl JsAssignmentDeclarations {
    pub(crate) fn new(
        root: Node<'_>,
        source: &str,
        lexical: &crate::syntax::JsTsLexicalBindingIndex,
    ) -> Self {
        let commonjs = crate::commonjs::CommonJsObjects::new(root, source, lexical);
        Self {
            state: JsAssignmentDeclarationState::new(
                js_commonjs_exported_roots(root, source, &commonjs),
                js_commonjs_exported_members(root, source, &commonjs),
                commonjs,
            ),
        }
    }

    pub(crate) fn commonjs(&self) -> &crate::commonjs::CommonJsObjects {
        &self.state.commonjs
    }

    pub(crate) fn enter(
        &mut self,
        file: &ProjectFile,
        source: &str,
        node: Node<'_>,
        parent_kind: Option<&str>,
        parsed: &mut JsTsParsedFile<'_>,
    ) {
        if let Some(scope) = js_assignment_scope_kind(node) {
            self.state.enter_scope(scope);
            register_js_assignment_parameters(node, source, &mut self.state);
        }
        register_js_assignment_variable(node, parent_kind, source, &mut self.state);
        if node.kind() == "variable_declarator"
            && self.state.scopes.len() > 1
            && let Some(name) = node
                .child_by_field_name("name")
                .filter(|name| name.kind() == "identifier")
            && let Some(object) = node
                .child_by_field_name("value")
                .and_then(crate::syntax::js_ts_object_literal_value)
        {
            // Local literal keys have the same lookup-only surface as
            // properties established by local member assignments.
            // Do not publish the local binding as a global declaration.
            let binding_name = name;
            let name = node_text(binding_name, source);
            let fq = parsed
                .local_binding_fq(binding_name, name)
                .expect("local object literal binder has an indexed binding scope");
            let short_name = fq.display_native(file.language(), segment_interner());
            let owner = CodeUnit::new_fq(
                file.clone(),
                brokk_bifrost_core::analyzer::model::CodeUnitType::Field,
                "",
                short_name,
                fq,
            );
            visit_js_object_literal_properties_for_surface(
                file,
                source,
                object,
                &owner,
                &owner,
                parsed,
                JsAssignmentSymbolSurface::DefinitionLookupOnly,
            );
        }
        if node.kind() == "assignment_expression" {
            visit_js_assignment_expression(file, source, node, parsed, &self.state);
        }
    }

    pub(crate) fn exit(&mut self, node: Node<'_>) {
        if js_assignment_scope_kind(node).is_some() {
            self.state.exit_scope();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsAssignmentBindingKind {
    /// A parameter or a local whose value comes from elsewhere. The object it
    /// holds can outlive the scope, so its members keep a file-scoped name.
    PlainLocal,
    /// A local declarator initialized with an object literal. The object is
    /// created in this scope, so its members are scoped to the binding (#3864).
    LocalObject,
    DeclarationRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsAssignmentScopeKind {
    Function,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsAssignmentSymbolSurface {
    Declaration,
    DefinitionLookupOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JsMemberAssignmentTarget {
    name: String,
    /// Structured counterpart to `name`, built segment-for-segment alongside
    /// it (see `js_member_assignment_target`): every link in the
    /// `object.property` chain is a `Member` segment, mirroring the `.`-joined
    /// `name` string exactly.
    fq: FqName,
    surface: JsAssignmentSymbolSurface,
    owner: StructuralOwnerClaim,
}

struct JsAssignmentScope {
    kind: JsAssignmentScopeKind,
    bindings: HashMap<String, JsAssignmentBindingKind>,
}

impl JsAssignmentScope {
    fn new(kind: JsAssignmentScopeKind) -> Self {
        Self {
            kind,
            bindings: HashMap::default(),
        }
    }
}

struct JsAssignmentDeclarationState {
    scopes: Vec<JsAssignmentScope>,
    commonjs_exported_roots: HashSet<String>,
    commonjs_exported_members: HashSet<String>,
    commonjs: crate::commonjs::CommonJsObjects,
}

impl JsAssignmentDeclarationState {
    fn new(
        commonjs_exported_roots: HashSet<String>,
        commonjs_exported_members: HashSet<String>,
        commonjs: crate::commonjs::CommonJsObjects,
    ) -> Self {
        Self {
            scopes: vec![JsAssignmentScope::new(JsAssignmentScopeKind::Function)],
            commonjs_exported_roots,
            commonjs_exported_members,
            commonjs,
        }
    }

    fn enter_scope(&mut self, kind: JsAssignmentScopeKind) {
        self.scopes.push(JsAssignmentScope::new(kind));
    }

    fn exit_scope(&mut self) {
        brokk_bifrost_core::analyzer::usages::exit_nested_scope(&mut self.scopes);
    }

    fn declare_current(&mut self, name: &str, kind: JsAssignmentBindingKind) {
        if name.is_empty() {
            return;
        }
        if let Some(scope) = self.scopes.last_mut() {
            scope.bindings.insert(name.to_string(), kind);
        }
    }

    fn declare_function_scoped(&mut self, name: &str, kind: JsAssignmentBindingKind) {
        if name.is_empty() {
            return;
        }
        if let Some(scope) = self
            .scopes
            .iter_mut()
            .rev()
            .find(|scope| scope.kind == JsAssignmentScopeKind::Function)
        {
            scope.bindings.insert(name.to_string(), kind);
        }
    }

    fn binding_of(&self, name: &str) -> Option<JsAssignmentBindingKind> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bindings.get(name).copied())
    }

    fn binding_kind_for_declarator(
        &self,
        name: &str,
        declarator: Node<'_>,
    ) -> JsAssignmentBindingKind {
        if self.commonjs_exported_roots.contains(name) {
            JsAssignmentBindingKind::DeclarationRoot
        } else if declarator
            .child_by_field_name("value")
            .and_then(crate::syntax::js_ts_object_literal_value)
            .is_some()
        {
            JsAssignmentBindingKind::LocalObject
        } else {
            JsAssignmentBindingKind::PlainLocal
        }
    }
}

fn js_assignment_scope_kind(node: Node<'_>) -> Option<JsAssignmentScopeKind> {
    match node.kind() {
        "function_declaration"
        | "function_expression"
        | "generator_function"
        | "arrow_function"
        | "method_definition" => Some(JsAssignmentScopeKind::Function),
        "statement_block" => Some(JsAssignmentScopeKind::Block),
        _ => None,
    }
}

fn register_js_assignment_parameters(
    node: Node<'_>,
    source: &str,
    state: &mut JsAssignmentDeclarationState,
) {
    let mut names = Vec::new();
    if let Some(parameters) = node.child_by_field_name("parameters") {
        names.extend(crate::syntax::pattern_binder_identifiers(parameters));
    }
    if let Some(parameter) = node.child_by_field_name("parameter") {
        names.extend(crate::syntax::pattern_binder_identifiers(parameter));
    }
    for name in names {
        state.declare_current(
            node_text(name, source).trim(),
            JsAssignmentBindingKind::PlainLocal,
        );
    }
}

fn register_js_assignment_variable(
    node: Node<'_>,
    parent_kind: Option<&str>,
    source: &str,
    state: &mut JsAssignmentDeclarationState,
) {
    if node.kind() != "variable_declarator" {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    for name in crate::syntax::pattern_binder_identifiers(name_node) {
        let name = node_text(name, source).trim();
        let kind = state.binding_kind_for_declarator(name, node);
        if parent_kind == Some("variable_declaration") {
            state.declare_function_scoped(name, kind);
        } else {
            state.declare_current(name, kind);
        }
    }
}

fn visit_js_assignment_expression(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut JsTsParsedFile<'_>,
    state: &JsAssignmentDeclarationState,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let value = node.child_by_field_name("right");
    if state.commonjs.is_exports(left)
        && let Some(value) = value
        && let Some(object) = crate::syntax::js_ts_object_literal_value(value)
    {
        parsed.record_materialization(MaterializationRecord::Export {
            range: brokk_bifrost_core::analyzer::tree_walk::node_range(node),
            form: ExportForm::CommonJsRoot,
            exported_name: "module.exports".to_string(),
            target: None,
        });
        visit_js_module_exports_object_literal_properties(file, source, object, parsed);
        return;
    }
    let value_is_function =
        value.is_some_and(|value| matches!(value.kind(), "arrow_function" | "function_expression"));
    let Some(target) = js_commonjs_export_assignment_name(left, value, source, &state.commonjs)
        .map(|name| {
            let fq =
                FqName::new().with_pushed(segment_interner().intern(&name, SegmentKind::Member));
            JsMemberAssignmentTarget {
                name,
                fq,
                surface: JsAssignmentSymbolSurface::Declaration,
                owner: StructuralOwnerClaim::Root,
            }
        })
        .or_else(|| js_member_assignment_target(left, source, state, parsed))
    else {
        return;
    };
    let kind = if value_is_function {
        brokk_bifrost_core::analyzer::model::CodeUnitType::Function
    } else {
        brokk_bifrost_core::analyzer::model::CodeUnitType::Field
    };
    let short_name = target
        .fq
        .display_native(file.language(), segment_interner());
    let code_unit = CodeUnit::new_fq(file.clone(), kind, "", short_name, target.fq);
    add_js_assignment_code_unit(
        parsed,
        target.surface,
        target.owner,
        code_unit.clone(),
        node,
        source,
    );
    let (signature, parameter_text) = js_assignment_signature(node, left, value, source);
    if let Some(value) = value.filter(|_| value_is_function) {
        parsed.add_signature_with_metadata(
            code_unit.clone(),
            js_signature_metadata(signature, value, source, &parameter_text),
        );
        visit_js_return_object_literal_properties(
            file, source, value, &code_unit, &code_unit, parsed,
        );
    } else {
        parsed.add_signature(code_unit.clone(), signature);
    }
    if !value_is_function
        && let Some(value) = value
        && let Some(object) = js_indexable_object_literal_value(value, source, true)
    {
        visit_js_object_literal_properties_for_surface(
            file,
            source,
            object,
            &code_unit,
            &code_unit,
            parsed,
            target.surface,
        );
    }
}

fn add_js_assignment_code_unit(
    parsed: &mut JsTsParsedFile<'_>,
    surface: JsAssignmentSymbolSurface,
    owner: StructuralOwnerClaim,
    code_unit: CodeUnit,
    node: Node<'_>,
    source: &str,
) {
    match surface {
        JsAssignmentSymbolSurface::Declaration => {
            parsed.add_assignment_code_unit(code_unit, node, owner);
        }
        JsAssignmentSymbolSurface::DefinitionLookupOnly => {
            parsed.add_definition_lookup_unit(code_unit, node, source);
        }
    }
}

fn js_commonjs_export_assignment_name(
    left: Node<'_>,
    value: Option<Node<'_>>,
    source: &str,
    commonjs: &crate::commonjs::CommonJsObjects,
) -> Option<String> {
    let exposes_surface = value.is_some_and(|value| {
        matches!(value.kind(), "arrow_function" | "function_expression")
            || js_initializer_has_surface_shape(value, source)
            || !matches!(value.kind(), "identifier" | "member_expression")
    });
    if !exposes_surface {
        return None;
    }
    let property = js_commonjs_export_assignment_property(left, source, commonjs)?;
    (!property.is_empty()).then_some(property)
}

fn js_commonjs_export_assignment_property(
    node: Node<'_>,
    source: &str,
    commonjs: &crate::commonjs::CommonJsObjects,
) -> Option<String> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    if property.kind() == "computed_property_name" {
        return None;
    }
    let property_name = node_text(property, source)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();

    if commonjs.is_exports(object) {
        return Some(property_name);
    }

    None
}

fn js_member_assignment_target(
    node: Node<'_>,
    source: &str,
    state: &JsAssignmentDeclarationState,
    parsed: &JsTsParsedFile<'_>,
) -> Option<JsMemberAssignmentTarget> {
    if node.kind() != "member_expression"
        || js_is_commonjs_export_assignment_target(node, &state.commonjs)
    {
        return None;
    }
    // Reject dynamic/private segments through the shared structured chain.
    // Classify the indexed binding before source capture, including hoisted
    // roots and distinct environments sharing one syntactic owner (#5589).
    let receiver = crate::syntax::static_member_receiver(node, source)?;
    let root_name = node_text(receiver.root, source).trim();
    let binding_kind = js_receiver_binding_kind(receiver.root, root_name, state, parsed);
    let mut fq = if matches!(root_name, "exports" | "module")
        && parsed.binding_is_local(receiver.root, root_name)
        || binding_kind == Some(JsAssignmentBindingKind::LocalObject)
    {
        parsed
            .local_receiver_fq(receiver.root, root_name)
            .expect("local assignment receiver has an indexed binding scope")
    } else if binding_kind == Some(JsAssignmentBindingKind::DeclarationRoot) {
        parsed.declaration_receiver_fq(receiver.root, root_name)?
    } else {
        FqName::new().with_pushed(segment_interner().intern(root_name, SegmentKind::Member))
    };
    let mut name = root_name.to_string();
    for property in &receiver.members {
        let property_name = node_text(*property, source);
        name.push('.');
        name.push_str(property_name);
        fq.push(segment_interner().intern(property_name, SegmentKind::Member));
    }
    let has_export_spelling = root_name == "exports"
        || root_name == "module"
            && receiver
                .members
                .first()
                .is_some_and(|property| node_text(*property, source) == "exports");
    let surface = if state.commonjs_exported_members.contains(&name) || has_export_spelling {
        JsAssignmentSymbolSurface::Declaration
    } else if matches!(
        binding_kind,
        Some(JsAssignmentBindingKind::PlainLocal | JsAssignmentBindingKind::LocalObject)
    ) {
        JsAssignmentSymbolSurface::DefinitionLookupOnly
    } else {
        JsAssignmentSymbolSurface::Declaration
    };
    Some(JsMemberAssignmentTarget {
        name,
        fq,
        surface,
        owner: StructuralOwnerClaim::UnspecifiedMember,
    })
}

fn js_receiver_binding_kind(
    receiver: Node<'_>,
    name: &str,
    state: &JsAssignmentDeclarationState,
    parsed: &JsTsParsedFile<'_>,
) -> Option<JsAssignmentBindingKind> {
    use crate::syntax::JsTsReceiverDeclarationKind;
    match parsed.receiver_binding_kind(receiver, name, |target| {
        js_is_commonjs_export_assignment_target(target, &state.commonjs)
    }) {
        Some(JsTsReceiverDeclarationKind::DeclarationRoot) => {
            Some(JsAssignmentBindingKind::DeclarationRoot)
        }
        Some(JsTsReceiverDeclarationKind::LocalObject)
            if !state.commonjs_exported_roots.contains(name) =>
        {
            Some(JsAssignmentBindingKind::LocalObject)
        }
        Some(JsTsReceiverDeclarationKind::LocalObject) => {
            Some(JsAssignmentBindingKind::DeclarationRoot)
        }
        Some(JsTsReceiverDeclarationKind::PlainLocal)
            if state.commonjs_exported_roots.contains(name)
                && state.binding_of(name) == Some(JsAssignmentBindingKind::DeclarationRoot) =>
        {
            Some(JsAssignmentBindingKind::DeclarationRoot)
        }
        Some(
            JsTsReceiverDeclarationKind::PlainLocal | JsTsReceiverDeclarationKind::Unsupported,
        ) => Some(JsAssignmentBindingKind::PlainLocal),
        None => state.binding_of(name),
    }
}

fn js_commonjs_exported_roots(
    root: Node<'_>,
    source: &str,
    commonjs: &crate::commonjs::CommonJsObjects,
) -> HashSet<String> {
    let mut roots = HashSet::default();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && js_is_commonjs_export_assignment_target(left, commonjs)
            && let Some(right) = node.child_by_field_name("right")
            && let Some(root) = js_commonjs_exported_root_identifier(right, source)
        {
            roots.insert(root.to_string());
        }
        WalkControl::Continue
    });
    roots
}

fn js_commonjs_exported_members(
    root: Node<'_>,
    source: &str,
    commonjs: &crate::commonjs::CommonJsObjects,
) -> HashSet<String> {
    let mut members = HashSet::default();
    walk_named_tree_preorder(root, true, |node| {
        if node.kind() == "assignment_expression"
            && let Some(left) = node.child_by_field_name("left")
            && js_is_commonjs_export_assignment_target(left, commonjs)
            && let Some(right) = node.child_by_field_name("right")
            && let Some(member) = js_member_expression_name(right, source)
        {
            members.insert(member);
        }
        WalkControl::Continue
    });
    members
}

fn js_member_expression_name(node: Node<'_>, source: &str) -> Option<String> {
    let receiver = crate::syntax::static_member_receiver(node, source)?;
    let mut name = node_text(receiver.root, source).to_string();
    for member in receiver.members {
        name.push('.');
        name.push_str(node_text(member, source));
    }
    Some(name)
}

fn js_commonjs_exported_root_identifier<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if matches!(node.kind(), "identifier" | "property_identifier") {
        trimmed_identifier_text(node, source)
    } else {
        None
    }
}

fn js_is_commonjs_export_assignment_target(
    mut node: Node<'_>,
    commonjs: &crate::commonjs::CommonJsObjects,
) -> bool {
    loop {
        if commonjs.is_exports(node) {
            return true;
        }
        let Some(object) = node.child_by_field_name("object") else {
            return false;
        };
        node = object;
    }
}

fn js_assignment_signature(
    assignment: Node<'_>,
    left: Node<'_>,
    value: Option<Node<'_>>,
    source: &str,
) -> (String, String) {
    let left_text = trim_statement(node_text(left, source));
    let Some(value) = value else {
        return (trim_statement(node_text(assignment, source)), String::new());
    };
    if matches!(value.kind(), "arrow_function" | "function_expression") {
        let params = js_rendered_parameter_text(value, source);
        return (format!("{left_text} = function{params} ..."), params);
    }
    if is_simple_js_ts_initializer(value) {
        return (
            format!("{left_text} = {}", trim_statement(node_text(value, source))),
            String::new(),
        );
    }
    (format!("{left_text} = ..."), String::new())
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn js_class_signature(node: Node<'_>, source: &str, exported: bool) -> String {
    let definition = if node.kind() == "export_statement" {
        node.child_by_field_name("declaration").unwrap_or(node)
    } else {
        node
    };
    let mut signature = declaration_header(definition, source).trim().to_string();
    if exported {
        signature = format!("export {signature}");
    }
    format!("{} {{", one_line(&signature))
}

fn js_default_export_class_signature(export: Node<'_>, source: &str) -> String {
    let signature = declaration_header(export, source).trim();
    format!("{} {{", one_line(signature))
}

fn js_function_signature(
    node: Node<'_>,
    source: &str,
    name: &str,
    exported: bool,
) -> (String, String) {
    let mut prefix = if exported { "export " } else { "" }.to_string();
    let async_prefix = if is_async_callable(node) {
        "async "
    } else {
        ""
    };
    let params = js_rendered_parameter_text(node, source);
    prefix.push_str(async_prefix);
    let jsx_suffix = if exported && is_component_like_name(name) && node_returns_jsx(node, source) {
        ": JSX.Element"
    } else {
        ""
    };
    (
        with_mutation_comment(
            format!("{prefix}function {name}{params}{jsx_suffix} ..."),
            node,
            source,
        ),
        params,
    )
}

fn js_default_export_function_signature(function: Node<'_>, source: &str) -> (String, String) {
    let async_prefix = if is_async_callable(function) {
        "async "
    } else {
        ""
    };
    let params = js_rendered_parameter_text(function, source);
    let signature = match function.kind() {
        "function_declaration" | "function_expression" => {
            format!("export default {async_prefix}function{params} ...")
        }
        "generator_function" => format!("export default {async_prefix}function*{params} ..."),
        _ => format!("export default {async_prefix}{params} => ..."),
    };
    (with_mutation_comment(signature, function, source), params)
}

fn js_method_signature(node: Node<'_>, source: &str) -> (String, String) {
    let name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source).trim_matches('"').trim().to_string())
        .unwrap_or_else(|| "method".to_string());
    let params = js_rendered_parameter_text(node, source);
    let jsx_suffix = if name == "render" && node_returns_jsx(node, source) {
        ": JSX.Element"
    } else {
        ""
    };
    (format!("function {name}{params}{jsx_suffix} ..."), params)
}

fn js_variable_function_signature(
    _statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    name: &str,
    exported: bool,
) -> (String, String) {
    let value = declarator
        .child_by_field_name("value")
        .unwrap_or(declarator);
    let async_prefix = if is_async_callable(value) {
        "async "
    } else {
        ""
    };
    let params = js_rendered_parameter_text(value, source);
    let jsx_suffix = if exported && is_component_like_name(name) && node_returns_jsx(value, source)
    {
        ": JSX.Element"
    } else {
        ""
    };
    let export_prefix = if exported { "export " } else { "" };
    (
        with_mutation_comment(
            format!("{export_prefix}{async_prefix}{name}{params}{jsx_suffix} => ..."),
            value,
            source,
        ),
        params,
    )
}

fn js_variable_signature(
    statement: Node<'_>,
    declarator: Node<'_>,
    source: &str,
    exported: bool,
) -> String {
    let header = variable_header(statement, declarator, source, exported);
    match declarator.child_by_field_name("value") {
        Some(value) if is_simple_js_ts_initializer(value) => {
            let value_text = trim_statement(node_text(value, source));
            format!("{header} = {value_text}")
        }
        _ => header,
    }
}

fn with_mutation_comment(signature: String, node: Node<'_>, source: &str) -> String {
    let mutations = mutation_names(node, source);
    if mutations.is_empty() {
        signature
    } else {
        format!("// mutates: {}\n{signature}", mutations.join(", "))
    }
}

fn mutation_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    collect_mutation_names(node, source, &mut names);
    names.into_iter().collect()
}

fn collect_mutation_names(root: Node<'_>, source: &str, names: &mut BTreeSet<String>) {
    walk_named_tree_preorder(root, true, |node| {
        if node.id() != root.id()
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
            )
        {
            return WalkControl::SkipChildren;
        }

        match node.kind() {
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left")
                    && let Some(name) = mutation_target_name(left, source)
                {
                    names.insert(name);
                }
            }
            "update_expression" => {
                let target = node
                    .child_by_field_name("argument")
                    .or_else(|| node.named_child(0))
                    .or_else(|| node.named_child(1));
                if let Some(target) = target
                    && let Some(name) = mutation_target_name(target, source)
                {
                    names.insert(name);
                }
            }
            _ => {}
        }

        WalkControl::Continue
    });
}

fn mutation_target_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" | "private_property_identifier" => {
            Some(node_text(node, source).trim().to_string())
        }
        "member_expression" => node
            .child_by_field_name("property")
            .and_then(|property| mutation_target_name(property, source)),
        _ => None,
    }
}

pub fn extract_js_type_identifiers(source: &str) -> BTreeSet<String> {
    extract_js_ts_type_identifiers(source, tree_sitter_javascript::LANGUAGE.into())
}
fn node_returns_jsx(node: Node<'_>, _source: &str) -> bool {
    if expression_returns_jsx(node)
        || (node.kind() == "arrow_function"
            && node
                .child_by_field_name("body")
                .is_some_and(expression_returns_jsx))
    {
        return true;
    }
    function_returns_parameter_shape(
        node,
        node.id(),
        |kind| {
            crate::syntax::is_function_like(kind) || matches!(kind, "class_declaration" | "class")
        },
        expression_returns_jsx,
    )
}

fn expression_returns_jsx(expression: Node<'_>) -> bool {
    let mut pending = vec![expression];
    while let Some(current) = pending.pop() {
        if current.is_extra() {
            // The shared return walker supplies the first named child. A
            // comment before the return expression is trivia, not its value.
            pending.extend(current.next_named_sibling());
            continue;
        }
        match current.kind() {
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment" => return true,
            "parenthesized_expression" | "await_expression" => {
                let mut cursor = current.walk();
                pending.extend(
                    current
                        .named_children(&mut cursor)
                        .filter(|child| !child.is_extra()),
                );
            }
            "ternary_expression" => pending.extend(
                ["consequence", "alternative"]
                    .into_iter()
                    .filter_map(|field| current.child_by_field_name(field)),
            ),
            "binary_expression"
                if current
                    .child_by_field_name("operator")
                    .is_some_and(|operator| matches!(operator.kind(), "&&" | "||" | "??")) =>
            {
                pending.extend(
                    ["left", "right"]
                        .into_iter()
                        .filter_map(|field| current.child_by_field_name(field)),
                );
            }
            "sequence_expression" => {
                let mut cursor = current.walk();
                pending.extend(
                    current
                        .named_children(&mut cursor)
                        .filter(|child| !child.is_extra())
                        .last(),
                );
            }
            _ => {}
        }
    }
    false
}

fn is_component_like_name(name: &str) -> bool {
    name.chars()
        .next()
        .map(|ch| ch.is_ascii_uppercase())
        .unwrap_or(false)
}

#[cfg(test)]
mod callable_modifier_tests {
    use super::*;
    use crate::test_support::assert_callable_metadata_flags;
    use brokk_bifrost_test_macros::hardwon;

    /// #2597: every JavaScript callable this walk records carries modifier
    /// facts, because `receiver_contract_of` reports no contract at all for a
    /// callable whose adapter never inspected modifiers -- and without a
    /// contract no procedure summary can bind the declaration.
    ///
    /// The four shapes are the ones that decide differently: a free function
    /// and a `static` method bind nothing in receiver position, an instance
    /// method binds one, and a constructor is neither.
    #[test]
    #[hardwon("#2597: JS callable modifier metadata was absent, preventing summary binding")]
    fn callable_metadata_records_javascript_static_and_constructor_structurally() {
        let source = "export function free(value) { return value; }\n\nexport class Widget {\n    constructor(spec) { this.spec = spec; }\n    static build(spec) { return new Widget(spec); }\n    render(target) { return target; }\n}\n\nexport const arrow = (value) => value;\n";
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "widget.js",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript parser language");
        let tree = parser
            .parse(source, None)
            .expect("parse JavaScript fixture");
        let parsed = parse_javascript_file(&file, source, &tree);

        assert_callable_metadata_flags(&parsed, "free", true, false);
        assert_callable_metadata_flags(&parsed, "arrow", true, false);
        assert_callable_metadata_flags(&parsed, "build", true, false);
        assert_callable_metadata_flags(&parsed, "render", false, false);
        assert_callable_metadata_flags(&parsed, "constructor", false, true);
    }
}

#[cfg(test)]
mod private_field_assignment_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    /// #2593: `Receiver.#field = value` is a write, never a declaration. A
    /// private name is only legal inside a class body that already declares
    /// it, so the grammar has already indexed the field with its exact class
    /// owner (#1926). Minting a second parentless Field from the assignment
    /// gave two units that render identically but carry different FqName
    /// segment kinds, so no lookup or usage query could tell them apart.
    #[test]
    #[hardwon("#2630: a private-name write minted a duplicate declaration")]
    fn private_name_assignment_through_named_receiver_declares_nothing() {
        let source = "class CurrentPointers {\n  static #pointerType = null;\n  static #out = [];\n  static set(pointerType) {\n    CurrentPointers.#pointerType = pointerType;\n    CurrentPointers.#out.length = 0;\n  }\n}\n";
        let temp = tempfile::tempdir().expect("tempdir");
        let file = ProjectFile::new(
            temp.path().canonicalize().expect("canonical root"),
            "pointers.js",
        );
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript parser language");
        let tree = parser
            .parse(source, None)
            .expect("parse JavaScript fixture");
        let parsed = parse_javascript_file(&file, source, &tree);

        let named = |name: &str| {
            parsed
                .ranges
                .keys()
                .chain(parsed.definition_lookup_units.iter())
                .filter(|unit| unit.short_name() == name)
                .count()
        };

        assert_eq!(
            named("CurrentPointers.#pointerType"),
            1,
            "the class field is the only declaration of #pointerType; recorded {:?}",
            parsed
                .ranges
                .keys()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            named("CurrentPointers.#out.length"),
            0,
            "a chain rooted through a private segment declares nothing; recorded {:?}",
            parsed
                .ranges
                .keys()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod jsx_declaration_tests {
    use super::*;

    /// JavaScript declaration extraction understands the TSX field and
    /// parameter wrappers used by the JSX dialect.
    #[test]
    fn jsx_fields_and_parameter_labels_survive_tsx_parsing() {
        let source = "export class Panel {\n  label = \"panel\";\n  render(props) { return <div class=\"panel\" />; }\n}\n";
        let directory = tempfile::tempdir().expect("temporary root");
        let file = ProjectFile::new(directory.path().canonicalize().unwrap(), "panel.jsx");
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let parsed = parse_javascript_file(&file, source, &tree);
        assert!(
            parsed
                .ranges
                .keys()
                .any(|unit| unit.terminal_name() == "label"),
            "{parsed:#?}"
        );
        let render = parsed
            .signature_metadata
            .iter()
            .find(|(unit, _)| unit.terminal_name() == "render")
            .and_then(|(_, metadata)| metadata.first())
            .expect("render signature");
        assert_eq!(
            render
                .parameters()
                .iter()
                .map(|parameter| parameter.label())
                .collect::<Vec<_>>(),
            ["props"]
        );
    }
}

#[cfg(test)]
mod bundled_export_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#3864: distinct bundled exports.default declarations merged across factories")]
    fn bundled_export_owners_are_distinct_and_contain_members() {
        for (source, expected_owners) in [
            (include_str!("../fixtures/3864/bundle.js"), 2),
            (include_str!("../fixtures/3864/mixed-wrappers.js"), 3),
        ] {
            for (extension, tree) in [
                ("js", crate::test_support::parse_javascript(source)),
                ("ts", crate::test_support::parse_typescript(source)),
            ] {
                let directory = tempfile::tempdir().unwrap();
                let file = ProjectFile::new(
                    directory.path().canonicalize().unwrap(),
                    format!("bundle.{extension}"),
                );
                assert!(!tree.root_node().has_error());
                let parsed = if extension == "js" {
                    parse_javascript_file(&file, source, &tree)
                } else {
                    crate::typescript::parse_typescript_file(&file, source, &tree)
                };
                let defaults = parsed
                    .ranges
                    .iter()
                    .filter(|(unit, _)| unit.terminal_name() == "default")
                    .collect::<Vec<_>>();
                assert_eq!(
                    defaults.len(),
                    expected_owners,
                    "distinct factory defaults: {:#?}",
                    parsed.ranges
                );
                assert_eq!(
                    defaults
                        .iter()
                        .filter(|(owner, _)| owner.is_function())
                        .count(),
                    2
                );
                for (owner, ranges) in defaults {
                    assert_eq!(
                        ranges.len(),
                        1,
                        "distinct factory sites: {owner:?} {ranges:?}"
                    );
                    let members = parsed
                        .children
                        .get(owner)
                        .expect("default owns returned members");
                    assert_eq!(members.len(), 1, "{members:?}");
                    for member in members {
                        for child in &parsed.ranges[member] {
                            assert!(
                                ranges
                                    .iter()
                                    .any(|parent| parent.start_byte <= child.start_byte
                                        && child.end_byte <= parent.end_byte),
                                "I1: {owner:?} {ranges:?} must contain {member:?} {child:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod declaration_surface_tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: unrelated lexical factories publish fictitious members"
    )]
    fn factory_shape_respects_lexical_binding() {
        let mut failures = Vec::new();
        for source in [
            "function identity(x){return 0;} function unrelated(){function identity(x){return x;}} export const api=identity({ghost(){}});",
            "function identity(x){return x;} function scope(){function identity(x){return 0;} const api=identity({ghost(){}});}",
            "function identity(x){return x;} { const identity = 0; const api=identity({ghost(){}}); }",
        ] {
            let source_text = [source, " function preserve(control){return control;} export const control=preserve({present(){}});"].concat();
            let source = source_text.as_str();
            for (extension, tree) in [
                ("js", crate::test_support::parse_javascript(source)),
                ("ts", crate::test_support::parse_typescript(source)),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let file = ProjectFile::new(
                    dir.path().canonicalize().unwrap(),
                    format!("scope.{extension}"),
                );
                assert!(!tree.root_node().has_error());
                let parsed = if extension == "js" {
                    parse_javascript_file(&file, source, &tree)
                } else {
                    crate::typescript::parse_typescript_file(&file, source, &tree)
                };
                assert!(
                    parsed
                        .ranges
                        .keys()
                        .any(|unit| unit.terminal_name() == "present"),
                    "positive shape-admission control: {parsed:#?}"
                );
                if parsed
                    .ranges
                    .keys()
                    .chain(parsed.definition_lookup_units.iter())
                    .any(|unit| unit.terminal_name() == "ghost")
                {
                    failures.push(format!("{extension}: {source}"));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: signatures scanned strings and nested callables for syntax"
    )]
    fn javascript_signature_syntax_boundaries() {
        let mut failures = Vec::new();
        for (source, expected) in [
            (
                "export function Panel(){return '<div/>';}",
                "export function Panel() ...",
            ),
            (
                "export function Panel(){function inner(){return <div/>;} return 1;}",
                "export function Panel() ...",
            ),
            (
                "export function Panel(){return String(<div/>);}",
                "export function Panel() ...",
            ),
            (
                "export function Panel(){return `text${<div/>}`;}",
                "export function Panel() ...",
            ),
            (
                "export function Panel(){return flag ? <div/> : null;}",
                "export function Panel(): JSX.Element ...",
            ),
            (
                "export function normal(){return 'async ';}",
                "export function normal() ...",
            ),
            (
                "export async/*comment*/function normal(){}",
                "export async function normal() ...",
            ),
            (
                "export default async/*comment*/function(){}",
                "export default async function() ...",
            ),
            (
                "export const normal=async/*comment*/()=>0;",
                "export async normal() => ...",
            ),
            (
                "export default class extends (function(){return Base;})() {run(){}}",
                "export default class extends (function(){return Base;})() {",
            ),
        ] {
            let tree = crate::test_support::parse_javascript(source);
            assert!(!tree.root_node().has_error(), "{source}");
            let dir = tempfile::tempdir().unwrap();
            let file = ProjectFile::new(dir.path().canonicalize().unwrap(), "signature.js");
            let parsed = parse_javascript_file(&file, source, &tree);
            let signatures: Vec<_> = parsed
                .signatures
                .values()
                .flatten()
                .map(String::as_str)
                .collect();
            if !signatures.contains(&expected) {
                failures.push(format!(
                    "{source}: expected {expected:?}, got {signatures:?}"
                ));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    pub(crate) fn javascript_declaration_snapshot(source: &str) -> String {
        let tree = crate::test_support::parse_javascript(source);
        assert!(
            !tree.root_node().has_error(),
            "{source}: {}",
            tree.root_node().to_sexp()
        );
        let dir = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(dir.path().canonicalize().unwrap(), "surface.js");
        parsed_snapshot(parse_javascript_file(&file, source, &tree))
    }

    pub(crate) fn parsed_snapshot(parsed: ParsedFile) -> String {
        let mut rows = Vec::new();
        let mut units: Vec<_> = parsed
            .ranges
            .keys()
            .chain(parsed.definition_lookup_units.iter())
            .collect();
        units.sort();
        units.dedup();
        for unit in units {
            let lookup_only = parsed.definition_lookup_units.contains(unit);
            let signatures = parsed.signatures.get(unit).cloned().unwrap_or_default();
            let labels: Vec<_> = parsed
                .signature_metadata
                .get(unit)
                .into_iter()
                .flatten()
                .map(|metadata| {
                    (
                        metadata
                            .parameters()
                            .iter()
                            .map(|parameter| parameter.label())
                            .collect::<Vec<_>>(),
                        metadata.callable_is_static(),
                        metadata.callable_is_constructor(),
                    )
                })
                .collect();
            let supers = parsed.raw_supertypes.get(unit).cloned().unwrap_or_default();
            rows.push(format!("{:?} {:?} lookup={lookup_only} signatures={signatures:?} labels={labels:?} supers={supers:?}", unit.kind(), unit.fq_segments_debug()));
        }
        let facts = parsed
            .source_facts
            .as_ref()
            .unwrap()
            .js_ts
            .as_ref()
            .unwrap();
        for export in &facts.exports {
            rows.push(format!("export {:?} {:?}", export.name, export.kind));
        }
        for record in &parsed.materialization_records {
            if let MaterializationRecord::Export {
                form,
                exported_name,
                target,
                ..
            } = record
            {
                rows.push(format!(
                    "materialized {form:?} {exported_name:?} target={:?}",
                    target.as_ref().map(CodeUnit::fq_segments_debug)
                ));
            }
        }
        rows.sort();
        rows.join("\n") + "\n"
    }

    pub(crate) fn assert_surface_golden(
        name: &str,
        sources: &[&str],
        snapshot: fn(&str) -> String,
    ) {
        let mut actual = String::new();
        for source in sources {
            actual.push_str(&format!("SOURCE {source}\n{}", snapshot(source)));
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/declaration-surfaces")
            .join(format!("{name}.txt"));
        if std::env::var_os("BIFROST_BLESS").is_some() {
            std::fs::write(&path, &actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap();
        assert_eq!(expected, actual, "{name}");
    }

    #[test]
    fn js_declaration_surfaces() {
        assert_surface_golden(
            "js_declaration_surfaces",
            &[
                "export default class extends Base { constructor(){ function unrelated(){this.foreign=1;} this.own=1; } run(){} }",
                "export default class\t extends  makeBase(1)\n {run(){}}",
                "export default async function(value){return value;}",
                "export default class {run(){}}",
                "exports.run=function(input, options){return input;};",
            ],
            javascript_declaration_snapshot,
        );
    }

    #[test]
    fn js_factory_surfaces() {
        assert_surface_golden(
            "js_factory_surfaces",
            &[
                "export default function(){return {run(){}};}",
                "import {defineConfig} from 'library'; export const api=defineConfig({run(){}});",
                "const preserve=(x)=>x; export const api=preserve({run(){}});",
                "const preserve=(x)=>{return x;}; export const api=preserve({run(){}});",
                "function wrap(config,other){return config;} export const api=wrap({run(){}},0);",
                "function wrap(other,config){return config;} export const api=wrap(0,{run(){}});",
                "function wrap(config){const helper={m(){return config;}};return 0;} export const api=wrap({ghost(){}});",
                "function wrap(config){return another;} export const api=wrap({ghost(){}});",
                "function wrap(){return 0;} export const api=wrap(1,{ghost(){}});",
            ],
            javascript_declaration_snapshot,
        );
    }

    #[test]
    fn js_commonjs_assignment_scopes() {
        assert_surface_golden(
            "js_commonjs_assignment_scopes",
            &[
                "const impl={run(){}}; module.exports={run:impl.run};",
                "var api=load(); module.exports=api; api.run=function(){};",
                "const api=load(); module.exports=api; api.run=function(){};",
                "const api=load(); module.exports=api; function f(api){api.run=function(){};}",
                "if(flag){var api=load();} module.exports=api; api.run=function(){};",
                "function f(){const local={run(){}};} const top={run(){}};",
            ],
            javascript_declaration_snapshot,
        );
    }

    #[test]
    fn js_jsx_signatures() {
        assert_surface_golden(
            "js_jsx_signatures",
            &[
                "export function Upper(){return <div/>;} export function lower(){return <div/>;}",
                "export const Upper=()=> <div/>; export const lower=()=> <div/>;",
                "class Yes {render(){return <div/>;}} class No {render(){return 42;}}",
            ],
            javascript_declaration_snapshot,
        );
    }

    #[test]
    fn js_mutation_summaries() {
        assert_surface_golden(
            "js_mutation_summaries",
            &[
                "export function update(){z.last=1; a.first++; function nested(){ghost=1;}}",
                "class Counter {#value=0; update(){this.#value=1;}}",
            ],
            javascript_declaration_snapshot,
        );
    }

    #[test]
    fn js_callable_grammar() {
        assert_surface_golden(
            "js_callable_grammar",
            &[
                "export const identity=value=>value; export class Worker {async run(input){return input;} static runStatic(input){return input;} constructor(input){this.input=input;}}",
            ],
            javascript_declaration_snapshot,
        );
    }
    #[test]
    #[hardwon(
        "4ed755aac3c5: quicksilver round 7 on brokk-bifrost-js-ts: unparenthesized identity arrows lose returned members"
    )]
    fn unparenthesized_arrow_preserves_object_shape() {
        let source = "const preserve=x=>x; export const api=preserve({run(){}});";
        let snapshot = javascript_declaration_snapshot(source);
        assert!(snapshot.contains("\"Member\", \"run\""), "{snapshot}");
    }
}
