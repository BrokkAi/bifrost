//! The `ParsedFile`-building half of Go declaration collection.
//!
//! The Go *language* half -- package identity, import specs, signature and
//! structured-type shapes -- lives in [`brokk_bifrost_go::declarations`]. The
//! walk below stays here because it fills a
//! [`ParsedFile`](crate::analyzer::tree_sitter_analyzer::ParsedFile), which is
//! this crate's private indexing accumulator (it carries Scala export, C++
//! template and Ruby dispatch facts and exposes its ranges only through
//! `pub(crate)` builders). Lowering it is the fleet-phase workstream that must
//! precede moving this walk.

use crate::analyzer::fq_name::SegmentKind;
use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile, SignatureMetadata};
// Re-exported rather than plainly imported: the rest of analysis (artifact,
// semantic, hierarchy) still reaches these through `super::declarations::`.
pub(crate) use brokk_bifrost_go::declarations::{
    collect_go_import_infos, collect_go_import_infos_from_declaration, collect_go_type_identifiers,
    determine_go_package_name, extract_go_receiver_name, go_embedded_struct_field,
    go_embedded_type_identity, go_embedded_type_nodes, go_embedded_type_texts,
    go_field_inline_container_type, go_function_signature, go_import_spec_binding_name,
    go_interface_method_signature, go_node_text, go_package_fq, go_segment, go_signature_metadata,
    go_struct_field_suffix, go_structured_type_identity, go_type_signature, go_value_signature,
    sole_spec_declaration_node,
};
use brokk_bifrost_go::packages::{GO_MODULE_SCOPE_SEGMENT, canonical_go_package_name};

use tree_sitter::{Node, Tree};

pub(super) fn parse_go_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
    let declared_package = determine_go_package_name(tree.root_node(), source);
    let package_name = canonical_go_package_name(file, &declared_package);
    let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name);
    parsed.content_qualifier = declared_package;
    let root = tree.root_node();

    collect_go_type_identifiers(root, source, &mut parsed.type_identifiers);

    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        visit_go_top_level_node(file, source, child, &mut parsed);
    }

    parsed
}

fn visit_go_imports(
    node: Node<'_>,
    source: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut imports = Vec::new();
    collect_go_import_infos_from_declaration(node, source, &mut imports);
    for info in imports {
        parsed.import_statements.push(info.raw_snippet.clone());
        parsed.imports.push(info);
    }
}

fn visit_go_function(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: Option<&CodeUnit>,
    package_name: String,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }
    let short_name = parent
        .map(|parent| format!("{}.{}", parent.short_name(), name))
        .unwrap_or_else(|| name.to_string());
    // The leaf is a function/method: a Member segment appended either to the
    // receiver type's structured name (method) or to the package prefix
    // (top-level function).
    let fq = match parent {
        Some(parent) => parent.fq().clone(),
        None => go_package_fq(&package_name),
    }
    .with_pushed(go_segment(name, SegmentKind::Member));
    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| go_node_text(parameters, source).trim().to_string());
    let code_unit = CodeUnit::with_signature_and_fq(
        file.clone(),
        CodeUnitType::Function,
        package_name,
        short_name,
        signature,
        false,
        fq,
    );
    let top_level = parent.cloned().unwrap_or_else(|| code_unit.clone());
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        parent.cloned(),
        Some(top_level),
    );
    let (signature, parameter_text) = go_function_signature(node, source);
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        go_signature_metadata(signature, node, source, &parameter_text),
    );
    Some(code_unit)
}

fn visit_go_top_level_node(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let package_name = parsed.package_name.clone();
    match node.kind() {
        "import_declaration" => visit_go_imports(node, source, parsed),
        "function_declaration" => {
            visit_go_function(file, source, node, None, package_name, parsed);
        }
        "method_declaration" => visit_go_method(file, source, node, &package_name, parsed),
        "type_declaration" => visit_go_type_declaration(file, source, node, &package_name, parsed),
        "var_declaration" => {
            visit_go_value_declaration(file, source, node, &package_name, "var", parsed)
        }
        "const_declaration" => {
            visit_go_value_declaration(file, source, node, &package_name, "const", parsed)
        }
        "ERROR" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                visit_go_top_level_node(file, source, child, parsed);
            }
        }
        _ => {}
    }
}

fn visit_go_method(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(receiver) = node.child_by_field_name("receiver") else {
        return;
    };
    let Some(receiver_name) = extract_go_receiver_name(receiver, source) else {
        return;
    };
    let parent_fq =
        go_package_fq(package_name).with_pushed(go_segment(&receiver_name, SegmentKind::Type));
    let parent = CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        receiver_name,
        parent_fq,
    );
    let _ = visit_go_function(
        file,
        source,
        node,
        Some(&parent),
        package_name.to_string(),
        parsed,
    );
}

fn visit_go_type_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "type_spec" => {
                let _ = visit_go_type_spec(file, source, child, package_name, parsed);
            }
            "type_alias" => {
                let _ = visit_go_type_alias(file, source, child, package_name, parsed);
            }
            _ => {
                let mut nested_cursor = child.walk();
                for spec in child.named_children(&mut nested_cursor) {
                    match spec.kind() {
                        "type_spec" => {
                            let _ = visit_go_type_spec(file, source, spec, package_name, parsed);
                        }
                        "type_alias" => {
                            let _ = visit_go_type_alias(file, source, spec, package_name, parsed);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn visit_go_type_spec(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let type_node = node.child_by_field_name("type")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let fq = go_package_fq(package_name).with_pushed(go_segment(name, SegmentKind::Type));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        name.to_string(),
        fq,
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        None,
        Some(code_unit.clone()),
    );
    parsed.add_signature(code_unit.clone(), go_type_signature(node, source));
    parsed.add_raw_supertypes(code_unit.clone(), go_embedded_type_texts(type_node, source));
    for embedded in go_embedded_type_nodes(type_node) {
        let label = go_node_text(embedded, source).trim().to_string();
        let Some(identity) = go_embedded_type_identity(embedded, source) else {
            continue;
        };
        let metadata =
            SignatureMetadata::new(label, Vec::new()).with_return_type_identity(Some(identity));
        let entries = parsed
            .signature_metadata
            .entry(code_unit.clone())
            .or_default();
        if !entries.contains(&metadata) {
            entries.push(metadata);
        }
    }

    match type_node.kind() {
        "struct_type" => visit_go_struct_fields(
            file,
            source,
            type_node,
            &code_unit,
            package_name,
            parsed,
            true,
        ),
        "interface_type" => {
            visit_go_interface_methods(
                file,
                source,
                type_node,
                &code_unit,
                package_name,
                parsed,
                true,
            );
        }
        _ => {}
    }
    Some(code_unit)
}

fn visit_go_type_alias(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let name_node = node.child_by_field_name("name")?;
    let name = go_node_text(name_node, source).trim();
    if name.is_empty() {
        return None;
    }

    let fq = go_package_fq(package_name)
        .with_pushed(go_segment(GO_MODULE_SCOPE_SEGMENT, SegmentKind::Package))
        .with_pushed(go_segment(name, SegmentKind::Member));
    let code_unit = CodeUnit::new_fq(
        file.clone(),
        CodeUnitType::Field,
        package_name.to_string(),
        format!("{GO_MODULE_SCOPE_SEGMENT}.{name}"),
        fq,
    );
    let range_node = sole_spec_declaration_node(node, "type_alias", "type_declaration");
    parsed.add_code_unit(
        code_unit.clone(),
        range_node,
        source,
        None,
        Some(code_unit.clone()),
    );
    parsed.add_signature(
        code_unit.clone(),
        go_node_text(node, source).trim().to_string(),
    );
    parsed.mark_type_alias(code_unit.clone());
    Some(code_unit)
}

fn visit_go_struct_fields(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    record_ranges: bool,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "field_declaration_list" {
            continue;
        }
        let mut field_cursor = child.walk();
        for field in child.named_children(&mut field_cursor) {
            if field.kind() != "field_declaration" {
                continue;
            }
            let suffix = go_struct_field_suffix(field, source);
            let field_names: Vec<_> = {
                let mut name_cursor = field.walk();
                field
                    .named_children(&mut name_cursor)
                    .filter(|name| name.kind() == "field_identifier")
                    .collect()
            };
            if field_names.is_empty() {
                if let Some((field_name, type_node)) = go_embedded_struct_field(field, source) {
                    let fq = parent
                        .fq()
                        .clone()
                        .with_pushed(go_segment(&field_name, SegmentKind::Member));
                    let code_unit = CodeUnit::new_fq(
                        file.clone(),
                        CodeUnitType::Field,
                        package_name.to_string(),
                        format!("{}.{}", parent.short_name(), field_name),
                        fq,
                    );
                    if record_ranges {
                        parsed.add_code_unit(
                            code_unit.clone(),
                            type_node,
                            source,
                            Some(parent.clone()),
                            Some(parent.clone()),
                        );
                    } else {
                        parsed.add_synthetic_code_unit(
                            code_unit.clone(),
                            Some(parent.clone()),
                            Some(parent.clone()),
                        );
                    }
                    let type_text = go_node_text(type_node, source).trim().to_string();
                    parsed.add_signature_with_metadata(
                        code_unit,
                        SignatureMetadata::new(type_text.clone(), Vec::new())
                            .with_return_type_text(Some(type_text))
                            .with_return_type_identity(go_embedded_type_identity(
                                type_node, source,
                            )),
                    );
                }
                continue;
            }
            for (index, name) in field_names.into_iter().enumerate() {
                let field_name = go_node_text(name, source).trim();
                if field_name.is_empty() {
                    continue;
                }
                let fq = parent
                    .fq()
                    .clone()
                    .with_pushed(go_segment(field_name, SegmentKind::Member));
                let code_unit = CodeUnit::new_fq(
                    file.clone(),
                    CodeUnitType::Field,
                    package_name.to_string(),
                    format!("{}.{}", parent.short_name(), field_name),
                    fq,
                );
                if record_ranges {
                    parsed.add_code_unit(
                        code_unit.clone(),
                        name,
                        source,
                        Some(parent.clone()),
                        Some(parent.clone()),
                    );
                } else {
                    parsed.add_synthetic_code_unit(
                        code_unit.clone(),
                        Some(parent.clone()),
                        Some(parent.clone()),
                    );
                }
                let type_node = field.child_by_field_name("type");
                let type_text = type_node
                    .map(|type_node| go_node_text(type_node, source).trim().to_string())
                    .filter(|type_text| !type_text.is_empty());
                parsed.add_signature_with_metadata(
                    code_unit,
                    SignatureMetadata::new(format!("{field_name}{suffix}"), Vec::new())
                        .with_return_type_text(type_text)
                        .with_return_type_identity(
                            type_node.and_then(|node| go_structured_type_identity(node, source)),
                        ),
                );
                if let Some(nested_type) = go_field_inline_container_type(field) {
                    let nested_has_source_range = record_ranges && index == 0;
                    match nested_type.kind() {
                        "struct_type" => visit_go_struct_fields(
                            file,
                            source,
                            nested_type,
                            &CodeUnit::new_fq(
                                file.clone(),
                                CodeUnitType::Field,
                                package_name.to_string(),
                                format!("{}.{}", parent.short_name(), field_name),
                                parent
                                    .fq()
                                    .clone()
                                    .with_pushed(go_segment(field_name, SegmentKind::Member)),
                            ),
                            package_name,
                            parsed,
                            nested_has_source_range,
                        ),
                        "interface_type" => visit_go_interface_methods(
                            file,
                            source,
                            nested_type,
                            &CodeUnit::new_fq(
                                file.clone(),
                                CodeUnitType::Field,
                                package_name.to_string(),
                                format!("{}.{}", parent.short_name(), field_name),
                                parent
                                    .fq()
                                    .clone()
                                    .with_pushed(go_segment(field_name, SegmentKind::Member)),
                            ),
                            package_name,
                            parsed,
                            nested_has_source_range,
                        ),
                        _ => {}
                    }
                }
            }
        }
    }
}

fn visit_go_interface_methods(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    parent: &CodeUnit,
    package_name: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
    record_ranges: bool,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "method_elem" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = go_node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }
        let signature = child
            .child_by_field_name("parameters")
            .map(|parameters| go_node_text(parameters, source).trim().to_string());
        let fq = parent
            .fq()
            .clone()
            .with_pushed(go_segment(name, SegmentKind::Member));
        let code_unit = CodeUnit::with_signature_and_fq(
            file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
            signature,
            false,
            fq,
        );
        if record_ranges {
            parsed.add_code_unit(
                code_unit.clone(),
                child,
                source,
                Some(parent.clone()),
                Some(parent.clone()),
            );
        } else {
            parsed.add_synthetic_code_unit(
                code_unit.clone(),
                Some(parent.clone()),
                Some(parent.clone()),
            );
        }
        let (signature, parameter_text) = go_interface_method_signature(child, source);
        parsed.add_signature_with_metadata(
            code_unit,
            go_signature_metadata(signature, child, source, &parameter_text),
        );
    }
}

fn visit_go_value_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    keyword: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let spec_kind = if keyword == "const" {
        "const_spec"
    } else {
        "var_spec"
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == spec_kind {
            visit_go_value_spec(file, source, child, package_name, keyword, parsed);
            continue;
        }
        let mut nested_cursor = child.walk();
        for spec in child.named_children(&mut nested_cursor) {
            if spec.kind() == spec_kind {
                visit_go_value_spec(file, source, spec, package_name, keyword, parsed);
            }
        }
    }
}

fn visit_go_value_spec(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    keyword: &str,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let identifier_count = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .count()
    };
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "identifier" {
            continue;
        }
        let name = go_node_text(child, source).trim();
        if name.is_empty() {
            continue;
        }
        let fq = go_package_fq(package_name)
            .with_pushed(go_segment(GO_MODULE_SCOPE_SEGMENT, SegmentKind::Package))
            .with_pushed(go_segment(name, SegmentKind::Member));
        let code_unit = CodeUnit::new_fq(
            file.clone(),
            CodeUnitType::Field,
            package_name.to_string(),
            format!("{GO_MODULE_SCOPE_SEGMENT}.{name}"),
            fq,
        );
        let declaration_kind = format!("{keyword}_declaration");
        let range_node = sole_spec_declaration_node(node, node.kind(), &declaration_kind);
        parsed.add_code_unit(
            code_unit.clone(),
            range_node,
            source,
            None,
            Some(code_unit.clone()),
        );
        parsed.add_signature(
            code_unit,
            go_value_signature(node, source, keyword, name, identifier_count),
        );
    }
}
