use crate::analyzer::model::StructuredTypeIdentityBuilder;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use crate::analyzer::{
    CodeUnit, CodeUnitType, DispatchExtensibility, GO_MODULE_SCOPE_SEGMENT, ImportInfo,
    ParameterMetadata, ProjectFile, SignatureMetadata, StructuredImportPath,
    StructuredImportPathKind, StructuredTypeIdentity, StructuredTypeName,
};
use crate::hash::HashSet;
use tree_sitter::{Node, Tree};

pub(super) fn parse_go_file(
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
    let declared_package = determine_go_package_name(tree.root_node(), source);
    let package_name = super::packages::canonical_go_package_name(file, &declared_package);
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

pub(super) fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text(node, source)
}

pub(crate) fn determine_go_package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "package_clause" {
            continue;
        }
        let mut package_cursor = child.walk();
        for package_child in child.named_children(&mut package_cursor) {
            if package_child.kind() == "package_identifier" || package_child.kind() == "identifier"
            {
                return go_node_text(package_child, source).trim().to_string();
            }
        }
    }
    String::new()
}

/// Collect every import declaration from a Go source tree.
///
/// Both the persisted analyzer and whole-workspace usage graph need the same
/// structured import facts. Keeping the AST extraction here prevents the graph
/// index from having to reconstruct import aliases from source text later.
pub(crate) fn collect_go_import_infos(root: Node<'_>, source: &str) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == "import_declaration" {
            collect_go_import_infos_from_declaration(child, source, &mut imports);
        }
    }
    imports
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

fn collect_go_import_infos_from_declaration(
    node: Node<'_>,
    source: &str,
    imports: &mut Vec<ImportInfo>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "import_spec" {
            if let Some(info) = parse_go_import_spec(child, source) {
                imports.push(info);
            }
            continue;
        }

        let mut nested_cursor = child.walk();
        for spec in child.named_children(&mut nested_cursor) {
            if spec.kind() == "import_spec"
                && let Some(info) = parse_go_import_spec(spec, source)
            {
                imports.push(info);
            }
        }
    }
}

fn go_import_spec_parts<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<(&'source str, Option<&'source str>)> {
    let path_node = node.child_by_field_name("path").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind().contains("string"))
    })?;
    let raw_path = go_node_text(path_node, source).trim();
    let path = raw_path
        .trim_matches('"')
        .trim_matches('`')
        .trim_matches('\'');
    if path.is_empty() {
        return None;
    }

    let alias = node
        .child_by_field_name("name")
        .map(|alias| go_node_text(alias, source).trim());
    Some((path, alias))
}

pub(crate) fn go_import_spec_binding_name<'source>(
    node: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    let (path, alias) = go_import_spec_parts(node, source)?;
    Some(alias.unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path)))
}

fn parse_go_import_spec(node: Node<'_>, source: &str) -> Option<ImportInfo> {
    let (path, alias) = go_import_spec_parts(node, source)?;
    let identifier = Some(
        alias
            .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path))
            .to_string(),
    );
    let path = path.to_string();
    let alias = alias.map(str::to_string);
    let raw_snippet = match alias.as_deref() {
        Some(alias) => format!("import {alias} \"{path}\""),
        None => format!("import \"{path}\""),
    };

    Some(ImportInfo {
        raw_snippet,
        is_wildcard: false,
        identifier,
        alias,
        path: Some(StructuredImportPath {
            segments: vec![path],
            kind: Some(StructuredImportPathKind::Namespace),
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: node.start_byte(),
        }),
    })
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
    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| go_node_text(parameters, source).trim().to_string());
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        CodeUnitType::Function,
        package_name,
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
    let parent = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        receiver_name,
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

    let code_unit = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        package_name.to_string(),
        name.to_string(),
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

    let code_unit = CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        package_name.to_string(),
        format!("{GO_MODULE_SCOPE_SEGMENT}.{name}"),
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
                    let code_unit = CodeUnit::new(
                        file.clone(),
                        CodeUnitType::Field,
                        package_name.to_string(),
                        format!("{}.{}", parent.short_name(), field_name),
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
                let code_unit = CodeUnit::new(
                    file.clone(),
                    CodeUnitType::Field,
                    package_name.to_string(),
                    format!("{}.{}", parent.short_name(), field_name),
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
                            &CodeUnit::new(
                                file.clone(),
                                CodeUnitType::Field,
                                package_name.to_string(),
                                format!("{}.{}", parent.short_name(), field_name),
                            ),
                            package_name,
                            parsed,
                            nested_has_source_range,
                        ),
                        "interface_type" => visit_go_interface_methods(
                            file,
                            source,
                            nested_type,
                            &CodeUnit::new(
                                file.clone(),
                                CodeUnitType::Field,
                                package_name.to_string(),
                                format!("{}.{}", parent.short_name(), field_name),
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

fn go_embedded_struct_field<'tree>(
    field: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    let mut cursor = field.walk();
    for child in field.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "raw_string_literal" | "interpreted_string_literal"
        ) {
            continue;
        }
        if let Some(name) = extract_go_type_name(child, source) {
            return Some((name, child));
        }
    }
    None
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
        let code_unit = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
            signature,
            false,
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
        let code_unit = CodeUnit::new(
            file.clone(),
            CodeUnitType::Field,
            package_name.to_string(),
            format!("{GO_MODULE_SCOPE_SEGMENT}.{name}"),
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

fn sole_spec_declaration_node<'tree>(
    spec: Node<'tree>,
    spec_kind: &str,
    declaration_kind: &str,
) -> Node<'tree> {
    let Some(parent) = spec.parent() else {
        return spec;
    };
    if parent.kind() != declaration_kind {
        return spec;
    }

    let mut cursor = parent.walk();
    let spec_count = parent
        .named_children(&mut cursor)
        .filter(|child| child.kind() == spec_kind)
        .take(2)
        .count();
    if spec_count == 1 { parent } else { spec }
}

fn go_type_signature(node: Node<'_>, source: &str) -> String {
    let raw = go_node_text(node, source).trim();
    if raw.contains('{') {
        format!("{} {{", raw.split('{').next().unwrap_or(raw).trim())
    } else {
        raw.to_string()
    }
}

fn go_function_signature(node: Node<'_>, source: &str) -> (String, String) {
    let raw = go_node_text(node, source).trim();
    let header = raw.split('{').next().unwrap_or(raw).trim();
    let parameter_text = go_rendered_parameter_text(node, source);
    if node.kind() == "method_declaration" || node.kind() == "function_declaration" {
        (format!("{header} {{ ... }}"), parameter_text)
    } else {
        (header.to_string(), parameter_text)
    }
}

fn go_interface_method_signature(node: Node<'_>, source: &str) -> (String, String) {
    (
        go_node_text(node, source).trim().to_string(),
        go_rendered_parameter_text(node, source),
    )
}

fn go_rendered_parameter_text(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("parameters")
        .map(|parameters| go_node_text(parameters, source).trim().to_string())
        .unwrap_or_else(|| "()".to_string())
}

fn go_signature_metadata(
    signature: String,
    node: Node<'_>,
    source: &str,
    parameter_text: &str,
) -> SignatureMetadata {
    let enrich = |metadata: SignatureMetadata| {
        let return_type = node
            .child_by_field_name("result")
            .filter(|result| result.kind() != "parameter_list");
        let receiver_type = go_method_receiver_type_node(node);
        metadata
            .with_return_type_text(go_callable_return_type_text(node, source))
            .with_return_type_identity(
                return_type.and_then(|result| go_structured_type_identity(result, source)),
            )
            .with_extension_receiver_type_identity(
                receiver_type.and_then(|receiver| go_structured_type_identity(receiver, source)),
            )
            .with_dispatch_extensibility(if node.kind() == "method_elem" {
                DispatchExtensibility::Open
            } else {
                DispatchExtensibility::Closed
            })
    };
    let Some(parameters_node) = node.child_by_field_name("parameters") else {
        return enrich(SignatureMetadata::new(signature, Vec::new()));
    };
    let raw = go_node_text(node, source);
    let leading_trim_bytes = raw.len().saturating_sub(raw.trim_start().len());
    let parameters_start = parameters_node
        .start_byte()
        .saturating_sub(node.start_byte())
        .saturating_sub(leading_trim_bytes);
    let parameters_end = parameters_start + parameter_text.len();
    if signature.get(parameters_start..parameters_end) != Some(parameter_text) {
        return enrich(SignatureMetadata::new(signature, Vec::new()));
    }
    let mut search_start = parameters_start;
    let parameters = go_parameter_label_nodes(node)
        .into_iter()
        .filter_map(|label_node| {
            let label = go_node_text(label_node, source).trim();
            if label.is_empty() || search_start > parameters_end {
                return None;
            }
            let haystack = signature.get(search_start..parameters_end)?;
            let relative_start = haystack.find(label)?;
            let start_byte = search_start + relative_start;
            let end_byte = start_byte + label.len();
            search_start = end_byte;
            Some(ParameterMetadata::new(label, start_byte, end_byte))
        })
        .collect();
    enrich(SignatureMetadata::new(signature, parameters))
}

fn go_method_receiver_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let receiver = node.child_by_field_name("receiver")?;
    let mut cursor = receiver.walk();
    let mut parameters = receiver
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "parameter_declaration");
    let parameter = parameters.next()?;
    if parameters.next().is_some() {
        return None;
    }
    parameter.child_by_field_name("type")
}

fn go_callable_return_type_text(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("result")
        .filter(|result| result.kind() != "parameter_list")
        .map(|result| go_node_text(result, source).trim().to_string())
        .filter(|result| !result.is_empty())
}

enum GoStructuredTypeFrame<'tree> {
    Visit(Node<'tree>),
    Pointer,
    Array,
    Slice,
    Map,
    Generic { argument_count: usize },
}

/// Preserve the parser-proven shape of a Go type without asking bounded
/// consumers to reconstruct it from the rendered declaration signature.
///
/// This is deliberately iterative: source can contain arbitrarily nested
/// pointer, container and generic wrappers, and indexing such a file must not
/// consume the Rust call stack.
pub(crate) fn go_structured_type_identity(
    node: Node<'_>,
    source: &str,
) -> Option<StructuredTypeIdentity> {
    go_structured_type_identity_with(node, source, || true)
}

pub(crate) fn go_structured_type_identity_bounded(
    node: Node<'_>,
    source: &str,
    visit: impl FnMut() -> bool,
) -> Option<StructuredTypeIdentity> {
    go_structured_type_identity_with(node, source, visit)
}

fn go_structured_type_identity_with(
    node: Node<'_>,
    source: &str,
    mut visit: impl FnMut() -> bool,
) -> Option<StructuredTypeIdentity> {
    let mut frames = vec![GoStructuredTypeFrame::Visit(node)];
    let mut values = Vec::new();
    let mut builder = StructuredTypeIdentityBuilder::default();

    while let Some(frame) = frames.pop() {
        match frame {
            GoStructuredTypeFrame::Visit(node) => {
                if !visit() {
                    return None;
                }
                match node.kind() {
                    "type_identifier" | "identifier" => {
                        let name = go_node_text(node, source).trim();
                        values.push(builder.named(StructuredTypeName::new(
                            vec![name.to_string()],
                            Vec::new(),
                            false,
                        )?)?);
                    }
                    "qualified_type" => {
                        let package = node.child_by_field_name("package")?;
                        let name = node.child_by_field_name("name")?;
                        let package = go_node_text(package, source).trim();
                        let name = go_node_text(name, source).trim();
                        values.push(builder.named(StructuredTypeName::new(
                            vec![package.to_string(), name.to_string()],
                            Vec::new(),
                            false,
                        )?)?);
                    }
                    "pointer_type" => {
                        frames.push(GoStructuredTypeFrame::Pointer);
                        frames.push(GoStructuredTypeFrame::Visit(go_type_wrapper_child(node)?));
                    }
                    "array_type" | "implicit_length_array_type" => {
                        frames.push(GoStructuredTypeFrame::Array);
                        frames.push(GoStructuredTypeFrame::Visit(
                            node.child_by_field_name("element")
                                .or_else(|| go_last_named_type_child(node))?,
                        ));
                    }
                    "slice_type" => {
                        frames.push(GoStructuredTypeFrame::Slice);
                        frames.push(GoStructuredTypeFrame::Visit(
                            node.child_by_field_name("element")
                                .or_else(|| go_last_named_type_child(node))?,
                        ));
                    }
                    "map_type" => {
                        let key = node.child_by_field_name("key")?;
                        let value = node.child_by_field_name("value")?;
                        frames.push(GoStructuredTypeFrame::Map);
                        frames.push(GoStructuredTypeFrame::Visit(value));
                        frames.push(GoStructuredTypeFrame::Visit(key));
                    }
                    "generic_type" => {
                        let base = node
                            .child_by_field_name("type")
                            .or_else(|| node.child_by_field_name("name"))
                            .or_else(|| node.named_child(0))?;
                        let arguments =
                            node.child_by_field_name("type_arguments").or_else(|| {
                                let mut cursor = node.walk();
                                node.named_children(&mut cursor)
                                    .find(|child| child.kind() == "type_arguments")
                            })?;
                        let mut argument_nodes = Vec::new();
                        let mut cursor = arguments.walk();
                        for argument in arguments.named_children(&mut cursor) {
                            argument_nodes.push(argument);
                        }
                        frames.push(GoStructuredTypeFrame::Generic {
                            argument_count: argument_nodes.len(),
                        });
                        for argument in argument_nodes.into_iter().rev() {
                            frames.push(GoStructuredTypeFrame::Visit(argument));
                        }
                        frames.push(GoStructuredTypeFrame::Visit(base));
                    }
                    "parenthesized_type" | "negated_type" => {
                        frames.push(GoStructuredTypeFrame::Visit(go_type_wrapper_child(node)?));
                    }
                    "type_elem" => {
                        let mut cursor = node.walk();
                        let mut children = node.named_children(&mut cursor);
                        let child = children.next()?;
                        if children.next().is_some() {
                            return None;
                        }
                        frames.push(GoStructuredTypeFrame::Visit(child));
                    }
                    _ => return None,
                }
            }
            GoStructuredTypeFrame::Pointer => {
                let inner = values.pop()?;
                values.push(builder.pointer(inner)?);
            }
            GoStructuredTypeFrame::Array => {
                let inner = values.pop()?;
                values.push(builder.array(inner)?);
            }
            GoStructuredTypeFrame::Slice => {
                let inner = values.pop()?;
                values.push(builder.slice(inner)?);
            }
            GoStructuredTypeFrame::Map => {
                let value = values.pop()?;
                let key = values.pop()?;
                values.push(builder.map(key, value)?);
            }
            GoStructuredTypeFrame::Generic { argument_count } => {
                if values.len() < argument_count + 1 {
                    return None;
                }
                let arguments = values.split_off(values.len() - argument_count);
                let base = values.pop()?;
                values.push(builder.generic(base, arguments)?);
            }
        }
    }

    (values.len() == 1)
        .then(|| values.pop())
        .flatten()
        .and_then(|root| builder.finish(root))
}

fn go_type_wrapper_child(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("type").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).next()
    })
}

fn go_last_named_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn go_embedded_type_texts(node: Node<'_>, source: &str) -> Vec<String> {
    let mut embedded = go_embedded_type_nodes(node)
        .into_iter()
        .map(|candidate| go_node_text(candidate, source).trim().to_string())
        .filter(|candidate| !candidate.is_empty())
        .collect::<Vec<_>>();
    embedded.sort();
    embedded.dedup();
    embedded
}

fn go_embedded_type_identity(type_node: Node<'_>, source: &str) -> Option<StructuredTypeIdentity> {
    let mut identity = go_structured_type_identity(type_node, source)?;
    let Some(field) = type_node
        .parent()
        .filter(|parent| parent.kind() == "field_declaration")
    else {
        return Some(identity);
    };
    let pointer = (0..field.child_count()).any(|index| {
        field
            .child(index)
            .is_some_and(|child| !child.is_named() && child.kind() == "*")
    });
    if pointer {
        identity = identity.wrap_pointer()?;
    }
    Some(identity)
}

fn go_embedded_type_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    match node.kind() {
        "struct_type" => {
            let Some(fields) = named_children_of_kind(node, "field_declaration_list")
                .into_iter()
                .next()
            else {
                return Vec::new();
            };
            named_children_of_kind(fields, "field_declaration")
                .into_iter()
                .filter(|field| children_by_field(*field, "name").is_empty())
                .filter_map(|field| field.child_by_field_name("type"))
                .collect()
        }
        "interface_type" => named_children_of_kind(node, "type_elem")
            .into_iter()
            .filter_map(|element| {
                let children = named_children(element);
                let [embedded] = children.as_slice() else {
                    return None;
                };
                matches!(embedded.kind(), "type_identifier" | "qualified_type").then_some(*embedded)
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn named_children_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == kind)
        .collect()
}

fn children_by_field<'tree>(node: Node<'tree>, field: &str) -> Vec<Node<'tree>> {
    let mut cursor = node.walk();
    node.children_by_field_name(field, &mut cursor).collect()
}

fn go_parameter_label_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        match parameter.kind() {
            "parameter_declaration" | "variadic_parameter_declaration" => {
                let mut names = Vec::new();
                let mut children = parameter.walk();
                for child in parameter.named_children(&mut children) {
                    if child.kind() == "identifier" {
                        names.push(child);
                    }
                }
                if names.is_empty() && parameter.kind() == "variadic_parameter_declaration" {
                    labels.push(parameter);
                } else if names.is_empty() {
                    labels.push(
                        parameter
                            .child_by_field_name("type")
                            .or_else(|| {
                                parameter
                                    .named_child(parameter.named_child_count().saturating_sub(1))
                            })
                            .unwrap_or(parameter),
                    );
                } else {
                    labels.extend(names);
                }
            }
            _ => {}
        }
    }
    labels
}

fn go_value_signature(
    node: Node<'_>,
    source: &str,
    keyword: &str,
    name: &str,
    identifier_count: usize,
) -> String {
    let raw = go_node_text(node, source).trim();
    let after_keyword = raw.strip_prefix(keyword).map(str::trim).unwrap_or(raw);
    if identifier_count > 1 && after_keyword.contains('=') {
        return name.to_string();
    }

    let remainder = after_keyword
        .strip_prefix(name)
        .map(str::trim)
        .unwrap_or(after_keyword);
    let (type_part, value_part) = remainder
        .split_once('=')
        .map(|(left, right)| (left.trim(), Some(right.trim())))
        .unwrap_or((remainder.trim(), None));

    let mut signature = name.to_string();
    if !type_part.is_empty() {
        signature.push(' ');
        signature.push_str(type_part);
    }

    if let Some(value) = value_part
        && go_value_is_simple_literal(value)
    {
        signature.push_str(" = ");
        signature.push_str(value);
    }

    signature
}

fn extract_go_receiver_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "parameter_declaration" => {
                let type_node = child.child_by_field_name("type").unwrap_or(child);
                if let Some(name) = extract_go_type_name(type_node, source) {
                    return Some(name);
                }
            }
            _ => {
                if let Some(name) = extract_go_type_name(child, source) {
                    return Some(name);
                }
            }
        }
    }
    None
}

fn extract_go_type_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" | "identifier" => {
            let text = go_node_text(node, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        "pointer_type" | "slice_type" | "array_type" | "generic_type" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_go_type_name(child, source))
        }
        "qualified_type" => node
            .child_by_field_name("name")
            .or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor).last()
            })
            .and_then(|child| extract_go_type_name(child, source)),
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find_map(|child| extract_go_type_name(child, source))
        }
    }
}

fn collect_go_type_identifiers(node: Node<'_>, source: &str, identifiers: &mut HashSet<String>) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" | "package_identifier" => {
                let text = go_node_text(node, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}

fn go_struct_field_suffix(node: Node<'_>, source: &str) -> String {
    let mut cursor = node.walk();
    let mut type_start = None;
    for child in node.named_children(&mut cursor) {
        if child.kind() == "field_identifier" {
            continue;
        }
        type_start = Some(child.start_byte());
        break;
    }
    type_start
        .and_then(|start| source.get(start..node.end_byte()))
        .map(|suffix| format!(" {}", suffix.trim()))
        .unwrap_or_default()
}

fn go_field_inline_container_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "struct_type" | "interface_type"))
}

fn go_value_is_simple_literal(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed == "iota"
        || trimmed == "true"
        || trimmed == "false"
        || trimmed == "nil"
        || trimmed.parse::<i128>().is_ok()
        || trimmed.parse::<f64>().is_ok()
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
}
