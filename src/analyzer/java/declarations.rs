use super::*;
use crate::analyzer::SignatureMetadata;
use crate::analyzer::tree_sitter_analyzer::{WalkControl, walk_named_tree_preorder};
use tree_sitter::{Node, Parser, Tree};

pub(super) fn determine_package_name(root: Node<'_>, source: &str) -> String {
    for index in 0..root.named_child_count() {
        let Some(child) = root.named_child(index) else {
            continue;
        };

        if child.kind() == "package_declaration" {
            return node_text(child, source)
                .trim()
                .strip_prefix("package ")
                .unwrap_or("")
                .strip_suffix(';')
                .unwrap_or("")
                .trim()
                .to_string();
        }

        if is_class_like_declaration_kind(child.kind()) {
            break;
        }
    }

    String::new()
}

fn strip_generic_type_arguments(input: &str) -> String {
    let mut depth = 0usize;
    let mut out = String::with_capacity(input.len());

    for ch in input.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }

    out
}

pub(super) fn normalize_java_full_name(fq_name: &str) -> String {
    let mut normalized = strip_generic_type_arguments(fq_name);

    if normalized.contains("$anon$") {
        let mut out = String::with_capacity(normalized.len());
        let mut chars = normalized.char_indices();

        while let Some((index, ch)) = chars.next() {
            if normalized[index..].starts_with("$anon$") {
                out.push_str("$anon$");
                for _ in 0.."anon$".len() {
                    chars.next();
                }
                continue;
            }

            out.push(if ch == '$' { '.' } else { ch });
        }

        return out;
    }

    normalized = strip_trailing_numeric_suffix(&normalized);
    normalized = strip_location_suffix(&normalized);
    normalized.replace('$', ".")
}

fn strip_trailing_numeric_suffix(input: &str) -> String {
    let colon_split = input.rsplit_once(':');
    let candidate = colon_split.map(|(head, _)| head).unwrap_or(input);
    let Some((prefix, suffix)) = candidate.rsplit_once('$') else {
        return input.to_string();
    };

    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return input.to_string();
    }

    if let Some((_, location)) = colon_split {
        format!("{prefix}:{location}")
    } else {
        prefix.to_string()
    }
}

fn strip_location_suffix(input: &str) -> String {
    let Some((head, tail)) = input.rsplit_once(':') else {
        return input.to_string();
    };
    if !tail.bytes().all(|byte| byte.is_ascii_digit()) {
        return input.to_string();
    }

    if let Some((grand_head, middle)) = head.rsplit_once(':')
        && middle.bytes().all(|byte| byte.is_ascii_digit())
    {
        return grand_head.to_string();
    }

    head.to_string()
}

pub(super) fn extract_java_call_receiver(reference: &str) -> Option<String> {
    let trimmed = reference.trim();
    if trimmed.is_empty() || !trimmed.is_ascii() {
        return None;
    }

    let before_args = trimmed
        .split_once('(')
        .map(|(head, _)| head)
        .unwrap_or(trimmed)
        .trim();
    let (receiver, method_name) = before_args.rsplit_once('.')?;
    if receiver.is_empty() || method_name.is_empty() || receiver.contains('$') {
        return None;
    }

    if !looks_like_java_method_name(method_name) {
        return None;
    }

    let segments: Vec<_> = receiver.split('.').collect();
    let last = *segments.last()?;
    if !looks_like_pascal_identifier(last) {
        return None;
    }

    for segment in &segments {
        if segment.is_empty()
            || !segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return None;
        }

        let first = segment.as_bytes()[0] as char;
        if !first.is_ascii_lowercase() && !first.is_ascii_uppercase() {
            return None;
        }
    }

    Some(receiver.to_string())
}

fn looks_like_java_method_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_lowercase() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn looks_like_pascal_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    first.is_ascii_uppercase() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub(super) fn is_java_anonymous_structure(fq_name: &str) -> bool {
    fq_name.contains("$anon$")
        || fq_name
            .rsplit_once('$')
            .map(|(_, suffix)| suffix.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false)
}

pub(super) fn collect_type_identifiers(
    node: Node<'_>,
    source: &str,
    identifiers: &mut HashSet<String>,
) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "type_identifier" | "scoped_type_identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    identifiers.insert(text.to_string());
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}

pub(super) fn visit_class_like(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: Option<&CodeUnit>,
    top_level_owner: Option<&CodeUnit>,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> Option<CodeUnit> {
    let mut first = None;
    let mut stack = vec![(node, parent.cloned(), top_level_owner.cloned())];
    while let Some((node, parent, top_level_owner)) = stack.pop() {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };

        let simple_name = node_text(name_node, source).trim().to_string();
        if simple_name.is_empty() {
            continue;
        }

        let short_name = parent
            .as_ref()
            .map(|parent| format!("{}.{}", parent.short_name(), simple_name))
            .unwrap_or(simple_name.clone());

        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Class,
            package_name.to_string(),
            short_name,
        );
        if first.is_none() {
            first = Some(code_unit.clone());
        }
        let raw_supertypes = extract_raw_supertypes(node, source);
        let signature = class_signature(node, source);

        let top_level = top_level_owner.unwrap_or_else(|| code_unit.clone());
        parsed.add_code_unit(
            code_unit.clone(),
            node,
            source,
            parent.clone(),
            Some(top_level.clone()),
        );
        parsed.set_raw_supertypes(code_unit.clone(), raw_supertypes);
        parsed.add_signature(code_unit.clone(), signature);

        if node.kind() == "record_declaration" {
            visit_record_components(
                file,
                source,
                node,
                package_name,
                &code_unit,
                &top_level,
                parsed,
            );
        }

        if let Some(body) = node.child_by_field_name("body") {
            for child in class_like_body_children_rev(body) {
                match child.kind() {
                    kind if is_class_like_declaration_kind(kind) => {
                        stack.push((child, Some(code_unit.clone()), Some(top_level.clone())));
                    }
                    "method_declaration" | "constructor_declaration" => {
                        visit_callable(
                            file,
                            source,
                            child,
                            package_name,
                            &code_unit,
                            &top_level,
                            parsed,
                        );
                    }
                    "field_declaration" | "constant_declaration" => {
                        visit_field_declaration(
                            file,
                            source,
                            child,
                            package_name,
                            &code_unit,
                            &top_level,
                            parsed,
                        );
                    }
                    "enum_constant" => {
                        visit_enum_constant(
                            file,
                            source,
                            child,
                            package_name,
                            &code_unit,
                            &top_level,
                            parsed,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    first
}

fn visit_callable(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let signature = node
        .child_by_field_name("parameters")
        .map(|parameters| canonical_parameters_signature(parameters, source));
    let short_name = format!("{}.{}", parent.short_name(), name);
    let callable_sig = callable_signature(node, source);
    let parameter_labels = node
        .child_by_field_name("parameters")
        .map(|parameters| parameter_labels(parameters, source))
        .unwrap_or_default();
    let code_unit = CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        signature.clone(),
        false,
    );

    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature_with_metadata(
        code_unit.clone(),
        SignatureMetadata::with_parameter_labels(callable_sig, parameter_labels),
    );

    if let Some(body) = node.child_by_field_name("body") {
        collect_lambda_expressions(
            file,
            source,
            body,
            package_name,
            &code_unit,
            top_level,
            parsed,
        );
    }
}

fn visit_field_declaration(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        parsed.add_code_unit(
            code_unit.clone(),
            node,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, field_signature(node, child, source));

        if let Some(value) = child.child_by_field_name("value") {
            collect_lambda_expressions(
                file,
                source,
                value,
                package_name,
                parent,
                top_level,
                parsed,
            );
        }
    }
}

fn visit_record_components(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };

    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "formal_parameter" {
            continue;
        }

        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };

        let name = node_text(name_node, source).trim();
        if name.is_empty() {
            continue;
        }

        let code_unit = CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        parsed.add_code_unit(
            code_unit.clone(),
            child,
            source,
            Some(parent.clone()),
            Some(top_level.clone()),
        );
        parsed.add_signature(code_unit, normalize_whitespace(node_text(child, source)));
    }
}

fn visit_enum_constant(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };

    let name = node_text(name_node, source).trim();
    if name.is_empty() {
        return;
    }

    let code_unit = CodeUnit::new(
        file.clone(),
        crate::analyzer::CodeUnitType::Field,
        package_name.to_string(),
        format!("{}.{}", parent.short_name(), name),
    );
    parsed.add_code_unit(
        code_unit.clone(),
        node,
        source,
        Some(parent.clone()),
        Some(top_level.clone()),
    );
    parsed.add_signature(code_unit, enum_constant_signature(node, source));
}

fn collect_lambda_expressions(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    package_name: &str,
    parent: &CodeUnit,
    top_level: &CodeUnit,
    parsed: &mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
) {
    let mut stack = vec![(node, parent.clone())];
    while let Some((node, parent)) = stack.pop() {
        let next_parent = if node.kind() == "lambda_expression" {
            let lambda = lambda_code_unit(file, package_name, &parent, node);
            parsed.add_code_unit(
                lambda.clone(),
                node,
                source,
                Some(parent),
                Some(top_level.clone()),
            );
            lambda
        } else {
            parent
        };
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|child| (child, next_parent.clone())),
        );
    }
}

fn lambda_code_unit(
    file: &ProjectFile,
    package_name: &str,
    parent: &CodeUnit,
    node: Node<'_>,
) -> CodeUnit {
    let line = node.start_position().row;
    let column = node.start_position().column;
    let short_name = if parent.is_function() {
        format!("{}$anon${line}:{column}", parent.short_name())
    } else {
        format!(
            "{}.{}$anon${line}:{column}",
            parent.short_name(),
            parent.identifier()
        )
    };
    CodeUnit::with_signature(
        file.clone(),
        crate::analyzer::CodeUnitType::Function,
        package_name.to_string(),
        short_name,
        None,
        true,
    )
}

pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

pub(super) fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn parse_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .expect("failed to load java parser");
    parser.parse(source, None)
}

pub(super) fn is_comment_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "line_comment" | "block_comment")
}

pub(super) fn is_declaration_parent(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "field_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "variable_declarator"
            | "formal_parameter"
            | "catch_formal_parameter"
            | "enhanced_for_statement"
            | "resource"
    )
}

pub(super) fn is_class_like_declaration_kind(kind: &str) -> bool {
    matches!(
        kind,
        "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration"
    )
}

pub(super) fn class_like_body_children_rev<'tree>(body: Node<'tree>) -> Vec<Node<'tree>> {
    let mut children = Vec::new();
    for index in (0..body.named_child_count()).rev() {
        let Some(child) = body.named_child(index) else {
            continue;
        };
        children.push(child);
    }
    children
}

pub(super) fn find_nearest_declaration_from_node(
    start_node: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let mut current = Some(start_node);

    while let Some(node) = current {
        match node.kind() {
            "method_declaration" | "constructor_declaration" => {
                if let Some(found) = check_formal_parameters(node, identifier, source) {
                    return Some(found);
                }
            }
            "enhanced_for_statement" => {
                if let Some(found) = match_named_field(
                    node,
                    "name",
                    identifier,
                    source,
                    DeclarationKind::EnhancedForVariable,
                ) {
                    return Some(found);
                }
            }
            "catch_clause" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "catch_formal_parameter"
                        && let Some(found) = match_named_field(
                            child,
                            "name",
                            identifier,
                            source,
                            DeclarationKind::CatchParameter,
                        )
                    {
                        return Some(found);
                    }
                }
            }
            "try_with_resources_statement" => {
                if let Some(resources) = node.child_by_field_name("resources") {
                    let mut cursor = resources.walk();
                    for child in resources.named_children(&mut cursor) {
                        if child.kind() == "resource"
                            && let Some(found) = match_named_field(
                                child,
                                "name",
                                identifier,
                                source,
                                DeclarationKind::ResourceVariable,
                            )
                        {
                            return Some(found);
                        }
                    }
                }
            }
            "lambda_expression" => {
                if let Some(parameters) = node.child_by_field_name("parameters") {
                    if parameters.kind() == "identifier" {
                        if node_text(parameters, source).trim() == identifier {
                            return Some(declaration_info(
                                identifier,
                                DeclarationKind::LambdaParameter,
                                parameters,
                            ));
                        }
                    } else {
                        let mut cursor = parameters.walk();
                        for child in parameters.named_children(&mut cursor) {
                            if child.kind() == "identifier"
                                && node_text(child, source).trim() == identifier
                            {
                                return Some(declaration_info(
                                    identifier,
                                    DeclarationKind::LambdaParameter,
                                    child,
                                ));
                            }
                            if child.kind() == "formal_parameter"
                                && let Some(found) = match_named_field(
                                    child,
                                    "name",
                                    identifier,
                                    source,
                                    DeclarationKind::LambdaParameter,
                                )
                            {
                                return Some(found);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(found) = check_preceding_local_variables(node, identifier, source) {
            return Some(found);
        }

        current = node.parent();
    }

    None
}

fn check_formal_parameters(
    node: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let params = node.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        if child.kind() == "formal_parameter"
            && let Some(found) = match_named_field(
                child,
                "name",
                identifier,
                source,
                DeclarationKind::Parameter,
            )
        {
            return Some(found);
        }
    }
    None
}

fn check_preceding_local_variables(
    current: Node<'_>,
    identifier: &str,
    source: &str,
) -> Option<DeclarationInfo> {
    let parent = current.parent()?;
    let mut cursor = parent.walk();
    for sibling in parent.named_children(&mut cursor) {
        if sibling.end_byte() > current.start_byte() {
            break;
        }
        if sibling.kind() != "local_variable_declaration" {
            continue;
        }
        let mut local_cursor = sibling.walk();
        for child in sibling.named_children(&mut local_cursor) {
            if child.kind() == "variable_declarator"
                && let Some(found) = match_named_field(
                    child,
                    "name",
                    identifier,
                    source,
                    DeclarationKind::LocalVariable,
                )
            {
                return Some(found);
            }
        }
    }
    None
}

fn match_named_field(
    node: Node<'_>,
    field_name: &str,
    identifier: &str,
    source: &str,
    kind: DeclarationKind,
) -> Option<DeclarationInfo> {
    let name_node = node.child_by_field_name(field_name)?;
    if node_text(name_node, source).trim() == identifier {
        Some(declaration_info(identifier, kind, name_node))
    } else {
        None
    }
}

fn declaration_info(identifier: &str, kind: DeclarationKind, node: Node<'_>) -> DeclarationInfo {
    DeclarationInfo {
        identifier: identifier.to_string(),
        kind,
        range: crate::analyzer::Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        },
    }
}

fn class_signature(node: Node<'_>, source: &str) -> String {
    let body_start = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    let header = source
        .get(node.start_byte()..body_start)
        .unwrap_or("")
        .trim_end();
    format!("{} {{", normalize_whitespace(header))
}

fn callable_signature(node: Node<'_>, source: &str) -> String {
    let end = node
        .child_by_field_name("body")
        .map(|body| body.start_byte())
        .unwrap_or(node.end_byte());
    normalize_whitespace(source.get(node.start_byte()..end).unwrap_or("").trim_end())
}

fn canonical_parameters_signature(parameters: Node<'_>, source: &str) -> String {
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    let mut ty = normalize_whitespace(node_text(type_node, source));
                    if let Some(dimensions) = child.child_by_field_name("dimensions") {
                        ty.push_str(node_text(dimensions, source).trim());
                    }
                    parts.push(ty);
                }
            }
            "spread_parameter" => {
                let mut spread_cursor = child.walk();
                for grandchild in child.named_children(&mut spread_cursor) {
                    if grandchild.kind() == "variable_declarator" {
                        continue;
                    }
                    if grandchild.kind() == "modifiers"
                        || grandchild.kind() == "annotation"
                        || grandchild.kind() == "marker_annotation"
                    {
                        continue;
                    }
                    parts.push(format!(
                        "{}[]",
                        normalize_whitespace(node_text(grandchild, source))
                    ));
                    break;
                }
            }
            "receiver_parameter" => {
                if let Some(type_node) = child.child_by_field_name("type") {
                    parts.push(normalize_whitespace(node_text(type_node, source)));
                }
            }
            _ => {}
        }
    }

    format!("({})", parts.join(", "))
}

fn parameter_labels(parameters: Node<'_>, source: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        let name = match child.kind() {
            "formal_parameter" => child.child_by_field_name("name"),
            "spread_parameter" => spread_parameter_name(child),
            _ => None,
        };
        if let Some(name) = name {
            let label = node_text(name, source).trim();
            if !label.is_empty() {
                labels.push(label.to_string());
            }
        }
    }
    labels
}

fn spread_parameter_name(parameter: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = parameter.walk();
    for child in parameter.named_children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            return child.child_by_field_name("name");
        }
    }
    None
}

fn field_signature(field_node: Node<'_>, declarator: Node<'_>, source: &str) -> String {
    let Some(type_node) = field_node.child_by_field_name("type") else {
        return normalize_whitespace(node_text(field_node, source));
    };
    let Some(name_node) = declarator.child_by_field_name("name") else {
        return normalize_whitespace(node_text(field_node, source));
    };

    let prefix = normalize_whitespace(
        source
            .get(field_node.start_byte()..type_node.start_byte())
            .unwrap_or(""),
    );
    let type_text = normalize_whitespace(node_text(type_node, source));
    let name_text = node_text(name_node, source).trim();

    let mut signature = String::new();
    for part in [prefix.as_str(), type_text.as_str(), name_text] {
        if part.is_empty() {
            continue;
        }
        if !signature.is_empty() {
            signature.push(' ');
        }
        signature.push_str(part);
    }

    let suffix = declarator
        .child_by_field_name("value")
        .and_then(|value| literal_field_initializer(value, source))
        .map(|value| format!(" = {value};"))
        .unwrap_or_else(|| ";".to_string());
    signature.push_str(&suffix);
    signature
}

fn literal_field_initializer<'a>(value: Node<'_>, source: &'a str) -> Option<&'a str> {
    let kind = value.kind();
    if kind.ends_with("_literal") || matches!(kind, "true" | "false" | "null_literal" | "null") {
        Some(node_text(value, source).trim())
    } else {
        None
    }
}

fn enum_constant_signature(node: Node<'_>, source: &str) -> String {
    let mut text = node_text(node, source).trim().to_string();
    if node.next_named_sibling().is_some() {
        text.push(',');
    }
    text
}

pub(super) fn module_code_unit(file: &ProjectFile, package_name: &str) -> CodeUnit {
    match package_name.rsplit_once('.') {
        Some((parent, leaf)) => CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Module,
            parent.to_string(),
            leaf.to_string(),
        ),
        None => CodeUnit::new(
            file.clone(),
            crate::analyzer::CodeUnitType::Module,
            String::new(),
            package_name.to_string(),
        ),
    }
}

pub(super) fn extract_raw_supertypes(node: Node<'_>, source: &str) -> Vec<String> {
    let mut raw = Vec::new();

    if let Some(superclass) = node.child_by_field_name("superclass") {
        collect_supertype_nodes(superclass, source, &mut raw);
    }
    if let Some(interfaces) = node.child_by_field_name("interfaces") {
        collect_supertype_nodes(interfaces, source, &mut raw);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "extends_interfaces" {
            collect_supertype_nodes(child, source, &mut raw);
        }
    }

    raw
}

fn collect_supertype_nodes(node: Node<'_>, source: &str, raw: &mut Vec<String>) {
    walk_named_tree_preorder(node, true, |node| {
        match node.kind() {
            "type_identifier" | "scoped_type_identifier" => {
                let text = node_text(node, source).trim();
                if !text.is_empty() {
                    raw.push(text.to_string());
                }
            }
            _ => {}
        }
        WalkControl::Continue
    });
}
