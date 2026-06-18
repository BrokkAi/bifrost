use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, ProjectFile};
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: CodeUnit,
    pub(super) member_name: String,
    pub(super) method_arity: Option<usize>,
}

impl TargetSpec {
    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
                member_name: target.identifier().to_string(),
                method_arity: None,
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == owner.identifier() {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner,
            member_name: target.identifier().to_string(),
            method_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| signature_arity(target.signature())),
        })
    }
}

fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    count_top_level_comma_separated(inner)
}

pub(in crate::analyzer::usages) fn seed_bindings_before(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_bindings_before_inner(node, cutoff_start, csharp, file, source, bindings);
}

fn seed_bindings_before_inner(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    match node.kind() {
        "parameter" => seed_parameter(node, csharp, file, source, bindings),
        "variable_declaration" => seed_variable_declaration(node, csharp, file, source, bindings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        seed_bindings_before_inner(child, cutoff_start, csharp, file, source, bindings);
    }
}

fn seed_parameter(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings);
}

fn seed_variable_declaration(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = node_text(type_node, source);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if type_text == "var" {
            if let Some(initializer_type) = object_created_type(child)
                && let Some(target) =
                    resolve_type_fq_name(csharp, file, node_text(initializer_type, source))
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings);
        }
    }
}

fn seed_symbol_for_type(
    name_node: Node<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if let Some(target) = resolve_type_fq_name(csharp, file, node_text(type_node, source)) {
        bindings.seed_symbol(node_text(name_node, source), target);
    } else {
        bindings.declare_shadow(node_text(name_node, source));
    }
}

fn object_created_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .or_else(|| first_type_child(node));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = object_created_type(child) {
            return Some(found);
        }
    }
    None
}

pub(super) fn resolves_to_target(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
    target: &CodeUnit,
) -> bool {
    let normalized = normalize_type_text(reference);
    csharp
        .resolve_visible_type(file, &normalized)
        .is_some_and(|resolved| resolved == *target)
        || reference_matches_target_fq_name(&normalized, target)
}

fn resolve_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = normalize_type_text(reference);
    if let Some(target) = csharp.resolve_visible_type(file, &normalized) {
        return Some(target.fq_name());
    }
    csharp
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.is_class() && reference_matches_target_fq_name(&normalized, unit))
        .map(|unit| unit.fq_name())
}

fn reference_matches_target_fq_name(reference: &str, target: &CodeUnit) -> bool {
    reference == target.fq_name() || reference == target.fq_name().replace('$', ".")
}

pub(super) fn normalize_type_text(reference: &str) -> String {
    let trimmed = reference.trim();
    let without_nullable = trimmed.trim_end_matches('?').trim();
    let without_arrays = without_nullable.trim_end_matches("[]").trim();
    without_arrays
        .split('<')
        .next()
        .unwrap_or(without_arrays)
        .trim()
        .to_string()
}

pub(in crate::analyzer::usages) fn reference_type_text(node: Node<'_>, source: &str) -> String {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "qualified_name" | "generic_name" | "nullable_type" | "array_type"
        ) {
            current = parent;
            continue;
        }
        break;
    }
    normalize_type_text(node_text(current, source))
}

pub(in crate::analyzer::usages) fn binding_scope_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "property_declaration"
                | "accessor_declaration"
                | "local_function_statement"
        ) {
            return parent;
        }
        node = parent;
    }
    node
}

pub(super) fn receiver_targets_owner(
    receiver: &str,
    owner: &CodeUnit,
    bindings: &LocalInferenceEngine<String>,
) -> SymbolResolution<String> {
    match bindings.resolve_symbol(receiver) {
        SymbolResolution::Precise(targets)
            if targets.iter().any(|target| target == &owner.fq_name()) =>
        {
            SymbolResolution::Precise(targets)
        }
        resolution => resolution,
    }
}

pub(in crate::analyzer::usages) fn is_type_reference_node(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent
            .child_by_field_name("type")
            .is_some_and(|type_node| same_node(type_node, node))
            || parent
                .child_by_field_name("return_type")
                .is_some_and(|type_node| same_node(type_node, node))
        {
            return true;
        }
        if parent.kind() == "type" {
            return true;
        }
        if parent.kind() == "object_creation_expression" {
            return true;
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_node(name, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type_argument_list"
                | "base_list"
        ) {
            node = parent;
            continue;
        }
        return false;
    }
    false
}

pub(super) fn argument_count(node: Node<'_>, _source: &str) -> usize {
    let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
    else {
        return 0;
    };
    count_named_children_of_kind(arguments, "argument")
}

fn count_named_children_of_kind(node: Node<'_>, kind: &str) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == kind)
        .count()
}

fn count_top_level_comma_separated(text: &str) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    let mut count = 1;
    let mut angle_depth: usize = 0;
    let mut paren_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut string_quote: Option<char> = None;
    let mut escaped = false;

    for ch in text.chars() {
        if let Some(quote) = string_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                string_quote = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => string_quote = Some(ch),
            '<' => angle_depth = angle_depth.saturating_add(1),
            '>' if angle_depth > 0 => angle_depth -= 1,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' if paren_depth > 0 => paren_depth -= 1,
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' if bracket_depth > 0 => bracket_depth -= 1,
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' if brace_depth > 0 => brace_depth -= 1,
            ',' if angle_depth == 0
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0 =>
            {
                count += 1;
            }
            _ => {}
        }
    }

    count
}

pub(in crate::analyzer::usages) fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "identifier"
                | "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type"
        )
    })
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

pub(super) fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

pub(in crate::analyzer::usages) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}
