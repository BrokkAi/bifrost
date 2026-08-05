//! C#'s syntax-level knowledge: name normalization, generic-arity stripping,
//! structured type-node identity, and the node predicates that decide whether an
//! identifier occupies a type, attribute, member or `using`-directive role.
//!
//! Everything here is a pure function of a `tree_sitter::Node`, a `&str` or a
//! [`CodeUnit`]; nothing reaches an analyzer. `analyzer/csharp/mod.rs` in
//! `brokk-bifrost-analysis` re-exports the names its framework call sites and
//! the rest of the C# seam already used.

use brokk_bifrost_core::analyzer::model::{CallableArity, DispatchExtensibility};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex};
use tree_sitter::Node;

pub fn csharp_callable_dispatch_extensibility(
    source: &str,
    node: Node<'_>,
    is_static: bool,
) -> DispatchExtensibility {
    if matches!(
        node.kind(),
        "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
    ) {
        return DispatchExtensibility::Closed;
    }

    let modifier_owner = csharp_enclosing_accessor_owner(node).unwrap_or(node);
    let plain_private = csharp_has_modifier(source, modifier_owner, "private")
        && !csharp_has_modifier(source, modifier_owner, "protected");
    if plain_private
        || csharp_has_modifier(source, modifier_owner, "sealed")
        || csharp_enclosing_callable_type(modifier_owner).is_some_and(|owner| {
            matches!(
                owner.kind(),
                "struct_declaration" | "record_struct_declaration"
            ) || csharp_has_modifier(source, owner, "sealed")
        })
    {
        return DispatchExtensibility::Closed;
    }

    let dynamically_dispatched = node.kind() == "destructor_declaration"
        || ["virtual", "abstract", "override"]
            .into_iter()
            .any(|modifier| csharp_has_modifier(source, modifier_owner, modifier))
        || csharp_enclosing_callable_type(modifier_owner)
            .is_some_and(|owner| owner.kind() == "interface_declaration" && !is_static);
    if dynamically_dispatched {
        DispatchExtensibility::Open
    } else {
        DispatchExtensibility::Closed
    }
}

pub fn csharp_has_modifier(source: &str, node: Node<'_>, modifier: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).any(|child| {
        child.kind() == "modifier"
            && source
                .get(child.start_byte()..child.end_byte())
                .is_some_and(|text| text == modifier)
    })
}

fn csharp_enclosing_accessor_owner(node: Node<'_>) -> Option<Node<'_>> {
    (node.kind() == "accessor_declaration")
        .then(|| node.parent())
        .flatten()
        .and_then(|parent| parent.parent())
        .filter(|owner| matches!(owner.kind(), "property_declaration" | "indexer_declaration"))
}

fn csharp_enclosing_callable_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
                | "interface_declaration"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

pub fn csharp_using_directive_is_static(node: Node<'_>) -> bool {
    if node.kind() != "using_directive" {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "static")
}
pub fn csharp_using_directive_is_global(node: Node<'_>) -> bool {
    if node.kind() != "using_directive" {
        return false;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "global")
}

pub fn csharp_using_directive_target(node: Node<'_>, source: &str) -> Option<String> {
    csharp_using_directive_target_node(node)
        .map(|target| csharp_type_node_identity(target, source))
        .filter(|target| !target.is_empty())
}

pub fn csharp_using_directive_target_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "using_directive" {
        return None;
    }
    let alias = node.child_by_field_name("name");
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| alias.is_none_or(|alias| child != &alias))
}

pub fn csharp_using_directive_namespace(node: Node<'_>, source: &str) -> Option<String> {
    (!csharp_using_directive_is_static(node) && node.child_by_field_name("name").is_none())
        .then(|| csharp_using_directive_target(node, source))
        .flatten()
}

pub fn csharp_as_expression_type_operand(parent: Node<'_>, node: Node<'_>) -> bool {
    parent.kind() == "as_expression"
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() == node.start_byte() && right.end_byte() == node.end_byte()
        })
}

pub fn csharp_is_expression_type_operand(parent: Node<'_>, node: Node<'_>) -> bool {
    match parent.kind() {
        "is_expression" => parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() == node.start_byte() && right.end_byte() == node.end_byte()
        }),
        "is_pattern_expression" => parent
            .child_by_field_name("pattern")
            .is_some_and(|pattern| {
                pattern.start_byte() == node.start_byte()
                    && pattern.end_byte() == node.end_byte()
                    && csharp_pattern_has_structured_type(pattern)
            }),
        "switch_expression_arm" | "switch_section" => {
            parent.named_child(0).is_some_and(|pattern| {
                pattern.start_byte() == node.start_byte()
                    && pattern.end_byte() == node.end_byte()
                    && csharp_pattern_has_structured_type(pattern)
            })
        }
        _ => false,
    }
}

fn csharp_pattern_has_structured_type(mut pattern: Node<'_>) -> bool {
    while matches!(pattern.kind(), "parenthesized_pattern" | "negated_pattern") {
        let Some(inner) = pattern.named_child(0) else {
            return false;
        };
        pattern = inner;
    }
    matches!(
        pattern.kind(),
        "type_pattern" | "declaration_pattern" | "recursive_pattern"
    )
}

pub fn csharp_arity_preserving_full_name(fq_name: &str) -> String {
    let normalized = fq_name
        .strip_prefix("global::")
        .unwrap_or(fq_name)
        .replace(['$', '+'], ".");
    normalize_csharp_constructor_name(normalized)
}

pub fn csharp_normalize_full_name(fq_name: &str) -> String {
    let normalized = fq_name
        .strip_prefix("global::")
        .unwrap_or(fq_name)
        .replace(['$', '+'], ".")
        .split('.')
        .map(strip_csharp_generic_arity)
        .collect::<Vec<_>>()
        .join(".");
    normalize_csharp_constructor_name(normalized)
}

fn normalize_csharp_constructor_name(normalized: String) -> String {
    let Some(owner) = normalized.strip_suffix(".#ctor") else {
        return normalized;
    };
    if owner.is_empty() {
        return normalized;
    }

    let constructor_name = owner
        .rfind('.')
        .map(|separator| &owner[separator + 1..])
        .unwrap_or(owner);
    let constructor_name = strip_csharp_generic_arity(constructor_name);
    if constructor_name.is_empty() {
        normalized
    } else {
        format!("{owner}.{constructor_name}")
    }
}

pub fn strip_csharp_generic_arity(segment: &str) -> &str {
    let Some((name, arity)) = segment.rsplit_once('`') else {
        return segment;
    };
    let backticks = 1 + name.bytes().rev().take_while(|byte| *byte == b'`').count();
    let name = name.trim_end_matches('`');
    if !name.is_empty()
        && (1..=2).contains(&backticks)
        && !arity.is_empty()
        && arity.bytes().all(|byte| byte.is_ascii_digit())
    {
        name
    } else {
        segment
    }
}

pub fn csharp_source_identifier(unit: &CodeUnit) -> &str {
    strip_csharp_generic_arity(unit.identifier())
}

pub fn csharp_source_name_segment(segment: &str) -> &str {
    strip_csharp_generic_arity(segment)
}

pub fn csharp_type_node_identity(node: Node<'_>, source: &str) -> String {
    csharp_type_node_identity_with_terminal_suffix(node, source, "", false)
}

fn csharp_type_node_identity_with_terminal_suffix(
    node: Node<'_>,
    source: &str,
    terminal_suffix: &str,
    strip_terminal_verbatim_prefix: bool,
) -> String {
    let mut segments = Vec::new();
    let mut stack = vec![node];
    let mut alias_qualified = false;
    while let Some(current) = stack.pop() {
        match current.kind() {
            "qualified_name" | "alias_qualified_name" | "member_access_expression" => {
                alias_qualified |= current.kind() == "alias_qualified_name";
                let qualifier = current
                    .child_by_field_name("qualifier")
                    .or_else(|| current.child_by_field_name("alias"))
                    .or_else(|| current.child_by_field_name("expression"))
                    .or_else(|| current.named_child(0));
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(current.named_child_count().saturating_sub(1)));
                if let Some(name) = name {
                    stack.push(name);
                }
                if let Some(qualifier) = qualifier {
                    stack.push(qualifier);
                }
            }
            "generic_name" => {
                let name = current
                    .child_by_field_name("name")
                    .or_else(|| current.named_child(0));
                let type_arguments = (0..current.named_child_count())
                    .filter_map(|index| current.named_child(index))
                    .find(|child| child.kind() == "type_argument_list");
                if let Some(name) = name {
                    let source_name = source
                        .get(name.start_byte()..name.end_byte())
                        .unwrap_or("")
                        .trim();
                    let arity = type_arguments.map_or(0, |arguments| arguments.named_child_count());
                    if !source_name.is_empty() {
                        segments.push(if arity == 0 {
                            source_name.to_string()
                        } else {
                            format!("{source_name}`{arity}")
                        });
                    }
                }
            }
            "nullable_type"
            | "array_type"
            | "pointer_type"
            | "type"
            | "simple_base_type"
            | "primary_constructor_base_type"
            | "type_pattern"
            | "declaration_pattern"
            | "recursive_pattern" => {
                if let Some(inner) = current
                    .child_by_field_name("type")
                    .or_else(|| current.named_child(0))
                {
                    stack.push(inner);
                }
            }
            "parenthesized_pattern" | "negated_pattern" => {
                if let Some(inner) = current.named_child(0) {
                    stack.push(inner);
                }
            }
            "identifier" | "predefined_type" => {
                let segment = source
                    .get(current.start_byte()..current.end_byte())
                    .unwrap_or("")
                    .trim();
                if !segment.is_empty() {
                    segments.push(segment.to_string());
                }
            }
            _ => {
                let fallback = source
                    .get(current.start_byte()..current.end_byte())
                    .map(normalize_csharp_type_fragment)
                    .unwrap_or_default();
                if !fallback.is_empty() {
                    segments.push(fallback);
                }
            }
        }
    }
    if let Some(terminal) = segments.last_mut() {
        if strip_terminal_verbatim_prefix && terminal.starts_with('@') {
            terminal.remove(0);
        }
        terminal.push_str(terminal_suffix);
    }
    if alias_qualified && segments.len() > 1 {
        format!("{}::{}", segments[0], segments[1..].join("."))
    } else {
        segments.join(".")
    }
}

pub fn csharp_type_reference_root(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = node.parent()?;
        if let Some(wrapper) = csharp_pattern_type_wrapper(parent, node) {
            node = wrapper;
            continue;
        }
        if matches!(
            parent.kind(),
            "qualified_name"
                | "alias_qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "pointer_type"
                | "type"
                | "simple_base_type"
                | "primary_constructor_base_type"
        ) {
            node = parent;
            continue;
        }
        if csharp_is_structured_type_role(parent, node)
            || csharp_as_expression_type_operand(parent, node)
            || csharp_is_expression_type_operand(parent, node)
        {
            return Some(node);
        }
        if matches!(
            parent.kind(),
            "type_argument_list" | "base_list" | "explicit_interface_specifier"
        ) || parent.kind() == "object_creation_expression"
        {
            return Some(node);
        }
        if parent.kind() == "using_directive"
            && (parent.child_by_field_name("name").is_some()
                || csharp_using_directive_is_static(parent))
            && csharp_using_directive_target_node(parent)
                .is_some_and(|target| same_csharp_node(target, node))
        {
            return Some(node);
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_csharp_node(name, node))
        {
            return Some(node);
        }
        return None;
    }
}

fn csharp_pattern_type_wrapper<'tree>(
    parent: Node<'tree>,
    node: Node<'tree>,
) -> Option<Node<'tree>> {
    match parent.kind() {
        "type_pattern" | "declaration_pattern" | "recursive_pattern" => parent
            .child_by_field_name("type")
            .filter(|candidate| same_csharp_node(*candidate, node))
            .map(|_| parent),
        "parenthesized_pattern" | "negated_pattern" => parent
            .named_child(0)
            .filter(|candidate| same_csharp_node(*candidate, node))
            .map(|_| parent),
        _ => None,
    }
}

fn csharp_is_structured_type_role(parent: Node<'_>, node: Node<'_>) -> bool {
    // A tuple element exposes both `type` and `name` identifier children. Keep
    // that distinction declaration-driven: only the grammar's `type` field is
    // a reference, even when the element name has identical text.
    let fields: &[&str] = if parent.kind() == "tuple_element" {
        &["type"]
    } else {
        &["type", "return_type", "returns"]
    };
    fields.iter().any(|field| {
        parent
            .child_by_field_name(field)
            .is_some_and(|candidate| same_csharp_node(candidate, node))
    })
}

/// Return the expression that can denote a type in a `nameof(...)` operand.
///
/// C# parses `nameof(Type)` in expression position, so the identifier does not
/// carry one of the ordinary syntax-tree type roles handled by
/// [`csharp_type_reference_root`]. A qualified operand may itself be a type
/// (`nameof(Namespace.Type)`); otherwise its receiver may be the type owner
/// (`nameof(Type.Member)`). Resolution remains responsible for choosing the
/// first valid interpretation and rejecting locals, fields, and other value
/// expressions with the same shape.
pub fn csharp_nameof_type_candidates<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Option<Node<'tree>>)> {
    if node.kind() != "invocation_expression" {
        return None;
    }
    let function = node
        .child_by_field_name("function")
        .or_else(|| node.named_child(0))?;
    if function.kind() != "identifier"
        || source.get(function.start_byte()..function.end_byte())? != "nameof"
    {
        return None;
    }
    let arguments = node.child_by_field_name("arguments").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "argument_list")
    })?;
    if arguments.named_child_count() != 1 {
        return None;
    }
    let argument = arguments.named_child(0)?;
    let operand = if argument.kind() == "argument" {
        argument
            .child_by_field_name("value")
            .or_else(|| argument.child_by_field_name("expression"))
            .or_else(|| argument.named_child(0))?
    } else {
        argument
    };
    let qualified_owner = if operand.kind() == "member_access_expression" {
        Some(
            operand
                .child_by_field_name("expression")
                .or_else(|| operand.named_child(0))?,
        )
    } else {
        None
    };
    matches!(
        operand.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "member_access_expression"
    )
    .then_some((operand, qualified_owner))
}

pub fn csharp_constant_pattern_type_candidate(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "constant_pattern" {
        return None;
    }
    let mut candidate = node.named_child(0)?;
    while candidate.kind() == "binary_expression" {
        candidate = candidate
            .child_by_field_name("left")
            .or_else(|| candidate.named_child(0))?;
    }
    matches!(
        candidate.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "member_access_expression"
    )
    .then_some(candidate)
}

pub fn csharp_member_access_type_receiver(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "member_access_expression" {
        return None;
    }
    let receiver = node
        .child_by_field_name("expression")
        .or_else(|| node.named_child(0))?;
    matches!(
        receiver.kind(),
        "identifier"
            | "qualified_name"
            | "alias_qualified_name"
            | "generic_name"
            | "member_access_expression"
    )
    .then_some(receiver)
}

pub fn csharp_type_terminal_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "predefined_type" => return Some(node),
            "qualified_name" | "alias_qualified_name" | "member_access_expression" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))?;
            }
            "generic_name" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))?;
            }
            "nullable_type"
            | "array_type"
            | "pointer_type"
            | "type"
            | "simple_base_type"
            | "primary_constructor_base_type"
            | "type_pattern"
            | "declaration_pattern"
            | "recursive_pattern" => {
                node = node
                    .child_by_field_name("type")
                    .or_else(|| node.named_child(0))?;
            }
            "parenthesized_pattern" | "negated_pattern" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

pub fn csharp_type_leftmost_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" | "predefined_type" => return Some(node),
            "qualified_name" | "alias_qualified_name" | "member_access_expression" => {
                node = node
                    .child_by_field_name("qualifier")
                    .or_else(|| node.child_by_field_name("alias"))
                    .or_else(|| node.child_by_field_name("expression"))
                    .or_else(|| node.named_child(0))?;
            }
            "generic_name" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))?;
            }
            "nullable_type"
            | "array_type"
            | "pointer_type"
            | "type"
            | "simple_base_type"
            | "primary_constructor_base_type"
            | "type_pattern"
            | "declaration_pattern"
            | "recursive_pattern" => {
                node = node
                    .child_by_field_name("type")
                    .or_else(|| node.named_child(0))?;
            }
            "parenthesized_pattern" | "negated_pattern" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

fn same_csharp_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

/// Return the structured name node when `node` is inside a C# attribute's name.
/// Identifiers in an attribute argument deliberately do not count.
pub fn csharp_attribute_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let start = node.start_byte();
    let end = node.end_byte();
    let mut current = node;
    loop {
        if current.kind() == "attribute" {
            return current
                .child_by_field_name("name")
                .filter(|name| name.start_byte() <= start && end <= name.end_byte());
        }
        current = current.parent()?;
    }
}

/// C# attribute lookup considers both the written type name and the same name
/// with `Attribute` appended to its terminal AST segment. A verbatim identifier
/// suppresses the suffix form.
pub fn csharp_attribute_type_names(name: Node<'_>, source: &str) -> Vec<String> {
    let exact = csharp_type_node_identity_with_terminal_suffix(name, source, "", true);
    if exact.is_empty() {
        return Vec::new();
    }

    let verbatim = csharp_attribute_terminal_name(name, source)
        .is_some_and(|terminal| terminal.starts_with('@'));
    if verbatim {
        return vec![exact];
    }

    let suffixed = csharp_type_node_identity_with_terminal_suffix(name, source, "Attribute", false);
    if suffixed == exact {
        vec![exact]
    } else {
        vec![exact, suffixed]
    }
}

pub fn csharp_attribute_terminal_name<'a>(name: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut terminal = name;
    while let Some(next) = match terminal.kind() {
        "qualified_name" | "alias_qualified_name" => terminal
            .child_by_field_name("name")
            .or_else(|| terminal.named_child(terminal.named_child_count().saturating_sub(1))),
        "generic_name" => terminal
            .child_by_field_name("name")
            .or_else(|| terminal.named_child(0)),
        _ => None,
    } {
        terminal = next;
    }
    source
        .get(terminal.start_byte()..terminal.end_byte())
        .map(str::trim)
        .filter(|terminal| !terminal.is_empty())
}

#[derive(Clone, Copy)]
pub struct CSharpMemberName<'tree> {
    pub identifier: Node<'tree>,
    pub explicit_generic_arity: Option<usize>,
    pub type_arguments: Option<Node<'tree>>,
}

#[derive(Clone, Copy)]
pub struct CSharpConditionalMemberAccess<'tree> {
    pub receiver: Node<'tree>,
    pub binding: Node<'tree>,
    pub name: Node<'tree>,
}

pub fn csharp_conditional_member_access(
    node: Node<'_>,
) -> Option<CSharpConditionalMemberAccess<'_>> {
    if node.kind() != "conditional_access_expression" {
        return None;
    }
    let receiver = node.child_by_field_name("condition")?;
    let mut cursor = node.walk();
    let binding = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "member_binding_expression")?;
    let name = binding.child_by_field_name("name")?;
    Some(CSharpConditionalMemberAccess {
        receiver,
        binding,
        name,
    })
}

pub fn csharp_member_name(node: Node<'_>) -> Option<CSharpMemberName<'_>> {
    match node.kind() {
        "identifier" => Some(CSharpMemberName {
            identifier: node,
            explicit_generic_arity: None,
            type_arguments: None,
        }),
        "generic_name" => {
            let identifier = node
                .child_by_field_name("name")
                .or_else(|| node.named_child(0))?;
            let type_arguments = node.child_by_field_name("type_arguments").or_else(|| {
                let mut cursor = node.walk();
                node.named_children(&mut cursor)
                    .find(|child| child.kind() == "type_argument_list")
            })?;
            Some(CSharpMemberName {
                identifier,
                explicit_generic_arity: Some(type_arguments.named_child_count()),
                type_arguments: Some(type_arguments),
            })
        }
        _ => None,
    }
}

pub fn csharp_unqualified_invocation_for_name(
    identifier: Node<'_>,
) -> Option<(Node<'_>, Option<usize>)> {
    let (function, explicit_generic_arity) = identifier
        .parent()
        .filter(|parent| parent.kind() == "generic_name")
        .and_then(|generic_name| {
            let name = csharp_member_name(generic_name)?;
            (name.identifier == identifier).then_some((generic_name, name.explicit_generic_arity))
        })
        .unwrap_or((identifier, None));
    let invocation = function.parent()?;
    (invocation.kind() == "invocation_expression"
        && invocation.child_by_field_name("function") == Some(function))
    .then_some((invocation, explicit_generic_arity))
}

pub fn csharp_signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')').map(|(inner, _)| inner))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    count_top_level_comma_separated(inner)
}

pub fn csharp_method_generic_arity(signature: Option<&str>) -> usize {
    signature
        .and_then(|signature| signature.strip_prefix('`'))
        .and_then(|signature| signature.split_once('(').map(|(arity, _)| arity))
        .and_then(|arity| arity.parse().ok())
        .unwrap_or(0)
}

pub fn csharp_callable_arity(index: &dyn CodeUnitIndex, unit: &CodeUnit) -> CallableArity {
    index
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| CallableArity::exact(csharp_signature_arity(unit.signature())))
}

pub fn csharp_signature_return_type(signature: &str, name: &str) -> Option<String> {
    type_text_before_name(signature, name)
}

fn type_text_before_name(signature: &str, name: &str) -> Option<String> {
    let before_name = signature.trim().rsplit_once(name)?.0.trim();
    let before_name = before_name.trim_end_matches(|ch: char| ch == '?' || ch.is_whitespace());
    let type_text = before_name
        .split_whitespace()
        .rfind(|part| !member_modifier(part))?;
    let type_text = normalize_csharp_type_fragment(type_text);
    (!type_text.is_empty()).then_some(type_text)
}

fn member_modifier(part: &str) -> bool {
    matches!(
        part,
        "public"
            | "private"
            | "protected"
            | "internal"
            | "static"
            | "readonly"
            | "volatile"
            | "const"
            | "new"
            | "virtual"
            | "override"
            | "abstract"
            | "sealed"
            | "required"
    )
}

pub fn normalize_csharp_type_fragment(reference: &str) -> String {
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
