//! Declaration properties interpreted while the coordinated producer owns syntax.

use crate::declarations::{
    cpp_callable_identity_suffix, cpp_callable_is_structural_constructor,
    cpp_comparable_parameter_shapes, cpp_declarator_adds_indirection,
    cpp_macro_swallowed_access_label, extract_function_declarator, node_text,
};
use crate::graph::resolver::{
    cpp_declared_field_type_fact, cpp_type_name_components, declarator_name_node,
    declarator_names_function_type, parse_cpp_integer_literal as parse_integer_literal,
    structured_alias_type_target,
};
use brokk_bifrost_core::analyzer::cpp_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId,
};
use brokk_bifrost_core::analyzer::tree_walk::{ParentIndex, node_range};
use brokk_bifrost_core::analyzer::{CodeUnit, Range};
use brokk_bifrost_core::hash::HashMap;
use tree_sitter::{Node, Parser};

/// Parse one source snapshot into the expression-only projection used by RQL.
/// This helper is intentionally query-scoped: it owns no cross-file cache and
/// retains only the source arena and rows for this one file.
pub fn parse_cpp_expression_source_facts(
    source: &str,
) -> brokk_bifrost_core::analyzer::cpp_facts::CppExpressionSourceFacts {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("the linked tree-sitter-cpp grammar matches this tree-sitter version");
    let tree = parser.parse(source, None).expect("uncancelled C++ parse");
    let mut collector = PrimarySourceFactCollector::new(source);
    let named_record_sizes = named_record_size_index(tree.root_node(), source);
    let mut expressions = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_named() {
            let occurrence = collector.intern_node(node);
            if let Some(fact) =
                capture_expression_fact(node, source, occurrence, &named_record_sizes)
            {
                expressions.push(fact);
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    brokk_bifrost_core::analyzer::cpp_facts::CppExpressionSourceFacts {
        source: collector.finish(),
        expressions,
    }
}

/// Capture one expression-shaped row while the primary tree is live. The
/// caller has already selected the occurrence; this function only interprets
/// the selected AST node and never searches source text for syntax.
pub(crate) fn capture_expression_fact(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
    named_record_sizes: &HashMap<String, Option<u64>>,
) -> Option<CppExpressionFact> {
    match node.kind() {
        "number_literal" => {
            let literal_text = node_text(node, source).trim().to_owned();
            Some(
                CppExpressionFact::new(occurrence, CppExpressionKind::IntegerLiteral)
                    .with_literal(literal_text),
            )
        }
        "string_literal" | "raw_string_literal" => {
            let literal_text = node_text(node, source).trim().to_owned();
            Some(
                CppExpressionFact::new(occurrence, CppExpressionKind::StringLiteral)
                    .with_literal(literal_text),
            )
        }
        "parameter_declaration" => capture_parameter(node, source, occurrence, named_record_sizes),
        "field_declaration" => capture_bit_field(node, source, occurrence)
            .or_else(|| capture_function_signature(node, source, occurrence)),
        "enum_specifier" => capture_enum_definition(node, source, occurrence),
        "enumerator" => capture_enumerator(node, source, occurrence),
        "function_definition" | "declaration" => {
            capture_function_signature(node, source, occurrence)
        }
        "for_statement" | "for_range_loop" => capture_loop_variable(node, source, occurrence),
        "sizeof_expression" => capture_sizeof(node, source, occurrence),
        _ => None,
    }
}

trait CppExpressionFactBuilder {
    fn with_literal(self, literal: String) -> Self;
}

impl CppExpressionFactBuilder for CppExpressionFact {
    fn with_literal(mut self, literal: String) -> Self {
        self.integer_value = parse_integer_literal(&literal);
        self.literal_text = Some(literal);
        self.complete()
    }
}

fn capture_parameter(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
    named_record_sizes: &HashMap<String, Option<u64>>,
) -> Option<CppExpressionFact> {
    let declarator = node.child_by_field_name("declarator")?;
    let shape = declarator_shape(declarator, source);
    let (type_text, _type_form, signedness, width_bits) =
        type_properties(node.child_by_field_name("type"), source);
    let name = crate::structural::declarator_name_node(declarator)
        .map(|name| node_text(name, source).to_owned());
    let kind = if shape.has_array {
        CppExpressionKind::ArrayParameter
    } else {
        CppExpressionKind::FunctionParameter
    };
    let mut fact = CppExpressionFact::new(occurrence, kind);
    fact.name = name;
    fact.type_text = type_text;
    fact.type_form = shape.top;
    fact.signedness = signedness;
    fact.width_bits = width_bits;
    fact.array_extent = shape.array_extent;
    fact.array_is_reference = Some(shape.has_reference);
    fact.parameter_by_value = Some(!shape.has_reference);
    fact.member_function = Some(enclosing_member_function(node, declarator));
    let type_size = exact_parameter_type_size(node, source, named_record_sizes);
    fact.type_size_bytes = type_size;
    fact.type_size_exact = Some(type_size.is_some());
    if shape.has_array {
        Some(if shape.array_extent.is_some() {
            fact.complete()
        } else {
            fact.open("array extent is not a literal")
        })
    } else {
        Some(match type_size {
            Some(_) => fact.complete(),
            None => fact.open("parameter type size is not exact"),
        })
    }
}

fn capture_bit_field(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
) -> Option<CppExpressionFact> {
    let clause = named_child(node, "bitfield_clause")?;
    let width_node = clause
        .child_by_field_name("value")
        .or_else(|| clause.child_by_field_name("width"))
        .or_else(|| {
            let mut cursor = clause.walk();
            clause
                .named_children(&mut cursor)
                .find(|child| child.kind() == "number_literal")
        });
    let declarator = node.child_by_field_name("declarator");
    let name = declarator
        .and_then(crate::structural::declarator_name_node)
        .map(|name| node_text(name, source).to_owned());
    let name = name.filter(|name| !name.is_empty());
    let (type_text, type_form, signedness, width_bits) =
        type_properties(node.child_by_field_name("type"), source);
    let mut fact = CppExpressionFact::new(occurrence, CppExpressionKind::BitField);
    fact.name = name;
    fact.type_text = type_text;
    fact.type_form = type_form;
    fact.signedness = signedness;
    fact.width_bits = width_bits;
    fact.member_function =
        Some(declarator.is_some_and(|declarator| enclosing_member_function(node, declarator)));
    fact.bit_field_anonymous = Some(fact.name.is_none());
    fact.bit_field_width = width_node
        .map(|width| node_text(width, source))
        .and_then(parse_integer_literal)
        .and_then(|width| u64::try_from(width).ok());
    Some(match fact.bit_field_width {
        Some(_) => fact.complete(),
        None => fact.open("bit-field width is not a literal"),
    })
}

fn capture_enum_definition(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
) -> Option<CppExpressionFact> {
    let mut fact = CppExpressionFact::new(occurrence, CppExpressionKind::EnumDefinition);
    fact.name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source).to_owned());
    fact.enum_scoped = Some({
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .any(|child| matches!(child.kind(), "class" | "struct"))
    });
    Some(fact.complete())
}

fn capture_enumerator(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
) -> Option<CppExpressionFact> {
    let mut fact = CppExpressionFact::new(occurrence, CppExpressionKind::Enumerator);
    fact.name = node
        .child_by_field_name("name")
        .map(|name| node_text(name, source).to_owned())
        .or_else(|| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| child.kind() == "identifier")
                .map(|name| node_text(name, source).to_owned())
        });
    let value = node.child_by_field_name("value");
    fact.has_initializer = Some(value.is_some());
    fact.enum_value =
        value.and_then(|value| parse_integer_literal(node_text(value, source).trim()));
    fact.enum_has_implicit_before_nonreference = enum_has_implicit_before_nonreference(node);
    fact.enum_ordinal = node.parent().and_then(|parent| {
        let mut ordinal = 0u32;
        let mut cursor = parent.walk();
        for sibling in parent.named_children(&mut cursor) {
            if sibling.id() == node.id() {
                return Some(ordinal);
            }
            if sibling.kind() == "enumerator" {
                ordinal = ordinal.saturating_add(1);
            }
        }
        None
    });
    Some(if fact.name.is_some() {
        fact.complete()
    } else {
        fact.open("enumerator name is unavailable")
    })
}

fn capture_function_signature(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
) -> Option<CppExpressionFact> {
    let declarator = first_descendant_kind(node, "function_declarator")?;
    let (type_text, type_form, signedness, width_bits) =
        type_properties(node.child_by_field_name("type"), source);
    let mut fact = CppExpressionFact::new(occurrence, CppExpressionKind::FunctionSignature);
    fact.name = crate::structural::declarator_name_node(declarator)
        .map(|name| node_text(name, source).to_owned());
    fact.type_text = type_text;
    fact.type_form = type_form;
    fact.signedness = signedness;
    fact.width_bits = width_bits;
    fact.member_function = Some(enclosing_member_function(node, declarator));
    fact.return_top_level_const = Some(declaration_has_direct_const_qualifier(node, source));
    fact.member_function_const = Some(declaration_has_direct_const_qualifier(declarator, source));
    Some(fact.complete())
}

fn capture_loop_variable(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
) -> Option<CppExpressionFact> {
    let name = loop_binding_name(node, source);
    let type_node = node.child_by_field_name("type").or_else(|| {
        node.child_by_field_name("initializer")
            .and_then(|init| init.child_by_field_name("type"))
    });
    let (type_text, type_form, signedness, width_bits) = type_properties(type_node, source);
    let mut fact = CppExpressionFact::new(occurrence, CppExpressionKind::LoopVariable);
    fact.name = name;
    fact.type_text = type_text;
    fact.type_form = type_form;
    fact.signedness = signedness;
    fact.width_bits = width_bits;
    fact.loop_has_short_ancestor = fact
        .name
        .as_deref()
        .map(|_| has_short_loop_ancestor(node, source));
    Some(if fact.name.is_some() {
        fact.complete()
    } else {
        fact.open("loop binding name is unavailable")
    })
}

fn capture_sizeof(
    node: Node<'_>,
    source: &str,
    occurrence: SourceOccurrenceId,
) -> Option<CppExpressionFact> {
    let operand_kind = if node.child_by_field_name("type").is_some() {
        CppSizeofOperandKind::Type
    } else if node.child_by_field_name("value").is_some() {
        CppSizeofOperandKind::Expression
    } else {
        return Some(
            CppExpressionFact::new(occurrence, CppExpressionKind::SizeofExpression)
                .open("sizeof operand is unavailable"),
        );
    };
    let operand = node
        .child_by_field_name("value")
        .or_else(|| node.child_by_field_name("type"));
    let mut side_effect = false;
    let mut stack = operand.into_iter().collect::<Vec<_>>();
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "call_expression"
                | "assignment_expression"
                | "update_expression"
                | "new_expression"
                | "delete_expression"
                | "comma_expression"
        ) {
            side_effect = true;
            break;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    let mut fact = CppExpressionFact::new(occurrence, CppExpressionKind::SizeofExpression);
    fact.sizeof_operand_kind = Some(operand_kind);
    fact.sizeof_operand_is_parameter = sizeof_operand_is_parameter(node, operand, source);
    fact.sizeof_has_side_effect = Some(side_effect);
    Some(fact.complete())
}

fn enclosing_member_function(node: Node<'_>, declarator: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if matches!(
            current.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            return true;
        }
        ancestor = current.parent();
    }
    first_descendant_kind(declarator, "qualified_identifier")
        .and_then(|qualified| qualified.child_by_field_name("scope"))
        .is_some_and(|scope| first_descendant_kind(scope, "type_identifier").is_some())
}

fn enum_has_implicit_before_nonreference(node: Node<'_>) -> Option<bool> {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "enum_specifier" {
            let list = first_descendant_kind(current, "enumerator_list")?;
            let mut cursor = list.walk();
            let enumerators = list
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "enumerator")
                .collect::<Vec<_>>();
            let current_index = enumerators
                .iter()
                .position(|enumerator| enumerator.id() == node.id())?;
            if node.child_by_field_name("value").is_none()
                || current_index == 0
                || current_index + 1 >= enumerators.len()
            {
                return Some(false);
            }
            let mut implicit_before_nonreference = false;
            for (index, enumerator) in enumerators.iter().enumerate() {
                if enumerator.child_by_field_name("value").is_none()
                    && enumerators[index + 1..]
                        .iter()
                        .any(|later| later.child_by_field_name("value").is_some())
                {
                    implicit_before_nonreference = true;
                    break;
                }
            }
            return Some(implicit_before_nonreference);
        }
        ancestor = current.parent();
    }
    None
}

fn loop_binding_name(node: Node<'_>, source: &str) -> Option<String> {
    let binding = node.child_by_field_name("declarator").or_else(|| {
        node.child_by_field_name("initializer")
            .and_then(first_declaration_or_name)
    })?;
    let name = crate::structural::declarator_name_node(binding)?;
    Some(node_text(name, source).to_owned())
}

fn has_short_loop_ancestor(node: Node<'_>, source: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if matches!(current.kind(), "for_statement" | "for_range_loop")
            && loop_binding_name(current, source).is_some_and(|name| name.chars().count() == 1)
        {
            return true;
        }
        ancestor = current.parent();
    }
    false
}

fn sizeof_operand_is_parameter(
    node: Node<'_>,
    operand: Option<Node<'_>>,
    source: &str,
) -> Option<bool> {
    let operand = operand?;
    let name_node = if matches!(operand.kind(), "identifier" | "field_identifier") {
        Some(operand)
    } else {
        first_descendant_kind(operand, "identifier")
    }?;
    let name = node_text(name_node, source);
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "function_definition" {
            let mut stack = vec![current];
            while let Some(candidate) = stack.pop() {
                if candidate.kind() == "parameter_declaration"
                    && candidate
                        .child_by_field_name("declarator")
                        .and_then(crate::structural::declarator_name_node)
                        .is_some_and(|candidate_name| node_text(candidate_name, source) == name)
                {
                    return Some(true);
                }
                let mut cursor = candidate.walk();
                let children = candidate.named_children(&mut cursor).collect::<Vec<_>>();
                stack.extend(children.into_iter().rev());
            }
            return Some(false);
        }
        ancestor = current.parent();
    }
    None
}

fn exact_parameter_type_size(
    node: Node<'_>,
    source: &str,
    named_record_sizes: &HashMap<String, Option<u64>>,
) -> Option<u64> {
    // Only a scalar/by-value declarator has the size of its written type.
    // Pointer ABI size and adjusted array parameters are not known here;
    // references likewise carry no exact-size evidence in this projection.
    if node
        .child_by_field_name("declarator")
        .is_some_and(cpp_declarator_adds_indirection)
    {
        return None;
    }
    let type_node = node.child_by_field_name("type")?;
    let type_text = node_text(type_node, source).trim();
    match type_text {
        "char" | "signed char" | "unsigned char" => Some(1),
        _ if matches!(
            type_node.kind(),
            "type_identifier" | "qualified_identifier" | "scoped_type_identifier"
        ) =>
        {
            named_record_sizes.get(type_text).copied().flatten()
        }
        _ => None,
    }
}

pub(crate) fn named_record_size_index(
    root: Node<'_>,
    source: &str,
) -> HashMap<String, Option<u64>> {
    let mut sizes = HashMap::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) && node.child_by_field_name("name").is_some()
        {
            let name = node
                .child_by_field_name("name")
                .expect("record name was checked above");
            let name = node_text(name, source).trim();
            if !name.is_empty() {
                sizes
                    .entry(name.to_owned())
                    .or_insert_with(|| exact_char_record_size(node, source));
            }
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    sizes
}

fn exact_char_record_size(record: Node<'_>, source: &str) -> Option<u64> {
    let fields = first_descendant_kind(record, "field_declaration_list")?;
    let mut cursor = fields.walk();
    let declarations = fields
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "field_declaration")
        .collect::<Vec<_>>();
    if declarations.is_empty() {
        return None;
    }
    let mut size = 0u64;
    for field in declarations {
        if named_child(field, "bitfield_clause").is_some() {
            return None;
        }
        let type_node = field.child_by_field_name("type")?;
        let type_text = node_text(type_node, source).trim();
        if !matches!(type_text, "char" | "signed char" | "unsigned char") {
            return None;
        }
        let mut cursor = field.walk();
        let mut declarators = field
            .children_by_field_name("declarator", &mut cursor)
            .peekable();
        declarators.peek()?;
        for declarator in declarators {
            let shape = declarator_shape(declarator, source);
            let field_size = if shape.has_array {
                shape.array_extent?
            } else if shape.top == CppTypeForm::Unknown {
                1
            } else {
                return None;
            };
            size = if record.kind() == "union_specifier" {
                size.max(field_size)
            } else {
                size.checked_add(field_size)?
            };
        }
    }
    Some(size)
}

fn named_child<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn first_descendant_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            return Some(current);
        }
        let mut cursor = current.walk();
        let children = current.named_children(&mut cursor).collect::<Vec<_>>();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn first_declaration_or_name(node: Node<'_>) -> Option<Node<'_>> {
    if matches!(node.kind(), "declaration" | "parameter_declaration") {
        return node.child_by_field_name("declarator");
    }
    if matches!(
        node.kind(),
        "identifier" | "field_identifier" | "reference_declarator" | "array_declarator"
    ) {
        return Some(node);
    }
    first_descendant_kind(node, "declaration")
        .and_then(|declaration| declaration.child_by_field_name("declarator"))
        .or_else(|| first_descendant_kind(node, "identifier"))
}

struct DeclaratorShape {
    top: CppTypeForm,
    has_array: bool,
    has_reference: bool,
    array_extent: Option<u64>,
}

fn declarator_shape(declarator: Node<'_>, source: &str) -> DeclaratorShape {
    let mut current = Some(declarator);
    let mut top = CppTypeForm::Unknown;
    let mut has_array = false;
    let mut has_reference = false;
    let mut array_extent = None;
    while let Some(node) = current {
        match node.kind() {
            "pointer_declarator" => {
                if top == CppTypeForm::Unknown {
                    top = CppTypeForm::Pointer;
                }
                current = node.child_by_field_name("declarator");
            }
            "reference_declarator" => {
                has_reference = true;
                if top == CppTypeForm::Unknown {
                    top = CppTypeForm::Reference;
                }
                current = node
                    .child_by_field_name("declarator")
                    .or_else(|| node.named_child(0));
            }
            "array_declarator" => {
                has_array = true;
                if top == CppTypeForm::Unknown {
                    top = CppTypeForm::Array;
                }
                array_extent = node
                    .child_by_field_name("size")
                    .or_else(|| node.child_by_field_name("value"))
                    .and_then(|size| parse_integer_literal(node_text(size, source)))
                    .and_then(|size| u64::try_from(size).ok());
                current = node.child_by_field_name("declarator");
            }
            "function_declarator" => {
                if top == CppTypeForm::Unknown {
                    top = CppTypeForm::Function;
                }
                current = node.child_by_field_name("declarator");
            }
            "init_declarator" | "parenthesized_declarator" | "attributed_declarator" => {
                current = node
                    .child_by_field_name("declarator")
                    .or_else(|| node.named_child(0));
            }
            _ => current = None,
        }
    }
    DeclaratorShape {
        top,
        has_array,
        has_reference,
        array_extent,
    }
}

fn type_properties(
    type_node: Option<Node<'_>>,
    source: &str,
) -> (Option<String>, CppTypeForm, CppSignedness, Option<u16>) {
    let Some(type_node) = type_node else {
        return (None, CppTypeForm::Unknown, CppSignedness::Unknown, None);
    };
    let text = node_text(type_node, source).trim().to_owned();
    let kind = type_node.kind();
    let builtin = matches!(kind, "primitive_type" | "sized_type_specifier")
        || matches!(
            text.as_str(),
            "bool"
                | "char"
                | "signed char"
                | "unsigned char"
                | "short"
                | "short int"
                | "unsigned short"
                | "unsigned short int"
                | "int"
                | "unsigned"
                | "unsigned int"
                | "long"
                | "long int"
                | "unsigned long"
                | "unsigned long int"
                | "long long"
                | "long long int"
                | "unsigned long long"
                | "unsigned long long int"
        );
    let type_form = if builtin {
        CppTypeForm::Builtin
    } else if matches!(
        kind,
        "type_identifier"
            | "qualified_identifier"
            | "scoped_type_identifier"
            | "template_type"
            | "enum_specifier"
    ) {
        CppTypeForm::Named
    } else {
        CppTypeForm::Unknown
    };
    let signedness = if text.split_whitespace().any(|part| part == "unsigned") {
        CppSignedness::Unsigned
    } else if text.split_whitespace().any(|part| part == "signed") {
        CppSignedness::Signed
    } else if builtin
        && matches!(
            text.as_str(),
            "char" | "int" | "short" | "long" | "long long"
        )
    {
        CppSignedness::Ambiguous
    } else {
        CppSignedness::Unknown
    };
    let width_bits = match text.as_str() {
        "bool" => Some(1),
        "char" | "signed char" | "unsigned char" => Some(8),
        "short" | "short int" | "signed short" | "signed short int" | "unsigned short"
        | "unsigned short int" => Some(16),
        "int" | "signed int" | "unsigned" | "unsigned int" => Some(32),
        "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "unsigned long long"
        | "unsigned long long int" => Some(64),
        _ => None,
    };
    (Some(text), type_form, signedness, width_bits)
}

fn declaration_has_direct_const_qualifier(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "type_qualifier" && node_text(child, source).trim() == "const")
}

/// Parse the bounded C++ statement rows used by the statement-fact RQL
/// relation. This is query-lifetime data; it owns no cross-file state.
pub fn parse_statement_fact_rows(source: &str) -> StatementFactRows {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("the linked tree-sitter-cpp grammar matches this tree-sitter version");
    let tree = parser.parse(source, None).expect("uncancelled C++ parse");
    brokk_bifrost_core::analyzer::statement_facts::producer::capture_statement_facts(
        &crate::structural::CPP_STRUCTURAL_SPEC,
        tree.root_node(),
        source,
    )
}

/// Parse one source snapshot into the class and exception projection used by
/// RQL. The rows are query-lifetime and own no cross-file state.
pub fn parse_cpp_class_fact_rows(source: &str) -> CppClassFactRows {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .expect("the linked tree-sitter-cpp grammar matches this tree-sitter version");
    let tree = parser.parse(source, None).expect("uncancelled C++ parse");
    let root = tree.root_node();
    let ancestry = ParentIndex::new(root);
    let mut rows = CppClassFactRows::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_named() {
            capture_class_fact_rows(node, source, &ancestry, &mut rows);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    rows
}

pub(crate) fn base_specifier_from_node(
    node: Node<'_>,
    source: &str,
    is_virtual: bool,
    access: CppAccessSpecifier,
) -> Option<CppBaseSpecifierFact> {
    let components = cpp_type_name_components(node, source)?;
    base_specifier_fact(node, components, is_virtual, access)
}

pub(crate) fn base_specifier_fact(
    node: Node<'_>,
    components: Vec<String>,
    is_virtual: bool,
    access: CppAccessSpecifier,
) -> Option<CppBaseSpecifierFact> {
    (!components.is_empty()).then_some(CppBaseSpecifierFact {
        absolute: node.child(0).is_some_and(|token| token.kind() == "::"),
        components,
        is_virtual,
        access,
    })
}

pub(crate) fn declaration_name<'tree>(
    node: Node<'tree>,
    unit: &CodeUnit,
    source: &str,
) -> Option<Node<'tree>> {
    if let Some(name) = node.child_by_field_name("name") {
        return crate::structural::declarator_name_node(name);
    }
    let mut cursor = node.walk();
    node.children_by_field_name("declarator", &mut cursor)
        .find_map(|declarator| {
            let name = crate::structural::declarator_name_node(declarator)?;
            (node_text(name, source) == unit.identifier()).then_some(name)
        })
}

/// Capture the structured type properties of one field declaration while its
/// declaration AST is still available.
pub(crate) fn capture_field_type(
    node: Node<'_>,
    field_name: &str,
    source: &str,
) -> (Option<CppDeclaredFieldTypeFact>, bool) {
    if let Some(recovered) = crate::declarations::recovered_pyobject_head_field(node, source)
        && node_text(recovered.name, source) == field_name
    {
        return (
            Some(CppDeclaredFieldTypeFact {
                type_text: node_text(recovered.type_node, source).to_owned(),
                indirection: recovered.pointer_depth(),
                binds_indirectly: recovered.pointer_depth() > 0,
                template_arguments: None,
            }),
            false,
        );
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return (None, false);
    };
    let mut cursor = node.walk();
    let declarator = node
        .children_by_field_name("declarator", &mut cursor)
        .find(|declarator| {
            crate::structural::declarator_name_node(*declarator)
                .is_some_and(|name| node_text(name, source) == field_name)
        });
    let names_function_type = declarator.is_some_and(declarator_names_function_type);
    let field_type = cpp_declared_field_type_fact(node, type_node, field_name, source);
    (field_type, names_function_type)
}

/// Capture one `namespace name = target;` definition while the primary tree is
/// live. The target path, the enclosing namespaces and the guard environment
/// come from the same structured helpers that using declarations use.
pub(crate) fn capture_namespace_alias(
    node: Node<'_>,
    source: &str,
    ancestry: &ParentIndex<'_>,
    namespaces: &crate::graph::resolver::OrphanedNamespaceScopeIndex,
    collector: &mut PrimarySourceFactCollector<'_>,
) -> Option<CppNamespaceAliasFact> {
    if node.kind() != "namespace_alias_definition" {
        return None;
    }
    let name = node.child_by_field_name("name")?;
    let mut cursor = node.walk();
    let target = node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "namespace_identifier" | "nested_namespace_specifier" | "splice_specifier"
        ) && child.id() != name.id()
    })?;
    let block = std::iter::successors(ancestry.parent(node), |current| ancestry.parent(*current))
        .take_while(|current| {
            !matches!(current.kind(), "namespace_definition" | "translation_unit")
        })
        .find(|current| current.kind() == "compound_statement");
    Some(CppNamespaceAliasFact {
        occurrence: collector.intern_node(node),
        name: node_text(name, source).to_owned(),
        target: crate::graph::resolver::cpp_name_component_nodes(target)
            .filter(|components| !components.is_empty())
            .map(|components| {
                components
                    .into_iter()
                    .map(|component| node_text(component, source).to_owned())
                    .collect()
            }),
        target_global: target.child(0).is_some_and(|child| child.kind() == "::"),
        namespace: namespaces.enclosing_namespace_components(node, source),
        block: block.map(|block| collector.intern_node(block)),
        guards: crate::graph::resolver::binding_site_guards(node, source)
            .as_ref()
            .map(crate::source_context::cpp_guard_set_from_runtime),
    })
}

pub(crate) fn capture_declaration(
    declaration: SourceDeclarationId,
    node: Node<'_>,
    unit: &CodeUnit,
    source: &str,
    ancestry: &ParentIndex<'_>,
) -> CppDeclarationSourceFact {
    let mut fact = CppDeclarationSourceFact::new(declaration);
    if matches!(node.kind(), "alias_declaration" | "type_definition")
        && crate::graph::resolver::alias_has_visible_file_scope(node)
        && let Some(name) = declaration_name(node, unit, source)
        && let Some(name) =
            crate::graph::resolver::normalize_reference_name(node_text(name, source))
        && let Some(target) = node.child_by_field_name("type")
        && let Some(target) =
            crate::graph::resolver::normalize_reference_name(node_text(target, source))
    {
        fact.file_scope_alias = Some(CppFileScopeAliasFact {
            name,
            target,
            namespace: crate::graph::resolver::enclosing_namespace_context(node, source),
        });
    }
    let mut owners = Vec::new();
    let mut current = ancestry.parent(node);
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "namespace_definition"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            owners.push(node_text(name, source).to_owned());
        }
        current = ancestry.parent(parent);
    }
    owners.reverse();
    owners.push(unit.identifier().to_owned());
    fact.lexical_path = owners;
    // A function-local class and its members are scoped by their callable
    // and block, which the written class chain alone cannot spell: it would
    // give a local `Widget` the path of a global one. Their structured
    // identity is that scope, so the path follows it.
    if crate::graph::resolver::is_function_local_unit(unit) {
        let interner = brokk_bifrost_core::analyzer::fq_name::segment_interner();
        fact.lexical_path = unit
            .fq()
            .segments()
            .iter()
            .map(|&segment| interner.resolve(segment).0.to_owned())
            .collect();
    }
    if matches!(
        node.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
    ) {
        fact.class_strength = if node.child_by_field_name("body").is_some() {
            CppClassDeclarationStrength::Full
        } else {
            CppClassDeclarationStrength::Forward
        };
        if node.kind() == "enum_specifier" {
            let mut cursor = node.walk();
            fact.enum_kind = if node
                .children(&mut cursor)
                .any(|child| matches!(child.kind(), "class" | "struct"))
            {
                CppEnumOwnerKind::Scoped
            } else {
                CppEnumOwnerKind::Unscoped
            };
        }
        let mut cursor = node.walk();
        for base_clause in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "base_class_clause")
        {
            let mut is_virtual = false;
            let mut cursor = base_clause.walk();
            for child in base_clause.children(&mut cursor) {
                match child.kind() {
                    "," => is_virtual = false,
                    "virtual" => is_virtual = true,
                    "type_identifier"
                    | "qualified_identifier"
                    | "scoped_type_identifier"
                    | "template_type" => {
                        if let Some(base) = base_specifier_from_node(
                            child,
                            source,
                            is_virtual,
                            base_access_specifier(base_clause, child, node.kind()),
                        ) {
                            fact.bases.push(base);
                        }
                        is_virtual = false;
                    }
                    _ => {}
                }
            }
        }
    }
    let mut cursor = node.walk();
    let declarator = node
        .children_by_field_name("declarator", &mut cursor)
        .find(|declarator| {
            crate::structural::declarator_name_node(*declarator)
                .is_some_and(|name| node_text(name, source) == unit.identifier())
        });
    if unit.is_function() {
        let callable = if node.kind() == "function_declarator" {
            Some(node)
        } else {
            node.child_by_field_name("declarator")
        };
        if let Some(declarator) = callable {
            if let Some(name) = declarator_name_node(declarator)
                && let Some(mut components) = cpp_type_name_components(name, source)
            {
                components.pop();
                fact.written_owner = components;
            }
            let mut chain = Some(declarator);
            while let Some(current) = chain {
                if current.kind() == "function_declarator" {
                    fact.callable_comparable_shapes =
                        Some(cpp_comparable_parameter_shapes(current, source, ancestry));
                    fact.callable_identity_suffix = cpp_callable_identity_suffix(current, source);
                    fact.callable_is_constructor =
                        cpp_callable_is_structural_constructor(current, source, ancestry);
                    fact.callable_is_deduction_guide =
                        cpp_callable_is_deduction_guide(node, current, unit, source);
                    fact.callable_is_template = ancestry.parent(node).is_some_and(|parent| {
                        parent.kind() == "template_declaration"
                            && parent
                                .named_child(parent.named_child_count().saturating_sub(1))
                                .is_some_and(|declaration| declaration.id() == node.id())
                    });
                    // Only identity qualifiers participate in overload hiding.
                    // The declarator can also contain override/final specifiers.
                    fact.trailing_qualifiers =
                        fact.callable_identity_suffix.clone().unwrap_or_default();
                    break;
                }
                chain = current.child_by_field_name("declarator");
            }
        }
    }
    if unit.is_field() {
        let (field_type, names_function_type) = capture_field_type(node, unit.identifier(), source);
        fact.field_type = field_type;
        fact.names_function_type = names_function_type;
    }
    let alias_type = if matches!(node.kind(), "alias_declaration" | "type_definition") {
        node.child_by_field_name("type")
    } else if unit.is_class() {
        crate::declarations::recovered_alias_type_node(node, unit.identifier(), source)
    } else {
        None
    };
    if let Some(alias_type) = alias_type {
        let alias_declarator = if node.kind() == "type_definition" {
            declarator
        } else {
            alias_type.child_by_field_name("declarator")
        };
        fact.names_function_type = alias_declarator.is_some_and(declarator_names_function_type);
        fact.adds_indirection = alias_declarator.is_some_and(cpp_declarator_adds_indirection);
        if !fact.names_function_type {
            fact.alias_target = structured_alias_type_target(alias_type, source);
            let mut target = alias_type;
            while target.kind() == "type_descriptor" {
                let Some(inner) = target.child_by_field_name("type") else {
                    break;
                };
                target = inner;
            }
            if matches!(
                target.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            ) && let Some(name) = target.child_by_field_name("name")
            {
                target = name;
            }
            fact.alias_target_text = Some(node_text(target, source).to_owned());
        }
    }
    fact
}

/// Add the class and exception rows whose meaning lives below a declaration
/// node. This is called by the primary iterative walk, while the tree and its
/// parent index are still owned by the producer.
pub(crate) fn capture_class_fact_rows(
    node: Node<'_>,
    source: &str,
    ancestry: &ParentIndex<'_>,
    rows: &mut CppClassFactRows,
) {
    match node.kind() {
        "class_specifier" | "struct_specifier" | "union_specifier" => {
            let mut path = enclosing_owner_path(node, ancestry, source);
            if let Some(name) = node.child_by_field_name("name") {
                path.push(node_text(name, source).to_owned());
            }
            let is_interface = node
                .child_by_field_name("body")
                .is_some_and(|body| tree_contains_pure_virtual(body, source));
            rows.classes.push(CppClassFact {
                range: node_range(node),
                path,
                is_interface,
            });
        }
        "function_definition" | "declaration" | "field_declaration" => {
            if let Some(member) = capture_member_fact(node, source, ancestry) {
                rows.members.push(member);
            }
        }
        "catch_clause" => {
            rows.catches.push(capture_catch_fact(node, source));
        }
        "throw_statement" => {
            rows.throws.push(capture_throw_fact(node, source));
        }
        _ => {}
    }
}

fn capture_member_fact(
    node: Node<'_>,
    source: &str,
    ancestry: &ParentIndex<'_>,
) -> Option<CppMemberFact> {
    let function_declarator = extract_function_declarator(node)?;
    let name_node = declarator_name_node(function_declarator)?;
    let name = node_text(name_node, source).to_owned();
    let mut owner = enclosing_owner_path(node, ancestry, source);
    let written_owner = cpp_type_name_components(name_node, source)
        .map(|mut components| {
            components.pop();
            components
        })
        .unwrap_or_default();
    append_owner_components(&mut owner, &written_owner);
    let owner_name = owner.last().map(String::as_str);
    let role = if name == "operator=" {
        CppMemberRole::AssignmentOperator
    } else if name.strip_prefix('~').is_some() {
        CppMemberRole::Destructor
    } else if owner_name == Some(name.as_str()) {
        CppMemberRole::Constructor
    } else {
        CppMemberRole::Method
    };
    let (copy_parameter, move_parameter, remaining_parameters_defaulted) =
        callable_parameter_shape(function_declarator, source, ancestry, owner_name);
    let special_member = match role {
        CppMemberRole::Destructor => CppSpecialMemberKind::Destructor,
        CppMemberRole::Constructor if copy_parameter => CppSpecialMemberKind::CopyConstructor,
        CppMemberRole::Constructor if move_parameter => CppSpecialMemberKind::MoveConstructor,
        CppMemberRole::Constructor if function_parameter_count(function_declarator) == 0 => {
            CppSpecialMemberKind::DefaultConstructor
        }
        CppMemberRole::AssignmentOperator if copy_parameter => CppSpecialMemberKind::CopyAssignment,
        CppMemberRole::AssignmentOperator if move_parameter => CppSpecialMemberKind::MoveAssignment,
        _ => CppSpecialMemberKind::None,
    };
    let state = if tree_contains_kind(node, "delete_method_clause") {
        CppSpecialMemberState::Deleted
    } else if tree_contains_kind(node, "default_method_clause") {
        CppSpecialMemberState::Defaulted
    } else {
        CppSpecialMemberState::Declared
    };
    let access = member_access_specifier(node, source, ancestry);
    let assignment_return = if role == CppMemberRole::AssignmentOperator {
        assignment_return_shape(node, source, owner_name)
    } else {
        CppAssignmentReturnShape::Unknown
    };
    let initializer_target = if role == CppMemberRole::Constructor {
        constructor_initializer_target(node, source, owner_name)
    } else {
        None
    };
    let delegation_calls = if role == CppMemberRole::Constructor {
        constructor_delegation_calls(node, source, ancestry, owner_name)
    } else {
        Vec::new()
    };
    Some(CppMemberFact {
        range: node_range(node),
        owner,
        name,
        role,
        special_member,
        state,
        access,
        copy_parameter,
        remaining_parameters_defaulted,
        assignment_return,
        initializer_target,
        delegation_calls,
        pure_virtual: tree_contains_pure_virtual(node, source),
    })
}

fn capture_catch_fact(node: Node<'_>, source: &str) -> CppCatchFact {
    let parameter = node
        .child_by_field_name("parameters")
        .and_then(|parameters| parameters.named_child(0));
    let type_node = parameter.and_then(|parameter| parameter.child_by_field_name("type"));
    let declarator = parameter.and_then(|parameter| parameter.child_by_field_name("declarator"));
    let value_category = declarator
        .map(classify_parameter_declarator)
        .unwrap_or(CppParameterValueCategory::Value);
    let type_name = type_node
        .and_then(|type_node| cpp_type_name_components(type_node, source))
        .unwrap_or_default();
    let class_type = type_node.is_some_and(|type_node| {
        !matches!(
            type_node.kind(),
            "primitive_type" | "sized_type_specifier" | "auto" | "decltype"
        )
    });
    CppCatchFact {
        range: node_range(node),
        value_category,
        type_name,
        class_type,
    }
}

fn capture_throw_fact(node: Node<'_>, source: &str) -> CppThrowFact {
    let expression = node.named_child(0);
    let (operand_shape, thrown_type) = match expression {
        None => (CppThrowOperandShape::Rethrow, Vec::new()),
        Some(expression) if expression.kind() == "new_expression" => (
            CppThrowOperandShape::Pointer,
            expression
                .child_by_field_name("type")
                .and_then(|type_node| cpp_type_name_components(type_node, source))
                .unwrap_or_default(),
        ),
        Some(_) => (CppThrowOperandShape::Value, Vec::new()),
    };
    CppThrowFact {
        range: node_range(node),
        operand_shape,
        thrown_type,
    }
}

fn function_parameter_count(function: Node<'_>) -> usize {
    function
        .child_by_field_name("parameters")
        .map_or(0, |parameters| parameters.named_child_count())
}

fn callable_parameter_shape(
    function: Node<'_>,
    source: &str,
    ancestry: &ParentIndex<'_>,
    owner_name: Option<&str>,
) -> (bool, bool, bool) {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return (false, false, true);
    };
    let parameter_nodes: Vec<_> = parameters.named_children(&mut parameters.walk()).collect();
    let remaining_parameters_defaulted = parameter_nodes.len() > 1
        && parameter_nodes
            .iter()
            .skip(1)
            .all(|parameter| parameter.child_by_field_name("default_value").is_some());
    let Some(first) = parameter_nodes.first().copied() else {
        return (false, false, remaining_parameters_defaulted);
    };
    let Some(_type_node) = first.child_by_field_name("type") else {
        return (false, false, remaining_parameters_defaulted);
    };
    let Some(owner_name) = owner_name else {
        return (false, false, remaining_parameters_defaulted);
    };
    let comparable = cpp_comparable_parameter_shapes(function, source, ancestry);
    let Some(CppComparableSlot::Shape(parameter)) = comparable.first() else {
        return (false, false, remaining_parameters_defaulted);
    };
    let reference = match parameter.node(parameter.root()) {
        CppComparableNode::Reference { inner } => Some(*inner),
        _ => None,
    };
    let Some(inner) = reference else {
        return (false, false, remaining_parameters_defaulted);
    };
    let CppComparableNode::Named { name, .. } = parameter.node(inner) else {
        return (false, false, remaining_parameters_defaulted);
    };
    let same_owner = name.path().last().is_some_and(|name| name == owner_name);
    if !same_owner {
        return (false, false, remaining_parameters_defaulted);
    }
    let rvalue = first
        .child_by_field_name("declarator")
        .is_some_and(|declarator| declarator_contains_rvalue_reference(declarator));
    let copy = !rvalue;
    let move_parameter = rvalue;
    (copy, move_parameter, remaining_parameters_defaulted)
}

fn declarator_contains_rvalue_reference(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if crate::declarations::reference_declarator_is_rvalue(current) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn classify_parameter_declarator(node: Node<'_>) -> CppParameterValueCategory {
    if declarator_contains_rvalue_reference(node) {
        CppParameterValueCategory::RValueReference
    } else {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current.kind() == "reference_declarator" {
                return CppParameterValueCategory::LValueReference;
            }
            if current.kind() == "pointer_declarator" {
                return CppParameterValueCategory::Pointer;
            }
            let mut cursor = current.walk();
            stack.extend(current.named_children(&mut cursor));
        }
        CppParameterValueCategory::Value
    }
}

fn assignment_return_shape(
    node: Node<'_>,
    source: &str,
    owner_name: Option<&str>,
) -> CppAssignmentReturnShape {
    let mut current = node.child_by_field_name("declarator");
    let mut reference = false;
    let mut pointer = false;
    while let Some(declarator) = current {
        reference |= declarator.kind() == "reference_declarator";
        pointer |= declarator.kind() == "pointer_declarator";
        current = declarator.child_by_field_name("declarator");
    }
    if !reference {
        return if pointer {
            CppAssignmentReturnShape::Unknown
        } else {
            CppAssignmentReturnShape::Value
        };
    }
    let return_type = node.child_by_field_name("type");
    if owner_name.is_some_and(|owner| {
        return_type
            .and_then(|type_node| cpp_type_name_components(type_node, source))
            .and_then(|components| components.last().cloned())
            .is_some_and(|name| name == owner)
    }) {
        CppAssignmentReturnShape::ReferenceToThis
    } else {
        CppAssignmentReturnShape::ReferenceOther
    }
}

fn constructor_initializer_target(
    node: Node<'_>,
    source: &str,
    owner_name: Option<&str>,
) -> Option<Vec<String>> {
    let owner_name = owner_name?;
    let mut cursor = node.walk();
    let initializer_list = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "field_initializer_list")?;
    let mut cursor = initializer_list.walk();
    initializer_list
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "field_initializer")
        .find_map(|initializer| {
            let name = initializer
                .child_by_field_name("name")
                .or_else(|| initializer.child_by_field_name("field"))
                .or_else(|| {
                    let mut cursor = initializer.walk();
                    initializer.named_children(&mut cursor).find(|child| {
                        matches!(
                            child.kind(),
                            "field_identifier"
                                | "type_identifier"
                                | "qualified_identifier"
                                | "scoped_type_identifier"
                        )
                    })
                })?;
            let components = cpp_type_name_components(name, source)?;
            components
                .last()
                .is_some_and(|component| component == owner_name)
                .then_some(components)
        })
}

fn constructor_delegation_calls(
    node: Node<'_>,
    source: &str,
    ancestry: &ParentIndex<'_>,
    owner_name: Option<&str>,
) -> Vec<Range> {
    let Some(owner_name) = owner_name else {
        return Vec::new();
    };
    let Some(body) = node.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut stack = vec![body];
    let mut calls = Vec::new();
    while let Some(current) = stack.pop() {
        if current.kind() == "call_expression"
            && ancestry
                .parent(current)
                .is_some_and(|parent| parent.kind() == "expression_statement")
            && let Some(function) = current.child_by_field_name("function")
            && function.kind() == "identifier"
            && node_text(function, source) == owner_name
        {
            calls.push(node_range(current));
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    calls
}

fn enclosing_owner_path(node: Node<'_>, ancestry: &ParentIndex<'_>, source: &str) -> Vec<String> {
    let mut owners = Vec::new();
    let mut current = ancestry.parent(node);
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "namespace_definition"
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            owners.push(node_text(name, source).to_owned());
        }
        current = ancestry.parent(parent);
    }
    owners.reverse();
    owners
}

fn append_owner_components(owner: &mut Vec<String>, written: &[String]) {
    let overlap = (0..=owner.len().min(written.len()))
        .rev()
        .find(|length| owner[owner.len().saturating_sub(*length)..] == written[..*length])
        .unwrap_or(0);
    owner.extend(written[overlap..].iter().cloned());
}

fn member_access_specifier(
    node: Node<'_>,
    source: &str,
    ancestry: &ParentIndex<'_>,
) -> CppAccessSpecifier {
    let mut current = ancestry.parent(node);
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) {
            let default = if parent.kind() == "class_specifier" {
                CppAccessSpecifier::Private
            } else {
                CppAccessSpecifier::Public
            };
            let Some(body) = parent.child_by_field_name("body") else {
                return CppAccessSpecifier::Unknown;
            };
            let mut access = default;
            let mut cursor = body.walk();
            for child in body.named_children(&mut cursor) {
                if child.start_byte() >= node.start_byte() {
                    break;
                }
                if child.kind() == "access_specifier" {
                    access = match child.child(0).map(|keyword| keyword.kind()) {
                        Some("public") => CppAccessSpecifier::Public,
                        Some("protected") => CppAccessSpecifier::Protected,
                        Some("private") => CppAccessSpecifier::Private,
                        _ => CppAccessSpecifier::Unknown,
                    };
                } else if let Some(label) = cpp_macro_swallowed_access_label(child, source) {
                    access = match label.access {
                        "public" => CppAccessSpecifier::Public,
                        "protected" => CppAccessSpecifier::Protected,
                        _ => CppAccessSpecifier::Private,
                    };
                }
            }
            return access;
        }
        current = ancestry.parent(parent);
    }
    CppAccessSpecifier::Unknown
}

pub(crate) fn base_access_specifier(
    clause: Node<'_>,
    base: Node<'_>,
    class_kind: &str,
) -> CppAccessSpecifier {
    let default = if matches!(class_kind, "struct_specifier" | "union_specifier") {
        CppAccessSpecifier::Public
    } else {
        CppAccessSpecifier::Private
    };
    let mut access = default;
    let mut cursor = clause.walk();
    for child in clause.children(&mut cursor) {
        if child.start_byte() >= base.start_byte() {
            break;
        }
        if child.kind() == "," {
            access = default;
        } else if child.kind() == "access_specifier" {
            access = match child.child(0).map(|keyword| keyword.kind()) {
                Some("public") => CppAccessSpecifier::Public,
                Some("protected") => CppAccessSpecifier::Protected,
                Some("private") => CppAccessSpecifier::Private,
                _ => CppAccessSpecifier::Unknown,
            };
        }
    }
    access
}

fn tree_contains_kind(node: Node<'_>, kind: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == kind {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn tree_contains_pure_virtual(node: Node<'_>, source: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "field_declaration"
            && current
                .child_by_field_name("default_value")
                .is_some_and(|value| {
                    value.kind() == "number_literal" && node_text(value, source).trim() == "0"
                })
            && current
                .child_by_field_name("declarator")
                .and_then(extract_function_declarator)
                .is_some()
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    tree_contains_kind(node, "pure_virtual_clause")
}

fn cpp_callable_is_deduction_guide(
    declaration: Node<'_>,
    function_declarator: Node<'_>,
    unit: &CodeUnit,
    source: &str,
) -> bool {
    if declaration.kind() != "declaration"
        || declaration.child_by_field_name("type").is_some()
        || function_declarator.kind() != "function_declarator"
    {
        return false;
    }
    let mut cursor = function_declarator.walk();
    function_declarator
        .named_children(&mut cursor)
        .any(|child| child.kind() == "trailing_return_type")
        && declarator_name_node(function_declarator)
            .is_some_and(|name| node_text(name, source) == unit.identifier())
}

/// One mounted, generation-selected canonical declaration family.
#[derive(Debug, Clone)]
pub struct CppFileSourceFacts {
    pub source: brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
    pub facts: CppSourceFacts,
    pub declaration_units: brokk_bifrost_core::hash::HashMap<SourceDeclarationId, Vec<CodeUnit>>,
    by_unit: brokk_bifrost_core::hash::HashMap<CodeUnit, Vec<usize>>,
}

impl CppFileSourceFacts {
    pub fn new(
        source: brokk_bifrost_core::analyzer::source_facts::SourceFactRows,
        facts: CppSourceFacts,
        declaration_units: brokk_bifrost_core::hash::HashMap<SourceDeclarationId, Vec<CodeUnit>>,
    ) -> Self {
        assert!(
            facts.valid_links(&source),
            "invalid C++ canonical source links"
        );
        let mut by_unit: brokk_bifrost_core::hash::HashMap<_, Vec<_>> = Default::default();
        for (index, fact) in facts.declarations.iter().enumerate() {
            if let Some(units) = declaration_units.get(&fact.declaration) {
                for unit in units {
                    by_unit.entry(unit.clone()).or_default().push(index);
                }
            }
        }
        Self {
            source,
            facts,
            declaration_units,
            by_unit,
        }
    }

    pub fn for_unit(&self, unit: &CodeUnit) -> impl Iterator<Item = &CppDeclarationSourceFact> {
        self.by_unit
            .get(unit)
            .into_iter()
            .flatten()
            .map(|index| &self.facts.declarations[*index])
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        self.source.estimated_bytes()
            + self.facts.estimated_retained_bytes()
            + self
                .declaration_units
                .values()
                .map(|units| units.capacity() * std::mem::size_of::<CodeUnit>())
                .sum::<usize>()
            + self
                .by_unit
                .values()
                .map(|indices| indices.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>()
    }
}

/// One source-backed navigation alternative for a mounted declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CppNavigationOccurrence {
    pub range: brokk_bifrost_core::analyzer::Range,
    pub role: CppOccurrenceRole,
    pub conditional_family: Option<(usize, usize)>,
}

/// Canonical declaration context with IDs resolved in its own dialect arena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppDeclarationOccurrence {
    pub fact: CppDeclarationSourceFact,
    pub range: brokk_bifrost_core::analyzer::Range,
    pub name_range: Option<brokk_bifrost_core::analyzer::Range>,
    pub exhaustive_family: Option<(usize, usize)>,
    pub displaced_namespace_closing_brace: Option<usize>,
}

impl CppFileSourceFacts {
    pub fn declaration_occurrences(&self, unit: &CodeUnit) -> Vec<CppDeclarationOccurrence> {
        self.for_unit(unit)
            .map(|fact| {
                let declaration = self.source.declaration(fact.declaration);
                CppDeclarationOccurrence {
                    range: self.source.occurrence(declaration.occurrence).range,
                    name_range: declaration.name.map(|id| self.source.occurrence(id).range),
                    exhaustive_family: fact.exhaustive_conditional_family.map(|id| {
                        let range = self.source.occurrence(id).range;
                        (range.start_byte, range.end_byte)
                    }),
                    displaced_namespace_closing_brace: fact
                        .displaced_namespace_closing_brace
                        .map(|id| self.source.occurrence(id).range.start_byte),
                    fact: fact.clone(),
                }
            })
            .collect()
    }

    pub fn navigation_occurrence(
        &self,
        fact: &CppDeclarationSourceFact,
    ) -> CppNavigationOccurrence {
        let declaration = self.source.declaration(fact.declaration);
        let range = self.source.occurrence(declaration.occurrence).range;
        let conditional_family = fact.conditional_family.map(|id| {
            let range = self.source.occurrence(id).range;
            (range.start_byte, range.end_byte)
        });
        CppNavigationOccurrence {
            range,
            role: fact.occurrence_role,
            conditional_family,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e3c20990a105: quicksilver round 4 on brokk-bifrost-cpp: range bindings, member const and numeric values used wrong syntax"
    )]
    fn source_fact_grammar_boundary() {
        let source = "void f() { for (char i : xs) { for (char item : xs) {} } }\nstruct C { void f(const int x); void g() const; };\nint n[] = {0X10, 0B10, 1uLL, 2Lu, 010};\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        // Hand-written half-open spans pin which grammar fields carry these facts.
        let mut stack = vec![tree.root_node()];
        let mut loops = Vec::new();
        let mut qualifiers = Vec::new();
        let mut literals = Vec::new();
        while let Some(node) = stack.pop() {
            match node.kind() {
                "for_range_loop" => {
                    assert!(node.child_by_field_name("left").is_none());
                    loops.push((
                        node.child_by_field_name("type").unwrap().byte_range(),
                        node.child_by_field_name("declarator").unwrap().byte_range(),
                    ));
                }
                "type_qualifier" => {
                    qualifiers.push((node.parent().unwrap().kind(), node.byte_range()))
                }
                "number_literal" => literals.push(node.byte_range()),
                _ => {}
            }
            let children: Vec<_> = node.named_children(&mut node.walk()).collect();
            stack.extend(children.into_iter().rev());
        }
        assert_eq!(loops, [(16..20, 21..22), (36..40, 41..45)]);
        assert_eq!(
            qualifiers,
            [
                ("parameter_declaration", 77..82),
                ("function_declarator", 100..105)
            ]
        );
        assert_eq!(literals, [121..125, 127..131, 133..137, 139..142, 144..147]);
        let rows = parse_cpp_expression_source_facts(source);
        let bindings: Vec<_> = rows
            .expressions
            .iter()
            .filter(|f| f.kind == CppExpressionKind::LoopVariable)
            .map(|f| {
                (
                    f.name.as_deref(),
                    f.type_text.as_deref(),
                    f.loop_has_short_ancestor,
                )
            })
            .collect();
        let methods: Vec<_> = rows
            .expressions
            .iter()
            .filter(|f| {
                f.kind == CppExpressionKind::FunctionSignature && f.member_function == Some(true)
            })
            .map(|f| (f.name.as_deref(), f.member_function_const))
            .collect();
        let values: Vec<_> = rows
            .expressions
            .iter()
            .filter(|f| f.kind == CppExpressionKind::IntegerLiteral)
            .map(|f| f.integer_value)
            .collect();
        assert_eq!(
            (bindings, methods, values),
            (
                vec![
                    (Some("i"), Some("char"), Some(false)),
                    (Some("item"), Some("char"), Some(true))
                ],
                vec![(Some("f"), Some(false)), (Some("g"), Some(true))],
                vec![Some(16), Some(2), Some(1), Some(2), Some(8)]
            )
        );
        // The C++20 init-statement is not the range binding. A traditional
        // declaration-initialized inner loop still sees the short range name.
        let rows = parse_cpp_expression_source_facts(
            "void f() { for (int setup = 0; char i : xs) { for (int j = 0; j < 3; ++j) {} } }",
        );
        let bindings: Vec<_> = rows
            .expressions
            .iter()
            .filter(|f| f.kind == CppExpressionKind::LoopVariable)
            .map(|f| {
                (
                    f.name.as_deref(),
                    f.type_text.as_deref(),
                    f.loop_has_short_ancestor,
                )
            })
            .collect();
        assert_eq!(
            bindings,
            [
                (Some("i"), Some("char"), Some(false)),
                (Some("j"), Some("int"), Some(true))
            ]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e3c20990a105: quicksilver round 4 on brokk-bifrost-cpp: base access leaked across commas"
    )]
    fn source_fact_base_access_defaults() {
        // [class.access.base]: omitted access is decided independently per base.
        let source = "struct A {}; struct B {}; struct S : private A, B {}; class C : public A, B {}; struct P : protected A {};";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let mut stack = vec![tree.root_node()];
        let mut access = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "base_class_clause" {
                for base in node
                    .named_children(&mut node.walk())
                    .filter(|n| n.kind() == "type_identifier")
                {
                    access.push(base_access_specifier(
                        node,
                        base,
                        node.parent().unwrap().kind(),
                    ));
                }
            }
            let children: Vec<_> = node.named_children(&mut node.walk()).collect();
            stack.extend(children.into_iter().rev());
        }
        assert_eq!(
            access,
            [
                CppAccessSpecifier::Private,
                CppAccessSpecifier::Public,
                CppAccessSpecifier::Public,
                CppAccessSpecifier::Private,
                CppAccessSpecifier::Protected
            ]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e3c20990a105: quicksilver round 4 on brokk-bifrost-cpp: parameter indirection reused pointee size"
    )]
    fn source_fact_parameter_sizes_respect_indirection() {
        let rows = parse_cpp_expression_source_facts(
            "void f(char a, signed char b, unsigned char c, char *p, char &r, char xs[3]);",
        );
        let sizes: Vec<_> = rows
            .expressions
            .iter()
            .filter(|f| {
                f.name.is_some()
                    && matches!(
                        f.kind,
                        CppExpressionKind::FunctionParameter | CppExpressionKind::ArrayParameter
                    )
            })
            .map(|f| (f.name.as_deref(), f.type_size_bytes, f.type_size_exact))
            .collect();
        assert_eq!(
            sizes,
            [
                (Some("a"), Some(1), Some(true)),
                (Some("b"), Some(1), Some(true)),
                (Some("c"), Some(1), Some(true)),
                (Some("p"), None, Some(false)),
                (Some("r"), None, Some(false)),
                (Some("xs"), None, Some(false))
            ]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e3c20990a105: quicksilver round 4 on brokk-bifrost-cpp: union sizes summed and later field declarators vanished"
    )]
    fn source_fact_record_sizes_follow_member_layout() {
        let rows = parse_cpp_expression_source_facts(
            "union U { char a[2]; char b[3]; }; struct S { char a, b; }; void f(U u, S s);",
        );
        let sizes: Vec<_> = rows
            .expressions
            .iter()
            .filter(|f| f.kind == CppExpressionKind::FunctionParameter)
            .map(|f| (f.name.as_deref(), f.type_size_bytes))
            .collect();
        // [class.union] requires room for the largest member; char has size one.
        assert_eq!(sizes, [(Some("u"), Some(3)), (Some("s"), Some(2))]);
    }

    const REFERENCES: &str = "struct C {\n C(C& a); C(const C& a); C(C&& a); C(const C&& a);\n C(C&& a, int n = 0); C(C* a);\n C& operator=(const C& a); C& operator=(C&& a);\n operator C&(); operator C&&();\n};\nC& l = c; C&& r = f();\nvoid f() { try {} catch(C& e) {} try {} catch(const C& e) {} try {} catch(C&& e) {} }\nstruct V {\n V(V& a);\n V& operator=(V& a);\n V(const V& a);\n V& operator=(const V& a);\n V(volatile V& a);\n V& operator=(volatile V& a);\n V(const volatile V& a);\n V& operator=(const volatile V& a);\n V(V& a, int n = 0);\n V(volatile V& a, int n = 0);\n};\n";

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "d4f00f8567e4: quicksilver round 4 on brokk-bifrost-cpp: unnamed && tokens hid rvalue references"
    )]
    #[brokk_bifrost_test_macros::hardwon(
        "d4f00f8567e4: quicksilver round 4 on brokk-bifrost-cpp: a mutable C& copy constructor was not classified as copy"
    )]
    fn cpp_reference_token_grammar() {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(REFERENCES, None).unwrap();
        assert!(!tree.root_node().has_error());
        // Half-open byte spans from the pinned grammar boundary table. The
        // reference wrapper has no fields; the parameter owns `declarator`.
        let expected = "reference_declarator 15..18 & 15..16 identifier 17..18
reference_declarator 30..33 & 30..31 identifier 32..33
reference_declarator 39..43 && 39..41 identifier 42..43
reference_declarator 55..59 && 55..57 identifier 58..59
reference_declarator 66..70 && 66..68 identifier 69..70
reference_declarator 95..118 & 95..96 function_declarator 97..118
reference_declarator 114..117 & 114..115 identifier 116..117
reference_declarator 121..139 & 121..122 function_declarator 123..139
reference_declarator 134..138 && 134..136 identifier 137..138
abstract_reference_declarator 152..155 & 152..153 abstract_function_declarator 153..155
abstract_reference_declarator 167..171 && 167..169 abstract_function_declarator 169..171
reference_declarator 177..180 & 177..178 identifier 179..180
reference_declarator 187..191 && 187..189 identifier 190..191
reference_declarator 224..227 & 224..225 identifier 226..227
reference_declarator 252..255 & 252..253 identifier 254..255
reference_declarator 274..278 && 274..276 identifier 277..278
reference_declarator 300..303 & 300..301 identifier 302..303
reference_declarator 308..325 & 308..309 function_declarator 310..325
reference_declarator 321..324 & 321..322 identifier 323..324
reference_declarator 337..340 & 337..338 identifier 339..340
reference_declarator 345..368 & 345..346 function_declarator 347..368
reference_declarator 364..367 & 364..365 identifier 366..367
reference_declarator 383..386 & 383..384 identifier 385..386
reference_declarator 391..417 & 391..392 function_declarator 393..417
reference_declarator 413..416 & 413..414 identifier 415..416
reference_declarator 438..441 & 438..439 identifier 440..441
reference_declarator 446..478 & 446..447 function_declarator 448..478
reference_declarator 474..477 & 474..475 identifier 476..477
reference_declarator 484..487 & 484..485 identifier 486..487
reference_declarator 514..517 & 514..515 identifier 516..517";
        let mut stack = vec![tree.root_node()];
        let mut actual = Vec::new();
        let mut references = Vec::new();
        let mut qualifiers = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "type_qualifier" && node.start_byte() >= 285 {
                assert_eq!(node.parent().unwrap().kind(), "parameter_declaration");
                qualifiers.push((
                    node.utf8_text(REFERENCES.as_bytes()).unwrap(),
                    node.byte_range(),
                ));
            }
            if matches!(
                node.kind(),
                "reference_declarator" | "abstract_reference_declarator"
            ) {
                let token = node.child(0).unwrap();
                let wrapped = node.named_child(0).unwrap();
                assert!(!token.is_named());
                assert!(node.child_by_field_name("declarator").is_none());
                assert_eq!(node.field_name_for_child(0), None);
                assert_eq!(node.field_name_for_child(1), None);
                if node.parent().unwrap().kind() == "parameter_declaration" {
                    assert_eq!(
                        node.parent().unwrap().child_by_field_name("declarator"),
                        Some(node)
                    );
                }
                actual.push(format!(
                    "{} {:?} {} {:?} {} {:?}",
                    node.kind(),
                    node.byte_range(),
                    token.kind(),
                    token.byte_range(),
                    wrapped.kind(),
                    wrapped.byte_range()
                ));
                references.push(node);
            }
            let children: Vec<_> = node.named_children(&mut node.walk()).collect();
            stack.extend(children.into_iter().rev());
        }
        assert_eq!(actual.join("\n"), expected);
        assert_eq!(
            qualifiers,
            [
                ("const", 330..335),
                ("const", 357..362),
                ("volatile", 373..381),
                ("volatile", 403..411),
                ("const", 422..427),
                ("volatile", 428..436),
                ("const", 458..463),
                ("volatile", 464..472),
                ("volatile", 504..512),
            ]
        );
        for node in references {
            let token = node.child(0).unwrap();
            let wrapped = node.named_child(0).unwrap();
            // A return wrapper also contains the function's parameters. The
            // producer calls this helper on parameter declarators only.
            if wrapped.kind() == "function_declarator" {
                continue;
            }
            assert_eq!(
                declarator_contains_rvalue_reference(node),
                token.kind() == "&&",
                "reference at {:?}",
                node.byte_range()
            );
        }
        let rows = parse_cpp_class_fact_rows(REFERENCES);
        use CppSpecialMemberKind::{
            CopyAssignment, CopyConstructor, MoveAssignment, MoveConstructor, None as NotSpecial,
        };
        // Pin the defect's public class/catch consequences as well as its
        // grammar boundary, including all cv-qualified lvalue references.
        let members: Vec<_> = rows
            .members
            .iter()
            .take(8)
            .map(|member| member.special_member)
            .collect();
        assert_eq!(
            members,
            [
                CopyConstructor,
                CopyConstructor,
                MoveConstructor,
                MoveConstructor,
                MoveConstructor,
                NotSpecial,
                CopyAssignment,
                MoveAssignment
            ]
        );
        assert!(rows.members[4].remaining_parameters_defaulted);
        let cv_members: Vec<_> = rows
            .members
            .iter()
            .filter(|member| member.owner == ["V"])
            .collect();
        assert_eq!(
            cv_members
                .iter()
                .map(|member| member.special_member)
                .collect::<Vec<_>>(),
            [
                CopyConstructor,
                CopyAssignment,
                CopyConstructor,
                CopyAssignment,
                CopyConstructor,
                CopyAssignment,
                CopyConstructor,
                CopyAssignment,
                CopyConstructor,
                CopyConstructor
            ]
        );
        assert!(cv_members.iter().all(|member| member.copy_parameter));
        assert!(
            cv_members[8..]
                .iter()
                .all(|member| member.remaining_parameters_defaulted)
        );
        assert_eq!(
            rows.catches
                .iter()
                .map(|catch| catch.value_category)
                .collect::<Vec<_>>(),
            [
                CppParameterValueCategory::LValueReference,
                CppParameterValueCategory::LValueReference,
                CppParameterValueCategory::RValueReference
            ]
        );
    }

    #[test]
    fn specialized_declaration_name_grammar_boundary() {
        for (source, field_kind, expected, offset) in [
            ("struct Plain {};", "type_identifier", "Plain", 7),
            ("template<> struct Box<int> {};", "template_type", "Box", 18),
            (
                "struct ns::Qualified {};",
                "qualified_identifier",
                "Qualified",
                11,
            ),
        ] {
            let tree = crate::diagnostics::parse_cpp_tree(source);
            assert!(!tree.root_node().has_error());
            let mut stack = vec![tree.root_node()];
            let mut names = Vec::new();
            while let Some(node) = stack.pop() {
                if node.kind() == "struct_specifier" {
                    let field = node.child_by_field_name("name").unwrap();
                    assert_eq!(field.kind(), field_kind);
                    let unit = CodeUnit::new(
                        brokk_bifrost_core::analyzer::ProjectFile::new(
                            std::env::temp_dir(),
                            "names.cpp",
                        ),
                        brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
                        "",
                        expected,
                    );
                    let name = declaration_name(node, &unit, source).unwrap();
                    names.push((node_text(name, source), name.byte_range()));
                }
                stack.extend(node.named_children(&mut node.walk()));
            }
            assert_eq!(names, [(expected, offset..offset + expected.len())]);
        }
    }
}
