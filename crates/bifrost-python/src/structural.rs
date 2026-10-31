//! Python structural spec: maps tree-sitter-python node types onto the
//! normalized kind vocabulary and extracts role edges from AST fields.
//! See `src/analyzer/structural/spec.rs` for the contract and
//! `.agent/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the design.

use brokk_bifrost_core::analyzer::common::node_source_text;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    CalleeSpineStep, attach_argument_role_with_derived_name, attach_role_with_derived_name,
    attach_terminal_callee, field_name_in_parent, nearest_ancestor, node_range,
    terminal_callee_leaf,
};
use brokk_bifrost_core::analyzer::structural::callable::CallSiteContext;
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::{
    AssignmentSequenceKind, AssignmentShape, IntegerLiteralValue, Span,
    decode_integer_literal_digits,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, PYTHON_MATERIALIZATION_SUPPORT, SourceExportBinding,
    SourceExportBindingKind, SourceExportFact, SourceExportFacts, SourceExportLocalDefinition,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, module_path_occurrence_namespace,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, DEEP_LEXICAL_ENVIRONMENT_SUPPORT, HoistingClass,
    LexicalEnvironmentSupport, ScopeFormation, default_scope_formation,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    CuratedExportSurface, DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedLeafFact, RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::{Language, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::Node;

use crate::bindings::{
    PythonDirectScopeBindingKind, python_direct_scope_bindings_bounded,
    python_executable_scope_children,
};
use crate::imports::python_import_bindings_from_tree;
use crate::syntax::{
    expression_name_node, python_conditional_expression_operands,
    python_deferred_annotation_identifier_ranges, python_keyword_argument_label,
    python_node_is_in_annotation, python_plain_string_literal,
};

#[derive(Debug, Default)]
pub struct PythonStructuralSpec;

pub static PYTHON_STRUCTURAL_SPEC: PythonStructuralSpec = PythonStructuralSpec;

/// Tree-sitter interleaves grammar extras (`comment`, `line_continuation`)
/// between the operands of a Python node wherever whitespace is allowed. A
/// backslash newline is the `line_continuation` extra, so an operand that is
/// selected by position among every named child can land on an extra instead.
/// Structural roles and shapes describe the operands, so selection skips extras.
fn python_first_named_operand(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| !child.is_extra())
}

pub(crate) fn python_parenthesized_expression_child(node: Node<'_>) -> Option<Node<'_>> {
    assert_eq!(node.kind(), "parenthesized_expression");
    let mut cursor = node.walk();
    let mut children = node
        .named_children(&mut cursor)
        .filter(|child| !child.is_extra());
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

fn python_unwrap_parenthesized(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        let Some(child) = python_parenthesized_expression_child(node) else {
            break;
        };
        node = child;
    }
    node
}

fn python_unstarred_sequence_shape(node: Node<'_>, starred_node_kinds: &[&str]) -> (u32, bool) {
    let mut unstarred_count = 0u32;
    let mut starred = false;
    for index in 0..node.named_child_count() {
        let child = node
            .named_child(index)
            .expect("named child index is below the named child count");
        if child.is_extra() {
            continue;
        }
        match child.kind() {
            kind if starred_node_kinds.contains(&kind) => starred = true,
            _ => unstarred_count += 1,
        }
    }
    (unstarred_count, starred)
}

/// Expand only displays whose argument names and cardinality are known from
/// syntax. Validate the entire pack before attaching any ordinary arguments.
fn python_literal_pack_arguments(argument: Node<'_>, sink: &mut RoleSink<'_>) -> bool {
    let Some(operand) = python_first_named_operand(argument) else {
        return false;
    };
    let operand = python_unwrap_parenthesized(operand);
    match (argument.kind(), operand.kind()) {
        ("list_splat", "tuple" | "list") => {
            let mut cursor = operand.walk();
            let elements: Vec<_> = operand
                .named_children(&mut cursor)
                .filter(|child| !child.is_extra())
                .collect();
            if elements
                .iter()
                .any(|element| element.kind() == "list_splat")
            {
                return false;
            }
            for element in elements {
                attach_argument_role_with_derived_name(sink, element, expression_name_node);
            }
            true
        }
        ("dictionary_splat", "dictionary") => {
            let mut entries = Vec::new();
            let mut indices = HashMap::default();
            let mut cursor = operand.walk();
            for pair in operand
                .named_children(&mut cursor)
                .filter(|child| !child.is_extra())
            {
                if pair.kind() != "pair" {
                    return false;
                }
                let (Some(key), Some(value)) = (
                    pair.child_by_field_name("key"),
                    pair.child_by_field_name("value"),
                ) else {
                    return false;
                };
                let Some(name) = python_plain_string_literal(key, sink.source()) else {
                    return false;
                };
                // Plain strings have no escapes. Select their content using
                // grammar nodes, including the zero-width content of "".
                let mut key_cursor = key.walk();
                let Some(content) = key
                    .named_children(&mut key_cursor)
                    .find(|child| matches!(child.kind(), "string_content" | "string_end"))
                else {
                    return false;
                };
                let span = Span {
                    start_byte: content.start_byte(),
                    end_byte: content.start_byte() + name.len(),
                };
                // Dict construction overwrites duplicate keys without moving
                // their insertion position. Only the retained value is passed.
                if let Some(&index) = indices.get(name) {
                    entries[index] = (span, value);
                } else {
                    indices.insert(name, entries.len());
                    entries.push((span, value));
                }
            }
            for (keyword, value) in entries {
                sink.kwarg_span(keyword, value);
            }
            true
        }
        _ => false,
    }
}

fn python_assignment_target_shape(node: Node<'_>) -> Option<(AssignmentSequenceKind, u32, bool)> {
    let node = python_unwrap_parenthesized(node);
    let kind = match node.kind() {
        "tuple_pattern" | "pattern_list" => AssignmentSequenceKind::Tuple,
        "list_pattern" => AssignmentSequenceKind::List,
        _ => return None,
    };
    let (count, starred) =
        python_unstarred_sequence_shape(node, &["list_splat_pattern", "splat_pattern"]);
    Some((kind, count, starred))
}

fn python_assignment_value_shape(node: Node<'_>) -> Option<(AssignmentSequenceKind, u32, bool)> {
    let node = python_unwrap_parenthesized(node);
    let kind = match node.kind() {
        "tuple" | "expression_list" => AssignmentSequenceKind::Tuple,
        "list" => AssignmentSequenceKind::List,
        _ => return None,
    };
    let (count, starred) = python_unstarred_sequence_shape(node, &["list_splat"]);
    Some((kind, count, starred))
}

fn python_assignment_shape(node: Node<'_>) -> Option<AssignmentShape> {
    if node.kind() != "assignment" {
        return None;
    }
    let (target_kind, target_unstarred_count, target_starred) =
        python_assignment_target_shape(node.child_by_field_name("left")?)?;
    let (value_kind, value_unstarred_count, value_starred) =
        python_assignment_value_shape(node.child_by_field_name("right")?)?;
    Some(AssignmentShape {
        target_kind,
        value_kind,
        target_unstarred_count,
        value_unstarred_count,
        target_starred,
        value_starred,
    })
}

fn python_integer_literal_value(node: Node<'_>, source: &str) -> Option<IntegerLiteralValue> {
    if node.kind() != "integer" {
        return None;
    }

    let text = node_source_text(node, source).as_bytes();
    let (radix, digits) = match (text.first(), text.get(1)) {
        (Some(b'0'), Some(b'b' | b'B')) => (2u32, &text[2..]),
        (Some(b'0'), Some(b'o' | b'O')) => (8u32, &text[2..]),
        (Some(b'0'), Some(b'x' | b'X')) => (16u32, &text[2..]),
        _ => (10u32, text),
    };
    decode_integer_literal_digits(radix, digits)
}

#[derive(Debug, PartialEq, Eq)]
enum PythonDictionaryKeyValue {
    String(String),
    Integer { negative: bool, magnitude: String },
    Boolean(bool),
    None,
}

impl PythonDictionaryKeyValue {
    fn equals(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(left), Self::String(right)) => left == right,
            (Self::None, Self::None) => true,
            (
                Self::Integer {
                    negative: left_negative,
                    magnitude: left_magnitude,
                },
                Self::Integer {
                    negative: right_negative,
                    magnitude: right_magnitude,
                },
            ) => left_negative == right_negative && left_magnitude == right_magnitude,
            (Self::Boolean(value), Self::Boolean(other)) => value == other,
            (
                Self::Boolean(value),
                Self::Integer {
                    negative,
                    magnitude,
                },
            )
            | (
                Self::Integer {
                    negative,
                    magnitude,
                },
                Self::Boolean(value),
            ) => !negative && magnitude == if *value { "1" } else { "0" },
            _ => false,
        }
    }
}

fn python_string_key_value(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "concatenated_string" {
        let mut value = String::new();
        let mut cursor = node.walk();
        for part in node
            .named_children(&mut cursor)
            .filter(|part| !part.is_extra())
        {
            if part.kind() != "string" {
                return None;
            }
            value.push_str(&python_string_key_value(part, source)?);
        }
        return Some(value);
    }
    if node.kind() != "string" {
        return None;
    }

    let mut raw = false;
    let mut content = String::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_start" => {
                let start = node_source_text(child, source).as_bytes();
                let prefix_end = start
                    .iter()
                    .position(|byte| matches!(byte, b'\'' | b'"'))
                    .unwrap_or(start.len());
                let prefix = std::str::from_utf8(&start[..prefix_end]).ok()?;
                if !prefix.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                    return None;
                }
                let prefix = prefix.to_ascii_lowercase();
                if prefix.contains('b') || prefix.contains('f') {
                    return None;
                }
                raw = prefix.contains('r');
            }
            "string_content" => content.push_str(node_source_text(child, source)),
            "escape_sequence" => content.push_str(node_source_text(child, source)),
            "string_end" => {}
            _ => return None,
        }
    }
    python_decode_string_content(&content, raw)
}

fn python_decode_string_content(content: &str, raw: bool) -> Option<String> {
    if raw {
        return Some(content.to_owned());
    }
    let mut chars = content.chars().peekable();
    let mut decoded = String::with_capacity(content.len());
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let escaped = chars.next()?;
        let replacement = match escaped {
            '\n' => continue,
            '\r' => {
                chars.next_if_eq(&'\n')?;
                continue;
            }
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'a' => '\u{0007}',
            'b' => '\u{0008}',
            'f' => '\u{000c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{000b}',
            'x' => python_escape_codepoint(&mut chars, 2)?,
            'u' => python_escape_codepoint(&mut chars, 4)?,
            'U' => python_escape_codepoint(&mut chars, 8)?,
            'N' => return None,
            '0'..='7' => {
                let mut value = escaped.to_digit(8)?;
                for _ in 0..2 {
                    let Some(next) = chars.peek().copied().filter(char::is_ascii_digit) else {
                        break;
                    };
                    let Some(digit) = next.to_digit(8) else {
                        break;
                    };
                    chars.next();
                    value = value * 8 + digit;
                }
                char::from_u32(value)?
            }
            other => {
                decoded.push('\\');
                other
            }
        };
        decoded.push(replacement);
    }
    Some(decoded)
}

fn python_escape_codepoint(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    digits: usize,
) -> Option<char> {
    let mut value = 0u32;
    for _ in 0..digits {
        value = value
            .checked_mul(16)?
            .checked_add(chars.next()?.to_digit(16)?)?;
    }
    char::from_u32(value)
}

fn python_dictionary_key_value(node: Node<'_>, source: &str) -> Option<PythonDictionaryKeyValue> {
    let node = python_unwrap_parenthesized(node);
    if matches!(node.kind(), "string" | "concatenated_string") {
        return python_string_key_value(node, source).map(PythonDictionaryKeyValue::String);
    }
    if matches!(node.kind(), "true" | "false") {
        return Some(PythonDictionaryKeyValue::Boolean(node.kind() == "true"));
    }
    if node.kind() == "none" {
        return Some(PythonDictionaryKeyValue::None);
    }

    let (integer, negative) = if node.kind() == "unary_operator" {
        let operator = node.child_by_field_name("operator")?;
        match node_source_text(operator, source) {
            "+" => (
                python_unwrap_parenthesized(node.child_by_field_name("argument")?),
                false,
            ),
            "-" => (
                python_unwrap_parenthesized(node.child_by_field_name("argument")?),
                true,
            ),
            _ => return None,
        }
    } else {
        (node, false)
    };
    let value = python_integer_literal_value(integer, source)?;
    let magnitude = value.decimal?;
    let negative = negative && magnitude != "0";
    Some(PythonDictionaryKeyValue::Integer {
        negative,
        magnitude,
    })
}

fn python_duplicate_dictionary_key(node: Node<'_>, source: &str) -> Option<bool> {
    if node.kind() != "pair" {
        return None;
    }
    let dictionary = node
        .parent()
        .filter(|parent| parent.kind() == "dictionary")?;
    let current_key = python_dictionary_key_value(node.child_by_field_name("key")?, source)?;
    let mut earlier_unknown = false;
    let mut all_entries = dictionary.walk();
    let has_unpacked_entry = dictionary
        .named_children(&mut all_entries)
        .any(|entry| !entry.is_extra() && entry.kind() != "pair");
    let mut cursor = dictionary.walk();
    for entry in dictionary.named_children(&mut cursor) {
        if entry.id() == node.id() {
            return if earlier_unknown || has_unpacked_entry {
                None
            } else {
                Some(false)
            };
        }
        match entry.kind() {
            "pair" => {
                let previous_key = entry
                    .child_by_field_name("key")
                    .and_then(|key| python_dictionary_key_value(key, source));
                if previous_key
                    .as_ref()
                    .is_some_and(|previous| current_key.equals(previous))
                {
                    return Some(true);
                }
                earlier_unknown |= previous_key.is_none();
            }
            _ if entry.is_extra() => {}
            _ => {
                earlier_unknown = true;
            }
        }
    }
    None
}

#[derive(Clone, Copy)]
pub struct PythonComparisonShape<'tree> {
    pub operator_count: usize,
    pub operand_count: usize,
    pub left: Option<Node<'tree>>,
    pub right: Option<Node<'tree>>,
    pub operator: Option<Node<'tree>>,
}

/// Read comparison operands and operator tokens from the grammar node. Python
/// comparison operators are repeated fields; named operator aliases such as
/// `is not` are distinguished from operands by their field name.
pub fn python_comparison_shape(node: Node<'_>) -> PythonComparisonShape<'_> {
    let mut operator_count = 0usize;
    let mut operand_count = 0usize;
    let mut left = None;
    let mut right = None;
    let mut operator = None;
    visit_python_comparison_children(node, |child, is_operator| {
        if is_operator {
            operator_count += 1;
            operator.get_or_insert(child);
        } else if child.is_named() && !child.is_extra() {
            operand_count += 1;
            if left.is_none() {
                left = Some(child);
            } else if right.is_none() {
                right = Some(child);
            }
        }
        true
    });
    debug_assert!(
        node.has_error() || operand_count == operator_count.saturating_add(1),
        "well-formed Python comparison must have one more operand than operators: {node:?}"
    );
    PythonComparisonShape {
        operator_count,
        operand_count,
        left,
        right,
        operator,
    }
}

/// Shared grammar-field traversal for singular roles and transient domains.
fn visit_python_comparison_children<'tree>(
    node: Node<'tree>,
    mut visit: impl FnMut(Node<'tree>, bool) -> bool,
) -> bool {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if !visit(cursor.node(), cursor.field_name() == Some("operators")) {
                return false;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    true
}

/// Whether a wrapper is a constant form used by comparison-of-constants:
/// parenthesized scalar literals and unary signs over numeric literals. This
/// deliberately does not fold arbitrary expressions such as `1 + 2`.
fn python_comparison_constant(node: Node<'_>) -> bool {
    let mut current = node;
    let mut signed = false;
    loop {
        match current.kind() {
            "parenthesized_expression" => {
                let Some(expression) = python_parenthesized_expression_child(current) else {
                    return false;
                };
                current = expression;
            }
            "unary_operator" => {
                if !current
                    .child_by_field_name("operator")
                    .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
                {
                    return false;
                }
                let Some(argument) = current.child_by_field_name("argument") else {
                    return false;
                };
                signed = true;
                current = argument;
            }
            "integer" | "float" => return true,
            "true" | "false" | "none" => return !signed,
            "string" | "concatenated_string" => {
                return !signed && python_plain_string_constant(current);
            }
            _ => return false,
        }
    }
}

/// Accept ordinary string tokens and implicit literal concatenation, but not
/// interpolated strings. Tree structure, rather than source-text scanning,
/// distinguishes the interpolation form.
fn python_plain_string_constant(node: Node<'_>) -> bool {
    let mut pending = vec![node];
    let mut saw_string = false;
    while let Some(current) = pending.pop() {
        match current.kind() {
            "string" => {
                saw_string = true;
                let mut cursor = current.walk();
                if current
                    .named_children(&mut cursor)
                    .any(|child| child.kind() == "interpolation")
                {
                    return false;
                }
            }
            "concatenated_string" => {
                let mut cursor = current.walk();
                let mut parts = 0;
                for child in current.named_children(&mut cursor) {
                    if child.kind() != "string" {
                        return false;
                    }
                    parts += 1;
                    pending.push(child);
                }
                if parts == 0 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    saw_string
}

/// Grammar node-type → normalized kind. Every name here must exist in the
/// tree-sitter-python grammar; `tests::python_kind_table_matches_grammar`
/// asserts that, so a grammar bump that renames a node fails loudly.
pub const PYTHON_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("call", NormalizedKind::Call),
    ("attribute", NormalizedKind::FieldAccess),
    ("function_definition", NormalizedKind::Function),
    ("lambda", NormalizedKind::Lambda),
    ("await", NormalizedKind::Await),
    ("yield", NormalizedKind::Yield),
    ("module", NormalizedKind::Module),
    ("class_definition", NormalizedKind::Class),
    ("assignment", NormalizedKind::Assignment),
    ("binary_operator", NormalizedKind::BinaryExpression),
    ("boolean_operator", NormalizedKind::BinaryExpression),
    ("comparison_operator", NormalizedKind::Comparison),
    ("assert_statement", NormalizedKind::Assertion),
    ("conditional_expression", NormalizedKind::If),
    // These wrappers are emitted as literals only for supported constant
    // forms; `should_extract` rejects computed or interpolated expressions.
    ("parenthesized_expression", NormalizedKind::Literal),
    ("unary_operator", NormalizedKind::Literal),
    // The implicit `__exit__` of a `with` statement runs at the construct's
    // own exit, so the statement is the source fact the resource-lifecycle
    // selector names for that release.
    ("with_statement", NormalizedKind::ResourceRelease),
    ("import_statement", NormalizedKind::Import),
    ("import_from_statement", NormalizedKind::Import),
    ("identifier", NormalizedKind::Identifier),
    ("string", NormalizedKind::StringLiteral),
    ("concatenated_string", NormalizedKind::StringLiteral),
    ("integer", NormalizedKind::NumericLiteral),
    ("float", NormalizedKind::NumericLiteral),
    ("true", NormalizedKind::BooleanLiteral),
    ("false", NormalizedKind::BooleanLiteral),
    ("none", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("raise_statement", NormalizedKind::Throw),
    ("except_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("for_statement", NormalizedKind::ForLoop),
    ("list", NormalizedKind::ListLiteral),
    ("set", NormalizedKind::CollectionLiteral),
    ("dictionary", NormalizedKind::CollectionLiteral),
    ("tuple", NormalizedKind::TupleLiteral),
    ("pair", NormalizedKind::ObjectProperty),
    ("while_statement", NormalizedKind::WhileLoop),
    // Python's indented suite.
    ("block", NormalizedKind::Block),
    ("decorator", NormalizedKind::Decorator),
    ("comment", NormalizedKind::Comment),
];

/// Attach `decorators` edges for a definition wrapped in Python's
/// `decorated_definition` node (which itself is not normalized).
fn attach_decorators(sink: &mut RoleSink<'_>, definition: Node<'_>) {
    let Some(parent) = definition.parent() else {
        return;
    };
    if parent.kind() != "decorated_definition" {
        return;
    }
    for index in 0..parent.named_child_count() {
        let Some(child) = parent.named_child(index) else {
            continue;
        };
        if child.kind() == "decorator" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
}

static PYTHON_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportAlias)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference)
    .supported(OccurrenceRole::GlobalDirective)
    .supported(OccurrenceRole::NonlocalDirective);

/// Whether a `dotted_name` names an imported module rather than an ordinary
/// attribute chain, which decides whether its tail is an import target.
///
/// `relative_import` is the wrapper the grammar puts around the module name of
/// `from .impl import x`. It is the same import target as the `pkg.impl` of
/// `from pkg.impl import x`, so it passes through like the other wrappers.
fn python_dotted_name_is_import(dotted_name: Node<'_>) -> bool {
    let mut current = dotted_name;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        match parent.kind() {
            "import_statement" | "import_from_statement" | "future_import_statement" => {
                return true;
            }
            "aliased_import" | "dotted_name" | "relative_import" => current = parent,
            _ => return false,
        }
    }
}

/// Classify one Python identifier token by its AST position.
///
/// Python has no separate type-identifier node, so annotation operands are
/// recognized by their enclosing `type` node — the same field the parser uses
/// to separate `def f(x: T)`'s binder from its annotation.
fn python_occurrence_role(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "identifier" {
        return None;
    }
    let parent = node.parent()?;
    let field = field_name_in_parent(parent, node);
    let role = match parent.kind() {
        "global_statement" => OccurrenceRole::GlobalDirective,
        "nonlocal_statement" => OccurrenceRole::NonlocalDirective,
        "function_definition" | "class_definition" if field == Some("name") => {
            OccurrenceRole::DeclarationName
        }
        // Every annotation, return type and type-alias operand is wrapped in a
        // `type` node; `generic_type`/`type_parameter` nest inside one.
        "type" | "generic_type" | "type_parameter" | "constrained_type" | "union_type" => {
            OccurrenceRole::TypeOperand
        }
        "parameters"
        | "lambda_parameters"
        | "typed_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "tuple_pattern"
        | "list_pattern"
        | "pattern_list"
        | "as_pattern_target" => OccurrenceRole::Binder,
        "default_parameter" | "typed_default_parameter" if field == Some("name") => {
            OccurrenceRole::Binder
        }
        "for_statement" | "for_in_clause" if field == Some("left") => OccurrenceRole::Binder,
        "assignment" if field == Some("left") => OccurrenceRole::Binder,
        "keyword_argument" if python_keyword_argument_label(node) => OccurrenceRole::LabelOrKey,
        "attribute" => match field {
            Some("attribute") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "aliased_import" if field == Some("alias") => OccurrenceRole::ImportAlias,
        "import_from_statement" if field == Some("name") => OccurrenceRole::ImportTarget,
        "dotted_name" => {
            let is_tail =
                parent.named_child(parent.named_child_count().saturating_sub(1)) == Some(node);
            match (is_tail, python_dotted_name_is_import(parent)) {
                (true, true) => OccurrenceRole::ImportTarget,
                (true, false) => OccurrenceRole::ValueReference,
                (false, _) => OccurrenceRole::PathSegment,
            }
        }
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

/// Whether `node` is the identifier token that binds one formal parameter.
///
/// Tree-sitter uses a bare identifier directly under `parameters` or
/// `lambda_parameters`, and wrapper nodes for annotations, defaults, and
/// splats. The shared label helper selects the exact name child for each
/// wrapper so identifiers in annotations/default values do not become
/// parameter facts.
fn python_identifier_is_parameter(node: Node<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "parameters" | "lambda_parameters" => true,
        "typed_parameter"
        | "default_parameter"
        | "typed_default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern"
        | "keyword_separator" => {
            crate::declarations::python_parameter_label_node(parent) == Some(node)
        }
        _ => false,
    }
}

/// Whether a `def` declares a method, that is, whether the suite it sits in
/// belongs to a `class_definition`.
///
/// This reads the parse tree rather than the nearest enclosing normalized kind
/// because the suite between a class and its methods is itself a normalized
/// node now (`NormalizedKind::Block`, issue #1474). Walking the concrete
/// ancestors is also the more direct statement of the rule: a nested `def`
/// inside a method reaches its enclosing `function_definition` first and stays
/// a function.
fn python_definition_is_method(definition: Node<'_>) -> bool {
    let mut current = definition;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "class_definition" => return true,
            // The suite that holds the members, and the wrapper a decorated
            // definition sits in, are pass-through on the way to the owner.
            "block" | "decorated_definition" => current = parent,
            _ => return false,
        }
    }
    false
}

/// The binding one Python binder token introduces, and the interval it is in
/// effect over.
///
/// Python's function locals are scope-categorical rather than positional: a
/// name assigned anywhere in a function body is a local of that function for
/// the whole body, which is why a read above the assignment is an
/// `UnboundLocalError` rather than a read of an outer name. That is exactly
/// `ScopeWide`. The one positional exception is a comprehension target, which
/// lives in the comprehension's own implicit scope; the same exception
/// `analyzer::python::bindings` records as `PythonComprehensionBinding`.
fn python_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    // A binder outside every form below is an ordinary assignment target --
    // the members of a module-level or block-level `a, b = ...` pattern list,
    // for example -- and Python's scope-categorical rule makes it a local of
    // its declaring scope for the whole scope. Answering `None` here made the
    // whole file's lexical environment incomplete as soon as one such binder
    // existed (scripts/test-cost/greedy.py's `s, k = heapq.heappop(heap)` at
    // module scope), which failed every code-smells gate that derived it.
    let Some(form) = nearest_ancestor(binder, |kind| {
        matches!(
            kind,
            "parameters"
                | "lambda_parameters"
                | "assignment"
                | "for_statement"
                | "for_in_clause"
                | "as_pattern"
                | "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
        )
    }) else {
        return Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        });
    };
    match form.kind() {
        "parameters" | "lambda_parameters" => Some(BindingActivation {
            kind: BindingKind::Parameter,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "assignment" => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "for_in_clause" => {
            // A comprehension clause binds only inside the comprehension.
            let comprehension = nearest_ancestor(form, |kind| {
                matches!(
                    kind,
                    "list_comprehension"
                        | "set_comprehension"
                        | "dictionary_comprehension"
                        | "generator_expression"
                )
            })?;
            Some(BindingActivation {
                kind: BindingKind::LoopVariable,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(comprehension),
            })
        }
        "for_statement" => Some(BindingActivation {
            kind: BindingKind::LoopVariable,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "as_pattern" => Some(BindingActivation {
            kind: BindingKind::PatternBinder,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        _ => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
    }
}

/// The text one plain string literal denotes, or `None` when the literal is
/// not plain: an f-string interpolation, an escape sequence this reader does
/// not decode, or an implicit concatenation. `None` is never an empty name --
/// it is "this value is computed", which makes the whole surface unreadable.
/// Whether every member of a curated surface was read from the parse tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadableSurface {
    Yes,
    No,
}

#[derive(Debug, Clone)]
struct PythonExportMember {
    name: String,
    range: Range,
}

/// Collect the members of an `__all__` value into `names`, reporting whether
/// every member was readable. Only a list or tuple display of plain string
/// literals is; anything else is a value the source computes.
fn python_collect_all_members(
    value: Node<'_>,
    source: &str,
    members: &mut Vec<PythonExportMember>,
) -> ReadableSurface {
    if !matches!(value.kind(), "list" | "tuple") {
        return ReadableSurface::No;
    }
    let mut cursor = value.walk();
    for element in value
        .named_children(&mut cursor)
        .filter(|element| !element.is_extra())
    {
        match python_plain_string_literal(element, source) {
            Some(text) => {
                members.push(PythonExportMember {
                    name: text.to_owned(),
                    range: node_range(element),
                });
            }
            None => return ReadableSurface::No,
        }
    }
    ReadableSurface::Yes
}

fn python_module_export_bindings(
    root: Node<'_>,
    source: &str,
) -> HashMap<Box<str>, SourceExportBinding> {
    let mut bindings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        for binding in python_direct_scope_bindings_bounded(node, source, || true)
            .expect("unbounded Python module binding scan completes")
        {
            let name = node_source_text(binding.declaration, source);
            if name.is_empty() {
                continue;
            }
            let kind = match binding.kind {
                PythonDirectScopeBindingKind::ClassDeclaration => SourceExportBindingKind::Class,
                PythonDirectScopeBindingKind::FunctionDeclaration => {
                    SourceExportBindingKind::Function
                }
                PythonDirectScopeBindingKind::Import => SourceExportBindingKind::Import,
                PythonDirectScopeBindingKind::Other => SourceExportBindingKind::Binding,
            };
            bindings.push(SourceExportBinding {
                name: name.to_owned(),
                kind,
                range: node_range(binding.declaration),
            });
        }
        stack.extend(python_executable_scope_children(node));
    }
    bindings.sort_unstable_by_key(|binding| binding.range.start_byte);
    let mut by_name = HashMap::default();
    for binding in bindings {
        by_name
            .entry(binding.name.clone().into())
            .or_insert(binding);
    }
    by_name
}

fn python_call_function_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "call" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    (function.kind() == "identifier").then(|| node_source_text(function, source))
}

fn python_current_module_expression(
    expression: Node<'_>,
    source: &str,
    sys_bindings: &HashSet<Box<str>>,
    module_aliases: &HashSet<Box<str>>,
) -> bool {
    let expression = python_unwrap_parenthesized(expression);
    if expression.kind() == "identifier"
        && module_aliases.contains(node_source_text(expression, source))
    {
        return true;
    }
    if expression.kind() == "subscript"
        && let (Some(value), Some(subscript)) = (
            expression.child_by_field_name("value"),
            expression.child_by_field_name("subscript"),
        )
        && subscript.kind() == "identifier"
        && node_source_text(subscript, source) == "__name__"
        && value.kind() == "attribute"
        && value
            .child_by_field_name("attribute")
            .is_some_and(|attribute| node_source_text(attribute, source) == "modules")
        && value.child_by_field_name("object").is_some_and(|object| {
            object.kind() == "identifier" && sys_bindings.contains(node_source_text(object, source))
        })
    {
        return true;
    }
    python_call_function_name(expression, source) == Some("__import__")
        && expression
            .child_by_field_name("arguments")
            .and_then(python_first_named_operand)
            .is_some_and(|argument| {
                argument.kind() == "identifier" && node_source_text(argument, source) == "__name__"
            })
}

fn python_module_definition_is_dynamic(root: Node<'_>, source: &str) -> bool {
    let sys_bindings: HashSet<Box<str>> = python_import_bindings_from_tree(root, source)
        .into_iter()
        .filter(|binding| binding.qualified_name == "sys")
        .map(|binding| binding.local_name.into_boxed_str())
        .collect();
    let mut assignments = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "assignment"
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            && left.kind() == "identifier"
        {
            assignments.push((node.start_byte(), left, right));
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    assignments.sort_unstable_by_key(|(start, _, _)| *start);
    let mut module_aliases = HashSet::default();
    for (_, left, right) in assignments {
        if python_current_module_expression(right, source, &sys_bindings, &module_aliases) {
            module_aliases.insert(node_source_text(left, source).into());
        }
    }

    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "wildcard_import"
            || python_call_function_name(node, source) == Some("globals")
        {
            return true;
        }
        if python_call_function_name(node, source) == Some("setattr")
            && node
                .child_by_field_name("arguments")
                .and_then(python_first_named_operand)
                .is_some_and(|object| {
                    python_current_module_expression(object, source, &sys_bindings, &module_aliases)
                })
        {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    root.has_error()
}

/// Parse the source-backed member rows for the module's explicit `__all__`.
///
/// Known literals are retained if another member makes the complete surface
/// unreadable. The materialization query then returns those useful rows and
/// reports that absence of additional rows is not proof of completeness.
fn python_source_export_facts(root: Node<'_>, source: &str) -> SourceExportFacts {
    let names_all = |node: Option<Node<'_>>| {
        node.is_some_and(|node| {
            node.kind() == "identifier" && node_source_text(node, source) == "__all__"
        })
    };
    let mut members = Vec::new();
    let mut stated = false;
    let mut readable = ReadableSurface::Yes;
    let module_bindings = python_module_export_bindings(root, source);
    let definitions_complete = !python_module_definition_is_dynamic(root, source);
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        if statement.kind() == "ERROR"
            && crate::syntax::python_contains_all_identifier(statement, source)
        {
            stated = true;
            readable = ReadableSurface::No;
            continue;
        }
        if statement.kind() != "expression_statement" {
            continue;
        }
        let mut inner = statement.walk();
        for expression in statement.named_children(&mut inner) {
            match expression.kind() {
                "ERROR" if crate::syntax::python_contains_all_identifier(expression, source) => {
                    stated = true;
                    readable = ReadableSurface::No;
                }
                "assignment" | "augmented_assignment" => {
                    if !names_all(expression.child_by_field_name("left")) {
                        continue;
                    }
                    stated = true;
                    let Some(value) = expression.child_by_field_name("right") else {
                        let mut cursor = expression.walk();
                        let has_assignment_operator = expression
                            .children(&mut cursor)
                            .any(|child| child.kind() == "=");
                        let annotation_only = expression.kind() == "assignment"
                            && expression.child_by_field_name("type").is_some()
                            && !has_assignment_operator
                            && !expression.has_error();
                        if !annotation_only {
                            readable = ReadableSurface::No;
                        }
                        continue;
                    };
                    if expression.kind() == "assignment" {
                        members.clear();
                        readable = ReadableSurface::Yes;
                    }
                    let extends = expression.kind() == "assignment"
                        || expression
                            .child_by_field_name("operator")
                            .is_some_and(|operator| operator.kind() == "+=");
                    if !extends
                        || python_collect_all_members(value, source, &mut members)
                            == ReadableSurface::No
                    {
                        readable = ReadableSurface::No;
                    }
                }
                "call" => {
                    let Some(function) = expression.child_by_field_name("function") else {
                        continue;
                    };
                    if function.kind() == "attribute"
                        && names_all(function.child_by_field_name("object"))
                    {
                        stated = true;
                        readable = ReadableSurface::No;
                    }
                }
                _ => {}
            }
        }
    }

    let mut names = HashSet::default();
    let exports = if stated {
        members
            .into_iter()
            .filter(|member| names.insert(member.name.clone()))
            .map(|member| {
                let local_definition = match module_bindings.get(member.name.as_str()) {
                    Some(binding) => SourceExportLocalDefinition::Defined {
                        binding: binding.clone(),
                    },
                    None if definitions_complete => SourceExportLocalDefinition::Undefined,
                    None => SourceExportLocalDefinition::Unknown,
                };
                SourceExportFact {
                    range: member.range,
                    exported_name: member.name,
                    local_definition,
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    SourceExportFacts {
        exports,
        declared: stated,
        complete: !stated || readable == ReadableSurface::Yes,
        definitions_complete,
    }
}

/// The names a Python module curates as its public surface: the value of its
/// module-level `__all__`.
///
/// Only the module's own statements are read. An `__all__` inside a function
/// is a local rather than the module's surface, and a name the module binds
/// conditionally is still bound by the statement this reader already sees.
/// A statement that assigns, extends, or mutates `__all__` with anything but a
/// list or tuple of plain string literals makes the surface unreadable: the
/// members are then unknown, and no import is classified from them.
fn python_curated_export_surface(root: Node<'_>, source: &str) -> CuratedExportSurface {
    let facts = python_source_export_facts(root, source);
    match (facts.declared, facts.complete) {
        (false, _) => CuratedExportSurface::Absent,
        (true, false) => CuratedExportSurface::Unreadable,
        (true, true) => CuratedExportSurface::Listed(
            facts
                .exports
                .into_iter()
                .map(|export| export.exported_name)
                .collect(),
        ),
    }
}

/// Which indirection relation one Python import token participates in.
///
/// Python's grammar names no re-export, so the relation follows the explicit
/// re-export rules the typing ecosystem already enforces (PEP 484 stub
/// semantics, applied by pyright and mypy in strict mode), which makes this
/// relation agree with what a type checker calls public:
///
/// 1. A name on the module's `__all__` is a re-export of whatever binding the
///    module gives that name.
/// 2. The redundant-alias forms `from x import y as y` and `import x as x`
///    are re-exports.
/// 3. `from x import *` is one star hop that forwards the public surface of
///    `x`; the expansion is the import machinery's work, not this producer's,
///    so the hop is recorded on the module reference and nothing is
///    enumerated here.
/// 4. Every other import is an ordinary import, including a plain
///    `from .impl import helper` in a package `__init__.py` that states no
///    `__all__`. The facade convention alone does not make a name public, and
///    a consumer that wants every name a facade imports already has the
///    import relation.
///
/// `None` is the answer for a name whose membership only an unreadable
/// `__all__` could settle; the file's relations then report incomplete rather
/// than guessing either way.
fn python_indirection_relation(
    token: Node<'_>,
    source: &str,
    surface: &CuratedExportSurface,
) -> Option<RouteHopKind> {
    let statement = nearest_ancestor(token, |kind| {
        matches!(
            kind,
            "import_statement" | "import_from_statement" | "future_import_statement"
        )
    })?;
    // The statement's own child that holds this token: a `module_name` field,
    // or one `name` field of the import list.
    let mut clause = token;
    while let Some(parent) = clause.parent() {
        if parent.id() == statement.id() {
            break;
        }
        clause = parent;
    }

    if field_name_in_parent(statement, clause) == Some("module_name") {
        // `from x import a` binds `a`, not `x`, so the module reference
        // forwards nothing -- unless the import is the star form, whose one
        // hop forwards the whole surface of `x`.
        let mut cursor = statement.walk();
        let star = statement
            .children(&mut cursor)
            .any(|child| child.kind() == "wildcard_import");
        return Some(if star {
            RouteHopKind::ReExport
        } else {
            RouteHopKind::Import
        });
    }

    let bound = match clause.kind() {
        "aliased_import" => {
            let name = clause.child_by_field_name("name")?;
            let alias = clause.child_by_field_name("alias")?;
            if node_source_text(name, source) == node_source_text(alias, source) {
                return Some(RouteHopKind::ReExport);
            }
            alias
        }
        // `import a.b.c` binds the top package `a`; `from m import a` binds
        // the single-segment name the import list spells.
        "dotted_name" if statement.kind() == "import_statement" => clause.named_child(0)?,
        "dotted_name" => clause,
        _ => return None,
    };
    match surface.lists(node_source_text(bound, source)) {
        Some(true) => Some(RouteHopKind::ReExport),
        Some(false) => Some(RouteHopKind::Import),
        None => None,
    }
}

/// Grammar steps for the shared call-callee spine. A value expression has no step.
pub fn callee_spine_step(kind: &str) -> Option<CalleeSpineStep> {
    use CalleeSpineStep::{Field, Name};
    match kind {
        "identifier" => Some(Name),
        "attribute" => Some(Field("attribute")),
        _ => None,
    }
}

impl StructuralSpec for PythonStructuralSpec {
    fn language(&self) -> Language {
        Language::Python
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn supports_string_literal_parenthesized(&self) -> bool {
        true
    }

    fn supports_string_literal_value(&self) -> bool {
        true
    }

    fn string_literal_value(&self, node: Node<'_>, source: &str) -> Option<String> {
        python_string_key_value(node, source)
    }

    fn supports_assignment_shape(&self) -> bool {
        true
    }

    fn assignment_shape(&self, node: Node<'_>) -> Option<AssignmentShape> {
        python_assignment_shape(node)
    }

    fn supports_integer_literal_value(&self) -> bool {
        true
    }

    fn integer_literal_value(&self, node: Node<'_>, source: &str) -> Option<IntegerLiteralValue> {
        python_integer_literal_value(node, source)
    }

    fn supports_duplicate_dictionary_keys(&self) -> bool {
        true
    }

    fn duplicate_dictionary_key(&self, node: Node<'_>, source: &str) -> Option<bool> {
        python_duplicate_dictionary_key(node, source)
    }

    fn string_literal_parenthesized(&self, node: Node<'_>) -> Option<bool> {
        if !matches!(node.kind(), "string" | "concatenated_string") {
            return None;
        }
        let mut current = node;
        let mut parenthesized = false;
        while let Some(parent) = current.parent() {
            if parent.kind() != "parenthesized_expression" {
                break;
            }
            assert_eq!(python_parenthesized_expression_child(parent), Some(current));
            current = parent;
            parenthesized = true;
        }
        Some(parenthesized)
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // `import x as y` is an alias, and `python_indirection_relation`
        // states which imports re-export (issue #1649).
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Alias)
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::ReExport)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    /// Python's one qualified-path chain is `dotted_name`, which is flat
    /// rather than left-nested: its named children are the segments in order.
    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if token.kind() != "identifier" {
            return None;
        }
        token
            .parent()
            .filter(|parent| parent.kind() == "dotted_name")
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        if root.kind() != "dotted_name" {
            return Vec::new();
        }
        let mut cursor = root.walk();
        root.named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .collect()
    }

    fn curated_export_surface(&self, root: Node<'_>, source: &str) -> CuratedExportSurface {
        python_curated_export_surface(root, source)
    }

    fn indirection_relation(
        &self,
        token: Node<'_>,
        source: &str,
        surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
        python_indirection_relation(token, source, surface)
    }

    fn scope_formation(&self, kind: NormalizedKind) -> ScopeFormation {
        match kind {
            // The normalized module fact is the file root, not a nested scope.
            // Top-level imports and assignments belong to the synthetic file scope.
            NormalizedKind::Module => ScopeFormation::NotAScope,
            // Python blocks do not introduce local-variable scopes. Names
            // assigned in an if/loop/try body remain function or module locals.
            NormalizedKind::Block | NormalizedKind::ForLoop | NormalizedKind::WhileLoop => {
                ScopeFormation::NotAScope
            }
            _ => default_scope_formation(kind),
        }
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        PYTHON_KIND_TABLE
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        match kind {
            NormalizedKind::Identifier if python_identifier_is_parameter(node) => {
                NormalizedKind::Parameter
            }
            NormalizedKind::Function if python_definition_is_method(node) => NormalizedKind::Method,
            NormalizedKind::Comparison if python_comparison_shape(node).operator_count > 1 => {
                NormalizedKind::ComparisonChain
            }
            _ => kind,
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::Module && node.byte_range().is_empty() {
            return false;
        }
        match node.kind() {
            "parenthesized_expression" | "unary_operator" => {
                kind == NormalizedKind::Literal && python_comparison_constant(node)
            }
            _ => kind != NormalizedKind::Assignment || node.child_by_field_name("right").is_some(),
        }
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_kind_from_table(
            kind,
            &[
                NormalizedKind::Method,
                // Module facts select the parser's file root for Python policies.
                NormalizedKind::Module,
                NormalizedKind::Parameter,
                NormalizedKind::SyntaxError,
                NormalizedKind::ComparisonChain,
                NormalizedKind::RegexPattern,
                NormalizedKind::RegexSequence,
                NormalizedKind::RegexGroup,
                NormalizedKind::RegexAlternation,
                NormalizedKind::RegexCharacterClass,
                NormalizedKind::RegexCharacterRange,
                NormalizedKind::RegexQuantifier,
                NormalizedKind::RegexAnchor,
                NormalizedKind::RegexEscape,
                NormalizedKind::RegexLiteral,
                NormalizedKind::RegexWildcard,
                NormalizedKind::RegexRiskHostname,
                NormalizedKind::RegexRiskRange,
                NormalizedKind::RegexRiskBadTag,
                NormalizedKind::RegexRiskExponential,
                NormalizedKind::RegexIncomplete,
                NormalizedKind::RegexRiskBackspaceEscape,
                NormalizedKind::RegexRiskDuplicateClassCharacter,
                NormalizedKind::RegexRiskUnmatchableCaret,
                NormalizedKind::RegexRiskUnmatchableDollar,
                NormalizedKind::RegexRiskIncompleteSpecialGroup,
                NormalizedKind::RegexRiskPolynomial,
            ],
            self.kind_table(),
        )
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &PYTHON_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &PYTHON_MATERIALIZATION_SUPPORT
    }

    fn source_export_facts(&self, root: Node<'_>, source: &str) -> Option<SourceExportFacts> {
        Some(python_source_export_facts(root, source))
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        python_binding_activation(binder, scope)
    }

    /// Python only classifies a scope segment inside a `dotted_name`, and every
    /// non-tail segment of a dotted name is a module.
    fn occurrence_namespace(
        &self,
        role: OccurrenceRole,
        declares: Option<NormalizedKind>,
    ) -> Option<Namespace> {
        module_path_occurrence_namespace(role, declares)
    }

    fn embedded_leaf_facts(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        source: &str,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<EmbeddedLeafFact> {
        if kind == NormalizedKind::Module {
            return crate::regex::module_assigned_facts(node, source);
        }
        if kind == NormalizedKind::Call {
            return crate::regex::embedded_facts(node, source);
        }
        if kind != NormalizedKind::StringLiteral {
            return Vec::new();
        }

        let mut facts = crate::regex::embedded_facts(node, source);
        if node.kind() != "string" || !python_node_is_in_annotation(node) {
            return facts;
        }

        facts.extend(
            python_deferred_annotation_identifier_ranges(node, source, cancellation)
                .unwrap_or_default()
                .into_iter()
                .map(|range| EmbeddedLeafFact {
                    kind: NormalizedKind::Identifier,
                    range,
                    parent: None,
                    construct: None,
                    occurrence_role: Some(OccurrenceRole::TypeOperand),
                }),
        );
        facts
    }

    fn comparison_operator_spans(
        &self,
        node: Node<'_>,
        step: &mut dyn FnMut() -> bool,
    ) -> Option<Vec<Span>> {
        if !step() || node.kind() != "comparison_operator" || node.has_error() || node.is_missing()
        {
            return None;
        }
        let mut operators = Vec::new();
        let mut operands = 0usize;
        let complete = visit_python_comparison_children(node, |child, is_operator| {
            if !step() || child.is_missing() || child.has_error() {
                return false;
            }
            if is_operator {
                if child.start_byte() >= child.end_byte() {
                    return false;
                }
                operators.push(Span {
                    start_byte: child.start_byte(),
                    end_byte: child.end_byte(),
                });
            } else if child.is_named() && !child.is_extra() {
                operands += 1;
            }
            true
        });
        (complete
            && !operators.is_empty()
            && operands == operators.len().saturating_add(1)
            && step())
        .then_some(operators)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = python_occurrence_role(node) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                if let Some(function) = node.child_by_field_name("function") {
                    // A call's own name is its callee's, so
                    // { "kind": "call", "name": "eval" } reads naturally.
                    attach_terminal_callee(
                        sink,
                        function,
                        terminal_callee_leaf(function, callee_spine_step),
                    );
                    if function.kind() == "attribute"
                        && let Some(object) = function.child_by_field_name("object")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            object,
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    for index in 0..arguments.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(argument) = arguments.named_child(index) else {
                            continue;
                        };
                        if argument.is_extra() {
                            continue;
                        }
                        match argument.kind() {
                            "keyword_argument" => {
                                if let (Some(keyword), Some(value)) = (
                                    argument.child_by_field_name("name"),
                                    argument.child_by_field_name("value"),
                                ) {
                                    sink.kwarg(keyword, value);
                                }
                            }
                            "list_splat" | "dictionary_splat"
                                if python_literal_pack_arguments(argument, sink) => {}
                            _ => attach_argument_role_with_derived_name(
                                sink,
                                argument,
                                expression_name_node,
                            ),
                        }
                    }
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(attribute) = node.child_by_field_name("attribute") {
                    sink.set_name(attribute);
                    sink.role_named(Role::Field, attribute, attribute);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Class => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => {
                if let Some(left) = node.child_by_field_name("left") {
                    attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                }
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(sink, Role::Right, right, expression_name_node);
                }
            }
            NormalizedKind::BinaryExpression => {
                if let Some(left) = node.child_by_field_name("left") {
                    attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                }
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(sink, Role::Right, right, expression_name_node);
                }
                if let Some(operator) = node.child_by_field_name("operator") {
                    sink.role_named(Role::Operator, operator, operator);
                }
            }
            NormalizedKind::Comparison => {
                let shape = python_comparison_shape(node);
                if shape.operator_count == 1 && shape.operand_count == 2 {
                    if let Some(left) = shape.left {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = shape.right {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                    if let Some(operator) = shape.operator {
                        sink.role_named(Role::Operator, operator, operator);
                    }
                }
            }
            NormalizedKind::Assertion => {
                if let Some(test) = python_first_named_operand(node) {
                    sink.role(Role::Test, test);
                }
            }
            NormalizedKind::If => {
                // The grammar names the `if` statement condition, but its
                // conditional expression has no fields: its three named
                // operands are value, condition, and alternative. Grammar
                // extras (`comment`, `line_continuation`) can be interleaved
                // between them, so select among the operands (#4797).
                let test = if node.kind() == "conditional_expression" {
                    let [consequence, test, alternative] =
                        python_conditional_expression_operands(node)
                            .expect("conditional expression operands");
                    sink.role(Role::Consequence, consequence);
                    sink.role(Role::Alternative, alternative);
                    Some(test)
                } else {
                    node.child_by_field_name("condition")
                };
                if let Some(test) = test {
                    sink.role(Role::Test, test);
                }
            }
            NormalizedKind::Return => {
                if let Some(value) = python_first_named_operand(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::Throw => {
                if let Some(value) = python_first_named_operand(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::Import => match node.kind() {
                "import_from_statement" => {
                    if let Some(module) = node.child_by_field_name("module_name") {
                        sink.role_named(Role::Module, module, module);
                    }
                }
                _ => {
                    for index in 0..node.named_child_count() {
                        if !sink.should_continue() {
                            break;
                        }
                        let Some(child) = node.named_child(index) else {
                            continue;
                        };
                        match child.kind() {
                            "dotted_name" => sink.role_named(Role::Module, child, child),
                            "aliased_import" => {
                                if let Some(name) = child.child_by_field_name("name") {
                                    sink.role_named(Role::Module, name, name);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            },
            NormalizedKind::Identifier | NormalizedKind::Parameter => sink.set_name(node),
            NormalizedKind::Decorator => {
                if let Some(name) = python_first_named_operand(node).and_then(expression_name_node)
                {
                    sink.set_name(name);
                }
            }
            NormalizedKind::ForLoop => {
                if let Some(right) = node.child_by_field_name("right") {
                    attach_role_with_derived_name(
                        sink,
                        Role::Iterable,
                        right,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::CollectionLiteral
            | NormalizedKind::TupleLiteral
            | NormalizedKind::ListLiteral => {
                for index in 0..node.named_child_count() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if child.is_extra() {
                        continue;
                    }
                    let element = python_unwrap_parenthesized(child);
                    attach_role_with_derived_name(
                        sink,
                        Role::Element,
                        element,
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::ObjectProperty => {
                if let Some(key) = node.child_by_field_name("key") {
                    sink.role(Role::Key, key);
                }
                if let Some(value) = node.child_by_field_name("value") {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::StringLiteral if node.kind() == "concatenated_string" => {
                for index in 0..node.named_child_count() {
                    let Some(part) = node.named_child(index) else {
                        continue;
                    };
                    if part.kind() == "string" {
                        sink.role(Role::Part, part);
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn node_of_kind<'tree>(root: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if node.kind() == kind {
                return Some(node);
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        None
    }

    fn string_literal_parenthesization(root: Node<'_>) -> (usize, usize) {
        let mut pending = vec![root];
        let mut string_count = 0;
        let mut parenthesized_count = 0;
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "string" | "concatenated_string") {
                string_count += 1;
                if PYTHON_STRUCTURAL_SPEC
                    .string_literal_parenthesized(node)
                    .expect("Python string-literal parenthesization is supported")
                {
                    parenthesized_count += 1;
                }
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        (string_count, parenthesized_count)
    }

    fn parse_python(source: &str) -> tree_sitter::Tree {
        crate::declarations::parse_python_tree(source).expect("Python source tree")
    }

    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: __all__ replacement retained old exports"
    )]
    fn qs6_all_replacement_and_extension() {
        for (source, expected) in [
            ("__all__ = ['old']\n__all__ = ['new']\n", vec!["new"]),
            (
                "__all__ = ['old']\n__all__ += ['new']\n",
                vec!["old", "new"],
            ),
            ("__all__ = computed\n__all__ = ['new']\n", vec!["new"]),
        ] {
            let tree = parse_python(source);
            let facts = python_source_export_facts(tree.root_node(), source);
            assert_eq!(
                facts
                    .exports
                    .iter()
                    .map(|e| e.exported_name.as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(facts.complete, "{source}: {facts:?}");
        }
    }

    #[test]
    #[hardwon(
        "6b123df7cc68: quicksilver round 6 on brokk-bifrost-python: named extras made literal exports and concatenations unreadable"
    )]
    fn qs6_literal_extras_grammar_boundary() {
        let source =
            "__all__ = [\n 'first', # comment\n 'second',\n]\nVALUE = ('a' # comment\n 'b')\n";
        let tree = parse_python(source);
        assert!(!tree.root_node().has_error());
        let facts = python_source_export_facts(tree.root_node(), source);
        assert!(facts.complete, "{facts:?}");
        assert_eq!(
            facts
                .exports
                .iter()
                .map(|e| e.exported_name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        let concat = node_of_kind(tree.root_node(), "concatenated_string").unwrap();
        assert_eq!(
            python_string_key_value(concat, source).as_deref(),
            Some("ab")
        );
    }

    #[test]
    fn qs6_structural_literal_grammar_matrix() {
        // Expected values follow CPython ast literal values; f/named-escape
        // strings remain unsupported rather than inventing a decoded value.
        for (literal, expected) in [
            (r#""{{key}}""#, Some("{{key}}")),
            (r#""{key}""#, Some("{key}")),
            (r#"f"{{key}}""#, None),
            (r#"f"plain""#, None),
            (r#"f"{key}""#, None),
            (r#""\N{LATIN CAPITAL LETTER A}""#, None),
            (r#""A""#, Some("A")),
            (
                r#""\n{LATIN CAPITAL LETTER A}""#,
                Some("\n{LATIN CAPITAL LETTER A}"),
            ),
        ] {
            let source = format!("value = {literal}\n");
            let tree = parse_python(&source);
            let node = node_of_kind(tree.root_node(), "string").unwrap();
            assert_eq!(
                python_string_key_value(node, &source).as_deref(),
                expected,
                "{literal}"
            );
        }
        for (rhs, kind, count, starred) in [
            ("[1, 2]", AssignmentSequenceKind::List, 2, false),
            ("(1, 2)", AssignmentSequenceKind::Tuple, 2, false),
            ("1, 2", AssignmentSequenceKind::Tuple, 2, false),
            ("[1, *items]", AssignmentSequenceKind::List, 1, true),
            ("(1, *items)", AssignmentSequenceKind::Tuple, 1, true),
        ] {
            let source = format!("a, *b = {rhs}\n");
            let tree = parse_python(&source);
            let assignment = node_of_kind(tree.root_node(), "assignment").unwrap();
            assert_eq!(
                python_assignment_value_shape(assignment.child_by_field_name("right").unwrap()),
                Some((kind, count, starred)),
                "{rhs}"
            );
        }
        for (value, constant) in [
            ("((True))", true),
            ("(False)", true),
            ("((None))", true),
            ("-None", false),
            ("-1", true),
            ("f'{value}'", false),
        ] {
            let source = format!("left == {value}\n");
            let tree = parse_python(&source);
            let comparison = node_of_kind(tree.root_node(), "comparison_operator").unwrap();
            let operand = comparison.named_child(1).unwrap();
            assert_eq!(python_comparison_constant(operand), constant, "{value}");
        }
    }

    #[test]
    fn qs6_source_export_namespace_shapes() {
        for (statement, dynamic) in [
            ("", false),
            (
                "import sys as runtime\nsetattr(runtime.modules[__name__], 'late', 1)\n",
                true,
            ),
            ("setattr(__import__(__name__), 'late', 1)\n", true),
            (
                "import sys as runtime\nalias = runtime.modules[__name__]\nsetattr(alias, 'late', 1)\n",
                true,
            ),
            ("globals()['late'] = 1\n", true),
        ] {
            let source = format!("__all__ = ['late']\n{statement}");
            let tree = parse_python(&source);
            let facts = python_source_export_facts(tree.root_node(), &source);
            assert_eq!(facts.definitions_complete, !dynamic, "{source}");
            assert!(
                matches!(
                    facts.exports[0].local_definition,
                    SourceExportLocalDefinition::Unknown
                ) == dynamic,
                "{facts:?}"
            );
            if !dynamic {
                assert!(matches!(
                    facts.exports[0].local_definition,
                    SourceExportLocalDefinition::Undefined
                ));
            }
        }
        let source = "__all__ =\n";
        let tree = parse_python(source);
        assert!(!python_source_export_facts(tree.root_node(), source).definitions_complete);
    }

    #[test]
    fn qs6_binding_kind_grammar_inventory() {
        let source = "def run(parameter):\n scalar = 1\n left, right = (1, 2)\n for loop in ():\n  pass\n values = [comp for comp in ()]\n";
        let tree = parse_python(source);
        let mut pending = vec![tree.root_node()];
        let mut found = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "identifier" {
                let text = node_source_text(node, source);
                if text == "comp" && node.parent().unwrap().kind() != "for_in_clause" {
                    continue;
                }
                if let Some(expected) = match text {
                    "parameter" => Some(BindingKind::Parameter),
                    "scalar" | "left" | "right" => Some(BindingKind::Local),
                    "loop" | "comp" => Some(BindingKind::LoopVariable),
                    _ => None,
                } {
                    let activation =
                        python_binding_activation(node, node_range(tree.root_node())).unwrap();
                    assert_eq!(activation.kind, expected, "{text}: {}", node.to_sexp());
                    found.push(text);
                }
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        assert_eq!(found.len(), 6);
    }

    #[test]
    fn missing_python_all_value_is_incomplete_after_parser_recovery() {
        let source = "__all__ =\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python parser");
        let tree = parser.parse(source, None).expect("Python source tree");
        let root = tree.root_node();
        let facts = python_source_export_facts(root, source);

        assert!(facts.declared, "recovered AST: {}", root.to_sexp());
        assert!(!facts.complete, "recovered AST: {}", root.to_sexp());
    }

    #[test]
    fn parenthesized_string_literals_allow_comment_children() {
        for (case, source) in [
            (
                "one comment between concatenated strings",
                "VALUE = (\n    r\"\\.\"  # dot\n    r\"(?!-)\"\n)\n",
            ),
            (
                "several comments between concatenated strings",
                "VALUE = (\n    r\"a\"  # first\n    # between\n    r\"b\"  # second\n    # trailing\n)\n",
            ),
            (
                "comment before the string",
                "VALUE = (\n    # starts below\n    r\"value\"\n)\n",
            ),
            (
                "nested parentheses with a comment",
                "VALUE = (\n    (\n        # nested\n        r\"value\"  # closes inner value\n    )\n)\n",
            ),
        ] {
            let tree = parse_python(source);
            let root = tree.root_node();
            assert!(!root.has_error(), "{case}: {}", root.to_sexp());
            let (string_count, parenthesized_count) = string_literal_parenthesization(root);
            assert!(string_count > 0, "{case}: {}", root.to_sexp());
            assert!(parenthesized_count > 0, "{case}: {}", root.to_sexp());
        }

        let tree = parse_python("VALUE = (\n    # comment\n    1  # trailing comment\n)\n");
        let mut pending = vec![tree.root_node()];
        let parenthesized = loop {
            let node = pending.pop().expect("parenthesized expression exists");
            if node.kind() == "parenthesized_expression" {
                break node;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        };
        assert!(python_comparison_constant(parenthesized));
        assert_eq!(python_unwrap_parenthesized(parenthesized).kind(), "integer");
    }

    #[test]
    #[hardwon(
        "#4797: a backslash continuation before `else` counted as a fourth conditional-expression operand"
    )]
    fn conditional_expression_selects_condition_past_extras() {
        for (case, source) in [
            (
                "line continuation",
                "def f(a, b):\n    return a if b \\\n        else c\n",
            ),
            (
                "comment",
                "def f(a, b, c):\n    return (a if b\n            # why not\n            else c)\n",
            ),
            (
                "plain",
                "def f(a, b, c):\n    return (a if b\n            else c)\n",
            ),
        ] {
            let tree = parse_python(source);
            let root = tree.root_node();
            assert!(!root.has_error(), "{case}: {}", root.to_sexp());
            let conditional = node_of_kind(root, "conditional_expression").unwrap_or_else(|| {
                panic!("{case}: no conditional expression in {}", root.to_sexp())
            });
            let test = python_conditional_expression_operands(conditional)
                .expect("conditional expression operands")[1];
            assert_eq!(test.kind(), "identifier", "{case}");
            assert_eq!(
                test.utf8_text(source.as_bytes()).unwrap(),
                "b",
                "{case}: {}",
                root.to_sexp()
            );
        }
    }

    #[test]
    #[hardwon(
        "#4797: a line continuation inside parentheses hid the sole operand from the parenthesization check"
    )]
    fn parenthesized_expression_skips_line_continuation() {
        let source = "VALUE = (\n    \"value\"\\\n)\n";
        let tree = parse_python(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let string = node_of_kind(root, "string").expect("string literal");
        assert_eq!(
            PYTHON_STRUCTURAL_SPEC.string_literal_parenthesized(string),
            Some(true),
            "{}",
            root.to_sexp()
        );
    }

    #[test]
    #[hardwon("#4797: a line continuation in a dict literal disabled duplicate-key detection")]
    fn duplicate_dictionary_key_skips_extras() {
        let source = "D = {1: 2, \\\n 1: 3}\n";
        let tree = parse_python(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let dictionary = node_of_kind(root, "dictionary").expect("dictionary literal");
        let mut cursor = dictionary.walk();
        let pairs: Vec<Node<'_>> = dictionary
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "pair")
            .collect();
        assert_eq!(pairs.len(), 2, "{}", root.to_sexp());
        assert_eq!(
            PYTHON_STRUCTURAL_SPEC.duplicate_dictionary_key(pairs[1], source),
            Some(true),
            "{}",
            root.to_sexp()
        );
    }

    #[test]
    fn django_domain_validator_strings_parse_without_parenthesization_panics() {
        let source = r#"
class DomainNameValidator(RegexValidator):
    message = _("Enter a valid domain name.")
    ul = "\u00a1-\uffff"  # Unicode letters range (must not be a raw string).
    # Host patterns.
    hostname_re = (
        r"[a-z" + ul + r"0-9](?:[a-z" + ul + r"0-9-]{0,61}[a-z" + ul + r"0-9])?"
    )
    # Max length for domain name labels is 63 characters per RFC 1034 sec. 3.1.
    domain_re = r"(?:\.(?!-)[a-z" + ul + r"0-9-]{1,63}(?<!-))*"
    # Top-level domain.
    tld_no_fqdn_re = (
        r"\."  # dot
        r"(?!-)"  # can't start with a dash
        r"(?:[a-z" + ul + "-]{2,63}"  # domain label
        r"|xn--[a-z0-9]{1,59})"  # or punycode label
        r"(?<!-)"  # can't end with a dash
    )
    tld_re = tld_no_fqdn_re + r"\.?"
    ascii_only_hostname_re = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    ascii_only_domain_re = r"(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*"
    ascii_only_tld_re = (
        r"\."  # dot
        r"(?!-)"  # can't start with a dash
        r"(?:[a-zA-Z0-9-]{2,63})"  # domain label
        r"(?<!-)"  # can't end with a dash
        r"\.?"  # may have a trailing dot
    )
"#;
        let tree = parse_python(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let (string_count, parenthesized_count) = string_literal_parenthesization(root);
        assert!(string_count > 0, "{}", root.to_sexp());
        assert!(parenthesized_count > 0, "{}", root.to_sexp());
    }

    #[test]
    fn decoded_string_values_match_python_escape_and_concatenation_semantics() {
        for (source, expected) in [
            (
                r#"MIDDLEWARE = "\x64jango.middleware.csrf.CsrfViewMiddleware""#,
                Some("django.middleware.csrf.CsrfViewMiddleware"),
            ),
            (
                r#"MIDDLEWARE = "django.middleware.csrf." "CsrfViewMiddleware""#,
                Some("django.middleware.csrf.CsrfViewMiddleware"),
            ),
            (
                r#"MIDDLEWARE = b"django.middleware.csrf.CsrfViewMiddleware""#,
                None,
            ),
        ] {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .expect("Python parser");
            let tree = parser.parse(source, None).expect("Python source tree");
            let mut pending = vec![tree.root_node()];
            let assignment = loop {
                let node = pending.pop().expect("Python tree has an assignment");
                if node.kind() == "assignment" {
                    break node;
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            };
            let value = assignment
                .child_by_field_name("right")
                .expect("assignment value");
            assert_eq!(
                python_string_key_value(value, source).as_deref(),
                expected,
                "{}",
                tree.root_node().to_sexp()
            );
        }
    }
    #[test]
    fn qs6_flat_import_paths_follow_grammar_fields_and_byte_ranges() {
        let source = "# \u{e9}\nimport alpha.beta.gamma as alias\nfrom alpha.beta import gamma\nalpha.beta\n";
        let tree = parse_python(source);
        let root = tree.root_node();
        assert!(!root.has_error(), "{}", root.to_sexp());
        let import = root.named_child(1).unwrap();
        assert_eq!(import.kind(), "import_statement");
        let aliased = import.child_by_field_name("name").unwrap();
        assert_eq!(aliased.kind(), "aliased_import");
        let dotted = aliased.child_by_field_name("name").unwrap();
        assert_eq!(dotted.kind(), "dotted_name");
        let tokens = PYTHON_STRUCTURAL_SPEC.path_segment_tokens(dotted);
        let start = source.find("alpha").unwrap();
        assert_eq!(
            tokens
                .iter()
                .map(|node| (node.kind(), node.byte_range()))
                .collect::<Vec<_>>(),
            vec![
                ("identifier", start..start + 5),
                ("identifier", start + 6..start + 10),
                ("identifier", start + 11..start + 16)
            ]
        );
        for token in tokens {
            assert_eq!(
                PYTHON_STRUCTURAL_SPEC.qualified_path_root(token),
                Some(dotted)
            );
        }
        let alias = aliased.child_by_field_name("alias").unwrap();
        assert_eq!(node_source_text(alias, source), "alias");
        assert!(PYTHON_STRUCTURAL_SPEC.qualified_path_root(alias).is_none());
        let from = root.named_child(2).unwrap();
        let module = from.child_by_field_name("module_name").unwrap();
        assert_eq!(module.kind(), "dotted_name");
        assert_eq!(
            PYTHON_STRUCTURAL_SPEC
                .path_segment_tokens(module)
                .iter()
                .map(|n| node_source_text(*n, source))
                .collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
        let attribute = root.named_child(3).unwrap().named_child(0).unwrap();
        assert_eq!(attribute.kind(), "attribute");
        assert!(
            PYTHON_STRUCTURAL_SPEC
                .path_segment_tokens(attribute)
                .is_empty()
        );
        assert!(
            PYTHON_STRUCTURAL_SPEC
                .qualified_path_root(attribute.child_by_field_name("attribute").unwrap())
                .is_none()
        );
    }

    #[test]
    fn qs6_syntactic_reexports_obey_redundant_aliases_and_all_membership() {
        for (all, listed, ordinary) in [
            ("", Some(RouteHopKind::Import), Some(RouteHopKind::Import)),
            (
                "__all__ = ['z']\n",
                Some(RouteHopKind::ReExport),
                Some(RouteHopKind::Import),
            ),
            ("__all__ = dynamic()\n", None, None),
        ] {
            let source = format!(
                "# \u{e9}\nimport a.b\nimport x as x\nfrom x import y as y\nfrom x import y as z\nfrom x import *\n{all}"
            );
            let tree = parse_python(&source);
            let root = tree.root_node();
            assert!(!root.has_error(), "{}", root.to_sexp());
            let surface = PYTHON_STRUCTURAL_SPEC.curated_export_surface(root, &source);
            for (index, field, expected) in [
                (1, "name", ordinary),
                (2, "name", Some(RouteHopKind::ReExport)),
                (3, "name", Some(RouteHopKind::ReExport)),
                (4, "name", listed),
                (5, "module_name", Some(RouteHopKind::ReExport)),
            ] {
                let clause = root
                    .named_child(index)
                    .unwrap()
                    .child_by_field_name(field)
                    .unwrap();
                let name = if clause.kind() == "aliased_import" {
                    clause.child_by_field_name("name").unwrap()
                } else {
                    clause
                };
                assert_eq!(name.kind(), "dotted_name");
                let token = name.named_child(0).unwrap();
                assert_eq!(token.kind(), "identifier");
                assert_eq!(
                    PYTHON_STRUCTURAL_SPEC.indirection_relation(token, &source, &surface),
                    expected,
                    "{}",
                    clause.to_sexp()
                );
            }
        }
    }
}
