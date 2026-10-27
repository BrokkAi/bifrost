//! Shared JavaScript/TypeScript structural specs for `query_code`.

use brokk_bifrost_core::analyzer::common::try_node_source_text as node_text;
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    CalleeSpineStep, attach_positional_argument_roles, attach_role_with_derived_name,
    attach_terminal_callee, field_name_in_parent, first_named_child, nearest_ancestor, node_range,
    terminal_callee_leaf, unquoted_string_content_span,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    linear_chain_tokens, qualified_chain_root, spelled_generic_arity,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallSiteContext, CallSiteFacts,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    DEEP_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::{
    IntegerLiteralValue, Span, decode_integer_literal_digits,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, JS_TS_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    Namespace, OccurrenceRole, OccurrenceRoleSupport, module_path_occurrence_namespace,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, BindingScopeCandidate, BindingScopeSelection,
    DEEP_LEXICAL_ENVIRONMENT_SUPPORT, HoistingClass, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseIndex, CallResultUseOpenReason, CallResultUseSite,
    IntentionalDiscardKind,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    CuratedExportSurface, DEEP_IDENTITY_AXES, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedLeafFact, RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

/// The left-nested qualified chains of both grammars: expression namespace
/// qualifiers (`nested_identifier`, naming its segment through `property`)
/// and TypeScript qualified type names (`nested_type_identifier`, through
/// `name`).
const JS_TS_PATH_CHAIN: &[(&str, Option<&str>)] = &[
    ("nested_identifier", Some("property")),
    ("nested_type_identifier", Some("name")),
];

#[derive(Debug)]
pub struct JsTsStructuralSpec {
    language: Language,
}

pub static JAVASCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::JavaScript,
};

pub static TYPESCRIPT_STRUCTURAL_SPEC: JsTsStructuralSpec = JsTsStructuralSpec {
    language: Language::TypeScript,
};

/// Classify one exact JavaScript or TypeScript call expression without
/// resolving its callee. The result-use rule is shared by both grammars:
/// expression statements drop a result, while every other ordinary expression
/// context consumes it. `void` is the one explicit discard spelling accepted
/// by the JS/TS adapter.
pub fn js_ts_call_result_use(call: Node<'_>, _source: &str) -> CallResultUseSite {
    let default = if call.kind() != "call_expression"
        || call.has_error()
        || has_recovery_ancestor(call)
        || has_recovery_descendant(call)
    {
        CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
    } else {
        let mut expression = call;
        loop {
            let Some(parent) = expression.parent() else {
                break CallResultUse::Open(CallResultUseOpenReason::UnclassifiedSyntax);
            };
            if parent.is_error() || parent.is_missing() {
                break CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax);
            }
            match parent.kind() {
                "parenthesized_expression"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    expression = parent;
                }
                "unary_expression"
                    if parent
                        .child_by_field_name("argument")
                        .is_some_and(|argument| argument.id() == expression.id())
                        && parent
                            .children(&mut parent.walk())
                            .any(|child| child.kind() == "void") =>
                {
                    break CallResultUse::IntentionalDiscard(
                        IntentionalDiscardKind::JavaScriptVoid,
                    );
                }
                "expression_statement"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    break CallResultUse::Discarded;
                }
                _ => break CallResultUse::Consumed,
            }
        }
    };
    CallResultUseSite::new(call.start_byte(), call.end_byte(), default)
}

fn has_recovery_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() || parent.is_missing() {
            return true;
        }
        node = parent;
    }
    false
}

fn has_recovery_descendant(root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.id() != root.id() && (node.is_error() || node.is_missing()) {
            return true;
        }
        for index in (0..node.named_child_count()).rev() {
            stack.push(node.named_child(index).expect("named child exists"));
        }
    }
    false
}

/// One source-snapshot index of exact JavaScript/TypeScript call spans.
#[derive(Debug, Clone)]
pub struct JsTsCallResultUseIndex {
    inner: CallResultUseIndex,
}

impl JsTsCallResultUseIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                sites.push(js_ts_call_result_use(node, source));
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child exists"));
            }
        }
        Self {
            inner: CallResultUseIndex::new(sites),
        }
    }

    pub fn at_span(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Result<&CallResultUseSite, CallResultUseOpenReason> {
        self.inner.at_span(start_byte, end_byte)
    }

    pub fn sites(&self) -> &[CallResultUseSite] {
        self.inner.sites()
    }
}

macro_rules! js_ts_kind_table {
    ($($ts_only:expr,)*) => {
        &[
            ("call_expression", NormalizedKind::Call),
            ("new_expression", NormalizedKind::Call),
            ("member_expression", NormalizedKind::FieldAccess),
            ("function_declaration", NormalizedKind::Function),
            ("function_expression", NormalizedKind::Function),
            ("generator_function_declaration", NormalizedKind::Function),
            ("generator_function", NormalizedKind::Function),
            ("method_definition", NormalizedKind::Method),
            ("arrow_function", NormalizedKind::Lambda),
            ("class", NormalizedKind::Class),
            ("class_declaration", NormalizedKind::Class),
            ("assignment_expression", NormalizedKind::Assignment),
            ("variable_declarator", NormalizedKind::Assignment),
            ("import_statement", NormalizedKind::Import),
            ("identifier", NormalizedKind::Identifier),
            ("property_identifier", NormalizedKind::Identifier),
            ("private_property_identifier", NormalizedKind::Identifier),
            ("shorthand_property_identifier", NormalizedKind::Identifier),
            (
                "shorthand_property_identifier_pattern",
                NormalizedKind::Identifier,
            ),
            ("array", NormalizedKind::CollectionLiteral),
            ("object", NormalizedKind::CollectionLiteral),
            ("jsx_element", NormalizedKind::JsxElement),
            ("jsx_self_closing_element", NormalizedKind::JsxElement),
            ("jsx_attribute", NormalizedKind::JsxAttribute),
            // JSX spread attributes are represented by a jsx_expression whose
            // only named child is a spread_element. `should_extract` below
            // admits this grammar node only in that opening-element context.
            ("jsx_expression", NormalizedKind::JsxSpreadAttribute),
            ("pair", NormalizedKind::ObjectProperty),
            ("computed_property_name", NormalizedKind::ComputedProperty),
            // `spread_element` is shared by object/array literals and call
            // arguments. Keep that shared syntax kind context-free; the
            // enclosing role and parent fact retain whether it is an object,
            // array, or argument spread.
            ("spread_element", NormalizedKind::SpreadElement),
            ("string", NormalizedKind::StringLiteral),
            ("template_string", NormalizedKind::StringLiteral),
            ("unary_expression", NormalizedKind::NumericLiteral),
            ("number", NormalizedKind::NumericLiteral),
            ("true", NormalizedKind::BooleanLiteral),
            ("false", NormalizedKind::BooleanLiteral),
            ("null", NormalizedKind::NullLiteral),
            ("return_statement", NormalizedKind::Return),
            ("throw_statement", NormalizedKind::Throw),
            ("catch_clause", NormalizedKind::Catch),
            ("if_statement", NormalizedKind::If),
            ("for_statement", NormalizedKind::Loop),
            ("for_in_statement", NormalizedKind::ForLoop),
            ("while_statement", NormalizedKind::WhileLoop),
            ("do_statement", NormalizedKind::WhileLoop),
            // `statement_block` is every braced body in both grammars;
            // `switch_body` is the statement list of a switch.
            ("statement_block", NormalizedKind::Block),
            ("switch_body", NormalizedKind::Block),
            ("decorator", NormalizedKind::Decorator),
            ("comment", NormalizedKind::Comment),
            $($ts_only,)*
        ]
    };
}

/// JavaScript's table is the union its two grammars need. `.jsx` is parsed
/// with the TSX grammar (#3322), which spells a class name `type_identifier`
/// and wraps every parameter in `required_parameter`/`optional_parameter`;
/// without those entries a `.jsx` class name would stop being an Identifier
/// fact the moment the dialect changed. `CompiledKinds` drops the entries a
/// concrete grammar does not have, so tree-sitter-javascript gets the entries
/// it has, which include the plain-JavaScript parameter patterns (#3841).
pub const JS_KIND_TABLE: &[(&str, NormalizedKind)] = js_ts_kind_table!(
    ("type_identifier", NormalizedKind::Identifier),
    ("required_parameter", NormalizedKind::Parameter),
    ("optional_parameter", NormalizedKind::Parameter),
    // Plain JavaScript has no parameter wrapper: a parameter is a bare
    // identifier, a default value, or a destructuring pattern that is a direct
    // child of `formal_parameters` (#3841). `refine_kind` lifts identifiers in
    // that position to Parameter, and `should_extract_with_parent` admits these
    // pattern nodes only in that position.
    ("assignment_pattern", NormalizedKind::Parameter),
    ("object_pattern", NormalizedKind::Parameter),
    ("array_pattern", NormalizedKind::Parameter),
);

/// The entries [`JS_KIND_TABLE`] carries only for the `.jsx` dialect's TSX
/// grammar. tree-sitter-javascript has no node with any of these names.
pub const JS_TSX_ONLY_KINDS: &[&str] = &[
    "type_identifier",
    "required_parameter",
    "optional_parameter",
];

pub const TS_KIND_TABLE: &[(&str, NormalizedKind)] = js_ts_kind_table!(
    ("abstract_class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    // A `type` alias declares a type, so its fact is a type-namespace
    // declaration and its name inherits `Namespace::Type` through
    // `default_occurrence_namespace`. Recorded as a bare `Declaration`, the
    // alias name landed in the value namespace beside a same-named `const`
    // (#2911).
    ("type_alias_declaration", NormalizedKind::Class),
    ("type_identifier", NormalizedKind::Identifier),
    ("nested_identifier", NormalizedKind::Identifier),
    // Bodiless callable declarations: overload signatures, ambient
    // declarations, interface members, and abstract methods (#1658). They
    // are declarations, so their nodes are facts a query can address.
    ("function_signature", NormalizedKind::Function),
    ("method_signature", NormalizedKind::Method),
    ("abstract_method_signature", NormalizedKind::Method),
    // TypeScript formal parameters are declarations in their own right. The
    // grammar also uses `rest_pattern` for array/object destructuring, so it
    // is intentionally not normalized here: the context-free kind table
    // cannot soundly distinguish a rest parameter from a destructuring rest.
    // Rest-parameter matching remains an explicit unsupported case until the
    // adapter can refine that context without overclassifying ordinary code.
    ("required_parameter", NormalizedKind::Parameter),
    ("optional_parameter", NormalizedKind::Parameter),
);

fn unquoted_string_span(node: Node<'_>) -> Option<Span> {
    if node.kind() != "string" {
        return None;
    }
    unquoted_string_content_span(node)
}

fn js_ts_string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    let value = crate::syntax::js_ts_string_literal_code_units(node, source)?;
    String::from_utf16(&value).ok()
}

fn js_ts_integer_literal_value(node: Node<'_>, source: &str) -> Option<IntegerLiteralValue> {
    let (literal, negative) = if node.kind() == "unary_expression" {
        let operator = node.child_by_field_name("operator")?;
        let negative = match operator.kind() {
            "+" => false,
            "-" => true,
            _ => return None,
        };
        (
            js_ts_numeric_target(node.child_by_field_name("argument")?)?,
            negative,
        )
    } else {
        (node, false)
    };
    if literal.kind() != "number" {
        return None;
    }
    let text = node_text(literal, source)?;
    let text = text.strip_suffix('n').unwrap_or(text);
    if text.is_empty() || text.contains('.') || text.contains('e') || text.contains('E') {
        return None;
    }
    let compact = text.replace('_', "");
    let (radix, digits) = if let Some(digits) = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = compact
        .strip_prefix("0b")
        .or_else(|| compact.strip_prefix("0B"))
    {
        (2, digits)
    } else if let Some(digits) = compact
        .strip_prefix("0o")
        .or_else(|| compact.strip_prefix("0O"))
    {
        (8, digits)
    } else {
        if compact.len() > 1
            && compact.starts_with('0')
            && compact.as_bytes().iter().skip(1).any(|byte| *byte != b'0')
        {
            return None;
        }
        (10, compact.as_str())
    };
    let value = decode_integer_literal_digits(radix, digits.as_bytes())?;
    Some(if negative { value.negated() } else { value })
}

fn js_ts_numeric_target(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "parenthesized_expression" {
        node = first_named_child(node)?;
    }
    Some(node)
}

fn js_ts_signed_numeric_unary(node: Node<'_>) -> bool {
    node.kind() == "unary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "+" | "-"))
        && node
            .child_by_field_name("argument")
            .and_then(js_ts_numeric_target)
            .is_some_and(|argument| argument.kind() == "number")
}

fn js_ts_is_inside_signed_numeric_wrapper<'tree>(
    node: Node<'tree>,
    parent_of: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
) -> bool {
    let mut parent = parent_of(node);
    while parent.is_some_and(|parent| parent.kind() == "parenthesized_expression") {
        parent = parent.and_then(&parent_of);
    }
    parent.is_some_and(|parent| {
        js_ts_signed_numeric_unary(parent)
            && parent
                .child_by_field_name("argument")
                .and_then(js_ts_numeric_target)
                .is_some_and(|argument| argument.id() == node.id())
    })
}

/// Grammar steps for the shared call-callee spine. A value expression has no step.
pub fn callee_spine_step(kind: &str) -> Option<CalleeSpineStep> {
    use CalleeSpineStep::{Field, Name};
    match kind {
        "identifier"
        | "property_identifier"
        | "private_property_identifier"
        | "type_identifier" => Some(Name),
        "member_expression" | "nested_identifier" => Some(Field("property")),
        "nested_type_identifier" | "qualified_identifier" | "generic_type" => Some(Field("name")),
        "instantiation_expression" => Some(Field("function")),
        _ => None,
    }
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression;
    loop {
        match current.kind() {
            "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "type_identifier" => return Some(current),
            "nested_identifier" | "member_expression" => {
                current = current.child_by_field_name("property")?;
            }
            "call_expression" => current = current.child_by_field_name("function")?,
            "new_expression" => current = current.child_by_field_name("constructor")?,
            "decorator" | "parenthesized_expression" | "non_null_expression" => {
                current = first_named_child(current)?;
            }
            _ => return None,
        }
    }
}

/// A JSX tag has intrinsic/component identity only after resolution. The
/// structural fact keeps a name span for simple identifiers, while qualified
/// and namespaced tags remain unnamed so a later projection cannot mistake a
/// terminal member segment for the tag's identity.
fn jsx_simple_tag_name<'tree>(tag: Node<'tree>) -> Option<Node<'tree>> {
    matches!(tag.kind(), "identifier" | "property_identifier").then_some(tag)
}

fn jsx_opening_element<'tree>(element: Node<'tree>) -> Option<Node<'tree>> {
    match element.kind() {
        "jsx_element" => element.child_by_field_name("open_tag"),
        "jsx_self_closing_element" => Some(element),
        _ => None,
    }
}

fn jsx_expression_operand<'tree>(value: Node<'tree>) -> Option<Node<'tree>> {
    if value.kind() == "jsx_expression" {
        first_named_child(value)
    } else {
        Some(value)
    }
}

fn jsx_spread_operand<'tree>(attribute: Node<'tree>) -> Option<Node<'tree>> {
    jsx_spread_expression(first_named_child(attribute)?)
}

fn jsx_spread_expression<'tree>(spread: Node<'tree>) -> Option<Node<'tree>> {
    (spread.kind() == "spread_element")
        .then(|| first_named_child(spread))
        .flatten()
}

fn jsx_attribute_value<'tree>(attribute: Node<'tree>) -> Option<Node<'tree>> {
    attribute
        .named_child(1)
        .and_then(jsx_expression_operand)
        .and_then(|value| {
            if value.kind() == "spread_element" {
                jsx_spread_expression(value)
            } else {
                Some(value)
            }
        })
}

fn attach_jsx_element_roles(sink: &mut RoleSink<'_>, element: Node<'_>) {
    let Some(opening) = jsx_opening_element(element) else {
        return;
    };
    if let Some(tag) = opening.child_by_field_name("name") {
        let name = jsx_simple_tag_name(tag);
        sink.role_maybe_named(Role::Tag, tag, name);
        if let Some(name) = name {
            sink.set_name(name);
        }
    }
    for index in 0..opening.named_child_count() {
        let Some(child) = opening.named_child(index) else {
            continue;
        };
        if matches!(child.kind(), "jsx_attribute" | "jsx_expression") {
            sink.role(Role::Attributes, child);
        }
    }
    if element.kind() == "jsx_element" {
        for index in 0..element.named_child_count() {
            let Some(child) = element.named_child(index) else {
                continue;
            };
            if !matches!(child.kind(), "jsx_opening_element" | "jsx_closing_element") {
                sink.role(Role::Children, child);
            }
        }
    }
}

fn attach_object_property_roles(sink: &mut RoleSink<'_>, property: Node<'_>) {
    let Some(key) = property.child_by_field_name("key") else {
        return;
    };
    if key.kind() != "computed_property_name" {
        if let Some(name) = unquoted_string_span(key) {
            sink.role_named_span(Role::Key, key, name);
        } else {
            sink.set_name(key);
            sink.role_named(Role::Key, key, key);
        }
    }
    if let Some(value) = property.child_by_field_name("value") {
        sink.role(Role::Value, value);
    }
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    if arguments.kind() == "template_string" {
        sink.role(Role::Arg, arguments);
        return;
    }
    attach_positional_argument_roles(sink, arguments, expression_name_node);
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    for index in 0..declaration.named_child_count() {
        let Some(child) = declaration.named_child(index) else {
            continue;
        };
        if child.kind() == "decorator" {
            attach_role_with_derived_name(sink, Role::Decorator, child, expression_name_node);
        }
    }
    attach_preceding_class_body_decorators(sink, declaration);
}

fn parameter_name_node<'tree>(parameter: Node<'tree>) -> Option<Node<'tree>> {
    match parameter.kind() {
        "required_parameter" | "optional_parameter" | "rest_pattern" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        // A plain JavaScript default value is an assignment_pattern whose
        // `left` is the bound pattern, which is TSX's `pattern` field.
        "assignment_pattern" => parameter.child_by_field_name("left"),
        // A destructuring parameter names its pattern, as TSX does.
        "object_pattern" | "array_pattern" => Some(parameter),
        _ => expression_name_node(parameter),
    }
}

/// Whether a node sits directly in a formal parameter list. Plain JavaScript
/// has no parameter wrapper node, so this position is what makes a bare
/// identifier or pattern a parameter (#3841).
fn is_formal_parameter_position(parent: Option<Node<'_>>) -> bool {
    parent.is_some_and(|parent| parent.kind() == "formal_parameters")
}

/// Whether an identifier is one of JavaScript's ordinary formal parameters.
///
/// The JavaScript grammar keeps simple parameters as bare `identifier` nodes,
/// unlike the TypeScript grammar's `required_parameter` wrapper.  The
/// normalized vocabulary must not make callers know that grammar distinction,
/// so refine bare identifiers by their immediate structured parent. TypeScript
/// parameter wrappers already produce the parameter fact, so their identifier
/// children must not be promoted as a second fact.
fn js_ts_parameter_identifier<'tree>(node: Node<'tree>, parents: &ParentIndex<'tree>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }

    let Some(parent) = parents.parent(node) else {
        return false;
    };
    match parent.kind() {
        "formal_parameters" => true,
        "arrow_function" => parent
            .child_by_field_name("parameter")
            .is_some_and(|parameter| parameter.id() == node.id()),
        _ => false,
    }
}

fn attach_preceding_class_body_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    let Some(parent) = declaration.parent() else {
        return;
    };
    if parent.kind() != "class_body" {
        return;
    }
    let mut pending = Vec::new();
    for index in 0..parent.named_child_count() {
        let Some(child) = parent.named_child(index) else {
            continue;
        };
        if child.id() == declaration.id() {
            for decorator in pending {
                attach_role_with_derived_name(
                    sink,
                    Role::Decorator,
                    decorator,
                    expression_name_node,
                );
            }
            return;
        }
        if child.kind() == "decorator" {
            pending.push(child);
        } else {
            pending.clear();
        }
    }
}

static JS_TS_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::DeclarationName)
    .supported(OccurrenceRole::Binder)
    .supported(OccurrenceRole::LabelOrKey)
    .supported(OccurrenceRole::TypeOperand)
    .supported(OccurrenceRole::PathSegment)
    .supported(OccurrenceRole::ImportAlias)
    .supported(OccurrenceRole::ImportTarget)
    .supported(OccurrenceRole::ReceiverPosition)
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::ValueReference);

const JS_TS_DECLARATION_HEADS: &[&str] = &[
    "function_declaration",
    "function_signature",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "class_declaration",
    "abstract_class_declaration",
    "class",
    "method_definition",
    "abstract_method_signature",
    "interface_declaration",
    "enum_declaration",
    "type_alias_declaration",
    "module",
    "internal_module",
    "public_field_definition",
    "property_signature",
    "method_signature",
    "enum_assignment",
    "type_parameter",
];

/// Whether a binding pattern position encloses this node, which is what
/// separates `const { a } = x` (a binder) from `f({ a })` (a read of `a`).
///
/// The two shapes use different grammar nodes —
/// `shorthand_property_identifier_pattern` inside `object_pattern` versus
/// `shorthand_property_identifier` inside `object` — so this never has to guess
/// from source text.
fn js_ts_is_binding_pattern<'tree>(
    node: Node<'tree>,
    parent_of: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
) -> bool {
    let mut current = node;
    // At least one destructuring node must sit between the token and the
    // binding form; otherwise `const x = source` would bind its right-hand
    // side as eagerly as its left.
    let mut through_pattern = false;
    while let Some(parent) = parent_of(current) {
        match parent.kind() {
            "assignment_pattern" | "object_assignment_pattern" => {
                // Match pattern_binder_identifiers: defaults bind only the left.
                if parent.child_by_field_name("left") != Some(current) {
                    return false;
                }
                through_pattern = true;
                current = parent;
            }
            "required_parameter" | "optional_parameter" => {
                let pattern = parent
                    .child_by_field_name("pattern")
                    .or_else(|| parent.child_by_field_name("name"));
                if pattern != Some(current) {
                    return false;
                }
                through_pattern = true;
                current = parent;
            }
            "object_pattern" | "array_pattern" | "rest_pattern" | "pair_pattern"
            | "formal_parameters" => {
                through_pattern = true;
                current = parent;
            }
            "for_in_statement" => {
                return through_pattern
                    && crate::syntax::for_in_declaration_kind(parent, current).is_some();
            }
            "variable_declarator" | "catch_clause" => return through_pattern,
            kind if crate::syntax::is_function_like(kind)
                || matches!(
                    kind,
                    "function_signature" | "abstract_method_signature" | "method_signature"
                ) =>
            {
                return through_pattern;
            }
            _ => return false,
        }
    }
    false
}

/// Classify one JavaScript/TypeScript identifier token by its AST position.
fn js_ts_occurrence_role<'tree>(
    node: Node<'tree>,
    parent_of: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
) -> Option<OccurrenceRole> {
    let node_kind = node.kind();
    if !matches!(
        node_kind,
        "identifier"
            | "property_identifier"
            | "private_property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "type_identifier"
    ) {
        return None;
    }
    if node_kind == "shorthand_property_identifier_pattern" {
        return Some(if js_ts_is_binding_pattern(node, parent_of) {
            OccurrenceRole::Binder
        } else {
            OccurrenceRole::ValueReference
        });
    }
    if node_kind == "shorthand_property_identifier" {
        return Some(OccurrenceRole::ValueReference);
    }

    let mut anchor = node;
    let mut parent = parent_of(anchor)?;
    while parent.kind() == "nested_identifier" {
        if field_name_in_parent(parent, anchor) != Some("property") {
            return Some(OccurrenceRole::PathSegment);
        }
        anchor = parent;
        parent = parent_of(anchor)?;
    }

    let field = field_name_in_parent(parent, anchor);
    let parent_kind = parent.kind();
    let role = match parent_kind {
        "import_specifier" | "export_specifier" => match field {
            Some("alias") => OccurrenceRole::ImportAlias,
            _ => OccurrenceRole::ImportTarget,
        },
        "namespace_import" | "import_clause" => OccurrenceRole::ImportAlias,
        "member_expression" => match field {
            Some("property") => OccurrenceRole::MemberPosition,
            Some("object") => OccurrenceRole::ReceiverPosition,
            _ => OccurrenceRole::ValueReference,
        },
        "pair" if field == Some("key") => OccurrenceRole::LabelOrKey,
        "pair_pattern" if field == Some("key") => OccurrenceRole::LabelOrKey,
        _ if field == Some("name") && JS_TS_DECLARATION_HEADS.contains(&parent_kind) => {
            OccurrenceRole::DeclarationName
        }
        "catch_clause" if field == Some("parameter") => OccurrenceRole::Binder,
        "for_in_statement" if field == Some("left") => {
            if crate::syntax::for_in_declaration_kind(parent, anchor).is_some() {
                OccurrenceRole::Binder
            } else {
                OccurrenceRole::ValueReference
            }
        }
        "variable_declarator" if field == Some("name") => OccurrenceRole::Binder,
        "required_parameter" | "optional_parameter" if field == Some("pattern") => {
            OccurrenceRole::Binder
        }
        "formal_parameters" | "rest_pattern" => OccurrenceRole::Binder,
        _ if node_kind == "property_identifier" || node_kind == "private_property_identifier" => {
            OccurrenceRole::MemberPosition
        }
        _ if node_kind == "type_identifier" => OccurrenceRole::TypeOperand,
        _ if js_ts_is_binding_pattern(anchor, parent_of) => OccurrenceRole::Binder,
        _ => OccurrenceRole::ValueReference,
    };
    Some(role)
}

// Declaration classification is shared by owner selection and activation.
fn js_ts_binding_form(binder: Node<'_>) -> Option<Node<'_>> {
    nearest_ancestor(binder, |kind| {
        JS_TS_DECLARATION_HEADS.contains(&kind)
            || matches!(
                kind,
                "variable_declarator"
                    | "catch_clause"
                    | "for_in_statement"
                    | "required_parameter"
                    | "optional_parameter"
                    | "formal_parameters"
                    | "arrow_function"
            )
    })
}

fn js_ts_form_is_var(form: Node<'_>) -> bool {
    match form.kind() {
        "variable_declarator" => form
            .parent()
            .is_some_and(|declaration| declaration.kind() == "variable_declaration"),
        "for_in_statement" => form
            .child_by_field_name("left")
            .is_some_and(|left| crate::syntax::for_in_declaration_kind(form, left) == Some("var")),
        _ => false,
    }
}

fn js_ts_binding_scope_selection(
    binder: Node<'_>,
    candidate: BindingScopeCandidate<'_>,
) -> BindingScopeSelection {
    let Some(form) = js_ts_binding_form(binder) else {
        return BindingScopeSelection::Use;
    };
    if !js_ts_form_is_var(form) {
        return BindingScopeSelection::Use;
    }
    if form.has_error() || form.is_missing() {
        return BindingScopeSelection::Unknown;
    }
    let scope = match candidate {
        BindingScopeCandidate::File { root } => {
            return if root.has_error() {
                BindingScopeSelection::Unknown
            } else {
                BindingScopeSelection::Use
            };
        }
        BindingScopeCandidate::Syntax(scope) => scope,
    };
    if scope.has_error() || scope.is_missing() {
        return BindingScopeSelection::Unknown;
    }
    if scope.kind() == "statement_block" {
        if scope
            .parent()
            .is_some_and(|owner| matches!(owner.kind(), "internal_module" | "module"))
        {
            return BindingScopeSelection::Unknown;
        }
        if let Some(owner) = scope.parent()
            && crate::syntax::js_ts_is_var_scope_kind(owner.kind())
            && owner.child_by_field_name("body") == Some(scope)
        {
            return BindingScopeSelection::Use;
        }
    } else if crate::syntax::js_ts_is_var_scope_kind(scope.kind())
        || crate::syntax::js_ts_is_class_scope_kind(scope.kind())
    {
        // A function without a represented body, or recovered class syntax,
        // must not export a body var into an outer scope or a parameter list.
        return BindingScopeSelection::Unknown;
    }
    BindingScopeSelection::Continue
}

/// Activation uses the very same owner row selected above (#5574).
fn js_ts_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let form = js_ts_binding_form(binder)?;
    match form.kind() {
        "required_parameter" | "optional_parameter" | "formal_parameters" | "arrow_function" => {
            Some(BindingActivation {
                kind: BindingKind::Parameter,
                hoisting: HoistingClass::ScopeWide,
                activation: scope,
            })
        }
        "catch_clause" => {
            let body = form.child_by_field_name("body")?;
            Some(BindingActivation {
                kind: BindingKind::CatchOrResource,
                hoisting: HoistingClass::DeclaredHead,
                activation: node_range(body),
            })
        }
        "for_in_statement" if js_ts_form_is_var(form) => Some(BindingActivation {
            kind: BindingKind::Local,
            hoisting: HoistingClass::ScopeWide,
            activation: scope,
        }),
        "for_in_statement" => Some(BindingActivation {
            kind: BindingKind::LoopVariable,
            hoisting: HoistingClass::DeclaredHead,
            activation: node_range(form),
        }),
        "function_declaration" | "generator_function_declaration" => Some(BindingActivation {
            kind: BindingKind::Local,
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

impl JsTsStructuralSpec {
    pub(crate) fn should_extract_with_parent<'tree>(
        &self,
        node: Node<'tree>,
        kind: NormalizedKind,
        parent_of: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
    ) -> bool {
        if kind == NormalizedKind::Parameter
            && matches!(
                node.kind(),
                "assignment_pattern" | "object_pattern" | "array_pattern"
            )
            && !is_formal_parameter_position(parent_of(node))
        {
            return false;
        }
        if kind == NormalizedKind::NumericLiteral && node.kind() == "unary_expression" {
            return js_ts_signed_numeric_unary(node);
        }
        if kind == NormalizedKind::NumericLiteral
            && node.kind() == "number"
            && js_ts_is_inside_signed_numeric_wrapper(node, &parent_of)
        {
            return false;
        }
        if kind == NormalizedKind::JsxSpreadAttribute
            && !(node.kind() == "jsx_expression"
                && parent_of(node).is_some_and(|parent| {
                    matches!(
                        parent.kind(),
                        "jsx_opening_element" | "jsx_self_closing_element"
                    )
                })
                && first_named_child(node).is_some_and(|child| child.kind() == "spread_element"))
        {
            return false;
        }
        kind != NormalizedKind::Assignment
            || node.kind() != "variable_declarator"
            || node.child_by_field_name("value").is_some()
    }

    pub(crate) fn extract_with_parent<'tree>(
        &self,
        node: Node<'tree>,
        kind: NormalizedKind,
        sink: &mut RoleSink<'_>,
        parent_of: impl Fn(Node<'tree>) -> Option<Node<'tree>>,
    ) {
        if let Some(role) = js_ts_occurrence_role(node, &parent_of) {
            sink.occurrence_role(node, role);
        }
        match kind {
            NormalizedKind::Call => {
                let callee_field = if node.kind() == "new_expression" {
                    "constructor"
                } else {
                    "function"
                };
                if let Some(function) = node.child_by_field_name(callee_field) {
                    attach_terminal_callee(
                        sink,
                        function,
                        terminal_callee_leaf(function, callee_spine_step),
                    );
                    if function.kind() == "member_expression"
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
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                if let Some(property) = node.child_by_field_name("property") {
                    sink.set_name(property);
                    sink.role_named(Role::Field, property, property);
                }
                if let Some(object) = node.child_by_field_name("object") {
                    attach_role_with_derived_name(sink, Role::Object, object, expression_name_node);
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Declaration => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Parameter => {
                if let Some(name) = parameter_name_node(node) {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        attach_role_with_derived_name(sink, Role::Left, name, expression_name_node);
                        if let Some(name_node) = expression_name_node(name) {
                            sink.set_name(name_node);
                        }
                    }
                    if let Some(value) = node.child_by_field_name("value") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                "assignment_expression" => {
                    if let Some(operator) = js_ts_assignment_operator(node) {
                        sink.role(Role::Operator, operator);
                    }
                    if let Some(left) = node.child_by_field_name("left") {
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                }
                _ => {}
            },
            NormalizedKind::Import => {
                if let Some(source) = node.child_by_field_name("source") {
                    if let Some(name) = unquoted_string_span(source) {
                        sink.role_named_span(Role::Module, source, name);
                    } else {
                        attach_role_with_derived_name(
                            sink,
                            Role::Module,
                            source,
                            expression_name_node,
                        );
                    }
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            NormalizedKind::Decorator => {
                if let Some(name) = first_named_child(node).and_then(expression_name_node) {
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
            NormalizedKind::CollectionLiteral => {
                attach_collection_elements(sink, node);
            }
            NormalizedKind::JsxElement => {
                attach_jsx_element_roles(sink, node);
            }
            NormalizedKind::JsxAttribute => {
                if let Some(name) = node
                    .named_child(0)
                    .filter(|name| name.kind() == "property_identifier")
                {
                    sink.set_name(name);
                }
                if let Some(value) = jsx_attribute_value(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::JsxSpreadAttribute => {
                if let Some(value) = jsx_spread_operand(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::ObjectProperty => {
                attach_object_property_roles(sink, node);
            }
            NormalizedKind::ComputedProperty => {
                if let Some(value) = first_named_child(node) {
                    sink.role(Role::Value, value);
                }
            }
            NormalizedKind::SpreadElement => {
                if let Some(value) = first_named_child(node) {
                    sink.role(Role::Value, value);
                }
            }
            _ => {}
        }
    }
}

impl StructuralSpec for JsTsStructuralSpec {
    fn language(&self) -> Language {
        self.language
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn supports_string_literal_value(&self) -> bool {
        true
    }

    fn string_literal_value_may_be_absent(&self, node: Node<'_>, source: &str) -> bool {
        matches!(node.kind(), "string" | "template_string")
            && js_ts_string_literal_value(node, source).is_none()
    }

    fn string_literal_value(&self, node: Node<'_>, source: &str) -> Option<String> {
        js_ts_string_literal_value(node, source)
    }

    fn supports_integer_literal_value(&self) -> bool {
        true
    }

    fn integer_literal_value(&self, node: Node<'_>, source: &str) -> Option<IntegerLiteralValue> {
        js_ts_integer_literal_value(node, source)
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        match self.language {
            Language::JavaScript => JS_KIND_TABLE,
            Language::TypeScript => TS_KIND_TABLE,
            _ => unreachable!("JS/TS structural spec only supports JavaScript and TypeScript"),
        }
    }

    fn refine_kind_with_parents<'tree>(
        &self,
        node: Node<'tree>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        source: &str,
        _context: &CallSiteContext,
        parents: &ParentIndex<'tree>,
    ) -> NormalizedKind {
        if kind == NormalizedKind::Identifier && js_ts_parameter_identifier(node, parents) {
            NormalizedKind::Parameter
        } else if kind == NormalizedKind::Method
            && node.kind() == "method_definition"
            && node
                .child_by_field_name("name")
                .and_then(|name| node_text(name, source))
                == Some("constructor")
        {
            NormalizedKind::Constructor
        } else {
            kind
        }
    }

    fn embedded_leaf_facts(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _source: &str,
        _cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> Vec<EmbeddedLeafFact> {
        if kind == NormalizedKind::Method
            && node.kind() == "method_definition"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "object")
        {
            vec![EmbeddedLeafFact {
                kind: NormalizedKind::ObjectProperty,
                range: node_range(node),
                parent: None,
                construct: None,
                occurrence_role: None,
            }]
        } else {
            Vec::new()
        }
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        self.should_extract_with_parent(node, kind, |node| node.parent())
    }

    fn call_site_facts(
        &self,
        node: Node<'_>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        // Both grammars distinguish construction from an ordinary call.
        (node.kind() == "new_expression").then(|| CallSiteFacts::of_kind(CallKind::Constructor))
    }

    fn supports_role(&self, role: Role) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_role_without_kwarg(role)
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        matches!(
            kind,
            NormalizedKind::Constructor | NormalizedKind::Parameter | NormalizedKind::SyntaxError
        ) || self
            .kind_table()
            .iter()
            .any(|(_, fact_kind)| fact_kind.satisfies(kind))
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &JS_TS_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &DEEP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &JS_TS_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &DEEP_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // `export { x }` resolves through the local binding (including an
        // imported one) to the origin declaration, so the export relation has
        // a producer. `export * from` names no token and contributes no row.
        static SUPPORT: IdentityRouteSupport = DEEP_IDENTITY_AXES
            .supported_relation(RouteHopKind::Export)
            .supported_relation(RouteHopKind::Import)
            .supported_relation(RouteHopKind::Alias)
            .supported_relation(RouteHopKind::ReExport)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn binding_scope_selection(
        &self,
        binder: Node<'_>,
        candidate: BindingScopeCandidate<'_>,
    ) -> BindingScopeSelection {
        js_ts_binding_scope_selection(binder, candidate)
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        js_ts_binding_activation(binder, scope)
    }

    fn declaration_binding_activation(
        &self,
        declaration_name: Node<'_>,
        scope: Range,
    ) -> Option<BindingActivation> {
        let parent = declaration_name.parent()?;
        matches!(
            parent.kind(),
            "function_declaration" | "generator_function_declaration"
        )
        .then(|| js_ts_binding_activation(declaration_name, scope))
        .flatten()
    }

    fn qualified_path_root<'tree>(&self, token: Node<'tree>) -> Option<Node<'tree>> {
        if !matches!(
            token.kind(),
            "identifier" | "property_identifier" | "type_identifier"
        ) {
            return None;
        }
        qualified_chain_root(token, JS_TS_PATH_CHAIN)
    }

    fn path_segment_tokens<'tree>(&self, root: Node<'tree>) -> Vec<Node<'tree>> {
        linear_chain_tokens(root, JS_TS_PATH_CHAIN, &[])
    }

    fn segment_generic_arity(&self, token: Node<'_>) -> Option<u32> {
        spelled_generic_arity(token, JS_TS_PATH_CHAIN, &["generic_type"])
    }

    fn generator_construct(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _source: &str,
    ) -> Option<&'static str> {
        if kind != NormalizedKind::CollectionLiteral {
            return None;
        }
        match node.kind() {
            "array" => Some("array"),
            "object" => Some("object"),
            _ => None,
        }
    }

    fn indirection_relation(
        &self,
        token: Node<'_>,
        _source: &str,
        _surface: &CuratedExportSurface,
    ) -> Option<RouteHopKind> {
        if let Some(export) = nearest_ancestor(token, |kind| kind == "export_statement") {
            return Some(if export.child_by_field_name("source").is_some() {
                RouteHopKind::ReExport
            } else {
                RouteHopKind::Export
            });
        }
        nearest_ancestor(token, |kind| kind == "import_statement").map(|_| RouteHopKind::Import)
    }

    /// The only scope segments this adapter classifies come from
    /// `nested_identifier`, which is a namespace qualifier in both grammars.
    fn occurrence_namespace(
        &self,
        role: OccurrenceRole,
        declares: Option<NormalizedKind>,
    ) -> Option<Namespace> {
        module_path_occurrence_namespace(role, declares)
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        self.extract_with_parent(node, kind, sink, |node| node.parent());
    }
}

fn js_ts_assignment_operator(assignment: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = assignment.walk();
    assignment.children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "=" | "+="
                | "-="
                | "*="
                | "/="
                | "%="
                | "^="
                | "&="
                | "|="
                | ">>="
                | ">>>="
                | "<<="
                | "**="
                | "&&="
                | "||="
                | "??="
        )
    })
}

/// One `elements` role edge per element of an `array` or `object` literal.
/// Every named child except comments is an element: array entries, object
/// pairs, spreads, shorthand properties, and object methods all count toward
/// the literal's element count.
fn attach_collection_elements(sink: &mut RoleSink<'_>, literal: Node<'_>) {
    for index in 0..literal.named_child_count() {
        let Some(child) = literal.named_child(index) else {
            continue;
        };
        if child.kind() == "comment" {
            continue;
        }
        attach_role_with_derived_name(sink, Role::Element, child, expression_name_node);
    }
}

#[cfg(test)]
mod result_use_tests {
    use super::{JsTsCallResultUseIndex, js_ts_call_result_use};
    use brokk_bifrost_core::analyzer::structural::result_use::{
        CallResultUse, IntentionalDiscardKind,
    };
    use tree_sitter::Parser;

    fn tree(source: &str, typescript: bool) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let language = if typescript {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        } else {
            tree_sitter_javascript::LANGUAGE.into()
        };
        parser.set_language(&language).expect("JS/TS grammar");
        parser.parse(source, None).expect("JS/TS tree")
    }

    fn call_nodes(tree: &tree_sitter::Tree) -> Vec<tree_sitter::Node<'_>> {
        let mut calls = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                calls.push(node);
            }
            for index in (0..node.named_child_count()).rev() {
                stack.push(node.named_child(index).expect("named child"));
            }
        }
        calls.sort_by_key(|node| node.start_byte());
        calls
    }

    #[test]
    fn statements_void_and_consumed_contexts_are_distinct_in_both_grammars() {
        for typescript in [false, true] {
            let source = if typescript {
                concat!(
                    "declare const s: string;\n",
                    "declare function sink(value: string): void;\n",
                    "s.trim();\n",
                    "void s.trim();\n",
                    "const value = s.trim();\n",
                    "sink(s.trim());\n",
                )
            } else {
                concat!(
                    "const s = 'value';\n",
                    "function sink(value) {}\n",
                    "s.trim();\n",
                    "void s.trim();\n",
                    "const value = s.trim();\n",
                    "sink(s.trim());\n",
                )
            };
            let tree = tree(source, typescript);
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let calls = call_nodes(&tree);
            assert_eq!(calls.len(), 5, "{}", tree.root_node().to_sexp());
            assert_eq!(
                js_ts_call_result_use(calls[0], source).default_use(),
                CallResultUse::Discarded
            );
            assert_eq!(
                js_ts_call_result_use(calls[1], source).default_use(),
                CallResultUse::IntentionalDiscard(IntentionalDiscardKind::JavaScriptVoid)
            );
            assert_eq!(
                js_ts_call_result_use(calls[2], source).default_use(),
                CallResultUse::Consumed
            );
            assert_eq!(
                js_ts_call_result_use(calls[3], source).default_use(),
                CallResultUse::Discarded
            );
            assert_eq!(
                js_ts_call_result_use(calls[4], source).default_use(),
                CallResultUse::Consumed
            );
        }
    }

    #[test]
    fn exact_index_uses_the_call_span_and_recovery_stays_open() {
        let source = "declare const s: string; s.trim();";
        let parsed = tree(source, false);
        let calls = call_nodes(&parsed);
        let index = JsTsCallResultUseIndex::new(parsed.root_node(), source);
        assert_eq!(
            index
                .at_span(calls[0].start_byte(), calls[0].end_byte())
                .expect("indexed call")
                .default_use(),
            CallResultUse::Discarded
        );
        assert!(index.at_span(source.len(), source.len()).is_err());

        let recovered_source = "const s = 'value'; s.trim(1 2);";
        let recovered_tree = tree(recovered_source, false);
        let recovered_calls = call_nodes(&recovered_tree);
        assert!(recovered_tree.root_node().has_error());
        assert!(
            matches!(
                js_ts_call_result_use(recovered_calls[0], recovered_source).default_use(),
                CallResultUse::Open(_)
            ),
            "{}",
            recovered_tree.root_node().to_sexp()
        );
    }
}

#[cfg(test)]
mod qualified_path_tests {
    use super::TYPESCRIPT_STRUCTURAL_SPEC;
    use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
    use tree_sitter::Parser;

    #[test]
    fn qualified_type_segments_keep_nested_generic_arity() {
        let cases = [
            (
                "type Result = Namespace.Outer<Inner<Leaf>>;",
                ["Namespace", "Outer"].as_slice(),
                [None, Some(1)].as_slice(),
            ),
            (
                "type Result = Library.Collection<Key, Value>;",
                ["Library", "Collection"].as_slice(),
                [None, Some(2)].as_slice(),
            ),
        ];
        for (source, expected_segments, expected_arities) in cases {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let mut paths = Vec::new();
            let mut stack = vec![tree.root_node()];
            while let Some(node) = stack.pop() {
                if node.kind() == "nested_type_identifier" {
                    paths.push(node);
                }
                for index in (0..node.named_child_count()).rev() {
                    stack.push(node.named_child(index).unwrap());
                }
            }
            let path = paths
                .into_iter()
                .max_by_key(|node| node.named_child_count())
                .unwrap_or_else(|| panic!("qualified type path: {}", tree.root_node().to_sexp()));
            let tokens = TYPESCRIPT_STRUCTURAL_SPEC.path_segment_tokens(path);
            let spellings: Vec<_> = tokens
                .iter()
                .map(|node| &source[node.start_byte()..node.end_byte()])
                .collect();
            assert_eq!(spellings, expected_segments);
            let arities: Vec<_> = tokens
                .iter()
                .map(|token| TYPESCRIPT_STRUCTURAL_SPEC.segment_generic_arity(*token))
                .collect();
            assert_eq!(arities, expected_arities);
        }
    }
}
