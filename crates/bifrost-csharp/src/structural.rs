//! C# structural spec for `query_code`.

use crate::syntax::{
    csharp_conditional_member_access, csharp_is_irrefutable_pattern, csharp_member_name,
};
use brokk_bifrost_core::analyzer::structural::adapter_helpers::{
    CalleeSpineStep, attach_decorators_under, attach_role_with_derived_name,
    attach_terminal_callee, csharp_integer_literal_value, first_named_child, terminal_callee_leaf,
};
use brokk_bifrost_core::analyzer::structural::callable::{
    CallKind, CallSiteContext, CallSiteFacts,
};
use brokk_bifrost_core::analyzer::structural::edges::{
    INVERSE_REFERENCE_EDGE_SUPPORT, ReferenceEdgeSupport,
};
use brokk_bifrost_core::analyzer::structural::facts::IntegerLiteralValue;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationMaterializationSupport, NO_MATERIALIZATION_SUPPORT,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    OccurrenceRole, OccurrenceRoleSupport,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingActivation, BindingKind, EnvironmentAxis, HoistingClass, LexicalEnvironmentSupport,
};
use brokk_bifrost_core::analyzer::structural::result_use::{
    CallResultUse, CallResultUseIndex, CallResultUseOpenReason, CallResultUseSite,
    IntentionalDiscardKind,
};
use brokk_bifrost_core::analyzer::structural::routes::{
    IdentityAxis, IdentityRouteSupport, RouteHopKind,
};
use brokk_bifrost_core::analyzer::structural::spec::{RoleSink, StructuralSpec};
use brokk_bifrost_core::analyzer::tree_walk::{
    named_children_iter, node_range, unwrap_parenthesized_expression,
};
use brokk_bifrost_core::analyzer::{Language, Range};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct CSharpStructuralSpec;

pub static CSHARP_STRUCTURAL_SPEC: CSharpStructuralSpec = CSharpStructuralSpec;

/// Classify the syntax around one exact C# invocation expression.
///
/// C# expression statements drop a result. The language's explicit discard
/// assignment (`_ = call()`) is retained as intentional discard, while every
/// other ordinary expression context consumes the value. Conditional access
/// is left open because nullable receiver dispatch is not the exact
/// `System.String` proof required by the reviewed BCL adapter.
pub fn csharp_call_result_use(call: Node<'_>, source: &str) -> CallResultUseSite {
    let default = if call.kind() != "invocation_expression"
        || call.has_error()
        || has_recovery_ancestor(call)
    {
        CallResultUse::Open(CallResultUseOpenReason::RecoveredSyntax)
    } else if has_deferred_ancestor(call) {
        CallResultUse::Open(CallResultUseOpenReason::DeferredContext)
    } else if has_conditional_access(call) {
        CallResultUse::Open(CallResultUseOpenReason::UnsupportedSyntax)
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
                "assignment_expression"
                    if parent
                        .child_by_field_name("right")
                        .is_some_and(|right| right.id() == expression.id()) =>
                {
                    let discard = parent.child_by_field_name("left").is_some_and(|left| {
                        left.kind() == "identifier"
                            && left
                                .utf8_text(source.as_bytes())
                                .is_ok_and(|text| text == "_")
                    });
                    break if discard {
                        CallResultUse::IntentionalDiscard(
                            IntentionalDiscardKind::CSharpDiscardAssignment,
                        )
                    } else {
                        CallResultUse::Consumed
                    };
                }
                "expression_statement"
                    if parent.named_child_count() == 1
                        && parent
                            .named_child(0)
                            .is_some_and(|child| child.id() == expression.id()) =>
                {
                    break CallResultUse::Discarded;
                }
                "lambda_expression" | "anonymous_method_expression" => {
                    break CallResultUse::Open(CallResultUseOpenReason::DeferredContext);
                }
                _ => break CallResultUse::Consumed,
            }
        }
    };
    CallResultUseSite::new(call.start_byte(), call.end_byte(), default)
}

fn has_recovery_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() {
            return true;
        }
        node = parent;
    }
    false
}

fn has_deferred_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "lambda_expression" | "anonymous_method_expression"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

fn has_conditional_access_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "conditional_access_expression" {
            return true;
        }
        node = parent;
    }
    false
}

fn has_conditional_access(call: Node<'_>) -> bool {
    call.child_by_field_name("function")
        .is_some_and(|function| function.kind() == "conditional_access_expression")
        || has_conditional_access_ancestor(call)
}

/// One source-snapshot index of exact C# invocation spans.
#[derive(Debug, Clone)]
pub struct CSharpCallResultUseIndex {
    inner: CallResultUseIndex,
}

impl CSharpCallResultUseIndex {
    pub fn new(root: Node<'_>, source: &str) -> Self {
        let mut sites = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "invocation_expression" {
                sites.push(csharp_call_result_use(node, source));
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

static CSHARP_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE
    .supported(OccurrenceRole::MemberPosition)
    .supported(OccurrenceRole::Binder);

pub const CSHARP_KIND_TABLE: &[(&str, NormalizedKind)] = &[
    ("binary_expression", NormalizedKind::BinaryExpression),
    ("prefix_unary_expression", NormalizedKind::UnaryExpression),
    ("postfix_unary_expression", NormalizedKind::UnaryExpression),
    ("is_pattern_expression", NormalizedKind::InstanceOf),
    ("conditional_expression", NormalizedKind::If),
    ("switch_expression", NormalizedKind::Switch),
    ("switch_section", NormalizedKind::Case),
    ("switch_expression_arm", NormalizedKind::Case),
    ("labeled_statement", NormalizedKind::Label),
    ("goto_statement", NormalizedKind::Goto),
    ("break_statement", NormalizedKind::Break),
    ("continue_statement", NormalizedKind::Continue),
    ("yield_statement", NormalizedKind::Yield),
    (
        "interpolated_string_expression",
        NormalizedKind::StringLiteral,
    ),
    ("cast_expression", NormalizedKind::Cast),
    ("as_expression", NormalizedKind::Cast),
    ("is_expression", NormalizedKind::InstanceOf),
    ("lock_statement", NormalizedKind::Lock),
    ("comment", NormalizedKind::Comment),
    ("invocation_expression", NormalizedKind::Call),
    ("object_creation_expression", NormalizedKind::Call),
    ("member_access_expression", NormalizedKind::FieldAccess),
    ("conditional_access_expression", NormalizedKind::FieldAccess),
    ("element_access_expression", NormalizedKind::FieldAccess),
    ("await_expression", NormalizedKind::Await),
    ("method_declaration", NormalizedKind::Method),
    ("operator_declaration", NormalizedKind::Method),
    ("conversion_operator_declaration", NormalizedKind::Method),
    ("constructor_declaration", NormalizedKind::Constructor),
    ("local_function_statement", NormalizedKind::Function),
    ("lambda_expression", NormalizedKind::Lambda),
    ("anonymous_method_expression", NormalizedKind::Lambda),
    ("parameter", NormalizedKind::Parameter),
    ("class_declaration", NormalizedKind::Class),
    ("interface_declaration", NormalizedKind::Class),
    ("struct_declaration", NormalizedKind::Class),
    ("enum_declaration", NormalizedKind::Class),
    ("record_declaration", NormalizedKind::Class),
    ("namespace_declaration", NormalizedKind::Module),
    ("file_scoped_namespace_declaration", NormalizedKind::Module),
    ("property_declaration", NormalizedKind::Declaration),
    ("variable_declarator", NormalizedKind::Assignment),
    ("assignment_expression", NormalizedKind::Assignment),
    ("using_directive", NormalizedKind::Import),
    ("attribute", NormalizedKind::Decorator),
    ("identifier", NormalizedKind::Identifier),
    // A lambda's unparenthesized parameter (`x => ..`) is its own token kind.
    ("implicit_parameter", NormalizedKind::Identifier),
    // A block is a local declaration space.
    ("block", NormalizedKind::Block),
    ("generic_name", NormalizedKind::Identifier),
    ("qualified_name", NormalizedKind::Identifier),
    ("alias_qualified_name", NormalizedKind::Identifier),
    ("predefined_type", NormalizedKind::Identifier),
    ("string_literal", NormalizedKind::StringLiteral),
    ("verbatim_string_literal", NormalizedKind::StringLiteral),
    ("raw_string_literal", NormalizedKind::StringLiteral),
    ("character_literal", NormalizedKind::CharacterLiteral),
    ("integer_literal", NormalizedKind::NumericLiteral),
    ("real_literal", NormalizedKind::NumericLiteral),
    ("boolean_literal", NormalizedKind::BooleanLiteral),
    ("null_literal", NormalizedKind::NullLiteral),
    ("return_statement", NormalizedKind::Return),
    ("throw_statement", NormalizedKind::Throw),
    ("throw_expression", NormalizedKind::Throw),
    ("catch_clause", NormalizedKind::Catch),
    ("if_statement", NormalizedKind::If),
    ("switch_statement", NormalizedKind::Switch),
    ("for_statement", NormalizedKind::Loop),
    ("foreach_statement", NormalizedKind::ForLoop),
    ("while_statement", NormalizedKind::WhileLoop),
    ("do_statement", NormalizedKind::WhileLoop),
];

use brokk_bifrost_core::analyzer::tree_walk::{expression_target_node, last_named_child};

/// Grammar steps for the shared call-callee spine. A value expression has no step.
pub fn callee_spine_step(kind: &str) -> Option<CalleeSpineStep> {
    use CalleeSpineStep::{ChildKind, Field, Name};
    match kind {
        "identifier" => Some(Name),
        "member_access_expression"
        | "member_binding_expression"
        | "qualified_name"
        | "alias_qualified_name" => Some(Field("name")),
        "generic_name" => Some(ChildKind("identifier")),
        "conditional_access_expression" => Some(ChildKind("member_binding_expression")),
        _ => None,
    }
}

fn expression_name_node<'tree>(expression: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = expression_target_node(expression);
    loop {
        match current.kind() {
            "identifier" | "predefined_type" => return Some(current),
            "generic_name" => current = first_named_child(current)?,
            "qualified_name" | "alias_qualified_name" => {
                current = current.child_by_field_name("name")?;
            }
            "invocation_expression" => current = current.child_by_field_name("function")?,
            "object_creation_expression" => current = current.child_by_field_name("type")?,
            "member_access_expression" => current = current.child_by_field_name("name")?,
            "conditional_access_expression" => current = conditional_member_binding(current)?,
            "member_binding_expression" | "attribute" => {
                current = current.child_by_field_name("name")?;
            }
            "argument" | "attribute_argument" => {
                current = first_argument_value(current).map(expression_target_node)?;
            }
            _ => return None,
        }
    }
}

fn is_numeric_literal_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "integer_literal" | "real_literal")
}

fn is_signed_numeric_prefix(node: Node<'_>) -> bool {
    if node.kind() != "prefix_unary_expression" {
        return false;
    }
    let operator = (0..node.child_count())
        .filter_map(|index| node.child(index))
        .find(|child| !child.is_named() && matches!(child.kind(), "+" | "-"))
        .map(|child| child.kind());
    brokk_bifrost_core::analyzer::tree_walk::is_signed_numeric_operand(
        last_named_child(node).map(expression_target_node),
        operator,
        is_numeric_literal_node,
    )
}

// These nodes have no operator field. Pointer forms are owned separately.
fn unary_operator(node: Node<'_>) -> Option<Node<'_>> {
    node.children(&mut node.walk()).find(|child| {
        !child.is_named() && matches!(child.kind(), "++" | "--" | "+" | "-" | "!" | "~" | "^")
    })
}

fn typed_pattern(node: Node<'_>) -> Option<Node<'_>> {
    let pattern = node.child_by_field_name("pattern")?;
    match pattern.kind() {
        "type_pattern" | "declaration_pattern" | "recursive_pattern" => pattern
            .child_by_field_name("type")
            .filter(|ty| ty.kind() != "implicit_type")
            .map(|_| pattern),
        _ => None,
    }
}

// Read label boundaries from grammar tokens, never from source spelling.
// Unknown or recovered labels must not acquire the empty Test set of default.
fn case_parts(node: Node<'_>) -> Option<(Vec<Node<'_>>, Vec<Node<'_>>)> {
    if node.has_error() || node.is_missing() {
        return None;
    }
    if node.kind() == "switch_expression_arm" {
        let mut children = named_children_iter(node).filter(|child| !child.is_extra());
        let pattern = children.next()?;
        let guarded = named_children_iter(node).any(|child| child.kind() == "when_clause");
        let body = children.find(|child| child.kind() != "when_clause")?;
        let tests = if !guarded && csharp_is_irrefutable_pattern(pattern) {
            Vec::new()
        } else {
            vec![pattern]
        };
        return Some((tests, vec![body]));
    }
    let mut tests = Vec::new();
    let mut body = Vec::new();
    let mut has_label = false;
    let mut header = false;
    let mut needs_test = false;
    let mut label_test = None;
    let mut guarded = false;
    for child in node
        .children(&mut node.walk())
        .filter(|child| !child.is_extra())
    {
        match child.kind() {
            "case" => {
                has_label = true;
                header = true;
                needs_test = true;
                label_test = None;
                guarded = false;
            }
            "default" => {
                has_label = true;
                header = true;
                label_test = None;
                guarded = false;
            }
            ":" => {
                if needs_test {
                    return None;
                }
                if let Some(test) = label_test.take()
                    && (guarded || !csharp_is_irrefutable_pattern(test))
                {
                    tests.push(test);
                }
                header = false;
            }
            _ if needs_test && child.is_named() => {
                label_test = Some(child);
                needs_test = false;
            }
            "when_clause" if header => guarded = true,
            _ if child.is_named() && !header => body.push(child),
            _ => return None,
        }
    }
    (has_label && !header && !needs_test).then_some((tests, body))
}

fn csharp_string_literal_value(node: Node<'_>, source: &str) -> Option<String> {
    let spelling = node.utf8_text(source.as_bytes()).ok()?;
    match node.kind() {
        "string_literal" => {
            let content = spelling.strip_prefix('"')?.strip_suffix('"')?;
            decode_csharp_cooked_string(content)
        }
        "verbatim_string_literal" => {
            let opening = spelling.find('"')?;
            let prefix = spelling.get(..opening)?;
            if !prefix.contains('@') {
                return None;
            }
            let content = spelling.get(opening + 1..spelling.len().checked_sub(1)?)?;
            let mut value = String::with_capacity(content.len());
            let mut chars = content.chars();
            while let Some(character) = chars.next() {
                if character == '"' {
                    if chars.next() != Some('"') {
                        return None;
                    }
                    value.push('"');
                } else {
                    value.push(character);
                }
            }
            Some(value)
        }
        "character_literal" => {
            let content = spelling.strip_prefix('\'')?.strip_suffix('\'')?;
            decode_csharp_cooked_string(content)
        }
        // Raw strings have indentation and interpolation rules that depend on
        // the complete literal token. Leave unsupported forms incomplete
        // rather than publishing a guessed value.
        "raw_string_literal" => None,
        _ => None,
    }
}

fn decode_csharp_cooked_string(content: &str) -> Option<String> {
    let mut value = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }
        let escape = chars.next()?;
        let decoded = match escape {
            'a' => '\x07',
            'b' => '\x08',
            'f' => '\x0c',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\x0b',
            '0' => '\0',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            '\n' => continue,
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                continue;
            }
            'x' => decode_csharp_unicode_escape(&mut chars, 1, 4)?,
            'u' => decode_csharp_unicode_escape(&mut chars, 4, 4)?,
            'U' => decode_csharp_unicode_escape(&mut chars, 8, 8)?,
            _ => return None,
        };
        value.push(decoded);
    }
    Some(value)
}

fn decode_csharp_unicode_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    minimum_digits: usize,
    maximum_digits: usize,
) -> Option<char> {
    let mut digits = String::new();
    while digits.len() < maximum_digits {
        let Some(character) = chars.peek().copied() else {
            break;
        };
        if !character.is_ascii_hexdigit() {
            break;
        }
        chars.next();
        digits.push(character);
    }
    if digits.len() < minimum_digits {
        return None;
    }
    char::from_u32(u32::from_str_radix(&digits, 16).ok()?)
}

fn is_inside_signed_numeric_wrapper(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    is_signed_numeric_prefix(parent)
}

fn callable_target_node(node: Node<'_>) -> Option<Node<'_>> {
    Some(expression_target_node(node))
}

fn conditional_member_binding(node: Node<'_>) -> Option<Node<'_>> {
    csharp_conditional_member_access(node).map(|access| access.binding)
}

/// Classify the terminal identifier of an ordinary or conditional member name.
///
/// A generic member name inserts one `generic_name` wrapper between the
/// identifier and its owning access node. Checking the owning node's `name`
/// field keeps receivers, declaration names and named-argument labels out of
/// the member-position role without inspecting source text.
fn csharp_member_position(node: Node<'_>) -> Option<OccurrenceRole> {
    if node.kind() != "identifier" {
        return None;
    }

    let parent = node.parent()?;
    let member_name = match parent.kind() {
        "member_access_expression" | "member_binding_expression" => {
            parent.child_by_field_name("name")?
        }
        "generic_name" => {
            let access = parent.parent()?;
            if !matches!(
                access.kind(),
                "member_access_expression" | "member_binding_expression"
            ) || access.child_by_field_name("name") != Some(parent)
            {
                return None;
            }
            parent
        }
        _ => return None,
    };

    csharp_member_name(member_name)
        .is_some_and(|member| member.identifier.id() == node.id())
        .then_some(OccurrenceRole::MemberPosition)
}

/// C# derives its scope tree from the callable, class-like, loop, catch and
/// block facts in [`CSHARP_KIND_TABLE`], and every binder it classifies states
/// an interval through [`csharp_binding_activation`] or declines. Import
/// binders and the package clause are not derived; the member walk reports
/// per-candidate callable applicability (#1478 M3).
static CSHARP_LEXICAL_ENVIRONMENT_SUPPORT: LexicalEnvironmentSupport =
    LexicalEnvironmentSupport::NONE
        .supported(EnvironmentAxis::Scopes)
        .supported(EnvironmentAxis::BindingIntervals)
        .supported(EnvironmentAxis::CallableApplicability);

/// The pattern and designation kinds whose `name` field declares a variable.
const CSHARP_PATTERN_BINDERS: &[&str] = &[
    "declaration_pattern",
    "var_pattern",
    "recursive_pattern",
    "list_pattern",
    "tuple_pattern",
    "parenthesized_variable_designation",
];

/// The pattern declaring one identifier. Inspecting each token preserves
/// repeated name fields in deconstruction designations and nested patterns.
pub fn csharp_pattern_binding_declaration(name: Node<'_>) -> Option<Node<'_>> {
    let declaration = name.parent()?;
    (CSHARP_PATTERN_BINDERS.contains(&declaration.kind()) && csharp_is_binder(name))
        .then_some(declaration)
}

/// Declaration spaces that need lexical lookup without an enclosing block.
pub fn csharp_pattern_scope(kind: &str) -> bool {
    matches!(
        kind,
        "arrow_expression_clause"
            | "lambda_expression"
            | "switch_expression_arm"
            | "switch_section"
    )
}

/// C# pattern lookup uses declaration order within its declaration space.
pub fn csharp_pattern_binding_visible(pattern: Node<'_>, focus: Node<'_>) -> Option<bool> {
    Some(pattern.end_byte() <= focus.start_byte())
}

/// Expression bodies and switch arms confine their pattern declarations.
pub fn csharp_pattern_bindings_may_escape_scope(kind: &str) -> bool {
    debug_assert!(csharp_pattern_scope(kind));
    false
}

/// The LINQ clauses that introduce a range variable.
const CSHARP_QUERY_BINDERS: &[&str] = &[
    "from_clause",
    "let_clause",
    "join_clause",
    "join_into_clause",
    "query_continuation",
];

/// Whether `node` is the token that declares a C# local, parameter, pattern
/// or query variable. A field's declarator names a member, not a binding.
fn csharp_is_binder(node: Node<'_>) -> bool {
    if node.kind() == "implicit_parameter" {
        return true;
    }
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    let named = |field: &str| parent.child_by_field_name(field) == Some(node);
    match parent.kind() {
        "variable_declarator" => {
            named("name")
                && parent
                    .parent()
                    .and_then(|declaration| declaration.parent())
                    .is_some_and(|owner| {
                        !matches!(
                            owner.kind(),
                            "field_declaration" | "event_field_declaration"
                        )
                    })
        }
        "parameter" | "catch_declaration" | "declaration_expression" | "from_clause" => {
            named("name")
        }
        "foreach_statement" => named("left"),
        // A designation lists every name it declares in its `name` field.
        kind if CSHARP_PATTERN_BINDERS.contains(&kind) => {
            let mut cursor = parent.walk();
            parent
                .children_by_field_name("name", &mut cursor)
                .any(|name| name.id() == node.id())
        }
        // A let, join, into or continuation clause names its variable with
        // the first identifier after its keyword; its expressions follow.
        kind if CSHARP_QUERY_BINDERS.contains(&kind) => {
            let mut cursor = parent.walk();
            parent.named_children(&mut cursor).find(|child| {
                child.kind() == "identifier" && parent.child_by_field_name("type") != Some(*child)
            }) == Some(node)
        }
        _ => false,
    }
}

/// The binding one C# binder token introduces, and the interval it is in
/// effect over.
///
/// A C# local's scope is its whole enclosing block (its declaration space);
/// using it before its declarator is an error, not a reference to an outer
/// binding, and a nested block may not redeclare the name. So a local, an
/// `out var` and a pattern variable are `ScopeWide` over the scope that
/// declares them. Parameters are `ScopeWide` over their callable. A
/// `using`/`fixed` resource is in effect over its statement, a catch variable
/// over its catch clause, and a `foreach` variable over the loop body. A LINQ
/// range variable states no interval: its scope is the rest of the query,
/// which this adapter does not model, so the file reports incomplete.
fn csharp_binding_activation(binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
    let binding = |kind, hoisting, activation| {
        Some(BindingActivation {
            kind,
            hoisting,
            activation,
        })
    };
    if binder.kind() == "implicit_parameter" {
        return binding(BindingKind::Parameter, HoistingClass::ScopeWide, scope);
    }
    let parent = binder.parent()?;
    match parent.kind() {
        "parameter" => binding(BindingKind::Parameter, HoistingClass::ScopeWide, scope),
        "catch_declaration" => binding(
            BindingKind::CatchOrResource,
            HoistingClass::DeclaredHead,
            node_range(parent.parent()?),
        ),
        "foreach_statement" => binding(
            BindingKind::LoopVariable,
            HoistingClass::DeclaredHead,
            node_range(parent.child_by_field_name("body")?),
        ),
        "variable_declarator" => {
            let statement = parent.parent()?.parent()?;
            if matches!(statement.kind(), "using_statement" | "fixed_statement") {
                return binding(
                    BindingKind::CatchOrResource,
                    HoistingClass::DeclaredHead,
                    node_range(statement),
                );
            }
            binding(BindingKind::Local, HoistingClass::ScopeWide, scope)
        }
        "declaration_expression" => binding(BindingKind::Local, HoistingClass::ScopeWide, scope),
        kind if CSHARP_PATTERN_BINDERS.contains(&kind) => {
            // A deconstructing `foreach` binds its loop variables.
            let foreach = std::iter::successors(Some(parent), |node| node.parent())
                .take_while(|node| {
                    CSHARP_PATTERN_BINDERS.contains(&node.kind())
                        || node.kind() == "declaration_expression"
                        || node.kind() == "foreach_statement"
                })
                .find(|node| node.kind() == "foreach_statement");
            match foreach {
                Some(foreach) => binding(
                    BindingKind::LoopVariable,
                    HoistingClass::DeclaredHead,
                    node_range(foreach.child_by_field_name("body")?),
                ),
                None => binding(BindingKind::PatternBinder, HoistingClass::ScopeWide, scope),
            }
        }
        _ => None,
    }
}

pub fn first_argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    if argument.kind() != "argument" {
        return Some(argument);
    }
    let keyword = argument.child_by_field_name("name");
    argument
        .child_by_field_name("value")
        .or_else(|| argument.child_by_field_name("expression"))
        .or_else(|| {
            brokk_bifrost_core::analyzer::tree_walk::named_children_iter(argument)
                .find(|child| keyword.is_none_or(|keyword| child.id() != keyword.id()))
        })
}

fn attach_argument_roles(sink: &mut RoleSink<'_>, arguments: Node<'_>) {
    for index in 0..arguments.named_child_count() {
        if !sink.should_continue() {
            break;
        }
        let Some(argument) = arguments.named_child(index) else {
            continue;
        };
        if argument.kind() != "argument" {
            continue;
        }
        let keyword = argument.child_by_field_name("name");
        if let Some(value) = first_argument_value(argument).map(expression_target_node) {
            if let Some(keyword) = keyword {
                sink.kwarg(keyword, value);
            } else {
                attach_role_with_derived_name(sink, Role::Arg, value, expression_name_node);
            }
        }
    }
}

fn attach_decorators(sink: &mut RoleSink<'_>, declaration: Node<'_>) {
    attach_decorators_under(
        sink,
        declaration,
        "attribute_list",
        &["attribute"],
        expression_name_node,
    );
}

fn variable_declarator_value(node: Node<'_>) -> Option<Node<'_>> {
    crate::syntax::variable_declarator_initializer(node).map(expression_target_node)
}

fn using_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let alias = node.child_by_field_name("name");
    (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| alias.is_none_or(|alias| child.id() != alias.id()))
}

fn attach_module_binding(sink: &mut RoleSink<'_>, target: Node<'_>, name: Node<'_>) {
    if let Some(first) = crate::syntax::csharp_type_leftmost_identifier(target)
        && first.id() != name.id()
    {
        sink.role_named_between_nodes(Role::Module, target, first, name);
    } else {
        sink.role_named(Role::Module, target, name);
    }
}

fn attach_import_modules(sink: &mut RoleSink<'_>, node: Node<'_>) {
    if let Some(alias) = node.child_by_field_name("name") {
        sink.role_named(Role::Module, node, alias);
        return;
    }
    if let Some(target) = using_type_node(node)
        && let Some(name) = expression_name_node(target)
    {
        attach_module_binding(sink, target, name);
    }
}

impl StructuralSpec for CSharpStructuralSpec {
    fn statement_fact_syntax(
        &self,
    ) -> Option<&dyn brokk_bifrost_core::analyzer::statement_facts::producer::StatementFactSyntax>
    {
        Some(self)
    }

    fn language(&self) -> Language {
        Language::CSharp
    }

    fn supports_boolean_literal_value(&self) -> bool {
        true
    }

    fn supports_integer_literal_value(&self) -> bool {
        true
    }

    fn integer_literal_value(&self, node: Node<'_>, source: &str) -> Option<IntegerLiteralValue> {
        csharp_integer_literal_value(node, source)
    }

    fn supports_string_literal_value(&self) -> bool {
        true
    }

    fn string_literal_value_may_be_absent(&self, node: Node<'_>, source: &str) -> bool {
        csharp_string_literal_value(node, source).is_none()
    }

    fn string_literal_value(&self, node: Node<'_>, source: &str) -> Option<String> {
        csharp_string_literal_value(node, source)
    }

    fn preprocess(
        &self,
        source: &str,
    ) -> Option<std::sync::Arc<dyn brokk_bifrost_core::analyzer::prepared_syntax::SourcePreprocessor>>
    {
        Some(std::sync::Arc::new(crate::preprocessor::scan_preprocessor(
            source,
        )))
    }

    fn parser_included_ranges(&self, source: &str) -> Option<Vec<tree_sitter::Range>> {
        crate::preprocessor::csharp_included_ranges(source)
    }

    fn declaration_attributes(
        &self,
        node: Node<'_>,
        source: &str,
    ) -> Option<brokk_bifrost_core::analyzer::structural::facts::DeclarationAttributes> {
        if !matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "struct_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
        ) {
            return None;
        }
        Some(brokk_bifrost_core::analyzer::structural::facts::DeclarationAttributes {
            modifiers: brokk_bifrost_core::analyzer::structural::adapter_helpers::declaration_modifier_words(node, source),
            type_kind: None,
        })
    }

    fn kind_table(&self) -> &'static [(&'static str, NormalizedKind)] {
        CSHARP_KIND_TABLE
    }

    fn supports_kind(&self, kind: NormalizedKind) -> bool {
        brokk_bifrost_core::analyzer::structural::spec::supports_kind_from_table(
            kind,
            &[NormalizedKind::SyntaxError, NormalizedKind::Comparison],
            self.kind_table(),
        )
    }

    fn refine_kind(
        &self,
        node: Node<'_>,
        kind: NormalizedKind,
        _enclosing: Option<NormalizedKind>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> NormalizedKind {
        if node.kind() == "variable_declarator" && variable_declarator_value(node).is_none() {
            return NormalizedKind::Declaration;
        }
        if kind == NormalizedKind::UnaryExpression && is_signed_numeric_prefix(node) {
            return NormalizedKind::NumericLiteral;
        }
        if kind == NormalizedKind::BinaryExpression
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| {
                    matches!(operator.kind(), "==" | "!=" | "<" | ">" | "<=" | ">=")
                })
        {
            return NormalizedKind::Comparison;
        }
        kind
    }

    fn should_extract(&self, node: Node<'_>, kind: NormalizedKind) -> bool {
        if kind == NormalizedKind::UnaryExpression {
            return unary_operator(node).is_some_and(|operator| {
                node.kind() != "postfix_unary_expression" || operator.kind() != "!"
            });
        }
        if node.kind() == "is_pattern_expression" {
            return typed_pattern(node).is_some();
        }
        if kind == NormalizedKind::Case {
            return case_parts(node).is_some();
        }
        if kind == NormalizedKind::FieldAccess && node.kind() == "conditional_access_expression" {
            return conditional_member_binding(node).is_some();
        }

        if kind == NormalizedKind::NumericLiteral
            && is_numeric_literal_node(node)
            && is_inside_signed_numeric_wrapper(node)
        {
            return false;
        }

        true
    }

    /// C# spells object creation as its own grammar node, so a constructor
    /// call is a node-type reading (#1478). Named arguments already reach the
    /// shared arena as keyword roles and need no classification here.
    fn call_site_facts(
        &self,
        node: Node<'_>,
        _source: &str,
        _context: &CallSiteContext,
    ) -> Option<CallSiteFacts> {
        (node.kind() == "object_creation_expression")
            .then(|| CallSiteFacts::of_kind(CallKind::Constructor))
    }

    fn supports_role(&self, role: Role) -> bool {
        // #2647: not yet extracted by this adapter.
        brokk_bifrost_core::analyzer::structural::spec::supports_role_without_iterable_or_element(
            role,
        )
    }

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport {
        &CSHARP_OCCURRENCE_ROLE_SUPPORT
    }

    fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport {
        &CSHARP_LEXICAL_ENVIRONMENT_SUPPORT
    }

    fn binding_activation(&self, binder: Node<'_>, scope: Range) -> Option<BindingActivation> {
        csharp_binding_activation(binder, scope)
    }

    fn materialization_support(&self) -> &DeclarationMaterializationSupport {
        &NO_MATERIALIZATION_SUPPORT
    }

    fn reference_edge_support(&self) -> &ReferenceEdgeSupport {
        &INVERSE_REFERENCE_EDGE_SUPPORT
    }

    fn identity_route_support(&self) -> &IdentityRouteSupport {
        // C#'s occurrence adapter is shallow, so it claims no path axes; its
        // declaration layer does enumerate the parts of a partial type, which
        // is exactly the partial-part relation.
        static SUPPORT: IdentityRouteSupport = IdentityRouteSupport::NONE
            .supported_axis(IdentityAxis::CanonicalIdentity)
            .supported_axis(IdentityAxis::PhysicalGrouping)
            .supported_relation(RouteHopKind::PartialPart)
            .supported_relation(RouteHopKind::NestedOwner);
        &SUPPORT
    }

    fn extract(&self, node: Node<'_>, kind: NormalizedKind, sink: &mut RoleSink<'_>) {
        if let Some(role) = csharp_member_position(node) {
            sink.occurrence_role(node, role);
        } else if csharp_is_binder(node) {
            sink.occurrence_role(node, OccurrenceRole::Binder);
        }

        match kind {
            NormalizedKind::BinaryExpression | NormalizedKind::Comparison => {
                brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles(
                    sink,
                    node,
                    &[
                        (Role::Left, "left"),
                        (Role::Right, "right"),
                        (Role::Operator, "operator"),
                    ],
                    expression_name_node,
                );
            }
            NormalizedKind::UnaryExpression => {
                if let Some(operator) = unary_operator(node) {
                    sink.role_named(Role::Operator, operator, operator);
                }
                if let Some(operand) = named_children_iter(node).find(|child| !child.is_extra()) {
                    attach_role_with_derived_name(
                        sink,
                        Role::Operand,
                        expression_target_node(operand),
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::InstanceOf if node.kind() == "is_pattern_expression" => {
                let pattern = typed_pattern(node).expect("admitted typed pattern");
                brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles(
                    sink,
                    node,
                    &[(Role::Operand, "expression")],
                    expression_name_node,
                );
                brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles(
                    sink,
                    pattern,
                    &[(Role::Type, "type"), (Role::Binding, "name")],
                    expression_name_node,
                );
                for designation in named_children_iter(pattern).filter(|child| {
                    matches!(
                        child.kind(),
                        "discard" | "parenthesized_variable_designation"
                    )
                }) {
                    sink.role(Role::Binding, designation);
                }
            }
            NormalizedKind::If => {
                brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles(
                    sink,
                    node,
                    &[
                        (Role::Test, "condition"),
                        (Role::Consequence, "consequence"),
                        (Role::Alternative, "alternative"),
                    ],
                    expression_name_node,
                );
            }
            NormalizedKind::Switch => {
                if node.kind() == "switch_statement" {
                    brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles(
                        sink,
                        node,
                        &[(Role::Test, "value"), (Role::Body, "body")],
                        expression_name_node,
                    );
                } else if let Some(test) = named_children_iter(node).find(|child| !child.is_extra())
                {
                    sink.role(Role::Test, expression_target_node(test));
                }
            }
            NormalizedKind::Case => {
                let (tests, body) = case_parts(node).expect("admitted case label");
                for test in tests {
                    sink.role(Role::Test, expression_target_node(test));
                }
                for statement in body {
                    // A switch-expression arm's body is an expression, so its
                    // parentheses are stripped like any other expression role.
                    sink.role(Role::Body, expression_target_node(statement));
                }
            }
            NormalizedKind::Label => {
                let mut children = named_children_iter(node).filter(|child| !child.is_extra());
                if let Some(label) = children.next() {
                    sink.role_named(Role::Label, label, label);
                }
                if let Some(body) = children.next() {
                    sink.role(Role::Body, body);
                }
            }
            NormalizedKind::Return | NormalizedKind::Throw => {
                if let Some(value) = named_children_iter(node).find(|child| !child.is_extra()) {
                    attach_role_with_derived_name(
                        sink,
                        Role::Value,
                        expression_target_node(value),
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::StringLiteral if node.kind() == "interpolated_string_expression" => {
                for interpolation in
                    named_children_iter(node).filter(|child| child.kind() == "interpolation")
                {
                    if let Some(expression) = named_children_iter(interpolation).find(|child| {
                        !child.is_extra()
                            && !matches!(
                                child.kind(),
                                "interpolation_brace"
                                    | "interpolation_alignment_clause"
                                    | "interpolation_format_clause"
                            )
                    }) {
                        sink.role(Role::Part, expression_target_node(expression));
                    }
                }
            }
            NormalizedKind::Lambda => attach_decorators(sink, node),
            NormalizedKind::Cast | NormalizedKind::InstanceOf => {
                let fields: &[(Role, &str)] = match node.kind() {
                    "cast_expression" => &[(Role::Type, "type"), (Role::Value, "value")],
                    "as_expression" => &[(Role::Value, "left"), (Role::Type, "right")],
                    _ => &[(Role::Operand, "left"), (Role::Type, "right")],
                };
                brokk_bifrost_core::analyzer::structural::adapter_helpers::attach_field_roles(
                    sink,
                    node,
                    fields,
                    expression_name_node,
                );
            }
            NormalizedKind::Lock => {
                let mut cursor = node.walk();
                let mut children = node
                    .named_children(&mut cursor)
                    .filter(|child| !child.is_extra());
                if let Some(value) = children.next() {
                    attach_role_with_derived_name(
                        sink,
                        Role::Value,
                        expression_target_node(value),
                        expression_name_node,
                    );
                }
                if let Some(body) = children.next() {
                    sink.role(Role::Body, body);
                }
            }

            NormalizedKind::Call => {
                let function = if node.kind() == "object_creation_expression" {
                    node.child_by_field_name("type")
                } else {
                    node.child_by_field_name("function")
                };
                if let Some(function) = function {
                    if let Some(leaf) = terminal_callee_leaf(function, callee_spine_step) {
                        let name = leaf
                            .parent()
                            .filter(|parent| parent.kind() == "generic_name")
                            .unwrap_or(leaf);
                        if let Some(arguments) =
                            csharp_member_name(name).and_then(|name| name.type_arguments)
                        {
                            for argument in
                                named_children_iter(arguments).filter(|child| !child.is_extra())
                            {
                                attach_role_with_derived_name(
                                    sink,
                                    Role::TypeArguments,
                                    argument,
                                    expression_name_node,
                                );
                            }
                        }
                    }
                    attach_terminal_callee(
                        sink,
                        function,
                        terminal_callee_leaf(function, callee_spine_step),
                    );
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "member_access_expression"
                        && let Some(receiver) = target.child_by_field_name("expression")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            expression_target_node(receiver),
                            expression_name_node,
                        );
                    }
                    if let Some(target) = callable_target_node(function)
                        && target.kind() == "conditional_access_expression"
                        && let Some(receiver) = target.child_by_field_name("condition")
                    {
                        attach_role_with_derived_name(
                            sink,
                            Role::Receiver,
                            expression_target_node(receiver),
                            expression_name_node,
                        );
                    }
                }
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    attach_argument_roles(sink, arguments);
                }
            }
            NormalizedKind::FieldAccess => {
                if node.kind() == "element_access_expression" {
                    if let Some(object) = node.child_by_field_name("expression") {
                        attach_role_with_derived_name(
                            sink,
                            Role::Object,
                            expression_target_node(object),
                            expression_name_node,
                        );
                    }
                    // The source syntax has no identifier for an indexer. The
                    // analysis resolver supplies the CLR property name `Item`
                    // after it has selected this structured AST node.
                    sink.role(Role::Field, node);
                    return;
                }
                let field = if node.kind() == "conditional_access_expression" {
                    conditional_member_binding(node)
                        .and_then(|binding| binding.child_by_field_name("name"))
                } else {
                    node.child_by_field_name("name")
                };
                if let Some(field) = field {
                    attach_role_with_derived_name(sink, Role::Field, field, expression_name_node);
                    if let Some(name) = expression_name_node(field) {
                        sink.set_name(name);
                    }
                }
                let object = if node.kind() == "conditional_access_expression" {
                    node.child_by_field_name("condition")
                } else {
                    node.child_by_field_name("expression")
                };
                if let Some(object) = object {
                    attach_role_with_derived_name(
                        sink,
                        Role::Object,
                        expression_target_node(object),
                        expression_name_node,
                    );
                }
            }
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Class
            | NormalizedKind::Module
            | NormalizedKind::Declaration => {
                // A namespace's `name` is a `qualified_name` for
                // `namespace App.Support`, so the fact takes the terminal
                // segment the same way a qualified callee or import does.
                // Every other declaration head names a bare identifier, which
                // `expression_name_node` returns unchanged.
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(expression_name_node(name).unwrap_or(name));
                }
                attach_decorators(sink, node);
            }
            // A parameter's attributes sit in its own attribute lists, which
            // is how `[FromQuery]` and other binding attributes reach the
            // shared decorator relation.
            NormalizedKind::Parameter => {
                if let Some(name) = node.child_by_field_name("name") {
                    sink.set_name(name);
                }
                attach_decorators(sink, node);
            }
            NormalizedKind::Assignment => match node.kind() {
                "variable_declarator" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        sink.role_named(Role::Left, name, name);
                        sink.set_name(name);
                    }
                    if let Some(value) = variable_declarator_value(node) {
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            value,
                            expression_name_node,
                        );
                    }
                }
                _ => {
                    if let Some(left) = node.child_by_field_name("left") {
                        let left = expression_target_node(left);
                        attach_role_with_derived_name(sink, Role::Left, left, expression_name_node);
                        if let Some(name) = expression_name_node(left) {
                            sink.set_name(name);
                        }
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        let right = expression_target_node(right);
                        attach_role_with_derived_name(
                            sink,
                            Role::Right,
                            right,
                            expression_name_node,
                        );
                    }
                    if let Some(operator) = node.child_by_field_name("operator") {
                        sink.role_named(Role::Operator, operator, operator);
                    }
                }
            },
            NormalizedKind::Import => attach_import_modules(sink, node),
            NormalizedKind::Decorator => {
                if let Some(name) = node.child_by_field_name("name") {
                    attach_terminal_callee(sink, name, expression_name_node(name).or(Some(name)));
                }
            }
            NormalizedKind::Identifier => match expression_name_node(node) {
                Some(name) => sink.set_name(name),
                None => sink.set_name(node),
            },
            _ => {}
        }
    }
}

impl brokk_bifrost_core::analyzer::statement_facts::producer::StatementFactSyntax
    for CSharpStructuralSpec
{
    fn supports_kind(
        &self,
        kind: brokk_bifrost_core::analyzer::statement_facts::StatementFactKind,
    ) -> bool {
        use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;
        !matches!(
            kind,
            StatementFactKind::MissingCaseInSwitch | StatementFactKind::AllocaInLoop
        )
    }

    fn is_indentation_loop(&self, node: Node<'_>) -> bool {
        matches!(
            node.kind(),
            "for_statement" | "foreach_statement" | "while_statement"
        )
    }

    fn is_transparent_body_owner(&self, node: Node<'_>) -> bool {
        matches!(
            node.kind(),
            "lock_statement" | "using_statement" | "fixed_statement"
        )
    }

    fn reaches_following_statement(&self, node: Node<'_>, source: &str) -> bool {
        match node.kind() {
            "return_statement" | "throw_statement" | "break_statement" | "continue_statement"
            | "goto_statement" | "lock_statement" | "using_statement" | "try_statement"
            | "checked_statement" | "unsafe_statement" | "fixed_statement"
            | "labeled_statement" => false,
            "yield_statement" => !node
                .children(&mut node.walk())
                .any(|child| child.kind() == "break"),
            "for_statement" | "while_statement" | "do_statement" => {
                match node.child_by_field_name("condition") {
                    None => false,
                    Some(condition) => {
                        let condition = unwrap_parenthesized_expression(condition);
                        !(condition.kind() == "boolean_literal"
                            && condition.utf8_text(source.as_bytes()).ok() == Some("true"))
                    }
                }
            }
            "switch_statement" => !named_children_iter(node)
                .filter(|child| child.kind() == "switch_body")
                .flat_map(named_children_iter)
                .filter(|child| child.kind() == "switch_section")
                .any(|section| {
                    section
                        .children(&mut section.walk())
                        .any(|child| child.kind() == "default")
                }),
            _ => true,
        }
    }

    fn roles<'tree>(&self, node: Node<'tree>, role: Role) -> Vec<Node<'tree>> {
        let target = match role {
            Role::Test if matches!(node.kind(), "switch_section" | "switch_expression_arm") => {
                return case_parts(node).map(|(tests, _)| tests).unwrap_or_default();
            }
            Role::Body if matches!(node.kind(), "switch_section" | "switch_expression_arm") => {
                return case_parts(node).map(|(_, body)| body).unwrap_or_default();
            }
            Role::Test if node.kind() == "switch_statement" => node.child_by_field_name("value"),
            Role::Test if node.kind() == "switch_expression" => {
                named_children_iter(node).find(|child| !child.is_extra())
            }
            Role::Body if node.kind() == "switch_expression" => Some(node),
            Role::Test => node.child_by_field_name("condition"),
            Role::Consequence => node.child_by_field_name("consequence"),
            Role::Alternative => node.child_by_field_name("alternative"),
            Role::Body if matches!(node.kind(), "lock_statement" | "fixed_statement") => {
                named_children_iter(node)
                    .filter(|child| !child.is_extra())
                    .last()
            }
            Role::Body => node.child_by_field_name("body"),
            Role::Left => node.child_by_field_name("left"),
            Role::Right => node.child_by_field_name("right"),
            Role::Operator => node.child_by_field_name("operator"),
            Role::Label if node.kind() == "labeled_statement" => {
                named_children_iter(node).find(|child| child.kind() == "identifier")
            }
            Role::Label if node.kind() == "goto_statement" => {
                if node
                    .children(&mut node.walk())
                    .any(|child| matches!(child.kind(), "case" | "default"))
                {
                    return Vec::new();
                }
                named_children_iter(node).find(|child| child.kind() == "identifier")
            }
            _ => None,
        };
        target.into_iter().collect()
    }

    fn loop_variable(&self, node: Node<'_>, source: &str) -> Option<String> {
        let name = match node.kind() {
            "foreach_statement" => node.child_by_field_name("left")?,
            "for_statement" => {
                let initializers = self.loop_initializers(node);
                // The tight-bound shortcut names one induction variable. Keep
                // its single-initializer restriction local to this proof.
                let &[initializer] = initializers.as_slice() else {
                    return None;
                };
                match initializer.kind() {
                    "variable_declaration" => named_children_iter(initializer)
                        .find(|child| child.kind() == "variable_declarator")?
                        .child_by_field_name("name")?,
                    "assignment_expression" => initializer.child_by_field_name("left")?,
                    _ => return None,
                }
            }
            _ => return None,
        };
        (name.kind() == "identifier")
            .then(|| name.utf8_text(source.as_bytes()).ok().map(str::to_owned))
            .flatten()
    }

    fn is_counted_loop(&self, node: Node<'_>) -> bool {
        node.kind() == "for_statement"
    }

    fn loop_initializers<'tree>(&self, node: Node<'tree>) -> Vec<Node<'tree>> {
        let mut cursor = node.walk();
        node.children_by_field_name("initializer", &mut cursor)
            .filter(|child| child.is_named() && !child.is_extra())
            .collect()
    }

    fn switch_enum<'tree>(&self, _node: Node<'tree>, _source: &str) -> Option<Node<'tree>> {
        // Native C# operand typing has not supplied an enum binding proof.
        None
    }

    fn enumeration(
        &self,
        node: Node<'_>,
        source: &str,
    ) -> Option<(
        brokk_bifrost_core::analyzer::statement_facts::EnumFact,
        Vec<brokk_bifrost_core::analyzer::statement_facts::EnumeratorFact>,
    )> {
        use brokk_bifrost_core::analyzer::statement_facts::{EnumFact, EnumeratorFact};
        if node.kind() != "enum_declaration" {
            return None;
        }
        let range = node_range(node);
        let name = node
            .child_by_field_name("name")?
            .utf8_text(source.as_bytes())
            .ok()?
            .to_owned();
        let enumerators = node
            .child_by_field_name("body")
            .into_iter()
            .flat_map(named_children_iter)
            .filter(|child| child.kind() == "enum_member_declaration")
            .filter_map(|member| {
                Some(EnumeratorFact {
                    range: node_range(member),
                    enum_range: range,
                    name: member
                        .child_by_field_name("name")?
                        .utf8_text(source.as_bytes())
                        .ok()?
                        .to_owned(),
                })
            })
            .collect();
        Some((
            EnumFact {
                range,
                name: Some(name),
            },
            enumerators,
        ))
    }

    fn name<'tree>(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        expression_name_node(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;
    use brokk_bifrost_test_macros::hardwon;
    use tree_sitter::Tree;

    fn parse(source: &str) -> Tree {
        let tree = crate::test_support::parse_raw_csharp(source);
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    fn identifier_roles(source: &str) -> Vec<(String, Option<OccurrenceRole>)> {
        let tree = parse(source);
        let mut pending = vec![tree.root_node()];
        let mut identifiers = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "identifier" {
                let spelling = node
                    .utf8_text(source.as_bytes())
                    .expect("identifier has valid source span")
                    .to_owned();
                identifiers.push((spelling, csharp_member_position(node)));
            }
            pending
                .extend((0..node.named_child_count()).filter_map(|index| node.named_child(index)));
        }
        identifiers
    }

    #[test]
    fn member_positions_are_limited_to_member_access_names() {
        let source = r#"
            class Runner {
                int Field;
                void Build(int count) { }

                void Run(Runner service, int count) {
                    var result = service.Build(count: count);
                    var optional = service?.Build(count: count);
                    var unrelated = count;
                }
            }
        "#;

        let identifiers = identifier_roles(source);
        let member_names: Vec<_> = identifiers
            .iter()
            .filter_map(|(spelling, role)| {
                (*role == Some(OccurrenceRole::MemberPosition)).then_some(spelling.as_str())
            })
            .collect();
        assert_eq!(member_names, ["Build", "Build"]);

        for spelling in ["service", "count", "Field", "unrelated", "result"] {
            assert!(
                identifiers
                    .iter()
                    .filter(|(name, _)| name == spelling)
                    .all(|(_, role)| *role != Some(OccurrenceRole::MemberPosition)),
                "{spelling} must not be a member-position occurrence"
            );
        }

        assert!(
            identifiers
                .iter()
                .filter(|(name, _)| name == "Build")
                .any(|(_, role)| role.is_none()),
            "the Build declaration must not be a member-position occurrence"
        );
    }

    #[test]
    fn string_literals_publish_decoded_values() {
        let source = r#"class Probe {
            string cooked = ".example.com";
            string escaped = "\u002F";
            string verbatim = @"/";
        }"#;
        let tree = parse(source);
        let mut pending = vec![tree.root_node()];
        let mut values = Vec::new();
        while let Some(node) = pending.pop() {
            if matches!(
                node.kind(),
                "string_literal" | "verbatim_string_literal" | "character_literal"
            ) {
                values.push(csharp_string_literal_value(node, source));
            }
            pending
                .extend((0..node.named_child_count()).filter_map(|index| node.named_child(index)));
        }
        values.sort();
        assert_eq!(
            values,
            vec![
                Some(".example.com".to_owned()),
                Some("/".to_owned()),
                Some("/".to_owned())
            ]
        );
    }

    #[test]
    fn result_use_index_classifies_csharp_uses() {
        let source = r#"
            class Runner {
                void Sink(string value) { }

                void Run(string value) {
                    value.Trim();
                    Sink(value.Trim());
                    _ = value.Trim();
                    value?.Trim();
                }
            }
        "#;
        let tree = parse(source);
        let root = tree.root_node();
        let mut calls = Vec::new();
        let mut pending = vec![root];
        while let Some(node) = pending.pop() {
            if node.kind() == "invocation_expression"
                && node
                    .child_by_field_name("function")
                    .is_some_and(|function| {
                        matches!(
                            function.kind(),
                            "member_access_expression" | "conditional_access_expression"
                        )
                    })
            {
                calls.push(node);
            }
            pending
                .extend((0..node.named_child_count()).filter_map(|index| node.named_child(index)));
        }
        calls.sort_by_key(|call| call.start_byte());
        let index = CSharpCallResultUseIndex::new(root, source);
        let uses: Vec<_> = calls
            .iter()
            .map(|call| {
                index
                    .at_span(call.start_byte(), call.end_byte())
                    .expect("member call has an indexed result-use site")
                    .default_use()
            })
            .collect();

        assert_eq!(uses.len(), 4);
        assert!(matches!(uses[0], CallResultUse::Discarded));
        assert!(matches!(uses[1], CallResultUse::Consumed));
        assert!(matches!(
            uses[2],
            CallResultUse::IntentionalDiscard(IntentionalDiscardKind::CSharpDiscardAssignment)
        ));
        assert!(matches!(
            uses[3],
            CallResultUse::Open(CallResultUseOpenReason::UnsupportedSyntax)
        ));
    }
    #[test]
    #[hardwon(
        "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: generic member identifiers lost their occurrence role"
    )]
    fn generic_member_grammar_preserves_identifier_roles() {
        let source = "class C { void M() { service.Build<int>(); service?.Build<string>(); Build<int>(); new Box<int>(); } }";
        let tree = parse(source);
        let mut pending = vec![tree.root_node()];
        let mut generic_count = 0;
        let mut member_count = 0;
        while let Some(node) = pending.pop() {
            if node.kind() == "generic_name" {
                generic_count += 1;
                assert!(node.child_by_field_name("name").is_none());
                let name = node.named_child(0).unwrap();
                assert_eq!(name.kind(), "identifier");
                assert_eq!(node.named_child(1).unwrap().kind(), "type_argument_list");
                assert_eq!(expression_name_node(node), Some(name));
                assert_eq!(terminal_callee_leaf(node, callee_spine_step), Some(name));
                let is_member = matches!(
                    node.parent().unwrap().kind(),
                    "member_access_expression" | "member_binding_expression"
                );
                assert_eq!(
                    csharp_member_position(name),
                    is_member.then_some(OccurrenceRole::MemberPosition)
                );
                member_count += usize::from(is_member);
                let argument = node.named_child(1).unwrap().named_child(0).unwrap();
                assert_eq!(csharp_member_position(argument), None);
            }
            pending.extend((0..node.named_child_count()).filter_map(|i| node.named_child(i)));
        }
        assert_eq!((generic_count, member_count), (4, 2));
    }

    #[test]
    #[hardwon(
        "ae2a8d00737b: quicksilver round 8 on brokk-bifrost-csharp: tuple declarators published their pattern as the initializer"
    )]
    fn declarator_grammar_distinguishes_patterns_from_initializers() {
        let source = "class C { void M() { var (x, y) = Pair(); var (a, (_, b)) = Nested(); int z = 1; int missing; var (c, d) /* note */ = /* value */ Pair(); } }";
        let tree = parse(source);
        let mut pending = vec![tree.root_node()];
        let mut declarations = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "variable_declarator" {
                declarations.push(node);
            }
            pending.extend((0..node.named_child_count()).filter_map(|i| node.named_child(i)));
        }
        declarations.sort_by_key(|node| node.start_byte());
        let expected = [
            Some("Pair()"),
            Some("Nested()"),
            Some("1"),
            None,
            Some("Pair()"),
        ];
        assert_eq!(declarations.len(), expected.len());
        for (node, expected) in declarations.into_iter().zip(expected) {
            if node.child_by_field_name("name").is_none() {
                assert_eq!(node.named_child(0).unwrap().kind(), "tuple_pattern");
            }
            assert_eq!(
                variable_declarator_value(node)
                    .map(|value| value.utf8_text(source.as_bytes()).unwrap()),
                expected
            );
        }
    }

    #[test]
    fn deferred_result_use_follows_ancestor_grammar() {
        for (statement, deferred) in [
            ("Sink(value.Trim());", false),
            ("Func<string> f = () => Sink(value.Trim());", true),
            ("Action f = delegate { var x = value.Trim(); };", true),
        ] {
            let source = format!("class C {{ void M() {{ {statement} }} }}");
            let tree = parse(&source);
            let mut pending = vec![tree.root_node()];
            let mut calls = 0;
            while let Some(node) = pending.pop() {
                if node.kind() == "invocation_expression"
                    && node.child_by_field_name("function").unwrap().kind()
                        == "member_access_expression"
                {
                    calls += 1;
                    let mut ancestors = Vec::new();
                    let mut ancestor = node.parent();
                    while let Some(parent) = ancestor {
                        ancestors.push(parent.kind());
                        ancestor = parent.parent();
                    }
                    assert_eq!(
                        ancestors.iter().any(|kind| matches!(
                            *kind,
                            "lambda_expression" | "anonymous_method_expression"
                        )),
                        deferred
                    );
                    let expected = if deferred {
                        CallResultUse::Open(CallResultUseOpenReason::DeferredContext)
                    } else {
                        CallResultUse::Consumed
                    };
                    assert_eq!(
                        csharp_call_result_use(node, &source).default_use(),
                        expected
                    );
                }
                pending.extend((0..node.named_child_count()).filter_map(|i| node.named_child(i)));
            }
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn literal_grammar_preserves_absent_and_decoded_values() {
        for (literal, kind, expected) in [
            (r#""""nonempty""""#, "raw_string_literal", None),
            ("\"\"\"\n    text\n    \"\"\"", "raw_string_literal", None),
            (r#""""#, "string_literal", Some("")),
            (r#""\u0123""#, "string_literal", Some("\u{123}")),
            (r#""\x123""#, "string_literal", Some("\u{123}")),
            (r#""\u123""#, "string_literal", None),
            (r#""\q""#, "string_literal", None),
            (r#""\\q""#, "string_literal", Some("\\q")),
            (r#"@"a""b""#, "verbatim_string_literal", Some("a\"b")),
        ] {
            let source = format!("class C {{ string value = {literal}; }}");
            let tree = crate::test_support::parse_raw_csharp(&source);
            let mut pending = vec![tree.root_node()];
            let mut literals = 0;
            while let Some(node) = pending.pop() {
                if node.kind() == kind {
                    literals += 1;
                    assert_eq!(node.utf8_text(source.as_bytes()).unwrap(), literal);
                    assert_eq!(
                        csharp_string_literal_value(node, &source).as_deref(),
                        expected,
                        "{literal}"
                    );
                    assert_eq!(
                        CSHARP_STRUCTURAL_SPEC.string_literal_value_may_be_absent(node, &source),
                        expected.is_none()
                    );
                }
                pending.extend((0..node.named_child_count()).filter_map(|i| node.named_child(i)));
            }
            assert_eq!(literals, 1, "{literal}: {}", tree.root_node().to_sexp());
        }
    }
}
