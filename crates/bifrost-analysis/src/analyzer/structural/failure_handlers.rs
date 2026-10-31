//! Source-backed shape of native failure handlers.

use crate::analyzer::Range;
use crate::analyzer::read_ledger::{DerivationExecutionCause, reason as derivation_reason};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::structural::body_relations::{
    BodyState, BodyStateAnswer, classify_body,
};
use brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionalRegions;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerBodyState {
    Empty,
    Nonempty,
    Open(HandlerBodyGap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerBodyGap {
    SyntaxRecovery,
    MissingBody,
    MissingTryBody,
    UnprovenActivation,
}

impl HandlerBodyGap {
    pub const fn execution_cause(self) -> Option<DerivationExecutionCause> {
        match self {
            Self::SyntaxRecovery
            | Self::MissingBody
            | Self::MissingTryBody
            | Self::UnprovenActivation => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::SyntaxRecovery => derivation_reason::SYNTAX_RECOVERY,
            Self::MissingBody => derivation_reason::MISSING_BODY,
            Self::MissingTryBody => derivation_reason::MISSING_TRY_BODY,
            Self::UnprovenActivation => derivation_reason::UNPROVEN_ACTIVATION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerBodyShape {
    pub state: HandlerBodyState,
    pub body: Option<Range>,
    pub try_body: Option<Range>,
}

/// Whether a C# handler rethrows the exception selected by its catch clause.
///
/// `throw new ...` and other throws are deliberately represented by `None`:
/// they do not propagate the caught exception and therefore do not suppress a
/// catch-all finding. `Unknown` is reserved for a recovered handler body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerRethrowKind {
    None,
    Bare,
    CaughtVariable,
    Both,
    Unknown,
}

impl HandlerRethrowKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bare => "bare",
            Self::CaughtVariable => "caught_variable",
            Self::Both => "both",
            Self::Unknown => derivation_reason::UNKNOWN,
        }
    }
}

/// The C#-specific facts that extend the shared handler body shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSharpCatchBodyFacts {
    pub shape: HandlerBodyShape,
    pub rethrow: HandlerRethrowKind,
}

/// Proof that a candidate branch selects the language's failure representation.
/// This is independent of the structural work performed by its body.
/// An open identity is a content gap. Producers must record execution
/// dependence separately if the proof stopped on an operational failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerIdentityProof {
    Exact,
    Open,
}

impl HandlerIdentityProof {
    pub const fn gap(self) -> Option<&'static str> {
        match self {
            Self::Exact => None,
            Self::Open => Some(derivation_reason::HANDLER_IDENTITY_UNPROVEN),
        }
    }
}

/// One failure branch selected by a language-native failure-handler hook.
///
/// Native failure syntax does not necessarily have a normalized `Catch` node
/// (Rust `match` arms are one example). The structural query engine keeps the
/// shared result vocabulary while the language adapter supplies the exact
/// branch range, handler-identity proof, and independent body shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeFailureBranch {
    pub handler: Range,
    pub identity: HandlerIdentityProof,
    pub shape: HandlerBodyShape,
}

/// Scala's native catch syntax contains one or more case clauses. The
/// structural fact selects the enclosing `catch_clause`, while policy needs
/// one state row for each case so a mixed catch reports only its empty cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalaCatchBodyShape {
    pub handler: Range,
    pub shape: HandlerBodyShape,
}

/// How a grammar attaches the handler body to the handler node.
#[derive(Clone, Copy)]
enum HandlerBody {
    /// The body is this required field.
    Field(&'static str),
    /// The body is the unique unnamed child of `body_kind` (Python's
    /// `except_clause` suite).
    OnlyChild,
    /// The body is an optional field or unique child of `body_kind` that the
    /// grammar omits when the handler has no statements (Kotlin `catch`,
    /// Ruby `rescue`). Its absence in recovery-free syntax is an empty body.
    OmittedWhenEmpty(Option<&'static str>),
}

/// Native syntax of one language's failure handler. Each language supplies
/// data rather than a mode: which node is the handler, which node owns the
/// protected body, how the handler body is found, and which immediate body
/// children perform no work.
struct HandlerSyntax {
    handler_kinds: &'static [&'static str],
    try_kinds: &'static [&'static str],
    /// The protected body's field on the try node; `None` when the grammar
    /// places protected statements directly in the try node (Ruby `begin`).
    try_body_field: Option<&'static str>,
    body_kind: &'static str,
    body: HandlerBody,
    is_no_op: fn(Node<'_>) -> bool,
}

const JAVA: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement", "try_with_resources_statement"],
    try_body_field: Some("body"),
    body_kind: "block",
    body: HandlerBody::Field("body"),
    is_no_op: |child| matches!(child.kind(), "line_comment" | "block_comment" | "comment"),
};

const JS_TS: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "statement_block",
    body: HandlerBody::Field("body"),
    // `;` is an empty statement: it evaluates nothing.
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

const PYTHON: HandlerSyntax = HandlerSyntax {
    // tree-sitter-python 0.25 spells `except*` as the same node kind.
    handler_kinds: &["except_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "block",
    body: HandlerBody::OnlyChild,
    // A suite cannot be syntactically empty, so `pass` and a bare `...` are
    // the language's spellings of an empty handler. Any other expression,
    // including a bare string, is treated as work.
    is_no_op: |child| match child.kind() {
        "comment" | "pass_statement" => true,
        "expression_statement" => {
            child.named_child_count() == 1
                && child
                    .named_child(0)
                    .is_some_and(|value| value.kind() == "ellipsis")
        }
        _ => false,
    },
};

const CSHARP: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "block",
    body: HandlerBody::Field("body"),
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

const PHP: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "compound_statement",
    body: HandlerBody::Field("body"),
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

const CPP: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_clause"],
    try_kinds: &["try_statement"],
    try_body_field: Some("body"),
    body_kind: "compound_statement",
    body: HandlerBody::Field("body"),
    // The grammar spells a lone `;` as an expression statement with no
    // expression.
    is_no_op: |child| {
        child.kind() == "comment"
            || (child.kind() == "expression_statement" && child.named_child_count() == 0)
    },
};

const KOTLIN: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["catch_block"],
    try_kinds: &["try_expression"],
    // The protected block is an unnamed `statements` child that is also
    // omitted when empty; the catch clause's own position proves the try.
    try_body_field: None,
    body_kind: "statements",
    body: HandlerBody::OmittedWhenEmpty(None),
    is_no_op: |child| matches!(child.kind(), "line_comment" | "multiline_comment"),
};

const RUBY: HandlerSyntax = HandlerSyntax {
    handler_kinds: &["rescue"],
    // A method, block or class body with `rescue` is an implicit `begin`.
    try_kinds: &["begin", "body_statement"],
    try_body_field: None,
    body_kind: "then",
    body: HandlerBody::OmittedWhenEmpty(Some("body")),
    is_no_op: |child| matches!(child.kind(), "comment" | "empty_statement"),
};

/// Classify only the exact Java catch clause selected by a normalized fact.
/// A non-comment child, including a declaration or nested callable, makes the
/// immediate handler body nonempty. Comments are never approval to suppress a
/// finding; policy suppression is a separate reviewed decision.
pub fn java_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &JAVA, &ConditionalRegions::default())
}

/// Classify an exact JavaScript or TypeScript `catch` clause, including an
/// optional-binding `catch {}`. Only the syntactic handler is classified; a
/// promise rejection callback is not a `catch` clause.
pub fn js_ts_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &JS_TS, &ConditionalRegions::default())
}

/// Classify an exact Python `except` or `except*` clause. A suite of only
/// `pass`, `...` and comments is empty.
pub fn python_except_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &PYTHON, &ConditionalRegions::default())
}

/// Classify the exact C# catch body and whether it propagates its caught
/// exception. Nested catch clauses and nested callable bodies are separate
/// handlers/scopes, so their throw statements do not count for this handler.
pub fn csharp_catch_body_facts(
    syntax: &PreparedSyntaxTree,
    catch: Range,
    regions: &ConditionalRegions,
) -> CSharpCatchBodyFacts {
    let shape = handler_body_shape(syntax, catch, &CSHARP, regions);
    let rethrow = match shape.state {
        HandlerBodyState::Open(_) => HandlerRethrowKind::Unknown,
        HandlerBodyState::Empty => HandlerRethrowKind::None,
        HandlerBodyState::Nonempty => csharp_catch_rethrow_kind(syntax, catch),
    };
    CSharpCatchBodyFacts { shape, rethrow }
}

fn csharp_catch_rethrow_kind(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerRethrowKind {
    let Some(catch_node) = exact_handler_node(syntax, catch, &CSHARP) else {
        return HandlerRethrowKind::Unknown;
    };
    let Some(body) = catch_node.child_by_field_name("body") else {
        return HandlerRethrowKind::Unknown;
    };
    let mut has_bare = false;
    let mut has_caught_variable = false;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if csharp_failure_boundary(node) {
            continue;
        }
        if node.kind() == "throw_statement" && csharp_throw_owner(node) == Some(catch_node) {
            match csharp_throw_relation(syntax, node, Some(catch_node)) {
                ThrowRelation::Bare => has_bare = true,
                ThrowRelation::CaughtVariable => has_caught_variable = true,
                ThrowRelation::Other | ThrowRelation::NoOwner => {}
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    match (has_bare, has_caught_variable) {
        (true, true) => HandlerRethrowKind::Both,
        (true, false) => HandlerRethrowKind::Bare,
        (false, true) => HandlerRethrowKind::CaughtVariable,
        (false, false) => HandlerRethrowKind::None,
    }
}

fn csharp_failure_boundary(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "catch_clause"
            | "method_declaration"
            | "constructor_declaration"
            | "destructor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "accessor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
    )
}

/// Find the nearest catch body without crossing a callable boundary.
fn csharp_throw_owner(node: Node<'_>) -> Option<Node<'_>> {
    let mut child = node;
    while let Some(parent) = child.parent() {
        if csharp_failure_boundary(parent) {
            return (parent.kind() == "catch_clause"
                && parent.child_by_field_name("body") == Some(child))
            .then_some(parent);
        }
        child = parent;
    }
    None
}

/// Relation of a throw operand to its nearest owning catch variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrowRelation {
    CaughtVariable,
    Bare,
    Other,
    NoOwner,
}

impl ThrowRelation {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CaughtVariable => "caught_variable",
            Self::Bare => "bare",
            Self::Other => "other",
            Self::NoOwner => "no_owner",
        }
    }
}

fn csharp_throw_relation(
    syntax: &PreparedSyntaxTree,
    node: Node<'_>,
    owner: Option<Node<'_>>,
) -> ThrowRelation {
    let Some(owner) = owner else {
        return ThrowRelation::NoOwner;
    };
    let mut cursor = node.walk();
    let Some(expression) = node
        .named_children(&mut cursor)
        .find(|node| !node.is_extra())
    else {
        return ThrowRelation::Bare;
    };
    let expression = brokk_bifrost_core::analyzer::tree_walk::unwrap_parenthesized_expression_with(
        expression,
        |node| {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| !child.is_extra())
        },
    );
    let name = named_child_kind(owner, "catch_declaration")
        .and_then(|declaration| declaration.child_by_field_name("name"));
    // C# CS0136 forbids shadowing a catch variable within its body. Callable
    // boundaries are excluded by the owner walk, so name equality identifies it.
    // Compare lookup names, so `@e` and `e` are the same variable.
    let lookup_name = |node: Node<'_>| {
        brokk_bifrost_csharp::syntax::csharp_lookup_identifier(
            node.utf8_text(syntax.source().as_bytes())
                .expect("identifier is UTF-8 source"),
        )
    };
    if expression.kind() == "identifier"
        && name.is_some_and(|name| lookup_name(name) == lookup_name(expression))
    {
        ThrowRelation::CaughtVariable
    } else {
        ThrowRelation::Other
    }
}

/// Classify an exact throw statement and return its owning catch range.
/// Recovery is distinct from a proven absence of an owner.
pub fn csharp_throw_facts(
    syntax: &PreparedSyntaxTree,
    range: Range,
) -> Option<(Option<Range>, ThrowRelation)> {
    let node = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    if node.kind() != "throw_statement"
        || node.start_byte() != range.start_byte
        || node.end_byte() != range.end_byte
        || node.has_error()
        || has_error_ancestor(node)
    {
        return None;
    }
    let owner = csharp_throw_owner(node);
    if owner.is_some_and(|owner| owner.has_error()) {
        return None;
    }
    Some((
        owner.map(brokk_bifrost_core::analyzer::tree_walk::node_range),
        csharp_throw_relation(syntax, node, owner),
    ))
}

/// Classify an exact PHP `catch` clause.
pub fn php_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &PHP, &ConditionalRegions::default())
}

/// Classify an exact C++ `catch` clause, including `catch (...)`.
pub fn cpp_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &CPP, &ConditionalRegions::default())
}

/// Classify an exact Kotlin `catch` block. An expression-position `try`
/// whose catch block is empty evaluates to `Unit` there; the handler is
/// still empty.
pub fn kotlin_catch_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &KOTLIN, &ConditionalRegions::default())
}

/// Classify an exact Ruby `rescue` clause of a `begin` or implicit-begin
/// body. The `rescue` modifier (`value rescue nil`) is a different node.
pub fn ruby_rescue_body_shape(syntax: &PreparedSyntaxTree, catch: Range) -> HandlerBodyShape {
    handler_body_shape(syntax, catch, &RUBY, &ConditionalRegions::default())
}

/// Classify the case clauses in one exact Scala `catch_clause`.
///
/// A braced or indented catch is a pattern match whose cases are independent
/// failure handlers. A catch whose body is an expression has no case clause
/// and remains open because the expression form is outside this structural
/// no-op rule. A unit literal is the one Scala expression that is a no-op.
pub fn scala_catch_body_shapes(
    syntax: &PreparedSyntaxTree,
    catch: Range,
) -> Vec<ScalaCatchBodyShape> {
    let open = |gap, body, try_body| HandlerBodyShape {
        state: HandlerBodyState::Open(gap),
        body,
        try_body,
    };
    let Some(node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(catch.start_byte, catch.end_byte)
        .filter(|node| {
            node.kind() == "catch_clause"
                && node.start_byte() == catch.start_byte
                && node.end_byte() == catch.end_byte
        })
    else {
        return vec![ScalaCatchBodyShape {
            handler: catch,
            shape: open(HandlerBodyGap::SyntaxRecovery, None, None),
        }];
    };

    let try_node = node
        .parent()
        .filter(|parent| parent.kind() == "try_expression");
    let try_body = try_node
        .and_then(|parent| parent.child_by_field_name("body"))
        .map(brokk_bifrost_core::analyzer::tree_walk::node_range);
    let syntax_recovered = node.has_error()
        || try_node.is_some_and(|parent| parent.has_error())
        || has_error_ancestor(node);

    let cases = brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
        node,
        "case_clause",
    )
    .into_iter()
    .filter(|case| scala_direct_case_matches(*case, node))
    .collect::<Vec<_>>();

    if cases.is_empty() {
        let body = node
            .child_by_field_name("body")
            .map(brokk_bifrost_core::analyzer::tree_walk::node_range);
        return vec![ScalaCatchBodyShape {
            handler: catch,
            shape: open(
                if syntax_recovered {
                    HandlerBodyGap::SyntaxRecovery
                } else if try_body.is_none() {
                    HandlerBodyGap::MissingTryBody
                } else {
                    HandlerBodyGap::MissingBody
                },
                body,
                try_body,
            ),
        }];
    }

    cases
        .into_iter()
        .map(|case| {
            let body_children = scala_case_body_children(case);
            let body = span_of_nodes(&body_children);
            let state = if syntax_recovered || case.has_error() || has_error_ancestor(case) {
                HandlerBodyState::Open(HandlerBodyGap::SyntaxRecovery)
            } else if try_body.is_none() {
                HandlerBodyState::Open(HandlerBodyGap::MissingTryBody)
            } else if body_children
                .iter()
                .any(|child| child.kind() != "unit" && !child.is_extra())
            {
                HandlerBodyState::Nonempty
            } else {
                HandlerBodyState::Empty
            };
            ScalaCatchBodyShape {
                handler: brokk_bifrost_core::analyzer::tree_walk::node_range(case),
                shape: HandlerBodyShape {
                    state,
                    body,
                    try_body,
                },
            }
        })
        .collect()
}

fn scala_case_body_children<'tree>(case: Node<'tree>) -> Vec<Node<'tree>> {
    let mut cursor = case.walk();
    case.children_by_field_name("body", &mut cursor)
        .filter(Node::is_named)
        .collect()
}

fn span_of_nodes(nodes: &[Node<'_>]) -> Option<Range> {
    let first = nodes.first()?;
    let last = nodes.last()?;
    Some(Range {
        start_byte: first.start_byte(),
        end_byte: last.end_byte(),
        start_line: first.start_position().row + 1,
        end_line: last.end_position().row + 1,
    })
}

fn scala_direct_case_matches(case: Node<'_>, catch: Node<'_>) -> bool {
    let mut ancestor = case.parent();
    while let Some(parent) = ancestor {
        if matches!(parent.kind(), "case_block" | "indented_cases") {
            return parent.parent().is_some_and(|owner| {
                owner.kind() == "catch_clause"
                    && owner.start_byte() == catch.start_byte()
                    && owner.end_byte() == catch.end_byte()
            });
        }
        if parent.kind() == "catch_clause" {
            return false;
        }
        ancestor = parent.parent();
    }
    false
}

fn has_error_ancestor(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        if parent.is_error() {
            return true;
        }
        ancestor = parent.parent();
    }
    false
}

fn handler_body_shape(
    syntax: &PreparedSyntaxTree,
    catch: Range,
    grammar: &HandlerSyntax,
    regions: &ConditionalRegions,
) -> HandlerBodyShape {
    let open = |gap, body, try_body| HandlerBodyShape {
        state: HandlerBodyState::Open(gap),
        body,
        try_body,
    };
    let Some(node) = exact_handler_node(syntax, catch, grammar) else {
        return open(HandlerBodyGap::SyntaxRecovery, None, None);
    };
    // A second body child is recovery, not a choice between bodies.
    fn unique_child<'tree>(node: Node<'tree>, kind: &str) -> Result<Option<Node<'tree>>, ()> {
        let mut cursor = node.walk();
        let mut children = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == kind);
        let first = children.next();
        if children.next().is_some() {
            Err(())
        } else {
            Ok(first)
        }
    }
    let body = match grammar.body {
        HandlerBody::Field(field) => {
            let Some(body) = node.child_by_field_name(field) else {
                return open(HandlerBodyGap::MissingBody, None, None);
            };
            Some(body)
        }
        HandlerBody::OnlyChild => match unique_child(node, grammar.body_kind) {
            Ok(Some(body)) => Some(body),
            Ok(None) => return open(HandlerBodyGap::MissingBody, None, None),
            Err(()) => return open(HandlerBodyGap::SyntaxRecovery, None, None),
        },
        HandlerBody::OmittedWhenEmpty(Some(field)) => node.child_by_field_name(field),
        HandlerBody::OmittedWhenEmpty(None) => match unique_child(node, grammar.body_kind) {
            Ok(body) => body,
            Err(()) => return open(HandlerBodyGap::SyntaxRecovery, None, None),
        },
    };
    let try_node = node
        .parent()
        .filter(|parent| grammar.try_kinds.contains(&parent.kind()));
    let try_body = match grammar.try_body_field {
        Some(field) => try_node
            .and_then(|parent| parent.child_by_field_name(field))
            .map(brokk_bifrost_core::analyzer::tree_walk::node_range),
        None => try_node.map(brokk_bifrost_core::analyzer::tree_walk::node_range),
    };
    let body_range = body.map(brokk_bifrost_core::analyzer::tree_walk::node_range);
    if try_body.is_none() {
        return open(HandlerBodyGap::MissingTryBody, body_range, None);
    }
    // Recovery can leave a clean-looking handler inside an ERROR node, for
    // example when tree-sitter-ruby reads `rescue E => end` as a variable
    // named `end`. Any ERROR ancestor makes the handler's shape unreliable.
    let mut ancestor = node.parent();
    let mut under_error = false;
    while let Some(parent) = ancestor {
        if parent.is_error() {
            under_error = true;
            break;
        }
        ancestor = parent.parent();
    }
    if under_error
        || node.has_error()
        || try_node.is_some_and(|parent| parent.has_error())
        || body.is_some_and(|body| body.kind() != grammar.body_kind || body.has_error())
    {
        return open(HandlerBodyGap::SyntaxRecovery, body_range, try_body);
    }
    let Some(body) = body else {
        return HandlerBodyShape {
            state: HandlerBodyState::Empty,
            body: None,
            try_body,
        };
    };
    HandlerBodyShape {
        state: match classify_body(body, regions, grammar.is_no_op) {
            BodyStateAnswer::Decided(BodyState::Code) => HandlerBodyState::Nonempty,
            BodyStateAnswer::Decided(_) => HandlerBodyState::Empty,
            BodyStateAnswer::Undecided => {
                HandlerBodyState::Open(HandlerBodyGap::UnprovenActivation)
            }
        },
        body: body_range,
        try_body,
    }
}

fn exact_handler_node<'tree>(
    syntax: &'tree PreparedSyntaxTree,
    catch: Range,
    grammar: &HandlerSyntax,
) -> Option<Node<'tree>> {
    syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(catch.start_byte, catch.end_byte)
        .filter(|node| {
            grammar.handler_kinds.contains(&node.kind())
                && node.start_byte() == catch.start_byte
                && node.end_byte() == catch.end_byte
        })
}

fn named_child_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, LanguageDialect};
    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource,
    };
    use brokk_bifrost_core::analyzer::tree_walk::node_range;
    use std::sync::Arc;

    #[track_caller]
    fn catch_shapes(source: &str) -> Vec<HandlerBodyShape> {
        shapes_with(
            source,
            tree_sitter_java::LANGUAGE.into(),
            Language::Java,
            "catch_clause",
            java_catch_body_shape,
        )
    }

    #[test]
    fn csharp_rethrow_scan_excludes_nested_scopes_without_skipping_siblings() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        for (nested, tail, expected) in [
            (
                "void Local() { throw new Exception(); }",
                "throw;",
                HandlerRethrowKind::Bare,
            ),
            (
                "void Local() { throw new Exception(); }",
                "throw e;",
                HandlerRethrowKind::CaughtVariable,
            ),
            (
                "void Local() { throw new Exception(); }",
                "",
                HandlerRethrowKind::None,
            ),
            (
                "try {} catch (Exception inner) { throw; }",
                "throw e;",
                HandlerRethrowKind::CaughtVariable,
            ),
            (
                "try {} catch (Exception inner) { throw; }",
                "",
                HandlerRethrowKind::None,
            ),
        ] {
            let source = format!(
                "class A {{ void F() {{ try {{}} catch (Exception e) {{ {nested} {tail} }} }} }}"
            );
            let tree = parser.parse(&source, None).unwrap();
            assert!(
                !tree.root_node().has_error(),
                "{}",
                tree.root_node().to_sexp()
            );
            let catches = brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
                tree.root_node(),
                "catch_clause",
            );
            let outer = catches.iter().min_by_key(|node| node.start_byte()).unwrap();
            let range = node_range(*outer);
            let body = outer.child_by_field_name("body").unwrap();
            assert_eq!(
                body.named_child(0).unwrap().kind(),
                if nested.starts_with("void") {
                    "local_function_statement"
                } else {
                    "try_statement"
                }
            );
            if !tail.is_empty() {
                assert_eq!(body.named_child(1).unwrap().kind(), "throw_statement");
            }
            let syntax = PreparedSyntaxTree::new(
                PreparedSyntaxSource::Exact(Arc::from(source)),
                tree,
                vec![0],
                LanguageDialect::Standard(Language::CSharp),
                PreparedSourceOrigin::Disk,
                None,
            );
            assert_eq!(csharp_catch_rethrow_kind(&syntax, range), expected);
        }
    }

    #[test]
    fn java_empty_catch_shape_is_exact_and_comments_are_not_acceptance() {
        for source in [
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception ignored) {} } }",
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception ignored) { /* ignored */ } } }",
            "class A { void f() { try (Resource r = open()) {} catch (Exception e) {} } }",
            "class A { void f() { try {} catch (IOException | RuntimeException e) {} } }",
        ] {
            let shapes = catch_shapes(source);
            let [shape] = shapes.as_slice() else {
                panic!("one native catch clause: {source}");
            };
            assert_eq!(shape.state, HandlerBodyState::Empty, "{source}");
            assert!(shape.body.is_some(), "{source}");
            assert!(shape.try_body.is_some(), "{source}");
        }
    }

    #[track_caller]
    fn prepared_shapes(
        source: &str,
        language: tree_sitter::Language,
        dialect: Language,
        handler_kind: &str,
    ) -> (PreparedSyntaxTree, Vec<Range>) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&language).expect("grammar loads");
        let tree = parser.parse(source, None).expect("source parses");
        let handlers = brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
            tree.root_node(),
            handler_kind,
        )
        .into_iter()
        .map(node_range)
        .collect::<Vec<_>>();
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::from(source)),
            tree,
            vec![0],
            LanguageDialect::Standard(dialect),
            PreparedSourceOrigin::Disk,
            None,
        );
        (prepared, handlers)
    }

    #[track_caller]
    fn shapes_with(
        source: &str,
        language: tree_sitter::Language,
        dialect: Language,
        handler_kind: &str,
        classify: fn(&PreparedSyntaxTree, Range) -> HandlerBodyShape,
    ) -> Vec<HandlerBodyShape> {
        let (prepared, handlers) = prepared_shapes(source, language, dialect, handler_kind);
        handlers
            .into_iter()
            .map(|handler| classify(&prepared, handler))
            .collect()
    }

    fn js_states(source: &str) -> Vec<HandlerBodyState> {
        shapes_with(
            source,
            tree_sitter_javascript::LANGUAGE.into(),
            Language::JavaScript,
            "catch_clause",
            js_ts_catch_body_shape,
        )
        .into_iter()
        .map(|shape| shape.state)
        .collect()
    }

    fn python_states(source: &str) -> Vec<HandlerBodyState> {
        shapes_with(
            source,
            tree_sitter_python::LANGUAGE.into(),
            Language::Python,
            "except_clause",
            python_except_body_shape,
        )
        .into_iter()
        .map(|shape| shape.state)
        .collect()
    }

    #[track_caller]
    fn scala_shapes(source: &str) -> Vec<ScalaCatchBodyShape> {
        let (prepared, catches) = prepared_shapes(
            source,
            brokk_bifrost_jvm::scala::language::LANGUAGE.into(),
            Language::Scala,
            "catch_clause",
        );
        catches
            .into_iter()
            .flat_map(|catch| scala_catch_body_shapes(&prepared, catch))
            .collect()
    }

    #[test]
    fn scala_catch_cases_classify_each_native_handler_shape() {
        use HandlerBodyState::{Empty, Nonempty, Open};

        let empty = scala_shapes(
            "object A { def f(): Unit = { try { work() } catch { case e: Exception => } } }",
        );
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].shape.state, Empty);
        assert!(empty[0].shape.try_body.is_some());

        let unit = scala_shapes(
            "object A { def f(): Unit = { try { work() } catch { case e: Exception => () } } }",
        );
        assert_eq!(unit.len(), 1);
        assert_eq!(unit[0].shape.state, Empty);

        let guarded = scala_shapes(
            "object A { def f(): Unit = { try { work() } catch { case e: IOException if ignore => } } }",
        );
        assert_eq!(guarded.len(), 1);
        assert_eq!(guarded[0].shape.state, Empty);

        let mixed = scala_shapes(
            "object A { def f(): Unit = { try { work() } catch { case ignored: Exception =>; case handled: RuntimeException => report(handled) } } }",
        );
        assert_eq!(
            mixed
                .iter()
                .map(|item| item.shape.state)
                .collect::<Vec<_>>(),
            vec![Empty, Nonempty]
        );

        for source in [
            "object A { def f(): Unit = { try { work() } catch { case e: Exception => throw e } } }",
            "object A { def f(): Unit = { try { work() } catch { case e: Exception => report(e) } } }",
            "object A { def f(): Unit = { try { work() } catch { case e: Exception => None } } }",
        ] {
            let shapes = scala_shapes(source);
            assert_eq!(shapes.len(), 1, "{source}");
            assert_eq!(shapes[0].shape.state, Nonempty, "{source}");
        }

        for (source, bodies) in [
            (
                "object A { def f(): Unit = { try { work() } catch { case e: Exception => () } } }",
                vec!["()"],
            ),
            (
                "object A { def f(): Unit = { try { work() } catch { case e: Exception => report(\"caf\u{e9}\"); cleanup() } } }",
                vec!["report(\"caf\u{e9}\"); cleanup()"],
            ),
            (
                "object A:\n  def f(): Unit =\n    try work()\n    catch\n      case e: Exception => report(e)\n      case other => ()\n",
                vec!["report(e)", "()"],
            ),
            (
                "object A { def f(): Unit = { try { work() } catch { case e: Exception => e match { case _ => report(e) } } } }",
                vec!["e match { case _ => report(e) }"],
            ),
        ] {
            let shapes = scala_shapes(source);
            assert_eq!(shapes.len(), bodies.len(), "{source}");
            for (shape, expected) in shapes.iter().zip(bodies) {
                let body = shape.shape.body.expect("case body span");
                assert_eq!(&source[body.start_byte..body.end_byte], expected);
                assert_eq!(
                    body.start_line,
                    source.as_bytes()[..body.start_byte]
                        .iter()
                        .filter(|&&byte| byte == b'\n')
                        .count()
                        + 1
                );
                assert_eq!(
                    body.end_line,
                    source.as_bytes()[..body.end_byte]
                        .iter()
                        .filter(|&&byte| byte == b'\n')
                        .count()
                        + 1
                );
            }
        }

        let expression =
            scala_shapes("object A { def f(): Unit = { try { work() } catch handler } }");
        assert_eq!(expression.len(), 1);
        assert_eq!(expression[0].shape.state, Open(HandlerBodyGap::MissingBody));

        let match_expression = scala_shapes(
            "object A { def f(): Unit = { try { work() } catch fallback() match { case e: Exception => () } } }",
        );
        assert_eq!(match_expression.len(), 1);
        assert_eq!(
            match_expression[0].shape.state,
            Open(HandlerBodyGap::MissingBody)
        );

        assert!(
            scala_shapes("object A { def f(): Unit = { try { work() } finally cleanup() } }")
                .is_empty()
        );
        assert!(
            scala_shapes(
                "object A { def f(): Unit = { Try(work()).recover { case e: Exception => } } }"
            )
            .is_empty()
        );

        let recovered = scala_shapes(
            "object A { def f(): Unit = { try { work() } catch { case e: Exception => if ( } } }",
        );
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered[0].shape.state,
            Open(HandlerBodyGap::SyntaxRecovery)
        );
    }

    #[test]
    fn js_ts_catch_shapes_distinguish_no_op_from_work() {
        use HandlerBodyState::{Empty, Nonempty};
        for (source, expected) in [
            ("try { f(); } catch (e) {}", Empty),
            ("try { f(); } catch {}", Empty),
            ("try { f(); } catch (e) { /* ignored */ ; }", Empty),
            ("try { f(); } catch ({ message }) {}", Empty),
            ("try { f(); } catch (e) { log(e); }", Nonempty),
            ("try { f(); } catch (e) { function later() {} }", Nonempty),
        ] {
            assert_eq!(js_states(source), vec![expected], "{source}");
        }
        let typed = shapes_with(
            "try { f(); } catch (e: unknown) {}",
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Language::TypeScript,
            "catch_clause",
            js_ts_catch_body_shape,
        );
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].state, Empty);
        assert!(js_states("try { f(); } finally {}").is_empty());
    }

    #[test]
    fn python_except_shapes_treat_pass_and_ellipsis_as_empty() {
        use HandlerBodyState::{Empty, Nonempty};
        for (source, expected) in [
            ("try:\n    f()\nexcept ValueError:\n    pass\n", Empty),
            ("try:\n    f()\nexcept:\n    ...\n", Empty),
            (
                "try:\n    f()\nexcept* OSError:\n    pass  # ignored\n",
                Empty,
            ),
            (
                "try:\n    f()\nexcept (A, B) as e:\n    pass\n    pass\n",
                Empty,
            ),
            ("try:\n    f()\nexcept ValueError:\n    log()\n", Nonempty),
            (
                "try:\n    f()\nexcept ValueError:\n    \"explained\"\n",
                Nonempty,
            ),
            ("try:\n    f()\nexcept ValueError:\n    raise\n", Nonempty),
            (
                "for x in y:\n    try:\n        f()\n    except ValueError:\n        continue\n",
                Nonempty,
            ),
        ] {
            assert_eq!(python_states(source), vec![expected], "{source}");
        }
        assert!(python_states("try:\n    f()\nfinally:\n    pass\n").is_empty());
    }

    #[test]
    fn recovered_java_catch_shape_stays_open() {
        let source = "class A { void f() { try {} catch (Exception e) { if ( } } }";
        let shapes = catch_shapes(source);
        let [shape] = shapes.as_slice() else {
            panic!("recovered source retains one catch clause");
        };
        assert_eq!(
            shape.state,
            HandlerBodyState::Open(HandlerBodyGap::SyntaxRecovery)
        );
    }

    #[test]
    fn java_catch_with_any_immediate_statement_is_nonempty() {
        for source in [
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception e) { throw e; } } }",
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception e) { int x = 1; } } }",
            "class A { void f(Exception problem) { try { throw problem; } catch (Exception e) { class Inner {} } } }",
        ] {
            let shapes = catch_shapes(source);
            let [shape] = shapes.as_slice() else {
                panic!("one native catch clause: {source}");
            };
            assert_eq!(shape.state, HandlerBodyState::Nonempty, "{source}");
        }
        assert!(
            catch_shapes("class A { void f() { try {} finally {} } }").is_empty(),
            "finally is not a catch handler"
        );
    }
}
