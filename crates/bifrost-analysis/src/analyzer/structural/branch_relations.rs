//! Structured comparisons of arms in one ordered `if` chain.
//!
//! The relation is deliberately conservative. A complete positive row proves
//! the particular relation from the parsed tree and lexical binder identity;
//! an open row names the fact that prevents proof. Neither source formatting
//! nor a generic clone score participates in a verdict.
//!
//! Two arms of one chain start from the same program state, so bodies whose
//! syntax trees match node for node, and whose names resolve to the same
//! bindings, perform the same operations: a getter, proxy trap, descriptor or
//! external method runs identically in either arm. Member and property names
//! therefore compare by their structured spelling on equivalent receivers,
//! and an unresolved member does not open an identical-body proof. Arm-local
//! declarations (block locals, catch and resource variables, loop variables
//! and comprehension targets) are the exception, handled by pairing their
//! binders, and a nested callable or local class body stays open because its
//! capture and class identity are not modeled. One unbound spelling is one
//! lookup only when no chain condition declares it with a binder the lexical
//! environment does not model, such as a Java pattern variable. Repeated
//! conditions additionally prove stability in `condition_stability`, which
//! admits no member access.

use super::kinds::NormalizedKind;
use super::lexical_environment::{BindingOfOutcome, EnvironmentFileResult, binding_of};
use super::occurrences::Namespace;
use super::resolution::BindingKind;
use crate::analyzer::CodeUnit;
use crate::analyzer::branch_boolean::{BooleanBranchOutcome, classify_boolean_branches};
use crate::analyzer::java_integral_parameter::{
    JavaIntegralDomain, JavaScalarType, java_decimal_int_value,
};
use crate::analyzer::languages::{LanguageSupport, language_support};
use crate::analyzer::{Language, Range};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchRelationKind {
    IdenticalBodies,
    RepeatedCondition,
    RedundantBooleanReturn,
}

impl BranchRelationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::IdenticalBodies => "identical_bodies",
            Self::RepeatedCondition => "repeated_condition",
            Self::RedundantBooleanReturn => "redundant_boolean_return",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchRelationVerdict {
    Proven,
    Distinct,
    Open(BranchOpenReason),
}

impl BranchRelationVerdict {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Distinct => "distinct",
            Self::Open(_) => "open",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchOpenReason {
    SyntaxRecovery,
    MissingBranchField,
    LexicalBindingUnavailable,
    NonLocalReference,
    EffectfulBody,
    EffectfulCondition,
    UnsupportedCondition,
    ComparisonBudget,
    MemberResolutionUnavailable,
    AmbiguousMember,
    DeferredBody,
}

impl BranchOpenReason {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SyntaxRecovery => "syntax_recovery",
            Self::MissingBranchField => "missing_branch_field",
            Self::LexicalBindingUnavailable => "lexical_binding_unavailable",
            Self::NonLocalReference => "non_local_reference",
            Self::EffectfulBody => "effectful_body",
            Self::EffectfulCondition => "effectful_condition",
            Self::UnsupportedCondition => "unsupported_condition",
            Self::ComparisonBudget => "comparison_budget",
            Self::MemberResolutionUnavailable => "member_resolution_unavailable",
            Self::AmbiguousMember => "ambiguous_member",
            Self::DeferredBody => "deferred_body",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchRelationRow {
    pub kind: BranchRelationKind,
    pub verdict: BranchRelationVerdict,
    pub owner: Range,
    pub earlier: Range,
    pub later: Range,
    pub earlier_ordinal: usize,
    pub later_ordinal: usize,
    /// Only Boolean-return rows have an orientation. This says what the two
    /// branches return, not that replacing them with the condition is safe.
    pub orientation: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct Arm<'tree> {
    condition: Option<Node<'tree>>,
    body: Node<'tree>,
}

/// Exact Java member targets supplied by the existing definition resolver.
/// A missing entry is never a negative lookup: it leaves this comparison open.
#[derive(Default)]
pub struct JavaMemberProofs {
    pub sites: HashMap<(usize, usize), Result<CodeUnit, BranchOpenReason>>,
    pub collection_gap: Option<BranchOpenReason>,
}

impl JavaMemberProofs {
    fn member_at(&self, node: Node<'_>) -> Result<&CodeUnit, BranchOpenReason> {
        self.sites
            .get(&(node.start_byte(), node.end_byte()))
            .map(|result| result.as_ref().map_err(|reason| *reason))
            .unwrap_or(Err(self
                .collection_gap
                .unwrap_or(BranchOpenReason::MemberResolutionUnavailable)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JavaMemberKind {
    Field,
    Method,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct JavaMemberSite {
    pub range: (usize, usize),
    pub kind: JavaMemberKind,
}

/// Collect the exact selector tokens once per prepared Java file. The caller
/// batches them through the existing resolver; collection never guesses a
/// declaration from a spelling or from a receiver's source text.
pub fn java_member_sites(
    syntax: &PreparedSyntaxTree,
) -> Result<Vec<JavaMemberSite>, BranchOpenReason> {
    const MAX_TREE_NODES: usize = 131_072;
    const MAX_MEMBER_SITES: usize = 256;
    let mut stack = vec![(syntax.tree().root_node(), false)];
    let mut sites = Vec::new();
    let mut visited = 0;
    while let Some((node, in_arm)) = stack.pop() {
        visited += 1;
        if visited > MAX_TREE_NODES || node.child_count() > MAX_TREE_NODES {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        if in_arm && is_nested_callable(node, Language::Java) {
            continue;
        }
        if in_arm && matches!(node.kind(), "field_access" | "method_invocation") {
            let (field, kind) = if node.kind() == "field_access" {
                ("field", JavaMemberKind::Field)
            } else {
                ("name", JavaMemberKind::Method)
            };
            let member = node
                .child_by_field_name(field)
                .ok_or(BranchOpenReason::MissingBranchField)?;
            sites.push(JavaMemberSite {
                range: (member.start_byte(), member.end_byte()),
                kind,
            });
            if sites.len() > MAX_MEMBER_SITES {
                return Err(BranchOpenReason::ComparisonBudget);
            }
        }
        stack.extend(non_extra_children(node).into_iter().map(|(field, child)| {
            (
                child,
                in_arm
                    || (node.kind() == "if_statement"
                        && matches!(field, Some("consequence" | "alternative"))),
            )
        }));
    }
    sites.sort_unstable();
    sites.dedup();
    Ok(sites)
}

/// Compare the arms of one `if` node. The range must identify the structural
/// `if` fact exactly; nested `if` nodes are separate seeds and are not folded
/// into this result except when they are the syntax of an `else if` chain.
pub fn relations_for_if(
    syntax: &PreparedSyntaxTree,
    language: Language,
    range: Range,
    env: &EnvironmentFileResult,
    members: &JavaMemberProofs,
) -> Vec<BranchRelationRow> {
    let if_kinds: &[&str] = match language {
        Language::Java
        | Language::JavaScript
        | Language::TypeScript
        | Language::Python
        | Language::CSharp
        | Language::Go
        | Language::Php
        | Language::Cpp => &["if_statement"],
        Language::Kotlin | Language::Rust | Language::Scala => &["if_expression"],
        Language::Ruby => &["if", "unless"],
        _ => return Vec::new(),
    };
    let Some(node) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        .filter(|node| node.start_byte() == range.start_byte && node.end_byte() == range.end_byte)
    else {
        return open_rows(range, BranchOpenReason::SyntaxRecovery);
    };
    if node.has_error() {
        return open_rows(range, BranchOpenReason::SyntaxRecovery);
    }
    // Other conditionals share the `If` fact (a C# `switch`, a Kotlin
    // `when`); these relations compare `if` arms only.
    if !if_kinds.contains(&node.kind()) {
        return Vec::new();
    }
    let arms = match collect_arms(node, language) {
        Ok(arms) => arms,
        Err(reason) => return open_rows(range, reason),
    };
    let condition_binders = match pattern_binders(
        arms.iter().filter_map(|arm| arm.condition),
        syntax.source(),
        language,
    ) {
        Ok(names) => names,
        Err(reason) => return open_rows(range, reason),
    };
    let chain = Chain {
        language,
        owner: node_range(node),
        source: syntax.source(),
        env,
        members,
        condition_binders: &condition_binders,
    };
    let mut rows = Vec::new();
    for later_ordinal in 1..arms.len() {
        let later = arms[later_ordinal];
        for earlier_ordinal in 0..later_ordinal {
            let earlier = arms[earlier_ordinal];
            let body_verdict = compare_trees(earlier.body, later.body, &chain);
            let body_verdict = if body_verdict == BranchRelationVerdict::Proven
                && matches!(language, Language::JavaScript | Language::TypeScript)
                && (has_with_ancestor(earlier.body) || has_with_ancestor(later.body))
            {
                BranchRelationVerdict::Open(BranchOpenReason::EffectfulBody)
            } else {
                body_verdict
            };
            rows.push(BranchRelationRow {
                kind: BranchRelationKind::IdenticalBodies,
                verdict: body_verdict,
                owner: node_range(node),
                earlier: node_range(earlier.body),
                later: node_range(later.body),
                earlier_ordinal,
                later_ordinal,
                orientation: None,
            });
            let (Some(earlier_condition), Some(later_condition)) =
                (earlier.condition, later.condition)
            else {
                continue;
            };
            let verdict = compare_trees(earlier_condition, later_condition, &chain);
            let verdict = if verdict == BranchRelationVerdict::Proven {
                arms[earlier_ordinal..=later_ordinal]
                    .iter()
                    .filter_map(|arm| arm.condition)
                    .map(|condition| condition_stability(condition, language, syntax, env))
                    .find(|verdict| *verdict != BranchRelationVerdict::Proven)
                    .unwrap_or(BranchRelationVerdict::Proven)
            } else {
                verdict
            };
            rows.push(BranchRelationRow {
                kind: BranchRelationKind::RepeatedCondition,
                verdict,
                owner: node_range(node),
                earlier: node_range(earlier_condition),
                later: node_range(later_condition),
                earlier_ordinal,
                later_ordinal,
                orientation: None,
            });
        }
    }
    rows.extend(redundant_boolean_row(syntax, language, node));
    rows
}

/// The redundant Boolean return pair of one `if`: its two arms, or its true
/// arm and the return that follows it in the same block.
fn redundant_boolean_row(
    syntax: &PreparedSyntaxTree,
    language: Language,
    node: Node<'_>,
) -> Option<BranchRelationRow> {
    let true_body = node.child_by_field_name(consequence_field(language))?;
    let false_body = if let Some(alternative) = node.child_by_field_name("alternative") {
        if alternative.kind() == "else_clause" {
            alternative.named_child(0)?
        } else {
            alternative
        }
    } else {
        // A Rust `if` in statement position is wrapped in an expression
        // statement, whose siblings are the block's other statements.
        let statement = match node.parent() {
            Some(parent)
                if language == Language::Rust && parent.kind() == "expression_statement" =>
            {
                parent
            }
            _ => node,
        };
        let parent = statement.parent().filter(|parent| !parent.has_error())?;
        let blocks: &[&str] = match language {
            Language::Java | Language::Python | Language::CSharp | Language::Rust => &["block"],
            Language::Php | Language::Cpp => &["compound_statement"],
            Language::JavaScript | Language::TypeScript => &["statement_block"],
            Language::Go => &["statement_list"],
            Language::Kotlin => &["statements"],
            Language::Scala => &["block", "indented_block"],
            Language::Ruby => &["body_statement"],
            _ => return None,
        };
        if !blocks.contains(&parent.kind()) {
            return None;
        }
        let mut following = statement.next_named_sibling()?;
        while following.is_extra() {
            following = following.next_named_sibling()?;
        }
        following
    };
    let outcome = classify_boolean_branches(language, syntax.source(), true_body, false_body)?;
    // The first arm of a Ruby `unless` runs when its condition is false.
    let outcome = match (node.kind(), outcome) {
        ("unless", BooleanBranchOutcome::Condition) => BooleanBranchOutcome::NegatedCondition,
        ("unless", BooleanBranchOutcome::NegatedCondition) => BooleanBranchOutcome::Condition,
        (_, outcome) => outcome,
    };
    Some(BranchRelationRow {
        kind: BranchRelationKind::RedundantBooleanReturn,
        verdict: BranchRelationVerdict::Proven,
        owner: node_range(node),
        earlier: node_range(true_body),
        later: node_range(false_body),
        earlier_ordinal: 0,
        later_ordinal: 1,
        orientation: Some(match outcome {
            BooleanBranchOutcome::Condition => "condition",
            BooleanBranchOutcome::NegatedCondition => "negated_condition",
        }),
    })
}

fn open_rows(range: Range, reason: BranchOpenReason) -> Vec<BranchRelationRow> {
    [
        BranchRelationKind::IdenticalBodies,
        BranchRelationKind::RepeatedCondition,
        BranchRelationKind::RedundantBooleanReturn,
    ]
    .into_iter()
    .map(|kind| BranchRelationRow {
        kind,
        verdict: BranchRelationVerdict::Open(reason),
        owner: range,
        earlier: range,
        later: range,
        earlier_ordinal: 0,
        later_ordinal: 0,
        orientation: None,
    })
    .collect()
}

fn collect_arms<'tree>(
    node: Node<'tree>,
    language: Language,
) -> Result<Vec<Arm<'tree>>, BranchOpenReason> {
    if is_chain_child(node) {
        return Ok(Vec::new());
    }
    let body_field = consequence_field(language);
    let mut arms = Vec::new();
    let mut current = node;
    loop {
        if current.has_error() {
            return Err(BranchOpenReason::SyntaxRecovery);
        }
        arms.push(Arm {
            condition: Some(
                current
                    .child_by_field_name("condition")
                    .ok_or(BranchOpenReason::MissingBranchField)?,
            ),
            body: current
                .child_by_field_name(body_field)
                .ok_or(BranchOpenReason::MissingBranchField)?,
        });
        if arms.len() > 16 {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        if language == Language::Python {
            let mut cursor = current.walk();
            for alternative in current.children_by_field_name("alternative", &mut cursor) {
                match alternative.kind() {
                    "elif_clause" => arms.push(Arm {
                        condition: Some(
                            alternative
                                .child_by_field_name("condition")
                                .ok_or(BranchOpenReason::MissingBranchField)?,
                        ),
                        body: alternative
                            .child_by_field_name("consequence")
                            .ok_or(BranchOpenReason::MissingBranchField)?,
                    }),
                    "else_clause" => arms.push(Arm {
                        condition: None,
                        body: alternative
                            .child_by_field_name("body")
                            .ok_or(BranchOpenReason::MissingBranchField)?,
                    }),
                    _ => return Err(BranchOpenReason::MissingBranchField),
                }
                if arms.len() > 16 {
                    return Err(BranchOpenReason::ComparisonBudget);
                }
            }
            return Ok(arms);
        }
        if language == Language::Php {
            let mut cursor = current.walk();
            let alternatives = current
                .children_by_field_name("alternative", &mut cursor)
                .collect::<Vec<_>>();
            let mut next = None;
            for alternative in alternatives {
                let body = alternative
                    .child_by_field_name("body")
                    .ok_or(BranchOpenReason::MissingBranchField)?;
                match alternative.kind() {
                    "else_if_clause" => arms.push(Arm {
                        condition: Some(
                            alternative
                                .child_by_field_name("condition")
                                .ok_or(BranchOpenReason::MissingBranchField)?,
                        ),
                        body,
                    }),
                    // `else if` (two words) nests another `if` statement.
                    "else_clause" if body.kind() == "if_statement" => next = Some(body),
                    "else_clause" => arms.push(Arm {
                        condition: None,
                        body,
                    }),
                    _ => return Err(BranchOpenReason::MissingBranchField),
                }
                if arms.len() > 16 {
                    return Err(BranchOpenReason::ComparisonBudget);
                }
            }
            match next {
                Some(next) => {
                    current = next;
                    continue;
                }
                None => return Ok(arms),
            }
        }
        let Some(mut alternative) = current.child_by_field_name("alternative") else {
            return Ok(arms);
        };
        if alternative.kind() == "else_clause" {
            alternative = alternative
                .named_child(0)
                .ok_or(BranchOpenReason::MissingBranchField)?;
        }
        // A Kotlin `else if` is an `if` expression that is the whole body of
        // the `else` arm.
        if let Some(nested) = kotlin_else_if(alternative) {
            alternative = nested;
        }
        if matches!(
            alternative.kind(),
            "if_statement" | "if_expression" | "elsif"
        ) {
            // A Go `else if` initializer runs between two conditions of the
            // chain.
            if alternative.child_by_field_name("initializer").is_some() {
                return Err(BranchOpenReason::EffectfulCondition);
            }
            current = alternative;
            continue;
        }
        arms.push(Arm {
            condition: None,
            body: alternative,
        });
        if arms.len() > 16 {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        return Ok(arms);
    }
}

/// The field that holds an `if`'s true arm.
pub(crate) fn consequence_field(language: Language) -> &'static str {
    if language == Language::Php {
        "body"
    } else {
        "consequence"
    }
}

fn is_chain_child(node: Node<'_>) -> bool {
    // PHP gives an `if` one `alternative` field per `elseif`/`else` clause.
    let is_alternative = |owner: Node<'_>, child: Node<'_>| {
        let mut cursor = owner.walk();
        owner
            .children_by_field_name("alternative", &mut cursor)
            .any(|alternative| alternative.id() == child.id())
    };
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "if_statement" | "if_expression" | "if" | "elsif"
    ) {
        return is_alternative(parent, node);
    }
    matches!(parent.kind(), "else_clause" | "control_structure_body")
        && (parent.kind() != "control_structure_body" || kotlin_else_if(parent) == Some(node))
        && parent.parent().is_some_and(|owner| {
            matches!(owner.kind(), "if_statement" | "if_expression")
                && is_alternative(owner, parent)
        })
}

/// The `if` expression that is the whole body of a Kotlin `else` arm.
fn kotlin_else_if(body: Node<'_>) -> Option<Node<'_>> {
    if body.kind() != "control_structure_body" || body.named_child_count() != 1 {
        return None;
    }
    body.named_child(0)
        .filter(|nested| nested.kind() == "if_expression")
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

/// What every comparison within one `if` chain shares.
#[derive(Clone, Copy)]
struct Chain<'a> {
    language: Language,
    /// The `if` whose chain is compared.
    owner: Range,
    source: &'a str,
    env: &'a EnvironmentFileResult,
    members: &'a JavaMemberProofs,
    /// See [`java_pattern_binders`].
    condition_binders: &'a [&'a str],
}

/// Compare two subtrees node for node.
///
/// A nested callable or local class at matching positions makes an otherwise
/// equal comparison `DeferredBody`: its shape is still compared, so a
/// syntactic difference inside it remains `Distinct`, but its names are not,
/// because its own parameters and locals bind per closure and its captures are
/// not modeled.
fn compare_trees(earlier: Node<'_>, later: Node<'_>, chain: &Chain<'_>) -> BranchRelationVerdict {
    let Chain {
        language,
        owner,
        source,
        env,
        members,
        condition_binders,
    } = *chain;
    // The flag records whether the pair lies inside a nested callable.
    let mut stack = vec![(earlier, later, false)];
    let mut renamed = HashMap::<usize, usize>::new();
    let mut reverse_renamed = HashMap::<usize, usize>::new();
    // Reads resolve after every arm-local binder is paired, so a read that
    // precedes its binder in source order, such as a comprehension element,
    // still sees the pairing.
    let mut reads = Vec::new();
    let mut deferred = false;
    let mut visited = 0;
    while let Some((left, right, nested)) = stack.pop() {
        visited += 1;
        if visited > 4096 {
            return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
        }
        if left.has_error() || right.has_error() || left.is_missing() || right.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        // A Ruby arm is a `then` or an `else`, each a statement list; only
        // their statements are compared.
        let ruby_arm = |node: Node<'_>| matches!(node.kind(), "then" | "else");
        if language == Language::Ruby && ruby_arm(left) && ruby_arm(right) {
            let (left_statements, right_statements) =
                (named_statements(left), named_statements(right));
            if left_statements.len() != right_statements.len() {
                return BranchRelationVerdict::Distinct;
            }
            stack.extend(
                left_statements
                    .into_iter()
                    .zip(right_statements)
                    .rev()
                    .map(|(left, right)| (left, right, nested)),
            );
            continue;
        }
        if left.kind() != right.kind() {
            // `this.value` and a bare `value` can name one Java field, which
            // only a field resolution for the bare name could prove. A bare
            // name bound to a local or parameter is never that field.
            if language == Language::Java
                && let Some((access, bare)) =
                    [(left, right), (right, left)]
                        .into_iter()
                        .find(|(access, bare)| {
                            access.kind() == "field_access"
                                && bare.kind() == "identifier"
                                && access
                                    .child_by_field_name("object")
                                    .is_some_and(|object| object.kind() == "this")
                        })
                && let Some(name) = source.get(bare.byte_range())
                && access
                    .child_by_field_name("field")
                    .and_then(|field| source.get(field.byte_range()))
                    == Some(name)
            {
                return match binding_of(env, name, bare.start_byte(), Some(Namespace::Value)) {
                    BindingOfOutcome::NoBinding => {
                        BranchRelationVerdict::Open(BranchOpenReason::MemberResolutionUnavailable)
                    }
                    BindingOfOutcome::Incomplete(_) => {
                        BranchRelationVerdict::Open(BranchOpenReason::LexicalBindingUnavailable)
                    }
                    BindingOfOutcome::Reached(_) | BindingOfOutcome::Shadowed { .. } => {
                        BranchRelationVerdict::Distinct
                    }
                };
            }
            return BranchRelationVerdict::Distinct;
        }
        let nested = nested || is_nested_callable(left, language);
        deferred |= nested;
        if position_dependent(left, language, source) || position_dependent(right, language, source)
        {
            return BranchRelationVerdict::Distinct;
        }
        if left.kind() == "field_access" {
            let (Some(left_field), Some(right_field), Some(left_object), Some(right_object)) = (
                left.child_by_field_name("field"),
                right.child_by_field_name("field"),
                left.child_by_field_name("object"),
                right.child_by_field_name("object"),
            ) else {
                return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
            };
            if !same_member(left_field, right_field, source, members) {
                return BranchRelationVerdict::Distinct;
            }
            stack.push((left_object, right_object, nested));
            continue;
        }
        if language == Language::Java && left.kind() == "method_invocation" {
            if left.child_count() > 4096 || right.child_count() > 4096 {
                return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
            }
            let (Some(left_name), Some(right_name)) = (
                left.child_by_field_name("name"),
                right.child_by_field_name("name"),
            ) else {
                return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
            };
            if !same_member(left_name, right_name, source, members) {
                return BranchRelationVerdict::Distinct;
            }
            let mut left_children = non_extra_children(left)
                .into_iter()
                .filter(|(field, _)| *field != Some("name"))
                .collect::<Vec<_>>();
            let mut right_children = non_extra_children(right)
                .into_iter()
                .filter(|(field, _)| *field != Some("name"))
                .collect::<Vec<_>>();
            // `this.render()` and an implicit-this `render()` are one virtual
            // call when both resolve to the same method; `super.` is not,
            // because it bypasses overriding.
            let left_this = explicit_this_receiver(left);
            let right_this = explicit_this_receiver(right);
            let left_implicit = left.child_by_field_name("object").is_none();
            let right_implicit = right.child_by_field_name("object").is_none();
            if (left_this && right_implicit) || (right_this && left_implicit) {
                match (members.member_at(left_name), members.member_at(right_name)) {
                    (Ok(a), Ok(b)) if a == b => {
                        for children in [&mut left_children, &mut right_children] {
                            children.retain(|(field, child)| {
                                *field != Some("object") && child.kind() != "."
                            });
                        }
                    }
                    (Ok(_), Ok(_)) => return BranchRelationVerdict::Distinct,
                    (Err(reason), _) | (_, Err(reason)) => {
                        return BranchRelationVerdict::Open(reason);
                    }
                }
            }
            if left_children.len() != right_children.len() {
                return BranchRelationVerdict::Distinct;
            }
            for ((left_field, left_child), (right_field, right_child)) in
                left_children.into_iter().zip(right_children).rev()
            {
                if left_field != right_field {
                    return BranchRelationVerdict::Distinct;
                }
                stack.push((left_child, right_child, nested));
            }
            continue;
        }
        if left.child_count() > 4096 || right.child_count() > 4096 {
            return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
        }
        let left_children = non_extra_children(left);
        let right_children = non_extra_children(right);
        if left_children.len() != right_children.len() {
            return BranchRelationVerdict::Distinct;
        }
        if !left_children.is_empty() {
            for ((left_field, left_child), (right_field, right_child)) in
                left_children.into_iter().zip(right_children).rev()
            {
                if left_field != right_field {
                    return BranchRelationVerdict::Distinct;
                }
                stack.push((left_child, right_child, nested));
            }
            continue;
        }
        let is_name = matches!(
            left.kind(),
            "identifier"
                | "simple_identifier"
                | "type_identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        );
        // A name inside a nested callable may be one of its own binders, so
        // it neither proves nor refutes the comparison, which is deferred.
        if nested && is_name {
            continue;
        }
        let (Some(name), Some(other_name)) = (
            source.get(left.byte_range()),
            source.get(right.byte_range()),
        ) else {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        };
        if matches!(
            left.kind(),
            "identifier" | "simple_identifier" | "shorthand_property_identifier_pattern"
        ) {
            // A declaration inside each arm is a pair of distinct bindings
            // that stand for each other, like a block local in each arm.
            let binder_at = |node: Node<'_>, spelling: &str, arm: Node<'_>| {
                env.bindings_named(spelling).iter().copied().find(|index| {
                    let range = env.bindings[*index].range;
                    range.start_byte == node.start_byte()
                        && range.end_byte == node.end_byte()
                        && arm_local_binding(env, *index, arm)
                })
            };
            match (
                binder_at(left, name, earlier),
                binder_at(right, other_name, later),
            ) {
                (Some(a), Some(b)) => {
                    if env.bindings[a].kind != env.bindings[b].kind
                        || env.bindings[a].hoisting != env.bindings[b].hoisting
                    {
                        return BranchRelationVerdict::Open(
                            BranchOpenReason::LexicalBindingUnavailable,
                        );
                    }
                    // A shorthand pattern's spelling is also the property it
                    // destructures.
                    if left.kind() == "shorthand_property_identifier_pattern" && name != other_name
                    {
                        return BranchRelationVerdict::Distinct;
                    }
                    if renamed.insert(a, b).is_some_and(|prior| prior != b)
                        || reverse_renamed.insert(b, a).is_some_and(|prior| prior != a)
                    {
                        return BranchRelationVerdict::Open(
                            BranchOpenReason::LexicalBindingUnavailable,
                        );
                    }
                    continue;
                }
                (Some(_), None) | (None, Some(_)) => {
                    return BranchRelationVerdict::Open(
                        BranchOpenReason::LexicalBindingUnavailable,
                    );
                }
                (None, None) => {}
            }
        }
        if matches!(left.kind(), "identifier" | "simple_identifier") {
            match (identifier_role(left), identifier_role(right)) {
                // A declaration the environment does not place inside its arm.
                (IdentifierRole::Binder, IdentifierRole::Binder) => {
                    return BranchRelationVerdict::Open(
                        BranchOpenReason::LexicalBindingUnavailable,
                    );
                }
                (IdentifierRole::Value, IdentifierRole::Value) => reads.push((left, right)),
                // A property, attribute, label or type name at matching
                // positions is the same structured name.
                (IdentifierRole::NonValue, IdentifierRole::NonValue) => {
                    if name != other_name {
                        return BranchRelationVerdict::Distinct;
                    }
                }
                (IdentifierRole::NonValue, _) | (_, IdentifierRole::NonValue) => {
                    return BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference);
                }
                _ => return BranchRelationVerdict::Distinct,
            }
        } else if left.is_named() && name != other_name {
            return BranchRelationVerdict::Distinct;
        }
    }
    for (left, right) in reads {
        let (Some(name), Some(other_name)) = (
            source.get(left.byte_range()),
            source.get(right.byte_range()),
        ) else {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        };
        // A Ruby assignment target is its own binder: the environment starts
        // that binding after the assignment, so a lookup at the target would
        // find an earlier assignment's row or nothing.
        let resolve = |node: Node<'_>, spelling: &str| {
            let own = (language == Language::Ruby)
                .then(|| {
                    env.bindings_named(spelling).iter().copied().find(|index| {
                        let range = env.bindings[*index].range;
                        range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
                    })
                })
                .flatten();
            match own {
                Some(index) => BindingOfOutcome::Reached(index),
                None => binding_of(env, spelling, node.start_byte(), Some(Namespace::Value)),
            }
        };
        let (a, b) = match (resolve(left, name), resolve(right, other_name)) {
            (BindingOfOutcome::Reached(a), BindingOfOutcome::Reached(b)) => (a, b),
            (
                BindingOfOutcome::Shadowed { winner: a, .. },
                BindingOfOutcome::Shadowed { winner: b, .. },
            ) => (a, b),
            (BindingOfOutcome::Reached(a), BindingOfOutcome::Shadowed { winner: b, .. })
            | (BindingOfOutcome::Shadowed { winner: a, .. }, BindingOfOutcome::Reached(b)) => {
                (a, b)
            }
            // One unbound spelling in both arms is one global or member
            // lookup from the same scope, unless a chain condition declares
            // it with a binder the environment does not model.
            (BindingOfOutcome::NoBinding, BindingOfOutcome::NoBinding) if name == other_name => {
                if condition_binders.contains(&name) {
                    return BranchRelationVerdict::Open(
                        BranchOpenReason::LexicalBindingUnavailable,
                    );
                }
                continue;
            }
            (BindingOfOutcome::NoBinding, _) | (_, BindingOfOutcome::NoBinding) => {
                return BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference);
            }
            (BindingOfOutcome::Incomplete(_), _) | (_, BindingOfOutcome::Incomplete(_)) => {
                return BranchRelationVerdict::Open(BranchOpenReason::LexicalBindingUnavailable);
            }
        };
        // A pattern binder that a chain condition declares, such as Rust's
        // `if let Some(v) = ..`, is in effect in some arms only, but the
        // environment states its interval as the whole `if`. In an arm where
        // it is not in effect, the same spelling names another binding.
        let declared_by_condition = |index: usize| {
            let range = env.bindings[index].range;
            let within =
                |start: usize, end: usize| start <= range.start_byte && range.end_byte <= end;
            env.bindings[index].kind == BindingKind::PatternBinder
                && within(owner.start_byte, owner.end_byte)
                && !within(earlier.start_byte(), earlier.end_byte())
                && !within(later.start_byte(), later.end_byte())
        };
        if declared_by_condition(a) || declared_by_condition(b) {
            return BranchRelationVerdict::Open(BranchOpenReason::LexicalBindingUnavailable);
        }
        // Every assignment to a Ruby local is a binding row of its own, but
        // all of them in one method are the same variable. In valid Go, two
        // declarations of one name in one block are a `:=` redeclaration,
        // which assigns the existing variable.
        if matches!(language, Language::Ruby | Language::Go)
            && name == other_name
            && env.bindings[a].kind == BindingKind::Local
            && env.bindings[b].kind == BindingKind::Local
            && env.bindings[a].declaring_scope == env.bindings[b].declaring_scope
        {
            continue;
        }
        if let Some(mapped) = renamed.get(&a) {
            if *mapped != b {
                return BranchRelationVerdict::Distinct;
            }
            continue;
        }
        if reverse_renamed.contains_key(&b) {
            return BranchRelationVerdict::Distinct;
        }
        if a != b && (arm_local_binding(env, a, earlier) || arm_local_binding(env, b, later)) {
            return BranchRelationVerdict::Open(BranchOpenReason::LexicalBindingUnavailable);
        }
        if !ordinary_binding(env, a) || !ordinary_binding(env, b) {
            if a == b && name == other_name {
                continue;
            }
            return BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference);
        }
        if a != b || name != other_name {
            return BranchRelationVerdict::Distinct;
        }
    }
    if deferred {
        BranchRelationVerdict::Open(BranchOpenReason::DeferredBody)
    } else {
        BranchRelationVerdict::Proven
    }
}

/// Whether a C or C++ binding's declaration makes its value stable between two
/// condition tests: it is not `volatile`, and in C++ its declared type is a
/// built-in type, so no overloaded operator can run.
fn cpp_stable_declaration(
    env: &EnvironmentFileResult,
    index: usize,
    reference: Node<'_>,
    source: &str,
    c_dialect: bool,
) -> bool {
    let mut root = reference;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let range = env.bindings[index].range;
    let Some(name) = root.named_descendant_for_byte_range(range.start_byte, range.end_byte) else {
        return false;
    };
    let Some(declaration) =
        std::iter::successors(name.parent(), |node| node.parent()).find(|node| {
            matches!(
                node.kind(),
                "declaration"
                    | "parameter_declaration"
                    | "optional_parameter_declaration"
                    | "for_range_loop"
            )
        })
    else {
        return false;
    };
    let mut cursor = declaration.walk();
    let volatile = declaration.children(&mut cursor).any(|child| {
        child.kind() == "type_qualifier" && source.get(child.byte_range()) == Some("volatile")
    });
    !volatile
        && (c_dialect
            || declaration
                .child_by_field_name("type")
                .is_some_and(|written| written.kind() == "primitive_type"))
}

/// Whether a Scala or C# binding is declared with the written Boolean type
/// (`Boolean`, `bool`).
fn declared_boolean(
    env: &EnvironmentFileResult,
    index: usize,
    reference: Node<'_>,
    source: &str,
) -> bool {
    let mut root = reference;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let range = env.bindings[index].range;
    let Some(name) = root.named_descendant_for_byte_range(range.start_byte, range.end_byte) else {
        return false;
    };
    let Some(declaration) = name.parent() else {
        return false;
    };
    // A C# declarator's type is on its enclosing variable declaration.
    let (names_binding, typed) = match declaration.kind() {
        "val_definition" | "var_definition" => (
            declaration.child_by_field_name("pattern"),
            Some(declaration),
        ),
        "parameter" => (declaration.child_by_field_name("name"), Some(declaration)),
        "variable_declarator" => (
            declaration.child_by_field_name("name"),
            declaration.parent(),
        ),
        _ => (None, None),
    };
    names_binding.is_some_and(|binding| binding.id() == name.id())
        && matches!(
            typed
                .and_then(|typed| typed.child_by_field_name("type"))
                .and_then(|written| source.get(written.byte_range())),
            Some("Boolean" | "bool")
        )
}

/// Whether `node` evaluates to its own source position, so two spellings of
/// it at different positions are different values: Rust's `line!()` and
/// `column!()`, PHP's case-insensitive `__LINE__` and Ruby's `__LINE__`.
fn position_dependent(node: Node<'_>, language: Language, source: &str) -> bool {
    match language {
        Language::Php => {
            return node.kind() == "name"
                && source
                    .get(node.byte_range())
                    .is_some_and(|name| name.eq_ignore_ascii_case("__LINE__"));
        }
        // The Ruby grammar spells `__LINE__` as an identifier.
        Language::Ruby => {
            return node.kind() == "line"
                || (node.kind() == "identifier"
                    && source.get(node.byte_range()) == Some("__LINE__"));
        }
        // `__LINE__` and `__COUNTER__` are macros the preprocessor replaces
        // with the line and a running count.
        Language::Cpp => {
            return node.kind() == "identifier"
                && matches!(
                    source.get(node.byte_range()),
                    Some("__LINE__" | "__COUNTER__")
                );
        }
        Language::Rust => {}
        _ => return false,
    }
    if node.kind() != "macro_invocation" {
        return false;
    }
    let Some(mut name) = node.child_by_field_name("macro") else {
        return false;
    };
    if name.kind() == "scoped_identifier"
        && let Some(last) = name.child_by_field_name("name")
    {
        name = last;
    }
    matches!(source.get(name.byte_range()), Some("line" | "column"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentifierRole {
    Value,
    Binder,
    NonValue,
}

fn identifier_role(node: Node<'_>) -> IdentifierRole {
    let Some(parent) = node.parent() else {
        return IdentifierRole::NonValue;
    };
    let field = (0..parent.child_count()).find_map(|index| {
        (parent.child(index) == Some(node)).then(|| parent.field_name_for_child(index as u32))
    });
    if matches!(
        parent.kind(),
        "jsx_opening_element" | "jsx_closing_element" | "jsx_self_closing_element"
    ) {
        return IdentifierRole::NonValue;
    }
    if parent.kind() == "method_invocation" && field.flatten() != Some("object") {
        return IdentifierRole::NonValue;
    }
    // Kotlin spells no fields: a member follows `.` in a navigation suffix, a
    // named argument's label precedes its `=`, and a local's name is the
    // direct child of its variable declaration.
    match parent.kind() {
        "navigation_suffix" => return IdentifierRole::NonValue,
        "value_argument" if node.next_sibling().is_some_and(|next| next.kind() == "=") => {
            return IdentifierRole::NonValue;
        }
        "variable_declaration" => return IdentifierRole::Binder,
        _ => {}
    }
    match field.flatten() {
        Some("name") if parent.kind() == "variable_declarator" => IdentifierRole::Binder,
        Some("name" | "property" | "field" | "attribute" | "key" | "type" | "label") => {
            IdentifierRole::NonValue
        }
        _ => IdentifierRole::Value,
    }
}

fn ordinary_binding(env: &EnvironmentFileResult, index: usize) -> bool {
    matches!(
        env.bindings[index].kind,
        BindingKind::Local | BindingKind::Parameter
    )
}

/// Whether a binding is declared inside `arm` and is in effect nowhere else:
/// a block local, a catch or resource variable, a loop variable or a
/// comprehension target. A Python assignment in an arm binds a function
/// local, whose activation covers the whole function, so it is not arm-local.
fn arm_local_binding(env: &EnvironmentFileResult, index: usize, arm: Node<'_>) -> bool {
    let binding = &env.bindings[index];
    matches!(
        binding.kind,
        BindingKind::Local
            | BindingKind::PatternBinder
            | BindingKind::LoopVariable
            | BindingKind::CatchOrResource
    ) && arm.start_byte() <= binding.activation.start_byte
        && binding.activation.end_byte <= arm.end_byte()
        && arm.start_byte() <= binding.range.start_byte
        && binding.range.end_byte <= arm.end_byte()
}

fn has_with_ancestor(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if current.kind() == "with_statement" {
            return true;
        }
        ancestor = current.parent();
    }
    false
}

fn stable_binding(env: &EnvironmentFileResult, index: usize) -> bool {
    if !ordinary_binding(env, index) {
        return false;
    }
    let mut scope = Some(env.bindings[index].declaring_scope);
    while let Some(index) = scope {
        let row = env.scope(index);
        if matches!(
            row.anchor.kind(),
            Some(
                NormalizedKind::Function
                    | NormalizedKind::Method
                    | NormalizedKind::Constructor
                    | NormalizedKind::Lambda
            )
        ) {
            return true;
        }
        scope = row.parent_scope;
    }
    false
}

fn named_statements(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !child.is_extra())
        .collect()
}

fn non_extra_children(node: Node<'_>) -> Vec<(Option<&str>, Node<'_>)> {
    (0..node.child_count())
        .filter_map(|index| {
            let child = node.child(index)?;
            (!child.is_extra()).then(|| (node.field_name_for_child(index as u32), child))
        })
        .collect()
}

/// Whether a Java member selector at matching positions names the same member.
/// Matching trees give the selectors the same receiver and arguments, so an
/// equal spelling is the same lookup; two resolved targets can still show
/// that the lookups differ.
fn same_member(left: Node<'_>, right: Node<'_>, source: &str, members: &JavaMemberProofs) -> bool {
    match (members.member_at(left), members.member_at(right)) {
        (Ok(a), Ok(b)) => a == b,
        _ => source.get(left.byte_range()) == source.get(right.byte_range()),
    }
}

fn explicit_this_receiver(invocation: Node<'_>) -> bool {
    invocation
        .child_by_field_name("object")
        .is_some_and(|object| object.kind() == "this")
}

/// A nested callable or local class creates a new closure or class per arm.
/// Its captures and class identity are not modeled, so its equivalence stays
/// open rather than inferred from matching syntax. The kinds cover the Java,
/// JavaScript, TypeScript and Python grammars; a Python decorated definition
/// is covered by the definition it wraps.
fn is_nested_callable(node: Node<'_>, language: Language) -> bool {
    // A Ruby `block` is a closure; elsewhere a `block` is a statement block.
    if language == Language::Ruby {
        return node.is_named()
            && matches!(
                node.kind(),
                "method"
                    | "singleton_method"
                    | "block"
                    | "do_block"
                    | "lambda"
                    | "class"
                    | "module"
                    | "singleton_class"
            );
    }
    node.is_named()
        && matches!(
            node.kind(),
            // Java. `class_body` also covers an anonymous class.
            "lambda_expression"
                | "method_declaration"
                | "constructor_declaration"
                | "class_declaration"
                | "record_declaration"
                | "enum_declaration"
                | "interface_declaration"
                | "class_body"
                // JavaScript and TypeScript.
                | "function_declaration"
                | "function_expression"
                | "generator_function"
                | "generator_function_declaration"
                | "arrow_function"
                | "method_definition"
                | "class"
                | "abstract_class_declaration"
                // Python.
                | "function_definition"
                | "lambda"
                | "class_definition"
                // Rust. An async block's body runs when it is awaited.
                | "closure_expression"
                | "function_item"
                | "impl_item"
                | "trait_item"
                | "mod_item"
                | "async_block"
                // Go.
                | "func_literal"
                // C and C++, beyond the shared lambda and function kinds.
                | "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                // C#, beyond the shared lambda and class-like kinds.
                | "anonymous_method_expression"
                | "local_function_statement"
                | "struct_declaration"
                | "record_struct_declaration"
                // Kotlin, beyond the shared function, class and
                // `anonymous_function` (PHP's closure kind too) kinds.
                | "lambda_literal"
                | "object_declaration"
                | "object_literal"
                | "companion_object"
                // PHP, beyond the shared function, method, class, interface,
                // enum and arrow-function kinds.
                | "anonymous_function"
                | "anonymous_class"
                | "trait_declaration"
                // Scala, beyond the shared `lambda_expression`,
                // `function_definition` and `class_definition`. `new T { .. }`
                // is an anonymous class.
                | "object_definition"
                | "trait_definition"
                | "given_definition"
                | "instance_expression"
        )
}

/// The spellings that Java pattern variables in the chain's conditions
/// declare.
///
/// The lexical environment does not model Java pattern variables. Their scope
/// is flow-sensitive: a condition's variable can cover its own arm or the
/// later arms, so one spelling read in two arms can denote two bindings. The
/// comparison therefore cannot treat such a spelling as one unbound lookup.
/// A pattern variable declared inside an arm is harmless: a matching arm
/// declares it at the matching position. JavaScript, TypeScript and Python
/// conditions declare no binding that is visible in only some arms; a Python
/// assignment expression binds one function local for every arm.
/// The names of the Java pattern variables declared under `roots`, outside
/// nested lambdas and classes. The lexical environment does not return
/// pattern binders, so a consumer that resolves names through it must treat
/// these names as possibly bound.
pub(crate) fn java_pattern_binders<'tree, 'source>(
    roots: impl IntoIterator<Item = Node<'tree>>,
    source: &'source str,
) -> Result<Vec<&'source str>, BranchOpenReason> {
    pattern_binders(roots, source, Language::Java)
}

fn pattern_binders<'tree, 'source>(
    roots: impl IntoIterator<Item = Node<'tree>>,
    source: &'source str,
    language: Language,
) -> Result<Vec<&'source str>, BranchOpenReason> {
    let Some(pattern_binding_name) =
        language_support(language).and_then(LanguageSupport::pattern_binding_name_provider)
    else {
        return Ok(Vec::new());
    };
    let mut stack = roots.into_iter().collect::<Vec<_>>();
    let mut names = Vec::new();
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > 4096 || node.child_count() > 4096 {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        // A pattern inside a lambda or anonymous class binds only there.
        if is_nested_callable(node, language) {
            continue;
        }
        let binder = pattern_binding_name(node);
        if let Some(binder) = binder {
            names.push(
                source
                    .get(binder.byte_range())
                    .ok_or(BranchOpenReason::SyntaxRecovery)?,
            );
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    Ok(names)
}

fn condition_stability(
    condition: Node<'_>,
    language: Language,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
) -> BranchRelationVerdict {
    let c_dialect = syntax.dialect() == crate::analyzer::LanguageDialect::CppC;
    let baseline = basic_condition_stability(condition, language, c_dialect, syntax.source(), env);
    if language != Language::Java
        || !matches!(
            baseline,
            BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition)
        )
    {
        return baseline;
    }
    java_primitive_condition_stability(condition, syntax, env)
}

fn basic_condition_stability(
    condition: Node<'_>,
    language: Language,
    c_dialect: bool,
    source: &str,
    env: &EnvironmentFileResult,
) -> BranchRelationVerdict {
    if matches!(language, Language::JavaScript | Language::TypeScript)
        && has_with_ancestor(condition)
    {
        return BranchRelationVerdict::Open(BranchOpenReason::EffectfulCondition);
    }
    if language == Language::Python && condition.kind() != "comparison_operator" {
        return BranchRelationVerdict::Open(BranchOpenReason::EffectfulCondition);
    }
    let mut stack = vec![condition];
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > 4096 || node.child_count() > 4096 {
            return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
        }
        if node.has_error() || node.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        let kind = node.kind();
        if matches!(
            (language, kind),
            (
                Language::JavaScript | Language::TypeScript,
                "string" | "number"
            ) | (Language::Java, "string_literal" | "decimal_integer_literal")
        ) {
            continue;
        }
        let allowed = match language {
            Language::JavaScript | Language::TypeScript => matches!(
                kind,
                "identifier"
                    | "true"
                    | "false"
                    | "null"
                    | "parenthesized_expression"
                    | "unary_expression"
                    | "binary_expression"
                    | "!"
                    | "==="
                    | "!=="
                    | "("
                    | ")"
            ),
            Language::Java => matches!(
                kind,
                "identifier"
                    | "true"
                    | "false"
                    | "null_literal"
                    | "parenthesized_expression"
                    | "unary_expression"
                    | "binary_expression"
                    | "!"
                    | "=="
                    | "!="
                    | "("
                    | ")"
            ),
            Language::Python => matches!(
                kind,
                "identifier"
                    | "none"
                    | "true"
                    | "false"
                    | "comparison_operator"
                    | "is"
                    | "not"
                    | "("
                    | ")"
            ),
            // C and C++ comparisons and logic over locals and literals. C has
            // no operator overloading; a C++ operand must be declared with a
            // built-in type. A `volatile` local can change between tests.
            Language::Cpp => matches!(
                kind,
                "identifier"
                    | "number_literal"
                    | "char_literal"
                    | "true"
                    | "false"
                    | "null"
                    | "nullptr"
                    | "condition_clause"
                    | "parenthesized_expression"
                    | "binary_expression"
                    | "unary_expression"
                    | "=="
                    | "!="
                    | "<"
                    | "<="
                    | ">"
                    | ">="
                    | "&&"
                    | "||"
                    | "!"
                    | "-"
                    | "("
                    | ")"
            ),
            // Go has no operator overloading: comparing and negating local
            // values runs no user code. A dereference, an address, a channel
            // receive, a member and a call are excluded.
            Language::Go => matches!(
                kind,
                "identifier"
                    | "int_literal"
                    | "float_literal"
                    | "rune_literal"
                    | "interpreted_string_literal"
                    | "interpreted_string_literal_content"
                    | "raw_string_literal"
                    | "raw_string_literal_content"
                    | "escape_sequence"
                    | "true"
                    | "false"
                    | "nil"
                    | "parenthesized_expression"
                    | "binary_expression"
                    | "unary_expression"
                    | "=="
                    | "!="
                    | "<"
                    | "<="
                    | ">"
                    | ">="
                    | "&&"
                    | "||"
                    | "!"
                    | "-"
                    | "\""
                    | "`"
                    | "("
                    | ")"
            ),
            // A C# condition of a user type runs its `operator true`, and `!`
            // and `==` can be user operators. A local declared `bool`,
            // negated with the built-in `!`, is stable.
            Language::CSharp => matches!(
                kind,
                "identifier"
                    | "boolean_literal"
                    | "parenthesized_expression"
                    | "prefix_unary_expression"
                    | "!"
                    | "("
                    | ")"
            ),
            // Kotlin has no truthiness conversion, so a condition name is a
            // `Boolean`, and `!` on it is built in. `==` calls `equals`;
            // `===` and `!==` compare identity.
            Language::Kotlin => matches!(
                kind,
                "simple_identifier"
                    | "boolean_literal"
                    | "null_literal"
                    | "parenthesized_expression"
                    | "prefix_expression"
                    | "equality_expression"
                    | "!"
                    | "==="
                    | "!=="
                    | "("
                    | ")"
            ),
            // A Rust comparison or `!` dispatches to a trait that user code
            // can implement, so only a bare `bool` local is stable.
            Language::Rust => matches!(
                kind,
                "identifier" | "boolean_literal" | "parenthesized_expression" | "(" | ")"
            ),
            // Ruby truthiness runs no method, but `==`, `!` and `not` are
            // method calls and a constant read can call `const_missing`.
            Language::Ruby => matches!(
                kind,
                "identifier" | "nil" | "true" | "false" | "parenthesized_statements" | "(" | ")"
            ),
            // PHP loose `==` can call `__toString`, and a property or element
            // read can call `__get` or `offsetGet`. Variables, constants and
            // literals compared with `===`/`!==` or negated run no user code.
            Language::Php => matches!(
                kind,
                "variable_name"
                    | "name"
                    | "$"
                    | "boolean"
                    | "null"
                    | "integer"
                    | "string"
                    | "string_content"
                    | "'"
                    | "parenthesized_expression"
                    | "binary_expression"
                    | "unary_op_expression"
                    | "==="
                    | "!=="
                    | "!"
                    | "("
                    | ")"
            ),
            // Scala `==` calls `equals`, and a condition of another type runs
            // an implicit conversion. A local declared `Boolean`, negated with
            // the built-in `!`, is stable.
            Language::Scala => matches!(
                kind,
                "identifier"
                    | "boolean_literal"
                    | "parenthesized_expression"
                    | "prefix_expression"
                    | "!"
                    | "("
                    | ")"
            ),
            _ => false,
        };
        if !allowed {
            return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
        }
        if matches!(kind, "identifier" | "simple_identifier") {
            let Some(name) = source.get(node.byte_range()) else {
                return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
            };
            match binding_of(env, name, node.start_byte(), Some(Namespace::Value)) {
                BindingOfOutcome::Reached(index)
                | BindingOfOutcome::Shadowed { winner: index, .. }
                    if stable_binding(env, index)
                        && (!matches!(language, Language::Scala | Language::CSharp)
                            || declared_boolean(env, index, node, source))
                        && (language != Language::Cpp
                            || cpp_stable_declaration(env, index, node, source, c_dialect)) => {}
                BindingOfOutcome::Reached(_) | BindingOfOutcome::Shadowed { .. } => {
                    return BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference);
                }
                BindingOfOutcome::NoBinding => {
                    return BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference);
                }
                BindingOfOutcome::Incomplete(_) => {
                    return BranchRelationVerdict::Open(
                        BranchOpenReason::LexicalBindingUnavailable,
                    );
                }
            }
        }
        stack.extend(non_extra_children(node).into_iter().map(|(_, child)| child));
    }
    BranchRelationVerdict::Proven
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaPrimitiveConditionType {
    Integral,
    Boolean,
}

fn java_primitive_condition_stability(
    condition: Node<'_>,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
) -> BranchRelationVerdict {
    let mut pending = vec![condition];
    let mut visited = 0;
    while let Some(mut node) = pending.pop() {
        visited += 1;
        if visited > 4096 || node.child_count() > 4096 {
            return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
        }
        if node.has_error() || node.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
            node = node.named_child(0).expect("one parenthesized expression");
            visited += 1;
            if visited > 4096 || node.has_error() || node.is_missing() {
                return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
            }
        }
        match node.kind() {
            "true" | "false" => {}
            "identifier" => {
                if let Err(reason) = java_binding_type(node, syntax, env).and_then(|kind| {
                    (kind == JavaPrimitiveConditionType::Boolean)
                        .then_some(())
                        .ok_or(BranchOpenReason::UnsupportedCondition)
                }) {
                    return BranchRelationVerdict::Open(reason);
                }
            }
            "unary_expression" => {
                let (Some(operator), Some(operand)) = (
                    node.child_by_field_name("operator"),
                    node.child_by_field_name("operand"),
                ) else {
                    return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
                };
                if operator.kind() != "!" {
                    return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                }
                pending.push(operand);
            }
            "binary_expression" => {
                let (Some(operator), Some(left), Some(right)) = (
                    node.child_by_field_name("operator"),
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
                };
                match operator.kind() {
                    "&&" | "||" => {
                        pending.push(right);
                        pending.push(left);
                    }
                    "<" | "<=" | ">" | ">=" => {
                        for operand in [left, right] {
                            if let Err(reason) = java_integral_operand(operand, syntax, env) {
                                return BranchRelationVerdict::Open(reason);
                            }
                        }
                    }
                    "==" | "!=" => {
                        let left_kind = java_equality_operand(left, syntax, env);
                        let right_kind = java_equality_operand(right, syntax, env);
                        match (left_kind, right_kind) {
                            (Ok(a), Ok(b)) if a == b => {}
                            (Ok(_), Ok(_)) => {
                                return BranchRelationVerdict::Open(
                                    BranchOpenReason::UnsupportedCondition,
                                );
                            }
                            (Err(reason), _) | (_, Err(reason)) => {
                                return BranchRelationVerdict::Open(reason);
                            }
                        }
                    }
                    _ => {
                        return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                    }
                }
            }
            _ => return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition),
        }
    }
    BranchRelationVerdict::Proven
}

fn java_integral_operand(
    node: Node<'_>,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
) -> Result<(), BranchOpenReason> {
    let node = java_peel_parentheses(node)?;
    if java_decimal_int_value(syntax.source(), node).is_some() {
        return Ok(());
    }
    let kind = java_binding_type(node, syntax, env)?;
    (kind == JavaPrimitiveConditionType::Integral)
        .then_some(())
        .ok_or(BranchOpenReason::UnsupportedCondition)
}

fn java_equality_operand(
    node: Node<'_>,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
) -> Result<JavaPrimitiveConditionType, BranchOpenReason> {
    let node = java_peel_parentheses(node)?;
    if matches!(node.kind(), "true" | "false") {
        return Ok(JavaPrimitiveConditionType::Boolean);
    }
    if java_decimal_int_value(syntax.source(), node).is_some() {
        return Ok(JavaPrimitiveConditionType::Integral);
    }
    java_binding_type(node, syntax, env)
}

fn java_peel_parentheses(mut node: Node<'_>) -> Result<Node<'_>, BranchOpenReason> {
    for _ in 0..64 {
        if node.kind() != "parenthesized_expression" {
            return Ok(node);
        }
        if node.has_error() || node.is_missing() {
            return Err(BranchOpenReason::SyntaxRecovery);
        }
        if node.named_child_count() != 1 {
            return Err(BranchOpenReason::MissingBranchField);
        }
        node = node.named_child(0).expect("one parenthesized expression");
    }
    (node.kind() != "parenthesized_expression")
        .then_some(node)
        .ok_or(BranchOpenReason::ComparisonBudget)
}

fn java_binding_type(
    node: Node<'_>,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
) -> Result<JavaPrimitiveConditionType, BranchOpenReason> {
    let binding = java_stable_binding(node, syntax.source(), env)?;
    let range = env.bindings[binding].range;
    let Some(declaration_name) = syntax
        .tree()
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        .filter(|name| {
            name.kind() == "identifier"
                && name.start_byte() == range.start_byte
                && name.end_byte() == range.end_byte
        })
    else {
        return Err(BranchOpenReason::LexicalBindingUnavailable);
    };
    let Some(parent) = declaration_name.parent() else {
        return Err(BranchOpenReason::LexicalBindingUnavailable);
    };
    let (declaration, dimensions) = match parent.kind() {
        "formal_parameter"
            if parent.child_by_field_name("name") == Some(declaration_name)
                && env.bindings[binding].kind == BindingKind::Parameter =>
        {
            (parent, parent.child_by_field_name("dimensions"))
        }
        "variable_declarator" if parent.child_by_field_name("name") == Some(declaration_name) => {
            let Some(declaration) = parent.parent().filter(|node| {
                node.kind() == "local_variable_declaration"
                    && env.bindings[binding].kind == BindingKind::Local
            }) else {
                return Err(BranchOpenReason::UnsupportedCondition);
            };
            (declaration, parent.child_by_field_name("dimensions"))
        }
        _ => return Err(BranchOpenReason::UnsupportedCondition),
    };
    if dimensions.is_some() || declaration.has_error() {
        return Err(BranchOpenReason::UnsupportedCondition);
    }
    let Some(type_node) = declaration.child_by_field_name("type") else {
        return Err(BranchOpenReason::MissingBranchField);
    };
    if type_node.has_error() {
        return Err(BranchOpenReason::SyntaxRecovery);
    }
    // A condition unboxes a boxed Boolean, and a relational operator or a
    // comparison with a number unboxes a boxed integral value. A stable
    // local unboxes to the same value each time, and a `null` one throws in
    // the first condition, before the repeated one runs. Two boxed operands
    // of `==` compare the identities of two stable locals, which are stable
    // too. See `JavaScalarType::from_wrapper_type` for why the wrapper name
    // suffices where the value is unboxed.
    if JavaIntegralDomain::from_type(type_node).is_some()
        || matches!(
            JavaScalarType::from_wrapper_type(type_node, syntax.source()),
            Some(JavaScalarType::Integral(_))
        )
    {
        Ok(JavaPrimitiveConditionType::Integral)
    } else if type_node.kind() == "boolean_type"
        || JavaScalarType::from_wrapper_type(type_node, syntax.source())
            == Some(JavaScalarType::Boolean)
    {
        Ok(JavaPrimitiveConditionType::Boolean)
    } else {
        Err(BranchOpenReason::UnsupportedCondition)
    }
}

fn java_stable_binding(
    node: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
) -> Result<usize, BranchOpenReason> {
    if node.kind() != "identifier" || node.has_error() || node.is_missing() {
        return Err(BranchOpenReason::UnsupportedCondition);
    }
    let name = source
        .get(node.byte_range())
        .ok_or(BranchOpenReason::SyntaxRecovery)?;
    match binding_of(env, name, node.start_byte(), Some(Namespace::Value)) {
        BindingOfOutcome::Reached(index) | BindingOfOutcome::Shadowed { winner: index, .. }
            if stable_binding(env, index) =>
        {
            Ok(index)
        }
        BindingOfOutcome::Reached(_)
        | BindingOfOutcome::Shadowed { .. }
        | BindingOfOutcome::NoBinding => Err(BranchOpenReason::NonLocalReference),
        BindingOfOutcome::Incomplete(_) => Err(BranchOpenReason::LexicalBindingUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::super::lexical_environment::environment_for_file;
    use super::super::provider::StructuralSyntaxLimitedOutcome;
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::inline_project::InlineTestProject;

    fn rows(language: Language, path: &str, source: &str) -> Vec<BranchRelationRow> {
        let fixture = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let file = fixture.file(path);
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let provider = analyzer
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .expect("language has a structural provider");
        let StructuralSyntaxLimitedOutcome::Available(syntax) =
            provider.structural_syntax_limited(&file, 32 * 1024, None)
        else {
            panic!("fixture syntax unavailable");
        };
        let syntax = syntax.into_inner();
        let mut stack = vec![syntax.tree().root_node()];
        let mut found = None;
        while let Some(node) = stack.pop() {
            if node.kind() == "if_statement" && !is_chain_child(node) {
                found = Some(node);
                break;
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).expect("child index is in bounds"));
            }
        }
        let node = found.expect("fixture has an if statement");
        let env = environment_for_file(analyzer.analyzer(), &file);
        relations_for_if(
            &syntax,
            language,
            node_range(node),
            &env,
            &JavaMemberProofs::default(),
        )
    }

    fn verdicts(
        rows: &[BranchRelationRow],
        kind: BranchRelationKind,
    ) -> Vec<BranchRelationVerdict> {
        rows.iter()
            .filter(|row| row.kind == kind)
            .map(|row| row.verdict)
            .collect()
    }

    #[test]
    fn java_boolean_returns_pair_only_with_the_next_statement_in_the_same_block() {
        for (source, orientation) in [
            (
                "class Sample { boolean f(boolean x) { if (x) return true; return false; } }",
                "condition",
            ),
            (
                "class Sample { boolean f(boolean x) { if (x) { return false; } /* note */ return true; } }",
                "negated_condition",
            ),
        ] {
            let rows = rows(Language::Java, "Sample.java", source);
            let boolean_rows = rows
                .iter()
                .filter(|row| row.kind == BranchRelationKind::RedundantBooleanReturn)
                .collect::<Vec<_>>();
            assert_eq!(boolean_rows.len(), 1, "{source}: {rows:?}");
            assert_eq!(boolean_rows[0].verdict, BranchRelationVerdict::Proven);
            assert_eq!(boolean_rows[0].orientation, Some(orientation));
            assert!(boolean_rows[0].later.start_byte > boolean_rows[0].owner.end_byte);
        }

        for source in [
            "class Sample { boolean f(boolean x) { if (x) return true; return true; } }",
            "class Sample { boolean f(boolean x) { if (x) return true; int marker = 0; return false; } }",
            "class Sample { boolean f(boolean x, boolean y) { if (x) { if (y) return true; } return false; } }",
        ] {
            let rows = rows(Language::Java, "Sample.java", source);
            assert!(
                verdicts(&rows, BranchRelationKind::RedundantBooleanReturn).is_empty(),
                "{source}: {rows:?}"
            );
        }
    }

    #[test]
    fn script_boolean_returns_pair_only_with_the_next_statement_in_the_same_block() {
        for (language, path, positive, inverse, intervening, nested) in [
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x) return true; return false; }",
                "function f(x) { if (x) { return false; } /* note */ return true; }",
                "function f(x) { if (x) return true; mark(); return false; }",
                "function f(x, y) { if (x) { if (y) return true; } return false; }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(x: boolean) { if (x) return true; return false; }",
                "function f(x: boolean) { if (x) { return false; } /* note */ return true; }",
                "function f(x: boolean) { if (x) return true; mark(); return false; }",
                "function f(x: boolean, y: boolean) { if (x) { if (y) return true; } return false; }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(x):\n    if x:\n        return True\n    return False\n",
                "def f(x):\n    if x:\n        return False\n    # note\n    return True\n",
                "def f(x):\n    if x:\n        return True\n    mark()\n    return False\n",
                "def f(x, y):\n    if x:\n        if y:\n            return True\n    return False\n",
            ),
        ] {
            for (source, orientation) in [(positive, "condition"), (inverse, "negated_condition")] {
                let rows = rows(language, path, source);
                let boolean_rows = rows
                    .iter()
                    .filter(|row| row.kind == BranchRelationKind::RedundantBooleanReturn)
                    .collect::<Vec<_>>();
                assert_eq!(boolean_rows.len(), 1, "{source}: {rows:?}");
                assert_eq!(boolean_rows[0].verdict, BranchRelationVerdict::Proven);
                assert_eq!(boolean_rows[0].orientation, Some(orientation));
                assert!(boolean_rows[0].later.start_byte > boolean_rows[0].owner.end_byte);
            }
            for source in [intervening, nested] {
                let rows = rows(language, path, source);
                assert!(
                    verdicts(&rows, BranchRelationKind::RedundantBooleanReturn).is_empty(),
                    "{source}: {rows:?}"
                );
            }
        }
    }

    #[test]
    fn java_branch_relations_prove_local_identity_and_stable_repetition() {
        let branch_rows = rows(
            Language::Java,
            "Sample.java",
            "class Sample { static int f(int x) { if (x == 1) return x; else if (x == 1) return x; else return 0; } }",
        );
        assert_eq!(
            verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Proven],
            "{branch_rows:#?}"
        );
        assert_eq!(
            verdicts(&branch_rows, BranchRelationKind::IdenticalBodies),
            vec![
                BranchRelationVerdict::Proven,
                BranchRelationVerdict::Distinct,
                BranchRelationVerdict::Distinct
            ],
            "{branch_rows:#?}"
        );
    }

    #[test]
    fn java_primitive_and_boxed_relational_and_boolean_composition_are_stable() {
        for source in [
            "class Sample { int f(int x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { int f(int x, int y) { if (x > y) return 1; else if (x > y) return 2; return 0; } }",
            "class Sample { int f(int x, boolean ready) { if (ready && x > 5) return 1; else if (ready && x > 5) return 2; return 0; } }",
            "class Sample { int f(int x, int y) { if (x > 5 || y < -1) return 1; else if (x > 5 || y < -1) return 2; return 0; } }",
            "class Sample { int f() { int x = 6; if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { int f(Integer x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { int f(Boolean ready, int x) { if (ready && x > 5) return 1; else if (ready && x > 5) return 2; return 0; } }",
        ] {
            let branch_rows = rows(Language::Java, "Sample.java", source);
            assert_eq!(
                verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
                vec![BranchRelationVerdict::Proven],
                "{source}: {branch_rows:#?}"
            );
        }
    }

    #[test]
    fn java_relational_repetition_keeps_unqualified_values_and_effects_open() {
        for source in [
            "class Sample { Double d; int f(Double x) { if (x > 5) return 1; else if (x > 5) return 2; return 0; } }",
            "class Sample { volatile int value; int f() { if (this.value > 5) return 1; else if (this.value > 5) return 2; return 0; } }",
            "class Sample { int f(int x) { if (x > 5) return 1; else if (x + 1 > 5) return 2; else if (x > 5) return 3; return 0; } }",
            "class Sample { boolean next() { return true; } int f(int x) { if (x > 5) return 1; else if (next()) return 2; else if (x > 5) return 3; return 0; } }",
            "class Sample { int f(int x) { if (x > 5) return 1; else if (++x > 0) return 2; else if (x > 5) return 3; return 0; } }",
        ] {
            let branch_rows = rows(Language::Java, "Sample.java", source);
            assert!(
                verdicts(&branch_rows, BranchRelationKind::RepeatedCondition).contains(
                    &BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition)
                ) || verdicts(&branch_rows, BranchRelationKind::RepeatedCondition).contains(
                    &BranchRelationVerdict::Open(BranchOpenReason::MemberResolutionUnavailable)
                ) || verdicts(&branch_rows, BranchRelationKind::RepeatedCondition).contains(
                    &BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference)
                ),
                "{source}: {branch_rows:#?}"
            );
            assert!(
                !verdicts(&branch_rows, BranchRelationKind::RepeatedCondition)
                    .contains(&BranchRelationVerdict::Proven),
                "{source}: {branch_rows:#?}"
            );
        }
    }

    #[test]
    fn typescript_branch_relations_ignore_comments_but_abstain_on_calls() {
        let branch_rows = rows(
            Language::TypeScript,
            "sample.ts",
            "function f(x: number) { if (x === 1) { /* one */ return x; } else if (x === 1) { /* two */ return x; } else { return 0; } }",
        );
        assert_eq!(
            verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Proven],
            "{branch_rows:#?}"
        );
        assert!(
            verdicts(&branch_rows, BranchRelationKind::IdenticalBodies)
                .contains(&BranchRelationVerdict::Proven),
            "{branch_rows:#?}"
        );

        let calls = rows(
            Language::TypeScript,
            "sample.ts",
            "function f(next: () => boolean) { if (next()) { return 1; } else if (next()) { return 2; } }",
        );
        assert!(
            matches!(
                verdicts(&calls, BranchRelationKind::RepeatedCondition).as_slice(),
                [BranchRelationVerdict::Open(_)]
            ),
            "{calls:#?}"
        );
    }

    #[test]
    fn python_identity_is_stable_but_truthiness_is_open() {
        let identity = rows(
            Language::Python,
            "sample.py",
            "def f(x):\n    if x is None:\n        return 1\n    elif x is None:\n        return 2\n",
        );
        assert_eq!(
            verdicts(&identity, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Proven],
            "{identity:#?}"
        );

        let truthiness = rows(
            Language::Python,
            "sample.py",
            "class Stateful:\n    def __bool__(self):\n        return True\n\ndef f(x):\n    if x:\n        return 1\n    elif x:\n        return 2\n",
        );
        assert_eq!(
            verdicts(&truthiness, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Open(
                BranchOpenReason::EffectfulCondition
            )],
            "{truthiness:#?}"
        );
    }

    #[test]
    fn javascript_and_jsx_share_exact_branch_evidence() {
        for (path, prefix) in [
            ("sample.js", ""),
            ("sample.jsx", "const element = <section />; "),
        ] {
            let source = format!(
                "{prefix}function f(x) {{ if (x === 'ready') return x; else if (x === 'ready') return x; else return 0; }}"
            );
            let branch_rows = rows(Language::JavaScript, path, &source);
            assert_eq!(
                verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
                vec![BranchRelationVerdict::Proven],
                "{path}: {branch_rows:#?}"
            );
            assert!(
                verdicts(&branch_rows, BranchRelationKind::IdenticalBodies)
                    .contains(&BranchRelationVerdict::Proven),
                "{path}: {branch_rows:#?}"
            );
        }
    }

    #[test]
    fn javascript_dynamic_with_lookup_and_file_binding_are_open() {
        let with_lookup = rows(
            Language::JavaScript,
            "sample.js",
            "function f(x, object) { with (object) { if (x === null) return x; else if (x === null) return x; } }",
        );
        assert!(
            verdicts(&with_lookup, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{with_lookup:#?}"
        );
        assert!(
            verdicts(&with_lookup, BranchRelationKind::IdenticalBodies)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{with_lookup:#?}"
        );

        let file_binding = rows(
            Language::JavaScript,
            "sample.js",
            "let current = null; function f() { if (current === null) return 1; else if (current === null) return 2; }",
        );
        assert!(
            verdicts(&file_binding, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{file_binding:#?}"
        );
    }

    #[test]
    fn repeated_java_volatile_field_remains_open() {
        let branch_rows = rows(
            Language::Java,
            "Sample.java",
            "class Sample { volatile boolean ready; int f() { if (ready == true) return 1; else if (ready == true) return 2; return 0; } }",
        );
        assert!(
            verdicts(&branch_rows, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| matches!(verdict, BranchRelationVerdict::Open(_))),
            "{branch_rows:#?}"
        );
    }

    #[test]
    fn identical_direct_calls_require_the_same_local_callee() {
        for (language, path, source) in [
            (
                Language::JavaScript,
                "sample.js",
                "function f(flag, callback) { if (flag) return callback(); else return callback(); }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(flag: boolean, callback: () => number) { if (flag) return callback(); else return callback(); }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(flag, callback):\n    if flag:\n        return callback()\n    else:\n        return callback()\n",
            ),
        ] {
            let branch_rows = rows(language, path, source);
            assert_eq!(
                verdicts(&branch_rows, BranchRelationKind::IdenticalBodies),
                vec![BranchRelationVerdict::Proven],
                "{path}: {branch_rows:#?}"
            );
        }
    }

    #[test]
    fn identical_local_updates_and_paired_branch_local_binders_are_proven() {
        let same_local = rows(
            Language::Java,
            "Sample.java",
            "class Sample { int f(boolean condition, int x) { if (condition) { x++; } else { x++; } return x; } }",
        );
        assert_eq!(
            verdicts(&same_local, BranchRelationKind::IdenticalBodies),
            vec![BranchRelationVerdict::Proven],
            "{same_local:#?}"
        );

        let paired_locals = rows(
            Language::Java,
            "Sample.java",
            "class Sample { int f(boolean condition) { if (condition) { int x = 0; x++; } else { int x = 0; x++; } return 0; } }",
        );
        assert_eq!(
            verdicts(&paired_locals, BranchRelationKind::IdenticalBodies),
            vec![BranchRelationVerdict::Proven],
            "{paired_locals:#?}"
        );
    }

    #[test]
    fn java_method_name_compares_as_a_name_not_through_a_same_named_local() {
        let calls = rows(
            Language::Java,
            "Sample.java",
            "class Sample { int log() { return 1; } int f(boolean condition) { int log = 0; if (condition) return log(); else return log(); } }",
        );
        assert_eq!(
            verdicts(&calls, BranchRelationKind::IdenticalBodies),
            vec![BranchRelationVerdict::Proven],
            "{calls:#?}"
        );
        let call_and_read = rows(
            Language::Java,
            "Sample.java",
            "class Sample { int log() { return 1; } int f(boolean condition) { int log = 0; if (condition) return log(); else return log; } }",
        );
        assert_eq!(
            verdicts(&call_and_read, BranchRelationKind::IdenticalBodies),
            vec![BranchRelationVerdict::Distinct],
            "{call_and_read:#?}"
        );
    }

    #[test]
    fn nonadjacent_repetition_requires_every_intervening_test_to_be_stable() {
        let stable = rows(
            Language::JavaScript,
            "sample.js",
            "function f(x) { if (x === 1) return 1; else if (x === 2) return 2; else if (x === 1) return 3; return 0; }",
        );
        assert_eq!(
            verdicts(&stable, BranchRelationKind::RepeatedCondition),
            vec![
                BranchRelationVerdict::Distinct,
                BranchRelationVerdict::Proven,
                BranchRelationVerdict::Distinct
            ],
            "{stable:#?}"
        );

        let effectful = rows(
            Language::JavaScript,
            "sample.js",
            "function f(x, next) { if (x === 1) return 1; else if (next()) return 2; else if (x === 1) return 3; return 0; }",
        );
        assert!(
            verdicts(&effectful, BranchRelationKind::RepeatedCondition)
                .iter()
                .all(|verdict| *verdict != BranchRelationVerdict::Proven),
            "{effectful:#?}"
        );
    }

    fn identical_bodies(
        language: Language,
        path: &str,
        source: &str,
    ) -> Vec<BranchRelationVerdict> {
        verdicts(
            &rows(language, path, source),
            BranchRelationKind::IdenticalBodies,
        )
    }

    /// Each arm creates its own closure, object method or class, whatever the
    /// grammar calls it and whatever parameters it binds.
    #[test]
    fn nested_callables_and_local_classes_in_matching_arms_stay_deferred() {
        let deferred = vec![BranchRelationVerdict::Open(BranchOpenReason::DeferredBody)];
        for (language, path, source) in [
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return function () { return x; }; } else { return function () { return x; }; } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return function* () { yield x; }; } else { return function* () { yield x; }; } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return { m() { return x; } }; } else { return { m() { return x; } }; } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return class { m() { return x; } }; } else { return class { m() { return x; } }; } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return (a) => a + x; } else { return (a) => a + x; } }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(x: number) { if (x === 1) { return function (a: number) { return a + x; }; } else { return function (a: number) { return a + x; }; } }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(x: number) { if (x === 1) { return class { m() { return x; } }; } else { return class { m() { return x; } }; } }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(x: number) { if (x === 1) { return (a: number) => a + x; } else { return (a: number) => a + x; } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(x):\n    if x is None:\n        class A:\n            pass\n        return A\n    else:\n        class A:\n            pass\n        return A\n",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(x, d):\n    if x is None:\n        @d\n        def g():\n            return x\n        return g\n    else:\n        @d\n        def g():\n            return x\n        return g\n",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(x):\n    if x is None:\n        return lambda a: a + x\n    else:\n        return lambda a: a + x\n",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { java.util.function.IntUnaryOperator f(int x) { if (x == 1) return a -> a + x; else return a -> a + x; } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { java.util.function.IntBinaryOperator f(int x) { if (x == 1) return (int a, int b) -> a + b + x; else return (int a, int b) -> a + b + x; } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { Object f(int x) { if (x == 1) { record R(int a) {} return new R(x); } else { record R(int a) {} return new R(x); } } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { Object f(int x) { if (x == 1) { enum E { A } return E.A; } else { enum E { A } return E.A; } } }",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                deferred,
                "{source}"
            );
        }
    }

    /// Deferring a nested callable does not hide a difference elsewhere in the
    /// arms, and a callable never equals a non-callable.
    #[test]
    fn deferred_callables_keep_distinct_arms_complete() {
        for (language, path, source) in [
            (
                Language::JavaScript,
                "sample.js",
                "function f(x, run) { if (x === 1) { run((a) => a); return 1; } else { run((a) => a); return 2; } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(x) { if (x === 1) { return () => x; } else { return x; } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(x, run):\n    if x is None:\n        run(lambda a: a)\n        return 1\n    else:\n        run(lambda a: a)\n        return 2\n",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { int f(int x, java.util.function.Consumer<java.util.function.IntUnaryOperator> run) { if (x == 1) { run.accept(a -> a); return 1; } else { run.accept(a -> a); return 2; } } }",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                vec![BranchRelationVerdict::Distinct],
                "{source}"
            );
        }
    }

    /// A pattern variable declared by a chain condition is a different binding
    /// in each arm, although the environment does not model it and both reads
    /// share one spelling.
    #[test]
    fn java_pattern_binders_keep_identical_reads_open() {
        for source in [
            "class Sample { Object f(Object o, Object p) { if (o instanceof String s) return s; else if (p instanceof String s) return s; return null; } }",
            "class Sample { record Point(int x, int y) {} int f(Object o, Object p) { if (o instanceof Point(int x, int y)) return x; else if (p instanceof Point(int x, int y)) return x; return 0; } }",
            "class Sample { int s; int f(Object o, boolean flag) { if (flag) return s; else if (o instanceof Integer s) return s; return 0; } }",
        ] {
            let bodies = identical_bodies(Language::Java, "Sample.java", source);
            assert!(
                bodies.contains(&BranchRelationVerdict::Open(
                    BranchOpenReason::LexicalBindingUnavailable
                )) && !bodies.contains(&BranchRelationVerdict::Proven),
                "{source}: {bodies:?}"
            );
        }

        // Pattern and loop variables declared at matching positions inside
        // each arm stand for each other.
        for source in [
            "class Sample { Object f(Object o, boolean flag) { if (flag) { if (o instanceof String s) return s; return null; } else { if (o instanceof String s) return s; return null; } } }",
            "class Sample { int f(int[] values, boolean flag) { int sum = 0; if (flag) { for (int v : values) sum += v; } else { for (int v : values) sum += v; } return sum; } }",
        ] {
            assert_eq!(
                identical_bodies(Language::Java, "Sample.java", source),
                vec![BranchRelationVerdict::Proven],
                "{source}"
            );
        }
    }

    /// Catch, resource, loop and comprehension binders declared inside each
    /// arm pair binder by binder, as block locals do.
    #[test]
    fn arm_local_catch_resource_loop_and_comprehension_binders_pair() {
        for (language, path, source) in [
            (
                Language::Java,
                "Sample.java",
                "class Sample { int g() { return 1; } int f(boolean flag) { if (flag) { try { return g(); } catch (RuntimeException e) { return e.hashCode(); } } else { try { return g(); } catch (RuntimeException other) { return other.hashCode(); } } } }",
            ),
            (
                Language::Java,
                "Sample.java",
                "class Sample { int f(boolean flag) throws Exception { if (flag) { try (java.io.StringReader r = new java.io.StringReader(\"\")) { return r.read(); } } else { try (java.io.StringReader q = new java.io.StringReader(\"\")) { return q.read(); } } } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(flag, g) { if (flag) { try { return g(); } catch (e) { return e; } } else { try { return g(); } catch (other) { return other; } } }",
            ),
            (
                Language::TypeScript,
                "sample.ts",
                "function f(flag: boolean, xs: number[], use: (v: number) => void) { if (flag) { for (const v of xs) use(v); } else { for (const w of xs) use(w); } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(flag, xs):\n    if flag:\n        return [y + 1 for y in xs]\n    else:\n        return [z + 1 for z in xs]\n",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                vec![BranchRelationVerdict::Proven],
                "{source}"
            );
        }

        for (language, path, source) in [
            (
                Language::Java,
                "Sample.java",
                "class Sample { int g() { return 1; } int f(boolean flag) { if (flag) { try { return g(); } catch (RuntimeException e) { return e.hashCode(); } } else { try { return g(); } catch (IllegalStateException e) { return e.hashCode(); } } } }",
            ),
            (
                Language::JavaScript,
                "sample.js",
                "function f(flag, g, other) { if (flag) { try { return g(); } catch (e) { return e; } } else { try { return g(); } catch (e) { return other; } } }",
            ),
            (
                Language::Python,
                "sample.py",
                "def f(flag, xs, z):\n    if flag:\n        return [y + 1 for y in xs]\n    else:\n        return [z + 1 for y in xs]\n",
            ),
        ] {
            assert_eq!(
                identical_bodies(language, path, source),
                vec![BranchRelationVerdict::Distinct],
                "{source}"
            );
        }
    }

    #[test]
    fn tsx_uses_the_typescript_branch_proof() {
        let branch_rows = rows(
            Language::TypeScript,
            "sample.tsx",
            "const element = <section />; function f(x: string) { if (x === 'ready') return x; else if (x === 'ready') return x; else return 0; }",
        );
        assert_eq!(
            verdicts(&branch_rows, BranchRelationKind::RepeatedCondition),
            vec![BranchRelationVerdict::Proven],
            "{branch_rows:#?}"
        );
        assert!(
            verdicts(&branch_rows, BranchRelationKind::IdenticalBodies)
                .contains(&BranchRelationVerdict::Proven),
            "{branch_rows:#?}"
        );
    }
}
