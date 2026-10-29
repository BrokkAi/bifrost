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
//! binders, and a nested callable or local class body stays open when its
//! capture or class identity is not modeled; Scala lambdas and local defs are
//! compared when their lexical rows are exact. One unbound spelling is one
//! lookup only when no chain condition declares it with a binder the lexical
//! environment does not model, such as a Java pattern variable. Repeated
//! conditions additionally prove stability in `condition_stability`, which
//! admits no member access.

use super::facts::FileFacts;
use super::kinds::NormalizedKind;
use super::lexical_environment::{BindingOfOutcome, EnvironmentFileResult, binding_of};
use super::occurrences::{Namespace, OccurrenceRole};
use super::resolution::BindingKind;
use crate::analyzer::CodeUnit;
use crate::analyzer::branch_boolean::{
    BooleanBranchOutcome, KotlinBooleanBranchClassification, ScalaBooleanBranchClassification,
    classify_boolean_branches, classify_kotlin_boolean_branches, classify_scala_boolean_branches,
    kotlin_when_is_a6_shape, scala_defines_named_type_bounded,
};
use crate::analyzer::read_ledger::{DerivationExecutionCause, reason as derivation_reason};

use crate::analyzer::java_integral_parameter::{
    JavaIntegralDomain, JavaScalarType, java_decimal_int_value,
};

use crate::analyzer::languages::{LanguageSupport, language_support_for_hook};
use crate::analyzer::{Language, ProjectFile, Range};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::structural::body_relations::{
    BodyState, BodyStateAnswer, empty_if_arm_relation,
};
use brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionalRegions;
use brokk_bifrost_core::analyzer::tree_walk::{has_child_of_kind as has_direct_token, node_range};
use brokk_bifrost_core::analyzer::work_budget::{BudgetLedger, define_work_dimensions};
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchRelationKind {
    IdenticalBodies,
    RepeatedCondition,
    RedundantBooleanReturn,
    EmptyArm,
}

impl BranchRelationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::IdenticalBodies => "identical_bodies",
            Self::RepeatedCondition => "repeated_condition",
            Self::RedundantBooleanReturn => "redundant_boolean_return",
            Self::EmptyArm => "empty_arm",
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
    UnprovenActivation,
}

impl BranchOpenReason {
    pub const fn execution_cause(self) -> Option<DerivationExecutionCause> {
        match self {
            Self::ComparisonBudget => Some(DerivationExecutionCause::Budget),
            Self::SyntaxRecovery
            | Self::MissingBranchField
            | Self::LexicalBindingUnavailable
            | Self::NonLocalReference
            | Self::EffectfulBody
            | Self::EffectfulCondition
            | Self::UnsupportedCondition
            | Self::MemberResolutionUnavailable
            | Self::AmbiguousMember
            | Self::DeferredBody
            | Self::UnprovenActivation => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::SyntaxRecovery => derivation_reason::SYNTAX_RECOVERY,
            Self::MissingBranchField => derivation_reason::MISSING_BRANCH_FIELD,
            Self::LexicalBindingUnavailable => derivation_reason::LEXICAL_BINDING_UNAVAILABLE,
            Self::NonLocalReference => derivation_reason::NON_LOCAL_REFERENCE,
            Self::EffectfulBody => derivation_reason::EFFECTFUL_BODY,
            Self::EffectfulCondition => derivation_reason::EFFECTFUL_CONDITION,
            Self::UnsupportedCondition => derivation_reason::UNSUPPORTED_CONDITION,
            Self::ComparisonBudget => derivation_reason::COMPARISON_BUDGET,
            Self::MemberResolutionUnavailable => derivation_reason::MEMBER_RESOLUTION_UNAVAILABLE,
            Self::AmbiguousMember => derivation_reason::AMBIGUOUS_MEMBER,
            Self::DeferredBody => derivation_reason::DEFERRED_BODY,
            Self::UnprovenActivation => derivation_reason::UNPROVEN_ACTIVATION,
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
    initializer: Option<Node<'tree>>,
    body: Node<'tree>,
}

/// Exact reference targets supplied by the existing definition resolver.
/// Existing Java member rules retain equality; new nonlocal proofs only
/// distinguish unequal targets and grant no condition stability.
/// A missing entry is never a negative lookup: it leaves this comparison open.
#[derive(Default)]
pub struct BranchReferenceProofs {
    pub sites: HashMap<(usize, usize), Result<CodeUnit, BranchOpenReason>>,
    pub collection_gap: Option<BranchOpenReason>,
    /// Physical storage declarations, admitted separately from presentation identity.
    pub storage_fields: HashMap<(usize, usize), BranchStorageField>,
}

impl BranchReferenceProofs {
    fn target_at(&self, node: Node<'_>) -> Result<&CodeUnit, BranchOpenReason> {
        self.sites
            .get(&(node.start_byte(), node.end_byte()))
            .map(|result| result.as_ref().map_err(|reason| *reason))
            .unwrap_or(Err(self
                .collection_gap
                .unwrap_or(BranchOpenReason::MemberResolutionUnavailable)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BranchReferenceKind {
    Field,
    Method,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BranchReferenceSite {
    pub range: (usize, usize),
    pub kind: BranchReferenceKind,
}

/// Grammar facts for field reads on the current object, including its base view.
/// These do not describe method dispatch or property evaluation.
pub struct BranchCurrentObjectFields {
    pub access_kind: &'static str,
    pub receiver_field: &'static str,
    pub member_field: &'static str,
    pub current_kind: &'static str,
    pub parent_kind: &'static str,
    pub invocation_kind: &'static str,
    pub invocation_target_field: &'static str,
    /// Immediate ancestors of a storage field's declaration name, innermost first.
    pub storage_ancestors: &'static [&'static str],
}

impl BranchCurrentObjectFields {
    pub fn member<'tree>(&self, node: Node<'tree>) -> Option<Node<'tree>> {
        if node.kind() != self.access_kind
            || node.parent().is_some_and(|parent| {
                parent.kind() == self.invocation_kind
                    && parent.child_by_field_name(self.invocation_target_field) == Some(node)
            })
        {
            return None;
        }
        let receiver = node.child_by_field_name(self.receiver_field)?;
        if receiver.kind() != self.current_kind && receiver.kind() != self.parent_kind {
            return None;
        }
        node.child_by_field_name(self.member_field)
    }

    pub fn is_storage_declaration(&self, name: Node<'_>) -> bool {
        let mut ancestor = name;
        for kind in self.storage_ancestors {
            let Some(parent) = ancestor.parent() else {
                return false;
            };
            if parent.kind() != *kind {
                return false;
            }
            ancestor = parent;
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchStorageField {
    pub file: ProjectFile,
    /// Exact declaration-name span distinguishes fields in one declaration list.
    pub range: Range,
}

/// Collect bounded reference sites from one exact snapshot. Language hooks
/// select grammar fields; shared code owns traversal and lexical admission.
pub fn reference_sites(
    syntax: &PreparedSyntaxTree,
    language: Language,
    facts: &FileFacts,
    env: &EnvironmentFileResult,
) -> Result<Vec<BranchReferenceSite>, BranchOpenReason> {
    const MAX_TREE_NODES: usize = 131_072;
    const MAX_REFERENCE_SITES: usize = 256;
    let Some(support) = language_support_for_hook(language, "branch_reference_site") else {
        return Ok(Vec::new());
    };
    debug_assert_eq!(facts.source(), syntax.source());
    if facts.nodes().len() > MAX_TREE_NODES {
        return Err(BranchOpenReason::ComparisonBudget);
    }
    let value_roles_supported = support
        .knowledge()
        .structural_spec()
        .occurrence_role_support()
        .is_supported(OccurrenceRole::ValueReference);
    let mut value_references = Vec::new();
    let mut non_values = Vec::new();
    for (index, node) in facts.nodes().iter().enumerate() {
        let index = u32::try_from(index).expect("bounded facts count fits u32");
        let roles = facts.occurrence_roles(index);
        if roles.contains(&OccurrenceRole::ValueReference)
            || roles.contains(&OccurrenceRole::ReceiverPosition)
        {
            value_references.push((node.range.start_byte, node.range.end_byte));
        } else if !roles.is_empty() {
            non_values.push((node.range.start_byte, node.range.end_byte));
        }
    }
    non_values.sort_unstable();
    non_values.dedup();
    value_references.sort_unstable();
    value_references.dedup();

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Region {
        Outside,
        Body,
        Condition,
    }
    let mut stack = vec![(syntax.tree().root_node(), Region::Outside)];
    let mut sites = Vec::new();
    let mut visited = 0;
    let mut role_budget = BranchWorkBudget::new();
    while let Some((node, region)) = stack.pop() {
        visited += 1;
        if visited > MAX_TREE_NODES || node.child_count() > MAX_TREE_NODES {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        if region != Region::Outside && is_nested_callable(node, language) {
            continue;
        }
        let site = match region {
            Region::Body => support.branch_body_reference_site(node, syntax.source()),
            Region::Condition => support.branch_condition_reference_site(node, syntax.source()),
            Region::Outside => None,
        }
        .or_else(|| {
            if region == Region::Outside {
                return None;
            }
            let member = support.branch_current_object_fields()?.member(node)?;
            Some(BranchReferenceSite {
                range: (member.start_byte(), member.end_byte()),
                kind: BranchReferenceKind::Field,
            })
        });
        if let Some(site) = site {
            // Bare reads require occurrence evidence and a complete lexical
            // negative. Selectors use the resolver's own grammar focus.
            let bare = site.range == (node.start_byte(), node.end_byte());
            let is_value = if value_roles_supported {
                value_references.binary_search(&site.range).is_ok()
            } else if bare && non_values.binary_search(&site.range).is_err() {
                // Some adapters publish only binder/member roles. Reuse the
                // comparator's structured AST role interpretation; do not
                // change persisted occurrence production to select these reads.
                identifier_role(node, &mut role_budget)? == IdentifierRole::Value
            } else {
                false
            };
            let unbound = matches!(
                binding_of(
                    env,
                    &syntax.source()[site.range.0..site.range.1],
                    site.range.0,
                    Some(Namespace::Value)
                ),
                BindingOfOutcome::NoBinding
            );
            if (!bare || is_value) && (!is_value || unbound) {
                sites.push(site);
                if sites.len() > MAX_REFERENCE_SITES {
                    return Err(BranchOpenReason::ComparisonBudget);
                }
            }
        }
        if stack
            .len()
            .checked_add(node.child_count())
            .is_none_or(|pending| pending > MAX_TREE_NODES)
        {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        stack.extend(non_extra_children(node).into_iter().map(|(field, child)| {
            let region = if matches!(node.kind(), "if_statement" | "if_expression") {
                match field {
                    Some("condition") => Region::Condition,
                    Some("consequence" | "alternative") => Region::Body,
                    _ => region,
                }
            } else {
                region
            };
            (child, region)
        }));
    }
    sites.sort_unstable();
    sites.dedup();
    Ok(sites)
}

const MAX_COMPARISON_TREE_NODES: usize = 4096;
const MAX_CHAIN_COMPARISONS: usize = 4096;

define_work_dimensions! {
    #[derive(Debug, Clone, Copy)]
    enum BranchWorkDimension;
    #[derive(Debug, Default, Clone, Copy)]
    struct BranchWork;
    all: [3];
    Steps => steps = 120 * 2 * MAX_COMPARISON_TREE_NODES,
    Comparisons => comparisons = MAX_CHAIN_COMPARISONS,
    Arms => arms = MAX_CHAIN_COMPARISONS + 1,
}

/// One chain's temporary work, never retained by the workspace. The step
/// envelope replaces the old sixteen-arm cutoff; cheap long chains can finish
/// without allowing either quadratic output or repeated stability walks to
/// grow without a bound. Local tree stops do not exhaust the whole chain.
struct BranchWorkBudget {
    ledger: BudgetLedger<BranchWork>,
    exhausted: bool,
}

impl BranchWorkBudget {
    fn new() -> Self {
        Self {
            ledger: BudgetLedger::with_zero_usage(BranchWork::default_limits()),
            exhausted: false,
        }
    }

    fn charge(&mut self, work: BranchWork) -> Result<(), BranchOpenReason> {
        if self.exhausted || self.ledger.charge(work).is_err() {
            self.exhausted = true;
            return Err(BranchOpenReason::ComparisonBudget);
        }
        Ok(())
    }

    fn step(&mut self) -> Result<(), BranchOpenReason> {
        self.charge(BranchWork {
            steps: 1,
            ..BranchWork::default()
        })
    }

    fn arm(&mut self) -> Result<(), BranchOpenReason> {
        self.charge(BranchWork {
            steps: 1,
            arms: 1,
            ..BranchWork::default()
        })
    }

    fn visit(
        &mut self,
        node: Node<'_>,
        visited: &mut usize,
        pending: usize,
    ) -> Result<(), BranchOpenReason> {
        self.step()?;
        *visited += 1;
        // Check before admitting children, so a wide tree cannot fill the
        // pending frontier before the visited-node limit takes effect.
        if *visited > MAX_COMPARISON_TREE_NODES
            || node.child_count() > MAX_COMPARISON_TREE_NODES
            || pending + node.child_count() > MAX_COMPARISON_TREE_NODES
        {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        Ok(())
    }
}

fn open_pair_rows(
    owner: Range,
    reason: BranchOpenReason,
) -> impl Iterator<Item = BranchRelationRow> {
    open_rows(owner, reason).into_iter().filter(|row| {
        matches!(
            row.kind,
            BranchRelationKind::IdenticalBodies | BranchRelationKind::RepeatedCondition
        )
    })
}

/// Compare the arms of one `if` node. The range must identify the structural
/// `if` fact exactly; nested `if` nodes are separate seeds and are not folded
/// into this result except when they are the syntax of an `else if` chain.
pub fn relations_for_if(
    syntax: &PreparedSyntaxTree,
    language: Language,
    range: Range,
    env: &EnvironmentFileResult,
    members: &BranchReferenceProofs,
    regions: &ConditionalRegions,
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
    if language == Language::Php && php_unsupported_lexical_ancestor(node) {
        return open_rows(range, BranchOpenReason::NonLocalReference);
    }
    // Other conditionals share the `If` fact (a C# ternary, a Kotlin
    // `when`). Statement-arm relations do not admit ternary expressions.
    // Only a Kotlin `when` shaped like an A6 Boolean result gets a
    // scoped open row; ordinary `when` expressions are outside this policy.
    if !if_kinds.contains(&node.kind()) {
        if language == Language::Kotlin
            && node.kind() == "when_expression"
            && kotlin_when_is_a6_shape(syntax.source(), node)
        {
            return vec![BranchRelationRow {
                kind: BranchRelationKind::RedundantBooleanReturn,
                verdict: BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition),
                owner: node_range(node),
                earlier: node_range(node),
                later: node_range(node),
                earlier_ordinal: 0,
                later_ordinal: 0,
                orientation: None,
            }];
        }
        return Vec::new();
    }
    let mut rows = Vec::new();
    rows.extend(redundant_boolean_row(syntax, language, node, env));
    if let Some(empty_arm) = empty_if_arm_relation(node, language, regions) {
        let consequence = node_range(empty_arm.consequence);
        let alternative = empty_arm.alternative.map(node_range).unwrap_or(consequence);
        let has_alternative = empty_arm.alternative.is_some();
        rows.push(BranchRelationRow {
            kind: BranchRelationKind::EmptyArm,
            verdict: match empty_arm.state {
                BodyStateAnswer::Decided(state) => {
                    assert_eq!(state, BodyState::Empty);
                    BranchRelationVerdict::Proven
                }
                BodyStateAnswer::Undecided => {
                    BranchRelationVerdict::Open(BranchOpenReason::UnprovenActivation)
                }
            },
            owner: node_range(empty_arm.owner),
            earlier: consequence,
            later: alternative,
            earlier_ordinal: 0,
            later_ordinal: usize::from(has_alternative),
            orientation: None,
        });
    }
    let independent = rows;
    let mut rows = Vec::new();
    let mut budget = BranchWorkBudget::new();
    let arms = match collect_arms(node, language, &mut budget) {
        Ok(arms) => arms,
        Err(reason) => {
            rows.extend(open_pair_rows(range, reason));
            rows.extend(independent);
            return rows;
        }
    };
    // A later condition may introduce a binder visible in an earlier-looking
    // arm. Complete all prerequisites before proving any pair in the chain.
    let condition_binders = match pattern_binders(
        arms.iter().filter_map(|arm| arm.condition),
        syntax.source(),
        language,
        &mut budget,
    ) {
        Ok(names) => names,
        Err(reason) => {
            rows.extend(open_pair_rows(range, reason));
            rows.extend(independent);
            return rows;
        }
    };
    let chain = Chain {
        language,
        owner: node_range(node),
        source: syntax.source(),
        env,
        members,
        condition_binders: &condition_binders,
    };
    let mut stability = vec![None; arms.len()];
    let condition_count = arms.iter().filter(|arm| arm.condition.is_some()).count();
    for later_ordinal in 1..arms.len() {
        let later = arms[later_ordinal];
        for earlier_ordinal in 0..later_ordinal {
            let earlier = arms[earlier_ordinal];
            let body_verdict = compare_trees(earlier.body, later.body, &chain, &mut budget);
            if budget.exhausted {
                rows.extend(
                    open_pair_rows(range, BranchOpenReason::ComparisonBudget).filter(|row| {
                        row.kind == BranchRelationKind::IdenticalBodies
                            || later_ordinal < condition_count
                    }),
                );
                rows.extend(independent);
                return rows;
            }
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
            // An initializer on a later arm executes between the tests. It
            // affects their stability, never the independent body comparison.
            let verdict = if arms[earlier_ordinal + 1..=later_ordinal]
                .iter()
                .any(|arm| arm.initializer.is_some())
            {
                BranchRelationVerdict::Open(BranchOpenReason::EffectfulCondition)
            } else {
                compare_trees(earlier_condition, later_condition, &chain, &mut budget)
            };
            let verdict = if verdict == BranchRelationVerdict::Proven {
                let mut verdict = BranchRelationVerdict::Proven;
                for index in earlier_ordinal..=later_ordinal {
                    if let Err(reason) = budget.step() {
                        verdict = BranchRelationVerdict::Open(reason);
                        break;
                    }
                    let Some(condition) = arms[index].condition else {
                        continue;
                    };
                    let stable = *stability[index].get_or_insert_with(|| {
                        condition_stability(condition, language, syntax, env, &mut budget)
                    });
                    if stable != BranchRelationVerdict::Proven {
                        verdict = stable;
                        break;
                    }
                }
                verdict
            } else {
                verdict
            };
            if budget.exhausted {
                let bodies_pending =
                    earlier_ordinal + 1 < later_ordinal || later_ordinal + 1 < arms.len();
                rows.extend(
                    open_pair_rows(range, BranchOpenReason::ComparisonBudget).filter(|row| {
                        row.kind == BranchRelationKind::RepeatedCondition || bodies_pending
                    }),
                );
                rows.extend(independent);
                return rows;
            }
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
    rows.extend(independent);
    rows
}

/// The redundant Boolean return pair of one `if`: its two arms, or its true
/// arm and the return that follows it in the same block.
fn redundant_boolean_row(
    syntax: &PreparedSyntaxTree,
    language: Language,
    node: Node<'_>,
    env: &EnvironmentFileResult,
) -> Option<BranchRelationRow> {
    if language == Language::Rust {
        let condition = node.child_by_field_name("condition")?;
        match rust_boolean_expression_bounded(
            condition,
            env,
            syntax.source(),
            &mut BranchWorkBudget::new(),
        ) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(reason) => return Some(open_redundant_boolean_row(node, node, node, reason)),
        }
    }
    let true_body = node.child_by_field_name(consequence_field(language))?;
    if language == Language::Scala
        && node.child_by_field_name("alternative").is_none()
        && (scala_has_else_keyword(node) || syntax.tree().root_node().has_error())
    {
        return Some(open_redundant_boolean_row(
            node,
            true_body,
            node,
            BranchOpenReason::SyntaxRecovery,
        ));
    }
    let false_body = if let Some(alternative) = node.child_by_field_name("alternative") {
        if language == Language::Scala && (alternative.has_error() || alternative.is_missing()) {
            return Some(open_redundant_boolean_row(
                node,
                true_body,
                alternative,
                BranchOpenReason::SyntaxRecovery,
            ));
        }
        if alternative.kind() == "else_clause" {
            let Some(body) = alternative.named_child(0) else {
                return (language == Language::Scala).then(|| {
                    open_redundant_boolean_row(
                        node,
                        true_body,
                        alternative,
                        BranchOpenReason::SyntaxRecovery,
                    )
                });
            };
            if language == Language::Scala && body.has_error() {
                return Some(open_redundant_boolean_row(
                    node,
                    true_body,
                    body,
                    BranchOpenReason::SyntaxRecovery,
                ));
            }
            body
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
        let Some(parent) = statement.parent().filter(|parent| !parent.has_error()) else {
            return (language == Language::Scala && syntax.tree().root_node().has_error()).then(
                || {
                    open_redundant_boolean_row(
                        node,
                        true_body,
                        node,
                        BranchOpenReason::SyntaxRecovery,
                    )
                },
            );
        };
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
        let Some(mut following) = statement.next_named_sibling() else {
            return (language == Language::Scala && syntax.tree().root_node().has_error()).then(
                || {
                    open_redundant_boolean_row(
                        node,
                        true_body,
                        node,
                        BranchOpenReason::SyntaxRecovery,
                    )
                },
            );
        };
        while following.is_extra() {
            following = following.next_named_sibling()?;
        }
        following
    };
    let outcome = if language == Language::Kotlin {
        match classify_kotlin_boolean_branches(syntax.source(), node, true_body, false_body) {
            KotlinBooleanBranchClassification::Proven(outcome) => outcome,
            KotlinBooleanBranchClassification::Open => {
                return Some(BranchRelationRow {
                    kind: BranchRelationKind::RedundantBooleanReturn,
                    verdict: BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition),
                    owner: node_range(node),
                    earlier: node_range(true_body),
                    later: node_range(false_body),
                    earlier_ordinal: 0,
                    later_ordinal: 1,
                    orientation: None,
                });
            }
            KotlinBooleanBranchClassification::NotApplicable => {
                classify_boolean_branches(language, syntax.source(), true_body, false_body)?
            }
        }
    } else if language == Language::Scala {
        match classify_scala_boolean_branches(syntax.source(), true_body, false_body, Some(node)) {
            ScalaBooleanBranchClassification::Proven(outcome) => outcome,
            ScalaBooleanBranchClassification::NotCandidate => return None,
            ScalaBooleanBranchClassification::Open => {
                return Some(BranchRelationRow {
                    kind: BranchRelationKind::RedundantBooleanReturn,
                    verdict: BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition),
                    owner: node_range(node),
                    earlier: node_range(true_body),
                    later: node_range(false_body),
                    earlier_ordinal: 0,
                    later_ordinal: 1,
                    orientation: None,
                });
            }
        }
    } else {
        classify_boolean_branches(language, syntax.source(), true_body, false_body)?
    };
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
        BranchRelationKind::EmptyArm,
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

fn open_redundant_boolean_row(
    owner: Node<'_>,
    earlier: Node<'_>,
    later: Node<'_>,
    reason: BranchOpenReason,
) -> BranchRelationRow {
    BranchRelationRow {
        kind: BranchRelationKind::RedundantBooleanReturn,
        verdict: BranchRelationVerdict::Open(reason),
        owner: node_range(owner),
        earlier: node_range(earlier),
        later: node_range(later),
        earlier_ordinal: 0,
        later_ordinal: 1,
        orientation: None,
    }
}

fn scala_has_else_keyword(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "else")
}

fn collect_arms<'tree>(
    node: Node<'tree>,
    language: Language,
    budget: &mut BranchWorkBudget,
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
        budget.arm()?;
        arms.push(Arm {
            initializer: current.child_by_field_name("initializer"),
            condition: Some(
                current
                    .child_by_field_name("condition")
                    .ok_or(BranchOpenReason::MissingBranchField)?,
            ),
            body: current
                .child_by_field_name(body_field)
                .ok_or(BranchOpenReason::MissingBranchField)?,
        });
        if language == Language::Python {
            let mut cursor = current.walk();
            for alternative in current.children_by_field_name("alternative", &mut cursor) {
                budget.arm()?;
                match alternative.kind() {
                    "elif_clause" => arms.push(Arm {
                        initializer: None,
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
                        initializer: None,
                        condition: None,
                        body: alternative
                            .child_by_field_name("body")
                            .ok_or(BranchOpenReason::MissingBranchField)?,
                    }),
                    _ => return Err(BranchOpenReason::MissingBranchField),
                }
            }
            return Ok(arms);
        }
        if language == Language::Php {
            let mut cursor = current.walk();
            let mut next = None;
            for alternative in current.children_by_field_name("alternative", &mut cursor) {
                budget.step()?;
                let body = alternative
                    .child_by_field_name("body")
                    .ok_or(BranchOpenReason::MissingBranchField)?;
                match alternative.kind() {
                    "else_if_clause" => {
                        budget.arm()?;
                        arms.push(Arm {
                            initializer: None,
                            condition: Some(
                                alternative
                                    .child_by_field_name("condition")
                                    .ok_or(BranchOpenReason::MissingBranchField)?,
                            ),
                            body,
                        });
                    }
                    // `else if` (two words) nests another `if` statement.
                    "else_clause" if body.kind() == "if_statement" => next = Some(body),
                    "else_clause" => {
                        budget.arm()?;
                        arms.push(Arm {
                            initializer: None,
                            condition: None,
                            body,
                        });
                    }
                    _ => return Err(BranchOpenReason::MissingBranchField),
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
            current = alternative;
            continue;
        }
        budget.arm()?;
        arms.push(Arm {
            initializer: None,
            condition: None,
            body: alternative,
        });
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

/// What every comparison within one `if` chain shares.
#[derive(Clone, Copy)]
struct Chain<'a> {
    language: Language,
    /// The `if` whose chain is compared.
    owner: Range,
    source: &'a str,
    env: &'a EnvironmentFileResult,
    members: &'a BranchReferenceProofs,
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
fn compare_trees(
    earlier: Node<'_>,
    later: Node<'_>,
    chain: &Chain<'_>,
    budget: &mut BranchWorkBudget,
) -> BranchRelationVerdict {
    if let Err(reason) = budget.charge(BranchWork {
        comparisons: 1,
        ..BranchWork::default()
    }) {
        return BranchRelationVerdict::Open(reason);
    }
    let Chain {
        language,
        owner,
        source,
        env,
        members,
        condition_binders,
    } = *chain;
    let current_object_fields = language_support_for_hook(language, "branch_current_object_fields")
        .and_then(|support| support.branch_current_object_fields());
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
        if let Err(reason) = budget.step() {
            return BranchRelationVerdict::Open(reason);
        }
        visited += 1;
        if visited > MAX_COMPARISON_TREE_NODES {
            return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
        }
        if left.has_error() || right.has_error() || left.is_missing() || right.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        // A Ruby arm is a `then` or an `else`, each a statement list; only
        // their statements are compared.
        let ruby_arm = |node: Node<'_>| matches!(node.kind(), "then" | "else");
        if language == Language::Ruby && ruby_arm(left) && ruby_arm(right) {
            if left.child_count() > MAX_COMPARISON_TREE_NODES
                || right.child_count() > MAX_COMPARISON_TREE_NODES
                || stack.len() + left.child_count() > MAX_COMPARISON_TREE_NODES
            {
                return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
            }
            let left_statements = match bounded_named_statements(left, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return BranchRelationVerdict::Open(reason),
            };
            let right_statements = match bounded_named_statements(right, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return BranchRelationVerdict::Open(reason),
            };
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
        if !nested
            && let Some(spec) = current_object_fields.as_ref()
            && let (Some(left_member), Some(right_member)) = (spec.member(left), spec.member(right))
            && let (Some(left_declaration), Some(right_declaration)) = (
                members
                    .storage_fields
                    .get(&(left_member.start_byte(), left_member.end_byte())),
                members
                    .storage_fields
                    .get(&(right_member.start_byte(), right_member.end_byte())),
            )
            && left_declaration == right_declaration
        {
            // Both receivers denote this object, and both strict targets name
            // the same physical storage slot. Presentation identity alone does
            // not justify this equality; properties and methods never enter it.
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
        let nested_callable = is_nested_callable(left, language);
        let php_exact_callable =
            language == Language::Php && php_exact_nested_callable(left, right);
        let scala_exact_callable = if language == Language::Scala {
            match scala_nested_callable_is_exact(left, right, env, budget) {
                Ok(exact) => exact,
                Err(reason) if budget.exhausted => return BranchRelationVerdict::Open(reason),
                // A local refusal cannot make a closure exact. Keep comparing
                // outer syntax so an independent difference can still refute it.
                Err(_) => false,
            }
        } else {
            false
        };
        let nested = nested || (nested_callable && !(php_exact_callable || scala_exact_callable));
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
            if left.child_count() > MAX_COMPARISON_TREE_NODES
                || right.child_count() > MAX_COMPARISON_TREE_NODES
                || stack.len() + left.child_count() > MAX_COMPARISON_TREE_NODES
            {
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
            let mut left_children = match bounded_non_extra_children(left, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return BranchRelationVerdict::Open(reason),
            }
            .into_iter()
            .filter(|(field, _)| *field != Some("name"))
            .collect::<Vec<_>>();
            let mut right_children = match bounded_non_extra_children(right, stack.len(), budget) {
                Ok(children) => children,
                Err(reason) => return BranchRelationVerdict::Open(reason),
            }
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
                match (members.target_at(left_name), members.target_at(right_name)) {
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
        if left.child_count() > MAX_COMPARISON_TREE_NODES
            || right.child_count() > MAX_COMPARISON_TREE_NODES
            || stack.len() + left.child_count() > MAX_COMPARISON_TREE_NODES
        {
            return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
        }
        let left_children = match bounded_non_extra_children(left, stack.len(), budget) {
            Ok(children) => children,
            Err(reason) => return BranchRelationVerdict::Open(reason),
        };
        let right_children = match bounded_non_extra_children(right, stack.len(), budget) {
            Ok(children) => children,
            Err(reason) => return BranchRelationVerdict::Open(reason),
        };
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
                        && (arm_local_binding(env, *index, arm)
                            || (language == Language::Scala
                                && scala_callable_binding(env, *index, arm)))
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
            let roles = identifier_role(left, budget).and_then(|left_role| {
                identifier_role(right, budget).map(|right_role| (left_role, right_role))
            });
            let roles = match roles {
                Ok(roles) => roles,
                Err(reason) => return BranchRelationVerdict::Open(reason),
            };
            match roles {
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
        if let Err(reason) = budget.step() {
            return BranchRelationVerdict::Open(reason);
        }
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
            (BindingOfOutcome::NoBinding, BindingOfOutcome::NoBinding)
                if members.collection_gap.is_some()
                    || members
                        .sites
                        .contains_key(&(left.start_byte(), left.end_byte()))
                    || members
                        .sites
                        .contains_key(&(right.start_byte(), right.end_byte())) =>
            {
                // Exact resolver targets may distinguish nonlocal operations,
                // even when constants have equal values. Equal presentation
                // CodeUnits can hide different canonical declarations, so they
                // never establish a new equality proof. Distinction grants
                // no stability privilege, including in conditions.
                return match (members.target_at(left), members.target_at(right)) {
                    (Ok(a), Ok(b)) if a != b => BranchRelationVerdict::Distinct,
                    (Ok(_), Ok(_)) => {
                        BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference)
                    }
                    (Err(reason), _) | (_, Err(reason)) => BranchRelationVerdict::Open(reason),
                };
            }
            (BindingOfOutcome::NoBinding, _) | (_, BindingOfOutcome::NoBinding) => {
                return BranchRelationVerdict::Open(BranchOpenReason::NonLocalReference);
            }
            (BindingOfOutcome::Incomplete(_), _) | (_, BindingOfOutcome::Incomplete(_)) => {
                return BranchRelationVerdict::Open(BranchOpenReason::LexicalBindingUnavailable);
            }
        };
        // A pattern binder that a chain condition declares, such as Java's
        // flow-sensitive pattern variable, is in effect in some arms only and
        // is not represented by the shared lexical environment. Rust's
        // `if let` binders are represented with their exact consequence-body
        // interval by the Rust adapter, so the Rust branch below can compare
        // the pattern binding with an outer binding precisely.
        let declared_by_condition = |index: usize| {
            let range = env.bindings[index].range;
            let within =
                |start: usize, end: usize| start <= range.start_byte && range.end_byte <= end;
            env.bindings[index].kind == BindingKind::PatternBinder
                && within(owner.start_byte, owner.end_byte)
                && !within(earlier.start_byte(), earlier.end_byte())
                && !within(later.start_byte(), later.end_byte())
        };
        if language != Language::Rust && (declared_by_condition(a) || declared_by_condition(b)) {
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
        if language == Language::Rust
            && (env.bindings[a].kind == BindingKind::PatternBinder
                || env.bindings[b].kind == BindingKind::PatternBinder)
        {
            if a == b && name == other_name {
                continue;
            }
            return BranchRelationVerdict::Distinct;
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

fn rust_unary_not_operand(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "unary_expression" || node.named_child_count() != 1 {
        return None;
    }
    let mut cursor = node.walk();
    if !node.children(&mut cursor).any(|child| child.kind() == "!") {
        return None;
    }
    node.named_child(0)
}

fn rust_boolean_expression_bounded(
    mut expression: Node<'_>,
    env: &EnvironmentFileResult,
    source: &str,
    budget: &mut BranchWorkBudget,
) -> Result<bool, BranchOpenReason> {
    let mut visited = 0;
    loop {
        budget.visit(expression, &mut visited, 0)?;
        match expression.kind() {
            "boolean_literal" => {
                return Ok(matches!(
                    source.get(expression.byte_range()),
                    Some("true" | "false")
                ));
            }
            "parenthesized_expression" if expression.named_child_count() == 1 => {
                expression = expression.named_child(0).expect("one named child");
            }
            "unary_expression" => {
                let Some(operand) = rust_unary_not_operand(expression) else {
                    return Ok(false);
                };
                expression = operand;
            }
            "identifier" => {
                let Some(name) = source.get(expression.byte_range()) else {
                    return Ok(false);
                };
                return Ok(
                    match binding_of(env, name, expression.start_byte(), Some(Namespace::Value)) {
                        BindingOfOutcome::Reached(index)
                        | BindingOfOutcome::Shadowed { winner: index, .. } => {
                            rust_declared_boolean(env, index, expression, source)
                        }
                        BindingOfOutcome::NoBinding | BindingOfOutcome::Incomplete(_) => false,
                    },
                );
            }
            _ => return Ok(false),
        }
    }
}

fn rust_declared_boolean(
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
    let form = std::iter::successors(Some(name), |node| node.parent())
        .find(|node| matches!(node.kind(), "parameter" | "let_declaration"));
    let Some(form) = form else {
        return false;
    };
    if form
        .child_by_field_name("type")
        .and_then(|written| source.get(written.byte_range()))
        == Some("bool")
    {
        return true;
    }
    form.kind() == "let_declaration"
        && form.child_by_field_name("type").is_none()
        && form
            .child_by_field_name("value")
            .is_some_and(|value| value.kind() == "boolean_literal")
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
        // Ruby uses an identifier in expressions and a `line` token in patterns.
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

fn identifier_role(
    node: Node<'_>,
    budget: &mut BranchWorkBudget,
) -> Result<IdentifierRole, BranchOpenReason> {
    let Some(parent) = node.parent() else {
        return Ok(IdentifierRole::NonValue);
    };
    if parent.child_count() > MAX_COMPARISON_TREE_NODES {
        return Err(BranchOpenReason::ComparisonBudget);
    }
    let mut field = None;
    let mut cursor = parent.walk();
    if cursor.goto_first_child() {
        loop {
            budget.step()?;
            if cursor.node() == node {
                field = Some(cursor.field_name());
                break;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    if matches!(
        parent.kind(),
        "jsx_opening_element" | "jsx_closing_element" | "jsx_self_closing_element"
    ) {
        return Ok(IdentifierRole::NonValue);
    }
    if parent.kind() == "method_invocation" && field.flatten() != Some("object") {
        return Ok(IdentifierRole::NonValue);
    }
    // Kotlin spells no fields: a member follows `.` in a navigation suffix, a
    // named argument's label precedes its `=`, and a local's name is the
    // direct child of its variable declaration.
    match parent.kind() {
        "navigation_suffix" => return Ok(IdentifierRole::NonValue),
        "value_argument" if node.next_sibling().is_some_and(|next| next.kind() == "=") => {
            return Ok(IdentifierRole::NonValue);
        }
        "variable_declaration" => return Ok(IdentifierRole::Binder),
        _ => {}
    }
    Ok(match field.flatten() {
        Some("name") if parent.kind() == "variable_declarator" => IdentifierRole::Binder,
        Some("name" | "property" | "field" | "attribute" | "key" | "type" | "label") => {
            IdentifierRole::NonValue
        }
        _ => IdentifierRole::Value,
    })
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

/// Scala callable parameters are separate bindings in each branch, just like
/// arm-local declarations. Their activation is wholly inside the arm even
/// though the shared classifier reserves `arm_local_binding` for declarations
/// introduced by the arm itself.
fn scala_callable_binding(env: &EnvironmentFileResult, index: usize, arm: Node<'_>) -> bool {
    let binding = &env.bindings[index];
    matches!(binding.kind, BindingKind::Local | BindingKind::Parameter)
        && arm.start_byte() <= binding.activation.start_byte
        && binding.activation.end_byte <= arm.end_byte()
        && arm.start_byte() <= binding.range.start_byte
        && binding.range.end_byte <= arm.end_byte()
}

fn has_with_ancestor(node: Node<'_>) -> bool {
    brokk_bifrost_core::analyzer::structural::adapter_helpers::nearest_ancestor(node, |kind| {
        kind == "with_statement"
    })
    .is_some()
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

fn bounded_named_statements<'tree>(
    node: Node<'tree>,
    pending: usize,
    budget: &mut BranchWorkBudget,
) -> Result<Vec<Node<'tree>>, BranchOpenReason> {
    Ok(bounded_non_extra_children(node, pending, budget)?
        .into_iter()
        .map(|(_, child)| child)
        .filter(Node::is_named)
        .collect())
}

/// Admit each inspected child before filtering or retaining it. A bounded
/// temporary list keeps field names and source order for paired comparisons.
fn bounded_non_extra_children<'tree>(
    node: Node<'tree>,
    pending: usize,
    budget: &mut BranchWorkBudget,
) -> Result<Vec<(Option<&'static str>, Node<'tree>)>, BranchOpenReason> {
    if node.child_count() > MAX_COMPARISON_TREE_NODES
        || pending + node.child_count() > MAX_COMPARISON_TREE_NODES
    {
        return Err(BranchOpenReason::ComparisonBudget);
    }
    let mut children = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            budget.step()?;
            let child = cursor.node();
            if !child.is_extra() {
                children.push((cursor.field_name(), child));
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    Ok(children)
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
fn same_member(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    members: &BranchReferenceProofs,
) -> bool {
    match (members.target_at(left), members.target_at(right)) {
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
/// open rather than inferred from matching syntax. PHP is the exception for
/// by-value closures and arrows: its lexical environment gives each parameter,
/// capture and local an exact binding, so their bodies can be compared.
/// The kinds cover the Java, JavaScript, TypeScript and Python grammars; a
/// Python decorated definition is covered by the definition it wraps.
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

/// Whether a Scala nested callable can be compared through the lexical
/// environment. Lambdas and local `def`s have environment rows for their
/// parameters and locals. An anonymous `new T { ... }` is an instance with a
/// distinct class identity, so it remains deferred even when its body text
/// matches. Deferred parameter and lazy-value shapes also retain uncertainty.
fn scala_nested_callable_is_exact(
    left: Node<'_>,
    right: Node<'_>,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> Result<bool, BranchOpenReason> {
    if left.kind() != right.kind()
        || !matches!(left.kind(), "lambda_expression" | "function_definition")
        || !env.completeness.is_complete()
    {
        return Ok(false);
    }
    let mut stack = vec![left, right];
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        budget.visit(node, &mut visited, stack.len())?;
        if node.has_error() || node.is_missing() {
            return Ok(false);
        }
        if matches!(
            node.kind(),
            "by_name_type"
                | "lazy_parameter_type"
                | "repeated_parameter_type"
                | "lazy_modifier"
                | "lazy"
        ) {
            return Ok(false);
        }
        stack.extend(
            bounded_non_extra_children(node, stack.len(), budget)?
                .into_iter()
                .map(|(_, child)| child),
        );
    }
    Ok(true)
}

fn php_exact_nested_callable(left: Node<'_>, right: Node<'_>) -> bool {
    if left.kind() != right.kind() {
        return false;
    }
    match left.kind() {
        "arrow_function" => true,
        "anonymous_function" => {
            !php_callable_has_by_ref_capture(left) && !php_callable_has_by_ref_capture(right)
        }
        _ => false,
    }
}

fn php_callable_has_by_ref_capture(node: Node<'_>) -> bool {
    if node.kind() != "anonymous_function" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "anonymous_function_use_clause")
        .any(|use_clause| {
            has_direct_token(use_clause, "by_ref")
                || has_direct_token(use_clause, "reference_modifier")
                || has_direct_token(use_clause, "&")
        })
}

fn php_unsupported_lexical_ancestor(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "anonymous_class" {
            return true;
        }
        if ancestor.kind() == "anonymous_function" && php_callable_has_by_ref_capture(ancestor) {
            return true;
        }
        current = ancestor.parent();
    }
    false
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
    pattern_binders(roots, source, Language::Java, &mut BranchWorkBudget::new())
}

fn pattern_binders<'tree, 'source>(
    roots: impl IntoIterator<Item = Node<'tree>>,
    source: &'source str,
    language: Language,
    budget: &mut BranchWorkBudget,
) -> Result<Vec<&'source str>, BranchOpenReason> {
    let Some(pattern_binding_name) =
        language_support_for_hook(language, "pattern_binding_name_provider")
            .and_then(LanguageSupport::pattern_binding_name_provider)
    else {
        return Ok(Vec::new());
    };
    let mut stack = Vec::new();
    for root in roots {
        budget.step()?;
        if stack.len() == MAX_COMPARISON_TREE_NODES {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        stack.push(root);
    }
    let mut names = Vec::new();
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        budget.visit(node, &mut visited, stack.len())?;
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
        stack.extend(
            bounded_non_extra_children(node, stack.len(), budget)?
                .into_iter()
                .map(|(_, child)| child)
                .filter(Node::is_named),
        );
    }
    Ok(names)
}

fn condition_stability(
    condition: Node<'_>,
    language: Language,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> BranchRelationVerdict {
    if language == Language::Scala {
        return scala_condition_stability(condition, syntax.source(), env, budget);
    }
    if language == Language::CSharp {
        return csharp_condition_stability(condition, syntax.source(), env, budget);
    }
    let c_dialect = syntax.dialect() == crate::analyzer::LanguageDialect::CppC;
    let baseline =
        basic_condition_stability(condition, language, c_dialect, syntax.source(), env, budget);
    if language != Language::Java
        || !matches!(
            baseline,
            BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition)
        )
    {
        return baseline;
    }
    java_primitive_condition_stability(condition, syntax, env, budget)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalaConditionScalarType {
    Integer,
    Boolean,
}

#[derive(Clone, Copy)]
enum ScalaConditionExpectation {
    Boolean,
    Integer,
}

/// Scala's operators are methods, so repeated conditions are stable only
/// when every operand is a local or by-value parameter with an exact primitive
/// type, or a decimal integer/Boolean literal. The stack keeps this walk
/// bounded and avoids treating an arbitrary expression with a primitive result
/// as a built-in operator invocation.
fn scala_condition_stability(
    condition: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> BranchRelationVerdict {
    let mut pending = vec![(condition, ScalaConditionExpectation::Boolean)];
    let mut visited = 0;
    while let Some((mut node, expectation)) = pending.pop() {
        if let Err(reason) = budget.visit(node, &mut visited, pending.len()) {
            return BranchRelationVerdict::Open(reason);
        }
        if node.has_error() || node.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        while node.kind() == "parenthesized_expression" {
            if node.named_child_count() != 1 {
                return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
            }
            node = node.named_child(0).expect("one parenthesized expression");
            if let Err(reason) = budget.visit(node, &mut visited, pending.len()) {
                return BranchRelationVerdict::Open(reason);
            }
            if visited > 4096 || node.has_error() || node.is_missing() {
                return BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget);
            }
        }
        let literal_type = match scala_condition_literal_type(node, source, budget) {
            Ok(literal_type) => literal_type,
            Err(reason) => return BranchRelationVerdict::Open(reason),
        };
        if let Some(scalar_type) = literal_type {
            if scala_condition_type_matches(scalar_type, expectation) {
                continue;
            }
            return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
        }
        match node.kind() {
            "identifier" => {
                let scalar_type = match scala_condition_binding_type(node, source, env, budget) {
                    Ok(scalar_type) => scalar_type,
                    Err(reason) => return BranchRelationVerdict::Open(reason),
                };
                if !scala_condition_type_matches(scalar_type, expectation) {
                    return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                }
            }
            "prefix_expression" => {
                let operator = match scala_prefix_operator(node, budget) {
                    Ok(Some(operator)) => operator,
                    Ok(None) => {
                        return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
                    }
                    Err(reason) => return BranchRelationVerdict::Open(reason),
                };
                let operand = match scala_prefix_operand(node, budget) {
                    Ok(Some(operand)) => operand,
                    Ok(None) => {
                        return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
                    }
                    Err(reason) => return BranchRelationVerdict::Open(reason),
                };
                match operator {
                    "!" if matches!(expectation, ScalaConditionExpectation::Boolean) => {
                        pending.push((operand, ScalaConditionExpectation::Boolean));
                    }
                    "-" if matches!(expectation, ScalaConditionExpectation::Integer) => {
                        pending.push((operand, ScalaConditionExpectation::Integer));
                    }
                    _ => {
                        return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                    }
                }
            }
            "infix_expression" => {
                let (Some(operator), Some(left), Some(right)) = (
                    node.child_by_field_name("operator"),
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
                };
                let Some(operator) = source.get(operator.byte_range()) else {
                    return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
                };
                match operator {
                    "&&" | "||" if matches!(expectation, ScalaConditionExpectation::Boolean) => {
                        pending.push((right, ScalaConditionExpectation::Boolean));
                        pending.push((left, ScalaConditionExpectation::Boolean));
                    }
                    "<" | "<=" | ">" | ">="
                        if matches!(expectation, ScalaConditionExpectation::Boolean) =>
                    {
                        pending.push((right, ScalaConditionExpectation::Integer));
                        pending.push((left, ScalaConditionExpectation::Integer));
                    }
                    "==" | "!=" if matches!(expectation, ScalaConditionExpectation::Boolean) => {
                        let left_type =
                            match scala_condition_operand_type(left, source, env, budget) {
                                Ok(left_type) => left_type,
                                Err(reason) => return BranchRelationVerdict::Open(reason),
                            };
                        let right_type =
                            match scala_condition_operand_type(right, source, env, budget) {
                                Ok(right_type) => right_type,
                                Err(reason) => return BranchRelationVerdict::Open(reason),
                            };
                        if left_type != right_type
                            || !matches!(
                                (left_type, right_type),
                                (
                                    ScalaConditionScalarType::Integer,
                                    ScalaConditionScalarType::Integer
                                ) | (
                                    ScalaConditionScalarType::Boolean,
                                    ScalaConditionScalarType::Boolean
                                )
                            )
                        {
                            return BranchRelationVerdict::Open(
                                BranchOpenReason::UnsupportedCondition,
                            );
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

fn scala_condition_type_matches(
    scalar_type: ScalaConditionScalarType,
    expectation: ScalaConditionExpectation,
) -> bool {
    matches!(
        (scalar_type, expectation),
        (
            ScalaConditionScalarType::Boolean,
            ScalaConditionExpectation::Boolean
        ) | (
            ScalaConditionScalarType::Integer,
            ScalaConditionExpectation::Integer
        )
    )
}

fn scala_condition_operand_type(
    mut node: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> Result<ScalaConditionScalarType, BranchOpenReason> {
    for _ in 0..64 {
        budget.step()?;
        if node.kind() == "parenthesized_expression" {
            if node.named_child_count() != 1 {
                return Err(BranchOpenReason::MissingBranchField);
            }
            node = node.named_child(0).expect("one parenthesized expression");
            continue;
        }
        if node.kind() == "prefix_expression" {
            if scala_prefix_operator(node, budget)? != Some("-") {
                return Err(BranchOpenReason::UnsupportedCondition);
            }
            node =
                scala_prefix_operand(node, budget)?.ok_or(BranchOpenReason::MissingBranchField)?;
            continue;
        }
        if let Some(scalar_type) = scala_condition_literal_type(node, source, budget)? {
            return Ok(scalar_type);
        }
        return match node.kind() {
            "identifier" => scala_condition_binding_type(node, source, env, budget),
            _ => Err(BranchOpenReason::UnsupportedCondition),
        };
    }
    Err(BranchOpenReason::ComparisonBudget)
}

fn scala_condition_literal_type(
    mut node: Node<'_>,
    source: &str,
    budget: &mut BranchWorkBudget,
) -> Result<Option<ScalaConditionScalarType>, BranchOpenReason> {
    let mut negative = false;
    for _ in 0..64 {
        budget.step()?;
        match node.kind() {
            "parenthesized_expression" => {
                let Some(child) = node.named_child(0) else {
                    return Ok(None);
                };
                node = child;
            }
            "prefix_expression" => {
                if scala_prefix_operator(node, budget)? != Some("-") {
                    return Ok(None);
                }
                negative = !negative;
                let Some(operand) = scala_prefix_operand(node, budget)? else {
                    return Ok(None);
                };
                node = operand;
            }
            "boolean_literal" if !negative => {
                return Ok(
                    matches!(source.get(node.byte_range()), Some("true" | "false"))
                        .then_some(ScalaConditionScalarType::Boolean),
                );
            }
            "integer_literal" => {
                let Some(mut text) = source.get(node.byte_range()) else {
                    return Ok(None);
                };
                if matches!(text.as_bytes().last(), Some(b'l' | b'L')) {
                    text = &text[..text.len() - 1];
                }
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Ok(None);
                }
                let Ok(magnitude) = text.parse::<u128>() else {
                    return Ok(None);
                };
                let max_i64 = if negative {
                    (i64::MAX as u128) + 1
                } else {
                    i64::MAX as u128
                };
                if magnitude > max_i64 {
                    return Ok(None);
                }
                return Ok(Some(ScalaConditionScalarType::Integer));
            }
            _ => return Ok(None),
        }
    }
    Err(BranchOpenReason::ComparisonBudget)
}

fn scala_prefix_operator(
    node: Node<'_>,
    budget: &mut BranchWorkBudget,
) -> Result<Option<&'static str>, BranchOpenReason> {
    Ok(bounded_non_extra_children(node, 0, budget)?
        .into_iter()
        .find_map(|(_, child)| match child.kind() {
            "!" => Some("!"),
            "-" => Some("-"),
            _ => None,
        }))
}

fn scala_prefix_operand<'tree>(
    node: Node<'tree>,
    budget: &mut BranchWorkBudget,
) -> Result<Option<Node<'tree>>, BranchOpenReason> {
    Ok(bounded_non_extra_children(node, 0, budget)?
        .into_iter()
        .map(|(_, child)| child)
        .find(Node::is_named))
}

fn scala_condition_binding_type(
    node: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> Result<ScalaConditionScalarType, BranchOpenReason> {
    let name = source
        .get(node.byte_range())
        .ok_or(BranchOpenReason::SyntaxRecovery)?;
    let index = match binding_of(env, name, node.start_byte(), Some(Namespace::Value)) {
        BindingOfOutcome::Reached(index) | BindingOfOutcome::Shadowed { winner: index, .. } => {
            index
        }
        BindingOfOutcome::NoBinding => return Err(BranchOpenReason::NonLocalReference),
        BindingOfOutcome::Incomplete(_) => return Err(BranchOpenReason::LexicalBindingUnavailable),
    };
    if !stable_binding(env, index) {
        return Err(BranchOpenReason::NonLocalReference);
    }
    scala_declared_condition_type(env, index, node, source, budget)?
        .ok_or(BranchOpenReason::UnsupportedCondition)
}

fn scala_declared_condition_type(
    env: &EnvironmentFileResult,
    index: usize,
    reference: Node<'_>,
    source: &str,
    budget: &mut BranchWorkBudget,
) -> Result<Option<ScalaConditionScalarType>, BranchOpenReason> {
    let mut root = reference;
    let mut visited = 0;
    while let Some(parent) = root.parent() {
        budget.step()?;
        visited += 1;
        if visited > MAX_COMPARISON_TREE_NODES {
            return Err(BranchOpenReason::ComparisonBudget);
        }
        root = parent;
    }
    let range = env.bindings[index].range;
    let Some(name) = root.named_descendant_for_byte_range(range.start_byte, range.end_byte) else {
        return Ok(None);
    };
    if name.start_byte() != range.start_byte || name.end_byte() != range.end_byte {
        return Ok(None);
    }
    let Some(declaration) = name.parent() else {
        return Ok(None);
    };
    let typed = match declaration.kind() {
        "parameter" => declaration.child_by_field_name("type"),
        "val_definition" | "var_definition"
            if declaration
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern.id() == name.id()) =>
        {
            declaration.child_by_field_name("type")
        }
        _ => return Ok(None),
    };
    if scala_has_deferred_shape(declaration, budget)? {
        return Ok(None);
    }
    if let Some(type_node) = typed {
        let Some(scalar_type) = scala_condition_type_name(type_node, source, budget)? else {
            return Ok(None);
        };
        // A qualified scala type does not depend on an unqualified shadow
        // proof. An incomplete proof must not fall through to an initializer.
        let shadowed = if type_node.kind() == "type_identifier" {
            let expected = match scalar_type {
                ScalaConditionScalarType::Integer => scala_integer_type_name(type_node, source),
                ScalaConditionScalarType::Boolean => Some("Boolean"),
            };
            let Some(expected) = expected else {
                return Ok(None);
            };
            scala_defines_named_type_bounded(reference, source, expected, || budget.step().is_ok())
                .ok_or(BranchOpenReason::ComparisonBudget)?
        } else {
            false
        };
        return Ok((!shadowed).then_some(scalar_type));
    }
    if declaration.kind() != "parameter"
        && let Some(value) = declaration.child_by_field_name("value")
    {
        return scala_condition_literal_type(value, source, budget);
    }
    Ok(None)
}

fn scala_integer_type_name(type_node: Node<'_>, source: &str) -> Option<&'static str> {
    match source.get(type_node.byte_range())? {
        "Int" => Some("Int"),
        "Long" => Some("Long"),
        "Short" => Some("Short"),
        "Byte" => Some("Byte"),
        _ => None,
    }
}

fn scala_has_deferred_shape(
    node: Node<'_>,
    budget: &mut BranchWorkBudget,
) -> Result<bool, BranchOpenReason> {
    let mut stack = vec![node];
    let mut visited = 0;
    while let Some(current) = stack.pop() {
        budget.visit(current, &mut visited, stack.len())?;
        if matches!(
            current.kind(),
            "by_name_type"
                | "lazy_parameter_type"
                | "repeated_parameter_type"
                | "lazy_modifier"
                | "lazy"
        ) {
            return Ok(true);
        }
        stack.extend(
            bounded_non_extra_children(current, stack.len(), budget)?
                .into_iter()
                .map(|(_, child)| child),
        );
    }
    Ok(false)
}

fn scala_condition_type_name(
    type_node: Node<'_>,
    source: &str,
    budget: &mut BranchWorkBudget,
) -> Result<Option<ScalaConditionScalarType>, BranchOpenReason> {
    let mut segments = Vec::new();
    let mut stack = vec![type_node];
    let mut visited = 0;
    while let Some(node) = stack.pop() {
        budget.visit(node, &mut visited, stack.len())?;
        match node.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => {
                segments.push(
                    source
                        .get(node.byte_range())
                        .ok_or(BranchOpenReason::SyntaxRecovery)?
                        .to_owned(),
                );
            }
            "type_arguments" | "arguments" | "annotation" | "structural_type" => {}
            _ => {
                let mut children = bounded_non_extra_children(node, stack.len(), budget)?
                    .into_iter()
                    .map(|(_, child)| child)
                    .collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
        }
    }
    Ok(
        match segments
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["Int"]
            | ["scala", "Int"]
            | ["Long"]
            | ["scala", "Long"]
            | ["Short"]
            | ["scala", "Short"]
            | ["Byte"]
            | ["scala", "Byte"] => Some(ScalaConditionScalarType::Integer),
            ["Boolean"] | ["scala", "Boolean"] => Some(ScalaConditionScalarType::Boolean),
            _ => None,
        },
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CSharpConditionType {
    Integral,
    Boolean,
}

fn csharp_condition_stability(
    condition: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> BranchRelationVerdict {
    let mut pending = vec![condition];
    let mut visited = 0;
    while let Some(mut node) = pending.pop() {
        if let Err(reason) = budget.visit(node, &mut visited, pending.len()) {
            return BranchRelationVerdict::Open(reason);
        }
        if node.has_error() || node.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
            node = node.named_child(0).expect("one parenthesized expression");
            if let Err(reason) = budget.visit(node, &mut visited, pending.len()) {
                return BranchRelationVerdict::Open(reason);
            }
            if visited > 4096 || node.has_error() || node.is_missing() {
                return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
            }
        }
        match node.kind() {
            "boolean_literal" => {
                if !matches!(source.get(node.byte_range()), Some("true" | "false")) {
                    return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
                }
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
                    "==" | "!=" => {
                        let left_type = csharp_scalar_operand_type(left, source, env, budget);
                        let right_type = csharp_scalar_operand_type(right, source, env, budget);
                        match (left_type, right_type) {
                            (Ok(left), Ok(right)) if left == right => {}
                            (Err(reason), _) | (_, Err(reason)) => {
                                return BranchRelationVerdict::Open(reason);
                            }
                            _ => {
                                return BranchRelationVerdict::Open(
                                    BranchOpenReason::UnsupportedCondition,
                                );
                            }
                        }
                    }
                    "<" | "<=" | ">" | ">=" => {
                        for operand in [left, right] {
                            if let Err(reason) = csharp_scalar_operand_type(
                                operand, source, env, budget,
                            )
                            .and_then(|kind| {
                                (kind == CSharpConditionType::Integral)
                                    .then_some(kind)
                                    .ok_or(BranchOpenReason::UnsupportedCondition)
                            }) {
                                return BranchRelationVerdict::Open(reason);
                            }
                        }
                    }
                    _ => {
                        return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                    }
                }
            }
            "prefix_unary_expression" => {
                let (Some(operator), Some(operand)) = (node.child(0), node.named_child(0)) else {
                    return BranchRelationVerdict::Open(BranchOpenReason::MissingBranchField);
                };
                if operator.kind() != "!" {
                    return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                }
                match csharp_scalar_operand_type(operand, source, env, budget) {
                    Ok(CSharpConditionType::Boolean) => {}
                    Ok(_) => {
                        return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                    }
                    Err(reason) => return BranchRelationVerdict::Open(reason),
                }
            }
            "identifier" => {
                if csharp_scalar_binding_type(node, source, env) != Ok(CSharpConditionType::Boolean)
                {
                    return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                }
            }
            _ => {
                return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
            }
        }
    }
    BranchRelationVerdict::Proven
}

fn csharp_scalar_operand_type(
    mut node: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> Result<CSharpConditionType, BranchOpenReason> {
    let mut visited = 0;
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        budget.visit(node, &mut visited, 0)?;
        node = node.named_child(0).expect("one parenthesized expression");
    }
    if node.has_error() || node.is_missing() {
        return Err(BranchOpenReason::SyntaxRecovery);
    }
    match node.kind() {
        "integer_literal" | "boolean_literal" => csharp_literal_type(node, source),
        "identifier" => csharp_scalar_binding_type(node, source, env),
        _ => Err(BranchOpenReason::UnsupportedCondition),
    }
}

fn csharp_literal_type(
    node: Node<'_>,
    source: &str,
) -> Result<CSharpConditionType, BranchOpenReason> {
    match node.kind() {
        "integer_literal"
            if source
                .get(node.byte_range())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some() =>
        {
            Ok(CSharpConditionType::Integral)
        }
        "boolean_literal" if matches!(source.get(node.byte_range()), Some("true" | "false")) => {
            Ok(CSharpConditionType::Boolean)
        }
        _ => Err(BranchOpenReason::UnsupportedCondition),
    }
}

fn csharp_scalar_binding_type(
    reference: Node<'_>,
    source: &str,
    env: &EnvironmentFileResult,
) -> Result<CSharpConditionType, BranchOpenReason> {
    let name = source
        .get(reference.byte_range())
        .ok_or(BranchOpenReason::SyntaxRecovery)?;
    let index = match binding_of(env, name, reference.start_byte(), Some(Namespace::Value)) {
        BindingOfOutcome::Reached(index) | BindingOfOutcome::Shadowed { winner: index, .. } => {
            index
        }
        BindingOfOutcome::NoBinding => return Err(BranchOpenReason::NonLocalReference),
        BindingOfOutcome::Incomplete(_) => {
            return Err(BranchOpenReason::LexicalBindingUnavailable);
        }
    };
    if !stable_binding(env, index) {
        return Err(BranchOpenReason::UnsupportedCondition);
    }

    let mut root = reference;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let range = env.bindings[index].range;
    let name_node = root
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        .ok_or(BranchOpenReason::LexicalBindingUnavailable)?;
    let declaration = name_node
        .parent()
        .ok_or(BranchOpenReason::LexicalBindingUnavailable)?;
    let (names_binding, typed) = match declaration.kind() {
        "parameter" => (declaration.child_by_field_name("name"), Some(declaration)),
        "variable_declarator" => (
            declaration.child_by_field_name("name"),
            declaration.parent(),
        ),
        _ => (None, None),
    };
    if names_binding != Some(name_node) {
        return Err(BranchOpenReason::UnsupportedCondition);
    }
    if declaration.kind() == "parameter" {
        let mut cursor = declaration.walk();
        if declaration.children(&mut cursor).any(|child| {
            child.kind() == "modifier"
                || matches!(child.kind(), "ref" | "out" | "in" | "params" | "this")
        }) {
            return Err(BranchOpenReason::UnsupportedCondition);
        }
    }
    let Some(typed) = typed else {
        return Err(BranchOpenReason::UnsupportedCondition);
    };
    if declaration.kind() == "variable_declarator"
        && (typed.kind() != "variable_declaration" || typed.has_error())
    {
        return Err(BranchOpenReason::SyntaxRecovery);
    }
    let type_node = typed
        .child_by_field_name("type")
        .ok_or(BranchOpenReason::UnsupportedCondition)?;
    if type_node.kind() == "implicit_type" {
        if declaration.kind() != "variable_declarator" {
            return Err(BranchOpenReason::UnsupportedCondition);
        }
        let mut cursor = declaration.walk();
        let initializer = declaration
            .named_children(&mut cursor)
            .find(|child| child.start_byte() > name_node.end_byte())
            .and_then(|child| {
                if child.kind() == "equals_value_clause" {
                    child.named_child(0)
                } else {
                    Some(child)
                }
            })
            .ok_or(BranchOpenReason::UnsupportedCondition)?;
        return csharp_literal_type(initializer, source);
    }
    csharp_declared_type(type_node, source).ok_or(BranchOpenReason::UnsupportedCondition)
}

fn csharp_declared_type(node: Node<'_>, source: &str) -> Option<CSharpConditionType> {
    if node.kind() != "predefined_type" {
        return None;
    }
    match source.get(node.byte_range())? {
        "sbyte" | "byte" | "short" | "ushort" | "char" | "int" | "uint" | "long" | "ulong" => {
            Some(CSharpConditionType::Integral)
        }
        "bool" => Some(CSharpConditionType::Boolean),
        _ => None,
    }
}

fn basic_condition_stability(
    condition: Node<'_>,
    language: Language,
    c_dialect: bool,
    source: &str,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
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
        if let Err(reason) = budget.visit(node, &mut visited, stack.len()) {
            return BranchRelationVerdict::Open(reason);
        }
        if node.has_error() || node.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        let kind = node.kind();
        if language == Language::Rust && kind == "unary_expression" {
            let Some(operand) = rust_unary_not_operand(node) else {
                return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
            };
            match rust_boolean_expression_bounded(operand, env, source, budget) {
                Ok(true) => {}
                Ok(false) => {
                    return BranchRelationVerdict::Open(BranchOpenReason::UnsupportedCondition);
                }
                Err(reason) => return BranchRelationVerdict::Open(reason),
            }
        }
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
            // Rust comparisons dispatch to traits that user code can
            // implement. Unary `!` is admitted below only after its operand
            // is proved to be a built-in Boolean binding or literal.
            Language::Rust => matches!(
                kind,
                "identifier"
                    | "boolean_literal"
                    | "parenthesized_expression"
                    | "unary_expression"
                    | "!"
                    | "("
                    | ")"
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
                    | "=="
                    | "!="
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
        let children = match bounded_non_extra_children(node, stack.len(), budget) {
            Ok(children) => children,
            Err(reason) => return BranchRelationVerdict::Open(reason),
        };
        stack.extend(children.into_iter().map(|(_, child)| child));
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
    budget: &mut BranchWorkBudget,
) -> BranchRelationVerdict {
    let mut pending = vec![condition];
    let mut visited = 0;
    while let Some(mut node) = pending.pop() {
        if let Err(reason) = budget.visit(node, &mut visited, pending.len()) {
            return BranchRelationVerdict::Open(reason);
        }
        if node.has_error() || node.is_missing() {
            return BranchRelationVerdict::Open(BranchOpenReason::SyntaxRecovery);
        }
        while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
            node = node.named_child(0).expect("one parenthesized expression");
            if let Err(reason) = budget.visit(node, &mut visited, pending.len()) {
                return BranchRelationVerdict::Open(reason);
            }
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
                            if let Err(reason) = java_integral_operand(operand, syntax, env, budget)
                            {
                                return BranchRelationVerdict::Open(reason);
                            }
                        }
                    }
                    "==" | "!=" => {
                        let left_kind = java_equality_operand(left, syntax, env, budget);
                        let right_kind = java_equality_operand(right, syntax, env, budget);
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
    budget: &mut BranchWorkBudget,
) -> Result<(), BranchOpenReason> {
    let node = java_peel_parentheses(node, budget)?;
    let kind = java_integral_or_binding_type(node, syntax, env)?;
    (kind == JavaPrimitiveConditionType::Integral)
        .then_some(())
        .ok_or(BranchOpenReason::UnsupportedCondition)
}

fn java_equality_operand(
    node: Node<'_>,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
    budget: &mut BranchWorkBudget,
) -> Result<JavaPrimitiveConditionType, BranchOpenReason> {
    let node = java_peel_parentheses(node, budget)?;
    if matches!(node.kind(), "true" | "false") {
        return Ok(JavaPrimitiveConditionType::Boolean);
    }
    java_integral_or_binding_type(node, syntax, env)
}

fn java_integral_or_binding_type(
    node: Node<'_>,
    syntax: &PreparedSyntaxTree,
    env: &EnvironmentFileResult,
) -> Result<JavaPrimitiveConditionType, BranchOpenReason> {
    if java_decimal_int_value(syntax.source(), node).is_some() {
        return Ok(JavaPrimitiveConditionType::Integral);
    }
    java_binding_type(node, syntax, env)
}

fn java_peel_parentheses<'tree>(
    mut node: Node<'tree>,
    budget: &mut BranchWorkBudget,
) -> Result<Node<'tree>, BranchOpenReason> {
    for _ in 0..64 {
        budget.step()?;
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "branch_relations/js_ts_tests_support.rs"]
pub mod js_ts_tests_support;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tree_sitter::{Parser, Tree};

    fn parse(source: &str, language: Language, path: &str) -> Tree {
        let grammar = crate::analyzer::parser_language_for_path(language, Path::new(path))
            .expect("registered grammar");
        let mut parser = Parser::new();
        parser.set_language(&grammar).unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        tree
    }

    fn environment(source: &str, root: Node<'_>, names: &[Node<'_>]) -> EnvironmentFileResult {
        use super::super::lexical_environment::{
            BindingRow, EnvironmentCompleteness, PackageClauseRow, ScopeAnchor, ScopeRow,
        };
        use super::super::resolution::{DeclaredVisibility, HoistingClass};
        let file = crate::analyzer::ProjectFile::new(std::env::temp_dir(), "case.scala");
        let identity = crate::analyzer::semantic::ContentIdentity::hash_bytes(source.as_bytes());
        let range = node_range(root);
        EnvironmentFileResult::new(
            vec![ScopeRow {
                file: file.clone(),
                content_identity: identity,
                index: 0,
                anchor: ScopeAnchor::File,
                range,
                parent_scope: None,
            }],
            names
                .iter()
                .enumerate()
                .map(|(index, name)| BindingRow {
                    file: file.clone(),
                    content_identity: identity,
                    node: None,
                    range: node_range(*name),
                    name: source[name.byte_range()].to_owned(),
                    kind: BindingKind::Local,
                    hoisting: HoistingClass::ScopeWide,
                    declaring_scope: 0,
                    activation: range,
                    source_order: index as u32,
                    visibility: DeclaredVisibility::Unknown,
                    import: None,
                })
                .collect(),
            PackageClauseRow {
                file,
                package_fq: None,
                syntactic: false,
            },
            EnvironmentCompleteness::Complete,
        )
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: explicit Scala custom types must not infer primitive stability from converted initializer literals"
    )]
    fn scala_converted_initializers_do_not_prove_custom_operators_stable() {
        let source = "object O { class Meter { var n = 0; def <(rhs: scala.Int): Boolean = { n += 1; n == rhs } }; implicit def wrap(i: scala.Int): Meter = new Meter; def f(): Unit = { val x: Meter = 1; if (x < 2) () else if (x < 2) () } }";
        let tree = parse(source, Language::Scala, "case.scala");
        let declarations = brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
            tree.root_node(),
            "val_definition",
        );
        let declaration = declarations[0];
        let name = declaration.child_by_field_name("pattern").unwrap();
        assert_eq!(
            declaration.child_by_field_name("type").unwrap().kind(),
            "type_identifier"
        );
        assert_eq!(
            declaration.child_by_field_name("value").unwrap().kind(),
            "integer_literal"
        );
        let env = environment(source, tree.root_node(), &[name]);
        assert_eq!(
            scala_declared_condition_type(&env, 0, name, source, &mut BranchWorkBudget::new())
                .unwrap(),
            None
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "dce884c96143: quicksilver round 12 on brokk-bifrost-analysis: shadowed Scala primitive annotations fell back to initializer inference"
    )]
    fn scalar_declarations_follow_grammar_types_and_lexical_shadowing() {
        for (source, expected) in [
            ("val x = 1", Some(ScalaConditionScalarType::Integer)),
            ("val x: Int = 1", Some(ScalaConditionScalarType::Integer)),
            (
                "val x: scala.Int = 1",
                Some(ScalaConditionScalarType::Integer),
            ),
            (
                "val x: Boolean = true",
                Some(ScalaConditionScalarType::Boolean),
            ),
            (
                "val x: scala.Boolean = true",
                Some(ScalaConditionScalarType::Boolean),
            ),
            ("class Int; val x: Int = 1", None),
            (
                "class Int; val x: scala.Int = 1",
                Some(ScalaConditionScalarType::Integer),
            ),
            (
                "class Long; val x: Int = 1",
                Some(ScalaConditionScalarType::Integer),
            ),
        ] {
            let tree = parse(source, Language::Scala, "case.scala");
            let declaration =
                brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
                    tree.root_node(),
                    "val_definition",
                )[0];
            let name = declaration.child_by_field_name("pattern").unwrap();
            assert_eq!(name.kind(), "identifier");
            let env = environment(source, tree.root_node(), &[name]);
            assert_eq!(
                scala_declared_condition_type(&env, 0, name, source, &mut BranchWorkBudget::new())
                    .unwrap(),
                expected,
                "{source}"
            );
        }
        for (source, declaration_kind, expected) in [
            ("fn f(x: bool) {}", "parameter", true),
            ("fn f(x: i32) {}", "parameter", false),
            ("fn f() { let x = true; }", "let_declaration", true),
        ] {
            let tree = parse(source, Language::Rust, "case.rs");
            let declarations =
                brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind(
                    tree.root_node(),
                    declaration_kind,
                );
            let name = declarations[0].child_by_field_name("pattern").unwrap();
            assert_eq!(name.kind(), "identifier");
            let env = environment(source, tree.root_node(), &[name]);
            assert_eq!(
                rust_declared_boolean(&env, 0, name, source),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn scalar_literals_and_parentheses_respect_grammar_and_work_limits() {
        for (value, expected) in [
            ("true", Some(ScalaConditionScalarType::Boolean)),
            ("false", Some(ScalaConditionScalarType::Boolean)),
            (
                "9223372036854775807L",
                Some(ScalaConditionScalarType::Integer),
            ),
            ("9223372036854775808L", None),
        ] {
            let source = format!("val x = {value}");
            let tree = parse(&source, Language::Scala, "case.scala");
            let declaration = tree.root_node().named_child(0).unwrap();
            let node = declaration.child_by_field_name("value").unwrap();
            assert!(matches!(node.kind(), "boolean_literal" | "integer_literal"));
            assert_eq!(&source[node.byte_range()], value);
            assert_eq!(
                scala_condition_literal_type(node, &source, &mut BranchWorkBudget::new()).unwrap(),
                expected,
                "{value}"
            );
        }
        for wrappers in [62, 63, 64] {
            let source = format!(
                "val x = {}true{}",
                "(".repeat(wrappers),
                ")".repeat(wrappers)
            );
            let tree = parse(&source, Language::Scala, "case.scala");
            let node = tree
                .root_node()
                .named_child(0)
                .unwrap()
                .child_by_field_name("value")
                .unwrap();
            let mut leaf = node;
            let mut depth = 0;
            while leaf.kind() == "parenthesized_expression" {
                assert_eq!(leaf.named_child_count(), 1);
                depth += 1;
                leaf = leaf.named_child(0).unwrap();
            }
            assert_eq!(depth, wrappers);
            assert_eq!(leaf.kind(), "boolean_literal");
            let env = environment(&source, tree.root_node(), &[]);
            let result =
                scala_condition_operand_type(node, &source, &env, &mut BranchWorkBudget::new());
            assert_eq!(
                result,
                if wrappers < 64 {
                    Ok(ScalaConditionScalarType::Boolean)
                } else {
                    Err(BranchOpenReason::ComparisonBudget)
                }
            );
        }
    }

    #[test]
    fn branch_arm_and_tree_work_limits_are_inclusive() {
        for count in [3, MAX_CHAIN_COMPARISONS + 1] {
            let source = format!(
                "if True:\n pass\n{}",
                "elif False:\n pass\n".repeat(count - 1)
            );
            let tree = parse(&source, Language::Python, "case.py");
            let node = tree.root_node().named_child(0).unwrap();
            let mut cursor = node.walk();
            let expected = std::iter::once(node.child_by_field_name("consequence").unwrap())
                .chain(
                    node.children_by_field_name("alternative", &mut cursor)
                        .map(|arm| arm.child_by_field_name("consequence").unwrap()),
                )
                .map(|body| body.byte_range())
                .collect::<Vec<_>>();
            assert_eq!(expected.len(), count);
            for limit in [count - 1, count, count + 1] {
                let mut budget = BranchWorkBudget {
                    ledger: BudgetLedger::with_zero_usage(BranchWork {
                        arms: limit,
                        ..BranchWork::default_limits()
                    }),
                    exhausted: false,
                };
                match collect_arms(node, Language::Python, &mut budget) {
                    Ok(arms) => {
                        assert!(limit >= count);
                        assert_eq!(
                            arms.into_iter()
                                .map(|arm| arm.body.byte_range())
                                .collect::<Vec<_>>(),
                            expected
                        );
                    }
                    Err(reason) => {
                        assert!(limit < count);
                        assert_eq!(reason, BranchOpenReason::ComparisonBudget);
                    }
                }
            }
        }
        let source = "x\n".repeat(MAX_COMPARISON_TREE_NODES);
        let tree = parse(&source, Language::Python, "case.py");
        let mut cursor = tree.walk();
        let mut leaves = Vec::new();
        loop {
            if cursor.node().kind() == "identifier" {
                leaves.push(cursor.node());
            }
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    break;
                }
            }
            if cursor.node().id() == tree.root_node().id() {
                break;
            }
        }
        assert_eq!(leaves.len(), MAX_COMPARISON_TREE_NODES);
        for inspected in [4095, 4096, 4097] {
            let mut budget = BranchWorkBudget::new();
            let mut visited = 0;
            for node in leaves.iter().cycle().take(inspected) {
                let result = budget.visit(*node, &mut visited, 0);
                assert_eq!(
                    result,
                    if visited <= MAX_COMPARISON_TREE_NODES {
                        Ok(())
                    } else {
                        Err(BranchOpenReason::ComparisonBudget)
                    }
                );
            }
        }
    }

    #[test]
    fn conditional_alternatives_own_only_their_else_if_chain() {
        use brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind;
        for (language, path, source, kind) in [
            (
                Language::Java,
                "Case.java",
                "class C { void f(boolean a, boolean b) { if (a) {} else if (b) {} } }",
                "if_statement",
            ),
            (
                Language::Rust,
                "case.rs",
                "fn f(a: bool, b: bool) { if a {} else if b {} }",
                "if_expression",
            ),
            (
                Language::Kotlin,
                "case.kt",
                "fun f(a: Boolean, b: Boolean) { if (a) {} else if (b) {} }",
                "if_expression",
            ),
        ] {
            let tree = parse(source, language, path);
            let nodes = collect_nodes_by_kind(tree.root_node(), kind);
            assert_eq!(nodes.len(), 2);
            assert!(!is_chain_child(nodes[0]));
            assert!(is_chain_child(nodes[1]), "{source}");
            let arms = collect_arms(nodes[0], language, &mut BranchWorkBudget::new()).unwrap();
            assert_eq!(arms.len(), 2, "{source}");
            assert!(arms.iter().all(|arm| arm.condition.is_some()));
            if language == Language::Kotlin {
                let alternative = nodes[0].child_by_field_name("alternative").unwrap();
                assert_eq!(alternative.kind(), "control_structure_body");
                assert_eq!(alternative.named_child_count(), 1);
                assert_eq!(kotlin_else_if(alternative), Some(nodes[1]));
            }
        }
    }

    #[test]
    fn ruby_position_values_and_method_boundaries_follow_the_grammar() {
        use brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind;
        let source = "if flag\n def f\n __LINE__\n end\nelse\n def g\n __LINE__\n end\nend\ncase x\nin __LINE__\n true\nend\ncase y\nin __LINE__\n false\nend";
        let tree = parse(source, Language::Ruby, "case.rb");
        // Pattern literals and ordinary expression identifiers have distinct
        // grammar shapes even though both evaluate to the source line.
        let mut stack = vec![tree.root_node()];
        let mut lines = Vec::new();
        while let Some(node) = stack.pop() {
            if node.kind() == "line" {
                lines.push(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
        assert_eq!(lines.len(), 2, "{}", tree.root_node().to_sexp());
        for line in lines {
            assert_eq!(&source[line.byte_range()], "__LINE__");
            assert!(position_dependent(line, Language::Ruby, source));
        }
        let methods = collect_nodes_by_kind(tree.root_node(), "method");
        assert_eq!(methods.len(), 2);
        for method in methods {
            assert!(method.child_by_field_name("name").is_some());
            assert!(is_nested_callable(method, Language::Ruby));
        }
    }

    fn prepared(source: &str, tree: Tree, language: Language, path: &str) -> PreparedSyntaxTree {
        use brokk_bifrost_core::analyzer::prepared_syntax::{
            PreparedSourceOrigin, PreparedSyntaxSource,
        };
        PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(source.into()),
            tree,
            crate::text_utils::compute_line_starts(source),
            crate::analyzer::LanguageDialect::for_path(language, Path::new(path)),
            PreparedSourceOrigin::Disk,
            None,
        )
    }

    #[test]
    fn primitive_condition_operators_match_their_literal_domains() {
        use brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind;
        for condition in [
            "true",
            "!false",
            "1 < 2",
            "true == false",
            "1 == 2",
            "true || false",
            "!(true || false)",
        ] {
            let source = format!("if ({condition}) () else ()");
            let tree = parse(&source, Language::Scala, "case.scala");
            let node = collect_nodes_by_kind(tree.root_node(), "if_expression")[0]
                .child_by_field_name("condition")
                .unwrap();
            let env = environment(&source, tree.root_node(), &[]);
            assert_eq!(
                scala_condition_stability(node, &source, &env, &mut BranchWorkBudget::new()),
                BranchRelationVerdict::Proven,
                "{condition}"
            );
        }
        for condition in ["!true", "!(true || false)"] {
            let source = format!("class C {{ void f() {{ if ({condition}) {{}} }} }}");
            let tree = parse(&source, Language::Java, "Case.java");
            let env = environment(&source, tree.root_node(), &[]);
            let syntax = prepared(&source, tree, Language::Java, "Case.java");
            let node = collect_nodes_by_kind(syntax.tree().root_node(), "if_statement")[0]
                .child_by_field_name("condition")
                .unwrap();
            assert_eq!(
                java_primitive_condition_stability(
                    node,
                    &syntax,
                    &env,
                    &mut BranchWorkBudget::new()
                ),
                BranchRelationVerdict::Proven
            );
        }
        for condition in ["true", "!false", "(true)"] {
            let source = format!("fn f() {{ if {condition} {{}} }}");
            let tree = parse(&source, Language::Rust, "case.rs");
            let node = collect_nodes_by_kind(tree.root_node(), "if_expression")[0]
                .child_by_field_name("condition")
                .unwrap();
            let env = environment(&source, tree.root_node(), &[]);
            assert_eq!(
                rust_boolean_expression_bounded(node, &env, &source, &mut BranchWorkBudget::new()),
                Ok(true)
            );
        }
    }

    #[test]
    fn scala_callable_grammar_separates_eager_and_deferred_parameters() {
        use brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind;
        for (source, kind, exact) in [
            ("val f = (x: Int) => x", "lambda_expression", true),
            ("def f(x: Int): Int = x", "function_definition", true),
            ("def f(x: => Int): Int = x", "function_definition", false),
        ] {
            let tree = parse(source, Language::Scala, "case.scala");
            let nodes = collect_nodes_by_kind(tree.root_node(), kind);
            assert_eq!(nodes.len(), 1);
            let env = environment(source, tree.root_node(), &[]);
            assert_eq!(
                scala_nested_callable_is_exact(
                    nodes[0],
                    nodes[0],
                    &env,
                    &mut BranchWorkBudget::new()
                )
                .unwrap(),
                exact,
                "{source}"
            );
        }
    }

    #[test]
    fn ruby_branch_children_are_complete_or_budget_exceeded() {
        let source = "if flag\n # comment\n caf\u{e9} = 1; ping()\n if other\n nested()\n end\nelse\n # spare\n caf\u{e9} = 2\nend";
        let tree = parse(source, Language::Ruby, "case.rb");
        let branch = tree.root_node().named_child(0).unwrap();
        for (field, kind, grammar_children, expected_statements) in [
            (
                "consequence",
                "then",
                vec![
                    ("assignment", true, false, 20..29),
                    (";", false, false, 29..30),
                    ("call", true, false, 31..37),
                    ("if", true, false, 39..62),
                ],
                vec![(20, 29), (31, 37), (39, 62)],
            ),
            (
                "alternative",
                "else",
                vec![
                    ("else", false, false, 63..67),
                    ("comment", true, true, 69..76),
                    ("assignment", true, false, 78..87),
                ],
                vec![(78, 87)],
            ),
        ] {
            let arm = branch.child_by_field_name(field).unwrap();
            assert_eq!(arm.kind(), kind);
            let mut cursor = arm.walk();
            assert_eq!(
                arm.children(&mut cursor)
                    .map(|child| (
                        child.kind(),
                        child.is_named(),
                        child.is_extra(),
                        child.byte_range(),
                    ))
                    .collect::<Vec<_>>(),
                grammar_children
            );

            let cost = grammar_children.len();
            for steps in 0..=cost + 1 {
                for pending in [
                    0,
                    MAX_COMPARISON_TREE_NODES - cost,
                    MAX_COMPARISON_TREE_NODES - cost + 1,
                ] {
                    let mut budget = BranchWorkBudget {
                        ledger: BudgetLedger::with_zero_usage(BranchWork {
                            steps,
                            ..BranchWork::default_limits()
                        }),
                        exhausted: false,
                    };
                    let answer = bounded_named_statements(arm, pending, &mut budget);
                    if steps < cost || pending + cost > MAX_COMPARISON_TREE_NODES {
                        assert_eq!(
                            answer.unwrap_err(),
                            BranchOpenReason::ComparisonBudget,
                            "{kind}, steps={steps}, pending={pending}"
                        );
                    } else {
                        assert_eq!(
                            answer
                                .unwrap()
                                .iter()
                                .map(|node| (node.start_byte(), node.end_byte()))
                                .collect::<Vec<_>>(),
                            expected_statements
                        );
                    }
                }
            }
        }
        // A wide arm must be refused before retaining a prefix, even with an
        // otherwise ample ledger. This is independent of the frontier bound.
        let wide_source = format!(
            "if flag\n{}end",
            "ping()\n".repeat(MAX_COMPARISON_TREE_NODES + 1)
        );
        let wide = parse(&wide_source, Language::Ruby, "wide.rb");
        let arm = wide
            .root_node()
            .named_child(0)
            .unwrap()
            .child_by_field_name("consequence")
            .unwrap();
        assert_eq!(arm.child_count(), MAX_COMPARISON_TREE_NODES + 1);
        assert_eq!(
            bounded_named_statements(arm, 0, &mut BranchWorkBudget::new()).unwrap_err(),
            BranchOpenReason::ComparisonBudget
        );
    }

    #[test]
    fn php_capture_and_class_ancestors_follow_grammar_boundaries() {
        let source = "<?php\n$a = function() use (&$caf\u{e9}) { /* ref */ if ($x) { yes(); } };\n$b = function() use ($caf\u{e9}) { /* value */ if ($x) { yes(); } };\n$c = fn() => $x ? yes() : no();\n$d = new class { function run() { /* class */ if ($x) { yes(); } } };\n";
        let tree = parse(source, Language::Php, "case.php");
        use brokk_bifrost_core::analyzer::exception_handling::collect_nodes_by_kind;
        let root = tree.root_node();
        let closures = collect_nodes_by_kind(root, "anonymous_function");
        assert_eq!(closures.len(), 2);
        for (closure, capture_kind, capture_range, variable_range, clause_range) in [
            (closures[0], "by_ref", 27..34, 28..34, 22..35),
            (closures[1], "variable_name", 91..97, 91..97, 86..98),
        ] {
            assert_eq!(
                closure.child_by_field_name("parameters").unwrap().kind(),
                "formal_parameters"
            );
            assert_eq!(
                closure.child_by_field_name("body").unwrap().kind(),
                "compound_statement"
            );
            let mut cursor = closure.walk();
            let clause = closure
                .named_children(&mut cursor)
                .find(|node| node.kind() == "anonymous_function_use_clause")
                .unwrap();
            assert_eq!(clause.byte_range(), clause_range);
            assert_eq!(clause.named_child_count(), 1);
            let capture = clause.named_child(0).unwrap();
            assert_eq!(
                (capture.kind(), capture.byte_range()),
                (capture_kind, capture_range)
            );
            let variable = if capture_kind == "by_ref" {
                assert_eq!(capture.child(0).unwrap().kind(), "&");
                capture.named_child(0).unwrap()
            } else {
                capture
            };
            assert_eq!(
                (variable.kind(), variable.byte_range()),
                ("variable_name", variable_range)
            );
            assert_eq!(&source[variable.byte_range()], "$caf\u{e9}");
        }
        let mut conditionals = collect_nodes_by_kind(root, "if_statement");
        conditionals.extend(collect_nodes_by_kind(root, "conditional_expression"));
        conditionals.sort_by_key(Node::start_byte);
        assert_eq!(conditionals.len(), 4);
        for (node, (kind, ancestors, unsupported)) in conditionals.into_iter().zip([
            (
                "if_statement",
                vec![
                    "compound_statement",
                    "anonymous_function",
                    "assignment_expression",
                    "expression_statement",
                    "program",
                ],
                true,
            ),
            (
                "if_statement",
                vec![
                    "compound_statement",
                    "anonymous_function",
                    "assignment_expression",
                    "expression_statement",
                    "program",
                ],
                false,
            ),
            (
                "conditional_expression",
                vec![
                    "arrow_function",
                    "assignment_expression",
                    "expression_statement",
                    "program",
                ],
                false,
            ),
            (
                "if_statement",
                vec![
                    "compound_statement",
                    "method_declaration",
                    "declaration_list",
                    "anonymous_class",
                    "object_creation_expression",
                    "assignment_expression",
                    "expression_statement",
                    "program",
                ],
                true,
            ),
        ]) {
            assert_eq!(node.kind(), kind);
            assert!(node.child_by_field_name("condition").is_some());
            let mut actual = Vec::new();
            let mut parent = node.parent();
            while let Some(ancestor) = parent {
                actual.push(ancestor.kind());
                parent = ancestor.parent();
            }
            assert_eq!(actual, ancestors);
            assert_eq!(php_unsupported_lexical_ancestor(node), unsupported);
        }
    }
    #[test]
    fn compared_tree_node_allowance_matches_grammar_walk() {
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        for expected in [4095, 4096, 4097] {
            let elements = (expected - 4) / 2;
            let source = format!(
                "[{}{}]",
                vec!["0"; elements].join(","),
                if expected % 2 == 1 { "," } else { "" }
            );
            let tree = parse(&source, Language::Python, "case.py");
            let root = tree.root_node();
            let mut nodes = vec![root];
            let mut count = 0;
            while let Some(node) = nodes.pop() {
                count += 1;
                let mut cursor = node.walk();
                nodes.extend(node.children(&mut cursor));
            }
            assert_eq!(count, expected);
            let env = environment(&source, root, &[]);
            let members = BranchReferenceProofs::default();
            let chain = Chain {
                language: Language::Python,
                owner: node_range(root),
                source: &source,
                env: &env,
                members: &members,
                condition_binders: &[],
            };
            assert_eq!(
                compare_trees(root, root, &chain, &mut BranchWorkBudget::new()),
                if count <= MAX_COMPARISON_TREE_NODES {
                    BranchRelationVerdict::Proven
                } else {
                    BranchRelationVerdict::Open(BranchOpenReason::ComparisonBudget)
                },
                "{count} grammar nodes"
            );
        }
    }
}
