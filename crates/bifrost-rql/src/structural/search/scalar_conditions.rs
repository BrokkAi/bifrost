//! Procedure-local scalar outcomes for structured conditional guards.
//!
//! Call once per materialized procedure with the prepared syntax from the
//! same snapshot, then join these outcomes to the exact structured condition
//! or comparison-operator span. A missing scalar fact remains open.

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_flow::scalar_state::{
    ScalarCallEffects, ScalarStateDerivation, ScalarTyping, go_scalar_seeds, guard_decides,
    java_scalar_seeds,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use crate::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use crate::analyzer::semantic::{
    ControlEdgeId, ControlEdgeKind, EvidenceCompleteness, EvidenceId, GuardFact, GuardPredicate,
    MemoryLocationKind, ProcedureHandle, ProcedureSemantics, ProgramPointId, ProofStatus,
    SemanticCapability, SemanticGapDischarge, SemanticGapImpact, SemanticGapSubject,
    SemanticValueKind, SourceMappingKind,
};
use crate::analyzer::{Language, LanguageDialect, ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;

// The scalar solver retains one value vector per reachable program point and
// revisits joins to a finite widening limit. Bound its matrix before entering
// the non-cancellable derivation, then check cancellation again on return.
const MAX_SCALAR_MATRIX_CELLS: usize = 250_000;
const MAX_SCALAR_CONTROL_EDGES: usize = 50_000;
const MAX_COMPOSED_CONDITIONS: usize = 1_024;
const MAX_COMPOSED_LEAVES: usize = 32;
const MAX_COMPOSED_NODES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScalarConditionGap {
    UnsupportedPredicate,
    UnprovenGuard,
    PartialGuard,
    MissingArm,
    UnreachableDecision,
    UnknownScalar,
    PartialProcedure,
    PartialProducer,
    InexactSource,
    StaleSource,
    Cancelled,
    WorkLimit,
    IncompleteCondition,
    UnqualifiedContinuation,
}

impl ScalarConditionGap {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedPredicate => "unsupported_predicate",
            Self::UnprovenGuard => "unproven_guard",
            Self::PartialGuard => "partial_guard",
            Self::MissingArm => "missing_arm",
            Self::UnreachableDecision => "unreachable_decision",
            Self::UnknownScalar => "unknown_scalar",
            Self::PartialProcedure => "partial_procedure",
            Self::PartialProducer => "partial_producer",
            Self::InexactSource => "inexact_source",
            Self::StaleSource => "stale_source",
            Self::Cancelled => "cancelled",
            Self::WorkLimit => "work_limit",
            Self::IncompleteCondition => "incomplete_condition",
            Self::UnqualifiedContinuation => "unqualified_continuation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScalarConditionVerdict {
    AlwaysFalse,
    AlwaysTrue,
    BothFeasible,
    Open(ScalarConditionGap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScalarConditionOutcome {
    pub(super) condition_start_byte: usize,
    pub(super) condition_end_byte: usize,
    pub(super) verdict: ScalarConditionVerdict,
}

fn complete_evidence(semantics: &ProcedureSemantics, id: EvidenceId) -> bool {
    let evidence = semantics
        .evidence_row(id)
        .expect("validated semantic row owns its evidence");
    matches!(&evidence.proof, ProofStatus::Proven)
        && matches!(&evidence.completeness, EvidenceCompleteness::Complete)
}

/// Whether the scalar solver models `predicate` as `language`'s producer
/// publishes it. Each language publishes numeric guards only for operands it
/// can structurally type, so the predicate list itself is shared; truth
/// tests exist only where a condition is read for its truth.
fn supported_scalar_guard(
    language: Language,
    semantics: &ProcedureSemantics,
    predicate: GuardPredicate,
) -> bool {
    let scalar_constant = |constant| {
        semantics.value(constant).is_some_and(|value| {
            matches!(
                value.kind,
                SemanticValueKind::UnsignedInteger(_)
                    | SemanticValueKind::SignedInteger(_)
                    | SemanticValueKind::FloatingPoint { .. }
                    | SemanticValueKind::Null
            )
        })
    };
    let numeric = || match predicate {
        GuardPredicate::ConstantBoolean { .. }
        | GuardPredicate::NullComparison { .. }
        | GuardPredicate::OrderedIntegerComparison { .. }
        | GuardPredicate::OrderedFloatComparison { .. }
        | GuardPredicate::NanComparison { .. } => true,
        GuardPredicate::ConstantEquality { constant, .. } => scalar_constant(constant),
        GuardPredicate::InstanceOf { .. }
        | GuardPredicate::ExactClass { .. }
        | GuardPredicate::HasMember { .. }
        | GuardPredicate::Truthy { .. }
        | GuardPredicate::Opaque { .. } => false,
    };
    match language {
        Language::Java | Language::Go => {
            numeric() || matches!(predicate, GuardPredicate::Truthy { .. })
        }
        Language::JavaScript | Language::TypeScript | Language::Python => {
            numeric() || matches!(predicate, GuardPredicate::Truthy { .. })
        }
        _ => matches!(predicate, GuardPredicate::NullComparison { .. }),
    }
}

/// Derive the procedure's scalar states with the numeric typing its language
/// establishes. Java seeds declared primitive formals and types every
/// primitive local and formal. JavaScript and TypeScript numbers are binary64
/// everywhere. Python integers are unbounded and its bindings untyped. Go
/// types declared and literal-initialized integer and Boolean bindings and
/// keeps no numeric fact for any other.
fn derive_scalar_states(
    language: Language,
    procedure: &ProcedureHandle,
    prepared: &PreparedSyntaxTree,
) -> ScalarStateDerivation {
    match language {
        Language::Java => {
            let seeds = java_scalar_seeds(procedure, prepared);
            ScalarStateDerivation::derive_typed(
                procedure,
                ScalarCallEffects::default(),
                &seeds.entry_facts,
                &seeds.typing,
            )
        }
        Language::Go => {
            let seeds = go_scalar_seeds(procedure, prepared);
            ScalarStateDerivation::derive_typed(
                procedure,
                ScalarCallEffects::default(),
                &seeds.entry_facts,
                &seeds.typing,
            )
        }
        Language::JavaScript | Language::TypeScript => ScalarStateDerivation::derive_typed(
            procedure,
            ScalarCallEffects::default(),
            &[],
            &ScalarTyping::dynamic_binary64(),
        ),
        _ => ScalarStateDerivation::derive(procedure),
    }
}

/// Whether the solver's fact at a reachable guard decides its predicate, so
/// that two feasible arms are a result rather than missing information.
fn guard_is_decided(
    procedure: &ProcedureHandle,
    scalar: &ScalarStateDerivation,
    guard: &GuardFact,
) -> bool {
    scalar
        .guard_operand_fact(procedure, guard)
        .is_some_and(|fact| guard_decides(procedure.semantics(), guard.predicate, fact))
}

/// Derive outcomes for every guard in one procedure: null identity, constant
/// conditions, and numeric order, equality, NaN and truth tests, each
/// qualified by the language's supported predicates. Short-circuit
/// conditions of an `if` compose their operands' guards. Other shapes stay
/// explicitly open.
pub(super) fn scalar_condition_outcomes(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    procedure: &ProcedureHandle,
    prepared: Arc<PreparedSyntaxTree>,
    cancellation: &CancellationToken,
) -> Result<Vec<ScalarConditionOutcome>, ScalarConditionGap> {
    if cancellation.is_cancelled() {
        return Err(ScalarConditionGap::Cancelled);
    }
    let prepared =
        validate_prepared_syntax_source_for_procedure(workspace, procedure, file, prepared)
            .map_err(|_| ScalarConditionGap::StaleSource)?;
    let language = prepared.dialect().language();
    let semantics = procedure.semantics();
    if semantics
        .points()
        .len()
        .saturating_mul(semantics.values().len())
        > MAX_SCALAR_MATRIX_CELLS
        || semantics.control_edges().len() > MAX_SCALAR_CONTROL_EDGES
    {
        return Err(ScalarConditionGap::WorkLimit);
    }
    // The language capability table is intentionally partial even for simple
    // methods. Producer-authored gaps, rather than that global table, record
    // the missing procedure-local control and value effects relevant to a
    // negative reachability proof.
    // An unresolved call or callable reference leaves its own result and
    // dispatch open, but in Java, JavaScript/TypeScript and Python it cannot
    // rebind a caller local: none has by-reference arguments, and captured
    // or escaped locals are already outside the solver's closed cells. A Go
    // local whose address reaches a call is likewise outside them. Such a
    // gap therefore does not open every guard in the procedure. A value gap on
    // a binding itself still does, because the solver would otherwise refine
    // that binding as if its value were known.
    let scoped_call_gap = |gap: &crate::analyzer::semantic::SemanticGap| {
        // A procedure-level suspension gap describes how callers construct
        // and schedule a generator or coroutine activation. Inside the body,
        // each suspension is lowered as a scaffold or as its own point gap.
        if matches!(
            gap.capability,
            SemanticCapability::GeneratorSuspension | SemanticCapability::AsyncSuspendResume
        ) && gap.subject == SemanticGapSubject::Procedure
        {
            return true;
        }
        // Java field access cannot rebind a method local, and the solver
        // treats every heap-loaded value as unknown. In JavaScript and Python,
        // accessors or descriptors may execute code, so retain their memory
        // gaps until those effects are modeled at the access point.
        if semantics.locator().language() == LanguageDialect::Standard(Language::Java)
            && let SemanticGapSubject::MemoryLocation(location) = gap.subject
            && gap.impacts.iter().all(|impact| {
                matches!(
                    impact,
                    SemanticGapImpact::ValueFlow
                        | SemanticGapImpact::HeapRead
                        | SemanticGapImpact::HeapWrite
                        | SemanticGapImpact::Aliasing
                )
            })
            && semantics.memory_location(location).is_some_and(|location| {
                !matches!(
                    location.kind,
                    MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
                )
            })
        {
            return true;
        }
        // A yield's normal resumption edge is retained, the solver releases
        // shared bindings there, and its abrupt resumption is a separate
        // exceptional gap at the same point, judged by the rule below.
        if gap.capability == SemanticCapability::GeneratorSuspension
            && gap.subject == SemanticGapSubject::Point
        {
            return true;
        }
        // An exceptional gap whose omitted paths leave the procedure without
        // running more of its code reaches no guard.
        if gap.capability == SemanticCapability::ExceptionalControlFlow
            && gap.subject == SemanticGapSubject::Point
            && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
        {
            return true;
        }
        // An exception dispatch that retains every handler and the
        // unmatched propagation as successors only leaves the selection
        // among them unrefined, which over-approximates the paths.
        if gap.capability == SemanticCapability::ExceptionalControlFlow
            && gap.subject == SemanticGapSubject::Point
            && gap.discharge == SemanticGapDischarge::RetainedControlTopology
        {
            return true;
        }
        // A binding a nested callable rebinds is released by the solver at
        // every call and suspension, where that callable could run.
        // Unmodeled captured inputs are read through capture locations, which
        // the solver never treats as closed cells, so such a gap cannot
        // change a local this procedure establishes.
        if gap.capability == SemanticCapability::Captures
            && matches!(
                gap.subject,
                SemanticGapSubject::Procedure
                    | SemanticGapSubject::MemoryLocation(_)
                    | SemanticGapSubject::Capture(_)
            )
        {
            return true;
        }
        if gap.capability == SemanticCapability::Captures
            && gap.discharge == SemanticGapDischarge::RebindAtCallOrSuspension
            && let SemanticGapSubject::Value(value) = gap.subject
            && semantics.value(value).is_some_and(|value| {
                matches!(
                    value.kind,
                    SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
                )
            })
        {
            return true;
        }
        matches!(
            gap.capability,
            SemanticCapability::Calls
                | SemanticCapability::CallableReferences
                | SemanticCapability::DynamicDispatch
        ) && gap.impacts.iter().all(|impact| {
            matches!(
                impact,
                SemanticGapImpact::ValueFlow
                    | SemanticGapImpact::Aliasing
                    | SemanticGapImpact::DispatchCoverage
            )
        }) && match gap.subject {
            SemanticGapSubject::CallSite(_) => true,
            SemanticGapSubject::Value(value) => !matches!(
                semantics.value(value).map(|value| &value.kind),
                Some(
                    SemanticValueKind::Local
                        | SemanticValueKind::Parameter { .. }
                        | SemanticValueKind::Receiver { .. }
                )
            ),
            _ => false,
        }
    };
    let partial_procedure = semantics
        .gaps()
        .iter()
        .filter(|gap| !scoped_call_gap(gap))
        .any(|gap| {
            matches!(
                gap.capability,
                SemanticCapability::NormalControlFlow
                    | SemanticCapability::ExceptionalControlFlow
                    | SemanticCapability::CleanupControlFlow
                    | SemanticCapability::NonLocalControl
                    | SemanticCapability::Assignments
                    | SemanticCapability::Values
                    | SemanticCapability::LocalFlow
                    | SemanticCapability::ParameterFlow
                    | SemanticCapability::GuardFacts
            ) || gap.impacts.contains(SemanticGapImpact::ValueFlow)
                || gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        });
    let partial_producer = semantics.points().iter().any(|point| {
        !complete_evidence(semantics, point.evidence)
            || point
                .events
                .iter()
                .any(|event| !complete_evidence(semantics, event.evidence))
    }) || semantics
        .control_edges()
        .iter()
        .any(|edge| !complete_evidence(semantics, edge.evidence))
        || semantics
            .values()
            .iter()
            .any(|value| !complete_evidence(semantics, value.evidence))
        || semantics
            .guard_facts()
            .iter()
            .any(|guard| !complete_evidence(semantics, guard.evidence));
    let scalar = (!partial_procedure && !partial_producer)
        .then(|| derive_scalar_states(language, procedure, &prepared));
    if cancellation.is_cancelled() {
        return Err(ScalarConditionGap::Cancelled);
    }
    let mut outcomes = semantics
        .guard_facts()
        .iter()
        .map(|guard| {
            let mapping = semantics
                .source_mapping(guard.source)
                .expect("validated guard owns its source mapping");
            let span = mapping.locator.anchor().span();
            let verdict = if mapping.kind != SourceMappingKind::Exact {
                ScalarConditionVerdict::Open(ScalarConditionGap::InexactSource)
            } else if partial_procedure {
                ScalarConditionVerdict::Open(ScalarConditionGap::PartialProcedure)
            } else if partial_producer {
                ScalarConditionVerdict::Open(ScalarConditionGap::PartialProducer)
            } else if !supported_scalar_guard(language, semantics, guard.predicate) {
                ScalarConditionVerdict::Open(ScalarConditionGap::UnsupportedPredicate)
            } else {
                let evidence = semantics
                    .evidence_row(guard.evidence)
                    .expect("validated guard owns its evidence");
                match (&evidence.proof, &evidence.completeness) {
                    (ProofStatus::Unproven(_), _) => {
                        ScalarConditionVerdict::Open(ScalarConditionGap::UnprovenGuard)
                    }
                    (_, EvidenceCompleteness::Partial(_)) => {
                        ScalarConditionVerdict::Open(ScalarConditionGap::PartialGuard)
                    }
                    (ProofStatus::Proven, EvidenceCompleteness::Complete) => single_guard_verdict(
                        procedure,
                        scalar.as_ref().expect("partial producer is open"),
                        guard,
                    ),
                }
            };
            ScalarConditionOutcome {
                condition_start_byte: span.start_byte() as usize,
                condition_end_byte: span.end_byte() as usize,
                verdict,
            }
        })
        .collect::<Vec<_>>();
    let composed = ComposedConditions {
        prepared: &prepared,
        procedure,
        language,
        scalar: scalar.as_ref(),
        partial_procedure,
        partial_producer,
        cancellation,
    };
    match language {
        Language::Java => outcomes.extend(composed.outcomes(&JavaConditionSyntax)?),
        Language::JavaScript | Language::TypeScript => {
            outcomes.extend(composed.outcomes(&JsTsConditionSyntax)?);
        }
        Language::Python => outcomes.extend(composed.outcomes(&PythonConditionSyntax)?),
        Language::Go => {
            let negation_guards = semantics
                .guard_facts()
                .iter()
                .map(|guard| {
                    let span = semantics
                        .source_mapping(guard.source)
                        .expect("validated guard owns its source mapping")
                        .locator
                        .anchor()
                        .span();
                    (span.start_byte() as usize, span.end_byte() as usize)
                })
                .collect();
            outcomes.extend(composed.outcomes(&GoConditionSyntax { negation_guards })?);
        }
        _ => {}
    }
    Ok(outcomes)
}

fn single_guard_verdict(
    procedure: &ProcedureHandle,
    scalar: &ScalarStateDerivation,
    guard: &GuardFact,
) -> ScalarConditionVerdict {
    if let GuardPredicate::ConstantBoolean { value } = guard.predicate {
        return if !scalar.is_reachable(guard.point) {
            ScalarConditionVerdict::Open(ScalarConditionGap::UnreachableDecision)
        } else if value {
            ScalarConditionVerdict::AlwaysTrue
        } else {
            ScalarConditionVerdict::AlwaysFalse
        };
    }
    let (Some(when_true), Some(when_false), Some(_)) =
        (guard.true_edge, guard.false_edge, guard.subject)
    else {
        return ScalarConditionVerdict::Open(ScalarConditionGap::MissingArm);
    };
    if !scalar.is_reachable(guard.point) {
        return ScalarConditionVerdict::Open(ScalarConditionGap::UnreachableDecision);
    }
    if !guard_is_decided(procedure, scalar, guard) {
        return ScalarConditionVerdict::Open(ScalarConditionGap::UnknownScalar);
    }
    match (
        scalar.edge_is_feasible(when_true),
        scalar.edge_is_feasible(when_false),
    ) {
        (false, true) => ScalarConditionVerdict::AlwaysFalse,
        (true, false) => ScalarConditionVerdict::AlwaysTrue,
        (true, true) => ScalarConditionVerdict::BothFeasible,
        (false, false) => ScalarConditionVerdict::Open(ScalarConditionGap::UnreachableDecision),
    }
}

fn node_span(node: Node<'_>) -> (usize, usize) {
    (node.start_byte(), node.end_byte())
}

fn peel_parentheses(mut node: Node<'_>) -> Result<Node<'_>, ScalarConditionGap> {
    let mut layers = 0_usize;
    while node.kind() == "parenthesized_expression" && node.named_child_count() == 1 {
        layers += 1;
        if layers > MAX_COMPOSED_NODES {
            return Err(ScalarConditionGap::WorkLimit);
        }
        node = node.named_child(0).expect("one named expression child");
    }
    Ok(node)
}

/// The statement that follows `statement` in its enclosing block, which is
/// where the lowering sends a condition's false arm when there is no
/// alternative. A statement outside a block of `block_kind`, or the last one
/// in it, continues to a target that has no statement span of its own.
fn following_statement<'tree>(
    statement: Node<'tree>,
    block_kind: &str,
) -> Result<Node<'tree>, ScalarConditionGap> {
    if statement
        .parent()
        .is_none_or(|parent| parent.kind() != block_kind)
    {
        return Err(ScalarConditionGap::UnqualifiedContinuation);
    }
    let mut next = statement.next_named_sibling();
    while next.is_some_and(|sibling| sibling.is_extra()) {
        next = next.and_then(|sibling| sibling.next_named_sibling());
    }
    next.ok_or(ScalarConditionGap::UnqualifiedContinuation)
}

/// How one condition node lowers: as a short-circuit operator whose operands
/// are separate decisions, as a negation that only swaps its operand's arms,
/// or as one decision.
enum ConditionShape<'tree> {
    ShortCircuit {
        left: Option<Node<'tree>>,
        right: Option<Node<'tree>>,
    },
    Negation(Option<Node<'tree>>),
    /// A chained comparison `a < x < b`: one decision per operator, each
    /// short-circuiting like `and` into the evaluation of the operand after
    /// its right-hand one.
    Chain(Node<'tree>),
    Leaf,
}

/// One language's syntax for a conditional statement whose condition may
/// short-circuit. Each adapter mirrors the language's CFG lowering: which
/// node owns a composable condition, which operators it splits into separate
/// decisions, and which source span each arm's target point carries.
trait ConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool;

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree>;

    /// The node whose span the guard for `leaf` carries.
    fn guard_anchor<'tree>(&self, leaf: Node<'tree>) -> Option<Node<'tree>> {
        Some(leaf)
    }

    /// The node whose span the target point of the owner's false arm carries.
    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap>;
}

struct JavaConditionSyntax;

impl ConditionSyntax for JavaConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_statement"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        c_family_shape(node)
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        match owner.child_by_field_name("alternative") {
            Some(alternative) => Ok(alternative),
            None => following_statement(owner, "block"),
        }
    }
}

/// JavaScript and TypeScript share the `if_statement` grammar. The lowering
/// sends the false arm to the first named child of an `else_clause`.
struct JsTsConditionSyntax;

impl ConditionSyntax for JsTsConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_statement"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        c_family_shape(node)
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        match owner.child_by_field_name("alternative") {
            Some(alternative) if alternative.kind() == "else_clause" => alternative
                .named_child(0)
                .ok_or(ScalarConditionGap::IncompleteCondition),
            Some(alternative) => Ok(alternative),
            None => following_statement(owner, "statement_block"),
        }
    }
}

/// Go splits `&&` and `||` like Java. Its lowering folds a negation into
/// the guard of a comparison it normalizes, and that guard carries the `!`
/// node's span; any other negation only swaps its operand's arms. The guard
/// spans of the procedure tell the two apart.
struct GoConditionSyntax {
    negation_guards: HashSet<(usize, usize)>,
}

impl ConditionSyntax for GoConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_statement"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "unary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "!")
            && !self.negation_guards.contains(&node_span(node))
        {
            return ConditionShape::Negation(node.child_by_field_name("operand"));
        }
        c_family_shape(node)
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        match owner.child_by_field_name("alternative") {
            Some(alternative) => Ok(alternative),
            None => following_statement(owner, "statement_list"),
        }
    }
}

/// `&&` and `||` split into separate decisions; `!` is one decision.
fn c_family_shape(node: Node<'_>) -> ConditionShape<'_> {
    if node.kind() == "binary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(operator.kind(), "&&" | "||"))
    {
        ConditionShape::ShortCircuit {
            left: node.child_by_field_name("left"),
            right: node.child_by_field_name("right"),
        }
    } else {
        ConditionShape::Leaf
    }
}

/// Python composes `if` and `elif` conditions. A comparison's guard carries
/// its operator's span, and `not` swaps its operand's arms.
struct PythonConditionSyntax;

impl ConditionSyntax for PythonConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        matches!(node.kind(), "if_statement" | "elif_clause")
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        match node.kind() {
            "boolean_operator"
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| matches!(operator.kind(), "and" | "or")) =>
            {
                ConditionShape::ShortCircuit {
                    left: node.child_by_field_name("left"),
                    right: node.child_by_field_name("right"),
                }
            }
            "not_operator" => ConditionShape::Negation(node.child_by_field_name("argument")),
            "comparison_operator"
                if {
                    let mut cursor = node.walk();
                    node.children_by_field_name("operators", &mut cursor)
                        .count()
                        > 1
                } =>
            {
                ConditionShape::Chain(node)
            }
            _ => ConditionShape::Leaf,
        }
    }

    fn guard_anchor<'tree>(&self, leaf: Node<'tree>) -> Option<Node<'tree>> {
        if leaf.kind() != "comparison_operator" {
            return Some(leaf);
        }
        let mut cursor = leaf.walk();
        let mut operators = leaf.children_by_field_name("operators", &mut cursor);
        match (operators.next(), operators.next()) {
            (Some(operator), None) => Some(operator),
            // A chained comparison is split into operator leaves by `shape`.
            _ => None,
        }
    }

    /// The lowering sends an `if` or `elif` condition's false arm to the next
    /// `elif` condition, else the `else` body, else the statement after the
    /// whole `if` statement.
    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        let statement = if owner.kind() == "elif_clause" {
            owner
                .parent()
                .ok_or(ScalarConditionGap::IncompleteCondition)?
        } else {
            owner
        };
        let mut cursor = statement.walk();
        let next = statement
            .children_by_field_name("alternative", &mut cursor)
            .find(|alternative| alternative.start_byte() > owner.start_byte());
        match next {
            Some(alternative) if alternative.kind() == "elif_clause" => alternative
                .child_by_field_name("condition")
                .ok_or(ScalarConditionGap::IncompleteCondition),
            Some(alternative) if alternative.kind() == "else_clause" => alternative
                .child_by_field_name("body")
                .ok_or(ScalarConditionGap::IncompleteCondition),
            Some(_) => Err(ScalarConditionGap::IncompleteCondition),
            None => following_statement(statement, "block"),
        }
    }
}

/// One operand decision of a short-circuit condition. `entry` is the node
/// whose span the lowering gives the point where evaluating the operand
/// begins: an enclosing right operand, parenthesis or negation starts at the
/// same point as its first operand.
#[derive(Clone, Copy)]
struct ConditionLeaf<'tree> {
    node: Node<'tree>,
    entry: Node<'tree>,
}

/// Split a condition the lowering decomposes (a short-circuit operator or a
/// negation) into its operand decisions; `None` for a single decision, whose
/// own guard outcome already covers it. Check leaf coverage from syntax;
/// branch truth is still decided solely by semantic CFG edges and the scalar
/// solver. The explicit stack bounds nesting.
fn composed_leaves<'tree>(
    syntax: &impl ConditionSyntax,
    condition: Node<'tree>,
) -> Result<Option<(Node<'tree>, Vec<ConditionLeaf<'tree>>)>, ScalarConditionGap> {
    let condition = peel_parentheses(condition)?;
    let mut stack = vec![(condition, condition)];
    let mut leaves = Vec::new();
    let mut composed = false;
    let mut visited = 0_usize;
    while let Some((node, entry)) = stack.pop() {
        visited += 1;
        if visited > MAX_COMPOSED_NODES {
            return Err(ScalarConditionGap::WorkLimit);
        }
        let node = peel_parentheses(node)?;
        if node.has_error() {
            return Err(ScalarConditionGap::InexactSource);
        }
        match syntax.shape(node) {
            ConditionShape::ShortCircuit { left, right } => {
                let (Some(left), Some(right)) = (left, right) else {
                    return Err(ScalarConditionGap::IncompleteCondition);
                };
                composed = true;
                stack.push((right, right));
                stack.push((left, entry));
            }
            ConditionShape::Negation(operand) => {
                let operand = operand.ok_or(ScalarConditionGap::IncompleteCondition)?;
                composed = true;
                stack.push((operand, entry));
            }
            ConditionShape::Chain(chain) => {
                // Mirror the lowering: operands are the named children and
                // decision `i` sends its true arm into the evaluation of
                // operand `i + 2`, where decision `i + 1` then follows.
                let mut cursor = chain.walk();
                let operators = chain
                    .children_by_field_name("operators", &mut cursor)
                    .collect::<Vec<_>>();
                let mut cursor = chain.walk();
                let operands = chain
                    .named_children(&mut cursor)
                    .filter(|child| !child.is_extra())
                    .collect::<Vec<_>>();
                if operands.len() != operators.len() + 1 {
                    return Err(ScalarConditionGap::IncompleteCondition);
                }
                composed = true;
                for (index, operator) in operators.into_iter().enumerate() {
                    let entry = if index == 0 {
                        entry
                    } else {
                        operands[index + 1]
                    };
                    leaves.push(ConditionLeaf {
                        node: operator,
                        entry,
                    });
                }
            }
            ConditionShape::Leaf => leaves.push(ConditionLeaf { node, entry }),
        }
        if stack.len().saturating_add(leaves.len()) > MAX_COMPOSED_LEAVES {
            return Err(ScalarConditionGap::WorkLimit);
        }
    }
    Ok(composed.then_some((condition, leaves)))
}

/// The short-circuit edge lands at the next operand's entry, while its guard
/// decision may follow operand evaluation. Require a single complete normal
/// path contained in that exact operand entry before using its terminal arms.
/// A modeled exceptional escape does not complete the Boolean condition.
fn exact_entry_reaches_guard(
    semantics: &ProcedureSemantics,
    entry: ProgramPointId,
    entry_node: Node<'_>,
    guard: &GuardFact,
) -> bool {
    let mut current = entry;
    let mut seen = HashSet::new();
    while seen.len() < MAX_COMPOSED_NODES && seen.insert(current) {
        let point = semantics
            .point(current)
            .expect("validated control path owns its point");
        if !complete_evidence(semantics, point.evidence) {
            return false;
        }
        // The guard point is identified exactly. A chained comparison's
        // decision carries its operator's span, which precedes the operand
        // whose evaluation leads to it.
        if current == guard.point {
            return true;
        }
        let mapping = semantics
            .source_mapping(point.source)
            .expect("validated point owns its source mapping");
        let span = mapping.locator.anchor().span();
        if mapping.kind != SourceMappingKind::Exact
            || (span.start_byte() as usize) < entry_node.start_byte()
            || (span.end_byte() as usize) > entry_node.end_byte()
        {
            return false;
        }
        if current == guard.point {
            return true;
        }
        let mut normal = None;
        for (_, edge) in semantics.successor_edges(current) {
            if !complete_evidence(semantics, edge.evidence) {
                return false;
            }
            match edge.kind {
                ControlEdgeKind::Normal if normal.replace(edge.target_point).is_none() => {}
                ControlEdgeKind::Exceptional => {}
                _ => return false,
            }
        }
        let Some(next) = normal else {
            return false;
        };
        current = next;
    }
    false
}

/// The inputs shared by every composed condition of one procedure.
struct ComposedConditions<'a> {
    prepared: &'a PreparedSyntaxTree,
    procedure: &'a ProcedureHandle,
    language: Language,
    scalar: Option<&'a ScalarStateDerivation>,
    partial_procedure: bool,
    partial_producer: bool,
    cancellation: &'a CancellationToken,
}

impl ComposedConditions<'_> {
    fn outcomes(
        &self,
        syntax: &impl ConditionSyntax,
    ) -> Result<Vec<ScalarConditionOutcome>, ScalarConditionGap> {
        let semantics = self.procedure.semantics();
        let root = self.prepared.tree().root_node();
        let mut groups = HashMap::<(usize, usize), (Node<'_>, Vec<&GuardFact>)>::new();
        for guard in semantics.guard_facts() {
            if self.cancellation.is_cancelled() {
                return Err(ScalarConditionGap::Cancelled);
            }
            let mapping = semantics
                .source_mapping(guard.source)
                .expect("validated guard owns its source mapping");
            let span = mapping.locator.anchor().span();
            let (start, end) = (span.start_byte() as usize, span.end_byte() as usize);
            let Some(mut ancestor) = root.named_descendant_for_byte_range(start, end) else {
                continue;
            };
            let mut ascended = 0_usize;
            loop {
                ascended += 1;
                if ascended > MAX_COMPOSED_NODES {
                    return Err(ScalarConditionGap::WorkLimit);
                }
                if syntax.is_owner(ancestor)
                    && let Some(condition) = ancestor.child_by_field_name("condition")
                    && condition.start_byte() <= start
                    && end <= condition.end_byte()
                {
                    groups
                        .entry(node_span(condition))
                        .or_insert_with(|| (ancestor, Vec::new()))
                        .1
                        .push(guard);
                    break;
                }
                let Some(parent) = ancestor.parent() else {
                    break;
                };
                ancestor = parent;
            }
            if groups.len() > MAX_COMPOSED_CONDITIONS {
                return Err(ScalarConditionGap::WorkLimit);
            }
        }

        let mut outcomes = Vec::new();
        for (_, (owner, guards)) in groups {
            if self.cancellation.is_cancelled() {
                return Err(ScalarConditionGap::Cancelled);
            }
            let raw_condition = owner
                .child_by_field_name("condition")
                .expect("grouped owner has a condition");
            let (condition, leaves) = match composed_leaves(syntax, raw_condition) {
                Ok(Some(parts)) => parts,
                Ok(None) => continue,
                Err(gap) => {
                    let condition = peel_parentheses(raw_condition).unwrap_or(raw_condition);
                    outcomes.push(ScalarConditionOutcome {
                        condition_start_byte: condition.start_byte(),
                        condition_end_byte: condition.end_byte(),
                        verdict: ScalarConditionVerdict::Open(gap),
                    });
                    continue;
                }
            };
            let verdict = if self.partial_procedure {
                ScalarConditionVerdict::Open(ScalarConditionGap::PartialProcedure)
            } else if self.partial_producer {
                ScalarConditionVerdict::Open(ScalarConditionGap::PartialProducer)
            } else {
                self.qualify(syntax, owner, &leaves, &guards)
                    .unwrap_or_else(ScalarConditionVerdict::Open)
            };
            outcomes.push(ScalarConditionOutcome {
                condition_start_byte: condition.start_byte(),
                condition_end_byte: condition.end_byte(),
                verdict,
            });
        }
        Ok(outcomes)
    }

    /// Decide one short-circuit condition from its operand guards' edges.
    ///
    /// Every guard edge must land on the consequence, the false destination,
    /// or the exact entry of a later operand whose single normal path reaches
    /// that operand's guard; other outgoing edges must be exceptional. Then
    /// the edges into the consequence and false destination are the only
    /// normal exits of the condition, whatever negation sent each operand
    /// arm there, and their feasibility decides the whole condition.
    fn qualify(
        &self,
        syntax: &impl ConditionSyntax,
        owner: Node<'_>,
        leaves: &[ConditionLeaf<'_>],
        guards: &[&GuardFact],
    ) -> Result<ScalarConditionVerdict, ScalarConditionGap> {
        let semantics = self.procedure.semantics();
        let scalar = self
            .scalar
            .expect("complete procedure has scalar derivation");
        let incomplete = ScalarConditionGap::IncompleteCondition;
        if owner.has_error() || guards.len() != leaves.len() {
            return Err(incomplete);
        }
        let consequence = owner.child_by_field_name("consequence").ok_or(incomplete)?;
        let false_destination = syntax.false_destination(owner)?;
        if consequence.has_error() || false_destination.has_error() {
            return Err(ScalarConditionGap::InexactSource);
        }
        let mut ordered_guards = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let anchor = syntax.guard_anchor(leaf.node).ok_or(incomplete)?;
            let mut matched = guards.iter().filter(|guard| {
                let mapping = semantics
                    .source_mapping(guard.source)
                    .expect("validated guard owns its source mapping");
                mapping.kind == SourceMappingKind::Exact
                    && node_span(anchor)
                        == (
                            mapping.locator.anchor().span().start_byte() as usize,
                            mapping.locator.anchor().span().end_byte() as usize,
                        )
            });
            let (Some(guard), None) = (matched.next(), matched.next()) else {
                return Err(incomplete);
            };
            ordered_guards.push(**guard);
        }
        // An unsupported operand, such as a call, refines nothing, so both of
        // its arms stay feasible. That over-approximation keeps a fixed result
        // decided by the other operands sound; two feasible terminals still
        // require every reachable operand to be decided below.
        if !ordered_guards
            .iter()
            .any(|guard| supported_scalar_guard(self.language, semantics, guard.predicate))
        {
            return Err(ScalarConditionGap::UnsupportedPredicate);
        }
        if ordered_guards
            .iter()
            .any(|guard| !complete_evidence(semantics, guard.evidence))
        {
            return Err(ScalarConditionGap::PartialGuard);
        }
        if !scalar.is_reachable(ordered_guards[0].point) {
            return Err(ScalarConditionGap::UnreachableDecision);
        }

        let mut true_terminals = Vec::<ControlEdgeId>::new();
        let mut false_terminals = Vec::<ControlEdgeId>::new();
        let mut true_target = None;
        let mut false_target = None;
        for (index, guard) in ordered_guards.iter().enumerate() {
            let (Some(true_edge), Some(false_edge)) = (guard.true_edge, guard.false_edge) else {
                return Err(ScalarConditionGap::MissingArm);
            };
            let mut arms = 0_usize;
            for (edge_id, edge) in semantics.successor_edges(guard.point) {
                if edge_id == true_edge || edge_id == false_edge {
                    arms += 1;
                } else if edge.kind != ControlEdgeKind::Exceptional {
                    return Err(incomplete);
                }
            }
            if arms != 2 {
                return Err(incomplete);
            }
            for edge_id in [true_edge, false_edge] {
                let edge = semantics
                    .control_edge(edge_id)
                    .expect("validated guard arm owns a control edge");
                if edge.source_point != guard.point
                    || !matches!(
                        edge.kind,
                        ControlEdgeKind::ConditionalTrue | ControlEdgeKind::ConditionalFalse
                    )
                {
                    return Err(incomplete);
                }
                if !complete_evidence(semantics, edge.evidence) {
                    return Err(ScalarConditionGap::PartialProducer);
                }
                let point = semantics
                    .point(edge.target_point)
                    .expect("validated control edge owns its target point");
                if !complete_evidence(semantics, point.evidence) {
                    return Err(ScalarConditionGap::PartialProducer);
                }
                let mapping = semantics
                    .source_mapping(point.source)
                    .expect("validated target point owns its source mapping");
                if mapping.kind != SourceMappingKind::Exact {
                    return Err(ScalarConditionGap::UnqualifiedContinuation);
                }
                let span = mapping.locator.anchor().span();
                let target = (span.start_byte() as usize, span.end_byte() as usize);
                let (terminals, terminal_target) = if target == node_span(consequence) {
                    (&mut true_terminals, &mut true_target)
                } else if target == node_span(false_destination) {
                    (&mut false_terminals, &mut false_target)
                } else if leaves.iter().zip(&ordered_guards).skip(index + 1).any(
                    |(later, later_guard)| {
                        target == node_span(later.entry)
                            && exact_entry_reaches_guard(
                                semantics,
                                edge.target_point,
                                later.entry,
                                later_guard,
                            )
                    },
                ) {
                    // This edge evaluates exactly a later authored operand.
                    continue;
                } else {
                    return Err(ScalarConditionGap::UnqualifiedContinuation);
                };
                if terminal_target
                    .replace(edge.target_point)
                    .is_some_and(|prior| prior != edge.target_point)
                {
                    return Err(incomplete);
                }
                terminals.push(edge_id);
            }
        }
        if true_terminals.is_empty() || false_terminals.is_empty() {
            return Err(ScalarConditionGap::MissingArm);
        }
        let feasible = |edge_id: &ControlEdgeId| {
            let edge = semantics
                .control_edge(*edge_id)
                .expect("validated terminal edge exists");
            scalar.is_reachable(edge.source_point) && scalar.edge_is_feasible(*edge_id)
        };
        let true_feasible = true_terminals.iter().any(feasible);
        let false_feasible = false_terminals.iter().any(feasible);
        Ok(match (true_feasible, false_feasible) {
            (false, true) => ScalarConditionVerdict::AlwaysFalse,
            (true, false) => ScalarConditionVerdict::AlwaysTrue,
            (false, false) => ScalarConditionVerdict::Open(ScalarConditionGap::UnreachableDecision),
            (true, true) => {
                if ordered_guards
                    .iter()
                    .filter(|guard| scalar.is_reachable(guard.point))
                    .all(|guard| guard_is_decided(self.procedure, scalar, guard))
                {
                    ScalarConditionVerdict::BothFeasible
                } else {
                    ScalarConditionVerdict::Open(ScalarConditionGap::UnknownScalar)
                }
            }
        })
    }
}
