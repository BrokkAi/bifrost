//! Procedure-local scalar outcomes for structured conditional guards.
//!
//! Call once per materialized procedure with the prepared syntax from the
//! same snapshot, then join these outcomes to the exact structured condition
//! or comparison-operator span. A missing scalar fact remains open.

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::tree_walk::has_child_of_kind as has_direct_token;
use brokk_bifrost_flow::scalar_state::{
    ScalarCallEffects, ScalarStateDerivation, ScalarTyping, declared_scalar_seeds, guard_decides,
    java_scalar_seeds,
};
use brokk_bifrost_php_analysis::analyzer::php::php_declared_scalar_types;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use crate::analyzer::declared_scalar::{
    csharp_declared_scalar_types, go_declared_scalar_types, rust_declared_scalar_types,
};
use crate::analyzer::resolve_analyzer;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, Dominators, dominators,
};
use crate::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use crate::analyzer::semantic::{
    ControlEdgeId, ControlEdgeKind, EvidenceCompleteness, EvidenceId, GuardFact, GuardPredicate,
    MemoryLocationKind, ProcedureHandle, ProcedureSemantics, ProgramPointId, ProofStatus,
    SemanticCapability, SemanticEffect, SemanticGap, SemanticGapDischarge, SemanticGapImpact,
    SemanticGapSubject, SemanticValueKind, SourceMappingKind, ValueId,
};
use crate::analyzer::{Language, ProjectFile, WorkspaceAnalyzer};
use crate::analyzer::{kotlin_declared_scalar_types, scala_declared_scalar_types};
use crate::cancellation::CancellationToken;
use brokk_bifrost_flow::flow_state::{
    cleanup_has_retained_destination, destructor_style_cleanup, gap_has_exit_only_control,
    points_before_exit_only_exceptions,
};

// Language facts augment the predicate/typing table below. A new true entry
// requires checking the producer, including every by-reference argument form.
struct ScalarLanguageFacts {
    field_access_runs_no_user_code: bool,
    strict_call_operands_and_address_arguments: bool,
    destructor_style_cleanup: bool,
}

fn scalar_language_facts(language: Language) -> ScalarLanguageFacts {
    ScalarLanguageFacts {
        field_access_runs_no_user_code: matches!(language, Language::Java | Language::Rust),
        // Rust schedules operands exactly once and writes back explicit &mut
        // arguments; the scalar solver releases autoref receivers (#6409). C# ref/out
        // has not been checked; Scala admits by-name arguments.
        strict_call_operands_and_address_arguments: language == Language::Rust,
        destructor_style_cleanup: destructor_style_cleanup(language),
    }
}

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

/// Keep procedure attribution once per derivation, rather than cloning it for
/// every guard that the same preflight left open.
#[derive(Debug, Clone)]
pub(super) struct ScalarConditionDerivation {
    pub(super) outcomes: Vec<ScalarConditionOutcome>,
    pub(super) procedure_gaps: Vec<super::CodeQueryRelatedSource>,
    pub(super) producer_gaps: Vec<super::CodeQueryRelatedSource>,
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
            ) || (matches!(language, Language::Kotlin | Language::Cpp)
                && matches!(value.kind, SemanticValueKind::Boolean(_)))
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
        Language::Java
        | Language::Go
        | Language::CSharp
        | Language::Rust
        | Language::Kotlin
        | Language::Cpp => numeric() || matches!(predicate, GuardPredicate::Truthy { .. }),
        Language::Scala => {
            let scalar_constant = |constant| {
                semantics.value(constant).is_some_and(|value| {
                    matches!(value.kind, SemanticValueKind::Boolean(_))
                        || matches!(
                            value.kind,
                            SemanticValueKind::UnsignedInteger(_)
                                | SemanticValueKind::SignedInteger(_)
                        )
                })
            };
            match predicate {
                GuardPredicate::ConstantBoolean { .. }
                | GuardPredicate::OrderedIntegerComparison { .. }
                | GuardPredicate::Truthy { .. } => true,
                GuardPredicate::ConstantEquality { constant, .. } => scalar_constant(constant),
                _ => false,
            }
        }
        Language::JavaScript | Language::TypeScript | Language::Python => {
            numeric() || matches!(predicate, GuardPredicate::Truthy { .. })
        }
        Language::Php => match predicate {
            GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::NullComparison { .. }
            | GuardPredicate::OrderedIntegerComparison { .. }
            | GuardPredicate::Truthy { .. } => true,
            GuardPredicate::ConstantEquality { constant, .. } => {
                semantics.value(constant).is_some_and(|value| {
                    matches!(
                        value.kind,
                        SemanticValueKind::UnsignedInteger(_) | SemanticValueKind::SignedInteger(_)
                    )
                })
            }
            _ => false,
        },
        Language::Ruby => match predicate {
            GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::OrderedIntegerComparison { .. }
            | GuardPredicate::Truthy { .. } => true,
            GuardPredicate::ConstantEquality { constant, .. } => {
                semantics.value(constant).is_some_and(|value| {
                    matches!(
                        value.kind,
                        SemanticValueKind::UnsignedInteger(_) | SemanticValueKind::SignedInteger(_)
                    )
                })
            }
            _ => false,
        },
        _ => matches!(predicate, GuardPredicate::NullComparison { .. }),
    }
}

/// Derive the procedure's scalar states with the numeric typing its language
/// establishes. Java seeds declared primitive formals and types every
/// primitive local and formal. JavaScript and TypeScript numbers are binary64
/// everywhere. Python integers are unbounded and its bindings untyped. Go,
/// C# and Scala type declared and literal-initialized integer and Boolean
/// bindings and keep no numeric fact for any other. Rust follows the same
/// scalar contract while keeping non-primitive operator implementations
/// opaque. Kotlin follows the same declared scalar path and additionally
/// publishes non-nullable primitive truth and equality guards. PHP types
/// exact integer and Boolean literal bindings and successful scalar-typed
/// parameters; every other binding has no numeric fact because dynamic writes
/// and weak-mode coercion are runtime behavior. A successful `int` or `bool`
/// parameter call has completed its coercion before the procedure body runs.
/// Ruby types only exact integer and Boolean literal-initialized locals. Its
/// integer domain is arbitrary precision, and the Ruby adapter assumes core
/// Integer comparison methods retain their built-in behavior; reopened or
/// monkey-patched operators remain open at the producer.
fn derive_scalar_states(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
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
        Language::Go
        | Language::CSharp
        | Language::Rust
        | Language::Kotlin
        | Language::Scala
        | Language::Cpp => {
            let declared = match language {
                Language::Go => go_declared_scalar_types(procedure, prepared),
                Language::CSharp => csharp_declared_scalar_types(procedure, prepared),
                Language::Rust => rust_declared_scalar_types(procedure, prepared),
                Language::Kotlin => kotlin_declared_scalar_types(procedure, prepared),
                Language::Scala => scala_declared_scalar_types(procedure, prepared),
                Language::Cpp => resolve_analyzer::<CppAnalyzer>(workspace.analyzer())
                    .expect("C++ procedure is mounted on a C++ analyzer")
                    .declared_scalar_types(file, procedure, prepared),
                _ => unreachable!("scalar declaration arm is exhaustive"),
            };
            let seeds = declared_scalar_seeds(procedure, declared);
            ScalarStateDerivation::derive_typed(
                procedure,
                ScalarCallEffects::default(),
                &seeds.entry_facts,
                &seeds.typing,
            )
        }
        Language::Php => {
            let declared = php_declared_scalar_types(procedure, prepared);
            let seeds = declared_scalar_seeds(procedure, declared);
            ScalarStateDerivation::derive_typed(
                procedure,
                ScalarCallEffects::default(),
                &seeds.entry_facts,
                &seeds.typing,
            )
        }
        Language::Ruby => {
            let declared = ruby_declared_scalar_types(procedure, prepared);
            let seeds = declared_scalar_seeds(procedure, declared);
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

/// #6409: can this gap change a guard beyond scalar_state::transfer_point?
fn gap_is_relevant_to_scalar_guards(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    facts: &ScalarLanguageFacts,
    dominance: Option<&Dominators<ProgramPointId>>,
    before_exceptions: &HashSet<ProgramPointId>,
) -> bool {
    // Missing paths, predicates and unrepresented writes are never repaired by
    // value havoc. Partial evidence is independently checked by the caller.
    if matches!(
        gap.capability,
        SemanticCapability::NormalControlFlow
            | SemanticCapability::NonLocalControl
            | SemanticCapability::GuardFacts
    ) {
        return true;
    }
    // E1: fact_of maps unestablished values to Unknown; Gap(ValueFlow)
    // writes Unknown in event order. Check both dominance and the last write,
    // including reads before the gap within the same point.
    if let SemanticGapSubject::Value(value) = gap.subject {
        let unused_temporary = semantics.value(value).is_some_and(|row| {
            matches!(row.kind, SemanticValueKind::Return | SemanticValueKind::Temporary)
        }) && !semantics.guard_facts().iter().any(|guard| guard.subject == Some(value)
            || matches!(guard.predicate, GuardPredicate::Truthy { value: operand } if operand == value));
        if unused_temporary || value_gap_is_modeled(semantics, gap, value, dominance) {
            return false;
        }
    }
    // Call operand evaluation is retained, and Invoke receiver/address havoc
    // plus explicit argument write-backs cover these mutations. CallEvaluation stays meaningful
    // to ordering consumers even though it cannot change these guard facts.
    if facts.strict_call_operands_and_address_arguments
        && gap.capability == SemanticCapability::Calls
        && matches!(gap.subject, SemanticGapSubject::CallSite(_))
        && gap.discharge == SemanticGapDischarge::CallResolution
    {
        return false;
    }
    // A Point Calls event releases shared and escaped-address writers exactly
    // as Invoke does. The address-taking premise is documented at that solver
    // arm; macro NormalControlFlow/NonLocalControl companions still veto.
    let release_only = gap.impacts.iter().all(|impact| {
        matches!(
            impact,
            SemanticGapImpact::DispatchCoverage
                | SemanticGapImpact::HeapRead
                | SemanticGapImpact::HeapWrite
                | SemanticGapImpact::Aliasing
        )
    });
    if gap.subject == SemanticGapSubject::Point && gap.capability == SemanticCapability::Calls {
        return !release_only;
    }
    // R-cleanup: emit_cleanup_completion_route (semantic/lowering.rs) emits
    // lifecycle facts at the completion point, then add_target_edge preserves
    // route.destination(). Destructor-style cleanup adds no normal successor;
    // exceptional exits have their own gap. transfer_point releases effects
    // through the companion Calls event. Finally/recover languages cannot use
    // this rule, because their cleanup can replace normal control (#6409).
    // Safe-Rust borrow discipline: a destructor reaches a closed scalar only
    // through the dropped value: stored &mut, derived raw pointer, or a
    // by-reference closure capture. Address values flowing into aggregates,
    // stores and call arguments escape via address_escape_points and are
    // released at Invoke and Point Calls gaps; shared_capture_bindings covers
    // by-reference captures. Autoref-returned guards cannot coexist with a
    // safe access to the borrowed receiver, made Unknown by Invoke receiver havoc.
    // Unsafe raw-pointer writes after reassignment retain the same limitation
    // as ordinary calls. Every lowered &mut/raw-pointer creation is Address;
    // the #6409 pattern rule marks ref mut scrutinee roots as escaped.
    // Unlowered cleanup routing includes moved-out drop flags, temporary
    // timing and coroutine-frame drops: these select which destructors run,
    // not new destinations. Destructor panics have their separate exceptional
    // row, so this exemption never discharges their effects or control.
    // Point gaps never write a scalar value: transfer_point's Gap(ValueFlow)
    // branch acts only on Value subjects. ReturnTransfer concerns the return
    // value/edge, which no body guard reads. Destructor value/heap/alias effects
    // reach a binding only through an escape or shared capture, covered by the
    // same-point release under safe-Rust borrow discipline. Producer impacts
    // remain facts for every consumer; relevance is decided here (#6409).
    let cleanup_effects = gap.impacts.iter().all(|impact| {
        matches!(
            impact,
            SemanticGapImpact::ValueFlow
                | SemanticGapImpact::Aliasing
                | SemanticGapImpact::HeapRead
                | SemanticGapImpact::HeapWrite
                | SemanticGapImpact::ReturnTransfer
                | SemanticGapImpact::DispatchCoverage
        )
    });
    // R-resource: CallEvaluation here means evaluating the destructor call;
    // the Invoke-equivalent release models that evaluation for scalar guards.
    // The retained destination is a property of the point for BOTH row kinds.
    if facts.destructor_style_cleanup
        && gap.subject == SemanticGapSubject::Point
        && ((gap.capability == SemanticCapability::CleanupControlFlow && cleanup_effects)
            || gap.capability == SemanticCapability::ResourceManagement)
        && semantics.gaps().iter().any(|other| {
            other.point == gap.point
                && other.subject == SemanticGapSubject::Point
                && other.capability == SemanticCapability::Calls
        })
        && cleanup_has_retained_destination(semantics, gap.point)
    {
        debug_assert!(semantics.point(gap.point).expect("validated gap point").events.iter().any(|event| {
            matches!(event.effect, SemanticEffect::Gap { gap: id } if semantics.gap(id).is_some_and(|row|
                row.capability == SemanticCapability::Calls && row.subject == SemanticGapSubject::Point))
        }), "the companion Calls gap must execute its scalar release");
        return false;
    }
    // Completion-only cleanup cannot add a path into ordinary-body guards.
    if matches!(
        gap.capability,
        SemanticCapability::CleanupControlFlow | SemanticCapability::ResourceManagement
    ) && !before_exceptions.contains(&gap.point)
    {
        return false;
    }
    // A procedure-level suspension gap describes how callers construct
    // and schedule a generator or coroutine activation. Inside the body,
    // each suspension is lowered as a scaffold or as its own point gap.
    if matches!(
        gap.capability,
        SemanticCapability::GeneratorSuspension | SemanticCapability::AsyncSuspendResume
    ) && gap.subject == SemanticGapSubject::Procedure
    {
        return false;
    }
    // E2: scalar_state::transfer_point makes field/index/static loads
    // Unknown; stores cannot write a closed binding. Rust Deref/Index user
    // code has separate Point Calls gaps. In JavaScript and Python,
    // accessors or descriptors may execute code, so retain their memory
    // gaps until those effects are modeled at the access point.
    if facts.field_access_runs_no_user_code
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
            matches!(
                location.kind,
                MemoryLocationKind::Field { .. }
                    | MemoryLocationKind::Property { .. }
                    | MemoryLocationKind::Index { .. }
                    | MemoryLocationKind::Static { .. }
            )
        })
    {
        return false;
    }
    // A yield's normal resumption edge is retained, the solver releases
    // shared bindings there, and its abrupt resumption is a separate
    // exceptional gap at the same point, judged by the rule below.
    if gap.capability == SemanticCapability::GeneratorSuspension
        && gap.subject == SemanticGapSubject::Point
    {
        return false;
    }
    // An exceptional gap whose omitted paths leave the procedure without
    // running more of its code reaches no guard.
    if gap_has_exit_only_control(gap) {
        return false;
    }
    // An exception dispatch that retains every handler and the
    // unmatched propagation as successors only leaves the selection
    // among them unrefined, which over-approximates the paths.
    if gap.capability == SemanticCapability::ExceptionalControlFlow
        && gap.subject == SemanticGapSubject::Point
        && gap.discharge == SemanticGapDischarge::RetainedControlTopology
    {
        return false;
    }
    // A binding a nested callable rebinds is released by the solver at
    // every call and suspension, where that callable could run. Scala's
    // closure target and captured environment are still unresolved, so
    // retain that lane's gap as open evidence instead of treating the
    // full declared scalar domain as a proved result.
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
        return false;
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
        return false;
    }

    // Preserve the previous scoped call/callable exemptions: their results
    // are Unknown and transfer_point releases caller-external writers.
    if matches!(
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
    } {
        return false;
    }
    matches!(
        gap.capability,
        SemanticCapability::ExceptionalControlFlow
            | SemanticCapability::CleanupControlFlow
            | SemanticCapability::Assignments
            | SemanticCapability::Values
            | SemanticCapability::LocalFlow
            | SemanticCapability::ParameterFlow
    ) || gap.impacts.contains(SemanticGapImpact::ValueFlow)
        || gap.impacts.contains(SemanticGapImpact::CallEvaluation)
}

// Reads include transfers, call operands, memory identities and guard operands.
// Counting all structural references is deliberately conservative: a declaration
// or an alias use can only retain a veto, never invent a dominance exemption.
fn point_reads_value(
    semantics: &ProcedureSemantics,
    effect: &SemanticEffect,
    value: ValueId,
) -> bool {
    match effect {
        SemanticEffect::Assignment { value: source, .. }
        | SemanticEffect::ValueFlow { source, .. }
        | SemanticEffect::ValueUse { value: source, .. } => *source == value,
        SemanticEffect::MemoryLoad { location, .. } => semantics
            .memory_location(*location)
            .is_some_and(|l| l.kind.uses_value(value)),
        SemanticEffect::MemoryStore {
            location,
            value: source,
            ..
        } => {
            *source == value
                || semantics
                    .memory_location(*location)
                    .is_some_and(|l| l.kind.uses_value(value))
        }
        SemanticEffect::AggregateInitializer {
            aggregate,
            value: source,
            ..
        } => *aggregate == value || *source == value,
        SemanticEffect::Invoke { call_site } => {
            semantics.call_site(*call_site).is_some_and(|call| {
                call.callee == value
                    || call.receiver == Some(value)
                    || call.arguments.iter().any(|a| a.value == value)
            })
        }
        SemanticEffect::ProcedureReturn { value: source }
        | SemanticEffect::Throw { value: source } => *source == Some(value),
        SemanticEffect::AsyncSuspend { awaited, .. } => *awaited == Some(value),
        // No E1 exemption when a complex operation might consume this value.
        SemanticEffect::Synchronization { .. }
        | SemanticEffect::CaptureBind { .. }
        | SemanticEffect::CallableCreation { .. }
        | SemanticEffect::CallableReference { .. } => true,
        _ => false,
    }
}

fn effect_writes_value(
    semantics: &ProcedureSemantics,
    effect: &SemanticEffect,
    value: ValueId,
) -> bool {
    match effect {
        SemanticEffect::Assignment { target, .. }
        | SemanticEffect::ValueFlow { target, .. }
        | SemanticEffect::MemoryLoad { result: target, .. }
        | SemanticEffect::AsyncResume {
            result: Some(target),
            ..
        } => *target == value,
        SemanticEffect::Gap { gap } => semantics.gap(*gap).is_some_and(|g| {
            g.subject == SemanticGapSubject::Value(value)
                && g.impacts.contains(SemanticGapImpact::ValueFlow)
        }),
        _ => false,
    }
}

fn value_gap_is_modeled(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    value: ValueId,
    dominance: Option<&Dominators<ProgramPointId>>,
) -> bool {
    if !gap.impacts.contains(SemanticGapImpact::ValueFlow) {
        return false;
    }
    if semantics
        .value(value)
        .is_some_and(|row| row.kind == SemanticValueKind::Local)
        && !semantics
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .any(|event| {
                !matches!(event.effect, SemanticEffect::Gap { .. })
                    && effect_writes_value(semantics, &event.effect, value)
            })
    {
        // Unsupported-pattern binding with no establishing write: fact_of
        // returns Unknown even before this bookkeeping gap (#6409).
        return true;
    }
    let Some(point) = semantics.point(gap.point) else {
        return false;
    };
    let Some(event_index) = point
        .events
        .iter()
        .position(|e| matches!(e.effect, SemanticEffect::Gap { gap: id } if id == gap.id))
    else {
        return false;
    };
    if point.events[event_index + 1..]
        .iter()
        .any(|e| effect_writes_value(semantics, &e.effect, value))
        || point.events[..event_index]
            .iter()
            .any(|e| point_reads_value(semantics, &e.effect, value))
    {
        return false;
    }
    let Some(dominance) = dominance else {
        return false;
    };
    semantics.points().iter().all(|point| {
        let reads = point.events.iter().any(|e| point_reads_value(semantics, &e.effect, value))
            || semantics.guard_facts().iter().any(|g| g.point == point.id && (g.subject == Some(value) || matches!(g.predicate, GuardPredicate::Truthy { value: operand } if operand == value)));
        !reads || dominance.dominates(semantics, gap.point, point.id)
    })
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
) -> Result<ScalarConditionDerivation, ScalarConditionGap> {
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
    let facts = scalar_language_facts(language);
    let mut cfg_budget = CfgAlgorithmBudget::default();
    let dominance = dominators(
        semantics,
        semantics.entry_point(),
        &mut CfgAlgorithmRequest::new(&mut cfg_budget, cancellation),
    )
    .ok();
    let before_exceptions = points_before_exit_only_exceptions(semantics);
    let vetoing_gaps = semantics
        .gaps()
        .iter()
        .filter(|gap| {
            gap_is_relevant_to_scalar_guards(
                semantics,
                gap,
                &facts,
                dominance.as_ref(),
                &before_exceptions,
            )
        })
        .collect::<Vec<_>>();
    let partial_procedure = !vetoing_gaps.is_empty();
    let partial_rows = semantics
        .points()
        .iter()
        .map(|point| (point.source, point.evidence))
        .chain(semantics.points().iter().flat_map(|point| {
            point
                .events
                .iter()
                .map(|event| (event.source, event.evidence))
        }))
        .chain(
            semantics
                .control_edges()
                .iter()
                .map(|edge| (edge.source, edge.evidence)),
        )
        .chain(
            semantics
                .values()
                .iter()
                .map(|value| (value.source, value.evidence)),
        )
        .chain(
            semantics
                .guard_facts()
                .iter()
                .map(|guard| (guard.source, guard.evidence)),
        )
        .filter(|(_, evidence)| !complete_evidence(semantics, *evidence))
        .collect::<Vec<_>>();
    let partial_producer = !partial_rows.is_empty();
    let partial_sources = partial_rows
        .iter()
        .flat_map(|(source, evidence)| {
            semantics
                .evidence_row(*evidence)
                .expect("validated row owns its evidence")
                .sources
                .iter()
                .copied()
                .chain(std::iter::once(*source))
        })
        .collect::<HashSet<_>>();
    let scalar = (!partial_procedure && !partial_producer)
        .then(|| derive_scalar_states(workspace, file, language, procedure, &prepared));
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
        Language::CSharp => outcomes.extend(composed.outcomes(&CSharpConditionSyntax)?),
        Language::Rust => outcomes.extend(composed.outcomes(&RustConditionSyntax)?),
        Language::Kotlin => outcomes.extend(composed.outcomes(&KotlinConditionSyntax)?),
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
        Language::Scala => outcomes.extend(composed.outcomes(&ScalaConditionSyntax)?),
        Language::Cpp => outcomes.extend(composed.outcomes(&CppConditionSyntax)?),
        Language::Php => outcomes.extend(composed.outcomes(&PhpConditionSyntax)?),
        Language::Ruby => outcomes.extend(composed.outcomes(&RubyConditionSyntax {
            source: prepared.source(),
        })?),
        _ => {}
    }
    let diagnostic_line_starts = crate::text_utils::compute_line_starts(prepared.source());
    let related_gaps = super::semantic::gap_related_sources(vetoing_gaps, |id| {
        super::semantic::mapping_diagnostic_source(
            procedure,
            prepared.source(),
            &diagnostic_line_starts,
            id,
        )
    });
    let mut partial_sources = partial_sources.into_iter().collect::<Vec<_>>();
    partial_sources.sort_unstable();
    let partial_related = partial_sources
        .into_iter()
        .map(|source| super::CodeQueryRelatedSource {
            source: super::semantic::mapping_diagnostic_source(
                procedure,
                prepared.source(),
                &diagnostic_line_starts,
                source,
            ),
            label: "producer/partial".into(),
        })
        .collect::<Vec<_>>();
    Ok(ScalarConditionDerivation {
        outcomes,
        procedure_gaps: related_gaps,
        producer_gaps: partial_related,
    })
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
    let span = brokk_bifrost_core::analyzer::common::node_span(node);
    (span.start_byte, span.end_byte)
}

fn peel_parentheses(mut node: Node<'_>) -> Result<Node<'_>, ScalarConditionGap> {
    let mut layers = 0_usize;
    while matches!(
        node.kind(),
        "parenthesized_expression" | "parenthesized_statements"
    ) && node.named_child_count() == 1
    {
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

fn first_ruby_branch_statement(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "else" | "then" | "do" | "body_statement" | "block_body" => {
                node = node.named_child(0)?;
            }
            _ => return Some(node),
        }
    }
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
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_statement"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        c_family_shape(node)
    }

    /// The node whose span the guard for `leaf` carries.
    fn guard_anchor<'tree>(&self, leaf: Node<'tree>) -> Option<Node<'tree>> {
        Some(leaf)
    }

    /// The syntax field containing the statement executed by a true arm.
    /// Most C-family grammars call it `consequence`; adapters whose grammar
    /// calls it `body` override this accessor.
    fn consequence<'tree>(&self, owner: Node<'tree>) -> Result<Node<'tree>, ScalarConditionGap> {
        owner
            .child_by_field_name("consequence")
            .ok_or(ScalarConditionGap::IncompleteCondition)
    }

    /// The node whose span the target point of the owner's false arm carries.
    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap>;
}

struct JavaConditionSyntax;

impl ConditionSyntax for JavaConditionSyntax {
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

/// C# splits `&&` and `||` like Java, and its lowering decides the operand
/// of `!` with swapped arms.
struct CSharpConditionSyntax;

impl ConditionSyntax for CSharpConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_statement"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "prefix_unary_expression"
            && node.child(0).is_some_and(|operator| operator.kind() == "!")
        {
            return ConditionShape::Negation(node.named_child(0));
        }
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

/// C and C++ use the C-family short-circuit grammar. Their built-in `!` is
/// split by the producer with swapped arms, so the structural composition
/// walker must make the same swap when it sees the syntax owner.
struct CppConditionSyntax;

impl ConditionSyntax for CppConditionSyntax {
    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "condition_clause"
            && let Some(value) = node.child_by_field_name("value")
        {
            return self.shape(value);
        }
        if node.kind() == "unary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "!")
        {
            return ConditionShape::Negation(node.child_by_field_name("argument"));
        }
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
            None => following_statement(owner, "compound_statement"),
        }
    }
}

/// Rust conditions are expressions owned by `if_expression`. Primitive `!`
/// swaps the operand arms; comparisons on any other type remain opaque in the
/// producer, so this adapter only supplies the structural composition shape.
struct RustConditionSyntax;

impl ConditionSyntax for RustConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_expression"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "unary_expression"
            && node.child(0).is_some_and(|operator| operator.kind() == "!")
        {
            return ConditionShape::Negation(node.named_child(0));
        }
        c_family_shape(node)
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        if let Some(alternative) = owner.child_by_field_name("alternative") {
            return alternative
                .named_child(0)
                .ok_or(ScalarConditionGap::IncompleteCondition);
        }
        let statement = owner
            .parent()
            .filter(|parent| parent.kind() == "expression_statement")
            .unwrap_or(owner);
        following_statement(statement, "block")
    }
}

/// Kotlin conditions are expression nodes. The semantic lowering splits
/// conjunctions, disjunctions, and Boolean negation exactly like this syntax
/// view; `<` and `==` remain leaf decisions whose producer has already proved
/// whether their primitive operator is safe to use.
struct KotlinConditionSyntax;

impl ConditionSyntax for KotlinConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_expression"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        let mut cursor = node.walk();
        if node.kind() == "prefix_expression"
            && node
                .children(&mut cursor)
                .any(|child| !child.is_named() && child.kind() == "!")
        {
            return ConditionShape::Negation(node.named_child(0));
        }
        if matches!(
            node.kind(),
            "conjunction_expression" | "disjunction_expression"
        ) {
            let operands = brokk_bifrost_core::analyzer::tree_walk::named_children(node);
            return ConditionShape::ShortCircuit {
                left: operands.first().copied(),
                right: operands.get(1).copied(),
            };
        }
        ConditionShape::Leaf
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        match owner.child_by_field_name("alternative") {
            Some(alternative) => Ok(alternative),
            None => following_statement(owner, "statements"),
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

/// Scala conditions are expressions. The lowering splits built-in Boolean
/// `&&` and `||`, and a built-in `!` on a typed Boolean swaps the operand's
/// arms. Other infix operators remain one opaque decision because Scala
/// resolves every operator as a method call.
struct ScalaConditionSyntax;

impl ConditionSyntax for ScalaConditionSyntax {
    fn is_owner(&self, node: Node<'_>) -> bool {
        node.kind() == "if_expression"
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "prefix_expression" && has_direct_token(node, "!") {
            return ConditionShape::Negation(node.named_child(0));
        }
        if node.kind() == "infix_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(operator.kind(), "&&" | "||"))
        {
            return ConditionShape::ShortCircuit {
                left: node.child_by_field_name("left"),
                right: node.child_by_field_name("right"),
            };
        }
        ConditionShape::Leaf
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        match owner.child_by_field_name("alternative") {
            Some(alternative) => Ok(alternative),
            None => {
                let block_kind = owner
                    .parent()
                    .map(|parent| parent.kind())
                    .filter(|kind| matches!(*kind, "block" | "indented_block"))
                    .ok_or(ScalarConditionGap::UnqualifiedContinuation)?;
                following_statement(owner, block_kind)
            }
        }
    }
}

/// PHP uses C-family `if` statements, but its boolean operators include the
/// lower-precedence `and` and `or` tokens as well. The lowering peels `!` and
/// splits all four short-circuit operators before publishing the leaf guard.
struct PhpConditionSyntax;

impl ConditionSyntax for PhpConditionSyntax {
    fn consequence<'tree>(&self, owner: Node<'tree>) -> Result<Node<'tree>, ScalarConditionGap> {
        owner
            .child_by_field_name("body")
            .ok_or(ScalarConditionGap::IncompleteCondition)
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "unary_op_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "!")
        {
            return ConditionShape::Negation(node.child_by_field_name("argument"));
        }
        if node.kind() == "binary_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(operator.kind(), "&&" | "and" | "||" | "or"))
        {
            return ConditionShape::ShortCircuit {
                left: node.child_by_field_name("left"),
                right: node.child_by_field_name("right"),
            };
        }
        ConditionShape::Leaf
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
            None => following_statement(owner, "compound_statement"),
        }
    }
}

/// Ruby conditions are `if` expressions whose Boolean operators are ordinary
/// binary/unary nodes. The producer already swaps `unless` arms and peels
/// negation, so this syntax view only mirrors the structured control shape.
struct RubyConditionSyntax<'a> {
    source: &'a str,
}

impl ConditionSyntax for RubyConditionSyntax<'_> {
    fn is_owner(&self, node: Node<'_>) -> bool {
        matches!(
            node.kind(),
            "if" | "unless" | "if_modifier" | "unless_modifier" | "conditional"
        )
    }

    fn consequence<'tree>(&self, owner: Node<'tree>) -> Result<Node<'tree>, ScalarConditionGap> {
        let body = owner
            .child_by_field_name("consequence")
            .or_else(|| owner.child_by_field_name("body"))
            .ok_or(ScalarConditionGap::IncompleteCondition)?;
        first_ruby_branch_statement(body).ok_or(ScalarConditionGap::IncompleteCondition)
    }

    fn shape<'tree>(&self, node: Node<'tree>) -> ConditionShape<'tree> {
        if node.kind() == "unary"
            && node
                .child_by_field_name("operator")
                .and_then(|operator| operator.utf8_text(self.source.as_bytes()).ok())
                .is_some_and(|operator| matches!(operator, "!" | "not"))
        {
            return ConditionShape::Negation(node.child_by_field_name("operand"));
        }
        if node.kind() == "binary"
            && node
                .child_by_field_name("operator")
                .and_then(|operator| operator.utf8_text(self.source.as_bytes()).ok())
                .is_some_and(|operator| matches!(operator, "&&" | "and" | "||" | "or"))
        {
            return ConditionShape::ShortCircuit {
                left: node.child_by_field_name("left"),
                right: node.child_by_field_name("right"),
            };
        }
        ConditionShape::Leaf
    }

    fn false_destination<'tree>(
        &self,
        owner: Node<'tree>,
    ) -> Result<Node<'tree>, ScalarConditionGap> {
        match owner.child_by_field_name("alternative") {
            Some(alternative) if alternative.kind() == "else" => {
                first_ruby_branch_statement(alternative)
                    .ok_or(ScalarConditionGap::IncompleteCondition)
            }
            Some(alternative) => Ok(alternative),
            None => following_statement(owner, "body_statement"),
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
        let consequence = syntax.consequence(owner)?;
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

use brokk_bifrost_ruby_analysis::ruby_declared_scalar_types;

use brokk_bifrost_cpp_analysis::analyzer::CppAnalyzer;

#[cfg(test)]
mod gap_relevance_tests {
    use super::super::tests::inline_project::InlineTestProject;
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::analyzer::semantic::{
        ProcedureSemanticsParts, SemanticArtifact, SemanticBudget, SemanticGapId,
        SemanticGapImpacts, SemanticGapKind, SemanticRequest,
    };

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6409: method autoref could write a receiver binding with no recorded write"
    )]
    fn method_autoref_does_not_preserve_literal_receiver_facts() {
        for declaration in ["let mut n = 0", "let mut n: u8 = 0"] {
            let source = format!("fn f() {{ {declaration}; n.add_assign(1); if n == 0 {{}} }}");
            let project = InlineTestProject::with_language(Language::Rust)
                .file("lib.rs", &source)
                .build();
            let file = project.file("lib.rs");
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = workspace
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Rust semantics");
            let artifact = outcome.available_value().expect("fixture semantics");
            let original = artifact
                .procedures()
                .iter()
                .find(|p| !p.guard_facts().is_empty())
                .expect("guard");
            let handle = artifact.procedure_handle(original.id()).expect("procedure");
            let origins = crate::analyzer::semantic::BindingOriginIndex::new(&handle);
            let receivers = original
                .call_sites()
                .iter()
                .filter_map(|call| call.receiver)
                .filter_map(|receiver| {
                    origins
                        .unique_binding_origin(receiver)
                        .map(|binding| (receiver, binding))
                })
                .collect::<Vec<_>>();
            assert!(
                !receivers.is_empty(),
                "the receiver binding must be exercised"
            );
            // Use the real repaired producer facts: the scalar solver, not a
            // producer write-back or a test rewrite, must invalidate n (#6409).
            assert!(!original.points().iter().flat_map(|point| &point.events).any(|event|
                matches!(event.effect, SemanticEffect::ValueFlow {
                    kind: crate::analyzer::semantic::ValueFlowKind::LanguageDefined, source, target }
                    if receivers.contains(&(source, target)))), "producer receiver write-back must stay absent");
            let tree =
                brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language(
                    &file,
                    Language::Rust,
                    &source,
                )
                .expect("parse");
            let prepared = Arc::new(PreparedSyntaxTree::new(
                brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource::Exact(
                    Arc::from(source.as_str()),
                ),
                tree,
                brokk_bifrost_core::text_utils::compute_line_starts(&source),
                crate::analyzer::LanguageDialect::Standard(Language::Rust),
                brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin::Disk,
                None,
            ));
            let derived =
                scalar_condition_outcomes(&workspace, &file, &handle, prepared, &cancellation)
                    .expect("scalar conditions");
            assert_eq!(derived.outcomes.len(), 1, "{declaration}: {derived:?}");
            assert!(
                matches!(
                    derived.outcomes[0].verdict,
                    ScalarConditionVerdict::BothFeasible
                        | ScalarConditionVerdict::Open(ScalarConditionGap::UnknownScalar)
                ),
                "{declaration}: {derived:?}"
            );
        }
    }

    #[test]
    fn value_gap_ordering_and_finally_cleanup_language_boundary() {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "C.java",
                "class C { int f() { int x = 0; try {} finally { return x; } } }",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &project.file("C.java"),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Java semantics");
        let artifact = outcome
            .available_value()
            .expect("complete fixture semantics");
        let original = artifact
            .procedures()
            .iter()
            .find(|p| !p.values().is_empty())
            .expect("method");
        assert!(original.gaps().is_empty());
        let (point, assignment, target) = original
            .points()
            .iter()
            .find_map(|point| {
                point.events.iter().find_map(|event| match event.effect {
                    SemanticEffect::Assignment { target, .. }
                        if original
                            .value(target)
                            .is_some_and(|v| v.kind == SemanticValueKind::Local) =>
                    {
                        Some((point.id, event.clone(), target))
                    }
                    _ => None,
                })
            })
            .expect("local establishing assignment");
        let read = original.points().iter().flat_map(|point| &point.events).find(|event| {
            matches!(event.effect, SemanticEffect::ValueFlow { source, .. } if source == target)
        }).expect("return read").clone();
        let gap = SemanticGap {
            id: SemanticGapId::new(0),
            point,
            subject: SemanticGapSubject::Value(target),
            capability: SemanticCapability::Values,
            impacts: SemanticGapImpacts::single(SemanticGapImpact::ValueFlow)
                .with(SemanticGapImpact::Aliasing),
            kind: SemanticGapKind::Unknown,
            budget: None,
            discharge: SemanticGapDischarge::None,
            detail: "test-only value uncertainty".into(),
            source: assignment.source,
            evidence: assignment.evidence,
        };
        // Java fully lowers this finally { return } precisely. Add the
        // destructor-shaped gap/event pair to pin the language boundary of
        // R-cleanup itself: matching points and impacts cannot license Java
        // cleanup to replace the normal completion destination.
        let mut call_gap = gap.clone();
        call_gap.id = SemanticGapId::new(1);
        call_gap.subject = SemanticGapSubject::Point;
        call_gap.capability = SemanticCapability::Calls;
        call_gap.impacts = SemanticGapImpacts::NONE;
        let mut cleanup_gap = call_gap.clone();
        cleanup_gap.id = SemanticGapId::new(2);
        cleanup_gap.capability = SemanticCapability::CleanupControlFlow;
        cleanup_gap.impacts = SemanticGapImpacts::single(SemanticGapImpact::DispatchCoverage)
            .with(SemanticGapImpact::HeapRead)
            .with(SemanticGapImpact::HeapWrite)
            .with(SemanticGapImpact::Aliasing)
            .with(SemanticGapImpact::ValueFlow)
            .with(SemanticGapImpact::ReturnTransfer);
        let mut gap_event = assignment.clone();
        gap_event.effect = SemanticEffect::Gap { gap: gap.id };
        for (mut events, irrelevant) in [
            (vec![gap_event.clone(), assignment.clone()], false),
            (vec![assignment.clone(), gap_event.clone()], true),
            (vec![assignment.clone(), read, gap_event.clone()], false),
        ] {
            let mut parts = ProcedureSemanticsParts::new(
                original.id(),
                original.locator().clone(),
                original.kind(),
                original.source(),
                original.evidence(),
            );
            parts.properties = original.properties();
            parts.values = original.values().to_vec();
            parts.source_mappings = original.source_mappings().to_vec();
            parts.evidence_rows = original.evidence_rows().to_vec();
            parts.blocks = original.blocks().to_vec();
            parts.points = original.points().to_vec();
            parts.control_edges = original.control_edges().to_vec();
            parts.gaps = vec![gap.clone(), call_gap.clone(), cleanup_gap.clone()];
            for extra in [&call_gap, &cleanup_gap] {
                let mut event = gap_event.clone();
                event.effect = SemanticEffect::Gap { gap: extra.id };
                events.push(event);
            }
            parts.points[point.index()].events = events.into_boxed_slice();
            let reordered = SemanticArtifact::try_new(
                artifact.key().clone(),
                artifact.capabilities().clone(),
                vec![parts],
            )
            .expect("ordered IR");
            let semantics = &reordered.procedures()[0];
            let mut cfg_budget = CfgAlgorithmBudget::default();
            let dominance = dominators(
                semantics,
                semantics.entry_point(),
                &mut CfgAlgorithmRequest::new(&mut cfg_budget, &cancellation),
            )
            .expect("dominance");
            assert_eq!(
                value_gap_is_modeled(semantics, &gap, target, Some(&dominance)),
                irrelevant
            );
            let normal_points = HashSet::from([point]);
            assert!(gap_is_relevant_to_scalar_guards(
                semantics,
                &cleanup_gap,
                &scalar_language_facts(Language::Java),
                Some(&dominance),
                &normal_points
            ));
            assert!(!gap_is_relevant_to_scalar_guards(
                semantics,
                &cleanup_gap,
                &scalar_language_facts(Language::Rust),
                Some(&dominance),
                &normal_points
            ));
            let mut resource_gap = cleanup_gap.clone();
            resource_gap.capability = SemanticCapability::ResourceManagement;
            resource_gap.impacts = SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation);
            assert!(!gap_is_relevant_to_scalar_guards(
                semantics,
                &resource_gap,
                &scalar_language_facts(Language::Rust),
                Some(&dominance),
                &normal_points
            ));
            assert!(gap_is_relevant_to_scalar_guards(
                semantics,
                &resource_gap,
                &scalar_language_facts(Language::Java),
                Some(&dominance),
                &normal_points
            ));
            let mut evaluation_gap = cleanup_gap.clone();
            evaluation_gap.impacts = evaluation_gap
                .impacts
                .with(SemanticGapImpact::CallEvaluation);
            assert!(gap_is_relevant_to_scalar_guards(
                semantics,
                &evaluation_gap,
                &scalar_language_facts(Language::Rust),
                Some(&dominance),
                &normal_points
            ));
        }
    }
}
