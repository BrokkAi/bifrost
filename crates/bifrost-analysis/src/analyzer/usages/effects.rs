//! Declarative effect rows: source-derived direct effects at a call site and
//! bounded transitive effect summaries for a procedure (issue #2437, slice 2).
//!
//! Milestone 4 gave a reviewed semantic-model pack the ability to attach
//! namespaced effect identifiers to an exact procedure identity
//! (`declared_effects` on a compiled procedure summary). This module is the
//! consumption half: it turns those declarations into two addressable row
//! domains.
//!
//! - `call_effect`: one row per (call site, dispatch arm, declared effect).
//!   The call's dispatch answer is the analyzer's own — proof, completeness and
//!   the site's candidate coverage are copied from it, never re-derived — and
//!   the effect is whatever the activated pack declares for the arm's callee.
//! - `procedure_effect`: one row per (procedure, effect id), computed by a
//!   bounded deterministic fixpoint over the same call edges.
//!
//! Three rules are load-bearing and mirror the `call_binding` discipline.
//!
//! - Both reports are mandatory. A call site whose effects could not be
//!   established, and a procedure whose reachable call graph could not be
//!   walked, still produce exactly one terminal row carrying the typed reason,
//!   so zero rows can never be read as "nothing here has an effect".
//! - Coverage is a column, repeated on every row of a site or a procedure, so
//!   one row alone is enough to reject an absence claim.
//! - Certainty is the meet of what the pack claims and what dispatch proved. A
//!   possible dispatch never yields a definite effect row, and a `possible`
//!   declaration never becomes definite because dispatch happened to be proven.
//!
//! The report algebra below never interprets source text or resolves a name.
//! The one analyzer-owned candidate projection in this module accepts an exact
//! source snapshot only to run the shared tree-sitter call relation, then
//! publishes canonical model keys and typed coverage before semantic lowering.
//! Effect reports still consume only already-resolved identities, dispatch
//! quality, and pack declarations.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::i_analyzer::IAnalyzer;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmRequest, DenseBidirectionalGraph, strongly_connected_components,
};
use crate::analyzer::semantic::{ExecutionTiming, LengthDelimitedDigest};
use crate::analyzer::semantic_model::{
    CompiledDeclaredEffect, CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming,
};
use crate::analyzer::usages::call_relations::{
    CallDispatchBoundaryKind, CallRelationLimits, CallRelationService,
};
use crate::analyzer::usages::call_shape::CallShapeReport;
use crate::analyzer::usages::callable_signature::callable_signature_reports;
use crate::analyzer::usages::get_definition::{CallApplicationKind, DefinitionLookupStatus};
use crate::analyzer::{AnalyzerQueryScope, CodeUnit, Language, ProjectFile, QueryScope, Range};
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::structural::callable::ReceiverContract;

/// Domain separator for one direct call-effect row id.
const CALL_EFFECT_ID_DOMAIN: &[u8] = b"bifrost.code_query.call_effect.v1";
/// Domain separator for one procedure-effect summary row id.
const PROCEDURE_EFFECT_ID_DOMAIN: &[u8] = b"bifrost.code_query.procedure_effect.v1";

macro_rules! effect_enum {
    ($(#[$meta:meta])* $name:ident, $all:ident { $($variant:ident => $label:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[$($name::$variant,)+];

        impl $name {
            /// Every label of this vocabulary, in declaration order: the value
            /// domain the matching row field publishes (issue #2515).
            pub const LABELS: &'static [&'static str] = &[$($label,)+];

            pub const fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<$name> {
                $all.iter().copied().find(|value| value.label() == label)
            }
        }
    };
}

effect_enum! {
    /// How far the effect is from the row's subject.
    ///
    /// A `call_effect` row is always `Direct`: it names the exact call whose
    /// callee the pack models. A `procedure_effect` row is `Direct` when the
    /// declaring procedure is the subject itself or a callee written in the
    /// subject's own body, and `Transitive` when at least one intermediate
    /// procedure sits between them.
    EffectClassification, ALL_EFFECT_CLASSIFICATIONS {
        Direct => "direct",
        Transitive => "transitive",
    }
}

effect_enum! {
    /// When the effect happens relative to the modeled call that declares it.
    ///
    /// This is the semantic pack's authored schedule and the stable schema-v1
    /// `timing` vocabulary. Source execution never rewrites it; the additive
    /// canonical `execution_timing` fact carries that composition instead.
    EffectTiming, ALL_EFFECT_TIMINGS {
        Immediate => "immediate",
        Deferred => "deferred",
        Unknown => "unknown",
    }
}

effect_enum! {
    /// How firmly the effect is attributed.
    ///
    /// `Definite` requires both halves: the pack claims every execution
    /// performs the effect, and every dispatch step along the attributing chain
    /// was proven and exhaustive. Any weakness on either axis yields
    /// `Possible`.
    EffectCertainty, ALL_EFFECT_CERTAINTIES {
        Definite => "definite",
        Possible => "possible",
    }
}

effect_enum! {
    /// What one row states.
    ///
    /// - `Declared`: the row names one effect an activated pack declares for
    ///   the resolved callee (`call_effect`) or for a procedure reachable from
    ///   the subject (`procedure_effect`).
    /// - `None`: the terminal row of a subject whose derivation completed and
    ///   found no declared effect. This is the only row that means "no effect
    ///   here", and it only means it when `coverage` is `exhaustive`.
    /// - `Incomplete`: the terminal row of a subject whose derivation could not
    ///   be completed. `reason` says why.
    /// - `Unsupported`: the terminal row of a subject the analyzer cannot
    ///   derive effects for at all.
    EffectDerivation, ALL_EFFECT_DERIVATIONS {
        Declared => "declared",
        None => "none",
        Incomplete => "incomplete",
        Unsupported => "unsupported",
    }
}

effect_enum! {
    /// Why an effect derivation is not exhaustive. An exhaustive derivation
    /// states none.
    ///
    /// - `DispatchUnresolved`: dispatch named no target, or named a target the
    ///   workspace does not index, so a callee could carry an effect nobody
    ///   asked about.
    /// - `DispatchTruncated`: the dispatch candidate set hit a bound.
    /// - `DispatchUnsupported`: the language or the semantic provider cannot
    ///   answer dispatch here.
    /// - `DispatchInterrupted`: dispatch was cancelled or exceeded a budget.
    /// - `CalleeUnkeyable`: a target exists but no canonical procedure identity
    ///   could be built for it, so no pack declaration can be looked up.
    /// - `ModelConflict`: several activated packs disagree about the callee, so
    ///   the runtime resolved the lookup to `Conflict` and nothing is claimed.
    /// - `CalleeUnmodeled`: the callee resolves outside the workspace and no
    ///   activated pack models it, so its effects are unknown.
    /// - `ProcedureBudgetExhausted`: the fixpoint reached its procedure,
    ///   depth or iteration bound.
    /// - `EffectBudgetExhausted`: one procedure carried more distinct effects
    ///   than the per-procedure bound retains.
    /// - `ProcedureUnreadable`: the subject declaration's own body could not be
    ///   read, so its call sites were never enumerated.
    EffectReason, ALL_EFFECT_REASONS {
        DispatchUnresolved => "dispatch_unresolved",
        DispatchTruncated => "dispatch_truncated",
        DispatchUnsupported => "dispatch_unsupported",
        DispatchInterrupted => "dispatch_interrupted",
        CalleeUnkeyable => "callee_unkeyable",
        ModelConflict => "model_conflict",
        CalleeUnmodeled => "callee_unmodeled",
        ProcedureBudgetExhausted => "procedure_budget_exhausted",
        EffectBudgetExhausted => "effect_budget_exhausted",
        ProcedureUnreadable => "procedure_unreadable",
    }
}

effect_enum! {
    /// Completeness of the effect set the row's subject publishes.
    ///
    /// `Exhaustive` is the only value under which an absence of `Declared` rows
    /// is a claim that the subject has no effect. Everything else says a row
    /// could be missing.
    EffectCoverage, ALL_EFFECT_COVERAGES {
        Exhaustive => "exhaustive",
        Open => "open",
        Truncated => "truncated",
        Unsupported => "unsupported",
    }
}

effect_enum! {
    /// The dispatch proof one `call_effect` row inherited.
    ///
    /// This is the arm's own `proof` label from the dispatch answer, repeated
    /// so an effect row is self-contained: a policy never has to fetch the
    /// sibling `dispatch_target` row to know whether the callee was proven.
    EffectProof, ALL_EFFECT_PROOFS {
        Proven => "proven",
        Unproven => "unproven",
    }
}

impl EffectCoverage {
    /// The weaker of two coverages. `Unsupported` dominates, then `Truncated`,
    /// then `Open`.
    pub fn meet(self, other: Self) -> Self {
        let rank = |value: Self| match value {
            Self::Exhaustive => 0,
            Self::Open => 1,
            Self::Truncated => 2,
            Self::Unsupported => 3,
        };
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }

    pub const fn is_exhaustive(self) -> bool {
        matches!(self, Self::Exhaustive)
    }
}

impl EffectCertainty {
    /// The weaker of two certainties: `Possible` absorbs.
    ///
    /// This is the meet the plan requires at a single attribution step — a
    /// possible dispatch never yields a definite effect row.
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Definite, Self::Definite) => Self::Definite,
            _ => Self::Possible,
        }
    }

    /// The stronger of two certainties, used when several chains attribute one
    /// effect to one procedure: the best-evidenced chain is what the row
    /// reports, because certainty here measures attribution evidence and not
    /// execution frequency.
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Possible, Self::Possible) => Self::Possible,
            _ => Self::Definite,
        }
    }
}

impl EffectTiming {
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Immediate, Self::Immediate) => Self::Immediate,
            (Self::Deferred, Self::Deferred) => Self::Deferred,
            _ => Self::Unknown,
        }
    }

    pub const fn from_compiled(timing: CompiledDeclaredEffectTiming) -> Self {
        match timing {
            CompiledDeclaredEffectTiming::Immediate => Self::Immediate,
            CompiledDeclaredEffectTiming::Deferred => Self::Deferred,
            CompiledDeclaredEffectTiming::Unknown => Self::Unknown,
        }
    }
}

const fn declared_effect_execution_timing(timing: CompiledDeclaredEffectTiming) -> ExecutionTiming {
    match timing {
        // A pack's `immediate` promise is only that the effect happens before
        // the modeled call returns. It does not make the call and effect one
        // indivisible program-point evaluation.
        CompiledDeclaredEffectTiming::Immediate => ExecutionTiming::SameInvocation,
        CompiledDeclaredEffectTiming::Deferred => ExecutionTiming::DeferredCallback,
        CompiledDeclaredEffectTiming::Unknown => ExecutionTiming::Unknown,
    }
}

impl EffectCertainty {
    pub const fn from_compiled(certainty: CompiledDeclaredEffectCertainty) -> Self {
        match certainty {
            CompiledDeclaredEffectCertainty::Definite => Self::Definite,
            CompiledDeclaredEffectCertainty::Possible => Self::Possible,
        }
    }
}

/// The canonical identity a semantic-model pack declaration is looked up by.
///
/// This is the `(language, owner FQN, member, has_receiver, parameter_count)`
/// key issue #1978 introduced for unmaterialized external callees, reused
/// verbatim so an effect declaration and a data-flow summary select the same
/// procedure by the same rule. It is a qualified identity: an owner-less name
/// never produces a key, so nothing here can degrade into unqualified
/// method-name matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModeledProcedureKey {
    pub language: String,
    pub owner: String,
    pub member: String,
    pub has_receiver: bool,
    pub parameter_count: u32,
}

/// Exact declaration name and receiver shape retained when persisted signature
/// metadata cannot supply formal arity.
///
/// This partial identity is sufficient only for negative model adjudication:
/// if no active result contract shares the exact language, owner, member, and
/// receiver shape, the workspace target is a conclusive non-match. A matching
/// name remains an open identity gap and never becomes a positive modeled arm.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModeledProcedureName {
    pub language: String,
    pub owner: String,
    pub member: String,
    pub has_receiver: bool,
}

/// One canonical dispatch arm resolved without materializing semantic IR.
///
/// Workspace declarations use the same persisted signature contract as the
/// effect and data-flow consumers. Go external package functions and concrete
/// receiver methods use one resolver-owned proof containing the canonical
/// imported-member spelling, receiver application, and effective argument
/// count. No independently lowered receiver or written-argument count enters
/// this identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModeledCallTargetArm {
    pub key: ModeledProcedureKey,
    /// Resolver-owned provenance for the canonical key. Control consumers
    /// must not let an authored external summary replace a workspace body's
    /// source-owned topology merely because both have the same modeled name.
    pub origin: ModeledCallTargetOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModeledCallTargetOrigin {
    WorkspaceBody,
    UnmaterializedExternal,
}

/// Completeness of a lightweight canonical call-target lookup.
///
/// `Exhaustive` means every retained dispatch alternative produced a canonical
/// model key. The other variants are deliberately typed so a model-aware
/// positive filter can distinguish a conclusive non-match from a matching call
/// whose alternative target set was not proved complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeledCallTargetCoverage {
    Exhaustive,
    /// Exact resolution either named only workspace targets that cannot bind a
    /// modeled procedure or adjudicated that there is no procedure target.
    Unmodeled,
    /// Exact resolution retained at least one canonical arm and a residual, or
    /// proved that an unnameable external/ambiguous target may remain.
    Open,
    Truncated,
    Unsupported,
    Cancelled,
}

/// Canonical target keys for one exact structured call shape, derived through
/// the analyzer's existing exact call relation and without semantic lowering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeledCallTargetLookup {
    pub arms: Vec<ModeledCallTargetArm>,
    /// Structured Go workspace identities whose exact declaration-side key
    /// could not be built because persisted signature metadata was missing or
    /// ambiguous. These names may prove that an active model cannot apply, but
    /// they are never promoted to positive arms: matching one means target
    /// coverage is incomplete.
    pub adjudicable_workspace_names: Vec<ModeledProcedureName>,
    /// Selector-base evidence retained by the same structured call-resolution
    /// pass. A value is sufficient only for negative model-applicability
    /// adjudication; it never mints a positive receiver target.
    pub call_application: ModeledCallApplication,
    pub coverage: ModeledCallTargetCoverage,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ModeledCallApplication {
    PackageFunction,
    BoundReceiver,
    ReceiverBindingUnknown,
    #[default]
    Unknown,
}

/// Resolve the canonical model identities of one exact call before semantic IR
/// materialization.
///
/// The supplied source must be the indexed snapshot that produced `shape`.
/// Exact call dispatch reparses that snapshot with tree-sitter and invokes the
/// ordinary definition resolver. Workspace targets are projected through
/// [`modeled_procedure_key_for_unit`]. A named Go external boundary is
/// projected only when the same structured resolution retained an exact
/// external call proof. Its qualifier has then been expanded through the import
/// binder, and its receiver shape and effective arity stay attached to that
/// identity. A named Go boundary with bound-receiver application is projected
/// only after the Go resolver has proved a unique public method on a modeled
/// concrete struct. Uncertain receiver applications remain open residuals.
/// Other languages' named external boundaries are left unsupported because a
/// dotted source shape does not prove whether the target is static or an
/// instance member.
pub fn modeled_call_targets_for_shape(
    analyzer: &dyn IAnalyzer,
    shape: &CallShapeReport,
    exact_source: Arc<str>,
    limits: CallRelationLimits,
    cancellation: Option<&CancellationToken>,
) -> ModeledCallTargetLookup {
    modeled_call_targets_for_shapes(analyzer, &[shape], exact_source, limits, cancellation)
        .pop()
        .expect("one call shape produces one canonical target lookup")
}

/// Batch form of [`modeled_call_targets_for_shape`]. All shapes must belong to
/// the same indexed source snapshot. The exact call relation resolves every
/// structured callee reference in one batch, retaining any selector-base
/// namespace evidence that the language resolver proves along the way.
pub fn modeled_call_targets_for_shapes(
    analyzer: &dyn IAnalyzer,
    shapes: &[&CallShapeReport],
    exact_source: Arc<str>,
    limits: CallRelationLimits,
    cancellation: Option<&CancellationToken>,
) -> Vec<ModeledCallTargetLookup> {
    use brokk_bifrost_core::analyzer::structural::callable::CallShapeCoverage;

    let file = shapes.first().map(|shape| &shape.outcome.file);
    debug_assert!(shapes.iter().all(|shape| Some(&shape.outcome.file) == file));
    let Some(file) = file else {
        return Vec::new();
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let lookups = CallRelationService::dispatch_many_at_bounded(
        analyzer,
        scope.token(),
        file,
        &shapes
            .iter()
            .map(|shape| shape.outcome.range)
            .collect::<Vec<_>>(),
        exact_source,
        limits,
        cancellation,
    );
    shapes.iter().zip(lookups).map(|(shape, lookup)| {
            if shape.outcome.coverage != CallShapeCoverage::Exact {
                return ModeledCallTargetLookup {
                    arms: Vec::new(),
                    adjudicable_workspace_names: Vec::new(),
                    call_application: ModeledCallApplication::Unknown,
                    coverage: ModeledCallTargetCoverage::Unsupported,
                };
            }
            let go_external_shape_supported = shape.arguments.iter().all(|argument| !argument.spread)
                && shape.groups.iter().all(|group| {
                    group.kind
                        == brokk_bifrost_core::analyzer::structural::callable::ArgumentListKind::Ordinary
                });
            project_modeled_call_target_lookup(
                analyzer,
                shape,
                go_external_shape_supported,
                lookup,
            )
        })
        .collect()
}

fn project_modeled_call_target_lookup(
    analyzer: &dyn IAnalyzer,
    shape: &CallShapeReport,
    go_external_shape_supported: bool,
    lookup: super::call_relations::CallDispatchLookup,
) -> ModeledCallTargetLookup {
    let mut arms = Vec::new();
    let mut adjudicable_workspace_names = Vec::new();
    let mut residual = 0usize;
    let mut potentially_modeled_residual = false;
    let mut unsupported = false;
    let call_application = lookup
        .exact_external_call
        .as_ref()
        .map_or(lookup.call_application, |proof| proof.call_application());
    for target in &lookup.targets {
        if let Some(key) = modeled_procedure_key_for_unit(analyzer, &target.definition) {
            arms.push(ModeledCallTargetArm {
                key,
                origin: ModeledCallTargetOrigin::WorkspaceBody,
            });
            continue;
        }
        residual = residual.saturating_add(1);
        if language_for_file(target.definition.source()) == Language::Go
            && let Some((owner, member)) =
                crate::analyzer::semantic::split_qualified_member(&target.definition.fq_name())
        {
            adjudicable_workspace_names.push(ModeledProcedureName {
                language: Language::Go.config_label().to_owned(),
                owner: owner.to_owned(),
                member: member.to_owned(),
                has_receiver: target.definition.owner_is_type_scope(),
            });
        } else {
            potentially_modeled_residual = true;
        }
    }
    for boundary in &lookup.boundaries {
        match boundary {
            CallDispatchBoundaryKind::External {
                callee_text: Some(target),
                ..
            } if language_for_file(&shape.outcome.file) == Language::Go
                && go_external_shape_supported =>
            {
                let exact = lookup
                    .exact_external_call
                    .as_ref()
                    .filter(|proof| proof.canonical_callee() == target.as_ref());
                let has_receiver = exact.and_then(|proof| match proof.call_application() {
                    CallApplicationKind::PackageFunction => Some(false),
                    CallApplicationKind::BoundReceiver => Some(true),
                    CallApplicationKind::ReceiverBindingUnknown | CallApplicationKind::Unknown => {
                        None
                    }
                });
                match (
                    exact,
                    has_receiver,
                    crate::analyzer::semantic::split_qualified_member(target),
                ) {
                    (Some(proof), Some(has_receiver), Some((owner, member))) => {
                        arms.push(ModeledCallTargetArm {
                            key: ModeledProcedureKey {
                                language: Language::Go.config_label().to_owned(),
                                owner: owner.to_owned(),
                                member: member.to_owned(),
                                has_receiver,
                                parameter_count: proof.parameter_count(),
                            },
                            origin: ModeledCallTargetOrigin::UnmaterializedExternal,
                        });
                    }
                    _ => {
                        residual = residual.saturating_add(1);
                        potentially_modeled_residual = true;
                    }
                }
            }
            CallDispatchBoundaryKind::External {
                callee_text: Some(_),
                ..
            } if language_for_file(&shape.outcome.file) == Language::Go
                && !matches!(
                    call_application,
                    CallApplicationKind::PackageFunction | CallApplicationKind::BoundReceiver
                ) =>
            {
                residual = residual.saturating_add(1);
                potentially_modeled_residual = true;
            }
            CallDispatchBoundaryKind::External {
                callee_text: Some(_),
                ..
            } if language_for_file(&shape.outcome.file) == Language::Go
                && call_application == CallApplicationKind::BoundReceiver =>
            {
                residual = residual.saturating_add(1);
                potentially_modeled_residual = true;
            }
            CallDispatchBoundaryKind::External {
                callee_text: Some(_),
                ..
            } => {
                unsupported = true;
                residual = residual.saturating_add(1);
            }
            CallDispatchBoundaryKind::Truncated => {
                residual = residual.saturating_add(1);
            }
            CallDispatchBoundaryKind::External {
                callee_text: None, ..
            }
            | CallDispatchBoundaryKind::UnprovenTargetIdentity => {
                residual = residual.saturating_add(1);
                potentially_modeled_residual = true;
            }
            CallDispatchBoundaryKind::Unresolved(status)
            | CallDispatchBoundaryKind::UnresolvedWithTarget { status, .. } => {
                residual = residual.saturating_add(1);
                if lookup.adjudicated_no_target
                    && matches!(
                        call_application,
                        CallApplicationKind::Unknown | CallApplicationKind::PackageFunction
                    )
                {
                    continue;
                }
                match status {
                    DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous => {
                        potentially_modeled_residual = true;
                    }
                    DefinitionLookupStatus::NoDefinition | DefinitionLookupStatus::NotFound => {
                        potentially_modeled_residual = true;
                    }
                    DefinitionLookupStatus::UnsupportedLanguage
                    | DefinitionLookupStatus::InvalidLocation => unsupported = true,
                    DefinitionLookupStatus::UnresolvableImportBoundary => {
                        potentially_modeled_residual = true;
                    }
                }
            }
        }
    }
    arms.sort();
    arms.dedup();
    adjudicable_workspace_names.sort();
    adjudicable_workspace_names.dedup();

    let coverage = if lookup.cancelled {
        ModeledCallTargetCoverage::Cancelled
    } else if lookup.budget_exhausted || lookup.truncated {
        ModeledCallTargetCoverage::Truncated
    } else if unsupported {
        ModeledCallTargetCoverage::Unsupported
    } else if residual > 0
        && arms.is_empty()
        && adjudicable_workspace_names.is_empty()
        && !potentially_modeled_residual
    {
        ModeledCallTargetCoverage::Unmodeled
    } else if residual > 0 || lookup.status.is_none() {
        ModeledCallTargetCoverage::Open
    } else {
        ModeledCallTargetCoverage::Exhaustive
    };
    ModeledCallTargetLookup {
        arms,
        adjudicable_workspace_names,
        call_application: match call_application {
            CallApplicationKind::PackageFunction => ModeledCallApplication::PackageFunction,
            CallApplicationKind::BoundReceiver => ModeledCallApplication::BoundReceiver,
            CallApplicationKind::ReceiverBindingUnknown => {
                ModeledCallApplication::ReceiverBindingUnknown
            }
            CallApplicationKind::Unknown => ModeledCallApplication::Unknown,
        },
        coverage,
    }
}

impl ModeledProcedureKey {
    /// The human-readable spelling of this key, retained on rows as the
    /// modeled-target text identity.
    pub fn display(&self) -> String {
        format!(
            "{}.{}/{}{}",
            self.owner,
            self.member,
            self.parameter_count,
            if self.has_receiver { "+recv" } else { "" }
        )
    }
}

/// One activated declaration bound to one exact callee, with the pack
/// provenance the row publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDeclaredEffect {
    pub effect_id: String,
    pub timing: EffectTiming,
    pub execution_timing: ExecutionTiming,
    pub certainty: EffectCertainty,
    pub pack_id: String,
    pub model_id: String,
    pub summary_id: String,
}

impl BoundDeclaredEffect {
    pub fn new(
        effect: &CompiledDeclaredEffect,
        pack_id: impl Into<String>,
        model_id: impl Into<String>,
        summary_id: impl Into<String>,
    ) -> Self {
        Self {
            effect_id: effect.id.clone(),
            timing: EffectTiming::from_compiled(effect.timing),
            execution_timing: declared_effect_execution_timing(effect.timing),
            certainty: EffectCertainty::from_compiled(effect.certainty),
            pack_id: pack_id.into(),
            model_id: model_id.into(),
            summary_id: summary_id.into(),
        }
    }
}

/// What the caller established about one dispatch arm of one call site.
///
/// Everything on this struct is copied from the analyzer's own dispatch answer
/// or from the activated pack; this module re-derives none of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEffectArm {
    /// The arm's semantic target identity, equal to `dispatch_target.target_id`.
    pub target_id: String,
    /// The workspace declaration identity of the callee, when the workspace
    /// indexes one.
    pub callee_declaration_id: Option<String>,
    /// The canonical key the declaration lookup used, when one could be built.
    pub key: Option<ModeledProcedureKey>,
    pub proof: EffectProof,
    /// Whether the arm's own evidence is complete, from the dispatch answer.
    pub complete: bool,
    /// When this exact source call executes relative to its registering
    /// construct, copied from the semantic call site.
    pub execution_timing: ExecutionTiming,
    /// What the activated pack lookup answered for this arm.
    pub lookup: ArmLookup,
}

/// The activated-pack answer for one arm's callee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmLookup {
    /// A unique activated summary models the callee; these are its
    /// declarations, in the compiler's canonical order. The callee's own
    /// behaviour is still reachable some other way -- a workspace body the
    /// walk reads, or an implementation the summary does not claim to speak
    /// for -- so the arm's own dispatch evidence still decides its coverage.
    Declared(Vec<BoundDeclaredEffect>),
    /// A unique activated summary is the *whole* answer for a callee the
    /// workspace does not materialize: it is authored complete, and either the
    /// callee is receiverless (nothing can override it) or the author claimed
    /// `covers_overrides` for every implementation outside the workspace
    /// (#2371).
    ///
    /// Such an arm closes. There is no body to read, and the resolver's own
    /// evidence about the callee is deliberately partial precisely because an
    /// activated summary is what supplies it, so treating that partial mark as
    /// a gap would make an authored claim unusable by construction. An empty
    /// declaration list here is the reviewed claim that the member performs no
    /// declared effect, not a row that went missing.
    SummarizedExternal(Vec<BoundDeclaredEffect>),
    /// No canonical key could be built for the arm's target.
    Unkeyable,
    /// Several activated summaries disagree about the callee.
    Conflict,
    /// A key exists and no activated pack declares anything for it. Whether
    /// this is a coverage gap depends on `analyzable`: a workspace procedure
    /// with a body is covered by propagation, an external callee is not.
    Unmodeled { analyzable: bool },
}

impl ArmLookup {
    /// Whether an authored complete summary is this arm's evidence, so the
    /// resolver's own `partial` mark on the arm states an absence the summary
    /// has already filled rather than a gap.
    ///
    /// One predicate, used for both axes the mark feeds -- the site's coverage
    /// and the row's certainty -- because it is one fact about the arm.
    pub const fn is_closed_by_summary(&self) -> bool {
        matches!(self, Self::SummarizedExternal(_))
    }
}

/// One direct effect row of one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEffectRow {
    pub id: String,
    pub site_id: String,
    pub site_ast_id: String,
    pub range: Range,
    pub target_id: Option<String>,
    pub callee_declaration_id: Option<String>,
    pub callee_symbol: Option<String>,
    pub effect_id: Option<String>,
    pub classification: EffectClassification,
    pub timing: Option<EffectTiming>,
    pub execution_timing: Option<ExecutionTiming>,
    pub certainty: Option<EffectCertainty>,
    pub proof: Option<EffectProof>,
    pub derivation: EffectDerivation,
    pub reason: Option<EffectReason>,
    pub pack_id: Option<String>,
    pub model_id: Option<String>,
    pub summary_id: Option<String>,
    pub terminal: bool,
}

/// Every direct effect row of one call site, plus the site-wide facts each row
/// repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEffectReport {
    pub file: ProjectFile,
    pub site_id: String,
    pub site_ast_id: String,
    /// The site's candidate coverage, met with every arm's own gaps.
    pub coverage: EffectCoverage,
    /// How many dispatch arms the site published.
    pub arm_count: usize,
    /// How many arms a unique activated summary modeled.
    pub modeled_arm_count: usize,
    pub rows: Vec<CallEffectRow>,
}

/// The site-level status the caller already knows before any arm is examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEffectSiteStatus {
    /// Dispatch produced an answer; `coverage` is its candidate coverage.
    Answered { coverage: EffectCoverage },
    /// Dispatch never ran to a published answer.
    Interrupted { reason: EffectReason },
}

/// Derive the direct effect rows of one call site.
///
/// The report is mandatory: a site with no modeled arm still yields exactly one
/// terminal row, so zero rows can never be read as "this call has no effect".
pub fn call_effect_report(
    file: &ProjectFile,
    site_id: &str,
    site_ast_id: &str,
    range: Range,
    status: CallEffectSiteStatus,
    arms: &[CallEffectArm],
) -> CallEffectReport {
    let mut coverage = match status {
        CallEffectSiteStatus::Answered { coverage } => coverage,
        CallEffectSiteStatus::Interrupted { .. } => EffectCoverage::Open,
    };
    let interrupted = match status {
        CallEffectSiteStatus::Answered { .. } => None,
        CallEffectSiteStatus::Interrupted { reason } => Some(reason),
    };
    if let Some(reason) = interrupted
        && reason == EffectReason::DispatchUnsupported
    {
        coverage = EffectCoverage::Unsupported;
    }

    // Definite attribution needs all three axes the dispatch answer publishes,
    // exactly as `DispatchSiteAnswer::dispatch_label` does: an exhaustive
    // candidate set with one arm in it, and that arm proven and complete. A
    // second candidate, or a set that may hold an unseen one, means this call
    // may reach a different callee, so the effect is possible even when the arm
    // itself is proven.
    let site_definite = coverage.is_exhaustive() && arms.len() == 1;
    let mut rows = Vec::new();
    let mut modeled_arm_count = 0usize;
    let mut gap: Option<EffectReason> = None;
    for arm in arms {
        // A summarized external arm carries no dispatch evidence that could be
        // incomplete: the resolver marks it partial exactly because the callee's
        // body is outside the indexed workspace, and the complete summary is
        // what supplies it. Every other arm's own completeness still governs.
        if !arm.complete && !arm.lookup.is_closed_by_summary() {
            gap = gap.or(Some(EffectReason::DispatchUnresolved));
            coverage = coverage.meet(EffectCoverage::Open);
        }
        match &arm.lookup {
            ArmLookup::Declared(effects) | ArmLookup::SummarizedExternal(effects) => {
                modeled_arm_count = modeled_arm_count.saturating_add(1);
                for effect in effects {
                    rows.push(declared_call_effect_row(
                        site_id,
                        site_ast_id,
                        range,
                        arm,
                        effect,
                        site_definite,
                    ));
                }
            }
            ArmLookup::Unkeyable => {
                gap = gap.or(Some(EffectReason::CalleeUnkeyable));
                coverage = coverage.meet(EffectCoverage::Open);
            }
            ArmLookup::Conflict => {
                gap = gap.or(Some(EffectReason::ModelConflict));
                coverage = coverage.meet(EffectCoverage::Open);
            }
            ArmLookup::Unmodeled { analyzable } => {
                if !analyzable {
                    gap = gap.or(Some(EffectReason::CalleeUnmodeled));
                    coverage = coverage.meet(EffectCoverage::Open);
                }
            }
        }
    }
    if let Some(reason) = interrupted {
        gap = Some(reason);
    }
    if arms.is_empty() && interrupted.is_none() && !coverage.is_exhaustive() {
        gap = gap.or(Some(EffectReason::DispatchUnresolved));
    }
    if coverage == EffectCoverage::Truncated {
        gap = gap.or(Some(EffectReason::DispatchTruncated));
    }

    if rows.is_empty() {
        let derivation = if interrupted == Some(EffectReason::DispatchUnsupported) {
            EffectDerivation::Unsupported
        } else if gap.is_some() {
            EffectDerivation::Incomplete
        } else {
            EffectDerivation::None
        };
        rows.push(CallEffectRow {
            id: call_effect_row_id(site_id, None, None),
            site_id: site_id.to_owned(),
            site_ast_id: site_ast_id.to_owned(),
            range,
            target_id: None,
            callee_declaration_id: None,
            callee_symbol: None,
            effect_id: None,
            classification: EffectClassification::Direct,
            timing: None,
            execution_timing: None,
            certainty: None,
            proof: None,
            derivation,
            reason: gap,
            pack_id: None,
            model_id: None,
            summary_id: None,
            terminal: true,
        });
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    CallEffectReport {
        file: file.clone(),
        site_id: site_id.to_owned(),
        site_ast_id: site_ast_id.to_owned(),
        coverage,
        arm_count: arms.len(),
        modeled_arm_count,
        rows,
    }
}

fn declared_call_effect_row(
    site_id: &str,
    site_ast_id: &str,
    range: Range,
    arm: &CallEffectArm,
    effect: &BoundDeclaredEffect,
    site_definite: bool,
) -> CallEffectRow {
    // The meet is the whole certainty rule: a `possible` declaration stays
    // possible under a proven dispatch, and a `definite` declaration is
    // downgraded by an unproven or incomplete arm, or by a candidate set that
    // may hold another callee.
    let dispatch_certainty = if site_definite
        && arm.proof == EffectProof::Proven
        && (arm.complete || arm.lookup.is_closed_by_summary())
    {
        EffectCertainty::Definite
    } else {
        EffectCertainty::Possible
    };
    CallEffectRow {
        id: call_effect_row_id(site_id, Some(&arm.target_id), Some(&effect.effect_id)),
        site_id: site_id.to_owned(),
        site_ast_id: site_ast_id.to_owned(),
        range,
        target_id: Some(arm.target_id.clone()),
        callee_declaration_id: arm.callee_declaration_id.clone(),
        callee_symbol: arm.key.as_ref().map(ModeledProcedureKey::display),
        effect_id: Some(effect.effect_id.clone()),
        classification: EffectClassification::Direct,
        timing: Some(effect.timing),
        execution_timing: Some(arm.execution_timing.compose(effect.execution_timing)),
        certainty: Some(effect.certainty.meet(dispatch_certainty)),
        proof: Some(arm.proof),
        derivation: EffectDerivation::Declared,
        reason: None,
        pack_id: Some(effect.pack_id.clone()),
        model_id: Some(effect.model_id.clone()),
        summary_id: Some(effect.summary_id.clone()),
        terminal: false,
    }
}

fn call_effect_row_id(site_id: &str, target_id: Option<&str>, effect_id: Option<&str>) -> String {
    let mut digest = LengthDelimitedDigest::new(CALL_EFFECT_ID_DOMAIN);
    digest.push(site_id.as_bytes());
    match target_id {
        Some(target) => {
            digest.push(b"target");
            digest.push(target.as_bytes());
        }
        None => digest.push(b"terminal"),
    }
    match effect_id {
        Some(effect) => {
            digest.push(b"effect");
            digest.push(effect.as_bytes());
        }
        None => digest.push(b"no_effect"),
    }
    digest.finish().to_string()
}

// ---------------------------------------------------------------------------
// Procedure effect summaries
// ---------------------------------------------------------------------------

/// Explicit bounds on the transitive fixpoint.
///
/// Every bound is stated rather than defaulted at a call site, and every one of
/// them degrades a procedure's coverage instead of silently truncating an
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcedureEffectBudget {
    /// How many distinct procedures the reachable call graph may hold.
    pub max_procedures: usize,
    /// How many call edges the graph may hold in total.
    pub max_edges: usize,
    /// How many call hops the walk may take from a seed procedure.
    pub max_depth: usize,
    /// How many distinct effect ids one procedure may publish.
    pub max_effects_per_procedure: usize,
    /// How many hops one retained witness chain may hold.
    pub max_witness_steps: usize,
    /// How many fixpoint sweeps the solver may run before it declares the
    /// answer truncated. A converging graph needs at most one sweep per
    /// component in reverse topological order; the bound exists so a
    /// pathological input cannot spin.
    pub max_iterations: usize,
}

impl Default for ProcedureEffectBudget {
    fn default() -> Self {
        Self {
            max_procedures: 4_096,
            max_edges: 32_768,
            max_depth: 32,
            max_effects_per_procedure: 64,
            max_witness_steps: 16,
            max_iterations: 64,
        }
    }
}

/// How one graph node's own effect set was established.
///
/// A node publishes an exhaustive effect set only when one of the two positive
/// bases holds. They are genuinely different proofs of the same fact -- "every
/// effect this procedure performs is accounted for" -- so the node records
/// which one it has rather than collapsing them into a boolean nobody can read
/// back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectNodeBasis {
    /// Nothing established the node's effect set: its body was never read and
    /// no summary states it. Every absence claim reaching it is non-exhaustive.
    Unestablished,
    /// The body was read and its call sites enumerated, so the node's effects
    /// are its declarations plus whatever propagates along its outgoing edges.
    BodyRead,
    /// A complete activated summary states the member's effects in full. The
    /// node is a leaf -- its own callees are outside the workspace and are not
    /// analyzable -- and that is not a gap, because the summary's completeness
    /// claim is exactly the assertion that nothing else is reachable through
    /// it. An empty `declared` list under this basis is the reviewed claim
    /// "this member performs no declared effect".
    CompleteSummary,
}

impl EffectNodeBasis {
    /// Whether the node's own effect set is complete, so an absence claim
    /// through it can stay exhaustive.
    pub const fn is_established(self) -> bool {
        matches!(self, Self::BodyRead | Self::CompleteSummary)
    }
}

/// One node of the reachable call graph the fixpoint runs over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectGraphProcedure {
    /// The procedure's stable declaration identity.
    pub declaration_id: String,
    /// A bounded display name, retained for the witness chain.
    pub display_name: String,
    /// Effects an activated pack declares for this procedure itself.
    pub declared: Vec<BoundDeclaredEffect>,
    /// What establishes this procedure's own effect set.
    pub basis: EffectNodeBasis,
    /// Typed gaps found while enumerating this procedure's call sites.
    pub local_gaps: Vec<EffectReason>,
}

/// One call edge of the reachable call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectGraphEdge {
    /// Index into the procedure list.
    pub caller: usize,
    /// Index into the procedure list.
    pub callee: usize,
    /// The `call_shape` site identity of the call that creates this edge, so a
    /// witness step joins the `call_effect` and `call_shape` domains by id.
    pub site_id: String,
    /// Whether dispatch proved this exact edge and nothing else.
    pub certainty: EffectCertainty,
    /// When the callee invocation executes relative to the caller.
    pub execution_timing: ExecutionTiming,
}

/// The reachable call graph of one query's procedures.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectGraph {
    pub procedures: Vec<EffectGraphProcedure>,
    pub edges: Vec<EffectGraphEdge>,
    /// Whether discovery itself hit a bound.
    pub truncated: bool,
}

/// One retained witness step: the call site that carries the hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectWitnessStep {
    pub site_id: String,
    pub callee_display_name: String,
}

/// One procedure-effect summary row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureEffectRow {
    pub id: String,
    pub procedure_declaration_id: String,
    pub procedure_name: String,
    pub effect_id: Option<String>,
    pub classification: Option<EffectClassification>,
    pub certainty: Option<EffectCertainty>,
    pub timing: Option<EffectTiming>,
    pub execution_timing: Option<ExecutionTiming>,
    /// Call hops from this procedure to the procedure the pack declares the
    /// effect on. `0` means the pack declares it on this procedure itself.
    pub depth: Option<usize>,
    pub derivation: EffectDerivation,
    pub reason: Option<EffectReason>,
    pub coverage: EffectCoverage,
    /// The retained witness chain, from this procedure outward, bounded by
    /// `max_witness_steps`.
    pub witness: Vec<EffectWitnessStep>,
    pub witness_truncated: bool,
    pub pack_id: Option<String>,
    pub model_id: Option<String>,
    pub summary_id: Option<String>,
    pub terminal: bool,
}

impl ProcedureEffectRow {
    /// The call site that establishes the effect: the last retained witness
    /// step, or none when the pack declares the effect on this procedure.
    pub fn witness_effect_site_id(&self) -> Option<&str> {
        self.witness.last().map(|step| step.site_id.as_str())
    }

    /// The first hop out of this procedure, when the chain has one.
    pub fn witness_site_id(&self) -> Option<&str> {
        self.witness.first().map(|step| step.site_id.as_str())
    }

    /// The bounded rendered chain a reader sees, `A -> B -> C`.
    pub fn witness_chain(&self) -> Option<String> {
        if self.witness.is_empty() {
            return None;
        }
        let mut rendered = self.procedure_name.clone();
        for step in &self.witness {
            rendered.push_str(" -> ");
            rendered.push_str(&step.callee_display_name);
        }
        if self.witness_truncated {
            rendered.push_str(" -> …");
        }
        Some(rendered)
    }
}

/// One procedure's complete summary: at least one row, always.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureEffectReport {
    pub procedure_declaration_id: String,
    pub coverage: EffectCoverage,
    pub rows: Vec<ProcedureEffectRow>,
}

/// One effect attributed to one procedure during the fixpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttributedEffect {
    depth: usize,
    certainty: EffectCertainty,
    timing: EffectTiming,
    execution_timing: ExecutionTiming,
    witness: Vec<EffectWitnessStep>,
    witness_truncated: bool,
    pack_id: String,
    model_id: String,
    summary_id: String,
}

impl AttributedEffect {
    /// Merge another attribution of the same effect onto the same procedure.
    ///
    /// The retained witness is the shallowest chain, and ties break on the
    /// chain's own site ids, so the answer does not depend on visit order.
    /// Certainty joins to the best-evidenced chain; timing joins to `Unknown`
    /// on disagreement, which is what keeps a deferred path from being
    /// laundered into an immediate claim.
    fn merge(&mut self, other: Self) -> bool {
        let mut changed = false;
        let certainty = self.certainty.join(other.certainty);
        if certainty != self.certainty {
            self.certainty = certainty;
            changed = true;
        }
        let timing = self.timing.join(other.timing);
        if timing != self.timing {
            self.timing = timing;
            changed = true;
        }
        let execution_timing = self.execution_timing.join(other.execution_timing);
        if execution_timing != self.execution_timing {
            self.execution_timing = execution_timing;
            changed = true;
        }
        let better =
            (other.depth, witness_key(&other.witness)) < (self.depth, witness_key(&self.witness));
        if better {
            self.depth = other.depth;
            self.witness = other.witness;
            self.witness_truncated = other.witness_truncated;
            self.pack_id = other.pack_id;
            self.model_id = other.model_id;
            self.summary_id = other.summary_id;
            changed = true;
        }
        changed
    }
}

fn witness_key(witness: &[EffectWitnessStep]) -> Vec<&str> {
    witness.iter().map(|step| step.site_id.as_str()).collect()
}

/// The dense call graph the SCC pass runs over.
#[derive(Debug)]
struct CallGraphView {
    outgoing: Vec<Vec<usize>>,
    incoming: Vec<Vec<usize>>,
    edges: Vec<(usize, usize)>,
}

impl CallGraphView {
    fn new(node_count: usize, edges: &[EffectGraphEdge]) -> Self {
        let mut pairs = edges
            .iter()
            .map(|edge| (edge.caller, edge.callee))
            .collect::<Vec<_>>();
        pairs.sort_unstable();
        pairs.dedup();
        let mut outgoing = vec![Vec::new(); node_count];
        let mut incoming = vec![Vec::new(); node_count];
        for (index, &(caller, callee)) in pairs.iter().enumerate() {
            outgoing[caller].push(index);
            incoming[callee].push(index);
        }
        Self {
            outgoing,
            incoming,
            edges: pairs,
        }
    }
}

impl DenseBidirectionalGraph for CallGraphView {
    type Node = usize;
    type Edge = usize;

    fn node_count(&self) -> usize {
        self.outgoing.len()
    }

    fn node_at(&self, index: usize) -> Option<Self::Node> {
        (index < self.outgoing.len()).then_some(index)
    }

    fn node_index(&self, node: Self::Node) -> Option<usize> {
        (node < self.outgoing.len()).then_some(node)
    }

    fn successors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.outgoing[node]
            .iter()
            .copied()
            .map(|edge| (edge, self.edges[edge].1))
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        self.incoming[node]
            .iter()
            .copied()
            .map(|edge| (edge, self.edges[edge].0))
    }

    fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
        self.edges.get(edge).copied()
    }
}

/// Run the bounded deterministic fixpoint and project one report per procedure.
///
/// The algorithm is a reverse-topological sweep over the graph's strongly
/// connected components, using the analyzer's own
/// [`strongly_connected_components`] rather than a second cycle detector, so a
/// recursive cycle converges in a bounded number of sweeps instead of
/// recursing. Effects flow from callee to caller: a caller inherits every
/// effect of every callee, one hop deeper, with the edge's certainty met into
/// the effect's own.
///
/// Every bound is a coverage degradation, never a silent loss: a truncated
/// discovery, an exhausted per-procedure effect bound and an unconverged
/// fixpoint each mark the affected procedures non-exhaustive.
pub fn summarize_procedure_effects(
    graph: &EffectGraph,
    budget: ProcedureEffectBudget,
) -> Vec<ProcedureEffectReport> {
    let node_count = graph.procedures.len();
    let view = CallGraphView::new(node_count, &graph.edges);
    let cancellation = CancellationToken::new();
    let mut algorithm_budget = CfgAlgorithmBudget::default();
    let mut request = CfgAlgorithmRequest::new(&mut algorithm_budget, &cancellation);
    let components = strongly_connected_components(&view, &mut request)
        .map(|result| result.components)
        .unwrap_or_else(|_| {
            // The SCC pass is bounded like every other analyzer graph walk. If
            // it cannot finish, treat every procedure as its own component and
            // let the iteration bound below report the truncation, rather than
            // dropping the answer.
            (0..node_count)
                .map(|node| vec![node].into_boxed_slice())
                .collect()
        });

    let mut component_by_node = vec![0usize; node_count];
    for (component, members) in components.iter().enumerate() {
        for &member in members.iter() {
            component_by_node[member] = component;
        }
    }

    let mut effects: Vec<BTreeMap<String, AttributedEffect>> = graph
        .procedures
        .iter()
        .map(|procedure| {
            procedure
                .declared
                .iter()
                .map(|declared| {
                    (
                        declared.effect_id.clone(),
                        AttributedEffect {
                            depth: 0,
                            certainty: declared.certainty,
                            timing: declared.timing,
                            execution_timing: declared.execution_timing,
                            witness: Vec::new(),
                            witness_truncated: false,
                            pack_id: declared.pack_id.clone(),
                            model_id: declared.model_id.clone(),
                            summary_id: declared.summary_id.clone(),
                        },
                    )
                })
                .collect()
        })
        .collect();

    let mut effect_budget_exhausted = vec![false; node_count];
    let mut depth_exhausted = vec![false; node_count];
    let mut sweeps = 0usize;
    let mut unconverged = false;
    // `strongly_connected_components` publishes components in a canonical
    // order; sweeping them in reverse propagates a callee's answer to its
    // caller within one pass on an acyclic graph, and repeats only for cycles.
    loop {
        sweeps = sweeps.saturating_add(1);
        if sweeps > budget.max_iterations {
            unconverged = true;
            break;
        }
        let mut changed = false;
        for component in components.iter().rev() {
            for &node in component.iter() {
                for edge in &graph.edges {
                    if edge.caller != node {
                        continue;
                    }
                    let callee = edge.callee;
                    let inherited = effects[callee]
                        .iter()
                        .map(|(id, effect)| (id.clone(), effect.clone()))
                        .collect::<Vec<_>>();
                    for (effect_id, source) in inherited {
                        let depth = source.depth.saturating_add(1);
                        if depth > budget.max_depth {
                            depth_exhausted[node] = true;
                            continue;
                        }
                        let mut witness = Vec::with_capacity(source.witness.len() + 1);
                        witness.push(EffectWitnessStep {
                            site_id: edge.site_id.clone(),
                            callee_display_name: graph.procedures[callee].display_name.clone(),
                        });
                        witness.extend(source.witness.iter().cloned());
                        let witness_truncated =
                            source.witness_truncated || witness.len() > budget.max_witness_steps;
                        witness.truncate(budget.max_witness_steps);
                        let candidate = AttributedEffect {
                            depth,
                            certainty: source.certainty.meet(edge.certainty),
                            timing: source.timing,
                            execution_timing: edge
                                .execution_timing
                                .compose(source.execution_timing),
                            witness,
                            witness_truncated,
                            pack_id: source.pack_id.clone(),
                            model_id: source.model_id.clone(),
                            summary_id: source.summary_id.clone(),
                        };
                        match effects[node].get_mut(&effect_id) {
                            Some(existing) => {
                                changed |= existing.merge(candidate);
                            }
                            None => {
                                if effects[node].len() >= budget.max_effects_per_procedure {
                                    effect_budget_exhausted[node] = true;
                                    continue;
                                }
                                effects[node].insert(effect_id, candidate);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Coverage flows the same direction the effects do: a procedure that cannot
    // prove its own callees' effect sets cannot prove its own.
    let mut coverage = graph
        .procedures
        .iter()
        .enumerate()
        .map(|(node, procedure)| {
            let mut value = if procedure.basis.is_established() {
                EffectCoverage::Exhaustive
            } else {
                EffectCoverage::Open
            };
            if !procedure.local_gaps.is_empty() {
                value = value.meet(EffectCoverage::Open);
            }
            if graph.truncated || effect_budget_exhausted[node] || depth_exhausted[node] {
                value = value.meet(EffectCoverage::Truncated);
            }
            if unconverged {
                value = value.meet(EffectCoverage::Truncated);
            }
            value
        })
        .collect::<Vec<_>>();
    let mut local_reason = graph
        .procedures
        .iter()
        .enumerate()
        .map(|(node, procedure)| {
            if !procedure.basis.is_established() {
                return Some(EffectReason::ProcedureUnreadable);
            }
            if let Some(reason) = procedure.local_gaps.first() {
                return Some(*reason);
            }
            if effect_budget_exhausted[node] {
                return Some(EffectReason::EffectBudgetExhausted);
            }
            if graph.truncated || depth_exhausted[node] || unconverged {
                return Some(EffectReason::ProcedureBudgetExhausted);
            }
            None
        })
        .collect::<Vec<_>>();
    for _ in 0..=components.len() {
        let mut changed = false;
        for edge in &graph.edges {
            let callee = coverage[edge.callee];
            let merged = coverage[edge.caller].meet(callee);
            if merged != coverage[edge.caller] {
                coverage[edge.caller] = merged;
                changed = true;
            }
            if local_reason[edge.caller].is_none()
                && let Some(reason) = local_reason[edge.callee]
            {
                local_reason[edge.caller] = Some(reason);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    graph
        .procedures
        .iter()
        .enumerate()
        .map(|(node, procedure)| {
            let node_coverage = coverage[node];
            let mut rows = effects[node]
                .iter()
                .map(|(effect_id, effect)| ProcedureEffectRow {
                    id: procedure_effect_row_id(&procedure.declaration_id, Some(effect_id)),
                    procedure_declaration_id: procedure.declaration_id.clone(),
                    procedure_name: procedure.display_name.clone(),
                    effect_id: Some(effect_id.clone()),
                    classification: Some(if effect.depth <= 1 {
                        EffectClassification::Direct
                    } else {
                        EffectClassification::Transitive
                    }),
                    certainty: Some(effect.certainty),
                    timing: Some(effect.timing),
                    execution_timing: Some(effect.execution_timing),
                    depth: Some(effect.depth),
                    derivation: EffectDerivation::Declared,
                    reason: None,
                    coverage: node_coverage,
                    witness: effect.witness.clone(),
                    witness_truncated: effect.witness_truncated,
                    pack_id: Some(effect.pack_id.clone()),
                    model_id: Some(effect.model_id.clone()),
                    summary_id: Some(effect.summary_id.clone()),
                    terminal: false,
                })
                .collect::<Vec<_>>();
            if rows.is_empty() {
                let reason = local_reason[node];
                rows.push(ProcedureEffectRow {
                    id: procedure_effect_row_id(&procedure.declaration_id, None),
                    procedure_declaration_id: procedure.declaration_id.clone(),
                    procedure_name: procedure.display_name.clone(),
                    effect_id: None,
                    classification: None,
                    certainty: None,
                    timing: None,
                    execution_timing: None,
                    depth: None,
                    derivation: if node_coverage == EffectCoverage::Unsupported {
                        EffectDerivation::Unsupported
                    } else if reason.is_some() {
                        EffectDerivation::Incomplete
                    } else {
                        EffectDerivation::None
                    },
                    reason,
                    coverage: node_coverage,
                    witness: Vec::new(),
                    witness_truncated: false,
                    pack_id: None,
                    model_id: None,
                    summary_id: None,
                    terminal: true,
                });
            }
            rows.sort_by(|left, right| left.id.cmp(&right.id));
            ProcedureEffectReport {
                procedure_declaration_id: procedure.declaration_id.clone(),
                coverage: node_coverage,
                rows,
            }
        })
        .collect()
}

fn procedure_effect_row_id(declaration_id: &str, effect_id: Option<&str>) -> String {
    let mut digest = LengthDelimitedDigest::new(PROCEDURE_EFFECT_ID_DOMAIN);
    digest.push(declaration_id.as_bytes());
    match effect_id {
        Some(effect) => {
            digest.push(b"effect");
            digest.push(effect.as_bytes());
        }
        None => digest.push(b"terminal"),
    }
    digest.finish().to_string()
}

/// The owner of a module-level declaration, or `None` when the declaration is
/// not module-level (#2610).
///
/// A declaration whose fully-qualified name has no owner segment is qualified
/// by whatever scope encloses it. When the adapter also recorded no package --
/// JavaScript and TypeScript never mint one, Ruby never does, and PHP does only
/// inside a `namespace` -- that scope is the file itself, and the declaration's
/// owner is its module identity. A unit that does carry a package is already
/// qualified by it, so it keeps whatever its own name says and never falls back
/// to a path.
fn module_level_owner(unit: &CodeUnit) -> Option<String> {
    if !unit.package_name().is_empty() {
        return None;
    }
    crate::analyzer::semantic::module_identity_owner(unit.source().rel_path())
}

/// The canonical procedure key for one workspace declaration, or `None` when
/// the declaration has no qualified owner at all.
///
/// The owner and member come from the declaration's own fully-qualified name
/// and never from a rendered call-site text, except that a module-level
/// declaration -- one whose name carries no owner segment and whose adapter
/// minted no package -- is owned by its module identity, the same identity an
/// authored summary names through its target `path` (#2610). The receiver shape
/// and parameter count come from the persisted signature contract. When the
/// adapter never recorded modifiers, the receiver shape is unknown and no key
/// is built: guessing would bind a static member's declaration to an instance
/// member's summary.
pub fn modeled_procedure_key(
    language: &str,
    unit: &CodeUnit,
    has_receiver: Option<bool>,
    parameter_count: Option<u32>,
) -> Option<ModeledProcedureKey> {
    let fq_name = unit.fq_name();
    let (owner, member) = match crate::analyzer::semantic::split_qualified_member(&fq_name) {
        Some((owner, member)) => (owner.to_owned(), member.to_owned()),
        None => (module_level_owner(unit)?, unit.terminal_name().to_owned()),
    };
    Some(ModeledProcedureKey {
        language: language.to_owned(),
        owner,
        member,
        has_receiver: has_receiver?,
        parameter_count: parameter_count?,
    })
}

/// Build the canonical procedure key for one persisted workspace declaration.
///
/// This is the one declaration-side key path shared by effect evaluation and
/// report accounting. It refuses overload sets and unrecorded receiver facts;
/// both cases lack the exact identity required to bind a reviewed summary.
pub fn modeled_procedure_key_for_unit(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<ModeledProcedureKey> {
    if !unit.is_callable() || unit.is_synthetic() {
        return None;
    }
    let entries = analyzer.signature_metadata(unit);
    if entries.len() != 1 {
        return None;
    }
    let mut reports = callable_signature_reports("modeled-procedure-key", unit, &entries);
    let signature = reports.pop()?.signature;
    let has_receiver = match signature.receiver_contract? {
        ReceiverContract::Instance | ReceiverContract::Extension => true,
        ReceiverContract::None | ReceiverContract::StaticOrCompanion => false,
    };
    let parameter_count = u32::try_from(signature.parameter_count).ok()?;
    let language = crate::analyzer::common::language_for_file(unit.source()).config_label();
    modeled_procedure_key(language, unit, Some(has_receiver), Some(parameter_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::structural::NormalizedKind;
    use crate::analyzer::usages::call_relations::{CallDispatchBoundaryKind, CallDispatchLookup};
    use crate::analyzer::usages::call_shape::call_shape_for_call;
    use crate::analyzer::usages::get_definition::ExactExternalCallProof;
    use crate::analyzer::{Language, ProjectFile};
    use crate::test_support::AnalyzerFixture;
    use std::env;

    fn file() -> ProjectFile {
        ProjectFile::new(env::temp_dir().join("bifrost-effects"), "App.java")
    }

    fn range() -> Range {
        Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 0,
            end_line: 0,
        }
    }

    fn declared(
        id: &str,
        execution_timing: ExecutionTiming,
        certainty: EffectCertainty,
    ) -> BoundDeclaredEffect {
        let timing = match execution_timing {
            ExecutionTiming::SameEvaluation | ExecutionTiming::SameInvocation => {
                EffectTiming::Immediate
            }
            ExecutionTiming::DeferredCallback => EffectTiming::Deferred,
            _ => EffectTiming::Unknown,
        };
        BoundDeclaredEffect {
            effect_id: id.to_owned(),
            timing,
            execution_timing,
            certainty,
            pack_id: "acme.effects".to_owned(),
            model_id: "acme.effects/1.0.0".to_owned(),
            summary_id: "summary.send".to_owned(),
        }
    }

    fn arm(target: &str, proof: EffectProof, lookup: ArmLookup) -> CallEffectArm {
        CallEffectArm {
            target_id: target.to_owned(),
            callee_declaration_id: Some(format!("decl:{target}")),
            key: Some(ModeledProcedureKey {
                language: "java".to_owned(),
                owner: "com.acme.AcmeHttpClient".to_owned(),
                member: "send".to_owned(),
                has_receiver: true,
                parameter_count: 1,
            }),
            proof,
            complete: proof == EffectProof::Proven,
            execution_timing: ExecutionTiming::SameEvaluation,
            lookup,
        }
    }

    fn go_shape(
        fixture: &AnalyzerFixture,
        source: &str,
        call: &str,
    ) -> (CallShapeReport, Arc<str>) {
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let facts = fixture
            .analyzer
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(&file))
            .expect("Go structural facts");
        let start = source.rfind(call).expect("call exists");
        let end = start + call.len();
        let call_id = facts
            .nodes()
            .iter()
            .enumerate()
            .find(|(_, node)| {
                node.kind == NormalizedKind::Call
                    && node.range.start_byte == start
                    && node.range.end_byte == end
            })
            .map(|(id, _)| u32::try_from(id).expect("fact node ID fits u32"))
            .expect("exact call node");
        (
            call_shape_for_call(&facts, &file, call_id).expect("exact call shape"),
            Arc::from(source),
        )
    }

    fn modeled_lookup(
        fixture: &AnalyzerFixture,
        shape: &CallShapeReport,
        source: Arc<str>,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ModeledCallTargetLookup {
        modeled_call_targets_for_shape(
            fixture.analyzer.analyzer(),
            shape,
            source,
            limits,
            cancellation,
        )
    }

    #[test]
    fn lightweight_modeled_targets_preserve_go_aliases_and_typed_gaps() {
        let alias_source = r#"package main
import files "os"
func caller() { _, _ = files.Open("book.xlsx") }
"#;
        let alias_fixture =
            AnalyzerFixture::new_for_language(Language::Go, &[("main.go", alias_source)]);
        let (alias_shape, alias_text) =
            go_shape(&alias_fixture, alias_source, "files.Open(\"book.xlsx\")");
        let limits = CallRelationLimits {
            max_files: 1,
            max_source_bytes: usize::MAX,
            max_candidates: 100,
        };
        let alias = modeled_lookup(&alias_fixture, &alias_shape, alias_text, limits, None);
        // The import binder proves package-function application, not that the
        // external package publishes one callable of this exact shape. This
        // fixture activates no declaration overlay, so target coverage stays
        // open even though the canonical alias classification is retained.
        assert_eq!(alias.coverage, ModeledCallTargetCoverage::Open);
        assert!(alias.arms.is_empty(), "{alias:#?}");
        assert_eq!(
            alias.call_application,
            ModeledCallApplication::PackageFunction
        );

        let dot_source = r#"package main
import . "os"
func caller() { _, _ = Open("book.xlsx") }
"#;
        let dot_fixture =
            AnalyzerFixture::new_for_language(Language::Go, &[("main.go", dot_source)]);
        let (dot_shape, dot_text) = go_shape(&dot_fixture, dot_source, "Open(\"book.xlsx\")");
        let dot = modeled_lookup(&dot_fixture, &dot_shape, dot_text, limits, None);
        assert_eq!(dot.coverage, ModeledCallTargetCoverage::Open, "{dot:#?}");
        assert_eq!(
            dot.call_application,
            ModeledCallApplication::PackageFunction,
            "{dot:#?}"
        );
        assert!(dot.arms.is_empty(), "{dot:#?}");

        let shadowed_predeclared_source = r#"package main
import . "os"
func len(values []int) (int, error) { return 0, nil }
func caller(values []int) {
    _, _ = Open("book.xlsx")
    _, _ = len(values)
}
"#;
        let shadowed_predeclared_fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("main.go", shadowed_predeclared_source)],
        );
        let (shadowed_predeclared_shape, shadowed_predeclared_text) = go_shape(
            &shadowed_predeclared_fixture,
            shadowed_predeclared_source,
            "len(values)",
        );
        let shadowed_predeclared = modeled_lookup(
            &shadowed_predeclared_fixture,
            &shadowed_predeclared_shape,
            shadowed_predeclared_text,
            limits,
            None,
        );
        assert!(
            shadowed_predeclared
                .arms
                .iter()
                .all(|arm| arm.key.owner != "os"),
            "{shadowed_predeclared:#?}"
        );
        assert!(
            shadowed_predeclared
                .adjudicable_workspace_names
                .iter()
                .all(|name| name.owner != "os"),
            "{shadowed_predeclared:#?}"
        );
        assert!(
            !shadowed_predeclared.arms.is_empty()
                || !shadowed_predeclared.adjudicable_workspace_names.is_empty(),
            "the package declaration must resolve before predeclared-name adjudication: {shadowed_predeclared:#?}"
        );

        let local_source = r#"package main
import os "os"
type opener struct{}
func (opener) Open(string) (int, error) { return 0, nil }
func caller(os opener) { _, _ = os.Open("book.xlsx") }
"#;
        let local_fixture =
            AnalyzerFixture::new_for_language(Language::Go, &[("main.go", local_source)]);
        let (local_shape, local_text) =
            go_shape(&local_fixture, local_source, "os.Open(\"book.xlsx\")");
        let local = modeled_lookup(&local_fixture, &local_shape, local_text, limits, None);
        assert_eq!(local.coverage, ModeledCallTargetCoverage::Open);
        assert!(local.arms.is_empty(), "{local:#?}");
        let [local_name] = local.adjudicable_workspace_names.as_slice() else {
            panic!("one structured local-method name: {local:#?}");
        };
        assert_ne!(local_name.owner, "os");
        assert_eq!(local_name.member, "Open");
        assert!(local_name.has_receiver);
        assert_eq!(
            local.call_application,
            ModeledCallApplication::BoundReceiver,
            "the parameter binding shadows the package import: {local:#?}"
        );

        let local_callable_source = r#"package main
func caller(Open func(string) (int, error)) { _, _ = Open("book.xlsx") }
"#;
        let local_callable_fixture =
            AnalyzerFixture::new_for_language(Language::Go, &[("main.go", local_callable_source)]);
        let (local_callable_shape, local_callable_text) = go_shape(
            &local_callable_fixture,
            local_callable_source,
            "Open(\"book.xlsx\")",
        );
        let local_callable = modeled_lookup(
            &local_callable_fixture,
            &local_callable_shape,
            local_callable_text,
            limits,
            None,
        );
        assert!(local_callable.arms.is_empty(), "{local_callable:#?}");
        assert_eq!(
            local_callable.coverage,
            ModeledCallTargetCoverage::Unmodeled
        );

        let unresolved_source = r#"package main
func caller() { _, _ = missing.Open("book.xlsx") }
"#;
        let unresolved_fixture =
            AnalyzerFixture::new_for_language(Language::Go, &[("main.go", unresolved_source)]);
        let (unresolved_shape, unresolved_text) = go_shape(
            &unresolved_fixture,
            unresolved_source,
            "missing.Open(\"book.xlsx\")",
        );
        let unresolved = modeled_lookup(
            &unresolved_fixture,
            &unresolved_shape,
            unresolved_text,
            limits,
            None,
        );
        assert!(unresolved.arms.is_empty(), "{unresolved:#?}");
        assert_eq!(unresolved.coverage, ModeledCallTargetCoverage::Open);
        assert_eq!(unresolved.call_application, ModeledCallApplication::Unknown);

        let modeled_with_residual = project_modeled_call_target_lookup(
            alias_fixture.analyzer.analyzer(),
            &alias_shape,
            true,
            CallDispatchLookup {
                status: Some(DefinitionLookupStatus::Ambiguous),
                call_application: CallApplicationKind::PackageFunction,
                exact_external_call: Some(ExactExternalCallProof::go_package_function(
                    "os.Open", 1,
                )),
                boundaries: vec![
                    CallDispatchBoundaryKind::External {
                        callee_text: Some("os.Open".into()),
                        normalized_static_owner: None,
                    },
                    CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NoDefinition),
                ],
                ..CallDispatchLookup::default()
            },
        );
        assert_eq!(
            modeled_with_residual.arms,
            vec![ModeledCallTargetArm {
                key: ModeledProcedureKey {
                    language: "go".to_owned(),
                    owner: "os".to_owned(),
                    member: "Open".to_owned(),
                    has_receiver: false,
                    parameter_count: 1,
                },
                origin: ModeledCallTargetOrigin::UnmaterializedExternal,
            }]
        );
        assert_eq!(
            modeled_with_residual.coverage,
            ModeledCallTargetCoverage::Open
        );

        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let interrupted = modeled_lookup(
            &alias_fixture,
            &alias_shape,
            Arc::from(alias_source),
            limits,
            Some(&cancelled),
        );
        assert!(interrupted.arms.is_empty());
        assert_eq!(interrupted.coverage, ModeledCallTargetCoverage::Cancelled);

        let budgeted = modeled_lookup(
            &alias_fixture,
            &alias_shape,
            Arc::from(alias_source),
            CallRelationLimits {
                max_source_bytes: 1,
                ..limits
            },
            None,
        );
        assert!(budgeted.arms.is_empty());
        assert_eq!(budgeted.coverage, ModeledCallTargetCoverage::Truncated);

        let spread_source = r#"package main
import "fmt"
func caller(values []any) { fmt.Println(values...) }
"#;
        let spread_fixture =
            AnalyzerFixture::new_for_language(Language::Go, &[("main.go", spread_source)]);
        let (spread_shape, spread_text) =
            go_shape(&spread_fixture, spread_source, "fmt.Println(values...)");
        let spread = modeled_lookup(&spread_fixture, &spread_shape, spread_text, limits, None);
        assert!(spread.arms.is_empty(), "{spread:#?}\n{spread_shape:#?}");
        assert_eq!(spread.coverage, ModeledCallTargetCoverage::Unsupported);
    }

    #[test]
    fn exact_concrete_go_receiver_boundary_mints_only_a_receiver_arm() {
        let source = r#"package main
import "testing"
func caller(t *testing.T) { t.Fatal("stop") }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let (shape, _) = go_shape(&fixture, source, "t.Fatal(\"stop\")");
        let dispatch = CallDispatchLookup {
            status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: Some(crate::analyzer::DispatchExtensibility::Closed),
            exact_external_call: Some(ExactExternalCallProof::go_concrete_receiver(
                "testing.T.Fatal",
                1,
            )),
            boundaries: vec![CallDispatchBoundaryKind::External {
                callee_text: Some("testing.T.Fatal".into()),
                normalized_static_owner: None,
            }],
            ..CallDispatchLookup::default()
        };

        let exact = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &shape,
            true,
            dispatch.clone(),
        );
        assert_eq!(exact.coverage, ModeledCallTargetCoverage::Exhaustive);
        assert_eq!(
            exact.arms,
            vec![ModeledCallTargetArm {
                key: ModeledProcedureKey {
                    language: "go".to_owned(),
                    owner: "testing.T".to_owned(),
                    member: "Fatal".to_owned(),
                    has_receiver: true,
                    parameter_count: 1,
                },
                origin: ModeledCallTargetOrigin::UnmaterializedExternal,
            }]
        );
        assert_eq!(
            exact.call_application,
            ModeledCallApplication::BoundReceiver
        );

        let uncertain = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &shape,
            true,
            CallDispatchLookup {
                call_application: CallApplicationKind::ReceiverBindingUnknown,
                exact_external_call: None,
                ..dispatch.clone()
            },
        );
        assert!(uncertain.arms.is_empty(), "{uncertain:#?}");
        assert_eq!(uncertain.coverage, ModeledCallTargetCoverage::Open);

        for dispatch_extensibility in [None, Some(crate::analyzer::DispatchExtensibility::Open)] {
            let open = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                true,
                CallDispatchLookup {
                    dispatch_extensibility,
                    exact_external_call: None,
                    ..dispatch.clone()
                },
            );
            assert!(open.arms.is_empty(), "{open:#?}");
            assert_eq!(open.coverage, ModeledCallTargetCoverage::Open);
        }

        let spread = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &shape,
            false,
            dispatch,
        );
        assert!(spread.arms.is_empty(), "{spread:#?}");
        assert_eq!(spread.coverage, ModeledCallTargetCoverage::Open);
    }

    #[test]
    fn modeled_go_target_uses_resolver_effective_arity_for_a_sole_tuple_call() {
        let source = r#"package main
import model "example.com/model"
func caller() { model.Binary(model.Pair()) }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let (shape, _) = go_shape(&fixture, source, "model.Binary(model.Pair())");
        assert_eq!(
            shape.arguments.len(),
            1,
            "the structural call retains one written argument"
        );
        let lookup = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &shape,
            true,
            CallDispatchLookup {
                status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                call_application: CallApplicationKind::PackageFunction,
                exact_external_call: Some(ExactExternalCallProof::go_package_function(
                    "example.com/model.Binary",
                    2,
                )),
                boundaries: vec![CallDispatchBoundaryKind::External {
                    callee_text: Some("example.com/model.Binary".into()),
                    normalized_static_owner: None,
                }],
                ..CallDispatchLookup::default()
            },
        );

        assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Exhaustive);
        let [arm] = lookup.arms.as_slice() else {
            panic!("one exact modeled arm: {lookup:#?}");
        };
        assert_eq!(arm.key.parameter_count, 2, "{lookup:#?}");
        assert_ne!(
            arm.key,
            ModeledProcedureKey {
                parameter_count: 1,
                ..arm.key.clone()
            },
            "a one-parameter summary cannot bind the two-result expansion"
        );
    }

    #[test]
    fn adjudicated_modeled_go_noncallable_is_unmodeled_not_open() {
        let source = r#"package main
import model "example.com/model"
func caller() { model.Duration(1) }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let (shape, _) = go_shape(&fixture, source, "model.Duration(1)");
        let dispatch = CallDispatchLookup {
            status: Some(DefinitionLookupStatus::NoDefinition),
            call_application: CallApplicationKind::PackageFunction,
            adjudicated_no_target: true,
            boundaries: vec![CallDispatchBoundaryKind::Unresolved(
                DefinitionLookupStatus::NoDefinition,
            )],
            ..CallDispatchLookup::default()
        };

        let adjudicated = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &shape,
            true,
            dispatch.clone(),
        );
        assert!(adjudicated.arms.is_empty(), "{adjudicated:#?}");
        assert_eq!(adjudicated.coverage, ModeledCallTargetCoverage::Unmodeled);

        let unproven = project_modeled_call_target_lookup(
            fixture.analyzer.analyzer(),
            &shape,
            true,
            CallDispatchLookup {
                adjudicated_no_target: false,
                ..dispatch
            },
        );
        assert!(unproven.arms.is_empty(), "{unproven:#?}");
        assert_eq!(unproven.coverage, ModeledCallTargetCoverage::Open);
    }

    #[test]
    fn external_typed_go_receiver_is_adjudicated_without_minting_a_target() {
        let source = r#"package main
import "embed"
var embedded embed.FS
func factory() embed.FS { return embedded }
func caller() {
    _, _ = embedded.Open("book.xlsx")
    _, _ = factory().Open("book.xlsx")
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
        let (shape, text) = go_shape(&fixture, source, "embedded.Open(\"book.xlsx\")");
        let lookup = modeled_lookup(
            &fixture,
            &shape,
            text,
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: 100,
            },
            None,
        );
        assert!(lookup.arms.is_empty(), "{lookup:#?}");
        assert!(lookup.adjudicable_workspace_names.is_empty(), "{lookup:#?}");
        assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Open);
        assert_eq!(
            lookup.call_application,
            ModeledCallApplication::BoundReceiver,
            "{lookup:#?}"
        );

        let (structured_shape, structured_text) =
            go_shape(&fixture, source, "factory().Open(\"book.xlsx\")");
        let structured = modeled_lookup(
            &fixture,
            &structured_shape,
            structured_text,
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: 100,
            },
            None,
        );
        assert!(structured.arms.is_empty(), "{structured:#?}");
        assert_eq!(structured.coverage, ModeledCallTargetCoverage::Open);
        assert_eq!(
            structured.call_application,
            ModeledCallApplication::BoundReceiver,
            "the structured call-expression base is a value: {structured:#?}"
        );
    }

    #[test]
    fn a_proven_arm_and_a_definite_declaration_yield_a_definite_direct_row() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    ExecutionTiming::SameEvaluation,
                    EffectCertainty::Definite,
                )]),
            )],
        );
        assert_eq!(report.rows.len(), 1);
        let row = &report.rows[0];
        assert_eq!(row.derivation, EffectDerivation::Declared);
        assert_eq!(row.certainty, Some(EffectCertainty::Definite));
        assert_eq!(row.classification, EffectClassification::Direct);
        assert_eq!(row.timing, Some(EffectTiming::Immediate));
        assert_eq!(row.execution_timing, Some(ExecutionTiming::SameEvaluation));
        assert_eq!(report.coverage, EffectCoverage::Exhaustive);
        assert!(!row.terminal);
    }

    #[test]
    fn exact_call_execution_composes_with_declared_effect_timing() {
        for (call_timing, effect_timing, expected) in [
            (
                ExecutionTiming::SameEvaluation,
                ExecutionTiming::SameInvocation,
                ExecutionTiming::SameInvocation,
            ),
            (
                ExecutionTiming::SameInvocation,
                ExecutionTiming::SameInvocation,
                ExecutionTiming::SameInvocation,
            ),
            (
                ExecutionTiming::DifferentTask,
                ExecutionTiming::SameInvocation,
                ExecutionTiming::DifferentTask,
            ),
            (
                ExecutionTiming::DifferentTask,
                ExecutionTiming::DeferredCallback,
                ExecutionTiming::Unknown,
            ),
            (
                ExecutionTiming::Unknown,
                ExecutionTiming::SameInvocation,
                ExecutionTiming::Unknown,
            ),
        ] {
            let authored_timing = match effect_timing {
                ExecutionTiming::DeferredCallback => EffectTiming::Deferred,
                ExecutionTiming::Unknown => EffectTiming::Unknown,
                _ => EffectTiming::Immediate,
            };
            let mut effect_arm = arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    effect_timing,
                    EffectCertainty::Definite,
                )]),
            );
            effect_arm.execution_timing = call_timing;
            let report = call_effect_report(
                &file(),
                "site",
                "ast",
                range(),
                CallEffectSiteStatus::Answered {
                    coverage: EffectCoverage::Exhaustive,
                },
                &[effect_arm],
            );
            assert_eq!(report.rows[0].timing, Some(authored_timing));
            assert_eq!(report.rows[0].execution_timing, Some(expected));
        }
    }

    #[test]
    fn authored_immediate_effect_means_before_return_not_same_program_point() {
        assert_eq!(
            EffectTiming::from_compiled(CompiledDeclaredEffectTiming::Immediate),
            EffectTiming::Immediate
        );
        assert_eq!(
            declared_effect_execution_timing(CompiledDeclaredEffectTiming::Immediate),
            ExecutionTiming::SameInvocation
        );
        assert_eq!(
            declared_effect_execution_timing(CompiledDeclaredEffectTiming::Deferred),
            ExecutionTiming::DeferredCallback
        );
        assert_eq!(
            declared_effect_execution_timing(CompiledDeclaredEffectTiming::Unknown),
            ExecutionTiming::Unknown
        );
    }

    #[test]
    fn an_unproven_arm_downgrades_a_definite_declaration_to_possible() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Open,
            },
            &[arm(
                "target",
                EffectProof::Unproven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    ExecutionTiming::SameEvaluation,
                    EffectCertainty::Definite,
                )]),
            )],
        );
        assert_eq!(report.rows[0].certainty, Some(EffectCertainty::Possible));
        assert_eq!(report.coverage, EffectCoverage::Open);
    }

    #[test]
    fn a_proven_arm_never_promotes_a_possible_declaration() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Declared(vec![declared(
                    "acme.network_io",
                    ExecutionTiming::SameEvaluation,
                    EffectCertainty::Possible,
                )]),
            )],
        );
        assert_eq!(report.rows[0].certainty, Some(EffectCertainty::Possible));
    }

    #[test]
    fn a_site_with_no_declared_effect_still_states_its_status() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Unmodeled { analyzable: true },
            )],
        );
        assert_eq!(report.rows.len(), 1);
        assert!(report.rows[0].terminal);
        assert_eq!(report.rows[0].derivation, EffectDerivation::None);
        assert_eq!(report.rows[0].reason, None);
        assert_eq!(report.coverage, EffectCoverage::Exhaustive);
    }

    #[test]
    fn an_unmodeled_external_callee_opens_the_sites_coverage() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Answered {
                coverage: EffectCoverage::Exhaustive,
            },
            &[arm(
                "target",
                EffectProof::Proven,
                ArmLookup::Unmodeled { analyzable: false },
            )],
        );
        assert_eq!(report.coverage, EffectCoverage::Open);
        assert_eq!(report.rows[0].derivation, EffectDerivation::Incomplete);
        assert_eq!(report.rows[0].reason, Some(EffectReason::CalleeUnmodeled));
    }

    #[test]
    fn an_interrupted_dispatch_states_the_typed_reason() {
        let report = call_effect_report(
            &file(),
            "site",
            "ast",
            range(),
            CallEffectSiteStatus::Interrupted {
                reason: EffectReason::DispatchUnsupported,
            },
            &[],
        );
        assert_eq!(report.coverage, EffectCoverage::Unsupported);
        assert_eq!(report.rows[0].derivation, EffectDerivation::Unsupported);
        assert_eq!(
            report.rows[0].reason,
            Some(EffectReason::DispatchUnsupported)
        );
    }

    fn procedure(name: &str, declared: Vec<BoundDeclaredEffect>) -> EffectGraphProcedure {
        EffectGraphProcedure {
            declaration_id: format!("decl:{name}"),
            display_name: name.to_owned(),
            declared,
            basis: EffectNodeBasis::BodyRead,
            local_gaps: Vec::new(),
        }
    }

    fn edge(caller: usize, callee: usize, site: &str) -> EffectGraphEdge {
        EffectGraphEdge {
            caller,
            callee,
            site_id: site.to_owned(),
            certainty: EffectCertainty::Definite,
            execution_timing: ExecutionTiming::SameEvaluation,
        }
    }

    #[test]
    fn a_direct_call_to_a_modeled_api_is_depth_one_and_direct() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::SameEvaluation,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        let row = &reports[0].rows[0];
        assert_eq!(row.effect_id.as_deref(), Some("acme.network_io"));
        assert_eq!(row.depth, Some(1));
        assert_eq!(row.classification, Some(EffectClassification::Direct));
        assert_eq!(row.witness.len(), 1);
        assert_eq!(row.witness_effect_site_id(), Some("site.pure"));
        assert_eq!(reports[0].coverage, EffectCoverage::Exhaustive);
    }

    #[test]
    fn a_two_hop_chain_is_transitive_and_retains_the_whole_witness() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure("App.helper", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::SameEvaluation,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.pure"), edge(1, 2, "site.helper")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        let row = &reports[0].rows[0];
        assert_eq!(row.depth, Some(2));
        assert_eq!(row.classification, Some(EffectClassification::Transitive));
        assert_eq!(
            row.witness
                .iter()
                .map(|step| step.site_id.as_str())
                .collect::<Vec<_>>(),
            vec!["site.pure", "site.helper"]
        );
        assert_eq!(
            row.witness_chain().as_deref(),
            Some("App.pure -> App.helper -> AcmeHttpClient.send")
        );
    }

    #[test]
    fn a_recursive_cycle_converges_under_the_iteration_bound() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.a", Vec::new()),
                procedure("App.b", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::SameEvaluation,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![
                edge(0, 1, "site.a"),
                edge(1, 0, "site.b"),
                edge(1, 2, "site.send"),
            ],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        for report in reports.iter().take(2) {
            assert_eq!(report.rows.len(), 1);
            assert_eq!(report.rows[0].effect_id.as_deref(), Some("acme.network_io"));
            assert_eq!(report.coverage, EffectCoverage::Exhaustive);
        }
        // The whole cycle is reachable, so both procedures carry the effect and
        // neither report is truncated.
        assert_eq!(reports[0].rows[0].depth, Some(2));
        assert_eq!(reports[1].rows[0].depth, Some(1));
    }

    #[test]
    fn a_deferred_declaration_stays_deferred_through_propagation() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure("App.helper", Vec::new()),
                procedure(
                    "AcmeScheduler.schedule",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::DeferredCallback,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.pure"), edge(1, 2, "site.helper")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].rows[0].timing, Some(EffectTiming::Deferred));
        assert_eq!(
            reports[0].rows[0].execution_timing,
            Some(ExecutionTiming::DeferredCallback)
        );
    }

    #[test]
    fn call_edge_execution_timing_survives_transitive_propagation() {
        for (execution_timing, expected) in [
            (
                ExecutionTiming::SameInvocation,
                ExecutionTiming::SameInvocation,
            ),
            (
                ExecutionTiming::DifferentTask,
                ExecutionTiming::DifferentTask,
            ),
            (ExecutionTiming::Unknown, ExecutionTiming::Unknown),
        ] {
            let mut call = edge(0, 1, "site.call");
            call.execution_timing = execution_timing;
            let graph = EffectGraph {
                procedures: vec![
                    procedure("App.run", Vec::new()),
                    procedure(
                        "AcmeClient.send",
                        vec![declared(
                            "acme.network_io",
                            ExecutionTiming::SameInvocation,
                            EffectCertainty::Definite,
                        )],
                    ),
                ],
                edges: vec![call],
                truncated: false,
            };
            let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
            assert_eq!(reports[0].rows[0].timing, Some(EffectTiming::Immediate));
            assert_eq!(reports[0].rows[0].execution_timing, Some(expected));
        }
    }

    #[test]
    fn authored_timing_propagates_unchanged_and_disagreeing_origins_join_unknown() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.run", Vec::new()),
                procedure(
                    "AcmeClient.sendNow",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::SameInvocation,
                        EffectCertainty::Definite,
                    )],
                ),
                procedure(
                    "AcmeClient.sendLater",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::DeferredCallback,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.now"), edge(0, 2, "site.later")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].rows[0].timing, Some(EffectTiming::Unknown));
        assert_eq!(
            reports[0].rows[0].execution_timing,
            Some(ExecutionTiming::Unknown)
        );
    }

    #[test]
    fn an_ambiguous_call_edge_downgrades_the_inherited_certainty() {
        let mut ambiguous = edge(0, 1, "site.pure");
        ambiguous.certainty = EffectCertainty::Possible;
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::SameEvaluation,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![ambiguous],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(
            reports[0].rows[0].certainty,
            Some(EffectCertainty::Possible)
        );
    }

    #[test]
    fn an_unreadable_callee_opens_every_caller_that_reaches_it() {
        let mut opaque = procedure("App.opaque", Vec::new());
        opaque.basis = EffectNodeBasis::Unestablished;
        let graph = EffectGraph {
            procedures: vec![procedure("App.pure", Vec::new()), opaque],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].coverage, EffectCoverage::Open);
        assert_eq!(reports[0].rows[0].derivation, EffectDerivation::Incomplete);
        assert_eq!(
            reports[0].rows[0].reason,
            Some(EffectReason::ProcedureUnreadable)
        );
    }

    #[test]
    fn a_summarized_leaf_keeps_its_callers_exhaustive_and_propagates_its_declaration() {
        // The external member has no body and no outgoing edge. Its complete
        // summary is what establishes its effect set, so the caller stays
        // exhaustive and still inherits the declaration.
        let mut external = procedure(
            "java.io.Writer.write/1+recv",
            vec![declared(
                "io.stream_write",
                ExecutionTiming::SameEvaluation,
                EffectCertainty::Definite,
            )],
        );
        external.basis = EffectNodeBasis::CompleteSummary;
        let graph = EffectGraph {
            procedures: vec![procedure("App.render", Vec::new()), external],
            edges: vec![edge(0, 1, "site.render")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].coverage, EffectCoverage::Exhaustive);
        assert_eq!(
            reports[0].rows[0].effect_id.as_deref(),
            Some("io.stream_write")
        );
        assert_eq!(reports[0].rows[0].derivation, EffectDerivation::Declared);
        assert_eq!(
            reports[0].rows[0].witness_chain().as_deref(),
            Some("App.render -> java.io.Writer.write/1+recv")
        );
    }

    #[test]
    fn a_known_empty_summarized_leaf_leaves_its_caller_absence_exhaustive() {
        let mut external = procedure("java.lang.String.length/0+recv", Vec::new());
        external.basis = EffectNodeBasis::CompleteSummary;
        let graph = EffectGraph {
            procedures: vec![procedure("App.pure", Vec::new()), external],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].coverage, EffectCoverage::Exhaustive);
        assert_eq!(reports[0].rows[0].derivation, EffectDerivation::None);
        assert_eq!(reports[0].rows[0].reason, None);
    }

    #[test]
    fn a_procedure_with_no_effect_and_a_complete_graph_states_an_exhaustive_absence() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.pure", Vec::new()),
                procedure("App.helper", Vec::new()),
            ],
            edges: vec![edge(0, 1, "site.pure")],
            truncated: false,
        };
        let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
        assert_eq!(reports[0].rows.len(), 1);
        assert!(reports[0].rows[0].terminal);
        assert_eq!(reports[0].rows[0].derivation, EffectDerivation::None);
        assert_eq!(reports[0].coverage, EffectCoverage::Exhaustive);
    }

    #[test]
    fn the_depth_bound_truncates_instead_of_dropping_the_answer() {
        let graph = EffectGraph {
            procedures: vec![
                procedure("App.a", Vec::new()),
                procedure("App.b", Vec::new()),
                procedure(
                    "AcmeHttpClient.send",
                    vec![declared(
                        "acme.network_io",
                        ExecutionTiming::SameEvaluation,
                        EffectCertainty::Definite,
                    )],
                ),
            ],
            edges: vec![edge(0, 1, "site.a"), edge(1, 2, "site.b")],
            truncated: false,
        };
        let budget = ProcedureEffectBudget {
            max_depth: 1,
            ..ProcedureEffectBudget::default()
        };
        let reports = summarize_procedure_effects(&graph, budget);
        assert_eq!(reports[0].rows.len(), 1);
        assert!(reports[0].rows[0].terminal);
        assert_eq!(reports[0].coverage, EffectCoverage::Truncated);
        assert_eq!(
            reports[0].rows[0].reason,
            Some(EffectReason::ProcedureBudgetExhausted)
        );
    }

    #[test]
    fn the_fixpoint_is_deterministic_under_reordered_edges() {
        let procedures = vec![
            procedure("App.a", Vec::new()),
            procedure("App.b", Vec::new()),
            procedure(
                "AcmeHttpClient.send",
                vec![declared(
                    "acme.network_io",
                    ExecutionTiming::SameEvaluation,
                    EffectCertainty::Definite,
                )],
            ),
        ];
        let forward = EffectGraph {
            procedures: procedures.clone(),
            edges: vec![
                edge(0, 1, "site.a"),
                edge(0, 2, "site.direct"),
                edge(1, 2, "site.b"),
            ],
            truncated: false,
        };
        let reversed = EffectGraph {
            procedures,
            edges: vec![
                edge(1, 2, "site.b"),
                edge(0, 2, "site.direct"),
                edge(0, 1, "site.a"),
            ],
            truncated: false,
        };
        assert_eq!(
            summarize_procedure_effects(&forward, ProcedureEffectBudget::default()),
            summarize_procedure_effects(&reversed, ProcedureEffectBudget::default())
        );
    }
}
