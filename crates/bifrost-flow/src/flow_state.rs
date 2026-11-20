//! The flow-sensitive state-event and flow-relation derivation layer (issue
//! #1480, milestone 2).
//!
//! One *state event* says that a binding or an object property is established,
//! killed, or read at one program point of the production control-flow graph.
//! One *flow relation* says how two such events relate along that graph:
//! `Reaching` (an establishment can serve a read), `Dominates` (every
//! entry-to-read path passes the write), or `SameEvaluation` (the read feeds
//! the very value the write assigns, so the write cannot serve it).
//!
//! The production semantic IR (`crate::analyzer::semantic`) owns procedure
//! topology and ordinary events. Rust's scope-only future-frame reads also use
//! the existing lexical environment and AST-resolved by-value uses; those
//! source facts never stand in for CFG reachability. Where a required axis is
//! incomplete, this layer reports it rather than approximating it -- the same
//! per-axis completeness contract the canonical reference-edge layer
//! ([`super::reference_edges`]) established for #1479.
//!
//! Deliberately not a stored graph: rows are derived on demand from one
//! lowered artifact, and every row is stamped with the workspace generation it
//! was derived in, so a later comparison can refuse to relate rows from two
//! different snapshots.
//!
//! The constrained-value vocabulary the rows carry -- [`StateEventClass`],
//! [`FlowSubjectKind`], [`FlowRelation`], [`FlowCertainty`], [`FlowStateAxis`]
//! -- is `brokk-bifrost-core`'s, because the RQL registries that spell those
//! same values live below this crate and must not own a second spelling table.

use crate::analyzer::reuse_verdict::{CarriesReuseVerdict, ExecutionCause, ReuseVerdict};
use crate::analyzer::semantic::binding_initialization::{
    BindingDefinitions, BindingEventKey, BindingInitializationEvent, invalidated_binding,
};
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, CfgAlgorithmWork,
    DenseBidirectionalGraph, Dominators, FeasibleSuccessors, GenKillFacts, LiveValueSets,
    Reachability, ReachingSets, dominators, forward_reachability, forward_reachability_from_all,
    live_values, reaching_definitions, reverse_reachability,
    strongly_connected_components_with_order,
};
use crate::analyzer::semantic::derive_property_reaching_over_graph;
use crate::analyzer::semantic::statement_entries::CandidateControlRouteIndex;
use crate::analyzer::semantic::{
    BindingOriginIndex, CallContinuationKind, CallInvocationMode, CallSiteHandle, CallSiteId,
    CallToReturnModel, CallTransferSet, CallableTarget, CallableTargetResolution,
    CandidateCoverage, CapabilitySupport, CaptureSource, ContentIdentity, ControlContinuation,
    ControlEdgeHandle, ControlEdgeId, ControlEdgeKind, EvidenceCompleteness, EvidenceId,
    IcfgProvider, LengthDelimitedDigest, MemoryAccessKind, MemoryLocationId, MemoryLocationKind,
    OracleCallContext, ProcedureHandle, ProcedureId, ProcedureSemantics, ProgramPointHandle,
    ProgramPointId, ProofStatus, PropertyReachCertainty, PropertyReachingIncompleteReason,
    PropertyReachingLimits, PropertyReachingRelation, PropertyReachingResult, PropertyReadRecord,
    PropertyStoreRecord, SemanticArtifact, SemanticArtifactKey, SemanticBudget, SemanticCallSite,
    SemanticCapabilities, SemanticCapability, SemanticEffect, SemanticGap, SemanticGapDischarge,
    SemanticGapId, SemanticGapImpact, SemanticGapKind, SemanticGapSubject, SemanticOutcome,
    SemanticRequest, SemanticValueKind, SemanticWork, SourceMappingId, SourceMappingKind,
    SourceSpan, StableDigest, SynchronizationOperation, SynchronizationPayload, ValueFlowKind,
    ValueFlowOracle, ValueId, WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, ProcedureSummaryMemberKey, ResolvedActiveSemanticModels,
};
use crate::analyzer::store::active_models::FamilyPresence;
use crate::analyzer::usages::CallRelationLimits;
use crate::analyzer::usages::call_shape::{CallShapeReport, call_shapes_in_file};
use crate::analyzer::usages::effects::{
    ModeledCallApplication, ModeledCallTargetCoverage, ModeledCallTargetLookup,
    ModeledCallTargetOrigin, ModeledProcedureKey, modeled_call_targets_for_shapes,
};
use crate::analyzer::{
    AnalyzerQueryScope, IAnalyzer, Language, ProjectFile, Range, WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::ast_id;
use brokk_bifrost_analysis::analyzer::structural::{
    BindingOfOutcome, EnvironmentAxis, Namespace, binding_of, environment_for_file,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;
use brokk_bifrost_core::profiling;
use brokk_bifrost_core::{
    hash::allocated_vec_slot_bytes,
    request_memo::RequestMemo,
    retention_budget::{RetainedBytes, RetentionBudget},
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use tree_sitter::Node;

/// Execute one topology-sensitive operation against the raw graph when no
/// edge is projected, or against the exact masked view otherwise. Keeping the
/// branch outside `DenseBidirectionalGraph` iteration preserves the existing
/// raw procedure path without an enum dispatch on every adjacency item.
macro_rules! with_control_graph {
    ($semantics:expr, $mask:expr, |$graph:ident| $body:block) => {{
        let semantics = $semantics;
        let mask = $mask;
        if mask.is_empty() {
            let $graph = semantics;
            $body
        } else {
            let masked_graph = ProjectedProcedureGraph::new(semantics, mask);
            let $graph = &masked_graph;
            $body
        }
    }};
}

pub use brokk_bifrost_core::analyzer::structural::flow_state::{
    ALL_FLOW_STATE_AXES as FLOW_STATE_AXES, FlowCertainty, FlowRelation, FlowStateAxis,
    FlowSubjectKind, StateEventClass, StateEventReadCause,
};

/// Stable content-scoped identity for one semantic procedure.
///
/// Mount-free by construction: the artifact contributes its public
/// fingerprint, never the `SemanticArtifactKey` that folds the workspace
/// mount, so the same content analyzed at two roots -- a head workspace and a
/// base revision exported to a temporary directory -- yields the same id. This
/// is the identity every rendered semantic row publishes, and it lives here,
/// below the RQL crate, because the concurrency engine names procedures in the
/// canonical locations it publishes and cannot reach a wire id defined above
/// it.
pub fn procedure_wire_id(handle: &ProcedureHandle) -> String {
    procedure_public_digest(handle).to_string()
}

/// Stable binary form of [`procedure_wire_id`].
///
/// Persisted result keys use the digest directly so they share the exact
/// mount-independent artifact and structured-locator identity used by public
/// semantic rows without decoding a rendered identifier.
pub fn procedure_public_digest(handle: &ProcedureHandle) -> StableDigest {
    let base = crate::analyzer::semantic::SemanticProcedureReference::public_digest_for(
        handle.artifact().key(),
        handle.semantics().locator(),
    );
    let alternate = |domain: &'static [u8]| {
        let mut digest = LengthDelimitedDigest::new(domain);
        digest.push(base.as_bytes());
        digest.finish()
    };
    match handle.interpretation() {
        crate::analyzer::semantic::ProcedureInterpretation::Base => base,
        crate::analyzer::semantic::ProcedureInterpretation::CandidateAlternate => {
            alternate(b"bifrost-code-query-procedure-candidate-alternate-v1")
        }
        crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate => {
            alternate(b"bifrost-code-query-procedure-executable-v1")
        }
    }
}

/// Stable content-scoped identity for one semantic program point.
pub fn program_point_wire_id(handle: &ProgramPointHandle) -> String {
    let procedure = handle.procedure();
    let point = procedure
        .semantics()
        .point(handle.id())
        .expect("validated program-point handle resolves in its procedure");
    let mapping = procedure
        .semantics()
        .source_mapping(point.source)
        .expect("validated program point has a source mapping");
    let mut digest = LengthDelimitedDigest::new(b"bifrost-code-query-semantic-wire-id-v2");
    match procedure.interpretation() {
        crate::analyzer::semantic::ProcedureInterpretation::Base => {}
        crate::analyzer::semantic::ProcedureInterpretation::CandidateAlternate => {
            digest.push(b"candidate-alternate");
        }
        crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate => {
            digest.push(b"executable-alternate");
        }
    }
    digest.push(procedure.artifact().key().public_fingerprint().as_bytes());
    digest.push(b"program_point");
    procedure
        .semantics()
        .locator()
        .push_stable_identity(&mut digest);
    digest.push(&handle.id().get().to_le_bytes());
    mapping.locator.push_stable_identity(&mut digest);
    let semantics = procedure.semantics();
    let boundary = if handle.id() == semantics.entry_point() {
        "entry"
    } else if handle.id() == semantics.normal_exit_point() {
        "normal_exit"
    } else if handle.id() == semantics.exceptional_exit_point() {
        "exceptional_exit"
    } else {
        "ordinary"
    };
    digest.push(boundary.as_bytes());
    digest.finish().to_string()
}

/// What a state event is about.
///
/// A binding is one lowered value of a binding kind (local, parameter, or
/// receiver): the semantic IR gives one value identity per lexical binding, so
/// two events naming the same binding carry the same [`ValueId`]. A property is
/// a field access whose base value the IR itself flows from a binding, plus the
/// member the field access names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowSubject {
    Binding {
        value: ValueId,
    },
    Property {
        /// A presentation binding for the field base when one is available.
        /// Property relation identity is the analysis-owned structured
        /// receiver/path/member key, not this display projection.
        base: ValueId,
        /// The source spelling retained for display and filtering only.
        member: Box<str>,
    },
}

impl FlowSubject {
    pub const fn axis(&self) -> FlowStateAxis {
        match self {
            Self::Binding { .. } => FlowStateAxis::BindingEvents,
            Self::Property { .. } => FlowStateAxis::PropertyEvents,
        }
    }

    /// The coarse constrained value a `:subject` filter names.
    pub const fn kind(&self) -> FlowSubjectKind {
        match self {
            Self::Binding { .. } => FlowSubjectKind::Binding,
            Self::Property { .. } => FlowSubjectKind::Property,
        }
    }

    /// The member a property subject names; `None` for a binding subject.
    pub fn member(&self) -> Option<&str> {
        match self {
            Self::Binding { .. } => None,
            Self::Property { member, .. } => Some(member),
        }
    }

    /// The lowered value this public subject presents: the binding itself, or
    /// the presentation base a property hangs off. Structured property
    /// relation identity is owned by analysis and is not reconstructed from
    /// this display value.
    pub const fn value(&self) -> ValueId {
        match self {
            Self::Binding { value } => *value,
            Self::Property { base, .. } => *base,
        }
    }
}

/// Where in the workspace a state event is spelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateEventSite {
    pub file: ProjectFile,
    pub range: Range,
    /// The content-scoped AST identity of the arena node covering the event's
    /// own source span, present exactly when the lowering's provenance lands on
    /// a facts-arena node. Never fabricated: `None` means the event is
    /// addressed by `file` plus byte range over the same analyzed content,
    /// which is exact, not heuristic.
    pub ast_id: Option<String>,
}

/// One establishment, kill, or read of one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateEventRow {
    /// Dense identity inside this derivation; the join key both ends of a
    /// [`FlowRelationRow`] use.
    pub event: usize,
    pub procedure: ProcedureId,
    pub event_class: StateEventClass,
    /// Present on synthetic reads placed at a suspension point. Ordinary
    /// semantic events keep `None`.
    pub read_cause: Option<StateEventReadCause>,
    pub subject: FlowSubject,
    pub point: ProgramPointId,
    /// The wire identity of `point`: the same stable id a `program_point` row
    /// publishes, so an event joins to its point (and through it to a control
    /// relation) by id equality rather than by a dense index that means nothing
    /// outside this procedure (#2443).
    pub point_id: Box<str>,
    /// The value the event moves: the assigned value for `Establish`/`Kill`,
    /// the produced value for `Read`. This is what the `SameEvaluation`
    /// derivation follows through the IR's own value dependence.
    pub value: ValueId,
    pub site: StateEventSite,
    pub generation: u64,
}

/// One relation between two state events of one procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRelationRow {
    pub relation: FlowRelation,
    pub certainty: FlowCertainty,
    /// The establishment or kill end, by [`StateEventRow::event`].
    pub source_event: usize,
    /// The read end, by [`StateEventRow::event`].
    pub target_event: usize,
    pub procedure: ProcedureId,
    pub generation: u64,
}

/// Why a derivation's rows are less than the whole truth.
#[derive(Clone, PartialEq, Eq)]
pub enum FlowStateIncompleteReason {
    /// The adapter declares the capability this axis stands on unsupported, so
    /// the absence of rows for it says nothing.
    AxisUnsupported(FlowStateAxis),
    /// No semantic provider is registered for the file's language.
    NoSemanticProvider,
    /// The semantic provider returned a typed error.
    SemanticProviderFailed { detail: String },
    /// The lowering itself is partial (the `semantic_analysis_partial` shape):
    /// ambiguous, unknown, unproven, or budget-limited artifacts.
    SemanticAnalysisPartial { detail: String },
    /// The lowering was cancelled, or a CFG algorithm was.
    Cancelled,
    /// The analyzed content the artifact was lowered from is no longer the
    /// content the structural facts describe.
    SourceGenerationChanged,
    /// Rust's lexical environment or AST-to-CFG move-site projection could not
    /// answer scope-only future-frame liveness for one procedure.
    BindingScopeLivenessUnavailable { detail: String },
    /// A request-local control projection was minted for another semantic
    /// artifact or named a missing/non-normal edge. No requested edge is
    /// omitted when this reason is present.
    ControlProjectionRejected { detail: String },
    /// An active non-return model may apply to a structured call, but exact
    /// dispatch or the semantic call/edge join remained open. The source edge
    /// is retained and control-shaped proofs stay incomplete.
    ModeledControlProjectionIncomplete { detail: String },
    /// The language has no structural facts arena, so no event can carry an
    /// `ast_id` join.
    NoStructuralFacts,
    /// The lowering published an explicit gap over a capability this
    /// derivation reads. The gap's own capability decides which axes it
    /// blocks; see [`axes_blocked_by`].
    LoweringGap {
        /// Exact procedure-local gaps behind this reason, empty for synthetic reasons.
        gaps: Vec<SemanticGapId>,
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: String,
    },
    /// A semantic or CFG algorithm ran out of its request budget. Truncation is never
    /// silent: the affected relation emits no rows at all.
    BudgetExhausted { axis: FlowStateAxis, detail: String },
    /// A field access whose base value the IR does not flow from any binding.
    /// Such an access has no stable property subject, so it contributes no
    /// event rather than an approximated one.
    PropertyBaseNotCanonical { accesses: usize },
    /// A scoped property proof retained a semantic endpoint that public
    /// event projection could not present. The exact join identity is kept.
    SelectedPropertyEndpointUnavailable {
        point: ProgramPointId,
        event_index: u32,
        source: SourceMappingId,
    },
    /// The lowering declares a local binding it never establishes, so reads of
    /// that binding have no establishment to reach them in this artifact and
    /// their absence is unknown, not proven.
    BindingWithoutEstablishment { bindings: usize },
    /// The selected local can be observed or changed through an address or a
    /// captured cell, outside the projected ordinary binding event sequence.
    BindingStateNotClosed { binding: ValueId },
    /// The structured property provider was not available for an artifact that
    /// advertises field memory. Property rows cannot be treated as complete.
    PropertyProviderUnavailable,
    /// Acquiring the property snapshot exhausted a semantic resident budget.
    /// Missing property rows block property axes, while a binding-only
    /// evaluation chain with no memory access remains independently provable.
    PropertySnapshotBudgetExhausted { detail: String },
    /// Acquiring the structured property snapshot returned a typed provider
    /// failure. Binding and control relations derived from the already
    /// materialized procedure remain independently answerable.
    PropertyProviderFailed { detail: String },
    /// The structured property snapshot was unavailable from a partial
    /// semantic-oracle outcome. This is scoped to property rows and relations.
    PropertyAnalysisPartial { detail: String },
    /// The structured property provider retained typed evidence, but one or
    /// more proof/completeness conditions remained open.
    PropertyReaching {
        reason: Box<PropertyReachingIncompleteReason>,
    },
}

// Procedure-local gap IDs are rendered as attributed sources, not allocation slots
// in reason prose. Keep the existing reason text stable for downstream reports.
impl std::fmt::Debug for FlowStateIncompleteReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AxisUnsupported(value) => f.debug_tuple("AxisUnsupported").field(value).finish(),
            Self::NoSemanticProvider => f.write_str("NoSemanticProvider"),
            Self::SemanticProviderFailed { detail } => f
                .debug_struct("SemanticProviderFailed")
                .field("detail", detail)
                .finish(),
            Self::SemanticAnalysisPartial { detail } => f
                .debug_struct("SemanticAnalysisPartial")
                .field("detail", detail)
                .finish(),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::SourceGenerationChanged => f.write_str("SourceGenerationChanged"),
            Self::BindingScopeLivenessUnavailable { detail } => f
                .debug_struct("BindingScopeLivenessUnavailable")
                .field("detail", detail)
                .finish(),
            Self::ControlProjectionRejected { detail } => f
                .debug_struct("ControlProjectionRejected")
                .field("detail", detail)
                .finish(),
            Self::ModeledControlProjectionIncomplete { detail } => f
                .debug_struct("ModeledControlProjectionIncomplete")
                .field("detail", detail)
                .finish(),
            Self::NoStructuralFacts => f.write_str("NoStructuralFacts"),
            Self::LoweringGap {
                capability,
                kind,
                detail,
                ..
            } => f
                .debug_struct("LoweringGap")
                .field("capability", capability)
                .field("kind", kind)
                .field("detail", detail)
                .finish(),
            Self::BudgetExhausted { axis, detail } => f
                .debug_struct("BudgetExhausted")
                .field("axis", axis)
                .field("detail", detail)
                .finish(),
            Self::PropertyBaseNotCanonical { accesses } => f
                .debug_struct("PropertyBaseNotCanonical")
                .field("accesses", accesses)
                .finish(),
            Self::SelectedPropertyEndpointUnavailable {
                point,
                event_index,
                source,
            } => f
                .debug_struct("SelectedPropertyEndpointUnavailable")
                .field("point", point)
                .field("event_index", event_index)
                .field("source", source)
                .finish(),
            Self::BindingWithoutEstablishment { bindings } => f
                .debug_struct("BindingWithoutEstablishment")
                .field("bindings", bindings)
                .finish(),
            Self::BindingStateNotClosed { binding } => f
                .debug_struct("BindingStateNotClosed")
                .field("binding", binding)
                .finish(),
            Self::PropertySnapshotBudgetExhausted { detail } => f
                .debug_struct("BudgetExhausted")
                .field("detail", detail)
                .finish(),
            Self::PropertyProviderUnavailable => f.write_str("PropertyProviderUnavailable"),
            Self::PropertyProviderFailed { detail } => f
                .debug_struct("PropertyProviderFailed")
                .field("detail", detail)
                .finish(),
            Self::PropertyAnalysisPartial { detail } => f
                .debug_struct("PropertyAnalysisPartial")
                .field("detail", detail)
                .finish(),
            Self::PropertyReaching { reason } => f
                .debug_struct("PropertyReaching")
                .field("reason", reason)
                .finish(),
        }
    }
}

impl FlowStateIncompleteReason {
    /// Whether this one reason stops `axis` from being completely enumerated.
    ///
    /// Total over the reason vocabulary on purpose: a reason added later must
    /// be classified deliberately rather than defaulting into silence. A caller
    /// that publishes only some axes reads this to decide whether a reason is
    /// about the answer it is giving at all -- a hole in the same-evaluation
    /// relation says nothing about a set of binding events, and reporting it
    /// on a state-event query would contradict the `complete` those very rows
    /// carry in their own `completeness` field.
    pub fn blocks(&self, axis: FlowStateAxis) -> bool {
        use FlowStateIncompleteReason::*;
        match self {
            AxisUnsupported(blocked) => *blocked == axis,
            BudgetExhausted { axis: blocked, .. } => *blocked == axis,
            LoweringGap { capability, .. } => {
                capability_axes_blocked_by(*capability).contains(&axis)
            }
            PropertyBaseNotCanonical { .. } | SelectedPropertyEndpointUnavailable { .. } => {
                property_axes().contains(&axis)
            }
            BindingWithoutEstablishment { .. } => matches!(
                axis,
                FlowStateAxis::BindingEvents
                    | FlowStateAxis::ReachingRelation
                    | FlowStateAxis::SameEvaluationRelation
            ),
            BindingStateNotClosed { .. } => matches!(
                axis,
                FlowStateAxis::BindingEvents | FlowStateAxis::ReachingRelation
            ),
            PropertyProviderUnavailable
            | PropertyProviderFailed { .. }
            | PropertyAnalysisPartial { .. }
            | PropertySnapshotBudgetExhausted { .. } => property_axes().contains(&axis),
            PropertyReaching { reason } => property_reason_blocks(reason, axis),
            ControlProjectionRejected { .. } | ModeledControlProjectionIncomplete { .. } => {
                matches!(
                    axis,
                    FlowStateAxis::ReachingRelation
                        | FlowStateAxis::DominanceRelation
                        | FlowStateAxis::PropertyReachingRelation
                        | FlowStateAxis::PropertyDominanceRelation
                )
            }
            NoSemanticProvider
            | SemanticProviderFailed { .. }
            | SemanticAnalysisPartial { .. }
            | Cancelled
            | SourceGenerationChanged
            | NoStructuralFacts => true,
            BindingScopeLivenessUnavailable { .. } => axis == FlowStateAxis::BindingEvents,
        }
    }
}

/// Keep typed property gaps scoped to the relation family they affect. In
/// particular, an evaluation-endpoint shortfall must not make complete
/// property stores appear unavailable, while a missing property location must
/// not make binding state incomplete.
fn property_reason_blocks(reason: &PropertyReachingIncompleteReason, axis: FlowStateAxis) -> bool {
    use PropertyReachingIncompleteReason::*;
    match reason {
        EvaluationEndpointUnavailable { .. }
        | EvaluationEvidenceIncomplete { .. }
        | EvaluationSourceUnknown => false,
        Reachability(_)
        | ReachingDefinitions(_)
        | ReachingPairs(_)
        | ReachingPairBudgetExceeded { .. } => axis == FlowStateAxis::PropertyReachingRelation,
        Dominators(_) => matches!(
            axis,
            FlowStateAxis::PropertyReachingRelation | FlowStateAxis::PropertyDominanceRelation
        ),
        CandidateCoverage(_) | StoreEvidenceIncomplete { .. } | ReadEvidenceIncomplete { .. } => {
            matches!(
                axis,
                FlowStateAxis::PropertyReachingRelation
                    | FlowStateAxis::PropertyDominanceRelation
                    | FlowStateAxis::SameEvaluationRelation
            )
        }
        SelectedReadMissing { .. }
        | SelectedReadAmbiguous { .. }
        | SelectedRelationEndpointUnavailable { .. }
        | SelectedRuntimeAccess { .. }
        | SelectedAncestorStore { .. }
        | SelectedAliasClosureUnavailable { .. }
        | SelectedSemanticGap { .. }
        | SelectedCleanupMemberGap { .. }
        | InputRelationBudgetExceeded { .. }
        | Cancelled
        | UnsupportedLocation { .. }
        | DurableIdentityUnavailable { .. }
        | SourceMappingUnavailable { .. }
        | FieldMemoryEndpointUnavailable { .. } => matches!(
            axis,
            FlowStateAxis::PropertyEvents
                | FlowStateAxis::PropertyReachingRelation
                | FlowStateAxis::PropertyDominanceRelation
                | FlowStateAxis::SameEvaluationRelation
        ),
    }
}

const fn property_axes() -> &'static [FlowStateAxis] {
    &[
        FlowStateAxis::PropertyEvents,
        FlowStateAxis::PropertyReachingRelation,
        FlowStateAxis::PropertyDominanceRelation,
        FlowStateAxis::SameEvaluationRelation,
    ]
}

/// #6409: these exceptional discharges cannot resume ordinary body control.
/// This is a control-only fact, not proof that the omitted effects are inert.
pub fn gap_has_exit_only_control(gap: &SemanticGap) -> bool {
    gap.capability == SemanticCapability::ExceptionalControlFlow
        && matches!(
            gap.control_flow_discharge(),
            SemanticGapDischarge::NonRejoiningExceptionalExit
                | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
                | SemanticGapDischarge::ExitOnlyProcedureCompletion
        )
}

/// An omitted exceptional route with no in-procedure user-code observer.
/// AfterInertDrops needs the workspace oracle's inert-drop proof; raw flow
/// state has no such proof and must leave that variant open.
fn gap_has_unobserved_exceptional_exit(gap: &SemanticGap) -> bool {
    gap_has_exit_only_control(gap)
        && gap.control_flow_discharge() == SemanticGapDischarge::NonRejoiningExceptionalExit
}

/// Cleanup can only continue its destination or unwind. Finally/recover
/// languages and unchecked C++ remain excluded from this contract (#6409).
pub fn destructor_style_cleanup(language: Language) -> bool {
    language == Language::Rust
}

/// The completion edge retained by emit_cleanup_completion_route in semantic/
/// lowering.rs carries the original destination and edge kind. Exit points
/// themselves carry companion bookkeeping gaps and have no continuation.
pub fn cleanup_has_retained_destination(
    semantics: &ProcedureSemantics,
    point: ProgramPointId,
) -> bool {
    point == semantics.normal_exit_point()
        || point == semantics.exceptional_exit_point()
        || semantics.successor_edges(point).next().is_some()
}

fn cleanup_is_control_irrelevant(semantics: &ProcedureSemantics, gap: &SemanticGap) -> bool {
    matches!(semantics.locator().language(), brokk_bifrost_core::analyzer::model::LanguageDialect::Standard(language) if destructor_style_cleanup(language))
        && gap.subject.is_point_or_value(semantics.cleanup_chains())
        && gap.capability == SemanticCapability::CleanupControlFlow
        && gap.impacts.iter().all(|impact| {
            matches!(
                impact,
                SemanticGapImpact::ValueFlow
                    | SemanticGapImpact::ReturnTransfer
                    | SemanticGapImpact::DispatchCoverage
                    | SemanticGapImpact::HeapRead
                    | SemanticGapImpact::HeapWrite
                    | SemanticGapImpact::Aliasing
            )
        })
        && cleanup_has_retained_destination(semantics, gap.point)
}

fn axes_blocked_by(semantics: &ProcedureSemantics, gap: &SemanticGap) -> &'static [FlowStateAxis] {
    // R-cleanup (#6409): emit_cleanup_completion_route retains destination;
    // no Invoke havoc premise is needed for control-shaped axes. Binding and
    // same-evaluation axes retain their original capability classifications.
    // #8602: only observer-free exceptional exits close relation axes. Active
    // defers and non-inert drops remain open despite exiting normal control.
    if gap_has_unobserved_exceptional_exit(gap)
        || cleanup_is_control_irrelevant(semantics, gap)
        || (matches!(
            gap.capability,
            SemanticCapability::CleanupControlFlow | SemanticCapability::ResourceManagement
        ) && !points_before_exit_only_exceptions(semantics).contains(&gap.point))
    {
        &[]
    } else {
        capability_axes_blocked_by(gap.capability)
    }
}

// A target-scoped proof may query cleanup/completion code itself. Keep its
// exceptional-region obligations even when global ordinary-body axes close;
// the exact target proof judges whether an exit can affect its relation.
fn scoped_axes_blocked_by(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
) -> &'static [FlowStateAxis] {
    if gap_has_exit_only_control(gap) {
        capability_axes_blocked_by(gap.capability)
    } else {
        axes_blocked_by(semantics, gap)
    }
}

/// Entry reachability after removing only certified exit-only exceptional
/// edges. Outside this set, cleanup cannot introduce an ordinary-body path.
pub fn points_before_exit_only_exceptions(
    semantics: &ProcedureSemantics,
) -> std::collections::HashSet<ProgramPointId> {
    let exits = semantics
        .gaps()
        .iter()
        .filter(|gap| gap_has_exit_only_control(gap))
        .map(|gap| gap.point)
        .collect::<HashSet<_>>();
    let mut reached = std::collections::HashSet::new();
    let mut stack = vec![semantics.entry_point()];
    while let Some(point) = stack.pop() {
        if !reached.insert(point) {
            continue;
        }
        stack.extend(semantics.successor_edges(point).filter_map(|(_, edge)| {
            (edge.kind != ControlEdgeKind::Exceptional || !exits.contains(&point))
                .then_some(edge.target_point)
        }));
    }
    reached
}

/// Which axes one gap capability blocks.
///
/// Total over the capability registry on purpose: a capability added later
/// must be classified deliberately, not defaulted into silence.
fn capability_axes_blocked_by(capability: SemanticCapability) -> &'static [FlowStateAxis] {
    use SemanticCapability::*;
    const CONTROL: &[FlowStateAxis] = &[
        FlowStateAxis::ReachingRelation,
        FlowStateAxis::DominanceRelation,
        FlowStateAxis::PropertyReachingRelation,
        FlowStateAxis::PropertyDominanceRelation,
    ];
    const BINDINGS: &[FlowStateAxis] = &[
        FlowStateAxis::BindingEvents,
        FlowStateAxis::SameEvaluationRelation,
    ];
    const PROPERTIES: &[FlowStateAxis] = &[
        FlowStateAxis::PropertyEvents,
        FlowStateAxis::PropertyReachingRelation,
        FlowStateAxis::PropertyDominanceRelation,
        FlowStateAxis::SameEvaluationRelation,
    ];
    const EVALUATION: &[FlowStateAxis] = &[FlowStateAxis::SameEvaluationRelation];
    // A published `GuardFacts` gap says a decision's condition was not
    // normalized, which is a statement about which successor executes, so it
    // leaves the two control-shaped axes open exactly as the other
    // control-flow capabilities do.
    match capability {
        GuardFacts
        | SwitchFacts
        | Procedures
        | BasicBlocks
        | ProgramPoints
        | EntryBoundary
        | NormalExitBoundary
        | ExceptionalExitBoundary
        | NormalControlFlow
        | ExceptionalControlFlow
        | CleanupControlFlow
        | NonLocalControl
        | NormalCallContinuation
        | ExceptionalCallContinuation
        | AsyncSuspendResume
        | GeneratorSuspension
        | DeferredExecution
        | ConcurrentSpawn
        | ResourceManagement => CONTROL,
        Assignments | Values | LocalFlow | ParameterFlow | ReceiverFlow | ReturnFlow
        | Allocations => BINDINGS,
        FieldMemory | StaticMemory | IndexMemory => PROPERTIES,
        Calls | DynamicDispatch | CallableReferences | Captures | Synchronization => EVALUATION,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowStateCompleteness {
    Complete,
    Incomplete {
        reasons: Vec<FlowStateIncompleteReason>,
    },
}

/// One target-local answer from an exact guard-edge dominance proof.
///
/// `ClosedNegative` means the retained control-flow graph already contains a
/// path to that target which bypasses every supplied guard edge. Adding an
/// omitted path cannot turn that negative into dominance. `Open` means the
/// retained graph has a dominating edge, but an undisclosed control path may
/// still bypass it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardDominanceAnswer {
    /// A supplied exact guard edge dominates the target with every relevant
    /// control gap discharged.
    Proven,
    /// The retained graph contains a target path which bypasses every supplied
    /// exact guard edge.
    ClosedNegative,
    /// A supplied edge dominates in the retained graph, but an undisclosed
    /// control path may still bypass it.
    Open,
}

impl FlowStateCompleteness {
    #[cfg(test)]
    fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn reasons(&self) -> &[FlowStateIncompleteReason] {
        match self {
            Self::Complete => &[],
            Self::Incomplete { reasons } => reasons,
        }
    }

    /// Whether rows for `axis` can be trusted to be the complete set.
    pub fn covers(&self, axis: FlowStateAxis) -> bool {
        !self.reasons().iter().any(|reason| reason.blocks(axis))
    }

    fn from_reasons(reasons: Vec<FlowStateIncompleteReason>) -> Self {
        if reasons.is_empty() {
            Self::Complete
        } else {
            Self::Incomplete { reasons }
        }
    }
}

/// One procedure's state events and flow relations, with the account of what
/// is missing.
#[derive(Debug, Clone)]
pub struct FlowStateDerivation {
    pub procedure: ProcedureId,
    pub events: Vec<StateEventRow>,
    pub relations: Vec<FlowRelationRow>,
    pub completeness: FlowStateCompleteness,
    pub generation: u64,
    procedure_artifact: Weak<SemanticArtifact>,
    dominance: Option<Dominators<ProgramPointId>>,
    control_edge_mask: ControlEdgeMask,
    binding_initialization: Option<BindingInitializationFacts>,
    event_keys: Vec<SemanticEventKey>,
    skipped_copies: SkippedCopies,
}

/// A proof about a binding at one modeled read, independent of which write
/// supplied its value. A represented bypass path is not a proof of an actual
/// uninitialized read: guard feasibility may remain unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingInitializationAnswer {
    Proven,
    MayBeUninitialized,
    Unreachable,
    Open {
        reasons: Vec<FlowStateIncompleteReason>,
    },
}

/// Whether a read participates in one establishment's own evaluation, from
/// [`FlowStateDerivation::read_feeds_establishment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameEvaluationAnswer {
    /// The read feeds the establishment and no open account can change that
    /// evaluation.
    Closed,
    /// The read does not feed this evaluation of the establishment.
    Outside,
    Open {
        reasons: Vec<FlowStateIncompleteReason>,
    },
}

/// Whether one ordinary local's established value is replaced on every
/// modeled continuation before any read of that value. This says nothing
/// about side effects of the establishment's right-hand side and grants no
/// permission to remove the assignment or its evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverwrittenUnreadAnswer {
    Proven {
        replacement_events: Vec<usize>,
    },
    ReadBeforeOverwrite {
        read_event: usize,
    },
    /// A path represented by the control graph exits or cycles without a
    /// replacement; feasibility of its guards is not asserted.
    PathWithoutOverwrite,
    Unreachable,
    Open {
        reasons: Vec<FlowStateIncompleteReason>,
    },
}

/// Source-level write liveness. `Dead` means no explicit access, move, borrow,
/// compound-assignment load, or capture can read this value on a modeled
/// continuation. Implicit drops are excluded. In particular this is not a
/// claim that the value has no observable effect: a destructor can observe it.
/// Consumers must never use `Dead` to delete or optimize a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadWriteAnswer {
    Dead,
    Live {
        read_event: usize,
    },
    Unreachable,
    Open {
        reasons: Vec<FlowStateIncompleteReason>,
    },
}

/// Exact syntax spans supplied from the same source snapshot as a semantic
/// procedure. The adapter supplies AST fields, not searched source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopSourceSite {
    pub kind: LoopSourceKind,
    pub loop_span: SourceSpan,
    pub body_span: SourceSpan,
    pub condition_span: Option<SourceSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopSourceKind {
    While,
    /// The condition's false arm enters the body and its true arm exits.
    Until,
    For,
    Do,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopRepeatIncompleteReason {
    Flow(FlowStateIncompleteReason),
    SourceJoin { stage: &'static str },
    GuardEvidence,
    ControlEvidence,
}

/// Whether a reachable execution of this exact source loop's body can take
/// its own repeat edge. `NoRepeat` is an all-path claim over modeled control;
/// an omitted continuation must be returned as `Open`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopRepeatAnswer {
    MayRepeat {
        edge: ControlEdgeId,
    },
    NoRepeat {
        intentional_constant_false_do: bool,
    },
    UnreachableBody,
    Open {
        reasons: Vec<LoopRepeatIncompleteReason>,
    },
}

#[derive(Debug, Clone, Default)]
struct BindingInitializationFacts {
    /// Reachable binding reads and establishments, before their own event.
    uninitialized_before_event: HashMap<usize, bool>,
    correlated_before_event: HashMap<usize, BindingInitializationAnswer>,
}

/// The structured, flow-sensitive closure of one value through exact local
/// by-value copies.
///
/// Establishment and read identities are dense indices into the owning
/// [`FlowStateDerivation`]. `proof_open` means there is no exact artifact/flow
/// account for the closure itself. `uncertain_reads`, `uncertain_transfers`,
/// and `unclosed_transfers` retain candidate-scoped uncertainty without
/// conflating the independent binding cells of two aliases.
#[derive(Debug, Clone)]
pub struct ExactLocalValueAliasClosure {
    pub establishments: HashSet<usize>,
    pub reads: HashSet<usize>,
    pub uncertain_reads: HashSet<usize>,
    pub uncertain_transfers: HashSet<usize>,
    pub unclosed_transfers: HashSet<usize>,
    pub proof_open: bool,
    reaching_establishment_by_read: HashMap<usize, usize>,
    copied_from_read_by_establishment: HashMap<usize, usize>,
}

impl FlowStateDerivation {
    fn dominance_context<'a>(
        &'a self,
        procedure: &'a ProcedureHandle,
    ) -> Option<(&'a ProcedureSemantics, &'a Dominators<ProgramPointId>)> {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        // Partial artifacts are not globally cached, so a durable key cannot
        // substitute for the exact materialization held by this derivation.
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            return None;
        }
        let semantics = procedure.semantics();
        let dominance = self.dominance.as_ref()?;
        if self.completeness.reasons().iter().any(|reason| {
            reason.blocks(FlowStateAxis::DominanceRelation)
                && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
        }) {
            return None;
        }
        Some((semantics, dominance))
    }

    pub fn event(&self, event: usize) -> &StateEventRow {
        &self.events[event]
    }

    /// Prove that an ordinary binding has been established on every modeled
    /// entry-to-read path, including joins with different reaching writes.
    /// This does not assert one exact value origin or validate use after a
    /// language-specific runtime operation. It consumes the same bounded CFG
    /// solve and projected control graph as the public reaching rows.
    pub fn binding_initialization_at_read(
        &self,
        procedure: &ProcedureHandle,
        read_event: usize,
        request: &mut FlowStateRequest<'_>,
    ) -> BindingInitializationAnswer {
        assert_eq!(self.event(read_event).event_class, StateEventClass::Read);
        self.binding_initialization_before_event(procedure, read_event, request)
    }

    /// Whether a modeled exceptional continuation from this local read goes
    /// directly to an exception handler. The adapter publishes this route
    /// only when a Python `NameError`/`UnboundLocalError` or catch-all handler
    /// is proven to match the local-read failure.
    pub fn binding_read_failure_is_handled(
        &self,
        procedure: &ProcedureHandle,
        read_event: usize,
    ) -> bool {
        assert_eq!(self.event(read_event).event_class, StateEventClass::Read);
        assert!(
            matches!(self.event(read_event).subject, FlowSubject::Binding { .. }),
            "handled local-read proof requires a binding event"
        );
        assert_eq!(self.procedure, procedure.id());
        assert!(
            self.procedure_artifact
                .upgrade()
                .is_some_and(|artifact| Arc::ptr_eq(&artifact, procedure.artifact())),
            "read exception proof requires the derivation's exact artifact"
        );
        let semantics = procedure.semantics();
        let read_point = self.event(read_event).point;
        semantics
            .successor_edges(read_point)
            .filter(|(_, edge)| edge.kind == ControlEdgeKind::Exceptional)
            .any(|(_, edge)| {
                // A general exception dispatcher also has switch-case edges,
                // but retains an exceptional edge for an unmatched exception.
                // Only the direct, proven local-read handler route is safe.
                semantics
                    .successor_edges(edge.target_point)
                    .any(|(_, handler_edge)| handler_edge.kind == ControlEdgeKind::SwitchCase)
                    && !semantics
                        .successor_edges(edge.target_point)
                        .any(|(_, handler_edge)| handler_edge.kind == ControlEdgeKind::Exceptional)
            })
    }

    /// Prove that an ordinary local was initialized before a projected write.
    /// A language adapter can use this to reject writes that would fail before
    /// establishment, such as assigning a JavaScript `let` in its TDZ.
    pub fn binding_initialization_before_establishment(
        &self,
        procedure: &ProcedureHandle,
        establishment_event: usize,
        request: &mut FlowStateRequest<'_>,
    ) -> BindingInitializationAnswer {
        assert_eq!(
            self.event(establishment_event).event_class,
            StateEventClass::Establish
        );
        self.binding_initialization_before_event(procedure, establishment_event, request)
    }

    fn binding_initialization_before_event(
        &self,
        procedure: &ProcedureHandle,
        event: usize,
        request: &mut FlowStateRequest<'_>,
    ) -> BindingInitializationAnswer {
        assert_eq!(self.procedure, procedure.id());
        assert!(
            self.procedure_artifact
                .upgrade()
                .is_some_and(|artifact| Arc::ptr_eq(&artifact, procedure.artifact())),
            "initialization proof requires the derivation's exact artifact"
        );
        let FlowSubject::Binding { value: binding } = self.event(event).subject else {
            panic!("initialization proof requires a binding event");
        };

        // Lowering gaps are classified one by one below, because some of them
        // are scoped to another binding or to a suspension that happens after
        // this binding is already initialized.
        let mut reasons = self
            .completeness
            .reasons()
            .iter()
            .filter(|reason| {
                !matches!(
                    reason,
                    FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                        | FlowStateIncompleteReason::LoweringGap { .. }
                ) && (reason.blocks(FlowStateAxis::BindingEvents)
                    || reason.blocks(FlowStateAxis::ReachingRelation)
                    || matches!(
                        reason,
                        FlowStateIncompleteReason::BudgetExhausted {
                            axis: FlowStateAxis::DominanceRelation,
                            ..
                        }
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        let semantics = procedure.semantics();
        if request.candidate_routes.as_ref().map(|(key, _)| key) != Some(procedure) {
            let index = match CandidateControlRouteIndex::build(
                semantics,
                &mut CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation),
            ) {
                Ok(index) => index,
                Err(error) => {
                    let mut reasons = Vec::new();
                    push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                    return BindingInitializationAnswer::Open { reasons };
                }
            };
            request.candidate_routes = Some((procedure.clone(), index));
        }
        let candidate_paths = &request.candidate_routes.as_ref().expect("indexed routes").1;
        // A discharged control gap still omits edges. They cannot uninitialize
        // the binding, but they can make a modeled-unreachable event reachable.
        let mut omitted_control = Vec::new();
        for gap in semantics.gaps() {
            if candidate_paths.has_candidate_edge(gap.evidence)
                && !candidate_paths.contains(gap.evidence, self.event(event).point)
            {
                continue;
            }
            let axes = capability_axes_blocked_by(gap.capability);
            if !(axes.contains(&FlowStateAxis::BindingEvents)
                || axes.contains(&FlowStateAxis::ReachingRelation)
                || gap.capability == SemanticCapability::Captures)
            {
                continue;
            }
            if !self.initialization_gap_is_discharged(
                semantics,
                gap,
                binding,
                self.event(event).point,
            ) {
                push_gap_reason(&mut reasons, gap);
            } else if axes.contains(&FlowStateAxis::ReachingRelation) {
                push_gap_reason(&mut omitted_control, gap);
            }
        }
        let mut cfg_request =
            CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
        let localized = locate_gap_reasons(
            semantics,
            reasons,
            |gap| initialization_gap_retains_topology(gap) || initialization_gap_retains_order(gap),
            &mut cfg_request,
        )
        .and_then(|located| {
            let mut reasons = located.unlocated;
            let mut topology_reasons = Vec::new();
            if reasons.is_empty() {
                with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                    let mut reaching_read = None;
                    for ids in located.by_point.values() {
                        for id in ids {
                            cfg_request.visit_pair()?;
                            let gap = semantics.gap(*id).expect("attributed gap exists");
                            if initialization_gap_retains_topology(gap) {
                                // #7536: Go retains every parent normal successor;
                                // Python exception dispatch retains every handler
                                // and unmatched propagation without selection code.
                                // Unknown feasibility or progress cannot invalidate
                                // a positive all-path initialization proof on this
                                // over-approximating graph. Child lifetime/effects
                                // (ConcurrentSpawn) are not covered by this claim.
                                push_gap_reason(&mut topology_reasons, gap);
                                continue;
                            }
                            if reaching_read.is_none() {
                                reaching_read = Some(reverse_reachability(
                                    graph,
                                    self.event(event).point,
                                    &mut cfg_request,
                                )?);
                            }
                            if !initialization_order_region_is_off_path(
                                graph,
                                semantics,
                                gap,
                                reaching_read
                                    .as_ref()
                                    .expect("read reachability was solved"),
                                &mut cfg_request,
                            )? {
                                push_gap_reason(&mut reasons, gap);
                            }
                        }
                    }
                    Ok::<_, CfgAlgorithmError<ProgramPointId>>(())
                })?;
            }
            Ok((reasons, topology_reasons))
        });
        let (reasons, topology_reasons) = match localized {
            Ok(localized) => localized,
            Err(error) => {
                let mut reasons = Vec::new();
                push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                return BindingInitializationAnswer::Open { reasons };
            }
        };
        if !reasons.is_empty() {
            return BindingInitializationAnswer::Open { reasons };
        }
        let Some(facts) = &self.binding_initialization else {
            // The reaching algorithm failed; its typed reason is present in
            // completeness and would have returned above.
            unreachable!("covered binding reaching has initialization facts");
        };
        let answer = if let Some(answer) = facts.correlated_before_event.get(&event) {
            answer.clone()
        } else {
            match facts.uninitialized_before_event.get(&event) {
                Some(false) => BindingInitializationAnswer::Proven,
                Some(true) => BindingInitializationAnswer::MayBeUninitialized,
                None if omitted_control.is_empty() => BindingInitializationAnswer::Unreachable,
                None => BindingInitializationAnswer::Open {
                    reasons: omitted_control,
                },
            }
        };
        if matches!(answer, BindingInitializationAnswer::Proven) || topology_reasons.is_empty() {
            answer
        } else {
            // Retained alternatives over-approximate feasible executions. A
            // path without an establishment does not certify a negative answer.
            BindingInitializationAnswer::Open {
                reasons: topology_reasons,
            }
        }
    }

    /// Whether one lowering gap cannot change the initialization state of
    /// `binding` before the selected event at `read_point`.
    ///
    /// - A capture gap scoped to another value leaves that value's state open,
    ///   not this binding's.
    /// - A procedure-scoped suspension gap describes how callers construct
    ///   and schedule a generator or coroutine activation. Inside the body,
    ///   each suspension is lowered separately: as an `AsyncSuspend` scaffold
    ///   with its resumptions, or as a point-scoped suspension gap.
    /// - A point-scoped suspension gap omits only the behavior that leaves its
    ///   own point: abrupt resumption (a thrown or returned value) and
    ///   non-resumption. Suspension changes no ordinary local that the
    ///   procedure does not share, and nothing can make an initialized local
    ///   uninitialized again unless the IR moves out of it. So when an
    ///   establishment of `binding` strictly dominates the gap point, every
    ///   omitted path starts with `binding` already initialized.
    ///
    /// - A yield's abrupt resumption is an exceptional gap at the yield's
    ///   point, beside its suspension gap, and takes the same rule.
    /// - An exceptional gap discharged as `NonRejoiningExceptionalExit` omits
    ///   only a route that leaves the procedure without entering a handler or
    ///   cleanup. No read of this procedure lies on that route, so it cannot
    ///   change any read's initialization.
    /// - A retained-control-topology exception-selection gap cannot affect
    ///   initialization when its dispatcher is unreachable from the entry.
    ///   A proven unbound-local read may route directly to its matching handler,
    ///   leaving the generic dispatcher available only to other exceptions.
    ///
    /// Other gaps may be discharged by the initialization-only reachability
    /// rule below; any gap that can still affect the selected read stays open.
    fn initialization_gap_is_discharged(
        &self,
        semantics: &ProcedureSemantics,
        gap: &SemanticGap,
        binding: ValueId,
        read_point: ProgramPointId,
    ) -> bool {
        // #6409: initialization concerns only paths continuing in this body.
        // All three discharges leave without rejoining it. AfterInertDrops is
        // ExitOnly-equivalent here even if cleanup runs user code; inertness
        // is required only by readers of effects on the exit route.
        if gap_has_exit_only_control(gap) {
            return true;
        }
        if gap.capability == SemanticCapability::ExceptionalControlFlow
            && gap.control_flow_discharge() == SemanticGapDischarge::RetainedControlTopology
            && self.dominance.as_ref().is_some_and(|dominance| {
                with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                    !dominance.dominates(graph, semantics.entry_point(), gap.point)
                })
            })
        {
            return true;
        }
        // #6409: destructor-style cleanup cannot uninitialize a fresh scalar
        // local. Finally/recover cleanup can redirect control and stays open.
        let cleanup_keeps_initialization = |gap: &SemanticGap| {
            cleanup_is_control_irrelevant(semantics, gap)
                || (gap.capability == SemanticCapability::ResourceManagement
                    && (gap.impacts.iter().next().is_none()
                        || (gap.subject.is_point_or_value(semantics.cleanup_chains())
                            && matches!(semantics.locator().language(),
                                brokk_bifrost_core::analyzer::model::LanguageDialect::Standard(language)
                                    if destructor_style_cleanup(language))
                            && cleanup_has_retained_destination(semantics, gap.point))))
        };
        if cleanup_keeps_initialization(gap) {
            return true;
        }
        let discharged = match gap.capability {
            SemanticCapability::Captures => match gap.subject {
                // A nested rebinding assigns the binding, so it cannot leave
                // it uninitialized.
                SemanticGapSubject::Value(value) => {
                    value != binding
                        || gap.control_flow_discharge()
                            == SemanticGapDischarge::RebindAtCallOrSuspension
                }
                SemanticGapSubject::Capture(capture) => {
                    semantics.capture(capture).is_some_and(|capture| {
                        matches!(
                            capture.captured,
                            crate::analyzer::semantic::CaptureSource::Value(value)
                                if value != binding
                        )
                    })
                }
                _ => false,
            },
            // A yield's abrupt resumption is published as an exceptional gap
            // at the yield's own point, beside its suspension gap. It omits
            // the same paths that leave that point.
            SemanticCapability::ExceptionalControlFlow
                if gap.subject == SemanticGapSubject::Point
                    && semantics.gaps().iter().any(|other| {
                        other.point == gap.point
                            && other.subject == SemanticGapSubject::Point
                            && other.capability == SemanticCapability::GeneratorSuspension
                    }) =>
            {
                self.established_before_suspension(semantics, gap, binding)
            }
            SemanticCapability::GeneratorSuspension | SemanticCapability::AsyncSuspendResume => {
                if gap.subject == SemanticGapSubject::Procedure {
                    return true;
                }
                self.established_before_suspension(semantics, gap, binding)
            }
            _ => false,
        };
        // #6409: initialization is a forward property on entry-to-read paths.
        // A gap at P hides only an establishment, a move-out, or a declaration
        // at P, but none affects R if P cannot reach R. Reflexive reachability
        // keeps same-point gaps open; back edges account for later loop trips.
        // Captured closures execute only at calls reachable from creation.
        // This assumes capabilities classify control: hiding control in a
        // Values or Assignments gap violates the existing producer contract.
        // Exit-only gaps leave the body and RetainedControlTopology keeps all
        // successors, so the modeled graph over-approximates body reachability.
        // Known limit: one other control gap anywhere disables this rule for
        // the entire procedure. Procedure-subject gaps have no selected point.
        // Do not reuse this rule for same-evaluation or reaching-relation
        // proofs: those properties are not forward-only.
        discharged
            || (gap.subject != SemanticGapSubject::Procedure
                && semantics.gaps().iter().all(|other| {
                    !capability_axes_blocked_by(other.capability)
                        .contains(&FlowStateAxis::ReachingRelation)
                        // #10879: value-scoped destructor gaps retain the same
                        // control destinations as point-scoped cleanup. They
                        // must not disable positional relevance of later gaps.
                        || cleanup_keeps_initialization(other)
                        || gap_has_exit_only_control(other)
                        || other.control_flow_discharge() == SemanticGapDischarge::RetainedControlTopology
                })
                && !self.point_reaches(semantics, gap.point, read_point, true))
    }

    /// Whether `binding` is initialized on every path the point-scoped
    /// suspension gap omits: nothing moves out of it, and an establishment
    /// strictly dominates the gap point.
    fn established_before_suspension(
        &self,
        semantics: &ProcedureSemantics,
        gap: &SemanticGap,
        binding: ValueId,
    ) -> bool {
        let Some(dominance) = &self.dominance else {
            return false;
        };
        let moved_out = semantics.points().iter().any(|point| {
            point
                .events
                .iter()
                .any(|event| binding_is_invalidated_by(&event.effect, binding))
        });
        !moved_out
            && with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                self.events.iter().any(|event| {
                    event.event_class == StateEventClass::Establish
                        && event.subject == (FlowSubject::Binding { value: binding })
                        && event.point != gap.point
                        && dominance.dominates(graph, event.point, gap.point)
                })
            })
    }

    /// The subset of `reads` whose value is carried into the value the
    /// establishment assigns. A read whose value is used only as the base,
    /// index or address operand of a memory access selects the loaded value
    /// without being it, so it is dropped; a read used both ways is kept.
    /// Builds the procedure's dependence once per call: ask only when more
    /// than one read competes for one assigned value.
    pub fn reads_carried_into(
        &self,
        procedure: &ProcedureHandle,
        establishment_event: usize,
        reads: &[usize],
    ) -> Vec<usize> {
        assert_eq!(self.procedure, procedure.id());
        let establishment = self.event(establishment_event);
        assert_eq!(establishment.event_class, StateEventClass::Establish);
        let semantics = procedure.semantics();
        let carried = EvaluationDependence::build(semantics)
            .carried_operands_of(establishment.value, semantics.values().len());
        reads
            .iter()
            .copied()
            .filter(|read| carried.contains(&self.event(*read).value))
            .collect()
    }

    /// Whether one binding read feeds one establishment within that
    /// establishment's own evaluation, and whether that evaluation has an open
    /// account.
    ///
    /// The read must have an exact `SameEvaluation` row to the establishment,
    /// and the read's point must lead to the establishment's point along
    /// single normal edges (exceptional successors may leave the chain). A
    /// cloned evaluation, such as a `finally` body lowered once per
    /// continuation, can share value identities across clones; the chain
    /// separates the clone that actually feeds this establishment from the
    /// others, which are `Outside`.
    ///
    /// The answer is `Open` when a gap that blocks the same-evaluation
    /// relation is procedure-scoped, is placed on the chain, or names the
    /// read or written binding, or when a non-gap reason blocks that relation.
    /// A property completeness reason blocks it only when the read or the
    /// establishment is a property, or a chain point accesses memory; on a
    /// binding-to-binding chain that accesses memory, open candidate coverage
    /// alone is still exempt because it hides no event.
    /// A gap elsewhere in the procedure, such as an unresolved call in another
    /// statement, cannot add a read to this evaluation.
    pub fn read_feeds_establishment(
        &self,
        procedure: &ProcedureHandle,
        read_event: usize,
        establishment_event: usize,
    ) -> SameEvaluationAnswer {
        assert_eq!(self.procedure, procedure.id());
        assert!(
            self.procedure_artifact
                .upgrade()
                .is_some_and(|artifact| Arc::ptr_eq(&artifact, procedure.artifact())),
            "same-evaluation proof requires the derivation's exact artifact"
        );
        let read = self.event(read_event);
        let establishment = self.event(establishment_event);
        assert_eq!(read.event_class, StateEventClass::Read);
        assert_eq!(establishment.event_class, StateEventClass::Establish);
        if !self.relations.iter().any(|relation| {
            relation.relation == FlowRelation::SameEvaluation
                && relation.certainty == FlowCertainty::Exact
                && relation.source_event == establishment_event
                && relation.target_event == read_event
        }) {
            return SameEvaluationAnswer::Outside;
        }
        let semantics = procedure.semantics();
        let chain = with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let mut chain = vec![read.point];
            let mut current = read.point;
            while current != establishment.point {
                if chain.len() > semantics.points().len() {
                    return SameEvaluationAnswer::Outside;
                }
                let mut normal = None;
                for (edge, successor) in graph.successors(current) {
                    match semantics
                        .control_edge(edge)
                        .expect("graph edges belong to the procedure")
                        .kind
                    {
                        ControlEdgeKind::Normal if normal.is_none() => normal = Some(successor),
                        ControlEdgeKind::Exceptional | ControlEdgeKind::AsyncExceptional => {}
                        _ => return SameEvaluationAnswer::Outside,
                    }
                }
                let Some(next) = normal else {
                    return SameEvaluationAnswer::Outside;
                };
                chain.push(next);
                current = next;
            }
            chain
        });

        let bindings = [
            read.subject.value(),
            read.value,
            establishment.subject.value(),
            establishment.value,
        ];
        // Property completeness can hide a property event only where memory
        // is accessed. A binding read that feeds a binding establishment with
        // no memory access on its chain has no property event to miss.
        let binding_pair = matches!(read.subject, FlowSubject::Binding { .. })
            && matches!(establishment.subject, FlowSubject::Binding { .. });
        let property_scoped = binding_pair
            && !chain.iter().any(|point| {
                semantics.point(*point).is_some_and(|point| {
                    point.events.iter().any(|event| {
                        matches!(
                            event.effect,
                            SemanticEffect::MemoryLoad { .. } | SemanticEffect::MemoryStore { .. }
                        )
                    })
                })
            });
        let mut reasons = self
            .completeness
            .reasons()
            .iter()
            .filter(|reason| {
                reason.blocks(FlowStateAxis::SameEvaluationRelation)
                    && !matches!(
                        reason,
                        FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                            | FlowStateIncompleteReason::LoweringGap { .. }
                    )
                    // Open candidate coverage says other stores may reach a
                    // retained property read (a non-closed receiver, or an
                    // ancestor store). Every read and store is already
                    // projected as an event before coverage is judged, so it
                    // cannot add or remove a read in this evaluation. It is
                    // the only reason exempted on a chain that accesses
                    // memory. Truncated coverage can mean dropped relations
                    // and stays blocking, as do the reasons that name a
                    // missing event.
                    && !(binding_pair
                        && matches!(
                            reason,
                            FlowStateIncompleteReason::PropertyReaching { reason }
                                if matches!(
                                    reason.as_ref(),
                                    PropertyReachingIncompleteReason::CandidateCoverage(
                                        CandidateCoverage::Open
                                    )
                                )
                        ))
                    && !(property_scoped
                        && matches!(
                            reason,
                            FlowStateIncompleteReason::PropertyBaseNotCanonical { .. }
                                | FlowStateIncompleteReason::PropertyProviderUnavailable
                                | FlowStateIncompleteReason::PropertyProviderFailed { .. }
                                | FlowStateIncompleteReason::PropertyAnalysisPartial { .. }
                                | FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { .. }
                                | FlowStateIncompleteReason::PropertyReaching { .. }
                        ))
            })
            .cloned()
            .collect::<Vec<_>>();
        for gap in semantics.gaps() {
            if !scoped_axes_blocked_by(semantics, gap)
                .contains(&FlowStateAxis::SameEvaluationRelation)
            {
                continue;
            }
            let relevant = match gap.subject {
                SemanticGapSubject::FutureConstruction
                | SemanticGapSubject::FutureActivation
                | SemanticGapSubject::Procedure => true,
                // A nested callable can rebind the binding only while this
                // procedure calls out or suspends.
                SemanticGapSubject::Value(value)
                    if gap.control_flow_discharge()
                        == SemanticGapDischarge::RebindAtCallOrSuspension =>
                {
                    bindings.contains(&value)
                        && chain.iter().any(|point| {
                            semantics.point(*point).is_some_and(|point| {
                                point.events.iter().any(|event| {
                                    matches!(
                                        event.effect,
                                        SemanticEffect::Invoke { .. }
                                            | SemanticEffect::MemoryInterference
                                    )
                                })
                            })
                        })
                }
                SemanticGapSubject::Value(value) => bindings.contains(&value),
                SemanticGapSubject::CleanupOwners(segment) => bindings
                    .iter()
                    .any(|value| semantics.cleanup_chains().contains_owner(segment, *value)),
                SemanticGapSubject::Capture(capture) => {
                    semantics.capture(capture).is_none_or(|capture| {
                        !matches!(
                            capture.captured,
                            crate::analyzer::semantic::CaptureSource::Value(value)
                                if !bindings.contains(&value)
                        )
                    })
                }
                _ => false,
            } || chain.contains(&gap.point);
            if relevant {
                push_gap_reason(&mut reasons, gap);
            }
        }
        if reasons.is_empty() {
            SameEvaluationAnswer::Closed
        } else {
            SameEvaluationAnswer::Open { reasons }
        }
    }

    /// Overwrite/absence proofs enumerate reads and completion, beyond the
    /// retained topology. A value is live only if some path reads it; an exit
    /// that no code observes reads nothing (owner decision, #8602). Cleanup
    /// and deferred observers still keep their own obligations open.
    pub fn overwrite_observation_completeness(
        &self,
        procedure: &ProcedureHandle,
    ) -> FlowStateCompleteness {
        assert_eq!(self.procedure, procedure.id());
        let mut reasons = self.completeness.reasons().to_vec();
        let semantics = procedure.semantics();
        for gap in semantics.gaps() {
            if capability_axes_blocked_by(gap.capability).contains(&FlowStateAxis::ReachingRelation)
                && axes_blocked_by(semantics, gap).is_empty()
                && !gap_has_unobserved_exceptional_exit(gap)
            {
                push_gap_reason(&mut reasons, gap);
            }
        }
        FlowStateCompleteness::from_reasons(reasons)
    }

    /// Prove that the value created by one ordinary local establishment is
    /// overwritten before a read on every modeled continuation. A return or
    /// a cycle with no replacement defeats the proof; a repeated execution of
    /// this same static establishment counts as a dynamic replacement.
    /// Work across calls shares `request`'s CFG budget and cancellation. The
    /// caller must separately qualify its language's dynamic local reads:
    /// for example, an `eval` that can inspect a local without a projected
    /// binding read is outside this proof's event vocabulary.
    pub fn overwritten_unread_local(
        &self,
        procedure: &ProcedureHandle,
        establishment_event: usize,
        request: &mut FlowStateRequest<'_>,
    ) -> OverwrittenUnreadAnswer {
        assert_eq!(self.procedure, procedure.id());
        assert!(
            self.procedure_artifact
                .upgrade()
                .is_some_and(|artifact| Arc::ptr_eq(&artifact, procedure.artifact())),
            "overwrite proof requires the derivation's exact artifact"
        );
        let establishment = self.event(establishment_event);
        assert_eq!(establishment.event_class, StateEventClass::Establish);
        let FlowSubject::Binding { value: binding } = establishment.subject else {
            panic!("overwrite proof requires an ordinary local or parameter binding");
        };
        let semantics = procedure.semantics();
        assert!(
            matches!(
                semantics
                    .value(binding)
                    .expect("projected binding exists")
                    .kind,
                SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
            ),
            "overwrite proof requires an ordinary local or by-value parameter binding"
        );

        let observation_completeness = self.overwrite_observation_completeness(procedure);
        let mut reasons = observation_completeness
            .reasons()
            .iter()
            .filter(|reason| !request.observation_reason_is_discharged(procedure, reason))
            .filter(|reason| {
                !matches!(
                    reason,
                    FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                ) && (reason.blocks(FlowStateAxis::BindingEvents)
                    || reason.blocks(FlowStateAxis::ReachingRelation)
                    || matches!(
                        reason,
                        FlowStateIncompleteReason::LoweringGap {
                            capability: SemanticCapability::Captures,
                            ..
                        }
                    ))
            })
            .cloned()
            .collect::<Vec<_>>();
        // A normal continuation may count as the only live route across an
        // unobserved abort. Keep a gap at the establishment or on a cycle:
        // its point may be revisited after a replacement candidate, so one
        // static gap cannot certify every dynamic occurrence of that value.
        for gap in semantics.gaps().iter().filter(|gap| {
            gap_has_unobserved_exceptional_exit(gap)
                && (gap.point == establishment.point
                    || self.point_reaches(semantics, gap.point, gap.point, false))
        }) {
            push_gap_reason(&mut reasons, gap);
        }
        let mut cfg_request =
            CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
        let result = locate_gap_reasons(
            semantics,
            reasons,
            overwrite_gap_is_point_local,
            &mut cfg_request,
        )
        .and_then(|located| {
            if !located.unlocated.is_empty() {
                return Ok(OverwrittenUnreadAnswer::Open {
                    reasons: located.unlocated,
                });
            }
            with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                overwritten_unread_over_graph(
                    graph,
                    OverwrittenUnreadWalkInputs {
                        semantics,
                        events: &self.events,
                        event_keys: &self.event_keys,
                        establishment_event,
                        binding,
                        gaps_by_point: &located.by_point,
                    },
                    &mut cfg_request,
                )
            })
        });
        match result {
            Ok(answer) => answer,
            Err(error) => {
                let mut reasons = Vec::new();
                push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                OverwrittenUnreadAnswer::Open { reasons }
            }
        }
    }

    /// Classify one ordinary binding establishment by explicit source reads.
    /// This relation is shared across languages; syntax qualification belongs
    /// to the caller. An unmodeled drop does not affect source read liveness.
    pub fn dead_write_local(
        &self,
        procedure: &ProcedureHandle,
        establishment_event: usize,
        request: &mut FlowStateRequest<'_>,
    ) -> DeadWriteAnswer {
        self.dead_write_local_with_macro_sources(procedure, establishment_event, &[], &[], request)
    }

    /// `macro_sources` are AST-verified macro invocation source mappings;
    /// `safe_macro_sources` are the subset resolved to local macro_rules with
    /// no identifier token spelling this binding. Both are query-time source
    /// evidence and are used only for this explicit-read relation.
    pub fn dead_write_local_with_macro_sources(
        &self,
        procedure: &ProcedureHandle,
        establishment_event: usize,
        macro_sources: &[SourceMappingId],
        safe_macro_sources: &[SourceMappingId],
        request: &mut FlowStateRequest<'_>,
    ) -> DeadWriteAnswer {
        self.dead_write_local_with_feasible_edges(
            procedure,
            establishment_event,
            macro_sources,
            safe_macro_sources,
            &[],
            request,
        )
    }

    /// Dead-write liveness over the shared feasible-successor view.
    pub fn dead_write_local_with_feasible_edges(
        &self,
        procedure: &ProcedureHandle,
        establishment_event: usize,
        macro_sources: &[SourceMappingId],
        safe_macro_sources: &[SourceMappingId],
        infeasible_edges: &[ControlEdgeId],
        request: &mut FlowStateRequest<'_>,
    ) -> DeadWriteAnswer {
        assert_eq!(self.procedure, procedure.id());
        assert!(
            self.procedure_artifact
                .upgrade()
                .is_some_and(|artifact| Arc::ptr_eq(&artifact, procedure.artifact()))
        );
        let origin = self.event(establishment_event);
        assert_eq!(origin.event_class, StateEventClass::Establish);
        let FlowSubject::Binding { value: binding } = origin.subject else {
            panic!("dead-write proof requires an ordinary binding");
        };
        let semantics = procedure.semantics();
        assert!(matches!(
            semantics.value(binding).expect("binding exists").kind,
            SemanticValueKind::Local | SemanticValueKind::Parameter { .. }
        ));
        let procedure_key = DeadWriteProcedureKey(
            Arc::as_ptr(procedure.artifact()) as usize,
            procedure.id(),
            procedure.interpretation(),
            self.generation,
        );
        let procedure_index = request
            .memos
            .dead_write_procedure_cache
            .get_or_insert_with(procedure_key, || {
                dead_write_procedure_index(self, procedure)
            });
        let mut omitted_edges = self
            .control_edge_mask
            .omitted
            .iter()
            .copied()
            .collect::<Vec<_>>();
        omitted_edges.extend_from_slice(infeasible_edges);
        omitted_edges.sort_unstable();
        omitted_edges.dedup();
        let macro_points = macro_sources
            .iter()
            .filter(|source| safe_macro_sources.binary_search(source).is_err())
            .flat_map(|source| procedure_index.macro_gap_points_by_source.get(source))
            .flatten()
            .copied()
            .collect::<HashSet<_>>();
        let mut entry_reachable = None;
        let mut gap_reachable = HashMap::default();
        if !macro_points.is_empty() {
            let entry = match self.cached_dead_write_reachability(
                procedure,
                procedure_key,
                &omitted_edges,
                infeasible_edges,
                semantics.entry_point(),
                request,
            ) {
                Ok(reachable) => reachable,
                Err(error) => {
                    let mut reasons = Vec::new();
                    push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                    return DeadWriteAnswer::Open { reasons };
                }
            };
            for point in macro_points {
                if !entry.membership()[point.index()] {
                    continue;
                }
                let reachable = match self.cached_dead_write_reachability(
                    procedure,
                    procedure_key,
                    &omitted_edges,
                    infeasible_edges,
                    point,
                    request,
                ) {
                    Ok(reachable) => reachable,
                    Err(error) => {
                        let mut reasons = Vec::new();
                        push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                        return DeadWriteAnswer::Open { reasons };
                    }
                };
                gap_reachable.insert(point, reachable);
            }
            entry_reachable = Some(entry);
        }
        let mut reasons = self
            .overwrite_observation_completeness(procedure)
            .reasons()
            .iter()
            .filter(|reason| !request.observation_reason_is_discharged(procedure, reason))
            .filter(|reason| {
                !matches!(
                    reason,
                    FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                ) && (reason.blocks(FlowStateAxis::BindingEvents)
                    || reason.blocks(FlowStateAxis::ReachingRelation)
                    || matches!(
                        reason,
                        FlowStateIncompleteReason::LoweringGap {
                            capability: SemanticCapability::Captures,
                            ..
                        }
                    ))
            })
            .filter(|reason| {
                !drop_omission_gap(semantics, reason)
                    && !(procedure.artifact().key().language().language() == Language::Rust
                        && nonrejoining_rust_abort_gap(semantics, reason))
                    && !opaque_macro_gap_irrelevant(
                        semantics,
                        reason,
                        macro_sources,
                        safe_macro_sources,
                        // A macro before this write may suppress the write
                        // itself. Only a macro unreachable from procedure
                        // entry can be discarded on CFG grounds.
                        |point| {
                            entry_reachable
                                .as_ref()
                                .is_some_and(|reachable| reachable.membership()[point.index()])
                        },
                    )
            })
            .cloned()
            .collect::<Vec<_>>();
        // Closure cells and address-taken bindings have reads outside the
        // ordinary binding event vocabulary, so absence is not provable.
        if procedure_index.escaped_bindings.contains(&binding) {
            reasons.push(FlowStateIncompleteReason::BindingStateNotClosed { binding });
        }
        // A non-drop gap that can reach the establishment may remove the write
        // from the configured program; a drop omission never removes code.
        // One cached forward closure answers this for every write in the graph.
        let mut prefix_candidates = reasons
            .iter()
            .filter_map(|reason| match reason {
                FlowStateIncompleteReason::LoweringGap { gaps, .. } => Some(gaps),
                _ => None,
            })
            .flatten()
            .filter_map(|id| semantics.gap(*id))
            .filter(|gap| !gap.is_implicit_drop_omission())
            .map(|gap| gap.point)
            .collect::<Vec<_>>();
        if !prefix_candidates.is_empty() {
            let entry = match self.cached_dead_write_reachability(
                procedure,
                procedure_key,
                &omitted_edges,
                infeasible_edges,
                semantics.entry_point(),
                request,
            ) {
                Ok(entry) => entry,
                Err(error) => {
                    push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                    return DeadWriteAnswer::Open { reasons };
                }
            };
            prefix_candidates.retain(|point| entry.membership()[point.index()]);
        }
        prefix_candidates.sort_unstable();
        prefix_candidates.dedup();
        let blocking_prefix = if prefix_candidates.is_empty() {
            false
        } else {
            match self.cached_dead_write_prefix_reachability(
                procedure,
                procedure_key,
                &omitted_edges,
                infeasible_edges,
                &prefix_candidates,
                request,
            ) {
                Ok(after_gaps) => after_gaps.membership()[origin.point.index()],
                Err(error) => {
                    push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                    return DeadWriteAnswer::Open { reasons };
                }
            }
        };
        // The established overwrite proof already checked these same
        // binding events and places point-local gaps only in the value's
        // live region. A later gap after the replacement cannot read this
        // value. Reuse that complete certificate before applying this
        // relation's otherwise conservative procedure-wide gap gate.
        if !reasons.is_empty()
            && !procedure_index.escaped_bindings.contains(&binding)
            // The overwrite certificate starts at this establishment. A
            // non-drop gap before it may remove the write from the configured
            // program. The suffix certificate cannot prove that reachability.
            && !blocking_prefix
            && matches!(
                self.overwritten_unread_local(procedure, establishment_event, request),
                OverwrittenUnreadAnswer::Proven { .. }
            )
        {
            return DeadWriteAnswer::Dead;
        }
        let mut certificate_edges = infeasible_edges.to_vec();
        if !reasons.is_empty() {
            let mut gap_points = HashSet::default();
            let located = reasons.iter().all(|reason| match reason {
                FlowStateIncompleteReason::LoweringGap { gaps, .. } => {
                    !gaps.is_empty()
                        && gaps.iter().all(|id| {
                            semantics.gap(*id).is_some_and(|gap| {
                                if matches!(
                                    gap.subject,
                                    SemanticGapSubject::Procedure
                                        | SemanticGapSubject::FutureConstruction
                                        | SemanticGapSubject::FutureActivation
                                ) {
                                    return false;
                                }
                                if !gap.is_implicit_drop_omission()
                                    && !(procedure.artifact().key().language().language()
                                        == Language::Rust
                                        && macro_sources.contains(&gap.source))
                                {
                                    return false;
                                }
                                gap_points.insert(gap.point);
                                true
                            })
                        })
                }
                FlowStateIncompleteReason::SelectedPropertyEndpointUnavailable {
                    point, ..
                } => {
                    gap_points.insert(*point);
                    true
                }
                // These reasons do not identify all affected program points.
                FlowStateIncompleteReason::AxisUnsupported(_)
                | FlowStateIncompleteReason::NoSemanticProvider
                | FlowStateIncompleteReason::SemanticProviderFailed { .. }
                | FlowStateIncompleteReason::SemanticAnalysisPartial { .. }
                | FlowStateIncompleteReason::Cancelled
                | FlowStateIncompleteReason::SourceGenerationChanged
                | FlowStateIncompleteReason::BindingScopeLivenessUnavailable { .. }
                | FlowStateIncompleteReason::ControlProjectionRejected { .. }
                | FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
                | FlowStateIncompleteReason::NoStructuralFacts
                | FlowStateIncompleteReason::BudgetExhausted { .. }
                | FlowStateIncompleteReason::PropertyBaseNotCanonical { .. }
                | FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                | FlowStateIncompleteReason::BindingStateNotClosed { .. }
                | FlowStateIncompleteReason::PropertyProviderUnavailable
                | FlowStateIncompleteReason::PropertyProviderFailed { .. }
                | FlowStateIncompleteReason::PropertyAnalysisPartial { .. }
                | FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { .. }
                | FlowStateIncompleteReason::PropertyReaching { .. } => false,
            });
            if !located
                || blocking_prefix
                || gap_points.contains(&origin.point)
                || procedure_index.escaped_bindings.contains(&binding)
            {
                return DeadWriteAnswer::Open { reasons };
            }
            match self.dead_write_certificate_edges(
                procedure,
                procedure_key,
                &omitted_edges,
                infeasible_edges,
                origin.point,
                gap_points,
                request,
            ) {
                Ok(edges) => certificate_edges.extend(edges),
                Err(error) => {
                    push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                    return DeadWriteAnswer::Open { reasons };
                }
            }
            certificate_edges.sort_unstable();
            certificate_edges.dedup();
            omitted_edges.extend_from_slice(&certificate_edges);
            omitted_edges.sort_unstable();
            omitted_edges.dedup();
            // Full-graph entry reachability cannot certify the reduced graph.
            entry_reachable = None;
        }
        let infeasible_edges = certificate_edges.as_slice();
        // All establishments of this binding share entry reachability,
        // ordered read/write events and the backward may-liveness solve.
        // Cache only within the request and retain its artifact identity.
        let reachable = entry_reachable.map_or_else(
            || {
                self.cached_dead_write_reachability(
                    procedure,
                    procedure_key,
                    &omitted_edges,
                    infeasible_edges,
                    semantics.entry_point(),
                    request,
                )
            },
            Ok,
        );
        let key = DeadWriteBindingKey(procedure_key, binding, omitted_edges);
        let prepared = if let Some(entry) = request.memos.dead_write_cache.get(&key) {
            entry.outcome.clone()
        } else {
            let outcome = reachable.and_then(|reachable| {
                let mut cfg_request =
                    CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
                with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                    let graph = &FeasibleSuccessors::new(graph, infeasible_edges.iter().copied());
                    prepare_dead_write_over_graph(
                        graph,
                        &self.events,
                        &self.event_keys,
                        procedure_index
                            .events_by_binding
                            .get(&binding)
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                        reachable,
                        &mut cfg_request,
                    )
                })
                .map(Arc::new)
            });
            request.memos.dead_write_cache.insert(
                key,
                DeadWriteCacheEntry {
                    _artifact: Arc::clone(procedure.artifact()),
                    outcome: outcome.clone(),
                },
            );
            outcome
        };
        let result = prepared.and_then(|prepared| {
            let mut cfg_request =
                CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
            with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                let graph = &FeasibleSuccessors::new(graph, infeasible_edges.iter().copied());
                dead_write_from_prepared(
                    graph,
                    &self.events,
                    &self.event_keys,
                    establishment_event,
                    &prepared,
                    &mut cfg_request,
                )
            })
        });
        if !reasons.is_empty() {
            return match result {
                Ok(answer @ DeadWriteAnswer::Live { .. }) => answer,
                Ok(_) => DeadWriteAnswer::Open { reasons },
                Err(error) => {
                    push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                    DeadWriteAnswer::Open { reasons }
                }
            };
        }
        match result {
            Ok(answer) => answer,
            Err(error) => {
                let mut reasons = Vec::new();
                push_algorithm_reason(error, FlowStateAxis::ReachingRelation, &mut reasons);
                DeadWriteAnswer::Open { reasons }
            }
        }
    }

    fn cached_dead_write_reachability(
        &self,
        procedure: &ProcedureHandle,
        procedure_key: DeadWriteProcedureKey,
        omitted_edges: &[ControlEdgeId],
        infeasible_edges: &[ControlEdgeId],
        start: ProgramPointId,
        request: &mut FlowStateRequest<'_>,
    ) -> Result<Arc<Reachability<ProgramPointId>>, CfgAlgorithmError<ProgramPointId>> {
        let key = DeadWriteControlKey(procedure_key, omitted_edges.to_vec(), start);
        if let Some(entry) = request.memos.dead_write_reachability_cache.get(&key) {
            return entry.outcome.clone();
        }
        let mut cfg_request =
            CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
        let outcome =
            with_control_graph!(procedure.semantics(), &self.control_edge_mask, |graph| {
                let graph = &FeasibleSuccessors::new(graph, infeasible_edges.iter().copied());
                forward_reachability(graph, start, &mut cfg_request)
            })
            .map(Arc::new);
        request.memos.dead_write_reachability_cache.insert(
            key,
            DeadWriteReachabilityCacheEntry {
                _artifact: Arc::clone(procedure.artifact()),
                outcome: outcome.clone(),
            },
        );
        outcome
    }

    #[allow(clippy::too_many_arguments)]
    fn dead_write_certificate_edges(
        &self,
        procedure: &ProcedureHandle,
        procedure_key: DeadWriteProcedureKey,
        omitted_edges: &[ControlEdgeId],
        infeasible_edges: &[ControlEdgeId],
        origin: ProgramPointId,
        mut gap_points: HashSet<ProgramPointId>,
        request: &mut FlowStateRequest<'_>,
    ) -> Result<Vec<ControlEdgeId>, CfgAlgorithmError<ProgramPointId>> {
        let order = self.cached_dead_write_component_order(
            procedure,
            procedure_key,
            omitted_edges,
            infeasible_edges,
            request,
        )?;
        // Earlier components cannot be reached by the write. Later components
        // cannot reach it. Same-component gaps may cut its loop entry paths.
        gap_points.retain(|point| order[point.index()] >= order[origin.index()]);
        // Read only the isolated points' own edges, so a write costs the
        // degree of its gaps rather than a scan of the whole procedure.
        let semantics = procedure.semantics();
        let mut edges: Vec<ControlEdgeId> = gap_points
            .iter()
            .flat_map(|&point| {
                semantics
                    .successor_edges(point)
                    .chain(semantics.predecessor_edges(point))
                    .map(|(edge, _)| edge)
            })
            .collect();
        edges.sort_unstable();
        edges.dedup();
        Ok(edges)
    }

    fn cached_dead_write_component_order(
        &self,
        procedure: &ProcedureHandle,
        procedure_key: DeadWriteProcedureKey,
        omitted_edges: &[ControlEdgeId],
        infeasible_edges: &[ControlEdgeId],
        request: &mut FlowStateRequest<'_>,
    ) -> Result<Arc<[usize]>, CfgAlgorithmError<ProgramPointId>> {
        let key = (procedure_key, omitted_edges.to_vec());
        if let Some(entry) = request.dead_write_component_order_cache.get(&key) {
            return entry.outcome.clone();
        }
        let mut cfg_request =
            CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
        let outcome =
            with_control_graph!(procedure.semantics(), &self.control_edge_mask, |graph| {
                let graph = &FeasibleSuccessors::new(graph, infeasible_edges.iter().copied());
                let (components, dfs) =
                    strongly_connected_components_with_order(graph, &mut cfg_request)?;
                let mut ranks = vec![usize::MAX; components.components.len()];
                let mut next = 0;
                let mut order = vec![0; graph.node_count()];
                for point in dfs.reverse_postorder {
                    let component = components
                        .component_of(graph, point)
                        .expect("DFS point belongs to graph");
                    if ranks[component] == usize::MAX {
                        ranks[component] = next;
                        next += 1;
                    }
                    order[point.index()] = ranks[component];
                }
                Ok(Arc::from(order))
            });
        request.dead_write_component_order_cache.insert(
            key,
            DeadWriteComponentOrderCacheEntry {
                _artifact: Arc::clone(procedure.artifact()),
                outcome: outcome.clone(),
            },
        );
        outcome
    }

    /// The forward closure of retained non-drop gaps, shared by all writes.
    fn cached_dead_write_prefix_reachability(
        &self,
        procedure: &ProcedureHandle,
        procedure_key: DeadWriteProcedureKey,
        omitted_edges: &[ControlEdgeId],
        infeasible_edges: &[ControlEdgeId],
        starts: &[ProgramPointId],
        request: &mut FlowStateRequest<'_>,
    ) -> Result<Arc<Reachability<ProgramPointId>>, CfgAlgorithmError<ProgramPointId>> {
        let key = (procedure_key, omitted_edges.to_vec(), starts.to_vec());
        if let Some(entry) = request.dead_write_prefix_reachability_cache.get(&key) {
            return entry.outcome.clone();
        }
        let mut cfg_request =
            CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
        let outcome =
            with_control_graph!(procedure.semantics(), &self.control_edge_mask, |graph| {
                let graph = &FeasibleSuccessors::new(graph, infeasible_edges.iter().copied());
                forward_reachability_from_all(graph, starts.iter().copied(), &mut cfg_request)
            })
            .map(Arc::new);
        request.dead_write_prefix_reachability_cache.insert(
            key,
            DeadWriteReachabilityCacheEntry {
                _artifact: Arc::clone(procedure.artifact()),
                outcome: outcome.clone(),
            },
        );
        outcome
    }

    /// Join an exact source loop to its body and own repeat edge, then ask
    /// whether the body can reach that edge before leaving this invocation of
    /// the loop. The source adapter must validate the prepared syntax against
    /// this artifact before passing its structured AST spans. The header and
    /// body come from the producer's loop site for the exact loop span, so a
    /// language whose lowering authors no loop sites stays open.
    pub fn loop_body_reaches_own_repeat(
        &self,
        procedure: &ProcedureHandle,
        site: LoopSourceSite,
        request: &mut FlowStateRequest<'_>,
    ) -> LoopRepeatAnswer {
        assert_eq!(self.procedure, procedure.id());
        assert!(
            self.procedure_artifact
                .upgrade()
                .is_some_and(|artifact| Arc::ptr_eq(&artifact, procedure.artifact())),
            "loop proof requires the derivation's exact artifact"
        );
        let reasons = self
            .completeness
            .reasons()
            .iter()
            .filter(|reason| reason.blocks(FlowStateAxis::DominanceRelation))
            .cloned()
            .map(LoopRepeatIncompleteReason::Flow)
            .collect::<Vec<_>>();
        if !reasons.is_empty() {
            return LoopRepeatAnswer::Open { reasons };
        }
        let semantics = procedure.semantics();
        let mut cfg_request =
            CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
        let result = with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            loop_repeat_over_graph(graph, semantics, site, &mut cfg_request)
        });
        match result {
            Ok(answer) => answer,
            Err(error) => {
                let mut reasons = Vec::new();
                push_algorithm_reason(error, FlowStateAxis::DominanceRelation, &mut reasons);
                LoopRepeatAnswer::Open {
                    reasons: reasons
                        .into_iter()
                        .map(LoopRepeatIncompleteReason::Flow)
                        .collect(),
                }
            }
        }
    }

    fn point_reaches(
        &self,
        semantics: &ProcedureSemantics,
        origin: ProgramPointId,
        target: ProgramPointId,
        include_origin: bool,
    ) -> bool {
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            point_reaches(graph, origin, target, include_origin)
        })
    }

    /// Follow exact reaching definitions through identity-preserving
    /// assignments into local bindings.
    ///
    /// One closure step must have both halves of the production semantic
    /// account: an exact `Reaching` row from a tracked establishment to a read,
    /// and a `SameEvaluation` row from that read to an establishment whose
    /// assigned value is connected only by structured `Assignment` edges.
    /// Intermediate temporary assignments cover transparent wrappers such as
    /// parentheses. The walk never crosses a call result, language-defined
    /// value flow, address creation, memory, a capture, or a non-local binding.
    ///
    /// The returned closure is bounded by this derivation's event count and
    /// the procedure's value count. A `May` reaching row or a direct copy into
    /// a parameter, receiver, or property is recorded explicitly instead of
    /// being promoted to an alias. An `AggregateCopy` likewise remains visible
    /// as ordinary data dependence, but its independent aggregate storage is
    /// retained as an unclosed identity transfer rather than an exact alias.
    pub fn exact_local_value_alias_closure(
        &self,
        procedure: &ProcedureHandle,
        root_establishments: &[usize],
    ) -> ExactLocalValueAliasClosure {
        let mut closure = ExactLocalValueAliasClosure {
            establishments: root_establishments.iter().copied().collect(),
            reads: HashSet::default(),
            uncertain_reads: HashSet::default(),
            uncertain_transfers: HashSet::default(),
            unclosed_transfers: HashSet::default(),
            proof_open: false,
            reaching_establishment_by_read: HashMap::default(),
            copied_from_read_by_establishment: HashMap::default(),
        };
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
            || self.result_flow_has_hard_hole()
            || closure.establishments.iter().any(|event| {
                self.events.get(*event).is_none_or(|event| {
                    event.event_class != StateEventClass::Establish
                        || event.procedure != self.procedure
                })
            })
        {
            closure.proof_open = true;
            return closure;
        }

        let semantics = procedure.semantics();
        struct RetainedFieldAccess {
            stored_values: Vec<ValueId>,
        }
        let mut unclosed_evaluation_ranges = Vec::new();
        for gap in semantics.gaps().iter().filter(|gap| {
            scoped_axes_blocked_by(semantics, gap).contains(&FlowStateAxis::SameEvaluationRelation)
                && !matches!(
                    gap.capability,
                    SemanticCapability::Calls
                        | SemanticCapability::DynamicDispatch
                        | SemanticCapability::CallableReferences
                )
                && gap.impacts.contains(SemanticGapImpact::ValueFlow)
                && matches!(
                    gap.control_flow_discharge(),
                    SemanticGapDischarge::None
                        | SemanticGapDischarge::CallResolution
                        | SemanticGapDischarge::CanonicalIndexIdentity
                )
        }) {
            let Some(mapping) = semantics.source_mapping(gap.source) else {
                closure.proof_open = true;
                continue;
            };
            let span = mapping.locator.anchor().span();
            if span.start_byte() >= span.end_byte() {
                closure.proof_open = true;
                continue;
            }
            let retained_field_access = match gap.subject {
                SemanticGapSubject::MemoryLocation(location) => semantics
                    .memory_location(location)
                    .and_then(|memory| match memory.kind {
                        MemoryLocationKind::Field { .. }
                        | MemoryLocationKind::Property { .. }
                        | MemoryLocationKind::Dereference { .. } => {
                            semantics.point(gap.point).and_then(|point| {
                                let mut retains_access = false;
                                let mut stored_values = Vec::new();
                                for event in &point.events {
                                    match event.effect {
                                        SemanticEffect::MemoryLoad {
                                            location: accessed, ..
                                        } if accessed == location => retains_access = true,
                                        SemanticEffect::MemoryStore {
                                            location: accessed,
                                            value,
                                            ..
                                        } if accessed == location => {
                                            retains_access = true;
                                            stored_values.push(value);
                                        }
                                        _ => {}
                                    }
                                }
                                retains_access.then_some(RetainedFieldAccess { stored_values })
                            })
                        }
                        MemoryLocationKind::Static { .. }
                        | MemoryLocationKind::Capture { .. }
                        | MemoryLocationKind::LexicalCell { .. }
                        | MemoryLocationKind::Index { .. } => None,
                    }),
                _ => None,
            };
            unclosed_evaluation_ranges.push((
                gap.point,
                span.start_byte() as usize,
                span.end_byte() as usize,
                retained_field_access,
            ));
        }
        let read_has_unclosed_transfer =
            |read: &StateEventRow, transparent_values: &HashSet<ValueId>| {
                read.site.range.start_byte < read.site.range.end_byte
                    && unclosed_evaluation_ranges.iter().any(
                        |(point, start, end, retained_field_access)| {
                            read.site.range.start_byte >= *start
                            && read.site.range.end_byte <= *end
                            // A retained load transfers none of its nested
                            // operands. A retained store transfers only the
                            // structured stored value. This distinguishes a
                            // nested receiver such as `x.Inner().Field` from
                            // an RHS actually written into unresolved memory.
                            && retained_field_access.as_ref().is_none_or(|access| {
                                access
                                    .stored_values
                                    .iter()
                                    .any(|value| transparent_values.contains(value))
                            })
                            && self.point_reaches(semantics, read.point, *point, true)
                        },
                    )
            };
        let mut reaching_by_establishment =
            HashMap::<usize, Vec<(usize, FlowCertainty)>>::default();
        let mut same_evaluation_by_read = HashMap::<usize, Vec<usize>>::default();
        for relation in &self.relations {
            match relation.relation {
                FlowRelation::Reaching => reaching_by_establishment
                    .entry(relation.source_event)
                    .or_default()
                    .push((relation.target_event, relation.certainty)),
                FlowRelation::SameEvaluation => same_evaluation_by_read
                    .entry(relation.target_event)
                    .or_default()
                    .push(relation.source_event),
                FlowRelation::Dominates => {}
            }
        }
        let mut transparent_assignments = HashMap::<ValueId, Vec<ValueId>>::default();
        // Go's conversion source is an expression-occurrence value, not the
        // binding cell it reads. `expression_value` caches by AST node id, so
        // two reads of one binding have distinct ValueIds and only the read
        // occurrence that actually feeds this conversion enters the set.
        let mut assignment_conversion_sources = HashSet::<ValueId>::default();
        // An identity-separating transfer remains ordinary data dependence,
        // but its validated adjacent Assignment does not preserve aggregate
        // storage identity. Retain the exact source read as an open transfer
        // rather than promoting the copied local into this resource-identity
        // closure.
        let mut identity_separating_assignments =
            HashSet::<(ProgramPointId, ValueId, ValueId)>::default();
        for point in semantics.points() {
            for event in &point.events {
                match event.effect {
                    SemanticEffect::Assignment { target, value }
                        if semantics
                            .value(target)
                            .is_some_and(|value| value.kind == SemanticValueKind::Temporary) =>
                    {
                        transparent_assignments
                            .entry(value)
                            .or_default()
                            .push(target);
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } if semantics.value(target).is_some_and(|value| {
                        matches!(
                            &value.kind,
                            SemanticValueKind::LanguageDefined(kind)
                                if kind.as_ref() == "go.assignment_conversion"
                        )
                    }) =>
                    {
                        assignment_conversion_sources.insert(source);
                    }
                    SemanticEffect::ValueFlow {
                        kind:
                            ValueFlowKind::Transfer(_)
                            | ValueFlowKind::OwnershipUnknown
                            | ValueFlowKind::ReferenceBoxing
                            | ValueFlowKind::ReferenceUnboxing,
                        source,
                        target,
                    } => {
                        identity_separating_assignments.insert((point.id, target, source));
                    }
                    _ => {}
                }
            }
        }
        let mut pending = root_establishments.to_vec();
        while let Some(establishment) = pending.pop() {
            for &(read_event, certainty) in reaching_by_establishment
                .get(&establishment)
                .into_iter()
                .flatten()
            {
                match certainty {
                    FlowCertainty::Exact => {
                        let previous = closure
                            .reaching_establishment_by_read
                            .entry(read_event)
                            .or_insert(establishment);
                        assert_eq!(
                            *previous, establishment,
                            "an Exact reaching read has one establishment"
                        );
                        if !closure.reads.insert(read_event) {
                            continue;
                        }
                        let read = &self.events[read_event];
                        let transparent_values = transparent_assignment_values(
                            &transparent_assignments,
                            read.value,
                            semantics.values().len(),
                        );
                        if transparent_values
                            .iter()
                            .any(|value| assignment_conversion_sources.contains(value))
                        {
                            // Assignment conversion preserves data dependence,
                            // but it is not proof that the converted value keeps
                            // the source's resource identity. Keep the source
                            // read visible without promoting the converted local.
                            closure.unclosed_transfers.insert(read.event);
                            continue;
                        }
                        if read_has_unclosed_transfer(read, &transparent_values) {
                            // The semantic producer scoped an unclosed
                            // same-evaluation boundary downstream of this
                            // exact read. It may copy into a parameter,
                            // property, capture, or otherwise unmodeled target,
                            // but it is not evidence for a second exact local
                            // binding. Materialized call-like uses are handled
                            // by use enumeration rather than hidden transfers.
                            closure.unclosed_transfers.insert(read.event);
                        }
                        for alias_event in same_evaluation_by_read
                            .get(&read.event)
                            .into_iter()
                            .flatten()
                        {
                            let alias = &self.events[*alias_event];
                            if !transparent_values.contains(&alias.value) {
                                continue;
                            }
                            match alias.subject {
                                FlowSubject::Binding { value }
                                    if semantics.value(value).is_some_and(|value| {
                                        value.kind == SemanticValueKind::Local
                                    }) =>
                                {
                                    if identity_separating_assignments.contains(&(
                                        alias.point,
                                        value,
                                        alias.value,
                                    )) {
                                        closure.unclosed_transfers.insert(read.event);
                                        continue;
                                    }
                                    debug_assert!(
                                        semantics.point(alias.point).is_some_and(|point| {
                                            point.events.iter().any(|event| {
                                                matches!(
                                                    event.effect,
                                                    SemanticEffect::Assignment { target, value: assigned }
                                                        if target == value && assigned == alias.value
                                                )
                                            })
                                        }),
                                        "a binding establishment is backed by its semantic assignment"
                                    );
                                    if closure.establishments.insert(alias.event) {
                                        closure
                                            .copied_from_read_by_establishment
                                            .insert(alias.event, read.event);
                                        pending.push(alias.event);
                                    }
                                }
                                FlowSubject::Binding { .. } | FlowSubject::Property { .. } => {
                                    closure.unclosed_transfers.insert(read.event);
                                }
                            }
                        }
                    }
                    FlowCertainty::May => {
                        closure.uncertain_reads.insert(read_event);
                        let read = &self.events[read_event];
                        let transparent_values = transparent_assignment_values(
                            &transparent_assignments,
                            read.value,
                            semantics.values().len(),
                        );
                        if transparent_values
                            .iter()
                            .any(|value| assignment_conversion_sources.contains(value))
                            || read_has_unclosed_transfer(read, &transparent_values)
                            || same_evaluation_by_read
                                .get(&read.event)
                                .into_iter()
                                .flatten()
                                .any(|alias_event| {
                                    transparent_values.contains(&self.events[*alias_event].value)
                                })
                        {
                            closure.uncertain_transfers.insert(read_event);
                        }
                    }
                }
            }
        }
        debug_assert!(closure.establishments.len() <= self.events.len());
        debug_assert!(closure.reads.len() <= self.events.len());
        debug_assert!(closure.uncertain_reads.len() <= self.events.len());
        debug_assert!(closure.uncertain_transfers.len() <= closure.uncertain_reads.len());
        closure
    }

    /// Whether one exact read in `closure` still observes the modeled result
    /// identity through its own alias cell.
    ///
    /// Each local copy creates an independent binding cell. The walk therefore
    /// checks address escape one provenance segment at a time: from a source
    /// establishment to the read copied into the next alias, and finally from
    /// that alias establishment to `read_event`. Escaping `&alias` cannot
    /// poison a later read from the original binding, while it does keep a
    /// later read from that alias open.
    pub fn exact_local_alias_read_identity_is_closed(
        &self,
        procedure: &ProcedureHandle,
        closure: &ExactLocalValueAliasClosure,
        read_event: usize,
    ) -> bool {
        self.walk_local_alias_read_identity(procedure, closure, read_event, |_| {})
    }

    /// The ordered event chain for one exact read, using the same predecessor
    /// walk and identity checks as [`Self::exact_local_alias_read_identity_is_closed`].
    /// The allocation is owned only by callers that need to retain a witness.
    pub fn exact_local_alias_read_identity_witness(
        &self,
        procedure: &ProcedureHandle,
        closure: &ExactLocalValueAliasClosure,
        read_event: usize,
    ) -> Option<Vec<usize>> {
        let mut reverse_witness = Vec::new();
        self.walk_local_alias_read_identity(procedure, closure, read_event, |event| {
            reverse_witness.push(event);
        })
        .then(|| {
            reverse_witness.reverse();
            reverse_witness
        })
    }

    fn walk_local_alias_read_identity(
        &self,
        procedure: &ProcedureHandle,
        closure: &ExactLocalValueAliasClosure,
        read_event: usize,
        mut witness_event: impl FnMut(usize),
    ) -> bool {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if closure.proof_open
            || self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
            || !closure.reads.contains(&read_event)
        {
            return false;
        }

        let semantics = procedure.semantics();
        let mut current_read = read_event;
        let mut visited = HashSet::default();
        loop {
            if !visited.insert(current_read) {
                return false;
            }
            debug_assert!(visited.len() <= self.events.len());
            witness_event(current_read);
            let Some(&establishment) = closure.reaching_establishment_by_read.get(&current_read)
            else {
                return false;
            };
            let establishment = &self.events[establishment];
            let read = &self.events[current_read];
            let identity_closed = match establishment.subject {
                FlowSubject::Binding { value: binding } => {
                    with_control_graph!(semantics, &self.control_edge_mask, |graph| {
                        binding_identity_is_closed_between(
                            semantics,
                            graph,
                            establishment.point,
                            read.point,
                            binding,
                        )
                    })
                }
                // Exact property reaching proves which direct property store
                // serves the read, but not that the property base stayed
                // unique. A copied base or an intervening call may mutate the
                // same cell without another event on this canonical base.
                // Keep property-root identity open until structured base
                // alias and escape closure exists.
                FlowSubject::Property { .. } => false,
            };
            if !identity_closed {
                return false;
            }
            witness_event(establishment.event);
            let Some(&source_read) = closure
                .copied_from_read_by_establishment
                .get(&establishment.event)
            else {
                return true;
            };
            current_read = source_read;
        }
    }

    /// The relations of one family, in derivation order.
    #[cfg(test)]
    fn relations_of(&self, relation: FlowRelation) -> impl Iterator<Item = &FlowRelationRow> {
        self.relations
            .iter()
            .filter(move |row| row.relation == relation)
    }

    /// For each target, whether at least one individual candidate dominates
    /// it in this procedure's already-derived dominator tree.
    ///
    /// `None` means the flow-state derivation cannot prove these predicates.
    /// An algorithm- or capability-wide dominance hole blocks the batch. A
    /// point-scoped control gap is harmless to one candidate-to-target proof
    /// when that same candidate dominates the gap point: any omitted outgoing
    /// behavior has already passed the candidate it would otherwise need to
    /// bypass. The candidates are tested independently and ORed; they are not
    /// treated as one collective vertex cut.
    pub fn any_candidate_dominates_targets(
        &self,
        procedure: &ProcedureHandle,
        candidates: &[ProgramPointId],
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;
        let control_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| {
                scoped_axes_blocked_by(semantics, gap).contains(&FlowStateAxis::DominanceRelation)
            })
            .collect::<Vec<_>>();
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            candidate_points_dominate_targets(graph, dominance, candidates, targets, &control_gaps)
        })
    }

    /// Result-specific counterpart to [`Self::any_candidate_dominates_targets`].
    ///
    /// A non-rejoining exceptional gap in the strict acyclic history of every
    /// exact result establishment cannot expose that result to a target while
    /// bypassing a later candidate. `ExitOnlyProcedureCompletion` has the same
    /// pre-origin rule only when every target is normal-entry-reachable and
    /// outside retained cleanup, exceptional, and asynchronous regions. The
    /// gap need not dominate an establishment: an optional pre-origin
    /// evaluation can only abort or register exit work on paths that execute
    /// it. All other point-scoped gaps retain the generic candidate-local proof
    /// obligation, and every procedure-wide or hard completeness hole remains
    /// blocking.
    pub fn any_candidate_dominates_result_uses(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        candidates: &[ProgramPointId],
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .chain(candidates)
                .chain(targets)
                .any(|point| semantics.point(*point).is_none())
        {
            return None;
        }

        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let control_gaps =
                result_control_gaps(semantics, graph, result_establishments, targets, |_| true);
            candidate_points_dominate_targets(graph, dominance, candidates, targets, &control_gaps)
        })
    }

    /// The selective dominance proof for normalized conditional guard arms.
    ///
    /// Unlike an arbitrary point, a validated guard-edge target is a language-
    /// authored boundary reached only after the condition's evaluations have
    /// completed. `RetainedEvaluationOrder` therefore cannot move work across
    /// it, and `RetainedControlTopology` promises that no source-local normal
    /// successor can bypass it. Those two proof obligations are discharged only
    /// here. Global relation completeness and the generic point API remain
    /// conservative.
    pub fn any_guard_arm_dominates_targets(
        &self,
        procedure: &ProcedureHandle,
        candidates: &[ControlEdgeHandle],
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;

        let candidate_edges = validated_guard_edges(procedure, candidates)?;

        let control_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| {
                scoped_axes_blocked_by(procedure.semantics(), gap)
                    .contains(&FlowStateAxis::DominanceRelation)
                    && !matches!(
                        gap.control_flow_discharge(),
                        SemanticGapDischarge::RetainedEvaluationOrder
                            | SemanticGapDischarge::RetainedControlTopology
                    )
            })
            .collect::<Vec<_>>();
        let answers = with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            guard_edges_dominate_targets(
                semantics,
                graph,
                dominance,
                &candidate_edges,
                targets,
                &control_gaps,
            )
        });
        if answers.contains(&GuardDominanceAnswer::Open) {
            return None;
        }
        Some(
            answers
                .iter()
                .map(|answer| *answer == GuardDominanceAnswer::Proven)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    /// Result-specific counterpart to [`Self::any_guard_arm_dominates_targets`].
    ///
    /// Retained guard provenance may discharge retained evaluation order and
    /// control topology as usual. In addition, a non-rejoining exceptional gap
    /// is irrelevant when it is in the strict acyclic history of every exact
    /// result establishment or retained reachability proves its point cannot
    /// reach the queried use after the guard's control projection.
    /// `ExitOnlyProcedureCompletion` has those same two result-specific rules
    /// only for an ordinary-body target: it must be normal-entry-reachable and
    /// outside retained cleanup, exceptional, and asynchronous regions. The
    /// pre-origin rule admits mandatory and optional evaluations; the
    /// target-relative rule admits strictly later and sibling-arm completion
    /// gaps. Completion may run active cleanup or deferred work, but it cannot
    /// resume the normal body. Markers between the origin and target,
    /// predecessors, and cycles remain blocking.
    ///
    /// Each result element carries target-local uncertainty as `Open`. The
    /// outer `None` is reserved for batch-wide proof unavailability.
    pub fn any_guard_arm_dominates_result_uses(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        candidates: &[ControlEdgeHandle],
        targets: &[ProgramPointId],
    ) -> Option<Box<[GuardDominanceAnswer]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| semantics.point(*point).is_none())
        {
            return None;
        }

        let candidate_edges = validated_guard_edges(procedure, candidates)?;
        Some(with_control_graph!(
            semantics,
            &self.control_edge_mask,
            |graph| {
                let control_gaps = result_control_gaps(
                    semantics,
                    graph,
                    result_establishments,
                    targets,
                    |discharge| {
                        !matches!(
                            discharge,
                            SemanticGapDischarge::RetainedEvaluationOrder
                                | SemanticGapDischarge::RetainedControlTopology
                        )
                    },
                );
                guard_edges_dominate_result_targets(
                    semantics,
                    graph,
                    dominance,
                    &candidate_edges,
                    targets,
                    &control_gaps,
                )
            }
        ))
    }

    /// Whether a point is confined to one exact guard arm relative to each
    /// result use.
    ///
    /// This is negative evidence for candidate validation, not a positive
    /// guard proof. A `true` answer means the candidate cannot validate that
    /// particular use from outside the supplied arm. A point-scoped control
    /// gap is therefore harmless when the use dominates the gap and the gap
    /// cannot revisit that static use: omitted behavior then begins only after
    /// the relevant use occurrence. This target-relative exception must not be
    /// applied to ordinary dominance, where an omitted later path can still
    /// invalidate a positive proof.
    ///
    /// `None` means the artifact or dominance derivation cannot answer. A
    /// `false` element means confinement was not proved for that use.
    pub fn any_guard_arm_confines_candidate_for_result_uses(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        candidates: &[ControlEdgeHandle],
        candidate_point: ProgramPointId,
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || semantics.point(candidate_point).is_none()
            || targets
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || self.result_flow_has_hard_hole()
        {
            return None;
        }

        let candidate_edges = validated_guard_edges(procedure, candidates)?;
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let control_gaps = result_control_gaps(
                semantics,
                graph,
                result_establishments,
                targets,
                |discharge| {
                    !matches!(
                        discharge,
                        SemanticGapDischarge::RetainedEvaluationOrder
                            | SemanticGapDischarge::RetainedControlTopology
                    )
                },
            );
            Some(guard_edges_confine_candidate_for_targets(
                semantics,
                graph,
                dominance,
                &candidate_edges,
                candidate_point,
                targets,
                &control_gaps,
            ))
        })
    }

    /// Whether each result use is confined to one exact guard arm for
    /// negative evidence.
    ///
    /// The caller supplies arms whose reviewed outcomes are already known not
    /// to establish success. A `true` answer proves only control confinement;
    /// it does not establish the guard predicate or give an arm negative
    /// meaning. In addition to gaps already confined by the exact edge, this
    /// proof can ignore a non-rejoining exceptional gap outside that arm only
    /// when the retained graph proves the gap cannot reach the use. This
    /// covers a sibling arm that returns before the use. The added exception
    /// excludes same-point, predecessor, and cyclic gaps; those remain subject
    /// to the existing exact-edge confinement rules. Ordinary positive
    /// dominance remains unchanged.
    ///
    /// `None` means the artifact or dominance derivation cannot answer. A
    /// `false` element means confinement was not proved for that use.
    pub fn any_guard_arm_confines_result_uses_for_negative_evidence(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        candidates: &[ControlEdgeHandle],
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || targets
                .iter()
                .any(|point| semantics.point(*point).is_none())
        {
            return None;
        }

        let candidate_edges = validated_guard_edges(procedure, candidates)?;
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let control_gaps = result_control_gaps(
                semantics,
                graph,
                result_establishments,
                targets,
                |discharge| {
                    !matches!(
                        discharge,
                        SemanticGapDischarge::RetainedEvaluationOrder
                            | SemanticGapDischarge::RetainedControlTopology
                    )
                },
            );
            Some(guard_edges_confine_targets_for_negative_evidence(
                semantics,
                graph,
                dominance,
                &candidate_edges,
                targets,
                &control_gaps,
            ))
        })
    }

    /// The selective dominance proof for validated normal-call continuations.
    ///
    /// A normal continuation is reached only when that exact call returns
    /// normally. `RetainedControlTopology` promises that the adapter retained
    /// every source-local normal successor, so unresolved range progress or
    /// liveness cannot create a path to a reached target that bypasses this
    /// continuation. `RetainedEvaluationOrder` remains blocking: operand
    /// effects can change which value a modeled refinement validates before
    /// the continuation is reached.
    pub fn any_normal_return_dominates_targets(
        &self,
        procedure: &ProcedureHandle,
        candidates: &[CallSiteHandle],
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let (semantics, dominance) = self.dominance_context(procedure)?;

        let mut candidate_points = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if candidate.procedure() != procedure {
                return None;
            }
            candidate_points.push(
                semantics
                    .call_site(candidate.id())?
                    .normal_continuation
                    .target()?,
            );
        }

        let control_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| {
                scoped_axes_blocked_by(semantics, gap).contains(&FlowStateAxis::DominanceRelation)
                    && gap.control_flow_discharge() != SemanticGapDischarge::RetainedControlTopology
            })
            .collect::<Vec<_>>();
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            candidate_points_dominate_targets(
                graph,
                dominance,
                &candidate_points,
                targets,
                &control_gaps,
            )
        })
    }

    /// Result-specific counterpart to
    /// [`Self::any_normal_return_dominates_targets`].
    ///
    /// Candidate identity remains an exact semantic call handle. A
    /// language-authored non-rejoining exceptional gap strictly before every
    /// establishment of this exact result is discharged. An exact candidate
    /// result used as an argument of the target invocation is also an ordering
    /// proof when the condition's binding cells remain unchanged through the
    /// rest of the invocation's operand evaluation.
    pub fn any_normal_return_dominates_result_uses(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        predicate_bindings: &[ValueId],
        candidates: &[CallSiteHandle],
        targets: &[ProgramPointId],
        target_calls: &[Option<CallSiteId>],
    ) -> Option<Box<[bool]>> {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            return None;
        }
        let semantics = procedure.semantics();
        let dominance = self.dominance.as_ref()?;
        if targets.len() != target_calls.len()
            || result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || self.completeness.reasons().iter().any(|reason| {
                reason.blocks(FlowStateAxis::DominanceRelation)
                    && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
            })
        {
            return None;
        }

        let candidate_points = normal_return_candidate_points(procedure, candidates)?;
        let predicate_bindings = predicate_bindings.iter().copied().collect::<HashSet<_>>();
        #[derive(Clone, Copy)]
        enum DirectOrdering {
            NotApplicable,
            Proven,
            Open,
        }
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let control_gaps = result_control_gaps(
                semantics,
                graph,
                result_establishments,
                targets,
                |discharge| discharge != SemanticGapDischarge::RetainedControlTopology,
            );
            let direct_ordering = targets
                .iter()
                .zip(target_calls)
                .map(|(target, target_call)| {
                    let Some(target_call) = target_call else {
                        return DirectOrdering::NotApplicable;
                    };
                    let Some(target_call) = semantics.call_site(*target_call) else {
                        return DirectOrdering::Open;
                    };
                    if target_call.point != *target {
                        return DirectOrdering::Open;
                    }
                    let mut applicable = false;
                    for (candidate, candidate_point) in candidates.iter().zip(&candidate_points) {
                        let candidate = semantics
                            .call_site(candidate.id())
                            .expect("normal-return candidates were validated above");
                        if !candidate.normal_result_is_argument_to(target_call) {
                            continue;
                        }
                        applicable = true;
                        if target_call_evaluation_is_open(semantics, target_call) {
                            // This exact candidate cannot prove ordering, but
                            // an independent earlier validator still can.
                            continue;
                        }
                        if !predicate_bindings.is_empty()
                            && dominance.dominates(graph, *candidate_point, *target)
                            && self.binding_state_is_closed_between(
                                semantics,
                                graph,
                                *candidate_point,
                                *target,
                                &predicate_bindings,
                            )
                            && control_gaps.iter().all(|gap| {
                                gap.control_flow_discharge()
                                    == SemanticGapDischarge::RetainedEvaluationOrder
                                    || (gap.subject != SemanticGapSubject::Procedure
                                        && (dominance.dominates(
                                            graph,
                                            *candidate_point,
                                            gap.point,
                                        )
                                            // Reaching this exact normal
                                            // continuation proves that a
                                            // strictly earlier non-rejoining
                                            // exit was not taken. Reject a
                                            // cycle: the exit marker is not a
                                            // general liveness discharge.
                                            || (gap.control_flow_discharge()
                                                == SemanticGapDischarge::NonRejoiningExceptionalExit
                                                && point_reaches(
                                                    graph,
                                                    gap.point,
                                                    *candidate_point,
                                                    false,
                                                )
                                                && !point_reaches(
                                                    graph,
                                                    *candidate_point,
                                                    gap.point,
                                                    false,
                                                ))))
                            })
                        {
                            return DirectOrdering::Proven;
                        }
                    }
                    if applicable {
                        // A direct candidate with open target evaluation does
                        // not erase an independent earlier validator. Exclude
                        // every direct candidate from the ordinary fallback,
                        // and require the earlier candidate's binding state to
                        // stay closed through this same target.
                        let non_argument_candidates = candidates
                            .iter()
                            .zip(&candidate_points)
                            .filter_map(|(candidate, point)| {
                                let candidate = semantics
                                    .call_site(candidate.id())
                                    .expect("normal-return candidates were validated above");
                                (!candidate.normal_result_is_argument_to(target_call)
                                    && !predicate_bindings.is_empty()
                                    && !target_call_has_call_evaluation_gap(semantics, target_call)
                                    && self.binding_state_is_closed_between(
                                        semantics,
                                        graph,
                                        *point,
                                        *target,
                                        &predicate_bindings,
                                    ))
                                .then_some(*point)
                            })
                            .collect::<Vec<_>>();
                        if candidate_points_dominate_targets(
                            graph,
                            dominance,
                            &non_argument_candidates,
                            &[*target],
                            &control_gaps,
                        )
                        .as_deref()
                            == Some([true].as_slice())
                        {
                            DirectOrdering::Proven
                        } else {
                            DirectOrdering::Open
                        }
                    } else {
                        DirectOrdering::NotApplicable
                    }
                })
                .collect::<Vec<_>>();
            if direct_ordering
                .iter()
                .any(|answer| matches!(answer, DirectOrdering::Open))
            {
                return None;
            }
            let directly_ordered = direct_ordering
                .iter()
                .map(|answer| matches!(answer, DirectOrdering::Proven))
                .collect::<Vec<_>>();
            let unresolved_targets = targets
                .iter()
                .zip(&directly_ordered)
                .filter_map(|(target, ordered)| (!*ordered).then_some(*target))
                .collect::<Vec<_>>();
            let unresolved_answers = if unresolved_targets.is_empty() {
                Vec::new().into_boxed_slice()
            } else {
                candidate_points_dominate_targets(
                    graph,
                    dominance,
                    &candidate_points,
                    &unresolved_targets,
                    &control_gaps,
                )?
            };
            let mut unresolved_answers = unresolved_answers.iter();
            Some(
                directly_ordered
                    .into_iter()
                    .map(|ordered| {
                        ordered
                            || *unresolved_answers
                                .next()
                                .expect("every unresolved target has one dominance answer")
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        })
    }

    /// Whether every detached result consumer is unable to gate each use.
    ///
    /// This is deliberately narrower than postdominance. A detached callee's
    /// return cannot gate its caller, but the child can still communicate back
    /// through shared state or a channel. A target is therefore closed only
    /// when that exact consumer is unavoidable for the result use and the
    /// parent reaches the use through a unique normal continuation before any
    /// represented control, invocation, suspension, or undisclosed boundary.
    /// Branches, loops, calls, and gaps keep the target open. In particular,
    /// retained evaluation order may move a later synchronizing sibling before
    /// the target even when the retained CFG happens to visit the target first.
    /// The walk starts after registration, so the spawn's own retained-
    /// topology marker is not part of the traversed parent continuation.
    pub fn detached_consumers_cannot_gate_result_uses(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        candidates: &[CallSiteHandle],
        targets: &[ProgramPointId],
    ) -> Option<Box<[bool]>> {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
            || candidates.is_empty()
            || targets
                .iter()
                .any(|target| procedure.semantics().point(*target).is_none())
            || self.completeness.reasons().iter().any(|reason| {
                reason.blocks(FlowStateAxis::DominanceRelation)
                    && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
            })
        {
            return None;
        }

        let semantics = procedure.semantics();
        if semantics
            .gaps()
            .iter()
            .any(|gap| gap.subject == SemanticGapSubject::Procedure)
        {
            return None;
        }
        let barrier_gap_points = semantics
            .gaps()
            .iter()
            .map(|gap| gap.point)
            .collect::<HashSet<_>>();
        let mut starts = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if candidate.procedure() != procedure {
                return None;
            }
            let call = semantics.call_site(candidate.id())?;
            if call.invocation_mode != CallInvocationMode::Detached {
                return None;
            }
            let unavoidable = self.any_candidate_dominates_result_uses(
                procedure,
                result_establishments,
                std::slice::from_ref(&call.point),
                targets,
            )?;
            starts.push((call.id, call.normal_continuation.target()?, unavoidable));
        }

        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let mut answers = vec![true; targets.len()];
            for (candidate, start, unavoidable) in starts {
                let mut reached = vec![false; targets.len()];
                let mut visited = HashSet::default();
                let mut current = start;
                loop {
                    if !visited.insert(current) {
                        break;
                    }
                    for (index, target) in targets.iter().enumerate() {
                        reached[index] |= current == *target;
                    }
                    if reached.iter().all(|answer| *answer) {
                        break;
                    }
                    let point = semantics.point(current)?;
                    let event_is_barrier = point.events.iter().any(|event| match event.effect {
                        SemanticEffect::MemoryInterference
                        | SemanticEffect::Invoke { .. }
                        | SemanticEffect::AsyncSuspend { .. }
                        | SemanticEffect::AsyncResume { .. } => true,
                        SemanticEffect::CallContinuation { call_site, kind } => {
                            current != start
                                || call_site != candidate
                                || kind != CallContinuationKind::Normal
                        }
                        SemanticEffect::Entry
                        | SemanticEffect::NormalExit
                        | SemanticEffect::ExceptionalExit
                        | SemanticEffect::Assignment { .. }
                        | SemanticEffect::ValueFlow { .. }
                        | SemanticEffect::ValueUse { .. }
                        | SemanticEffect::Allocation { .. }
                        | SemanticEffect::MemoryLoad { .. }
                        | SemanticEffect::MemoryStore { .. }
                        | SemanticEffect::AggregateInitializer { .. }
                        | SemanticEffect::CallableCreation { .. }
                        | SemanticEffect::CallableReference { .. }
                        | SemanticEffect::CaptureBind { .. }
                        | SemanticEffect::Synchronization { .. }
                        | SemanticEffect::ProcedureReturn { .. }
                        | SemanticEffect::Throw { .. }
                        | SemanticEffect::Gap { .. } => false,
                    });
                    if event_is_barrier || barrier_gap_points.contains(&current) {
                        break;
                    }
                    let mut successors = graph.successors(current);
                    let Some((edge, successor)) = successors.next() else {
                        break;
                    };
                    if successors.next().is_some()
                        || semantics.control_edge(edge)?.kind != ControlEdgeKind::Normal
                    {
                        break;
                    }
                    current = successor;
                }
                for ((answer, reached), unavoidable) in
                    answers.iter_mut().zip(reached).zip(unavoidable.iter())
                {
                    *answer &= reached && *unavoidable;
                }
            }
            Some(answers.into_boxed_slice())
        })
    }

    /// Whether one exact guard arm preserves the identity of a modeled result
    /// through the arm boundary.
    ///
    /// This is deliberately a positive-edge proof, not a claim that all guard
    /// arms were found. A point-scoped gap after the arm target cannot change
    /// which value selected that already-reached arm. A non-rejoining exit
    /// cannot reach the arm at all, and retained evaluation order matters only
    /// when its exact source range contains a competing write to the tracked
    /// binding. `ExitOnlyProcedureCompletion` is harmless only when its point
    /// is strictly and acyclically before every result establishment and the
    /// exact arm target is an ordinary-body point, outside every retained
    /// cleanup, exceptional, or asynchronous region. Other undischargeable
    /// gaps before the arm keep that one edge unpublishable. Binding/reaching
    /// provider failures remain hard because the candidate result identity
    /// itself then has no exact flow account.
    pub fn guard_arm_preserves_result_identity(
        &self,
        procedure: &ProcedureHandle,
        result_establishments: &[ProgramPointId],
        relevant_values: &[ValueId],
        candidate: &ControlEdgeHandle,
    ) -> bool {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
            || result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| procedure.semantics().point(*point).is_none())
            || relevant_values.is_empty()
            || self.result_flow_has_hard_hole()
        {
            return false;
        }
        let semantics = procedure.semantics();
        let Some(dominance) = self.dominance.as_ref() else {
            return false;
        };
        let Some(candidate_edge) =
            validated_guard_edges(procedure, std::slice::from_ref(candidate))
                .and_then(|edges| edges.into_iter().next())
        else {
            return false;
        };
        let relevant_values = relevant_values.iter().copied().collect::<HashSet<_>>();
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            let control_gaps = result_control_gaps(
                semantics,
                graph,
                result_establishments,
                &[candidate_edge.target],
                |discharge| {
                    !matches!(
                        discharge,
                        SemanticGapDischarge::RetainedControlTopology
                            | SemanticGapDischarge::NonRejoiningExceptionalExit
                    )
                },
            )
            .into_iter()
            .filter(|gap| {
                gap.control_flow_discharge() != SemanticGapDischarge::RetainedEvaluationOrder
                    || self.gap_contains_competing_binding_write(
                        semantics,
                        gap,
                        &relevant_values,
                        result_establishments,
                    )
            })
            .collect::<Vec<_>>();
            candidate_points_dominate_targets(
                graph,
                dominance,
                &[candidate_edge.target],
                &[candidate_edge.target],
                &control_gaps,
            )
            .as_deref()
                == Some([true].as_slice())
        })
    }

    /// Whether the retained flow state completely enumerates observations of
    /// one exact result after it comes into existence.
    ///
    /// Unlike a dominance proof, an exhaustive count has no final proof
    /// barrier: an omitted transfer can expose another read even when all
    /// already-retained reads are guarded. A pre-origin transfer can also
    /// bypass the exact establishment and expose an older binding value. A
    /// non-rejoining exceptional marker cannot add a normal-body observation;
    /// omitted cleanup or deferred behavior is represented by its own gap.
    /// The check is therefore result-scoped but procedure-wide. It ignores
    /// unrelated value/location/call gaps and producer-declared retained
    /// topology, while refusing provider failures and relevant value-flow gaps.
    pub fn result_observations_are_complete(
        &self,
        procedure: &ProcedureHandle,
        result_origins: &[ProgramPointId],
        relevant_values: &[ValueId],
    ) -> bool {
        self.result_observation_enumeration_is_complete(procedure, result_origins, relevant_values)
            && self.result_identity_is_closed(procedure, result_origins, relevant_values)
    }

    /// Whether omitted control can introduce a repeat of a retained result
    /// origin. Non-rejoining exceptional exits cannot return to that origin;
    /// retained topology/order markers do not omit a source-local successor.
    pub fn result_occurrence_control_is_complete(&self, procedure: &ProcedureHandle) -> bool {
        self.result_observation_account_is_available(procedure)
            && procedure.semantics().points().iter().all(|point| {
                let evidence = procedure
                    .semantics()
                    .evidence_row(point.evidence)
                    .expect("validated control point evidence");
                matches!(evidence.proof, ProofStatus::Proven)
                    && matches!(evidence.completeness, EvidenceCompleteness::Complete)
            })
            && procedure.semantics().control_edges().iter().all(|edge| {
                let evidence = procedure
                    .semantics()
                    .evidence_row(edge.evidence)
                    .expect("validated control edge evidence");
                matches!(evidence.proof, ProofStatus::Proven)
                    && matches!(evidence.completeness, EvidenceCompleteness::Complete)
            })
            && !self.completeness.reasons().iter().any(|reason| {
                reason.blocks(FlowStateAxis::DominanceRelation)
                    && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
            })
            && !procedure.semantics().gaps().iter().any(|gap| {
                scoped_axes_blocked_by(procedure.semantics(), gap)
                    .contains(&FlowStateAxis::DominanceRelation)
                    && !matches!(
                        gap.control_flow_discharge(),
                        SemanticGapDischarge::RetainedControlTopology
                            | SemanticGapDischarge::RetainedEvaluationOrder
                            | SemanticGapDischarge::NonRejoiningExceptionalExit
                            | SemanticGapDischarge::ExitOnlyProcedureCompletion
                    )
            })
    }

    /// Whether retained flow and gaps completely enumerate observations,
    /// without conflating that question with binding-cell address escape.
    ///
    /// Callers that track exact by-value aliases use this method once for the
    /// shared observation set, then validate each observation's independent
    /// cell provenance with [`Self::exact_local_alias_read_identity_is_closed`].
    pub fn result_observation_enumeration_is_complete(
        &self,
        procedure: &ProcedureHandle,
        result_origins: &[ProgramPointId],
        relevant_values: &[ValueId],
    ) -> bool {
        if !self.result_observation_account_is_available(procedure)
            || result_origins.is_empty()
            || result_origins
                .iter()
                .any(|point| procedure.semantics().point(*point).is_none())
        {
            return false;
        }

        let semantics = procedure.semantics();
        if self.dominance.is_none() {
            return false;
        }
        let relevant_values = relevant_values.iter().copied().collect::<HashSet<_>>();
        let retained_read_values = self
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Read)
            .map(|event| event.value)
            .collect::<HashSet<_>>();
        !semantics.gaps().iter().any(|gap| {
            gap.impacts.contains(SemanticGapImpact::ValueFlow)
                && result_observation_gap_is_relevant(
                    semantics,
                    gap,
                    &relevant_values,
                    &retained_read_values,
                    result_origins,
                )
                && match gap.control_flow_discharge() {
                    // Every source-local successor remains represented, so
                    // this marker cannot hide another static observation.
                    SemanticGapDischarge::RetainedControlTopology => false,
                    // Every operand remains represented. Its unspecified order
                    // matters only when that order can change this binding.
                    SemanticGapDischarge::RetainedEvaluationOrder => self
                        .gap_contains_competing_binding_write(
                            semantics,
                            gap,
                            &relevant_values,
                            result_origins,
                        ),
                    // This omitted arm exits normal evaluation. Static uses on
                    // cleanup/deferred routes are represented by their own
                    // effects or by an independent cleanup/deferred gap; this
                    // marker alone cannot add another normal-body observation.
                    SemanticGapDischarge::NonRejoiningExceptionalExit => false,
                    // ExitOnlyProcedureCompletion may still read, transfer,
                    // or otherwise observe this result while the procedure
                    // unwinds. Its point being before the result is a control
                    // proof, not an observation-enumeration proof.
                    SemanticGapDischarge::ExitOnlyProcedureCompletion => true,
                    // Canonical index identity certifies only that equal
                    // literal occurrences name one index. It does not project
                    // indexed properties into flow state, so the raw gap
                    // remains blocking here.
                    SemanticGapDischarge::CanonicalIndexIdentity
                    | SemanticGapDischarge::ExactFieldLayout => true,
                    SemanticGapDischarge::ModeledEffectPartition
                    | SemanticGapDischarge::CreatingRealizationBindsCaptures
                    | SemanticGapDischarge::DataDependency => true,
                    // Runtime-read discharge belongs to the activation-aware
                    // refinement, not this raw flow-state completeness proof.
                    SemanticGapDischarge::RuntimeReadBehavior => true,
                    // A nested rebinding can change the binding at a call or
                    // suspension; an observation proof enumerates neither.
                    SemanticGapDischarge::RebindAtCallOrSuspension => true,
                    // The inert-drop proof needs analyzer access, which this
                    // raw flow-state proof does not have.
                    SemanticGapDischarge::InertDropGlue
                    | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops => true,
                    SemanticGapDischarge::ImplicitDropExecution
                    | SemanticGapDischarge::None
                    | SemanticGapDischarge::ResidualConversion
                    | SemanticGapDischarge::CallResolution => true,
                }
        })
    }

    /// Whether this derivation can support a result-scoped observation proof.
    ///
    /// This validates the artifact identity and the binding/reaching account,
    /// but deliberately does not interpret lowering gaps. A caller proving a
    /// narrower structured fact, such as whether one ephemeral call result was
    /// discarded, can classify gaps against that exact source evaluation
    /// without inheriting unrelated procedure-wide incompleteness.
    pub fn result_observation_account_is_available(&self, procedure: &ProcedureHandle) -> bool {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        self.procedure == procedure.id()
            && Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
            && !self.result_flow_has_hard_hole()
    }

    /// Whether address escape can change a tracked binding between its exact
    /// establishment and a later retained observation.
    ///
    /// A call cannot erase the receiver or argument evaluation already
    /// materialized at that same point. A typed address derived from the
    /// binding can nevertheless escape through an earlier call, memory store,
    /// capture, or asynchronous publication and let another evaluation replace
    /// the binding before a later read. Address identity comes from the semantic
    /// producer and follows only structured assignment/value flow; parentheses
    /// and other by-value wrappers are not reference escapes.
    pub fn result_identity_is_closed(
        &self,
        procedure: &ProcedureHandle,
        result_origins: &[ProgramPointId],
        relevant_values: &[ValueId],
    ) -> bool {
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
            || result_origins.is_empty()
            || result_origins
                .iter()
                .any(|point| procedure.semantics().point(*point).is_none())
            || relevant_values.is_empty()
            || self.result_flow_has_hard_hole()
        {
            return false;
        }
        result_alias_identity_is_closed(
            self,
            procedure.semantics(),
            result_origins,
            &relevant_values.iter().copied().collect::<HashSet<_>>(),
        )
    }

    fn gap_contains_competing_binding_write(
        &self,
        semantics: &ProcedureSemantics,
        gap: &SemanticGap,
        relevant_values: &HashSet<ValueId>,
        result_origins: &[ProgramPointId],
    ) -> bool {
        let Some(mapping) = semantics.source_mapping(gap.source) else {
            return true;
        };
        let span = mapping.locator.anchor().span();
        let start = span.start_byte() as usize;
        let end = span.end_byte() as usize;
        let mut origin_inside_gap = false;
        for origin in result_origins {
            let Some(origin_mapping) = semantics
                .point(*origin)
                .and_then(|point| semantics.source_mapping(point.source))
            else {
                return true;
            };
            let origin_span = origin_mapping.locator.anchor().span();
            origin_inside_gap |= origin_span.start_byte() as usize >= start
                && origin_span.end_byte() as usize <= end;
        }
        with_control_graph!(semantics, &self.control_edge_mask, |graph| {
            self.events.iter().any(|event| {
                matches!(
                    event.event_class,
                    StateEventClass::Establish | StateEventClass::Kill
                ) && relevant_values.contains(&event.subject.value())
                    && !result_origins.contains(&event.point)
                    && event.site.range.start_byte >= start
                    && event.site.range.end_byte <= end
                    // Retained order is arbitrary inside this exact gap span.
                    // Outside it, only a write that can occur after a current
                    // result origin can replace that result's binding value.
                    && (origin_inside_gap
                        || result_origins.iter().any(|origin| {
                            point_reaches(graph, *origin, event.point, false)
                        }))
            })
        })
    }

    /// Whether retained flow proves that no evaluation between `origin` and
    /// `observation` can replace one of the tracked binding cells.
    ///
    /// Exact address provenance handles indirect mutation and escape. Direct
    /// establishments and kills are checked separately because they do not
    /// need an address. A retained-evaluation-order gap is safe only when its
    /// entire source span contains no competing write: the adapter retained
    /// every operand, but their chosen CFG order is not language-authored.
    fn binding_state_is_closed_between<G>(
        &self,
        semantics: &ProcedureSemantics,
        graph: &G,
        origin: ProgramPointId,
        observation: ProgramPointId,
        relevant_values: &HashSet<ValueId>,
    ) -> bool
    where
        G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
    {
        if relevant_values.is_empty()
            || relevant_values.iter().any(|binding| {
                !binding_identity_is_closed_between(semantics, graph, origin, observation, *binding)
            })
            || semantics.gaps().iter().any(|gap| {
                gap.capability == SemanticCapability::Captures
                    && capture_gap_may_involve_bindings(semantics, gap, relevant_values)
                    // A closure created before the validator can retain a
                    // captured cell and mutate it later. A closure created in
                    // the remaining operand window can execute before the
                    // target invocation. Stay open when the producer cannot
                    // name the captured binding; do not infer an alias from
                    // source spelling.
                    && (point_reaches(graph, gap.point, origin, true)
                        || (point_reaches(graph, origin, gap.point, true)
                            && point_reaches(graph, gap.point, observation, true)))
            })
            || self.events.iter().any(|event| {
                matches!(
                    event.event_class,
                    StateEventClass::Establish | StateEventClass::Kill
                ) && relevant_values.contains(&event.subject.value())
                    && (event.point == origin || point_reaches(graph, origin, event.point, false))
                    && (event.point == observation
                        || point_reaches(graph, event.point, observation, false))
            })
        {
            return false;
        }

        !semantics.gaps().iter().any(|gap| {
            gap.control_flow_discharge() == SemanticGapDischarge::RetainedEvaluationOrder
                && self.gap_contains_competing_binding_write(
                    semantics,
                    gap,
                    relevant_values,
                    &[origin],
                )
        })
    }

    fn result_flow_has_hard_hole(&self) -> bool {
        self.completeness.reasons().iter().any(|reason| {
            [
                FlowStateAxis::BindingEvents,
                FlowStateAxis::ReachingRelation,
            ]
            .into_iter()
            .any(|axis| reason.blocks(axis))
                && !matches!(
                    reason,
                    FlowStateIncompleteReason::LoweringGap { .. }
                        | FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                        | FlowStateIncompleteReason::PropertyBaseNotCanonical { .. }
                        | FlowStateIncompleteReason::PropertyProviderUnavailable
                        | FlowStateIncompleteReason::PropertyProviderFailed { .. }
                        | FlowStateIncompleteReason::PropertyAnalysisPartial { .. }
                        | FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { .. }
                        | FlowStateIncompleteReason::PropertyReaching { .. }
                )
        })
    }
}

fn result_observation_gap_is_relevant(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    relevant_values: &HashSet<ValueId>,
    retained_read_values: &HashSet<ValueId>,
    result_origins: &[ProgramPointId],
) -> bool {
    if gap.control_flow_discharge() == SemanticGapDischarge::ExitOnlyProcedureCompletion {
        // Completion may run arbitrary active cleanup/deferred code and can
        // therefore observe captured result values unrelated to the local
        // operation that triggered the exit. Its point/value subject scopes
        // the omitted exceptional transfer, not all values that completion
        // code can read.
        return true;
    }
    match gap.subject {
        SemanticGapSubject::FutureConstruction
        | SemanticGapSubject::FutureActivation
        | SemanticGapSubject::Procedure => {
            // A procedure-wide capture gap accounts for values entering this
            // child from its lexical parent. It cannot hide another static
            // observation of a result established after the child entry. An
            // entry-origin result may itself be a captured value, so retain
            // the gap for that cross-procedure account.
            gap.capability != SemanticCapability::Captures
                || result_origins.contains(&semantics.entry_point())
        }
        SemanticGapSubject::Point => true,
        SemanticGapSubject::Value(value) => relevant_values.contains(&value),
        SemanticGapSubject::CleanupOwners(segment) => relevant_values
            .iter()
            .any(|value| semantics.cleanup_chains().contains_owner(segment, *value)),
        SemanticGapSubject::MemoryLocation(location) => semantics
            .memory_location(location)
            .is_some_and(|memory| match memory.kind {
                MemoryLocationKind::Field { base, .. }
                | MemoryLocationKind::Property { base, .. }
                | MemoryLocationKind::Dereference { address: base } => {
                    relevant_values.contains(&base)
                        && !(retained_read_values.contains(&base)
                            && gap_point_retains_memory_access(semantics, gap, location))
                }
                MemoryLocationKind::Index { base, .. } => relevant_values.contains(&base),
                MemoryLocationKind::LexicalCell { binding } => relevant_values.contains(&binding),
                MemoryLocationKind::Static { .. } | MemoryLocationKind::Capture { .. } => false,
            }),
        SemanticGapSubject::Capture(capture) => {
            semantics
                .capture(capture)
                .is_some_and(|capture| match capture.captured {
                    crate::analyzer::semantic::CaptureSource::Value(value) => {
                        relevant_values.contains(&value)
                    }
                    crate::analyzer::semantic::CaptureSource::Location(location) => semantics
                        .memory_location(location)
                        .is_some_and(|location| match location.kind {
                            MemoryLocationKind::Field { base, .. }
                            | MemoryLocationKind::Property { base, .. }
                            | MemoryLocationKind::Dereference { address: base }
                            | MemoryLocationKind::Index { base, .. } => {
                                relevant_values.contains(&base)
                            }
                            MemoryLocationKind::LexicalCell { binding } => {
                                relevant_values.contains(&binding)
                            }
                            MemoryLocationKind::Static { .. }
                            | MemoryLocationKind::Capture { .. } => false,
                        }),
                })
        }
        // These gaps refine an already represented call's target, result, or
        // continuation. They cannot erase its already materialized receiver or
        // arguments, and therefore cannot hide another static result read.
        // Closure invocation enumeration remains separate and accepts only an
        // exact callable identity; unresolved routing stays open there.
        SemanticGapSubject::CallSite(_)
        | SemanticGapSubject::CallContinuation { .. }
        | SemanticGapSubject::AsyncContinuation { .. } => false,
    }
}

/// Whether the gap's exact point still represents the access whose location
/// identity is incomplete.
///
/// Together with a retained read of the base value, a retained field access
/// represents that static base observation. The location-scoped gap remains
/// relevant to property and alias consumers, but cannot hide another
/// observation of that base. Index locations and binding cells deliberately
/// do not use this exemption: neither has a projected property event that can
/// close the corresponding observation account.
fn gap_point_retains_memory_access(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    location: MemoryLocationId,
) -> bool {
    semantics.point(gap.point).is_some_and(|point| {
        point.events.iter().any(|event| {
            matches!(
                &event.effect,
                SemanticEffect::MemoryLoad {
                    location: accessed,
                    ..
                } | SemanticEffect::MemoryStore {
                    location: accessed,
                    ..
                } if *accessed == location
            )
        })
    })
}

fn result_alias_identity_is_closed(
    derivation: &FlowStateDerivation,
    semantics: &ProcedureSemantics,
    result_origins: &[ProgramPointId],
    relevant_values: &HashSet<ValueId>,
) -> bool {
    let address_aliases = address_alias_values(semantics, relevant_values);
    let binding_origins = BindingOriginIndex::from_semantics(semantics);
    if address_aliases.is_empty() {
        return true;
    }
    let observations = derivation
        .events
        .iter()
        .filter(|event| {
            event.event_class == StateEventClass::Read && relevant_values.contains(&event.value)
        })
        .map(|event| event.point)
        .collect::<HashSet<_>>();
    if observations.is_empty() {
        return true;
    }

    if indirect_address_write_points(
        semantics,
        &address_aliases,
        relevant_values,
        &binding_origins,
    )
    .into_iter()
    .any(|write| {
        result_origins.iter().any(|origin| {
            derivation.point_reaches(semantics, *origin, write, true)
                && observations.iter().any(|observation| {
                    derivation.point_reaches(semantics, write, *observation, false)
                })
        })
    }) {
        return false;
    }

    !address_escape_points(semantics, &address_aliases, &[])
        .into_iter()
        .any(|escape| {
            result_origins.iter().any(|origin| {
                observations.iter().any(|observation| {
                    (derivation.point_reaches(semantics, *origin, escape, true)
                        && derivation.point_reaches(semantics, escape, *observation, false))
                        || (derivation.point_reaches(semantics, escape, *origin, false)
                            && derivation.point_reaches(semantics, *origin, *observation, false))
                })
            })
        })
}

fn capture_gap_may_involve_bindings(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    relevant_values: &HashSet<ValueId>,
) -> bool {
    let value_may_involve_bindings = |value| {
        relevant_values.contains(&value)
            || semantics
                .value(value)
                .is_none_or(|value| value.kind == SemanticValueKind::Callable)
    };
    let location_may_involve_bindings = |location| {
        semantics
            .memory_location(location)
            .is_none_or(|location| match location.kind {
                MemoryLocationKind::Field { base, .. }
                | MemoryLocationKind::Property { base, .. }
                | MemoryLocationKind::Dereference { address: base }
                | MemoryLocationKind::Index { base, .. } => relevant_values.contains(&base),
                MemoryLocationKind::LexicalCell { binding } => relevant_values.contains(&binding),
                // A child capture slot does not identify its parent value.
                // Static storage has no binding value to confuse with one.
                MemoryLocationKind::Capture { .. } => true,
                MemoryLocationKind::Static { .. } => false,
            })
    };
    match gap.subject {
        SemanticGapSubject::Value(value) => value_may_involve_bindings(value),
        SemanticGapSubject::CleanupOwners(segment) => semantics
            .cleanup_chains()
            .owners(segment)
            .any(|owner| value_may_involve_bindings(owner.value)),
        SemanticGapSubject::MemoryLocation(location) => location_may_involve_bindings(location),
        SemanticGapSubject::Capture(capture) => {
            semantics
                .capture(capture)
                .is_none_or(|capture| match capture.captured {
                    crate::analyzer::semantic::CaptureSource::Value(value) => {
                        value_may_involve_bindings(value)
                    }
                    crate::analyzer::semantic::CaptureSource::Location(location) => {
                        location_may_involve_bindings(location)
                    }
                })
        }
        SemanticGapSubject::FutureConstruction
        | SemanticGapSubject::FutureActivation
        | SemanticGapSubject::Procedure
        | SemanticGapSubject::Point
        | SemanticGapSubject::CallSite(_)
        | SemanticGapSubject::CallContinuation { .. }
        | SemanticGapSubject::AsyncContinuation { .. } => true,
    }
}

fn binding_identity_is_closed_between<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    origin: ProgramPointId,
    observation: ProgramPointId,
    binding: ValueId,
) -> bool
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let relevant = std::iter::once(binding).collect::<HashSet<_>>();
    let address_aliases = address_alias_values(semantics, &relevant);
    let binding_origins = BindingOriginIndex::from_semantics(semantics);
    if indirect_address_write_points(semantics, &address_aliases, &relevant, &binding_origins)
        .into_iter()
        .any(|write| {
            point_reaches(graph, origin, write, true)
                && point_reaches(graph, write, observation, false)
        })
    {
        return false;
    }
    if address_escape_points(semantics, &address_aliases, &[])
        .into_iter()
        .any(|escape| {
            (point_reaches(graph, origin, escape, true)
                && point_reaches(graph, escape, observation, false))
                || (point_reaches(graph, escape, origin, false)
                    && point_reaches(graph, origin, observation, false))
        })
    {
        return false;
    }
    !semantics.gaps().iter().any(|gap| {
        gap.impacts.contains(SemanticGapImpact::ValueFlow)
            && gap
                .subject
                .contains_value(semantics.cleanup_chains(), binding)
            && point_reaches(graph, origin, gap.point, true)
            && point_reaches(graph, gap.point, observation, true)
    })
}

fn indirect_address_write_points(
    semantics: &ProcedureSemantics,
    address_aliases: &HashSet<ValueId>,
    relevant_values: &HashSet<ValueId>,
    binding_origins: &BindingOriginIndex,
) -> Vec<ProgramPointId> {
    let mut writes = semantics
        .gaps()
        .iter()
        .filter_map(|gap| {
            (gap.capability == SemanticCapability::Assignments
                && gap.impacts.contains(SemanticGapImpact::HeapWrite))
            .then_some(gap.subject)
            .and_then(|subject| match subject {
                SemanticGapSubject::Value(value) if address_aliases.contains(&value) => {
                    Some(gap.point)
                }
                _ => None,
            })
        })
        .collect::<Vec<_>>();
    for point in semantics.points() {
        for event in &point.events {
            let address = match event.effect {
                SemanticEffect::MemoryStore { location, .. } => semantics
                    .memory_location(location)
                    .and_then(|location| match location.kind {
                        MemoryLocationKind::Dereference { address } => Some(address),
                        _ => None,
                    }),
                _ => None,
            };
            let Some(address) = address else { continue };
            if !address_aliases.contains(&address) {
                continue;
            }
            let origins = binding_origins.addressed_binding_origins(address);
            if origins.unique_binding().is_some() {
                continue;
            }
            let may_bindings = if origins.is_complete() {
                origins.bindings()
            } else {
                binding_origins.address_taken_binding_set()
            };
            if may_bindings
                .iter()
                .any(|binding| relevant_values.contains(binding))
            {
                writes.push(point.id);
            }
        }
    }
    writes.sort_unstable();
    writes.dedup();
    writes
}

pub(crate) fn address_escape_points(
    semantics: &ProcedureSemantics,
    address_aliases: &HashSet<ValueId>,
    modeled_address_calls: &[CallSiteId],
) -> HashSet<ProgramPointId> {
    let mut escape_points = semantics
        .call_sites()
        .iter()
        .filter(|call| !modeled_address_calls.contains(&call.id))
        .filter(|call| {
            address_aliases.contains(&call.callee)
                || call
                    .receiver
                    .is_some_and(|receiver| address_aliases.contains(&receiver))
                || call
                    .arguments
                    .iter()
                    .any(|argument| address_aliases.contains(&argument.value))
        })
        .map(|call| call.point)
        .collect::<HashSet<_>>();
    escape_points.extend(semantics.captures().iter().filter_map(|capture| {
        match capture.captured {
            crate::analyzer::semantic::CaptureSource::Value(value) => {
                address_aliases.contains(&value).then_some(capture.point)
            }
            crate::analyzer::semantic::CaptureSource::Location(location) => semantics
                .memory_location(location)
                .and_then(|location| match location.kind {
                    MemoryLocationKind::LexicalCell { binding }
                        if address_aliases.contains(&binding) =>
                    {
                        Some(capture.point)
                    }
                    MemoryLocationKind::Field { base, .. }
                    | MemoryLocationKind::Property { base, .. }
                    | MemoryLocationKind::Dereference { address: base }
                    | MemoryLocationKind::Index { base, .. }
                        if address_aliases.contains(&base) =>
                    {
                        Some(capture.point)
                    }
                    MemoryLocationKind::Static { .. }
                    | MemoryLocationKind::Capture { .. }
                    | MemoryLocationKind::LexicalCell { .. }
                    | MemoryLocationKind::Field { .. }
                    | MemoryLocationKind::Property { .. }
                    | MemoryLocationKind::Dereference { .. }
                    | MemoryLocationKind::Index { .. } => None,
                }),
        }
    }));
    escape_points.extend(semantics.points().iter().flat_map(|point| {
        point.events.iter().filter_map(|event| match event.effect {
            // A retained channel payload publishes the address even when the
            // channel's control topology is known. Later reads cannot assume
            // that the receiver left the original binding unchanged.
            SemanticEffect::Synchronization {
                operation: SynchronizationOperation::ChannelSend,
                payload: Some(SynchronizationPayload::Send { value, .. }),
                ..
            } if address_aliases.contains(&value) => Some(point.id),
            // #6409: storing a borrow inside a dropped aggregate retains a
            // writer just as publishing it through a memory store does.
            SemanticEffect::AggregateInitializer { value, .. }
            | SemanticEffect::MemoryStore { value, .. }
                if address_aliases.contains(&value) =>
            {
                Some(point.id)
            }
            SemanticEffect::AsyncSuspend {
                awaited: Some(value),
                ..
            } if address_aliases.contains(&value) => Some(point.id),
            SemanticEffect::ProcedureReturn { value: Some(value) }
            | SemanticEffect::Throw { value: Some(value) }
                if address_aliases.contains(&value) =>
            {
                Some(point.id)
            }
            _ => None,
        })
    }));
    escape_points
}

pub(crate) fn address_alias_values(
    semantics: &ProcedureSemantics,
    relevant_values: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    // #6409: a place read temporary can sit between a binding and its
    // Address. Recover the nearest binding with the shared structured origin
    // index; stopping at locals avoids treating &copy as an address of the
    // local from which copy was initialized. After Address creation only
    // identity-preserving flow transports the escaping reference.
    let origins = BindingOriginIndex::from_semantics(semantics);
    let seeds = semantics
        .values()
        .iter()
        .filter(|value| value.kind == SemanticValueKind::Address)
        .filter(|value| {
            origins
                .addressed_binding_origins(value.id)
                .bindings()
                .iter()
                .any(|binding| relevant_values.contains(binding))
        })
        .map(|value| value.id)
        .collect::<HashSet<_>>();
    crate::value_flow::identity_alias_closure(semantics, &seeds)
}

/// Values that retain `source` identity through plain semantic assignments.
///
/// Only temporaries can be transparent intermediates. A local is a closure
/// endpoint discovered from its state establishment, while an address,
/// return, callable, language-defined value, or other semantic role is a
/// distinct boundary. In particular, this walk never follows `ValueFlow`:
/// that relation includes calls and language-defined transformations whose
/// result need not retain source identity.
fn transparent_assignment_values(
    assignments: &HashMap<ValueId, Vec<ValueId>>,
    source: ValueId,
    value_count: usize,
) -> HashSet<ValueId> {
    let mut values = std::iter::once(source).collect::<HashSet<_>>();
    let mut stack = vec![source];
    while let Some(current) = stack.pop() {
        for target in assignments.get(&current).into_iter().flatten() {
            if values.insert(*target) {
                debug_assert!(values.len() <= value_count);
                stack.push(*target);
            }
        }
    }
    values
}

fn point_reaches<G>(
    graph: &G,
    origin: ProgramPointId,
    target: ProgramPointId,
    include_origin: bool,
) -> bool
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    if include_origin && origin == target {
        return true;
    }
    let mut visited = HashSet::default();
    let mut stack = graph
        .successors(origin)
        .map(|(_, target)| target)
        .collect::<Vec<_>>();
    while let Some(point) = stack.pop() {
        if !visited.insert(point) {
            continue;
        }
        if point == target {
            return true;
        }
        stack.extend(graph.successors(point).map(|(_, target)| target));
    }
    false
}

#[derive(Debug, Clone, Copy)]
struct ValidatedGuardEdge {
    id: ControlEdgeId,
    target: ProgramPointId,
}

fn validated_guard_edges(
    procedure: &ProcedureHandle,
    candidates: &[ControlEdgeHandle],
) -> Option<Vec<ValidatedGuardEdge>> {
    let semantics = procedure.semantics();
    let mut candidate_edges = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.procedure() != procedure {
            return None;
        }
        let edge = semantics.control_edge(candidate.id())?;
        if !matches!(
            edge.kind,
            ControlEdgeKind::ConditionalTrue | ControlEdgeKind::ConditionalFalse
        ) || !semantics.guard_facts().iter().any(|guard| {
            guard.true_edge == Some(candidate.id()) || guard.false_edge == Some(candidate.id())
        }) {
            return None;
        }
        candidate_edges.push(ValidatedGuardEdge {
            id: candidate.id(),
            target: edge.target_point,
        });
    }
    Some(candidate_edges)
}

fn normal_return_candidate_points(
    procedure: &ProcedureHandle,
    candidates: &[CallSiteHandle],
) -> Option<Vec<ProgramPointId>> {
    let semantics = procedure.semantics();
    let mut candidate_points = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if candidate.procedure() != procedure {
            return None;
        }
        candidate_points.push(
            semantics
                .call_site(candidate.id())?
                .normal_continuation
                .target()?,
        );
    }
    Some(candidate_points)
}

fn target_call_evaluation_is_open(
    semantics: &ProcedureSemantics,
    target: &SemanticCallSite,
) -> bool {
    target_call_has_call_evaluation_gap(semantics, target)
        || semantics.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::CallSite(target.id)
                && gap.capability == SemanticCapability::DeferredExecution
                && gap.control_flow_discharge() == SemanticGapDischarge::CallResolution
        })
}

fn target_call_has_call_evaluation_gap(
    semantics: &ProcedureSemantics,
    target: &SemanticCallSite,
) -> bool {
    semantics.gaps().iter().any(|gap| match gap.subject {
        SemanticGapSubject::CallSite(call) if call == target.id => {
            gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        }
        SemanticGapSubject::Point if gap.point == target.point => {
            gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        }
        SemanticGapSubject::FutureConstruction
        | SemanticGapSubject::FutureActivation
        | SemanticGapSubject::Procedure
        | SemanticGapSubject::Point
        | SemanticGapSubject::Value(_)
        | SemanticGapSubject::CleanupOwners(_)
        | SemanticGapSubject::MemoryLocation(_)
        | SemanticGapSubject::Capture(_)
        | SemanticGapSubject::CallSite(_)
        | SemanticGapSubject::CallContinuation { .. }
        | SemanticGapSubject::AsyncContinuation { .. } => false,
    })
}

fn result_control_gaps<'semantics, G>(
    semantics: &'semantics ProcedureSemantics,
    graph: &G,
    result_establishments: &[ProgramPointId],
    targets: &[ProgramPointId],
    discharge_blocks: impl Fn(SemanticGapDischarge) -> bool,
) -> Vec<&'semantics SemanticGap>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    // Both markers certify work that cannot resume the normal body. Retained
    // point placement is nevertheless a valid result-scoped discharge only
    // before every exact origin and outside a cycle. Exit-only work can still
    // enter cleanup or handler regions, so its pre-origin discharge also
    // requires every queried target to be an ordinary-body point. The marker
    // remains standing everywhere else until an ordinary target-specific
    // proof establishes that its retained point cannot reach the reviewed use.
    let eligible_gap_points = semantics
        .gaps()
        .iter()
        .filter(|gap| {
            gap.subject != SemanticGapSubject::Procedure
                && matches!(
                    gap.control_flow_discharge(),
                    SemanticGapDischarge::NonRejoiningExceptionalExit
                        | SemanticGapDischarge::ExitOnlyProcedureCompletion
                )
                && discharge_blocks(gap.control_flow_discharge())
        })
        .map(|gap| gap.point)
        .collect::<Vec<_>>();
    let establishment_points = result_establishments
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let strictly_preceding_establishments =
        strictly_later_point_pairs(graph, &eligible_gap_points, &establishment_points);
    let ordinary_body_points = ordinary_body_points(semantics, graph);
    let all_targets_are_ordinary = !targets.is_empty()
        && targets
            .iter()
            .all(|target| ordinary_body_points.contains(target));
    semantics
        .gaps()
        .iter()
        .filter(|gap| {
            scoped_axes_blocked_by(semantics, gap).contains(&FlowStateAxis::DominanceRelation)
                && discharge_blocks(gap.control_flow_discharge())
                && !(gap.subject != SemanticGapSubject::Procedure
                    && matches!(
                        gap.control_flow_discharge(),
                        SemanticGapDischarge::NonRejoiningExceptionalExit
                            | SemanticGapDischarge::ExitOnlyProcedureCompletion
                    )
                    && (gap.control_flow_discharge()
                        == SemanticGapDischarge::NonRejoiningExceptionalExit
                        || all_targets_are_ordinary)
                    && result_establishments.iter().all(|establishment| {
                        gap.point != *establishment
                            && strictly_preceding_establishments
                                .contains(&(gap.point, *establishment))
                    }))
        })
        .collect()
}

fn candidate_points_dominate_targets<G>(
    graph: &G,
    dominance: &Dominators<ProgramPointId>,
    candidates: &[ProgramPointId],
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> Option<Box<[bool]>>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut answers = Vec::with_capacity(targets.len());
    // Gap placement depends on the candidate, not the target. Cache it
    // across the batch instead of walking the same dominator chains once
    // per sensitive use.
    let mut candidate_gap_safety = vec![None; candidates.len()];
    for target in targets {
        let mut has_retained_dominator = false;
        let mut proven = false;
        for (index, candidate) in candidates.iter().copied().enumerate() {
            if !dominance.dominates(graph, candidate, *target) {
                continue;
            }
            has_retained_dominator = true;
            let gap_safe = *candidate_gap_safety[index].get_or_insert_with(|| {
                control_gaps.iter().all(|gap| {
                    gap.subject != SemanticGapSubject::Procedure
                        && (dominance.dominates(graph, candidate, gap.point)
                            || (gap_has_unobserved_exceptional_exit(gap)
                                && point_reaches(graph, gap.point, candidate, false)
                                && !point_reaches(graph, candidate, gap.point, false)))
                })
            });
            if gap_safe {
                proven = true;
                break;
            }
        }
        if !has_retained_dominator {
            // Adding omitted paths can destroy a dominance relation, but
            // cannot manufacture one absent from the retained CFG.
            answers.push(false);
            continue;
        }
        if !proven {
            return None;
        }
        answers.push(true);
    }
    Some(answers.into_boxed_slice())
}

fn guard_edges_dominate_targets<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    dominance: &Dominators<ProgramPointId>,
    candidates: &[ValidatedGuardEdge],
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> Box<[GuardDominanceAnswer]>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let target_local_completions =
        non_rejoining_gaps_that_cannot_reach_targets(graph, targets, control_gaps);
    guard_edges_dominate_targets_with_local_completions(
        semantics,
        graph,
        dominance,
        candidates,
        targets,
        control_gaps,
        &target_local_completions,
    )
}

fn guard_edges_dominate_result_targets<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    dominance: &Dominators<ProgramPointId>,
    candidates: &[ValidatedGuardEdge],
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> Box<[GuardDominanceAnswer]>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let target_local_completions =
        result_completion_gaps_that_cannot_reach_targets(semantics, graph, targets, control_gaps);
    guard_edges_dominate_targets_with_local_completions(
        semantics,
        graph,
        dominance,
        candidates,
        targets,
        control_gaps,
        &target_local_completions,
    )
}

#[allow(clippy::too_many_arguments)]
fn guard_edges_dominate_targets_with_local_completions<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    dominance: &Dominators<ProgramPointId>,
    candidates: &[ValidatedGuardEdge],
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
    target_local_completions: &HashSet<(ProgramPointId, SemanticGapId)>,
) -> Box<[GuardDominanceAnswer]>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    // Reachability is computed once per exact candidate edge and reused for
    // every target and point-scoped gap in the batch. An explicit stack keeps
    // the traversal safe for arbitrarily deep retained control-flow graphs.
    let reachable_without_candidate = candidates
        .iter()
        .map(|candidate| {
            reachable_points_without_edge(graph, semantics.entry_point(), candidate.id)
        })
        .collect::<Vec<_>>();
    let mut answers = Vec::with_capacity(targets.len());
    for target in targets {
        let mut has_retained_edge_dominator = false;
        let mut proven = false;
        for (index, candidate) in candidates.iter().copied().enumerate() {
            if !dominance.dominates(graph, candidate.target, *target)
                || reachable_without_candidate[index].contains(target)
            {
                continue;
            }
            has_retained_edge_dominator = true;
            let gap_safe = control_gaps.iter().all(|gap| {
                if gap.subject == SemanticGapSubject::Procedure {
                    return false;
                }
                let candidate_precedes_gap =
                    dominance.dominates(graph, candidate.target, gap.point)
                        && !reachable_without_candidate[index].contains(&gap.point);
                // The caller supplies only producer-authored completion gaps
                // whose omitted work cannot resume this procedure's normal
                // evaluation. The caller has additionally restricted an
                // exit-only completion to targets certified reachable through
                // ordinary-body edges: cleanup or handler targets may still be
                // entered by that omitted work. At an eligible target, if the
                // retained gap point cannot reach it, whether because the gap
                // is strictly later or confined to a sibling arm, the omitted
                // completion cannot manufacture a new entry-to-target path
                // that bypasses the guard edge. Predecessor and cyclic gaps
                // remain blocking because their retained points can still
                // reach this target.
                candidate_precedes_gap || target_local_completions.contains(&(*target, gap.id))
            });
            if gap_safe {
                proven = true;
                break;
            }
        }
        if !has_retained_edge_dominator {
            // The retained graph already contains a path that bypasses every
            // exact edge. Adding omitted paths cannot make one unavoidable.
            answers.push(GuardDominanceAnswer::ClosedNegative);
            continue;
        }
        answers.push(if proven {
            GuardDominanceAnswer::Proven
        } else {
            GuardDominanceAnswer::Open
        });
    }
    answers.into_boxed_slice()
}

fn guard_edges_confine_candidate_for_targets<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    dominance: &Dominators<ProgramPointId>,
    candidates: &[ValidatedGuardEdge],
    candidate_point: ProgramPointId,
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> Box<[bool]>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    // Edge-exclusion reachability is shared by every protected use. The
    // retained arm must first confine the candidate itself; target locality
    // only decides whether an otherwise blocking gap begins too late to
    // change the candidate's relevance to one already-reached use.
    let reachable_without_candidate = candidates
        .iter()
        .map(|candidate| {
            reachable_points_without_edge(graph, semantics.entry_point(), candidate.id)
        })
        .collect::<Vec<_>>();
    let strictly_later_non_rejoining_gaps = strictly_later_non_rejoining_gap_pairs(
        graph,
        std::slice::from_ref(&candidate_point),
        control_gaps,
    );
    let strictly_later_target_gaps = strictly_later_gap_pairs(graph, targets, control_gaps);
    let retained_candidates = candidates
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, candidate)| {
            dominance.dominates(graph, candidate.target, candidate_point)
                && !reachable_without_candidate[*index].contains(&candidate_point)
        })
        .collect::<Vec<_>>();

    targets
        .iter()
        .map(|target| {
            retained_candidates.iter().any(|(index, candidate)| {
                control_gaps.iter().all(|gap| {
                    if gap.subject == SemanticGapSubject::Procedure {
                        return false;
                    }
                    let candidate_precedes_gap =
                        dominance.dominates(graph, candidate.target, gap.point)
                            && !reachable_without_candidate[*index].contains(&gap.point);
                    let non_rejoining_strictly_after_candidate = gap.control_flow_discharge()
                        == SemanticGapDischarge::NonRejoiningExceptionalExit
                        && strictly_later_non_rejoining_gaps
                            .contains(&(candidate_point, gap.point));
                    // Dominance alone is insufficient inside a loop: the gap
                    // may still reach the same static use on a later
                    // iteration. Require strict acyclic order as well, so
                    // omitted behavior begins after every occurrence covered
                    // by this target-relative answer.
                    let target_strictly_precedes_gap = dominance
                        .dominates(graph, *target, gap.point)
                        && strictly_later_target_gaps.contains(&(*target, gap.point));
                    candidate_precedes_gap
                        || non_rejoining_strictly_after_candidate
                        || target_strictly_precedes_gap
                })
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn guard_edges_confine_targets_for_negative_evidence<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    dominance: &Dominators<ProgramPointId>,
    candidates: &[ValidatedGuardEdge],
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> Box<[bool]>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let target_local_completions =
        non_rejoining_gaps_that_cannot_reach_targets(graph, targets, control_gaps);
    guard_edges_dominate_targets_with_local_completions(
        semantics,
        graph,
        dominance,
        candidates,
        targets,
        control_gaps,
        &target_local_completions,
    )
    .iter()
    .map(|answer| *answer == GuardDominanceAnswer::Proven)
    .collect::<Vec<_>>()
    .into_boxed_slice()
}

fn strictly_later_non_rejoining_gap_pairs<G>(
    graph: &G,
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> HashSet<(ProgramPointId, ProgramPointId)>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let gap_points = control_gaps
        .iter()
        .filter(|gap| {
            gap.subject != SemanticGapSubject::Procedure
                && gap.control_flow_discharge() == SemanticGapDischarge::NonRejoiningExceptionalExit
        })
        .map(|gap| gap.point)
        .collect::<HashSet<_>>();
    strictly_later_point_pairs(graph, targets, &gap_points)
}

fn strictly_later_gap_pairs<G>(
    graph: &G,
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> HashSet<(ProgramPointId, ProgramPointId)>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let gap_points = control_gaps
        .iter()
        .filter(|gap| gap.subject != SemanticGapSubject::Procedure)
        .map(|gap| gap.point)
        .collect::<HashSet<_>>();
    strictly_later_point_pairs(graph, targets, &gap_points)
}

fn non_rejoining_gaps_that_cannot_reach_targets<G>(
    graph: &G,
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> HashSet<(ProgramPointId, SemanticGapId)>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let gaps = control_gaps
        .iter()
        .copied()
        .filter(|gap| {
            gap.subject != SemanticGapSubject::Procedure
                && gap.control_flow_discharge() == SemanticGapDischarge::NonRejoiningExceptionalExit
        })
        .collect::<Vec<_>>();
    gaps_that_cannot_reach_targets(graph, targets, &gaps)
}

fn result_completion_gaps_that_cannot_reach_targets<G>(
    semantics: &ProcedureSemantics,
    graph: &G,
    targets: &[ProgramPointId],
    control_gaps: &[&SemanticGap],
) -> HashSet<(ProgramPointId, SemanticGapId)>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let gaps = control_gaps
        .iter()
        .copied()
        .filter(|gap| {
            gap.subject != SemanticGapSubject::Procedure
                && matches!(
                    gap.control_flow_discharge(),
                    SemanticGapDischarge::NonRejoiningExceptionalExit
                        | SemanticGapDischarge::ExitOnlyProcedureCompletion
                )
        })
        .collect::<Vec<_>>();
    let exit_only_gaps = gaps
        .iter()
        .filter(|gap| {
            gap.control_flow_discharge() == SemanticGapDischarge::ExitOnlyProcedureCompletion
        })
        .map(|gap| gap.id)
        .collect::<HashSet<_>>();
    let ordinary_body_points = ordinary_body_points(semantics, graph);
    let mut pairs = gaps_that_cannot_reach_targets(graph, targets, &gaps);
    pairs.retain(|(target, gap)| {
        !exit_only_gaps.contains(gap) || ordinary_body_points.contains(target)
    });
    pairs
}

fn ordinary_body_points<G>(semantics: &ProcedureSemantics, graph: &G) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut points = HashSet::default();
    let mut stack = vec![semantics.entry_point()];
    while let Some(point) = stack.pop() {
        if !points.insert(point) {
            continue;
        }
        stack.extend(graph.successors(point).filter_map(|(edge_id, target)| {
            let edge = semantics
                .control_edge(edge_id)
                .expect("a retained graph edge resolves in its procedure");
            matches!(
                edge.kind,
                ControlEdgeKind::Normal
                    | ControlEdgeKind::ConditionalTrue
                    | ControlEdgeKind::ConditionalFalse
                    | ControlEdgeKind::SwitchCase
                    | ControlEdgeKind::LoopBack
            )
            .then_some(target)
        }));
    }

    // A point with both an ordinary predecessor and an unwind predecessor is
    // still completion-observable. Exclude the complete retained region
    // reachable from any exceptional, cleanup, or asynchronous edge target;
    // this prevents a shared completion point from being certified merely
    // because one normal route also enters it.
    let mut completion_reachable = HashSet::default();
    let mut completion_stack = semantics
        .control_edges()
        .iter()
        .enumerate()
        .filter_map(|(index, edge)| {
            let edge_id = ControlEdgeId::try_from_index(index)
                .expect("a validated procedure's edge index fits its dense ID");
            (graph.edge_endpoints(edge_id).is_some()
                && matches!(
                    edge.kind,
                    ControlEdgeKind::Exceptional
                        | ControlEdgeKind::Cleanup
                        | ControlEdgeKind::AsyncNormal
                        | ControlEdgeKind::AsyncExceptional
                ))
            .then_some(edge.target_point)
        })
        .collect::<Vec<_>>();
    while let Some(point) = completion_stack.pop() {
        if !completion_reachable.insert(point) {
            continue;
        }
        completion_stack.extend(graph.successors(point).map(|(_, target)| target));
    }
    points.retain(|point| !completion_reachable.contains(point));
    points.remove(&semantics.normal_exit_point());
    points.remove(&semantics.exceptional_exit_point());
    points
}

fn gaps_that_cannot_reach_targets<G>(
    graph: &G,
    targets: &[ProgramPointId],
    gaps: &[&SemanticGap],
) -> HashSet<(ProgramPointId, SemanticGapId)>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    // Reachability is independent of the candidate guard edge. Batch it before
    // the candidate x target x gap proof loop so that loop performs only set
    // lookups. Traversing from the smaller distinct endpoint set bounds this
    // account by O(min(targets, distinct gap points) * (points + edges)). The
    // result preserves each gap ID: a producer-authored completion marker
    // must never discharge a different, co-located raw gap.
    let target_points = targets.iter().copied().collect::<HashSet<_>>();
    let gap_points = gaps.iter().map(|gap| gap.point).collect::<HashSet<_>>();
    let mut pairs = HashSet::default();

    if target_points.len() <= gap_points.len() {
        for target in target_points {
            let points_reaching_target = points_reaching(graph, target);
            for gap in gaps {
                if !points_reaching_target.contains(&gap.point) {
                    pairs.insert((target, gap.id));
                }
            }
        }
    } else {
        for gap_point in gap_points {
            let reachable_from_gap = reachable_points_from(graph, gap_point);
            for target in &target_points {
                if !reachable_from_gap.contains(target) {
                    pairs.extend(
                        gaps.iter()
                            .filter(|gap| gap.point == gap_point)
                            .map(|gap| (*target, gap.id)),
                    );
                }
            }
        }
    }
    pairs
}

fn strictly_later_point_pairs<G>(
    graph: &G,
    targets: &[ProgramPointId],
    gap_points: &HashSet<ProgramPointId>,
) -> HashSet<(ProgramPointId, ProgramPointId)>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let target_points = targets.iter().copied().collect::<HashSet<_>>();
    let mut pairs = HashSet::default();

    if target_points.len() <= gap_points.len() {
        for target in target_points {
            let reachable_from_target = reachable_points_from(graph, target);
            let points_reaching_target = points_reaching(graph, target);
            for gap in gap_points {
                if reachable_from_target.contains(gap) && !points_reaching_target.contains(gap) {
                    pairs.insert((target, *gap));
                }
            }
        }
    } else {
        for gap in gap_points {
            let reachable_from_gap = reachable_points_from(graph, *gap);
            let points_reaching_gap = points_reaching(graph, *gap);
            for target in &target_points {
                if points_reaching_gap.contains(target) && !reachable_from_gap.contains(target) {
                    pairs.insert((*target, *gap));
                }
            }
        }
    }
    pairs
}

fn reachable_points_from<G>(graph: &G, origin: ProgramPointId) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    reachable_points_by(graph, origin, |point| {
        graph.successors(point).map(|(_, target)| target)
    })
}

fn points_reaching<G>(graph: &G, target: ProgramPointId) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    reachable_points_by(graph, target, |point| {
        graph
            .predecessors(point)
            .map(|(_, predecessor)| predecessor)
    })
}

fn reachable_points_without_edge<G>(
    graph: &G,
    entry: ProgramPointId,
    excluded: ControlEdgeId,
) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    reachable_points_by(graph, entry, |point| {
        graph
            .successors(point)
            .filter_map(|(edge_id, target)| (edge_id != excluded).then_some(target))
    })
}

fn reachable_points_by<G, Neighbors, Points>(
    graph: &G,
    origin: ProgramPointId,
    mut neighbors: Neighbors,
) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
    Neighbors: FnMut(ProgramPointId) -> Points,
    Points: IntoIterator<Item = ProgramPointId>,
{
    let mut reachable = std::iter::once(origin).collect::<HashSet<_>>();
    let mut stack = vec![origin];
    while let Some(point) = stack.pop() {
        for target in neighbors(point) {
            if reachable.insert(target) {
                debug_assert!(reachable.len() <= graph.node_count());
                stack.push(target);
            }
        }
    }
    reachable
}

/// The requested procedures of one file, plus the file-level lowering account.
///
/// A file that fails to lower yields no procedures and an explicit incomplete
/// result, never an empty complete one. [`flow_state_for_file`] and
/// [`flow_state_for_materialized_artifact`] request every procedure;
/// [`flow_state_for_materialized_procedure`] retains one exact procedure from
/// the caller's artifact allocation.
#[derive(Debug, Clone)]
pub struct FileFlowState {
    pub procedures: Vec<FlowStateDerivation>,
    pub completeness: FlowStateCompleteness,
    pub generation: u64,
    /// Identity of the captured active-model set that shaped this derivation.
    /// `None` means the caller supplied no model snapshot; an activated empty
    /// set retains its real (non-`None`) hash.
    active_model_set_hash: Option<Box<str>>,
    /// Whether this derivation is a function of the inputs it read. Every
    /// execution stop that shaped it also marks the ambient channel until the
    /// ambient marks are removed.
    reuse: ReuseVerdict,
}

/// One exact procedure-local normal edge selected for request-local omission.
///
/// Dense procedure and edge IDs are meaningful only under the
/// [`SemanticArtifactKey`] carried by their enclosing [`FlowControlProjection`].
/// Construction sorts and deduplicates these pairs; materialization validates
/// every pair before any edge is hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FlowControlEdgeOmission {
    procedure: ProcedureId,
    edge: ControlEdgeId,
}

impl FlowControlEdgeOmission {
    const fn new(procedure: ProcedureId, edge: ControlEdgeId) -> Self {
        Self { procedure, edge }
    }
}

/// An artifact-scoped, request-local projection of reviewed absent normal
/// continuations.
///
/// The projection does not mutate the cached semantic artifact. A stale key
/// or any invalid/non-normal edge rejects the whole projection, retains every
/// source edge, and records an incomplete control proof.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowControlProjection {
    artifact: SemanticArtifactKey,
    omitted_normal_edges: Box<[FlowControlEdgeOmission]>,
}

impl FlowControlProjection {
    fn new(
        artifact: SemanticArtifactKey,
        omitted_normal_edges: impl IntoIterator<Item = FlowControlEdgeOmission>,
    ) -> Self {
        let mut omitted_normal_edges = omitted_normal_edges.into_iter().collect::<Vec<_>>();
        omitted_normal_edges.sort_unstable();
        omitted_normal_edges.dedup();
        Self {
            artifact,
            omitted_normal_edges: omitted_normal_edges.into_boxed_slice(),
        }
    }

    const fn artifact(&self) -> &SemanticArtifactKey {
        &self.artifact
    }

    fn omitted_normal_edges(&self) -> &[FlowControlEdgeOmission] {
        &self.omitted_normal_edges
    }

    fn is_empty(&self) -> bool {
        self.omitted_normal_edges.is_empty()
    }
}

impl FileFlowState {
    fn incomplete(
        reasons: Vec<FlowStateIncompleteReason>,
        generation: u64,
        active_model_set_hash: Option<Box<str>>,
        reuse: ReuseVerdict,
    ) -> Self {
        Self {
            procedures: Vec::new(),
            completeness: FlowStateCompleteness::Incomplete { reasons },
            generation,
            active_model_set_hash,
            reuse,
        }
    }

    /// The exact activated-model identity captured by this request.
    pub fn active_model_set_hash(&self) -> Option<&str> {
        self.active_model_set_hash.as_deref()
    }
}

impl CarriesReuseVerdict for FileFlowState {
    fn reuse_verdict(&self) -> ReuseVerdict {
        self.reuse
    }
}

/// An execution stop of a flow-state derivation. Every flow-state stop marks
/// the ambient channel as a non-budget dependence, including a semantic budget
/// refusal, so its verdict is `Other`.
const EXECUTION_STOP: ReuseVerdict = ReuseVerdict::ExecutionDependent(ExecutionCause::Other);

/// The verdict of a semantic outcome whose variant is execution dependent by
/// its shape: a cancellation or an exceeded budget.
fn semantic_outcome_verdict<T>(outcome: &SemanticOutcome<T>) -> ReuseVerdict {
    if matches!(
        outcome,
        SemanticOutcome::Cancelled { .. } | SemanticOutcome::ExceededBudget { .. }
    ) {
        EXECUTION_STOP
    } else {
        ReuseVerdict::Content
    }
}

/// Preserve execution stops independently of whether a partial value survived.
fn semantic_outcome_stop_reason<T>(
    outcome: &SemanticOutcome<T>,
    axis: FlowStateAxis,
) -> Option<FlowStateIncompleteReason> {
    match outcome {
        SemanticOutcome::Cancelled { .. } => Some(FlowStateIncompleteReason::Cancelled),
        SemanticOutcome::ExceededBudget { exceeded, .. } => {
            Some(FlowStateIncompleteReason::BudgetExhausted {
                axis,
                detail: exceeded.to_string(),
            })
        }
        _ => None,
    }
}

/// Borrowed controls for one derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DeadWriteProcedureKey(
    usize,
    ProcedureId,
    crate::analyzer::semantic::ProcedureInterpretation,
    u64,
);
impl RetainedBytes for DeadWriteProcedureKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeadWriteControlKey(DeadWriteProcedureKey, Vec<ControlEdgeId>, ProgramPointId);
impl RetainedBytes for DeadWriteControlKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + allocated_vec_slot_bytes(&self.1)
    }
}
type DeadWritePrefixKey = (
    DeadWriteProcedureKey,
    Vec<ControlEdgeId>,
    Vec<ProgramPointId>,
);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeadWriteBindingKey(DeadWriteProcedureKey, ValueId, Vec<ControlEdgeId>);
impl RetainedBytes for DeadWriteBindingKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + allocated_vec_slot_bytes(&self.2)
    }
}

/// Fresh private regions for one flow request, created by its analyzer owner.
#[derive(Debug)]
pub struct FlowStateRequestMemos {
    // P-class request memos: eviction or refusal only causes recomputation.
    // Each named region belongs to the analyzer owner and invalidates on Drop.
    dead_write_procedure_cache: RequestMemo<DeadWriteProcedureKey, DeadWriteProcedureIndex>,
    dead_write_reachability_cache:
        RequestMemo<DeadWriteControlKey, DeadWriteReachabilityCacheEntry>,
    dead_write_cache: RequestMemo<DeadWriteBindingKey, DeadWriteCacheEntry>,
}

impl FlowStateRequestMemos {
    pub fn new(owner: &RetentionBudget) -> Self {
        Self {
            dead_write_procedure_cache: RequestMemo::new(owner, "flow.dead_write_procedure"),
            dead_write_reachability_cache: RequestMemo::new(owner, "flow.dead_write_reachability"),
            dead_write_cache: RequestMemo::new(owner, "flow.dead_write"),
        }
    }
}

#[derive(Debug)]
pub struct FlowStateRequest<'request> {
    pub cancellation: &'request CancellationToken,
    discharged_observation_gaps: Option<(ProcedureHandle, HashSet<SemanticGapId>)>,
    memos: FlowStateRequestMemos,
    // #12910's shared prefix closure and component order. These two remain
    // request-local maps until they move into owner-budget regions too.
    dead_write_prefix_reachability_cache:
        HashMap<DeadWritePrefixKey, DeadWriteReachabilityCacheEntry>,
    dead_write_component_order_cache:
        HashMap<(DeadWriteProcedureKey, Vec<ControlEdgeId>), DeadWriteComponentOrderCacheEntry>,
    /// The CFG-algorithm budget stays crate-private: it is this crate's own
    /// work vocabulary, and an out-of-crate caller configures a derivation
    /// through [`FlowStateRequest::new`], not by naming budget dimensions.
    pub(crate) cfg_budget: CfgAlgorithmBudget,
    /// The separate optional nonreturn-proof ledger of a lent operation. `None`
    /// (every standalone request) keeps the legacy rule: each derivation clones
    /// `cfg_budget` at entry for that proof and discards its spending.
    nonreturn_cfg_budget: Option<CfgAlgorithmBudget>,
    candidate_routes: Option<(ProcedureHandle, CandidateControlRouteIndex)>,
    control_projection: Option<&'request FlowControlProjection>,
    /// Outer `None` means this raw derivation did not select semantic models.
    /// `Some(None)` deliberately freezes no publication; `Some(Some(_))`
    /// freezes the exact active/overlay pair selected by the request owner.
    active_semantic_model_snapshot: Option<Option<Arc<ActiveSemanticModelSnapshot>>>,
    nonreturn_discovery_cache: Option<&'request NonreturnDiscoveryCache>,
}

impl<'request> FlowStateRequest<'request> {
    /// Install workspace-proven observation discharges for this exact artifact.
    /// Every logical owner of a stored gap must have been discharged.
    pub fn with_discharged_observation_gaps(
        mut self,
        procedure: ProcedureHandle,
        gaps: HashSet<SemanticGapId>,
    ) -> Self {
        assert!(self.memos.dead_write_cache.is_unused());
        self.discharged_observation_gaps = Some((procedure, gaps));
        self
    }

    fn observation_reason_is_discharged(
        &self,
        procedure: &ProcedureHandle,
        reason: &FlowStateIncompleteReason,
    ) -> bool {
        let Some((owner, discharged)) = &self.discharged_observation_gaps else {
            return false;
        };
        if owner.id() != procedure.id() || !Arc::ptr_eq(owner.artifact(), procedure.artifact()) {
            return false;
        }
        let FlowStateIncompleteReason::LoweringGap { gaps, .. } = reason else {
            return false;
        };
        !gaps.is_empty() && gaps.iter().all(|gap| discharged.contains(gap))
    }

    pub fn refusal_count(&self) -> usize {
        self.cfg_budget.refusal_count()
    }

    pub fn new(cancellation: &'request CancellationToken, memos: FlowStateRequestMemos) -> Self {
        Self {
            cancellation,
            discharged_observation_gaps: None,
            memos,
            dead_write_component_order_cache: HashMap::default(),
            dead_write_prefix_reachability_cache: HashMap::default(),
            cfg_budget: CfgAlgorithmBudget::default(),
            nonreturn_cfg_budget: None,
            candidate_routes: None,
            control_projection: None,
            active_semantic_model_snapshot: None,
            nonreturn_discovery_cache: None,
        }
    }

    /// Apply one exact control projection to this derivation request.
    ///
    /// Validation happens after the request materializes its artifact. Invalid
    /// input therefore fails closed as typed incomplete flow state rather than
    /// as a constructor error that a caller could ignore.
    #[cfg(test)]
    fn with_control_projection(mut self, projection: &'request FlowControlProjection) -> Self {
        self.control_projection = Some(projection);
        self
    }

    /// Project the exact non-return claims from one already-captured atomic
    /// active/overlay publication. `None` freezes the raw source graph and
    /// performs no call discovery. Callers capture the snapshot once for their
    /// logical request so a concurrent activation cannot mix semantic-model
    /// identities inside one result.
    pub fn with_active_semantic_model_snapshot(
        mut self,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        self.install_active_semantic_model_snapshot(snapshot);
        self
    }

    pub fn with_nonreturn_discovery_cache(
        mut self,
        cache: &'request NonreturnDiscoveryCache,
    ) -> Self {
        self.install_nonreturn_discovery_cache(cache);
        self
    }

    /// The borrowing form of [`Self::with_active_semantic_model_snapshot`], for
    /// a request lent by [`FlowStateOperation::with_request`].
    pub fn install_active_semantic_model_snapshot(
        &mut self,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) {
        self.active_semantic_model_snapshot = Some(snapshot);
    }

    /// The borrowing form of [`Self::with_nonreturn_discovery_cache`].
    pub fn install_nonreturn_discovery_cache(&mut self, cache: &'request NonreturnDiscoveryCache) {
        self.nonreturn_discovery_cache = Some(cache);
    }

    /// Split off the owned work state; everything else is per-call. Destructured
    /// without `..` so a new field must be classified as owned or per-call.
    fn into_owned_state(self) -> FlowStateOwnedState {
        let Self {
            cancellation: _,
            discharged_observation_gaps,
            memos,
            dead_write_prefix_reachability_cache,
            dead_write_component_order_cache,
            cfg_budget,
            nonreturn_cfg_budget,
            candidate_routes,
            control_projection: _,
            active_semantic_model_snapshot: _,
            nonreturn_discovery_cache: _,
        } = self;
        // A request carrying a discharge selection ran under a memo namespace
        // the shared keys do not name; its state never returns to an operation.
        // `debug_assert`: this also runs from a drop guard, where a panic
        // during unwind would abort. No lent request can acquire a selection:
        // the only installer consumes the request.
        debug_assert!(
            discharged_observation_gaps.is_none(),
            "a request with discharged observation gaps cannot restore memo state into a shared operation"
        );
        FlowStateOwnedState {
            memos,
            dead_write_prefix_reachability_cache,
            dead_write_component_order_cache,
            cfg_budget,
            // Only `from_owned_state` makes a restorable request, and it always
            // installs the optional ledger. No default ledger is invented here:
            // this runs from a drop guard, and a refund would hide spending.
            nonreturn_cfg_budget: nonreturn_cfg_budget
                .expect("a lent request keeps its operation's optional nonreturn ledger"),
            candidate_routes,
        }
    }

    fn from_owned_state(
        cancellation: &'request CancellationToken,
        state: FlowStateOwnedState,
    ) -> Self {
        let FlowStateOwnedState {
            memos,
            dead_write_prefix_reachability_cache,
            dead_write_component_order_cache,
            cfg_budget,
            nonreturn_cfg_budget,
            candidate_routes,
        } = state;
        Self {
            cancellation,
            discharged_observation_gaps: None,
            memos,
            dead_write_prefix_reachability_cache,
            dead_write_component_order_cache,
            cfg_budget,
            nonreturn_cfg_budget: Some(nonreturn_cfg_budget),
            candidate_routes,
            control_projection: None,
            active_semantic_model_snapshot: None,
            nonreturn_discovery_cache: None,
        }
    }
}

/// The request fields whose lifetime is a resource owner's, not one call's:
/// the memo regions under the analyzer's retention budget, the prefix and
/// order maps, the candidate routes and the CFG work ledger. Keys unchanged.
#[derive(Debug)]
struct FlowStateOwnedState {
    memos: FlowStateRequestMemos,
    dead_write_prefix_reachability_cache:
        HashMap<DeadWritePrefixKey, DeadWriteReachabilityCacheEntry>,
    dead_write_component_order_cache:
        HashMap<(DeadWriteProcedureKey, Vec<ControlEdgeId>), DeadWriteComponentOrderCacheEntry>,
    cfg_budget: CfgAlgorithmBudget,
    /// The optional nonreturn-proof ledger, kept apart from `cfg_budget`: the
    /// legacy rule gave that proof its own clone of the ordinary balance and
    /// limits so exhausting it never starves ordinary flow relations. It starts
    /// at the pristine ordinary default and then accumulates across derivations.
    nonreturn_cfg_budget: CfgAlgorithmBudget,
    candidate_routes: Option<(ProcedureHandle, CandidateControlRouteIndex)>,
}

/// One work owner's spent grant and memos across several derivations: the
/// semantic ledger that otherwise lives inside one derivation call, plus the
/// request-owned state above. An RQL traversal cache keeps one per file for
/// seeds that shared the old whole-file allowance.
///
/// The operation is lent, never replaced: `with_request` moves the owned state
/// into a temporary [`FlowStateRequest`] and a drop guard moves the SAME
/// spent state back, also on unwind, so a panic neither refunds a ledger nor
/// discards a memo region. There is no constructor from a standalone request,
/// so a request with discharged observation gaps cannot become one. Memo keys
/// carry the artifact allocation address, so the owner must keep the strong
/// artifact Arc alive for the operation's lifetime.
#[derive(Debug)]
pub struct FlowStateOperation {
    semantic_budget: SemanticBudget,
    /// `None` only while a request is lent out.
    state: Option<FlowStateOwnedState>,
}

/// Read-only spent-work view of an operation, for controls that show grants
/// accumulate or restart. Not a budget override.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowStateOperationConsumption {
    pub cfg_used: CfgAlgorithmWork,
    pub semantic_used: SemanticWork,
    pub cfg_refusals: usize,
    pub semantic_refusals: usize,
    pub nonreturn_cfg_used: CfgAlgorithmWork,
    pub nonreturn_cfg_refusals: usize,
}

impl FlowStateOperation {
    pub fn new(memos: FlowStateRequestMemos) -> Self {
        Self {
            semantic_budget: SemanticBudget::default(),
            state: Some(FlowStateOwnedState {
                memos,
                dead_write_prefix_reachability_cache: HashMap::default(),
                dead_write_component_order_cache: HashMap::default(),
                cfg_budget: CfgAlgorithmBudget::default(),
                nonreturn_cfg_budget: CfgAlgorithmBudget::default(),
                candidate_routes: None,
            }),
        }
    }

    /// Lend the operation's semantic ledger and a temporary request borrowing
    /// this call's token. The request's other per-call controls (snapshot,
    /// nonreturn cache) are installed by `run` through the `install_*`
    /// methods; nothing but the owned state survives the call.
    pub fn with_request<'t, R>(
        &mut self,
        cancellation: &'t CancellationToken,
        run: impl FnOnce(&mut SemanticBudget, &mut FlowStateRequest<'t>) -> R,
    ) -> R {
        let state = self
            .state
            .take()
            .expect("a flow-state operation is lent to one request at a time");
        let mut lease = OperationRequestLease {
            slot: &mut self.state,
            request: Some(FlowStateRequest::from_owned_state(cancellation, state)),
        };
        run(
            &mut self.semantic_budget,
            lease
                .request
                .as_mut()
                .expect("the lease holds its request until drop"),
        )
    }

    #[doc(hidden)]
    pub fn consumption(&self) -> FlowStateOperationConsumption {
        let state = self
            .state
            .as_ref()
            .expect("consumption is read while no request is lent");
        FlowStateOperationConsumption {
            cfg_used: state.cfg_budget.used(),
            semantic_used: self.semantic_budget.used(),
            cfg_refusals: state.cfg_budget.refusal_count(),
            semantic_refusals: self.semantic_budget.refusal_count(),
            nonreturn_cfg_used: state.nonreturn_cfg_budget.used(),
            nonreturn_cfg_refusals: state.nonreturn_cfg_budget.refusal_count(),
        }
    }
}

/// Returns the lent state to its operation on every exit, including unwind.
struct OperationRequestLease<'a, 't> {
    slot: &'a mut Option<FlowStateOwnedState>,
    request: Option<FlowStateRequest<'t>>,
}

impl Drop for OperationRequestLease<'_, '_> {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            *self.slot = Some(request.into_owned_state());
        }
    }
}

/// Cheap discovery filter only. The runtime owns the reusable effective-owner
/// index; exact dispatch plus exact-arity runtime agreement remain the positive
/// evidence below.
fn normal_continuation_absence_may_name(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
) -> bool {
    normal_continuation_absence_accepts(models, shape, false)
        || normal_continuation_absence_accepts_written_or_implicit_receiver(models, shape, true)
}

fn normal_continuation_absence_may_apply(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
    application: ModeledCallApplication,
) -> bool {
    match application {
        ModeledCallApplication::PackageFunction => {
            normal_continuation_absence_accepts(models, shape, false)
        }
        ModeledCallApplication::BoundReceiver => {
            normal_continuation_absence_accepts(models, shape, true)
        }
        ModeledCallApplication::ReceiverBindingUnknown => {
            normal_continuation_absence_accepts_written_or_implicit_receiver(models, shape, true)
        }
        ModeledCallApplication::Unknown => {
            normal_continuation_absence_accepts(models, shape, false)
                || normal_continuation_absence_accepts_written_or_implicit_receiver(
                    models, shape, true,
                )
        }
    }
}

fn normal_continuation_absence_accepts(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
    has_receiver: bool,
) -> bool {
    normal_continuation_absence_accepts_arity(models, shape, has_receiver, shape.arguments.len())
}

/// Go's absence candidates come from a Go-realm question, which never reaches
/// the JVM-family owner and so is never open.
fn go_has_normal_continuation_absence_candidates(models: &ResolvedActiveSemanticModels) -> bool {
    match models.has_normal_continuation_absence_candidates(Language::Go.config_label()) {
        FamilyPresence::Present => true,
        FamilyPresence::Absent => false,
        FamilyPresence::Open(open) => {
            unreachable!("a Go realm question has no JVM-family part: {open:?}")
        }
    }
}

fn normal_continuation_absence_accepts_arity(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
    has_receiver: bool,
    parameter_count: usize,
) -> bool {
    let Some(member) = shape.outcome.callee_name.as_deref() else {
        return false;
    };
    let Ok(parameter_count) = u32::try_from(parameter_count) else {
        return false;
    };
    let language = crate::analyzer::common::language_for_file(&shape.outcome.file).config_label();
    // An open owner list proves nothing, so the call keeps its continuation.
    let Ok(owners) =
        models.normal_continuation_absence_candidate_owners(language, member, has_receiver)
    else {
        return false;
    };
    owners.iter().any(|owner| {
        models.proves_normal_continuation_absent(ProcedureSummaryMemberKey::new(
            language,
            owner,
            member,
            has_receiver,
            parameter_count,
        ))
    })
}

fn normal_continuation_absence_accepts_written_or_implicit_receiver(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
    has_receiver: bool,
) -> bool {
    if normal_continuation_absence_accepts(models, shape, has_receiver) {
        return true;
    }
    crate::analyzer::common::language_for_file(&shape.outcome.file) == Language::Go
        && shape.arguments.len().checked_sub(1).is_some_and(|arity| {
            normal_continuation_absence_accepts_arity(models, shape, has_receiver, arity)
        })
}

#[derive(Default)]
struct ModeledControlProjectionDerivation {
    nonreturning_procedures: HashSet<ProcedureId>,
    omissions: Vec<FlowControlEdgeOmission>,
    file_reasons: Vec<FlowStateIncompleteReason>,
    procedure_reasons: HashMap<ProcedureId, Vec<FlowStateIncompleteReason>>,
}

impl ModeledControlProjectionDerivation {
    fn push_incomplete(&mut self, procedure: Option<ProcedureId>, detail: impl Into<String>) {
        let reason = FlowStateIncompleteReason::ModeledControlProjectionIncomplete {
            detail: detail.into(),
        };
        match procedure {
            Some(procedure) => self
                .procedure_reasons
                .entry(procedure)
                .or_default()
                .push(reason),
            None => self.file_reasons.push(reason),
        }
    }

    fn extend(&mut self, other: Self) {
        self.nonreturning_procedures
            .extend(other.nonreturning_procedures);
        self.omissions.extend(other.omissions);
        self.file_reasons.extend(other.file_reasons);
        for (procedure, reasons) in other.procedure_reasons {
            self.procedure_reasons
                .entry(procedure)
                .or_default()
                .extend(reasons);
        }
    }
}

/// One exact root- or dependency-procedure call whose complete dispatch set
/// could become non-returning when all of its workspace callees do.
#[derive(Clone, Debug)]
struct WorkspaceNonreturnCall {
    call: CallSiteId,
    transfers: CallTransferSet,
}

/// Request-local control evidence for one procedure reached from the file
/// being derived. Handles keep every dense ID scoped to its exact immutable
/// artifact; nothing in this proof is persisted across requests.
#[derive(Clone, Debug)]
struct WorkspaceNonreturnProcedure {
    handle: ProcedureHandle,
    exact_call_resolutions: HashSet<CallSiteId>,
    nonreturn_candidates: Vec<WorkspaceNonreturnCall>,
    abort_path_user_code: WorkspaceAbortPathUserCode,
    incomplete_detail: Option<Box<str>>,
}

/// Completed discovery shared only by one query. The Boolean distinguishes
/// a root procedure, whose calls all require adjudication, from a dependency
/// that may return after the conservative CFG prefilter.
#[derive(Default, Debug)]
pub struct NonreturnDiscoveryCache {
    entries: Mutex<HashMap<(ProcedureHandle, bool, usize), CachedNonreturnDiscovery>>,
}

#[derive(Debug)]
struct CachedNonreturnDiscovery {
    procedure: WorkspaceNonreturnProcedure,
    callees: Vec<ProcedureHandle>,
    reads: Arc<crate::analyzer::usages::common::QueryMemoReads>,
    _snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
}

impl WorkspaceNonreturnProcedure {
    fn incomplete(handle: ProcedureHandle, detail: impl Into<Box<str>>) -> Self {
        Self {
            handle,
            exact_call_resolutions: HashSet::default(),
            nonreturn_candidates: Vec::new(),
            abort_path_user_code: WorkspaceAbortPathUserCode::NotRelevant,
            incomplete_detail: Some(detail.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceAbortPathUserCode {
    NotRelevant,
    Uncomputed,
    Computed(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkspaceNonreturnEvaluation {
    Proven,
    Pending,
    Incomplete(Box<str>),
    Cancelled,
}

enum WorkspaceNonreturnDiscovery {
    Complete {
        procedure: WorkspaceNonreturnProcedure,
        callees: Vec<ProcedureHandle>,
    },
    Cancelled,
}

enum WorkspaceNonreturnInterruption {
    Incomplete(Box<str>),
    Cancelled,
}

#[derive(Default)]
struct SemanticCallSpanIndex {
    by_span: HashMap<(usize, usize), Vec<(ProcedureId, CallSiteId)>>,
}

impl SemanticCallSpanIndex {
    fn build(artifact: &SemanticArtifact, requested_procedure: Option<ProcedureId>) -> Self {
        let mut index = Self::default();
        for procedure in artifact.procedures().iter().filter(|procedure| {
            requested_procedure.is_none_or(|requested| procedure.id() == requested)
        }) {
            for call in procedure
                .call_sites()
                .iter()
                .filter(|call| call.invocation_mode == CallInvocationMode::Ordinary)
            {
                let Some(mapping) = procedure.source_mapping(call.source) else {
                    continue;
                };
                if mapping.kind != SourceMappingKind::Exact {
                    continue;
                }
                let span = mapping.locator.anchor().span();
                index
                    .by_span
                    .entry((span.start_byte() as usize, span.end_byte() as usize))
                    .or_default()
                    .push((procedure.id(), call.id));
            }
        }
        index
    }

    fn matches(&self, shape: &CallShapeReport) -> &[(ProcedureId, CallSiteId)] {
        self.by_span
            .get(&(shape.outcome.range.start_byte, shape.outcome.range.end_byte))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

fn modeled_key_proves_absent(
    models: &ResolvedActiveSemanticModels,
    key: &ModeledProcedureKey,
) -> bool {
    models.proves_normal_continuation_absent(ProcedureSummaryMemberKey::new(
        &key.language,
        &key.owner,
        &key.member,
        key.has_receiver,
        key.parameter_count,
    ))
}

fn incomplete_lookup_may_hide_nonreturn(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
    lookup: &ModeledCallTargetLookup,
) -> bool {
    if !matches!(
        lookup.coverage,
        ModeledCallTargetCoverage::Open
            | ModeledCallTargetCoverage::Truncated
            | ModeledCallTargetCoverage::Unsupported
            | ModeledCallTargetCoverage::Cancelled
    ) {
        return false;
    }
    if lookup.arms.is_empty() {
        return normal_continuation_absence_may_apply(models, shape, lookup.call_application);
    }
    lookup.arms.iter().all(|arm| {
        arm.origin == ModeledCallTargetOrigin::UnmaterializedExternal
            && modeled_key_proves_absent(models, &arm.key)
    })
}

fn modeled_normal_edge(
    artifact: &SemanticArtifact,
    procedure_id: ProcedureId,
    call_id: CallSiteId,
) -> Result<Option<FlowControlEdgeOmission>, String> {
    let procedure = artifact
        .procedure(procedure_id)
        .expect("the exact call-span index names an artifact procedure");
    modeled_normal_control_edge(procedure, call_id)
        .map(|edge| edge.map(|edge| FlowControlEdgeOmission::new(procedure_id, edge)))
}

fn modeled_normal_control_edge(
    procedure: &ProcedureSemantics,
    call_id: CallSiteId,
) -> Result<Option<ControlEdgeId>, String> {
    let call = procedure
        .call_site(call_id)
        .expect("the exact call-span index names a procedure call");
    if call.invocation_mode != CallInvocationMode::Ordinary {
        return Ok(None);
    }
    let target = match call.normal_continuation {
        ControlContinuation::Absent => return Ok(None),
        ControlContinuation::Target(target) => target,
        continuation => {
            return Err(format!(
                "call {:?} has unresolved normal continuation `{}`",
                call.id,
                continuation.label()
            ));
        }
    };
    let edges = normal_control_edges_to_target(procedure, call.point, target);
    if edges.len() != 1 {
        return Err(format!(
            "call {:?} normal continuation maps to {} exact normal edges: {edges:?}",
            call.id,
            edges.len()
        ));
    }
    Ok(Some(edges[0]))
}

fn normal_control_edges_to_target(
    procedure: &ProcedureSemantics,
    point: ProgramPointId,
    target: ProgramPointId,
) -> Vec<ControlEdgeId> {
    procedure
        .successor_edges(point)
        .filter_map(|(edge_id, edge)| {
            (edge.kind == ControlEdgeKind::Normal && edge.target_point == target).then_some(edge_id)
        })
        .collect()
}

fn derive_modeled_control_projection(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    facts: &brokk_bifrost_analysis::analyzer::structural::facts::FileFacts,
    artifact: &SemanticArtifact,
    requested_procedure: Option<ProcedureId>,
    models: &ResolvedActiveSemanticModels,
    cancellation: &CancellationToken,
) -> ModeledControlProjectionDerivation {
    // The lightweight resolver can currently mint exact unmaterialized model
    // keys only for Go package functions and concrete receiver methods. Do not
    // make an active Go claim add call-shape work to every other language in a
    // mixed workspace.
    if crate::analyzer::common::language_for_file(file) != Language::Go {
        return ModeledControlProjectionDerivation::default();
    }
    if !go_has_normal_continuation_absence_candidates(models) || cancellation.is_cancelled() {
        return ModeledControlProjectionDerivation::default();
    }

    let shapes = call_shapes_in_file(facts, file, facts.nodes().len());
    let call_spans = SemanticCallSpanIndex::build(artifact, requested_procedure);
    let candidate_shapes = shapes
        .iter()
        .filter(|shape| normal_continuation_absence_may_name(models, shape))
        // Unsupported `defer` retains its outer structural call shape but
        // emits no semantic call site. Detached calls are excluded from the
        // span index above. Neither has a synchronous caller edge that a
        // non-return model may remove, so both are inapplicable rather than
        // file-wide modeled-control incompleteness.
        .filter(|shape| !call_spans.matches(shape).is_empty())
        .collect::<Vec<_>>();
    if candidate_shapes.is_empty() {
        return ModeledControlProjectionDerivation::default();
    }

    let exact_source: Arc<str> = Arc::from(facts.source());
    let lookups = modeled_call_targets_for_shapes(
        analyzer,
        &candidate_shapes,
        exact_source,
        CallRelationLimits {
            max_files: 1,
            max_source_bytes: facts.source().len(),
            max_candidates: facts.nodes().len().max(1),
        },
        Some(cancellation),
    );
    assert_eq!(
        candidate_shapes.len(),
        lookups.len(),
        "the modeled-call batch returns one lookup per structured call"
    );

    let mut derived = ModeledControlProjectionDerivation::default();
    for (shape, lookup) in candidate_shapes.into_iter().zip(lookups) {
        let span_matches = call_spans.matches(shape);

        if lookup.coverage != ModeledCallTargetCoverage::Exhaustive {
            if incomplete_lookup_may_hide_nonreturn(models, shape, &lookup) {
                let detail = format!(
                    "structured call {}..{} has incomplete modeled-target coverage {:?}",
                    shape.outcome.range.start_byte, shape.outcome.range.end_byte, lookup.coverage
                );
                let mut procedures = span_matches
                    .iter()
                    .map(|(procedure, _)| *procedure)
                    .collect::<Vec<_>>();
                procedures.sort_unstable();
                procedures.dedup();
                for procedure in procedures {
                    derived.push_incomplete(Some(procedure), detail.clone());
                }
            }
            continue;
        }
        if lookup.arms.is_empty()
            || !lookup.arms.iter().all(|arm| {
                arm.origin == ModeledCallTargetOrigin::UnmaterializedExternal
                    && modeled_key_proves_absent(models, &arm.key)
            })
        {
            continue;
        }

        for (procedure_id, call_id) in span_matches {
            match modeled_normal_edge(artifact, *procedure_id, *call_id) {
                Ok(Some(omission)) => derived.omissions.push(omission),
                Ok(None) => {}
                Err(detail) => derived.push_incomplete(Some(*procedure_id), detail),
            }
        }
    }
    derived
}

fn call_transfer_dispatch_is_exact(transfers: &CallTransferSet) -> bool {
    transfers.coverage == CandidateCoverage::Exhaustive
        && (!transfers.transfers.is_empty() || !transfers.boundaries.is_empty())
        && transfers
            .transfers
            .iter()
            .all(|transfer| transfer.proof == ProofStatus::Proven)
        && transfers
            .boundaries
            .iter()
            .all(|boundary| boundary.dispatch.proof == ProofStatus::Proven)
}

fn exact_call_can_be_nonreturn(transfers: &CallTransferSet) -> bool {
    // An external boundary remains body-partial because the callee is outside
    // the workspace. That does not weaken its independently proven
    // normal-continuation model, which comes from the exact activated summary.
    call_transfer_dispatch_is_exact(transfers)
        && transfers.boundaries.iter().all(|boundary| {
            boundary.model == CallToReturnModel::Exceptional
                && boundary.dispatch.unmaterialized_external_target().is_some()
        })
}

fn workspace_call_proves_nonreturn(
    call: &WorkspaceNonreturnCall,
    proven: &HashSet<ProcedureHandle>,
) -> bool {
    exact_call_can_be_nonreturn(&call.transfers)
        && call
            .transfers
            .transfers
            .iter()
            .all(|transfer| proven.contains(&transfer.callee))
}

fn workspace_nonreturn_cfg_interruption(
    handle: &ProcedureHandle,
    operation: &'static str,
    error: CfgAlgorithmError<ProgramPointId>,
) -> WorkspaceNonreturnInterruption {
    match error {
        CfgAlgorithmError::InvalidNode(point) => {
            unreachable!(
                "validated workspace non-return procedure {:?} has invalid point {point}",
                handle.semantics().locator()
            )
        }
        CfgAlgorithmError::Cancelled { .. } => WorkspaceNonreturnInterruption::Cancelled,
        CfgAlgorithmError::ExceededBudget(exceeded) => WorkspaceNonreturnInterruption::Incomplete(
            format!(
                "workspace non-return {operation} for {:?} exhausted the {:?} CFG limit {} at {}",
                handle.semantics().locator(),
                exceeded.limit_kind,
                exceeded.limit,
                exceeded.attempted
            )
            .into_boxed_str(),
        ),
    }
}

fn workspace_abort_path_user_code_state(
    semantics: &ProcedureSemantics,
) -> WorkspaceAbortPathUserCode {
    let has_relevant_gap = semantics.gaps().iter().any(|gap| {
        gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
            && crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                gap, false,
            )
    });
    if has_relevant_gap {
        WorkspaceAbortPathUserCode::Uncomputed
    } else {
        WorkspaceAbortPathUserCode::NotRelevant
    }
}

fn discover_workspace_nonreturn_procedure(
    provider: &WorkspaceIcfgProvider<'_>,
    root_artifact: &Arc<SemanticArtifact>,
    handle: ProcedureHandle,
    semantic_budget: &mut SemanticBudget,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
) -> WorkspaceNonreturnDiscovery {
    let semantics = handle.semantics();
    let mut algorithm_request = CfgAlgorithmRequest::new(cfg_budget, cancellation);
    let reachable =
        match forward_reachability(semantics, semantics.entry_point(), &mut algorithm_request) {
            Ok(reachable) => reachable,
            Err(error) => {
                match workspace_nonreturn_cfg_interruption(&handle, "entry reachability", error) {
                    WorkspaceNonreturnInterruption::Incomplete(detail) => {
                        return WorkspaceNonreturnDiscovery::Complete {
                            procedure: WorkspaceNonreturnProcedure::incomplete(handle, detail),
                            callees: Vec::new(),
                        };
                    }
                    WorkspaceNonreturnInterruption::Cancelled => {
                        return WorkspaceNonreturnDiscovery::Cancelled;
                    }
                }
            }
        };
    let reachable_calls = semantics
        .call_sites()
        .iter()
        .filter(|call| {
            call.invocation_mode == CallInvocationMode::Ordinary
                && reachable.contains(semantics, call.point)
        })
        .map(|call| call.id)
        .collect::<Vec<_>>();

    // Root-file calls are the publication surface and therefore all need
    // adjudication. A dependency procedure is useful only as a whole-procedure
    // proof. Before following its ordinary call graph, remove every normal call
    // scaffold that this solver could ever remove. If the normal exit remains
    // reachable even under that strongest possible mask, no combination of
    // descendant non-return proofs can make this dependency non-returning.
    if !Arc::ptr_eq(handle.artifact(), root_artifact) {
        let possible_omissions = reachable_calls
            .iter()
            .filter_map(|call| modeled_normal_control_edge(semantics, *call).ok().flatten())
            .collect::<Vec<_>>();
        let possible_mask = ControlEdgeMask::new(semantics, possible_omissions);
        let normal_exit_still_reachable = if possible_mask.is_empty() {
            Ok(reachable.contains(semantics, semantics.normal_exit_point()))
        } else {
            with_control_graph!(semantics, &possible_mask, |graph| {
                let mut algorithm_request = CfgAlgorithmRequest::new(cfg_budget, cancellation);
                match forward_reachability(graph, semantics.entry_point(), &mut algorithm_request) {
                    Ok(possible_reachability) => {
                        Ok(possible_reachability.contains(graph, semantics.normal_exit_point()))
                    }
                    Err(error) => Err(error),
                }
            })
        };
        let normal_exit_still_reachable = match normal_exit_still_reachable {
            Ok(reachable) => reachable,
            Err(error) => {
                match workspace_nonreturn_cfg_interruption(&handle, "dependency prefilter", error) {
                    WorkspaceNonreturnInterruption::Incomplete(detail) => {
                        return WorkspaceNonreturnDiscovery::Complete {
                            procedure: WorkspaceNonreturnProcedure::incomplete(handle, detail),
                            callees: Vec::new(),
                        };
                    }
                    WorkspaceNonreturnInterruption::Cancelled => {
                        return WorkspaceNonreturnDiscovery::Cancelled;
                    }
                }
            }
        };
        if normal_exit_still_reachable {
            return WorkspaceNonreturnDiscovery::Complete {
                procedure: WorkspaceNonreturnProcedure {
                    handle,
                    exact_call_resolutions: HashSet::default(),
                    nonreturn_candidates: Vec::new(),
                    abort_path_user_code: WorkspaceAbortPathUserCode::NotRelevant,
                    incomplete_detail: None,
                },
                callees: Vec::new(),
            };
        }
    }

    let mut exact_call_resolutions = HashSet::default();
    let mut nonreturn_candidates = Vec::new();
    let mut discovered_callees = Vec::new();
    let mut incomplete_detail = None;
    for call in reachable_calls {
        if cancellation.is_cancelled() {
            return WorkspaceNonreturnDiscovery::Cancelled;
        }
        let outcome = provider.call_transfers(
            &handle,
            call,
            &mut SemanticRequest::new(semantic_budget, cancellation),
        );
        let value = match outcome {
            Ok(SemanticOutcome::Complete { value, .. }) => value,
            // Outcome quality and transfer-set closure are distinct axes. A
            // caller-side lowering gap can make the operation unknown while
            // retaining an exhaustive, proven dispatch component (notably an
            // exact external `os.Exit` boundary). Admit available payloads;
            // `exact_call_can_be_nonreturn` still requires exhaustive coverage,
            // proven workspace targets, and proven exact exceptional boundaries
            // before this solver can remove any edge. The lowering
            // gap itself remains in the procedure and is checked below.
            Ok(SemanticOutcome::Ambiguous { candidates, .. }) => candidates,
            Ok(SemanticOutcome::Unknown {
                partial: Some(value),
                ..
            })
            | Ok(SemanticOutcome::Unsupported {
                partial: Some(value),
                ..
            }) => value,
            Ok(SemanticOutcome::Unproven { partial, .. }) => partial,
            Ok(
                SemanticOutcome::Unknown { partial: None, .. }
                | SemanticOutcome::Unsupported { partial: None, .. },
            ) => continue,
            Ok(SemanticOutcome::ExceededBudget { exceeded, .. }) => {
                incomplete_detail = Some(
                    format!(
                        "workspace non-return dispatch for {:?} call {call} exhausted its semantic budget: {exceeded}",
                        handle.semantics().locator()
                    )
                    .into_boxed_str(),
                );
                break;
            }
            Ok(SemanticOutcome::Cancelled { .. }) => {
                return WorkspaceNonreturnDiscovery::Cancelled;
            }
            Err(error) => {
                incomplete_detail = Some(
                    format!(
                        "workspace non-return dispatch for {:?} call {call} failed: {error}",
                        handle.semantics().locator()
                    )
                    .into_boxed_str(),
                );
                break;
            }
        };
        if call_transfer_dispatch_is_exact(&value) {
            exact_call_resolutions.insert(call);
        }
        if !exact_call_can_be_nonreturn(&value) {
            continue;
        }
        discovered_callees.extend(
            value
                .transfers
                .iter()
                .map(|transfer| transfer.callee.clone()),
        );
        nonreturn_candidates.push(WorkspaceNonreturnCall {
            call,
            transfers: value,
        });
    }

    let abort_path_user_code = workspace_abort_path_user_code_state(semantics);
    WorkspaceNonreturnDiscovery::Complete {
        procedure: WorkspaceNonreturnProcedure {
            handle,
            exact_call_resolutions,
            nonreturn_candidates,
            abort_path_user_code,
            incomplete_detail,
        },
        callees: discovered_callees,
    }
}

fn normal_return_gap_is_discharged(
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    exact_call_resolutions: &HashSet<CallSiteId>,
    abort_paths_run_user_code: bool,
) -> bool {
    if crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
        gap,
        abort_paths_run_user_code,
    ) {
        return true;
    }
    if gap.control_flow_discharge() != SemanticGapDischarge::CallResolution {
        return false;
    }
    debug_assert!(
        matches!(gap.subject, SemanticGapSubject::CallSite(_)),
        "validated call-resolution gap must be scoped to a call site"
    );
    let SemanticGapSubject::CallSite(call) = gap.subject else {
        return false;
    };
    semantics.call_site(call).is_some() && exact_call_resolutions.contains(&call)
}

fn evaluate_workspace_nonreturn_procedure(
    procedure: &mut WorkspaceNonreturnProcedure,
    proven: &HashSet<ProcedureHandle>,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
) -> WorkspaceNonreturnEvaluation {
    if let Some(detail) = &procedure.incomplete_detail {
        return WorkspaceNonreturnEvaluation::Incomplete(detail.clone());
    }
    let handle = procedure.handle.clone();
    let semantics = handle.semantics();
    let mut omitted = Vec::new();
    for call in &procedure.nonreturn_candidates {
        if !workspace_call_proves_nonreturn(call, proven) {
            continue;
        }
        match modeled_normal_control_edge(semantics, call.call) {
            Ok(Some(edge)) => omitted.push(edge),
            Ok(None) => {}
            Err(_) => {
                // Unresolved or non-canonical call scaffolding is already a
                // lowering/raw-flow completeness concern. It prevents this
                // optional proof, but is not a solver interruption.
                return WorkspaceNonreturnEvaluation::Pending;
            }
        }
    }
    let mask = ControlEdgeMask::new(semantics, omitted);
    evaluate_projected_nonreturn(
        &handle,
        &mask,
        &procedure.exact_call_resolutions,
        &mut procedure.abort_path_user_code,
        cfg_budget,
        cancellation,
    )
}

fn evaluate_projected_nonreturn(
    handle: &ProcedureHandle,
    mask: &ControlEdgeMask,
    exact_call_resolutions: &HashSet<CallSiteId>,
    abort_path_user_code: &mut WorkspaceAbortPathUserCode,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
) -> WorkspaceNonreturnEvaluation {
    let semantics = handle.semantics();
    with_control_graph!(semantics, mask, |graph| {
        let mut algorithm_request = CfgAlgorithmRequest::new(cfg_budget, cancellation);
        let reachable =
            match forward_reachability(graph, semantics.entry_point(), &mut algorithm_request) {
                Ok(reachable) => reachable,
                Err(error) => {
                    return match workspace_nonreturn_cfg_interruption(
                        handle,
                        "fixed-point reachability",
                        error,
                    ) {
                        WorkspaceNonreturnInterruption::Incomplete(detail) => {
                            WorkspaceNonreturnEvaluation::Incomplete(detail)
                        }
                        WorkspaceNonreturnInterruption::Cancelled => {
                            WorkspaceNonreturnEvaluation::Cancelled
                        }
                    };
                }
            };
        if reachable.contains(graph, semantics.normal_exit_point()) {
            return WorkspaceNonreturnEvaluation::Pending;
        }

        let relevant_implicit_abort_gap_is_reachable = !matches!(
            *abort_path_user_code,
            WorkspaceAbortPathUserCode::NotRelevant
        ) && semantics.gaps().iter().any(|gap| {
            gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                && (matches!(gap.subject, SemanticGapSubject::Procedure)
                    || reachable.contains(graph, gap.point))
                && crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                    gap, false,
                )
        });
        let abort_paths_run_user_code = if !relevant_implicit_abort_gap_is_reachable {
            false
        } else {
            match *abort_path_user_code {
                WorkspaceAbortPathUserCode::NotRelevant => false,
                WorkspaceAbortPathUserCode::Computed(runs_user_code) => runs_user_code,
                WorkspaceAbortPathUserCode::Uncomputed => {
                    let mut algorithm_request = CfgAlgorithmRequest::new(cfg_budget, cancellation);
                    match crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code_bounded(
                        semantics,
                        &mut algorithm_request,
                    ) {
                        Ok(runs_user_code) => {
                            *abort_path_user_code =
                                WorkspaceAbortPathUserCode::Computed(runs_user_code);
                            runs_user_code
                        }
                        Err(error) => {
                            return match workspace_nonreturn_cfg_interruption(
                                handle,
                                "abort-path classification",
                                error,
                            ) {
                                WorkspaceNonreturnInterruption::Incomplete(detail) => {
                                    WorkspaceNonreturnEvaluation::Incomplete(detail)
                                }
                                WorkspaceNonreturnInterruption::Cancelled => {
                                    WorkspaceNonreturnEvaluation::Cancelled
                                }
                            };
                        }
                    }
                }
            }
        };
        let has_undischarged_gap = semantics.gaps().iter().any(|gap| {
            if !gap.impacts.contains(SemanticGapImpact::ReturnTransfer) {
                return false;
            }
            let gap_is_reachable = matches!(gap.subject, SemanticGapSubject::Procedure)
                || reachable.contains(graph, gap.point);
            gap_is_reachable
                && !normal_return_gap_is_discharged(
                    semantics,
                    gap,
                    exact_call_resolutions,
                    abort_paths_run_user_code,
                )
        });
        if has_undischarged_gap {
            // A reachable undischarged gap invalidates this candidate. Later
            // removal of candidate callees can only restore more paths, so
            // it cannot make this incomplete body non-returning.
            WorkspaceNonreturnEvaluation::Pending
        } else {
            WorkspaceNonreturnEvaluation::Proven
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn derive_workspace_nonreturn_projection(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    artifact: &Arc<SemanticArtifact>,
    requested_procedure: Option<ProcedureId>,
    snapshot: Option<&Arc<ActiveSemanticModelSnapshot>>,
    semantic_budget: &mut SemanticBudget,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
    shared_provider: Option<&WorkspaceIcfgProvider<'_>>,
    discovery_cache: Option<&NonreturnDiscoveryCache>,
) -> ModeledControlProjectionDerivation {
    let language = crate::analyzer::common::language_for_file(file);
    let go_models_can_diverge = language == Language::Go
        && snapshot.is_some_and(|snapshot| {
            go_has_normal_continuation_absence_candidates(snapshot.active_models())
        });
    let python_source_can_diverge = language == Language::Python
        && python_has_local_nonreturn_candidate(artifact, requested_procedure);
    if !(go_models_can_diverge || python_source_can_diverge) || cancellation.is_cancelled() {
        return ModeledControlProjectionDerivation::default();
    }

    let roots = artifact
        .procedures()
        .iter()
        .filter(|procedure| requested_procedure.is_none_or(|requested| procedure.id() == requested))
        .map(|procedure| {
            artifact
                .procedure_handle(procedure.id())
                .expect("a validated artifact owns every procedure it lists")
        })
        .collect::<Vec<_>>();
    if let Some(provider) = shared_provider {
        assert!(
            std::ptr::eq(provider.workspace(), workspace),
            "shared non-return provider belongs to this workspace"
        );
        let provider_snapshot = provider.oracle().active_semantic_model_snapshot();
        assert!(
            match (provider_snapshot.as_ref(), snapshot) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            },
            "shared non-return provider uses this model snapshot"
        );
        derive_nonreturn_projection(
            provider,
            artifact,
            roots,
            semantic_budget,
            cfg_budget,
            cancellation,
            discovery_cache,
        )
    } else {
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            workspace,
            snapshot.cloned(),
        );
        derive_nonreturn_projection(
            &provider,
            artifact,
            roots,
            semantic_budget,
            cfg_budget,
            cancellation,
            discovery_cache,
        )
    }
}

fn python_has_local_nonreturn_candidate(
    artifact: &SemanticArtifact,
    requested_procedure: Option<ProcedureId>,
) -> bool {
    let roots = requested_procedure
        .map(|procedure| vec![procedure])
        .unwrap_or_else(|| {
            artifact
                .procedures()
                .iter()
                .map(|procedure| procedure.id())
                .collect()
        });
    let mut scheduled = roots.iter().copied().collect::<HashSet<_>>();
    let mut pending = VecDeque::from(roots);
    // This is only a cheap gate for the CFG proof below. A local call graph
    // candidate avoids constructing an interprocedural provider for every
    // Python procedure; the provider still proves actual control reachability.
    while let Some(procedure_id) = pending.pop_front() {
        let procedure = artifact
            .procedure(procedure_id)
            .expect("a local Python call target names a materialized procedure");
        if procedure.points().iter().any(|point| {
            point
                .events
                .iter()
                .any(|event| matches!(&event.effect, SemanticEffect::Throw { .. }))
        }) {
            return true;
        }
        for call in procedure.call_sites() {
            if call.normal_continuation == ControlContinuation::Absent {
                return true;
            }
            if let CallableTargetResolution::Proven(CallableTarget::Local(callee)) =
                &call.declared_targets
                && scheduled.insert(*callee)
            {
                pending.push_back(*callee);
            }
        }
    }
    false
}

/// Exact, request-local absent normal continuations for one immutable procedure.
/// An empty edge inventory is not a proof that every call returns. Consumers
/// must retain the incomplete reasons when discovery could not finish.
#[derive(Debug, Clone)]
pub struct ProcedureContinuationProjection {
    procedure: ProcedureHandle,
    normal_return_absent: bool,
    mask: ControlEdgeMask,
    reasons: Vec<FlowStateIncompleteReason>,
}

impl ProcedureContinuationProjection {
    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    /// Positive whole-procedure proof for this source or specialized invocation.
    /// Absence of this certificate does not establish that a body returns.
    pub fn normal_return_is_absent(&self) -> bool {
        self.normal_return_absent
    }

    /// Specialize one invocation using its exact, exhaustive source dispatch
    /// set. The caller owns the dispatch witness for this call occurrence.
    /// The returned graph is a separate value; the source projection and any
    /// other invocation of the same procedure retain their own continuations.
    pub fn with_nonreturning_source_call(
        &self,
        call: &CallSiteHandle,
        targets: &[&Self],
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Self>, FlowStateIncompleteReason> {
        assert_eq!(
            call.procedure(),
            &self.procedure,
            "call and projection share exact artifact identity"
        );
        if request.cancellation.is_cancelled() {
            return Err(FlowStateIncompleteReason::Cancelled);
        }
        request
            .budget
            .admit(SemanticWork {
                nested_entries: 1 + targets.len(),
                ..SemanticWork::default()
            })
            .map_err(
                |error| FlowStateIncompleteReason::ModeledControlProjectionIncomplete {
                    detail: format!(
                        "contextual continuation target proof exhausted its budget: {error:?}"
                    ),
                },
            )?;
        let row = self
            .procedure
            .semantics()
            .call_site(call.id())
            .expect("scoped call exists");
        if row.invocation_mode != CallInvocationMode::Ordinary
            || row.execution_timing != crate::analyzer::semantic::ExecutionTiming::SameEvaluation
            || targets.is_empty()
            || targets
                .iter()
                .any(|target| !target.normal_return_is_absent())
        {
            return Ok(None);
        }
        request
            .budget
            .admit(SemanticWork {
                nested_entries: self.mask.omitted.len()
                    + self.reasons.len()
                    + 2 * self.procedure.semantics().points().len()
                    + self.procedure.semantics().control_edges().len(),
                ..SemanticWork::default()
            })
            .map_err(
                |error| FlowStateIncompleteReason::ModeledControlProjectionIncomplete {
                    detail: format!(
                        "contextual continuation graph exhausted its budget: {error:?}"
                    ),
                },
            )?;
        let edge = modeled_normal_control_edge(self.procedure.semantics(), call.id()).map_err(
            |detail| FlowStateIncompleteReason::ModeledControlProjectionIncomplete { detail },
        )?;
        let Some(edge) = edge else {
            return Ok(None);
        };
        // Retain only an already-established whole-body certificate. A new
        // contextual body proof needs the same return-gap checks as the source
        // fixed point; graph reachability alone is insufficient.
        Ok(Some(Self {
            procedure: self.procedure.clone(),
            normal_return_absent: self.normal_return_absent,
            reasons: self.reasons.clone(),
            mask: ControlEdgeMask::new(
                self.procedure.semantics(),
                self.mask.omitted.iter().copied().chain([edge]),
            ),
        }))
    }

    /// Certify this invocation's whole body after contextual call masking.
    /// The caller supplies exact, exhaustive dispatch witnesses for these
    /// same-instance calls. Reachable return gaps and exceptional user code
    /// use the same checks as source fixed-point evaluation.
    pub fn certify_normal_return_absence(
        &mut self,
        exact_calls: &[CallSiteHandle],
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, FlowStateIncompleteReason> {
        request
            .budget
            .admit(SemanticWork {
                nested_entries: exact_calls.len() + self.procedure.semantics().gaps().len() + 1,
                ..SemanticWork::default()
            })
            .map_err(
                |error| FlowStateIncompleteReason::ModeledControlProjectionIncomplete {
                    detail: format!("contextual return proof exhausted its budget: {error:?}"),
                },
            )?;
        let exact = exact_calls
            .iter()
            .map(|call| {
                assert_eq!(
                    call.procedure(),
                    &self.procedure,
                    "exact call belongs to this invocation's artifact"
                );
                call.id()
            })
            .collect::<HashSet<_>>();
        let mut cfg_budget = CfgAlgorithmBudget::uniform(usize::MAX);
        let result = evaluate_projected_nonreturn(
            &self.procedure,
            &self.mask,
            &exact,
            &mut workspace_abort_path_user_code_state(self.procedure.semantics()),
            &mut cfg_budget,
            request.cancellation,
        );
        let used = cfg_budget.used();
        request.budget.charge_work(SemanticWork {
            nested_entries: used.node_visits + used.edge_visits,
            ..SemanticWork::default()
        });
        match result {
            WorkspaceNonreturnEvaluation::Proven => {
                self.normal_return_absent = true;
                Ok(true)
            }
            WorkspaceNonreturnEvaluation::Pending => Ok(self.normal_return_absent),
            WorkspaceNonreturnEvaluation::Cancelled => Err(FlowStateIncompleteReason::Cancelled),
            WorkspaceNonreturnEvaluation::Incomplete(detail) => Err(
                FlowStateIncompleteReason::ModeledControlProjectionIncomplete {
                    detail: detail.to_string(),
                },
            ),
        }
    }

    /// The same validated control view serves reachability, dominance, loops,
    /// and lock dataflow without changing source artifact identity.
    pub fn graph(&self) -> ProjectedProcedureGraph<'_> {
        ProjectedProcedureGraph::new(self.procedure.semantics(), &self.mask)
    }
}

/// Derive source and active-model non-return facts without requiring an external
/// terminator model to activate source discovery. Both work ledgers belong to
/// the caller. The provider supplies the caller's captured model snapshot.
pub fn procedure_continuation_projection(
    provider: &WorkspaceIcfgProvider<'_>,
    procedure: &ProcedureHandle,
    semantic_budget: &mut SemanticBudget,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
) -> ProcedureContinuationProjection {
    let derived = derive_nonreturn_projection(
        provider,
        procedure.artifact(),
        vec![procedure.clone()],
        semantic_budget,
        cfg_budget,
        cancellation,
        None,
    );
    continuation_projection_from_derivation(procedure, derived, cancellation)
}

fn continuation_projection_from_derivation(
    procedure: &ProcedureHandle,
    mut derived: ModeledControlProjectionDerivation,
    cancellation: &CancellationToken,
) -> ProcedureContinuationProjection {
    let mut reasons = derived.file_reasons;
    reasons.extend(
        derived
            .procedure_reasons
            .remove(&procedure.id())
            .unwrap_or_default(),
    );
    if cancellation.is_cancelled() {
        reasons.push(FlowStateIncompleteReason::Cancelled);
    }
    ProcedureContinuationProjection {
        procedure: procedure.clone(),
        normal_return_absent: derived.nonreturning_procedures.contains(&procedure.id()),
        mask: ControlEdgeMask::new(
            procedure.semantics(),
            derived
                .omissions
                .into_iter()
                .filter(|omission| omission.procedure == procedure.id())
                .map(|omission| omission.edge),
        ),
        reasons,
    }
}

fn derive_nonreturn_projection(
    provider: &WorkspaceIcfgProvider<'_>,
    artifact: &Arc<SemanticArtifact>,
    roots: Vec<ProcedureHandle>,
    semantic_budget: &mut SemanticBudget,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
    discovery_cache: Option<&NonreturnDiscoveryCache>,
) -> ModeledControlProjectionDerivation {
    let mut scheduled = roots.iter().cloned().collect::<HashSet<_>>();
    let mut pending = roots.into_iter().collect::<VecDeque<_>>();
    let mut procedures = Vec::new();
    while let Some(handle) = pending.pop_front() {
        if cancellation.is_cancelled() {
            return ModeledControlProjectionDerivation::default();
        }
        let root = Arc::ptr_eq(handle.artifact(), artifact);
        let snapshot = provider.oracle().active_semantic_model_snapshot();
        let key = (
            handle.clone(),
            root,
            snapshot
                .as_ref()
                .map_or(0, |snapshot| Arc::as_ptr(snapshot) as usize),
        );
        let cached = discovery_cache.and_then(|cache| {
            cache
                .entries
                .lock()
                .expect("nonreturn discovery cache mutex is not poisoned")
                .get(&key)
                .map(|entry| {
                    crate::analyzer::usages::common::replay_memo_reads(
                        &entry.reads,
                        provider.workspace().analyzer(),
                    );
                    WorkspaceNonreturnDiscovery::Complete {
                        procedure: entry.procedure.clone(),
                        callees: entry.callees.clone(),
                    }
                })
        });
        let discovery = cached.unwrap_or_else(|| {
            let (discovery, reads) = crate::analyzer::usages::common::capture_memo_reads(
                crate::analyzer::usages::common::QueryMemoOwner::NonreturnDiscovery,
                provider.workspace().analyzer(),
                || {
                    discover_workspace_nonreturn_procedure(
                        provider,
                        artifact,
                        handle,
                        semantic_budget,
                        cfg_budget,
                        cancellation,
                    )
                },
            );
            if let (Some(cache), WorkspaceNonreturnDiscovery::Complete { procedure, callees }) =
                (discovery_cache, &discovery)
                && let Some(reads) = reads.admitted()
                && procedure.incomplete_detail.is_none()
                && procedure.exact_call_resolutions.len()
                    == procedure
                        .handle
                        .semantics()
                        .call_sites()
                        .iter()
                        .filter(|call| call.invocation_mode == CallInvocationMode::Ordinary)
                        .count()
            {
                cache
                    .entries
                    .lock()
                    .expect("nonreturn discovery cache mutex is not poisoned")
                    .insert(
                        key,
                        CachedNonreturnDiscovery {
                            procedure: procedure.clone(),
                            callees: callees.clone(),
                            reads: Arc::new(reads),
                            _snapshot: snapshot,
                        },
                    );
            }
            discovery
        });
        let (procedure, callees) = match discovery {
            WorkspaceNonreturnDiscovery::Complete { procedure, callees } => (procedure, callees),
            WorkspaceNonreturnDiscovery::Cancelled => {
                return ModeledControlProjectionDerivation::default();
            }
        };
        for callee in callees {
            if scheduled.insert(callee.clone()) {
                pending.push_back(callee);
            }
        }
        procedures.push(procedure);
    }

    let mut callers: HashMap<ProcedureHandle, Vec<usize>> = HashMap::default();
    for (caller, procedure) in procedures.iter().enumerate() {
        for callee in procedure
            .nonreturn_candidates
            .iter()
            .flat_map(|call| call.transfers.transfers.iter())
            .map(|transfer| transfer.callee.clone())
        {
            let dependents = callers.entry(callee).or_default();
            if !dependents.contains(&caller) {
                dependents.push(caller);
            }
        }
    }

    // Normal termination requires a finite return derivation. Its complement
    // is a greatest fixed point: begin with candidate non-returning bodies,
    // then remove any body with a returning path or an incomplete proof.
    // Removing a callee restores its callers' normal call edges, so every
    // affected caller must be rechecked. Only the stable set is published.
    // This proves a recursive group without a base case while preserving any
    // group from which a normal return or unresolved boundary remains possible.
    let mut nonreturn = procedures
        .iter()
        .map(|procedure| procedure.handle.clone())
        .collect::<HashSet<_>>();
    let mut incomplete_reasons: HashMap<ProcedureHandle, HashSet<Box<str>>> = HashMap::default();
    let mut evaluation_pending = (0..procedures.len()).collect::<VecDeque<_>>();
    let mut evaluation_queued = vec![true; procedures.len()];
    while let Some(index) = evaluation_pending.pop_front() {
        evaluation_queued[index] = false;
        if cancellation.is_cancelled() {
            return ModeledControlProjectionDerivation::default();
        }
        let handle = procedures[index].handle.clone();
        if !nonreturn.contains(&handle) {
            continue;
        }
        match evaluate_workspace_nonreturn_procedure(
            &mut procedures[index],
            &nonreturn,
            cfg_budget,
            cancellation,
        ) {
            WorkspaceNonreturnEvaluation::Proven => continue,
            WorkspaceNonreturnEvaluation::Pending => {}
            WorkspaceNonreturnEvaluation::Incomplete(detail) => {
                incomplete_reasons
                    .entry(handle.clone())
                    .or_default()
                    .insert(detail);
            }
            WorkspaceNonreturnEvaluation::Cancelled => {
                return ModeledControlProjectionDerivation::default();
            }
        }
        assert!(nonreturn.remove(&handle), "evaluated candidate is present");
        for caller in callers.get(&handle).into_iter().flatten().copied() {
            if !evaluation_queued[caller] {
                evaluation_queued[caller] = true;
                evaluation_pending.push_back(caller);
            }
        }
    }
    if cancellation.is_cancelled() {
        return ModeledControlProjectionDerivation::default();
    }
    let proven = nonreturn;

    // A dependency failure matters only to callers whose own non-return proof
    // did not complete. Carry the original bounded failure back through those
    // exact candidate edges; a caller independently proved non-returning does
    // not inherit an irrelevant diagnostic.
    let mut failure_pending = incomplete_reasons
        .iter()
        .flat_map(|(handle, reasons)| {
            reasons
                .iter()
                .cloned()
                .map(move |reason| (handle.clone(), reason))
        })
        .collect::<VecDeque<_>>();
    while let Some((failed, reason)) = failure_pending.pop_front() {
        if cancellation.is_cancelled() {
            return ModeledControlProjectionDerivation::default();
        }
        for caller in callers.get(&failed).into_iter().flatten().copied() {
            let caller_handle = procedures[caller].handle.clone();
            if proven.contains(&caller_handle) {
                continue;
            }
            if incomplete_reasons
                .entry(caller_handle.clone())
                .or_default()
                .insert(reason.clone())
            {
                failure_pending.push_back((caller_handle, reason.clone()));
            }
        }
    }

    let mut derived = ModeledControlProjectionDerivation::default();
    for procedure in procedures
        .iter()
        .filter(|procedure| Arc::ptr_eq(procedure.handle.artifact(), artifact))
    {
        if cancellation.is_cancelled() {
            return ModeledControlProjectionDerivation::default();
        }
        if proven.contains(&procedure.handle) {
            derived
                .nonreturning_procedures
                .insert(procedure.handle.id());
        }
        if let Some(reasons) = incomplete_reasons.get(&procedure.handle) {
            let mut reasons = reasons
                .iter()
                .map(|reason| reason.as_ref())
                .collect::<Vec<&str>>();
            reasons.sort_unstable();
            derived.push_incomplete(
                Some(procedure.handle.id()),
                brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                    format_args!(
                        "workspace non-return proof is incomplete: {}",
                        reasons.join("; ")
                    ),
                    format_args!("workspace non-return proof is incomplete"),
                    reasons.iter(),
                ),
            );
        }
        for call in &procedure.nonreturn_candidates {
            if !workspace_call_proves_nonreturn(call, &proven) {
                continue;
            }
            match modeled_normal_control_edge(procedure.handle.semantics(), call.call) {
                Ok(Some(edge)) => derived
                    .omissions
                    .push(FlowControlEdgeOmission::new(procedure.handle.id(), edge)),
                Ok(None) => {}
                Err(detail) => derived.push_incomplete(Some(procedure.handle.id()), detail),
            }
        }
    }
    derived
}

/// Derive state events and flow relations for every procedure one file lowers.
///
/// The acquisition path is the one the `cfg-*` query steps use: materialize the
/// file's program semantics through the workspace, then read the immutable
/// artifact. Nothing else is consulted for a relation.
pub fn flow_state_for_file(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    request: &mut FlowStateRequest<'_>,
) -> FileFlowState {
    let analyzer = workspace.analyzer();
    let _semantic_model_scope = request
        .active_semantic_model_snapshot
        .as_ref()
        .map(|snapshot| {
            AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, snapshot.clone())
        });
    let generation = analyzer.project().analysis_generation();
    let active_snapshot = request
        .active_semantic_model_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.as_ref())
        .cloned();
    let active_models = active_snapshot
        .as_ref()
        .map(|snapshot| snapshot.active_models().as_ref());
    let active_model_set_hash =
        active_models.map(|models| Box::<str>::from(models.active_model_set_hash()));
    let mut budget = match SemanticBudget::new(SemanticWork::default_limits()) {
        Ok(budget) => budget,
        Err(error) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=provider:budget_configuration",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                generation,
                active_model_set_hash,
                EXECUTION_STOP,
            );
        }
    };
    let outcome = workspace.materialize_program_semantics(
        file,
        &mut SemanticRequest::new(&mut budget, request.cancellation),
    );
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=provider:semantic detail={error:?}",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                generation,
                active_model_set_hash,
                EXECUTION_STOP,
            );
        }
    };

    flow_state_for_materialized_outcome(
        workspace,
        file,
        outcome,
        None,
        generation,
        active_snapshot,
        active_model_set_hash,
        &mut budget,
        request,
        None,
    )
}

/// Derive one file's flow state with a captured model snapshot and default
/// request controls.
pub fn flow_state_for_file_with_snapshot(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
) -> FileFlowState {
    let token = cancellation.cloned().unwrap_or_default();
    let mut request = FlowStateRequest::new(
        &token,
        FlowStateRequestMemos::new(workspace.retention_budget()),
    )
    .with_active_semantic_model_snapshot(active_semantic_model_snapshot);
    flow_state_for_file(workspace, file, &mut request)
}

/// Derive state events and flow relations from one artifact outcome the caller
/// already materialized.
///
/// Semantic handles are scoped to one immutable artifact allocation. A caller
/// that will join these rows back to handles from an existing outcome must
/// pass that exact outcome here instead of materializing the same durable key
/// again: complete-cache eviction and partial outcomes may otherwise produce
/// equal keys backed by different allocations, for which handle identity is
/// intentionally not interchangeable.
pub fn flow_state_for_materialized_artifact(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    request: &mut FlowStateRequest<'_>,
) -> FileFlowState {
    flow_state_for_materialized_fresh_budget(workspace, file, outcome, None, request, None)
}

/// Derive all procedures while reusing one query's ICFG provider, charging
/// the caller's semantic ledger (a `FlowStateOperation`'s, for a retained one).
pub fn flow_state_for_materialized_artifact_with_provider(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    request: &mut FlowStateRequest<'_>,
    semantic_budget: &mut SemanticBudget,
    provider: &WorkspaceIcfgProvider<'_>,
) -> FileFlowState {
    flow_state_for_materialized_selection(
        workspace,
        file,
        outcome,
        None,
        request,
        semantic_budget,
        Some(provider),
    )
}

/// Derive state events and flow relations for one procedure from the exact
/// artifact outcome that minted its handle.
///
/// Result-contract success-guard projection already owns such a handle and
/// needs no facts from sibling procedures. Keeping this as a distinct entry
/// point preserves full-file row enumeration for ordinary `cfg-*` queries and
/// capture-sensitive use validation while avoiding unrelated dominator and
/// reaching-definition work for that local proof.
pub fn flow_state_for_materialized_procedure(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    procedure: &ProcedureHandle,
    request: &mut FlowStateRequest<'_>,
) -> FileFlowState {
    if let Some(artifact) = outcome.available_value() {
        assert!(
            Arc::ptr_eq(artifact, procedure.artifact()),
            "procedure-scoped flow state requires a handle from the supplied artifact allocation"
        );
    }

    flow_state_for_materialized_fresh_budget(
        workspace,
        file,
        outcome,
        Some(procedure),
        request,
        None,
    )
}

/// Derive one exact procedure while reusing one query's ICFG provider,
/// charging the caller's semantic ledger.
pub fn flow_state_for_materialized_procedure_with_provider(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    procedure: &ProcedureHandle,
    request: &mut FlowStateRequest<'_>,
    semantic_budget: &mut SemanticBudget,
    provider: &WorkspaceIcfgProvider<'_>,
) -> FileFlowState {
    if let Some(artifact) = outcome.available_value() {
        assert!(Arc::ptr_eq(artifact, procedure.artifact()));
    }
    flow_state_for_materialized_selection(
        workspace,
        file,
        outcome,
        Some(procedure),
        request,
        semantic_budget,
        Some(provider),
    )
}

/// Prove only the reaching relations of the property read at one exact point.
/// This is a new scope, not a filter over aggregate completeness. The source
/// derivation and its diagnostics are never modified. Unknown stored values
/// remain their original handles; this proves storage, not scalar contents.
pub fn flow_state_for_selected_property(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    state: &FileFlowState,
    procedure: &ProcedureHandle,
    point: ProgramPointId,
    request: &mut FlowStateRequest<'_>,
) -> FileFlowState {
    let Some(original) = state
        .procedures
        .iter()
        .find(|row| row.procedure == procedure.id())
    else {
        return FileFlowState::incomplete(
            vec![FlowStateIncompleteReason::PropertyAnalysisPartial {
                detail: "selected procedure has no flow-state derivation".into(),
            }],
            state.generation,
            state.active_model_set_hash.clone(),
            state.reuse,
        );
    };
    assert!(
        Weak::ptr_eq(
            &original.procedure_artifact,
            &Arc::downgrade(procedure.artifact())
        ),
        "selected property requires the exact materialized artifact"
    );
    debug_assert!(original.events.iter().all(|event| &event.site.file == file));
    let analyzer = workspace.analyzer();
    let _scope = request
        .active_semantic_model_snapshot
        .as_ref()
        .map(|snapshot| {
            AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, snapshot.clone())
        });
    let mut reasons = state.completeness.reasons().to_vec();
    let mut reuse = state.reuse;
    let selected_model_hash = request
        .active_semantic_model_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.as_ref())
        .map(|snapshot| snapshot.active_models().active_model_set_hash());
    if state.active_model_set_hash() != selected_model_hash {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=snapshot:models",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
        reasons.push(FlowStateIncompleteReason::PropertyProviderFailed {
            detail: "selected property activation differs from the event projection".into(),
        });
    }
    if analyzer.project().analysis_generation() != state.generation {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=snapshot",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
        reasons.push(FlowStateIncompleteReason::SourceGenerationChanged);
    }
    // These are acquisition/control failures, independent of a property
    // subject. Aggregate memory/lowering reasons are checked by the selected
    // provider against their original semantic identities below. A snapshot
    // budget stop also withheld the original event endpoints: a fresh
    // snapshot cannot repair that event projection, so its cause stays.
    reasons.extend(
        original
            .completeness
            .reasons()
            .iter()
            .filter(|reason| {
                reason.blocks(FlowStateAxis::PropertyReachingRelation)
                    && !matches!(
                        reason,
                        FlowStateIncompleteReason::LoweringGap { .. }
                            | FlowStateIncompleteReason::PropertyBaseNotCanonical { .. }
                            | FlowStateIncompleteReason::PropertyReaching { .. }
                            | FlowStateIncompleteReason::PropertyProviderUnavailable
                            | FlowStateIncompleteReason::PropertyProviderFailed { .. }
                            | FlowStateIncompleteReason::PropertyAnalysisPartial { .. }
                    )
            })
            .cloned(),
    );
    // No selected relation can join to an aggregate projection that withheld
    // every property endpoint. Do not acquire or solve another snapshot for
    // each point; cancellation is still observed as a separate typed stop.
    if original.completeness.reasons().iter().any(|reason| {
        matches!(
            reason,
            FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { .. }
        )
    }) {
        analyzer.mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
        if let Err(reason) =
            crate::analyzer::semantic::selected_property_read_event_index(procedure, point)
        {
            reasons.push(FlowStateIncompleteReason::PropertyReaching { reason });
        }
        if request.cancellation.is_cancelled() {
            reasons.push(FlowStateIncompleteReason::Cancelled);
        }
        return FileFlowState::incomplete(
            reasons,
            state.generation,
            state.active_model_set_hash.clone(),
            reuse,
        );
    }
    let mut derived = original.clone();
    derived.relations.clear();
    let outcome = workspace.semantic_oracle_provider().procedure_relations(
        procedure,
        &OracleCallContext::empty(),
        &mut SemanticRequest::new(&mut SemanticBudget::default(), request.cancellation),
    );
    match outcome {
        Err(error) => reasons.push(FlowStateIncompleteReason::PropertyProviderFailed {
            detail: error.to_string(),
        }),
        Ok(outcome) => {
            let verdict = semantic_outcome_verdict(&outcome);
            if !verdict.is_content() {
                analyzer.mark_execution_dependent();
                reuse.join_in(verdict);
                if let Err(reason) =
                    crate::analyzer::semantic::selected_property_read_event_index(procedure, point)
                {
                    reasons.push(FlowStateIncompleteReason::PropertyReaching { reason });
                }
            }
            if !matches!(outcome, SemanticOutcome::Complete { .. }) {
                reasons.push(
                    semantic_outcome_stop_reason(&outcome, FlowStateAxis::PropertyReachingRelation)
                        .unwrap_or_else(|| FlowStateIncompleteReason::PropertyAnalysisPartial {
                            detail: format!(
                                "selected property acquisition is `{}`",
                                outcome_label(&outcome)
                            ),
                        }),
                );
            }
            // A stopped snapshot may omit stores and therefore kill facts;
            // even a retained may-reaching pair need not hold in the full graph.
            if verdict.is_content()
                && let Some(snapshot) = outcome.available_value()
            {
                let graph =
                    ProjectedProcedureGraph::new(procedure.semantics(), &derived.control_edge_mask);
                let selected =
                    crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
                        snapshot,
                        &graph,
                        procedure.semantics().entry_point(),
                        point,
                        PropertyReachingLimits {
                            cfg_work: request.cfg_budget.limits(),
                            ..PropertyReachingLimits::default()
                        },
                        request.cancellation,
                    );
                reasons.extend(selected.incomplete_reasons().iter().cloned().map(|reason| {
                    FlowStateIncompleteReason::PropertyReaching {
                        reason: Box::new(reason),
                    }
                }));
                // Check every selected modeled endpoint, even a dead store
                // that contributes no reaching row. Missing joins remain
                // explicit rather than silently shrinking the proof domain.
                for (class, point, event_index, source) in selected
                    .stores()
                    .iter()
                    .map(|row| {
                        (
                            StateEventClass::Establish,
                            row.point.id(),
                            row.event_index,
                            row.source,
                        )
                    })
                    .chain(selected.reads().iter().map(|row| {
                        (
                            StateEventClass::Read,
                            row.point.id(),
                            row.event_index,
                            row.source,
                        )
                    }))
                {
                    if !derived.skipped_copies.contains((point, event_index))
                        && property_event_id(
                            &derived.events,
                            &derived.event_keys,
                            class,
                            point,
                            event_index,
                            source,
                        )
                        .is_none()
                    {
                        reasons.push(
                            FlowStateIncompleteReason::SelectedPropertyEndpointUnavailable {
                                point,
                                event_index,
                                source,
                            },
                        );
                    }
                }
                derived.relations = property_reaching_relations(
                    &derived.events,
                    &derived.event_keys,
                    &selected,
                    &derived.skipped_copies,
                    state.generation,
                );
            }
        }
    }
    if analyzer.project().analysis_generation() != state.generation {
        reasons.push(FlowStateIncompleteReason::SourceGenerationChanged);
    }
    // Acquisition can retain a budget outcome when cancellation arrives
    // after that refusal. Observe the request independently at completion.
    if request.cancellation.is_cancelled() {
        analyzer.mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
        if !reasons.contains(&FlowStateIncompleteReason::Cancelled) {
            reasons.push(FlowStateIncompleteReason::Cancelled);
        }
        derived.relations.clear();
    }
    derived.completeness = FlowStateCompleteness::from_reasons(reasons.clone());
    FileFlowState {
        procedures: vec![derived],
        completeness: FlowStateCompleteness::from_reasons(reasons),
        generation: state.generation,
        active_model_set_hash: state.active_model_set_hash.clone(),
        reuse,
    }
}

/// The one selection body. Every materialized entry point funnels here with
/// the semantic ledger it wants this derivation charged to.
fn flow_state_for_materialized_selection(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    selected_procedure: Option<&ProcedureHandle>,
    request: &mut FlowStateRequest<'_>,
    budget: &mut SemanticBudget,
    provider: Option<&WorkspaceIcfgProvider<'_>>,
) -> FileFlowState {
    let analyzer = workspace.analyzer();
    let _semantic_model_scope = request
        .active_semantic_model_snapshot
        .as_ref()
        .map(|snapshot| {
            AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, snapshot.clone())
        });
    let generation = analyzer.project().analysis_generation();
    let active_snapshot = request
        .active_semantic_model_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.as_ref())
        .cloned();
    let active_model_set_hash = active_snapshot
        .as_ref()
        .map(|snapshot| Box::<str>::from(snapshot.active_models().active_model_set_hash()));
    flow_state_for_materialized_outcome(
        workspace,
        file,
        outcome,
        selected_procedure,
        generation,
        active_snapshot,
        active_model_set_hash,
        budget,
        request,
        provider,
    )
}

/// The legacy direct entry points keep one fresh semantic grant per call,
/// even when a standalone caller reuses one request across derivations.
fn flow_state_for_materialized_fresh_budget(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    selected_procedure: Option<&ProcedureHandle>,
    request: &mut FlowStateRequest<'_>,
    provider: Option<&WorkspaceIcfgProvider<'_>>,
) -> FileFlowState {
    let mut budget = match SemanticBudget::new(SemanticWork::default_limits()) {
        Ok(budget) => budget,
        Err(error) => {
            let analyzer = workspace.analyzer();
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=provider:budget_configuration",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
            let active_model_set_hash = request
                .active_semantic_model_snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.as_ref())
                .map(|snapshot| Box::<str>::from(snapshot.active_models().active_model_set_hash()));
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                analyzer.project().analysis_generation(),
                active_model_set_hash,
                EXECUTION_STOP,
            );
        }
    };
    flow_state_for_materialized_selection(
        workspace,
        file,
        outcome,
        selected_procedure,
        request,
        &mut budget,
        provider,
    )
}

/// Every flow-state derivation ends here. A cancelled token makes the result
/// an execution stop on EVERY return path, including the early returns and the
/// paths that only abandon optional work silently (the nonreturn projection
/// returns an empty derivation on cancellation) or record a bare `Cancelled`
/// reason without a verdict. Reason rows are unchanged.
#[allow(clippy::too_many_arguments)]
fn flow_state_for_materialized_outcome(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    selected_procedure: Option<&ProcedureHandle>,
    generation: u64,
    active_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    active_model_set_hash: Option<Box<str>>,
    budget: &mut SemanticBudget,
    request: &mut FlowStateRequest<'_>,
    provider: Option<&WorkspaceIcfgProvider<'_>>,
) -> FileFlowState {
    let mut state = derive_flow_state_for_materialized_outcome(
        workspace,
        file,
        outcome,
        selected_procedure,
        generation,
        active_snapshot,
        active_model_set_hash,
        budget,
        request,
        provider,
    );
    if request.cancellation.is_cancelled() {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=cancelled",
                file!(),
                line!()
            )
        });
        workspace.analyzer().mark_execution_dependent();
        state.reuse.join_in(EXECUTION_STOP);
    }
    state
}

#[allow(clippy::too_many_arguments)]
fn derive_flow_state_for_materialized_outcome(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    selected_procedure: Option<&ProcedureHandle>,
    generation: u64,
    active_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    active_model_set_hash: Option<Box<str>>,
    budget: &mut SemanticBudget,
    request: &mut FlowStateRequest<'_>,
    provider: Option<&WorkspaceIcfgProvider<'_>>,
) -> FileFlowState {
    let requested_procedure = selected_procedure.map(ProcedureHandle::id);
    let analyzer = workspace.analyzer();
    let active_models = active_snapshot
        .as_ref()
        .map(|snapshot| snapshot.active_models().as_ref());
    // Both ledgers may be shared with earlier derivations (a retained
    // `FlowStateOperation`). Only a refusal this derivation itself caused is
    // its own cause; an outer query's recorded stop stays sticky through the
    // analyzer's execution-dependence marks.
    let cfg_refusals_at_entry = request.cfg_budget.refusal_count();
    let semantic_refusals_at_entry = budget.refusal_count();

    let mut reuse = semantic_outcome_verdict(&outcome);
    if !reuse.is_content() {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause={}",
                file!(),
                line!(),
                if matches!(&outcome, SemanticOutcome::Cancelled { .. }) {
                    "cancelled"
                } else {
                    "budget:semantic"
                }
            )
        });
        analyzer.mark_execution_dependent();
    }
    if let Some(artifact) = outcome.available_value()
        && artifact.procedures().iter().any(|procedure| {
            procedure.gaps().iter().any(|gap| {
                matches!(
                    gap.kind,
                    crate::analyzer::semantic::SemanticGapKind::ExceededBudget
                )
            })
        })
    {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=budget:semantic_artifact",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
    }
    let mut file_reasons = Vec::new();
    match &outcome {
        SemanticOutcome::Complete { .. } => {}
        SemanticOutcome::Cancelled { .. } => {
            file_reasons.push(FlowStateIncompleteReason::Cancelled)
        }
        SemanticOutcome::Unsupported { capability, .. } => {
            file_reasons.push(FlowStateIncompleteReason::SemanticAnalysisPartial {
                detail: format!(
                    "semantic capability `{}` is unsupported",
                    capability.label()
                ),
            });
        }
        SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unproven { .. }
        | SemanticOutcome::ExceededBudget { .. } => {
            file_reasons.push(FlowStateIncompleteReason::SemanticAnalysisPartial {
                detail: format!("semantic lowering outcome is `{}`", outcome_label(&outcome)),
            });
        }
    }
    let Some(artifact) = outcome.available_value().cloned() else {
        file_reasons.push(FlowStateIncompleteReason::NoSemanticProvider);
        return FileFlowState::incomplete(file_reasons, generation, active_model_set_hash, reuse);
    };

    let Some(facts) = structural_facts(analyzer, file) else {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=provider:structural_facts",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        file_reasons.push(FlowStateIncompleteReason::NoStructuralFacts);
        return FileFlowState::incomplete(
            file_reasons,
            generation,
            active_model_set_hash,
            reuse.join(EXECUTION_STOP),
        );
    };
    if facts.source_identity() != artifact.key().revision().content() {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=snapshot",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        file_reasons.push(FlowStateIncompleteReason::SourceGenerationChanged);
        return FileFlowState::incomplete(
            file_reasons,
            generation,
            active_model_set_hash,
            reuse.join(EXECUTION_STOP),
        );
    }
    let site_index = {
        let _scope = profiling::scope("flow.site_index");
        SiteIndex::build(&facts)
    };
    let selected_procedures_have_suspend = artifact.procedures().iter().any(|procedure| {
        requested_procedure.is_none_or(|requested| procedure.id() == requested)
            && procedure.points().iter().any(|point| {
                point
                    .events
                    .iter()
                    .any(|event| matches!(event.effect, SemanticEffect::AsyncSuspend { .. }))
            })
    });
    let scope_frame_projection = if crate::analyzer::common::language_for_file(file)
        == Language::Rust
        && selected_procedures_have_suspend
    {
        match rust_scope_frame_facts(analyzer, file, &facts) {
            Ok(facts) => ScopeFrameProjection::Ready(facts),
            Err(detail) => ScopeFrameProjection::Unavailable(detail),
        }
    } else {
        ScopeFrameProjection::NotApplicable
    };

    let mut modeled_projection =
        active_models.map_or_else(ModeledControlProjectionDerivation::default, |models| {
            let _scope = profiling::scope("flow.modeled_control_projection");
            derive_modeled_control_projection(
                analyzer,
                file,
                &facts,
                &artifact,
                requested_procedure,
                models,
                request.cancellation,
            )
        });
    let language = crate::analyzer::common::language_for_file(file);
    let python_has_modeled_or_source_nonreturn = language == Language::Python
        && python_has_local_nonreturn_candidate(&artifact, requested_procedure);
    let go_has_nonreturn_models = active_snapshot.as_ref().is_some_and(|snapshot| {
        go_has_normal_continuation_absence_candidates(snapshot.active_models())
    });
    if python_has_modeled_or_source_nonreturn
        || (language == Language::Go && go_has_nonreturn_models)
    {
        // The optional control proof obeys the request's CFG limits but owns a
        // separate ledger. Exhausting wrapper discovery must retain raw edges;
        // it must not consume the budget for the ordinary flow relations that
        // remain valid without this precision improvement.
        //
        // A lent operation owns this ledger across derivations (its recorded
        // spending is the only provenance of "pristine"); a standalone request
        // keeps the per-call clone, byte for byte as before.
        let mut per_call_budget;
        let optional_at_entry = request.nonreturn_cfg_budget.as_ref().map(|owned| {
            (
                owned.used() != CfgAlgorithmWork::default(),
                owned.refusal_count(),
            )
        });
        let nonreturn_cfg_budget = match request.nonreturn_cfg_budget.as_mut() {
            Some(owned) => owned,
            None => {
                per_call_budget = request.cfg_budget.clone();
                &mut per_call_budget
            }
        };
        let _scope = profiling::scope("flow.workspace_nonreturn_projection");
        modeled_projection.extend(derive_workspace_nonreturn_projection(
            workspace,
            file,
            &artifact,
            requested_procedure,
            active_snapshot.as_ref(),
            budget,
            nonreturn_cfg_budget,
            request.cancellation,
            provider,
            request.nonreturn_discovery_cache,
        ));
        // A refusal on an owned ledger that earlier derivations already spent
        // depends on those seeds, not on this file's content: an execution
        // stop. A refusal from a ledger with no recorded spending is what the
        // legacy whole-file pass would have produced too: the reason stays
        // Content-incomplete. The delta is relative to entry, so an earlier
        // seed's refusal never becomes this derivation's cause.
        if let (Some((spent_at_entry, refusals_at_entry)), Some(owned)) =
            (optional_at_entry, request.nonreturn_cfg_budget.as_ref())
            && spent_at_entry
            && owned.refusal_count() > refusals_at_entry
        {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=budget:nonreturn_shared",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
            reuse.join_in(EXECUTION_STOP);
        }
    }
    file_reasons.extend(modeled_projection.file_reasons);
    let mut procedure_projection_reasons = modeled_projection.procedure_reasons;

    let requested_projection = request
        .control_projection
        .filter(|projection| !projection.is_empty());
    let combined_projection =
        if requested_projection.is_some() || !modeled_projection.omissions.is_empty() {
            Some(FlowControlProjection::new(
                requested_projection
                    .map(|projection| projection.artifact().clone())
                    .unwrap_or_else(|| artifact.key().clone()),
                requested_projection
                    .into_iter()
                    .flat_map(FlowControlProjection::omitted_normal_edges)
                    .copied()
                    .chain(modeled_projection.omissions),
            ))
        } else {
            None
        };
    let mut control_edge_masks = match combined_projection.as_ref() {
        Some(projection) => match validated_control_edge_masks(&artifact, projection) {
            Ok(masks) => masks,
            Err(reason) => {
                file_reasons.push(reason);
                HashMap::default()
            }
        },
        None => HashMap::default(),
    };

    let derive_selected_procedures_scope = profiling::scope("flow.derive_selected_procedures");
    let procedures = artifact
        .procedures()
        .iter()
        .filter(|procedure| requested_procedure.is_none_or(|requested| procedure.id() == requested))
        .map(|base| {
            // Whole-artifact enumeration explicitly selects base interpretations.
            let handle = selected_procedure.cloned().unwrap_or_else(|| {
                artifact
                    .procedure_handle(base.id())
                    .expect("artifact owns procedure")
            });
            let procedure = handle.semantics();
            let procedure_reasons = procedure_projection_reasons
                .remove(&procedure.id())
                .map_or_else(
                    || file_reasons.clone(),
                    |reasons| file_reasons.iter().cloned().chain(reasons).collect(),
                );
            let (derivation, procedure_reuse) = derive_procedure(
                workspace,
                &handle,
                file,
                &facts,
                &site_index,
                &scope_frame_projection,
                generation,
                &procedure_reasons,
                control_edge_masks
                    .remove(&procedure.id())
                    .unwrap_or_default(),
                request,
                budget,
            );
            reuse.join_in(procedure_reuse);
            derivation
        })
        .collect();
    drop(derive_selected_procedures_scope);

    let cfg_refused = request.cfg_budget.refusal_count() > cfg_refusals_at_entry;
    let semantic_refused = budget.refusal_count() > semantic_refusals_at_entry;
    if cfg_refused || semantic_refused {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=budget:flow_derivation cfg={cfg_refused} semantic={semantic_refused}",
                file!(),
                line!(),
            )
        });
        analyzer.mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
    }
    FileFlowState {
        procedures,
        completeness: FlowStateCompleteness::from_reasons(file_reasons),
        generation,
        active_model_set_hash,
        reuse,
    }
}

type SourceByteSpan = (usize, usize);

struct ScopeFrameBinding {
    activation: SourceByteSpan,
    scope: SourceByteSpan,
    move_uses: Vec<SourceByteSpan>,
}

struct RustScopeFrameFacts {
    bindings: HashMap<SourceByteSpan, ScopeFrameBinding>,
}

enum ScopeFrameProjection {
    NotApplicable,
    Ready(RustScopeFrameFacts),
    Unavailable(String),
}

/// Build one request-local Rust liveness projection from the existing lexical
/// environment plus AST-resolved by-value uses. The move classification is
/// intentionally syntactic: a `Copy` local may look moved, and consumers of
/// scope-only reads must also select bindings by initializer identity.
fn rust_scope_frame_facts(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    facts: &brokk_bifrost_analysis::analyzer::structural::facts::FileFacts,
) -> Result<RustScopeFrameFacts, String> {
    let environment = environment_for_file(analyzer, file);
    for axis in [EnvironmentAxis::Scopes, EnvironmentAxis::BindingIntervals] {
        if !environment.completeness.covers(axis) {
            return Err(format!(
                "Rust lexical environment does not cover {axis:?}: {:?}",
                environment.completeness
            ));
        }
    }
    let environment_identity = environment
        .scopes
        .first()
        .map(|scope| scope.content_identity)
        .or_else(|| {
            environment
                .bindings
                .first()
                .map(|binding| binding.content_identity)
        });
    if environment_identity != Some(facts.source_identity()) {
        return Err("Rust lexical environment describes different source content".into());
    }
    let tree = parse_tree_for_language(file, Language::Rust, facts.source())
        .ok_or_else(|| "Rust syntax tree is unavailable for move-use projection".to_string())?;

    let mut move_uses = HashMap::<SourceByteSpan, HashSet<SourceByteSpan>>::default();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && is_rust_by_value_binding_use(node) {
            let span = (node.start_byte(), node.end_byte());
            let name = facts
                .source()
                .get(span.0..span.1)
                .expect("Rust identifier node ranges are within the parsed source");
            let binding = match binding_of(&environment, name, span.0, Some(Namespace::Value)) {
                BindingOfOutcome::Reached(binding) => Some(binding),
                BindingOfOutcome::Shadowed { winner, .. } => Some(winner),
                BindingOfOutcome::NoBinding => None,
                BindingOfOutcome::Incomplete(axis) => {
                    return Err(format!(
                        "Rust binding-of is incomplete for a by-value use: {axis:?}"
                    ));
                }
            };
            if let Some(binding) = binding {
                let declaration = &environment.bindings[binding].range;
                move_uses
                    .entry((declaration.start_byte, declaration.end_byte))
                    .or_default()
                    .insert(span);
            }
        }
        for child_index in (0..node.child_count()).rev() {
            if let Some(child) = node.child(child_index) {
                stack.push(child);
            }
        }
    }

    let bindings = environment
        .bindings
        .iter()
        .map(|binding| {
            let scope = environment.scope(binding.declaring_scope);
            let mut binding_moves = move_uses
                .remove(&(binding.range.start_byte, binding.range.end_byte))
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            binding_moves.sort_unstable();
            (
                (binding.range.start_byte, binding.range.end_byte),
                ScopeFrameBinding {
                    activation: (binding.activation.start_byte, binding.activation.end_byte),
                    scope: (scope.range.start_byte, scope.range.end_byte),
                    move_uses: binding_moves,
                },
            )
        })
        .collect();
    Ok(RustScopeFrameFacts { bindings })
}

/// Whether this identifier is the whole value consumed by one of the Rust
/// constructs whose by-value behavior matters to future-frame liveness.
/// Parentheses are transparent; references and method receivers remain
/// distinct AST shapes and therefore do not qualify.
fn is_rust_by_value_binding_use(identifier: Node<'_>) -> bool {
    let mut value = identifier;
    loop {
        let Some(parent) = value.parent() else {
            return false;
        };
        if parent.kind() == "parenthesized_expression"
            && parent.named_child_count() == 1
            && parent
                .named_child(0)
                .is_some_and(|child| child.id() == value.id())
        {
            value = parent;
            continue;
        }
        return match parent.kind() {
            "arguments" => parent.parent().is_some_and(|call| {
                call.kind() == "call_expression"
                    && call
                        .child_by_field_name("arguments")
                        .is_some_and(|arguments| arguments.id() == parent.id())
            }),
            "let_declaration" | "assignment_expression" => {
                let field = if parent.kind() == "let_declaration" {
                    "value"
                } else {
                    "right"
                };
                parent
                    .child_by_field_name(field)
                    .is_some_and(|right| right.id() == value.id())
            }
            "return_expression" | "base_field_initializer" => {
                parent.named_child_count() == 1
                    && parent
                        .named_child(0)
                        .is_some_and(|child| child.id() == value.id())
            }
            "field_initializer" => parent
                .child_by_field_name("value")
                .is_some_and(|field_value| field_value.id() == value.id()),
            "shorthand_field_initializer" => {
                parent.named_child_count() == 1
                    && parent
                        .named_child(0)
                        .is_some_and(|field_value| field_value.id() == value.id())
            }
            _ => false,
        };
    }
}

fn validated_control_edge_masks(
    artifact: &SemanticArtifact,
    projection: &FlowControlProjection,
) -> Result<HashMap<ProcedureId, ControlEdgeMask>, FlowStateIncompleteReason> {
    if projection.artifact() != artifact.key() {
        return Err(FlowStateIncompleteReason::ControlProjectionRejected {
            detail: format!(
                "control projection artifact key {:?} does not match materialized artifact {:?}",
                projection.artifact(),
                artifact.key()
            ),
        });
    }

    let invalid = projection
        .omitted_normal_edges()
        .iter()
        .copied()
        .filter(|omission| {
            artifact
                .procedure(omission.procedure)
                .and_then(|procedure| procedure.control_edge(omission.edge))
                .is_none_or(|edge| edge.kind != ControlEdgeKind::Normal)
        })
        .collect::<Vec<_>>();
    if !invalid.is_empty() {
        return Err(FlowStateIncompleteReason::ControlProjectionRejected {
            detail: format!(
                "control projection named missing or non-normal procedure-local edges: {invalid:?}"
            ),
        });
    }

    let mut by_procedure = HashMap::<ProcedureId, Vec<ControlEdgeId>>::default();
    for omission in projection.omitted_normal_edges() {
        by_procedure
            .entry(omission.procedure)
            .or_default()
            .push(omission.edge);
    }
    Ok(by_procedure
        .into_iter()
        .map(|(procedure, omitted)| {
            let semantics = artifact
                .procedure(procedure)
                .expect("validated control projection procedure exists");
            (procedure, ControlEdgeMask::new(semantics, omitted))
        })
        .collect())
}

fn outcome_label<T>(outcome: &SemanticOutcome<T>) -> &'static str {
    outcome.label()
}

fn structural_facts(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<Arc<brokk_bifrost_analysis::analyzer::structural::facts::FileFacts>> {
    let language = crate::analyzer::common::language_for_file(file);
    analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file))
}

/// Exact byte-span to facts-arena identity lookup for one file.
///
/// The lookup is exact, not heuristic: the facts snapshot and the semantic
/// artifact describe the same analyzed content, so span equality over it is a
/// join, not a guess. When several arena nodes carry the same span the
/// innermost wins, because facts are stored in preorder and the innermost node
/// is the token the lowering anchored on.
struct SiteIndex {
    by_span: HashMap<(usize, usize), u32>,
    identity: ContentIdentity,
}

impl SiteIndex {
    fn build(facts: &brokk_bifrost_analysis::analyzer::structural::facts::FileFacts) -> Self {
        let mut by_span = HashMap::default();
        for (node, fact) in facts.nodes().iter().enumerate() {
            by_span.insert((fact.range.start_byte, fact.range.end_byte), node as u32);
        }
        Self {
            by_span,
            identity: facts.source_identity(),
        }
    }

    fn ast_id(&self, span: SourceSpan) -> Option<String> {
        self.by_span
            .get(&(span.start_byte() as usize, span.end_byte() as usize))
            .map(|node| ast_id(self.identity, *node))
    }
}

/// One procedure's derivation.
#[allow(clippy::too_many_arguments)]
fn derive_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure_handle: &ProcedureHandle,
    file: &ProjectFile,
    facts: &brokk_bifrost_analysis::analyzer::structural::facts::FileFacts,
    site_index: &SiteIndex,
    scope_frame_projection: &ScopeFrameProjection,
    generation: u64,
    file_reasons: &[FlowStateIncompleteReason],
    control_edge_mask: ControlEdgeMask,
    request: &mut FlowStateRequest<'_>,
    semantic_budget: &mut SemanticBudget,
) -> (FlowStateDerivation, ReuseVerdict) {
    let artifact = procedure_handle.artifact();
    let procedure = procedure_handle.semantics();
    let mut reasons = file_reasons.to_vec();
    collect_capability_reasons(artifact.capabilities(), &mut reasons);
    collect_gap_reasons(procedure, &mut reasons);

    let properties_available = artifact
        .capabilities()
        .support(SemanticCapability::FieldMemory)
        != CapabilitySupport::Unsupported;

    let procedure_artifact = Arc::downgrade(procedure_handle.artifact());
    let (property_result, reuse) = if properties_available {
        let (property, reuse) = materialize_property_reaching(
            workspace,
            procedure_handle,
            &control_edge_mask,
            request,
            semantic_budget,
        );
        let property = match property {
            Ok(result) => {
                for reason in result.incomplete_reasons() {
                    reasons.push(FlowStateIncompleteReason::PropertyReaching {
                        reason: Box::new(reason.clone()),
                    });
                }
                Some(result)
            }
            Err(FlowStateIncompleteReason::BudgetExhausted { detail, .. }) => {
                // Preserve property provenance for scoped binding proofs.
                reasons.push(FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { detail });
                None
            }
            Err(reason) => {
                reasons.push(reason);
                None
            }
        };
        (property, reuse)
    } else {
        (None, ReuseVerdict::Content)
    };
    let mut builder = EventBuilder {
        procedure: procedure.id(),
        procedure_handle: procedure_handle.clone(),
        file,
        facts,
        site_index,
        scope_frame_projection,
        generation,
        events: Vec::new(),
        event_keys: Vec::new(),
        uncanonical_accesses: 0,
        properties_available,
        skipped_copies: SkippedCopies::default(),
    };
    reasons.extend(
        builder
            .collect(procedure, property_result.as_ref())
            .into_iter()
            .map(|detail| FlowStateIncompleteReason::BindingScopeLivenessUnavailable { detail }),
    );
    let uncanonical_accesses = builder.uncanonical_accesses;
    let mut events = builder.events;
    let mut event_keys = builder.event_keys;

    if uncanonical_accesses > 0 {
        reasons.push(FlowStateIncompleteReason::PropertyBaseNotCanonical {
            accesses: uncanonical_accesses,
        });
    }
    if !properties_available {
        reasons.extend(
            property_axes()
                .iter()
                .copied()
                .map(FlowStateIncompleteReason::AxisUnsupported),
        );
    }

    let skipped_copies = builder.skipped_copies;
    append_kill_events(
        &mut events,
        &mut event_keys,
        property_result.as_ref(),
        &skipped_copies,
    );
    let unestablished = unestablished_local_bindings(procedure, &events);
    if unestablished > 0 {
        reasons.push(FlowStateIncompleteReason::BindingWithoutEstablishment {
            bindings: unestablished,
        });
    }

    let (relations, dominance, mut binding_initialization) = derive_relations(
        procedure,
        &control_edge_mask,
        &events,
        &event_keys,
        property_result.as_ref(),
        &skipped_copies,
        generation,
        request,
        &mut reasons,
    );
    if crate::analyzer::common::language_for_file(file) == Language::Python
        && let Some(facts) = binding_initialization.as_mut()
    {
        let invalidated_bindings = events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Kill)
            .filter_map(|event| match event.subject {
                FlowSubject::Binding { value } => Some(value),
                FlowSubject::Property { .. } => None,
            })
            .collect::<HashSet<_>>();
        let potentially_uninitialized_reads = facts
            .uninitialized_before_event
            .iter()
            .filter_map(|(&event, &uninitialized)| {
                let row = events.get(event)?;
                let FlowSubject::Binding { value } = row.subject else {
                    return None;
                };
                (uninitialized
                    && row.event_class == StateEventClass::Read
                    && (procedure_handle
                        .semantics()
                        .value(value)
                        .is_some_and(|value| value.kind == SemanticValueKind::Local)
                        || invalidated_bindings.contains(&value)))
                .then_some(event)
            })
            .collect::<HashSet<_>>();
        match correlated_initialization_answers(
            procedure_handle,
            &events,
            &event_keys,
            &control_edge_mask,
            &potentially_uninitialized_reads,
            semantic_budget,
            request.cancellation,
        ) {
            Ok(answers) => {
                for (event, answer) in answers {
                    let previous = facts.correlated_before_event.insert(event, answer);
                    assert!(
                        previous.is_none(),
                        "one source-backed read has one correlated initialization answer"
                    );
                }
            }
            Err(crate::type_flow::CorrelationError::Budget(error)) => {
                reasons.push(FlowStateIncompleteReason::BudgetExhausted {
                    axis: FlowStateAxis::ReachingRelation,
                    detail: format!("path-sensitive binding initialization: {error}"),
                });
            }
            Err(crate::type_flow::CorrelationError::Cancelled { .. }) => {
                reasons.push(FlowStateIncompleteReason::Cancelled);
            }
        }
    }

    let derivation = FlowStateDerivation {
        procedure: procedure.id(),
        events,
        relations,
        completeness: FlowStateCompleteness::from_reasons(reasons),
        generation,
        procedure_artifact,
        dominance,
        control_edge_mask,
        binding_initialization,
        event_keys,
        skipped_copies,
    };
    (derivation, reuse)
}

fn correlated_initialization_answers(
    procedure: &ProcedureHandle,
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    control_edge_mask: &ControlEdgeMask,
    potentially_uninitialized_reads: &HashSet<usize>,
    budget: &mut SemanticBudget,
    cancellation: &CancellationToken,
) -> Result<HashMap<usize, BindingInitializationAnswer>, crate::type_flow::CorrelationError> {
    let semantics = procedure.semantics();
    if potentially_uninitialized_reads.is_empty() {
        return Ok(HashMap::default());
    }
    let invalidated_bindings = events
        .iter()
        .filter(|event| event.event_class == StateEventClass::Kill)
        .filter_map(|event| match event.subject {
            FlowSubject::Binding { value } => Some(value),
            FlowSubject::Property { .. } => None,
        })
        .collect::<HashSet<_>>();
    let candidate_bindings = events
        .iter()
        .filter(|event| {
            potentially_uninitialized_reads.contains(&event.event)
                && event.event_class == StateEventClass::Read
        })
        .filter_map(|event| match event.subject {
            FlowSubject::Binding { value }
                if semantics.value(value).is_some_and(|value| {
                    value.kind == SemanticValueKind::Local
                        || invalidated_bindings.contains(&value.id)
                }) =>
            {
                Some(value)
            }
            FlowSubject::Binding { .. } | FlowSubject::Property { .. } => None,
        })
        .collect::<HashSet<_>>();
    if candidate_bindings.is_empty() {
        return Ok(HashMap::default());
    }
    let uninitialized_entry_bindings = candidate_bindings
        .iter()
        .copied()
        .filter(|&binding| {
            semantics
                .value(binding)
                .is_some_and(|value| value.kind == SemanticValueKind::Local)
        })
        .collect::<HashSet<_>>();
    let mut data_bindings = events
        .iter()
        .filter(|event| {
            matches!(
                event.event_class,
                StateEventClass::Read | StateEventClass::Establish | StateEventClass::Kill
            )
        })
        .filter_map(|event| match event.subject {
            FlowSubject::Binding { value }
                if candidate_bindings.contains(&value)
                    && semantics.value(value).is_some_and(|value| {
                        value.kind == SemanticValueKind::Local
                            || invalidated_bindings.contains(&value.id)
                    }) =>
            {
                Some(value)
            }
            FlowSubject::Property { .. } => None,
            FlowSubject::Binding { .. } => None,
        })
        .collect::<Vec<_>>();
    data_bindings.sort_unstable();
    data_bindings.dedup();
    if data_bindings.is_empty() {
        return Ok(HashMap::default());
    }

    let read_events = events
        .iter()
        .zip(event_keys)
        .filter_map(|(event, key)| {
            if event.event_class != StateEventClass::Read
                || !potentially_uninitialized_reads.contains(&event.event)
            {
                return None;
            }
            let FlowSubject::Binding { value } = event.subject else {
                return None;
            };
            if data_bindings.binary_search(&value).is_err() {
                return None;
            }
            let event_index = key.event_index as usize;
            semantics
                .point(key.point)
                .is_some_and(|point| event_index < point.events.len())
                .then_some((event.event, key.point, event_index, value))
        })
        .collect::<Vec<_>>();
    if read_events.is_empty() {
        return Ok(HashMap::default());
    }
    let correlation_events = semantics
        .points()
        .iter()
        .map(|point| (0..point.events.len()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let bool_bindings = crate::type_flow::guard_condition_bindings(procedure);
    let binding_origins = BindingOriginIndex::new(procedure);
    let mut open_bindings: crate::hash::HashSet<_> = binding_origins
        .address_taken_bindings()
        .into_iter()
        .collect();
    for location in semantics.memory_locations() {
        if let MemoryLocationKind::LexicalCell { binding }
        | MemoryLocationKind::Capture {
            binding: Some(binding),
            ..
        } = &location.kind
        {
            open_bindings.insert(*binding);
        }
    }
    for capture in semantics.captures() {
        if capture.mode != crate::analyzer::semantic::CaptureMode::Value
            && let crate::analyzer::semantic::CaptureSource::Value(binding) = &capture.captured
        {
            open_bindings.insert(*binding);
        }
    }
    let mut omitted_edges = control_edge_mask
        .omitted
        .iter()
        .copied()
        .collect::<Vec<_>>();
    omitted_edges.sort_unstable();
    let mut uncertain_return_edges = Vec::new();
    for gap in semantics.gaps() {
        if gap.capability != SemanticCapability::DynamicDispatch {
            continue;
        }
        let SemanticGapSubject::CallSite(call_id) = gap.subject else {
            continue;
        };
        let Some(call) = semantics.call_site(call_id) else {
            continue;
        };
        if call.invocation_mode != CallInvocationMode::Ordinary {
            continue;
        }
        if gap.kind != SemanticGapKind::Ambiguous
            && matches!(&call.declared_targets, CallableTargetResolution::Proven(_))
        {
            continue;
        }
        let Some(target) = call.normal_continuation.target() else {
            continue;
        };
        let edges = normal_control_edges_to_target(semantics, call.point, target);
        assert_eq!(
            edges.len(),
            1,
            "a represented call continuation maps to one normal CFG edge"
        );
        uncertain_return_edges.push(edges[0]);
    }
    uncertain_return_edges.sort_unstable();
    uncertain_return_edges.dedup();
    let analysis = crate::type_flow::analyze_correlations_with_observations(
        procedure,
        &bool_bindings,
        &data_bindings,
        &open_bindings,
        &uninitialized_entry_bindings,
        &correlation_events,
        &read_events,
        &uncertain_return_edges,
        &omitted_edges,
        budget,
        Some(cancellation),
    )?;
    let mut answers = HashMap::default();
    for row in analysis.data_reaching_at_event {
        let answer = if row.definitions.is_empty() {
            BindingInitializationAnswer::Unreachable
        } else if row.unknown {
            BindingInitializationAnswer::Open {
                reasons: vec![FlowStateIncompleteReason::BindingStateNotClosed {
                    binding: row.binding,
                }],
            }
        } else if row.may_be_uninitialized {
            BindingInitializationAnswer::MayBeUninitialized
        } else {
            BindingInitializationAnswer::Proven
        };
        assert!(answers.insert(row.event, answer).is_none());
    }
    Ok(answers)
}

fn collect_capability_reasons(
    capabilities: &SemanticCapabilities,
    reasons: &mut Vec<FlowStateIncompleteReason>,
) {
    for (capability, axes) in [
        (
            SemanticCapability::Assignments,
            FlowStateAxis::BindingEvents,
        ),
        (
            SemanticCapability::NormalControlFlow,
            FlowStateAxis::ReachingRelation,
        ),
        (
            SemanticCapability::NormalControlFlow,
            FlowStateAxis::DominanceRelation,
        ),
        (
            SemanticCapability::NormalControlFlow,
            FlowStateAxis::PropertyReachingRelation,
        ),
        (
            SemanticCapability::NormalControlFlow,
            FlowStateAxis::PropertyDominanceRelation,
        ),
    ] {
        if capabilities.support(capability) == CapabilitySupport::Unsupported {
            reasons.push(FlowStateIncompleteReason::AxisUnsupported(axes));
        }
    }
}

fn collect_gap_reasons(
    procedure: &ProcedureSemantics,
    reasons: &mut Vec<FlowStateIncompleteReason>,
) {
    for gap in procedure.gaps() {
        if !axes_blocked_by(procedure, gap).is_empty() {
            push_gap_reason(reasons, gap);
        }
    }
}

fn push_gap_reason(reasons: &mut Vec<FlowStateIncompleteReason>, gap: &SemanticGap) {
    if let Some(FlowStateIncompleteReason::LoweringGap { gaps, .. }) = reasons.iter_mut().find(|reason| matches!(reason,
        FlowStateIncompleteReason::LoweringGap { capability, kind, .. } if *capability == gap.capability && *kind == gap.kind
    )) {
        gaps.push(gap.id);
    } else {

        reasons.push(FlowStateIncompleteReason::LoweringGap {
            gaps: vec![gap.id], capability: gap.capability, kind: gap.kind, detail: gap.detail.to_string(),
        });
    }
}

/// The single property-reaching acquisition path for one exact procedure
/// over its unmodified control graph.
///
/// Flow-state derivation and the RQL field access steps both obtain their
/// `PropertyReachingResult` here, so a store or load is classified by one
/// owner. The result's own incompleteness is never summarized away.
pub fn property_reaching_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    request: &FlowStateRequest<'_>,
    semantic_budget: &mut SemanticBudget,
) -> (
    Result<PropertyReachingResult, FlowStateIncompleteReason>,
    ReuseVerdict,
) {
    materialize_property_reaching(
        workspace,
        procedure,
        &ControlEdgeMask::default(),
        request,
        semantic_budget,
    )
}

/// Materialize the analysis-owned property relation for one exact procedure.
///
/// The value-flow snapshot and its structured location identities are owned by
/// `bifrost-analysis`; flow-state only chooses the graph view. A request-local
/// control projection therefore uses the same analysis projection over the
/// masked graph, rather than rebuilding property identity from bindings or
/// source spelling.
fn materialize_property_reaching(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    control_edge_mask: &ControlEdgeMask,
    request: &FlowStateRequest<'_>,
    semantic_budget: &mut SemanticBudget,
) -> (
    Result<PropertyReachingResult, FlowStateIncompleteReason>,
    ReuseVerdict,
) {
    let admissions = semantic_budget.scratch_mark();
    let outcome = match workspace.semantic_oracle_provider().procedure_relations(
        procedure,
        &OracleCallContext::empty(),
        &mut SemanticRequest::new(semantic_budget, request.cancellation),
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=provider:property_relation detail={error:?}",
                    file!(),
                    line!()
                )
            });
            workspace.analyzer().mark_execution_dependent();
            let reason = FlowStateIncompleteReason::PropertyProviderFailed {
                detail: error.to_string(),
            };
            return (Err(reason), EXECUTION_STOP);
        }
    };
    let mut reuse = semantic_outcome_verdict(&outcome);
    if !reuse.is_content() {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause={}",
                file!(),
                line!(),
                if matches!(&outcome, SemanticOutcome::Cancelled { .. }) {
                    "cancelled"
                } else {
                    "budget:semantic"
                }
            )
        });
        workspace.analyzer().mark_execution_dependent();
    }
    // Collection stops refuse: missing MemoryStore rows remove kills and can
    // invent reaching pairs. Post-solve caps such as max_reaching_pairs only
    // truncate the solved relation and keep its rows.
    if let Some(reason) =
        semantic_outcome_stop_reason(&outcome, FlowStateAxis::PropertyReachingRelation)
    {
        drop(outcome);
        semantic_budget.release_scratch_since(&admissions);
        return (Err(reason), reuse);
    }
    let Some(snapshot) = outcome.available_value() else {
        let reason = FlowStateIncompleteReason::PropertyAnalysisPartial {
            detail: format!(
                "property value-flow snapshot outcome is `{}`",
                outcome_label(&outcome)
            ),
        };
        return (Err(reason), reuse);
    };
    let Some(provider) = workspace.analyzer().property_reaching_provider() else {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=provider:property_relation",
                file!(),
                line!()
            )
        });
        workspace.analyzer().mark_execution_dependent();
        return (
            Err(FlowStateIncompleteReason::PropertyProviderUnavailable),
            reuse.join(EXECUTION_STOP),
        );
    };
    let limits = PropertyReachingLimits {
        cfg_work: request.cfg_budget.limits(),
        ..PropertyReachingLimits::default()
    };
    let result = if control_edge_mask.is_empty() {
        provider.property_reaching(snapshot, limits, request.cancellation)
    } else {
        let graph = ProjectedProcedureGraph::new(procedure.semantics(), control_edge_mask);
        derive_property_reaching_over_graph(
            snapshot,
            &graph,
            procedure.semantics().entry_point(),
            limits,
            request.cancellation,
        )
    };
    if result.incomplete_reasons().iter().any(|reason| {
        matches!(
            reason,
            PropertyReachingIncompleteReason::InputRelationBudgetExceeded { .. }
                | PropertyReachingIncompleteReason::ReachingPairBudgetExceeded { .. }
                | PropertyReachingIncompleteReason::CandidateCoverage(
                    crate::analyzer::semantic::CandidateCoverage::Truncated
                )
                | PropertyReachingIncompleteReason::ReachingDefinitions(
                    CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::Cancelled { .. }
                )
                | PropertyReachingIncompleteReason::Reachability(
                    CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::Cancelled { .. }
                )
                | PropertyReachingIncompleteReason::Dominators(
                    CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::Cancelled { .. }
                )
                | PropertyReachingIncompleteReason::ReachingPairs(
                    CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::Cancelled { .. }
                )
                | PropertyReachingIncompleteReason::Cancelled
        )
    }) {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=property_relation detail={:?}",
                file!(),
                line!(),
                result.incomplete_reasons()
            )
        });
        workspace.analyzer().mark_execution_dependent();
        reuse.join_in(EXECUTION_STOP);
    }
    (Ok(result), reuse)
}

/// What one field access presents as, before any counting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PropertyProbe {
    Subject(FlowSubject),
    UncanonicalBase,
}

/// The semantic identity of a projected event. This stays parallel to the
/// public rows instead of widening `StateEventRow`: downstream RQL fixtures
/// construct those rows directly, while structured property records need the
/// source mapping and event ordinal to join without consulting spelling.
type SemanticEventKey = BindingEventKey;

struct EventBuilder<'a> {
    procedure: ProcedureId,
    procedure_handle: ProcedureHandle,
    file: &'a ProjectFile,
    facts: &'a brokk_bifrost_analysis::analyzer::structural::facts::FileFacts,
    site_index: &'a SiteIndex,
    scope_frame_projection: &'a ScopeFrameProjection,
    generation: u64,
    events: Vec<StateEventRow>,
    event_keys: Vec<SemanticEventKey>,
    uncanonical_accesses: usize,
    properties_available: bool,
    skipped_copies: SkippedCopies,
}

/// Position of one event inside a procedure: its point and event index.
type EventPosition = (ProgramPointId, u32);

/// Same-point field copies that the event projection omits.
///
/// Rust lowers `let m = Meta { count: 1 };` to a load of the literal's field
/// into a temporary and a store of that temporary into the same field of `m`.
/// When the literal and `m` are one subject, that pair moves a value from a
/// slot to itself. It is not an access in the source, so it emits neither a
/// Read nor an Establish. Reaching rows that name the skipped store forward
/// to the stores that reach the skipped load.
#[derive(Debug, Default, Clone)]
struct SkippedCopies {
    /// Skipped store position to the position of the load that feeds it.
    store_to_load: HashMap<EventPosition, EventPosition>,
    /// The loads that `store_to_load` maps to, so membership is one lookup.
    loads: HashSet<EventPosition>,
}

impl SkippedCopies {
    fn contains(&self, position: EventPosition) -> bool {
        self.store_to_load.contains_key(&position) || self.loads.contains(&position)
    }
}

/// Reaching rows indexed by the position of the read they end at, to resolve
/// a skipped copy store to the stores that supply its value.
struct ForwardedReaching<'a> {
    skipped: &'a SkippedCopies,
    by_read: HashMap<EventPosition, Vec<&'a PropertyReachingRelation>>,
}

impl<'a> ForwardedReaching<'a> {
    fn new(result: &'a PropertyReachingResult, skipped: &'a SkippedCopies) -> Self {
        let mut by_read = HashMap::<_, Vec<_>>::default();
        if !skipped.store_to_load.is_empty() {
            for relation in result.reaching() {
                by_read
                    .entry((relation.read.point.id(), relation.read.event_index))
                    .or_default()
                    .push(relation);
            }
        }
        Self { skipped, by_read }
    }

    /// The stores that supply the value `store` writes, with the certainty of
    /// the whole chain. An ordinary store supplies itself. A skipped copy
    /// store supplies whatever reaches the load it copies, and the chain is
    /// exact only when every link is.
    fn origins(
        &self,
        store: &'a PropertyStoreRecord,
        certainty: PropertyReachCertainty,
    ) -> Vec<(&'a PropertyStoreRecord, PropertyReachCertainty)> {
        let mut origins = Vec::new();
        let mut visited = HashSet::default();
        let mut pending = vec![(store, certainty)];
        while let Some((store, certainty)) = pending.pop() {
            let position = (store.point.id(), store.event_index);
            let Some(load) = self.skipped.store_to_load.get(&position) else {
                origins.push((store, certainty));
                continue;
            };
            if !visited.insert(position) {
                continue;
            }
            for relation in self.by_read.get(load).into_iter().flatten() {
                let chained = match (certainty, relation.certainty) {
                    (PropertyReachCertainty::Exact, PropertyReachCertainty::Exact) => {
                        PropertyReachCertainty::Exact
                    }
                    _ => PropertyReachCertainty::May,
                };
                pending.push((&relation.store, chained));
            }
        }
        origins
    }
}

impl EventBuilder<'_> {
    /// Project every state event of one procedure, in program-point order and
    /// then event order inside a point, so two derivations of one artifact
    /// produce identical rows.
    fn collect(
        &mut self,
        procedure: &ProcedureSemantics,
        property_result: Option<&PropertyReachingResult>,
    ) -> Vec<String> {
        let binding_origins = BindingOriginIndex::from_semantics(procedure);
        let bases = BindingBases::build(procedure, &binding_origins);
        let receiver_preparations = procedure.implicit_receiver_preparation_memory_events();
        let property_stores = property_result.map_or_else(HashMap::default, |result| {
            result
                .stores()
                .iter()
                .map(|store| ((store.point.id(), store.event_index), store))
                .collect::<HashMap<_, _>>()
        });
        let property_reads = property_result.map_or_else(HashMap::default, |result| {
            result
                .reads()
                .iter()
                .map(|read| ((read.point.id(), read.event_index), read))
                .collect::<HashMap<_, _>>()
        });
        self.skipped_copies = self.find_self_copies(
            procedure,
            &bases,
            &receiver_preparations,
            &property_stores,
            &property_reads,
        );
        for point in procedure.points() {
            for (event_index, event) in point.events.iter().enumerate() {
                if receiver_preparations.contains(&(point.id, event_index))
                    || self.skipped_copies.contains((point.id, event_index as u32))
                {
                    continue;
                }
                let (class, subject, value) = match &event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        let Some(target_value) = procedure.value(*target) else {
                            continue;
                        };
                        if !target_value.kind.is_binding() {
                            continue;
                        }
                        (
                            StateEventClass::Establish,
                            FlowSubject::Binding { value: *target },
                            *value,
                        )
                    }
                    SemanticEffect::ValueFlow { source, target, .. } => {
                        let Some(source_value) = procedure.value(*source) else {
                            continue;
                        };
                        if !source_value.kind.is_binding() {
                            continue;
                        }
                        (
                            StateEventClass::Read,
                            FlowSubject::Binding { value: *source },
                            *target,
                        )
                    }
                    SemanticEffect::CaptureBind { capture } => {
                        let capture = procedure
                            .capture(*capture)
                            .expect("validated capture event");
                        if capture.mode != crate::analyzer::semantic::CaptureMode::Value {
                            continue;
                        }
                        let crate::analyzer::semantic::CaptureSource::Value(value) =
                            capture.captured
                        else {
                            continue;
                        };
                        if !procedure
                            .value(value)
                            .is_some_and(|value| value.kind.is_binding())
                        {
                            continue;
                        }
                        (StateEventClass::Read, FlowSubject::Binding { value }, value)
                    }
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field | MemoryAccessKind::Property,
                        location,
                        ..
                    } => {
                        let Some(store) = property_stores.get(&(point.id, event_index as u32))
                        else {
                            continue;
                        };
                        assert_eq!(
                            store.source, event.source,
                            "a structured property store names its owning semantic event"
                        );
                        let Some(subject) = self.property_subject(procedure, &bases, *location)
                        else {
                            continue;
                        };
                        (StateEventClass::Establish, subject, store.value.id())
                    }
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field | MemoryAccessKind::Property,
                        location,
                        ..
                    } => {
                        let Some(read) = property_reads.get(&(point.id, event_index as u32)) else {
                            continue;
                        };
                        assert_eq!(
                            read.source, event.source,
                            "a structured property read names its owning semantic event"
                        );
                        let Some(subject) = self.property_subject(procedure, &bases, *location)
                        else {
                            continue;
                        };
                        (StateEventClass::Read, subject, read.value.id())
                    }
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::LexicalCell | MemoryAccessKind::Capture,
                        location,
                        value,
                    } => {
                        let Some(binding) = procedure.memory_location(*location).and_then(
                            |location| match location.kind {
                                MemoryLocationKind::LexicalCell { binding } => Some(binding),
                                MemoryLocationKind::Capture {
                                    binding: Some(binding),
                                    ..
                                } => Some(binding),
                                _ => None,
                            },
                        ) else {
                            continue;
                        };
                        if point.events.iter().any(|event| {
                            matches!(
                                event.effect,
                                SemanticEffect::Assignment {
                                    target,
                                    value: assigned,
                                } if target == binding && assigned == *value
                            )
                        }) {
                            continue;
                        }
                        (
                            StateEventClass::Establish,
                            FlowSubject::Binding { value: binding },
                            *value,
                        )
                    }
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Dereference,
                        location,
                        value,
                    } => {
                        let Some(MemoryLocationKind::Dereference { address }) = procedure
                            .memory_location(*location)
                            .map(|location| &location.kind)
                        else {
                            continue;
                        };
                        let Some(binding) = binding_origins
                            .addressed_binding_origins(*address)
                            .unique_binding()
                        else {
                            continue;
                        };
                        (
                            StateEventClass::Establish,
                            FlowSubject::Binding { value: binding },
                            *value,
                        )
                    }
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::LexicalCell | MemoryAccessKind::Capture,
                        location,
                        result,
                    } => {
                        let Some(binding) = procedure.memory_location(*location).and_then(
                            |location| match location.kind {
                                MemoryLocationKind::LexicalCell { binding } => Some(binding),
                                MemoryLocationKind::Capture {
                                    binding: Some(binding),
                                    ..
                                } => Some(binding),
                                _ => None,
                            },
                        ) else {
                            continue;
                        };
                        (
                            StateEventClass::Read,
                            FlowSubject::Binding { value: binding },
                            *result,
                        )
                    }
                    _ => continue,
                };
                let Some(site) = self.site(procedure, event.source) else {
                    continue;
                };
                self.events.push(StateEventRow {
                    event: self.events.len(),
                    procedure: self.procedure,
                    event_class: class,
                    read_cause: None,
                    subject,
                    point: point.id,
                    point_id: self.point_id(point.id),
                    value,
                    site,
                    generation: self.generation,
                });
                self.event_keys.push(SemanticEventKey {
                    point: point.id,
                    event_index: event_index as u32,
                    source: event.source,
                });
            }
        }
        self.append_async_suspend_reads(procedure)
    }

    /// Add request-local future-frame reads for modeled post-resume uses and
    /// Rust locals whose lexical scope and CFG paths keep them live through a
    /// later ordinary scope-end drop.
    fn append_async_suspend_reads(&mut self, procedure: &ProcedureSemantics) -> Vec<String> {
        let suspensions = procedure
            .points()
            .iter()
            .filter_map(|point| {
                let (_, event) = point.events.iter().enumerate().find(|(_, event)| {
                    matches!(event.effect, SemanticEffect::AsyncSuspend { .. })
                })?;
                Some((point.id, event.source))
            })
            .collect::<Vec<_>>();
        if suspensions.is_empty() {
            return Vec::new();
        }
        let mut incomplete = match self.scope_frame_projection {
            ScopeFrameProjection::Unavailable(detail) => vec![detail.clone()],
            ScopeFrameProjection::NotApplicable | ScopeFrameProjection::Ready(_) => Vec::new(),
        };
        let mut read_points = HashMap::<ValueId, HashSet<ProgramPointId>>::default();
        let mut write_points = HashMap::<ValueId, HashSet<ProgramPointId>>::default();
        let mut establishment_points = HashMap::<ValueId, HashSet<ProgramPointId>>::default();
        for event in &self.events {
            let FlowSubject::Binding { value } = event.subject else {
                continue;
            };
            match event.event_class {
                StateEventClass::Read => {
                    read_points.entry(value).or_default().insert(event.point);
                }
                StateEventClass::Establish | StateEventClass::Kill => {
                    write_points.entry(value).or_default().insert(event.point);
                }
            }
            if event.event_class == StateEventClass::Establish {
                establishment_points
                    .entry(value)
                    .or_default()
                    .insert(event.point);
            }
        }
        let bindings = procedure
            .values()
            .iter()
            .filter(|value| value.kind == SemanticValueKind::Local)
            .map(|value| value.id)
            .collect::<Vec<_>>();
        let mut move_point_cache =
            HashMap::<SourceByteSpan, Option<HashSet<ProgramPointId>>>::default();
        for (suspend, source) in suspensions {
            let await_span = self
                .site(procedure, source)
                .map(|site| (site.range.start_byte, site.range.end_byte));
            let point_event_count = procedure
                .point(suspend)
                .expect("suspension point belongs to its procedure")
                .events
                .len();
            let mut synthetic_event_index = u32::try_from(point_event_count)
                .expect("semantic point event count fits the event-key index");
            for binding in &bindings {
                let subject = FlowSubject::Binding { value: *binding };
                let live_after_resume = binding_read_reachable_without_write(
                    procedure,
                    suspend,
                    read_points.get(binding),
                    write_points.get(binding),
                );
                if !live_after_resume {
                    let Some((await_start, await_end)) = await_span else {
                        incomplete.push(format!(
                            "suspension point {} has no source range for scope liveness",
                            suspend.index()
                        ));
                        continue;
                    };
                    let ScopeFrameProjection::Ready(scope_facts) = self.scope_frame_projection
                    else {
                        continue;
                    };
                    let Some(value) = procedure.value(*binding) else {
                        continue;
                    };
                    let Some(mapping) = procedure.source_mapping(value.source) else {
                        incomplete.push(format!(
                            "local value {} has no declaration source mapping",
                            binding.index()
                        ));
                        continue;
                    };
                    let declaration = mapping.locator.anchor().span();
                    let declaration = (
                        declaration.start_byte() as usize,
                        declaration.end_byte() as usize,
                    );
                    let Some(scope_binding) = scope_facts.bindings.get(&declaration) else {
                        incomplete.push(format!(
                            "local value {} does not join a Rust lexical binding row at {:?}",
                            binding.index(),
                            declaration
                        ));
                        continue;
                    };
                    if !(scope_binding.scope.0 <= await_start
                        && await_end <= scope_binding.scope.1
                        && scope_binding.activation.0 <= await_start
                        && await_end <= scope_binding.activation.1)
                    {
                        continue;
                    }

                    let mut moves = HashSet::default();
                    let mut missing_move_site = None;
                    for move_use in scope_binding
                        .move_uses
                        .iter()
                        .copied()
                        .filter(|(start, _)| *start < await_end)
                    {
                        let points = move_point_cache
                            .entry(move_use)
                            .or_insert_with(|| program_points_for_source_span(procedure, move_use));
                        if let Some(points) = points {
                            moves.extend(points.iter().copied());
                        } else {
                            missing_move_site = Some(move_use);
                            break;
                        }
                    }
                    if let Some(move_use) = missing_move_site {
                        incomplete.push(format!(
                            "by-value use of local {} at bytes {:?} has no source-mapped CFG point",
                            binding.index(),
                            move_use
                        ));
                        continue;
                    }
                    if !binding_live_on_path_to_suspend(
                        procedure,
                        suspend,
                        establishment_points.get(binding),
                        write_points.get(binding),
                        &moves,
                    ) {
                        continue;
                    }
                    let Some(site) = self.site(procedure, source) else {
                        incomplete.push(format!(
                            "suspension point {} has no source mapping for a scope-only read",
                            suspend.index()
                        ));
                        continue;
                    };
                    self.events.push(StateEventRow {
                        event: self.events.len(),
                        procedure: self.procedure,
                        event_class: StateEventClass::Read,
                        read_cause: Some(StateEventReadCause::ScopeEndDrop),
                        subject,
                        point: suspend,
                        point_id: self.point_id(suspend),
                        value: *binding,
                        site,
                        generation: self.generation,
                    });
                    self.event_keys.push(SemanticEventKey {
                        point: suspend,
                        event_index: synthetic_event_index,
                        source,
                    });
                    synthetic_event_index = synthetic_event_index
                        .checked_add(1)
                        .expect("synthetic event-key index fits the event-key index");
                    continue;
                }
                let Some(site) = self.site(procedure, source) else {
                    continue;
                };
                self.events.push(StateEventRow {
                    event: self.events.len(),
                    procedure: self.procedure,
                    event_class: StateEventClass::Read,
                    read_cause: Some(StateEventReadCause::PostResumeUse),
                    subject,
                    point: suspend,
                    point_id: self.point_id(suspend),
                    value: *binding,
                    site,
                    generation: self.generation,
                });
                self.event_keys.push(SemanticEventKey {
                    point: suspend,
                    event_index: synthetic_event_index,
                    source,
                });
                synthetic_event_index = synthetic_event_index
                    .checked_add(1)
                    .expect("synthetic event-key index fits the event-key index");
            }
        }
        incomplete.sort();
        incomplete.dedup();
        incomplete
    }

    /// Find the field copies whose load and store name one subject.
    ///
    /// A pair qualifies only when the original load base is an allocation
    /// result of this procedure, both events are at one point, the load comes
    /// first, the store writes exactly the loaded value, nothing else reads
    /// that value, and both locations present as the same property subject.
    /// When the literal does not canonicalize to its holder the subjects
    /// differ and the transfer stays a real transfer. Probing never counts an
    /// uncanonical access: the events that survive are counted when emitted.
    fn find_self_copies(
        &self,
        procedure: &ProcedureSemantics,
        bases: &BindingBases,
        receiver_preparations: &HashSet<(ProgramPointId, usize)>,
        property_stores: &HashMap<(ProgramPointId, u32), &PropertyStoreRecord>,
        property_reads: &HashMap<(ProgramPointId, u32), &PropertyReadRecord>,
    ) -> SkippedCopies {
        let mut skipped = SkippedCopies::default();
        let allocation_results: HashSet<_> = procedure
            .allocations()
            .iter()
            .map(|allocation| allocation.result)
            .collect();
        for point in procedure.points() {
            for (load_index, load_event) in point.events.iter().enumerate() {
                let SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Field | MemoryAccessKind::Property,
                    location: load_location,
                    result,
                } = &load_event.effect
                else {
                    continue;
                };
                let load_position = (point.id, load_index as u32);
                let Some(read) = property_reads.get(&load_position) else {
                    continue;
                };
                let Some(base) = procedure
                    .memory_location(*load_location)
                    .and_then(|location| match &location.kind {
                        MemoryLocationKind::Field { base, .. }
                        | MemoryLocationKind::Property { base, .. } => Some(*base),
                        _ => None,
                    })
                else {
                    continue;
                };
                if !allocation_results.contains(&base) {
                    continue;
                }
                if receiver_preparations.contains(&(point.id, load_index))
                    || !bases.consumed_only_by_one_store(*result)
                {
                    continue;
                }
                let Some(PropertyProbe::Subject(load_subject)) =
                    self.probe_property_subject(procedure, bases, *load_location)
                else {
                    continue;
                };
                for (store_index, store_event) in
                    point.events.iter().enumerate().skip(load_index + 1)
                {
                    let SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field | MemoryAccessKind::Property,
                        location: store_location,
                        value,
                    } = &store_event.effect
                    else {
                        continue;
                    };
                    let store_position = (point.id, store_index as u32);
                    if value != result
                        || receiver_preparations.contains(&(point.id, store_index))
                        || !property_stores
                            .get(&store_position)
                            .is_some_and(|store| store.value.id() == read.value.id())
                    {
                        continue;
                    }
                    if self.probe_property_subject(procedure, bases, *store_location)
                        == Some(PropertyProbe::Subject(load_subject.clone()))
                    {
                        // Two loads may write the same value, so a later load can
                        // re-pair a store; the earlier load stays an ordinary read.
                        // Each load pairs with at most one store (the loop breaks).
                        if let Some(previous) =
                            skipped.store_to_load.insert(store_position, load_position)
                        {
                            skipped.loads.remove(&previous);
                        }
                        skipped.loads.insert(load_position);
                    }
                    break;
                }
            }
        }
        skipped
    }

    /// The source-facing property subject of one field access. This is only a
    /// presentation projection: structured property relations use the
    /// analysis-owned durable object/path/member key and never this binding or
    /// spelling value. A base the IR cannot present as a binding is counted and
    /// skipped rather than approximated from source order.
    fn property_subject(
        &mut self,
        procedure: &ProcedureSemantics,
        bases: &BindingBases,
        location: MemoryLocationId,
    ) -> Option<FlowSubject> {
        match self.probe_property_subject(procedure, bases, location)? {
            PropertyProbe::Subject(subject) => Some(subject),
            PropertyProbe::UncanonicalBase => {
                self.uncanonical_accesses = self.uncanonical_accesses.saturating_add(1);
                None
            }
        }
    }

    /// [`Self::property_subject`] without the side effect of counting an
    /// uncanonical base.
    fn probe_property_subject(
        &self,
        procedure: &ProcedureSemantics,
        bases: &BindingBases,
        location: MemoryLocationId,
    ) -> Option<PropertyProbe> {
        if !self.properties_available {
            return None;
        }
        let location = procedure.memory_location(location)?;
        let (base, member) = match &location.kind {
            MemoryLocationKind::Field { base, member } => {
                let span = member.anchor().span();
                let member: Box<str> = self
                    .facts
                    .source()
                    .get(span.start_byte() as usize..span.end_byte() as usize)?
                    .into();
                (*base, member)
            }
            MemoryLocationKind::Property { base, key } => (*base, key.clone().into()),
            _ => return None,
        };
        let Some(canonical) = bases.canonical(base) else {
            return Some(PropertyProbe::UncanonicalBase);
        };
        Some(PropertyProbe::Subject(FlowSubject::Property {
            base: canonical,
            member,
        }))
    }

    /// The stable wire id of one program point, minted from the same artifact
    /// the derivation ran over.
    fn point_id(&self, point: ProgramPointId) -> Box<str> {
        let handle = self
            .procedure_handle
            .point_handle(point)
            .expect("a validated procedure owns the point its own events name");
        program_point_wire_id(&handle).into()
    }

    fn site(
        &self,
        procedure: &ProcedureSemantics,
        mapping: SourceMappingId,
    ) -> Option<StateEventSite> {
        let mapping = procedure.source_mapping(mapping)?;
        let span = mapping.locator.anchor().span();
        Some(StateEventSite {
            file: self.file.clone(),
            range: Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize + 1,
                end_line: span.end().line() as usize + 1,
            },
            ast_id: self.site_index.ast_id(span),
        })
    }
}

fn binding_read_reachable_without_write(
    procedure: &ProcedureSemantics,
    origin: ProgramPointId,
    reads: Option<&HashSet<ProgramPointId>>,
    writes: Option<&HashSet<ProgramPointId>>,
) -> bool {
    let Some(reads) = reads else {
        return false;
    };
    let writes = writes.cloned().unwrap_or_default();
    let mut visited = HashSet::default();
    let mut stack = procedure
        .successors(origin)
        .map(|(_, target)| target)
        .collect::<Vec<_>>();
    while let Some(point) = stack.pop() {
        if !visited.insert(point) || writes.contains(&point) {
            continue;
        }
        if reads.contains(&point) {
            return true;
        }
        stack.extend(procedure.successors(point).map(|(_, target)| target));
    }
    false
}

/// Find the CFG point(s) that own a structured Rust use site. Exact source
/// mappings win; if the lowerer maps only an enclosing expression, use the
/// narrowest source-mapped point that contains the identifier.
fn program_points_for_source_span(
    procedure: &ProcedureSemantics,
    wanted: SourceByteSpan,
) -> Option<HashSet<ProgramPointId>> {
    let mut exact = HashSet::default();
    let mut narrowest_width = usize::MAX;
    let mut enclosing = HashSet::default();
    for point in procedure.points() {
        let source_mappings =
            std::iter::once(point.source).chain(point.events.iter().map(|event| event.source));
        for source in source_mappings {
            let Some(mapping) = procedure.source_mapping(source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            let actual = (span.start_byte() as usize, span.end_byte() as usize);
            if actual == wanted {
                exact.insert(point.id);
            } else if actual.0 <= wanted.0 && wanted.1 <= actual.1 {
                let width = actual.1 - actual.0;
                if width < narrowest_width {
                    narrowest_width = width;
                    enclosing.clear();
                    enclosing.insert(point.id);
                } else if width == narrowest_width {
                    enclosing.insert(point.id);
                }
            }
        }
    }
    if !exact.is_empty() {
        Some(exact)
    } else if !enclosing.is_empty() {
        Some(enclosing)
    } else {
        None
    }
}

/// Whether any CFG path carries one establishment to `suspend` without an
/// intervening by-value move or another establishment of the same binding.
/// Stopping at each write and starting from every establishment handles
/// reinitialization while preserving the existential path required when only
/// one branch moves the value.
fn binding_live_on_path_to_suspend(
    procedure: &ProcedureSemantics,
    suspend: ProgramPointId,
    establishments: Option<&HashSet<ProgramPointId>>,
    writes: Option<&HashSet<ProgramPointId>>,
    moves: &HashSet<ProgramPointId>,
) -> bool {
    let Some(establishments) = establishments else {
        return false;
    };
    let writes = writes.cloned().unwrap_or_default();
    let mut stack = establishments
        .iter()
        .flat_map(|origin| {
            procedure
                .successors(*origin)
                .map(|(_, target)| target)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut visited = HashSet::default();
    while let Some(point) = stack.pop() {
        if point == suspend {
            return true;
        }
        if !visited.insert(point) || writes.contains(&point) || moves.contains(&point) {
            continue;
        }
        stack.extend(procedure.successors(point).map(|(_, target)| target));
    }
    false
}

/// The subject each value presents as in a property access.
///
/// A value read from a binding presents as that binding (`ValueFlow`). A
/// value loaded from static storage presents as the first value loaded from
/// that location. An allocation result presents as itself, or as the one
/// binding that provably holds exactly that allocation. Nothing else
/// canonicalizes a base.
struct BindingBases {
    canonical: HashMap<ValueId, ValueId>,
    /// Consumers of each allocation result and each field or property load
    /// result, other than the object slot accesses that name it as a base.
    other_uses: HashMap<ValueId, usize>,
    /// Every value that is the object of a field, property or index slot.
    slot_bases: HashSet<ValueId>,
}

/// What one pass over a procedure learns about an allocation result and the
/// bindings that receive it.
#[derive(Default)]
struct AllocationFlows {
    /// Each `Assignment { target, value: allocation }`, with the assignment's
    /// event evidence.
    assigned_to: Vec<(ValueId, EvidenceId)>,
    /// Reads of the allocation other than its own slot accesses and the
    /// binding assignments in `assigned_to`.
    other_uses: usize,
}

impl BindingBases {
    /// A value read from a binding presents as that binding. A value loaded
    /// from static storage (a Java or C# static, a Go package variable, a
    /// Python module global) presents as the first value loaded from the
    /// same location, the storage-rooted counterpart of a binding.
    ///
    /// An allocation result (a struct or object literal) is its own subject.
    /// It presents as a binding `B` only when the allocation flows nowhere but
    /// into `B` and `B` is established nowhere else, so that `B.f` and the
    /// literal's `f` are one slot. Two allocation sites never share a subject:
    /// `let mut x = A { f: 1 }; x = A { f: 2 };` keeps both literals apart.
    fn build(procedure: &ProcedureSemantics, origins: &BindingOriginIndex) -> Self {
        let mut canonical = HashMap::default();
        let mut static_roots = HashMap::<MemoryLocationId, ValueId>::default();
        for point in procedure.points() {
            for event in point.events.iter() {
                match &event.effect {
                    SemanticEffect::ValueFlow { source, target, .. } => {
                        if procedure
                            .value(*source)
                            .is_some_and(|value| value.kind.is_binding())
                        {
                            canonical.entry(*target).or_insert(*source);
                        }
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } if procedure
                        .memory_location(*location)
                        .is_some_and(|location| {
                            matches!(location.kind, MemoryLocationKind::Static { .. })
                        }) =>
                    {
                        let root = *static_roots.entry(*location).or_insert(*result);
                        canonical.entry(*result).or_insert(root);
                    }
                    _ => {}
                }
            }
        }
        let (flows, establishments) = allocation_flows(procedure);
        for allocation in procedure.allocations() {
            let allocation = allocation.result;
            let flow = flows
                .get(&allocation)
                .expect("every allocation result has a flow record");
            // A binding is a candidate holder only for one proven, sole flow.
            let holder = match flow.assigned_to.as_slice() {
                [(binding, evidence)]
                    if flow.other_uses == 0
                        && establishments.get(binding) == Some(&1)
                        && !origins.address_taken_binding_set().contains(binding)
                        && procedure
                            .value(*binding)
                            .is_some_and(|value| value.kind == SemanticValueKind::Local)
                        && procedure.evidence_row(*evidence).is_some_and(|row| {
                            row.proof.establishes_complete_evidence(&row.completeness)
                        }) =>
                {
                    Some(*binding)
                }
                _ => None,
            };
            canonical
                .entry(allocation)
                .or_insert(holder.unwrap_or(allocation));
            // A binding that receives an allocation presents as itself, so the
            // copy store into its field (`m.f` in `let m = Meta { f: 1 }`) has
            // a subject: the allocation's own subject when the binding is its
            // sole holder, the binding's own otherwise (`x = Meta { f: 2 }`
            // after `let mut x = Meta { f: 1 }`). Bindings that receive no
            // allocation keep their old presentation (#13899).
            for (binding, _) in &flow.assigned_to {
                if procedure
                    .value(*binding)
                    .is_some_and(|value| value.kind.is_binding())
                {
                    canonical.entry(*binding).or_insert(*binding);
                }
            }
        }
        let slot_bases = procedure
            .memory_locations()
            .iter()
            .filter_map(|location| match &location.kind {
                MemoryLocationKind::Field { base, .. }
                | MemoryLocationKind::Property { base, .. }
                | MemoryLocationKind::Index { base, .. } => Some(*base),
                _ => None,
            })
            .collect();
        let other_uses = flows
            .into_iter()
            .map(|(value, flow)| (value, flow.other_uses))
            .collect();
        Self {
            canonical,
            other_uses,
            slot_bases,
        }
    }

    /// Whether `result`, a field or property load result, is consumed by
    /// exactly one store and by nothing else.
    fn consumed_only_by_one_store(&self, result: ValueId) -> bool {
        self.other_uses.get(&result) == Some(&1) && !self.slot_bases.contains(&result)
    }

    fn canonical(&self, value: ValueId) -> Option<ValueId> {
        self.canonical.get(&value).copied()
    }
}

/// Every flow of every allocation result, and how many times each binding is
/// established, in one pass.
///
/// The read-side match is exhaustive on purpose: a new effect that reads a
/// value must be classified here before it can compile, because a missed read
/// would let an escaping allocation present as a binding.
fn allocation_flows(
    procedure: &ProcedureSemantics,
) -> (HashMap<ValueId, AllocationFlows>, HashMap<ValueId, usize>) {
    let mut flows = procedure
        .allocations()
        .iter()
        .map(|allocation| (allocation.result, AllocationFlows::default()))
        .collect::<HashMap<_, _>>();
    // Field and property load results are tracked the same way, so a copy
    // temporary can be proven to feed one store and nothing else.
    for point in procedure.points() {
        for event in point.events.iter() {
            if let SemanticEffect::MemoryLoad {
                kind: MemoryAccessKind::Field | MemoryAccessKind::Property,
                result,
                ..
            } = &event.effect
            {
                flows.entry(*result).or_default();
            }
        }
    }
    let mut establishments = HashMap::<ValueId, usize>::default();
    let use_of = |flows: &mut HashMap<ValueId, AllocationFlows>, value: ValueId| {
        if let Some(flow) = flows.get_mut(&value) {
            flow.other_uses += 1;
        }
    };
    for location in procedure.memory_locations() {
        // The base of a field, property or index access is the object's own
        // slot. Any other consumer of the allocation value is a flow.
        match &location.kind {
            MemoryLocationKind::Index {
                index: Some(index), ..
            } => use_of(&mut flows, *index),
            MemoryLocationKind::Dereference { address } => use_of(&mut flows, *address),
            // A cell or capture slot names a binding, never an allocation.
            MemoryLocationKind::Field { .. }
            | MemoryLocationKind::Property { .. }
            | MemoryLocationKind::Index { index: None, .. }
            | MemoryLocationKind::LexicalCell { .. }
            | MemoryLocationKind::Capture { .. }
            | MemoryLocationKind::Static { .. } => {}
        }
    }
    for call in procedure.call_sites() {
        use_of(&mut flows, call.callee);
        for value in call.receiver.iter().chain(call.thrown.iter()) {
            use_of(&mut flows, *value);
        }
        for argument in call.arguments.iter() {
            use_of(&mut flows, argument.value);
        }
    }
    // A captured binding can be rebound by the child procedure, whose writes
    // this procedure does not see. Counting the capture as an establishment
    // keeps such a binding from ever presenting as one allocation.
    for capture in procedure.captures() {
        let captured = match capture.captured {
            CaptureSource::Value(value) => Some(value),
            CaptureSource::Location(location) => {
                procedure
                    .memory_location(location)
                    .and_then(|row| match row.kind {
                        MemoryLocationKind::LexicalCell { binding } => Some(binding),
                        _ => None,
                    })
            }
        };
        if let Some(binding) = captured {
            *establishments.entry(binding).or_default() += 1;
        }
    }
    for move_out in procedure.move_outs() {
        use_of(&mut flows, move_out.source_value);
        use_of(&mut flows, move_out.target_value);
    }
    for point in procedure.points() {
        for event in point.events.iter() {
            match &event.effect {
                SemanticEffect::Assignment { target, value } => {
                    *establishments.entry(*target).or_default() += 1;
                    if let Some(flow) = flows.get_mut(value) {
                        flow.assigned_to.push((*target, event.evidence));
                    }
                }
                SemanticEffect::AggregateInitializer {
                    aggregate, value, ..
                } => {
                    use_of(&mut flows, *aggregate);
                    use_of(&mut flows, *value);
                }
                SemanticEffect::ValueFlow { source, target, .. } => {
                    // The lowering records one binding write as an
                    // `Assignment` and a `ValueFlow` of the same value at one
                    // point; the second record is not another establishment.
                    let paired = point.events.iter().any(|other| {
                        matches!(
                            other.effect,
                            SemanticEffect::Assignment { target: assigned_to, value: assigned }
                                if assigned_to == *target && assigned == *source
                        )
                    });
                    if !paired {
                        *establishments.entry(*target).or_default() += 1;
                        use_of(&mut flows, *source);
                    }
                }
                SemanticEffect::ValueUse { value, .. } => use_of(&mut flows, *value),
                SemanticEffect::MemoryStore {
                    location, value, ..
                } => {
                    let cell_binding =
                        procedure
                            .memory_location(*location)
                            .and_then(|row| match row.kind {
                                MemoryLocationKind::LexicalCell { binding }
                                | MemoryLocationKind::Capture {
                                    binding: Some(binding),
                                    ..
                                } => Some(binding),
                                _ => None,
                            });
                    let paired = cell_binding.is_some_and(|binding| {
                        point.events.iter().any(|other| {
                            matches!(
                                other.effect,
                                SemanticEffect::Assignment { target, value: assigned }
                                    if target == binding && assigned == *value
                            )
                        })
                    });
                    // A cell store beside the assignment of the same value to
                    // the same binding is the lowering's second record of one
                    // establishment, not another flow.
                    if !paired {
                        use_of(&mut flows, *value);
                        if let Some(binding) = cell_binding {
                            *establishments.entry(binding).or_default() += 1;
                        }
                    }
                }
                SemanticEffect::Synchronization {
                    subject, payload, ..
                } => {
                    use_of(&mut flows, *subject);
                    if let Some(SynchronizationPayload::Send { value, .. }) = payload {
                        use_of(&mut flows, *value);
                    }
                }
                SemanticEffect::CallableCreation { callable, .. }
                | SemanticEffect::CallableReference { callable, .. } => {
                    if let Some(receiver) = callable.bound_receiver {
                        use_of(&mut flows, receiver);
                    }
                }
                SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                    if let Some(value) = value {
                        use_of(&mut flows, *value);
                    }
                }
                SemanticEffect::AsyncSuspend { awaited, .. } => {
                    if let Some(value) = awaited {
                        use_of(&mut flows, *value);
                    }
                }
                SemanticEffect::CaptureBind { capture } => {
                    if let Some(CaptureSource::Value(value)) =
                        procedure.capture(*capture).map(|row| row.captured)
                    {
                        use_of(&mut flows, value);
                    }
                }
                SemanticEffect::Entry
                | SemanticEffect::NormalExit
                | SemanticEffect::ExceptionalExit
                | SemanticEffect::Allocation { .. }
                | SemanticEffect::MemoryLoad { .. }
                | SemanticEffect::Invoke { .. }
                | SemanticEffect::CallContinuation { .. }
                | SemanticEffect::AsyncResume { .. }
                | SemanticEffect::Gap { .. }
                | SemanticEffect::MemoryInterference => {}
            }
        }
    }
    (flows, establishments)
}

/// A binding write with more than one establishment terminates the binding's
/// other definitions, so it emits a `Kill` beside its `Establish`. Property
/// kills use only the structured relation's strong-update certificate and
/// same-location store count; their presentation subject is not consulted.
///
/// The rule is deliberately order-free. The dense program-point index is the
/// lowering's emission order, not a control-flow order, so "which write came
/// first" is not derivable without the CFG; what *is* derivable, and what the
/// gen/kill fixed point below actually uses, is that each write kills every
/// other definition of its subject.
fn append_kill_events(
    events: &mut Vec<StateEventRow>,
    event_keys: &mut Vec<SemanticEventKey>,
    property_result: Option<&PropertyReachingResult>,
    skipped: &SkippedCopies,
) {
    assert_eq!(
        events.len(),
        event_keys.len(),
        "each projected event has one semantic join key"
    );
    let strong_property_events = property_result.map_or_else(HashSet::default, |result| {
        // A skipped copy store is not a write of the source program, so it
        // neither kills the store that fed it nor counts toward a second store.
        let projected = || {
            result.stores().iter().filter(|store| {
                !skipped
                    .store_to_load
                    .contains_key(&(store.point.id(), store.event_index))
            })
        };
        let mut store_counts = HashMap::<_, usize>::default();
        for store in projected() {
            *store_counts.entry(store.location.clone()).or_default() += 1;
        }
        projected()
            .filter(|store| {
                store.strong_update
                    && store_counts
                        .get(&store.location)
                        .copied()
                        .unwrap_or_default()
                        >= 2
            })
            .map(|store| (store.point.id(), store.event_index, store.source))
            .collect::<HashSet<_>>()
    });
    let mut establishments: HashMap<FlowSubject, usize> = HashMap::default();
    for event in events.iter() {
        if event.event_class == StateEventClass::Establish
            && matches!(&event.subject, FlowSubject::Binding { .. })
        {
            *establishments.entry(event.subject.clone()).or_insert(0) += 1;
        }
    }
    let mut kills = Vec::new();
    for (event, key) in events.iter().zip(event_keys.iter()) {
        if event.event_class != StateEventClass::Establish {
            continue;
        }
        match &event.subject {
            FlowSubject::Binding { .. } => {
                if establishments.get(&event.subject).copied().unwrap_or(0) < 2 {
                    continue;
                }
            }
            FlowSubject::Property { .. } => {
                if !strong_property_events.contains(&(key.point, key.event_index, key.source)) {
                    continue;
                }
            }
        }
        kills.push((
            StateEventRow {
                event: 0,
                event_class: StateEventClass::Kill,
                ..event.clone()
            },
            *key,
        ));
    }
    for (mut kill, key) in kills {
        kill.event = events.len();
        events.push(kill);
        event_keys.push(key);
    }
}

/// Locals the lowering declares but never establishes.
///
/// Parameters and receivers are bound at the procedure boundary and so
/// legitimately carry no establishment event; a local that carries none is a
/// hole in the assignment axis, and reads of it cannot be proven unreached.
fn unestablished_local_bindings(procedure: &ProcedureSemantics, events: &[StateEventRow]) -> usize {
    let established: HashSet<ValueId> = events
        .iter()
        .filter(|event| event.event_class == StateEventClass::Establish)
        .filter_map(|event| match &event.subject {
            FlowSubject::Binding { value } => Some(*value),
            FlowSubject::Property { .. } => None,
        })
        .collect();
    procedure
        .values()
        .iter()
        .filter(|value| value.kind == SemanticValueKind::Local)
        .filter(|value| !established.contains(&value.id))
        .count()
}

#[allow(clippy::too_many_arguments)]
fn derive_relations(
    procedure: &ProcedureSemantics,
    control_edge_mask: &ControlEdgeMask,
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    property_result: Option<&PropertyReachingResult>,
    skipped: &SkippedCopies,
    generation: u64,
    request: &mut FlowStateRequest<'_>,
    reasons: &mut Vec<FlowStateIncompleteReason>,
) -> (
    Vec<FlowRelationRow>,
    Option<Dominators<ProgramPointId>>,
    Option<BindingInitializationFacts>,
) {
    let relations = same_evaluation_relations(procedure, events, generation);
    if control_edge_mask.is_empty() {
        return derive_control_relations(
            procedure,
            procedure,
            events,
            event_keys,
            property_result,
            skipped,
            generation,
            request,
            reasons,
            relations,
        );
    }
    let graph = ProjectedProcedureGraph::new(procedure, control_edge_mask);
    derive_control_relations(
        &graph,
        procedure,
        events,
        event_keys,
        property_result,
        skipped,
        generation,
        request,
        reasons,
        relations,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_control_relations<G>(
    graph: &G,
    procedure: &ProcedureSemantics,
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    property_result: Option<&PropertyReachingResult>,
    skipped: &SkippedCopies,
    generation: u64,
    request: &mut FlowStateRequest<'_>,
    reasons: &mut Vec<FlowStateIncompleteReason>,
    mut relations: Vec<FlowRelationRow>,
) -> (
    Vec<FlowRelationRow>,
    Option<Dominators<ProgramPointId>>,
    Option<BindingInitializationFacts>,
)
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let entry = procedure.entry_point();
    let mut algorithm_request =
        CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
    let dominance = match dominators(graph, entry, &mut algorithm_request) {
        Ok(dominance) => dominance,
        Err(error) => {
            push_algorithm_reason(error, FlowStateAxis::DominanceRelation, reasons);
            reasons.push(FlowStateIncompleteReason::AxisUnsupported(
                FlowStateAxis::ReachingRelation,
            ));
            reasons.push(FlowStateIncompleteReason::AxisUnsupported(
                FlowStateAxis::PropertyReachingRelation,
            ));
            reasons.push(FlowStateIncompleteReason::AxisUnsupported(
                FlowStateAxis::PropertyDominanceRelation,
            ));
            return (relations, None, None);
        }
    };

    let initialization_events = binding_initialization_events(events, event_keys);
    let definitions = BindingDefinitions::build(procedure, &initialization_events);
    let facts = definitions.gen_kill(procedure);
    let reaching = match reaching_definitions(graph, entry, &facts, &mut algorithm_request) {
        Ok(reaching) => reaching,
        Err(error) => {
            push_algorithm_reason(error, FlowStateAxis::ReachingRelation, reasons);
            relations.extend(dominance_relations(graph, events, &dominance, generation));
            if let Some(property_result) = property_result {
                relations.extend(property_flow_relations(
                    graph,
                    events,
                    event_keys,
                    property_result,
                    skipped,
                    &dominance,
                    generation,
                ));
            }
            return (relations, Some(dominance), None);
        }
    };

    relations.extend(reaching_relations(
        graph,
        events,
        &definitions,
        &reaching,
        &dominance,
        generation,
    ));
    relations.extend(dominance_relations(graph, events, &dominance, generation));
    if let Some(property_result) = property_result {
        relations.extend(property_flow_relations(
            graph,
            events,
            event_keys,
            property_result,
            skipped,
            &dominance,
            generation,
        ));
    }
    let binding_initialization = BindingInitializationFacts {
        uninitialized_before_event: definitions.uninitialized_before_event(
            procedure,
            &initialization_events,
            &reaching,
        ),
        correlated_before_event: HashMap::default(),
    };
    (relations, Some(dominance), Some(binding_initialization))
}

/// Immutable procedure-local control view that hides exact modeled edges.
///
/// The source semantic artifact remains unchanged. Omitted incoming and
/// outgoing counts keep adjacency iteration exact-sized without copying the
/// retained graph or losing canonical edge order.
#[derive(Debug, Clone, Default)]
struct ControlEdgeMask {
    omitted: HashSet<ControlEdgeId>,
    omitted_outgoing: Vec<usize>,
    omitted_incoming: Vec<usize>,
}

impl ControlEdgeMask {
    fn new(
        procedure: &ProcedureSemantics,
        omitted: impl IntoIterator<Item = ControlEdgeId>,
    ) -> Self {
        let omitted = omitted.into_iter().collect::<HashSet<_>>();
        if omitted.is_empty() {
            return Self::default();
        }
        let mut omitted_outgoing = vec![0usize; procedure.points().len()];
        let mut omitted_incoming = vec![0usize; procedure.points().len()];
        for edge in &omitted {
            let (source, target) = DenseBidirectionalGraph::edge_endpoints(procedure, *edge)
                .expect("a projected control edge belongs to its validated procedure");
            omitted_outgoing[source.index()] = omitted_outgoing[source.index()].saturating_add(1);
            omitted_incoming[target.index()] = omitted_incoming[target.index()].saturating_add(1);
        }
        Self {
            omitted,
            omitted_outgoing,
            omitted_incoming,
        }
    }

    fn is_empty(&self) -> bool {
        self.omitted.is_empty()
    }
}

pub struct ProjectedProcedureGraph<'a> {
    procedure: &'a ProcedureSemantics,
    mask: &'a ControlEdgeMask,
}

impl<'a> ProjectedProcedureGraph<'a> {
    fn new(procedure: &'a ProcedureSemantics, mask: &'a ControlEdgeMask) -> Self {
        Self { procedure, mask }
    }
}

impl DenseBidirectionalGraph for ProjectedProcedureGraph<'_> {
    type Node = ProgramPointId;
    type Edge = ControlEdgeId;

    fn node_count(&self) -> usize {
        DenseBidirectionalGraph::node_count(self.procedure)
    }

    fn node_at(&self, index: usize) -> Option<Self::Node> {
        DenseBidirectionalGraph::node_at(self.procedure, index)
    }

    fn node_index(&self, node: Self::Node) -> Option<usize> {
        DenseBidirectionalGraph::node_index(self.procedure, node)
    }

    fn successors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        RetainedEdges::new(
            DenseBidirectionalGraph::successors(self.procedure, node),
            &self.mask.omitted,
            if self.mask.is_empty() {
                0
            } else {
                self.mask.omitted_outgoing[node.index()]
            },
        )
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        RetainedEdges::new(
            DenseBidirectionalGraph::predecessors(self.procedure, node),
            &self.mask.omitted,
            if self.mask.is_empty() {
                0
            } else {
                self.mask.omitted_incoming[node.index()]
            },
        )
    }

    fn edge_endpoints(&self, edge: Self::Edge) -> Option<(Self::Node, Self::Node)> {
        (!self.mask.omitted.contains(&edge))
            .then(|| DenseBidirectionalGraph::edge_endpoints(self.procedure, edge))
            .flatten()
    }
}

struct RetainedEdges<'a, I> {
    inner: I,
    omitted: &'a HashSet<ControlEdgeId>,
    remaining: usize,
}

impl<'a, I> RetainedEdges<'a, I>
where
    I: ExactSizeIterator<Item = (ControlEdgeId, ProgramPointId)>,
{
    fn new(inner: I, omitted: &'a HashSet<ControlEdgeId>, omitted_count: usize) -> Self {
        debug_assert!(omitted_count <= inner.len());
        let remaining = inner.len().saturating_sub(omitted_count);
        Self {
            inner,
            omitted,
            remaining,
        }
    }
}

impl<I> Iterator for RetainedEdges<'_, I>
where
    I: Iterator<Item = (ControlEdgeId, ProgramPointId)>,
{
    type Item = (ControlEdgeId, ProgramPointId);

    fn next(&mut self) -> Option<Self::Item> {
        for edge in self.inner.by_ref() {
            if self.omitted.contains(&edge.0) {
                continue;
            }
            self.remaining = self.remaining.saturating_sub(1);
            return Some(edge);
        }
        debug_assert_eq!(self.remaining, 0);
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<I> DoubleEndedIterator for RetainedEdges<'_, I>
where
    I: DoubleEndedIterator<Item = (ControlEdgeId, ProgramPointId)>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        while let Some(edge) = self.inner.next_back() {
            if self.omitted.contains(&edge.0) {
                continue;
            }
            self.remaining = self.remaining.saturating_sub(1);
            return Some(edge);
        }
        debug_assert_eq!(self.remaining, 0);
        None
    }
}

impl<I> ExactSizeIterator for RetainedEdges<'_, I>
where
    I: ExactSizeIterator<Item = (ControlEdgeId, ProgramPointId)>,
{
    fn len(&self) -> usize {
        self.remaining
    }
}

fn push_algorithm_reason(
    error: CfgAlgorithmError<ProgramPointId>,
    axis: FlowStateAxis,
    reasons: &mut Vec<FlowStateIncompleteReason>,
) {
    match error {
        CfgAlgorithmError::Cancelled { .. } => {
            reasons.push(FlowStateIncompleteReason::Cancelled);
        }
        CfgAlgorithmError::ExceededBudget(exceeded) => {
            reasons.push(FlowStateIncompleteReason::BudgetExhausted {
                axis,
                detail: format!(
                    "{:?} limit {} exceeded at {}",
                    exceeded.limit_kind, exceeded.limit, exceeded.attempted
                ),
            });
        }
        CfgAlgorithmError::InvalidNode(node) => {
            unreachable!("a validated procedure owns its own program point {node:?}")
        }
    }
}

// #7340: location alone does not prove locality. Every attributed gap in a
// reason must satisfy the consumer's audited predicate; future kinds fail closed.
struct LocatedGapReasons {
    by_point: BTreeMap<ProgramPointId, Vec<SemanticGapId>>,
    unlocated: Vec<FlowStateIncompleteReason>,
}

fn locate_gap_reasons(
    semantics: &ProcedureSemantics,
    reasons: Vec<FlowStateIncompleteReason>,
    is_local: impl Fn(&SemanticGap) -> bool,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<LocatedGapReasons, CfgAlgorithmError<ProgramPointId>> {
    let (located, unlocated): (Vec<_>, Vec<_>) = reasons.into_iter().partition(|reason| {
        matches!(reason, FlowStateIncompleteReason::LoweringGap { gaps, .. }
            if !gaps.is_empty() && gaps.iter().all(|id| semantics.gap(*id)
                .is_some_and(&is_local)))
    });
    let mut by_point = BTreeMap::<_, Vec<_>>::new();
    if unlocated.is_empty() {
        // Index once per query, charging each gap once. Ordered points and the
        // retained gap order within each point keep reported reasons deterministic.
        for reason in located {
            let FlowStateIncompleteReason::LoweringGap { gaps, .. } = reason else {
                unreachable!("only attributed lowering gaps are scoped");
            };
            for id in gaps {
                request.visit_pair()?;
                let gap = semantics.gap(id).expect("attributed gap exists");
                by_point.entry(gap.point).or_default().push(id);
            }
        }
    }
    Ok(LocatedGapReasons {
        by_point,
        unlocated,
    })
}

fn initialization_gap_retains_topology(gap: &SemanticGap) -> bool {
    // ConcurrentSpawn retains parent successors but not the child's later
    // effects, so it intentionally does not match this positive-proof contract.
    matches!(
        (
            gap.capability,
            gap.kind,
            gap.subject,
            gap.control_flow_discharge()
        ),
        (
            SemanticCapability::NormalControlFlow | SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
            SemanticGapSubject::Point,
            SemanticGapDischarge::RetainedControlTopology
        )
    )
}

fn initialization_gap_retains_order(gap: &SemanticGap) -> bool {
    matches!(
        (
            gap.capability,
            gap.kind,
            gap.subject,
            gap.control_flow_discharge()
        ),
        (
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
            SemanticGapSubject::Point,
            SemanticGapDischarge::RetainedEvaluationOrder
        )
    )
}

fn initialization_order_region_is_off_path<G>(
    graph: &G,
    semantics: &ProcedureSemantics,
    gap: &SemanticGap,
    reaching_read: &Reachability<ProgramPointId>,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<bool, CfgAlgorithmError<ProgramPointId>>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    request.visit_pair()?;
    let Some(mapping) = semantics.source_mapping(gap.source) else {
        return Ok(false);
    };
    // Go's assignment, spawn/defer registration, and range-target producers
    // can attach the gap after the operands. Its point alone is not its scope:
    // include every point mapped within the enclosing evaluation's syntax range.
    // Reverse reachability includes the read itself and all loop back edges.
    if reaching_read.contains(graph, gap.point) {
        return Ok(false);
    }
    let span = mapping.locator.anchor().span();
    for point in semantics.points() {
        request.visit_node::<ProgramPointId>()?;
        let Some(mapping) = semantics.source_mapping(point.source) else {
            return Ok(false);
        };
        let point_span = mapping.locator.anchor().span();
        if point_span.start_byte() >= span.start_byte()
            && point_span.end_byte() <= span.end_byte()
            && reaching_read.contains(graph, point.id)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

// #7340 lowerer audit: this allow-list intentionally excludes assignment/storage,
// capture, deferred execution, resource lifetime and region/order obligations
// (D1-D10). A point on those gaps need not be their complete execution scope.
fn overwrite_gap_is_point_local(gap: &SemanticGap) -> bool {
    if gap.subject == SemanticGapSubject::Point
        && gap.capability == SemanticCapability::ExceptionalControlFlow
        && gap.kind == SemanticGapKind::Unsupported
        && matches!(
            gap.control_flow_discharge(),
            SemanticGapDischarge::ExitOnlyProcedureCompletion
                | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
        )
    {
        // This is an omitted exit at the operation, not a procedure-wide
        // cleanup summary. Independent cleanup obligations remain checked.
        // The overwrite walk stops before operations after replacement.
        return true;
    }
    matches!(
        (
            gap.capability,
            gap.kind,
            gap.subject,
            gap.control_flow_discharge()
        ),
        // #7340 audit: PHP/Go/Python Point return gaps describe transfer at
        // the return boundary; named-result/defer Value gaps remain global.
        (
            SemanticCapability::ReturnFlow,
            SemanticGapKind::Unsupported,
            SemanticGapSubject::Point,
            SemanticGapDischarge::None
        )
        // #7340 audit: JS/TS control.rs member_expression emits this only at
        // the access operation, after evaluating its object and index.
        | (
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            SemanticGapSubject::Point,
            SemanticGapDischarge::RuntimeReadBehavior
        )
        // #7340 audit: Go/Rust checks and JS/Python yield gaps mark the actual
        // abort/resume point. Deferred Unknown and early drop-summary markers
        // (ExitOnly/AfterInertDrops, D6/D9) do not match this tuple.
        | (
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
            SemanticGapSubject::Point,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        )
    )
}

struct OverwrittenUnreadWalkInputs<'a> {
    semantics: &'a ProcedureSemantics,
    events: &'a [StateEventRow],
    event_keys: &'a [SemanticEventKey],
    establishment_event: usize,
    binding: ValueId,
    gaps_by_point: &'a BTreeMap<ProgramPointId, Vec<SemanticGapId>>,
}

fn drop_omission_gap(semantics: &ProcedureSemantics, reason: &FlowStateIncompleteReason) -> bool {
    let FlowStateIncompleteReason::LoweringGap { gaps, .. } = reason else {
        return false;
    };
    !gaps.is_empty()
        && gaps.iter().all(|id| {
            semantics.gap(*id).is_some_and(|gap| {
                // This relation excludes implicit destructor reads, not generic
                // deferred or exit-only work that can observe the binding.
                gap.is_implicit_drop_omission()
                    && matches!(
                        gap.capability,
                        SemanticCapability::CleanupControlFlow
                            | SemanticCapability::ResourceManagement
                            | SemanticCapability::Calls
                            | SemanticCapability::ExceptionalControlFlow
                    )
            })
        })
}

/// Rust's non-rejoining exceptional-flow discharge describes only an abort
/// route out of this procedure, including routes with inert binding drops or
/// other exit-only cleanup. That route cannot reach an explicit source read.
/// Other gaps at the same point are checked independently, including opaque
/// macro gaps; this certificate does not make a write safe to delete.
fn nonrejoining_rust_abort_gap(
    semantics: &ProcedureSemantics,
    reason: &FlowStateIncompleteReason,
) -> bool {
    let FlowStateIncompleteReason::LoweringGap { gaps, .. } = reason else {
        return false;
    };
    !gaps.is_empty()
        && gaps.iter().all(|id| {
            semantics.gap(*id).is_some_and(|gap| {
                gap.subject == SemanticGapSubject::Point
                    && gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.kind == SemanticGapKind::Unsupported
                    && matches!(
                        gap.control_flow_discharge(),
                        SemanticGapDischarge::NonRejoiningExceptionalExit
                            | SemanticGapDischarge::NonRejoiningExceptionalExitAfterInertDrops
                            | SemanticGapDischarge::ExitOnlyProcedureCompletion
                    )
            })
        })
}

fn opaque_macro_gap_irrelevant(
    semantics: &ProcedureSemantics,
    reason: &FlowStateIncompleteReason,
    macro_sources: &[SourceMappingId],
    safe_macro_sources: &[SourceMappingId],
    reaches: impl Fn(ProgramPointId) -> bool,
) -> bool {
    let FlowStateIncompleteReason::LoweringGap { gaps, .. } = reason else {
        return false;
    };
    !gaps.is_empty()
        && gaps.iter().all(|id| {
            semantics.gap(*id).is_some_and(|gap| {
                gap.subject == SemanticGapSubject::Point
                    && gap.capability == SemanticCapability::NormalControlFlow
                    && gap.kind == SemanticGapKind::Unsupported
                    && macro_sources.binary_search(&gap.source).is_ok()
                    && (safe_macro_sources.binary_search(&gap.source).is_ok()
                        || !reaches(gap.point))
            })
        })
}

#[derive(Debug)]
struct DeadWritePrepared {
    reachable: Arc<Reachability<ProgramPointId>>,
    ordered: Vec<Vec<(u32, usize, StateEventClass)>>,
    liveness: LiveValueSets,
    distance_to_read: Vec<usize>,
    witness_by_point: Vec<Option<usize>>,
}

#[derive(Debug)]
struct DeadWriteProcedureIndex {
    _artifact: Arc<SemanticArtifact>,
    events_by_binding: HashMap<ValueId, Vec<usize>>,
    escaped_bindings: HashSet<ValueId>,
    macro_gap_points_by_source: HashMap<SourceMappingId, Vec<ProgramPointId>>,
}

#[derive(Debug)]
struct DeadWriteComponentOrderCacheEntry {
    _artifact: Arc<SemanticArtifact>,
    outcome: Result<Arc<[usize]>, CfgAlgorithmError<ProgramPointId>>,
}

#[derive(Debug)]
struct DeadWriteReachabilityCacheEntry {
    _artifact: Arc<SemanticArtifact>,
    outcome: Result<Arc<Reachability<ProgramPointId>>, CfgAlgorithmError<ProgramPointId>>,
}

fn dead_write_procedure_index(
    derivation: &FlowStateDerivation,
    procedure: &ProcedureHandle,
) -> DeadWriteProcedureIndex {
    let semantics = procedure.semantics();
    let mut events_by_binding: HashMap<ValueId, Vec<usize>> = HashMap::default();
    for event in &derivation.events {
        if let FlowSubject::Binding { value } = event.subject
            && (event.event_class == StateEventClass::Establish
                || event.event_class == StateEventClass::Read
                    && event.read_cause != Some(StateEventReadCause::ScopeEndDrop))
        {
            events_by_binding
                .entry(value)
                .or_default()
                .push(event.event);
        }
    }
    let mut escaped_bindings = HashSet::default();
    for location in semantics.memory_locations() {
        match location.kind {
            MemoryLocationKind::LexicalCell { binding }
            | MemoryLocationKind::Capture {
                binding: Some(binding),
                ..
            } => {
                escaped_bindings.insert(binding);
            }
            _ => {}
        }
    }
    for capture in semantics.captures() {
        match capture.captured {
            crate::analyzer::semantic::CaptureSource::Value(value)
                if capture.mode != crate::analyzer::semantic::CaptureMode::Value =>
            {
                escaped_bindings.insert(value);
            }
            crate::analyzer::semantic::CaptureSource::Location(location) => {
                if let Some(MemoryLocationKind::LexicalCell { binding }) = semantics
                    .memory_location(location)
                    .map(|location| &location.kind)
                {
                    escaped_bindings.insert(*binding);
                }
            }
            _ => {}
        }
    }
    for event in semantics.points().iter().flat_map(|point| &point.events) {
        if let SemanticEffect::Assignment { target, value }
        | SemanticEffect::ValueFlow {
            kind: crate::analyzer::semantic::ValueFlowKind::AddressOf,
            target,
            source: value,
        } = event.effect
            && semantics
                .value(target)
                .is_some_and(|target| target.kind == SemanticValueKind::Address)
        {
            escaped_bindings.insert(value);
        }
    }
    let mut macro_gap_points_by_source: HashMap<SourceMappingId, Vec<ProgramPointId>> =
        HashMap::default();
    for gap in semantics.gaps() {
        if gap.subject == SemanticGapSubject::Point
            && gap.capability == SemanticCapability::NormalControlFlow
            && gap.kind == SemanticGapKind::Unsupported
        {
            macro_gap_points_by_source
                .entry(gap.source)
                .or_default()
                .push(gap.point);
        }
    }
    for points in macro_gap_points_by_source.values_mut() {
        points.sort_unstable();
        points.dedup();
    }
    DeadWriteProcedureIndex {
        _artifact: Arc::clone(procedure.artifact()),
        events_by_binding,
        escaped_bindings,
        macro_gap_points_by_source,
    }
}

#[derive(Debug)]
struct DeadWriteCacheEntry {
    // Keep the pointer-keyed semantic artifact alive for this request.
    _artifact: Arc<SemanticArtifact>,
    outcome: Result<Arc<DeadWritePrepared>, CfgAlgorithmError<ProgramPointId>>,
}

fn prepare_dead_write_over_graph<G>(
    graph: &G,
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    binding_event_ids: &[usize],
    reachable: Arc<Reachability<ProgramPointId>>,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<DeadWritePrepared, CfgAlgorithmError<ProgramPointId>>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut ordered = vec![Vec::<(u32, usize, StateEventClass)>::new(); graph.node_count()];
    for &event_id in binding_event_ids {
        request.visit_pair()?;
        let event = &events[event_id];
        let key = &event_keys[event_id];
        ordered[event.point.index()].push((key.event_index, event.event, event.event_class));
    }
    for row in &mut ordered {
        row.sort_unstable_by_key(|entry| entry.0);
    }
    let mut facts = GenKillFacts::new(graph.node_count(), 1);
    for (index, row) in ordered.iter().enumerate() {
        if let Some(&(_, _, class)) = row.first() {
            if class == StateEventClass::Read {
                facts.record_generated(index, 0);
            }
            if class == StateEventClass::Establish {
                facts.record_killed(index, 0);
            }
        }
    }
    let liveness = live_values(graph, &facts, request)?;
    // A reverse multi-source walk records one shortest explicit read witness
    // for every live point. Establishments are barriers. Successor order
    // resolves equal-distance ties just as the forward witness walk did.
    let mut distance_to_read = vec![usize::MAX; graph.node_count()];
    let mut witness_by_point = vec![None; graph.node_count()];
    let mut queue = VecDeque::new();
    let mut reached_order = Vec::new();
    for (index, row) in ordered.iter().enumerate() {
        if let Some(&(_, read_event, StateEventClass::Read)) = row.first() {
            distance_to_read[index] = 0;
            witness_by_point[index] = Some(read_event);
            queue.push_back(index);
        }
    }
    while let Some(index) = queue.pop_front() {
        request.visit_node()?;
        reached_order.push(index);
        let point = graph.node_at(index).expect("dense control point exists");
        for (_, predecessor) in graph.predecessors(point) {
            request.visit_pair()?;
            let preceding = predecessor.index();
            if distance_to_read[preceding] != usize::MAX
                || ordered[preceding]
                    .first()
                    .is_some_and(|entry| entry.2 == StateEventClass::Establish)
                || !liveness.live_in(preceding, 0)
            {
                continue;
            }
            distance_to_read[preceding] = distance_to_read[index] + 1;
            queue.push_back(preceding);
        }
    }
    for index in reached_order {
        if distance_to_read[index] == 0 {
            continue;
        }
        let point = graph.node_at(index).expect("dense control point exists");
        for (_, successor) in graph.successors(point) {
            request.visit_pair()?;
            if distance_to_read[successor.index()] != usize::MAX
                && distance_to_read[successor.index()] + 1 == distance_to_read[index]
            {
                witness_by_point[index] = witness_by_point[successor.index()];
                break;
            }
        }
    }
    Ok(DeadWritePrepared {
        reachable,
        ordered,
        liveness,
        distance_to_read,
        witness_by_point,
    })
}

fn dead_write_from_prepared<G>(
    graph: &G,
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    establishment_event: usize,
    prepared: &DeadWritePrepared,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<DeadWriteAnswer, CfgAlgorithmError<ProgramPointId>>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let origin = &events[establishment_event];
    if !prepared.reachable.contains(graph, origin.point) {
        return Ok(DeadWriteAnswer::Unreachable);
    }
    let ordered = &prepared.ordered;
    let liveness = &prepared.liveness;
    // The first dynamic visit starts just after the selected establishment.
    // A loop back edge enters the point from its beginning as usual.
    let origin_index = event_keys[establishment_event].event_index;
    let same_point = &ordered[origin.point.index()];
    let next_index = same_point.partition_point(|entry| entry.0 <= origin_index);
    if let Some(&(_, event, class)) = same_point.get(next_index) {
        request.visit_pair()?;
        if class == StateEventClass::Read {
            return Ok(DeadWriteAnswer::Live { read_event: event });
        }
        if class == StateEventClass::Establish {
            return Ok(DeadWriteAnswer::Dead);
        }
    }
    let mut best_distance = usize::MAX;
    let mut witness = None;
    for (_, successor) in graph.successors(origin.point) {
        request.visit_pair()?;
        let index = successor.index();
        if liveness.live_in(index, 0) && prepared.distance_to_read[index] < best_distance {
            best_distance = prepared.distance_to_read[index];
            witness = prepared.witness_by_point[index];
        }
    }
    Ok(
        witness.map_or(DeadWriteAnswer::Dead, |read_event| DeadWriteAnswer::Live {
            read_event,
        }),
    )
}

fn overwritten_unread_over_graph<G>(
    graph: &G,
    inputs: OverwrittenUnreadWalkInputs<'_>,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<OverwrittenUnreadAnswer, CfgAlgorithmError<ProgramPointId>>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let OverwrittenUnreadWalkInputs {
        semantics,
        events,
        event_keys,
        establishment_event,
        binding,
        gaps_by_point,
    } = inputs;
    let origin = &events[establishment_event];
    let unobserved_exit_points = semantics
        .gaps()
        .iter()
        .filter(|gap| gap_has_unobserved_exceptional_exit(gap))
        .map(|gap| gap.point)
        .collect::<HashSet<_>>();
    let reachable = forward_reachability(graph, semantics.entry_point(), request)?;
    if !reachable.contains(graph, origin.point) {
        // #7340: missing prefix edges cannot prove source unreachability. Any
        // reachable gap leaves this entry proof open, independently of the
        // capability axes table and the establishment-to-kill walk.
        let mut reasons = Vec::new();
        for (&point, gaps) in gaps_by_point {
            if reachable.contains(graph, point) {
                for id in gaps {
                    push_gap_reason(
                        &mut reasons,
                        semantics.gap(*id).expect("attributed gap exists"),
                    );
                }
            }
        }
        return Ok(if reasons.is_empty() {
            OverwrittenUnreadAnswer::Unreachable
        } else {
            OverwrittenUnreadAnswer::Open { reasons }
        });
    }

    // A local represented by an address or closure cell is not closed under
    // the ordinary binding events. A value snapshot is different: CaptureBind
    // reads the source binding here, and the child owns a distinct value. Shared,
    // moved and unknown captures still need proof beyond this graph.
    let aliased = semantics
        .memory_locations()
        .iter()
        .try_fold(false, |found, location| {
            request.visit_pair()?;
            Ok::<_, CfgAlgorithmError<ProgramPointId>>(
                found
                    || matches!(
                        location.kind,
                        MemoryLocationKind::LexicalCell { binding: captured }
                            | MemoryLocationKind::Capture {
                                binding: Some(captured),
                                ..
                            } if captured == binding
                    ),
            )
        })?;
    let captured = semantics.captures().iter().try_fold(false, |found, capture| {
        request.visit_pair()?;
        let captures_binding = match capture.captured {
            crate::analyzer::semantic::CaptureSource::Value(value) => {
                value == binding && capture.mode != crate::analyzer::semantic::CaptureMode::Value
            }
            crate::analyzer::semantic::CaptureSource::Location(location) => semantics
                .memory_location(location)
                .is_some_and(|location| {
                    matches!(location.kind, MemoryLocationKind::LexicalCell { binding: value } if value == binding)
                }),
        };
        Ok::<_, CfgAlgorithmError<ProgramPointId>>(found || captures_binding)
    })?;
    let addressed = semantics.points().iter().try_fold(false, |found, point| {
        point.events.iter().try_fold(found, |found, event| {
            request.visit_pair()?;
            Ok::<_, CfgAlgorithmError<ProgramPointId>>(
                found
                    || matches!(
                        event.effect,
                        SemanticEffect::Assignment { target, value } | SemanticEffect::ValueFlow { kind: crate::analyzer::semantic::ValueFlowKind::AddressOf, target, source: value }
                            if value == binding
                                && semantics.value(target).is_some_and(|value| value.kind == SemanticValueKind::Address)
                    ),
            )
        })
    })?;
    if aliased || captured || addressed {
        return Ok(OverwrittenUnreadAnswer::Open {
            reasons: vec![FlowStateIncompleteReason::BindingStateNotClosed { binding }],
        });
    }

    let mut projected = HashMap::default();
    for (event, key) in events.iter().zip(event_keys) {
        request.visit_pair()?;
        if event.subject == (FlowSubject::Binding { value: binding })
            && matches!(
                event.event_class,
                StateEventClass::Read | StateEventClass::Establish
            )
        {
            assert!(
                projected
                    .insert(*key, (event.event, event.event_class))
                    .is_none(),
                "one semantic event projects at most one binding state event"
            );
        }
    }

    // State `point_count` is the first visit to the establishment's point,
    // starting after that event. Every later visit scans the whole point, so
    // re-entering the same static write counts as replacing the old value.
    let point_count = graph.node_count();
    let initial = point_count;
    let mut visited = vec![false; point_count + 1];
    let mut continuing = vec![false; point_count + 1];
    let mut adjacency = vec![Vec::<usize>::new(); point_count + 1];
    let mut queue = VecDeque::from([initial]);
    visited[initial] = true;
    let mut replacements = HashSet::default();
    while let Some(state) = queue.pop_front() {
        request.visit_pair()?;
        let point_id = if state == initial {
            origin.point
        } else {
            graph.node_at(state).expect("visited graph node exists")
        };
        let point = semantics.point(point_id).expect("graph point exists");
        // Reuse the live-value walk, including exceptional continuations. A
        // point-level gap cannot be ordered against events in that point, so
        // keep gaps at the origin and replacement points conservative.
        if let Some(gaps) = gaps_by_point.get(&point_id) {
            let mut reasons = Vec::new();
            for id in gaps {
                push_gap_reason(
                    &mut reasons,
                    semantics.gap(*id).expect("attributed gap exists"),
                );
            }
            return Ok(OverwrittenUnreadAnswer::Open { reasons });
        }
        let start = if state == initial {
            event_keys[establishment_event].event_index as usize + 1
        } else {
            0
        };
        let mut replacement = None;
        for (event_index, semantic_event) in point.events.iter().enumerate().skip(start) {
            request.visit_pair()?;
            let key = SemanticEventKey {
                point: point_id,
                event_index: event_index as u32,
                source: semantic_event.source,
            };
            if let Some(&(event, class)) = projected.get(&key) {
                match class {
                    StateEventClass::Read => {
                        return Ok(OverwrittenUnreadAnswer::ReadBeforeOverwrite {
                            read_event: event,
                        });
                    }
                    StateEventClass::Establish => {
                        replacement = Some(event);
                        break;
                    }
                    StateEventClass::Kill => unreachable!("kills are not projected here"),
                }
            }
            if binding_is_invalidated_by(&semantic_event.effect, binding) {
                return Ok(OverwrittenUnreadAnswer::Open {
                    reasons: vec![FlowStateIncompleteReason::BindingStateNotClosed { binding }],
                });
            }
        }
        if let Some(event) = replacement {
            replacements.insert(event);
            continue;
        }
        if point_id == semantics.normal_exit_point()
            || point_id == semantics.exceptional_exit_point()
        {
            return Ok(OverwrittenUnreadAnswer::PathWithoutOverwrite);
        }
        continuing[state] = true;
        let mut has_successor = false;
        for (edge_id, successor) in graph.successors(point_id) {
            request.visit_pair()?;
            if unobserved_exit_points.contains(&point_id)
                && semantics
                    .control_edge(edge_id)
                    .expect("graph edge belongs to the procedure")
                    .kind
                    == ControlEdgeKind::Exceptional
            {
                continue;
            }
            has_successor = true;
            let next = successor.index();
            adjacency[state].push(next);
            if !visited[next] {
                visited[next] = true;
                queue.push_back(next);
            }
        }
        if !has_successor {
            return Ok(OverwrittenUnreadAnswer::PathWithoutOverwrite);
        }
    }

    // Any cycle in the surviving pre-replacement graph admits a continuation
    // that never replaces the value. Kahn's walk distinguishes this from a
    // diamond that merely joins at an already visited point.
    let mut indegree = vec![0usize; point_count + 1];
    let mut remaining = 0usize;
    for state in 0..=point_count {
        if !continuing[state] {
            continue;
        }
        request.visit_pair()?;
        remaining += 1;
        for &next in &adjacency[state] {
            request.visit_pair()?;
            if continuing[next] {
                indegree[next] += 1;
            }
        }
    }
    let mut ready = (0..=point_count)
        .filter(|&state| continuing[state] && indegree[state] == 0)
        .collect::<VecDeque<_>>();
    while let Some(state) = ready.pop_front() {
        request.visit_pair()?;
        remaining -= 1;
        for &next in &adjacency[state] {
            request.visit_pair()?;
            if continuing[next] {
                indegree[next] -= 1;
                if indegree[next] == 0 {
                    ready.push_back(next);
                }
            }
        }
    }
    if remaining != 0 {
        return Ok(OverwrittenUnreadAnswer::PathWithoutOverwrite);
    }
    let mut replacement_events = replacements.into_iter().collect::<Vec<_>>();
    replacement_events.sort_unstable();
    assert!(
        !replacement_events.is_empty(),
        "a proved continuation has at least one replacement event"
    );
    Ok(OverwrittenUnreadAnswer::Proven { replacement_events })
}

fn loop_repeat_over_graph<G>(
    graph: &G,
    semantics: &ProcedureSemantics,
    site: LoopSourceSite,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<LoopRepeatAnswer, CfgAlgorithmError<ProgramPointId>>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let join_open = |stage| LoopRepeatAnswer::Open {
        reasons: vec![LoopRepeatIncompleteReason::SourceJoin { stage }],
    };
    let within_loop = |span: SourceSpan| {
        site.loop_span.start_byte() <= span.start_byte()
            && span.end_byte() <= site.loop_span.end_byte()
    };
    if !within_loop(site.body_span)
        || site
            .condition_span
            .is_some_and(|condition| !within_loop(condition))
    {
        return Ok(join_open("source_containment"));
    }
    for point in semantics.points() {
        request.visit_pair()?;
        let evidence = semantics
            .evidence_row(point.evidence)
            .expect("validated point has evidence");
        if !matches!(evidence.proof, ProofStatus::Proven)
            || !matches!(evidence.completeness, EvidenceCompleteness::Complete)
        {
            return Ok(LoopRepeatAnswer::Open {
                reasons: vec![LoopRepeatIncompleteReason::ControlEvidence],
            });
        }
    }
    for edge in semantics.control_edges() {
        request.visit_pair()?;
        let evidence = semantics
            .evidence_row(edge.evidence)
            .expect("validated edge has evidence");
        if !matches!(evidence.proof, ProofStatus::Proven)
            || !matches!(evidence.completeness, EvidenceCompleteness::Complete)
        {
            return Ok(LoopRepeatAnswer::Open {
                reasons: vec![LoopRepeatIncompleteReason::ControlEvidence],
            });
        }
    }
    // The producer attests each loop's iteration header and body entry; a
    // span search cannot tell a loop point from a suite or label that shares
    // its span, or from a condition point that each iteration re-enters.
    let mut sites = Vec::new();
    for loop_site in semantics.loop_sites() {
        request.visit_pair()?;
        let mapping = semantics
            .source_mapping(loop_site.source)
            .expect("validated loop site has a source mapping");
        if mapping.kind == SourceMappingKind::Exact
            && mapping.locator.anchor().span() == site.loop_span
        {
            sites.push(loop_site);
        }
    }
    let [loop_site] = sites.as_slice() else {
        return Ok(join_open("loop_site"));
    };
    let header = loop_site.header;
    let body = loop_site.body;
    // The producer-authored body entry is the source identity for the body.
    // Ruby additionally attests a dedicated body source in the loop evidence
    // because its CFG point deliberately covers only the runtime statements.
    let point_body_mapping = semantics
        .source_mapping(
            semantics
                .point(body)
                .expect("validated loop site body point exists")
                .source,
        )
        .expect("validated point has a source mapping");
    let evidence = semantics
        .evidence_row(loop_site.evidence)
        .expect("validated loop site has evidence");
    let mut body_sources = evidence
        .sources
        .iter()
        .copied()
        .filter(|source| *source != loop_site.source);
    let evidence_body_source = body_sources.next();
    assert!(
        body_sources.next().is_none(),
        "a loop site has at most one dedicated body source"
    );
    if let Some(source) = evidence_body_source {
        let mapping = semantics
            .source_mapping(source)
            .expect("validated loop evidence body source exists");
        if mapping.kind != SourceMappingKind::Exact {
            return Ok(join_open("body_entry"));
        }
    } else {
        // Older producers attest only the loop source and body point. Keep
        // their conservative source-containment check until they publish a
        // dedicated body source like Ruby does.
        let body_span = point_body_mapping.locator.anchor().span();
        let body_matches = body_span == site.body_span
            || (site.kind == LoopSourceKind::Do && body_span == site.loop_span);
        if point_body_mapping.kind != SourceMappingKind::Exact || !body_matches {
            return Ok(join_open("body_entry"));
        }
    }

    let entry_reachability = forward_reachability(graph, semantics.entry_point(), request)?;
    let mut exit = None;
    let mut intentional_constant_false_do = false;
    if let Some(condition) = site.condition_span {
        let mut guards = Vec::new();
        for guard in semantics.guard_facts() {
            request.visit_pair()?;
            let mapping = semantics
                .source_mapping(guard.source)
                .expect("validated guard has a source mapping");
            let guard_span = mapping.locator.anchor().span();
            let within_condition = mapping.kind == SourceMappingKind::Exact
                && condition.start_byte() <= guard_span.start_byte()
                && guard_span.end_byte() <= condition.end_byte();
            let folded_while_at_header = site.kind == LoopSourceKind::While
                && guard.point == header
                && guard.predicate.constant_value().is_some();
            let enters_body = match site.kind {
                LoopSourceKind::Until => guard.false_edge.is_some_and(|edge| {
                    semantics
                        .control_edge(edge)
                        .is_some_and(|edge| edge.target_point == body)
                }),
                _ => guard.true_edge.is_some_and(|edge| {
                    semantics
                        .control_edge(edge)
                        .is_some_and(|edge| edge.target_point == body)
                }),
            };
            let constant_exit_arm = match site.kind {
                LoopSourceKind::Until => {
                    guard.predicate.constant_value() == Some(true) && guard.true_edge.is_some()
                }
                _ => guard.predicate.constant_value() == Some(false) && guard.false_edge.is_some(),
            };
            if (within_condition || folded_while_at_header) && (enters_body || constant_exit_arm) {
                guards.push(guard);
            }
        }
        if guards.len() != 1 {
            // A post-test body may terminate before its condition. In that
            // case the retained CFG has no reachable condition guard, and
            // the graph walk below can prove whether the body has its own
            // repeat edge without inventing a guard fact.
            let condition_reachable = entry_reachability.contains(graph, header);
            if condition_reachable {
                return Ok(join_open("guard"));
            }
        } else {
            let guard = guards[0];
            let evidence = semantics
                .evidence_row(guard.evidence)
                .expect("validated guard has evidence");
            if !matches!(evidence.proof, ProofStatus::Proven)
                || !matches!(evidence.completeness, EvidenceCompleteness::Complete)
            {
                return Ok(LoopRepeatAnswer::Open {
                    reasons: vec![LoopRepeatIncompleteReason::GuardEvidence],
                });
            }
            intentional_constant_false_do =
                site.kind == LoopSourceKind::Do && guard.predicate.constant_value() == Some(false);
            let exit_edge = match site.kind {
                LoopSourceKind::Until => guard.true_edge,
                _ => guard.false_edge,
            };
            if let Some(exit_edge) = exit_edge {
                let edge = semantics
                    .control_edge(exit_edge)
                    .expect("validated guard edge exists");
                let expected_kind = match site.kind {
                    LoopSourceKind::Until => ControlEdgeKind::ConditionalTrue,
                    _ => ControlEdgeKind::ConditionalFalse,
                };
                if edge.source_point != guard.point || edge.kind != expected_kind {
                    return Ok(join_open("false_edge"));
                }
                exit = Some(edge.target_point);
            } else if guard.predicate.constant_value()
                != Some(!matches!(site.kind, LoopSourceKind::Until))
            {
                return Ok(join_open("false_arm"));
            }
        }
    } else if site.kind != LoopSourceKind::For {
        return Ok(join_open("condition"));
    }

    if !entry_reachability.contains(graph, body) {
        return Ok(LoopRepeatAnswer::UnreachableBody);
    }
    let mut visited = vec![false; graph.node_count()];
    let mut queue = VecDeque::from([body]);
    visited[body.index()] = true;
    while let Some(point) = queue.pop_front() {
        request.visit_pair()?;
        if Some(point) == exit
            || point == semantics.normal_exit_point()
            || point == semantics.exceptional_exit_point()
        {
            continue;
        }
        // One iteration ends when control leaves this loop's source region.
        // In particular, an enclosing loop may later enter this source loop
        // again without traversing this loop's own back edge. Cleanup authored
        // inside the loop stays in the walk and can still override an exit.
        let point_source = semantics
            .source_mapping(
                semantics
                    .point(point)
                    .expect("graph point belongs to procedure")
                    .source,
            )
            .expect("validated point has a source mapping");
        if point_source.kind != SourceMappingKind::Exact {
            return Ok(join_open("iteration_boundary"));
        }
        if !within_loop(point_source.locator.anchor().span()) {
            continue;
        }
        for (edge_id, target) in graph.successors(point) {
            request.visit_pair()?;
            let body_repeat = target == body
                && semantics
                    .control_edge(edge_id)
                    .is_some_and(|edge| edge.kind == ControlEdgeKind::LoopBack);
            if target == header
                // Ruby's `redo` repeats the current body without re-running
                // its condition. The producer targets the exact body entry,
                // so retain that explicit body loop-back as repetition while
                // leaving nested-loop headers distinct.
                || body_repeat
            {
                // A conditional arm can return directly to the proven header;
                // it retains ConditionalTrue/False rather than LoopBack. Once
                // bounded to this iteration, either edge proves repetition.
                return Ok(LoopRepeatAnswer::MayRepeat { edge: edge_id });
            }
            if !visited[target.index()] {
                visited[target.index()] = true;
                queue.push_back(target);
            }
        }
    }
    Ok(LoopRepeatAnswer::NoRepeat {
        intentional_constant_false_do,
    })
}

/// Project only binding events into the shared IR transfer kernel.
fn binding_initialization_events(
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
) -> Vec<BindingInitializationEvent> {
    assert_eq!(events.len(), event_keys.len());
    events
        .iter()
        .zip(event_keys)
        .filter_map(|(event, key)| {
            let FlowSubject::Binding { value: binding } = event.subject else {
                return None;
            };
            matches!(
                event.event_class,
                StateEventClass::Read | StateEventClass::Establish
            )
            .then_some(BindingInitializationEvent {
                event: event.event,
                key: *key,
                binding,
                establishes: event.event_class == StateEventClass::Establish,
            })
        })
        .collect()
}

fn binding_is_invalidated_by(effect: &SemanticEffect, binding: ValueId) -> bool {
    invalidated_binding(effect) == Some(binding)
}

/// Reaching rows.
///
/// Exactness rule: a reaching establishment `E` serves a read `R` with `Exact`
/// certainty when `E` is the *only* definition of `R`'s subject in the read
/// point's IN set **and** `E`'s point dominates `R`'s point. The first
/// conjunct rules out a join that carries a second definition; the second
/// rules out a path that reaches the read without passing the write at all
/// (a one-armed conditional's IN set carries only the one write, but some
/// entry-to-read path misses it). Anything else is `May`.
fn reaching_relations<G>(
    graph: &G,
    events: &[StateEventRow],
    definitions: &BindingDefinitions,
    reaching: &ReachingSets,
    dominance: &Dominators<ProgramPointId>,
    generation: u64,
) -> Vec<FlowRelationRow>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut rows = Vec::new();
    for read in events.iter().filter(|event| {
        event.event_class == StateEventClass::Read
            && matches!(&event.subject, FlowSubject::Binding { .. })
    }) {
        let point = read.point.index();
        let live = reaching
            .reaching_in(point)
            .filter(|definition| {
                *definition < definitions.events().len()
                    && definitions.binding(*definition) == read.subject.value()
            })
            .collect::<Vec<_>>();
        for definition in live.iter().copied() {
            let establishment = definitions.events()[definition];
            let establishment_point = events[establishment].point;
            let certainty =
                if live.len() == 1 && dominance.dominates(graph, establishment_point, read.point) {
                    FlowCertainty::Exact
                } else {
                    FlowCertainty::May
                };
            rows.push(FlowRelationRow {
                relation: FlowRelation::Reaching,
                certainty,
                source_event: establishment,
                target_event: read.event,
                procedure: read.procedure,
                generation,
            });
        }
    }
    rows
}

/// Project analysis-owned property rows into flow-state's presentation
/// vocabulary. The relation has already been keyed by the durable receiver,
/// access path, and structured member in `bifrost-analysis`; the `FlowSubject`
/// on each event is only a source-facing presentation value.
fn property_reaching_relations(
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    property_result: &PropertyReachingResult,
    skipped: &SkippedCopies,
    generation: u64,
) -> Vec<FlowRelationRow> {
    let forwarded = ForwardedReaching::new(property_result, skipped);
    let mut rows = Vec::new();
    for relation in property_result.reaching() {
        let Some(target_event) = property_event_id(
            events,
            event_keys,
            StateEventClass::Read,
            relation.read.point.id(),
            relation.read.event_index,
            relation.read.source,
        ) else {
            continue;
        };
        for (store, certainty) in forwarded.origins(&relation.store, relation.certainty) {
            let Some(source_event) = property_event_id(
                events,
                event_keys,
                StateEventClass::Establish,
                store.point.id(),
                store.event_index,
                store.source,
            ) else {
                continue;
            };
            rows.push(FlowRelationRow {
                relation: FlowRelation::Reaching,
                certainty: match certainty {
                    PropertyReachCertainty::Exact => FlowCertainty::Exact,
                    PropertyReachCertainty::May => FlowCertainty::May,
                },
                source_event,
                target_event,
                procedure: relation.read.procedure.id(),
                generation,
            });
        }
    }

    merge_forwarded_relation_rows(rows)
}

/// Merge relation rows that name the same pair of events.
///
/// A store reaches a read both directly and through a skipped copy whose load
/// it feeds, so forwarding can project one pair twice. The pair keeps one row,
/// and its certainty is `May` when either projection is `May`.
fn merge_forwarded_relation_rows(rows: Vec<FlowRelationRow>) -> Vec<FlowRelationRow> {
    let mut merged: Vec<FlowRelationRow> = Vec::with_capacity(rows.len());
    let mut positions = HashMap::<(FlowRelation, usize, usize), usize>::default();
    for row in rows {
        match positions.entry((row.relation, row.source_event, row.target_event)) {
            std::collections::hash_map::Entry::Occupied(position) => {
                let kept = &mut merged[*position.get()];
                if row.certainty == FlowCertainty::May {
                    kept.certainty = FlowCertainty::May;
                }
            }
            std::collections::hash_map::Entry::Vacant(position) => {
                position.insert(merged.len());
                merged.push(row);
            }
        }
    }
    merged
}

fn property_flow_relations<G>(
    graph: &G,
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    property_result: &PropertyReachingResult,
    skipped: &SkippedCopies,
    dominance: &Dominators<ProgramPointId>,
    generation: u64,
) -> Vec<FlowRelationRow>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut rows =
        property_reaching_relations(events, event_keys, property_result, skipped, generation);
    let forwarded = ForwardedReaching::new(property_result, skipped);

    for written in property_result.stores() {
        // A skipped copy store dominates nothing itself; the stores that
        // supply its value dominate the reads of the location it wrote.
        for (store, _) in forwarded.origins(written, PropertyReachCertainty::Exact) {
            let Some(source_event) = property_event_id(
                events,
                event_keys,
                StateEventClass::Establish,
                store.point.id(),
                store.event_index,
                store.source,
            ) else {
                continue;
            };
            for read in property_result
                .reads()
                .iter()
                .filter(|read| read.location == written.location)
                .filter(|read| read.point.id() != store.point.id())
            {
                if !dominance.dominates(graph, store.point.id(), read.point.id()) {
                    continue;
                }
                let Some(target_event) = property_event_id(
                    events,
                    event_keys,
                    StateEventClass::Read,
                    read.point.id(),
                    read.event_index,
                    read.source,
                ) else {
                    continue;
                };
                rows.push(FlowRelationRow {
                    relation: FlowRelation::Dominates,
                    certainty: FlowCertainty::Exact,
                    source_event,
                    target_event,
                    procedure: store.procedure.id(),
                    generation,
                });
                if store.strong_update
                    && let Some(kill_event) = property_event_id(
                        events,
                        event_keys,
                        StateEventClass::Kill,
                        store.point.id(),
                        store.event_index,
                        store.source,
                    )
                {
                    rows.push(FlowRelationRow {
                        relation: FlowRelation::Dominates,
                        certainty: FlowCertainty::Exact,
                        source_event: kill_event,
                        target_event,
                        procedure: store.procedure.id(),
                        generation,
                    });
                }
            }
        }
    }
    merge_forwarded_relation_rows(rows)
}

fn property_event_id(
    events: &[StateEventRow],
    event_keys: &[SemanticEventKey],
    event_class: StateEventClass,
    point: ProgramPointId,
    event_index: u32,
    source: SourceMappingId,
) -> Option<usize> {
    assert_eq!(
        events.len(),
        event_keys.len(),
        "each projected event has one semantic join key"
    );
    events
        .iter()
        .zip(event_keys.iter())
        .find_map(|(event, key)| {
            (event.event_class == event_class
                && key.point == point
                && key.event_index == event_index
                && key.source == source
                && matches!(&event.subject, FlowSubject::Property { .. }))
            .then_some(event.event)
        })
}

/// Dominance rows, restricted to write/read pairs of one subject so the row
/// volume stays bounded by the events the reaching relation already pairs.
///
/// Dominance is a separate relation from all-paths reaching on purpose: it
/// states that every entry-to-read path passes the write's point, and says
/// nothing about whether the write's value survives to the read. Rows are
/// emitted only between distinct program points: two events at one point are
/// ordered inside the point, which dominance does not describe.
fn dominance_relations<G>(
    graph: &G,
    events: &[StateEventRow],
    dominance: &Dominators<ProgramPointId>,
    generation: u64,
) -> Vec<FlowRelationRow>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut rows = Vec::new();
    for write in events.iter().filter(|event| {
        matches!(
            event.event_class,
            StateEventClass::Establish | StateEventClass::Kill
        ) && matches!(&event.subject, FlowSubject::Binding { .. })
    }) {
        for read in events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Read)
            .filter(|event| matches!(&event.subject, FlowSubject::Binding { .. }))
            .filter(|event| event.subject == write.subject)
            .filter(|event| event.point != write.point)
        {
            if dominance.dominates(graph, write.point, read.point) {
                rows.push(FlowRelationRow {
                    relation: FlowRelation::Dominates,
                    certainty: FlowCertainty::Exact,
                    source_event: write.event,
                    target_event: read.event,
                    procedure: write.procedure,
                    generation,
                });
            }
        }
    }
    rows
}

/// Same-evaluation rows.
///
/// Derived from the IR's own intra-evaluation value dependence: the read's
/// produced value feeds, through `ValueFlow`, non-binding assignments, field
/// loads, and call-site operands, the very value the establishment assigns.
/// The walk deliberately never crosses an assignment *into* a binding, because
/// that edge is the flow-sensitive step this layer exists to measure: crossing
/// it would relate a read to every later statement that transitively consumes
/// the binding.
fn same_evaluation_relations(
    procedure: &ProcedureSemantics,
    events: &[StateEventRow],
    generation: u64,
) -> Vec<FlowRelationRow> {
    let dependence = EvaluationDependence::build(procedure);
    let reads = events
        .iter()
        .filter(|event| event.event_class == StateEventClass::Read)
        .collect::<Vec<_>>();
    let mut rows = Vec::new();
    for establishment in events
        .iter()
        .filter(|event| event.event_class == StateEventClass::Establish)
    {
        let operands = dependence.operands_of(establishment.value, procedure.values().len());
        for read in reads.iter().filter(|read| operands.contains(&read.value)) {
            rows.push(FlowRelationRow {
                relation: FlowRelation::SameEvaluation,
                certainty: FlowCertainty::Exact,
                source_event: establishment.event,
                target_event: read.event,
                procedure: establishment.procedure,
                generation,
            });
        }
    }
    rows
}

/// Intra-evaluation value dependence: value -> the values it is computed from.
struct EvaluationDependence {
    sources: HashMap<ValueId, Vec<DependenceEdge>>,
}

/// One value-dependence edge. An `address` edge is the base, index or address
/// operand of a memory access: the loaded value is selected by that operand
/// but does not carry it.
#[derive(Clone, Copy)]
struct DependenceEdge {
    source: ValueId,
    address: bool,
}

impl EvaluationDependence {
    fn build(procedure: &ProcedureSemantics) -> Self {
        let mut sources: HashMap<ValueId, Vec<DependenceEdge>> = HashMap::default();
        let mut record_edge = |target: ValueId, source: ValueId, address: bool| {
            sources
                .entry(target)
                .or_default()
                .push(DependenceEdge { source, address });
        };

        for point in procedure.points() {
            for event in point.events.iter() {
                match &event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        let binding = procedure
                            .value(*target)
                            .is_some_and(|value| value.kind.is_binding());
                        if !binding {
                            record_edge(*target, *value, false);
                        }
                    }
                    SemanticEffect::ValueFlow { source, target, .. } => {
                        record_edge(*target, *source, false)
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => {
                        if let Some(location) = procedure.memory_location(*location) {
                            match &location.kind {
                                MemoryLocationKind::Field { base, .. }
                                | MemoryLocationKind::Property { base, .. }
                                | MemoryLocationKind::Dereference { address: base } => {
                                    record_edge(*result, *base, true)
                                }
                                MemoryLocationKind::Index { base, index, .. } => {
                                    record_edge(*result, *base, true);
                                    if let Some(index) = index {
                                        record_edge(*result, *index, true);
                                    }
                                }
                                // A lexical cell load reads the binding's own
                                // value, so the binding is carried, not an
                                // address that selects some other value.
                                MemoryLocationKind::LexicalCell { binding } => {
                                    record_edge(*result, *binding, false);
                                }
                                MemoryLocationKind::Static { .. }
                                | MemoryLocationKind::Capture { .. } => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        for call_site in procedure.call_sites() {
            let Some(result) = call_site.result else {
                continue;
            };
            record_edge(result, call_site.callee, false);
            if let Some(receiver) = call_site.receiver {
                record_edge(result, receiver, false);
            }
            for argument in call_site.arguments.iter() {
                record_edge(result, argument.value, false);
            }
        }
        Self { sources }
    }

    /// Every value `value` is computed from, `value` included. The walk is an
    /// explicit stack bounded by the procedure's own value count, so a cyclic
    /// dependence cannot make it diverge.
    fn operands_of(&self, value: ValueId, value_count: usize) -> HashSet<ValueId> {
        self.walk(value, value_count, true)
    }

    /// The values `value` carries: [`Self::operands_of`] without the base,
    /// index and address operands of memory accesses.
    fn carried_operands_of(&self, value: ValueId, value_count: usize) -> HashSet<ValueId> {
        self.walk(value, value_count, false)
    }

    fn walk(
        &self,
        value: ValueId,
        value_count: usize,
        through_addresses: bool,
    ) -> HashSet<ValueId> {
        let mut visited = HashSet::default();
        let mut stack = vec![value];
        while let Some(current) = stack.pop() {
            if !visited.insert(current) {
                continue;
            }
            debug_assert!(
                visited.len() <= value_count.saturating_add(1),
                "value dependence visited more values than the procedure owns"
            );
            if let Some(edges) = self.sources.get(&current) {
                stack.extend(
                    edges
                        .iter()
                        .filter(|edge| through_addresses || !edge.address)
                        .map(|edge| edge.source),
                );
            }
        }
        visited
    }
}

#[cfg(test)]
fn test_request(cancellation: &CancellationToken) -> FlowStateRequest<'_> {
    FlowStateRequest::new(
        cancellation,
        FlowStateRequestMemos::new(&RetentionBudget::for_test_capacity(64 * 1024 * 1024)),
    )
}

impl RetainedBytes for DeadWriteProcedureIndex {
    fn retained_bytes(&self) -> usize {
        let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::allocated();
        // Artifact backing is independently accounted by the semantic owner.
        heap.map(&self.events_by_binding);
        for events in self.events_by_binding.values() {
            heap.vec(events);
        }
        heap.hash_set(&self.escaped_bindings);
        heap.map(&self.macro_gap_points_by_source);
        for points in self.macro_gap_points_by_source.values() {
            heap.vec(points);
        }
        std::mem::size_of::<Self>() + heap.total()
    }
}
impl RetainedBytes for DeadWriteReachabilityCacheEntry {
    fn retained_bytes(&self) -> usize {
        let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::allocated();
        if let Ok(value) = &self.outcome {
            heap.arc(value, |value, heap| heap.add(value.allocated_heap_bytes()));
        }
        std::mem::size_of::<Self>() + heap.total()
    }
}
impl RetainedBytes for DeadWriteCacheEntry {
    fn retained_bytes(&self) -> usize {
        let mut heap = crate::analyzer::store::cache_budget::RetainedHeap::allocated();
        if let Ok(value) = &self.outcome {
            heap.arc(value, |value, heap| {
                heap.arc(&value.reachable, |reachable, heap| {
                    heap.add(reachable.allocated_heap_bytes())
                });
                heap.vec(&value.ordered);
                for events in &value.ordered {
                    heap.vec(events);
                }
                heap.add(value.liveness.allocated_heap_bytes());
                heap.vec(&value.distance_to_read);
                heap.vec(&value.witness_by_point);
            });
        }
        std::mem::size_of::<Self>() + heap.total()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::ExecutionTiming;
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;
    use crate::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
        compile_source,
    };
    use crate::analyzer::{AnalyzerConfig, Language};
    use brokk_bifrost_test_macros::hardwon;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    struct Fixture {
        _project: BuiltInlineTestProject,
        workspace: WorkspaceAnalyzer,
        files: Vec<ProjectFile>,
    }

    impl Fixture {
        fn new(language: Language, sources: &[(&str, &str)]) -> Self {
            let mut project = InlineTestProject::with_language(language);
            for (relative_path, source) in sources {
                project = project.file(*relative_path, *source);
            }
            let project = project.build();
            let files = sources
                .iter()
                .map(|(relative_path, _)| project.file(relative_path))
                .collect::<Vec<_>>();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            Self {
                _project: project,
                workspace,
                files,
            }
        }

        fn state(&self, index: usize) -> FileFlowState {
            let cancellation = CancellationToken::default();
            flow_state_for_file(
                &self.workspace,
                &self.files[index],
                &mut test_request(&cancellation),
            )
        }

        fn materialized(&self, index: usize) -> SemanticOutcome<Arc<SemanticArtifact>> {
            let cancellation = CancellationToken::default();
            let mut budget =
                SemanticBudget::new(SemanticWork::default_limits()).expect("valid test budget");
            self.workspace
                .materialize_program_semantics(
                    &self.files[index],
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("test semantics materialize")
        }

        fn state_with_budget(&self, index: usize, budget: CfgAlgorithmBudget) -> FileFlowState {
            let cancellation = CancellationToken::default();
            let mut request = test_request(&cancellation);
            request.cfg_budget = budget;
            flow_state_for_file(&self.workspace, &self.files[index], &mut request)
        }

        fn state_with_control_projection(
            &self,
            index: usize,
            projection: &FlowControlProjection,
        ) -> FileFlowState {
            let cancellation = CancellationToken::default();
            let mut request = test_request(&cancellation).with_control_projection(projection);
            flow_state_for_file(&self.workspace, &self.files[index], &mut request)
        }

        fn state_with_active_models(
            &self,
            index: usize,
            snapshot: &Arc<ActiveSemanticModelSnapshot>,
        ) -> FileFlowState {
            let cancellation = CancellationToken::default();
            let mut request = test_request(&cancellation)
                .with_active_semantic_model_snapshot(Some(Arc::clone(snapshot)));
            flow_state_for_file(&self.workspace, &self.files[index], &mut request)
        }

        fn activate_models(&self, source: &str) -> Arc<ActiveSemanticModelSnapshot> {
            self.activate_model_sources(&[("test:flow-nonreturn", source)])
        }

        fn activate_exact_nonreturn_models(&self) -> Arc<ActiveSemanticModelSnapshot> {
            self.activate_model_sources(&[
                (
                    "test:flow-nonreturn-declarations",
                    GO_NONRETURN_DECLARATIONS,
                ),
                ("test:flow-nonreturn", GO_NONRETURN_MODEL),
            ])
        }

        fn activate_model_sources(
            &self,
            sources: &[(&str, &str)],
        ) -> Arc<ActiveSemanticModelSnapshot> {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
                .expect("ephemeral semantic-model catalog");
            for (source_id, source) in sources {
                let pack = compile_source(
                    SourceFormat::Json,
                    source.as_bytes(),
                    &CompilerOptions::default(),
                )
                .unwrap_or_else(|diagnostics| {
                    panic!("test semantic model must compile: {diagnostics:#?}")
                });
                catalog
                    .register_session_pack(
                        &pack,
                        &SessionPackSource {
                            kind: SessionPackSourceKind::Embedded,
                            source_id: (*source_id).to_owned(),
                        },
                    )
                    .expect("register the test semantic model");
            }
            self.activate_catalog(&catalog)
        }

        fn activate_empty_models(&self) -> Arc<ActiveSemanticModelSnapshot> {
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
                .expect("ephemeral empty semantic-model catalog");
            self.activate_catalog(&catalog)
        }

        fn activate_catalog(
            &self,
            catalog: &SemanticPackCatalog,
        ) -> Arc<ActiveSemanticModelSnapshot> {
            let request =
                brokk_bifrost_analysis::test_support::go_semantic_model_activation_request(None);
            match acquire_active_semantic_models(
                self.workspace.analyzer(),
                catalog,
                None,
                &request,
                &CancellationToken::default(),
            ) {
                SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
                outcome => panic!("test semantic model must activate: {outcome:#?}"),
            }
        }

        fn procedure(&self, index: usize, id: ProcedureId) -> ProcedureHandle {
            let outcome = self.materialized(index);
            outcome
                .available_value()
                .expect("test semantics are available")
                .procedure_handle(id)
                .expect("the test artifact owns its derived procedure")
        }
    }

    #[test]
    fn procedure_public_digest_is_mount_independent_and_structurally_separated() {
        const SOURCE: &str = r#"package sample

func first(input int) int { return input }
func second(input int) int { return input }
"#;
        let first_mount = Fixture::new(Language::Go, &[("main.go", SOURCE)]);
        let second_mount = Fixture::new(Language::Go, &[("main.go", SOURCE)]);
        let first = first_mount.procedure(0, ProcedureId::new(0));
        let remounted_first = second_mount.procedure(0, ProcedureId::new(0));
        let second = first_mount.procedure(0, ProcedureId::new(1));

        assert_eq!(
            procedure_public_digest(&first),
            procedure_public_digest(&remounted_first),
            "an equivalent checkout mount must not rotate public identity"
        );
        assert_eq!(
            procedure_wire_id(&first),
            procedure_public_digest(&first).to_string(),
            "rendered and binary procedure identities share one recipe"
        );
        assert_ne!(
            procedure_public_digest(&first),
            procedure_public_digest(&second),
            "distinct structured procedure locators must remain separate"
        );

        let changed = Fixture::new(
            Language::Go,
            &[(
                "main.go",
                r#"package sample

func first(input int) int { return input + 1 }
func second(input int) int { return input }
"#,
            )],
        );
        assert_ne!(
            procedure_public_digest(&first),
            procedure_public_digest(&changed.procedure(0, ProcedureId::new(0))),
            "artifact content must remain part of the public root identity"
        );
    }

    #[test]
    fn masked_procedure_graph_preserves_exact_bidirectional_iteration() {
        let fixture = Fixture::new(
            Language::Go,
            &[(
                "main.go",
                r#"package sample
func choose(flag bool) int {
    value := 0
    if flag {
        value = 1
    } else {
        value = 2
    }
    return value
}
"#,
            )],
        );
        let state = fixture.state(0);
        let derivation = state
            .procedures
            .iter()
            .max_by_key(|derivation| derivation.events.len())
            .expect("the fixture lowers one callable procedure");
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        assert!(
            semantics.control_edges().len() >= 3,
            "the branch fixture supplies first, middle, and last edges"
        );
        let edges = semantics.control_edges();
        let omitted = [0, edges.len() / 2, edges.len() - 1]
            .map(|index| ControlEdgeId::try_from_index(index).expect("fixture edge index fits"))
            .into_iter()
            .collect::<HashSet<_>>();
        let mask = ControlEdgeMask::new(semantics, omitted.iter().copied());
        let graph = ProjectedProcedureGraph::new(semantics, &mask);

        for index in 0..semantics.points().len() {
            let point = ProgramPointId::try_from_index(index).expect("fixture point index fits");
            let expected_successors = DenseBidirectionalGraph::successors(semantics, point)
                .filter(|(edge, _)| !omitted.contains(edge))
                .collect::<Vec<_>>();
            let successors = DenseBidirectionalGraph::successors(&graph, point);
            assert_eq!(successors.len(), expected_successors.len());
            assert_eq!(successors.collect::<Vec<_>>(), expected_successors);
            assert_eq!(
                DenseBidirectionalGraph::successors(&graph, point)
                    .rev()
                    .collect::<Vec<_>>(),
                expected_successors
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
            );

            let expected_predecessors = DenseBidirectionalGraph::predecessors(semantics, point)
                .filter(|(edge, _)| !omitted.contains(edge))
                .collect::<Vec<_>>();
            let predecessors = DenseBidirectionalGraph::predecessors(&graph, point);
            assert_eq!(predecessors.len(), expected_predecessors.len());
            assert_eq!(predecessors.collect::<Vec<_>>(), expected_predecessors);
            assert_eq!(
                DenseBidirectionalGraph::predecessors(&graph, point)
                    .rev()
                    .collect::<Vec<_>>(),
                expected_predecessors
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
            );
        }

        for (index, edge) in semantics.control_edges().iter().enumerate() {
            let edge_id = ControlEdgeId::try_from_index(index).expect("fixture edge index fits");
            let expected =
                (!omitted.contains(&edge_id)).then_some((edge.source_point, edge.target_point));
            assert_eq!(
                DenseBidirectionalGraph::edge_endpoints(&graph, edge_id),
                expected
            );
        }
    }

    /// The derivation of the procedure whose source span covers `needle`'s
    /// first byte in `source`.
    fn procedure_containing(
        state: &FileFlowState,
        events_with: impl Fn(&StateEventRow) -> bool,
    ) -> &FlowStateDerivation {
        state
            .procedures
            .iter()
            .find(|derivation| derivation.events.iter().any(&events_with))
            .expect("a procedure whose events match the predicate")
    }

    fn spelling<'a>(source: &'a str, event: &StateEventRow) -> &'a str {
        &source[event.site.range.start_byte..event.site.range.end_byte]
    }

    fn gap_spelled<'a>(
        procedure: &'a ProcedureHandle,
        source: &str,
        expected: &str,
    ) -> &'a SemanticGap {
        procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                let mapping = procedure
                    .semantics()
                    .source_mapping(gap.source)
                    .expect("a gap has a source mapping");
                let span = mapping.locator.anchor().span();
                &source[span.start_byte() as usize..span.end_byte() as usize] == expected
            })
            .unwrap_or_else(|| panic!("{expected} publishes a gap"))
    }

    fn two_result_read_points(
        derivation: &FlowStateDerivation,
        source: &str,
    ) -> (ProgramPointId, ProgramPointId, ProgramPointId) {
        let establishment = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(source, event) == "exact := value"
            })
            .expect("the exact result binding is established")
            .point;
        let mut exact_reads = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(source, event) == "exact.value"
            })
            .map(|event| (event.event, event.point))
            .collect::<Vec<_>>();
        exact_reads.sort_unstable();
        let [(_, candidate), (_, target)] = exact_reads.as_slice() else {
            panic!("the two exact result reads are materialized: {exact_reads:#?}");
        };
        (establishment, *candidate, *target)
    }

    fn call_handles_spelled(
        procedure: &ProcedureHandle,
        source: &str,
        expected: &str,
    ) -> Vec<CallSiteHandle> {
        let semantics = procedure.semantics();
        semantics
            .call_sites()
            .iter()
            .filter(|call| {
                let mapping = semantics
                    .source_mapping(call.source)
                    .expect("validated call has a source mapping");
                let span = mapping.locator.anchor().span();
                &source[span.start_byte() as usize..span.end_byte() as usize] == expected
            })
            .map(|call| {
                procedure
                    .call_site_handle(call.id)
                    .expect("the procedure owns the call site")
            })
            .collect()
    }

    fn call_handle_spelled(
        procedure: &ProcedureHandle,
        source: &str,
        expected: &str,
    ) -> CallSiteHandle {
        let mut calls = call_handles_spelled(procedure, source, expected);
        assert_eq!(
            calls.len(),
            1,
            "{expected} must name one semantic call site: {calls:#?}"
        );
        calls.pop().expect("the exact call count was checked")
    }

    fn normal_edge_for_call(procedure: &ProcedureHandle, call: &CallSiteHandle) -> ControlEdgeId {
        assert_eq!(call.procedure(), procedure);
        let semantics = procedure.semantics();
        let call = semantics
            .call_site(call.id())
            .expect("the procedure owns the call site");
        let target = call
            .normal_continuation
            .target()
            .expect("the call has a normal continuation");
        let edges = normal_control_edges_to_target(semantics, call.point, target);
        assert_eq!(
            edges.len(),
            1,
            "a normal call continuation has one exact source edge: {edges:?}"
        );
        edges[0]
    }

    const GO_UNRESOLVED_IMPORTED_FIELD_ACCESS: &str = r#"
package sample

import (
    "net/http"
    "net/url"
)

func observations(raw string, request *http.Request) string {
    parsed, _ := url.Parse(raw)
    request.URL = parsed
    return parsed.Scheme
}
"#;

    const GO_VALIDATOR_RESULT_ARGUMENT_ORDER: &str = r#"
package sample

func checked(value error) string { return "checked" }
func use(first string, second string) {}
func mutate(target *error) string { return "mutated" }
func publish(target *error) string { return "published" }

func safe(value error) {
    use(checked(value), "constant")
}

func invalidated(value error) {
    use(checked(value), mutate(&value))
}

func afterReceive(ch chan int, value error) {
    observed := <-ch
    _ = observed
    use(checked(value), "constant")
}

func escaped(value error) {
    use(publish(&value), checked(value))
}

func captured(value error) {
    mutate := func() string { value = nil; return "mutated" }
    use(checked(value), mutate())
}
"#;

    const JS_PROJECTED_NONRETURN_REACHING: &str = r#"
function abort() {}

function branch(flag) {
  const ns = {};
  ns.value = 1;
  if (flag) {
    ns.value = 2;
    abort();
  }
  return ns.value;
}
"#;

    const GO_CONTROL_GAP_AT_TARGET: &str = r#"
package sample

type item struct { value int }

func read(value *item) int {
    ready := true
    _ = ready
    return value.value
}
"#;

    const JS_READ_BEFORE_ESTABLISHMENT: &str = r#"
function beforeEstablishment() {
  const ns = {};
  const early = ns.value;
  ns.value = 1;
  return early;
}
"#;

    const TS_READ_BEFORE_ESTABLISHMENT: &str = r#"
function beforeEstablishment(): number | undefined {
  const ns: { value?: number } = {};
  const early = ns.value;
  ns.value = 1;
  return early;
}
"#;

    const JS_SHADOW_REBIND: &str = r#"
function shadowRebind(flag) {
  let value = 1;
  if (flag) {
    let inner = 2;
    return inner;
  }
  value = 3;
  return value;
}
"#;

    const GO_AGGREGATE_COPY_VALUE_ALIAS: &str = r#"package app

type resource struct{}

func copyValue() {
    original := [1]*resource{}
    copied := original
    _ = copied[0]
}
"#;

    const GO_MAY_ASSIGNMENT_CONVERSION_ALIAS: &str = r#"package app

type resource struct{}

func acquire() *resource { return nil }

func mayConversionAlias(change bool, acquire func() *resource) any {
	source := acquire()
	if change {
		source = nil
	}
	var converted any = source
	return converted
}
"#;

    const GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS: &str = r#"
package sample

type item struct { value int }

func observe(bool) {}
func pause() {}

func linear(result *item, condition bool) int {
    linearResult := result
    go observe(condition)
    return linearResult.value
}

func interposedCall(result *item, condition bool) int {
    callResult := result
    go observe(condition)
    pause()
    return callResult.value
}

func branched(result *item, condition bool, branch bool) int {
    branchResult := result
    go observe(condition)
    if branch {
        branch = false
    }
    return branchResult.value
}

func looped(result *item, condition bool, count int) int {
    loopResult := result
    go observe(condition)
    for index := 0; index < count; index++ {}
    return loopResult.value
}

func received(result *item, condition bool, ready chan bool) int {
    gapResult := result
    go observe(condition)
    <-ready
    return gapResult.value
}

func optional(result *item, condition bool, spawn bool) int {
    optionalResult := result
    if spawn {
        go observe(condition)
    }
    return optionalResult.value
}

func captured(result *item, condition bool) int {
    return func() int {
        capturedResult := result
        go observe(condition)
        return capturedResult.value
    }()
}
"#;

    #[test]
    fn detached_consumer_irrelevance_requires_an_uninterrupted_parent_continuation() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS)],
        );
        let state = fixture.state(0);

        for (binding, expected) in [
            ("linearResult", true),
            ("callResult", false),
            ("branchResult", false),
            ("loopResult", false),
            ("gapResult", false),
            ("optionalResult", false),
        ] {
            let assignment = format!("{binding} := result");
            let read = format!("{binding}.value");
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS, event) == read
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let establishment = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS, event) == assignment
                })
                .expect("the copied result has one exact establishment");
            let target = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Read
                        && spelling(GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS, event) == read
                })
                .expect("the copied result has one exact property read");
            let candidate = call_handle_spelled(
                &procedure,
                GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS,
                "observe(condition)",
            );

            assert_eq!(
                derivation
                    .detached_consumers_cannot_gate_result_uses(
                        &procedure,
                        &[establishment.point],
                        std::slice::from_ref(&candidate),
                        &[target.point],
                    )
                    .as_deref(),
                Some([expected].as_slice()),
                "{binding} has the expected parent-continuation proof"
            );

            if expected {
                let call = procedure
                    .semantics()
                    .call_site(candidate.id())
                    .expect("the procedure owns the detached call");
                let start = call
                    .normal_continuation
                    .target()
                    .expect("the detached registration continues normally");
                let [event] = procedure
                    .semantics()
                    .point(start)
                    .expect("the continuation point exists")
                    .events
                    .as_ref()
                else {
                    panic!("the straight-line start has one event");
                };
                assert!(matches!(
                    event.effect,
                    SemanticEffect::CallContinuation {
                        call_site,
                        kind: CallContinuationKind::Normal,
                    } if call_site == candidate.id()
                ));
            }
        }

        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS, event)
                    == "capturedResult.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        assert!(
            procedure.semantics().gaps().iter().all(|gap| {
                gap.subject != SemanticGapSubject::Procedure
                    || gap.capability != SemanticCapability::Captures
            }),
            "the exact captured child has no procedure-scoped capture uncertainty"
        );
        let establishment = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS, event)
                        == "capturedResult := result"
            })
            .expect("the captured result has one exact establishment");
        let target = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS, event)
                        == "capturedResult.value"
            })
            .expect("the captured result has one exact property read");
        let candidate = call_handle_spelled(
            &procedure,
            GO_DETACHED_CONSUMER_PARENT_CONTINUATIONS,
            "observe(condition)",
        );
        assert_eq!(
            derivation
                .detached_consumers_cannot_gate_result_uses(
                    &procedure,
                    &[establishment.point],
                    &[candidate],
                    &[target.point],
                )
                .as_deref(),
            Some([true].as_slice()),
            "an exact capture preserves the uninterrupted child-local continuation"
        );
    }

    const GO_CHILD_LOCAL_RESULT_WITH_CAPTURE_GAP: &str = r#"
package sample

type item struct{}

func acquire() *item { return nil }
func consume(*item) {}
func observe(int) {}

func outer(captured int) {
    func() {
        observe(captured)
        result := acquire()
        consume(result)
    }()
}
"#;

    const GO_UNRESOLVED_IMPORTED_FIELD_STORE_BASE: &str = r#"
package sample

import "net/url"

func update(raw string) {
    parsed, _ := url.Parse(raw)
    parsed.Scheme = "https"
}
"#;

    #[test]
    fn retained_unresolved_field_store_closes_its_base_observation() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_UNRESOLVED_IMPORTED_FIELD_STORE_BASE)],
        );
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Go semantics are available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.gaps().iter().any(|gap| {
                    let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                        return false;
                    };
                    gap.capability == SemanticCapability::FieldMemory
                        && procedure.point(gap.point).is_some_and(|point| {
                            point.events.iter().any(|event| {
                                matches!(
                                    event.effect,
                                    SemanticEffect::MemoryStore {
                                        location: accessed,
                                        ..
                                    } if accessed == location
                                )
                            })
                        })
                })
            })
            .expect("the imported field store belongs to one lowered procedure");
        let store_gap = procedure
            .gaps()
            .iter()
            .find(|gap| {
                let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                    return false;
                };
                gap.capability == SemanticCapability::FieldMemory
                    && procedure.point(gap.point).is_some_and(|point| {
                        point.events.iter().any(|event| {
                            matches!(
                                event.effect,
                                SemanticEffect::MemoryStore {
                                    location: accessed,
                                    ..
                                } if accessed == location
                            )
                        })
                    })
            })
            .expect("the field store has an unresolved declaration identity");
        let SemanticGapSubject::MemoryLocation(store_location) = store_gap.subject else {
            unreachable!("the selected gap has a memory-location subject");
        };
        let MemoryLocationKind::Field { base, ref member } = procedure
            .memory_location(store_location)
            .expect("the gap names a retained memory location")
            .kind
        else {
            unreachable!("the selected location is a field");
        };
        let member_span = member.anchor().span();
        assert_eq!(
            GO_UNRESOLVED_IMPORTED_FIELD_STORE_BASE
                .get(member_span.start_byte() as usize..member_span.end_byte() as usize),
            Some("Scheme"),
            "the store location retains its exact grammar-backed member identifier"
        );

        let derivation = state
            .procedures
            .iter()
            .find(|derivation| derivation.procedure == procedure.id())
            .expect("the imported field store has retained flow state");
        let root = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_UNRESOLVED_IMPORTED_FIELD_STORE_BASE, event)
                        == "parsed, _ := url.Parse(raw)"
            })
            .expect("the parsed URL result has one exact establishment");
        let procedure_handle = artifact
            .procedure_handle(procedure.id())
            .expect("the materialized artifact owns the selected procedure");
        let closure = derivation
            .exact_local_value_alias_closure(&procedure_handle, std::slice::from_ref(&root.event));
        let base_reads = closure
            .reads
            .iter()
            .copied()
            .filter(|event| derivation.event(*event).value == base)
            .collect::<Vec<_>>();
        let [base_read] = base_reads.as_slice() else {
            panic!("the store has one exact selector-base read: {base_reads:?}")
        };
        assert_eq!(
            spelling(
                GO_UNRESOLVED_IMPORTED_FIELD_STORE_BASE,
                derivation.event(*base_read)
            ),
            "parsed"
        );
        assert!(
            !closure.unclosed_transfers.contains(base_read),
            "a retained field store completely represents its base observation"
        );
    }

    const GO_UNPROJECTED_INDEX_ACCESS: &str = r#"
package sample

func first() int {
    values := [2]int{}
    return values[0]
}
"#;

    #[test]
    fn unprojected_index_access_keeps_base_observation_enumeration_open() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_UNPROJECTED_INDEX_ACCESS)]);
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Go semantics are available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.gaps().iter().any(|gap| {
                    gap.capability == SemanticCapability::IndexMemory
                        && matches!(gap.subject, SemanticGapSubject::MemoryLocation(_))
                })
            })
            .expect("the indexed access belongs to one lowered procedure");
        let gap = procedure
            .gaps()
            .iter()
            .find(|gap| {
                let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                    return false;
                };
                gap.capability == SemanticCapability::IndexMemory
                    && procedure.point(gap.point).is_some_and(|point| {
                        point.events.iter().any(|event| {
                            matches!(
                                event.effect,
                                SemanticEffect::MemoryLoad {
                                    location: accessed,
                                    ..
                                } if accessed == location
                            )
                        })
                    })
            })
            .expect("the index load retains a typed location gap");
        let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
            unreachable!("the selected gap has a memory-location subject");
        };
        assert_eq!(
            gap.discharge,
            SemanticGapDischarge::CanonicalIndexIdentity,
            "the literal marker certifies selector identity but not flow-state projection"
        );
        for impact in [
            SemanticGapImpact::HeapRead,
            SemanticGapImpact::HeapWrite,
            SemanticGapImpact::Aliasing,
        ] {
            assert!(
                gap.impacts.contains(impact),
                "the unprojected index gap must block {impact:?}"
            );
        }
        let base = match procedure
            .memory_location(location)
            .expect("the gap names a retained memory location")
            .kind
        {
            MemoryLocationKind::Index { base, index, .. } => {
                assert!(
                    index.is_some(),
                    "a literal index keeps exact IR identity while flow-state projection remains open"
                );
                base
            }
            ref kind => panic!("the indexed access must name an index location, got {kind:?}"),
        };
        let derivation = state
            .procedures
            .iter()
            .find(|derivation| derivation.procedure == procedure.id())
            .expect("the indexed access has retained flow state");
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::PropertyEvents),
            "indexed memory must not certify unprojected properties"
        );
        let retained_read_values = derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Read)
            .map(|event| event.value)
            .collect::<HashSet<_>>();
        assert!(gap_point_retains_memory_access(procedure, gap, location));
        assert!(retained_read_values.contains(&base));
        let base_read = derivation
            .events
            .iter()
            .find(|event| event.event_class == StateEventClass::Read && event.value == base)
            .expect("the indexed access retains its base read");
        let root = derivation
            .relations_of(FlowRelation::Reaching)
            .find(|relation| {
                relation.target_event == base_read.event
                    && relation.certainty == FlowCertainty::Exact
            })
            .expect("the local allocation exactly reaches the indexed base read")
            .source_event;
        assert_eq!(
            derivation.event(root).event_class,
            StateEventClass::Establish,
            "the exact reaching source is a binding establishment"
        );
        let procedure_handle = artifact
            .procedure_handle(procedure.id())
            .expect("the indexed procedure remains live");
        let alias_closure = derivation.exact_local_value_alias_closure(&procedure_handle, &[root]);
        assert!(
            alias_closure.reads.contains(&base_read.event),
            "the local allocation reaches the indexed base read"
        );
        assert!(
            alias_closure.unclosed_transfers.contains(&base_read.event),
            "canonical index identity must not close flow-state alias transfer"
        );
        assert!(
            result_observation_gap_is_relevant(
                procedure,
                gap,
                &std::iter::once(base).collect(),
                &retained_read_values,
                &[procedure.entry_point()],
            ),
            "an indexed access stays open until its property events are projected"
        );
    }

    #[test]
    fn exact_procedure_capture_preserves_child_local_result_observations() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_CHILD_LOCAL_RESULT_WITH_CAPTURE_GAP)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_CHILD_LOCAL_RESULT_WITH_CAPTURE_GAP, event) == "result := acquire()"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        assert!(
            semantics.gaps().iter().all(|gap| {
                !(gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::Captures)
            }),
            "the resolved outer parameter must not publish a capture gap"
        );
        let establishment = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_CHILD_LOCAL_RESULT_WITH_CAPTURE_GAP, event)
                        == "result := acquire()"
            })
            .expect("the child-local result binding is established");
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_CHILD_LOCAL_RESULT_WITH_CAPTURE_GAP, event) == "result"
            })
            .expect("the child-local result binding is observed");
        let relevant_values = [
            establishment.subject.value(),
            establishment.value,
            read.value,
        ];
        assert!(
            derivation.result_observation_enumeration_is_complete(
                &procedure,
                &[establishment.point],
                &relevant_values,
            ),
            "an outer capture cannot hide a static observation of a result established inside the child"
        );
        assert!(
            derivation.result_observation_enumeration_is_complete(
                &procedure,
                &[semantics.entry_point()],
                &relevant_values,
            ),
            "an entry-origin result can cross the exact capture boundary"
        );
    }

    #[test]
    fn unsupported_normal_control_flow_blocks_both_cfg_relation_axes() {
        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Assignments)
            .build();
        let mut reasons = Vec::new();
        collect_capability_reasons(&capabilities, &mut reasons);

        assert_eq!(reasons.len(), 4, "got {reasons:?}");
        for axis in [
            FlowStateAxis::ReachingRelation,
            FlowStateAxis::DominanceRelation,
            FlowStateAxis::PropertyReachingRelation,
            FlowStateAxis::PropertyDominanceRelation,
        ] {
            assert!(reasons.contains(&FlowStateIncompleteReason::AxisUnsupported(axis)));
        }
    }

    fn relation_spellings<'a>(
        source: &'a str,
        derivation: &FlowStateDerivation,
        relation: FlowRelation,
    ) -> Vec<(&'a str, &'a str, FlowCertainty)> {
        derivation
            .relations_of(relation)
            .map(|row| {
                (
                    spelling(source, derivation.event(row.source_event)),
                    spelling(source, derivation.event(row.target_event)),
                    row.certainty,
                )
            })
            .collect()
    }

    fn assert_write_consumes_its_read_in_one_evaluation(
        source: &str,
        derivation: &FlowStateDerivation,
        write_spelling: &str,
        read_spelling: &str,
    ) {
        let same = relation_spellings(source, derivation, FlowRelation::SameEvaluation);
        assert!(
            same.contains(&(write_spelling, read_spelling, FlowCertainty::Exact)),
            "the write and the read it consumes must be same-evaluation; got {same:?}"
        );
    }

    const JS_READ_AFTER_ESTABLISHMENT: &str = r#"
function afterEstablishment() {
  const ns = {};
  ns.value = 1;
  return ns.value;
}
"#;

    const JAVA_BINDING_INITIALIZATION: &str = r#"
class Sample {
    static int joined(boolean flag) {
        int x;
        if (flag) { x = 1; } else { x = 2; }
        x = x;
        return x;
    }

    static int bypass(boolean flag) {
        int x;
        if (flag) { x = 1; }
        x = x;
        return x;
    }

    static int loop(boolean flag) {
        int x;
        while (flag) { x = 1; break; }
        x = x;
        return x;
    }

    static int parameter(int value) {
        value = value;
        return value;
    }

    static int unreachable() {
        int x = 1;
        return x;
        x = x;
    }
}
"#;

    const JAVA_OVERWRITTEN_UNREAD: &str = r#"
class Sample {
    static int clean() {
        int x;
        x = 1;
        x = 2;
        return x;
    }
    static int priorRead() {
        int x;
        x = 1;
        int y = x;
        x = 2;
        return x + y;
    }
    static int samePointRead() {
        int x;
        x = 1;
        x = x;
        x = 2;
        return x;
    }
    static int compoundUpdate() {
        int x;
        x = 1;
        x += 2;
        return x;
    }
    static int increment() {
        int x;
        x = 1;
        x++;
        return x;
    }
    static int branchRead(boolean flag) {
        int x;
        x = 1;
        if (flag) { return x; }
        x = 2;
        return x;
    }
    static int bypass(boolean flag) {
        int x;
        x = 1;
        if (flag) { x = 2; }
        return 0;
    }
    static int effectful() {
        int x;
        x = sideEffect();
        x = 2;
        return x;
    }
    static int nonOverwritingCycle(boolean flag) {
        int x;
        x = 1;
        while (flag) { flag = true; }
        x = 2;
        return x;
    }
    static int reentry(boolean flag) {
        int x;
        do { x = 1; } while (flag);
        x = 2;
        return x;
    }
    static int cleanup() {
        int x;
        x = 1;
        try { x = sideEffect(); }
        finally { sideEffect(); int observed = x; }
        return x;
    }
    static int captured() {
        int x;
        x = 1;
        Runnable r = () -> System.out.println(x);
        r.run();
        return 0;
    }
    static int unreachable() {
        int x;
        return 0;
        x = 1;
        x = 2;
    }
    static int sideEffect() { return 1; }
}
"#;

    const JAVA_LOOP_REPEAT: &str = r#"
class Sample {
    static void whileReturn(boolean flag) { while (flag) { return; } }
    static void whileContinue(boolean flag) { while (flag) { if (flag) return; continue; } }
    static void forReturn(boolean flag) { for (; flag; flag = false) { return; } }
    static void forContinue(boolean flag) { for (; flag; flag = false) { continue; } }
    static void nestedReturn(boolean outer, boolean inner) { while (outer) { while (inner) { break; } return; } }
    static void nestedContinue(boolean outer, boolean inner) { while (outer) { while (inner) { break; } continue; } }
    static void doFalse() { do { work(); } while (false); }
    static void whileFalse() { while (false) { work(); } }
    static void cleanupContinue(boolean flag) { while (flag) { try { continue; } finally { work(); } } }
    static void cleanupBreak(boolean flag) { while (flag) { try { break; } finally { work(); } } }
    static void forEverContinue() { for (;;) { continue; } }
    static void forEverBreak() { for (;;) { break; } }
    static void forConditionalBreak(boolean stop) { for (;;) { if (stop) break; } }
    static void enclosingRepeat(boolean again) { while (again) { for (;;) { break; } } }
    static void finallyRepeats() { for (;;) { try { break; } finally { continue; } } }
    static void finallyExits() { for (;;) { try { continue; } finally { break; } } }
    static void forIncrement(int n) { for (int i = 0; i < n; i++) { work(); } }
    static void forDecrement(int n) { for (int i = n; i > 0; --i) { work(); } }
    static void forIncrementReturn(int n) { for (int i = 0; i < n; i++) { return; } }
    static void forNoUpdateReturn(boolean flag) { for (; flag;) { return; } }
    static void work() {}
}
"#;

    #[test]
    fn java_loop_repeat_joins_body_to_its_own_edge_and_exit() {
        let fixture = Fixture::new(Language::Java, &[("src/Sample.java", JAVA_LOOP_REPEAT)]);
        let state = fixture.state(0);
        let cases = [
            (
                "whileReturn",
                "while (flag) { return; }",
                "{ return; }",
                Some("flag"),
                LoopSourceKind::While,
                "no",
            ),
            (
                "whileContinue",
                "while (flag) { if (flag) return; continue; }",
                "{ if (flag) return; continue; }",
                Some("flag"),
                LoopSourceKind::While,
                "may",
            ),
            (
                "forReturn",
                "for (; flag; flag = false) { return; }",
                "{ return; }",
                Some("flag"),
                LoopSourceKind::For,
                "no",
            ),
            (
                "forContinue",
                "for (; flag; flag = false) { continue; }",
                "{ continue; }",
                Some("flag"),
                LoopSourceKind::For,
                "may",
            ),
            (
                "nestedReturn",
                "while (outer) { while (inner) { break; } return; }",
                "{ while (inner) { break; } return; }",
                Some("outer"),
                LoopSourceKind::While,
                "no",
            ),
            (
                "nestedContinue",
                "while (outer) { while (inner) { break; } continue; }",
                "{ while (inner) { break; } continue; }",
                Some("outer"),
                LoopSourceKind::While,
                "may",
            ),
            (
                "nestedContinue",
                "while (inner) { break; }",
                "{ break; }",
                Some("inner"),
                LoopSourceKind::While,
                "no",
            ),
            (
                "nestedContinue",
                "while (outer) { while (inner) { break; } continue; }",
                "{ break; }",
                Some("outer"),
                LoopSourceKind::While,
                "open",
            ),
            (
                "doFalse",
                "do { work(); } while (false);",
                "{ work(); }",
                Some("(false)"),
                LoopSourceKind::Do,
                "intentional",
            ),
            (
                "whileFalse",
                "while (false) { work(); }",
                "{ work(); }",
                Some("false"),
                LoopSourceKind::While,
                "unreachable",
            ),
            (
                "cleanupContinue",
                "while (flag) { try { continue; } finally { work(); } }",
                "{ try { continue; } finally { work(); } }",
                Some("flag"),
                LoopSourceKind::While,
                "may",
            ),
            (
                "cleanupBreak",
                "while (flag) { try { break; } finally { work(); } }",
                "{ try { break; } finally { work(); } }",
                Some("flag"),
                LoopSourceKind::While,
                "no",
            ),
            (
                "forEverContinue",
                "for (;;) { continue; }",
                "{ continue; }",
                None,
                LoopSourceKind::For,
                "may",
            ),
            (
                "forEverBreak",
                "for (;;) { break; }",
                "{ break; }",
                None,
                LoopSourceKind::For,
                "no",
            ),
            (
                "forConditionalBreak",
                "for (;;) { if (stop) break; }",
                "{ if (stop) break; }",
                None,
                LoopSourceKind::For,
                "may",
            ),
            (
                "enclosingRepeat",
                "for (;;) { break; }",
                "{ break; }",
                None,
                LoopSourceKind::For,
                "no",
            ),
            (
                "finallyRepeats",
                "for (;;) { try { break; } finally { continue; } }",
                "{ try { break; } finally { continue; } }",
                None,
                LoopSourceKind::For,
                "may",
            ),
            (
                "finallyExits",
                "for (;;) { try { continue; } finally { break; } }",
                "{ try { continue; } finally { break; } }",
                None,
                LoopSourceKind::For,
                "no",
            ),
            (
                "forIncrement",
                "for (int i = 0; i < n; i++) { work(); }",
                "{ work(); }",
                Some("i < n"),
                LoopSourceKind::For,
                "may",
            ),
            (
                "forDecrement",
                "for (int i = n; i > 0; --i) { work(); }",
                "{ work(); }",
                Some("i > 0"),
                LoopSourceKind::For,
                "may",
            ),
            (
                "forIncrementReturn",
                "for (int i = 0; i < n; i++) { return; }",
                "{ return; }",
                Some("i < n"),
                LoopSourceKind::For,
                "no",
            ),
            (
                "forNoUpdateReturn",
                "for (; flag;) { return; }",
                "{ return; }",
                Some("flag"),
                LoopSourceKind::For,
                "no",
            ),
        ];
        let mut failures = Vec::new();
        for (method, loop_text, body_text, condition_text, kind, expected) in cases {
            let method_start = JAVA_LOOP_REPEAT
                .find(&format!("static void {method}"))
                .expect("method exists");
            let loop_start = method_start
                + JAVA_LOOP_REPEAT[method_start..]
                    .find(loop_text)
                    .expect("loop exists");
            let loop_end = loop_start + loop_text.len();
            let derivation = state
                .procedures
                .iter()
                .find(|derivation| {
                    let procedure = fixture.procedure(0, derivation.procedure);
                    let semantics = procedure.semantics();
                    semantics.points().iter().any(|point| {
                        let span = semantics
                            .source_mapping(point.source)
                            .expect("point mapping exists")
                            .locator
                            .anchor()
                            .span();
                        span.start_byte() as usize == loop_start
                            && span.end_byte() as usize == loop_end
                    })
                })
                .expect("loop has a semantic procedure");
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let source_span = |start: usize, end: usize| {
                semantics
                    .source_mappings()
                    .iter()
                    .map(|mapping| mapping.locator.anchor().span())
                    .find(|span| {
                        span.start_byte() as usize == start && span.end_byte() as usize == end
                    })
                    .unwrap_or_else(|| {
                        let position = |offset: usize| {
                            let prefix = &JAVA_LOOP_REPEAT[..offset];
                            let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
                            let column = prefix.rsplit('\n').next().expect("line exists").len();
                            crate::analyzer::semantic::SourcePosition::new(
                                offset as u32,
                                line as u32,
                                column as u32,
                            )
                        };
                        SourceSpan::new(position(start), position(end))
                            .expect("source substring has a valid span")
                    })
            };
            let body_start = loop_start + loop_text.find(body_text).expect("body exists");
            let condition_span = condition_text.map(|condition| {
                let start = loop_start + loop_text.find(condition).expect("condition exists");
                source_span(start, start + condition.len())
            });
            let site = LoopSourceSite {
                kind,
                loop_span: source_span(loop_start, loop_end),
                body_span: source_span(body_start, body_start + body_text.len()),
                condition_span,
            };
            let cancellation = CancellationToken::default();
            let answer = derivation.loop_body_reaches_own_repeat(
                &procedure,
                site,
                &mut test_request(&cancellation),
            );
            if method == "whileReturn" {
                let mut bounded = test_request(&cancellation);
                bounded.cfg_budget = CfgAlgorithmBudget::uniform(1);
                assert!(matches!(
                    derivation.loop_body_reaches_own_repeat(&procedure, site, &mut bounded),
                    LoopRepeatAnswer::Open { reasons }
                        if reasons.iter().any(|reason| matches!(
                            reason,
                            LoopRepeatIncompleteReason::Flow(
                                FlowStateIncompleteReason::BudgetExhausted { .. }
                            )
                        ))
                ));
                let cancelled = CancellationToken::default();
                cancelled.cancel();
                assert!(matches!(
                    derivation.loop_body_reaches_own_repeat(
                        &procedure,
                        site,
                        &mut test_request(&cancelled)
                    ),
                    LoopRepeatAnswer::Open { reasons }
                        if reasons.contains(&LoopRepeatIncompleteReason::Flow(
                            FlowStateIncompleteReason::Cancelled
                        ))
                ));
            }
            let valid = match expected {
                "no" => matches!(
                    answer,
                    LoopRepeatAnswer::NoRepeat {
                        intentional_constant_false_do: false
                    }
                ),
                "intentional" => matches!(
                    answer,
                    LoopRepeatAnswer::NoRepeat {
                        intentional_constant_false_do: true
                    }
                ),
                "may" => matches!(answer, LoopRepeatAnswer::MayRepeat { .. }),
                "open" => matches!(answer, LoopRepeatAnswer::Open { .. }),
                "unreachable" => matches!(answer, LoopRepeatAnswer::UnreachableBody),
                _ => unreachable!(),
            };
            if !valid {
                failures.push(format!(
                    "{method} {loop_text}: expected {expected}, got {answer:?}; {:?}",
                    derivation.completeness,
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn overwritten_unread_local_distinguishes_replacement_reads_and_bypass() {
        let fixture = Fixture::new(
            Language::Java,
            &[("src/Sample.java", JAVA_OVERWRITTEN_UNREAD)],
        );
        let state = fixture.state(0);
        let mut failures = Vec::new();
        for (method, expected) in [
            ("clean", "proven"),
            ("priorRead", "read"),
            ("samePointRead", "read"),
            ("compoundUpdate", "read_or_exception_gap"),
            ("increment", "read"),
            ("branchRead", "read"),
            ("bypass", "bypass"),
            ("effectful", "proven"),
            ("nonOverwritingCycle", "bypass"),
            ("reentry", "proven"),
            ("cleanup", "cleanup"),
            ("captured", "read"),
            ("unreachable", "unreachable"),
        ] {
            let start = JAVA_OVERWRITTEN_UNREAD
                .find(&format!("static int {method}"))
                .expect("method exists");
            let first_write = start
                + JAVA_OVERWRITTEN_UNREAD[start..]
                    .find("x = ")
                    .expect("first write exists");
            let derivation = state
                .procedures
                .iter()
                .find(|derivation| {
                    derivation.events.iter().any(|event| {
                        event.event_class == StateEventClass::Establish
                            && event.site.range.start_byte == first_write
                    })
                })
                .expect("method has first establishment");
            let first = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && event.site.range.start_byte == first_write
                })
                .expect("first establishment exists");
            let procedure = fixture.procedure(0, derivation.procedure);
            if method == "cleanup" {
                assert!(procedure.semantics().control_edges().iter().any(|edge| {
                    matches!(
                        edge.kind,
                        ControlEdgeKind::Exceptional | ControlEdgeKind::Cleanup
                    )
                }));
            }
            let cancellation = CancellationToken::default();
            let answer = derivation.overwritten_unread_local(
                &procedure,
                first.event,
                &mut test_request(&cancellation),
            );
            if matches!(answer, OverwrittenUnreadAnswer::Proven { .. }) {
                for capacity in [64 * 1024 * 1024, 1] {
                    let owner = RetentionBudget::for_test_capacity(capacity);
                    let mut request =
                        FlowStateRequest::new(&cancellation, FlowStateRequestMemos::new(&owner));
                    for _ in 0..2 {
                        let dead =
                            derivation.dead_write_local(&procedure, first.event, &mut request);
                        assert!(
                            matches!(dead, DeadWriteAnswer::Dead),
                            "{method}: overwritten_unread must imply Dead, got {dead:?}"
                        );
                    }
                    drop(request);
                    assert_eq!(owner.accounted_bytes(), 0);
                }
            }
            let valid = match expected {
                "proven" => matches!(answer, OverwrittenUnreadAnswer::Proven { .. }),
                "read" => matches!(answer, OverwrittenUnreadAnswer::ReadBeforeOverwrite { .. }),
                "read_or_exception_gap" => {
                    matches!(answer, OverwrittenUnreadAnswer::ReadBeforeOverwrite { .. })
                        || matches!(answer, OverwrittenUnreadAnswer::Open { ref reasons }
                        if reasons.iter().any(|reason| matches!(
                            reason,
                            FlowStateIncompleteReason::LoweringGap {
                                capability: SemanticCapability::ExceptionalControlFlow,
                                ..
                            }
                        )))
                }
                "bypass" => matches!(answer, OverwrittenUnreadAnswer::PathWithoutOverwrite),
                "cleanup" => matches!(
                    answer,
                    OverwrittenUnreadAnswer::ReadBeforeOverwrite { .. }
                        | OverwrittenUnreadAnswer::PathWithoutOverwrite
                        | OverwrittenUnreadAnswer::Open { .. }
                ),
                "open" => matches!(answer, OverwrittenUnreadAnswer::Open { ref reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    FlowStateIncompleteReason::LoweringGap {
                        capability: SemanticCapability::Captures,
                        ..
                    }
                ))),
                "unreachable" => matches!(answer, OverwrittenUnreadAnswer::Unreachable),
                _ => unreachable!(),
            };
            if !valid {
                failures.push(format!(
                    "{method}: expected {expected}, got {answer:?}; completeness: {:?}",
                    derivation.completeness
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn overwritten_unread_respects_deferred_mutable_capture_reads() {
        for (source, overwritten) in [
            (
                "function outer() { let x = 1; const read = () => x; x = 2; return read(); }",
                true,
            ),
            (
                "function outer() { let x = 1; const read = () => x; const observed = read(); x = 2; return [observed, x]; }",
                false,
            ),
        ] {
            let fixture = Fixture::new(Language::JavaScript, &[("src/sample.js", source)]);
            let state = fixture.state(0);
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Establish
                    && spelling(source, event) == "x = 1"
            });
            let first = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(source, event) == "x = 1"
                })
                .unwrap();
            let procedure = fixture.procedure(0, derivation.procedure);
            let cancellation = CancellationToken::default();
            let answer = derivation.overwritten_unread_local(
                &procedure,
                first.event,
                &mut test_request(&cancellation),
            );
            if overwritten {
                assert!(
                    matches!(answer, OverwrittenUnreadAnswer::Proven { .. }),
                    "{answer:?}"
                );
            } else {
                // An unresolved invocation can also abort before replacement;
                // either that path or the captured read defeats an all-path proof.
                assert!(
                    matches!(
                        answer,
                        OverwrittenUnreadAnswer::ReadBeforeOverwrite { .. }
                            | OverwrittenUnreadAnswer::PathWithoutOverwrite
                            | OverwrittenUnreadAnswer::Open { .. }
                    ),
                    "{answer:?}"
                );
            }
        }
    }

    #[test]
    fn deleting_local_reads_its_value_before_unbinding_it() {
        const SOURCE: &str = r#"
def deleted():
    x = 1
    del x
    x = 2
    return x
"#;
        let fixture = Fixture::new(Language::Python, &[("src/main.py", SOURCE)]);
        let state = fixture.state(0);
        let first_write = SOURCE.find("x = 1").expect("first assignment exists");
        let derivation = state
            .procedures
            .iter()
            .find(|derivation| {
                derivation.events.iter().any(|event| {
                    event.event_class == StateEventClass::Establish
                        && event.site.range.start_byte == first_write
                })
            })
            .expect("the assignment establishes a binding");
        let first = derivation
            .events
            .iter()
            .find(|event| event.site.range.start_byte == first_write)
            .expect("first establishment exists");
        let procedure = fixture.procedure(0, derivation.procedure);
        let cancellation = CancellationToken::default();
        let answer = derivation.overwritten_unread_local(
            &procedure,
            first.event,
            &mut test_request(&cancellation),
        );
        assert!(
            matches!(answer, OverwrittenUnreadAnswer::ReadBeforeOverwrite { .. }),
            "deleting a local reads its current value: {answer:?}"
        );
    }

    #[test]
    fn initialization_order_regions_fail_closed_on_missing_mappings_and_work_limits() {
        const SOURCE: &str = "package sample\nfunc next() int { return 0 }\nfunc sink2(a, b int) {}\nfunc f(items []int) { for range items {}; value := 1; value = value; sink2(next(), items[0]) }\n";
        let fixture = Fixture::new(Language::Go, &[("main.go", SOURCE)]);
        let state = fixture.state(0);
        let offset = SOURCE.find("value = value").unwrap() + 8;
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read && event.site.range.start_byte == offset
        });
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read && event.site.range.start_byte == offset
            })
            .unwrap();
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let gap = semantics
            .gaps()
            .iter()
            .find(|gap| initialization_gap_retains_order(gap))
            .expect("the competing index read and call retain an order region");
        let cancellation = CancellationToken::default();
        let mut request = test_request(&cancellation);
        assert_eq!(
            derivation.binding_initialization_at_read(&procedure, read.event, &mut request),
            BindingInitializationAnswer::Proven
        );
        let mut request = test_request(&cancellation);
        request.cfg_budget = CfgAlgorithmBudget::uniform(1);
        let exhausted =
            derivation.binding_initialization_at_read(&procedure, read.event, &mut request);
        assert!(
            matches!(exhausted, BindingInitializationAnswer::Open { reasons }
            if reasons.iter().any(|reason| matches!(reason, FlowStateIncompleteReason::BudgetExhausted { .. })))
        );
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let cancelled_answer = derivation.binding_initialization_at_read(
            &procedure,
            read.event,
            &mut test_request(&cancelled),
        );
        assert!(
            matches!(cancelled_answer, BindingInitializationAnswer::Open { reasons }
            if reasons.contains(&FlowStateIncompleteReason::Cancelled))
        );

        let mut budget = CfgAlgorithmBudget::default();
        let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
        with_control_graph!(semantics, &derivation.control_edge_mask, |graph| {
            let reaching_read = reverse_reachability(graph, read.point, &mut request).unwrap();
            assert!(
                initialization_order_region_is_off_path(
                    graph,
                    semantics,
                    gap,
                    &reaching_read,
                    &mut request
                )
                .unwrap()
            );
            // Artifact validation disallows absent mappings. Exercise the helper's
            // fail-closed boundary with a detached gap carrying an invalid ID.
            let mut missing = gap.clone();
            missing.source = SourceMappingId::new(u32::MAX);
            assert!(
                !initialization_order_region_is_off_path(
                    graph,
                    semantics,
                    &missing,
                    &reaching_read,
                    &mut request
                )
                .unwrap()
            );
        });

        let other = semantics
            .gaps()
            .iter()
            .find(|other| initialization_gap_retains_topology(other))
            .expect("the prior loop retains a topology gap with the same capability and kind");
        let mut reasons = Vec::new();
        push_gap_reason(&mut reasons, gap);
        let FlowStateIncompleteReason::LoweringGap { gaps, .. } = &mut reasons[0] else {
            unreachable!()
        };
        gaps.push(other.id);
        let located = locate_gap_reasons(
            semantics,
            reasons.clone(),
            initialization_gap_retains_order,
            &mut request,
        )
        .unwrap();
        assert_eq!(
            located.unlocated, reasons,
            "one unaudited member retains the entire reason"
        );
        assert!(located.by_point.is_empty());
    }

    const RUST_INITIALIZATION_GAP_REACHABILITY: &str = r#"
fn back_edge(mut low: usize) {
    loop {
        low = low;
        const { 1 };
    }
}
fn sibling(mut low: usize, flag: bool) {
    if flag {
        low = low;
    } else {
        const { 1 };
    }
}
fn blocked(mut low: usize, flag: bool) -> (usize, usize) {
    if flag { try { 1 }; }
    low = low;
    const { 1 };
    (low, low)
}
fn add_scalar(mut low: usize) -> Option<usize> {
    low = low;
    unresolved_value
}
"#;

    #[test]
    fn initialization_gap_reachability_keeps_back_edges_and_unknown_control_open() {
        let fixture = Fixture::new(
            Language::Rust,
            &[("src/lib.rs", RUST_INITIALIZATION_GAP_REACHABILITY)],
        );
        let state = fixture.state(0);
        for (name, expected_open, gap_detail) in [
            ("back_edge", true, "inline const evaluation"),
            ("sibling", false, "inline const evaluation"),
            ("blocked", true, "inline const evaluation"),
        ] {
            let start = RUST_INITIALIZATION_GAP_REACHABILITY
                .find(&format!("fn {name}("))
                .expect("fixture procedure");
            let read_at = start
                + RUST_INITIALIZATION_GAP_REACHABILITY[start..]
                    .find("low = low")
                    .expect("self assignment")
                + 6;
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Read && event.site.range.start_byte == read_at
            });
            let read = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Read
                        && event.site.range.start_byte == read_at
                })
                .expect("self-assignment read");
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let gap = semantics
                .gaps()
                .iter()
                .find(|gap| {
                    gap.capability == SemanticCapability::Values
                        && gap.detail.starts_with(gap_detail)
                })
                .expect("the producer publishes the vetoing Values gap");
            assert_eq!(
                derivation.point_reaches(semantics, gap.point, read.point, true),
                name == "back_edge",
                "{name}: modeled reachability includes loop back edges"
            );
            if name == "blocked" {
                assert!(
                    semantics.gaps().iter().any(|gap| {
                        matches!(
                            gap.capability,
                            SemanticCapability::NonLocalControl
                                | SemanticCapability::NormalControlFlow
                        ) && !gap_has_exit_only_control(gap)
                            && gap.discharge != SemanticGapDischarge::RetainedControlTopology
                    }),
                    "the procedure-wide precondition must fail: {:?}",
                    semantics.gaps()
                );
            }
            let answer = derivation.binding_initialization_at_read(
                &procedure,
                read.event,
                &mut test_request(&CancellationToken::default()),
            );
            if expected_open {
                let BindingInitializationAnswer::Open { reasons } = answer else {
                    panic!("{name}: expected an open proof, got {answer:?}");
                };
                assert!(reasons.iter().any(|reason| matches!(reason,
                    FlowStateIncompleteReason::LoweringGap { capability: SemanticCapability::Values, gaps, .. }
                        if gaps.contains(&gap.id)
                )), "{name}: the selected Values gap still vetoes: {reasons:?}");
            } else {
                assert_eq!(answer, BindingInitializationAnswer::Proven, "{name}");
            }
            assert!(
                !derivation.initialization_gap_is_discharged(
                    semantics,
                    gap,
                    read.subject.value(),
                    gap.point,
                ),
                "reflexive reachability keeps the gap's own point open"
            );
        }
    }

    #[test]
    #[hardwon("#6409: a Values gap after the read kept a self-assignment's initialization open")]
    fn initialization_ignores_a_value_gap_after_the_read() {
        let fixture = Fixture::new(
            Language::Rust,
            &[("src/lib.rs", RUST_INITIALIZATION_GAP_REACHABILITY)],
        );
        let state = fixture.state(0);
        let start = RUST_INITIALIZATION_GAP_REACHABILITY
            .find("fn add_scalar(")
            .unwrap();
        let read_at = start
            + RUST_INITIALIZATION_GAP_REACHABILITY[start..]
                .find("low = low")
                .unwrap()
            + 6;
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read && event.site.range.start_byte == read_at
        });
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read && event.site.range.start_byte == read_at
            })
            .unwrap();
        let procedure = fixture.procedure(0, derivation.procedure);
        let gap = procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| match gap.subject {
                SemanticGapSubject::Value(value)
                    if gap.capability == SemanticCapability::Values =>
                {
                    let value = procedure.semantics().value(value).unwrap();
                    let span = procedure
                        .semantics()
                        .source_mapping(value.source)
                        .unwrap()
                        .locator
                        .anchor()
                        .span();
                    span.start_byte() as usize > read_at
                        && &RUST_INITIALIZATION_GAP_REACHABILITY
                            [span.start_byte() as usize..span.end_byte() as usize]
                            == "unresolved_value"
                }
                _ => false,
            })
            .expect("the unresolved value has a Values gap after the read");
        assert!(matches!(gap.subject, SemanticGapSubject::Value(_)));
        assert_eq!(
            derivation.binding_initialization_at_read(
                &procedure,
                read.event,
                &mut test_request(&CancellationToken::default())
            ),
            BindingInitializationAnswer::Proven
        );
    }

    #[test]
    fn binding_initialization_distinguishes_join_bypass_loop_and_parameter() {
        let fixture = Fixture::new(
            Language::Java,
            &[("src/Sample.java", JAVA_BINDING_INITIALIZATION)],
        );
        let state = fixture.state(0);
        let cases = [
            ("joined", BindingInitializationAnswer::Proven),
            ("bypass", BindingInitializationAnswer::MayBeUninitialized),
            ("loop", BindingInitializationAnswer::MayBeUninitialized),
            ("parameter", BindingInitializationAnswer::Proven),
            ("unreachable", BindingInitializationAnswer::Unreachable),
        ];
        for (method, expected) in cases {
            let start = JAVA_BINDING_INITIALIZATION
                .find(&format!("static int {method}"))
                .expect("method exists");
            let assignment = if method == "parameter" {
                " = value;"
            } else {
                " = x;"
            };
            let read_at = start
                + JAVA_BINDING_INITIALIZATION[start..]
                    .find(assignment)
                    .expect("self assignment exists")
                + 3;
            let (derivation, read) = state
                .procedures
                .iter()
                .find_map(|derivation| {
                    derivation.events.iter().find_map(|event| {
                        (event.event_class == StateEventClass::Read
                            && event.site.range.start_byte == read_at)
                            .then_some((derivation, event.event))
                    })
                })
                .expect("self-assignment RHS has a binding read");
            let procedure = fixture.procedure(0, derivation.procedure);
            assert_eq!(
                derivation.binding_initialization_at_read(
                    &procedure,
                    read,
                    &mut test_request(&CancellationToken::default())
                ),
                expected,
                "{method}: {:?}",
                derivation.completeness
            );
        }
    }

    #[test]
    fn js_before_write_initialization_distinguishes_let_tdz_and_hoisted_var() {
        const SOURCE: &str = r#"
function afterLet() { let a; a = 1; a = 2; }
function beforeLet() { b = 1; let b; b = 2; }
function beforeVar() { c = 1; var c; c = 2; }
"#;
        let fixture = Fixture::new(Language::JavaScript, &[("src/sample.js", SOURCE)]);
        let state = fixture.state(0);
        for (spelling, expected) in [
            ("a = 1", BindingInitializationAnswer::Proven),
            ("c = 1", BindingInitializationAnswer::Proven),
        ] {
            let start = SOURCE.find(spelling).expect("write exists");
            let (derivation, event) = state
                .procedures
                .iter()
                .find_map(|derivation| {
                    derivation.events.iter().find_map(|event| {
                        (event.event_class == StateEventClass::Establish
                            && event.site.range.start_byte == start)
                            .then_some((derivation, event.event))
                    })
                })
                .expect("plain assignment projects a binding establishment");
            let procedure = fixture.procedure(0, derivation.procedure);
            assert_eq!(
                derivation.binding_initialization_before_establishment(
                    &procedure,
                    event,
                    &mut test_request(&CancellationToken::default())
                ),
                expected,
                "{spelling}: {:?}",
                derivation.completeness
            );
        }
        for spelling in ["b = 1", "b = 2"] {
            let start = SOURCE.find(spelling).expect("TDZ-related write exists");
            let (derivation, event) = state
                .procedures
                .iter()
                .find_map(|derivation| {
                    derivation.events.iter().find_map(|event| {
                        (event.event_class == StateEventClass::Establish
                            && event.site.range.start_byte == start)
                            .then_some((derivation, event.event))
                    })
                })
                .expect("plain assignment projects a binding establishment");
            let procedure = fixture.procedure(0, derivation.procedure);
            assert!(matches!(
                derivation.binding_initialization_before_establishment(&procedure, event, &mut test_request(&CancellationToken::default())),
                BindingInitializationAnswer::Open { reasons }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        FlowStateIncompleteReason::LoweringGap {
                            capability: SemanticCapability::LocalFlow,
                            ..
                        }
                    ))
            ));
        }
    }

    #[test]
    fn python_delete_marks_the_local_uninitialized_until_assignment() {
        const SOURCE: &str = r#"
def deleted():
    x = 1
    del x
    x = x
    return x
"#;
        let fixture = Fixture::new(Language::Python, &[("src/main.py", SOURCE)]);
        let state = fixture.state(0);
        let read_at = SOURCE.find("x = x").expect("self assignment exists") + 4;
        let (derivation, read) = state
            .procedures
            .iter()
            .find_map(|derivation| {
                derivation.events.iter().find_map(|event| {
                    (event.event_class == StateEventClass::Read
                        && event.site.range.start_byte == read_at)
                        .then_some((derivation, event.event))
                })
            })
            .expect("the self-assignment RHS is a projected binding read");
        let procedure = fixture.procedure(0, derivation.procedure);
        assert!(matches!(
            derivation.binding_initialization_at_read(
                &procedure,
                read,
                &mut test_request(&CancellationToken::default())
            ),
            BindingInitializationAnswer::MayBeUninitialized
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4720: a local helper with no normal exit left a caller read spuriously uninitialized"
    )]
    fn python_workspace_nonreturning_constructor_proves_the_following_local_read() {
        const SOURCE: &str = r#"class Terminates:
    def __init__(self):
        self.ready = True
        raise

def caller(flag):
    if flag:
        value = 1
    else:
        Terminates()
    return value
"#;
        let fixture = Fixture::new(Language::Python, &[("src/main.py", SOURCE)]);
        let state = fixture.state(0);
        let read_at = SOURCE.rfind("value").expect("return read exists");
        let (derivation, read) = state
            .procedures
            .iter()
            .find_map(|derivation| {
                derivation.events.iter().find_map(|event| {
                    (event.event_class == StateEventClass::Read
                        && event.site.range.start_byte == read_at)
                        .then_some((derivation, event.event))
                })
            })
            .expect("return expression projects a local binding read");
        let procedure = fixture.procedure(0, derivation.procedure);
        assert_eq!(
            derivation.binding_initialization_at_read(
                &procedure,
                read,
                &mut test_request(&CancellationToken::default())
            ),
            BindingInitializationAnswer::Proven,
            "the constructor's exceptional-only body removes the caller's else continuation: {:?}",
            derivation.completeness
        );
        let call = call_handle_spelled(&procedure, SOURCE, "Terminates()");
        let normal_edge = normal_edge_for_call(&procedure, &call);
        assert!(
            derivation.control_edge_mask.omitted.contains(&normal_edge),
            "the shared workspace effect projection omits the proven non-returning call edge"
        );
    }

    #[test]
    fn binding_initialization_and_overwrite_observe_same_point_event_order() {
        use crate::analyzer::semantic::ProcedureSemanticsParts;

        const SOURCE: &str = r#"
class Sample {
    static int sample() {
        int x;
        x = 1;
        return x;
    }
}
"#;
        let fixture = Fixture::new(Language::Java, &[("src/Sample.java", SOURCE)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(SOURCE, event) == "x = 1"
        });
        let original = fixture.procedure(0, derivation.procedure);
        let semantics = original.semantics();
        assert!(semantics.call_sites().is_empty());
        assert!(semantics.guard_facts().is_empty());
        assert!(semantics.switch_facts().is_empty());
        let write = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event) == "x = 1"
            })
            .expect("the assignment establishes x");
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read && event.subject == write.subject
            })
            .expect("the return reads x");
        let read_effect = semantics
            .point(read.point)
            .expect("read point exists")
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow { source, .. }
                        if source == read.subject.value()
                )
            })
            .expect("the read has a semantic event")
            .clone();
        let write_effect = semantics
            .point(write.point)
            .expect("write point exists")
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::Assignment { target, .. }
                        if target == write.subject.value()
                )
            })
            .expect("the write has a semantic event")
            .clone();

        let mut parts = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            semantics.locator().clone(),
            semantics.kind(),
            semantics.source(),
            semantics.evidence(),
        );
        parts.properties = semantics.properties();
        parts.values = semantics.values().to_vec();
        parts.allocations = semantics.allocations().to_vec();
        parts.memory_locations = semantics.memory_locations().to_vec();
        parts.captures = semantics.captures().to_vec();
        parts.call_sites = semantics.call_sites().to_vec();
        parts.source_mappings = semantics.source_mappings().to_vec();
        parts.evidence_rows = semantics.evidence_rows().to_vec();
        parts.gaps = semantics.gaps().to_vec();
        parts.blocks = semantics.blocks().to_vec();
        parts.points = semantics.points().to_vec();
        parts.control_edges = semantics.control_edges().to_vec();
        parts.points[write.point.index()].events = vec![
            read_effect.clone(),
            write_effect.clone(),
            read_effect.clone(),
            write_effect.clone(),
        ]
        .into_boxed_slice();
        let artifact = SemanticArtifact::try_new(
            original.artifact().key().clone(),
            original.artifact().capabilities().clone(),
            vec![parts],
        )
        .expect("the reordered semantic procedure remains valid");
        let procedure = &artifact.procedures()[0];
        let mut projected_read = read.clone();
        projected_read.procedure = procedure.id();
        projected_read.point = write.point;
        let mut projected_write = write.clone();
        projected_write.procedure = procedure.id();
        let mut events = [
            projected_read.clone(),
            projected_write.clone(),
            projected_read,
            projected_write,
        ];
        for (index, event) in events.iter_mut().enumerate() {
            event.event = index;
        }
        let keys = [
            read_effect.clone(),
            write_effect.clone(),
            read_effect,
            write_effect,
        ]
        .into_iter()
        .enumerate()
        .map(|(event_index, event)| SemanticEventKey {
            point: write.point,
            event_index: event_index as u32,
            source: event.source,
        })
        .collect::<Vec<_>>();
        let initialization_events = binding_initialization_events(&events, &keys);
        let definitions = BindingDefinitions::build(procedure, &initialization_events);
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::default();
        let reaching = reaching_definitions(
            procedure,
            procedure.entry_point(),
            &definitions.gen_kill(procedure),
            &mut CfgAlgorithmRequest::new(&mut budget, &cancellation),
        )
        .expect("the bounded reaching solve completes");
        let facts =
            definitions.uninitialized_before_event(procedure, &initialization_events, &reaching);
        assert_eq!(facts.get(&0), Some(&true));
        assert_eq!(facts.get(&2), Some(&false));
        let answer = overwritten_unread_over_graph(
            procedure,
            OverwrittenUnreadWalkInputs {
                semantics: procedure,
                events: &events,
                event_keys: &keys,
                establishment_event: 1,
                binding: write.subject.value(),
                gaps_by_point: &BTreeMap::new(),
            },
            &mut CfgAlgorithmRequest::new(&mut budget, &cancellation),
        )
        .expect("same-point overwrite walk completes");
        assert_eq!(
            answer,
            OverwrittenUnreadAnswer::ReadBeforeOverwrite { read_event: 2 }
        );
    }

    const JS_BRANCH_ESTABLISHMENTS: &str = r#"
function branchEstablishments(flag) {
  const ns = {};
  if (flag) {
    ns.value = 1;
  } else {
    ns.value = 2;
  }
  return ns.value;
}
"#;

    #[test]
    fn retained_dominance_batches_individual_candidates_and_gates_incomplete_axes() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_BRANCH_ESTABLISHMENTS)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let writes = derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Establish)
            .filter(|event| {
                matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value")
            })
            .map(|event| event.point)
            .collect::<Vec<_>>();
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value")
            })
            .expect("the returned property is read")
            .point;
        assert_eq!(writes.len(), 2, "{:#?}", derivation.events);
        assert_eq!(
            derivation
                .any_candidate_dominates_targets(&procedure, &writes, &[read])
                .as_deref(),
            Some([false].as_slice()),
            "the two branch writes collectively cut every path, but neither one individually dominates the read"
        );
        assert_eq!(
            derivation
                .any_candidate_dominates_targets(
                    &procedure,
                    &[procedure.semantics().entry_point()],
                    &[read, read],
                )
                .as_deref(),
            Some([true, true].as_slice()),
            "answers stay aligned with duplicate batched targets"
        );

        let starved = fixture.state_with_budget(0, CfgAlgorithmBudget::uniform(0));
        let starved_derivation = procedure_containing(
            &starved,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        assert!(
            starved_derivation
                .any_candidate_dominates_targets(
                    &procedure,
                    &[procedure.semantics().entry_point()],
                    &[read],
                )
                .is_none(),
            "an uncovered dominance axis must not answer from a partial derivation"
        );
    }

    #[test]
    fn retained_dominance_rejects_another_artifact_with_the_same_dense_procedure_id() {
        let derived_fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = derived_fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );

        let unrelated_fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let unrelated = unrelated_fixture.procedure(0, derivation.procedure);
        assert_eq!(
            derivation.procedure,
            unrelated.id(),
            "the regression requires colliding artifact-local procedure ids"
        );
        let entry = unrelated.semantics().entry_point();
        assert!(
            derivation
                .any_candidate_dominates_targets(&unrelated, &[entry], &[entry])
                .is_none(),
            "a dense procedure id cannot make another artifact's CFG interchangeable"
        );
    }

    const GO_CONTROL_GAP_BEFORE_TARGET: &str = r#"
package sample

type item struct { value int }

func validate() {}

func read(ch chan int, value *item) int {
    observed := <-ch
    after := observed
    _ = after
    validate()
    return value.value
}
"#;

    const GO_RETAINED_INITIALIZATION_CASES: &str = r#"
package sample

func next() int { return 1 }
func sink2(left, right int) {}
func itemsFromCall(left, right int) []int { return nil }

func deferOrder(items []int) {
    value := 1
    value = value
    defer sink2(next(), items[0])
}

func rangeOrder(items []int) {
    value := 1
    value = value
    for k, v := range itemsFromCall(next(), items[0]) { _ = k + v }
    _ = value
}

func selectTopology(ch chan int) {
    value := 1
    select { case <-ch: value = value }
    _ = value
}

func receiveTopology(ch chan int) {
    value := 1
    <-ch
    value = value
    _ = value
}
"#;

    #[test]
    fn retained_initialization_fixture_shapes_publish_the_expected_gap_tuples() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_RETAINED_INITIALIZATION_CASES)],
        );
        let outcome = fixture.materialized(0);
        let artifact = outcome
            .available_value()
            .expect("Go semantics are available");
        let source = GO_RETAINED_INITIALIZATION_CASES;
        let mut found = HashSet::default();
        for procedure in artifact.procedures() {
            for gap in procedure.gaps() {
                let expected = match gap.discharge {
                    SemanticGapDischarge::RetainedEvaluationOrder => None,
                    SemanticGapDischarge::RetainedControlTopology
                        if gap.detail.contains("select may block") =>
                    {
                        Some((
                            "select { case <-ch: value = value }",
                            SemanticCapability::NormalControlFlow,
                        ))
                    }
                    SemanticGapDischarge::RetainedControlTopology
                        if gap.detail.contains("channel receive may block") =>
                    {
                        Some(("<-ch", SemanticCapability::NormalControlFlow))
                    }
                    _ => None,
                };
                let mapping = procedure
                    .source_mapping(gap.source)
                    .expect("each retained gap has a source mapping");
                let span = mapping.locator.anchor().span();
                let mapped = &source[span.start_byte() as usize..span.end_byte() as usize];
                let order_syntax = if gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder
                {
                    if mapped.contains("defer sink2(next(), items[0])") {
                        Some("defer sink2(next(), items[0])")
                    } else if mapped.contains("range itemsFromCall(next(), items[0])") {
                        Some("range itemsFromCall(next(), items[0])")
                    } else {
                        None
                    }
                } else {
                    None
                };
                let expected = expected.or_else(|| {
                    order_syntax.map(|syntax| (syntax, SemanticCapability::NormalControlFlow))
                });
                if let Some((syntax, capability)) = expected {
                    assert!(
                        mapped.contains(syntax),
                        "gap mapping {mapped:?} should cover {syntax:?}"
                    );
                    assert_eq!(gap.capability, capability);
                    assert_eq!(gap.kind, SemanticGapKind::Unknown);
                    assert_eq!(gap.subject, SemanticGapSubject::Point);
                    found.insert(syntax);
                }
            }
        }
        assert_eq!(
            found,
            [
                "defer sink2(next(), items[0])",
                "range itemsFromCall(next(), items[0])",
                "select { case <-ch: value = value }",
                "<-ch",
            ]
            .into_iter()
            .collect(),
            "the defer, select, and receive cases each publish their intended tuple"
        );
    }

    #[test]
    fn channel_blocking_stays_global_incomplete_but_preserves_structured_result_dominance() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_CONTROL_GAP_BEFORE_TARGET)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let receive_gap = procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.detail.as_ref() == "channel receive may block and requires scheduler refinement"
            })
            .expect("the receive publishes its ordinary control gap");
        assert_eq!(
            receive_gap.discharge,
            SemanticGapDischarge::RetainedControlTopology
        );
        let candidate = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_CONTROL_GAP_BEFORE_TARGET, event) == "after := observed"
            })
            .expect("the post-receive binding is established")
            .point;
        let target = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value")
            })
            .expect("the returned field is read")
            .point;
        assert!(
            derivation
                .dominance
                .as_ref()
                .expect("the CFG algorithm completed")
                .dominates(procedure.semantics(), candidate, target),
            "the retained topology alone would call the post-receive candidate a dominator"
        );
        assert!(
            derivation
                .any_candidate_dominates_targets(&procedure, &[candidate], &[target],)
                .is_none(),
            "retained topology is a selective discharge and must not make the generic dominance API complete"
        );
        let validator = call_handle_spelled(&procedure, GO_CONTROL_GAP_BEFORE_TARGET, "validate()");
        assert_eq!(
            derivation
                .any_normal_return_dominates_result_uses(
                    &procedure,
                    &[candidate],
                    &[],
                    std::slice::from_ref(&validator),
                    &[target],
                    &[None],
                )
                .as_deref(),
            Some([true].as_slice()),
            "blocking can prevent the target from being reached, but cannot add a source-local bypass around the validator"
        );
    }

    const GO_NON_REJOINING_GAP_BEFORE_RESULT: &str = r#"
package sample

type item struct { value int }

func validate() {}

func read(input *item, value *item) int {
    _ = input.value
    exact := value
    validate()
    return exact.value
}
"#;

    #[test]
    #[hardwon(
        "6e0319679345: non-rejoining Go panic gaps before a result must not block its exact dominance proof"
    )]
    fn result_dominance_discharges_only_a_non_rejoining_gap_before_establishment() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_NON_REJOINING_GAP_BEFORE_RESULT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_NON_REJOINING_GAP_BEFORE_RESULT, event) == "exact.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let point_for = |needle: &str, event_class| {
            derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == event_class
                        && spelling(GO_NON_REJOINING_GAP_BEFORE_RESULT, event) == needle
                })
                .unwrap_or_else(|| panic!("{needle} publishes a {event_class:?} event"))
                .point
        };
        let pre_gap_point = point_for("input.value", StateEventClass::Read);
        let establishment = point_for("exact := value", StateEventClass::Establish);
        let target = point_for("exact.value", StateEventClass::Read);
        let validator =
            call_handle_spelled(&procedure, GO_NON_REJOINING_GAP_BEFORE_RESULT, "validate()");
        let candidate = procedure
            .semantics()
            .call_site(validator.id())
            .expect("the validator call resolves")
            .normal_continuation
            .target()
            .expect("the validator has a normal continuation");
        let gap = procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.point == pre_gap_point
                    && gap.detail.as_ref() == "selection may panic on a nil operand"
            })
            .expect("the pre-establishment selector publishes its panic gap");
        assert_eq!(
            gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        );
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        assert!(
            dominance.dominates(procedure.semantics(), gap.point, establishment)
                && !dominance.dominates(procedure.semantics(), candidate, gap.point),
            "the gap is before the result and is not made harmless by ordinary candidate placement"
        );
        assert_eq!(
            derivation
                .any_normal_return_dominates_targets(
                    &procedure,
                    std::slice::from_ref(&validator),
                    &[target],
                )
                .as_deref(),
            Some([true].as_slice()),
            "the unobserved exit cannot bypass the normal-return candidate"
        );
        assert_eq!(
            derivation
                .any_normal_return_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[],
                    std::slice::from_ref(&validator),
                    &[target],
                    &[None],
                )
                .as_deref(),
            Some([true].as_slice()),
            "an abort before establishment cannot expose this exact result to the target"
        );
    }

    const GO_EXIT_ONLY_DEFER_RELATIVE_TO_RESULT: &str = r#"
package sample

type item struct{}

func closePool() {}
func reportPre(err error) {}
func reportPost(err error) {}
func reportCyclic(err error) {}

func preOrigin(mode int, value *item, err error) int {
    switch mode {
    case 0:
        defer closePool()
    default:
    }
    exactPre := value
    if err != nil {
        reportPre(err)
    }
    _ = exactPre
    return 0
}

func postOrigin(mode int, value *item, err error) int {
    exactPost := value
    switch mode {
    case 0:
        defer closePool()
    default:
    }
    if err != nil {
        reportPost(err)
    }
    _ = exactPost
    return 0
}

func cyclic(mode int, value *item, err error) int {
    for mode != 0 {
        defer closePool()
        exactCyclic := value
        if err != nil {
            reportCyclic(err)
        }
        _ = exactCyclic
        mode = 0
    }
    return 0
}
"#;

    #[test]
    fn exit_only_completion_is_discharged_in_strict_acyclic_pre_origin_history() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_EXIT_ONLY_DEFER_RELATIVE_TO_RESULT)],
        );
        let state = fixture.state(0);

        for (establishment_spelling, report_spelling, expected) in [
            (
                "exactPre := value",
                "reportPre(err)",
                GuardDominanceAnswer::Proven,
            ),
            (
                "exactPost := value",
                "reportPost(err)",
                GuardDominanceAnswer::Open,
            ),
            (
                "exactCyclic := value",
                "reportCyclic(err)",
                GuardDominanceAnswer::Open,
            ),
        ] {
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_EXIT_ONLY_DEFER_RELATIVE_TO_RESULT, event)
                        == establishment_spelling
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let establishment = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(GO_EXIT_ONLY_DEFER_RELATIVE_TO_RESULT, event)
                            == establishment_spelling
                })
                .expect("the exact result binding is established");
            let markers = semantics
                .gaps()
                .iter()
                .filter(|gap| gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion)
                .collect::<Vec<_>>();
            assert_eq!(markers.len(), 2, "{:#?}", semantics.gaps());
            assert!(
                markers
                    .iter()
                    .any(|gap| { gap.capability == SemanticCapability::DeferredExecution })
            );
            assert!(
                markers
                    .iter()
                    .any(|gap| { gap.capability == SemanticCapability::CleanupControlFlow })
            );

            let retained = result_control_gaps(
                semantics,
                semantics,
                &[establishment.point],
                &[establishment.point],
                |_| true,
            );
            let marker_is_retained = markers
                .iter()
                .any(|marker| retained.iter().any(|gap| std::ptr::eq(*gap, *marker)));
            assert_eq!(
                marker_is_retained,
                expected != GuardDominanceAnswer::Proven,
                "only a strict acyclic pre-origin registration is dischargeable"
            );

            let report = call_handle_spelled(
                &procedure,
                GO_EXIT_ONLY_DEFER_RELATIVE_TO_RESULT,
                report_spelling,
            );
            let report_point = semantics
                .call_site(report.id())
                .expect("the reporter call resolves")
                .point;
            let guard = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                    )
                })
                .expect("the error comparison publishes a normalized guard");
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null comparison")
            };
            let failure_edge = if null_on_true {
                guard.false_edge
            } else {
                guard.true_edge
            }
            .and_then(|edge| procedure.control_edge_handle(edge))
            .expect("the non-null error arm has a scoped edge");

            assert_eq!(
                derivation
                    .any_guard_arm_dominates_result_uses(
                        &procedure,
                        &[establishment.point],
                        std::slice::from_ref(&failure_edge),
                        &[report_point],
                    )
                    .as_deref(),
                Some([expected].as_slice()),
                "the exit-only gap is localized relative to the exact result origin"
            );
            assert_eq!(
                derivation.guard_arm_preserves_result_identity(
                    &procedure,
                    &[establishment.point],
                    &[establishment.value, establishment.subject.value()],
                    &failure_edge,
                ),
                expected == GuardDominanceAnswer::Proven,
                "guard publication uses the same pre-origin locality"
            );
            assert!(
                !derivation.result_observation_enumeration_is_complete(
                    &procedure,
                    &[establishment.point],
                    &[establishment.value, establishment.subject.value()],
                ),
                "exit-time work can still observe the result even when it cannot bypass the guard"
            );

            if expected == GuardDominanceAnswer::Proven {
                assert!(
                    derivation
                        .any_guard_arm_dominates_targets(
                            &procedure,
                            std::slice::from_ref(&failure_edge),
                            &[report_point],
                        )
                        .is_none(),
                    "generic dominance must keep the exit-only gap open"
                );
            }
        }
    }

    const GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET: &str = r#"
package sample

type item struct { value int }

func cleanup() {}
func cleanupFailure() {}
func reportLater(err error) {}
func reportSibling(err error) {}
func reportBetween(err error) {}
func reportCyclic(err error) {}
func reportCleanup(err error) {}
func reportMixed(err error) {}

func later(input *item, value *item, err error) int {
    defer cleanup()
    exactLater := value
    if err != nil {
        reportLater(err)
    }
    _ = input.value
    _ = exactLater
    return 0
}

func sibling(mode int, input *item, value *item, err error) int {
    defer cleanup()
    exactSibling := value
    if mode == 0 {
        _ = input.value
    } else if err != nil {
        reportSibling(err)
    }
    _ = exactSibling
    return 0
}

func between(input *item, value *item, err error) int {
    defer cleanup()
    exactBetween := value
    _ = input.value
    if err != nil {
        reportBetween(err)
    }
    _ = exactBetween
    return 0
}

func cyclic(mode int, input *item, value *item, err error) int {
    defer cleanup()
    exactCyclic := value
    for mode != 0 {
        if err != nil {
            reportCyclic(err)
        }
        _ = input.value
        mode = 0
    }
    _ = exactCyclic
    return 0
}

func cleanupOnly(preInput *item, postInput *item, value *item, err error) int {
    defer cleanup()
    _ = preInput.value
    exactCleanup := value
    if err != nil {
        defer cleanupFailure()
        reportCleanup(err)
        return 0
    }
    _ = postInput.value
    _ = exactCleanup
    return 0
}

func mixed(value *item, err error, ch chan int) int {
    defer cleanup()
    exactMixed := value
    if err != nil {
        reportMixed(err)
        return 1
    }
    ch <- 1
}
"#;

    #[test]
    fn active_cleanup_completion_is_target_local_but_not_generic_control() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET)],
        );
        let state = fixture.state(0);

        for (establishment_spelling, report_spelling, expected) in [
            (
                "exactLater := value",
                "reportLater(err)",
                GuardDominanceAnswer::Proven,
            ),
            (
                "exactSibling := value",
                "reportSibling(err)",
                GuardDominanceAnswer::Proven,
            ),
            (
                "exactBetween := value",
                "reportBetween(err)",
                GuardDominanceAnswer::Open,
            ),
            (
                "exactCyclic := value",
                "reportCyclic(err)",
                GuardDominanceAnswer::Open,
            ),
        ] {
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET, event)
                        == establishment_spelling
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let establishment = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET, event)
                            == establishment_spelling
                })
                .expect("the exact result binding is established");
            let completion = gap_spelled(
                &procedure,
                GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET,
                "input.value",
            );
            assert_eq!(
                completion.capability,
                SemanticCapability::ExceptionalControlFlow
            );
            let SemanticGapSubject::Value(completion_value) = completion.subject else {
                panic!("the active-cleanup panic gap is scoped to its produced value")
            };
            assert_eq!(
                completion.discharge,
                SemanticGapDischarge::ExitOnlyProcedureCompletion,
                "a panic with active cleanup exits this procedure without resuming its body"
            );
            assert!(completion.impacts.contains(SemanticGapImpact::ValueFlow));

            let report = call_handle_spelled(
                &procedure,
                GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET,
                report_spelling,
            );
            let report_point = semantics
                .call_site(report.id())
                .expect("the reporter call resolves")
                .point;
            let guard = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                    )
                })
                .expect("the error comparison publishes a normalized guard");
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null comparison")
            };
            let failure_edge = if null_on_true {
                guard.false_edge
            } else {
                guard.true_edge
            }
            .and_then(|edge| procedure.control_edge_handle(edge))
            .expect("the non-null error arm has a scoped edge");

            assert_eq!(
                derivation
                    .any_guard_arm_dominates_result_uses(
                        &procedure,
                        &[establishment.point],
                        std::slice::from_ref(&failure_edge),
                        &[report_point],
                    )
                    .as_deref(),
                Some([expected].as_slice()),
                "only a completion point outside the target's retained history is local"
            );
            assert!(
                derivation
                    .any_guard_arm_dominates_targets(
                        &procedure,
                        std::slice::from_ref(&failure_edge),
                        &[report_point],
                    )
                    .is_none(),
                "generic guard dominance keeps exit-only completion open"
            );
            assert!(
                !derivation.result_observation_enumeration_is_complete(
                    &procedure,
                    &[establishment.point],
                    &[establishment.value, establishment.subject.value()],
                ),
                "active cleanup may observe a captured result even when the local panic value is unrelated"
            );
            assert!(
                completion_value != establishment.value
                    && completion_value != establishment.subject.value(),
                "the observation regression requires an unrelated gap subject"
            );
        }

        let mixed = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET, event)
                    == "exactMixed := value"
        });
        let mixed_procedure = fixture.procedure(0, mixed.procedure);
        let mixed_semantics = mixed_procedure.semantics();
        let channel_gaps = mixed_semantics
            .gaps()
            .iter()
            .filter(|gap| {
                let mapping = mixed_semantics
                    .source_mapping(gap.source)
                    .expect("a channel-send gap has a source mapping");
                let span = mapping.locator.anchor().span();
                &GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET
                    [span.start_byte() as usize..span.end_byte() as usize]
                    == "ch <- 1"
            })
            .collect::<Vec<_>>();
        let channel_completion = channel_gaps
            .iter()
            .copied()
            .find(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion
            })
            .unwrap_or_else(|| {
                panic!("channel send must publish its exit-only panic gap: {channel_gaps:#?}")
            });
        let channel_control = channel_gaps
            .iter()
            .copied()
            .find(|gap| {
                gap.capability == SemanticCapability::NormalControlFlow
                    && gap.discharge == SemanticGapDischarge::RetainedControlTopology
            })
            .unwrap_or_else(|| {
                panic!("channel send must retain its source-local topology: {channel_gaps:#?}")
            });
        assert_eq!(
            channel_completion.point, channel_control.point,
            "the two obligations intentionally share one retained point"
        );
        let mixed_report = call_handle_spelled(
            &mixed_procedure,
            GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET,
            "reportMixed(err)",
        );
        let mixed_report_point = mixed_semantics
            .call_site(mixed_report.id())
            .expect("the mixed reporter call resolves")
            .point;
        let mixed_guard = mixed_semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .expect("the mixed error comparison publishes a guard");
        let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
            mixed_guard.predicate
        else {
            unreachable!("filtered to a null comparison")
        };
        let mixed_failure_edge = if null_on_true {
            mixed_guard.false_edge
        } else {
            mixed_guard.true_edge
        }
        .and_then(|edge| mixed_procedure.control_edge_handle(edge))
        .expect("the mixed non-null error arm has a scoped edge");
        let mixed_dominance = mixed
            .dominance
            .as_ref()
            .expect("the mixed CFG algorithm completed");
        let mixed_candidates =
            validated_guard_edges(&mixed_procedure, std::slice::from_ref(&mixed_failure_edge))
                .expect("the mixed failure arm is an exact guard edge");
        assert_eq!(
            guard_edges_dominate_result_targets(
                mixed_semantics,
                mixed_semantics,
                mixed_dominance,
                &mixed_candidates,
                &[mixed_report_point],
                &[channel_completion],
            )
            .as_ref(),
            [GuardDominanceAnswer::Proven].as_slice(),
            "the exit-only completion alone is local to the later sibling arm"
        );
        assert_eq!(
            guard_edges_dominate_result_targets(
                mixed_semantics,
                mixed_semantics,
                mixed_dominance,
                &mixed_candidates,
                &[mixed_report_point],
                &[channel_completion, channel_control],
            )
            .as_ref(),
            [GuardDominanceAnswer::Open].as_slice(),
            "the raw helper leaves discharge policy to its semantic consumer"
        );

        let cleanup = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET, event)
                    == "exactCleanup := value"
        });
        let cleanup_procedure = fixture.procedure(0, cleanup.procedure);
        let cleanup_semantics = cleanup_procedure.semantics();
        let cleanup_completion = gap_spelled(
            &cleanup_procedure,
            GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET,
            "postInput.value",
        );
        assert_eq!(
            cleanup_completion.discharge,
            SemanticGapDischarge::ExitOnlyProcedureCompletion
        );
        let cleanup_guard = cleanup_semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .expect("the cleanup error comparison publishes a guard");
        let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
            cleanup_guard.predicate
        else {
            unreachable!("filtered to a null comparison")
        };
        let cleanup_failure_edge = if null_on_true {
            cleanup_guard.false_edge
        } else {
            cleanup_guard.true_edge
        }
        .and_then(|edge| cleanup_procedure.control_edge_handle(edge))
        .expect("the cleanup non-null error arm has a scoped edge");
        let cleanup_candidates = validated_guard_edges(
            &cleanup_procedure,
            std::slice::from_ref(&cleanup_failure_edge),
        )
        .expect("the cleanup failure arm is an exact guard edge");
        let [cleanup_candidate] = cleanup_candidates.as_slice() else {
            panic!("one cleanup failure candidate")
        };
        let cleanup_dominance = cleanup
            .dominance
            .as_ref()
            .expect("the cleanup CFG algorithm completed");
        let reachable_without_failure = reachable_points_without_edge(
            cleanup_semantics,
            cleanup_semantics.entry_point(),
            cleanup_candidate.id,
        );
        let reachable_from_completion =
            reachable_points_from(cleanup_semantics, cleanup_completion.point);
        let ordinary_points = ordinary_body_points(cleanup_semantics, cleanup_semantics);
        let cleanup_target = cleanup_semantics
            .control_edges()
            .iter()
            .filter(|edge| edge.kind == ControlEdgeKind::Cleanup)
            .map(|edge| edge.target_point)
            .find(|target| {
                cleanup_dominance.dominates(cleanup_semantics, cleanup_candidate.target, *target)
                    && !reachable_without_failure.contains(target)
                    && !reachable_from_completion.contains(target)
                    && !ordinary_points.contains(target)
            })
            .unwrap_or_else(|| {
                panic!(
                    "the failure-only defer must expose a cleanup-only target: {:#?}",
                    cleanup_semantics.control_edges()
                )
            });
        let cleanup_establishment = cleanup
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET, event)
                        == "exactCleanup := value"
            })
            .expect("the cleanup result is established");
        let pre_origin_completion = gap_spelled(
            &cleanup_procedure,
            GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET,
            "preInput.value",
        );
        assert_eq!(
            pre_origin_completion.capability,
            SemanticCapability::ExceptionalControlFlow
        );
        assert_eq!(
            pre_origin_completion.discharge,
            SemanticGapDischarge::ExitOnlyProcedureCompletion,
            "the already-active first defer scopes this pre-origin panic"
        );
        assert!(
            pre_origin_completion.point != cleanup_establishment.point
                && reachable_points_from(cleanup_semantics, pre_origin_completion.point)
                    .contains(&cleanup_establishment.point)
                && !reachable_points_from(cleanup_semantics, cleanup_establishment.point)
                    .contains(&pre_origin_completion.point),
            "the active-cleanup exceptional marker is strictly and acyclically pre-origin"
        );
        let reachable_from_pre_origin =
            reachable_points_from(cleanup_semantics, pre_origin_completion.point);
        let pre_origin_cleanup_target = cleanup_semantics
            .control_edges()
            .iter()
            .filter(|edge| edge.kind == ControlEdgeKind::Cleanup)
            .map(|edge| edge.target_point)
            .find(|target| {
                *target != cleanup_semantics.normal_exit_point()
                    && *target != cleanup_semantics.exceptional_exit_point()
                    && *target != cleanup_target
                    && reachable_from_pre_origin.contains(target)
                    && !cleanup_dominance.dominates(
                        cleanup_semantics,
                        cleanup_candidate.target,
                        *target,
                    )
                    && !ordinary_points.contains(target)
            })
            .unwrap_or_else(|| {
                panic!(
                    "the already-active first defer must expose a shared cleanup target: {:#?}",
                    cleanup_semantics.control_edges()
                )
            });
        assert!(ordinary_points.contains(&cleanup_establishment.point));
        assert!(
            !result_control_gaps(
                cleanup_semantics,
                cleanup_semantics,
                &[cleanup_establishment.point],
                &[cleanup_establishment.point],
                |_| true,
            )
            .iter()
            .any(|gap| gap.id == pre_origin_completion.id),
            "strict pre-origin completion is local to an ordinary-body target"
        );
        assert!(
            result_control_gaps(
                cleanup_semantics,
                cleanup_semantics,
                &[cleanup_establishment.point],
                &[pre_origin_cleanup_target],
                |_| true,
            )
            .iter()
            .any(|gap| gap.id == pre_origin_completion.id),
            "strict pre-origin placement cannot discharge the panic for an active cleanup target"
        );
        assert!(
            gaps_that_cannot_reach_targets(
                cleanup_semantics,
                &[cleanup_target],
                &[cleanup_completion],
            )
            .contains(&(cleanup_target, cleanup_completion.id)),
            "raw reachability alone would localize the completion marker"
        );
        assert_eq!(
            guard_edges_dominate_result_targets(
                cleanup_semantics,
                cleanup_semantics,
                cleanup_dominance,
                &cleanup_candidates,
                &[cleanup_target],
                &[cleanup_completion],
            )
            .as_ref(),
            [GuardDominanceAnswer::Open].as_slice(),
            "exit-only work may enter a cleanup target even when its retained point cannot"
        );
    }

    const GO_POINT_DOMINANCE_RELATIVE_TO_RESULT: &str = r#"
package sample

type item struct { value int }

func read(input *item, value *item) int {
    _ = input.value
    exact := value
    first := exact.value
    return first + exact.value
}
"#;

    #[test]
    #[hardwon(
        "cf2e70f23ccf: result-relative ordering must discharge only strict pre-establishment exceptional exits"
    )]
    fn result_point_dominance_discharges_only_pre_establishment_exceptional_exits() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_POINT_DOMINANCE_RELATIVE_TO_RESULT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_POINT_DOMINANCE_RELATIVE_TO_RESULT, event) == "exact.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let (establishment, candidate, target) =
            two_result_read_points(derivation, GO_POINT_DOMINANCE_RELATIVE_TO_RESULT);
        let pre_gap = gap_spelled(
            &procedure,
            GO_POINT_DOMINANCE_RELATIVE_TO_RESULT,
            "input.value",
        );
        assert_eq!(
            pre_gap.detail.as_ref(),
            "selection may panic on a nil operand"
        );
        assert_eq!(
            pre_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        );
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        assert!(
            dominance.dominates(procedure.semantics(), pre_gap.point, establishment)
                && dominance.dominates(procedure.semantics(), candidate, target),
            "the regression requires a pre-result gap and retained point dominance"
        );
        assert_eq!(
            derivation
                .any_candidate_dominates_targets(&procedure, &[candidate], &[target])
                .as_deref(),
            Some([true].as_slice()),
            "an unobserved exceptional exit cannot bypass the candidate to reach its use"
        );
        assert_eq!(
            derivation
                .any_candidate_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[candidate],
                    &[target],
                )
                .as_deref(),
            Some([true].as_slice()),
            "an abort before establishment cannot expose this exact result after bypassing its first use"
        );
    }

    const GO_POINT_DOMINANCE_POST_RESULT_GAP: &str = r#"
package sample

type item struct { value int }

func read(input *item, value *item) int {
    exact := value
    _ = input.value
    first := exact.value
    return first + exact.value
}
"#;

    #[test]
    // Owner ruling on #8602 (2026-10-31): an unobserved exit cannot change in-procedure dominance; this replaces the cf2e70f23ccf boundary.
    fn result_point_dominance_discharges_post_establishment_unobserved_exits() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_POINT_DOMINANCE_POST_RESULT_GAP)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_POINT_DOMINANCE_POST_RESULT_GAP, event) == "exact.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let (establishment, candidate, target) =
            two_result_read_points(derivation, GO_POINT_DOMINANCE_POST_RESULT_GAP);
        let post_gap = gap_spelled(
            &procedure,
            GO_POINT_DOMINANCE_POST_RESULT_GAP,
            "input.value",
        );
        assert_eq!(
            post_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        );
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        assert!(
            dominance.dominates(procedure.semantics(), establishment, post_gap.point)
                && dominance.dominates(procedure.semantics(), post_gap.point, candidate)
                && dominance.dominates(procedure.semantics(), candidate, target),
            "the post-result gap is the only intended obstacle before a retained candidate dominator"
        );
        assert_eq!(
            derivation
                .any_candidate_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[candidate],
                    &[target],
                )
                .as_deref(),
            Some([true].as_slice()),
            "a reached candidate follows only the normal continuation of an unobserved exit"
        );
    }

    const GO_POINT_DOMINANCE_GAP_AFTER_CANDIDATE: &str = r#"
package sample

type item struct { value int }

func read(input *item, value *item) int {
    exact := value
    first := exact.value
    _ = input.value
    return first + exact.value
}
"#;

    #[test]
    #[hardwon(
        "cf2e70f23ccf: candidate-local proof must retain post-candidate exceptional-gap safety"
    )]
    fn result_point_dominance_keeps_candidate_local_gap_safety() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_POINT_DOMINANCE_GAP_AFTER_CANDIDATE)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_POINT_DOMINANCE_GAP_AFTER_CANDIDATE, event) == "exact.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let (establishment, candidate, target) =
            two_result_read_points(derivation, GO_POINT_DOMINANCE_GAP_AFTER_CANDIDATE);
        let post_candidate_gap = gap_spelled(
            &procedure,
            GO_POINT_DOMINANCE_GAP_AFTER_CANDIDATE,
            "input.value",
        );
        assert_eq!(
            post_candidate_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        );
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        assert!(
            dominance.dominates(procedure.semantics(), establishment, candidate)
                && dominance.dominates(procedure.semantics(), candidate, post_candidate_gap.point)
                && dominance.dominates(procedure.semantics(), candidate, target),
            "the candidate precedes both the ordinary gap and the later target"
        );
        assert_eq!(
            derivation
                .any_candidate_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[candidate],
                    &[target],
                )
                .as_deref(),
            Some([true].as_slice()),
            "the result-specific proof retains the generic candidate-local gap obligation"
        );
    }

    const GO_POINT_DOMINANCE_CYCLIC_PRE_RESULT_GAP: &str = r#"
package sample

type item struct { value int }

func read(input *item, value *item) int {
    total := 0
    for input != nil {
        _ = input.value
        exact := value
        first := exact.value
        total += first + exact.value
        input = nil
    }
    return total
}
"#;

    #[test]
    #[hardwon(
        "cf2e70f23ccf: cyclic gaps before establishment cannot be treated as a one-time pre-origin exit"
    )]
    fn result_point_dominance_retains_cyclic_pre_establishment_gaps() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_POINT_DOMINANCE_CYCLIC_PRE_RESULT_GAP)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_POINT_DOMINANCE_CYCLIC_PRE_RESULT_GAP, event) == "exact.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let (establishment, candidate, target) =
            two_result_read_points(derivation, GO_POINT_DOMINANCE_CYCLIC_PRE_RESULT_GAP);
        let cyclic_gap = gap_spelled(
            &procedure,
            GO_POINT_DOMINANCE_CYCLIC_PRE_RESULT_GAP,
            "input.value",
        );
        assert_eq!(
            cyclic_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        );
        let semantics = procedure.semantics();
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        assert!(
            dominance.dominates(semantics, cyclic_gap.point, establishment)
                && reachable_points_from(semantics, establishment).contains(&cyclic_gap.point)
                && dominance.dominates(semantics, candidate, target),
            "the gap dominates establishment but can be revisited after that establishment"
        );
        let retained_gaps =
            result_control_gaps(semantics, semantics, &[establishment], &[target], |_| true);
        assert!(
            retained_gaps
                .iter()
                .any(|gap| std::ptr::eq(*gap, cyclic_gap)),
            "dominance does not make a cyclic gap strictly earlier than the result"
        );
        assert!(
            derivation
                .any_candidate_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[candidate],
                    &[target],
                )
                .is_none(),
            "a later loop iteration can revisit the omitted exceptional-flow boundary"
        );
    }

    const SCALA_DEFERRED_TARGET_ARGUMENT_ORDER: &str = r#"
object Sample {
  def checked(): String = "checked"
  def checkedEarlier(): String = "checked"
  def consume(value: => String): Unit = ()

  def unsafe(binding: String): Unit = {
    consume(checked())
  }

  def earlier(binding: String): Unit = {
    checked()
    consume("constant")
  }

  def mixed(binding: String): Unit = {
    checkedEarlier()
    consume(checked())
  }
}
"#;

    #[test]
    fn direct_result_argument_does_not_assume_scala_by_name_arguments_are_eager() {
        let fixture = Fixture::new(
            Language::Scala,
            &[("Sample.scala", SCALA_DEFERRED_TARGET_ARGUMENT_ORDER)],
        );
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Scala semantics are available");
        let semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("unsafe")
            })
            .expect("unsafe procedure");
        let procedure = artifact
            .procedure_handle(semantics.id())
            .expect("procedure handle");
        let derivation = state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == procedure.id())
            .expect("flow-state derivation");
        let predicate_binding = semantics
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
            .expect("stable predicate parameter binding")
            .id;
        let validator = call_handle_spelled(
            &procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "checked()",
        );
        let target = call_handle_spelled(
            &procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "consume(checked())",
        );
        let validator_call = semantics
            .call_site(validator.id())
            .expect("validator call site");
        let target_call = semantics.call_site(target.id()).expect("target call site");
        assert!(target_call.arguments.iter().any(|argument| {
            validator_call.result == Some(argument.value)
                || validator_call.normal_results.contains(&argument.value)
        }));
        let strictness_gap = semantics
            .gaps()
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::CallSite(target.id())
                    && gap.capability == SemanticCapability::DeferredExecution
                    && gap.discharge == SemanticGapDischarge::CallResolution
            })
            .expect("the exact target call retains its argument-strictness gap");
        assert_eq!(strictness_gap.point, target_call.point);
        assert!(
            !strictness_gap
                .impacts
                .contains(SemanticGapImpact::CallEvaluation),
            "this ordinary argument exercises the call-resolution arm, not a structured-call impact"
        );

        assert!(
            derivation
                .any_normal_return_dominates_result_uses(
                    &procedure,
                    &[semantics.entry_point()],
                    &[predicate_binding],
                    std::slice::from_ref(&validator),
                    &[target_call.point],
                    &[Some(target.id())],
                )
                .is_none(),
            "a by-name target may defer or repeat the validator result argument"
        );

        let earlier_semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("earlier")
            })
            .expect("earlier procedure");
        let earlier_procedure = artifact
            .procedure_handle(earlier_semantics.id())
            .expect("earlier procedure handle");
        let earlier_derivation = state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == earlier_procedure.id())
            .expect("earlier flow-state derivation");
        let earlier_validator = call_handle_spelled(
            &earlier_procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "checked()",
        );
        let earlier_target = call_handle_spelled(
            &earlier_procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "consume(\"constant\")",
        );
        let earlier_target_call = earlier_semantics
            .call_site(earlier_target.id())
            .expect("earlier target call site");
        let earlier_validator_call = earlier_semantics
            .call_site(earlier_validator.id())
            .expect("earlier validator call site");
        assert!(earlier_target_call.arguments.iter().all(|argument| {
            earlier_validator_call.result != Some(argument.value)
                && !earlier_validator_call
                    .normal_results
                    .contains(&argument.value)
        }));
        assert!(earlier_semantics.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::CallSite(earlier_target.id())
                && gap.capability == SemanticCapability::DeferredExecution
                && gap.discharge == SemanticGapDischarge::CallResolution
        }));
        assert_eq!(
            earlier_derivation
                .any_normal_return_dominates_result_uses(
                    &earlier_procedure,
                    &[earlier_semantics.entry_point()],
                    &[earlier_semantics
                        .values()
                        .iter()
                        .find(|value| {
                            matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. })
                        })
                        .expect("earlier stable predicate parameter binding")
                        .id],
                    std::slice::from_ref(&earlier_validator),
                    &[earlier_target_call.point],
                    &[Some(earlier_target.id())],
                )
                .as_deref(),
            Some([true].as_slice()),
            "an unrelated deferred target must not erase ordinary earlier dominance"
        );

        let mixed_semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("mixed")
            })
            .expect("mixed procedure");
        let mixed_procedure = artifact
            .procedure_handle(mixed_semantics.id())
            .expect("mixed procedure handle");
        let mixed_derivation = state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == mixed_procedure.id())
            .expect("mixed flow-state derivation");
        let earlier_mixed_validator = call_handle_spelled(
            &mixed_procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "checkedEarlier()",
        );
        let direct_mixed_validator = call_handle_spelled(
            &mixed_procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "checked()",
        );
        let mixed_target = call_handle_spelled(
            &mixed_procedure,
            SCALA_DEFERRED_TARGET_ARGUMENT_ORDER,
            "consume(checked())",
        );
        let mixed_target_call = mixed_semantics
            .call_site(mixed_target.id())
            .expect("mixed target call site");
        assert_eq!(
            mixed_derivation
                .any_normal_return_dominates_result_uses(
                    &mixed_procedure,
                    &[mixed_semantics.entry_point()],
                    &[mixed_semantics
                        .values()
                        .iter()
                        .find(|value| {
                            matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. })
                        })
                        .expect("mixed stable predicate parameter binding")
                        .id],
                    &[earlier_mixed_validator, direct_mixed_validator],
                    &[mixed_target_call.point],
                    &[Some(mixed_target.id())],
                )
                .as_deref(),
            Some([true].as_slice()),
            "a deferred direct candidate must not erase an independent earlier validator"
        );
    }

    const RUST_OPEN_TARGET_OPERAND_ORDER: &str = r#"
fn checked(_value: Option<i32>) -> bool { true }
fn use_values(_validated: bool, _after: ()) {}

fn captured_operand(mut value: Option<i32>) {
    use_values(checked(value), (|| { value = None; })());
}

struct Receiver;
impl Receiver {
    fn consume(&mut self, _validated: bool) {}
}

fn receiver_adjustment(mut receiver: Receiver, value: Option<i32>) {
    receiver.consume(checked(value));
}

// Guard carries a real Drop impl so the fixture retains destructor gaps after
// #5911 stopped inventing them for proven non-Drop values.
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {}
}

fn unrelated_adjustment(mut receiver: Receiver, value: Option<i32>, guard: Guard) {
    use_values(checked(value), ());
    receiver.consume(false);
    unknown_macro!();
}
"#;

    #[test]
    fn direct_result_argument_stays_open_for_unknown_capture_and_call_evaluation() {
        let fixture = Fixture::new(
            Language::Rust,
            &[("src/lib.rs", RUST_OPEN_TARGET_OPERAND_ORDER)],
        );
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Rust semantics are available");

        for (procedure_name, parameter_ordinal, target_spelling) in [
            (
                "captured_operand",
                0,
                "use_values(checked(value), (|| { value = None; })())",
            ),
            ("receiver_adjustment", 1, "receiver.consume(checked(value))"),
        ] {
            let semantics = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(procedure_name)
                })
                .unwrap_or_else(|| panic!("{procedure_name} procedure"));
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("procedure handle");
            let derivation = state
                .procedures
                .iter()
                .find(|candidate| candidate.procedure == procedure.id())
                .expect("flow-state derivation");
            let predicate_binding = semantics
                .values()
                .iter()
                .find(|value| {
                    matches!(
                        value.kind,
                        SemanticValueKind::Parameter { ordinal, .. }
                            if ordinal == parameter_ordinal
                    )
                })
                .expect("predicate parameter binding")
                .id;
            let validator =
                call_handle_spelled(&procedure, RUST_OPEN_TARGET_OPERAND_ORDER, "checked(value)");
            let target =
                call_handle_spelled(&procedure, RUST_OPEN_TARGET_OPERAND_ORDER, target_spelling);
            let validator_call = semantics
                .call_site(validator.id())
                .expect("validator call site");
            let candidate_point = validator_call
                .normal_continuation
                .target()
                .expect("validator normal continuation");
            let target_call = semantics.call_site(target.id()).expect("target call site");
            assert!(validator_call.normal_result_is_argument_to(target_call));

            if procedure_name == "captured_operand" {
                let capture_gap = semantics
                    .gaps()
                    .iter()
                    .find(|gap| {
                        gap.capability == SemanticCapability::Captures
                            && matches!(
                                gap.subject,
                                SemanticGapSubject::Value(value)
                                    if semantics.value(value).is_some_and(|value| {
                                        value.kind == SemanticValueKind::Callable
                                    })
                            )
                    })
                    .expect("the inline closure retains its unknown capture environment");
                assert!(
                    point_reaches(semantics, candidate_point, capture_gap.point, true)
                        && point_reaches(semantics, capture_gap.point, target_call.point, true),
                    "the unknown capture is created in the remaining target operand window"
                );
            } else {
                // The receiver adjustment rides on the call-target gap of the
                // exact call (#3757), which keeps caller-side evaluation open
                // until the call's resolution answers it.
                assert!(semantics.gaps().iter().any(|gap| {
                    gap.point == target_call.point
                        && gap.subject == SemanticGapSubject::CallSite(target_call.id)
                        && gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                }));
            }

            assert!(
                derivation
                    .any_normal_return_dominates_result_uses(
                        &procedure,
                        &[semantics.entry_point()],
                        &[predicate_binding],
                        std::slice::from_ref(&validator),
                        &[target_call.point],
                        &[Some(target.id())],
                    )
                    .is_none(),
                "unknown capture or caller-side evaluation keeps {procedure_name} open"
            );
        }
    }

    #[test]
    fn target_call_evaluation_check_ignores_an_unrelated_gap() {
        let fixture = Fixture::new(
            Language::Rust,
            &[("src/lib.rs", RUST_OPEN_TARGET_OPERAND_ORDER)],
        );
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Rust semantics are available");
        let semantics = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("unrelated_adjustment")
            })
            .expect("unrelated_adjustment procedure");
        let procedure = artifact
            .procedure_handle(semantics.id())
            .expect("procedure handle");
        let derivation = state
            .procedures
            .iter()
            .find(|candidate| candidate.procedure == procedure.id())
            .expect("flow-state derivation");
        let predicate_binding = semantics
            .values()
            .iter()
            .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 1, .. }))
            .expect("predicate parameter binding")
            .id;
        let validator =
            call_handle_spelled(&procedure, RUST_OPEN_TARGET_OPERAND_ORDER, "checked(value)");
        let target = call_handle_spelled(
            &procedure,
            RUST_OPEN_TARGET_OPERAND_ORDER,
            "use_values(checked(value), ())",
        );
        let unrelated_macro = call_handle_spelled(
            &procedure,
            RUST_OPEN_TARGET_OPERAND_ORDER,
            "unknown_macro!()",
        );
        let target_call = semantics.call_site(target.id()).expect("target call site");
        let unrelated_macro_call = semantics
            .call_site(unrelated_macro.id())
            .expect("unknown_macro!() call site");
        let adjustment = call_handle_spelled(
            &procedure,
            RUST_OPEN_TARGET_OPERAND_ORDER,
            "receiver.consume(false)",
        );
        assert!(semantics.gaps().iter().any(|gap| {
            gap.point != target_call.point
                && gap.subject == SemanticGapSubject::CallSite(adjustment.id())
                && gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        }));
        assert!(target_call_evaluation_is_open(
            semantics,
            semantics.call_site(adjustment.id()).expect("adjusted call"),
        ));
        assert!(
            !target_call_evaluation_is_open(semantics, target_call),
            "a later call's evaluation gap must not contaminate the exact target"
        );
        // #5267/#5239 lowered non-built-in macros as open calls with an unknown-macro gap.
        assert!(semantics.gaps().iter().any(|gap| {
            gap.point == unrelated_macro_call.point
                && gap.subject == SemanticGapSubject::CallSite(unrelated_macro.id())
                && gap.capability == SemanticCapability::Calls
                && gap.kind == SemanticGapKind::Unknown
                && gap.detail.as_ref()
                    == "unknown macro expansion: captured tokens are not evaluated or passed as argument values"
        }));
        assert!(
            derivation
                .any_normal_return_dominates_result_uses(
                    &procedure,
                    &[semantics.entry_point()],
                    &[predicate_binding],
                    std::slice::from_ref(&validator),
                    &[target_call.point],
                    &[Some(target.id())],
                )
                .is_none(),
            "the unrelated unexpanded macro keeps generic dominance open"
        );
    }

    const GO_OPTIONAL_NON_REJOINING_GAP_BEFORE_GUARDED_RESULT: &str = r#"
package sample

type item struct { value int }

func read(check bool, input *item, value *item) int {
    if check {
        _ = input.value
    }
    exact := value
    if exact != nil {
        return exact.value
    }
    return 0
}
"#;

    #[test]
    #[hardwon(
        "6614ef58a7c4: optional non-dominating panic gaps before origin must not poison exact result proof"
    )]
    fn result_guard_dominance_discharges_an_optional_gap_before_establishment() {
        let fixture = Fixture::new(
            Language::Go,
            &[(
                "main.go",
                GO_OPTIONAL_NON_REJOINING_GAP_BEFORE_GUARDED_RESULT,
            )],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_OPTIONAL_NON_REJOINING_GAP_BEFORE_GUARDED_RESULT, event)
                    == "exact.value"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let establishment = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_OPTIONAL_NON_REJOINING_GAP_BEFORE_GUARDED_RESULT, event)
                        == "exact := value"
            })
            .expect("the exact result binding is established")
            .point;
        let target = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_OPTIONAL_NON_REJOINING_GAP_BEFORE_GUARDED_RESULT, event)
                        == "exact.value"
            })
            .expect("the guarded result is read")
            .point;
        let optional_gap = gap_spelled(
            &procedure,
            GO_OPTIONAL_NON_REJOINING_GAP_BEFORE_GUARDED_RESULT,
            "input.value",
        );
        assert_eq!(
            optional_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit
        );
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        assert!(
            !dominance.dominates(semantics, optional_gap.point, establishment)
                && reachable_points_from(semantics, optional_gap.point).contains(&establishment)
                && !reachable_points_from(semantics, establishment).contains(&optional_gap.point),
            "the optional gap is a strict acyclic predecessor without dominating the result"
        );
        let guard = semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .expect("the nil comparison publishes a normalized guard");
        let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
            guard.predicate
        else {
            unreachable!("filtered to a null-comparison guard")
        };
        let success_edge = if null_on_true {
            guard.false_edge
        } else {
            guard.true_edge
        }
        .expect("the non-nil guard arm has a control edge");
        let success_handle = procedure
            .control_edge_handle(success_edge)
            .expect("the guard edge has a scoped handle");
        assert!(
            derivation
                .any_guard_arm_dominates_targets(
                    &procedure,
                    std::slice::from_ref(&success_handle),
                    &[target],
                )
                .is_none(),
            "generic guard dominance must retain the pre-establishment panic gap"
        );
        assert_eq!(
            derivation
                .any_guard_arm_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[success_handle],
                    &[target],
                )
                .as_deref(),
            Some([GuardDominanceAnswer::Proven].as_slice()),
            "the result-specific guard proof can exclude an abort before the result exists"
        );
    }

    const GO_MIXED_CLOSED_AND_OPEN_GUARD_TARGETS: &str = r#"
package sample

import "os"

type holder struct { values []int }

func mixed(path string, h *holder) string {
    for range h.values {
        _ = h.values
    }
    file, err := os.Open(path)
    if err != nil {
        _ = file.Name()
        return ""
    }
    return file.Name()
}
"#;

    #[test]
    fn guard_dominance_keeps_closed_negative_when_another_target_is_proven() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_MIXED_CLOSED_AND_OPEN_GUARD_TARGETS)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_MIXED_CLOSED_AND_OPEN_GUARD_TARGETS, event) == "file"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let mut targets = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_MIXED_CLOSED_AND_OPEN_GUARD_TARGETS, event) == "file"
            })
            .collect::<Vec<_>>();
        targets.sort_unstable_by_key(|event| event.site.range.start_line);
        let [failure_arm_use, success_arm_use] = targets.as_slice() else {
            panic!("the exact file result has two Name receiver reads: {targets:#?}")
        };
        assert_eq!(
            failure_arm_use.subject, success_arm_use.subject,
            "both Name receivers read the same lexical file binding"
        );
        let establishment = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && event.subject == failure_arm_use.subject
                    && spelling(GO_MIXED_CLOSED_AND_OPEN_GUARD_TARGETS, event)
                        == "file, err := os.Open(path)"
            })
            .expect("the exact file result is established");
        let guard = semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .expect("the error comparison publishes a normalized guard");
        let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
            guard.predicate
        else {
            unreachable!("filtered to a null-comparison guard")
        };
        let success_edge = if null_on_true {
            guard.true_edge
        } else {
            guard.false_edge
        }
        .expect("the nil-error arm has a control edge");
        let success_handle = procedure
            .control_edge_handle(success_edge)
            .expect("the success edge has a scoped handle");

        assert!(
            derivation
                .any_guard_arm_dominates_targets(
                    &procedure,
                    std::slice::from_ref(&success_handle),
                    &[failure_arm_use.point, success_arm_use.point],
                )
                .is_none(),
            "the generic API preserves its batch-level open contract"
        );
        assert_eq!(
            derivation
                .any_guard_arm_dominates_result_uses(
                    &procedure,
                    &[establishment.point],
                    std::slice::from_ref(&success_handle),
                    &[failure_arm_use.point, success_arm_use.point],
                )
                .as_deref(),
            Some(
                [
                    GuardDominanceAnswer::ClosedNegative,
                    GuardDominanceAnswer::Proven,
                ]
                .as_slice()
            ),
            "the proven success arm must not erase the failure arm's closed negative"
        );
    }

    const GO_REJOINING_ERROR_ARM: &str = r#"
package sample

type item struct { value int }

func fallthrough(result *item, err error) int {
    joined := result
    if err != nil {
        ignored := true
        _ = ignored
    }
    return joined.value
}

func earlyReturn(result *item, err error) int {
    guarded := result
    if err != nil {
        return 0
    }
    return guarded.value
}
"#;

    #[test]
    #[hardwon(
        "f4c4576aa165: a rejoining error arm must remain a bypass when proving conditional guard dominance"
    )]
    fn rejoining_error_arm_does_not_dominate_result_use() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_REJOINING_ERROR_ARM)]);
        let state = fixture.state(0);

        for (binding, establishment_spelling, expected) in [
            ("joined.value", "joined := result", false),
            ("guarded.value", "guarded := result", true),
        ] {
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_REJOINING_ERROR_ARM, event) == binding
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let establishment = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(GO_REJOINING_ERROR_ARM, event) == establishment_spelling
                })
                .expect("the result binding is established")
                .point;
            let target = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Read
                        && spelling(GO_REJOINING_ERROR_ARM, event) == binding
                })
                .expect("the result is read")
                .point;
            let guard = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                    )
                })
                .expect("the error comparison publishes a normalized guard");
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null-comparison guard")
            };
            let success_edge = if null_on_true {
                guard.true_edge
            } else {
                guard.false_edge
            }
            .expect("the nil-error arm has a control edge");
            let success_target = semantics
                .control_edge(success_edge)
                .expect("the success edge resolves")
                .target_point;
            assert!(
                derivation
                    .dominance
                    .as_ref()
                    .expect("the CFG algorithm completed")
                    .dominates(semantics, success_target, target),
                "the regression requires the success edge target to dominate the use"
            );
            let success_handle = procedure
                .control_edge_handle(success_edge)
                .expect("the success edge has a scoped handle");
            assert_eq!(
                derivation
                    .any_guard_arm_dominates_targets(
                        &procedure,
                        std::slice::from_ref(&success_handle),
                        &[target],
                    )
                    .as_deref(),
                Some([expected].as_slice()),
                "generic guard dominance must retain the exact conditional edge"
            );
            assert_eq!(
                derivation
                    .any_guard_arm_dominates_result_uses(
                        &procedure,
                        &[establishment],
                        &[success_handle],
                        &[target],
                    )
                    .as_deref(),
                Some(
                    [if expected {
                        GuardDominanceAnswer::Proven
                    } else {
                        GuardDominanceAnswer::ClosedNegative
                    }]
                    .as_slice()
                ),
                "a success guard proves the later use only when its exact edge is unavoidable"
            );
        }
    }

    const GO_BRANCH_LOCAL_TARGET_BEFORE_NON_REJOINING_GAP: &str = r#"
package sample

type item struct { acyclicValue, cyclicValue int }

func observeAcyclic(err error) {}
func observeCyclic(err error) {}

func acyclic(result *item, err error) int {
    exact := result
    if err != nil {
        observeAcyclic(err)
    }
    return exact.acyclicValue
}

func cyclic(result *item, err error) {
    exact := result
    for {
        if err != nil {
            observeCyclic(err)
        }
        _ = exact.cyclicValue
    }
}
"#;

    #[test]
    #[hardwon(
        "634e91920ec2: unreachable non-rejoining Go panics must not block a later guard-use proof"
    )]
    fn result_guard_dominance_ignores_non_rejoining_gaps_that_cannot_reach_the_use() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_BRANCH_LOCAL_TARGET_BEFORE_NON_REJOINING_GAP)],
        );
        let state = fixture.state(0);

        for (selector, call, expected) in [
            ("exact.acyclicValue", "observeAcyclic(err)", Some(true)),
            ("exact.cyclicValue", "observeCyclic(err)", None),
        ] {
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_BRANCH_LOCAL_TARGET_BEFORE_NON_REJOINING_GAP, event) == selector
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let establishment = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(GO_BRANCH_LOCAL_TARGET_BEFORE_NON_REJOINING_GAP, event)
                            == "exact := result"
                })
                .expect("the exact result binding is established")
                .point;
            let target_call = call_handle_spelled(
                &procedure,
                GO_BRANCH_LOCAL_TARGET_BEFORE_NON_REJOINING_GAP,
                call,
            );
            let target = semantics
                .call_site(target_call.id())
                .expect("the branch-local observer call resolves")
                .point;
            let selector_point = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Read
                        && spelling(GO_BRANCH_LOCAL_TARGET_BEFORE_NON_REJOINING_GAP, event)
                            == selector
                })
                .expect("the result selector publishes a read")
                .point;
            let gap = semantics
                .gaps()
                .iter()
                .find(|gap| {
                    gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
                        && gap.detail.as_ref() == "selection may panic on a nil operand"
                        && gap.point == selector_point
                })
                .expect("the later selector publishes its non-rejoining gap");
            let guard = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                    )
                })
                .expect("the error comparison publishes a normalized guard");
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null-comparison guard")
            };
            let failure_edge = if null_on_true {
                guard.false_edge
            } else {
                guard.true_edge
            }
            .expect("the non-nil error arm has a control edge");
            let failure_handle = procedure
                .control_edge_handle(failure_edge)
                .expect("the failure edge has a scoped handle");
            let failure_target = semantics
                .control_edge(failure_edge)
                .expect("the failure edge resolves")
                .target_point;
            let reachable_without_failure =
                reachable_points_without_edge(semantics, semantics.entry_point(), failure_edge);

            assert!(
                derivation
                    .dominance
                    .as_ref()
                    .expect("the CFG algorithm completed")
                    .dominates(semantics, failure_target, target)
                    && !reachable_without_failure.contains(&target),
                "the exact failure edge must dominate its branch-local observer"
            );
            assert!(
                reachable_without_failure.contains(&gap.point),
                "the success branch bypasses the observer and rejoins before the later selector"
            );
            assert!(
                point_reaches(semantics, target, gap.point, false),
                "the observer's normal path reaches the later selector"
            );
            assert_eq!(
                point_reaches(semantics, gap.point, target, false),
                expected.is_none(),
                "only the looped case has a reverse path from the gap to the earlier target"
            );
            let gap_anchored_cache =
                strictly_later_non_rejoining_gap_pairs(semantics, &[target, gap.point], &[gap]);
            assert_eq!(
                gap_anchored_cache.contains(&(target, gap.point)),
                expected.is_some(),
                "the batched reverse/forward walks preserve strict acyclic order"
            );
            assert!(
                !gap_anchored_cache.contains(&(gap.point, gap.point)),
                "a gap is never strictly later than itself"
            );

            let answer = derivation.any_guard_arm_dominates_result_uses(
                &procedure,
                &[establishment],
                std::slice::from_ref(&failure_handle),
                &[target],
            );
            match expected {
                Some(_) => assert_eq!(
                    answer.as_deref(),
                    Some([GuardDominanceAnswer::Proven].as_slice()),
                    "a later non-rejoining alternative that cannot reach the use cannot bypass its guard"
                ),
                None => assert_eq!(
                    answer.as_deref(),
                    Some([GuardDominanceAnswer::Open].as_slice()),
                    "a gap in the observer's cycle must remain blocking"
                ),
            }
            assert_eq!(
                derivation
                    .any_guard_arm_dominates_result_uses(
                        &procedure,
                        &[establishment],
                        &[failure_handle],
                        &[gap.point],
                    )
                    .as_deref(),
                Some([GuardDominanceAnswer::ClosedNegative].as_slice()),
                "the branch-local failure edge must not guard the joined selector itself"
            );
        }
    }

    const GO_NEGATIVE_GUARD_SIBLING_GAPS: &str = r#"
package sample

type item struct {
    siblingValue, siblingOppositeValue, predecessorValue, cyclicValue, openValue int
    siblingGap, predecessorGap, cyclicGap, openGap int
}

func cleanup() {}

func acyclicSibling(result *item, err error, other *item) int {
    exact := result
    if err == nil {
        _ = other.siblingGap
        return exact.siblingOppositeValue
    }
    return exact.siblingValue
}

func predecessor(result *item, err error, other *item) int {
    exact := result
    _ = other.predecessorGap
    if err == nil {
        return 0
    }
    return exact.predecessorValue
}

func cyclic(result *item, err error, other *item) {
    exact := result
    for {
        if err == nil {
            _ = other.cyclicGap
            continue
        }
        _ = exact.cyclicValue
    }
}

func openSibling(result *item, err error, other *item) int {
    exact := result
    if err == nil {
        defer cleanup()
        _ = other.openGap
        return 0
    }
    return exact.openValue
}
"#;

    #[test]
    fn positive_and_negative_guard_proofs_apply_their_distinct_completion_contracts() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_NEGATIVE_GUARD_SIBLING_GAPS)]);
        let state = fixture.state(0);

        for (
            target_spelling,
            gap_spelling,
            gap_discharge,
            gap_reaches_target,
            target_reaches_gap,
            expected_positive,
            expected_negative,
        ) in [
            (
                "exact.siblingValue",
                "other.siblingGap",
                SemanticGapDischarge::NonRejoiningExceptionalExit,
                false,
                false,
                true,
                true,
            ),
            (
                "exact.predecessorValue",
                "other.predecessorGap",
                SemanticGapDischarge::NonRejoiningExceptionalExit,
                true,
                false,
                false,
                false,
            ),
            (
                "exact.cyclicValue",
                "other.cyclicGap",
                SemanticGapDischarge::NonRejoiningExceptionalExit,
                true,
                true,
                false,
                false,
            ),
            (
                "exact.openValue",
                "other.openGap",
                SemanticGapDischarge::ExitOnlyProcedureCompletion,
                false,
                false,
                true,
                false,
            ),
        ] {
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_NEGATIVE_GUARD_SIBLING_GAPS, event) == target_spelling
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let point_for = |needle: &str, event_class: StateEventClass| {
                derivation
                    .events
                    .iter()
                    .find(|event| {
                        event.event_class == event_class
                            && spelling(GO_NEGATIVE_GUARD_SIBLING_GAPS, event) == needle
                    })
                    .unwrap_or_else(|| panic!("{needle} publishes a {event_class:?} event"))
                    .point
            };
            let establishment = point_for("exact := result", StateEventClass::Establish);
            let target = point_for(target_spelling, StateEventClass::Read);
            let gap_point = point_for(gap_spelling, StateEventClass::Read);
            let gap = semantics
                .gaps()
                .iter()
                .find(|gap| {
                    gap.point == gap_point
                        && gap.discharge == gap_discharge
                        && gap.detail.as_ref() == "selection may panic on a nil operand"
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{gap_spelling} publishes its expected control gap: {:#?}",
                        semantics.gaps()
                    )
                });
            let guard = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                    )
                })
                .expect("the error comparison publishes a normalized guard");
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null-comparison guard")
            };
            let negative_edge = if null_on_true {
                guard.false_edge
            } else {
                guard.true_edge
            }
            .expect("the non-nil negative arm has a control edge");
            let negative_handle = procedure
                .control_edge_handle(negative_edge)
                .expect("the negative edge has a scoped handle");
            let negative_target = semantics
                .control_edge(negative_edge)
                .expect("the negative edge resolves")
                .target_point;
            let reachable_without_negative =
                reachable_points_without_edge(semantics, semantics.entry_point(), negative_edge);

            assert!(
                derivation
                    .dominance
                    .as_ref()
                    .expect("the CFG algorithm completed")
                    .dominates(semantics, negative_target, target)
                    && !reachable_without_negative.contains(&target),
                "the exact negative edge must dominate {target_spelling}"
            );
            assert!(
                reachable_without_negative.contains(&gap.point),
                "{gap_spelling} must remain reachable without the negative edge"
            );
            assert_eq!(
                point_reaches(semantics, gap.point, target, false),
                gap_reaches_target,
                "the retained gap-to-use reachability distinguishes the sibling exception"
            );
            assert_eq!(
                point_reaches(semantics, target, gap.point, false),
                target_reaches_gap,
                "only the cyclic case lets the use revisit the gap"
            );
            let positive = derivation.any_guard_arm_dominates_result_uses(
                &procedure,
                &[establishment],
                std::slice::from_ref(&negative_handle),
                &[target],
            );
            if expected_positive {
                assert_eq!(
                    positive.as_deref(),
                    Some([GuardDominanceAnswer::Proven].as_slice()),
                    "the producer-authored completion sibling cannot bypass {target_spelling}"
                );
            } else {
                assert_eq!(
                    positive.as_deref(),
                    Some([GuardDominanceAnswer::Open].as_slice()),
                    "the predecessor, cyclic, and open gaps must keep {target_spelling} blocking"
                );
            }
            assert_eq!(
                derivation
                    .any_guard_arm_confines_result_uses_for_negative_evidence(
                        &procedure,
                        &[establishment],
                        std::slice::from_ref(&negative_handle),
                        &[target],
                    )
                    .as_deref(),
                Some([expected_negative].as_slice()),
                "only the non-rejoining sibling can be ignored for negative evidence"
            );
            if target_spelling == "exact.siblingValue" {
                let opposite_target =
                    point_for("exact.siblingOppositeValue", StateEventClass::Read);
                assert_eq!(
                    derivation
                        .any_guard_arm_confines_result_uses_for_negative_evidence(
                            &procedure,
                            &[establishment],
                            &[negative_handle],
                            &[target, opposite_target],
                        )
                        .as_deref(),
                    Some([true, false].as_slice()),
                    "batched negative answers stay aligned to each supplied use"
                );
            }
        }
    }

    const GO_TARGET_RELATIVE_CANDIDATE_CONFINEMENT: &str = r#"
package sample

type item struct {
    acyclicBefore, acyclicAfter int
    cyclicBefore, cyclicAfter int
}

func inspectAcyclic(err error) {}
func inspectCyclic(err error) {}
func cleanup() {}

func acyclic(result *item, err error) {
    exact := result
    if err != nil {
        inspectAcyclic(err)
    }
    _ = exact.acyclicBefore
    defer cleanup()
    _ = exact.acyclicAfter
}

func cyclic(result *item, err error) {
    exact := result
    if err != nil {
        inspectCyclic(err)
    }
    for {
        _ = exact.cyclicBefore
        defer cleanup()
        _ = exact.cyclicAfter
    }
}
"#;

    #[test]
    #[hardwon(
        "fef1c7e37792: result proof must scope exceptional gaps to each exact use without ignoring cycles"
    )]
    fn candidate_confinement_ignores_only_acyclic_gaps_after_each_result_use() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_TARGET_RELATIVE_CANDIDATE_CONFINEMENT)],
        );
        let state = fixture.state(0);

        for (
            before,
            after,
            observer,
            gap_detail,
            gap_discharge,
            expected_positive,
            expected,
            gap_reaches_before,
        ) in [
            (
                "exact.acyclicBefore",
                "exact.acyclicAfter",
                "inspectAcyclic(err)",
                "selection may panic on a nil operand",
                SemanticGapDischarge::ExitOnlyProcedureCompletion,
                GuardDominanceAnswer::Proven,
                [true, false],
                false,
            ),
            (
                "exact.cyclicBefore",
                "exact.cyclicAfter",
                "inspectCyclic(err)",
                "defer registration inside a loop has unbounded per-iteration captures and is not lowered",
                SemanticGapDischarge::ExitOnlyProcedureCompletion,
                GuardDominanceAnswer::Proven,
                [false, false],
                true,
            ),
        ] {
            let derivation = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_TARGET_RELATIVE_CANDIDATE_CONFINEMENT, event) == before
            });
            let procedure = fixture.procedure(0, derivation.procedure);
            let semantics = procedure.semantics();
            let establishment = derivation
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(GO_TARGET_RELATIVE_CANDIDATE_CONFINEMENT, event)
                            == "exact := result"
                })
                .expect("the exact result binding is established")
                .point;
            let use_points = [before, after].map(|selector| {
                derivation
                    .events
                    .iter()
                    .find(|event| {
                        event.event_class == StateEventClass::Read
                            && spelling(GO_TARGET_RELATIVE_CANDIDATE_CONFINEMENT, event) == selector
                    })
                    .unwrap_or_else(|| panic!("the {selector} read is retained"))
                    .point
            });
            let candidate = call_handle_spelled(
                &procedure,
                GO_TARGET_RELATIVE_CANDIDATE_CONFINEMENT,
                observer,
            );
            let candidate_point = semantics
                .call_site(candidate.id())
                .expect("the observer call resolves")
                .point;
            let open_gap = semantics
                .gaps()
                .iter()
                .find(|gap| gap.discharge == gap_discharge && gap.detail.as_ref() == gap_detail)
                .unwrap_or_else(|| {
                    panic!(
                        "the active defer keeps {after}'s control path open: {:#?}",
                        semantics.gaps()
                    )
                });
            assert_ne!(open_gap.subject, SemanticGapSubject::Procedure);
            assert_eq!(
                point_reaches(semantics, open_gap.point, use_points[0], false),
                gap_reaches_before,
                "only the loop can revisit the earlier static use after the gap"
            );

            let guard = semantics
                .guard_facts()
                .iter()
                .find(|guard| {
                    matches!(
                        guard.predicate,
                        crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                    )
                })
                .expect("the error comparison publishes a normalized guard");
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null-comparison guard")
            };
            let failure_edge = if null_on_true {
                guard.false_edge
            } else {
                guard.true_edge
            }
            .expect("the non-nil error arm has a control edge");
            let failure_handle = procedure
                .control_edge_handle(failure_edge)
                .expect("the failure edge has a scoped handle");

            assert_eq!(
                derivation
                    .any_guard_arm_dominates_result_uses(
                        &procedure,
                        &[establishment],
                        std::slice::from_ref(&failure_handle),
                        &[candidate_point],
                    )
                    .as_deref(),
                Some([expected_positive].as_slice()),
                "only result-specific positive dominance may localize exit-only completion"
            );
            assert_eq!(
                derivation
                    .any_guard_arm_confines_candidate_for_result_uses(
                        &procedure,
                        &[establishment],
                        &[failure_handle],
                        candidate_point,
                        &use_points,
                    )
                    .as_deref(),
                Some(expected.as_slice()),
                "only an acyclic earlier use can exclude the branch-local candidate"
            );
        }
    }

    const GO_PROJECTED_NONRETURN: &str = r#"
package sample

import "os"

type item struct { value int }

func inspect(result *item, err error) int {
    exact := result
    if err != nil {
        os.Exit(1)
    }
    return exact.value
}
"#;

    const GO_NONRETURN_DECLARATIONS: &str = r#"{
  "schema_version": 2,
  "pack_id": "test.flow.go-os-exit-declarations",
  "version": "1.0.0",
  "producer": { "name": "bifrost-flow-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test:flow-os-exit-declarations", "revision": "reviewed" },
  "license": "Apache-2.0",
  "completeness": "partial",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "go.os.exit.declarations",
    "activation": [{}],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "type.flow-test-go-os-module",
        "name": "os",
        "type_kind": "module",
        "visibility": "package",
        "is_abstract": false,
        "is_sealed": false,
        "has_explicit_type_terms": false,
        "type_parameters": [],
        "type_parameter_constraints": [],
        "embedded_types": [],
        "hierarchy": [],
        "aliases": ["os"],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "os/types.go",
          "symbol": "os"
        }
      }],
      "members": [{
        "id": "member.flow-test-go-os-exit",
        "owner": "type.flow-test-go-os-module",
        "name": "Exit",
        "member_kind": "function",
        "visibility": "public",
        "is_static": true,
        "is_abstract": false,
        "is_virtual": false,
        "signature": {
          "type_parameters": [],
          "parameters": [{
            "name": "code",
            "type": {
              "kind": "named",
              "name": "int",
              "arguments": [],
              "nullable": false
            },
            "optional": false,
            "variadic": false
          }]
        },
        "aliases": [],
        "locator": {
          "kind": "artifact",
          "path": "os/proc.go",
          "symbol": "os.Exit"
        }
      }],
      "relations": []
    }
  }]
}"#;

    const GO_NONRETURN_MODEL: &str = r#"{
  "schema_version": 2,
  "pack_id": "test.flow.go-nonreturn",
  "version": "1.0.0",
  "producer": { "name": "bifrost-flow-test", "version": "1.0.0" },
  "language": "go",
  "ecosystem": "go",
  "compatibility": { "bifrost": ">=0.10.5, <1.0.0", "toolchains": [] },
  "provenance": { "source": "test:flow-nonreturn", "revision": "reviewed" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "go.os.exit",
    "activation": [{}],
    "payload": {
      "kind": "procedure_summaries",
      "summaries": [{
        "id": "os.exit",
        "target": {
          "path": "src/os/proc.go",
          "symbol": "os.Exit(code int)",
          "has_receiver": false,
          "parameter_count": 1
        },
        "completeness": "complete",
        "normal_continuation_absent": true,
        "transfers": [],
        "effects": []
      }]
    }
  }]
}"#;

    const GO_AUTOMATIC_NONRETURN: &str = r#"
package sample

import "os"

type item struct { value int }
type terminator struct{}

func Exit(code int) {}
func (terminator) Exit(code int) {}
func cleanupProbe() {}

func modeled(result *item, err error) int {
    exact := result
    if err != nil {
        os.Exit(1)
    }
    return exact.value
}

func workspace(result *item, err error) int {
    local := result
    if err != nil {
        Exit(1)
    }
    return local.value
}

func member(result *item, err error, stop terminator) int {
    bound := result
    if err != nil {
        stop.Exit(1)
    }
    return bound.value
}

func spawned(result *item) int {
    spawnedResult := result
    go os.Exit(1)
    return spawnedResult.value
}

func deferred(result *item) int {
    deferredResult := result
    defer os.Exit(1)
    return deferredResult.value
}

func multiCleanup(result *item) int {
    cleanupResult := result
    defer os.Exit(1)
    cleanupProbe()
    return cleanupResult.value
}
"#;

    #[test]
    fn active_nonreturn_models_project_only_exact_external_normal_edges() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_AUTOMATIC_NONRETURN)]);
        let raw = fixture.state(0);
        let empty_fixture = Fixture::new(Language::Go, &[("main.go", GO_AUTOMATIC_NONRETURN)]);
        let empty_models = empty_fixture.activate_empty_models();
        let empty_modeled = empty_fixture.state_with_active_models(0, &empty_models);
        let models = fixture.activate_exact_nonreturn_models();
        let projected = fixture.state_with_active_models(0, &models);
        assert_eq!(raw.active_model_set_hash(), None);
        assert_eq!(
            empty_modeled.active_model_set_hash(),
            Some(empty_models.active_models().active_model_set_hash()),
            "an activated empty set remains distinct from no model snapshot"
        );
        assert!(
            empty_modeled
                .procedures
                .iter()
                .all(|procedure| procedure.control_edge_mask.is_empty()),
            "the no-claim fast path preserves every source edge"
        );
        assert_eq!(
            projected.active_model_set_hash(),
            Some(models.active_models().active_model_set_hash()),
            "the derived state retains the exact request model identity"
        );

        for (read, call, expected_omitted) in [
            ("exact.value", "os.Exit(1)", true),
            ("local.value", "Exit(1)", false),
            ("bound.value", "stop.Exit(1)", false),
            ("deferredResult.value", "os.Exit(1)", true),
        ] {
            let raw_derivation = procedure_containing(&raw, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_AUTOMATIC_NONRETURN, event) == read
            });
            let projected_derivation = procedure_containing(&projected, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_AUTOMATIC_NONRETURN, event) == read
            });
            let procedure = fixture.procedure(0, raw_derivation.procedure);
            let call = call_handle_spelled(&procedure, GO_AUTOMATIC_NONRETURN, call);
            let normal_edge = normal_edge_for_call(&procedure, &call);
            assert_eq!(
                projected_derivation
                    .control_edge_mask
                    .omitted
                    .contains(&normal_edge),
                expected_omitted,
                "only the exact unmaterialized os.Exit target may consume normal control"
            );
            assert!(
                !projected_derivation
                    .completeness
                    .reasons()
                    .iter()
                    .any(|reason| matches!(
                        reason,
                        FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
                    )),
                "conclusive workspace and bound-receiver near misses stay complete"
            );
        }

        let raw_cleanup = procedure_containing(&raw, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_AUTOMATIC_NONRETURN, event) == "cleanupResult.value"
        });
        let projected_cleanup = procedure_containing(&projected, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_AUTOMATIC_NONRETURN, event) == "cleanupResult.value"
        });
        let cleanup_procedure = fixture.procedure(0, raw_cleanup.procedure);
        let cleanup_calls =
            call_handles_spelled(&cleanup_procedure, GO_AUTOMATIC_NONRETURN, "os.Exit(1)");
        assert_eq!(
            cleanup_calls.len(),
            2,
            "normal and exceptional completion routes specialize the same deferred source call"
        );
        let cleanup_normal_edges = cleanup_calls
            .iter()
            .map(|call| normal_edge_for_call(&cleanup_procedure, call))
            .collect::<HashSet<_>>();
        assert_eq!(cleanup_normal_edges.len(), 2);
        assert!(raw_cleanup.control_edge_mask.is_empty());
        assert_eq!(
            projected_cleanup.control_edge_mask.omitted, cleanup_normal_edges,
            "every exact cleanup specialization of the modeled defer loses its normal edge"
        );
        assert!(
            !projected_cleanup
                .completeness
                .reasons()
                .iter()
                .any(|reason| matches!(
                    reason,
                    FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
                )),
            "multiple exact semantic calls for one defer span remain conclusive"
        );

        let spawned = procedure_containing(&projected, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_AUTOMATIC_NONRETURN, event) == "spawnedResult.value"
        });
        let spawned_procedure = fixture.procedure(0, spawned.procedure);
        let spawned_calls =
            call_handles_spelled(&spawned_procedure, GO_AUTOMATIC_NONRETURN, "os.Exit(1)");
        let [spawned_call] = spawned_calls.as_slice() else {
            panic!("the spawned outer call must lower exactly once: {spawned_calls:#?}");
        };
        let semantic_call = spawned_procedure
            .semantics()
            .call_site(spawned_call.id())
            .expect("the spawned procedure owns its call");
        assert_eq!(semantic_call.invocation_mode, CallInvocationMode::Detached);
        assert_eq!(
            semantic_call.execution_timing,
            ExecutionTiming::DifferentTask
        );
        assert!(semantic_call.normal_results.is_empty());
        assert!(semantic_call.result.is_none());
        assert!(semantic_call.thrown.is_none());
        assert!(semantic_call.normal_continuation.target().is_some());
        assert_eq!(
            semantic_call.exceptional_continuation,
            ControlContinuation::Absent
        );
        let spawned_normal_edge = normal_edge_for_call(&spawned_procedure, spawned_call);
        assert!(
            spawned.control_edge_mask.is_empty(),
            "a spawned target cannot make its parent's registration edge non-returning"
        );
        assert!(
            !spawned
                .control_edge_mask
                .omitted
                .contains(&spawned_normal_edge)
        );
        assert!(
            !spawned.completeness.reasons().iter().any(|reason| matches!(
                reason,
                FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
            )),
            "a detached call is inapplicable to synchronous control projection and must not poison the file"
        );
    }

    const GO_WORKSPACE_NONRETURN_CALLERS: &str = r#"
package sample

type wrappedItem struct { value int }

func throughDirect(result *wrappedItem, err error) int {
    direct := result
    if err != nil {
        die()
    }
    return direct.value
}

func throughTwoHop(result *wrappedItem, err error) int {
    twoHop := result
    if err != nil {
        dieTwice()
    }
    return twoHop.value
}

func throughConditional(result *wrappedItem, err error) int {
    conditional := result
    if err != nil {
        conditionalDie(err != nil)
    }
    return conditional.value
}

func throughReturning(result *wrappedItem, err error) int {
    returning := result
    if err != nil {
        returns()
    }
    return returning.value
}

func throughFunctionValue(result *wrappedItem, err error, fn func()) int {
    functionValue := result
    if err != nil {
        callFunction(fn)
    }
    return functionValue.value
}

func throughRecursion(result *wrappedItem, err error) int {
    recursive := result
    if err != nil {
        recurse()
    }
    return recursive.value
}

func throughSpawn(result *wrappedItem, err error) int {
    spawned := result
    if err != nil {
        spawnedDie()
    }
    return spawned.value
}
"#;

    const GO_WORKSPACE_NONRETURN_HELPERS: &str = r#"
package sample

import "os"

func die() {
    os.Exit(1)
}

func dieTwice() {
    die()
}

func conditionalDie(stop bool) {
    if stop {
        os.Exit(1)
    }
}

func returns() {}

func callFunction(fn func()) {
    fn()
}

func recurse() {
    recurse()
}

func spawnedDie() {
    go die()
}
"#;

    #[test]
    fn workspace_nonreturn_fixed_point_projects_only_proved_root_file_calls() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("main.go", GO_WORKSPACE_NONRETURN_CALLERS),
                ("helper.go", GO_WORKSPACE_NONRETURN_HELPERS),
            ],
        );
        let raw = fixture.state(0);
        let models = fixture.activate_exact_nonreturn_models();
        let projected = fixture.state_with_active_models(0, &models);

        for (read, call, expected_omitted) in [
            ("direct.value", "die()", true),
            ("twoHop.value", "dieTwice()", true),
            ("conditional.value", "conditionalDie(err != nil)", false),
            ("returning.value", "returns()", false),
            ("functionValue.value", "callFunction(fn)", false),
            ("recursive.value", "recurse()", true),
            ("spawned.value", "spawnedDie()", false),
        ] {
            let raw_derivation = procedure_containing(&raw, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_WORKSPACE_NONRETURN_CALLERS, event) == read
            });
            let projected_derivation = procedure_containing(&projected, |event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_WORKSPACE_NONRETURN_CALLERS, event) == read
            });
            let procedure = fixture.procedure(0, raw_derivation.procedure);
            let call = call_handle_spelled(&procedure, GO_WORKSPACE_NONRETURN_CALLERS, call);
            let normal_edge = normal_edge_for_call(&procedure, &call);
            assert_eq!(
                projected_derivation
                    .control_edge_mask
                    .omitted
                    .contains(&normal_edge),
                expected_omitted,
                "only exhaustive workspace chains rooted in the modeled external terminator may consume the root-file edge: read={read}, completeness={:?}",
                projected_derivation.completeness
            );
        }
    }

    #[test]
    fn source_continuation_projection_preserves_returning_paths_and_interruptions() {
        const SOURCE: &str = r#"package sample
func never() { for {} }
func returns() {}
func dead() { never(); value := 1; _ = value }
func live() { returns(); value := 1; _ = value }
func cycle() { cycle() }
func first() { second() }
func second() { first() }
func recursiveReturns(stop bool) { if stop { return }; recursiveReturns(stop) }
func deadCycle() { cycle(); value := 1; _ = value }
func deadMutual() { first(); value := 1; _ = value }
func liveCycle(stop bool) { recursiveReturns(stop); value := 1; _ = value }
func baseFirst(stop bool) { baseSecond(stop) }
func baseSecond(stop bool) { if stop { return }; baseFirst(stop) }
func liveMutual(stop bool) { baseFirst(stop); value := 1; _ = value }
"#;
        let fixture = Fixture::new(Language::Go, &[("main.go", SOURCE)]);
        let artifact = fixture.materialized(0).available_value().cloned().unwrap();
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        let cancellation = CancellationToken::default();
        for (name, call_spelling, absent) in [
            ("dead", "never()", true),
            ("live", "returns()", false),
            ("deadCycle", "cycle()", true),
            ("deadMutual", "first()", true),
            ("liveCycle", "recursiveReturns(stop)", false),
            ("liveMutual", "baseFirst(stop)", false),
        ] {
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap();
            let call = call_handle_spelled(&procedure, SOURCE, call_spelling);
            let normal_edge = normal_edge_for_call(&procedure, &call);
            let projection = procedure_continuation_projection(
                &provider,
                &procedure,
                &mut SemanticBudget::default(),
                &mut CfgAlgorithmBudget::default(),
                &cancellation,
            );
            assert_eq!(projection.procedure, procedure);
            assert_eq!(
                projection.mask.omitted.contains(&normal_edge),
                absent,
                "source-only call completion for {name}: {projection:?}"
            );
            assert!(projection.reasons.is_empty(), "{projection:?}");
            let graph = projection.graph();
            let reachable = forward_reachability(
                &graph,
                procedure.semantics().entry_point(),
                &mut CfgAlgorithmRequest::new(&mut CfgAlgorithmBudget::default(), &cancellation),
            )
            .unwrap();
            assert_eq!(
                reachable.contains(&graph, procedure.semantics().normal_exit_point()),
                !absent,
                "projected reachability must agree with normal completion in {name}"
            );
            let dominance = dominators(
                &graph,
                procedure.semantics().entry_point(),
                &mut CfgAlgorithmRequest::new(&mut CfgAlgorithmBudget::default(), &cancellation),
            )
            .unwrap();
            assert_eq!(
                dominance.dominates(
                    &graph,
                    procedure.semantics().entry_point(),
                    procedure.semantics().normal_exit_point()
                ),
                !absent,
                "dominance must use the same reachable control view in {name}"
            );
            let starved = procedure_continuation_projection(
                &provider,
                &procedure,
                &mut SemanticBudget::default(),
                &mut CfgAlgorithmBudget::uniform(0),
                &cancellation,
            );
            assert!(starved.mask.omitted.is_empty());
            assert!(
                !starved.reasons.is_empty(),
                "budget exhaustion must remain explicit"
            );
            let cancelled = CancellationToken::default();
            cancelled.cancel();
            let interrupted = procedure_continuation_projection(
                &provider,
                &procedure,
                &mut SemanticBudget::default(),
                &mut CfgAlgorithmBudget::default(),
                &cancelled,
            );
            assert!(interrupted.mask.omitted.is_empty());
            assert!(
                interrupted
                    .reasons
                    .contains(&FlowStateIncompleteReason::Cancelled)
            );
        }
    }

    #[test]
    #[hardwon(
        "#11234: nonreturn discovery replay dropped typed completion and retained operational fills"
    )]
    fn nonreturn_memo_completion_conformance() {
        use brokk_bifrost_analysis::analyzer::usages::common::{
            QueryMemoOwner, assert_memo_owner_conformance_for_test,
        };
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", "package sample\nfunc never(){ for {} }\n")],
        );
        let artifact = fixture.materialized(0).available_value().cloned().unwrap();
        let handle = artifact
            .procedure_handle(artifact.procedures()[0].id())
            .unwrap();
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        let cancellation = CancellationToken::new();
        assert_memo_owner_conformance_for_test(
            QueryMemoOwner::NonreturnDiscovery,
            fixture.workspace.analyzer(),
            NonreturnDiscoveryCache::default,
            |cache| {
                let derived = derive_nonreturn_projection(
                    &provider,
                    &artifact,
                    vec![handle.clone()],
                    &mut SemanticBudget::default(),
                    &mut CfgAlgorithmBudget::default(),
                    &cancellation,
                    Some(cache),
                );
                let projection =
                    continuation_projection_from_derivation(&handle, derived, &cancellation);
                (
                    projection.normal_return_absent,
                    format!("{:?}", projection.reasons),
                )
            },
            |cache| !cache.entries.lock().unwrap().is_empty(),
        );
    }

    #[test]
    #[hardwon("#9015: shared Go nonreturn callees were rediscovered for every root")]
    fn shared_nonreturn_callee_across_go_roots() {
        const ROOTS: &str = "package sample\nfunc r0(){ shared() }\nfunc r1(){ shared() }\nfunc r2(){ shared() }\nfunc r3(){ shared() }\nfunc r4(){ shared() }\nfunc r5(){ shared() }\nfunc r6(){ shared() }\nfunc r7(){ shared() }\n";
        const HELPER: &str = "package sample\nfunc shared(){ deep() }\nfunc deep(){ for {} }\n";
        let fixture = Fixture::new(Language::Go, &[("roots.go", ROOTS), ("helper.go", HELPER)]);
        let artifact = fixture.materialized(0).available_value().cloned().unwrap();
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        let cancellation = CancellationToken::default();
        let cache = NonreturnDiscoveryCache::default();
        for procedure in artifact.procedures() {
            let handle = artifact.procedure_handle(procedure.id()).unwrap();
            let derived = derive_nonreturn_projection(
                &provider,
                &artifact,
                vec![handle.clone()],
                &mut SemanticBudget::default(),
                &mut CfgAlgorithmBudget::default(),
                &cancellation,
                Some(&cache),
            );
            let projection =
                continuation_projection_from_derivation(&handle, derived, &cancellation);
            assert!(projection.normal_return_absent, "{projection:?}");
            assert!(projection.reasons.is_empty(), "{projection:?}");
        }
    }

    #[test]
    fn invocation_continuation_specialization_keeps_other_calls_reachable() {
        const SOURCE: &str = r#"package sample
func never() { for {} }
func returns() {}
func invoke(helper func()) { helper() }
func detached(helper func()) { go helper() }
"#;
        let fixture = Fixture::new(Language::Go, &[("main.go", SOURCE)]);
        let artifact = fixture.materialized(0).available_value().cloned().unwrap();
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        let cancellation = CancellationToken::default();
        let projection = |name: &str| {
            let procedure = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap();
            procedure_continuation_projection(
                &provider,
                &procedure,
                &mut SemanticBudget::default(),
                &mut CfgAlgorithmBudget::default(),
                &cancellation,
            )
        };
        let base = projection("invoke");
        let never = projection("never");
        let returning = projection("returns");
        assert!(never.normal_return_is_absent());
        assert!(!returning.normal_return_is_absent());
        assert!(!base.normal_return_is_absent());
        let call = call_handle_spelled(base.procedure(), SOURCE, "helper()");
        let specialized = base
            .with_nonreturning_source_call(
                &call,
                &[&never],
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .unwrap()
            .expect("this invocation's exact helper never returns");
        let mut certified = specialized.clone();
        assert!(
            certified
                .certify_normal_return_absence(
                    std::slice::from_ref(&call),
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                )
                .unwrap()
        );
        assert!(certified.normal_return_is_absent());
        assert!(!specialized.normal_return_is_absent());
        let mut returning_context = base.clone();
        assert!(
            !returning_context
                .certify_normal_return_absence(
                    std::slice::from_ref(&call),
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                )
                .unwrap()
        );
        for (view, reaches_exit) in [(&specialized, false), (&base, true)] {
            let graph = view.graph();
            let reachable = forward_reachability(
                &graph,
                view.procedure().semantics().entry_point(),
                &mut CfgAlgorithmRequest::new(&mut CfgAlgorithmBudget::default(), &cancellation),
            )
            .unwrap();
            assert_eq!(
                reachable.contains(&graph, view.procedure().semantics().normal_exit_point()),
                reaches_exit
            );
        }
        for targets in [vec![&returning], vec![&never, &returning], Vec::new()] {
            assert!(
                base.with_nonreturning_source_call(
                    &call,
                    &targets,
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation)
                )
                .unwrap()
                .is_none(),
                "every target must carry a nonreturn proof"
            );
        }
        let detached = projection("detached");
        let spawn = call_handle_spelled(detached.procedure(), SOURCE, "helper()");
        assert!(
            detached
                .with_nonreturning_source_call(
                    &spawn,
                    &[&never],
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation)
                )
                .unwrap()
                .is_none(),
            "a detached callee does not remove its parent's continuation"
        );
        assert!(
            base.with_nonreturning_source_call(
                &call,
                &[&never],
                &mut SemanticRequest::new(&mut SemanticBudget::uniform(1).unwrap(), &cancellation)
            )
            .is_err(),
            "specialization must obey the outer work budget"
        );
    }

    #[test]
    fn workspace_nonreturn_cfg_exhaustion_retains_raw_edges_and_reports_incomplete() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("main.go", GO_WORKSPACE_NONRETURN_CALLERS),
                ("helper.go", GO_WORKSPACE_NONRETURN_HELPERS),
            ],
        );
        let models = fixture.activate_exact_nonreturn_models();
        let cancellation = CancellationToken::default();
        let mut request = test_request(&cancellation)
            .with_active_semantic_model_snapshot(Some(Arc::clone(&models)));
        request.cfg_budget = CfgAlgorithmBudget::uniform(0);
        let starved = flow_state_for_file(&fixture.workspace, &fixture.files[0], &mut request);
        let direct = procedure_containing(&starved, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_WORKSPACE_NONRETURN_CALLERS, event) == "direct.value"
        });
        let procedure = fixture.procedure(0, direct.procedure);
        let call = call_handle_spelled(&procedure, GO_WORKSPACE_NONRETURN_CALLERS, "die()");
        let normal_edge = normal_edge_for_call(&procedure, &call);

        assert!(
            !direct.control_edge_mask.omitted.contains(&normal_edge),
            "an exhausted optional workspace proof must preserve the raw call edge"
        );
        assert!(
            direct.completeness.reasons().iter().any(|reason| {
                matches!(
                    reason,
                    FlowStateIncompleteReason::ModeledControlProjectionIncomplete { detail }
                        if detail.contains("workspace non-return entry reachability")
                            && detail.contains("CFG limit 0")
                )
            }),
            "the affected root procedure must report the solver's CFG exhaustion: {:?}",
            direct.completeness
        );
    }

    #[test]
    fn incomplete_nonreturn_lookup_classification_is_fail_closed_and_selective() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_AUTOMATIC_NONRETURN)]);
        let models = fixture.activate_models(GO_NONRETURN_MODEL);
        let facts = structural_facts(fixture.workspace.analyzer(), &fixture.files[0])
            .expect("the Go fixture publishes structural facts");
        let shapes = call_shapes_in_file(&facts, &fixture.files[0], facts.nodes().len());
        let shape = shapes
            .iter()
            .find(|shape| {
                &GO_AUTOMATIC_NONRETURN
                    [shape.outcome.range.start_byte..shape.outcome.range.end_byte]
                    == "os.Exit(1)"
            })
            .expect("the fixture publishes the os.Exit call shape");
        let active_models = models.active_models();

        let empty_lookup = |coverage, call_application| ModeledCallTargetLookup {
            arms: Vec::new(),
            call_application,
            coverage,
        };
        for coverage in [
            ModeledCallTargetCoverage::Open,
            ModeledCallTargetCoverage::Truncated,
            ModeledCallTargetCoverage::Unsupported,
            ModeledCallTargetCoverage::Cancelled,
        ] {
            assert!(
                incomplete_lookup_may_hide_nonreturn(
                    active_models,
                    shape,
                    &empty_lookup(coverage, ModeledCallApplication::PackageFunction),
                ),
                "an applicable receiverless lookup with {coverage:?} coverage is incomplete"
            );
            assert!(
                !incomplete_lookup_may_hide_nonreturn(
                    active_models,
                    shape,
                    &empty_lookup(coverage, ModeledCallApplication::BoundReceiver),
                ),
                "a receiverless model does not poison a known bound-receiver call"
            );
        }
        for coverage in [
            ModeledCallTargetCoverage::Exhaustive,
            ModeledCallTargetCoverage::Unmodeled,
        ] {
            assert!(!incomplete_lookup_may_hide_nonreturn(
                active_models,
                shape,
                &empty_lookup(coverage, ModeledCallApplication::PackageFunction),
            ));
        }

        let exact_key = ModeledProcedureKey {
            language: "go".to_owned(),
            owner: "os".to_owned(),
            member: "Exit".to_owned(),
            has_receiver: false,
            parameter_count: 1,
        };
        let arm_lookup = |origin, key| ModeledCallTargetLookup {
            arms: vec![crate::analyzer::usages::effects::ModeledCallTargetArm { key, origin }],
            call_application: ModeledCallApplication::PackageFunction,
            coverage: ModeledCallTargetCoverage::Open,
        };
        assert!(incomplete_lookup_may_hide_nonreturn(
            active_models,
            shape,
            &arm_lookup(
                ModeledCallTargetOrigin::UnmaterializedExternal,
                exact_key.clone(),
            ),
        ));
        assert!(!incomplete_lookup_may_hide_nonreturn(
            active_models,
            shape,
            &arm_lookup(ModeledCallTargetOrigin::WorkspaceBody, exact_key),
        ));
        assert!(!incomplete_lookup_may_hide_nonreturn(
            active_models,
            shape,
            &arm_lookup(
                ModeledCallTargetOrigin::UnmaterializedExternal,
                ModeledProcedureKey {
                    language: "go".to_owned(),
                    owner: "other".to_owned(),
                    member: "Exit".to_owned(),
                    has_receiver: false,
                    parameter_count: 1,
                },
            ),
        ));
    }

    #[test]
    fn conflicting_nonreturn_claims_do_not_enter_control_discovery() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_AUTOMATIC_NONRETURN)]);
        let mut nonreturn: serde_json::Value =
            serde_json::from_str(GO_NONRETURN_MODEL).expect("test model JSON");
        nonreturn["shards"][0]["payload"]["summaries"][0]["effects"] = serde_json::json!([{
            "kind": "unknown_call_boundary",
            "event": "test.flow.exit-boundary"
        }]);
        let mut returning = nonreturn.clone();
        returning["pack_id"] = serde_json::json!("test.flow.go-returning-conflict");
        returning["provenance"]["source"] = serde_json::json!("test:flow-returning-conflict");
        returning["shards"][0]["id"] = serde_json::json!("go.os.exit.returning");
        let summary = &mut returning["shards"][0]["payload"]["summaries"][0];
        summary["id"] = serde_json::json!("os.exit.returning");
        summary["normal_continuation_absent"] = serde_json::json!(false);
        let nonreturn = serde_json::to_string(&nonreturn).expect("test model renders");
        let returning = serde_json::to_string(&returning).expect("test model renders");
        let models = fixture.activate_model_sources(&[
            ("test:flow-nonreturn", &nonreturn),
            ("test:flow-returning", &returning),
        ]);
        assert!(
            !models.active_models().proves_normal_continuation_absent(
                ProcedureSummaryMemberKey::new("go", "os", "Exit", false, 1,)
            ),
            "disagreeing active packs must fail closed"
        );
        assert!(
            models
                .active_models()
                .normal_continuation_absence_candidate_owners("go", "Exit", false)
                .expect("a Go realm question is never open")
                .is_empty(),
            "only effective unique claims may trigger call-shape and dispatch work"
        );

        let facts = structural_facts(fixture.workspace.analyzer(), &fixture.files[0])
            .expect("the Go fixture publishes structural facts");
        let shapes = call_shapes_in_file(&facts, &fixture.files[0], facts.nodes().len());
        let shape = shapes
            .iter()
            .find(|shape| {
                &GO_AUTOMATIC_NONRETURN
                    [shape.outcome.range.start_byte..shape.outcome.range.end_byte]
                    == "os.Exit(1)"
            })
            .expect("the fixture publishes an os.Exit call shape");
        let interrupted = ModeledCallTargetLookup {
            arms: Vec::new(),
            call_application: ModeledCallApplication::PackageFunction,
            coverage: ModeledCallTargetCoverage::Cancelled,
        };
        assert!(
            !incomplete_lookup_may_hide_nonreturn(models.active_models(), shape, &interrupted,),
            "an interrupted lookup cannot hide a claim the runtime would never accept"
        );

        let state = fixture.state_with_active_models(0, &models);
        assert!(
            state.procedures.iter().all(|procedure| {
                procedure.control_edge_mask.is_empty()
                    && !procedure.completeness.reasons().iter().any(|reason| {
                        matches!(
                            reason,
                            FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
                        )
                    })
            }),
            "the empty effective inventory must preserve the raw fast path"
        );
    }

    #[test]
    fn projected_nonreturn_changes_rejoining_dominance_only_at_exact_edges() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_PROJECTED_NONRETURN)]);
        let raw = fixture.state(0);
        let inspect = procedure_containing(&raw, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_PROJECTED_NONRETURN, event) == "exact.value"
        });
        let inspect_procedure = fixture.procedure(0, inspect.procedure);
        let inspect_call =
            call_handle_spelled(&inspect_procedure, GO_PROJECTED_NONRETURN, "os.Exit(1)");
        let inspect_omitted = normal_edge_for_call(&inspect_procedure, &inspect_call);

        let projection = FlowControlProjection::new(
            inspect_procedure.artifact().key().clone(),
            [
                FlowControlEdgeOmission::new(inspect.procedure, inspect_omitted),
                FlowControlEdgeOmission::new(inspect.procedure, inspect_omitted),
            ],
        );
        assert_eq!(
            projection.omitted_normal_edges(),
            [FlowControlEdgeOmission::new(
                inspect.procedure,
                inspect_omitted
            )],
            "request identity is duplicate-free"
        );

        let projected = fixture.state_with_control_projection(0, &projection);
        let projected_inspect = procedure_containing(&projected, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_PROJECTED_NONRETURN, event) == "exact.value"
        });
        let semantics = inspect_procedure.semantics();
        let target = projected_inspect
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_PROJECTED_NONRETURN, event) == "exact.value"
            })
            .expect("the result is read after the branch")
            .point;
        let guard = semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .expect("the error comparison publishes a normalized guard");
        let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
            guard.predicate
        else {
            unreachable!("filtered to a null-comparison guard")
        };
        let success_edge = if null_on_true {
            guard.true_edge
        } else {
            guard.false_edge
        }
        .expect("the nil-error arm has a control edge");
        let success_handle = inspect_procedure
            .control_edge_handle(success_edge)
            .expect("the exact guard edge is scoped to the procedure");
        assert_eq!(
            inspect
                .any_guard_arm_dominates_targets(
                    &inspect_procedure,
                    std::slice::from_ref(&success_handle),
                    &[target],
                )
                .as_deref(),
            Some([false].as_slice()),
            "the raw error arm rejoins after os.Exit"
        );
        assert_eq!(
            projected_inspect
                .any_guard_arm_dominates_targets(
                    &inspect_procedure,
                    std::slice::from_ref(&success_handle),
                    &[target],
                )
                .as_deref(),
            Some([true].as_slice()),
            "removing the exact normal continuation makes the nil-error arm unavoidable"
        );

        let call_point = semantics
            .call_site(inspect_call.id())
            .expect("the exit call resolves")
            .point;
        assert!(
            inspect.point_reaches(semantics, call_point, target, false),
            "the raw call continuation rejoins at the result use"
        );
        assert!(
            !projected_inspect.point_reaches(semantics, call_point, target, false),
            "post-derivation reachability uses the retained mask"
        );
        assert_eq!(projected_inspect.control_edge_mask.omitted.len(), 1);
        assert!(
            projected_inspect
                .control_edge_mask
                .omitted
                .contains(&inspect_omitted)
        );
        let masked = ProjectedProcedureGraph::new(semantics, &projected_inspect.control_edge_mask);
        for (index, edge) in semantics.control_edges().iter().enumerate() {
            let edge_id = ControlEdgeId::try_from_index(index).expect("fixture edge index fits");
            let expected =
                (edge_id != inspect_omitted).then_some((edge.source_point, edge.target_point));
            assert_eq!(
                DenseBidirectionalGraph::edge_endpoints(&masked, edge_id),
                expected,
                "only the adjudicated normal edge may disappear"
            );
        }
    }

    #[test]
    fn control_projection_validation_is_atomic_and_rejects_stale_artifacts() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("main.go", GO_PROJECTED_NONRETURN),
                ("other.go", "package sample\nfunc unrelated() {}\n"),
            ],
        );
        let raw = fixture.state(0);
        let inspect = procedure_containing(&raw, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_PROJECTED_NONRETURN, event) == "exact.value"
        });
        let procedure = fixture.procedure(0, inspect.procedure);
        let call = call_handle_spelled(&procedure, GO_PROJECTED_NONRETURN, "os.Exit(1)");
        let valid = normal_edge_for_call(&procedure, &call);
        let non_normal = procedure
            .semantics()
            .control_edges()
            .iter()
            .enumerate()
            .find_map(|(index, edge)| {
                matches!(
                    edge.kind,
                    ControlEdgeKind::ConditionalTrue | ControlEdgeKind::ConditionalFalse
                )
                .then(|| ControlEdgeId::try_from_index(index).expect("fixture edge index fits"))
            })
            .expect("the if statement publishes a non-normal conditional edge");
        let mixed = FlowControlProjection::new(
            procedure.artifact().key().clone(),
            [
                FlowControlEdgeOmission::new(inspect.procedure, valid),
                FlowControlEdgeOmission::new(inspect.procedure, non_normal),
            ],
        );
        let rejected = fixture.state_with_control_projection(0, &mixed);
        let rejected_inspect = procedure_containing(&rejected, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_PROJECTED_NONRETURN, event) == "exact.value"
        });
        assert!(rejected_inspect.control_edge_mask.is_empty());
        assert_eq!(
            rejected_inspect.relations, inspect.relations,
            "one invalid row rejects every omission, including the valid one"
        );
        assert!(rejected.completeness.reasons().iter().any(|reason| {
            matches!(
                reason,
                FlowStateIncompleteReason::ControlProjectionRejected { detail }
                    if detail.contains("missing or non-normal")
            )
        }));
        assert!(
            rejected_inspect
                .completeness
                .reasons()
                .iter()
                .any(|reason| matches!(
                    reason,
                    FlowStateIncompleteReason::ControlProjectionRejected { .. }
                )),
            "the typed rejection blocks procedure-local control proofs too"
        );

        let unrelated = fixture
            .state(1)
            .procedures
            .first()
            .expect("the other file lowers a procedure")
            .procedure;
        let other_key = fixture.procedure(1, unrelated).artifact().key().clone();
        assert_ne!(&other_key, procedure.artifact().key());
        let stale = FlowControlProjection::new(
            other_key,
            [FlowControlEdgeOmission::new(inspect.procedure, valid)],
        );
        let stale_state = fixture.state_with_control_projection(0, &stale);
        let stale_inspect = procedure_containing(&stale_state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_PROJECTED_NONRETURN, event) == "exact.value"
        });
        assert!(stale_inspect.control_edge_mask.is_empty());
        assert!(stale_state.completeness.reasons().iter().any(|reason| {
            matches!(
                reason,
                FlowStateIncompleteReason::ControlProjectionRejected { detail }
                    if detail.contains("does not match materialized artifact")
            )
        }));
    }

    const GO_GUARD_AFTER_FIELD_RESULT_ASSIGNMENT: &str = r#"
package sample

type item struct{}
type holder struct { first, second *item }

func pair() (*item, error) { return nil, nil }

func store(target *holder) {
    var err error
    target.first, err = pair()
    if err != nil {
        return
    }
    target.second, err = pair()
    if err != nil {
        return
    }
}
"#;

    #[test]
    #[hardwon(
        "885be3d47b72: exact error-result identity must distinguish unrelated gaps from competing writes"
    )]
    fn guard_identity_ignores_nonrejoining_and_noncompeting_assignment_gaps() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_GUARD_AFTER_FIELD_RESULT_ASSIGNMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_GUARD_AFTER_FIELD_RESULT_ASSIGNMENT, event) == "err"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let mut guarded_establishments = semantics
            .guard_facts()
            .iter()
            .filter(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .map(|guard| {
                let guard_subject = guard.subject.expect("the nil guard has a subject");
                let guard_read = derivation
                    .events
                    .iter()
                    .find(|event| {
                        event.event_class == StateEventClass::Read && event.value == guard_subject
                    })
                    .expect("the guard reads the error binding");
                let establishment = derivation
                    .relations
                    .iter()
                    .find(|relation| {
                        relation.relation == FlowRelation::Reaching
                            && relation.certainty == FlowCertainty::Exact
                            && relation.target_event == guard_read.event
                    })
                    .map(|relation| derivation.event(relation.source_event))
                    .expect("one exact result establishment reaches the guard");
                (guard, guard_read, establishment)
            })
            .collect::<Vec<_>>();
        guarded_establishments
            .sort_unstable_by_key(|(_, _, establishment)| establishment.site.range.start_byte);
        let [first, second] = guarded_establishments.as_slice() else {
            panic!("two sequential error guards: {guarded_establishments:#?}");
        };

        for (guard, guard_read, establishment) in &guarded_establishments {
            let same_point_gaps = semantics
                .gaps()
                .iter()
                .filter(|gap| gap.point == establishment.point)
                .map(|gap| gap.discharge)
                .collect::<HashSet<_>>();
            assert!(
                same_point_gaps.contains(&SemanticGapDischarge::NonRejoiningExceptionalExit)
                    && same_point_gaps.contains(&SemanticGapDischarge::RetainedEvaluationOrder),
                "the field assignment retains both structured gaps: {:#?}",
                semantics.gaps()
            );
            let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
                guard.predicate
            else {
                unreachable!("filtered to a null comparison")
            };
            let success_edge = if null_on_true {
                guard.true_edge
            } else {
                guard.false_edge
            }
            .and_then(|edge| procedure.control_edge_handle(edge))
            .expect("the nil arm has a scoped edge");
            let relevant_values = [
                establishment.value,
                establishment.subject.value(),
                guard_read.value,
            ];

            assert!(
                derivation.guard_arm_preserves_result_identity(
                    &procedure,
                    &[establishment.point],
                    &relevant_values,
                    &success_edge,
                ),
                "same-point and overwritten prior gaps cannot select a different error value"
            );
        }

        let binding = first.2.subject.value();
        assert_eq!(second.2.subject.value(), binding);
        let relevant_values = std::iter::once(binding).collect::<HashSet<_>>();
        let assignment_gap = |establishment: &StateEventRow| {
            semantics
                .gaps()
                .iter()
                .find(|gap| {
                    if gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder {
                        return false;
                    }
                    let mapping = semantics
                        .source_mapping(gap.source)
                        .expect("a retained-order gap has a source mapping");
                    let span = mapping.locator.anchor().span();
                    span.start_byte() as usize == establishment.site.range.start_byte
                        && span.end_byte() as usize == establishment.site.range.end_byte
                })
                .expect("the field assignment has one retained-order gap")
        };
        assert!(
            !derivation.gap_contains_competing_binding_write(
                semantics,
                assignment_gap(first.2),
                &relevant_values,
                &[second.2.point],
            ),
            "an overwritten write in a prior gap cannot compete with the current result"
        );
        assert!(
            derivation.gap_contains_competing_binding_write(
                semantics,
                assignment_gap(second.2),
                &relevant_values,
                &[first.2.point],
            ),
            "a later retained-order write must remain a possible competitor"
        );
    }

    const GO_UNSPECIFIED_OPERAND_ORDER: &str = r#"
package sample

type item struct { value int }

func next() int { return 1 }
func combine(left, right int) int { return left + right }

func read(value *item) int {
    return combine(next(), value.value)
}
"#;

    #[test]
    fn arbitrary_call_continuations_cannot_discharge_retained_evaluation_order() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_UNSPECIFIED_OPERAND_ORDER)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let target = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value")
            })
            .expect("the selector publishes a property read")
            .point;
        let order_gap = semantics
            .gaps()
            .iter()
            .find(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder)
            .expect("the call records Go's unspecified operand order");
        let dominance = derivation
            .dominance
            .as_ref()
            .expect("the CFG algorithm completed");
        let candidate = semantics
            .points()
            .iter()
            .filter(|point| {
                point.events.iter().any(|event| {
                    matches!(
                        event.effect,
                        SemanticEffect::CallContinuation {
                            kind: crate::analyzer::semantic::CallContinuationKind::Normal,
                            ..
                        }
                    )
                })
            })
            .map(|point| point.id)
            .find(|point| dominance.dominates(semantics, *point, target))
            .expect("source-order topology places next() before the selector");
        assert!(
            !dominance.dominates(semantics, candidate, order_gap.point),
            "the call continuation occurs after the unresolved ordering boundary"
        );
        assert!(
            derivation
                .any_candidate_dominates_targets(&procedure, &[candidate], &[target])
                .is_none(),
            "an arbitrary retained point cannot turn one permitted Go operand order into a dominance proof"
        );
    }

    const GO_UNRELATED_WRITE_OUTSIDE_UNSPECIFIED_ORDER: &str = r#"
package sample

type item struct { value int }

func next() int { return 1 }
func combine(left, right int) int { return left + right }

func read(value *item, replacement *item) int {
    result := combine(next(), value.value)
    value = replacement
    return result
}
"#;

    #[test]
    #[hardwon(
        "237bb2bb831c: operand-order uncertainty must consider only writes inside the mapped call expression"
    )]
    fn retained_evaluation_order_checks_only_writes_inside_its_source_mapping() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_UNRELATED_WRITE_OUTSIDE_UNSPECIFIED_ORDER)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let order_gap = semantics
            .gaps()
            .iter()
            .find(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder)
            .expect("the call records Go's unspecified operand order");
        let reassignment = derivation
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.event_class,
                    StateEventClass::Establish | StateEventClass::Kill
                ) && spelling(GO_UNRELATED_WRITE_OUTSIDE_UNSPECIFIED_ORDER, event)
                    == "value = replacement"
            })
            .expect("the later parameter reassignment is represented");
        let relevant_values = std::iter::once(reassignment.subject.value()).collect::<HashSet<_>>();

        assert!(
            !derivation.gap_contains_competing_binding_write(
                semantics,
                order_gap,
                &relevant_values,
                &[],
            ),
            "a write after the call is not an operand-order ambiguity inside the call"
        );
    }

    const GO_RANGE_GUARD: &str = r#"
package sample

type item struct { value int }

func guardedRange(values []int, target *item) int {
    for range values {
        if target != nil {
            return target.value
        }
    }
    return 0
}
"#;

    #[test]
    fn validated_guard_arms_discharge_only_retained_range_topology() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_RANGE_GUARD)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let target = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value")
            })
            .expect("the guarded selector publishes a property read")
            .point;
        let range_gap = semantics
            .gaps()
            .iter()
            .find(|gap| gap.discharge == SemanticGapDischarge::RetainedControlTopology)
            .expect("the range keeps its explicit normal-control gap");
        assert_eq!(range_gap.capability, SemanticCapability::NormalControlFlow);
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::ReachingRelation)
                && !derivation
                    .completeness
                    .covers(FlowStateAxis::DominanceRelation),
            "the retained-topology marker must not certify global flow relations"
        );

        let guard = semantics
            .guard_facts()
            .iter()
            .find(|guard| {
                matches!(
                    guard.predicate,
                    crate::analyzer::semantic::GuardPredicate::NullComparison { .. }
                )
            })
            .expect("the nil comparison publishes a normalized guard");
        let crate::analyzer::semantic::GuardPredicate::NullComparison { null_on_true } =
            guard.predicate
        else {
            unreachable!("filtered to a null-comparison guard")
        };
        let success_edge = if null_on_true {
            guard.false_edge
        } else {
            guard.true_edge
        }
        .expect("the non-nil guard arm has a control edge");
        let success_handle = procedure
            .control_edge_handle(success_edge)
            .expect("the validated guard edge has a scoped handle");
        let success_target = semantics
            .control_edge(success_edge)
            .expect("the guard edge resolves")
            .target_point;
        assert!(
            derivation
                .any_candidate_dominates_targets(&procedure, &[success_target], &[target])
                .is_none(),
            "the generic point API must retain the range uncertainty"
        );
        assert_eq!(
            derivation
                .any_guard_arm_dominates_targets(&procedure, &[success_handle], &[target])
                .as_deref(),
            Some([true].as_slice()),
            "a validated success arm occurs after the range decision and before its guarded use"
        );

        let ordinary_edge = semantics
            .successor_edges(semantics.entry_point())
            .find(|(_, edge)| edge.kind == ControlEdgeKind::Normal)
            .map(|(id, _)| id)
            .expect("the procedure entry has its ordinary successor");
        let ordinary_handle = procedure
            .control_edge_handle(ordinary_edge)
            .expect("the ordinary edge has a scoped handle");
        assert!(
            derivation
                .any_guard_arm_dominates_targets(&procedure, &[ordinary_handle], &[target])
                .is_none(),
            "a non-conditional edge cannot impersonate normalized guard provenance"
        );
    }

    const TS_CONDITIONAL_ESTABLISHMENT: &str = r#"
function conditionalEstablishment(flag: boolean): number {
  const ns: { value?: number } = {};
  if (flag) {
    ns.value = 1;
  }
  return ns.value === undefined ? 0 : ns.value;
}
"#;

    /// A one-armed conditional write reaches the post-join read on some path
    /// and misses it on another, so the relation is `may` and no dominance row
    /// relates the two.
    #[test]
    fn a_one_armed_conditional_establishment_reaches_with_may_certainty() {
        let fixture = Fixture::new(
            Language::TypeScript,
            &[("src/main.ts", TS_CONDITIONAL_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let reaching = relation_spellings(
            TS_CONDITIONAL_ESTABLISHMENT,
            derivation,
            FlowRelation::Reaching,
        );
        let from_the_arm = reaching
            .iter()
            .filter(|(source, _, _)| *source == "ns.value = 1")
            .collect::<Vec<_>>();
        assert!(
            !from_the_arm.is_empty(),
            "the conditional write must reach the post-join read; got {reaching:?}"
        );
        assert!(
            from_the_arm
                .iter()
                .all(|(_, _, certainty)| *certainty == FlowCertainty::May),
            "a one-armed write can only be a may-reach; got {from_the_arm:?}"
        );

        let dominates = relation_spellings(
            TS_CONDITIONAL_ESTABLISHMENT,
            derivation,
            FlowRelation::Dominates,
        );
        assert!(
            !dominates
                .iter()
                .any(|(source, _, _)| *source == "ns.value = 1"),
            "a one-armed write dominates no post-join read; got {dominates:?}"
        );
    }

    const GO_MOD: &str = "module example.com/app\n\ngo 1.22\n";
    const GO_EXACT_LOCAL_VALUE_ALIASES: &str = r#"package app

import "os"

type holder struct { file *os.File }

func aliases(change bool, replacement *os.File) string {
    file, _ := os.Open("aliases.xlsx")
    alias := file
    copy := (alias)
    if change { copy = replacement }
    return copy.Name()
}

func nonLocal(target *os.File, value holder) {
    file, _ := os.Open("non-local.xlsx")
    target = file
    value.file = file
}
"#;

    #[test]
    fn exact_local_value_alias_closure_crosses_only_proven_local_copies() {
        let fixture = Fixture::new(
            Language::Go,
            &[("go.mod", GO_MOD), ("app.go", GO_EXACT_LOCAL_VALUE_ALIASES)],
        );
        let state = fixture.state(1);

        let aliases = procedure_containing(&state, |event| {
            spelling(GO_EXACT_LOCAL_VALUE_ALIASES, event) == "file, _ := os.Open(\"aliases.xlsx\")"
        });
        let aliases_procedure = fixture.procedure(1, aliases.procedure);
        let roots = aliases
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_EXACT_LOCAL_VALUE_ALIASES, event)
                        == "file, _ := os.Open(\"aliases.xlsx\")"
            })
            .map(|event| event.event)
            .collect::<Vec<_>>();
        assert_eq!(roots.len(), 1, "one protected result establishment");
        let closure = aliases.exact_local_value_alias_closure(&aliases_procedure, &roots);
        let establishments = closure
            .establishments
            .iter()
            .map(|event| spelling(GO_EXACT_LOCAL_VALUE_ALIASES, aliases.event(*event)))
            .collect::<HashSet<_>>();
        assert_eq!(
            establishments,
            [
                "file, _ := os.Open(\"aliases.xlsx\")",
                "alias := file",
                "copy := (alias)",
            ]
            .into_iter()
            .collect::<HashSet<_>>(),
            "direct and parenthesized local copies retain exact identity"
        );
        let alias_read = closure
            .reads
            .iter()
            .copied()
            .find(|event| spelling(GO_EXACT_LOCAL_VALUE_ALIASES, aliases.event(*event)) == "alias")
            .expect("parenthesized assignment reads the saved alias");
        let witness = aliases
            .exact_local_alias_read_identity_witness(&aliases_procedure, &closure, alias_read)
            .expect("exact local copy retains its ordered witness");
        let witness_establishments = witness
            .iter()
            .copied()
            .map(|event| aliases.event(event))
            .filter(|event| event.event_class == StateEventClass::Establish)
            .map(|event| spelling(GO_EXACT_LOCAL_VALUE_ALIASES, event))
            .collect::<Vec<_>>();
        assert_eq!(
            witness_establishments,
            ["file, _ := os.Open(\"aliases.xlsx\")", "alias := file"]
        );
        assert_eq!(witness.last(), Some(&alias_read));
        let returned_copy = closure
            .uncertain_reads
            .iter()
            .copied()
            .find(|event| spelling(GO_EXACT_LOCAL_VALUE_ALIASES, aliases.event(*event)) == "copy")
            .expect("the conditional reassignment makes the returned local copy uncertain");
        assert!(
            !closure.reads.contains(&returned_copy),
            "a read reached by both the original and replacement definitions is not exact"
        );
        assert!(
            !closure.uncertain_transfers.contains(&returned_copy),
            "a May-reaching method receiver is an uncertain observation, not a candidate local copy"
        );

        let non_local = procedure_containing(&state, |event| {
            spelling(GO_EXACT_LOCAL_VALUE_ALIASES, event)
                == "file, _ := os.Open(\"non-local.xlsx\")"
        });
        let non_local_procedure = fixture.procedure(1, non_local.procedure);
        let roots = non_local
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_EXACT_LOCAL_VALUE_ALIASES, event)
                        == "file, _ := os.Open(\"non-local.xlsx\")"
            })
            .map(|event| event.event)
            .collect::<Vec<_>>();
        let closure = non_local.exact_local_value_alias_closure(&non_local_procedure, &roots);
        assert_eq!(
            closure.establishments.len(),
            1,
            "parameter and property targets are not local aliases"
        );
        assert!(
            !closure.unclosed_transfers.is_empty(),
            "structured gaps keep unclosed non-local transfers explicit"
        );
    }

    const GO_ASSIGNMENT_CONVERSION_ALIAS: &str = r#"package app

type resource struct{}

func acquire() *resource { return nil }
func consume(*resource) {}

func conversionAlias(acquire func() *resource) any {
	source := acquire()
	consume(source)
	var converted any = source
	return converted
}
"#;

    #[test]
    fn exact_local_value_alias_closure_keeps_go_assignment_conversion_open() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("go.mod", GO_MOD),
                ("app.go", GO_ASSIGNMENT_CONVERSION_ALIAS),
            ],
        );
        let state = fixture.state(1);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_ASSIGNMENT_CONVERSION_ALIAS, event) == "source := acquire()"
        });
        let procedure = fixture.procedure(1, derivation.procedure);
        let root = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_ASSIGNMENT_CONVERSION_ALIAS, event) == "source := acquire()"
            })
            .expect("the acquired value establishes source");
        let conversion = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_ASSIGNMENT_CONVERSION_ALIAS, event) == "converted any = source"
            })
            .expect("the converted value establishes its typed local");
        let converted_value = procedure
            .semantics()
            .value(conversion.value)
            .expect("the conversion establishment carries a semantic value");
        assert!(matches!(
            &converted_value.kind,
            SemanticValueKind::LanguageDefined(kind)
                if kind.as_ref() == "go.assignment_conversion"
        ));
        let conversion_source = procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if target == conversion.value => Some(source),
                _ => None,
            })
            .expect("the typed initializer has an explicit assignment conversion");
        let conversion_source_read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read && event.value == conversion_source
            })
            .expect("the conversion source is one tracked binding read");
        let ordinary_source_read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_ASSIGNMENT_CONVERSION_ALIAS, event) == "source"
                    && event.value != conversion_source
            })
            .expect("the call consumes a separate read occurrence of the same binding");
        assert_ne!(
            ordinary_source_read.value, conversion_source_read.value,
            "binding reads are occurrence-specific semantic values"
        );

        let closure = derivation.exact_local_value_alias_closure(&procedure, &[root.event]);
        assert!(
            closure.reads.contains(&conversion_source_read.event),
            "the exact source read remains part of the candidate closure"
        );
        assert!(
            !closure
                .unclosed_transfers
                .contains(&ordinary_source_read.event),
            "a later conversion does not open an earlier read occurrence"
        );
        assert!(
            !closure.establishments.contains(&conversion.event),
            "an assignment conversion cannot establish an exact resource alias"
        );
        assert!(
            closure
                .unclosed_transfers
                .contains(&conversion_source_read.event),
            "the conversion's data flow remains an explicitly open identity transfer"
        );
    }

    const GO_TYPED_ZERO_BINDINGS: &str = r#"package app

func reported(flag bool) error {
    var reportedErr error
    if flag {
        var reportedErr error
        return reportedErr
    }
    return reportedErr
}
"#;

    #[test]
    fn go_typed_no_init_bindings_have_exact_distinct_zero_establishments() {
        let fixture = Fixture::new(
            Language::Go,
            &[("go.mod", GO_MOD), ("app.go", GO_TYPED_ZERO_BINDINGS)],
        );
        let state = fixture.state(1);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && spelling(GO_TYPED_ZERO_BINDINGS, event) == "reportedErr"
        });
        let procedure = fixture.procedure(1, derivation.procedure);

        assert!(
            !derivation
                .completeness
                .reasons()
                .iter()
                .any(|reason| matches!(
                    reason,
                    FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                )),
            "typed zero-value declarations close the binding axis: {:#?}",
            derivation.completeness
        );
        let zero_establishments = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Establish
                    && procedure
                        .semantics()
                        .value(event.value)
                        .is_some_and(|value| {
                            matches!(
                                &value.kind,
                                SemanticValueKind::LanguageDefined(kind)
                                    if kind.as_ref() == "go.zero_value"
                            )
                        })
            })
            .collect::<Vec<_>>();
        assert_eq!(zero_establishments.len(), 2, "{zero_establishments:#?}");
        assert_ne!(
            zero_establishments[0].value, zero_establishments[1].value,
            "shadowed typed declarations own distinct zero values"
        );
        assert_ne!(
            zero_establishments[0].subject, zero_establishments[1].subject,
            "shadowed typed declarations own distinct binding cells"
        );

        let reads = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_TYPED_ZERO_BINDINGS, event) == "reportedErr"
            })
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), 2, "{reads:#?}");
        let reaching_sources = reads
            .iter()
            .map(|read| {
                let exact = derivation
                    .relations
                    .iter()
                    .filter(|relation| {
                        relation.relation == FlowRelation::Reaching
                            && relation.certainty == FlowCertainty::Exact
                            && relation.target_event == read.event
                    })
                    .collect::<Vec<_>>();
                assert_eq!(exact.len(), 1, "one exact zero reaches {read:#?}");
                exact[0].source_event
            })
            .collect::<HashSet<_>>();
        assert_eq!(
            reaching_sources,
            zero_establishments
                .iter()
                .map(|event| event.event)
                .collect::<HashSet<_>>()
        );
    }

    #[test]
    fn materialized_procedure_scope_skips_unrelated_flow_derivations() {
        let fixture = Fixture::new(
            Language::Go,
            &[(
                "main.go",
                r#"package sample

func first(input int) int {
    value := input
    return value
}

func second(input int) int {
    value := input
    return value
}
"#,
            )],
        );
        let outcome = fixture.materialized(0);
        let artifact = outcome
            .available_value()
            .cloned()
            .expect("Go semantics are available");
        let cancellation = CancellationToken::default();
        let full = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        assert!(
            full.procedures.len() >= 2,
            "both functions derive: {full:#?}"
        );

        let selected = &full.procedures[1];
        let procedure = artifact
            .procedure_handle(selected.procedure)
            .expect("the artifact owns the selected procedure");
        let scoped = flow_state_for_materialized_procedure(
            &fixture.workspace,
            &fixture.files[0],
            outcome,
            &procedure,
            &mut test_request(&cancellation),
        );

        let [derived] = scoped.procedures.as_slice() else {
            panic!("only the selected procedure derives: {scoped:#?}");
        };
        assert_eq!(derived.procedure, selected.procedure);
        assert_eq!(derived.events, selected.events);
        assert_eq!(derived.relations, selected.relations);
        assert_eq!(derived.completeness, selected.completeness);
        assert_eq!(scoped.completeness, full.completeness);
        assert_eq!(scoped.generation, full.generation);
        assert_eq!(scoped.active_model_set_hash(), full.active_model_set_hash());
    }

    const GO_TWO_FUNCTIONS: &str = r#"package sample

func first(input int) int {
    value := input
    return value
}

func second(input int) int {
    value := input
    return value
}
"#;

    /// A fresh operation over the test retention owner, and the two exact
    /// procedure handles of `GO_TWO_FUNCTIONS` from one artifact allocation.
    fn operation_fixture() -> (
        Fixture,
        SemanticOutcome<Arc<SemanticArtifact>>,
        [ProcedureHandle; 2],
    ) {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_TWO_FUNCTIONS)]);
        let outcome = fixture.materialized(0);
        let artifact = outcome
            .available_value()
            .cloned()
            .expect("Go semantics are available");
        let mut handles = artifact
            .procedures()
            .iter()
            .map(|procedure| {
                artifact
                    .procedure_handle(procedure.id())
                    .expect("the artifact owns its procedures")
            })
            .collect::<Vec<_>>();
        assert!(handles.len() >= 2, "both functions lower: {handles:#?}");
        handles.truncate(2);
        let [first, second] = <[ProcedureHandle; 2]>::try_from(handles).expect("two handles");
        (fixture, outcome, [first, second])
    }

    fn test_operation() -> FlowStateOperation {
        FlowStateOperation::new(FlowStateRequestMemos::new(
            &RetentionBudget::for_test_capacity(64 * 1024 * 1024),
        ))
    }

    /// The provider-aware entry point, entered through the operation.
    fn derive_through(
        operation: &mut FlowStateOperation,
        fixture: &Fixture,
        outcome: &SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        cancellation: &CancellationToken,
    ) -> FileFlowState {
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        operation.with_request(cancellation, |budget, request| {
            flow_state_for_materialized_procedure_with_provider(
                &fixture.workspace,
                &fixture.files[0],
                outcome.clone(),
                procedure,
                request,
                budget,
                &provider,
            )
        })
    }

    fn marker_index(
        procedure: &ProcedureHandle,
    ) -> (DeadWriteProcedureKey, DeadWriteProcedureIndex) {
        (
            DeadWriteProcedureKey(
                Arc::as_ptr(procedure.artifact()) as usize,
                procedure.id(),
                procedure.interpretation(),
                u64::MAX,
            ),
            DeadWriteProcedureIndex {
                _artifact: Arc::clone(procedure.artifact()),
                events_by_binding: HashMap::default(),
                escaped_bindings: HashSet::default(),
                macro_gap_points_by_source: HashMap::default(),
            },
        )
    }

    #[test]
    #[hardwon(
        "#14156: same-file procedure derivations each received a fresh semantic and CFG grant"
    )]
    fn operation_carries_one_spent_grant_and_memos_across_derivations() {
        let (fixture, outcome, [first, second]) = operation_fixture();
        let cancellation = CancellationToken::default();
        let mut operation = test_operation();
        let pristine = operation.consumption();
        assert_eq!(pristine.cfg_used, CfgAlgorithmWork::default());

        let first_state = derive_through(&mut operation, &fixture, &outcome, &first, &cancellation);
        let after_first = operation.consumption();
        assert!(
            after_first.cfg_used != pristine.cfg_used,
            "the first derivation charged the CFG ledger"
        );

        // A memo region written between derivations survives, with its keys.
        let (key, index) = marker_index(&first);
        operation.with_request(&cancellation, |_, request| {
            assert!(request.memos.dead_write_procedure_cache.is_unused());
            request.memos.dead_write_procedure_cache.insert(key, index);
        });

        let second_state =
            derive_through(&mut operation, &fixture, &outcome, &second, &cancellation);
        let after_second = operation.consumption();
        assert!(
            after_second.cfg_used != after_first.cfg_used,
            "the second derivation spends on top of the first, not from zero"
        );
        assert_eq!(
            (after_second.cfg_refusals, after_second.semantic_refusals),
            (0, 0)
        );
        operation.with_request(&cancellation, |_, request| {
            assert!(request.memos.dead_write_procedure_cache.get(&key).is_some());
            assert!(!request.memos.dead_write_procedure_cache.is_unused());
            // Derivation itself never touches the other dead-write memos.
            assert!(request.memos.dead_write_cache.is_unused());
            assert!(request.memos.dead_write_reachability_cache.is_unused());
        });

        // Same rows as a legacy fresh-per-call derivation: only the grant moved.
        let legacy = flow_state_for_materialized_procedure(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &second,
            &mut test_request(&cancellation),
        );
        let [lent] = second_state.procedures.as_slice() else {
            panic!("only the selected procedure derives");
        };
        let [fresh] = legacy.procedures.as_slice() else {
            panic!("only the selected procedure derives");
        };
        assert_eq!(lent.events, fresh.events);
        assert_eq!(lent.relations, fresh.relations);
        assert_eq!(lent.completeness, fresh.completeness);
        assert_eq!(first_state.procedures.len(), 1);
    }

    #[test]
    #[hardwon(
        "#14156: a panic during a lent derivation must not refund the spent ledgers or drop the memos"
    )]
    fn unwinding_derivation_restores_the_same_spent_operation_state() {
        let (fixture, outcome, [first, second]) = operation_fixture();
        let cancellation = CancellationToken::default();
        let mut operation = test_operation();
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        let (key, index) = marker_index(&first);
        let mut charged = None;
        let mut optional_charged = None;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            operation.with_request(&cancellation, |budget, request| {
                drop(flow_state_for_materialized_procedure_with_provider(
                    &fixture.workspace,
                    &fixture.files[0],
                    outcome.clone(),
                    &first,
                    request,
                    budget,
                    &provider,
                ));
                request.memos.dead_write_procedure_cache.insert(key, index);
                budget
                    .admit(SemanticWork {
                        events: 1,
                        ..SemanticWork::default()
                    })
                    .expect("the injected semantic charge fits the existing grant");
                {
                    // Charge the third (optional nonreturn) ledger too.
                    let semantics = first.semantics();
                    let optional = request
                        .nonreturn_cfg_budget
                        .as_mut()
                        .expect("a lent request carries the operation's optional ledger");
                    forward_reachability(
                        semantics,
                        semantics.entry_point(),
                        &mut CfgAlgorithmRequest::new(optional, &cancellation),
                    )
                    .expect("the default optional allowance covers one pass");
                    optional_charged = Some(optional.used());
                }
                charged = Some((request.cfg_budget.used(), budget.used()));
                panic!("injected panic after charging all three ledgers and writing a memo");
            })
        }));
        assert!(unwound.is_err());
        let (cfg_used, semantic_used) = charged.expect("charges happened before the panic");
        assert!(cfg_used != CfgAlgorithmWork::default());
        assert!(semantic_used != SemanticWork::default());
        // Restored, not replaced by a default grant.
        assert_eq!(operation.consumption().cfg_used, cfg_used);
        assert_eq!(operation.semantic_budget.used(), semantic_used);
        let optional_used = optional_charged.expect("optional charge happened before the panic");
        assert!(optional_used != CfgAlgorithmWork::default());
        assert_eq!(operation.consumption().nonreturn_cfg_used, optional_used);
        operation.with_request(&cancellation, |_, request| {
            assert!(request.memos.dead_write_procedure_cache.get(&key).is_some());
        });
        // The operation keeps serving seeds on top of the spent allowance.
        drop(derive_through(
            &mut operation,
            &fixture,
            &outcome,
            &second,
            &cancellation,
        ));
        assert!(operation.consumption().cfg_used != cfg_used);
    }

    const PYTHON_NONRETURN_SEEDS: &str = r#"class Terminates:
    def __init__(self):
        self.ready = True
        raise

def caller_a(flag):
    if flag:
        value = 1
    else:
        Terminates()
    return value

def caller_b(flag):
    if flag:
        value = 2
    else:
        Terminates()
    return value
"#;
    const PYTHON_PLAIN: &str = "def plain(x):\n    return x\n";

    /// `src/main.py` (raising constructor plus two callers that make every
    /// derivation of them run the optional nonreturn proof) and `src/plain.py`
    /// (a body with no nonreturn candidate in its closure).
    fn python_nonreturn_fixture() -> (Fixture, [SemanticOutcome<Arc<SemanticArtifact>>; 2]) {
        let fixture = Fixture::new(
            Language::Python,
            &[
                ("src/main.py", PYTHON_NONRETURN_SEEDS),
                ("src/plain.py", PYTHON_PLAIN),
            ],
        );
        let outcomes = [fixture.materialized(0), fixture.materialized(1)];
        (fixture, outcomes)
    }

    fn handles_of(outcome: &SemanticOutcome<Arc<SemanticArtifact>>) -> Vec<ProcedureHandle> {
        let artifact = outcome
            .available_value()
            .expect("fixture semantics are available");
        artifact
            .procedures()
            .iter()
            .map(|procedure| {
                artifact
                    .procedure_handle(procedure.id())
                    .expect("the artifact owns its procedures")
            })
            .collect()
    }

    /// The procedures that call something: here exactly the two callers, whose
    /// closure reaches the raising constructor.
    fn callers_of(handles: &[ProcedureHandle]) -> Vec<ProcedureHandle> {
        let callers = handles
            .iter()
            .filter(|handle| !handle.semantics().call_sites().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        assert!(callers.len() >= 2, "both callers lower: {handles:#?}");
        callers
    }

    fn derive_file_through(
        operation: &mut FlowStateOperation,
        fixture: &Fixture,
        file_index: usize,
        outcome: &SemanticOutcome<Arc<SemanticArtifact>>,
        procedure: &ProcedureHandle,
        cancellation: &CancellationToken,
    ) -> FileFlowState {
        let provider =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.workspace, None);
        operation.with_request(cancellation, |budget, request| {
            flow_state_for_materialized_procedure_with_provider(
                &fixture.workspace,
                &fixture.files[file_index],
                outcome.clone(),
                procedure,
                request,
                budget,
                &provider,
            )
        })
    }

    fn has_modeled_incomplete(state: &FileFlowState) -> bool {
        state.procedures.iter().any(|derivation| {
            derivation.completeness.reasons().iter().any(|reason| {
                matches!(
                    reason,
                    FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
                )
            })
        })
    }

    #[test]
    #[hardwon(
        "#14156: the optional nonreturn proof ledger restarted for every seed, enlarging the legacy per-file allowance"
    )]
    fn optional_nonreturn_ledger_accumulates_across_seeds_apart_from_the_ordinary_ledger() {
        let (fixture, [main, _]) = python_nonreturn_fixture();
        let cancellation = CancellationToken::default();
        let handles = handles_of(&main);
        assert!(handles.len() >= 3, "constructor and both callers lower");

        let mut operation = test_operation();
        let mut optional_after = Vec::new();
        for handle in &handles {
            drop(derive_file_through(
                &mut operation,
                &fixture,
                0,
                &main,
                handle,
                &cancellation,
            ));
            optional_after.push(operation.consumption().nonreturn_cfg_used);
        }
        let shared = operation.consumption();
        assert!(
            optional_after[0] != CfgAlgorithmWork::default(),
            "the first seed's optional proof spent its own ledger"
        );
        assert!(
            shared.nonreturn_cfg_used != optional_after[0],
            "later seeds spend on top of the first, not from a fresh allowance: {optional_after:?}"
        );
        assert_eq!((shared.cfg_refusals, shared.nonreturn_cfg_refusals), (0, 0));

        // Independence: the same seeds through one reused legacy request. Its
        // optional proof clones the ordinary ledger per call and discards the
        // spending, so only ordinary flow work reaches its cumulative ledger.
        let mut legacy = test_request(&cancellation);
        for handle in &handles {
            drop(flow_state_for_materialized_procedure(
                &fixture.workspace,
                &fixture.files[0],
                main.clone(),
                handle,
                &mut legacy,
            ));
        }
        assert!(legacy.nonreturn_cfg_budget.is_none());
        assert_eq!(
            shared.cfg_used,
            legacy.cfg_budget.used(),
            "optional proof spending never reaches the ordinary ledger"
        );
    }

    #[test]
    #[hardwon(
        "#14156: a pristine optional nonreturn refusal must stay Content-incomplete, as the legacy whole-file pass reported it"
    )]
    fn pristine_optional_refusals_stay_content_incomplete_even_twice() {
        let (fixture, [main, _]) = python_nonreturn_fixture();
        let cancellation = CancellationToken::default();
        let callers = callers_of(&handles_of(&main));
        let mut operation = test_operation();
        operation
            .state
            .as_mut()
            .expect("not lent")
            .nonreturn_cfg_budget = CfgAlgorithmBudget::uniform(0);
        for handle in callers.iter().take(2) {
            let before = operation.consumption();
            let state =
                derive_file_through(&mut operation, &fixture, 0, &main, handle, &cancellation);
            let after = operation.consumption();
            assert!(after.nonreturn_cfg_refusals > before.nonreturn_cfg_refusals);
            assert_eq!(
                after.nonreturn_cfg_used,
                CfgAlgorithmWork::default(),
                "a zero allowance refuses without recording any spending"
            );
            assert!(has_modeled_incomplete(&state), "{state:#?}");
            assert!(
                state.reuse.is_content(),
                "no recorded spending means this refusal is a pristine one: {state:#?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#14156: a shared optional ledger exhausted by earlier seeds was reported as file content for later seeds"
    )]
    fn optional_refusal_after_recorded_spending_is_an_execution_stop_then_clean_seeds_stay_clean() {
        let (fixture, [main, plain_outcome]) = python_nonreturn_fixture();
        let cancellation = CancellationToken::default();
        let callers = callers_of(&handles_of(&main));
        let plain = handles_of(&plain_outcome)
            .into_iter()
            .next()
            .expect("plain.py lowers one procedure");

        // An allowance that fits one reachability pass but not a whole proof.
        let mut probe = CfgAlgorithmBudget::default();
        let semantics = callers[0].semantics();
        forward_reachability(
            semantics,
            semantics.entry_point(),
            &mut CfgAlgorithmRequest::new(&mut probe, &cancellation),
        )
        .expect("an unconstrained reachability pass completes");
        let one = probe.used();
        let mut operation = test_operation();
        operation
            .state
            .as_mut()
            .expect("not lent")
            .nonreturn_cfg_budget =
            CfgAlgorithmBudget::uniform(one.node_visits.max(one.edge_visits));

        let first = derive_file_through(
            &mut operation,
            &fixture,
            0,
            &main,
            &callers[0],
            &cancellation,
        );
        let after_first = operation.consumption();
        assert!(
            after_first.nonreturn_cfg_used != CfgAlgorithmWork::default(),
            "the first seed recorded optional spending"
        );
        assert!(
            after_first.nonreturn_cfg_refusals > 0,
            "the allowance cannot cover the whole proof"
        );
        assert!(
            first.reuse.is_content(),
            "the first refusal began from a ledger with no recorded spending: {first:#?}"
        );

        let second = derive_file_through(
            &mut operation,
            &fixture,
            0,
            &main,
            &callers[1],
            &cancellation,
        );
        assert!(
            operation.consumption().nonreturn_cfg_refusals > after_first.nonreturn_cfg_refusals
        );
        assert!(
            has_modeled_incomplete(&second),
            "the reason rows are unchanged"
        );
        assert!(
            !second.reuse.is_content(),
            "a refusal after recorded spending depends on earlier seeds: {second:#?}"
        );

        // The next seed never runs the optional proof: the earlier refusal is
        // not its cause (deltas are relative to entry).
        let clean = derive_file_through(
            &mut operation,
            &fixture,
            1,
            &plain_outcome,
            &plain,
            &cancellation,
        );
        assert!(clean.reuse.is_content(), "{clean:#?}");
    }

    #[test]
    #[hardwon(
        "#14156: a cancelled token left a Content verdict on early returns and on silently abandoned optional work"
    )]
    fn cancelled_token_makes_every_return_path_an_execution_stop() {
        let (fixture, [main, _]) = python_nonreturn_fixture();
        let callers = callers_of(&handles_of(&main));
        let live = CancellationToken::default();
        let cancelled = CancellationToken::default();
        cancelled.cancel();

        // Late path: the nonreturn proof returns an empty derivation silently.
        let mut operation = test_operation();
        let state =
            derive_file_through(&mut operation, &fixture, 0, &main, &callers[0], &cancelled);
        assert!(!state.reuse.is_content(), "{state:#?}");

        // Early return: an outcome with no artifact.
        let unsupported = || SemanticOutcome::Unsupported {
            capability: SemanticCapability::Procedures,
            partial: None,
            work: SemanticWork::default(),
        };
        let run = |token: &CancellationToken| {
            let mut request = test_request(token);
            flow_state_for_materialized_artifact(
                &fixture.workspace,
                &fixture.files[0],
                unsupported(),
                &mut request,
            )
        };
        let healthy_none = run(&live);
        assert!(healthy_none.reuse.is_content());
        let cancelled_none = run(&cancelled);
        assert!(!cancelled_none.reuse.is_content());
        assert_eq!(
            healthy_none.completeness.reasons(),
            cancelled_none.completeness.reasons(),
            "reason rows are unchanged by the verdict join"
        );
    }

    #[test]
    #[hardwon("#14156: seed rows must equal the legacy per-call rows when no ledger refuses")]
    fn operation_seeds_match_legacy_direct_derivations_without_refusals() {
        let (fixture, [main, _]) = python_nonreturn_fixture();
        let cancellation = CancellationToken::default();
        let handles = handles_of(&main);
        let mut operation = test_operation();
        for handle in &handles {
            let lent =
                derive_file_through(&mut operation, &fixture, 0, &main, handle, &cancellation);
            let direct = flow_state_for_materialized_procedure(
                &fixture.workspace,
                &fixture.files[0],
                main.clone(),
                handle,
                &mut test_request(&cancellation),
            );
            let ([lent_row], [direct_row]) =
                (lent.procedures.as_slice(), direct.procedures.as_slice())
            else {
                panic!("one procedure each");
            };
            assert_eq!(lent_row.events, direct_row.events);
            assert_eq!(lent_row.relations, direct_row.relations);
            assert_eq!(lent_row.completeness, direct_row.completeness);
            assert_eq!(
                lent_row.control_edge_mask.omitted,
                direct_row.control_edge_mask.omitted
            );
            assert_eq!(lent.reuse, direct.reuse);
        }
    }

    #[test]
    #[hardwon(
        "#14156: Go seeds under active nonreturn models restarted the optional proof ledger and rediscovered shared callees"
    )]
    fn go_seeds_share_one_optional_ledger_and_the_existing_discovery_cache() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("main.go", GO_WORKSPACE_NONRETURN_CALLERS),
                ("helper.go", GO_WORKSPACE_NONRETURN_HELPERS),
            ],
        );
        let models = fixture.activate_exact_nonreturn_models();
        let outcome = fixture.materialized(0);
        let handles = handles_of(&outcome);
        assert!(
            handles.len() >= 4,
            "the caller file lowers several procedures sharing die()"
        );
        let cancellation = CancellationToken::default();
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
            &fixture.workspace,
            Some(Arc::clone(&models)),
        );
        let seed = |operation: &mut FlowStateOperation,
                    cache: &NonreturnDiscoveryCache,
                    handle: &ProcedureHandle| {
            operation.with_request(&cancellation, |budget, request| {
                request.install_active_semantic_model_snapshot(Some(Arc::clone(&models)));
                request.install_nonreturn_discovery_cache(cache);
                flow_state_for_materialized_procedure_with_provider(
                    &fixture.workspace,
                    &fixture.files[0],
                    outcome.clone(),
                    handle,
                    request,
                    budget,
                    &provider,
                )
            })
        };

        // K seeds on ONE operation and ONE discovery cache.
        let cache = NonreturnDiscoveryCache::default();
        let mut operation = test_operation();
        let mut optional_after = Vec::new();
        for handle in &handles {
            drop(seed(&mut operation, &cache, handle));
            optional_after.push(operation.consumption().nonreturn_cfg_used);
        }
        let shared = operation.consumption();
        assert!(
            optional_after[0] != CfgAlgorithmWork::default(),
            "the optional proof ran under the active models and spent its ledger"
        );
        assert!(
            shared.nonreturn_cfg_used != optional_after[0],
            "later seeds spend on the same ledger instead of a fresh allowance: {optional_after:?}"
        );
        assert_eq!(
            (shared.cfg_refusals, shared.nonreturn_cfg_refusals),
            (0, 0),
            "no ledger refuses under the default allowances"
        );
        assert!(
            !cache.entries.lock().unwrap().is_empty(),
            "the existing request-wide discovery cache holds the shared callees"
        );

        // Counter-evidence that the existing cache (not a new one) serves the
        // shared callee discovery: the same seed on a fresh operation spends
        // less optional work when the cache is already warm than when cold.
        let probe = handles
            .iter()
            .find(|handle| !handle.semantics().call_sites().is_empty())
            .expect("a caller exists");
        let mut cold_operation = test_operation();
        drop(seed(
            &mut cold_operation,
            &NonreturnDiscoveryCache::default(),
            probe,
        ));
        let cold = cold_operation.consumption().nonreturn_cfg_used;
        let mut warm_operation = test_operation();
        drop(seed(&mut warm_operation, &cache, probe));
        let warm = warm_operation.consumption().nonreturn_cfg_used;
        let total = |work: CfgAlgorithmWork| work.node_visits + work.edge_visits;
        assert!(
            total(warm) < total(cold),
            "a warm discovery cache removes callee rediscovery from the optional ledger: cold={cold:?} warm={warm:?}"
        );

        // Independence: the same seeds through one reused legacy request. Its
        // optional proof clones the ordinary ledger per call and discards the
        // spending, so the ordinary totals must match the operation's.
        let legacy_cache = NonreturnDiscoveryCache::default();
        let mut legacy = test_request(&cancellation)
            .with_active_semantic_model_snapshot(Some(Arc::clone(&models)))
            .with_nonreturn_discovery_cache(&legacy_cache);
        for handle in &handles {
            drop(flow_state_for_materialized_procedure(
                &fixture.workspace,
                &fixture.files[0],
                outcome.clone(),
                handle,
                &mut legacy,
            ));
        }
        assert!(legacy.nonreturn_cfg_budget.is_none());
        assert_eq!(
            shared.cfg_used,
            legacy.cfg_budget.used(),
            "optional proof spending never reaches the ordinary ledger"
        );
    }

    #[test]
    #[hardwon(
        "#14156: a shared per-file allowance must exhaust across seeds, not restart per seed"
    )]
    fn exhausted_operation_stays_exhausted_for_the_next_seed() {
        let (fixture, outcome, [first, second]) = operation_fixture();
        let cancellation = CancellationToken::default();
        let mut operation = test_operation();
        operation.state.as_mut().expect("not lent").cfg_budget = CfgAlgorithmBudget::uniform(1);
        let first_state = derive_through(&mut operation, &fixture, &outcome, &first, &cancellation);
        let refused = operation.consumption().cfg_refusals;
        assert!(refused > 0, "a one-unit CFG allowance refuses");
        assert!(!first_state.reuse.is_content());
        // The second seed spends the same exhausted ledger: it refuses on its
        // own account too, so it is typed incomplete rather than silently clean.
        let second_state =
            derive_through(&mut operation, &fixture, &outcome, &second, &cancellation);
        assert!(operation.consumption().cfg_refusals > refused);
        assert!(!second_state.reuse.is_content());
        assert!(
            second_state.procedures[0]
                .completeness
                .reasons()
                .iter()
                .any(|reason| matches!(reason, FlowStateIncompleteReason::BudgetExhausted { .. })),
            "{second_state:#?}"
        );
    }

    #[test]
    #[hardwon(
        "#14156: an earlier seed's refusal on a shared ledger tainted a later seed that did not refuse"
    )]
    fn earlier_refusal_is_not_a_cause_for_a_later_clean_derivation() {
        let (fixture, outcome, [first, _]) = operation_fixture();
        let cancellation = CancellationToken::default();
        let mut operation = test_operation();
        // Record one refusal on the shared semantic ledger while leaving its
        // limits generous, as an earlier seed's stop would.
        assert!(
            operation
                .semantic_budget
                .admit(SemanticWork::uniform(usize::MAX / 2))
                .is_err()
        );
        let before = operation.consumption();
        assert!(
            before.semantic_refusals > 0,
            "the setup refusal is recorded on the shared ledger"
        );
        let state = derive_through(&mut operation, &fixture, &outcome, &first, &cancellation);
        assert_eq!(
            operation.consumption().semantic_refusals,
            before.semantic_refusals
        );
        assert!(
            state.reuse.is_content(),
            "only a refusal this derivation caused is its cause: {state:#?}"
        );
    }

    #[test]
    #[hardwon("#14156: the direct flow entry points must keep one fresh semantic grant per call")]
    fn legacy_direct_entry_points_ignore_a_spent_operation_ledger() {
        let (fixture, outcome, [first, _]) = operation_fixture();
        let cancellation = CancellationToken::default();
        let mut operation = test_operation();
        drop(derive_through(
            &mut operation,
            &fixture,
            &outcome,
            &first,
            &cancellation,
        ));
        // A legacy call with a reused request is unaffected by the operation.
        let mut request = test_request(&cancellation);
        let one = flow_state_for_materialized_procedure(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &first,
            &mut request,
        );
        let two = flow_state_for_materialized_procedure(
            &fixture.workspace,
            &fixture.files[0],
            outcome,
            &first,
            &mut request,
        );
        assert_eq!(one.procedures[0].events, two.procedures[0].events);
        assert_eq!(
            one.procedures[0].completeness,
            two.procedures[0].completeness
        );
        assert!(one.reuse.is_content() && two.reuse.is_content());
    }

    #[test]
    #[hardwon(
        "3ac44dca99bb: unresolved property access was treated as a complete Go base observation"
    )]
    fn retained_unresolved_property_access_does_not_open_base_observation_enumeration() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_UNRESOLVED_IMPORTED_FIELD_ACCESS)],
        );
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Go semantics are available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .gaps()
                    .iter()
                    .filter(|gap| {
                        gap.capability == SemanticCapability::FieldMemory
                            && matches!(gap.subject, SemanticGapSubject::MemoryLocation(_))
                    })
                    .count()
                    >= 2
            })
            .expect("the imported field accesses belong to one lowered procedure");
        let load_gap = procedure
            .gaps()
            .iter()
            .find(|gap| {
                let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                    return false;
                };
                gap.capability == SemanticCapability::FieldMemory
                    && procedure.point(gap.point).is_some_and(|point| {
                        point.events.iter().any(|event| {
                            matches!(
                                event.effect,
                                SemanticEffect::MemoryLoad {
                                    location: accessed,
                                    ..
                                } if accessed == location
                            )
                        })
                    })
            })
            .expect("the imported field load has unresolved declaration identity");
        let SemanticGapSubject::MemoryLocation(load_location) = load_gap.subject else {
            unreachable!("the selected gap has a memory-location subject");
        };
        let base = match procedure
            .memory_location(load_location)
            .expect("the gap names a retained memory location")
            .kind
        {
            MemoryLocationKind::Field { base, .. } => base,
            ref kind => panic!("the imported selector must name a field, got {kind:?}"),
        };
        let relevant_values = std::iter::once(base).collect::<HashSet<_>>();
        let derivation = state
            .procedures
            .iter()
            .find(|derivation| derivation.procedure == procedure.id())
            .expect("the imported field access has retained flow state");
        let retained_read_values = derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Read)
            .map(|event| event.value)
            .collect::<HashSet<_>>();
        let origins = [procedure.entry_point()];

        assert!(gap_point_retains_memory_access(
            procedure,
            load_gap,
            load_location
        ));
        assert!(
            retained_read_values.contains(&base),
            "the imported selector retains a read of its base value"
        );
        assert!(
            !result_observation_gap_is_relevant(
                procedure,
                load_gap,
                &relevant_values,
                &retained_read_values,
                &origins,
            ),
            "unresolved property identity cannot hide the retained observation of its base"
        );

        let no_base_read = HashSet::default();
        assert!(
            result_observation_gap_is_relevant(
                procedure,
                load_gap,
                &relevant_values,
                &no_base_read,
                &origins,
            ),
            "a same-point access without a retained base read must keep enumeration open"
        );

        let mut no_access = load_gap.clone();
        no_access.point = procedure.entry_point();
        assert_ne!(no_access.point, load_gap.point);
        assert!(!gap_point_retains_memory_access(
            procedure,
            &no_access,
            load_location
        ));
        assert!(
            result_observation_gap_is_relevant(
                procedure,
                &no_access,
                &relevant_values,
                &retained_read_values,
                &origins,
            ),
            "a location gap without its exact retained access must keep enumeration open"
        );

        let store_gap = procedure
            .gaps()
            .iter()
            .find(|gap| {
                let SemanticGapSubject::MemoryLocation(location) = gap.subject else {
                    return false;
                };
                gap.capability == SemanticCapability::FieldMemory
                    && procedure.point(gap.point).is_some_and(|point| {
                        point.events.iter().any(|event| {
                            matches!(
                                event.effect,
                                SemanticEffect::MemoryStore {
                                    location: accessed,
                                    ..
                                } if accessed == location
                            )
                        })
                    })
            })
            .expect("the imported field store has unresolved declaration identity");
        let SemanticGapSubject::MemoryLocation(store_location) = store_gap.subject else {
            unreachable!("the selected gap has a memory-location subject");
        };
        let stored_value = procedure
            .point(store_gap.point)
            .into_iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::MemoryStore {
                    location, value, ..
                } if location == store_location => Some(value),
                _ => None,
            })
            .expect("the store gap point retains the exact stored value");
        let stored_sources = procedure
            .point(store_gap.point)
            .into_iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if target == stored_value
                    && procedure.value(target).is_some_and(|value| {
                        matches!(
                            &value.kind,
                            SemanticValueKind::LanguageDefined(kind)
                                if kind.as_ref() == "go.assignment_conversion"
                        )
                    }) =>
                {
                    Some(source)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let [stored_source] = stored_sources.as_slice() else {
            panic!(
                "the stored value has one exact assignment-conversion source: {stored_sources:?}"
            )
        };
        let root = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_UNRESOLVED_IMPORTED_FIELD_ACCESS, event)
                        == "parsed, _ := url.Parse(raw)"
            })
            .expect("the parsed URL result has one exact establishment");
        let procedure_handle = artifact
            .procedure_handle(procedure.id())
            .expect("the materialized artifact owns the selected procedure");
        let closure = derivation
            .exact_local_value_alias_closure(&procedure_handle, std::slice::from_ref(&root.event));
        let load_base_read = closure
            .reads
            .iter()
            .copied()
            .find(|event| derivation.event(*event).value == base)
            .expect("the exact closure reaches the retained selector-base read");
        let stored_source_read = closure
            .reads
            .iter()
            .copied()
            .find(|event| derivation.event(*event).value == *stored_source)
            .expect("the exact closure reaches the retained conversion-source read");
        assert_ne!(load_base_read, stored_source_read);
        assert!(
            !closure.unclosed_transfers.contains(&load_base_read),
            "a retained field load completely represents its base observation"
        );
        assert!(
            closure.unclosed_transfers.contains(&stored_source_read),
            "a value stored into unresolved memory remains an unclosed transfer"
        );
        assert_eq!(
            closure.unclosed_transfers,
            std::iter::once(stored_source_read).collect::<HashSet<_>>(),
            "only the unresolved store remains open"
        );
    }

    #[test]
    fn cpp_dead_write_configuration_gaps_stay_open() {
        for source in [
            "int check() { if constexpr (false) { int x; x = 1; return x; } return 0; }",
            "int check() {\n#if 0\nint x; x = 1; return x;\n#endif\nreturn 0; }",
        ] {
            let fixture = Fixture::new(Language::Cpp, &[("src/Case.cpp", source)]);
            let state = fixture.state(0);
            let original = procedure_containing(&state, |event| {
                event.event_class == StateEventClass::Establish
                    && spelling(source, event) == "x = 1"
            });
            let write = original
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(source, event) == "x = 1"
                })
                .expect("configured source retains the write");
            let procedure = fixture.procedure(0, original.procedure);
            eprintln!("source={source} gaps={:?}", procedure.semantics().gaps());
            let cancellation = CancellationToken::default();
            let mut request = test_request(&cancellation);
            let answer = original.dead_write_local(&procedure, write.event, &mut request);
            assert!(
                matches!(answer, DeadWriteAnswer::Open { .. }),
                "{source}: {answer:?}"
            );
        }
    }

    #[test]
    fn dead_write_operand_order_gap_stays_open_and_prefix_walk_is_shared() {
        const SOURCE: &str = r#"package sample
type item struct { value int }
func check() int {
    x := &item{value: 1}
    y := 2
    z := 3
    v0 := 4
    v1 := 5
    v2 := 6
    v3 := 7
    v4 := 8
    v5 := 9
    v6 := 10
    v7 := 11
    v8 := 12
    v9 := 13
    v10 := 14
    v11 := 15
    v12 := 16
    v13 := 17
    v14 := 18
    v15 := 19
    result := combine(next(), x.value)
    return result + y + z + v0 + v1 + v2 + v3 + v4 + v5 + v6 + v7 + v8 + v9 + v10 + v11 + v12 + v13 + v14 + v15
}"#;
        let fixture = Fixture::new(Language::Go, &[("sample.go", SOURCE)]);
        let state = fixture.state(0);
        let cancellation = CancellationToken::default();
        let mut checked = 0;
        for derivation in &state.procedures {
            let procedure = fixture.procedure(0, derivation.procedure);
            let order_gap = procedure
                .semantics()
                .gaps()
                .iter()
                .find(|gap| gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder)
                .expect("Go records the operand order gap");
            let mut reasons = Vec::new();
            push_gap_reason(&mut reasons, order_gap);
            let mut derivation = derivation.clone();
            derivation.completeness = FlowStateCompleteness::from_reasons(reasons);
            let mut request = test_request(&cancellation);
            for write in derivation.events.iter().filter(|event| {
                event.event_class == StateEventClass::Establish
                    && matches!(event.subject, FlowSubject::Binding { .. })
            }) {
                let answer = derivation.dead_write_local(&procedure, write.event, &mut request);
                assert!(matches!(answer, DeadWriteAnswer::Open { .. }), "{answer:?}");
                checked += 1;
            }
            assert_eq!(request.dead_write_prefix_reachability_cache.len(), 1);
            assert_eq!(
                request
                    .dead_write_prefix_reachability_cache
                    .keys()
                    .next()
                    .unwrap()
                    .2
                    .len(),
                1
            );
            // All writes use the same cached pass, including its charged work.
            let closure = &request
                .dead_write_prefix_reachability_cache
                .values()
                .next()
                .unwrap()
                .outcome;
            assert!(closure.is_ok());
        }
        assert!(checked >= 20);
    }

    #[test]
    fn dead_write_live_certificate_respects_gap_points_and_escape() {
        const SOURCE: &str = "fn check() -> i32 { let mut x; x = 1; unknown(); let y = x; y }";
        let fixture = Fixture::new(Language::Rust, &[("sample.rs", SOURCE)]);
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(SOURCE, event) == "x = 1"
        });
        let write = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event) == "x = 1"
            })
            .expect("write exists");
        let read = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read && event.subject == write.subject
            })
            .expect("read exists");
        let procedure = fixture.procedure(0, original.procedure);
        let semantics = procedure.semantics();
        let later = semantics
            .points()
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| event.effect == SemanticEffect::NormalExit)
            })
            .expect("normal exit exists");
        let cancellation = CancellationToken::default();
        for (point, escaped, live) in [
            (later.id, false, true),
            (semantics.call_sites()[0].point, false, false),
            (read.point, false, false),
            (later.id, true, false),
            (write.point, false, false),
        ] {
            use crate::analyzer::semantic::{ProcedureSemanticsParts, SemanticGapImpacts};
            let mut parts = ProcedureSemanticsParts::new(
                semantics.id(),
                semantics.locator().clone(),
                semantics.kind(),
                semantics.source(),
                semantics.evidence(),
            );
            parts.properties = semantics.properties();
            parts.cleanup_chains = semantics.cleanup_chains().clone();
            parts.drops = semantics.drops().to_vec();
            parts.move_outs = semantics.move_outs().to_vec();
            parts.scope_ends = semantics.scope_ends().to_vec();
            parts.values = semantics.values().to_vec();
            parts.allocations = semantics.allocations().to_vec();
            parts.memory_locations = semantics.memory_locations().to_vec();
            parts.captures = semantics.captures().to_vec();
            parts.call_sites = semantics.call_sites().to_vec();
            parts.source_mappings = semantics.source_mappings().to_vec();
            parts.evidence_rows = semantics.evidence_rows().to_vec();
            parts.gaps = semantics.gaps().to_vec();
            parts.blocks = semantics.blocks().to_vec();
            parts.points = semantics.points().to_vec();
            parts.control_edges = semantics.control_edges().to_vec();
            let id = SemanticGapId::new(parts.gaps.len() as u32);
            let site = semantics.point(point).expect("gap point exists");
            parts.gaps.push(SemanticGap {
                id,
                point,
                subject: SemanticGapSubject::Point,
                capability: SemanticCapability::Assignments,
                impacts: SemanticGapImpacts::for_gap(
                    SemanticCapability::Assignments,
                    SemanticGapSubject::Point,
                ),
                kind: SemanticGapKind::Unknown,
                budget: None,
                dispatch: Default::default(),
                discharge: SemanticGapDischarge::None,
                detail: "test-only point gap".into(),
                source: site.source,
                evidence: site.evidence,
            });
            let mut point_events = parts.points[point.index()].events.to_vec();
            point_events.insert(
                0,
                crate::analyzer::semantic::SemanticEvent::new(
                    SemanticEffect::Gap { gap: id },
                    site.source,
                    site.evidence,
                ),
            );
            parts.points[point.index()].events = point_events.into_boxed_slice();
            let artifact = Arc::new(
                SemanticArtifact::try_new(
                    procedure.artifact().key().clone(),
                    procedure.artifact().capabilities().clone(),
                    vec![parts],
                )
                .expect("injected gap preserves valid semantics"),
            );
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("procedure exists");
            let mut derivation = original.clone();
            derivation.procedure_artifact = Arc::downgrade(&artifact);
            let mut reasons = Vec::new();
            push_gap_reason(
                &mut reasons,
                procedure.semantics().gap(id).expect("gap exists"),
            );
            derivation.completeness = FlowStateCompleteness::from_reasons(reasons);
            let mut request = test_request(&cancellation);
            if escaped {
                let mut index = dead_write_procedure_index(&derivation, &procedure);
                index.escaped_bindings.insert(write.subject.value());
                request.memos.dead_write_procedure_cache.insert(
                    DeadWriteProcedureKey(
                        Arc::as_ptr(procedure.artifact()) as usize,
                        procedure.id(),
                        procedure.interpretation(),
                        derivation.generation,
                    ),
                    index,
                );
            }
            let answer = derivation.dead_write_local_with_macro_sources(
                &procedure,
                write.event,
                &[site.source],
                &[],
                &mut request,
            );
            if live {
                assert!(matches!(answer, DeadWriteAnswer::Live { .. }), "{answer:?}");
            } else {
                assert!(matches!(answer, DeadWriteAnswer::Open { .. }), "{answer:?}");
            }
        }
    }

    #[test]
    fn dead_write_component_order_is_shared_across_writes() {
        let source = format!(
            "fn check() -> i32 {{ let a = Vec::<i32>::new(); let b = Vec::<i32>::new(); let mut x; {} x }}",
            "x = 1;".repeat(20)
        );
        let fixture = Fixture::new(Language::Rust, &[("sample.rs", &source)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(&source, event) == "x = 1"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        assert!(procedure.semantics().gaps().len() >= 2);
        let cancellation = CancellationToken::default();
        let mut request = test_request(&cancellation);
        let key = DeadWriteProcedureKey(
            Arc::as_ptr(procedure.artifact()) as usize,
            procedure.id(),
            procedure.interpretation(),
            derivation.generation,
        );
        let first = derivation
            .cached_dead_write_component_order(&procedure, key, &[], &[], &mut request)
            .unwrap();
        let mut checked = 0;
        for write in derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Establish)
        {
            let order = derivation
                .cached_dead_write_component_order(&procedure, key, &[], &[], &mut request)
                .unwrap();
            assert!(Arc::ptr_eq(&first, &order));
            let _answer = derivation.dead_write_local(&procedure, write.event, &mut request);
            checked += 1;
        }
        assert!(checked >= 20);
        assert_eq!(request.dead_write_component_order_cache.len(), 1);
    }

    #[test]
    fn dead_write_unreachable_prefix_keeps_dead() {
        const SOURCE: &str = "class Sample { int check(boolean flag) { int x; if (flag) { int y = 0; } x = 1; x = 2; return x; } }";
        let fixture = Fixture::new(Language::Java, &[("Sample.java", SOURCE)]);
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(SOURCE, event) == "x = 1"
        });
        let write = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event) == "x = 1"
            })
            .expect("write exists");
        let procedure = fixture.procedure(0, original.procedure);
        let semantics = procedure.semantics();
        let cancellation = CancellationToken::default();
        let point = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event).contains("y = 0")
            })
            .expect("branch establishment")
            .point;
        {
            use crate::analyzer::semantic::{ProcedureSemanticsParts, SemanticGapImpacts};
            let mut parts = ProcedureSemanticsParts::new(
                semantics.id(),
                semantics.locator().clone(),
                semantics.kind(),
                semantics.source(),
                semantics.evidence(),
            );
            parts.properties = semantics.properties();
            parts.cleanup_chains = semantics.cleanup_chains().clone();
            parts.drops = semantics.drops().to_vec();
            parts.move_outs = semantics.move_outs().to_vec();
            parts.scope_ends = semantics.scope_ends().to_vec();
            parts.values = semantics.values().to_vec();
            parts.allocations = semantics.allocations().to_vec();
            parts.memory_locations = semantics.memory_locations().to_vec();
            parts.captures = semantics.captures().to_vec();
            parts.call_sites = semantics.call_sites().to_vec();
            parts.source_mappings = semantics.source_mappings().to_vec();
            parts.evidence_rows = semantics.evidence_rows().to_vec();
            parts.gaps = semantics.gaps().to_vec();
            parts.blocks = semantics.blocks().to_vec();
            parts.points = semantics.points().to_vec();
            parts.control_edges = semantics.control_edges().to_vec();
            let id = SemanticGapId::new(parts.gaps.len() as u32);
            let site = semantics.point(point).expect("gap point exists");
            parts.gaps.push(SemanticGap {
                id,
                point,
                subject: SemanticGapSubject::Point,
                capability: SemanticCapability::ReturnFlow,
                impacts: SemanticGapImpacts::for_gap(
                    SemanticCapability::ReturnFlow,
                    SemanticGapSubject::Point,
                ),
                kind: SemanticGapKind::Unsupported,
                budget: None,
                dispatch: Default::default(),
                discharge: SemanticGapDischarge::None,
                detail: "test-only point gap".into(),
                source: site.source,
                evidence: site.evidence,
            });
            let mut point_events = parts.points[point.index()].events.to_vec();
            point_events.insert(
                0,
                crate::analyzer::semantic::SemanticEvent::new(
                    SemanticEffect::Gap { gap: id },
                    site.source,
                    site.evidence,
                ),
            );
            parts.points[point.index()].events = point_events.into_boxed_slice();
            let artifact = Arc::new(
                SemanticArtifact::try_new(
                    procedure.artifact().key().clone(),
                    procedure
                        .artifact()
                        .capabilities()
                        .iter()
                        .fold(
                            SemanticCapabilities::builder(),
                            |builder, (capability, support)| builder.support(capability, support),
                        )
                        .partial(SemanticCapability::ReturnFlow)
                        .build(),
                    vec![parts],
                )
                .expect("injected gap preserves valid semantics"),
            );
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("procedure exists");
            let mut derivation = original.clone();
            derivation.procedure_artifact = Arc::downgrade(&artifact);
            let mut reasons = Vec::new();
            push_gap_reason(
                &mut reasons,
                procedure.semantics().gap(id).expect("gap exists"),
            );
            derivation.completeness = FlowStateCompleteness::from_reasons(reasons);
            let mut request = test_request(&cancellation);
            let gap_point = original
                .events
                .iter()
                .find(|event| {
                    event.event_class == StateEventClass::Establish
                        && spelling(SOURCE, event).contains("y = 0")
                })
                .expect("branch establishment")
                .point;
            derivation.control_edge_mask = ControlEdgeMask::new(
                procedure.semantics(),
                procedure
                    .semantics()
                    .control_edges()
                    .iter()
                    .enumerate()
                    .filter(|(_, edge)| edge.target_point == gap_point)
                    .map(|(index, _)| ControlEdgeId::try_from_index(index).unwrap()),
            );
            let answer = derivation.dead_write_local_with_macro_sources(
                &procedure,
                write.event,
                &[],
                &[],
                &mut request,
            );
            assert!(matches!(answer, DeadWriteAnswer::Dead), "{answer:?}");
        }
    }

    #[test]
    fn dead_write_loop_drop_gap_stays_open() {
        const SOURCE: &str = "class Sample { int check(boolean flag) { int x; while (flag) { int y = 0; x = 1; int z = x; } return 0; } }";
        let fixture = Fixture::new(Language::Java, &[("Sample.java", SOURCE)]);
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(SOURCE, event) == "x = 1"
        });
        let write = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event) == "x = 1"
            })
            .expect("write exists");
        let procedure = fixture.procedure(0, original.procedure);
        let semantics = procedure.semantics();
        let cancellation = CancellationToken::default();
        let point = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event).contains("y = 0")
            })
            .expect("branch establishment")
            .point;
        {
            use crate::analyzer::semantic::{ProcedureSemanticsParts, SemanticGapImpacts};
            let mut parts = ProcedureSemanticsParts::new(
                semantics.id(),
                semantics.locator().clone(),
                semantics.kind(),
                semantics.source(),
                semantics.evidence(),
            );
            parts.properties = semantics.properties();
            parts.cleanup_chains = semantics.cleanup_chains().clone();
            parts.drops = semantics.drops().to_vec();
            parts.move_outs = semantics.move_outs().to_vec();
            parts.scope_ends = semantics.scope_ends().to_vec();
            parts.values = semantics.values().to_vec();
            parts.allocations = semantics.allocations().to_vec();
            parts.memory_locations = semantics.memory_locations().to_vec();
            parts.captures = semantics.captures().to_vec();
            parts.call_sites = semantics.call_sites().to_vec();
            parts.source_mappings = semantics.source_mappings().to_vec();
            parts.evidence_rows = semantics.evidence_rows().to_vec();
            parts.gaps = Vec::new();
            parts.blocks = semantics.blocks().to_vec();
            parts.points = semantics.points().to_vec();
            for point in &mut parts.points {
                point.events = point
                    .events
                    .iter()
                    .filter(|event| !matches!(event.effect, SemanticEffect::Gap { .. }))
                    .cloned()
                    .collect();
            }
            parts.control_edges = semantics.control_edges().to_vec();
            let id = SemanticGapId::new(parts.gaps.len() as u32);
            let site = semantics.point(point).expect("gap point exists");
            parts.gaps.push(SemanticGap {
                id,
                point,
                subject: SemanticGapSubject::Point,
                capability: SemanticCapability::Calls,
                impacts: SemanticGapImpacts::for_gap(
                    SemanticCapability::Calls,
                    SemanticGapSubject::Point,
                ),
                kind: SemanticGapKind::Unknown,
                budget: None,
                dispatch: Default::default(),
                discharge: SemanticGapDischarge::ImplicitDropExecution,
                detail: "implicit drop glue is not modeled".into(),
                source: site.source,
                evidence: site.evidence,
            });
            let mut point_events = parts.points[point.index()].events.to_vec();
            point_events.insert(
                0,
                crate::analyzer::semantic::SemanticEvent::new(
                    SemanticEffect::Gap { gap: id },
                    site.source,
                    site.evidence,
                ),
            );
            parts.points[point.index()].events = point_events.into_boxed_slice();
            let artifact = Arc::new(
                SemanticArtifact::try_new(
                    procedure.artifact().key().clone(),
                    procedure.artifact().capabilities().clone(),
                    vec![parts],
                )
                .expect("injected gap preserves valid semantics"),
            );
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("procedure exists");
            let mut derivation = original.clone();
            derivation.procedure_artifact = Arc::downgrade(&artifact);
            let mut reasons = Vec::new();
            push_gap_reason(
                &mut reasons,
                procedure.semantics().gap(id).expect("gap exists"),
            );
            derivation.completeness = FlowStateCompleteness::from_reasons(reasons);
            assert_eq!(procedure.semantics().gaps().len(), 1);
            assert!(procedure.semantics().gaps()[0].is_implicit_drop_omission());
            let mut request = test_request(&cancellation);
            let key = DeadWriteProcedureKey(
                Arc::as_ptr(procedure.artifact()) as usize,
                procedure.id(),
                procedure.interpretation(),
                derivation.generation,
            );
            let order = derivation
                .cached_dead_write_component_order(&procedure, key, &[], &[], &mut request)
                .unwrap();
            assert_eq!(order[point.index()], order[write.point.index()]);
            // Bypass the surface's drop exemption and invoke its certificate
            // directly with the sole drop gap retained. Cutting this loop's
            // gap must prevent a Live witness by removing entry to the write.
            let edges = derivation
                .dead_write_certificate_edges(
                    &procedure,
                    key,
                    &[],
                    &[],
                    write.point,
                    [point].into_iter().collect(),
                    &mut request,
                )
                .unwrap();
            let reachable = derivation
                .cached_dead_write_reachability(
                    &procedure,
                    key,
                    &edges,
                    &edges,
                    procedure.semantics().entry_point(),
                    &mut request,
                )
                .unwrap();
            assert!(!reachable.membership()[write.point.index()]);
        }
    }

    #[test]
    fn overwritten_unread_keeps_unlocated_observation_gaps_blocking() {
        const SOURCE: &str = "class Sample { int clean() { int x; x = 1; x = 2; return x; } }";
        let fixture = Fixture::new(Language::Java, &[("src/Sample.java", SOURCE)]);
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(SOURCE, event) == "x = 1"
        });
        let event = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event) == "x = 1"
            })
            .expect("the first write projects an establishment")
            .event;
        let procedure = fixture.procedure(0, original.procedure);
        let cancellation = CancellationToken::default();
        assert!(matches!(
            original.overwritten_unread_local(&procedure, event, &mut test_request(&cancellation)),
            OverwrittenUnreadAnswer::Proven { .. }
        ));
        let reason = FlowStateIncompleteReason::LoweringGap {
            gaps: Vec::new(),
            capability: SemanticCapability::Assignments,
            kind: SemanticGapKind::Unknown,
            detail: "test-only observation gap without a point".into(),
        };
        let mut derivation = original.clone();
        derivation.completeness = FlowStateCompleteness::from_reasons(vec![reason.clone()]);
        assert_eq!(
            derivation.overwritten_unread_local(
                &procedure,
                event,
                &mut test_request(&cancellation)
            ),
            OverwrittenUnreadAnswer::Open {
                reasons: vec![reason]
            }
        );
    }

    #[test]
    fn overwritten_unread_keeps_live_and_entry_gaps_open() {
        use crate::analyzer::semantic::{ProcedureSemanticsParts, SemanticGapImpacts};

        const SOURCE: &str =
            "class Sample { int check() { int x; x = 1; new Object(); x = 2; return x; } }";
        let fixture = Fixture::new(Language::Java, &[("src/Sample.java", SOURCE)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish && spelling(SOURCE, event) == "x = 1"
        });
        let first = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(SOURCE, event) == "x = 1"
            })
            .expect("the first write projects an establishment");
        let original = fixture.procedure(0, derivation.procedure);
        let semantics = original.semantics();
        let exit = semantics
            .points()
            .iter()
            .find(|point| {
                point
                    .events
                    .iter()
                    .any(|event| event.effect == SemanticEffect::ExceptionalExit)
            })
            .expect("the call has an exceptional exit");
        assert!(
            semantics.control_edges().iter().any(|edge| {
                edge.kind == ControlEdgeKind::Exceptional && edge.target_point == exit.id
            }),
            "the exceptional destination must have a real incoming exceptional edge"
        );
        assert!(semantics.guard_facts().is_empty());
        assert!(semantics.switch_facts().is_empty());
        let mut parts = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            semantics.locator().clone(),
            semantics.kind(),
            semantics.source(),
            semantics.evidence(),
        );
        parts.properties = semantics.properties();
        parts.values = semantics.values().to_vec();
        parts.allocations = semantics.allocations().to_vec();
        parts.memory_locations = semantics.memory_locations().to_vec();
        parts.captures = semantics.captures().to_vec();
        parts.call_sites = semantics.call_sites().to_vec();
        parts.source_mappings = semantics.source_mappings().to_vec();
        parts.evidence_rows = semantics.evidence_rows().to_vec();
        parts.gaps = semantics.gaps().to_vec();
        parts.blocks = semantics.blocks().to_vec();
        parts.points = semantics.points().to_vec();
        parts.control_edges = semantics.control_edges().to_vec();
        let id = SemanticGapId::new(parts.gaps.len() as u32);
        parts.gaps.push(SemanticGap {
            id,
            point: exit.id,
            subject: SemanticGapSubject::Point,
            capability: SemanticCapability::Assignments,
            impacts: SemanticGapImpacts::for_gap(
                SemanticCapability::Assignments,
                SemanticGapSubject::Point,
            ),
            kind: SemanticGapKind::Unknown,
            budget: None,
            dispatch: Default::default(),
            discharge: SemanticGapDischarge::None,
            detail: "test-only observation gap at the exceptional destination".into(),
            source: exit.source,
            evidence: exit.evidence,
        });
        let point = &mut parts.points[exit.id.index()];
        let mut events = point.events.to_vec();
        events.insert(
            0,
            crate::analyzer::semantic::SemanticEvent::new(
                SemanticEffect::Gap { gap: id },
                exit.source,
                exit.evidence,
            ),
        );
        point.events = events.into_boxed_slice();
        let mut prefix_parts = parts.clone();
        let artifact = SemanticArtifact::try_new(
            original.artifact().key().clone(),
            original.artifact().capabilities().clone(),
            vec![parts],
        )
        .expect("the exceptional-destination gap preserves valid semantics");
        let semantics = &artifact.procedures()[0];
        let mut reasons = Vec::new();
        push_gap_reason(
            &mut reasons,
            semantics.gap(id).expect("the injected gap exists"),
        );
        let cancellation = CancellationToken::default();
        let mut budget = CfgAlgorithmBudget::default();
        let mut run = |located_reasons: &[FlowStateIncompleteReason]| {
            let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
            let located =
                locate_gap_reasons(semantics, located_reasons.to_vec(), |_| true, &mut request)
                    .expect("synthetic located reasons are indexed");
            overwritten_unread_over_graph(
                semantics,
                OverwrittenUnreadWalkInputs {
                    semantics,
                    events: &derivation.events,
                    event_keys: &derivation.event_keys,
                    establishment_event: first.event,
                    binding: first.subject.value(),
                    gaps_by_point: &located.by_point,
                },
                &mut request,
            )
            .expect("the live-value walk completes")
        };
        // Without an observation gap, the old value can escape exceptionally
        // before its normal-path replacement. This proves the path is visited.
        assert_eq!(run(&[]), OverwrittenUnreadAnswer::PathWithoutOverwrite);
        assert_eq!(run(&reasons), OverwrittenUnreadAnswer::Open { reasons });

        // Independently test the entry proof: disconnect the origin while
        // keeping a reachable return-flow gap at entry. Without the gap,
        // the retained graph alone would incorrectly claim source unreachability.
        let entry = semantics.entry_point();
        prefix_parts
            .control_edges
            .retain(|edge| edge.source_point != entry);
        let gap = &mut prefix_parts.gaps[id.index()];
        gap.point = entry;
        gap.capability = SemanticCapability::ReturnFlow;
        gap.kind = SemanticGapKind::Unsupported;
        gap.impacts = SemanticGapImpacts::for_gap(gap.capability, gap.subject);
        for point in &mut prefix_parts.points {
            point.events = point
                .events
                .iter()
                .filter(|event| event.effect != (SemanticEffect::Gap { gap: id }))
                .cloned()
                .collect();
        }
        let point = &mut prefix_parts.points[entry.index()];
        let mut events = point.events.to_vec();
        events.push(crate::analyzer::semantic::SemanticEvent::new(
            SemanticEffect::Gap { gap: id },
            point.source,
            point.evidence,
        ));
        point.events = events.into_boxed_slice();
        let capabilities = original
            .artifact()
            .capabilities()
            .iter()
            .fold(
                SemanticCapabilities::builder(),
                |builder, (capability, support)| builder.support(capability, support),
            )
            .partial(SemanticCapability::ReturnFlow)
            .build();
        let prefix_artifact = SemanticArtifact::try_new(
            original.artifact().key().clone(),
            capabilities,
            vec![prefix_parts],
        )
        .expect("a located gap may retain a disconnected source region");
        let semantics = &prefix_artifact.procedures()[0];
        let mut reasons = Vec::new();
        push_gap_reason(&mut reasons, semantics.gap(id).unwrap());
        let mut budget = CfgAlgorithmBudget::default();
        let mut run = |located_reasons: &[FlowStateIncompleteReason]| {
            let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
            let located =
                locate_gap_reasons(semantics, located_reasons.to_vec(), |_| true, &mut request)
                    .expect("synthetic located reasons are indexed");
            overwritten_unread_over_graph(
                semantics,
                OverwrittenUnreadWalkInputs {
                    semantics,
                    events: &derivation.events,
                    event_keys: &derivation.event_keys,
                    establishment_event: first.event,
                    binding: first.subject.value(),
                    gaps_by_point: &located.by_point,
                },
                &mut request,
            )
            .expect("the independent entry walk completes")
        };
        assert_eq!(run(&[]), OverwrittenUnreadAnswer::Unreachable);
        assert_eq!(run(&reasons), OverwrittenUnreadAnswer::Open { reasons });
    }

    #[test]
    fn overwritten_unread_local_consumes_the_shared_cfg_budget() {
        let fixture = Fixture::new(
            Language::Java,
            &[("src/Sample.java", JAVA_OVERWRITTEN_UNREAD)],
        );
        let state = fixture.state(0);
        let first_write = JAVA_OVERWRITTEN_UNREAD
            .find("x = 1;")
            .expect("first write exists");
        let derivation = state
            .procedures
            .iter()
            .find(|derivation| {
                derivation.events.iter().any(|event| {
                    event.event_class == StateEventClass::Establish
                        && event.site.range.start_byte == first_write
                })
            })
            .expect("clean method has an establishment");
        let first = derivation
            .events
            .iter()
            .find(|event| event.site.range.start_byte == first_write)
            .expect("first establishment exists");
        let procedure = fixture.procedure(0, derivation.procedure);
        let cancellation = CancellationToken::default();
        let mut request = test_request(&cancellation);
        request.cfg_budget = CfgAlgorithmBudget::uniform(1);
        assert!(matches!(
            derivation.overwritten_unread_local(&procedure, first.event, &mut request),
            OverwrittenUnreadAnswer::Open { reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    FlowStateIncompleteReason::BudgetExhausted {
                        axis: FlowStateAxis::ReachingRelation,
                        ..
                    }
                ))
        ));
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            derivation.overwritten_unread_local(
                &procedure,
                first.event,
                &mut test_request(&cancelled)
            ),
            OverwrittenUnreadAnswer::Open { reasons }
                if reasons.contains(&FlowStateIncompleteReason::Cancelled)
        ));
    }

    #[test]
    #[hardwon(
        "661a63f06f4c: mutable Python capture was misclassified as an established binding read"
    )]
    fn mutable_python_capture_does_not_expose_a_provable_binding_read() {
        const SOURCE: &str = r#"
def outer():
    x = 1
    def inner():
        nonlocal x
        x = 2
    inner()
    x = x
    return x
"#;
        let fixture = Fixture::new(Language::Python, &[("src/main.py", SOURCE)]);
        let state = fixture.state(0);
        let read_at = SOURCE.find("x = x").expect("self assignment exists") + 4;
        assert!(
            state
                .procedures
                .iter()
                .flat_map(|derivation| &derivation.events)
                .all(|event| event.event_class != StateEventClass::Read
                    || event.site.range.start_byte != read_at)
        );
        assert!(state.procedures.iter().any(|derivation| {
            derivation.completeness.reasons().iter().any(|reason| {
                matches!(
                    reason,
                    FlowStateIncompleteReason::LoweringGap {
                        capability: SemanticCapability::Captures,
                        ..
                    }
                )
            })
        }));
    }

    #[test]
    fn exhausted_cfg_budget_keeps_binding_initialization_open() {
        let fixture = Fixture::new(
            Language::Java,
            &[("src/Sample.java", JAVA_BINDING_INITIALIZATION)],
        );
        let state = fixture.state_with_budget(0, CfgAlgorithmBudget::uniform(1));
        let read_at = JAVA_BINDING_INITIALIZATION
            .find("x = x;")
            .expect("self assignment exists")
            + 4;
        let (derivation, read) = state
            .procedures
            .iter()
            .find_map(|derivation| {
                derivation.events.iter().find_map(|event| {
                    (event.event_class == StateEventClass::Read
                        && event.site.range.start_byte == read_at)
                        .then_some((derivation, event.event))
                })
            })
            .expect("the self-assignment RHS is a projected binding read");
        let procedure = fixture.procedure(0, derivation.procedure);
        assert!(matches!(
            derivation.binding_initialization_at_read(&procedure, read, &mut test_request(&CancellationToken::default())),
            BindingInitializationAnswer::Open { reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    FlowStateIncompleteReason::BudgetExhausted { .. }
                ))
        ));
    }

    #[test]
    #[hardwon(
        "#14370: property snapshot cancel/budget stops were collapsed into PropertyAnalysisPartial"
    )]
    fn property_snapshot_cancellation_preserves_stop_reason() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let read = derivation.events.iter().find(|event| {
            event.event_class == StateEventClass::Read
                && matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "value")
        }).expect("property read");
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let (result, reuse) = property_reaching_for_procedure(
            &fixture.workspace,
            &procedure,
            &test_request(&cancellation),
            &mut SemanticBudget::default(),
        );
        assert_eq!(result.unwrap_err(), FlowStateIncompleteReason::Cancelled);
        assert_eq!(reuse, EXECUTION_STOP);
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &state,
            &procedure,
            read.point,
            &mut test_request(&cancellation),
        );
        assert_eq!(selected.reuse, EXECUTION_STOP);
        assert!(selected.procedures[0].relations.is_empty());
        assert!(
            selected
                .completeness
                .reasons()
                .contains(&FlowStateIncompleteReason::Cancelled)
        );
        assert!(
            !selected.completeness.reasons().iter().any(|reason| {
                matches!(
                    reason,
                    FlowStateIncompleteReason::PropertyAnalysisPartial { .. }
                )
            }),
            "{selected:?}"
        );
    }

    #[test]
    #[hardwon(
        "#14370: property snapshot cancel/budget stops were collapsed into PropertyAnalysisPartial"
    )]
    fn property_snapshot_budget_preserves_stop_reason() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::uniform(1).expect("valid test budget");
        // The real oracle can retain a partial snapshot on refusal. Its stop
        // must still reach the property caller as budget, not generic coverage.
        let outcome = fixture
            .workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("snapshot acquisition");
        let SemanticOutcome::ExceededBudget {
            partial: Some(_),
            exceeded,
            ..
        } = outcome
        else {
            panic!("expected an oracle budget stop with a partial snapshot, got {outcome:?}");
        };
        let (result, reuse) = property_reaching_for_procedure(
            &fixture.workspace,
            &procedure,
            &test_request(&cancellation),
            &mut SemanticBudget::uniform(1).expect("valid test budget"),
        );
        assert_eq!(
            result.unwrap_err(),
            FlowStateIncompleteReason::BudgetExhausted {
                axis: FlowStateAxis::PropertyReachingRelation,
                detail: exceeded.to_string(),
            }
        );
        assert_eq!(reuse, EXECUTION_STOP);
        let stopped = flow_state_for_materialized_outcome(
            &fixture.workspace,
            &fixture.files[0],
            fixture.materialized(0),
            Some(&procedure),
            state.generation,
            None,
            state.active_model_set_hash.clone(),
            &mut SemanticBudget::uniform(1).expect("valid test budget"),
            &mut test_request(&cancellation),
            None,
        );
        let [derived] = stopped.procedures.as_slice() else {
            panic!("one selected derivation: {stopped:?}");
        };
        assert!(
            derived
                .events
                .iter()
                .all(|event| { !matches!(event.subject, FlowSubject::Property { .. }) })
        );
        for axis in property_axes() {
            assert!(!derived.completeness.covers(*axis), "{axis:?}: {derived:?}");
            assert!(
                derived.completeness.reasons().iter().any(|reason| {
                    matches!(reason, FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { detail }
                        if detail == &exceeded.to_string())
                }),
                "missing typed budget cause for {axis:?}: {derived:?}"
            );
        }
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(event.subject, FlowSubject::Property { .. })
            })
            .expect("healthy property read endpoint");
        let refreshed = fixture
            .workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .expect("fresh snapshot acquisition");
        assert!(
            matches!(refreshed, SemanticOutcome::Complete { .. }),
            "{refreshed:?}"
        );
        // A fresh snapshot could complete, but cannot repair the withheld
        // aggregate endpoints. Selection keeps the refusal without solving.
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &stopped,
            &procedure,
            read.point,
            &mut test_request(&cancellation),
        );
        assert!(
            !selected.completeness.reasons().iter().any(|reason| {
                matches!(
                    reason,
                    FlowStateIncompleteReason::SelectedPropertyEndpointUnavailable { .. }
                )
            }),
            "budget-withheld endpoints are not independent content gaps: {selected:?}"
        );
        assert!(selected.completeness.reasons().iter().any(|reason| {
            matches!(reason, FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { detail }
                if detail == &exceeded.to_string())
        }), "selected retry lost the aggregate budget cause: {selected:?}");
        assert_eq!(selected.completeness.reasons().len(), 1, "{selected:?}");
        assert!(
            selected
                .procedures
                .iter()
                .all(|derived| derived.relations.is_empty())
        );
        assert_eq!(selected.reuse, EXECUTION_STOP);
        let entry = procedure.semantics().entry_point();
        let absent = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &stopped,
            &procedure,
            entry,
            &mut test_request(&cancellation),
        );
        assert!(absent.completeness.reasons().iter().any(|reason| {
            matches!(reason, FlowStateIncompleteReason::PropertyReaching { reason }
                if matches!(reason.as_ref(), PropertyReachingIncompleteReason::SelectedReadMissing { point } if *point == entry))
        }), "immutable entry read inventory was lost: {absent:?}");
        assert!(absent.completeness.reasons().iter().any(|reason| matches!(
            reason,
            FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { .. }
        )));
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let cancelled_retry = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &stopped,
            &procedure,
            read.point,
            &mut test_request(&cancelled),
        );
        assert!(
            cancelled_retry
                .completeness
                .reasons()
                .contains(&FlowStateIncompleteReason::Cancelled,)
        );
        assert!(cancelled_retry.completeness.reasons().iter().any(|reason| {
            matches!(reason, FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { detail }
                if detail == &exceeded.to_string())
        }));
        assert!(
            cancelled_retry
                .procedures
                .iter()
                .all(|derived| derived.relations.is_empty())
        );
        assert_eq!(cancelled_retry.reuse, EXECUTION_STOP);
    }

    #[test]
    #[hardwon(
        "#14370: refused property snapshots left dropped rows on the caller's resident ledger"
    )]
    fn property_snapshot_refusal_releases_scratch_admissions() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            matches!(event.subject, FlowSubject::Property { .. })
        });
        let procedure = fixture.procedure(0, original.procedure);
        let token = CancellationToken::default();
        let retained = SemanticWork {
            values: 1,
            ..SemanticWork::default()
        };
        let mut witnessed_admitted_refusal = false;
        for limit in 2..=128 {
            let mut probe = SemanticBudget::uniform(limit).expect("valid budget");
            probe.admit(retained).expect("preexisting caller rows fit");
            let outcome = fixture
                .workspace
                .semantic_oracle_provider()
                .procedure_relations(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut probe, &token),
                )
                .expect("oracle snapshot");
            if !matches!(
                outcome,
                SemanticOutcome::ExceededBudget {
                    partial: Some(_),
                    ..
                }
            ) || probe.resident_census().unowned == retained
            {
                continue;
            }
            witnessed_admitted_refusal = true;
            let mut budget = SemanticBudget::uniform(limit).expect("valid budget");
            budget.admit(retained).expect("preexisting caller rows fit");
            let (result, reuse) = property_reaching_for_procedure(
                &fixture.workspace,
                &procedure,
                &test_request(&token),
                &mut budget,
            );
            let FlowStateIncompleteReason::BudgetExhausted { detail, .. } = result.unwrap_err()
            else {
                panic!("expected typed snapshot budget refusal");
            };
            assert_eq!(reuse, EXECUTION_STOP);
            assert_eq!(
                budget.resident_census().unowned,
                retained,
                "discarded snapshot leaked scratch at limit {limit}"
            );
            assert_ne!(
                budget.used(),
                retained,
                "performed admissions must remain in telemetry"
            );
            assert_ne!(
                budget.resident_peak(),
                retained,
                "the attempted peak must survive refund"
            );
            assert!(budget.refusal_count() > 0);
            assert_eq!(
                budget
                    .first_refusal()
                    .expect("preserved refusal")
                    .exceeded
                    .to_string(),
                detail
            );
            budget
                .admit(retained)
                .expect("later caller may reuse the released capacity");
            break;
        }
        assert!(
            witnessed_admitted_refusal,
            "fixture must admit rows before stopping"
        );
    }

    #[test]
    #[hardwon("#14370: fresh selected acquisition stops lost immutable read-selection evidence")]
    fn property_snapshot_fresh_stop_preserves_ir_read_selection() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            matches!(event.subject, FlowSubject::Property { .. })
        });
        let procedure = fixture.procedure(0, original.procedure);
        let entry = procedure.semantics().entry_point();
        let mut witnessed_partial_cancellation = false;
        for checks in 1..=4096 {
            let probe = CancellationToken::cancel_after_checks_for_test(checks);
            let outcome = fixture
                .workspace
                .semantic_oracle_provider()
                .procedure_relations(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &probe),
                )
                .expect("oracle snapshot");
            if !matches!(
                outcome,
                SemanticOutcome::Cancelled {
                    partial: Some(_),
                    ..
                }
            ) {
                if !probe.cancel_after_checks_tripped_for_test() {
                    break;
                }
                continue;
            }
            witnessed_partial_cancellation = true;
            let token = CancellationToken::cancel_after_checks_for_test(checks);
            let selected = flow_state_for_selected_property(
                &fixture.workspace,
                &fixture.files[0],
                &state,
                &procedure,
                entry,
                &mut test_request(&token),
            );
            assert!(
                selected
                    .completeness
                    .reasons()
                    .contains(&FlowStateIncompleteReason::Cancelled),
                "{selected:?}"
            );
            assert!(selected.completeness.reasons().iter().any(|reason| {
                matches!(reason, FlowStateIncompleteReason::PropertyReaching { reason }
                    if matches!(reason.as_ref(), PropertyReachingIncompleteReason::SelectedReadMissing { point } if *point == entry))
            }), "fresh stopped acquisition lost the IR selection fact: {selected:?}");
            assert!(
                selected
                    .procedures
                    .iter()
                    .all(|row| row.relations.is_empty())
            );
            assert_eq!(selected.reuse, EXECUTION_STOP);
            break;
        }
        assert!(
            witnessed_partial_cancellation,
            "fixture must cancel with a partial snapshot"
        );
    }

    #[test]
    #[hardwon(
        "#14370: snapshot budget provenance blocked intact binding-only same-evaluation proofs"
    )]
    fn property_snapshot_budget_preserves_binding_only_evaluation() {
        const SOURCE: &str = r#"
function copyAndLoad() {
    const local = 1;
    const copy = local;
    const ns = {};
    ns.value = 1;
    const field = ns.value;
    return copy + field;
}
"#;
        let fixture = Fixture::new(Language::JavaScript, &[("src/main.js", SOURCE)]);
        let state = fixture.state(0);
        let original =
            procedure_containing(&state, |event| spelling(SOURCE, event).contains("copy"));
        let procedure = fixture.procedure(0, original.procedure);
        let cancellation = CancellationToken::default();
        let stopped = flow_state_for_materialized_outcome(
            &fixture.workspace,
            &fixture.files[0],
            fixture.materialized(0),
            Some(&procedure),
            state.generation,
            None,
            state.active_model_set_hash.clone(),
            &mut SemanticBudget::uniform(1).expect("valid test budget"),
            &mut test_request(&cancellation),
            None,
        );
        let [derived] = stopped.procedures.as_slice() else {
            panic!("one selected derivation: {stopped:?}");
        };
        let pair = |binding_name: &str| {
            derived
                .relations
                .iter()
                .find(|relation| {
                    relation.relation == FlowRelation::SameEvaluation
                        && matches!(
                            derived.events[relation.source_event].subject,
                            FlowSubject::Binding { .. }
                        )
                        && matches!(
                            derived.events[relation.target_event].subject,
                            FlowSubject::Binding { .. }
                        )
                        && spelling(SOURCE, &derived.events[relation.source_event])
                            .contains(binding_name)
                })
                .expect("retained exact binding same-evaluation pair")
        };
        let copy = pair("copy");
        let field = pair("field");
        assert_eq!(
            derived.read_feeds_establishment(&procedure, copy.target_event, copy.source_event,),
            SameEvaluationAnswer::Closed
        );
        assert!(matches!(derived.read_feeds_establishment(
            &procedure, field.target_event, field.source_event,
        ), SameEvaluationAnswer::Open { reasons } if reasons.iter().any(|reason| {
            reason.blocks(FlowStateAxis::SameEvaluationRelation)
        })));
        for axis in property_axes() {
            assert!(!derived.completeness.covers(*axis), "{axis:?}: {derived:?}");
        }
        // A genuine same-evaluation stop still blocks the memory-free pair.
        let mut evaluation_stopped = derived.clone();
        evaluation_stopped.completeness =
            FlowStateCompleteness::from_reasons(vec![FlowStateIncompleteReason::BudgetExhausted {
                axis: FlowStateAxis::SameEvaluationRelation,
                detail: "same-evaluation control budget exhausted".into(),
            }]);
        assert!(matches!(evaluation_stopped.read_feeds_establishment(
            &procedure, copy.target_event, copy.source_event,
        ), SameEvaluationAnswer::Open { reasons } if reasons.iter().any(|reason| {
            matches!(reason, FlowStateIncompleteReason::BudgetExhausted {
                axis: FlowStateAxis::SameEvaluationRelation, ..
            })
        })));
    }

    #[test]
    #[hardwon("#14370: late cancellation was hidden by a selected-property budget refusal")]
    fn property_snapshot_budget_preserves_late_cancellation() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && matches!(event.subject, FlowSubject::Property { .. })
        });
        let procedure = fixture.procedure(0, original.procedure);
        let read = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(event.subject, FlowSubject::Property { .. })
            })
            .expect("property read");
        let mut saw_budget_and_cancellation = false;
        let mut reached_uncancelled_return = false;
        // Sweep deterministic token checkpoints through acquisition and the
        // stopped solver, including cancellation after its budget refusal.
        for checks in 1..=4096 {
            let token = CancellationToken::cancel_after_checks_for_test(checks);
            let mut request = test_request(&token);
            request.cfg_budget = CfgAlgorithmBudget::uniform(0);
            let selected = flow_state_for_selected_property(
                &fixture.workspace,
                &fixture.files[0],
                &state,
                &procedure,
                read.point,
                &mut request,
            );
            if !token.cancel_after_checks_tripped_for_test() {
                reached_uncancelled_return = true;
                break;
            }
            let budget_stopped = selected.completeness.reasons().iter().any(|reason| {
                matches!(reason, FlowStateIncompleteReason::PropertyReaching { reason }
                if matches!(reason.as_ref(), PropertyReachingIncompleteReason::Reachability(
                    CfgAlgorithmError::ExceededBudget(_)
                )))
            });
            if budget_stopped {
                saw_budget_and_cancellation = true;
                assert!(
                    selected
                        .completeness
                        .reasons()
                        .contains(&FlowStateIncompleteReason::Cancelled,),
                    "late cancellation lost behind budget refusal at check {checks}: {selected:?}"
                );
                assert!(
                    selected
                        .procedures
                        .iter()
                        .all(|derived| derived.relations.is_empty())
                );
                assert_eq!(selected.reuse, EXECUTION_STOP);
            }
        }
        assert!(
            reached_uncancelled_return,
            "checkpoint sweep did not reach an uncancelled return"
        );
        assert!(
            saw_budget_and_cancellation,
            "no completion checkpoint observed cancellation after budget refusal"
        );
    }

    #[test]
    #[hardwon(
        "#14370: interrupted selected projection misreported a valid property read as missing"
    )]
    fn property_snapshot_interrupted_projection_does_not_invent_missing_read() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && matches!(event.subject, FlowSubject::Property { .. })
        });
        let procedure = fixture.procedure(0, original.procedure);
        let point = original
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(event.subject, FlowSubject::Property { .. })
            })
            .expect("valid property read")
            .point;
        let live = CancellationToken::default();
        let outcome = fixture
            .workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .expect("complete property snapshot");
        let snapshot = outcome
            .available_value()
            .expect("retained property snapshot");
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let selected = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
            snapshot,
            procedure.semantics(),
            procedure.semantics().entry_point(),
            point,
            PropertyReachingLimits::default(),
            &cancelled,
        );
        assert!(
            selected
                .incomplete_reasons()
                .contains(&PropertyReachingIncompleteReason::Cancelled)
        );
        assert!(
            !selected.incomplete_reasons().iter().any(|reason| {
                matches!(
                    reason,
                    PropertyReachingIncompleteReason::SelectedReadMissing { .. }
                )
            }),
            "cancelled scan did not certify missing read: {selected:?}"
        );
        let complete = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
            snapshot,
            procedure.semantics(),
            procedure.semantics().entry_point(),
            point,
            PropertyReachingLimits::default(),
            &live,
        );
        assert!(
            complete.is_complete(),
            "uninterrupted selected proof: {complete:?}"
        );
        let mut reached_complete = false;
        for checks in 1..=4096 {
            let token = CancellationToken::cancel_after_checks_for_test(checks);
            let interrupted =
                crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
                    snapshot,
                    procedure.semantics(),
                    procedure.semantics().entry_point(),
                    point,
                    PropertyReachingLimits::default(),
                    &token,
                );
            if !token.cancel_after_checks_tripped_for_test() {
                assert!(interrupted.is_complete(), "{interrupted:?}");
                reached_complete = true;
                break;
            }
            assert!(
                interrupted.incomplete_reasons().iter().all(|reason| {
                    matches!(
                        reason,
                        PropertyReachingIncompleteReason::Cancelled
                            | PropertyReachingIncompleteReason::Reachability(
                                CfgAlgorithmError::Cancelled { .. }
                            )
                            | PropertyReachingIncompleteReason::ReachingDefinitions(
                                CfgAlgorithmError::Cancelled { .. }
                            )
                            | PropertyReachingIncompleteReason::Dominators(
                                CfgAlgorithmError::Cancelled { .. }
                            )
                            | PropertyReachingIncompleteReason::ReachingPairs(
                                CfgAlgorithmError::Cancelled { .. }
                            )
                    )
                }),
                "interrupted proof invented a non-cancellation cause at check {checks}: {interrupted:?}"
            );
        }
        assert!(
            reached_complete,
            "checkpoint sweep did not reach a complete proof"
        );
        let limited = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
            snapshot,
            procedure.semantics(),
            procedure.semantics().entry_point(),
            point,
            PropertyReachingLimits {
                max_input_relations: 0,
                ..PropertyReachingLimits::default()
            },
            &live,
        );
        assert!(limited.incomplete_reasons().iter().any(|reason| {
            matches!(
                reason,
                PropertyReachingIncompleteReason::InputRelationBudgetExceeded { .. }
            )
        }));
        assert!(
            !limited.incomplete_reasons().iter().any(|reason| {
                matches!(
                    reason,
                    PropertyReachingIncompleteReason::SelectedReadMissing { .. }
                )
            }),
            "limited scan did not certify missing read: {limited:?}"
        );
        // Immutable IR certifies that the entry contains no property read;
        // this content gap remains valid independently of cancellation.
        let entry = procedure.semantics().entry_point();
        let absent = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
            snapshot,
            procedure.semantics(),
            entry,
            entry,
            PropertyReachingLimits::default(),
            &cancelled,
        );
        assert!(absent.incomplete_reasons().iter().any(|reason| {
            matches!(reason, PropertyReachingIncompleteReason::SelectedReadMissing { point } if *point == entry)
        }));
        assert!(
            absent
                .incomplete_reasons()
                .contains(&PropertyReachingIncompleteReason::Cancelled)
        );
    }

    #[test]
    #[hardwon(
        "#14370: cancelled selected projection attributed unrelated property gaps to the read"
    )]
    fn property_snapshot_cancelled_projection_scopes_content_gaps() {
        use crate::analyzer::semantic::ProcedureSemanticsParts;

        const SOURCE: &str = r#"
function mixed() {
    const other = {};
    other.unrelated = 1;
    const ns = {};
    ns.value = 1;
    return ns.value;
}
"#;
        let fixture = Fixture::new(Language::JavaScript, &[("src/main.js", SOURCE)]);
        let state = fixture.state(0);
        let original = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Read
                && matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "value")
        });
        let procedure = fixture.procedure(0, original.procedure);
        let point = original.events.iter().find(|event| {
            event.event_class == StateEventClass::Read
                && matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "value")
        }).expect("selected read").point;
        // Supply a valid partial producer fact at an unrelated store before
        // asking the real oracle to seal and project the memory relations.
        let semantics = procedure.semantics();
        let mut parts = ProcedureSemanticsParts::new(
            ProcedureId::new(0),
            semantics.locator().clone(),
            semantics.kind(),
            semantics.source(),
            semantics.evidence(),
        );
        parts.properties = semantics.properties();
        parts.values = semantics.values().to_vec();
        parts.allocations = semantics.allocations().to_vec();
        parts.memory_locations = semantics.memory_locations().to_vec();
        parts.captures = semantics.captures().to_vec();
        parts.call_sites = semantics.call_sites().to_vec();
        parts.source_mappings = semantics.source_mappings().to_vec();
        parts.evidence_rows = semantics.evidence_rows().to_vec();
        parts.gaps = semantics.gaps().to_vec();
        parts.blocks = semantics.blocks().to_vec();
        parts.points = semantics.points().to_vec();
        parts.control_edges = semantics.control_edges().to_vec();
        let store = original.events.iter().find(|event| {
            event.event_class == StateEventClass::Establish
                && matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "unrelated")
        }).expect("unrelated store");
        let evidence = crate::analyzer::semantic::EvidenceId::new(parts.evidence_rows.len() as u32);
        let event = parts.points[store.point.index()]
            .events
            .iter_mut()
            .find(|event| matches!(event.effect, SemanticEffect::MemoryStore { .. }))
            .expect("store IR event");
        let mut row = semantics
            .evidence_row(event.evidence)
            .expect("store evidence")
            .clone();
        row.id = evidence;
        row.completeness =
            EvidenceCompleteness::Partial("test-only unrelated store evidence".into());
        event.evidence = evidence;
        parts.evidence_rows.push(row);
        let artifact = SemanticArtifact::try_new(
            procedure.artifact().key().clone(),
            procedure.artifact().capabilities().clone(),
            vec![parts],
        )
        .expect("valid partial producer artifact");
        let procedure = Arc::new(artifact)
            .procedure_handle(ProcedureId::new(0))
            .expect("test procedure");
        let live = CancellationToken::default();
        let outcome = fixture
            .workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &live),
            )
            .expect("property snapshot");
        let snapshot = outcome.available_value().expect("available snapshot");
        let aggregate = crate::analyzer::semantic::derive_property_reaching(
            snapshot,
            PropertyReachingLimits::default(),
            &live,
        );
        let unrelated_gaps = aggregate.incomplete_reasons().iter().filter(|reason| {
            matches!(reason, PropertyReachingIncompleteReason::StoreEvidenceIncomplete { point: gap_point, .. } if *gap_point != point)
        }).collect::<Vec<_>>();
        assert!(
            !unrelated_gaps.is_empty(),
            "fixture must project an unrelated content gap: {aggregate:?}"
        );
        let mut reached_uncancelled = false;
        for checks in 1..=4096 {
            let token = CancellationToken::cancel_after_checks_for_test(checks);
            let selected = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
                snapshot,
                procedure.semantics(),
                procedure.semantics().entry_point(),
                point,
                PropertyReachingLimits::default(),
                &token,
            );
            if !token.cancel_after_checks_tripped_for_test() {
                reached_uncancelled = true;
                break;
            }
            if selected.reads().is_empty() {
                assert!(
                    selected
                        .incomplete_reasons()
                        .contains(&PropertyReachingIncompleteReason::Cancelled),
                    "{selected:?}"
                );
                assert!(
                    selected
                        .incomplete_reasons()
                        .iter()
                        .all(|reason| !unrelated_gaps.contains(&reason)),
                    "unrelated content attributed before selected receiver was known at check {checks}: {selected:?}"
                );
            }
        }
        assert!(reached_uncancelled, "checkpoint sweep did not finish");
    }

    /// The selected analysis and public event projection evolve separately:
    /// endpoint loss, cancellation and CFG limits must never turn into a
    /// complete empty selected answer.
    #[test]
    fn selected_property_preserves_endpoint_and_request_failures() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let outcome = fixture.materialized(0);
        let artifact = outcome.available_value().cloned().expect("JS artifact");
        let token = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome,
            &mut test_request(&token),
        );
        let (index, read) = state.procedures.iter().enumerate().find_map(|(index, row)| {
            row.events.iter().find(|event| event.event_class == StateEventClass::Read
                && matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "value"))
                .map(|event| (index, event.event))
        }).expect("property read");
        let procedure = artifact
            .procedure_handle(state.procedures[index].procedure)
            .expect("procedure");
        let point = state.procedures[index].events[read].point;
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &state,
            &procedure,
            point,
            &mut test_request(&token),
        );
        assert!(
            selected.procedures[0]
                .completeness
                .covers(FlowStateAxis::PropertyReachingRelation),
            "baseline selected proof: {selected:?}"
        );
        assert!(!selected.procedures[0].relations.is_empty());
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .workspace
            .semantic_oracle_provider()
            .procedure_relations(
                &procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &token),
            )
            .expect("published relation snapshot");
        let snapshot = outcome.available_value().expect("available snapshot");
        let store = snapshot
            .relations()
            .iter()
            .find(|relation| {
                relation.kind == crate::analyzer::semantic::ValueFlowRelationKind::MemoryStore
            })
            .expect("fixture store");
        let omitted_key = (store.point.id(), store.event_index);
        let retained = snapshot
            .relations()
            .iter()
            .filter(|relation| {
                relation.kind != crate::analyzer::semantic::ValueFlowRelationKind::MemoryStore
            })
            .cloned()
            .collect();
        let damaged = crate::analyzer::semantic::ValueFlowSnapshot::with_discharged_gaps(
            procedure.clone(),
            OracleCallContext::empty(),
            retained,
            CandidateCoverage::Exhaustive,
            crate::analyzer::semantic::OracleLimits::default(),
            procedure
                .semantics()
                .gaps()
                .iter()
                .filter(|gap| {
                    snapshot.gap_is_discharged(crate::analyzer::semantic::GapKey::Gap(gap.id))
                })
                .map(|gap| crate::analyzer::semantic::GapKey::Gap(gap.id))
                .collect(),
        )
        .expect("retained rows still satisfy the oracle relation contract");
        let selected = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
            &damaged,
            procedure.semantics(),
            procedure.semantics().entry_point(),
            point,
            PropertyReachingLimits::default(),
            &token,
        );
        assert!(!selected.is_complete(), "omitted IR store: {selected:?}");
        assert!(selected.incomplete_reasons().iter().any(|reason|
            matches!(reason, PropertyReachingIncompleteReason::SelectedRelationEndpointUnavailable {
                point, event_index, relation: crate::analyzer::semantic::ValueFlowRelationKind::MemoryStore, ..
            } if (*point, *event_index) == omitted_key)), "exact omitted key: {selected:?}");
        let selected = crate::analyzer::semantic::derive_selected_property_reaching_over_graph(
            snapshot,
            procedure.semantics(),
            procedure.semantics().entry_point(),
            point,
            PropertyReachingLimits {
                max_input_relations: 0,
                ..PropertyReachingLimits::default()
            },
            &token,
        );
        assert!(!selected.is_complete(), "input frontier: {selected:?}");
        assert!(selected.incomplete_reasons().iter().any(|reason| matches!(
            reason,
            PropertyReachingIncompleteReason::InputRelationBudgetExceeded { limit: 0, .. }
        )));
        let mut missing = state.clone();
        // Keep the parallel join keys intact, but remove the endpoint's
        // property presentation. This models independently failed projection.
        missing.procedures[index].events[read].subject = FlowSubject::Binding {
            value: state.procedures[index].events[read].value,
        };
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &missing,
            &procedure,
            point,
            &mut test_request(&token),
        );
        assert!(selected.completeness.reasons().iter().any(|reason|
            matches!(reason, FlowStateIncompleteReason::SelectedPropertyEndpointUnavailable { point: missing, .. } if *missing == point)));
        assert!(
            !selected
                .completeness
                .covers(FlowStateAxis::PropertyReachingRelation)
        );
        let mut limited = test_request(&token);
        limited.cfg_budget = CfgAlgorithmBudget::uniform(0);
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &state,
            &procedure,
            point,
            &mut limited,
        );
        assert!(
            !selected
                .completeness
                .covers(FlowStateAxis::PropertyReachingRelation),
            "budget: {selected:?}"
        );
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &state,
            &procedure,
            point,
            &mut test_request(&cancelled),
        );
        assert!(
            !selected
                .completeness
                .covers(FlowStateAxis::PropertyReachingRelation),
            "cancelled: {selected:?}"
        );
    }

    #[test]
    fn a_read_after_an_establishment_reaches_exactly_and_is_dominated() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        assert!(
            derivation.events.iter().all(|event| {
                event.event_class != StateEventClass::Kill
                    || !matches!(&event.subject, FlowSubject::Property { .. })
            }),
            "a single structured property store must not manufacture a kill"
        );

        let reaching = relation_spellings(
            JS_READ_AFTER_ESTABLISHMENT,
            derivation,
            FlowRelation::Reaching,
        );
        assert!(
            reaching.contains(&("ns.value = 1", "ns.value", FlowCertainty::Exact)),
            "expected an exact reaching row for the property; got {reaching:?}"
        );

        let dominates = relation_spellings(
            JS_READ_AFTER_ESTABLISHMENT,
            derivation,
            FlowRelation::Dominates,
        );
        assert!(
            dominates.contains(&("ns.value = 1", "ns.value", FlowCertainty::Exact)),
            "expected a dominance row for the property; got {dominates:?}"
        );
    }

    #[test]
    #[hardwon(
        "5c5d4e214494: an operation precondition was inferred without a stable predicate binding"
    )]
    fn direct_result_argument_requires_a_stable_predicate_binding() {
        let fixture = Fixture::new(
            Language::Go,
            &[("main.go", GO_VALIDATOR_RESULT_ARGUMENT_ORDER)],
        );
        let outcome = fixture.materialized(0);
        let cancellation = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome.clone(),
            &mut test_request(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Go semantics are available");

        for (procedure_name, expected) in [
            ("safe", Some(true)),
            ("invalidated", None),
            ("afterReceive", Some(true)),
            ("escaped", None),
            ("captured", Some(true)),
        ] {
            let semantics = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(procedure_name)
                })
                .unwrap_or_else(|| panic!("{procedure_name} procedure"));
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("procedure handle");
            let derivation = state
                .procedures
                .iter()
                .find(|candidate| candidate.procedure == procedure.id())
                .expect("flow-state derivation");
            let predicate_binding = semantics
                .values()
                .iter()
                .find(|value| matches!(value.kind, SemanticValueKind::Parameter { ordinal: 0, .. }))
                .expect("predicate parameter binding")
                .id;
            let validator = call_handle_spelled(
                &procedure,
                GO_VALIDATOR_RESULT_ARGUMENT_ORDER,
                "checked(value)",
            );
            let target_spelling = match procedure_name {
                "invalidated" => "use(checked(value), mutate(&value))",
                "escaped" => "use(publish(&value), checked(value))",
                "captured" => "use(checked(value), mutate())",
                "safe" | "afterReceive" => "use(checked(value), \"constant\")",
                _ => unreachable!("the case table names every target spelling"),
            };
            let target = call_handle_spelled(
                &procedure,
                GO_VALIDATOR_RESULT_ARGUMENT_ORDER,
                target_spelling,
            );
            let target_call = semantics.call_site(target.id()).expect("target call site");
            let answer = derivation.any_normal_return_dominates_result_uses(
                &procedure,
                &[semantics.entry_point()],
                &[predicate_binding],
                std::slice::from_ref(&validator),
                &[target_call.point],
                &[Some(target.id())],
            );
            if procedure_name == "safe" {
                assert!(
                    derivation
                        .any_normal_return_dominates_result_uses(
                            &procedure,
                            &[semantics.entry_point()],
                            &[predicate_binding],
                            std::slice::from_ref(&validator),
                            &[target_call.point],
                            &[Some(validator.id())],
                        )
                        .is_none(),
                    "a call id from another invocation cannot activate the target-argument shortcut"
                );
            }
            match expected {
                Some(answer_expected) => assert_eq!(
                    answer.as_deref(),
                    Some([answer_expected].as_slice()),
                    "the exact validator result orders the stable target argument"
                ),
                None => assert!(
                    answer.is_none(),
                    "a mutation or unresolved escape keeps ordering open in {procedure_name}"
                ),
            }
        }
    }

    #[test]
    fn projected_nonreturn_drives_reaching_definitions_over_the_same_mask() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_PROJECTED_NONRETURN_REACHING)],
        );
        let raw = fixture.state(0);
        let branch = procedure_containing(
            &raw,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, branch.procedure);
        let call = call_handle_spelled(&procedure, JS_PROJECTED_NONRETURN_REACHING, "abort()");
        let omitted = normal_edge_for_call(&procedure, &call);
        let projection = FlowControlProjection::new(
            procedure.artifact().key().clone(),
            [FlowControlEdgeOmission::new(branch.procedure, omitted)],
        );
        let projected = fixture.state_with_control_projection(0, &projection);
        let projected_branch = procedure_containing(
            &projected,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );

        let raw_reaching = relation_spellings(
            JS_PROJECTED_NONRETURN_REACHING,
            branch,
            FlowRelation::Reaching,
        );
        assert!(
            raw_reaching.contains(&("ns.value = 2", "ns.value", FlowCertainty::May)),
            "the raw rejoining branch definition reaches the return: {raw_reaching:?}"
        );
        let projected_reaching = relation_spellings(
            JS_PROJECTED_NONRETURN_REACHING,
            projected_branch,
            FlowRelation::Reaching,
        );
        assert!(
            projected_reaching.contains(&("ns.value = 1", "ns.value", FlowCertainty::Exact)),
            "the retained definition becomes exact: {projected_reaching:?}; completeness: {:?}",
            projected_branch.completeness
        );
        assert!(
            !projected_reaching
                .iter()
                .any(|(source, target, _)| *source == "ns.value = 2" && *target == "ns.value"),
            "a definition on the terminating arm cannot reach the return: {projected_reaching:?}"
        );
    }

    #[test]
    fn retained_dominance_allows_a_control_gap_at_the_target() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_CONTROL_GAP_AT_TARGET)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let procedure = fixture.procedure(0, derivation.procedure);
        let candidate = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_CONTROL_GAP_AT_TARGET, event) == "ready := true"
            })
            .expect("the pre-read binding is established")
            .point;
        let target = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value")
            })
            .expect("the returned field is read")
            .point;
        let selector_gap = procedure
            .semantics()
            .gaps()
            .iter()
            .find(|gap| gap.detail.as_ref() == "selection may panic on a nil operand")
            .expect("the selector records its independent panic gap");
        assert_eq!(
            selector_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit,
            "the Go adapter owns the non-rejoining provenance"
        );
        assert_eq!(
            selector_gap.point, target,
            "the queried read owns the point-scoped selector gap"
        );
        assert_eq!(
            derivation
                .any_candidate_dominates_targets(&procedure, &[candidate], &[target])
                .as_deref(),
            Some([true].as_slice()),
            "omitted behavior from the target cannot create an entry-to-target path that bypasses an earlier candidate"
        );
    }

    #[test]
    fn a_plain_object_literal_procedure_covers_every_axis() {
        for (language, path, source) in [
            (
                Language::JavaScript,
                "src/main.js",
                JS_READ_BEFORE_ESTABLISHMENT,
            ),
            (
                Language::TypeScript,
                "src/main.ts",
                TS_READ_BEFORE_ESTABLISHMENT,
            ),
        ] {
            let fixture = Fixture::new(language, &[(path, source)]);
            let state = fixture.state(0);
            let derivation = procedure_containing(
                &state,
                |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
            );
            assert!(
                derivation.completeness.is_complete(),
                "{language:?} must publish no gap for the plain-literal shape; got {:?}",
                derivation.completeness
            );
            for axis in FLOW_STATE_AXES {
                assert!(
                    derivation.completeness.covers(*axis),
                    "{language:?} must cover {axis:?}"
                );
            }
        }
    }

    const JS_ESCAPING_OBJECT: &str = r#"
function escapingObject(sink) {
  const ns = {};
  sink(ns);
  return ns.value;
}
"#;

    #[test]
    fn an_escaping_object_literal_keeps_the_axes_uncovered() {
        let fixture = Fixture::new(Language::JavaScript, &[("src/main.js", JS_ESCAPING_OBJECT)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::PropertyEvents),
            "an escaping base must keep the property axis uncovered; got {:?}",
            derivation.completeness
        );
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::PropertyReachingRelation)
        );
    }

    #[test]
    fn a_read_before_the_only_establishment_has_no_reaching_row() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_BEFORE_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        let reaching = relation_spellings(
            JS_READ_BEFORE_ESTABLISHMENT,
            derivation,
            FlowRelation::Reaching,
        );
        assert!(
            !reaching
                .iter()
                .any(|(source, target, _)| *source == "ns.value = 1" && *target == "ns.value"),
            "the later write must not reach the earlier read; got {reaching:?}"
        );
    }

    #[test]
    #[hardwon("#2014: return-position reads were not anchored on their identifier occurrence")]
    fn a_return_position_read_anchors_on_the_identifier_occurrence() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_BEFORE_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(JS_READ_BEFORE_ESTABLISHMENT, event) == "early"
        });
        let read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && matches!(&event.subject, FlowSubject::Binding { .. })
                    && spelling(JS_READ_BEFORE_ESTABLISHMENT, event) == "early"
            })
            .expect("the returned binding is read");
        let identifier_start = JS_READ_BEFORE_ESTABLISHMENT
            .rfind("early")
            .expect("the fixture returns the binding");
        assert_eq!(
            (read.site.range.start_byte, read.site.range.end_byte),
            (identifier_start, identifier_start + "early".len()),
            "the read must anchor on the returned identifier, not the statement"
        );
        assert!(
            read.site.ast_id.is_some(),
            "the identifier anchor must land on a facts-arena node so the RQLP join works"
        );
    }

    #[test]
    fn a_rebind_emits_a_kill_and_kills_the_earlier_establishment() {
        let fixture = Fixture::new(Language::JavaScript, &[("src/main.js", JS_SHADOW_REBIND)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(JS_SHADOW_REBIND, event) == "value = 3"
        });

        let kills = derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Kill)
            .map(|event| spelling(JS_SHADOW_REBIND, event))
            .collect::<Vec<_>>();
        assert!(
            kills.contains(&"value = 3"),
            "the rebind must emit a kill; got {kills:?}"
        );
        let establishes = derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Establish)
            .map(|event| spelling(JS_SHADOW_REBIND, event))
            .collect::<Vec<_>>();
        assert!(
            establishes.contains(&"value = 3"),
            "the rebind must also establish; got {establishes:?}"
        );

        let reaching = relation_spellings(JS_SHADOW_REBIND, derivation, FlowRelation::Reaching);
        let serving_the_final_read = reaching
            .iter()
            .filter(|(_, target, _)| *target == "value")
            .collect::<Vec<_>>();
        assert_eq!(
            serving_the_final_read,
            vec![&("value = 3", "value", FlowCertainty::Exact)],
            "only the rebind may serve the final read; got {reaching:?}"
        );
    }

    const GO_CALL_REASSIGNMENT: &str = r#"
package sample

func first() error { return nil }
func externalCall() error { return nil }

func overwrite(externalCall func() error) {
    err := first()
    err = externalCall()
    if err != nil { return }
}
"#;

    #[test]
    #[hardwon("f30141c8e280: opaque Go scalar calls failed to kill an earlier establishment")]
    fn a_go_scalar_call_reassignment_kills_the_earlier_establishment() {
        let fixture = Fixture::new(Language::Go, &[("main.go", GO_CALL_REASSIGNMENT)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_CALL_REASSIGNMENT, event) == "err = externalCall()"
        });
        let assignment_events = derivation
            .events
            .iter()
            .filter(|event| spelling(GO_CALL_REASSIGNMENT, event) == "err = externalCall()")
            .collect::<Vec<_>>();
        assert!(
            assignment_events
                .iter()
                .any(|event| event.event_class == StateEventClass::Establish),
            "the call assignment must establish the binding: {assignment_events:#?}"
        );
        assert!(
            assignment_events
                .iter()
                .any(|event| event.event_class == StateEventClass::Kill),
            "the call assignment must kill the prior definition: {assignment_events:#?}"
        );

        let guard_read = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_CALL_REASSIGNMENT, event) == "err"
            })
            .max_by_key(|event| event.site.range.start_byte)
            .expect("the later nil guard reads err");
        let reaching_guard = derivation
            .relations_of(FlowRelation::Reaching)
            .filter(|relation| relation.target_event == guard_read.event)
            .collect::<Vec<_>>();
        let [reaching_guard] = reaching_guard.as_slice() else {
            panic!("one definition must reach the later guard: {reaching_guard:#?}");
        };
        let reaching_source = derivation.event(reaching_guard.source_event);
        assert_eq!(
            spelling(GO_CALL_REASSIGNMENT, reaching_source),
            "err = externalCall()",
            "the earlier establishment must not survive the overwrite"
        );
        assert_eq!(reaching_guard.certainty, FlowCertainty::Exact);

        let procedure = fixture.procedure(0, derivation.procedure);
        let semantics = procedure.semantics();
        let converted = semantics
            .value(reaching_source.value)
            .expect("the establishment carries a published value");
        assert_eq!(
            converted.kind,
            SemanticValueKind::LanguageDefined("go.assignment_conversion".into()),
            "unproved conversion must not claim raw source identity"
        );
        let call = call_handle_spelled(&procedure, GO_CALL_REASSIGNMENT, "externalCall()");
        let raw_result = semantics
            .call_site(call.id())
            .and_then(|call| call.normal_result(0))
            .expect("the scalar call publishes one raw normal result");
        let conversion_sources = semantics
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .filter_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if target == reaching_source.value => Some(source),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            conversion_sources,
            vec![raw_result],
            "the opaque assignment value must retain exact structured dependence on the raw call result"
        );
        assert!(semantics.points().iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ValueFlow {
                        kind: crate::analyzer::semantic::ValueFlowKind::Local,
                        source,
                        target,
                    } if source == reaching_source.value
                        && target == reaching_source.subject.value()
                )
            })
        }));
        assert!(
            semantics
                .gaps()
                .iter()
                .all(|gap| gap.capability != SemanticCapability::Values),
            "the structured conversion dependence replaces a broad Values gap: {:#?}",
            semantics.gaps()
        );
    }

    const JS_SAME_ASSIGNMENT: &str = r#"
function wrap(value) {
  return value;
}

function sameAssignment(x) {
  x = wrap(x);
  return x;
}
"#;

    #[test]
    fn a_same_assignment_write_is_same_evaluation_with_its_own_read() {
        let fixture = Fixture::new(Language::JavaScript, &[("src/main.js", JS_SAME_ASSIGNMENT)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(JS_SAME_ASSIGNMENT, event) == "x = wrap(x)"
        });

        assert_write_consumes_its_read_in_one_evaluation(
            JS_SAME_ASSIGNMENT,
            derivation,
            "x = wrap(x)",
            "x",
        );

        let write = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(JS_SAME_ASSIGNMENT, event) == "x = wrap(x)"
            })
            .expect("the assignment establishes the parameter binding");
        let own_read = derivation
            .relations_of(FlowRelation::SameEvaluation)
            .filter(|row| row.source_event == write.event)
            .map(|row| row.target_event)
            .collect::<Vec<_>>();
        assert!(!own_read.is_empty());
        for read in own_read {
            assert!(
                !derivation
                    .relations_of(FlowRelation::Reaching)
                    .any(|row| { row.source_event == write.event && row.target_event == read }),
                "a write must never reach a read inside its own evaluation"
            );
        }
    }

    const JS_NAMESPACE_SELF_ASSIGNMENT: &str = r#"
function namespaceArtifact() {
  const ns = {};
  ns.a = ns;
  return ns.a.a;
}
"#;

    #[test]
    fn a_self_namespace_assignment_is_same_evaluation_with_its_own_read() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_NAMESPACE_SELF_ASSIGNMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(JS_NAMESPACE_SELF_ASSIGNMENT, event) == "ns.a = ns"
        });
        assert_write_consumes_its_read_in_one_evaluation(
            JS_NAMESPACE_SELF_ASSIGNMENT,
            derivation,
            "ns.a = ns",
            "ns",
        );
    }

    #[test]
    #[hardwon("eb52f52ac7d4: a copied Go aggregate alias was incorrectly treated as exact closure")]
    fn exact_local_value_alias_closure_keeps_go_aggregate_copy_open() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("go.mod", GO_MOD),
                ("app.go", GO_AGGREGATE_COPY_VALUE_ALIAS),
            ],
        );
        let state = fixture.state(1);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_AGGREGATE_COPY_VALUE_ALIAS, event) == "original := [1]*resource{}"
        });
        let procedure = fixture.procedure(1, derivation.procedure);
        let root = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_AGGREGATE_COPY_VALUE_ALIAS, event)
                        == "original := [1]*resource{}"
            })
            .expect("the fresh array value establishes original");
        let copied = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_AGGREGATE_COPY_VALUE_ALIAS, event) == "copied := original"
            })
            .expect("the array copy establishes its independent local");
        let source_read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read
                    && spelling(GO_AGGREGATE_COPY_VALUE_ALIAS, event) == "original"
            })
            .expect("the aggregate copy retains its ordinary source read");

        let closure = derivation
            .exact_local_value_alias_closure(&procedure, std::slice::from_ref(&root.event));
        assert!(
            closure.reads.contains(&source_read.event),
            "AggregateCopy remains ordinary exact data dependence"
        );
        assert!(
            !closure.establishments.contains(&copied.event),
            "independent array storage is not promoted as exact resource identity"
        );
        assert!(
            closure.unclosed_transfers.contains(&source_read.event),
            "the copied array remains a candidate-scoped identity frontier"
        );
        assert!(
            !closure.proof_open,
            "the structured closure itself remains available"
        );
    }

    #[test]
    #[hardwon("3ac44dca99bb: a may Go assignment conversion was treated as an exact alias")]
    fn exact_local_value_alias_closure_keeps_may_go_assignment_conversion_uncertain() {
        let fixture = Fixture::new(
            Language::Go,
            &[
                ("go.mod", GO_MOD),
                ("app.go", GO_MAY_ASSIGNMENT_CONVERSION_ALIAS),
            ],
        );
        let state = fixture.state(1);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
                && spelling(GO_MAY_ASSIGNMENT_CONVERSION_ALIAS, event) == "source := acquire()"
        });
        let procedure = fixture.procedure(1, derivation.procedure);
        let root = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_MAY_ASSIGNMENT_CONVERSION_ALIAS, event) == "source := acquire()"
            })
            .expect("the acquired value establishes source");
        let conversion = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(GO_MAY_ASSIGNMENT_CONVERSION_ALIAS, event)
                        == "converted any = source"
            })
            .expect("the converted value establishes its typed local");
        let conversion_source = procedure
            .semantics()
            .points()
            .iter()
            .flat_map(|point| &point.events)
            .find_map(|event| match event.effect {
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if target == conversion.value => Some(source),
                _ => None,
            })
            .expect("the typed initializer has an explicit assignment conversion");
        let conversion_source_read = derivation
            .events
            .iter()
            .find(|event| {
                event.event_class == StateEventClass::Read && event.value == conversion_source
            })
            .expect("the typed conversion reads source after the conditional replacement");

        let closure = derivation.exact_local_value_alias_closure(&procedure, &[root.event]);
        assert!(
            closure
                .uncertain_reads
                .contains(&conversion_source_read.event),
            "the original establishment may reach the conversion read"
        );
        assert!(
            closure
                .uncertain_transfers
                .contains(&conversion_source_read.event),
            "a May-reaching assignment conversion remains an uncertain identity transfer"
        );
    }

    const JS_MAY_LOCAL_VALUE_ALIAS: &str = r#"
function mayAlias(change, replacement) {
  let value = 1;
  if (change) {
    value = replacement;
  }
  const alias = value;
  return alias;
}
"#;

    #[test]
    #[hardwon("85e699d19f66: a may alias transfer was promoted to exact local closure")]
    fn exact_local_value_alias_closure_does_not_promote_a_may_transfer() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_MAY_LOCAL_VALUE_ALIAS)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(JS_MAY_LOCAL_VALUE_ALIAS, event) == "value = 1"
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let roots = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Establish
                    && spelling(JS_MAY_LOCAL_VALUE_ALIAS, event) == "value = 1"
            })
            .map(|event| event.event)
            .collect::<Vec<_>>();
        assert_eq!(roots.len(), 1, "one candidate establishment");

        let closure = derivation.exact_local_value_alias_closure(&procedure, &roots);
        assert_eq!(
            closure.establishments.len(),
            1,
            "a May-reaching source cannot establish an exact alias"
        );
        assert!(
            !closure.uncertain_transfers.is_empty(),
            "the candidate transfer remains explicitly open"
        );
    }

    const RUST_SCOPED_LOCAL_FLOW_GAP: &str = r#"
fn scoped_local_flow_gap() -> i32 {
    let value = 1;
    let (alias,) = (value,);
    alias
}
"#;

    #[test]
    #[hardwon("2dbc14570554: a scoped local-flow gap was lost during Go alias closure")]
    fn exact_local_value_alias_closure_keeps_a_scoped_local_flow_gap_open() {
        let fixture = Fixture::new(
            Language::Rust,
            &[("src/lib.rs", RUST_SCOPED_LOCAL_FLOW_GAP)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            event.event_class == StateEventClass::Establish
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        let root = derivation
            .events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Establish)
            .min_by_key(|event| event.site.range.start_byte)
            .expect("the plain local is established");

        let closure = derivation.exact_local_value_alias_closure(&procedure, &[root.event]);
        assert_eq!(
            closure.establishments.len(),
            1,
            "destructuring is not promoted to an exact alias"
        );
        assert!(
            !closure.unclosed_transfers.is_empty(),
            "the declaratively same-evaluation-blocking LocalFlow gap stays open"
        );
    }

    const RUBY_LOCAL_BINDER: &str = r#"
def local_binder(x)
  total = 0
  total + x
end
"#;

    #[test]
    #[hardwon(
        "#2906: partial Ruby heap assignment flow reported a false unsupported property axis"
    )]
    fn ruby_partial_field_memory_does_not_report_the_property_axis_unsupported() {
        let fixture = Fixture::new(Language::Ruby, &[("src/main.rb", RUBY_LOCAL_BINDER)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(RUBY_LOCAL_BINDER, event).contains("total")
        });
        let procedure = fixture.procedure(0, derivation.procedure);
        assert_eq!(
            procedure
                .artifact()
                .capabilities()
                .support(SemanticCapability::FieldMemory),
            CapabilitySupport::Partial,
            "Ruby must advertise the structured field-memory subset"
        );
        assert!(
            !derivation.completeness.reasons().contains(
                &FlowStateIncompleteReason::AxisUnsupported(FlowStateAxis::PropertyEvents)
            ),
            "got {:?}",
            derivation.completeness
        );
        assert!(
            derivation
                .completeness
                .covers(FlowStateAxis::PropertyEvents)
        );
        assert!(
            derivation
                .events
                .iter()
                .all(|event| matches!(&event.subject, FlowSubject::Binding { .. }))
        );
    }

    #[test]
    fn an_exhausted_cfg_budget_reports_the_relation_axes_incomplete() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state_with_budget(0, CfgAlgorithmBudget::uniform(1));
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        assert!(
            derivation
                .completeness
                .reasons()
                .iter()
                .any(|reason| matches!(reason, FlowStateIncompleteReason::BudgetExhausted { .. })),
            "got {:?}",
            derivation.completeness
        );
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::DominanceRelation)
        );
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::ReachingRelation)
        );
        assert_eq!(
            derivation.relations_of(FlowRelation::Reaching).count()
                + derivation.relations_of(FlowRelation::Dominates).count(),
            0,
            "an exhausted budget emits no partial relation rows"
        );
        assert!(
            !derivation.events.is_empty(),
            "events do not depend on the CFG algorithms"
        );
    }

    #[test]
    fn a_file_that_does_not_lower_reports_an_uncovered_result() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[
                ("src/main.js", JS_READ_AFTER_ESTABLISHMENT),
                ("notes.txt", "not a program\n"),
            ],
        );
        let state = fixture.state(1);
        let models = fixture.activate_models(GO_NONRETURN_MODEL);
        let modeled_state = fixture.state_with_active_models(1, &models);
        assert!(
            !state.completeness.is_complete(),
            "{:?}",
            state.completeness
        );
        for axis in FLOW_STATE_AXES {
            assert!(
                !state.completeness.covers(*axis),
                "{axis:?} must not be covered by a file that does not lower"
            );
        }
        assert_eq!(
            modeled_state.active_model_set_hash(),
            Some(models.active_models().active_model_set_hash()),
            "an early incomplete return retains the captured model identity"
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let first = fixture.state(0);
        let second = fixture.state(0);
        assert_eq!(first.procedures.len(), second.procedures.len());
        for (first, second) in first.procedures.iter().zip(second.procedures.iter()) {
            assert_eq!(first.events, second.events);
            assert_eq!(first.relations, second.relations);
            assert_eq!(
                format!("{:?}", first.completeness),
                format!("{:?}", second.completeness)
            );
        }
    }

    #[test]
    fn events_carry_the_arena_identity_and_the_generation() {
        let fixture = Fixture::new(
            Language::JavaScript,
            &[("src/main.js", JS_READ_AFTER_ESTABLISHMENT)],
        );
        let state = fixture.state(0);
        let derivation = procedure_containing(
            &state,
            |event| matches!(&event.subject, FlowSubject::Property { member, .. } if &**member == "value"),
        );
        assert!(!derivation.events.is_empty());
        for event in &derivation.events {
            assert_eq!(event.generation, state.generation);
            assert_eq!(event.procedure, derivation.procedure);
            assert!(event.site.range.start_byte < event.site.range.end_byte);
        }
        assert!(
            derivation
                .events
                .iter()
                .any(|event| event.site.ast_id.is_some()),
            "at least one event must land on a facts-arena node"
        );
    }

    /// The `f` property events of the one procedure that has any, as
    /// (class, subject base, spelling).
    fn f_property_events<'a>(
        state: &FileFlowState,
        source: &'a str,
    ) -> Vec<(StateEventClass, ValueId, &'a str)> {
        let rows = state
            .procedures
            .iter()
            .flat_map(|derivation| derivation.events.iter())
            .filter_map(|event| match &event.subject {
                FlowSubject::Property { base, member } if member.as_ref() == "f" => {
                    Some((event.event_class, *base, spelling(source, event)))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!rows.is_empty(), "the source has `f` property events");
        rows
    }

    fn base_of(
        rows: &[(StateEventClass, ValueId, &str)],
        class: StateEventClass,
        spelled: &str,
    ) -> ValueId {
        let mut matching = rows
            .iter()
            .filter(|(row_class, _, row_spelling)| *row_class == class && *row_spelling == spelled);
        let (_, base, _) = matching
            .next()
            .unwrap_or_else(|| panic!("{class:?} event spelled {spelled:?} in {rows:?}"));
        assert!(
            matching.all(|(_, other, _)| other == base),
            "{class:?} events spelled {spelled:?} share one base in {rows:?}"
        );
        *base
    }

    #[test]
    #[hardwon(
        "#13211: struct-literal field establish events were silently dropped by uncanonical allocation bases"
    )]
    fn struct_literal_fields_present_as_the_binding_that_solely_holds_it() {
        const SOURCE: &str = "struct Meta { f: i32 }\n\
            fn held() -> i32 { let mut m = Meta { f: 1 }; m.f = 2; m.f }";
        let fixture = Fixture::new(Language::Rust, &[("sample.rs", SOURCE)]);
        let state = fixture.state(0);
        let rows = f_property_events(&state, SOURCE);
        let binding = state
            .procedures
            .iter()
            .flat_map(|derivation| derivation.events.iter())
            .find_map(|event| match event.subject {
                FlowSubject::Binding { value }
                    if event.event_class == StateEventClass::Establish =>
                {
                    Some(value)
                }
                _ => None,
            })
            .expect("`m` is established");
        let literal = base_of(&rows, StateEventClass::Establish, "Meta { f: 1 }");
        assert_eq!(literal, binding, "the literal's slot is `m`'s slot");
        assert_eq!(
            base_of(&rows, StateEventClass::Establish, "m.f = 2"),
            binding
        );
        assert_eq!(base_of(&rows, StateEventClass::Read, "m.f"), binding);
        assert!(
            rows.iter()
                .any(|(class, base, _)| *class == StateEventClass::Kill && *base == binding),
            "the overwrite kills the literal's definition: {rows:?}"
        );
    }

    #[test]
    fn struct_literals_that_are_not_solely_held_keep_distinct_subjects() {
        for (source, literals) in [
            (
                "struct Meta { f: i32 }\n\
                 fn two() -> i32 { let a = Meta { f: 1 }; let b = Meta { f: 2 }; a.f + b.f }",
                ["Meta { f: 1 }", "Meta { f: 2 }"],
            ),
            (
                "struct Meta { f: i32 }\n\
                 fn unbound() { let _t = (Meta { f: 1 }, Meta { f: 2 }); }",
                ["Meta { f: 1 }", "Meta { f: 2 }"],
            ),
            (
                "struct Meta { f: i32 }\n\
                 fn reassigned() { let mut x = Meta { f: 1 }; x = Meta { f: 2 }; }",
                ["Meta { f: 1 }", "Meta { f: 2 }"],
            ),
            (
                "struct Meta { f: i32 }\n\
                 fn conditional(c: bool) { let _x = if c { Meta { f: 1 } } else { Meta { f: 2 } }; }",
                ["Meta { f: 1 }", "Meta { f: 2 }"],
            ),
            (
                "struct Meta { f: i32 }\n\
                 fn consume(_m: Meta) {}\n\
                 fn moved() -> Meta { consume(Meta { f: 1 }); Meta { f: 2 } }",
                ["Meta { f: 1 }", "Meta { f: 2 }"],
            ),
        ] {
            let fixture = Fixture::new(Language::Rust, &[("sample.rs", source)]);
            let state = fixture.state(0);
            let rows = f_property_events(&state, source);
            let first = base_of(&rows, StateEventClass::Establish, literals[0]);
            let second = base_of(&rows, StateEventClass::Establish, literals[1]);
            assert_ne!(first, second, "{source}: {rows:?}");
        }
    }

    #[test]
    fn captured_or_addressed_holder_does_not_absorb_the_literal() {
        for source in [
            "struct Meta { f: i32 }\n\
             fn captured() -> i32 { let m = Meta { f: 1 }; let c = || m.f; c() }",
            "struct Meta { f: i32 }\n\
             fn addressed() -> i32 { let m = Meta { f: 1 }; let r = &m; r.f }",
        ] {
            let fixture = Fixture::new(Language::Rust, &[("sample.rs", source)]);
            let state = fixture.state(0);
            let rows = f_property_events(&state, source);
            let literal = base_of(&rows, StateEventClass::Establish, "Meta { f: 1 }");
            let binding = state
                .procedures
                .iter()
                .flat_map(|derivation| derivation.events.iter())
                .find_map(|event| match event.subject {
                    FlowSubject::Binding { value }
                        if event.event_class == StateEventClass::Establish
                            && spelling(source, event).starts_with("let m") =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .expect("`m` is established");
            assert_ne!(literal, binding, "{source}");
        }
    }

    /// `let m = Meta { f: 1 }; m.f` copies the literal's field into `m.f` at
    /// the `let` point. That self-copy is not a source access: it emits no
    /// event, kills nothing, and the reaching and dominance rows and the
    /// selected proof still run from the literal's store to the later read.
    #[test]
    fn struct_literal_self_copy_is_skipped_and_flows_forward() {
        const SOURCE: &str = "struct Meta { f: i32 }\n\
            fn build() -> i32 { let m = Meta { f: 1 }; m.f }";
        let fixture = Fixture::new(Language::Rust, &[("sample.rs", SOURCE)]);
        let outcome = fixture.materialized(0);
        let artifact = outcome.available_value().cloned().expect("Rust artifact");
        let token = CancellationToken::default();
        let state = flow_state_for_materialized_artifact(
            &fixture.workspace,
            &fixture.files[0],
            outcome,
            &mut test_request(&token),
        );
        let derivation = state
            .procedures
            .iter()
            .find(|derivation| {
                derivation.events.iter().any(|event| {
                    matches!(&event.subject, FlowSubject::Property { member, .. } if member.as_ref() == "f")
                })
            })
            .expect("`build` has property events");
        // This inline fixture is not a Cargo crate, so it lacks the crate-wide
        // Drop absence proof and its derivation carries Drop lowering gaps.
        // The field-access golden rust-state-events pins completeness.
        let property_events = derivation
            .events
            .iter()
            .filter(|event| matches!(&event.subject, FlowSubject::Property { .. }))
            .collect::<Vec<_>>();
        let count = |class| {
            property_events
                .iter()
                .filter(|event| event.event_class == class)
                .count()
        };
        assert_eq!(count(StateEventClass::Establish), 1, "{property_events:?}");
        assert_eq!(count(StateEventClass::Read), 1, "{property_events:?}");
        assert_eq!(count(StateEventClass::Kill), 0, "{property_events:?}");
        let establish = property_events
            .iter()
            .find(|event| event.event_class == StateEventClass::Establish)
            .expect("establish");
        let read = property_events
            .iter()
            .find(|event| event.event_class == StateEventClass::Read)
            .expect("read");
        assert_eq!(establish.subject, read.subject);
        // The oracle reaches the read from two non-killing candidate stores,
        // the literal's initializer and the copy, so the literal's row is
        // `May`. Forwarding the copy reaches the same pair again; it must merge
        // into one row, never a second one or a stronger certainty.
        let pair_rows = |relation| {
            derivation
                .relations
                .iter()
                .filter(|row| {
                    row.relation == relation
                        && row.source_event == establish.event
                        && row.target_event == read.event
                })
                .collect::<Vec<_>>()
        };
        let reaching = pair_rows(FlowRelation::Reaching);
        assert_eq!(
            reaching.len(),
            1,
            "one Reaching row from the literal store to the read: {:?}",
            derivation.relations
        );
        let dominates = pair_rows(FlowRelation::Dominates);
        assert!(
            dominates.len() == 1 && dominates[0].certainty == FlowCertainty::Exact,
            "one Exact Dominates row from the literal store to the read: {:?}",
            derivation.relations
        );
        let procedure = artifact
            .procedure_handle(derivation.procedure)
            .expect("procedure");
        let selected = flow_state_for_selected_property(
            &fixture.workspace,
            &fixture.files[0],
            &state,
            &procedure,
            read.point,
            &mut test_request(&token),
        );
        // The selected proof carries the fixture's cleanup Drop gap, so its
        // coverage is not asserted here (see the comment above).
        let selected = &selected.procedures[0];
        let selected_reaching = selected
            .relations
            .iter()
            .filter(|row| {
                row.relation == FlowRelation::Reaching
                    && row.source_event == establish.event
                    && row.target_event == read.event
            })
            .collect::<Vec<_>>();
        assert!(
            selected_reaching.len() == 1 && selected_reaching[0].certainty == reaching[0].certainty,
            "the selected proof has the derivation's one Reaching row: {:?}",
            selected.relations
        );
    }
}
