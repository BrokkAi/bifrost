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
//! The production semantic IR (`crate::analyzer::semantic`) is the *only*
//! evidence source. There is no lexical, textual, or source-order fallback
//! anywhere in this module, by construction: nothing here reads source order,
//! containment, or spelling to decide a relation. Where the lowering does not
//! model an axis, this layer reports that axis uncovered rather than
//! approximating it -- the same per-axis completeness contract the canonical
//! reference-edge layer ([`super::reference_edges`]) established for #1479.
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

use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, DenseBidirectionalGraph,
    Dominators, GenKillFacts, ReachingSets, dominators, forward_reachability, reaching_definitions,
};
use crate::analyzer::semantic::{
    CallSiteHandle, CallSiteId, CallToReturnModel, CallTransferSet, CandidateCoverage,
    CapabilitySupport, ContentIdentity, ControlContinuation, ControlEdgeHandle, ControlEdgeId,
    ControlEdgeKind, IcfgProvider, LengthDelimitedDigest, MemoryAccessKind, MemoryLocationId,
    MemoryLocationKind, ProcedureHandle, ProcedureId, ProcedureSemantics, ProgramPointHandle,
    ProgramPointId, ProofStatus, SemanticArtifact, SemanticArtifactKey, SemanticBudget,
    SemanticCallSite, SemanticCapabilities, SemanticCapability, SemanticEffect, SemanticGap,
    SemanticGapDischarge, SemanticGapId, SemanticGapImpact, SemanticGapKind, SemanticGapSubject,
    SemanticLocator, SemanticOutcome, SemanticRequest, SemanticValueKind, SemanticWork,
    SourceMappingId, SourceMappingKind, SourceSpan, ValueFlowKind, ValueId, WorkspaceIcfgProvider,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, ProcedureSummaryMemberKey, ResolvedActiveSemanticModels,
};
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
use brokk_bifrost_core::profiling;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};

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
            let masked_graph = MaskedProcedureGraph::new(semantics, mask);
            let $graph = &masked_graph;
            $body
        }
    }};
}

pub use brokk_bifrost_core::analyzer::structural::flow_state::{
    ALL_FLOW_STATE_AXES as FLOW_STATE_AXES, FlowCertainty, FlowRelation, FlowStateAxis,
    FlowSubjectKind, StateEventClass,
};

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
    digest.push(procedure.artifact().key().public_fingerprint().as_bytes());
    digest.push(b"program_point");
    push_locator(&mut digest, procedure.semantics().locator());
    digest.push(&handle.id().get().to_le_bytes());
    push_locator(&mut digest, &mapping.locator);
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

fn push_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    digest.push(locator.path().as_str().as_bytes());
    digest.push(locator.language().stable_label().as_bytes());
    digest.push(locator.role().stable_label().as_bytes());
    digest.push_anchor(locator.anchor());
    for segment in locator.declaration().segments() {
        digest.push(segment.kind().stable_label().as_bytes());
        match segment.name() {
            Some(name) => {
                digest.push(b"named");
                digest.push(name.as_bytes());
            }
            None => digest.push(b"anonymous"),
        }
        digest.push_anchor(segment.anchor());
        digest.push(&segment.sibling_ordinal().to_le_bytes());
    }
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
        /// The binding the IR's own value flow says the field base holds.
        base: ValueId,
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

    /// The lowered value this subject is identified by: the binding itself, or
    /// the canonical base a property hangs off.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        capability: SemanticCapability,
        kind: SemanticGapKind,
        detail: String,
    },
    /// A CFG algorithm ran out of its request budget. Truncation is never
    /// silent: the affected relation emits no rows at all.
    BudgetExhausted { axis: FlowStateAxis, detail: String },
    /// A field access whose base value the IR does not flow from any binding.
    /// Such an access has no stable property subject, so it contributes no
    /// event rather than an approximated one.
    PropertyBaseNotCanonical { accesses: usize },
    /// The lowering declares a local binding it never establishes, so reads of
    /// that binding have no establishment to reach them in this artifact and
    /// their absence is unknown, not proven.
    BindingWithoutEstablishment { bindings: usize },
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
            LoweringGap { capability, .. } => axes_blocked_by(*capability).contains(&axis),
            PropertyBaseNotCanonical { .. } => axis == FlowStateAxis::PropertyEvents,
            BindingWithoutEstablishment { .. } => {
                axis != FlowStateAxis::PropertyEvents && axis != FlowStateAxis::DominanceRelation
            }
            ControlProjectionRejected { .. } | ModeledControlProjectionIncomplete { .. } => {
                matches!(
                    axis,
                    FlowStateAxis::ReachingRelation | FlowStateAxis::DominanceRelation
                )
            }
            NoSemanticProvider
            | SemanticProviderFailed { .. }
            | SemanticAnalysisPartial { .. }
            | Cancelled
            | SourceGenerationChanged
            | NoStructuralFacts => true,
        }
    }
}

/// Which axes one gap capability blocks.
///
/// Total over the capability registry on purpose: a capability added later
/// must be classified deliberately, not defaulted into silence.
fn axes_blocked_by(capability: SemanticCapability) -> &'static [FlowStateAxis] {
    use SemanticCapability::*;
    const CONTROL: &[FlowStateAxis] = &[
        FlowStateAxis::ReachingRelation,
        FlowStateAxis::DominanceRelation,
    ];
    const BINDINGS: &[FlowStateAxis] = &[
        FlowStateAxis::BindingEvents,
        FlowStateAxis::SameEvaluationRelation,
    ];
    const PROPERTIES: &[FlowStateAxis] = &[
        FlowStateAxis::PropertyEvents,
        FlowStateAxis::SameEvaluationRelation,
    ];
    const EVALUATION: &[FlowStateAxis] = &[FlowStateAxis::SameEvaluationRelation];
    // A published `GuardFacts` gap says a decision's condition was not
    // normalized, which is a statement about which successor executes, so it
    // leaves the two control-shaped axes open exactly as the other
    // control-flow capabilities do.
    match capability {
        GuardFacts
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
        Calls | DynamicDispatch | CallableReferences | Captures => EVALUATION,
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
    pub fn event(&self, event: usize) -> &StateEventRow {
        &self.events[event]
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
    /// being promoted to an alias.
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
            axes_blocked_by(gap.capability).contains(&FlowStateAxis::SameEvaluationRelation)
                && !matches!(
                    gap.capability,
                    SemanticCapability::Calls
                        | SemanticCapability::DynamicDispatch
                        | SemanticCapability::CallableReferences
                )
                && gap.impacts.contains(SemanticGapImpact::ValueFlow)
                && matches!(
                    gap.discharge,
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
                        MemoryLocationKind::Field { .. } => {
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            // Partial artifacts are not globally cached. A second materialization
            // can therefore share a durable key while exposing different rows.
            // It is an honest unavailable proof, not an interchangeable CFG.
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
        let control_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| {
                axes_blocked_by(gap.capability).contains(&FlowStateAxis::DominanceRelation)
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            return None;
        }
        let semantics = procedure.semantics();
        let dominance = self.dominance.as_ref()?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .chain(candidates)
                .chain(targets)
                .any(|point| semantics.point(*point).is_none())
            || self.completeness.reasons().iter().any(|reason| {
                reason.blocks(FlowStateAxis::DominanceRelation)
                    && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
            })
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
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

        let candidate_edges = validated_guard_edges(procedure, candidates)?;

        let control_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| {
                axes_blocked_by(gap.capability).contains(&FlowStateAxis::DominanceRelation)
                    && !matches!(
                        gap.discharge,
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            return None;
        }
        let semantics = procedure.semantics();
        let dominance = self.dominance.as_ref()?;
        if result_establishments.is_empty()
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            return None;
        }
        let semantics = procedure.semantics();
        let dominance = self.dominance.as_ref()?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || semantics.point(candidate_point).is_none()
            || targets
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || self.result_flow_has_hard_hole()
            || self.completeness.reasons().iter().any(|reason| {
                reason.blocks(FlowStateAxis::DominanceRelation)
                    && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
            })
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
        if self.procedure != procedure.id()
            || !Weak::ptr_eq(&self.procedure_artifact, &procedure_artifact)
        {
            return None;
        }
        let semantics = procedure.semantics();
        let dominance = self.dominance.as_ref()?;
        if result_establishments.is_empty()
            || result_establishments
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || targets
                .iter()
                .any(|point| semantics.point(*point).is_none())
            || self.completeness.reasons().iter().any(|reason| {
                reason.blocks(FlowStateAxis::DominanceRelation)
                    && !matches!(reason, FlowStateIncompleteReason::LoweringGap { .. })
            })
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
        let procedure_artifact = Arc::downgrade(procedure.artifact());
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
                axes_blocked_by(gap.capability).contains(&FlowStateAxis::DominanceRelation)
                    && gap.discharge != SemanticGapDischarge::RetainedControlTopology
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
                                gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder
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
                                            || (gap.discharge
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
                gap.discharge != SemanticGapDischarge::RetainedEvaluationOrder
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
                && match gap.discharge {
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
                    SemanticGapDischarge::CanonicalIndexIdentity => true,
                    SemanticGapDischarge::None | SemanticGapDischarge::CallResolution => true,
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
            gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder
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
    if gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion {
        // Completion may run arbitrary active cleanup/deferred code and can
        // therefore observe captured result values unrelated to the local
        // operation that triggered the exit. Its point/value subject scopes
        // the omitted exceptional transfer, not all values that completion
        // code can read.
        return true;
    }
    match gap.subject {
        SemanticGapSubject::Procedure => {
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
        SemanticGapSubject::MemoryLocation(location) => semantics
            .memory_location(location)
            .is_some_and(|memory| match memory.kind {
                MemoryLocationKind::Field { base, .. } => {
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

    if indirect_address_write_points(semantics, &address_aliases).any(|write| {
        result_origins.iter().any(|origin| {
            derivation.point_reaches(semantics, *origin, write, true)
                && observations.iter().any(|observation| {
                    derivation.point_reaches(semantics, write, *observation, false)
                })
        })
    }) {
        return false;
    }

    !address_escape_points(semantics, &address_aliases)
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
                MemoryLocationKind::Field { base, .. } | MemoryLocationKind::Index { base, .. } => {
                    relevant_values.contains(&base)
                }
                MemoryLocationKind::LexicalCell { binding } => relevant_values.contains(&binding),
                // A child capture slot does not identify its parent value.
                // Static storage has no binding value to confuse with one.
                MemoryLocationKind::Capture { .. } => true,
                MemoryLocationKind::Static { .. } => false,
            })
    };
    match gap.subject {
        SemanticGapSubject::Value(value) => value_may_involve_bindings(value),
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
        SemanticGapSubject::Procedure
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
    if indirect_address_write_points(semantics, &address_aliases).any(|write| {
        point_reaches(graph, origin, write, true) && point_reaches(graph, write, observation, false)
    }) {
        return false;
    }
    if address_escape_points(semantics, &address_aliases)
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
            && matches!(gap.subject, SemanticGapSubject::Value(value) if value == binding)
            && point_reaches(graph, origin, gap.point, true)
            && point_reaches(graph, gap.point, observation, true)
    })
}

fn indirect_address_write_points<'a>(
    semantics: &'a ProcedureSemantics,
    address_aliases: &'a HashSet<ValueId>,
) -> impl Iterator<Item = ProgramPointId> + 'a {
    semantics.gaps().iter().filter_map(|gap| {
        (gap.capability == SemanticCapability::Assignments
            && gap.impacts.contains(SemanticGapImpact::HeapWrite))
        .then_some(gap.subject)
        .and_then(|subject| match subject {
            SemanticGapSubject::Value(value) if address_aliases.contains(&value) => Some(gap.point),
            _ => None,
        })
    })
}

fn address_escape_points(
    semantics: &ProcedureSemantics,
    address_aliases: &HashSet<ValueId>,
) -> HashSet<ProgramPointId> {
    let mut escape_points = semantics
        .call_sites()
        .iter()
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
                    | MemoryLocationKind::Index { base, .. }
                        if address_aliases.contains(&base) =>
                    {
                        Some(capture.point)
                    }
                    MemoryLocationKind::Static { .. }
                    | MemoryLocationKind::Capture { .. }
                    | MemoryLocationKind::LexicalCell { .. }
                    | MemoryLocationKind::Field { .. }
                    | MemoryLocationKind::Index { .. } => None,
                }),
        }
    }));
    escape_points.extend(semantics.points().iter().flat_map(|point| {
        point.events.iter().filter_map(|event| match event.effect {
            SemanticEffect::MemoryStore { value, .. } if address_aliases.contains(&value) => {
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

fn address_alias_values(
    semantics: &ProcedureSemantics,
    relevant_values: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    // Address creation is represented by the existing structured Assignment
    // into a typed Address result. Seed only from a directly tracked source:
    // ordinary value propagation before `&` copies a value, not its binding
    // identity. From the exact Address seed, assignments and value-flow events
    // do preserve the escaping reference identity.
    let mut aliases = semantics
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| match event.effect {
            SemanticEffect::Assignment { target, value }
                if relevant_values.contains(&value)
                    && semantics
                        .value(target)
                        .is_some_and(|value| value.kind == SemanticValueKind::Address) =>
            {
                Some(target)
            }
            _ => None,
        })
        .collect::<HashSet<_>>();
    loop {
        let mut changed = false;
        for point in semantics.points() {
            for event in &point.events {
                let (source, target) = match event.effect {
                    SemanticEffect::Assignment { target, value } => (value, target),
                    SemanticEffect::ValueFlow { source, target, .. } => (source, target),
                    _ => continue,
                };
                if aliases.contains(&source) && aliases.insert(target) {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    aliases
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
                && gap.discharge == SemanticGapDischarge::CallResolution
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
        SemanticGapSubject::Procedure
        | SemanticGapSubject::Point
        | SemanticGapSubject::Value(_)
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
                    gap.discharge,
                    SemanticGapDischarge::NonRejoiningExceptionalExit
                        | SemanticGapDischarge::ExitOnlyProcedureCompletion
                )
                && discharge_blocks(gap.discharge)
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
            axes_blocked_by(gap.capability).contains(&FlowStateAxis::DominanceRelation)
                && discharge_blocks(gap.discharge)
                && !(gap.subject != SemanticGapSubject::Procedure
                    && matches!(
                        gap.discharge,
                        SemanticGapDischarge::NonRejoiningExceptionalExit
                            | SemanticGapDischarge::ExitOnlyProcedureCompletion
                    )
                    && (gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
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
                        && dominance.dominates(graph, candidate, gap.point)
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
                    let non_rejoining_strictly_after_candidate = gap.discharge
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
    let reachable_without_candidate = candidates
        .iter()
        .map(|candidate| {
            reachable_points_without_edge(graph, semantics.entry_point(), candidate.id)
        })
        .collect::<Vec<_>>();
    let non_rejoining_gaps_outside_target_history =
        non_rejoining_gaps_that_cannot_reach_targets(graph, targets, control_gaps);

    targets
        .iter()
        .map(|target| {
            candidates.iter().enumerate().any(|(index, candidate)| {
                if !dominance.dominates(graph, candidate.target, *target)
                    || reachable_without_candidate[index].contains(target)
                {
                    return false;
                }
                control_gaps.iter().all(|gap| {
                    if gap.subject == SemanticGapSubject::Procedure {
                        return false;
                    }
                    let candidate_precedes_gap =
                        dominance.dominates(graph, candidate.target, gap.point)
                            && !reachable_without_candidate[index].contains(&gap.point);
                    let non_rejoining_gap_cannot_reach_target = gap.discharge
                        == SemanticGapDischarge::NonRejoiningExceptionalExit
                        && non_rejoining_gaps_outside_target_history.contains(&(*target, gap.id));
                    candidate_precedes_gap || non_rejoining_gap_cannot_reach_target
                })
            })
        })
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
                && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
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
                && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit
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
                    gap.discharge,
                    SemanticGapDischarge::NonRejoiningExceptionalExit
                        | SemanticGapDischarge::ExitOnlyProcedureCompletion
                )
        })
        .collect::<Vec<_>>();
    let exit_only_gaps = gaps
        .iter()
        .filter(|gap| gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion)
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
    let mut reachable = std::iter::once(origin).collect::<HashSet<_>>();
    let mut stack = vec![origin];
    while let Some(point) = stack.pop() {
        for (_, target) in graph.successors(point) {
            if reachable.insert(target) {
                debug_assert!(reachable.len() <= graph.node_count());
                stack.push(target);
            }
        }
    }
    reachable
}

fn points_reaching<G>(graph: &G, target: ProgramPointId) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut reaching = std::iter::once(target).collect::<HashSet<_>>();
    let mut stack = vec![target];
    while let Some(point) = stack.pop() {
        for (_, predecessor) in graph.predecessors(point) {
            if reaching.insert(predecessor) {
                debug_assert!(reaching.len() <= graph.node_count());
                stack.push(predecessor);
            }
        }
    }
    reaching
}

fn reachable_points_without_edge<G>(
    graph: &G,
    entry: ProgramPointId,
    excluded: ControlEdgeId,
) -> HashSet<ProgramPointId>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut reachable = std::iter::once(entry).collect::<HashSet<_>>();
    let mut stack = vec![entry];
    while let Some(point) = stack.pop() {
        for (edge_id, target) in graph.successors(point) {
            if edge_id != excluded && reachable.insert(target) {
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
    ) -> Self {
        Self {
            procedures: Vec::new(),
            completeness: FlowStateCompleteness::Incomplete { reasons },
            generation,
            active_model_set_hash,
        }
    }

    /// The exact activated-model identity captured by this request.
    pub fn active_model_set_hash(&self) -> Option<&str> {
        self.active_model_set_hash.as_deref()
    }
}

/// Borrowed controls for one derivation.
#[derive(Debug)]
pub struct FlowStateRequest<'request> {
    pub cancellation: &'request CancellationToken,
    /// The CFG-algorithm budget stays crate-private: it is this crate's own
    /// work vocabulary, and an out-of-crate caller configures a derivation
    /// through [`FlowStateRequest::new`], not by naming budget dimensions.
    pub(crate) cfg_budget: CfgAlgorithmBudget,
    control_projection: Option<&'request FlowControlProjection>,
    /// Outer `None` means this raw derivation did not select semantic models.
    /// `Some(None)` deliberately freezes no publication; `Some(Some(_))`
    /// freezes the exact active/overlay pair selected by the request owner.
    active_semantic_model_snapshot: Option<Option<Arc<ActiveSemanticModelSnapshot>>>,
}

impl<'request> FlowStateRequest<'request> {
    pub fn new(cancellation: &'request CancellationToken) -> Self {
        Self {
            cancellation,
            cfg_budget: CfgAlgorithmBudget::default(),
            control_projection: None,
            active_semantic_model_snapshot: None,
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
        self.active_semantic_model_snapshot = Some(snapshot);
        self
    }
}

/// Cheap discovery filter only. The runtime owns the reusable effective-owner
/// index; exact dispatch plus exact-arity runtime agreement remain the positive
/// evidence below.
fn normal_continuation_absence_may_name(
    models: &ResolvedActiveSemanticModels,
    shape: &CallShapeReport,
) -> bool {
    [false, true]
        .into_iter()
        .any(|has_receiver| normal_continuation_absence_accepts(models, shape, has_receiver))
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
    models
        .normal_continuation_absence_candidate_owners(language, member, has_receiver)
        .iter()
        .any(|owner| {
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
struct WorkspaceNonreturnCall {
    call: CallSiteId,
    transfers: CallTransferSet,
}

/// Request-local control evidence for one procedure reached from the file
/// being derived. Handles keep every dense ID scoped to its exact immutable
/// artifact; nothing in this proof is persisted across requests.
struct WorkspaceNonreturnProcedure {
    handle: ProcedureHandle,
    exact_call_resolutions: HashSet<CallSiteId>,
    nonreturn_candidates: Vec<WorkspaceNonreturnCall>,
    abort_path_user_code: WorkspaceAbortPathUserCode,
    incomplete_detail: Option<Box<str>>,
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
            for call in procedure.call_sites() {
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
    ) || !lookup.adjudicable_workspace_names.is_empty()
    {
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
    let edges = procedure
        .successor_edges(call.point)
        .filter_map(|(edge_id, edge)| {
            (edge.kind == ControlEdgeKind::Normal && edge.target_point == target).then_some(edge_id)
        })
        .collect::<Vec<_>>();
    if edges.len() != 1 {
        return Err(format!(
            "call {:?} normal continuation maps to {} exact normal edges: {edges:?}",
            call.id,
            edges.len()
        ));
    }
    Ok(Some(edges[0]))
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
    if !models.has_normal_continuation_absence_candidates(Language::Go.config_label())
        || cancellation.is_cancelled()
    {
        return ModeledControlProjectionDerivation::default();
    }

    let shapes = call_shapes_in_file(facts, file, facts.nodes().len());
    let call_spans = SemanticCallSpanIndex::build(artifact, requested_procedure);
    let candidate_shapes = shapes
        .iter()
        .filter(|shape| normal_continuation_absence_may_name(models, shape))
        // `go` and unsupported `defer` intentionally retain their outer
        // structural call shape but emit no synchronous semantic call site.
        // There is no caller edge to project, so they are an inapplicable
        // shape rather than file-wide modeled-control incompleteness.
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
            || !lookup.adjudicable_workspace_names.is_empty()
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
        .filter(|call| reachable.contains(semantics, call.point))
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
    if gap.discharge != SemanticGapDischarge::CallResolution {
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
    with_control_graph!(semantics, &mask, |graph| {
        let mut algorithm_request = CfgAlgorithmRequest::new(cfg_budget, cancellation);
        let reachable =
            match forward_reachability(graph, semantics.entry_point(), &mut algorithm_request) {
                Ok(reachable) => reachable,
                Err(error) => {
                    return match workspace_nonreturn_cfg_interruption(
                        &handle,
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
            procedure.abort_path_user_code,
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
            match procedure.abort_path_user_code {
                WorkspaceAbortPathUserCode::NotRelevant => false,
                WorkspaceAbortPathUserCode::Computed(runs_user_code) => runs_user_code,
                WorkspaceAbortPathUserCode::Uncomputed => {
                    let mut algorithm_request = CfgAlgorithmRequest::new(cfg_budget, cancellation);
                    match crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code_bounded(
                        semantics,
                        &mut algorithm_request,
                    ) {
                        Ok(runs_user_code) => {
                            procedure.abort_path_user_code =
                                WorkspaceAbortPathUserCode::Computed(runs_user_code);
                            runs_user_code
                        }
                        Err(error) => {
                            return match workspace_nonreturn_cfg_interruption(
                                &handle,
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
                    &procedure.exact_call_resolutions,
                    abort_paths_run_user_code,
                )
        });
        if has_undischarged_gap {
            // A later callee proof may remove the only route to this gap.
            // Keep it pending; the reverse-dependency queue will revisit this
            // procedure only when one of its candidate callees changes state.
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
    snapshot: &Arc<ActiveSemanticModelSnapshot>,
    semantic_budget: &mut SemanticBudget,
    cfg_budget: &mut CfgAlgorithmBudget,
    cancellation: &CancellationToken,
) -> ModeledControlProjectionDerivation {
    if crate::analyzer::common::language_for_file(file) != Language::Go
        || !snapshot
            .active_models()
            .has_normal_continuation_absence_candidates(Language::Go.config_label())
        || cancellation.is_cancelled()
    {
        return ModeledControlProjectionDerivation::default();
    }

    let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot(
        workspace,
        Some(Arc::clone(snapshot)),
    );
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
    let mut scheduled = roots.iter().cloned().collect::<HashSet<_>>();
    let mut pending = roots.into_iter().collect::<VecDeque<_>>();
    let mut procedures = Vec::new();
    while let Some(handle) = pending.pop_front() {
        if cancellation.is_cancelled() {
            return ModeledControlProjectionDerivation::default();
        }
        let (procedure, callees) = match discover_workspace_nonreturn_procedure(
            &provider,
            artifact,
            handle,
            semantic_budget,
            cfg_budget,
            cancellation,
        ) {
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

    let mut proven = HashSet::default();
    let mut incomplete = HashSet::default();
    let mut incomplete_reasons: HashMap<ProcedureHandle, HashSet<Box<str>>> = HashMap::default();
    let mut evaluation_pending = (0..procedures.len()).collect::<VecDeque<_>>();
    let mut evaluation_queued = vec![true; procedures.len()];
    while let Some(index) = evaluation_pending.pop_front() {
        evaluation_queued[index] = false;
        if cancellation.is_cancelled() {
            return ModeledControlProjectionDerivation::default();
        }
        let handle = procedures[index].handle.clone();
        if proven.contains(&handle) || incomplete.contains(&handle) {
            continue;
        }
        match evaluate_workspace_nonreturn_procedure(
            &mut procedures[index],
            &proven,
            cfg_budget,
            cancellation,
        ) {
            WorkspaceNonreturnEvaluation::Proven => {
                proven.insert(handle.clone());
                for caller in callers.get(&handle).into_iter().flatten().copied() {
                    if !evaluation_queued[caller] {
                        evaluation_queued[caller] = true;
                        evaluation_pending.push_back(caller);
                    }
                }
            }
            WorkspaceNonreturnEvaluation::Pending => {}
            WorkspaceNonreturnEvaluation::Incomplete(detail) => {
                incomplete.insert(handle.clone());
                incomplete_reasons.entry(handle).or_default().insert(detail);
            }
            WorkspaceNonreturnEvaluation::Cancelled => {
                return ModeledControlProjectionDerivation::default();
            }
        }
    }
    if cancellation.is_cancelled() {
        return ModeledControlProjectionDerivation::default();
    }

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
        if let Some(reasons) = incomplete_reasons.get(&procedure.handle) {
            let mut reasons = reasons
                .iter()
                .map(|reason| reason.as_ref())
                .collect::<Vec<&str>>();
            reasons.sort_unstable();
            derived.push_incomplete(
                Some(procedure.handle.id()),
                format!(
                    "workspace non-return proof is incomplete: {}",
                    reasons.join("; ")
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
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                generation,
                active_model_set_hash,
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
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                generation,
                active_model_set_hash,
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
    )
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
    flow_state_for_materialized_selection(workspace, file, outcome, None, request)
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

    flow_state_for_materialized_selection(workspace, file, outcome, Some(procedure.id()), request)
}

fn flow_state_for_materialized_selection(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    requested_procedure: Option<ProcedureId>,
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
    let active_model_set_hash = active_snapshot
        .as_ref()
        .map(|snapshot| Box::<str>::from(snapshot.active_models().active_model_set_hash()));
    let mut budget = match SemanticBudget::new(SemanticWork::default_limits()) {
        Ok(budget) => budget,
        Err(error) => {
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                generation,
                active_model_set_hash,
            );
        }
    };

    flow_state_for_materialized_outcome(
        workspace,
        file,
        outcome,
        requested_procedure,
        generation,
        active_snapshot,
        active_model_set_hash,
        &mut budget,
        request,
    )
}

#[allow(clippy::too_many_arguments)]
fn flow_state_for_materialized_outcome(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
    outcome: SemanticOutcome<Arc<SemanticArtifact>>,
    requested_procedure: Option<ProcedureId>,
    generation: u64,
    active_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    active_model_set_hash: Option<Box<str>>,
    budget: &mut SemanticBudget,
    request: &mut FlowStateRequest<'_>,
) -> FileFlowState {
    let analyzer = workspace.analyzer();
    let active_models = active_snapshot
        .as_ref()
        .map(|snapshot| snapshot.active_models().as_ref());

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
        return FileFlowState::incomplete(file_reasons, generation, active_model_set_hash);
    };

    let Some(facts) = structural_facts(analyzer, file) else {
        file_reasons.push(FlowStateIncompleteReason::NoStructuralFacts);
        return FileFlowState::incomplete(file_reasons, generation, active_model_set_hash);
    };
    if facts.source_identity() != artifact.key().revision().content() {
        file_reasons.push(FlowStateIncompleteReason::SourceGenerationChanged);
        return FileFlowState::incomplete(file_reasons, generation, active_model_set_hash);
    }
    let site_index = {
        let _scope = profiling::scope("flow.site_index");
        SiteIndex::build(&facts)
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
    if let Some(snapshot) = active_snapshot.as_ref() {
        // The optional control proof obeys the request's CFG limits but owns a
        // separate ledger. Exhausting wrapper discovery must retain raw edges;
        // it must not consume the budget for the ordinary flow relations that
        // remain valid without this precision improvement.
        let mut nonreturn_cfg_budget = request.cfg_budget.clone();
        let _scope = profiling::scope("flow.workspace_nonreturn_projection");
        modeled_projection.extend(derive_workspace_nonreturn_projection(
            workspace,
            file,
            &artifact,
            requested_procedure,
            snapshot,
            budget,
            &mut nonreturn_cfg_budget,
            request.cancellation,
        ));
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
        .map(|procedure| {
            let procedure_reasons = procedure_projection_reasons
                .remove(&procedure.id())
                .map_or_else(
                    || file_reasons.clone(),
                    |reasons| file_reasons.iter().cloned().chain(reasons).collect(),
                );
            derive_procedure(
                &artifact,
                procedure,
                file,
                &facts,
                &site_index,
                generation,
                &procedure_reasons,
                control_edge_masks
                    .remove(&procedure.id())
                    .unwrap_or_default(),
                request,
            )
        })
        .collect();
    drop(derive_selected_procedures_scope);

    FileFlowState {
        procedures,
        completeness: FlowStateCompleteness::from_reasons(file_reasons),
        generation,
        active_model_set_hash,
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
    match outcome {
        SemanticOutcome::Complete { .. } => "complete",
        SemanticOutcome::Ambiguous { .. } => "ambiguous",
        SemanticOutcome::Unknown { .. } => "unknown",
        SemanticOutcome::Unsupported { .. } => "unsupported",
        SemanticOutcome::Unproven { .. } => "unproven",
        SemanticOutcome::ExceededBudget { .. } => "exceeded_budget",
        SemanticOutcome::Cancelled { .. } => "cancelled",
    }
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

/// A binding value is one the language binds by name; a temporary, constant,
/// return slot, or exception value is not a state subject.
fn is_binding_kind(kind: &SemanticValueKind) -> bool {
    matches!(
        kind,
        SemanticValueKind::Local
            | SemanticValueKind::Parameter { .. }
            | SemanticValueKind::Receiver { .. }
    )
}

/// One procedure's derivation.
#[allow(clippy::too_many_arguments)]
fn derive_procedure(
    artifact: &Arc<SemanticArtifact>,
    procedure: &ProcedureSemantics,
    file: &ProjectFile,
    facts: &brokk_bifrost_analysis::analyzer::structural::facts::FileFacts,
    site_index: &SiteIndex,
    generation: u64,
    file_reasons: &[FlowStateIncompleteReason],
    control_edge_mask: ControlEdgeMask,
    request: &mut FlowStateRequest<'_>,
) -> FlowStateDerivation {
    let mut reasons = file_reasons.to_vec();
    collect_capability_reasons(artifact.capabilities(), &mut reasons);
    collect_gap_reasons(procedure, &mut reasons);

    let properties_available = artifact
        .capabilities()
        .support(SemanticCapability::FieldMemory)
        != CapabilitySupport::Unsupported;

    let procedure_handle = artifact
        .procedure_handle(procedure.id())
        .expect("a validated artifact owns every procedure it lists");
    let procedure_artifact = Arc::downgrade(procedure_handle.artifact());
    let mut builder = EventBuilder {
        procedure: procedure.id(),
        procedure_handle,
        file,
        facts,
        site_index,
        generation,
        events: Vec::new(),
        uncanonical_accesses: 0,
        properties_available,
    };
    builder.collect(procedure);
    let uncanonical_accesses = builder.uncanonical_accesses;
    let mut events = builder.events;

    if uncanonical_accesses > 0 {
        reasons.push(FlowStateIncompleteReason::PropertyBaseNotCanonical {
            accesses: uncanonical_accesses,
        });
    }
    if !properties_available {
        reasons.push(FlowStateIncompleteReason::AxisUnsupported(
            FlowStateAxis::PropertyEvents,
        ));
    }

    append_kill_events(&mut events);
    let unestablished = unestablished_local_bindings(procedure, &events);
    if unestablished > 0 {
        reasons.push(FlowStateIncompleteReason::BindingWithoutEstablishment {
            bindings: unestablished,
        });
    }

    let (relations, dominance) = derive_relations(
        procedure,
        &control_edge_mask,
        &events,
        generation,
        request,
        &mut reasons,
    );

    FlowStateDerivation {
        procedure: procedure.id(),
        events,
        relations,
        completeness: FlowStateCompleteness::from_reasons(reasons),
        generation,
        procedure_artifact,
        dominance,
        control_edge_mask,
    }
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
    let mut seen: HashSet<(SemanticCapability, SemanticGapKind)> = HashSet::default();
    for gap in procedure.gaps() {
        if !seen.insert((gap.capability, gap.kind)) {
            continue;
        }
        reasons.push(FlowStateIncompleteReason::LoweringGap {
            capability: gap.capability,
            kind: gap.kind,
            detail: gap.detail.to_string(),
        });
    }
}

struct EventBuilder<'a> {
    procedure: ProcedureId,
    procedure_handle: ProcedureHandle,
    file: &'a ProjectFile,
    facts: &'a brokk_bifrost_analysis::analyzer::structural::facts::FileFacts,
    site_index: &'a SiteIndex,
    generation: u64,
    events: Vec<StateEventRow>,
    uncanonical_accesses: usize,
    properties_available: bool,
}

impl EventBuilder<'_> {
    /// Project every state event of one procedure, in program-point order and
    /// then event order inside a point, so two derivations of one artifact
    /// produce identical rows.
    fn collect(&mut self, procedure: &ProcedureSemantics) {
        let bases = BindingBases::build(procedure);
        for point in procedure.points() {
            for event in point.events.iter() {
                let (class, subject, value) = match &event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        let Some(target_value) = procedure.value(*target) else {
                            continue;
                        };
                        if !is_binding_kind(&target_value.kind) {
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
                        if !is_binding_kind(&source_value.kind) {
                            continue;
                        }
                        (
                            StateEventClass::Read,
                            FlowSubject::Binding { value: *source },
                            *target,
                        )
                    }
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Field,
                        location,
                        value,
                    } => {
                        let Some(subject) = self.property_subject(procedure, &bases, *location)
                        else {
                            continue;
                        };
                        (StateEventClass::Establish, subject, *value)
                    }
                    SemanticEffect::MemoryLoad {
                        kind: MemoryAccessKind::Field,
                        location,
                        result,
                    } => {
                        let Some(subject) = self.property_subject(procedure, &bases, *location)
                        else {
                            continue;
                        };
                        (StateEventClass::Read, subject, *result)
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
                    subject,
                    point: point.id,
                    point_id: self.point_id(point.id),
                    value,
                    site,
                    generation: self.generation,
                });
            }
        }
    }

    /// The property subject of one field access, or `None` when the IR does
    /// not flow the access base from a binding. A base the IR cannot canonicalize
    /// has no stable subject identity across two access sites, so it is
    /// counted and skipped rather than approximated from the source text.
    fn property_subject(
        &mut self,
        procedure: &ProcedureSemantics,
        bases: &BindingBases,
        location: MemoryLocationId,
    ) -> Option<FlowSubject> {
        if !self.properties_available {
            return None;
        }
        let location = procedure.memory_location(location)?;
        let MemoryLocationKind::Field { base, member } = &location.kind else {
            return None;
        };
        let Some(canonical) = bases.canonical(*base) else {
            self.uncanonical_accesses = self.uncanonical_accesses.saturating_add(1);
            return None;
        };
        let span = member.anchor().span();
        let member = self
            .facts
            .source()
            .get(span.start_byte() as usize..span.end_byte() as usize)?;
        Some(FlowSubject::Property {
            base: canonical,
            member: member.into(),
        })
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

/// The binding each value is the IR's own copy of.
///
/// Built from `ValueFlow` alone: an effect that says "this binding's value
/// flows into that value" is the lowering's own statement that the target
/// holds the binding. Nothing else canonicalizes a base.
struct BindingBases {
    canonical: HashMap<ValueId, ValueId>,
}

impl BindingBases {
    fn build(procedure: &ProcedureSemantics) -> Self {
        let mut canonical = HashMap::default();
        for point in procedure.points() {
            for event in point.events.iter() {
                let SemanticEffect::ValueFlow { source, target, .. } = &event.effect else {
                    continue;
                };
                let Some(source_value) = procedure.value(*source) else {
                    continue;
                };
                if is_binding_kind(&source_value.kind) {
                    canonical.entry(*target).or_insert(*source);
                }
            }
        }
        Self { canonical }
    }

    fn canonical(&self, value: ValueId) -> Option<ValueId> {
        self.canonical.get(&value).copied()
    }
}

/// A write to a subject that has more than one establishment terminates the
/// subject's other definitions, so it emits a `Kill` beside its `Establish`.
///
/// The rule is deliberately order-free. The dense program-point index is the
/// lowering's emission order, not a control-flow order, so "which write came
/// first" is not derivable without the CFG; what *is* derivable, and what the
/// gen/kill fixed point below actually uses, is that each write kills every
/// other definition of its subject.
fn append_kill_events(events: &mut Vec<StateEventRow>) {
    let mut establishments: HashMap<FlowSubject, usize> = HashMap::default();
    for event in events.iter() {
        if event.event_class == StateEventClass::Establish {
            *establishments.entry(event.subject.clone()).or_insert(0) += 1;
        }
    }
    let mut kills = Vec::new();
    for event in events.iter() {
        if event.event_class != StateEventClass::Establish {
            continue;
        }
        if establishments.get(&event.subject).copied().unwrap_or(0) < 2 {
            continue;
        }
        kills.push(StateEventRow {
            event: 0,
            event_class: StateEventClass::Kill,
            ..event.clone()
        });
    }
    for mut kill in kills {
        kill.event = events.len();
        events.push(kill);
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

fn derive_relations(
    procedure: &ProcedureSemantics,
    control_edge_mask: &ControlEdgeMask,
    events: &[StateEventRow],
    generation: u64,
    request: &mut FlowStateRequest<'_>,
    reasons: &mut Vec<FlowStateIncompleteReason>,
) -> (Vec<FlowRelationRow>, Option<Dominators<ProgramPointId>>) {
    let relations = same_evaluation_relations(procedure, events, generation);
    if control_edge_mask.is_empty() {
        return derive_control_relations(
            procedure, procedure, events, generation, request, reasons, relations,
        );
    }
    let graph = MaskedProcedureGraph::new(procedure, control_edge_mask);
    derive_control_relations(
        &graph, procedure, events, generation, request, reasons, relations,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_control_relations<G>(
    graph: &G,
    procedure: &ProcedureSemantics,
    events: &[StateEventRow],
    generation: u64,
    request: &mut FlowStateRequest<'_>,
    reasons: &mut Vec<FlowStateIncompleteReason>,
    mut relations: Vec<FlowRelationRow>,
) -> (Vec<FlowRelationRow>, Option<Dominators<ProgramPointId>>)
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
            return (relations, None);
        }
    };

    let definitions = Definitions::build(events);
    let facts = definitions.gen_kill(procedure.points().len());
    let reaching = match reaching_definitions(graph, entry, &facts, &mut algorithm_request) {
        Ok(reaching) => reaching,
        Err(error) => {
            push_algorithm_reason(error, FlowStateAxis::ReachingRelation, reasons);
            relations.extend(dominance_relations(graph, events, &dominance, generation));
            return (relations, Some(dominance));
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
    (relations, Some(dominance))
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

struct MaskedProcedureGraph<'a> {
    procedure: &'a ProcedureSemantics,
    mask: &'a ControlEdgeMask,
}

impl<'a> MaskedProcedureGraph<'a> {
    fn new(procedure: &'a ProcedureSemantics, mask: &'a ControlEdgeMask) -> Self {
        assert!(
            !mask.is_empty(),
            "an empty mask uses the raw procedure graph"
        );
        Self { procedure, mask }
    }
}

impl DenseBidirectionalGraph for MaskedProcedureGraph<'_> {
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
            self.mask.omitted_outgoing[node.index()],
        )
    }

    fn predecessors(
        &self,
        node: Self::Node,
    ) -> impl DoubleEndedIterator<Item = (Self::Edge, Self::Node)> + ExactSizeIterator + '_ {
        RetainedEdges::new(
            DenseBidirectionalGraph::predecessors(self.procedure, node),
            &self.mask.omitted,
            self.mask.omitted_incoming[node.index()],
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

/// The dense definition identities the reaching fixed point is solved over:
/// one per establishment event.
struct Definitions {
    /// Definition id -> event id.
    events: Vec<usize>,
    /// Definition id -> the dense program point index it is generated at.
    points: Vec<usize>,
    /// Definition id -> subject.
    subjects: Vec<FlowSubject>,
    /// Event id -> definition id.
    by_event: HashMap<usize, usize>,
}

impl Definitions {
    fn build(events: &[StateEventRow]) -> Self {
        let mut definitions = Self {
            events: Vec::new(),
            points: Vec::new(),
            subjects: Vec::new(),
            by_event: HashMap::default(),
        };
        for event in events {
            if event.event_class != StateEventClass::Establish {
                continue;
            }
            definitions
                .by_event
                .insert(event.event, definitions.events.len());
            definitions.events.push(event.event);
            definitions.points.push(event.point.index());
            definitions.subjects.push(event.subject.clone());
        }
        definitions
    }

    fn gen_kill(&self, point_count: usize) -> GenKillFacts {
        let mut facts = GenKillFacts::new(point_count, self.events.len().max(1));
        for (definition, point) in self.points.iter().copied().enumerate() {
            facts.record_generated(point, definition);
            for (other, subject) in self.subjects.iter().enumerate() {
                if other != definition && *subject == self.subjects[definition] {
                    facts.record_killed(point, other);
                }
            }
        }
        facts
    }
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
    definitions: &Definitions,
    reaching: &ReachingSets,
    dominance: &Dominators<ProgramPointId>,
    generation: u64,
) -> Vec<FlowRelationRow>
where
    G: DenseBidirectionalGraph<Node = ProgramPointId, Edge = ControlEdgeId>,
{
    let mut rows = Vec::new();
    for read in events
        .iter()
        .filter(|event| event.event_class == StateEventClass::Read)
    {
        let point = read.point.index();
        let live = reaching
            .reaching_in(point)
            .filter(|definition| definitions.subjects[*definition] == read.subject)
            .collect::<Vec<_>>();
        for definition in live.iter().copied() {
            let establishment = definitions.events[definition];
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
        )
    }) {
        for read in events
            .iter()
            .filter(|event| event.event_class == StateEventClass::Read)
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
    sources: HashMap<ValueId, Vec<ValueId>>,
}

impl EvaluationDependence {
    fn build(procedure: &ProcedureSemantics) -> Self {
        let mut sources: HashMap<ValueId, Vec<ValueId>> = HashMap::default();
        let mut record = |target: ValueId, source: ValueId| {
            sources.entry(target).or_default().push(source);
        };
        for point in procedure.points() {
            for event in point.events.iter() {
                match &event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        let binding = procedure
                            .value(*target)
                            .is_some_and(|value| is_binding_kind(&value.kind));
                        if !binding {
                            record(*target, *value);
                        }
                    }
                    SemanticEffect::ValueFlow { source, target, .. } => record(*target, *source),
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => {
                        if let Some(location) = procedure.memory_location(*location) {
                            match &location.kind {
                                MemoryLocationKind::Field { base, .. } => record(*result, *base),
                                MemoryLocationKind::Index { base, index } => {
                                    record(*result, *base);
                                    if let Some(index) = index {
                                        record(*result, *index);
                                    }
                                }
                                MemoryLocationKind::LexicalCell { binding } => {
                                    record(*result, *binding);
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
            record(result, call_site.callee);
            if let Some(receiver) = call_site.receiver {
                record(result, receiver);
            }
            for argument in call_site.arguments.iter() {
                record(result, argument.value);
            }
        }
        Self { sources }
    }

    /// Every value `value` is computed from, `value` included. The walk is an
    /// explicit stack bounded by the procedure's own value count, so a cyclic
    /// dependence cannot make it diverge.
    fn operands_of(&self, value: ValueId, value_count: usize) -> HashSet<ValueId> {
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
            if let Some(sources) = self.sources.get(&current) {
                stack.extend(sources.iter().copied());
            }
        }
        visited
    }
}

#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;
    use crate::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
        SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat,
        acquire_active_semantic_models, compile_source,
    };
    use crate::analyzer::{AnalyzerConfig, Language};

    use super::inline_project::{BuiltInlineTestProject, InlineTestProject};

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
                &mut FlowStateRequest::new(&cancellation),
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
            let mut request = FlowStateRequest::new(&cancellation);
            request.cfg_budget = budget;
            flow_state_for_file(&self.workspace, &self.files[index], &mut request)
        }

        fn state_with_control_projection(
            &self,
            index: usize,
            projection: &FlowControlProjection,
        ) -> FileFlowState {
            let cancellation = CancellationToken::default();
            let mut request =
                FlowStateRequest::new(&cancellation).with_control_projection(projection);
            flow_state_for_file(&self.workspace, &self.files[index], &mut request)
        }

        fn state_with_active_models(
            &self,
            index: usize,
            snapshot: &Arc<ActiveSemanticModelSnapshot>,
        ) -> FileFlowState {
            let cancellation = CancellationToken::default();
            let mut request = FlowStateRequest::new(&cancellation)
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
            match acquire_active_semantic_models(
                self.workspace.analyzer(),
                catalog,
                None,
                &SemanticModelActivationRequest {
                    bifrost_version: env!("CARGO_PKG_VERSION")
                        .parse()
                        .expect("crate version is semver"),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "go".to_owned(),
                        ecosystem: "go".to_owned(),
                        package: None,
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: None,
                    }],
                    controls: Vec::new(),
                    limits: SemanticModelRuntimeLimits::default(),
                },
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
            &mut FlowStateRequest::new(&cancellation),
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
            &mut FlowStateRequest::new(&cancellation),
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
        let graph = MaskedProcedureGraph::new(semantics, &mask);

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
        let edges = semantics
            .successor_edges(call.point)
            .filter_map(|(edge_id, edge)| {
                (edge.kind == ControlEdgeKind::Normal && edge.target_point == target)
                    .then_some(edge_id)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            edges.len(),
            1,
            "a normal call continuation has one exact source edge: {edges:?}"
        );
        edges[0]
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

    #[test]
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
            &mut FlowStateRequest::new(&cancellation),
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
            &mut FlowStateRequest::new(&cancellation),
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
            &mut FlowStateRequest::new(&cancellation),
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
            MemoryLocationKind::Index { base, index } => {
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
    fn procedure_capture_gap_does_not_hide_child_local_result_observations() {
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
        let capture_gap = semantics
            .gaps()
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::Captures
            })
            .expect("the omitted outer parameter publishes a child procedure capture gap");
        assert_eq!(capture_gap.point, semantics.entry_point());
        assert!(
            !derivation.completeness.is_complete(),
            "generic flow completeness must retain the capture gap"
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
            !derivation.result_observation_enumeration_is_complete(
                &procedure,
                &[semantics.entry_point()],
                &relevant_values,
            ),
            "an entry-origin result may itself cross the unsupported capture boundary"
        );
    }

    #[test]
    fn unsupported_normal_control_flow_blocks_both_cfg_relation_axes() {
        let capabilities = SemanticCapabilities::builder()
            .complete(SemanticCapability::Assignments)
            .build();
        let mut reasons = Vec::new();
        collect_capability_reasons(&capabilities, &mut reasons);

        assert_eq!(reasons.len(), 2, "got {reasons:?}");
        assert!(
            reasons.contains(&FlowStateIncompleteReason::AxisUnsupported(
                FlowStateAxis::ReachingRelation
            ))
        );
        assert!(
            reasons.contains(&FlowStateIncompleteReason::AxisUnsupported(
                FlowStateAxis::DominanceRelation
            ))
        );
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

    const JS_READ_AFTER_ESTABLISHMENT: &str = r#"
function afterEstablishment() {
  const ns = {};
  ns.value = 1;
  return ns.value;
}
"#;

    /// The acceptance shape: a read after an establishment on a straight line
    /// relates to it as `Reaching` with `Exact` certainty, and the write also
    /// dominates the read. Both rows exist because the two statements are two
    /// different claims.
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
        assert!(
            derivation
                .any_normal_return_dominates_targets(
                    &procedure,
                    std::slice::from_ref(&validator),
                    &[target],
                )
                .is_none(),
            "generic dominance must retain the exceptional-flow hole"
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

func mixed(value *item, err error) int {
    defer cleanup()
    exactMixed := value
    if err != nil {
        reportMixed(err)
        return 1
    }
    select {}
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
        let select_gaps = mixed_semantics
            .gaps()
            .iter()
            .filter(|gap| {
                let mapping = mixed_semantics
                    .source_mapping(gap.source)
                    .expect("a select gap has a source mapping");
                let span = mapping.locator.anchor().span();
                &GO_ACTIVE_CLEANUP_COMPLETION_RELATIVE_TO_TARGET
                    [span.start_byte() as usize..span.end_byte() as usize]
                    == "select {}"
            })
            .collect::<Vec<_>>();
        let select_completion = select_gaps
            .iter()
            .copied()
            .find(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.discharge == SemanticGapDischarge::ExitOnlyProcedureCompletion
            })
            .unwrap_or_else(|| {
                panic!("select must publish its exit-only panic gap: {select_gaps:#?}")
            });
        let select_raw_control = select_gaps
            .iter()
            .copied()
            .find(|gap| {
                gap.capability == SemanticCapability::NormalControlFlow
                    && gap.discharge == SemanticGapDischarge::None
            })
            .unwrap_or_else(|| panic!("select must retain its raw blocking gap: {select_gaps:#?}"));
        assert_eq!(
            select_completion.point, select_raw_control.point,
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
                &[select_completion],
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
                &[select_completion, select_raw_control],
            )
            .as_ref(),
            [GuardDominanceAnswer::Open].as_slice(),
            "a completion marker must not discharge a co-located raw control gap"
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
        assert!(
            derivation
                .any_candidate_dominates_targets(&procedure, &[candidate], &[target])
                .is_none(),
            "generic point dominance must retain the exceptional-flow hole"
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
    fn result_point_dominance_retains_post_establishment_exceptional_exits() {
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
        assert!(
            derivation
                .any_candidate_dominates_result_uses(
                    &procedure,
                    &[establishment],
                    &[candidate],
                    &[target],
                )
                .is_none(),
            "an exceptional-flow hole after result establishment and before the candidate remains blocking"
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

    #[test]
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
            &mut FlowStateRequest::new(&cancellation),
        );
        let artifact = outcome
            .available_value()
            .expect("Go semantics are available");

        for (procedure_name, expected) in [
            ("safe", Some(true)),
            ("invalidated", None),
            ("afterReceive", Some(true)),
            ("escaped", None),
            ("captured", None),
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
            &mut FlowStateRequest::new(&cancellation),
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

fn unrelated_adjustment(mut receiver: Receiver, value: Option<i32>) {
    use_values(checked(value), ());
    receiver.consume(false);
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
            &mut FlowStateRequest::new(&cancellation),
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
                assert!(semantics.gaps().iter().any(|gap| {
                    gap.point == target_call.point
                        && gap.subject == SemanticGapSubject::Point
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
            &mut FlowStateRequest::new(&cancellation),
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
        let target_call = semantics.call_site(target.id()).expect("target call site");
        assert!(semantics.gaps().iter().any(|gap| {
            gap.point != target_call.point
                && gap.subject == SemanticGapSubject::Point
                && gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        }));
        assert!(
            !target_call_evaluation_is_open(semantics, target_call),
            "a later call's evaluation gap must not contaminate the exact target"
        );
        assert!(semantics.gaps().iter().any(|gap| {
            gap.point == semantics.exceptional_exit_point()
                && gap.subject == SemanticGapSubject::Point
                && gap.capability == SemanticCapability::CleanupControlFlow
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
            "the owned parameters' independent cleanup-control hole keeps generic dominance open"
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
  "schema_version": 1,
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
  "schema_version": 1,
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
        assert!(
            call_handles_spelled(&spawned_procedure, GO_AUTOMATIC_NONRETURN, "os.Exit(1)",)
                .is_empty(),
            "the spawned outer call must not lower as a synchronous semantic call"
        );
        assert!(
            spawned.control_edge_mask.is_empty(),
            "a spawned target has no caller normal edge for the model to omit"
        );
        assert!(
            !spawned.completeness.reasons().iter().any(|reason| matches!(
                reason,
                FlowStateIncompleteReason::ModeledControlProjectionIncomplete { .. }
            )),
            "a spawned outer call has no synchronous semantic edge and must not poison the file"
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
            ("recursive.value", "recurse()", false),
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
        let mut request = FlowStateRequest::new(&cancellation)
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
            adjudicable_workspace_names: Vec::new(),
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
            adjudicable_workspace_names: Vec::new(),
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
            adjudicable_workspace_names: Vec::new(),
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
        let masked = MaskedProcedureGraph::new(semantics, &projected_inspect.control_edge_mask);
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
            "the retained definition becomes exact: {projected_reaching:?}"
        );
        assert!(
            !projected_reaching
                .iter()
                .any(|(source, target, _)| *source == "ns.value = 2" && *target == "ns.value"),
            "a definition on the terminating arm cannot reach the return: {projected_reaching:?}"
        );
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

    const GO_CONTROL_GAP_AT_TARGET: &str = r#"
package sample

type item struct { value int }

func read(value *item) int {
    ready := true
    _ = ready
    return value.value
}
"#;

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

    const JS_READ_BEFORE_ESTABLISHMENT: &str = r#"
function beforeEstablishment() {
  const ns = {};
  const early = ns.value;
  ns.value = 1;
  return early;
}
"#;

    /// The #2015 acceptance shape: a procedure whose only object is a local
    /// plain literal used purely as a member-access base carries no lowering
    /// gap, so every axis is covered and the missing reaching row below is a
    /// conclusion, not an unknown.
    const TS_READ_BEFORE_ESTABLISHMENT: &str = r#"
function beforeEstablishment(): number | undefined {
  const ns: { value?: number } = {};
  const early = ns.value;
  ns.value = 1;
  return early;
}
"#;

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

    /// An object literal that escapes into a call can grow accessors behind
    /// the lowering's back, so its accesses keep the conservative gaps and
    /// the property and relation axes stay uncovered.
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
                .covers(FlowStateAxis::ReachingRelation)
        );
    }

    /// Source co-presence is not evidence: the only write to the property
    /// follows the read on every path, so no reaching row exists for it.
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

    /// #2014: a read in return position anchors on the identifier occurrence,
    /// not on the enclosing `return` statement, so an RQLP capture of that
    /// identifier joins the event by `ast_id` instead of silently joining
    /// nothing.
    #[test]
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
                    && matches!(event.subject, FlowSubject::Binding { .. })
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

    /// A rebind emits both a kill and an establishment at its point, and the
    /// earlier establishment does not survive it to the final read.
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

func overwrite() {
    err := first()
    err = externalCall()
    if err != nil { return }
}
"#;

    /// A scalar call assignment remains a definite binding write even when
    /// Go's implicit conversion cannot be proven identity-preserving. The
    /// opaque post-conversion value establishes and kills the binding, so the
    /// earlier call result cannot reach the later guard.
    #[test]
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

    /// `x = wrap(x)`: the read sits inside the evaluation of the very write
    /// that rebinds it. The two are related as same-evaluation, and the write
    /// does not reach its own read.
    #[test]
    fn a_same_assignment_write_is_same_evaluation_with_its_own_read() {
        let fixture = Fixture::new(Language::JavaScript, &[("src/main.js", JS_SAME_ASSIGNMENT)]);
        let state = fixture.state(0);
        let derivation = procedure_containing(&state, |event| {
            spelling(JS_SAME_ASSIGNMENT, event) == "x = wrap(x)"
        });

        let same = relation_spellings(JS_SAME_ASSIGNMENT, derivation, FlowRelation::SameEvaluation);
        assert!(
            same.contains(&("x = wrap(x)", "x", FlowCertainty::Exact)),
            "the write and the read it consumes must be same-evaluation; got {same:?}"
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

    /// The `671e9b23b` shape: the namespace-assignment artifact reads the very
    /// binding it writes into, so the two are same-evaluation.
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
        let same = relation_spellings(
            JS_NAMESPACE_SELF_ASSIGNMENT,
            derivation,
            FlowRelation::SameEvaluation,
        );
        assert!(
            same.contains(&("ns.a = ns", "ns", FlowCertainty::Exact)),
            "the artifact write consumes its own binding read; got {same:?}"
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

func conversionAlias() any {
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

    const GO_MAY_ASSIGNMENT_CONVERSION_ALIAS: &str = r#"package app

type resource struct{}

func acquire() *resource { return nil }

func mayConversionAlias(change bool) any {
	source := acquire()
	if change {
		source = nil
	}
	var converted any = source
	return converted
}
"#;

    #[test]
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

    const GO_RANGE_SELF_BINDER: &str = r#"package app

func rangeSelfBinder(x []int) int {
	total := 0
	for x := range x {
		total += x
	}
	return total
}
"#;

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

    /// The `edb00e017` shape, positive since #2013. The Go lowering publishes
    /// an establishment for the `:=` range binder whose value is derived from
    /// the iterable, so the outer `x` read of the binder's own right-hand side
    /// relates to it as same-evaluation, and the compound write consumes its
    /// operand reads the same way. The binding-events axis is fully
    /// enumerated; the same-evaluation axis stays uncovered because the range
    /// mechanics honestly publish a `Calls` gap.
    #[test]
    fn the_go_range_self_binder_establishes_and_relates_as_same_evaluation() {
        let fixture = Fixture::new(
            Language::Go,
            &[("go.mod", GO_MOD), ("app.go", GO_RANGE_SELF_BINDER)],
        );
        let state = fixture.state(1);
        let derivation = procedure_containing(&state, |event| {
            spelling(GO_RANGE_SELF_BINDER, event) == "total := 0"
        });
        assert!(
            !derivation.completeness.reasons().iter().any(|reason| {
                matches!(
                    reason,
                    FlowStateIncompleteReason::BindingWithoutEstablishment { .. }
                )
            }),
            "the range binder is established; got {:?}",
            derivation.completeness
        );
        assert!(derivation.completeness.covers(FlowStateAxis::BindingEvents));
        let same = relation_spellings(
            GO_RANGE_SELF_BINDER,
            derivation,
            FlowRelation::SameEvaluation,
        );
        assert!(
            same.iter()
                .any(|(write, _, certainty)| *write == "x" && *certainty == FlowCertainty::Exact),
            "the binder must relate to the outer `x` read of its own iterable; got {same:?}"
        );
        assert!(
            same.contains(&("total += x", "total", FlowCertainty::Exact))
                && same.contains(&("total += x", "x", FlowCertainty::Exact)),
            "the compound write consumes its own operand reads; got {same:?}"
        );
    }

    const RUBY_LOCAL_BINDER: &str = r#"
def local_binder(x)
  total = 0
  total + x
end
"#;

    /// A language whose adapter declares no field-memory capability reports
    /// the property axis unsupported rather than silently empty. (Go carried
    /// this pin until #2662 gave it field memory, Rust until #2667, and the
    /// C family until #2666.)
    #[test]
    fn a_language_without_field_memory_reports_the_property_axis_unsupported() {
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
            CapabilitySupport::Unsupported,
            "the fixture language must substantiate the unsupported-axis contract"
        );
        assert!(
            derivation.completeness.reasons().contains(
                &FlowStateIncompleteReason::AxisUnsupported(FlowStateAxis::PropertyEvents)
            ),
            "got {:?}",
            derivation.completeness
        );
        assert!(
            !derivation
                .completeness
                .covers(FlowStateAxis::PropertyEvents)
        );
        assert!(
            derivation
                .events
                .iter()
                .all(|event| matches!(event.subject, FlowSubject::Binding { .. }))
        );
    }

    /// Budget exhaustion is a typed incompleteness, never a truncated row set.
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

    /// A file with no semantic provider yields an explicit uncovered result,
    /// not an empty complete one.
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

    /// Two derivations of one unchanged workspace produce identical rows.
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

    /// Every event carries the arena identity join and the workspace
    /// generation the artifact was read at.
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
}
