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

use super::occurrence_rows::ast_id;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, Dominators, GenKillFacts,
    ReachingSets, dominators, reaching_definitions,
};
use crate::analyzer::semantic::{
    CapabilitySupport, ContentIdentity, MemoryAccessKind, MemoryLocationId, MemoryLocationKind,
    ProcedureId, ProcedureSemantics, ProgramPointId, SemanticArtifact, SemanticBudget,
    SemanticCapability, SemanticEffect, SemanticGapKind, SemanticOutcome, SemanticRequest,
    SemanticValueKind, SemanticWork, SourceMappingId, SourceSpan, ValueId,
};
use crate::analyzer::{IAnalyzer, ProjectFile, Range, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

pub use brokk_bifrost_core::analyzer::structural::flow_state::{
    ALL_FLOW_STATE_AXES as FLOW_STATE_AXES, FlowCertainty, FlowRelation, FlowStateAxis,
    FlowSubjectKind, StateEventClass,
};

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
    match capability {
        Procedures
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
        use FlowStateIncompleteReason::*;
        !self.reasons().iter().any(|reason| match reason {
            AxisUnsupported(blocked) => *blocked == axis,
            BudgetExhausted { axis: blocked, .. } => *blocked == axis,
            LoweringGap { capability, .. } => axes_blocked_by(*capability).contains(&axis),
            PropertyBaseNotCanonical { .. } => axis == FlowStateAxis::PropertyEvents,
            BindingWithoutEstablishment { .. } => {
                axis != FlowStateAxis::PropertyEvents && axis != FlowStateAxis::DominanceRelation
            }
            NoSemanticProvider
            | SemanticProviderFailed { .. }
            | SemanticAnalysisPartial { .. }
            | Cancelled
            | SourceGenerationChanged
            | NoStructuralFacts => true,
        })
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
}

impl FlowStateDerivation {
    pub fn event(&self, event: usize) -> &StateEventRow {
        &self.events[event]
    }

    /// The relations of one family, in derivation order.
    #[cfg(test)]
    fn relations_of(&self, relation: FlowRelation) -> impl Iterator<Item = &FlowRelationRow> {
        self.relations
            .iter()
            .filter(move |row| row.relation == relation)
    }
}

/// Every procedure of one file, plus the file-level lowering account.
///
/// A file that fails to lower yields no procedures and an explicit incomplete
/// result, never an empty complete one.
#[derive(Debug, Clone)]
pub struct FileFlowState {
    pub procedures: Vec<FlowStateDerivation>,
    pub completeness: FlowStateCompleteness,
    pub generation: u64,
}

impl FileFlowState {
    fn incomplete(reasons: Vec<FlowStateIncompleteReason>, generation: u64) -> Self {
        Self {
            procedures: Vec::new(),
            completeness: FlowStateCompleteness::Incomplete { reasons },
            generation,
        }
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
}

impl<'request> FlowStateRequest<'request> {
    pub fn new(cancellation: &'request CancellationToken) -> Self {
        Self {
            cancellation,
            cfg_budget: CfgAlgorithmBudget::default(),
        }
    }
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
    let generation = analyzer.project().analysis_generation();
    let mut budget = match SemanticBudget::new(SemanticWork::default_limits()) {
        Ok(budget) => budget,
        Err(error) => {
            return FileFlowState::incomplete(
                vec![FlowStateIncompleteReason::SemanticProviderFailed {
                    detail: error.to_string(),
                }],
                generation,
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
            );
        }
    };

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
        return FileFlowState::incomplete(file_reasons, generation);
    };

    let Some(facts) = structural_facts(analyzer, file) else {
        file_reasons.push(FlowStateIncompleteReason::NoStructuralFacts);
        return FileFlowState::incomplete(file_reasons, generation);
    };
    if facts.source_identity() != artifact.key().revision().content() {
        file_reasons.push(FlowStateIncompleteReason::SourceGenerationChanged);
        return FileFlowState::incomplete(file_reasons, generation);
    }
    let site_index = SiteIndex::build(&facts);

    let procedures = artifact
        .procedures()
        .iter()
        .map(|procedure| {
            derive_procedure(
                &artifact,
                procedure,
                file,
                &facts,
                &site_index,
                generation,
                &file_reasons,
                request,
            )
        })
        .collect();

    FileFlowState {
        procedures,
        completeness: FlowStateCompleteness::from_reasons(file_reasons),
        generation,
    }
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
) -> Option<Arc<super::facts::FileFacts>> {
    let language = crate::analyzer::common::language_for_file(file);
    analyzer
        .structural_search_providers()
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
    fn build(facts: &super::facts::FileFacts) -> Self {
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
    artifact: &SemanticArtifact,
    procedure: &ProcedureSemantics,
    file: &ProjectFile,
    facts: &super::facts::FileFacts,
    site_index: &SiteIndex,
    generation: u64,
    file_reasons: &[FlowStateIncompleteReason],
    request: &mut FlowStateRequest<'_>,
) -> FlowStateDerivation {
    let mut reasons = file_reasons.to_vec();
    collect_capability_reasons(artifact, &mut reasons);
    collect_gap_reasons(procedure, &mut reasons);

    let properties_available = artifact
        .capabilities()
        .support(SemanticCapability::FieldMemory)
        != CapabilitySupport::Unsupported;

    let mut builder = EventBuilder {
        procedure: procedure.id(),
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

    let relations = derive_relations(procedure, &events, generation, request, &mut reasons);

    FlowStateDerivation {
        procedure: procedure.id(),
        events,
        relations,
        completeness: FlowStateCompleteness::from_reasons(reasons),
        generation,
    }
}

fn collect_capability_reasons(
    artifact: &SemanticArtifact,
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
    ] {
        if artifact.capabilities().support(capability) == CapabilitySupport::Unsupported {
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
    file: &'a ProjectFile,
    facts: &'a super::facts::FileFacts,
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
    events: &[StateEventRow],
    generation: u64,
    request: &mut FlowStateRequest<'_>,
    reasons: &mut Vec<FlowStateIncompleteReason>,
) -> Vec<FlowRelationRow> {
    let mut relations = same_evaluation_relations(procedure, events, generation);

    let entry = procedure.entry_point();
    let mut algorithm_request =
        CfgAlgorithmRequest::new(&mut request.cfg_budget, request.cancellation);
    let dominance = match dominators(procedure, entry, &mut algorithm_request) {
        Ok(dominance) => dominance,
        Err(error) => {
            push_algorithm_reason(error, FlowStateAxis::DominanceRelation, reasons);
            reasons.push(FlowStateIncompleteReason::AxisUnsupported(
                FlowStateAxis::ReachingRelation,
            ));
            return relations;
        }
    };

    let definitions = Definitions::build(events);
    let facts = definitions.gen_kill(procedure.points().len());
    let reaching = match reaching_definitions(procedure, entry, &facts, &mut algorithm_request) {
        Ok(reaching) => reaching,
        Err(error) => {
            push_algorithm_reason(error, FlowStateAxis::ReachingRelation, reasons);
            relations.extend(dominance_relations(
                procedure, events, &dominance, generation,
            ));
            return relations;
        }
    };

    relations.extend(reaching_relations(
        procedure,
        events,
        &definitions,
        &reaching,
        &dominance,
        generation,
    ));
    relations.extend(dominance_relations(
        procedure, events, &dominance, generation,
    ));
    relations
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
fn reaching_relations(
    procedure: &ProcedureSemantics,
    events: &[StateEventRow],
    definitions: &Definitions,
    reaching: &ReachingSets,
    dominance: &Dominators<ProgramPointId>,
    generation: u64,
) -> Vec<FlowRelationRow> {
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
            let certainty = if live.len() == 1
                && dominance.dominates(procedure, establishment_point, read.point)
            {
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
fn dominance_relations(
    procedure: &ProcedureSemantics,
    events: &[StateEventRow],
    dominance: &Dominators<ProgramPointId>,
    generation: u64,
) -> Vec<FlowRelationRow> {
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
            if dominance.dominates(procedure, write.point, read.point) {
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
mod tests {
    use super::*;
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject};
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        files: Vec<ProjectFile>,
    }

    impl Fixture {
        fn new(language: Language, sources: &[(&str, &str)]) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let files = sources
                .iter()
                .map(|(relative_path, source)| {
                    let file = ProjectFile::new(root.clone(), *relative_path);
                    file.write(source).expect("write fixture source");
                    file
                })
                .collect::<Vec<_>>();
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
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

        fn state_with_budget(&self, index: usize, budget: CfgAlgorithmBudget) -> FileFlowState {
            let cancellation = CancellationToken::default();
            let mut request = FlowStateRequest::new(&cancellation);
            request.cfg_budget = budget;
            flow_state_for_file(&self.workspace, &self.files[index], &mut request)
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
    const GO_RANGE_SELF_BINDER: &str = r#"package app

func rangeSelfBinder(x []int) int {
	total := 0
	for x := range x {
		total += x
	}
	return total
}
"#;

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

    /// Go declares no field-memory capability, so the property axis is
    /// reported unsupported rather than silently empty.
    #[test]
    fn a_language_without_field_memory_reports_the_property_axis_unsupported() {
        let fixture = Fixture::new(
            Language::Go,
            &[("go.mod", GO_MOD), ("app.go", GO_RANGE_SELF_BINDER)],
        );
        let state = fixture.state(1);
        let derivation = procedure_containing(&state, |event| {
            spelling(GO_RANGE_SELF_BINDER, event) == "total := 0"
        });
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
