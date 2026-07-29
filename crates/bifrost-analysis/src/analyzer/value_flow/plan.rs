use std::{cmp::Ordering, error::Error, fmt, hash::Hash, mem::size_of_val, sync::Arc};

use crate::analyzer::dataflow::{
    CuratedCallModel, CuratedCallModelFingerprint, ExternalSemanticSummarySet,
    ExternalSummarySetFingerprint, MAX_SUMMARY_BOUNDARY_BINDINGS, SemanticInputStatus,
    SemanticProcedureSummary, SummaryBoundary, SummaryBoundaryKind, SummaryDataflowResult,
    SummaryEvidence, SummaryExitKind, SummaryPort, SummaryTransfer, UnmodeledCallBehavior,
};
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AccessPathRoot, CallArgumentEndpoint, CallBinding,
    CallBindings, CallSiteHandle, CallSiteId, CallableTarget, CallableTargetResolution,
    CandidateCoverage, DeclarationLocator, DispatchBoundaryKind, EvidenceCompleteness,
    IcfgEdgeKind, MemoryLocationKind, ObjectCardinality, ProcedureHandle, ProgramPointHandle,
    ProgramPointId, ProofStatus, SemanticArtifact, SemanticArtifactKey, SemanticEffect,
    ValueFlowRelationKind, ValueFlowSnapshot,
};
use crate::hash::HashMap;

use super::{
    ValueFlowCarrier, ValueFlowCarrierId, ValueFlowCarrierKey, ValueFlowModelError,
    ValueFlowObservationPhase, ValueFlowSinkId, ValueFlowSinkSpec, ValueFlowSourceId,
    ValueFlowSourceSpec,
};

pub const MAX_VALUE_FLOW_CARRIERS: usize = 262_144;
pub const MAX_VALUE_FLOW_RELATIONS: usize = 1_000_000;
pub const MAX_VALUE_FLOW_SOURCES: usize = 65_536;
pub const MAX_VALUE_FLOW_SINKS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueFlowPlanLimits {
    max_carriers: usize,
    max_relations: usize,
    max_sources: usize,
    max_sinks: usize,
}

impl ValueFlowPlanLimits {
    pub fn new(
        max_carriers: usize,
        max_relations: usize,
        max_sources: usize,
        max_sinks: usize,
    ) -> Result<Self, ValueFlowPlanError> {
        if max_carriers == 0
            || max_carriers > MAX_VALUE_FLOW_CARRIERS
            || max_relations == 0
            || max_relations > MAX_VALUE_FLOW_RELATIONS
            || max_sources == 0
            || max_sources > MAX_VALUE_FLOW_SOURCES
            || max_sinks == 0
            || max_sinks > MAX_VALUE_FLOW_SINKS
        {
            return Err(ValueFlowPlanError::InvalidLimits);
        }
        Ok(Self {
            max_carriers,
            max_relations,
            max_sources,
            max_sinks,
        })
    }
}

impl Default for ValueFlowPlanLimits {
    fn default() -> Self {
        Self {
            max_carriers: MAX_VALUE_FLOW_CARRIERS,
            max_relations: MAX_VALUE_FLOW_RELATIONS,
            max_sources: MAX_VALUE_FLOW_SOURCES,
            max_sinks: MAX_VALUE_FLOW_SINKS,
        }
    }
}

/// One discovered oracle payload and the semantic outcome that produced it.
#[derive(Debug, Clone)]
pub struct ValueFlowInput<T> {
    value: T,
    status: SemanticInputStatus,
}

impl<T> ValueFlowInput<T> {
    pub const fn new(value: T, status: SemanticInputStatus) -> Self {
        Self { value, status }
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub const fn status(&self) -> SemanticInputStatus {
        self.status
    }

    pub fn into_parts(self) -> (T, SemanticInputStatus) {
        (self.value, self.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LocalFlowRule {
    pub point: ProgramPointHandle,
    pub event_index: u32,
    pub kind: ValueFlowRelationKind,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallFlowRuleKind {
    Call,
    NormalReturn,
    ExceptionalReturn,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowLocalSummaryRule {
    point: ProgramPointId,
    event_index: u32,
    kind: ValueFlowRelationKind,
    source: ValueFlowCarrierKey,
    target: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCallSummaryRule {
    call: CallSiteId,
    callee_artifact: SemanticArtifactKey,
    callee_declaration: DeclarationLocator,
    kind: CallFlowRuleKind,
    source: ValueFlowCarrierKey,
    target: ValueFlowCarrierKey,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCuratedModelSummaryRule {
    call: CallSiteId,
    model: CuratedCallModelFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowFallbackSummaryRule {
    call: CallSiteId,
    inputs: Box<[ValueFlowCarrierKey]>,
    reachable_components: Box<[usize]>,
    normal_output: Option<ValueFlowCarrierKey>,
    exceptional_output: Option<ValueFlowCarrierKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowLocationBindingSummaryRule {
    call: CallSiteId,
    port: SummaryPort,
    carrier: ValueFlowCarrierKey,
}

/// Stable, procedure-local value-flow identity used by reusable client summaries.
///
/// Source, sink, sanitizer, and transform matching are intentionally absent;
/// clients add those independently according to their invalidation contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCarrierSummaryIdentity {
    unmodeled_call_behavior: UnmodeledCallBehavior,
    external_summaries: Box<[ExternalSummarySetFingerprint]>,
    fallback_globals: Box<[ValueFlowCarrierKey]>,
    has_snapshot: bool,
    local_rules: Box<[ValueFlowLocalSummaryRule]>,
    call_rules: Box<[ValueFlowCallSummaryRule]>,
    curated_models: Box<[ValueFlowCuratedModelSummaryRule]>,
    fallback_rules: Box<[ValueFlowFallbackSummaryRule]>,
    location_bindings: Box<[ValueFlowLocationBindingSummaryRule]>,
}

impl ValueFlowCarrierSummaryIdentity {
    pub(crate) fn retained_bytes(&self) -> usize {
        let local = size_of_val(self.local_rules.as_ref()).saturating_add(
            self.local_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(rule.source.retained_bytes())
                    .saturating_add(rule.target.retained_bytes())
                    .saturating_add(proof_heap_bytes(&rule.proof))
                    .saturating_add(completeness_heap_bytes(&rule.completeness))
            }),
        );
        let calls = size_of_val(self.call_rules.as_ref()).saturating_add(
            self.call_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(rule.callee_artifact.path().as_str().len())
                    .saturating_add(declaration_heap_bytes(&rule.callee_declaration))
                    .saturating_add(rule.source.retained_bytes())
                    .saturating_add(rule.target.retained_bytes())
                    .saturating_add(proof_heap_bytes(&rule.proof))
                    .saturating_add(completeness_heap_bytes(&rule.completeness))
            }),
        );
        let fallbacks = size_of_val(self.fallback_rules.as_ref()).saturating_add(
            self.fallback_rules.iter().fold(0usize, |total, rule| {
                total
                    .saturating_add(size_of_val(rule.inputs.as_ref()))
                    .saturating_add(
                        rule.inputs
                            .iter()
                            .map(ValueFlowCarrierKey::retained_bytes)
                            .fold(0usize, usize::saturating_add),
                    )
                    .saturating_add(size_of_val(rule.reachable_components.as_ref()))
                    .saturating_add(
                        rule.normal_output
                            .as_ref()
                            .map_or(0, ValueFlowCarrierKey::retained_bytes),
                    )
                    .saturating_add(
                        rule.exceptional_output
                            .as_ref()
                            .map_or(0, ValueFlowCarrierKey::retained_bytes),
                    )
            }),
        );
        let location_bindings = size_of_val(self.location_bindings.as_ref()).saturating_add(
            self.location_bindings
                .iter()
                .map(|binding| binding.carrier.retained_bytes())
                .fold(0usize, usize::saturating_add),
        );
        std::mem::size_of::<Self>()
            .saturating_add(local)
            .saturating_add(calls)
            .saturating_add(size_of_val(self.curated_models.as_ref()))
            .saturating_add(size_of_val(self.external_summaries.as_ref()))
            .saturating_add(size_of_val(self.fallback_globals.as_ref()))
            .saturating_add(
                self.fallback_globals
                    .iter()
                    .map(ValueFlowCarrierKey::retained_bytes)
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(fallbacks)
            .saturating_add(location_bindings)
    }
}

fn declaration_heap_bytes(declaration: &DeclarationLocator) -> usize {
    size_of_val(declaration.segments()).saturating_add(
        declaration
            .segments()
            .iter()
            .filter_map(|segment| segment.name())
            .map(str::len)
            .fold(0usize, usize::saturating_add),
    )
}

fn proof_heap_bytes(proof: &ProofStatus) -> usize {
    match proof {
        ProofStatus::Proven => 0,
        ProofStatus::Unproven(reason) => reason.len(),
    }
}

fn completeness_heap_bytes(completeness: &EvidenceCompleteness) -> usize {
    match completeness {
        EvidenceCompleteness::Complete => 0,
        EvidenceCompleteness::Partial(reason) => reason.len(),
    }
}

fn summary_evidence_is_proven_complete(evidence: &SummaryEvidence) -> bool {
    evidence
        .alternatives()
        .iter()
        .any(|alternative| alternative.quality().is_proven() && alternative.quality().is_complete())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallFlowRule {
    pub call: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub kind: CallFlowRuleKind,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CallFallbackProfile {
    call: CallSiteHandle,
    inputs: Box<[ValueFlowCarrierId]>,
    reachable_components: Box<[usize]>,
    normal_output: Option<ValueFlowCarrierId>,
    exceptional_output: Option<ValueFlowCarrierId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundaryTransferApplication {
    pub modeled: bool,
    pub complete: bool,
    pub abstained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundBoundaryTransfer {
    pub target: ValueFlowCarrierId,
    pub proven_complete: bool,
}

/// One curated transfer model after its selector has been bound to a live
/// semantic call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowCuratedCallModel {
    call: CallSiteHandle,
    model: CuratedCallModel,
}

/// Structured binding from a summary heap/capture port to one live bounded
/// value-flow carrier at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowSummaryLocationBinding {
    call: CallSiteHandle,
    port: SummaryPort,
    carrier: ValueFlowCarrier,
}

impl ValueFlowSummaryLocationBinding {
    pub fn new(call: CallSiteHandle, port: SummaryPort, carrier: ValueFlowCarrier) -> Self {
        Self {
            call,
            port,
            carrier,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BoundSummaryLocationBinding {
    call: CallSiteHandle,
    port: SummaryPort,
    carrier: ValueFlowCarrierId,
}

impl ValueFlowCuratedCallModel {
    pub fn new(call: CallSiteHandle, model: CuratedCallModel) -> Self {
        Self { call, model }
    }

    pub fn call(&self) -> &CallSiteHandle {
        &self.call
    }

    pub const fn model(&self) -> &CuratedCallModel {
        &self.model
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundValueFlowSource {
    pub id: ValueFlowSourceId,
    pub spec: ValueFlowSourceSpec,
    pub carrier: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct BoundValueFlowSink {
    pub id: ValueFlowSinkId,
    pub spec: ValueFlowSinkSpec,
    pub carrier: ValueFlowCarrierId,
}

/// Immutable, canonical, already-resolved transfer plan for one solver run.
#[derive(Debug, Clone)]
pub struct ValueFlowPlan {
    root: ProcedureHandle,
    unmodeled_call_behavior: UnmodeledCallBehavior,
    external_summaries: ExternalSemanticSummarySet,
    curated_call_models: Box<[ValueFlowCuratedCallModel]>,
    carriers: Box<[ValueFlowCarrier]>,
    carrier_keys: Box<[ValueFlowCarrierKey]>,
    carrier_ids: HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    local_rules: Box<[LocalFlowRule]>,
    call_rules: Box<[CallFlowRule]>,
    fallback_profiles: Box<[CallFallbackProfile]>,
    fallback_locations: FallbackLocationIndex,
    summary_location_bindings: Box<[BoundSummaryLocationBinding]>,
    sources: Box<[BoundValueFlowSource]>,
    sinks: Box<[BoundValueFlowSink]>,
    snapshot_procedures: Box<[ProcedureHandle]>,
    binding_pairs: Box<[(CallSiteHandle, ProcedureHandle)]>,
    discovery_status: SemanticInputStatus,
    discovery_complete: bool,
    structural_discovery_complete: bool,
    owner: Arc<()>,
}

impl PartialEq for ValueFlowPlan {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.unmodeled_call_behavior == other.unmodeled_call_behavior
            && self.external_summaries == other.external_summaries
            && self.curated_call_models == other.curated_call_models
            && self.carriers == other.carriers
            && self.carrier_keys == other.carrier_keys
            && self.carrier_ids == other.carrier_ids
            && self.local_rules == other.local_rules
            && self.call_rules == other.call_rules
            && self.fallback_profiles == other.fallback_profiles
            && self.fallback_locations == other.fallback_locations
            && self.summary_location_bindings == other.summary_location_bindings
            && self.sources == other.sources
            && self.sinks == other.sinks
            && self.snapshot_procedures == other.snapshot_procedures
            && self.binding_pairs == other.binding_pairs
            && self.discovery_status == other.discovery_status
            && self.discovery_complete == other.discovery_complete
            && self.structural_discovery_complete == other.structural_discovery_complete
    }
}

impl Eq for ValueFlowPlan {}

impl Hash for ValueFlowPlan {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.unmodeled_call_behavior.hash(state);
        self.external_summaries.fingerprint().hash(state);
        self.curated_call_models.len().hash(state);
        for model in &self.curated_call_models {
            model.call.hash(state);
            model.model.fingerprint().hash(state);
        }
        self.carrier_keys.hash(state);
        self.local_rules.hash(state);
        self.call_rules.hash(state);
        self.fallback_profiles.hash(state);
        self.summary_location_bindings.hash(state);
        self.sources.hash(state);
        self.sinks.hash(state);
        self.snapshot_procedures.hash(state);
        self.binding_pairs.hash(state);
        self.discovery_status.hash(state);
        self.discovery_complete.hash(state);
        self.structural_discovery_complete.hash(state);
    }
}

impl ValueFlowPlan {
    pub fn try_new(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_call_behavior(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            UnmodeledCallBehavior::default(),
        )
    }

    pub fn with_call_behavior(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            ValueFlowPlanLimits::default(),
            unmodeled_call_behavior,
        )
    }

    pub fn with_limits(
        root: ProcedureHandle,
        snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        bindings: Vec<ValueFlowInput<CallBindings>>,
        sources: Vec<ValueFlowSourceSpec>,
        sinks: Vec<ValueFlowSinkSpec>,
        limits: ValueFlowPlanLimits,
    ) -> Result<Self, ValueFlowPlanError> {
        Self::with_limits_and_call_behavior(
            root,
            snapshots,
            bindings,
            sources,
            sinks,
            limits,
            UnmodeledCallBehavior::default(),
        )
    }

    pub fn with_limits_and_call_behavior(
        root: ProcedureHandle,
        mut snapshots: Vec<ValueFlowInput<ValueFlowSnapshot>>,
        mut bindings: Vec<ValueFlowInput<CallBindings>>,
        mut sources: Vec<ValueFlowSourceSpec>,
        mut sinks: Vec<ValueFlowSinkSpec>,
        limits: ValueFlowPlanLimits,
        unmodeled_call_behavior: UnmodeledCallBehavior,
    ) -> Result<Self, ValueFlowPlanError> {
        if sources.len() > limits.max_sources || sinks.len() > limits.max_sinks {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        if snapshots.iter().any(|input| {
            !input.value().context().calls().is_empty() || input.value().context().was_truncated()
        }) || bindings.iter().any(|input| {
            !input.value().context().calls().is_empty() || input.value().context().was_truncated()
        }) {
            return Err(ValueFlowPlanError::ContextSensitiveInputUnsupported);
        }
        snapshots.sort_by(|left, right| compare_snapshots(left.value(), right.value()));
        bindings.sort_by(|left, right| compare_bindings(left.value(), right.value()));
        sources.sort_by(|left, right| left.key().cmp(right.key()));
        sinks.sort_by(|left, right| left.key().cmp(right.key()));
        if adjacent_duplicate(sources.iter().map(ValueFlowSourceSpec::key))
            || adjacent_duplicate(sinks.iter().map(ValueFlowSinkSpec::key))
        {
            return Err(ValueFlowPlanError::DuplicateEventKey);
        }

        let mount = root.artifact().key().mount();
        let mut discovery_status = SemanticInputStatus::Complete;
        let mut discovery_complete = true;
        let mut structural_discovery_complete = true;
        let mut carrier_candidates = Vec::new();
        let mut relation_count = 0usize;
        let snapshot_procedures = snapshots
            .iter()
            .map(|input| input.value().procedure().clone())
            .collect::<Vec<_>>();
        let binding_pairs = bindings
            .iter()
            .map(|input| (input.value().call().clone(), input.value().callee().clone()))
            .collect::<Vec<_>>();
        for input in &snapshots {
            validate_mount(input.value().procedure(), mount)?;
            discovery_status = discovery_status.merge(input.status());
            discovery_complete &= input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Exhaustive;
            relation_count = relation_count.saturating_add(input.value().relations().len());
            for relation in input.value().relations() {
                carrier_candidates.push(ValueFlowCarrier::from(&relation.source));
                carrier_candidates.push(ValueFlowCarrier::from(&relation.target));
            }
        }
        for input in &bindings {
            validate_mount(input.value().call().procedure(), mount)?;
            validate_mount(input.value().callee(), mount)?;
            discovery_status = discovery_status.merge(input.status());
            discovery_complete &= input.status().is_complete()
                && input.value().coverage() == CandidateCoverage::Exhaustive
                && !input.value().context().was_truncated();
            structural_discovery_complete &= !input.value().context().was_truncated();
            for binding in input.value().bindings() {
                relation_count = relation_count.saturating_add(call_binding_rule_count(binding));
                append_binding_carriers(binding, &mut carrier_candidates)?;
            }
        }
        for source in &sources {
            validate_event(source.point(), source.carrier(), mount)?;
            discovery_complete &= matches!(source.proof(), ProofStatus::Proven)
                && matches!(source.completeness(), EvidenceCompleteness::Complete);
            structural_discovery_complete &= matches!(source.proof(), ProofStatus::Proven)
                && matches!(source.completeness(), EvidenceCompleteness::Complete);
            carrier_candidates.push(source.carrier().clone());
        }
        for sink in &sinks {
            validate_event(sink.point(), sink.carrier(), mount)?;
            discovery_complete &= matches!(sink.proof(), ProofStatus::Proven)
                && matches!(sink.completeness(), EvidenceCompleteness::Complete);
            structural_discovery_complete &= matches!(sink.proof(), ProofStatus::Proven)
                && matches!(sink.completeness(), EvidenceCompleteness::Complete);
            carrier_candidates.push(sink.carrier().clone());
        }
        if relation_count > limits.max_relations {
            return Err(ValueFlowPlanError::LimitExceeded);
        }

        let mut keyed = carrier_candidates
            .into_iter()
            .map(|carrier| Ok((carrier.stable_key()?, carrier)))
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        keyed.dedup_by(|left, right| left.1 == right.1);
        if keyed.len() > limits.max_carriers {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ValueFlowPlanError::StableCarrierCollision);
        }
        let mut carriers = Vec::with_capacity(keyed.len());
        let mut carrier_keys = Vec::with_capacity(keyed.len());
        let mut carrier_ids = HashMap::default();
        for (index, (key, carrier)) in keyed.into_iter().enumerate() {
            let id = ValueFlowCarrierId::try_from_index(index)
                .map_err(|_| ValueFlowPlanError::CarrierIdOverflow)?;
            carrier_ids.insert(carrier.clone(), id);
            carrier_keys.push(key);
            carriers.push(carrier);
        }

        let mut local_rules = Vec::new();
        for input in snapshots {
            let (snapshot, _) = input.into_parts();
            for relation in snapshot.relations() {
                local_rules.push(LocalFlowRule {
                    point: relation.point().clone(),
                    event_index: relation.event_index(),
                    kind: relation.kind,
                    source: lookup_carrier(&carrier_ids, &relation.source)?,
                    target: lookup_carrier(&carrier_ids, &relation.target)?,
                    proof: relation.proof.clone(),
                    completeness: relation.completeness.clone(),
                });
            }
        }
        local_rules.sort_by(compare_local_rules);

        let mut call_rules = Vec::new();
        for input in bindings {
            let (bindings, _) = input.into_parts();
            append_call_rules(&bindings, &carrier_ids, &mut call_rules)?;
        }
        call_rules.sort_by(compare_call_rules);
        call_rules.dedup_by(|left, right| {
            left.call == right.call
                && left.callee == right.callee
                && left.kind == right.kind
                && left.source == right.source
                && left.target == right.target
                && left.proof == right.proof
                && left.completeness == right.completeness
        });

        let carrier_components = build_carrier_components(carriers.len(), &local_rules);
        let fallback_locations =
            build_fallback_location_index(&carriers, &carrier_ids, &carrier_components);
        let fallback_profiles = build_call_fallback_profiles(
            std::iter::once(&root)
                .chain(snapshot_procedures.iter())
                .collect::<Vec<_>>(),
            &carrier_ids,
            &carrier_components,
        );

        let bound_sources = sources
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSource {
                    id: ValueFlowSourceId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SourceIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;
        let bound_sinks = sinks
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                Ok(BoundValueFlowSink {
                    id: ValueFlowSinkId::try_from_index(index)
                        .map_err(|_| ValueFlowPlanError::SinkIdOverflow)?,
                    carrier: *carrier_ids
                        .get(spec.carrier())
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                    spec,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?;

        Ok(Self {
            root,
            unmodeled_call_behavior,
            external_summaries: ExternalSemanticSummarySet::default(),
            curated_call_models: Box::default(),
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            call_rules: call_rules.into_boxed_slice(),
            fallback_profiles: fallback_profiles.into_boxed_slice(),
            fallback_locations,
            summary_location_bindings: Box::default(),
            sources: bound_sources.into_boxed_slice(),
            sinks: bound_sinks.into_boxed_slice(),
            snapshot_procedures: snapshot_procedures.into_boxed_slice(),
            binding_pairs: binding_pairs.into_boxed_slice(),
            discovery_status,
            discovery_complete,
            structural_discovery_complete,
            owner: Arc::new(()),
        })
    }

    pub fn root(&self) -> &ProcedureHandle {
        &self.root
    }

    /// Visit every concrete semantic artifact allocation retained by handles
    /// in this immutable plan. Duplicate allocations are intentional: bounded
    /// host registries deduplicate them while accounting and validating.
    pub(crate) fn for_each_retained_artifact(&self, mut visit: impl FnMut(&Arc<SemanticArtifact>)) {
        let mut visit_procedure = |procedure: &ProcedureHandle| visit(procedure.artifact());
        visit_procedure(&self.root);
        for procedure in &self.snapshot_procedures {
            visit_procedure(procedure);
        }
        for (call, callee) in &self.binding_pairs {
            visit_procedure(call.procedure());
            visit_procedure(callee);
        }
        for carrier in &self.carriers {
            if let Some(procedure) = carrier.procedure() {
                visit_procedure(procedure);
            }
        }
        for rule in &self.local_rules {
            visit_procedure(rule.point.procedure());
        }
        for rule in &self.call_rules {
            visit_procedure(rule.call.procedure());
            visit_procedure(&rule.callee);
        }
        for profile in &self.fallback_profiles {
            visit_procedure(profile.call.procedure());
        }
        for model in &self.curated_call_models {
            visit_procedure(model.call.procedure());
        }
        for binding in &self.summary_location_bindings {
            visit_procedure(binding.call.procedure());
        }
        for source in &self.sources {
            visit_procedure(source.spec.point().procedure());
        }
        for sink in &self.sinks {
            visit_procedure(sink.spec.point().procedure());
        }
    }

    /// Visit every semantic artifact identity retained by this plan.
    pub fn for_each_retained_artifact_key(&self, mut visit: impl FnMut(&SemanticArtifactKey)) {
        self.for_each_retained_artifact(|artifact| visit(artifact.key()));
    }

    /// Conservative retained size of plan-owned metadata, excluding semantic
    /// artifact allocations which host registries account separately.
    pub fn retained_bytes(&self) -> usize {
        let carrier_key_bytes = self
            .carrier_keys
            .iter()
            .map(ValueFlowCarrierKey::retained_bytes)
            .fold(0usize, usize::saturating_add);
        let local_rule_heap = self.local_rules.iter().fold(0usize, |total, rule| {
            total
                .saturating_add(proof_heap_bytes(&rule.proof))
                .saturating_add(completeness_heap_bytes(&rule.completeness))
        });
        let call_rule_heap = self.call_rules.iter().fold(0usize, |total, rule| {
            total
                .saturating_add(proof_heap_bytes(&rule.proof))
                .saturating_add(completeness_heap_bytes(&rule.completeness))
        });
        let source_heap = self.sources.iter().fold(0usize, |total, source| {
            total
                .saturating_add(source.spec.key().retained_bytes())
                .saturating_add(self.carrier_keys[source.carrier.index()].retained_bytes())
                .saturating_add(proof_heap_bytes(source.spec.proof()))
                .saturating_add(completeness_heap_bytes(source.spec.completeness()))
        });
        let sink_heap = self.sinks.iter().fold(0usize, |total, sink| {
            total
                .saturating_add(sink.spec.key().retained_bytes())
                .saturating_add(self.carrier_keys[sink.carrier.index()].retained_bytes())
                .saturating_add(proof_heap_bytes(sink.spec.proof()))
                .saturating_add(completeness_heap_bytes(sink.spec.completeness()))
        });

        std::mem::size_of::<Self>()
            .saturating_add(self.external_summaries.retained_heap_bytes())
            .saturating_add(size_of_val(self.curated_call_models.as_ref()))
            .saturating_add(
                self.curated_call_models
                    .iter()
                    .map(|model| model.model.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(size_of_val(self.carriers.as_ref()))
            // Locations own an access path in addition to the carrier enum.
            // Its stable key is a conservative structural estimate of that path.
            .saturating_add(carrier_key_bytes)
            .saturating_add(size_of_val(self.carrier_keys.as_ref()))
            .saturating_add(carrier_key_bytes)
            .saturating_add(
                self.carrier_ids
                    .capacity()
                    .saturating_mul(
                        std::mem::size_of::<(ValueFlowCarrier, ValueFlowCarrierId)>()
                            .saturating_add(1),
                    )
                    // The map clones every carrier; charge the structural keys
                    // again to conservatively cover cloned locations.
                    .saturating_add(carrier_key_bytes),
            )
            .saturating_add(size_of_val(self.local_rules.as_ref()))
            .saturating_add(local_rule_heap)
            .saturating_add(size_of_val(self.call_rules.as_ref()))
            .saturating_add(call_rule_heap)
            .saturating_add(size_of_val(self.fallback_profiles.as_ref()))
            .saturating_add(
                self.fallback_profiles
                    .iter()
                    .map(|profile| {
                        size_of_val(profile.inputs.as_ref())
                            .saturating_add(size_of_val(profile.reachable_components.as_ref()))
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.fallback_locations.retained_heap_bytes())
            .saturating_add(size_of_val(self.summary_location_bindings.as_ref()))
            .saturating_add(size_of_val(self.sources.as_ref()))
            .saturating_add(source_heap)
            .saturating_add(size_of_val(self.sinks.as_ref()))
            .saturating_add(sink_heap)
            .saturating_add(size_of_val(self.snapshot_procedures.as_ref()))
            .saturating_add(size_of_val(self.binding_pairs.as_ref()))
            // Account for the plan-ownership Arc allocation and reference counts.
            .saturating_add(
                std::mem::size_of::<usize>()
                    .saturating_mul(2)
                    .saturating_add(1),
            )
    }

    pub const fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.unmodeled_call_behavior
    }

    /// Install complete external semantic summaries used before the configured
    /// fallback profile. The set owns its content-addressed validity identity,
    /// so changing a model partitions value-flow and downstream taint caches.
    pub fn with_external_summaries(
        mut self,
        summaries: ExternalSemanticSummarySet,
    ) -> Result<Self, ValueFlowPlanError> {
        if summaries.compatibility().is_some_and(|compatibility| {
            compatibility.unmodeled_call_behavior() != self.unmodeled_call_behavior
                || compatibility.dependencies() != self.root.artifact().key().dependencies()
        }) {
            return Err(ValueFlowPlanError::IncompatibleExternalSummary);
        }
        self.external_summaries = summaries;
        Ok(self)
    }

    pub const fn external_summaries(&self) -> &ExternalSemanticSummarySet {
        &self.external_summaries
    }

    /// Install selector-bound curated models. Exactly one model may own a call
    /// site; exact target summaries are still selected first during transfer.
    pub fn with_curated_call_models(
        mut self,
        mut models: Vec<ValueFlowCuratedCallModel>,
    ) -> Result<Self, ValueFlowPlanError> {
        let mount = self.root.artifact().key().mount();
        for model in &models {
            validate_mount(model.call.procedure(), mount)?;
            if model
                .call
                .procedure()
                .semantics()
                .call_site(model.call.id())
                .is_none()
            {
                return Err(ValueFlowPlanError::StaleCallModel);
            }
        }
        models.sort_by(|left, right| compare_calls(&left.call, &right.call));
        if models.windows(2).any(|pair| pair[0].call == pair[1].call) {
            return Err(ValueFlowPlanError::DuplicateCallModel);
        }
        self.curated_call_models = models.into_boxed_slice();
        Ok(self)
    }

    /// Bind the stable heap/capture ports referenced by exact or curated
    /// models. The carriers must already belong to the demand-driven plan.
    pub fn with_summary_location_bindings(
        mut self,
        mut bindings: Vec<ValueFlowSummaryLocationBinding>,
    ) -> Result<Self, ValueFlowPlanError> {
        if bindings.len() > MAX_SUMMARY_BOUNDARY_BINDINGS {
            return Err(ValueFlowPlanError::LimitExceeded);
        }
        let mount = self.root.artifact().key().mount();
        for binding in &bindings {
            validate_mount(binding.call.procedure(), mount)?;
            if !matches!(binding.port, SummaryPort::Capture(_) | SummaryPort::Heap(_)) {
                return Err(ValueFlowPlanError::InvalidSummaryLocationPort);
            }
        }
        bindings.sort_by(|left, right| {
            compare_calls(&left.call, &right.call).then_with(|| left.port.cmp(&right.port))
        });
        if bindings
            .windows(2)
            .any(|pair| pair[0].call == pair[1].call && pair[0].port == pair[1].port)
        {
            return Err(ValueFlowPlanError::DuplicateSummaryLocationBinding);
        }
        self.summary_location_bindings = bindings
            .into_iter()
            .map(|binding| {
                Ok(BoundSummaryLocationBinding {
                    call: binding.call,
                    port: binding.port,
                    carrier: self
                        .carrier_id(&binding.carrier)
                        .ok_or(ValueFlowPlanError::MissingCarrier)?,
                })
            })
            .collect::<Result<Vec<_>, ValueFlowPlanError>>()?
            .into_boxed_slice();
        Ok(self)
    }

    pub fn carriers(&self) -> &[ValueFlowCarrier] {
        &self.carriers
    }

    pub fn carrier(&self, id: ValueFlowCarrierId) -> Option<&ValueFlowCarrier> {
        self.carriers.get(id.index())
    }

    pub fn carrier_key(&self, id: ValueFlowCarrierId) -> Option<&ValueFlowCarrierKey> {
        self.carrier_keys.get(id.index())
    }

    pub(crate) fn carrier_id_for_key(
        &self,
        key: &ValueFlowCarrierKey,
    ) -> Option<ValueFlowCarrierId> {
        self.carrier_keys
            .binary_search(key)
            .ok()
            .and_then(|index| ValueFlowCarrierId::try_from_index(index).ok())
    }

    pub(crate) fn sink_id_for_key(
        &self,
        key: &super::ValueFlowEventKey,
    ) -> Option<ValueFlowSinkId> {
        self.sinks
            .binary_search_by(|sink| sink.spec.key().cmp(key))
            .ok()
            .map(|index| self.sinks[index].id)
    }

    pub fn carrier_id(&self, carrier: &ValueFlowCarrier) -> Option<ValueFlowCarrierId> {
        self.carrier_ids.get(carrier).copied()
    }

    pub const fn discovery_status(&self) -> SemanticInputStatus {
        self.discovery_status
    }

    pub const fn discovery_complete(&self) -> bool {
        self.discovery_complete
    }

    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }

    pub(crate) fn execution_discovery_complete<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> bool {
        self.structural_discovery_complete
            && result.reached().iter().all(|reached| {
                let procedure = reached.point().procedure();
                self.has_snapshot(procedure)
                    && procedure
                        .semantics()
                        .point(reached.point().id())
                        .is_some_and(|point| {
                            point.events.iter().all(|event| match event.effect {
                                SemanticEffect::Invoke { call_site } => {
                                    procedure.call_site_handle(call_site).is_some_and(|call| {
                                        self.has_binding_for_call(&call)
                                            || self.call_boundaries_are_fully_modeled(result, &call)
                                    })
                                }
                                _ => true,
                            })
                        })
            })
    }

    pub(crate) fn execution_result_complete<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
    ) -> bool {
        if !result.termination().is_fixed_point() || !self.execution_discovery_complete(result) {
            return false;
        }
        let fully_modeled_calls = result
            .coverage()
            .boundaries()
            .iter()
            .filter_map(SummaryBoundary::origin)
            .filter(|call| self.call_boundaries_are_fully_modeled(result, call))
            .collect::<Vec<_>>();
        let edge_is_discharged = |edge: &crate::analyzer::dataflow::SummaryEdge| {
            matches!(
                edge.kind(),
                IcfgEdgeKind::CallToNormalContinuation
                    | IcfgEdgeKind::CallToExceptionalContinuation
            ) && edge
                .origin()
                .is_some_and(|origin| fully_modeled_calls.contains(&origin))
        };
        result
            .coverage()
            .unproven_edges()
            .iter()
            .all(edge_is_discharged)
            && result
                .coverage()
                .partial_edges()
                .iter()
                .all(edge_is_discharged)
            && result
                .coverage()
                .boundaries()
                .iter()
                .all(|boundary| self.boundary_is_fully_modeled(result, boundary))
    }

    fn call_boundaries_are_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        call: &CallSiteHandle,
    ) -> bool {
        let mut saw_dispatch = false;
        for boundary in result
            .coverage()
            .boundaries()
            .iter()
            .filter(|boundary| boundary.origin() == Some(call))
        {
            match boundary.kind() {
                SummaryBoundaryKind::Dispatch(_) => {
                    saw_dispatch = true;
                    if !self.dispatch_boundary_is_fully_modeled(boundary) {
                        return false;
                    }
                }
                SummaryBoundaryKind::Semantic(_) => {}
                SummaryBoundaryKind::Limit(_) | SummaryBoundaryKind::Continuation { .. } => {
                    return false;
                }
            }
        }
        saw_dispatch
    }

    fn boundary_is_fully_modeled<Fact>(
        &self,
        result: &SummaryDataflowResult<Fact>,
        boundary: &SummaryBoundary,
    ) -> bool {
        if matches!(boundary.kind(), SummaryBoundaryKind::Semantic(_)) {
            return boundary
                .origin()
                .is_some_and(|call| self.call_boundaries_are_fully_modeled(result, call));
        }
        self.dispatch_boundary_is_fully_modeled(boundary)
    }

    fn dispatch_boundary_is_fully_modeled(&self, boundary: &SummaryBoundary) -> bool {
        let Some(call) = boundary.origin() else {
            return false;
        };
        let SummaryBoundaryKind::Dispatch(kind) = boundary.kind() else {
            return false;
        };
        if let Some(summary) = self.external_summary_for_boundary(kind) {
            return matches!(boundary.proof(), Some(ProofStatus::Proven))
                && summary.completeness().is_complete()
                && self.model_is_fully_bindable(call, summary.transfers());
        }
        self.curated_model_for_call(call)
            .is_some_and(|model| self.model_is_fully_bindable(call, model.transfers()))
    }

    fn model_is_fully_bindable(
        &self,
        call: &CallSiteHandle,
        transfers: &[SummaryTransfer],
    ) -> bool {
        transfers.iter().all(|transfer| {
            summary_evidence_is_proven_complete(transfer.evidence())
                && self.summary_port_carrier(call, transfer.input()).is_some()
                && self
                    .summary_port_carrier(call, transfer.exit().port())
                    .is_some()
        })
    }

    pub(crate) fn has_snapshot(&self, procedure: &ProcedureHandle) -> bool {
        self.snapshot_procedures
            .iter()
            .any(|candidate| candidate == procedure)
    }

    pub(crate) fn summary_procedures(&self) -> impl Iterator<Item = &ProcedureHandle> {
        std::iter::once(&self.root).chain(self.snapshot_procedures.iter())
    }

    pub(crate) fn has_binding_for_call(&self, call: &CallSiteHandle) -> bool {
        self.binding_pairs
            .iter()
            .any(|(candidate, _)| candidate == call)
    }

    pub(crate) fn carrier_summary_identities(
        &self,
    ) -> HashMap<ProcedureHandle, ValueFlowCarrierSummaryIdentity> {
        #[derive(Default)]
        struct Builder {
            has_snapshot: bool,
            local_rules: Vec<ValueFlowLocalSummaryRule>,
            call_rules: Vec<ValueFlowCallSummaryRule>,
            curated_models: Vec<ValueFlowCuratedModelSummaryRule>,
            fallback_rules: Vec<ValueFlowFallbackSummaryRule>,
            location_bindings: Vec<ValueFlowLocationBindingSummaryRule>,
        }

        let mut builders = HashMap::<ProcedureHandle, Builder>::default();
        for procedure in self.summary_procedures() {
            builders.entry(procedure.clone()).or_default().has_snapshot |=
                self.has_snapshot(procedure);
        }
        for rule in &self.local_rules {
            builders
                .entry(rule.point.procedure().clone())
                .or_default()
                .local_rules
                .push(ValueFlowLocalSummaryRule {
                    point: rule.point.id(),
                    event_index: rule.event_index,
                    kind: rule.kind,
                    source: self.carrier_keys[rule.source.index()].clone(),
                    target: self.carrier_keys[rule.target.index()].clone(),
                    proof: rule.proof.clone(),
                    completeness: rule.completeness.clone(),
                });
        }
        for rule in &self.call_rules {
            builders
                .entry(rule.call.procedure().clone())
                .or_default()
                .call_rules
                .push(ValueFlowCallSummaryRule {
                    call: rule.call.id(),
                    callee_artifact: rule.callee.artifact().key().clone(),
                    callee_declaration: rule.callee.semantics().locator().declaration().clone(),
                    kind: rule.kind,
                    source: self.carrier_keys[rule.source.index()].clone(),
                    target: self.carrier_keys[rule.target.index()].clone(),
                    proof: rule.proof.clone(),
                    completeness: rule.completeness.clone(),
                });
        }
        for model in &self.curated_call_models {
            builders
                .entry(model.call.procedure().clone())
                .or_default()
                .curated_models
                .push(ValueFlowCuratedModelSummaryRule {
                    call: model.call.id(),
                    model: model.model.fingerprint(),
                });
        }
        for profile in &self.fallback_profiles {
            builders
                .entry(profile.call.procedure().clone())
                .or_default()
                .fallback_rules
                .push(ValueFlowFallbackSummaryRule {
                    call: profile.call.id(),
                    inputs: profile
                        .inputs
                        .iter()
                        .map(|carrier| self.carrier_keys[carrier.index()].clone())
                        .collect(),
                    reachable_components: profile.reachable_components.clone(),
                    normal_output: profile
                        .normal_output
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                    exceptional_output: profile
                        .exceptional_output
                        .map(|carrier| self.carrier_keys[carrier.index()].clone()),
                });
        }
        for binding in &self.summary_location_bindings {
            builders
                .entry(binding.call.procedure().clone())
                .or_default()
                .location_bindings
                .push(ValueFlowLocationBindingSummaryRule {
                    call: binding.call.id(),
                    port: binding.port.clone(),
                    carrier: self.carrier_keys[binding.carrier.index()].clone(),
                });
        }
        builders
            .into_iter()
            .map(|(procedure, builder)| {
                let external_summaries = self.external_summary_fingerprints_for(&procedure);
                let fallback_globals = if builder.fallback_rules.is_empty() {
                    Box::default()
                } else {
                    self.fallback_locations
                        .bounded_globals
                        .iter()
                        .map(|carrier| self.carrier_keys[carrier.index()].clone())
                        .collect()
                };
                (
                    procedure,
                    ValueFlowCarrierSummaryIdentity {
                        unmodeled_call_behavior: self.unmodeled_call_behavior,
                        external_summaries,
                        fallback_globals,
                        has_snapshot: builder.has_snapshot,
                        local_rules: builder.local_rules.into_boxed_slice(),
                        call_rules: builder.call_rules.into_boxed_slice(),
                        curated_models: builder.curated_models.into_boxed_slice(),
                        fallback_rules: builder.fallback_rules.into_boxed_slice(),
                        location_bindings: builder.location_bindings.into_boxed_slice(),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn carrier_summary_identity_total_rows(&self) -> usize {
        self.local_rules
            .len()
            .saturating_add(self.call_rules.len())
            .saturating_add(self.curated_call_models.len())
            .saturating_add(self.summary_location_bindings.len())
            .saturating_add(
                self.fallback_profiles
                    .iter()
                    .fold(0usize, |total, profile| {
                        total
                            .saturating_add(1)
                            .saturating_add(profile.inputs.len())
                            .saturating_add(profile.reachable_components.len())
                            .saturating_add(usize::from(profile.normal_output.is_some()))
                            .saturating_add(usize::from(profile.exceptional_output.is_some()))
                    }),
            )
            .saturating_add(self.fallback_locations.bounded_globals.len())
    }

    fn external_summary_fingerprints_for(
        &self,
        procedure: &ProcedureHandle,
    ) -> Box<[ExternalSummarySetFingerprint]> {
        let mut fingerprints = Vec::new();
        for call in procedure.semantics().call_sites() {
            let targets: &[CallableTarget] = match &call.declared_targets {
                CallableTargetResolution::Proven(target) => std::slice::from_ref(target),
                CallableTargetResolution::Ambiguous(targets)
                | CallableTargetResolution::Unproven(targets)
                | CallableTargetResolution::ExceededBudget(targets) => targets,
                CallableTargetResolution::Unknown | CallableTargetResolution::Unsupported => {
                    return vec![self.external_summaries.fingerprint()].into_boxed_slice();
                }
            };
            fingerprints.extend(targets.iter().filter_map(|target| match target {
                CallableTarget::Local(_) => None,
                CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                    self.external_summaries.fingerprint_for(locator)
                }
            }));
        }
        fingerprints.sort_unstable();
        fingerprints.dedup();
        fingerprints.into_boxed_slice()
    }

    pub(crate) fn is_call_input(&self, call: &CallSiteHandle, carrier: ValueFlowCarrierId) -> bool {
        let Some(profile) = self.fallback_profile(call) else {
            return false;
        };
        profile.inputs.binary_search(&carrier).is_ok()
            || self
                .fallback_locations
                .bounded_globals
                .binary_search(&carrier)
                .is_ok()
            || self
                .fallback_locations
                .location_components
                .get(&carrier)
                .is_some_and(|component| {
                    profile
                        .reachable_components
                        .binary_search(component)
                        .is_ok()
                })
    }

    pub(crate) fn external_summary_for_boundary(
        &self,
        boundary: &DispatchBoundaryKind,
    ) -> Option<&SemanticProcedureSummary> {
        if matches!(boundary, DispatchBoundaryKind::Deferred { .. }) {
            return None;
        }
        self.external_summaries
            .summary_for(boundary.target_locator()?)
    }

    pub(crate) fn curated_model_for_call(
        &self,
        call: &CallSiteHandle,
    ) -> Option<&CuratedCallModel> {
        self.curated_call_models
            .binary_search_by(|candidate| compare_calls(&candidate.call, call))
            .ok()
            .map(|index| &self.curated_call_models[index].model)
    }

    fn summary_port_carrier(
        &self,
        call: &CallSiteHandle,
        port: &SummaryPort,
    ) -> Option<ValueFlowCarrierId> {
        if matches!(port, SummaryPort::Capture(_) | SummaryPort::Heap(_)) {
            return self
                .summary_location_bindings
                .binary_search_by(|binding| {
                    compare_calls(&binding.call, call).then_with(|| binding.port.cmp(port))
                })
                .ok()
                .map(|index| self.summary_location_bindings[index].carrier);
        }
        let row = call.procedure().semantics().call_site(call.id())?;
        let value = match port {
            SummaryPort::Receiver => row.receiver?,
            SummaryPort::Parameter(index) => row.arguments.get(*index as usize)?.value,
            SummaryPort::NormalReturn => row.result?,
            SummaryPort::ExceptionalReturn => row.thrown?,
            SummaryPort::Capture(_) | SummaryPort::Heap(_) => return None,
        };
        let value = call.procedure().value_handle(value)?;
        self.carrier_id(&ValueFlowCarrier::Value(value))
    }

    pub(crate) fn visit_boundary_transfers(
        &self,
        call: &CallSiteHandle,
        boundary: Option<&DispatchBoundaryKind>,
        kind: IcfgEdgeKind,
        input: ValueFlowCarrierId,
        mut visitor: impl FnMut(BoundBoundaryTransfer) -> bool,
    ) -> BoundaryTransferApplication {
        if let Some(summary) =
            boundary.and_then(|boundary| self.external_summary_for_boundary(boundary))
        {
            return self.visit_modeled_transfers(
                call,
                kind,
                input,
                summary.transfers(),
                summary.completeness().is_complete(),
                visitor,
            );
        }
        if let Some(model) = self.curated_model_for_call(call) {
            return self.visit_modeled_transfers(
                call,
                kind,
                input,
                model.transfers(),
                true,
                visitor,
            );
        }

        let is_input = self.is_call_input(call, input);
        if self.unmodeled_call_behavior == UnmodeledCallBehavior::Paranoid && is_input {
            self.visit_fallback_outputs(call, kind, |target| {
                visitor(BoundBoundaryTransfer {
                    target,
                    proven_complete: false,
                })
            });
        }
        BoundaryTransferApplication {
            modeled: false,
            complete: false,
            abstained: self.unmodeled_call_behavior == UnmodeledCallBehavior::RequireModel
                && is_input,
        }
    }

    fn visit_modeled_transfers(
        &self,
        call: &CallSiteHandle,
        kind: IcfgEdgeKind,
        input: ValueFlowCarrierId,
        transfers: &[SummaryTransfer],
        mut complete: bool,
        mut visitor: impl FnMut(BoundBoundaryTransfer) -> bool,
    ) -> BoundaryTransferApplication {
        let exit = match kind {
            IcfgEdgeKind::CallToNormalContinuation => SummaryExitKind::Normal,
            IcfgEdgeKind::CallToExceptionalContinuation => SummaryExitKind::Exceptional,
            _ => {
                return BoundaryTransferApplication {
                    modeled: false,
                    complete: false,
                    abstained: false,
                };
            }
        };
        for transfer in transfers
            .iter()
            .filter(|transfer| transfer.exit().kind() == exit)
        {
            let Some(source) = self.summary_port_carrier(call, transfer.input()) else {
                complete = false;
                continue;
            };
            let Some(target) = self.summary_port_carrier(call, transfer.exit().port()) else {
                complete = false;
                continue;
            };
            if source == input
                && !visitor(BoundBoundaryTransfer {
                    target,
                    proven_complete: summary_evidence_is_proven_complete(transfer.evidence()),
                })
            {
                break;
            }
            complete &= summary_evidence_is_proven_complete(transfer.evidence());
        }
        BoundaryTransferApplication {
            modeled: true,
            complete,
            abstained: false,
        }
    }

    fn visit_fallback_outputs(
        &self,
        call: &CallSiteHandle,
        kind: IcfgEdgeKind,
        mut visitor: impl FnMut(ValueFlowCarrierId) -> bool,
    ) {
        let Some(profile) = self.fallback_profile(call) else {
            return;
        };
        for target in self.fallback_locations.bounded_globals.iter().copied() {
            if !visitor(target) {
                return;
            }
        }
        for component in &profile.reachable_components {
            if let Some(targets) = self.fallback_locations.by_component.get(component) {
                for target in targets.iter().copied() {
                    if !visitor(target) {
                        return;
                    }
                }
            }
        }
        let result = match kind {
            IcfgEdgeKind::CallToNormalContinuation => profile.normal_output,
            IcfgEdgeKind::CallToExceptionalContinuation => profile.exceptional_output,
            _ => None,
        };
        if let Some(result) = result {
            let already_emitted = self
                .fallback_locations
                .bounded_globals
                .binary_search(&result)
                .is_ok()
                || profile.reachable_components.iter().any(|component| {
                    self.fallback_locations
                        .by_component
                        .get(component)
                        .is_some_and(|targets| targets.binary_search(&result).is_ok())
                });
            if !already_emitted {
                let _ = visitor(result);
            }
        }
    }

    fn fallback_profile(&self, call: &CallSiteHandle) -> Option<&CallFallbackProfile> {
        self.fallback_profiles
            .binary_search_by(|profile| compare_calls(&profile.call, call))
            .ok()
            .map(|index| &self.fallback_profiles[index])
    }

    pub(crate) fn is_callee_port(
        &self,
        carrier: ValueFlowCarrierId,
        callee: &ProcedureHandle,
    ) -> bool {
        matches!(self.carrier(carrier), Some(ValueFlowCarrier::Port(port)) if port.procedure() == callee)
    }

    pub fn source(&self, id: ValueFlowSourceId) -> Option<&ValueFlowSourceSpec> {
        self.sources.get(id.index()).map(|source| &source.spec)
    }

    pub fn sources(
        &self,
    ) -> impl ExactSizeIterator<Item = (ValueFlowSourceId, &ValueFlowSourceSpec)> {
        self.sources.iter().map(|source| (source.id, &source.spec))
    }

    pub fn sink(&self, id: ValueFlowSinkId) -> Option<&ValueFlowSinkSpec> {
        self.sinks.get(id.index()).map(|sink| &sink.spec)
    }

    pub fn sinks(&self) -> impl ExactSizeIterator<Item = (ValueFlowSinkId, &ValueFlowSinkSpec)> {
        self.sinks.iter().map(|sink| (sink.id, &sink.spec))
    }

    pub(crate) fn local_rules_at(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = &LocalFlowRule> {
        self.local_rules
            .iter()
            .filter(move |rule| &rule.point == point)
    }

    pub(crate) fn local_rule_views(
        &self,
        point: &ProgramPointHandle,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, ValueFlowCarrierId, bool)> {
        self.local_rules_at(point).map(|rule| {
            (
                rule.source,
                rule.target,
                matches!(rule.proof, ProofStatus::Proven)
                    && matches!(rule.completeness, EvidenceCompleteness::Complete),
            )
        })
    }

    pub(crate) fn call_rules<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        kind: CallFlowRuleKind,
    ) -> impl Iterator<Item = &'a CallFlowRule> + 'a {
        self.call_rules
            .iter()
            .filter(move |rule| &rule.call == call && &rule.callee == callee && rule.kind == kind)
    }

    pub(crate) fn call_targets<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules(call, callee, CallFlowRuleKind::Call)
            .filter(move |rule| rule.source == source)
            .map(rule_target)
    }

    pub(crate) fn normal_return_targets<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules(call, callee, CallFlowRuleKind::NormalReturn)
            .filter(move |rule| rule.source == source)
            .map(rule_target)
    }

    pub(crate) fn exceptional_return_targets<'a>(
        &'a self,
        call: &'a CallSiteHandle,
        callee: &'a ProcedureHandle,
        source: ValueFlowCarrierId,
    ) -> impl Iterator<Item = (ValueFlowCarrierId, bool)> + 'a {
        self.call_rules(call, callee, CallFlowRuleKind::ExceptionalReturn)
            .filter(move |rule| rule.source == source)
            .map(rule_target)
    }

    pub(crate) fn sources_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = &BoundValueFlowSource> {
        self.sources
            .iter()
            .filter(move |source| source.spec.point() == point && source.spec.phase() == phase)
    }

    pub(crate) fn source_bindings_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = (ValueFlowSourceId, ValueFlowCarrierId)> {
        self.sources_at(point, phase)
            .map(|source| (source.id, source.carrier))
    }

    pub(crate) fn sinks_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = &BoundValueFlowSink> {
        self.sinks
            .iter()
            .filter(move |sink| sink.spec.point() == point && sink.spec.phase() == phase)
    }

    pub(crate) fn sink_bindings_at(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
    ) -> impl Iterator<Item = (ValueFlowSinkId, ValueFlowCarrierId)> {
        self.sinks_at(point, phase)
            .map(|sink| (sink.id, sink.carrier))
    }
}

fn rule_target(rule: &CallFlowRule) -> (ValueFlowCarrierId, bool) {
    (
        rule.target,
        matches!(rule.proof, ProofStatus::Proven)
            && matches!(rule.completeness, EvidenceCompleteness::Complete),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowPlanError {
    InvalidLimits,
    LimitExceeded,
    ForeignWorkspace,
    InvalidEventCarrier,
    ContextSensitiveInputUnsupported,
    InvalidCallArgumentLocation,
    DuplicateEventKey,
    DuplicateCallModel,
    StaleCallModel,
    InvalidSummaryLocationPort,
    DuplicateSummaryLocationBinding,
    IncompatibleExternalSummary,
    StableCarrierCollision,
    CarrierIdOverflow,
    SourceIdOverflow,
    SinkIdOverflow,
    MissingCarrier,
    Model(ValueFlowModelError),
}

impl fmt::Display for ValueFlowPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid value-flow plan limits"),
            Self::LimitExceeded => formatter.write_str("value-flow plan limit exceeded"),
            Self::ForeignWorkspace => {
                formatter.write_str("value-flow input belongs to another workspace mount")
            }
            Self::InvalidEventCarrier => {
                formatter.write_str("value-flow event carrier belongs to another procedure")
            }
            Self::ContextSensitiveInputUnsupported => formatter.write_str(
                "context-sensitive oracle input cannot be flattened into a value-flow plan",
            ),
            Self::InvalidCallArgumentLocation => {
                formatter.write_str("call argument contains an invalid abstract location")
            }
            Self::DuplicateEventKey => formatter.write_str("duplicate value-flow event key"),
            Self::DuplicateCallModel => {
                formatter.write_str("multiple curated call models target the same call site")
            }
            Self::StaleCallModel => formatter.write_str("curated call model targets a stale call"),
            Self::InvalidSummaryLocationPort => {
                formatter.write_str("summary location binding requires a heap or capture port")
            }
            Self::DuplicateSummaryLocationBinding => formatter
                .write_str("multiple summary location bindings target the same call and port"),
            Self::IncompatibleExternalSummary => formatter
                .write_str("external summaries are incompatible with the active analysis contract"),
            Self::StableCarrierCollision => {
                formatter.write_str("distinct value-flow carriers share one stable key")
            }
            Self::CarrierIdOverflow => formatter.write_str("value-flow carrier ID overflow"),
            Self::SourceIdOverflow => formatter.write_str("value-flow source ID overflow"),
            Self::SinkIdOverflow => formatter.write_str("value-flow sink ID overflow"),
            Self::MissingCarrier => formatter.write_str("value-flow plan carrier is missing"),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

impl Error for ValueFlowPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ValueFlowModelError> for ValueFlowPlanError {
    fn from(error: ValueFlowModelError) -> Self {
        Self::Model(error)
    }
}

fn validate_mount(
    procedure: &ProcedureHandle,
    mount: crate::analyzer::semantic::WorkspaceMountId,
) -> Result<(), ValueFlowPlanError> {
    if procedure.artifact().key().mount() == mount {
        Ok(())
    } else {
        Err(ValueFlowPlanError::ForeignWorkspace)
    }
}

fn validate_event(
    point: &ProgramPointHandle,
    carrier: &ValueFlowCarrier,
    mount: crate::analyzer::semantic::WorkspaceMountId,
) -> Result<(), ValueFlowPlanError> {
    validate_mount(point.procedure(), mount)?;
    if carrier
        .procedure()
        .is_some_and(|procedure| procedure != point.procedure())
    {
        return Err(ValueFlowPlanError::InvalidEventCarrier);
    }
    Ok(())
}

fn lookup_carrier(
    ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    endpoint: &crate::analyzer::semantic::ValueFlowEndpoint,
) -> Result<ValueFlowCarrierId, ValueFlowPlanError> {
    ids.get(&ValueFlowCarrier::from(endpoint))
        .copied()
        .ok_or(ValueFlowPlanError::MissingCarrier)
}

fn append_binding_carriers(
    binding: &CallBinding,
    output: &mut Vec<ValueFlowCarrier>,
) -> Result<(), ValueFlowPlanError> {
    match binding {
        CallBinding::Receiver { actual, formal, .. } => {
            output.push(ValueFlowCarrier::Value(actual.clone()));
            output.push(ValueFlowCarrier::Port(formal.clone()));
        }
        CallBinding::ArgumentGroup(group) => {
            for mapping in group.mappings() {
                output.push(argument_carrier(mapping.value().actual())?);
                output.push(ValueFlowCarrier::Port(mapping.value().formal().clone()));
            }
        }
        CallBinding::ImplicitArgument { source, formal, .. } => {
            output.push(ValueFlowCarrier::Value(source.clone()));
            output.push(ValueFlowCarrier::Port(formal.clone()));
        }
        CallBinding::NormalReturn { formal, result, .. }
        | CallBinding::ExceptionalReturn { formal, result, .. } => {
            output.push(ValueFlowCarrier::Port(formal.clone()));
            output.push(ValueFlowCarrier::Value(result.clone()));
        }
    }
    Ok(())
}

fn call_binding_rule_count(binding: &CallBinding) -> usize {
    match binding {
        CallBinding::ArgumentGroup(group) => group.mappings().len(),
        _ => 1,
    }
}

fn append_call_rules(
    bindings: &CallBindings,
    ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    output: &mut Vec<CallFlowRule>,
) -> Result<(), ValueFlowPlanError> {
    let mut append =
        |kind, source: ValueFlowCarrier, target: ValueFlowCarrier, proof, completeness| {
            output.push(CallFlowRule {
                call: bindings.call().clone(),
                callee: bindings.callee().clone(),
                kind,
                source: *ids.get(&source).ok_or(ValueFlowPlanError::MissingCarrier)?,
                target: *ids.get(&target).ok_or(ValueFlowPlanError::MissingCarrier)?,
                proof,
                completeness,
            });
            Ok::<_, ValueFlowPlanError>(())
        };
    for binding in bindings.bindings() {
        match binding {
            CallBinding::Receiver { actual, formal, .. } => append(
                CallFlowRuleKind::Call,
                ValueFlowCarrier::Value(actual.clone()),
                ValueFlowCarrier::Port(formal.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
            CallBinding::ArgumentGroup(group) => {
                for mapping in group.mappings() {
                    append(
                        CallFlowRuleKind::Call,
                        argument_carrier(mapping.value().actual())?,
                        ValueFlowCarrier::Port(mapping.value().formal().clone()),
                        mapping.proof().clone(),
                        mapping.completeness().clone(),
                    )?;
                }
            }
            CallBinding::ImplicitArgument { source, formal, .. } => append(
                CallFlowRuleKind::Call,
                ValueFlowCarrier::Value(source.clone()),
                ValueFlowCarrier::Port(formal.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
            CallBinding::NormalReturn { formal, result, .. } => append(
                CallFlowRuleKind::NormalReturn,
                ValueFlowCarrier::Port(formal.clone()),
                ValueFlowCarrier::Value(result.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
            CallBinding::ExceptionalReturn { formal, result, .. } => append(
                CallFlowRuleKind::ExceptionalReturn,
                ValueFlowCarrier::Port(formal.clone()),
                ValueFlowCarrier::Value(result.clone()),
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            )?,
        }
    }
    Ok(())
}

fn argument_carrier(
    endpoint: &CallArgumentEndpoint,
) -> Result<ValueFlowCarrier, ValueFlowPlanError> {
    match endpoint {
        CallArgumentEndpoint::Value(value) => Ok(ValueFlowCarrier::Value(value.clone())),
        CallArgumentEndpoint::Location { location, .. } => {
            let cardinality = if matches!(location.path().root(), AccessPathRoot::TypeSummary(_)) {
                ObjectCardinality::Summary
            } else {
                ObjectCardinality::Unknown
            };
            let object = AbstractObject::new(location.path().root().clone(), cardinality)
                .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
            let location = AbstractLocation::new(object, location.path().clone())
                .map_err(|_| ValueFlowPlanError::InvalidCallArgumentLocation)?;
            Ok(ValueFlowCarrier::Location(Box::new(location)))
        }
    }
}

fn build_call_fallback_profiles(
    mut procedures: Vec<&ProcedureHandle>,
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    carrier_components: &[usize],
) -> Vec<CallFallbackProfile> {
    procedures.sort_by(|left, right| compare_procedures(left, right));
    procedures.dedup_by(|left, right| *left == *right);
    let mut profiles = Vec::new();
    for procedure in procedures {
        for row in procedure.semantics().call_sites() {
            let Some(call) = procedure.call_site_handle(row.id) else {
                continue;
            };
            let mut input_values = Vec::with_capacity(row.arguments.len().saturating_add(1));
            if let Some(receiver) = row.receiver.and_then(|value| procedure.value_handle(value)) {
                input_values.push(receiver);
            }
            input_values.extend(
                row.arguments
                    .iter()
                    .filter_map(|argument| procedure.value_handle(argument.value)),
            );

            let mut inputs = input_values
                .iter()
                .filter_map(|value| {
                    carrier_ids
                        .get(&ValueFlowCarrier::Value(value.clone()))
                        .copied()
                })
                .collect::<Vec<_>>();
            let mut input_components = inputs
                .iter()
                .map(|carrier| carrier_components[carrier.index()])
                .collect::<Vec<_>>();
            input_components.sort_unstable();
            input_components.dedup();
            inputs.sort_unstable();
            inputs.dedup();
            let result_carrier = |value| {
                procedure
                    .value_handle(value)
                    .and_then(|value| carrier_ids.get(&ValueFlowCarrier::Value(value)).copied())
            };
            profiles.push(CallFallbackProfile {
                call,
                inputs: inputs.into_boxed_slice(),
                reachable_components: input_components.into_boxed_slice(),
                normal_output: row.result.and_then(result_carrier),
                exceptional_output: row.thrown.and_then(result_carrier),
            });
        }
    }
    profiles.sort_by(|left, right| compare_calls(&left.call, &right.call));
    profiles
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FallbackLocationIndex {
    by_component: HashMap<usize, Vec<ValueFlowCarrierId>>,
    bounded_globals: Vec<ValueFlowCarrierId>,
    location_components: HashMap<ValueFlowCarrierId, usize>,
}

impl FallbackLocationIndex {
    fn retained_heap_bytes(&self) -> usize {
        let by_component = self
            .by_component
            .capacity()
            .saturating_mul(
                std::mem::size_of::<(usize, Vec<ValueFlowCarrierId>)>().saturating_add(1),
            )
            .saturating_add(
                self.by_component
                    .values()
                    .map(|carriers| {
                        carriers
                            .capacity()
                            .saturating_mul(std::mem::size_of::<ValueFlowCarrierId>())
                    })
                    .fold(0usize, usize::saturating_add),
            );
        let bounded_globals = self
            .bounded_globals
            .capacity()
            .saturating_mul(std::mem::size_of::<ValueFlowCarrierId>());
        let location_components = self
            .location_components
            .capacity()
            .saturating_mul(std::mem::size_of::<(ValueFlowCarrierId, usize)>().saturating_add(1));
        by_component
            .saturating_add(bounded_globals)
            .saturating_add(location_components)
    }
}

fn build_fallback_location_index(
    carriers: &[ValueFlowCarrier],
    carrier_ids: &HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    carrier_components: &[usize],
) -> FallbackLocationIndex {
    let mut index = FallbackLocationIndex::default();
    for (position, carrier) in carriers.iter().enumerate() {
        let ValueFlowCarrier::Location(location) = carrier else {
            continue;
        };
        let id = ValueFlowCarrierId::try_from_index(position)
            .expect("canonical carrier count is bounded before fallback indexing");
        let root = location.path().root();
        if matches!(
            root,
            AccessPathRoot::Static(_)
                | AccessPathRoot::TypeSummary(_)
                | AccessPathRoot::ModuleObject(_)
                | AccessPathRoot::External(_)
        ) {
            index.bounded_globals.push(id);
        } else if let Some(component) = root_carrier(root)
            .and_then(|carrier| carrier_ids.get(&carrier).copied())
            .map(|carrier| carrier_components[carrier.index()])
        {
            index.location_components.insert(id, component);
            index.by_component.entry(component).or_default().push(id);
        }
    }
    index.bounded_globals.sort_unstable();
    for locations in index.by_component.values_mut() {
        locations.sort_unstable();
    }
    index
}

fn root_carrier(root: &AccessPathRoot) -> Option<ValueFlowCarrier> {
    match root {
        AccessPathRoot::Value(value) => Some(ValueFlowCarrier::Value(value.clone())),
        AccessPathRoot::CallResult(result) => {
            Some(ValueFlowCarrier::Value(result.result().clone()))
        }
        AccessPathRoot::ProcedurePort(port) | AccessPathRoot::CaptureSlot(port) => {
            Some(ValueFlowCarrier::Port(port.clone()))
        }
        AccessPathRoot::Allocation(allocation) => allocation
            .procedure()
            .semantics()
            .allocation(allocation.id())
            .and_then(|row| allocation.procedure().value_handle(row.result))
            .map(ValueFlowCarrier::Value),
        AccessPathRoot::LexicalCell(location) => location
            .procedure()
            .semantics()
            .memory_location(location.id())
            .and_then(|row| match row.kind {
                MemoryLocationKind::LexicalCell { binding } => {
                    location.procedure().value_handle(binding)
                }
                _ => None,
            })
            .map(ValueFlowCarrier::Value),
        AccessPathRoot::Static(_)
        | AccessPathRoot::TypeSummary(_)
        | AccessPathRoot::ModuleObject(_)
        | AccessPathRoot::External(_) => None,
    }
}

fn build_carrier_components(carrier_count: usize, local_rules: &[LocalFlowRule]) -> Vec<usize> {
    fn find_root(parents: &mut [usize], mut index: usize) -> usize {
        while parents[index] != index {
            parents[index] = parents[parents[index]];
            index = parents[index];
        }
        index
    }

    let mut parents = (0..carrier_count).collect::<Vec<_>>();
    let mut ranks = vec![0_u8; carrier_count];
    for rule in local_rules {
        let source = find_root(&mut parents, rule.source.index());
        let target = find_root(&mut parents, rule.target.index());
        if source == target {
            continue;
        }
        match ranks[source].cmp(&ranks[target]) {
            Ordering::Less => parents[source] = target,
            Ordering::Greater => parents[target] = source,
            Ordering::Equal => {
                parents[target] = source;
                ranks[source] = ranks[source].saturating_add(1);
            }
        }
    }
    (0..carrier_count)
        .map(|index| find_root(&mut parents, index))
        .collect()
}

fn compare_snapshots(left: &ValueFlowSnapshot, right: &ValueFlowSnapshot) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| {
        compare_call_contexts(left.context().calls(), right.context().calls()).then_with(|| {
            left.context()
                .was_truncated()
                .cmp(&right.context().was_truncated())
        })
    })
}

fn compare_bindings(left: &CallBindings, right: &CallBindings) -> Ordering {
    compare_calls(left.call(), right.call())
        .then_with(|| compare_procedures(left.callee(), right.callee()))
        .then_with(|| compare_call_contexts(left.context().calls(), right.context().calls()))
        .then_with(|| {
            left.context()
                .was_truncated()
                .cmp(&right.context().was_truncated())
        })
}

fn compare_call_contexts(left: &[CallSiteHandle], right: &[CallSiteHandle]) -> Ordering {
    left.iter()
        .zip(right)
        .find_map(|(left, right)| {
            let ordering = compare_calls(left, right);
            (ordering != Ordering::Equal).then_some(ordering)
        })
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

fn compare_local_rules(left: &LocalFlowRule, right: &LocalFlowRule) -> Ordering {
    compare_points(&left.point, &right.point)
        .then_with(|| left.event_index.cmp(&right.event_index))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| relation_kind_rank(left.kind).cmp(&relation_kind_rank(right.kind)))
}

fn relation_kind_rank(kind: ValueFlowRelationKind) -> u8 {
    match kind {
        ValueFlowRelationKind::Assignment => 0,
        ValueFlowRelationKind::Parameter => 1,
        ValueFlowRelationKind::Receiver => 2,
        ValueFlowRelationKind::NormalReturn => 3,
        ValueFlowRelationKind::ExceptionalReturn => 4,
        ValueFlowRelationKind::Allocation => 5,
        ValueFlowRelationKind::MemoryLoad => 6,
        ValueFlowRelationKind::MemoryStore => 7,
        ValueFlowRelationKind::Capture => 8,
        ValueFlowRelationKind::LanguageDefined => 9,
    }
}

fn compare_call_rules(left: &CallFlowRule, right: &CallFlowRule) -> Ordering {
    compare_calls(&left.call, &right.call)
        .then_with(|| compare_procedures(&left.callee, &right.callee))
        .then_with(|| call_rule_rank(left.kind).cmp(&call_rule_rank(right.kind)))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.target.cmp(&right.target))
}

fn call_rule_rank(kind: CallFlowRuleKind) -> u8 {
    match kind {
        CallFlowRuleKind::Call => 0,
        CallFlowRuleKind::NormalReturn => 1,
        CallFlowRuleKind::ExceptionalReturn => 2,
    }
}

fn compare_procedures(left: &ProcedureHandle, right: &ProcedureHandle) -> Ordering {
    left.artifact()
        .key()
        .cmp(right.artifact().key())
        .then_with(|| left.semantics().locator().cmp(right.semantics().locator()))
        .then_with(|| left.id().cmp(&right.id()))
        .then_with(|| {
            Arc::as_ptr(left.artifact())
                .cast::<()>()
                .cmp(&Arc::as_ptr(right.artifact()).cast::<()>())
        })
}

fn compare_points(left: &ProgramPointHandle, right: &ProgramPointHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn compare_calls(left: &CallSiteHandle, right: &CallSiteHandle) -> Ordering {
    compare_procedures(left.procedure(), right.procedure()).then_with(|| left.id().cmp(&right.id()))
}

fn adjacent_duplicate<'a, T: Eq + 'a>(mut values: impl Iterator<Item = &'a T>) -> bool {
    let Some(mut previous) = values.next() else {
        return false;
    };
    for value in values {
        if value == previous {
            return true;
        }
        previous = value;
    }
    false
}
