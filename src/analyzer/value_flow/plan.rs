use std::{cmp::Ordering, error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::dataflow::{
    SemanticInputStatus, SummaryDataflowResult, UnmodeledCallBehavior,
};
use crate::analyzer::semantic::{
    AbstractLocation, AbstractObject, AccessPathRoot, CallArgumentEndpoint, CallBinding,
    CallBindings, CallSiteHandle, CallSiteId, CandidateCoverage, DeclarationLocator,
    EvidenceCompleteness, ObjectCardinality, ProcedureHandle, ProgramPointHandle, ProgramPointId,
    ProofStatus, SemanticArtifactKey, SemanticEffect, ValueFlowRelationKind, ValueFlowSnapshot,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Stable, procedure-local value-flow identity used by reusable client summaries.
///
/// Source, sink, sanitizer, and transform matching are intentionally absent;
/// clients add those independently according to their invalidation contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ValueFlowCarrierSummaryIdentity {
    unmodeled_call_behavior: UnmodeledCallBehavior,
    has_snapshot: bool,
    local_rules: Box<[ValueFlowLocalSummaryRule]>,
    call_rules: Box<[ValueFlowCallSummaryRule]>,
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
        std::mem::size_of::<Self>()
            .saturating_add(local)
            .saturating_add(calls)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallFlowRule {
    pub call: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub kind: CallFlowRuleKind,
    pub source: ValueFlowCarrierId,
    pub target: ValueFlowCarrierId,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundValueFlowSource {
    pub id: ValueFlowSourceId,
    pub spec: ValueFlowSourceSpec,
    pub carrier: ValueFlowCarrierId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    carriers: Box<[ValueFlowCarrier]>,
    carrier_keys: Box<[ValueFlowCarrierKey]>,
    carrier_ids: HashMap<ValueFlowCarrier, ValueFlowCarrierId>,
    local_rules: Box<[LocalFlowRule]>,
    call_rules: Box<[CallFlowRule]>,
    sources: Box<[BoundValueFlowSource]>,
    sinks: Box<[BoundValueFlowSink]>,
    snapshot_procedures: Box<[ProcedureHandle]>,
    binding_pairs: Box<[(CallSiteHandle, ProcedureHandle)]>,
    discovery_status: SemanticInputStatus,
    discovery_complete: bool,
    owner: Arc<()>,
}

impl PartialEq for ValueFlowPlan {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.unmodeled_call_behavior == other.unmodeled_call_behavior
            && self.carriers == other.carriers
            && self.carrier_keys == other.carrier_keys
            && self.carrier_ids == other.carrier_ids
            && self.local_rules == other.local_rules
            && self.call_rules == other.call_rules
            && self.sources == other.sources
            && self.sinks == other.sinks
            && self.snapshot_procedures == other.snapshot_procedures
            && self.binding_pairs == other.binding_pairs
            && self.discovery_status == other.discovery_status
            && self.discovery_complete == other.discovery_complete
    }
}

impl Eq for ValueFlowPlan {}

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
            for binding in input.value().bindings() {
                relation_count = relation_count.saturating_add(call_binding_rule_count(binding));
                append_binding_carriers(binding, &mut carrier_candidates)?;
            }
        }
        for source in &sources {
            validate_event(source.point(), source.carrier(), mount)?;
            discovery_complete &= matches!(source.proof(), ProofStatus::Proven)
                && matches!(source.completeness(), EvidenceCompleteness::Complete);
            carrier_candidates.push(source.carrier().clone());
        }
        for sink in &sinks {
            validate_event(sink.point(), sink.carrier(), mount)?;
            discovery_complete &= matches!(sink.proof(), ProofStatus::Proven)
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
            carriers: carriers.into_boxed_slice(),
            carrier_keys: carrier_keys.into_boxed_slice(),
            carrier_ids,
            local_rules: local_rules.into_boxed_slice(),
            call_rules: call_rules.into_boxed_slice(),
            sources: bound_sources.into_boxed_slice(),
            sinks: bound_sinks.into_boxed_slice(),
            snapshot_procedures: snapshot_procedures.into_boxed_slice(),
            binding_pairs: binding_pairs.into_boxed_slice(),
            discovery_status,
            discovery_complete,
            owner: Arc::new(()),
        })
    }

    pub fn root(&self) -> &ProcedureHandle {
        &self.root
    }

    pub const fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.unmodeled_call_behavior
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
        self.discovery_complete
            && result.reached().iter().all(|reached| {
                let procedure = reached.point().procedure();
                self.has_snapshot(procedure)
                    && procedure
                        .semantics()
                        .point(reached.point().id())
                        .is_some_and(|point| {
                            point.events.iter().all(|event| match event.effect {
                                SemanticEffect::Invoke { call_site } => procedure
                                    .call_site_handle(call_site)
                                    .is_some_and(|call| self.has_binding_for_call(&call)),
                                _ => true,
                            })
                        })
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
        builders
            .into_iter()
            .map(|(procedure, builder)| {
                (
                    procedure,
                    ValueFlowCarrierSummaryIdentity {
                        unmodeled_call_behavior: self.unmodeled_call_behavior,
                        has_snapshot: builder.has_snapshot,
                        local_rules: builder.local_rules.into_boxed_slice(),
                        call_rules: builder.call_rules.into_boxed_slice(),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn carrier_summary_identity_total_rows(&self) -> usize {
        self.local_rules.len().saturating_add(self.call_rules.len())
    }

    pub(crate) fn is_call_input(&self, call: &CallSiteHandle, carrier: ValueFlowCarrierId) -> bool {
        if self.call_rules.iter().any(|rule| {
            &rule.call == call && rule.kind == CallFlowRuleKind::Call && rule.source == carrier
        }) {
            return true;
        }
        let Some(ValueFlowCarrier::Value(value)) = self.carrier(carrier) else {
            return false;
        };
        if value.procedure() != call.procedure() {
            return false;
        }
        let Some(call_row) = call.procedure().semantics().call_site(call.id()) else {
            return false;
        };
        call_row.receiver == Some(value.id())
            || call_row
                .arguments
                .iter()
                .any(|argument| argument.value == value.id())
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
