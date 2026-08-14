use std::{collections::BTreeMap, error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::dataflow::UnmodeledCallBehavior;
use crate::analyzer::semantic::ProgramPointHandle;
use crate::analyzer::value_flow::{
    ValueFlowCarrierId, ValueFlowEventKind, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowSinkId, ValueFlowSourceId,
};

use super::{SourceEventKey, TaintClassSet, TaintEdgeFunction, TaintUniverse, TaintUniverseHash};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSourceBinding {
    source: ValueFlowSourceId,
    classes: TaintClassSet,
    origin: SourceEventKey,
}

impl TaintSourceBinding {
    pub const fn new(
        source: ValueFlowSourceId,
        classes: TaintClassSet,
        origin: SourceEventKey,
    ) -> Self {
        Self {
            source,
            classes,
            origin,
        }
    }

    pub const fn source(&self) -> ValueFlowSourceId {
        self.source
    }

    pub const fn classes(&self) -> &TaintClassSet {
        &self.classes
    }

    pub const fn origin(&self) -> &SourceEventKey {
        &self.origin
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSinkBinding {
    sink: ValueFlowSinkId,
    accepted: TaintClassSet,
}

impl TaintSinkBinding {
    pub const fn new(sink: ValueFlowSinkId, accepted: TaintClassSet) -> Self {
        Self { sink, accepted }
    }

    pub const fn sink(&self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn accepted(&self) -> &TaintClassSet {
        &self.accepted
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSanitizerBinding {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    event_index: u32,
    carrier: ValueFlowCarrierId,
    removed: TaintClassSet,
    resolved: bool,
}

impl TaintSanitizerBinding {
    pub const fn resolved(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self {
            point,
            phase,
            event_index,
            carrier,
            removed,
            resolved: true,
        }
    }

    pub const fn unresolved(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self {
            point,
            phase,
            event_index,
            carrier,
            removed,
            resolved: false,
        }
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn phase(&self) -> ValueFlowObservationPhase {
        self.phase
    }

    pub const fn carrier(&self) -> ValueFlowCarrierId {
        self.carrier
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

    pub const fn removed(&self) -> &TaintClassSet {
        &self.removed
    }

    pub const fn is_resolved(&self) -> bool {
        self.resolved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTransformBinding {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    event_index: u32,
    carrier: ValueFlowCarrierId,
    function: TaintEdgeFunction,
}

impl TaintTransformBinding {
    pub const fn new(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        function: TaintEdgeFunction,
    ) -> Self {
        Self {
            point,
            phase,
            event_index,
            carrier,
            function,
        }
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn phase(&self) -> ValueFlowObservationPhase {
        self.phase
    }

    pub const fn carrier(&self) -> ValueFlowCarrierId {
        self.carrier
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

    pub const fn function(&self) -> &TaintEdgeFunction {
        &self.function
    }
}

/// One already-resolved, policy-neutral taint fixed-point input.
#[derive(Debug, Clone)]
pub struct TaintAnalysisPlan {
    value_flow: ValueFlowPlan,
    universe: TaintUniverse,
    sources: Box<[TaintSourceBinding]>,
    sinks: Box<[TaintSinkBinding]>,
    sanitizers: Box<[TaintSanitizerBinding]>,
    transforms: Box<[TaintTransformBinding]>,
    identity: TaintEdgeFunction,
    phase_transfers: Box<[ResolvedTaintTransfer]>,
    discovery_complete: bool,
    owner: Arc<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedTaintTransfer {
    point: ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrierId,
    function: TaintEdgeFunction,
    complete: bool,
}

#[derive(Clone, Copy)]
enum OrderedTaintTransfer<'binding> {
    Sanitizer(&'binding TaintSanitizerBinding),
    Transform(&'binding TaintTransformBinding),
}

impl<'binding> OrderedTaintTransfer<'binding> {
    fn point(self) -> &'binding ProgramPointHandle {
        match self {
            Self::Sanitizer(binding) => binding.point(),
            Self::Transform(binding) => binding.point(),
        }
    }

    const fn phase(self) -> ValueFlowObservationPhase {
        match self {
            Self::Sanitizer(binding) => binding.phase(),
            Self::Transform(binding) => binding.phase(),
        }
    }

    const fn event_index(self) -> u32 {
        match self {
            Self::Sanitizer(binding) => binding.event_index(),
            Self::Transform(binding) => binding.event_index(),
        }
    }

    const fn carrier(self) -> ValueFlowCarrierId {
        match self {
            Self::Sanitizer(binding) => binding.carrier(),
            Self::Transform(binding) => binding.carrier(),
        }
    }

    fn same_ordering_slot(self, other: Self) -> bool {
        self.point() == other.point()
            && self.phase() == other.phase()
            && self.event_index() == other.event_index()
            && self.carrier() == other.carrier()
    }

    const fn kind_rank(self) -> u8 {
        match self {
            Self::Sanitizer(_) => 0,
            Self::Transform(_) => 1,
        }
    }
}

fn compare_ordered_transfers(
    left: &OrderedTaintTransfer<'_>,
    right: &OrderedTaintTransfer<'_>,
) -> std::cmp::Ordering {
    left.point()
        .procedure()
        .semantics()
        .locator()
        .cmp(right.point().procedure().semantics().locator())
        .then_with(|| left.point().id().cmp(&right.point().id()))
        .then_with(|| left.phase().cmp(&right.phase()))
        .then_with(|| left.event_index().cmp(&right.event_index()))
        .then_with(|| left.carrier().cmp(&right.carrier()))
        .then_with(|| left.kind_rank().cmp(&right.kind_rank()))
}

impl TaintAnalysisPlan {
    pub fn new(
        value_flow: ValueFlowPlan,
        universe: TaintUniverse,
        mut sources: Vec<TaintSourceBinding>,
        mut sinks: Vec<TaintSinkBinding>,
        mut sanitizers: Vec<TaintSanitizerBinding>,
        mut transforms: Vec<TaintTransformBinding>,
    ) -> Result<Self, TaintPlanError> {
        sources.sort_by_key(TaintSourceBinding::source);
        sinks.sort_by_key(TaintSinkBinding::sink);
        sanitizers.sort_by(compare_sanitizers);
        transforms.sort_by(compare_transforms);
        if sources
            .windows(2)
            .any(|pair| pair[0].source == pair[1].source)
            || sinks.windows(2).any(|pair| pair[0].sink == pair[1].sink)
        {
            return Err(TaintPlanError::DuplicateBinding);
        }
        for source in &sources {
            if value_flow.source(source.source).is_none()
                || source.classes.universe() != universe.hash()
                || source.classes.is_empty()
                || value_flow.source(source.source).is_none_or(|spec| {
                    source.origin.value_flow_key() != spec.key()
                        || spec.key().kind() != ValueFlowEventKind::Source
                })
            {
                return Err(TaintPlanError::InvalidSource);
            }
        }
        for sink in &sinks {
            if value_flow.sink(sink.sink).is_none()
                || sink.accepted.universe() != universe.hash()
                || sink.accepted.is_empty()
            {
                return Err(TaintPlanError::InvalidSink);
            }
        }
        for sanitizer in &sanitizers {
            validate_carrier_binding(
                &value_flow,
                sanitizer.point(),
                sanitizer.carrier,
                sanitizer.removed.universe(),
                universe.hash(),
            )?;
        }
        for transform in &transforms {
            validate_carrier_binding(
                &value_flow,
                transform.point(),
                transform.carrier,
                transform.function.universe(),
                universe.hash(),
            )?;
        }
        let identity = TaintEdgeFunction::identity(&universe);
        let mut ordered = sanitizers
            .iter()
            .map(OrderedTaintTransfer::Sanitizer)
            .chain(transforms.iter().map(OrderedTaintTransfer::Transform))
            .collect::<Vec<_>>();
        ordered.sort_by(compare_ordered_transfers);
        if ordered
            .windows(2)
            .any(|pair| pair[0].same_ordering_slot(pair[1]))
        {
            return Err(TaintPlanError::AmbiguousTransferOrder);
        }
        let mut phase_transfers = Vec::new();
        for event in ordered {
            let transfer = transfer_entry(
                &mut phase_transfers,
                event.point(),
                event.phase(),
                event.carrier(),
                &identity,
            );
            match event {
                OrderedTaintTransfer::Sanitizer(sanitizer) if sanitizer.is_resolved() => {
                    transfer.function = transfer
                        .function
                        .compose(&TaintEdgeFunction::kill(sanitizer.removed()));
                }
                OrderedTaintTransfer::Sanitizer(_) => transfer.complete = false,
                OrderedTaintTransfer::Transform(transform) => {
                    transfer.function = transfer.function.compose(transform.function());
                }
            }
        }
        phase_transfers.sort_by(compare_resolved_transfers);
        let discovery_complete = value_flow.discovery_complete()
            && sanitizers.iter().all(TaintSanitizerBinding::is_resolved);
        Ok(Self {
            value_flow,
            universe,
            sources: sources.into_boxed_slice(),
            sinks: sinks.into_boxed_slice(),
            sanitizers: sanitizers.into_boxed_slice(),
            transforms: transforms.into_boxed_slice(),
            identity,
            phase_transfers: phase_transfers.into_boxed_slice(),
            discovery_complete,
            owner: Arc::new(()),
        })
    }

    pub const fn value_flow(&self) -> &ValueFlowPlan {
        &self.value_flow
    }

    pub const fn universe(&self) -> &TaintUniverse {
        &self.universe
    }

    pub const fn sources(&self) -> &[TaintSourceBinding] {
        &self.sources
    }

    pub const fn sinks(&self) -> &[TaintSinkBinding] {
        &self.sinks
    }

    pub(crate) const fn sanitizers(&self) -> &[TaintSanitizerBinding] {
        &self.sanitizers
    }

    pub(crate) const fn transforms(&self) -> &[TaintTransformBinding] {
        &self.transforms
    }

    pub(crate) fn summary_key_rows(&self) -> usize {
        self.value_flow
            .carrier_summary_identity_total_rows()
            .saturating_add(self.sources.len())
            .saturating_add(self.sinks.len())
            .saturating_add(self.sanitizers.len())
            .saturating_add(self.transforms.len())
    }

    pub const fn discovery_complete(&self) -> bool {
        self.discovery_complete
    }

    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }

    pub(crate) fn for_each_retained_artifact(
        &self,
        visit: impl FnMut(&Arc<crate::analyzer::semantic::SemanticArtifact>),
    ) {
        self.value_flow.for_each_retained_artifact(visit);
    }

    pub(crate) fn for_each_retained_artifact_key(
        &self,
        visit: impl FnMut(&crate::analyzer::semantic::SemanticArtifactKey),
    ) {
        self.value_flow.for_each_retained_artifact_key(visit);
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.value_flow.retained_bytes())
            .saturating_add(self.universe.retained_bytes())
            .saturating_add(size_of_val(&*self.sources))
            .saturating_add(size_of_val(&*self.sinks))
            .saturating_add(size_of_val(&*self.sanitizers))
            .saturating_add(size_of_val(&*self.transforms))
            .saturating_add(size_of_val(&*self.phase_transfers))
            .saturating_add(
                self.sources
                    .iter()
                    .map(|source| {
                        source
                            .classes
                            .retained_heap_bytes()
                            .saturating_add(source.origin.value_flow_key().retained_bytes())
                    })
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.sinks
                    .iter()
                    .map(|sink| sink.accepted.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.sanitizers
                    .iter()
                    .map(|sanitizer| sanitizer.removed.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(
                self.transforms
                    .iter()
                    .map(|transform| transform.function.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
            .saturating_add(self.identity.retained_heap_bytes())
            .saturating_add(
                self.phase_transfers
                    .iter()
                    .map(|transfer| transfer.function.retained_heap_bytes())
                    .fold(0usize, usize::saturating_add),
            )
    }

    pub(crate) fn source(&self, id: ValueFlowSourceId) -> Option<&TaintSourceBinding> {
        self.sources
            .binary_search_by_key(&id, TaintSourceBinding::source)
            .ok()
            .map(|index| &self.sources[index])
    }

    pub(crate) fn sink(&self, id: ValueFlowSinkId) -> Option<&TaintSinkBinding> {
        self.sinks
            .binary_search_by_key(&id, TaintSinkBinding::sink)
            .ok()
            .map(|index| &self.sinks[index])
    }

    pub(crate) fn identity(&self) -> &TaintEdgeFunction {
        &self.identity
    }

    pub(crate) fn transfer_function(
        &self,
        point: &ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        carrier: ValueFlowCarrierId,
    ) -> (&TaintEdgeFunction, bool) {
        self.phase_transfers
            .iter()
            .find(|transfer| {
                &transfer.point == point && transfer.phase == phase && transfer.carrier == carrier
            })
            .map_or((&self.identity, true), |transfer| {
                (&transfer.function, transfer.complete)
            })
    }
}

fn transfer_entry<'a>(
    transfers: &'a mut Vec<ResolvedTaintTransfer>,
    point: &ProgramPointHandle,
    phase: ValueFlowObservationPhase,
    carrier: ValueFlowCarrierId,
    identity: &TaintEdgeFunction,
) -> &'a mut ResolvedTaintTransfer {
    if let Some(index) = transfers.iter().position(|transfer| {
        &transfer.point == point && transfer.phase == phase && transfer.carrier == carrier
    }) {
        return &mut transfers[index];
    }
    transfers.push(ResolvedTaintTransfer {
        point: point.clone(),
        phase,
        carrier,
        function: identity.clone(),
        complete: true,
    });
    transfers.last_mut().expect("just inserted transfer")
}

fn compare_resolved_transfers(
    left: &ResolvedTaintTransfer,
    right: &ResolvedTaintTransfer,
) -> std::cmp::Ordering {
    left.point
        .procedure()
        .semantics()
        .locator()
        .cmp(right.point.procedure().semantics().locator())
        .then_with(|| left.point.id().cmp(&right.point.id()))
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| left.carrier.cmp(&right.carrier))
}

fn validate_carrier_binding(
    plan: &ValueFlowPlan,
    point: &ProgramPointHandle,
    carrier: ValueFlowCarrierId,
    actual_universe: TaintUniverseHash,
    expected_universe: TaintUniverseHash,
) -> Result<(), TaintPlanError> {
    let Some(bound) = plan.carrier(carrier) else {
        return Err(TaintPlanError::InvalidCarrierBinding);
    };
    if actual_universe != expected_universe
        || bound
            .procedure()
            .is_some_and(|procedure| procedure != point.procedure())
    {
        return Err(TaintPlanError::InvalidCarrierBinding);
    }
    Ok(())
}

fn compare_sanitizers(
    left: &TaintSanitizerBinding,
    right: &TaintSanitizerBinding,
) -> std::cmp::Ordering {
    left.point
        .procedure()
        .semantics()
        .locator()
        .cmp(right.point.procedure().semantics().locator())
        .then_with(|| left.point.id().cmp(&right.point.id()))
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| left.event_index.cmp(&right.event_index))
        .then_with(|| left.carrier.cmp(&right.carrier))
        .then_with(|| left.removed.cmp(&right.removed))
        .then_with(|| left.resolved.cmp(&right.resolved))
}

fn compare_transforms(
    left: &TaintTransformBinding,
    right: &TaintTransformBinding,
) -> std::cmp::Ordering {
    left.point
        .procedure()
        .semantics()
        .locator()
        .cmp(right.point.procedure().semantics().locator())
        .then_with(|| left.point.id().cmp(&right.point.id()))
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| left.event_index.cmp(&right.event_index))
        .then_with(|| left.carrier.cmp(&right.carrier))
        .then_with(|| left.function.cmp(&right.function))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintBatchCompatibilityKey {
    workspace_snapshot: Box<str>,
    propagation_semantics: Box<str>,
    unmodeled_call_behavior: UnmodeledCallBehavior,
    universe: TaintUniverseHash,
}

impl TaintBatchCompatibilityKey {
    pub fn new(
        workspace_snapshot: impl Into<String>,
        propagation_semantics: impl Into<String>,
        universe: TaintUniverseHash,
    ) -> Result<Self, TaintPlanError> {
        Self::with_call_behavior(
            workspace_snapshot,
            propagation_semantics,
            UnmodeledCallBehavior::default(),
            universe,
        )
    }

    pub fn with_call_behavior(
        workspace_snapshot: impl Into<String>,
        propagation_semantics: impl Into<String>,
        unmodeled_call_behavior: UnmodeledCallBehavior,
        universe: TaintUniverseHash,
    ) -> Result<Self, TaintPlanError> {
        let workspace_snapshot = workspace_snapshot.into();
        let propagation_semantics = propagation_semantics.into();
        if workspace_snapshot.is_empty() || propagation_semantics.is_empty() {
            return Err(TaintPlanError::InvalidCompatibilityKey);
        }
        Ok(Self {
            workspace_snapshot: workspace_snapshot.into_boxed_str(),
            propagation_semantics: propagation_semantics.into_boxed_str(),
            unmodeled_call_behavior,
            universe,
        })
    }

    pub const fn workspace_snapshot(&self) -> &str {
        &self.workspace_snapshot
    }

    pub const fn propagation_semantics(&self) -> &str {
        &self.propagation_semantics
    }

    pub const fn unmodeled_call_behavior(&self) -> UnmodeledCallBehavior {
        self.unmodeled_call_behavior
    }

    pub const fn universe(&self) -> TaintUniverseHash {
        self.universe
    }
}

#[derive(Debug, Clone)]
pub struct TaintPolicyPlan {
    policy_id: Box<str>,
    compatibility: TaintBatchCompatibilityKey,
    analysis: TaintAnalysisPlan,
}

impl TaintPolicyPlan {
    pub fn new(
        policy_id: impl Into<String>,
        compatibility: TaintBatchCompatibilityKey,
        analysis: TaintAnalysisPlan,
    ) -> Result<Self, TaintPlanError> {
        let policy_id = policy_id.into();
        if policy_id.is_empty()
            || compatibility.universe != analysis.universe().hash()
            || compatibility.unmodeled_call_behavior
                != analysis.value_flow().unmodeled_call_behavior()
        {
            return Err(TaintPlanError::InvalidPolicy);
        }
        Ok(Self {
            policy_id: policy_id.into_boxed_str(),
            compatibility,
            analysis,
        })
    }

    pub const fn analysis(&self) -> &TaintAnalysisPlan {
        &self.analysis
    }
}

#[derive(Debug, Clone)]
pub struct TaintBatch {
    compatibility: TaintBatchCompatibilityKey,
    projections: Box<[TaintPolicyProjection]>,
    analysis: TaintAnalysisPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintPolicyProjection {
    policy_id: Box<str>,
    sources: Box<[TaintSourceBinding]>,
    sinks: Box<[TaintSinkBinding]>,
}

impl TaintPolicyProjection {
    pub const fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub const fn sources(&self) -> &[TaintSourceBinding] {
        &self.sources
    }

    pub const fn sinks(&self) -> &[TaintSinkBinding] {
        &self.sinks
    }
}

impl TaintBatch {
    pub const fn compatibility(&self) -> &TaintBatchCompatibilityKey {
        &self.compatibility
    }

    pub fn policy_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.projections
            .iter()
            .map(TaintPolicyProjection::policy_id)
    }

    pub const fn projections(&self) -> &[TaintPolicyProjection] {
        &self.projections
    }

    pub const fn analysis(&self) -> &TaintAnalysisPlan {
        &self.analysis
    }
}

pub struct TaintBatchPlanner;

impl TaintBatchPlanner {
    pub fn partition(policies: Vec<TaintPolicyPlan>) -> Result<Vec<TaintBatch>, TaintPlanError> {
        let mut groups: BTreeMap<TaintBatchCompatibilityKey, Vec<TaintPolicyPlan>> =
            BTreeMap::new();
        for policy in policies {
            groups
                .entry(policy.compatibility.clone())
                .or_default()
                .push(policy);
        }
        groups
            .into_iter()
            .map(|(compatibility, mut policies)| {
                policies.sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
                if policies
                    .windows(2)
                    .any(|pair| pair[0].policy_id == pair[1].policy_id)
                {
                    return Err(TaintPlanError::DuplicatePolicyId);
                }
                let first = policies.first().ok_or(TaintPlanError::EmptyBatch)?;
                for policy in policies.iter().skip(1) {
                    ensure_same_semantics(&first.analysis, &policy.analysis)?;
                }
                let value_flow = ValueFlowPlan::union_observations(
                    &policies
                        .iter()
                        .map(|policy| policy.analysis.value_flow())
                        .collect::<Vec<_>>(),
                )
                .map_err(|_| TaintPlanError::IncompatibleBatchMember)?;
                let projections = policies
                    .iter()
                    .map(|policy| {
                        Ok(TaintPolicyProjection {
                            policy_id: policy.policy_id.clone(),
                            sources: remap_sources(&policy.analysis, &value_flow)?
                                .into_boxed_slice(),
                            sinks: remap_sinks(&policy.analysis, &value_flow)?.into_boxed_slice(),
                        })
                    })
                    .collect::<Result<Vec<_>, TaintPlanError>>()?
                    .into_boxed_slice();
                let mut sources = Vec::new();
                let mut sinks = Vec::new();
                for projection in &projections {
                    merge_sources(&mut sources, &projection.sources)?;
                    merge_sinks(&mut sinks, &projection.sinks)?;
                }
                let analysis = TaintAnalysisPlan::new(
                    value_flow.clone(),
                    first.analysis.universe.clone(),
                    sources,
                    sinks,
                    remap_sanitizers(&first.analysis, &value_flow)?,
                    remap_transforms(&first.analysis, &value_flow)?,
                )?;
                Ok(TaintBatch {
                    compatibility,
                    projections,
                    analysis,
                })
            })
            .collect()
    }
}

fn ensure_same_semantics(
    left: &TaintAnalysisPlan,
    right: &TaintAnalysisPlan,
) -> Result<(), TaintPlanError> {
    if left.universe != right.universe
        || !left
            .value_flow
            .has_same_propagation_semantics(&right.value_flow)
        || !same_sanitizers(left, right)
        || !same_transforms(left, right)
    {
        return Err(TaintPlanError::IncompatibleBatchMember);
    }
    Ok(())
}

fn remap_sources(
    analysis: &TaintAnalysisPlan,
    value_flow: &ValueFlowPlan,
) -> Result<Vec<TaintSourceBinding>, TaintPlanError> {
    analysis
        .sources
        .iter()
        .map(|source| {
            let spec = analysis
                .value_flow
                .source(source.source)
                .ok_or(TaintPlanError::InvalidSource)?;
            let remapped = value_flow
                .source_id_for_key(spec.key())
                .ok_or(TaintPlanError::InvalidSource)?;
            Ok(TaintSourceBinding::new(
                remapped,
                source.classes.clone(),
                source.origin.clone(),
            ))
        })
        .collect()
}

fn remap_sinks(
    analysis: &TaintAnalysisPlan,
    value_flow: &ValueFlowPlan,
) -> Result<Vec<TaintSinkBinding>, TaintPlanError> {
    analysis
        .sinks
        .iter()
        .map(|sink| {
            let spec = analysis
                .value_flow
                .sink(sink.sink)
                .ok_or(TaintPlanError::InvalidSink)?;
            let remapped = value_flow
                .sink_id_for_key(spec.key())
                .ok_or(TaintPlanError::InvalidSink)?;
            Ok(TaintSinkBinding::new(remapped, sink.accepted.clone()))
        })
        .collect()
}

fn remapped_carrier(
    source: &ValueFlowPlan,
    target: &ValueFlowPlan,
    carrier: ValueFlowCarrierId,
) -> Result<ValueFlowCarrierId, TaintPlanError> {
    let key = source
        .carrier_key(carrier)
        .ok_or(TaintPlanError::InvalidCarrierBinding)?;
    target
        .carrier_id_for_key(key)
        .ok_or(TaintPlanError::InvalidCarrierBinding)
}

fn remap_sanitizers(
    analysis: &TaintAnalysisPlan,
    value_flow: &ValueFlowPlan,
) -> Result<Vec<TaintSanitizerBinding>, TaintPlanError> {
    analysis
        .sanitizers
        .iter()
        .map(|binding| {
            let carrier = remapped_carrier(&analysis.value_flow, value_flow, binding.carrier)?;
            Ok(if binding.resolved {
                TaintSanitizerBinding::resolved(
                    binding.point.clone(),
                    binding.phase,
                    binding.event_index,
                    carrier,
                    binding.removed.clone(),
                )
            } else {
                TaintSanitizerBinding::unresolved(
                    binding.point.clone(),
                    binding.phase,
                    binding.event_index,
                    carrier,
                    binding.removed.clone(),
                )
            })
        })
        .collect()
}

fn remap_transforms(
    analysis: &TaintAnalysisPlan,
    value_flow: &ValueFlowPlan,
) -> Result<Vec<TaintTransformBinding>, TaintPlanError> {
    analysis
        .transforms
        .iter()
        .map(|binding| {
            Ok(TaintTransformBinding::new(
                binding.point.clone(),
                binding.phase,
                binding.event_index,
                remapped_carrier(&analysis.value_flow, value_flow, binding.carrier)?,
                binding.function.clone(),
            ))
        })
        .collect()
}

fn same_sanitizers(left: &TaintAnalysisPlan, right: &TaintAnalysisPlan) -> bool {
    left.sanitizers.len() == right.sanitizers.len()
        && left
            .sanitizers
            .iter()
            .zip(&right.sanitizers)
            .all(|(left_binding, right_binding)| {
                left_binding.point == right_binding.point
                    && left_binding.phase == right_binding.phase
                    && left_binding.event_index == right_binding.event_index
                    && left_binding.removed == right_binding.removed
                    && left_binding.resolved == right_binding.resolved
                    && left.value_flow.carrier_key(left_binding.carrier)
                        == right.value_flow.carrier_key(right_binding.carrier)
            })
}

fn same_transforms(left: &TaintAnalysisPlan, right: &TaintAnalysisPlan) -> bool {
    left.transforms.len() == right.transforms.len()
        && left
            .transforms
            .iter()
            .zip(&right.transforms)
            .all(|(left_binding, right_binding)| {
                left_binding.point == right_binding.point
                    && left_binding.phase == right_binding.phase
                    && left_binding.event_index == right_binding.event_index
                    && left_binding.function == right_binding.function
                    && left.value_flow.carrier_key(left_binding.carrier)
                        == right.value_flow.carrier_key(right_binding.carrier)
            })
}

fn merge_sources(
    target: &mut Vec<TaintSourceBinding>,
    incoming: &[TaintSourceBinding],
) -> Result<(), TaintPlanError> {
    for source in incoming {
        if let Some(existing) = target.iter_mut().find(|item| item.source == source.source) {
            if existing.origin != source.origin {
                return Err(TaintPlanError::IncompatibleBatchMember);
            }
            existing.classes = existing.classes.union(&source.classes);
        } else {
            target.push(source.clone());
        }
    }
    target.sort_by_key(TaintSourceBinding::source);
    Ok(())
}

fn merge_sinks(
    target: &mut Vec<TaintSinkBinding>,
    incoming: &[TaintSinkBinding],
) -> Result<(), TaintPlanError> {
    for sink in incoming {
        if let Some(existing) = target.iter_mut().find(|item| item.sink == sink.sink) {
            existing.accepted = existing.accepted.union(&sink.accepted);
        } else {
            target.push(sink.clone());
        }
    }
    target.sort_by_key(TaintSinkBinding::sink);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintPlanError {
    InvalidSource,
    InvalidSink,
    InvalidCarrierBinding,
    DuplicateBinding,
    InvalidCompatibilityKey,
    InvalidPolicy,
    DuplicatePolicyId,
    EmptyBatch,
    IncompatibleBatchMember,
    AmbiguousTransferOrder,
}

impl fmt::Display for TaintPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource => formatter.write_str("invalid taint source binding"),
            Self::InvalidSink => formatter.write_str("invalid taint sink binding"),
            Self::InvalidCarrierBinding => formatter.write_str("invalid taint carrier binding"),
            Self::DuplicateBinding => formatter.write_str("duplicate taint source or sink binding"),
            Self::InvalidCompatibilityKey => {
                formatter.write_str("invalid taint batch compatibility key")
            }
            Self::InvalidPolicy => formatter.write_str("invalid taint policy plan"),
            Self::DuplicatePolicyId => formatter.write_str("duplicate taint policy ID"),
            Self::EmptyBatch => formatter.write_str("taint batch has no policy plans"),
            Self::IncompatibleBatchMember => {
                formatter.write_str("taint batch members have different propagation semantics")
            }
            Self::AmbiguousTransferOrder => formatter.write_str(
                "taint transfers sharing one point, phase, carrier, and ordinal are ambiguous",
            ),
        }
    }
}

impl Error for TaintPlanError {}
