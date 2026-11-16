//! Owned inputs of one candidate search. These are the caches used by Search,
//! not its work list, reaches, path derivations, or a second identity catalog.

use super::*;
use crate::analyzer::semantic::partial_flow::{
    HeapSelector, PartialFlowPort, ProcedurePartialFlows,
};
use crate::analyzer::semantic::service::{
    ArtifactRetentionVisitor, RetainedArtifactWalker, RetentionCensusSink,
};
use crate::analyzer::store::cache_budget::RetainedHeap;
use crate::taint::{TaintClassSet, TaintEdgeFunction};
use crate::value_flow::DurableProcedureKey;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposedInputStatus {
    Available,
    NestedExecutionInputsUnavailable,
    ProviderInputsUnavailable,
    BarrierReplayInputsUnavailable,
    RetentionRefused,
}

#[derive(Debug)]
pub struct ComposedInputBacking {
    status: ComposedInputStatus,
    inputs: Option<SearchInputs<TaintClassSet, TaintEdgeFunction>>,
    functions: Vec<TaintEdgeFunction>,
    original_source_evidence: Box<[EndpointEvidence]>,
}

impl ComposedInputBacking {
    pub fn status(&self) -> ComposedInputStatus {
        self.status
    }
    pub fn input_caches(&self) -> Option<&SearchInputs<TaintClassSet, TaintEdgeFunction>> {
        self.inputs.as_ref()
    }
    pub fn function(&self, id: LabelFunctionId) -> &TaintEdgeFunction {
        &self.functions[id.index()]
    }
    /// The source's immutable recipe fields and its ORIGINAL evidence. The
    /// source row's evidence is the final, potentially stronger report judgment.
    pub fn source_recipe(&self, index: usize) -> Option<(&BoundSource, EndpointEvidence)> {
        let inputs = self.inputs.as_ref()?;
        Some((
            inputs.sources.get(index)?,
            *self.original_source_evidence.get(index)?,
        ))
    }
    pub(super) fn unavailable(status: ComposedInputStatus) -> Self {
        Self {
            status,
            inputs: None,
            functions: Vec::new(),
            original_source_evidence: Box::default(),
        }
    }
    pub(super) fn new(
        mut inputs: SearchInputs<TaintClassSet, TaintEdgeFunction>,
        functions: Vec<TaintEdgeFunction>,
        original_source_evidence: Box<[EndpointEvidence]>,
        heap: &mut RetainedHeap,
    ) -> Self {
        inputs.discard_indexes();
        let backing = Self {
            status: ComposedInputStatus::Available,
            inputs: Some(inputs),
            functions,
            original_source_evidence,
        };
        backing.retained_heap(heap);
        if heap.is_refused() {
            // A refused census is terminal, so none of its owner identities can
            // be used after these allocations are dropped.
            Self::unavailable(ComposedInputStatus::RetentionRefused)
        } else {
            backing
        }
    }
    /// Join the candidate's shared retained census; the stable owner makes
    /// subsequent visits through that same census idempotent.
    pub fn retained_heap(&self, heap: &mut RetainedHeap) {
        if heap.is_refused() || self.inputs.is_none() {
            return;
        }
        assert!(
            !self.functions.is_empty(),
            "the function table contains identity"
        );
        // This stable, moved allocation is the bundle's census owner. A later
        // union census visits it only once, including exclusive map storage.
        if !heap.allocation(
            self.functions.as_ptr() as usize,
            self.functions
                .capacity()
                .saturating_mul(std::mem::size_of::<TaintEdgeFunction>()),
        ) {
            return;
        }
        heap.add_entries(self.functions.len());
        for function in &self.functions {
            function.retained_heap(heap);
        }
        heap.owned_slice(&self.original_source_evidence);
        if let Some(inputs) = &self.inputs {
            inputs.retained_heap(heap);
        }
    }
}

pub(super) fn capture_source_evidence(
    sources: &[BoundSource],
    heap: &mut RetainedHeap,
) -> Box<[EndpointEvidence]> {
    let bytes = sources
        .len()
        .checked_mul(std::mem::size_of::<EndpointEvidence>());
    let Some(bytes) = bytes else {
        RetentionCensusSink::refuse(heap);
        return Box::default();
    };
    if !heap.reserve_scratch(bytes) {
        return Box::default();
    }
    let mut rows = Box::<[EndpointEvidence]>::new_uninit_slice(sources.len());
    for (slot, source) in rows.iter_mut().zip(sources) {
        slot.write(source.evidence);
    }
    // SAFETY: the equally sized iteration initialized every evidence slot.
    let rows = unsafe { rows.assume_init() };
    if bytes != 0 {
        heap.adopt_allocation(rows.as_ptr() as usize, bytes, bytes);
    }
    if heap.is_refused() {
        drop(rows);
        heap.release_scratch(bytes);
        Box::default()
    } else {
        rows
    }
}

fn with_artifacts(
    heap: &mut RetainedHeap,
    visit: impl FnOnce(&mut RetainedArtifactWalker<'_, RetainedHeap>),
) {
    let mut visitor = RetainedArtifactWalker::new(heap);
    visit(&mut visitor);
    visitor.finish();
}
fn key(visitor: &mut impl ArtifactRetentionVisitor, key: &DurableProcedureKey) {
    visitor.artifact_key(&key.0);
}
fn vector<T>(visitor: &mut impl ArtifactRetentionVisitor, values: &Vec<T>) {
    if values.capacity() != 0 {
        visitor.allocation(
            values.as_ptr() as usize,
            values.capacity().saturating_mul(std::mem::size_of::<T>()),
        );
    }
}
fn completeness(visitor: &mut impl ArtifactRetentionVisitor, status: &Completeness) {
    if let Completeness::Incomplete { reason, .. } = status {
        visitor.owned_slice(reason.as_bytes());
    }
}
fn selectors(visitor: &mut impl ArtifactRetentionVisitor, values: &[HeapSelector]) {
    visitor.owned_slice(values);
    for selector in values {
        match selector {
            HeapSelector::Field(locator) => visitor.locator(locator),
            HeapSelector::Property(text) | HeapSelector::ConstantIndex(text) => {
                visitor.owned_slice(text.as_bytes());
            }
            _ => {}
        }
    }
}
fn port(visitor: &mut impl ArtifactRetentionVisitor, value: &PartialFlowPort) {
    let mut value = value;
    while let PartialFlowPort::Heap {
        root,
        selectors: fields,
        ..
    } = value
    {
        visitor.owned_box(root.as_ref());
        selectors(visitor, fields);
        value = root;
    }
}
/// Shared typed port census, including locator payloads on field selectors.
pub fn retained_port(heap: &mut RetainedHeap, value: &PartialFlowPort) {
    with_artifacts(heap, |visitor| port(visitor, value));
}
fn location(visitor: &mut impl ArtifactRetentionVisitor, value: &CallerLocation) {
    port(visitor, &value.actual);
    selectors(visitor, &value.selectors);
}
fn writeback(visitor: &mut impl ArtifactRetentionVisitor, value: &WritebackBinding) {
    port(visitor, &value.actual);
    port(visitor, &value.formal);
    visitor.owned_slice(&value.direct_fields);
    for field in &value.direct_fields {
        visitor.locator(field);
    }
    visitor.owned_slice(&value.storage);
    for storage in &value.storage {
        storage.visit_retained_allocations(visitor);
    }
}
fn dispatch_candidate(visitor: &mut impl ArtifactRetentionVisitor, value: &DispatchCandidate) {
    key(visitor, &value.procedure);
    if let Some(ports) = &value.written_heap_ports {
        visitor.owned_slice(ports);
        for value in ports {
            port(visitor, value);
        }
    }
    for ports in [&value.arguments, &value.returns] {
        visitor.owned_slice(ports);
        for (left, right) in ports {
            port(visitor, left);
            port(visitor, right);
        }
    }
    visitor.owned_slice(&value.writeback);
    for binding in &value.writeback {
        writeback(visitor, binding);
    }
}
impl Dispatch {
    pub fn retained_heap(&self, heap: &mut RetainedHeap) {
        with_artifacts(heap, |visitor| {
            vector(visitor, &self.candidates);
            for candidate in &self.candidates {
                dispatch_candidate(visitor, candidate);
            }
            completeness(visitor, &self.completeness);
            if let Some(gap) = &self.external_body_unavailable {
                gap.target.retained_heap(visitor);
            }
        });
    }
}
impl CallModel<TaintEdgeFunction> {
    pub fn retained_heap(&self, heap: &mut RetainedHeap) {
        for transfer in &self.transfers {
            transfer.function.retained_heap(heap);
        }
        with_artifacts(heap, |visitor| {
            vector(visitor, &self.transfers);
            for transfer in &self.transfers {
                port(visitor, &transfer.actual);
                port(visitor, &transfer.output);
            }
            if let Some(summary) = &self.summary {
                summary.retained_allocations(visitor);
            }
            if let Some(target) = &self.summary_target {
                target.retained_allocations(visitor);
            }
            for bindings in [&self.writeback, &self.receiver_reads] {
                visitor.owned_slice(bindings);
                for binding in bindings {
                    writeback(visitor, binding);
                }
            }
            completeness(visitor, &self.completeness);
            if let Some(closures) = &self.authored {
                visitor.owned_slice(closures);
                for closure in closures {
                    visitor.procedure(closure.call().procedure());
                    visitor.context(closure.call_context());
                    visitor.locator(closure.target());
                    visitor.owned_slice(closure.origin().model().as_str().as_bytes());
                }
            }
        });
    }
}
impl Openness {
    pub fn retained_heap(&self, heap: &mut RetainedHeap) {
        with_artifacts(heap, |visitor| {
            if let Self::Open {
                residual,
                residual_causes,
                blocked,
                reason,
                ..
            } = self
            {
                visitor.owned_slice(residual);
                for call in residual {
                    key(visitor, &call.0);
                }
                visitor.owned_slice(residual_causes);
                visitor.owned_slice(reason.as_bytes());
                if let Some(blocked) = blocked {
                    visitor.procedure(blocked.gap.procedure());
                }
            }
        });
    }
}
impl StoreWriteObservation {
    pub fn retained_heap(&self, heap: &mut RetainedHeap) {
        with_artifacts(heap, |visitor| {
            key(visitor, &self.procedure);
            visitor.procedure(&self.owner);
            self.carrier.retained_artifacts(visitor);
        });
    }
}
impl StoreChannelLinks {
    pub fn retained_heap(&self, heap: &mut RetainedHeap) {
        with_artifacts(heap, |visitor| {
            vector(visitor, &self.writes);
            if let Some(reason) = &self.incomplete {
                visitor.owned_slice(reason.as_bytes());
            }
            for link in &self.writes {
                key(visitor, &link.write_call.0);
                key(visitor, &link.read_call.0);
                visitor.locator(&link.write_site);
                visitor.locator(&link.read_site);
                visitor.locator(link.read_origin.value_flow_key().site());
                link.read_carrier.retained_artifacts(visitor);
            }
        });
    }
}

// Visit just storage that InteriorFlows::clone allocates. Live handles remain
// shared and are priced by the normal semantic owner census, not clone funding.
fn interior_clone_storage(value: &InteriorFlows, visitor: &mut impl ArtifactRetentionVisitor) {
    vector(visitor, &value.flows);
    completeness(visitor, &value.completeness);
    for flow in &value.flows {
        visitor.owned_slice(&flow.crossed);
        for calls in &flow.crossed {
            visitor.owned_slice(calls);
        }
        if let Some(witness) = &flow.witness {
            visitor.owned_slice(witness);
        }
        if let InteriorTarget::Port(value) = &flow.target {
            port(visitor, value);
        }
    }
}
struct CloneBytes(usize);
impl RetentionCensusSink for CloneBytes {
    fn allocation(&mut self, _: usize, bytes: usize) -> bool {
        self.0 = self.0.saturating_add(bytes);
        true
    }
    fn exclusive(&mut self, bytes: usize) {
        self.0 = self.0.saturating_add(bytes);
    }
    fn reserve_scratch(&mut self, _: usize) -> bool {
        unreachable!("clone storage traversal allocates no scratch")
    }
    fn release_scratch(&mut self, _: usize) {
        unreachable!("clone storage traversal allocates no scratch")
    }
    fn is_refused(&self) -> bool {
        false
    }
    fn refuse(&mut self) {
        self.0 = usize::MAX;
    }
    fn weak_allocation(&mut self, _: usize, _: usize) {
        unreachable!("clone storage has no weak owners")
    }
}
impl ArtifactRetentionVisitor for CloneBytes {
    fn artifact(&mut self, _: &Arc<crate::analyzer::semantic::SemanticArtifact>) {
        unreachable!("clone storage excludes shared artifacts")
    }
    fn relation(&mut self, _: &crate::analyzer::semantic::OracleRelationHandle) {
        unreachable!("clone storage excludes shared relations")
    }
}
pub(super) fn interior_clone_bytes(value: &InteriorFlows) -> usize {
    let mut bytes = CloneBytes(0);
    interior_clone_storage(value, &mut bytes);
    bytes.0
}
struct AdoptClone<'a>(&'a mut RetainedHeap, &'a mut usize);
impl RetentionCensusSink for AdoptClone<'_> {
    fn allocation(&mut self, identity: usize, bytes: usize) -> bool {
        if bytes == 0 || self.0.is_refused() {
            return false;
        }
        let adopted = self.0.adopt_allocation(identity, bytes, bytes);
        if adopted {
            *self.1 = self
                .1
                .checked_sub(bytes)
                .expect("clone storage was prepaid");
        }
        adopted
    }
    fn exclusive(&mut self, _: usize) {
        unreachable!("clone storage uses allocation identities")
    }
    fn reserve_scratch(&mut self, _: usize) -> bool {
        unreachable!("clone storage traversal allocates no scratch")
    }
    fn release_scratch(&mut self, _: usize) {
        unreachable!("clone storage traversal allocates no scratch")
    }
    fn is_refused(&self) -> bool {
        self.0.is_refused()
    }
    fn refuse(&mut self) {
        RetentionCensusSink::refuse(self.0);
    }
    fn weak_allocation(&mut self, _: usize, _: usize) {
        unreachable!("clone storage has no weak owners")
    }
}
impl ArtifactRetentionVisitor for AdoptClone<'_> {
    fn artifact(&mut self, _: &Arc<crate::analyzer::semantic::SemanticArtifact>) {
        unreachable!("clone storage excludes shared artifacts")
    }
    fn relation(&mut self, _: &crate::analyzer::semantic::OracleRelationHandle) {
        unreachable!("clone storage excludes shared relations")
    }
}
pub(super) fn adopt_interior_clone(
    value: &InteriorFlows,
    heap: &mut RetainedHeap,
    remaining: &mut usize,
) {
    interior_clone_storage(value, &mut AdoptClone(heap, remaining));
}

fn partial_flows(value: &Arc<ProcedurePartialFlows>, heap: &mut RetainedHeap) {
    heap.arc(value, |value, heap| {
        with_artifacts(heap, |visitor| {
            vector(visitor, &value.ports);
            vector(visitor, &value.flows);
            vector(visitor, &value.discharged_gaps);
            if let Some(detail) = &value.detail {
                visitor.owned_string(detail);
            }
            for value in &value.ports {
                port(visitor, value);
            }
            for flow in &value.flows {
                visitor.owned_slice(&flow.crossed);
                for calls in &flow.crossed {
                    visitor.owned_slice(calls);
                }
            }
        });
    });
}
fn source(value: &BoundSource, heap: &mut RetainedHeap) {
    value.classes.retained_heap(heap);
    if let Some(entry) = &value.selected_entry {
        entry.retained_heap(heap);
    }
    with_artifacts(heap, |visitor| {
        visitor.procedure(value.point.procedure());
        value.carrier.retained_artifacts(visitor);
        visitor.locator(value.origin.value_flow_key().site());
    });
}
fn endpoint(value: &Endpoint, heap: &mut RetainedHeap) {
    with_artifacts(heap, |visitor| match value {
        Endpoint::Port(value) => port(visitor, value),
        Endpoint::Location(value) => location(visitor, value),
        Endpoint::CallHandoff { candidate, .. } => {
            visitor.owned_box(candidate.as_ref());
            dispatch_candidate(visitor, candidate);
        }
        Endpoint::Writeback {
            candidate,
            heap,
            storage,
            ..
        } => {
            visitor.owned_box(candidate.as_ref());
            dispatch_candidate(visitor, candidate);
            port(visitor, heap);
            visitor.owned_box(storage.as_ref());
            storage.visit_retained_allocations(visitor);
        }
        Endpoint::Source(_) | Endpoint::Sink(_) | Endpoint::StoreWrite(_) => {}
        Endpoint::Execution(_) | Endpoint::Object(_) => {
            unreachable!("taint candidate searches have no execution or object roots")
        }
    });
}
fn interior_input(value: &InteriorInput, heap: &mut RetainedHeap) {
    // The fixed partition box and cloned row heaps were prepaid and adopted
    // per actual allocation. Revisit them through the same registry, never a
    // scalar aggregate that could hide a shared owner.
    heap.owned_slice(&value.partitions);
    heap.vec(&value.seeds);
    heap.vec(&value.seed_ends);
    for seed in &value.seeds {
        if let InteriorSeed::Source {
            selected_entry: Some(entry),
            ..
        } = seed
        {
            entry.retained_heap(heap);
        }
    }
    with_artifacts(heap, |visitor| {
        for seed in &value.seeds {
            match seed {
                InteriorSeed::Source { carrier, .. } => carrier.retained_artifacts(visitor),
                InteriorSeed::Port(value) => port(visitor, value),
                InteriorSeed::Writeback {
                    storage,
                    selectors: fields,
                    ..
                } => {
                    visitor.owned_box(storage.as_ref());
                    storage.visit_retained_allocations(visitor);
                    selectors(visitor, fields);
                }
            }
        }
        if let InteriorObservations::Many(rows) = &value.observations {
            vector(visitor, rows);
        }
        for observation in value.observations.as_slice() {
            match observation {
                InteriorObservation::Sink { carrier, .. } => carrier.retained_artifacts(visitor),
                InteriorObservation::Location(value) => location(visitor, value),
            }
        }
        for partition in value.partitions.iter().flatten() {
            // Revisit actual clone capacities, not a scalar payload estimate.
            interior_clone_storage(&partition.flows, visitor);
            visitor.procedure(&partition.flows.procedure);
        }
    });
    for value in &value.seed_ends {
        endpoint(value, heap);
    }
}
fn annotation_hop(value: &Hop, visitor: &mut impl ArtifactRetentionVisitor) {
    match value {
        Hop::Sanitizer { call, .. } | Hop::Transform { call, .. } => key(visitor, &call.0),
        _ => unreachable!("annotation caches contain only sanitizer and transform placements"),
    }
}
impl SearchInputs<TaintClassSet, TaintEdgeFunction> {
    fn retained_heap(&self, heap: &mut RetainedHeap) {
        assert!(
            self.execution_roots.is_empty() && self.object_roots.is_empty(),
            "only a taint query enters the candidate API"
        );
        heap.vec(&self.execution_roots);
        heap.vec(&self.object_roots);
        heap.map(&self.accepted);
        for fact in self.accepted.values() {
            fact.retained_heap(heap);
        }
        heap.vec(&self.sources);
        for value in &self.sources {
            source(value, heap);
        }
        macro_rules! index {
            ($field:ident) => {{
                heap.map(&self.$field);
                for (procedure, rows) in &self.$field {
                    heap.vec(rows);
                    with_artifacts(heap, |visitor| key(visitor, procedure));
                }
            }};
        }
        index!(sources_in);
        index!(sinks_in);
        index!(store_writes_in);
        heap.map(&self.annotations);
        for (call, rows) in &self.annotations {
            heap.vec(rows);
            with_artifacts(heap, |visitor| {
                key(visitor, &call.0);
                for row in rows {
                    if let Some(value) = &row.input {
                        port(visitor, value);
                    }
                    if let Some(value) = &row.output {
                        port(visitor, value);
                    }
                    annotation_hop(&row.hop, visitor);
                }
            });
        }
        heap.map(&self.links);
        for (call, rows) in &self.links {
            heap.vec(rows);
            with_artifacts(heap, |visitor| {
                key(visitor, &call.0);
                for row in rows {
                    port(visitor, &row.input);
                    port(visitor, &row.output);
                    annotation_hop(&row.hop, visitor);
                }
            });
        }
        heap.map(&self.procedures);
        for (procedure, data) in &self.procedures {
            with_artifacts(heap, |visitor| key(visitor, procedure));
            if let Some(data) = data {
                heap.arc(data, |data, heap| {
                    partial_flows(&data.flows, heap);
                    if let Some(projections) = &data.projections {
                        heap.owned_slice(projections);
                        for projection in projections.iter().flatten() {
                            partial_flows(&projection.flows, heap);
                        }
                    }
                    if let Some(endpoints) = data.endpoints.get() {
                        heap.vec(&endpoints.sanitizers);
                        heap.vec(&endpoints.transforms);
                        heap.vec(&endpoints.causes);
                        for sanitizer in &endpoints.sanitizers {
                            sanitizer.function.retained_heap(heap);
                        }
                        for transform in &endpoints.transforms {
                            transform.function.retained_heap(heap);
                        }
                        with_artifacts(heap, |visitor| {
                            completeness(visitor, &endpoints.completeness);
                            for sanitizer in &endpoints.sanitizers {
                                visitor.procedure(sanitizer.point.procedure());
                                sanitizer.input.retained_artifacts(visitor);
                                sanitizer.output.retained_artifacts(visitor);
                            }
                            for transform in &endpoints.transforms {
                                visitor.procedure(transform.point.procedure());
                                transform.input.retained_artifacts(visitor);
                                transform.output.retained_artifacts(visitor);
                            }
                        });
                    }
                });
            }
        }
        heap.map(&self.interiors);
        for (procedure, data) in &self.interiors {
            with_artifacts(heap, |visitor| key(visitor, procedure));
            if let Some(data) = data {
                heap.arc(data, |data, heap| {
                    if let Some(input) = &data.input {
                        interior_input(input, heap);
                    }
                });
            }
        }
        heap.map(&self.location_interiors);
        for ((procedure, place), data) in &self.location_interiors {
            with_artifacts(heap, |visitor| {
                key(visitor, procedure);
                location(visitor, place);
            });
            if let Some(input) = &data.input {
                interior_input(input, heap);
            }
        }
        heap.map(&self.modeled_reader_origins);
        for ((procedure, place), rows) in &self.modeled_reader_origins {
            heap.vec(rows);
            with_artifacts(heap, |visitor| {
                key(visitor, procedure);
                location(visitor, place);
                for row in rows {
                    row.visit_retained_allocations(visitor);
                }
            });
        }
        heap.map(&self.handles);
        for (procedure, input) in &self.handles {
            with_artifacts(heap, |visitor| {
                key(visitor, procedure);
                visitor.procedure(&input.procedure);
            });
            if let Some(input) = &input.acquisition {
                interior_input(input, heap);
            }
        }
        heap.map(&self.dispatches);
        for (call, dispatch) in &self.dispatches {
            with_artifacts(heap, |visitor| key(visitor, &call.0));
            heap.arc(dispatch, |dispatch, heap| {
                heap.vec(&dispatch.candidates);
                for candidate in &dispatch.candidates {
                    heap.arc(candidate, |candidate, heap| {
                        with_artifacts(heap, |visitor| dispatch_candidate(visitor, candidate))
                    });
                }
                with_artifacts(heap, |visitor| {
                    if let Some(reason) = &dispatch.incomplete_reason {
                        visitor.owned_slice(reason.as_bytes());
                    }
                    if let Some(gap) = &dispatch.external_body_unavailable {
                        gap.target.retained_heap(visitor);
                    }
                });
            });
        }
        for models in [&self.models, &self.dispatched_models] {
            heap.map(models);
            for (call, model) in models {
                with_artifacts(heap, |visitor| key(visitor, &call.0));
                if let Some(model) = model {
                    heap.arc(model, |model, heap| model.retained_heap(heap));
                }
            }
        }
        heap.map(&self.callers);
        for (procedure, input) in &self.callers {
            with_artifacts(heap, |visitor| key(visitor, procedure));
            heap.arc(input, |input, heap| {
                heap.vec(&input.answer.calls);
                with_artifacts(heap, |visitor| {
                    completeness(visitor, &input.answer.completeness);
                    for call in &input.answer.calls {
                        key(visitor, &call.0);
                    }
                });
            });
        }
        heap.map(&self.parents);
        with_artifacts(heap, |visitor| {
            for (child, parent) in &self.parents {
                key(visitor, child);
                if let Some(parent) = parent {
                    key(visitor, parent);
                }
            }
        });
        heap.vec(&self.store_writes);
        for value in &self.store_writes {
            value.retained_heap(heap);
        }
    }
}

fn same_map<K: Eq + std::hash::Hash, V>(
    left: &crate::hash::HashMap<K, V>,
    right: &crate::hash::HashMap<K, V>,
    mut same: impl FnMut(&V, &V) -> bool,
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|(key, value)| right.get(key).is_some_and(|other| same(value, other)))
}
fn same_entry(
    left: &Option<Arc<crate::value_flow::SelectedSourceEntryView>>,
    right: &Option<Arc<crate::value_flow::SelectedSourceEntryView>>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.has_same_input_backing(right),
        _ => false,
    }
}
fn same_seed(left: &InteriorSeed, right: &InteriorSeed) -> bool {
    match (left, right) {
        (
            InteriorSeed::Source {
                point: lp,
                phase: lphase,
                carrier: lc,
                selected_entry: le,
            },
            InteriorSeed::Source {
                point: rp,
                phase: rphase,
                carrier: rc,
                selected_entry: re,
            },
        ) => lp == rp && lphase == rphase && lc == rc && same_entry(le, re),
        _ => left == right,
    }
}
impl ComposedInputBacking {
    fn same_function(&self, left: LabelFunctionId, other: &Self, right: LabelFunctionId) -> bool {
        self.function(left) == other.function(right)
    }
    fn same_endpoint(&self, left: &Endpoint, other: &Self, right: &Endpoint) -> bool {
        match (left, right) {
            (
                Endpoint::CallHandoff {
                    call: lc,
                    candidate: ltarget,
                    binding: lb,
                    function: lf,
                    quality: lq,
                },
                Endpoint::CallHandoff {
                    call: rc,
                    candidate: rtarget,
                    binding: rb,
                    function: rf,
                    quality: rq,
                },
            ) => {
                lc == rc
                    && ltarget == rtarget
                    && lb == rb
                    && lq == rq
                    && self.same_function(*lf, other, *rf)
            }
            _ => left == right,
        }
    }
    fn same_interior(
        &self,
        left: &Option<InteriorInput>,
        other: &Self,
        right: &Option<InteriorInput>,
    ) -> bool {
        let (Some(left), Some(right)) = (left, right) else {
            return false;
        };
        !left.partitions.is_empty()
            && left.seeds.len() == right.seeds.len()
            && left
                .seeds
                .iter()
                .zip(&right.seeds)
                .all(|(left, right)| same_seed(left, right))
            && left.seed_ends.len() == right.seed_ends.len()
            && left
                .seed_ends
                .iter()
                .zip(&right.seed_ends)
                .all(|(left, right)| self.same_endpoint(left, other, right))
            && left.observations.as_slice() == right.observations.as_slice()
            && left.partitions.len() == right.partitions.len()
            && left
                .partitions
                .iter()
                .zip(&right.partitions)
                .all(|(left, right)| {
                    let (Some(left), Some(right)) = (left, right) else {
                        return false;
                    };
                    self.same_function(left.function, other, right.function)
                        && left.flows.procedure == right.flows.procedure
                        && left.flows.flows == right.flows.flows
                        && left.flows.completeness == Completeness::Complete
                        && right.flows.completeness == Completeness::Complete
                })
    }
    fn same_placement(&self, left: &Hop, other: &Self, right: &Hop) -> bool {
        match (left, right) {
            (
                Hop::Transform {
                    call: lc,
                    function: lf,
                    uncertain: lu,
                },
                Hop::Transform {
                    call: rc,
                    function: rf,
                    uncertain: ru,
                },
            ) => lc == rc && lu == ru && self.same_function(*lf, other, *rf),
            (
                Hop::Sanitizer {
                    call: lc,
                    function: lf,
                    proven: lp,
                    uncertain: lu,
                },
                Hop::Sanitizer {
                    call: rc,
                    function: rf,
                    proven: rp,
                    uncertain: ru,
                },
            ) => lc == rc && lp == rp && lu == ru && self.same_function(*lf, other, *rf),
            _ => false,
        }
    }
    /// Sufficient typed correspondence of this search's FULL input domain.
    /// It grants neither absence nor positive proof. Only proven, resolved
    /// sanitizer annotations may disappear; callers separately validate their
    /// original root/frontier kill recipes. Materialization and auxiliary
    /// namespace mismatches fail closed rather than guessing equivalence.
    pub fn has_same_nonkill_inputs(&self, other: &Self) -> bool {
        if self.status != ComposedInputStatus::Available
            || other.status != ComposedInputStatus::Available
        {
            return false;
        }
        let (Some(left), Some(right)) = (&self.inputs, &other.inputs) else {
            return false;
        };
        if left.execution_roots != right.execution_roots
            || left.object_roots != right.object_roots
            || left.endpoint_projections != right.endpoint_projections
            || !left.sanitizers_resolved
            || !right.sanitizers_resolved
            || left.accepted != right.accepted
            || left.sources.len() != right.sources.len()
            || left.sources_in != right.sources_in
            || left.sinks_in != right.sinks_in
            || left.parents != right.parents
            || left.modeled_reader_origins != right.modeled_reader_origins
            || !left.store_writes.is_empty()
            || !right.store_writes.is_empty()
            || !left.store_writes_in.is_empty()
            || !right.store_writes_in.is_empty()
        {
            return false;
        }
        if !left
            .sources
            .iter()
            .zip(&right.sources)
            .enumerate()
            .all(|(index, (left, right))| {
                self.original_source_evidence.get(index)
                    == other.original_source_evidence.get(index)
                    && self.original_source_evidence.get(index).is_some()
                    && left.point == right.point
                    && left.phase == right.phase
                    && left.carrier == right.carrier
                    && left.classes == right.classes
                    && left.origin == right.origin
                    && same_entry(&left.selected_entry, &right.selected_entry)
            })
        {
            return false;
        }
        if !same_map(&left.procedures, &right.procedures, |left, right| {
            let (Some(left), Some(right)) = (left, right) else {
                return false;
            };
            let (Some(lp), Some(rp), Some(le), Some(re)) = (
                &left.projections,
                &right.projections,
                left.endpoints.get(),
                right.endpoints.get(),
            ) else {
                return false;
            };
            !lp.is_empty()
                && left.flows == right.flows
                && left.flows.outcome
                    == crate::analyzer::semantic::partial_flow::PartialFlowOutcome::Complete
                && le.sources == re.sources
                && le
                    .sanitizers
                    .iter()
                    .chain(&re.sanitizers)
                    .all(|sanitizer| sanitizer.proven && sanitizer.resolved)
                && le.causes == re.causes
                && le.causes.is_empty()
                && le.transforms == re.transforms
                && le.completeness == Completeness::Complete
                && re.completeness == Completeness::Complete
                && lp.len() == rp.len()
                && lp.iter().zip(rp).all(|(left, right)| {
                    let (Some(left), Some(right)) = (left, right) else {
                        return false;
                    };
                    left.flows == right.flows
                        && self.same_function(left.function, other, right.function)
                })
        }) {
            return false;
        }
        if !same_map(&left.interiors, &right.interiors, |left, right| {
            match (left, right) {
                (None, None) => true,
                (Some(left), Some(right)) => self.same_interior(&left.input, other, &right.input),
                _ => false,
            }
        }) || !same_map(
            &left.location_interiors,
            &right.location_interiors,
            |left, right| self.same_interior(&left.input, other, &right.input),
        ) || !same_map(&left.handles, &right.handles, |left, right| {
            left.procedure == right.procedure
                && match (&left.acquisition, &right.acquisition) {
                    (None, None) => true,
                    _ => self.same_interior(&left.acquisition, other, &right.acquisition),
                }
        }) {
            return false;
        }
        if !same_map(&left.dispatches, &right.dispatches, |left, right| {
            left.candidates == right.candidates
                && left.uncertain == right.uncertain
                && left.incomplete_reason == right.incomplete_reason
                && left.incomplete_cause == right.incomplete_cause
                && left.external_body_unavailable == right.external_body_unavailable
                && left.continuation == right.continuation
        }) || left.models != right.models
            || left.dispatched_models != right.dispatched_models
            || !same_map(&left.callers, &right.callers, |left, right| {
                left.answer == right.answer
                    && left.retained_len == right.retained_len
                    && left.clipped == right.clipped
                    && left.answer.completeness == Completeness::Complete
                    && !left.clipped
            })
        {
            return false;
        }
        if !same_map(&left.links, &right.links, |left, right| {
            left.len() == right.len()
                && left.iter().zip(right).all(|(left, right)| {
                    left.input == right.input
                        && left.output == right.output
                        && self.same_placement(&left.hop, other, &right.hop)
                })
        }) {
            return false;
        }
        let is_kill = |row: &&Annotation| {
            matches!(
                row.hop,
                Hop::Sanitizer {
                    proven: true,
                    uncertain: false,
                    ..
                }
            )
        };
        // Check both domains: a key present on only one side is allowed only
        // when every row there is a proven resolved sanitizer placement.
        for (call, rows) in &left.annotations {
            let mut l = rows.iter().filter(|row| !is_kill(row));
            let mut r = right
                .annotations
                .get(call)
                .into_iter()
                .flatten()
                .filter(|row| !is_kill(row));
            loop {
                match (l.next(), r.next()) {
                    (None, None) => break,
                    (Some(left), Some(right))
                        if left.input == right.input
                            && left.output == right.output
                            && self.same_placement(&left.hop, other, &right.hop) => {}
                    _ => return false,
                }
            }
        }
        right.annotations.iter().all(|(call, rows)| {
            left.annotations.contains_key(call) || rows.iter().all(|row| is_kill(&row))
        })
    }
    /// Visit the original frontier sanitizer recipes, including their distinct
    /// input and output carriers. Root-plan recipes remain owned by the caller.
    pub fn all_sanitizers_match(&self, mut predicate: impl FnMut(&BoundSanitizer) -> bool) -> bool {
        if self.status != ComposedInputStatus::Available {
            return false;
        }
        self.inputs.as_ref().is_some_and(|inputs| {
            inputs.procedures.values().all(|data| {
                data.as_ref().is_some_and(|data| {
                    data.endpoints
                        .get()
                        .is_some_and(|endpoints| endpoints.sanitizers.iter().all(&mut predicate))
                })
            })
        })
    }
}
