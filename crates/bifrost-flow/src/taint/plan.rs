use std::{collections::BTreeMap, error::Error, fmt, mem::size_of_val, sync::Arc};

use crate::analyzer::semantic::{
    LengthDelimitedDigest, ProgramPointHandle, SemanticLocator, StableDigest,
};
use crate::dataflow::UnmodeledCallBehavior;
use crate::value_flow::{
    ValueFlowCarrierId, ValueFlowEventKind, ValueFlowObservationPhase, ValueFlowPlan,
    ValueFlowSinkId, ValueFlowSinkSpec, ValueFlowSourceId, ValueFlowSourceSpec,
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
    /// The carrier whose taint is established by the sanitizer input port.
    /// For a call-bound sanitizer, the effect is applied while this carrier is
    /// mapped across the call boundary. The caller-side carrier remains
    /// available on the call-to-return edge, so an unused sanitizer result does
    /// not clear the original value.
    carrier: ValueFlowCarrierId,
    /// The carrier established by the sanitizer output port. This is retained
    /// as part of the binding identity and validated against the same value
    /// flow plan. It identifies the output path for the call-bound effect.
    output: ValueFlowCarrierId,
    removed: TaintClassSet,
    proven: bool,
    complete: bool,
}

impl TaintSanitizerBinding {
    pub const fn resolved(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self::resolved_with_output(point, phase, event_index, carrier, carrier, removed)
    }

    pub const fn resolved_with_output(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        output: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self {
            point,
            phase,
            event_index,
            carrier,
            output,
            removed,
            proven: true,
            complete: true,
        }
    }

    pub const fn unresolved(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self::unresolved_with_output(point, phase, event_index, carrier, carrier, removed)
    }

    pub const fn unresolved_with_output(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        output: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self {
            point,
            phase,
            event_index,
            carrier,
            output,
            removed,
            proven: false,
            complete: false,
        }
    }

    pub const fn proven_incomplete_with_output(
        point: ProgramPointHandle,
        phase: ValueFlowObservationPhase,
        event_index: u32,
        carrier: ValueFlowCarrierId,
        output: ValueFlowCarrierId,
        removed: TaintClassSet,
    ) -> Self {
        Self {
            point,
            phase,
            event_index,
            carrier,
            output,
            removed,
            proven: true,
            complete: false,
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

    pub const fn output(&self) -> ValueFlowCarrierId {
        self.output
    }

    pub const fn event_index(&self) -> u32 {
        self.event_index
    }

    pub const fn removed(&self) -> &TaintClassSet {
        &self.removed
    }

    pub const fn is_resolved(&self) -> bool {
        self.complete
    }

    pub const fn is_proven(&self) -> bool {
        self.proven
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

/// The resolution of one optional store discrimination dimension (the key a
/// value is stored under, or the store instance it is stored in).
///
/// A dimension separates two ends of a persistence boundary only when both
/// ends carry a proven identity and the identities differ. Everything else
/// joins: an undeclared dimension expresses "the whole store" and an unproven
/// one must not manufacture a separation the analysis cannot defend. Joining
/// is the sound direction for a may-analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaintStoreDimension {
    /// The policy did not declare this dimension on the entry.
    Undeclared,
    /// Declared, but the compiler could not prove a stable identity for the
    /// selected call's dimension port.
    Unproven,
    /// Declared and resolved to a stable identity digest minted by the
    /// policy compiler (a constant key token, or a store-instance location).
    Proven(StableDigest),
}

impl TaintStoreDimension {
    fn separates(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Proven(left), Self::Proven(right)) => left != right,
            _ => false,
        }
    }
}

/// The runtime store identity one write or read binding participates in: the
/// declared store name plus the resolved discrimination dimensions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintStoreChannel {
    store: Box<str>,
    instance: TaintStoreDimension,
    key: TaintStoreDimension,
}

impl TaintStoreChannel {
    pub fn new(
        store: impl Into<Box<str>>,
        instance: TaintStoreDimension,
        key: TaintStoreDimension,
    ) -> Self {
        let store = store.into();
        assert!(
            !store.is_empty(),
            "a store channel requires a declared store name"
        );
        Self {
            store,
            instance,
            key,
        }
    }

    pub fn store(&self) -> &str {
        &self.store
    }

    pub const fn instance(&self) -> &TaintStoreDimension {
        &self.instance
    }

    pub const fn key(&self) -> &TaintStoreDimension {
        &self.key
    }

    /// Whether a write on this channel may reach a read on `other`.
    ///
    /// Store names must match exactly; each discrimination dimension then
    /// separates the pair only when both ends prove distinct identities.
    pub fn may_alias(&self, other: &Self) -> bool {
        self.store == other.store
            && !self.instance.separates(&other.instance)
            && !self.key.separates(&other.key)
    }
}

/// One declared store write: the internal value-flow sink observing the
/// written carrier, and the channel identity the write publishes into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintStoreWriteBinding {
    sink: ValueFlowSinkId,
    channel: TaintStoreChannel,
    complete: bool,
}

impl TaintStoreWriteBinding {
    pub const fn new(sink: ValueFlowSinkId, channel: TaintStoreChannel, complete: bool) -> Self {
        Self {
            sink,
            channel,
            complete,
        }
    }

    pub const fn sink(&self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn channel(&self) -> &TaintStoreChannel {
        &self.channel
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// One declared store read: the internal value-flow source establishing the
/// returned carrier, and the channel identity the read consumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintStoreReadBinding {
    source: ValueFlowSourceId,
    channel: TaintStoreChannel,
    complete: bool,
}

impl TaintStoreReadBinding {
    pub const fn new(
        source: ValueFlowSourceId,
        channel: TaintStoreChannel,
        complete: bool,
    ) -> Self {
        Self {
            source,
            channel,
            complete,
        }
    }

    pub const fn source(&self) -> ValueFlowSourceId {
        self.source
    }

    pub const fn channel(&self) -> &TaintStoreChannel {
        &self.channel
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
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
    store_writes: Box<[TaintStoreWriteBinding]>,
    store_reads: Box<[TaintStoreReadBinding]>,
    identity: TaintEdgeFunction,
    phase_transfers: Box<[ResolvedTaintTransfer]>,
    sanitizers_resolved: bool,
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
            validate_carrier_binding(
                &value_flow,
                sanitizer.point(),
                sanitizer.output,
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
        // Only in-place bindings are phase transfers. A distinct input/output
        // pair is consumed by the call/return boundary mapping in the taint
        // client; putting it in a phase slot would kill the caller's original
        // value even when the sanitizer result is unused.
        let mut ordered = sanitizers
            .iter()
            .filter(|sanitizer| sanitizer.carrier() == sanitizer.output())
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
                OrderedTaintTransfer::Sanitizer(sanitizer) if sanitizer.is_proven() => {
                    transfer.function = transfer
                        .function
                        .compose(&TaintEdgeFunction::kill(sanitizer.removed()));
                }
                OrderedTaintTransfer::Sanitizer(_) => {}
                OrderedTaintTransfer::Transform(transform) => {
                    transfer.function = transfer.function.compose(transform.function());
                }
            }
            if let OrderedTaintTransfer::Sanitizer(sanitizer) = event
                && !sanitizer.is_resolved()
            {
                transfer.complete = false;
            }
        }
        phase_transfers.sort_by(compare_resolved_transfers);
        let sanitizers_resolved = sanitizers.iter().all(TaintSanitizerBinding::is_resolved);
        Ok(Self {
            value_flow,
            universe,
            sources: sources.into_boxed_slice(),
            sinks: sinks.into_boxed_slice(),
            sanitizers: sanitizers.into_boxed_slice(),
            transforms: transforms.into_boxed_slice(),
            store_writes: Box::default(),
            store_reads: Box::default(),
            identity,
            phase_transfers: phase_transfers.into_boxed_slice(),
            sanitizers_resolved,
            owner: Arc::new(()),
        })
    }

    /// Attach persistence-boundary bindings to this plan.
    ///
    /// Every write must name a value-flow sink of this plan and every read a
    /// value-flow source, each at most once. The driver seeds each read's
    /// taint source binding with the classes observed at the writes whose
    /// channel may alias the read's channel; the plan itself only carries the
    /// linkage identity.
    pub fn with_stores(
        mut self,
        mut store_writes: Vec<TaintStoreWriteBinding>,
        mut store_reads: Vec<TaintStoreReadBinding>,
    ) -> Result<Self, TaintPlanError> {
        store_writes.sort_by(|left, right| {
            left.sink
                .cmp(&right.sink)
                .then_with(|| left.channel.cmp(&right.channel))
        });
        store_reads.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then_with(|| left.channel.cmp(&right.channel))
        });
        if store_writes
            .windows(2)
            .any(|pair| pair[0].sink == pair[1].sink)
            || store_reads
                .windows(2)
                .any(|pair| pair[0].source == pair[1].source)
        {
            return Err(TaintPlanError::DuplicateBinding);
        }
        for write in &store_writes {
            if self.value_flow.sink(write.sink).is_none() {
                return Err(TaintPlanError::InvalidSink);
            }
        }
        for read in &store_reads {
            if self.value_flow.source(read.source).is_none() {
                return Err(TaintPlanError::InvalidSource);
            }
        }
        self.store_writes = store_writes.into_boxed_slice();
        self.store_reads = store_reads.into_boxed_slice();
        Ok(self)
    }

    /// Derive the plan the store-seeding driver solves to observe which
    /// classes reach each declared store write: the same plan with every
    /// write's value-flow sink bound to accept the full universe. The caller
    /// discards the resulting findings after reading the per-sink classes;
    /// this variant never projects policy findings.
    pub fn with_store_write_observations(&self) -> Result<Self, TaintPlanError> {
        let full = self
            .universe
            .class_set(self.universe.classes().iter())
            .expect("a universe accepts its own classes");
        let mut sinks = self.sinks.to_vec();
        for write in &self.store_writes {
            if sinks.iter().any(|sink| sink.sink() == write.sink) {
                return Err(TaintPlanError::DuplicateBinding);
            }
            sinks.push(TaintSinkBinding::new(write.sink, full.clone()));
        }
        let rebuilt = Self::new(
            self.value_flow.clone(),
            self.universe.clone(),
            self.sources.to_vec(),
            sinks,
            self.sanitizers.to_vec(),
            self.transforms.to_vec(),
        )?;
        rebuilt.with_stores(self.store_writes.to_vec(), self.store_reads.to_vec())
    }

    /// Derive the plan with the given store reads seeded as taint sources.
    /// Each seed names one of this plan's store-read sources and the classes
    /// the linked writes were observed to receive; the origin key is the
    /// read's own source event. A read with no seed stays inert.
    pub fn with_seeded_store_reads(
        &self,
        seeds: &[(ValueFlowSourceId, TaintClassSet)],
    ) -> Result<Self, TaintPlanError> {
        let mut sources = self.sources.to_vec();
        for (source, classes) in seeds {
            if classes.is_empty() {
                continue;
            }
            if !self.store_reads.iter().any(|read| read.source == *source) {
                return Err(TaintPlanError::InvalidSource);
            }
            if sources.iter().any(|binding| binding.source() == *source) {
                return Err(TaintPlanError::DuplicateBinding);
            }
            let spec = self
                .value_flow
                .source(*source)
                .ok_or(TaintPlanError::InvalidSource)?;
            sources.push(TaintSourceBinding::new(
                *source,
                classes.clone(),
                SourceEventKey::new(spec.key().clone()),
            ));
        }
        let rebuilt = Self::new(
            self.value_flow.clone(),
            self.universe.clone(),
            sources,
            self.sinks.to_vec(),
            self.sanitizers.to_vec(),
            self.transforms.to_vec(),
        )?;
        rebuilt.with_stores(self.store_writes.to_vec(), self.store_reads.to_vec())
    }

    pub fn store_writes(&self) -> &[TaintStoreWriteBinding] {
        &self.store_writes
    }

    pub fn store_reads(&self) -> &[TaintStoreReadBinding] {
        &self.store_reads
    }

    /// Whether every store binding this plan compiled resolved completely.
    /// Mirrors [`Self::sanitizers_resolved`]: an incomplete store binding must
    /// keep the run from reporting a complete verdict.
    pub fn stores_resolved(&self) -> bool {
        self.store_writes
            .iter()
            .all(TaintStoreWriteBinding::is_complete)
            && self
                .store_reads
                .iter()
                .all(TaintStoreReadBinding::is_complete)
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
            .saturating_add(self.store_writes.len())
            .saturating_add(self.store_reads.len())
    }

    /// Whether every sanitizer this plan compiled resolved to a model.
    ///
    /// This is the only discovery input the taint layer owns. Value-flow
    /// discovery is not re-asked here: `ValueFlowPlan::execution_result_complete`
    /// already asks it over the solved result, and asks it in the #1952 sense,
    /// which accepts a snapshot left open only by call-target refinement whose
    /// residual calls this result fully modeled. The plan-time
    /// `ValueFlowPlan::discovery_complete` flag is strictly stronger than that:
    /// it demands every snapshot be complete outright. Conjoining it here
    /// withheld both `Complete` and `ProvenBySummary` from exactly the runs a
    /// boundary model exists to close (#2342).
    pub const fn sanitizers_resolved(&self) -> bool {
        self.sanitizers_resolved
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
            .saturating_add(size_of_val(&*self.store_writes))
            .saturating_add(size_of_val(&*self.store_reads))
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

    /// Conservative directional transfer fan-out inputs for snapshot
    /// planning. Value-flow relations account for local, call, fallback, and
    /// endpoint transfer work; taint's phase-composed sanitizer and transform
    /// relations add one cost for each retained transfer slot and authored
    /// event. The result is an upper-bound proxy, not a propagation count.
    pub(crate) fn directional_transfer_fanout_estimates(&self) -> (usize, usize) {
        let taint_transfer_work = self
            .phase_transfers
            .len()
            .saturating_add(self.sanitizers.len())
            .saturating_add(self.transforms.len());
        (
            self.value_flow
                .forward_transfer_fanout_estimate()
                .saturating_add(taint_transfer_work),
            self.value_flow
                .backward_transfer_fanout_estimate()
                .saturating_add(taint_transfer_work),
        )
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
        .then_with(|| left.output.cmp(&right.output))
        .then_with(|| left.removed.cmp(&right.removed))
        .then_with(|| left.proven.cmp(&right.proven))
        .then_with(|| left.complete.cmp(&right.complete))
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

const TAINT_PROPAGATION_SEMANTICS_DOMAIN: &[u8] = b"bifrost.taint.propagation-semantics.v1";

/// The identity of every ingredient that decides propagation results for one
/// solve: the workspace snapshot the plan was built from, the analysis root,
/// the value flow's own propagation semantics, the sanitizers that remove
/// taint along the way, and the persistence-store bindings that seed taint
/// across region boundaries.
///
/// This is a domain-separated SHA-256 over stable encodings, never a rendered
/// string. `Debug` output is not a stability contract, and a Debug-formatted
/// locator inside a batching identity silently splits or merges compatibility
/// classes whenever a derive or a field changes. Length-delimiting each
/// ingredient also removes the delimiter ambiguity that string concatenation
/// carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintPropagationSemanticsId(StableDigest);

impl TaintPropagationSemanticsId {
    /// Mint the identity from the ingredients themselves. There is no
    /// constructor that takes a pre-rendered string, so no caller can put a
    /// Debug rendering into this identity.
    pub fn new(
        workspace_snapshot: &StableDigest,
        root: &SemanticLocator,
        value_flow_propagation_hash: u64,
        sanitizer_hash: u64,
        store_hash: u64,
    ) -> Self {
        let mut digest = LengthDelimitedDigest::new(TAINT_PROPAGATION_SEMANTICS_DOMAIN);
        digest.push(workspace_snapshot.as_bytes());
        root.push_stable_identity(&mut digest);
        digest.push(&value_flow_propagation_hash.to_le_bytes());
        digest.push(&sanitizer_hash.to_le_bytes());
        digest.push(&store_hash.to_le_bytes());
        Self(digest.finish())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for TaintPropagationSemanticsId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// Two policies may share one propagation solve exactly when every ingredient
/// that can change propagation results is equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintBatchCompatibilityKey {
    propagation_semantics: TaintPropagationSemanticsId,
    unmodeled_call_behavior: UnmodeledCallBehavior,
    universe: TaintUniverseHash,
}

impl TaintBatchCompatibilityKey {
    pub fn new(
        propagation_semantics: TaintPropagationSemanticsId,
        universe: TaintUniverseHash,
    ) -> Self {
        Self::with_call_behavior(
            propagation_semantics,
            UnmodeledCallBehavior::default(),
            universe,
        )
    }

    pub const fn with_call_behavior(
        propagation_semantics: TaintPropagationSemanticsId,
        unmodeled_call_behavior: UnmodeledCallBehavior,
        universe: TaintUniverseHash,
    ) -> Self {
        Self {
            propagation_semantics,
            unmodeled_call_behavior,
            universe,
        }
    }

    pub const fn propagation_semantics(&self) -> TaintPropagationSemanticsId {
        self.propagation_semantics
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
    /// Derive the batch whose analysis has the given store-read seeds bound
    /// as taint sources. Seeding changes bindings, never propagation
    /// semantics, so the compatibility key and per-policy projections carry
    /// over unchanged.
    pub fn with_seeded_store_reads(
        &self,
        seeds: &[(ValueFlowSourceId, TaintClassSet)],
    ) -> Result<Self, TaintPlanError> {
        Ok(Self {
            compatibility: self.compatibility,
            projections: self.projections.clone(),
            analysis: self.analysis.with_seeded_store_reads(seeds)?,
        })
    }

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
            groups.entry(policy.compatibility).or_default().push(policy);
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
                )?
                .with_stores(
                    remap_store_writes(&first.analysis, &value_flow)?,
                    remap_store_reads(&first.analysis, &value_flow)?,
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
        || !same_stores(left, right)
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
            Ok(if binding.complete {
                TaintSanitizerBinding::resolved_with_output(
                    binding.point.clone(),
                    binding.phase,
                    binding.event_index,
                    carrier,
                    remapped_carrier(&analysis.value_flow, value_flow, binding.output)?,
                    binding.removed.clone(),
                )
            } else if binding.proven {
                TaintSanitizerBinding::proven_incomplete_with_output(
                    binding.point.clone(),
                    binding.phase,
                    binding.event_index,
                    carrier,
                    remapped_carrier(&analysis.value_flow, value_flow, binding.output)?,
                    binding.removed.clone(),
                )
            } else {
                TaintSanitizerBinding::unresolved_with_output(
                    binding.point.clone(),
                    binding.phase,
                    binding.event_index,
                    carrier,
                    remapped_carrier(&analysis.value_flow, value_flow, binding.output)?,
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
                    && left_binding.proven == right_binding.proven
                    && left_binding.complete == right_binding.complete
                    && left.value_flow.carrier_key(left_binding.carrier)
                        == right.value_flow.carrier_key(right_binding.carrier)
                    && left.value_flow.carrier_key(left_binding.output)
                        == right.value_flow.carrier_key(right_binding.output)
            })
}

fn remap_store_writes(
    analysis: &TaintAnalysisPlan,
    value_flow: &ValueFlowPlan,
) -> Result<Vec<TaintStoreWriteBinding>, TaintPlanError> {
    analysis
        .store_writes
        .iter()
        .map(|binding| {
            let spec = analysis
                .value_flow
                .sink(binding.sink)
                .ok_or(TaintPlanError::InvalidSink)?;
            let remapped = value_flow
                .sink_id_for_key(spec.key())
                .ok_or(TaintPlanError::InvalidSink)?;
            Ok(TaintStoreWriteBinding::new(
                remapped,
                binding.channel.clone(),
                binding.complete,
            ))
        })
        .collect()
}

fn remap_store_reads(
    analysis: &TaintAnalysisPlan,
    value_flow: &ValueFlowPlan,
) -> Result<Vec<TaintStoreReadBinding>, TaintPlanError> {
    analysis
        .store_reads
        .iter()
        .map(|binding| {
            let spec = analysis
                .value_flow
                .source(binding.source)
                .ok_or(TaintPlanError::InvalidSource)?;
            let remapped = value_flow
                .source_id_for_key(spec.key())
                .ok_or(TaintPlanError::InvalidSource)?;
            Ok(TaintStoreReadBinding::new(
                remapped,
                binding.channel.clone(),
                binding.complete,
            ))
        })
        .collect()
}

fn same_stores(left: &TaintAnalysisPlan, right: &TaintAnalysisPlan) -> bool {
    left.store_writes.len() == right.store_writes.len()
        && left.store_reads.len() == right.store_reads.len()
        && left
            .store_writes
            .iter()
            .zip(&right.store_writes)
            .all(|(left_binding, right_binding)| {
                left_binding.channel == right_binding.channel
                    && left_binding.complete == right_binding.complete
                    && left
                        .value_flow
                        .sink(left_binding.sink)
                        .map(ValueFlowSinkSpec::key)
                        == right
                            .value_flow
                            .sink(right_binding.sink)
                            .map(ValueFlowSinkSpec::key)
            })
        && left
            .store_reads
            .iter()
            .zip(&right.store_reads)
            .all(|(left_binding, right_binding)| {
                left_binding.channel == right_binding.channel
                    && left_binding.complete == right_binding.complete
                    && left
                        .value_flow
                        .source(left_binding.source)
                        .map(ValueFlowSourceSpec::key)
                        == right
                            .value_flow
                            .source(right_binding.source)
                            .map(ValueFlowSourceSpec::key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticLanguage,
        SemanticRole, SourceAnchor, SourcePosition, SourceSpan, WorkspaceMountId,
        WorkspaceRelativePath,
    };
    use crate::taint::SourceClassId;

    fn locator(path: &str, name: &str) -> SemanticLocator {
        let span =
            SourceSpan::new(SourcePosition::new(0, 0, 0), SourcePosition::new(1, 0, 1)).unwrap();
        let anchor = SourceAnchor::new(span, 0);
        SemanticLocator::new(
            WorkspaceMountId::hash_bytes("mount"),
            WorkspaceRelativePath::new(path).unwrap(),
            SemanticLanguage::Standard(Language::Java),
            DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor, 0)
                    .unwrap(),
            ])
            .unwrap(),
            SemanticRole::Procedure,
            anchor,
        )
    }

    fn snapshot(seed: u8) -> StableDigest {
        StableDigest::from_array([seed; 32])
    }

    #[test]
    fn propagation_semantics_separates_every_ingredient_that_changes_results() {
        let base =
            TaintPropagationSemanticsId::new(&snapshot(1), &locator("src/A.java", "run"), 7, 9, 11);

        assert_eq!(
            base,
            TaintPropagationSemanticsId::new(&snapshot(1), &locator("src/A.java", "run"), 7, 9, 11),
            "equal ingredients must produce one batch compatibility class"
        );
        for changed in [
            TaintPropagationSemanticsId::new(&snapshot(2), &locator("src/A.java", "run"), 7, 9, 11),
            TaintPropagationSemanticsId::new(&snapshot(1), &locator("src/B.java", "run"), 7, 9, 11),
            TaintPropagationSemanticsId::new(
                &snapshot(1),
                &locator("src/A.java", "other"),
                7,
                9,
                11,
            ),
            TaintPropagationSemanticsId::new(&snapshot(1), &locator("src/A.java", "run"), 8, 9, 11),
            TaintPropagationSemanticsId::new(&snapshot(1), &locator("src/A.java", "run"), 7, 8, 11),
        ] {
            assert_ne!(
                base, changed,
                "an ingredient that changes propagation results must change the identity"
            );
        }
    }

    #[test]
    fn propagation_semantics_is_a_digest_of_the_ingredients_not_a_rendering_of_them() {
        // The regression this pins: the identity used to be
        // `format!("...:{:?}:...", locator)`, so a `Debug` change to
        // `SemanticLocator` silently repartitioned every taint batch. Rebuilding
        // the digest here from the same domain and the same length-delimited
        // stable encodings reproduces the identity exactly, which is only true
        // while construction goes through the digest rather than through any
        // rendered text.
        let root = locator("src/A.java", "run");
        let mut expected = LengthDelimitedDigest::new(TAINT_PROPAGATION_SEMANTICS_DOMAIN);
        expected.push(snapshot(1).as_bytes());
        root.push_stable_identity(&mut expected);
        expected.push(&7_u64.to_le_bytes());
        expected.push(&9_u64.to_le_bytes());
        expected.push(&11_u64.to_le_bytes());

        assert_eq!(
            TaintPropagationSemanticsId::new(&snapshot(1), &root, 7, 9, 11).as_bytes(),
            expected.finish().as_bytes()
        );
    }

    #[test]
    fn store_channels_separate_only_on_proven_distinct_dimensions() {
        let proven_a = TaintStoreDimension::Proven(snapshot(10));
        let proven_b = TaintStoreDimension::Proven(snapshot(11));
        let primary = |instance: TaintStoreDimension, key: TaintStoreDimension| {
            TaintStoreChannel::new("primary", instance, key)
        };

        // Equal store name and no separating dimension: aliases.
        assert!(
            primary(TaintStoreDimension::Undeclared, proven_a.clone())
                .may_alias(&primary(TaintStoreDimension::Undeclared, proven_a.clone())),
            "equal proven keys on one store must alias"
        );
        // A proven-distinct key separates.
        assert!(
            !primary(TaintStoreDimension::Undeclared, proven_a.clone())
                .may_alias(&primary(TaintStoreDimension::Undeclared, proven_b.clone())),
            "proven distinct keys must separate"
        );
        // A proven-distinct instance separates.
        assert!(
            !primary(proven_a.clone(), TaintStoreDimension::Undeclared)
                .may_alias(&primary(proven_b.clone(), TaintStoreDimension::Undeclared)),
            "proven distinct instances must separate"
        );
        // Any unproven or undeclared side joins: the analysis cannot defend a
        // separation it did not prove.
        assert!(
            primary(TaintStoreDimension::Unproven, proven_a.clone())
                .may_alias(&primary(proven_b.clone(), proven_a.clone())),
            "an unproven instance must join"
        );
        assert!(
            primary(
                TaintStoreDimension::Undeclared,
                TaintStoreDimension::Unproven
            )
            .may_alias(&primary(TaintStoreDimension::Undeclared, proven_b)),
            "an unproven key must join"
        );
        // Different store names never alias, whatever the dimensions say.
        assert!(
            !primary(
                TaintStoreDimension::Undeclared,
                TaintStoreDimension::Undeclared
            )
            .may_alias(&TaintStoreChannel::new(
                "secondary",
                TaintStoreDimension::Undeclared,
                TaintStoreDimension::Undeclared,
            )),
            "distinct store names must separate"
        );
    }

    #[test]
    fn compatibility_keys_separate_call_behavior_from_propagation_semantics() {
        let semantics =
            TaintPropagationSemanticsId::new(&snapshot(1), &locator("src/A.java", "run"), 7, 9, 11);
        let universe =
            TaintUniverse::new(vec![SourceClassId::new("input.user-controlled").unwrap()])
                .unwrap()
                .hash();

        assert_eq!(
            TaintBatchCompatibilityKey::new(semantics, universe),
            TaintBatchCompatibilityKey::with_call_behavior(
                semantics,
                UnmodeledCallBehavior::default(),
                universe,
            )
        );
        assert_ne!(
            TaintBatchCompatibilityKey::new(semantics, universe),
            TaintBatchCompatibilityKey::with_call_behavior(
                semantics,
                UnmodeledCallBehavior::Optimistic,
                universe,
            )
        );
    }
}
