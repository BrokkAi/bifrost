//! Request-local publication dependence, separate from heap alias equality.

use std::collections::VecDeque;

use super::{
    ConcurrencyOpenReason, ConcurrencyStorageFamily, InvocationId, Invocations,
    reference_control_is_complete, reference_evidence_is_complete,
};
use crate::analyzer::semantic::{
    CallSiteId, CaptureMode, CaptureSource, MemoryLocationId, MemoryLocationKind,
    SemanticCapability, SemanticEffect, SemanticGapDischarge, SemanticGapImpact,
    SemanticGapSubject, SemanticRequest, SemanticValueKind, SemanticWork, SynchronizationOperation,
    TransferOperation, ValueFlowKind, ValueId, ValueTransfer,
};
use crate::hash::{HashMap, HashSet};

pub(super) struct PrivateStorage {
    families: HashSet<ConcurrencyStorageFamily>,
}

impl PrivateStorage {
    pub(super) fn contains(&self, family: &ConcurrencyStorageFamily) -> bool {
        self.families.contains(family)
    }

    pub(super) fn exclude(&mut self, family: &ConcurrencyStorageFamily) {
        self.families.remove(family);
    }
}

// Reading Contents does not expose CellAddress. Only address creation and
// reference capture can publish the storage containing those contents.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Node {
    Value(InvocationId, ValueId),
    Contents(InvocationId, MemoryLocationId),
    CellAddress(InvocationId, MemoryLocationId),
}

#[derive(Debug)]
enum Failure {
    Incomplete,
    Budget,
}

#[derive(Default)]
struct Graph {
    ids: HashMap<Node, usize>,
    predecessors: Vec<Vec<usize>>,
    boundaries: HashSet<usize>,
}

impl Graph {
    fn node(&mut self, node: Node, request: &mut SemanticRequest<'_>) -> Result<usize, Failure> {
        if let Some(id) = self.ids.get(&node) {
            return Ok(*id);
        }
        charge(request, 1)?;
        let id = self.predecessors.len();
        self.ids.insert(node, id);
        self.predecessors.push(Vec::new());
        Ok(id)
    }

    fn edge(
        &mut self,
        source: Node,
        target: Node,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), Failure> {
        charge(request, 1)?;
        let source = self.node(source, request)?;
        let target = self.node(target, request)?;
        self.predecessors[target].push(source);
        Ok(())
    }

    fn boundary(&mut self, node: Node, request: &mut SemanticRequest<'_>) -> Result<(), Failure> {
        charge(request, 1)?;
        let node = self.node(node, request)?;
        self.boundaries.insert(node);
        Ok(())
    }
}

pub(super) fn private_storage_in_slice(
    invocations: &Invocations,
    closed_calls: &HashSet<(InvocationId, CallSiteId)>,
    request: &mut SemanticRequest<'_>,
) -> Result<Option<PrivateStorage>, ConcurrencyOpenReason> {
    match build(invocations, closed_calls, request) {
        Ok(private) => Ok(Some(private)),
        Err(Failure::Incomplete) => Ok(None),
        Err(Failure::Budget) => Err(ConcurrencyOpenReason::BudgetExhausted),
    }
}

fn build(
    invocations: &Invocations,
    closed_calls: &HashSet<(InvocationId, CallSiteId)>,
    request: &mut SemanticRequest<'_>,
) -> Result<PrivateStorage, Failure> {
    let mut graph = Graph::default();
    let mut families = Vec::new();
    let mut cell_addresses = HashMap::default();
    let mut receivers = HashSet::default();
    let mut targets = HashMap::<_, Vec<InvocationId>>::default();
    let mut retained_call_targets =
        HashMap::<(InvocationId, CallSiteId), Vec<InvocationId>>::default();
    for entry in &invocations.entries {
        charge(request, 1)?;
        targets
            .entry(entry.context.procedure.clone())
            .or_default()
            .push(entry.context.invocation);
        if let Some(caller) = entry.caller {
            retained_call_targets
                .entry(caller)
                .or_default()
                .push(entry.context.invocation);
        }
    }
    for entry in &invocations.entries {
        let context = &entry.context;
        let id = context.invocation;
        let semantics = context.procedure.semantics();
        charge(
            request,
            semantics.values().len()
                + semantics.memory_locations().len()
                + semantics.allocations().len()
                + semantics.captures().len()
                + semantics.call_sites().len()
                + semantics.gaps().len()
                + semantics.control_edges().len()
                + semantics.points().len()
                + semantics
                    .points()
                    .iter()
                    .map(|point| point.events.len())
                    .sum::<usize>(),
        )?;
        if !reference_control_is_complete(&context.procedure) {
            return Err(Failure::Incomplete);
        }
        let closed_callable_uses = semantics
            .call_sites()
            .iter()
            .filter(|call| closed_calls.contains(&(id, call.id)))
            .map(|call| (call.point, call.callee))
            .collect::<HashSet<_>>();
        let mut retained_return_destinations = HashMap::default();
        if let Some((caller_id, call_id)) = entry.caller
            && closed_calls.contains(&(caller_id, call_id))
        {
            let caller = &invocations.entries[caller_id.0 as usize].context;
            let call = caller
                .procedure
                .semantics()
                .call_site(call_id)
                .expect("retained invocation caller owns its call site");
            charge(
                request,
                semantics
                    .points()
                    .iter()
                    .map(|point| point.events.len())
                    .sum(),
            )?;
            for point in semantics.points() {
                for event in &point.events {
                    let SemanticEffect::ValueFlow { target, kind, .. } = event.effect else {
                        continue;
                    };
                    if semantics.value(target).expect("owned flow target").kind
                        != SemanticValueKind::Return
                    {
                        continue;
                    }
                    let ordinal = match kind {
                        ValueFlowKind::Return => Some(0),
                        ValueFlowKind::IndexedReturn { ordinal } => Some(ordinal),
                        _ => None,
                    };
                    let Some(destination) = ordinal.and_then(|ordinal| {
                        call.normal_result(
                            usize::try_from(ordinal).expect("semantic result ordinal fits usize"),
                        )
                    }) else {
                        continue;
                    };
                    let destination = Node::Value(caller_id, destination);
                    if let Some(existing) = retained_return_destinations.insert(target, destination)
                    {
                        assert!(
                            existing == destination,
                            "one callee return value has one caller result destination"
                        );
                    }
                }
            }
        }
        for (returned, destination) in &retained_return_destinations {
            graph.edge(Node::Value(id, *returned), *destination, request)?;
        }
        for gap in semantics.gaps() {
            if !reference_evidence_is_complete(semantics, gap.evidence) {
                return Err(Failure::Incomplete);
            }
            if (matches!(
                gap.capability,
                SemanticCapability::NormalControlFlow | SemanticCapability::ConcurrentSpawn
            ) && gap.discharge == SemanticGapDischarge::RetainedControlTopology)
                || (matches!(
                    gap.capability,
                    SemanticCapability::ExceptionalControlFlow
                        | SemanticCapability::ExceptionalCallContinuation
                ) && gap.discharge == SemanticGapDischarge::NonRejoiningExceptionalExit)
            {
                continue;
            }
            let retained_memory = if let SemanticGapSubject::MemoryLocation(location) = gap.subject
            {
                let point = semantics.point(gap.point).expect("owned gap point");
                charge(request, point.events.len())?;
                point.events.iter().any(|event| {
                    matches!(event.effect,
                    SemanticEffect::MemoryLoad { location: accessed, .. }
                        | SemanticEffect::MemoryStore { location: accessed, .. }
                        if accessed == location)
                })
            } else {
                false
            };
            match (gap.capability, gap.subject) {
                (
                    SemanticCapability::Calls | SemanticCapability::DynamicDispatch,
                    SemanticGapSubject::CallSite(call),
                ) => {
                    // Publication follows the retained actual roots, without
                    // asserting a callee identity or a heap-effects summary.
                    semantics.call_site(call).expect("owned dispatch gap");
                    continue;
                }
                (SemanticCapability::CallableReferences, SemanticGapSubject::Value(value)) => {
                    if closed_callable_uses.contains(&(gap.point, value)) {
                        continue;
                    }
                    // Even an unresolved callable or return operand may escape.
                    // Mark that value as a boundary instead of certifying the
                    // missing target or transfer. Cell contents remain distinct
                    // from the address of the cell that stored the value.
                    graph.boundary(Node::Value(id, value), request)?;
                    continue;
                }
                (SemanticCapability::ReturnFlow, SemanticGapSubject::Value(value)) => {
                    let point = semantics.point(gap.point).expect("owned return gap point");
                    charge(request, point.events.len())?;
                    if !point.events.iter().any(|event| {
                        matches!(event.effect,
                        SemanticEffect::ValueFlow { target, .. } if target == value)
                    }) {
                        return Err(Failure::Incomplete);
                    }
                    graph.boundary(Node::Value(id, value), request)?;
                    continue;
                }
                (SemanticCapability::FieldMemory, SemanticGapSubject::MemoryLocation(location))
                    if retained_memory
                        && matches!(
                            semantics
                                .memory_location(location)
                                .expect("owned field gap")
                                .kind,
                            MemoryLocationKind::Field { .. }
                        ) =>
                {
                    // The source base and read/store are retained. Publication
                    // conservatively follows the whole base and publishes every
                    // stored value, so it needs no exact field declaration.
                    continue;
                }
                (
                    SemanticCapability::StaticMemory,
                    SemanticGapSubject::MemoryLocation(location),
                ) if retained_memory
                    && matches!(
                        semantics
                            .memory_location(location)
                            .expect("owned static gap")
                            .kind,
                        MemoryLocationKind::Static { .. }
                    ) =>
                {
                    continue;
                }
                _ => {}
            }
            if gap.impacts.contains(SemanticGapImpact::HeapWrite)
                || gap.impacts.contains(SemanticGapImpact::Aliasing)
                || gap.impacts.contains(SemanticGapImpact::ValueFlow)
                || gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                || gap.capability == SemanticCapability::Captures
            {
                return Err(Failure::Incomplete);
            }
        }

        for value in semantics.values() {
            if value.kind == SemanticValueKind::Return
                && !retained_return_destinations.contains_key(&value.id)
            {
                graph.boundary(Node::Value(id, value.id), request)?;
            }
        }
        let mut binding_locations = HashMap::default();
        for location in semantics.memory_locations() {
            if !reference_evidence_is_complete(semantics, location.evidence) {
                return Err(Failure::Incomplete);
            }
            let binding = match location.kind {
                MemoryLocationKind::LexicalCell { binding } => Some(binding),
                MemoryLocationKind::Capture { binding, .. } => binding,
                _ => None,
            };
            if let Some(binding) = binding {
                assert!(
                    binding_locations.insert(binding, location.id).is_none(),
                    "one binding owns one cell"
                );
                graph.edge(
                    Node::Value(id, binding),
                    Node::Contents(id, location.id),
                    request,
                )?;
                graph.edge(
                    Node::Contents(id, location.id),
                    Node::Value(id, binding),
                    request,
                )?;
                let node = graph.node(Node::CellAddress(id, location.id), request)?;
                let binding_node = graph.node(Node::Value(id, binding), request)?;
                cell_addresses.insert(binding_node, node);
                families.push((
                    ConcurrencyStorageFamily::LexicalCell {
                        invocation: id,
                        location: location.id,
                    },
                    node,
                ));
            }
            match location.kind {
                MemoryLocationKind::Field { base, .. } | MemoryLocationKind::Index { base, .. } => {
                    // Container dependence is a conservative publication edge,
                    // never a statement that container and loaded value alias.
                    graph.edge(
                        Node::Value(id, base),
                        Node::Contents(id, location.id),
                        request,
                    )?;
                }
                MemoryLocationKind::Static { .. } => {
                    graph.boundary(Node::Contents(id, location.id), request)?
                }
                _ => {}
            }
        }
        for allocation in semantics.allocations() {
            if !reference_evidence_is_complete(semantics, allocation.evidence) {
                return Err(Failure::Incomplete);
            }
            let node = graph.node(Node::Value(id, allocation.result), request)?;
            families.push((
                ConcurrencyStorageFamily::Allocation {
                    invocation: id,
                    allocation: allocation.id,
                },
                node,
            ));
        }
        for call in semantics.call_sites() {
            if call.execution_timing == crate::analyzer::semantic::ExecutionTiming::Unknown {
                return Err(Failure::Incomplete);
            }
            if !reference_evidence_is_complete(semantics, call.evidence) {
                return Err(Failure::Incomplete);
            }
            if !closed_calls.contains(&(id, call.id)) {
                graph.boundary(Node::Value(id, call.callee), request)?;
            }
            if let Some(receiver) = call.receiver {
                receivers.insert(graph.node(Node::Value(id, receiver), request)?);
            }
            let retained_targets = closed_calls
                .contains(&(id, call.id))
                .then(|| retained_call_targets.get(&(id, call.id)))
                .flatten();
            let Some(retained_targets) = retained_targets else {
                if let Some(receiver) = call.receiver {
                    graph.boundary(Node::Value(id, receiver), request)?;
                }
                for argument in &call.arguments {
                    graph.boundary(Node::Value(id, argument.value), request)?;
                }
                continue;
            };
            assert!(
                !retained_targets.is_empty(),
                "retained call target index contains only nonempty entries"
            );
            let mut receiver_complete = true;
            let mut arguments_complete = vec![true; call.arguments.len()];
            for target_id in retained_targets {
                charge(request, 1)?;
                let target = &invocations.entries[target_id.0 as usize].context;
                let mut target_receiver_complete = call.receiver.is_none();
                let mut target_arguments_complete = vec![false; call.arguments.len()];
                for formal in target.procedure.semantics().values() {
                    let actual = match formal.kind {
                        SemanticValueKind::Receiver { dispatch: true } => {
                            target_receiver_complete = call.receiver.is_some();
                            call.receiver
                        }
                        SemanticValueKind::Parameter { ordinal, .. } => {
                            let ordinal = usize::try_from(ordinal)
                                .expect("semantic parameter ordinal fits usize");
                            let actual = call.arguments.get(ordinal).map(|argument| argument.value);
                            if actual.is_some() {
                                assert!(
                                    !target_arguments_complete[ordinal],
                                    "one retained call target has one formal per parameter ordinal"
                                );
                                target_arguments_complete[ordinal] = true;
                            }
                            actual
                        }
                        _ => None,
                    };
                    if let Some(actual) = actual {
                        graph.edge(
                            Node::Value(id, actual),
                            Node::Value(*target_id, formal.id),
                            request,
                        )?;
                    }
                }
                receiver_complete &= target_receiver_complete;
                for (complete, target_complete) in
                    arguments_complete.iter_mut().zip(target_arguments_complete)
                {
                    *complete &= target_complete;
                }
            }
            if !receiver_complete && let Some(receiver) = call.receiver {
                graph.boundary(Node::Value(id, receiver), request)?;
            }
            for (argument, complete) in call.arguments.iter().zip(arguments_complete) {
                if !complete {
                    graph.boundary(Node::Value(id, argument.value), request)?;
                }
            }
        }
        for point in semantics.points() {
            for event in &point.events {
                if !reference_evidence_is_complete(semantics, event.evidence) {
                    return Err(Failure::Incomplete);
                }
                match &event.effect {
                    SemanticEffect::Assignment { target, value } => {
                        graph.edge(Node::Value(id, *value), Node::Value(id, *target), request)?;
                        if semantics
                            .value(*target)
                            .expect("owned assignment target")
                            .kind
                            == SemanticValueKind::Address
                            && !semantics
                                .allocations()
                                .iter()
                                .any(|allocation| allocation.result == *value)
                        {
                            let Some(location) = binding_locations.get(value) else {
                                // Projected storage addresses require a place
                                // relation; loaded contents cannot replace it.
                                // A reference-producing allocation is different:
                                // its result already names the allocated address,
                                // and the assignment records initializer dependence.
                                return Err(Failure::Incomplete);
                            };
                            graph.edge(
                                Node::CellAddress(id, *location),
                                Node::Value(id, *target),
                                request,
                            )?;
                        }
                    }
                    SemanticEffect::AggregateInitializer {
                        aggregate, value, ..
                    } => {
                        graph.edge(
                            Node::Value(id, *value),
                            Node::Value(id, *aggregate),
                            request,
                        )?;
                    }
                    SemanticEffect::ValueFlow {
                        source,
                        target,
                        kind,
                    } => {
                        if matches!(
                            kind,
                            ValueFlowKind::Transfer(ValueTransfer {
                                operation: TransferOperation::Unknown,
                                ..
                            })
                        ) || (*kind == ValueFlowKind::LanguageDefined
                            && !matches!(&semantics.value(*target).expect("owned flow target").kind,
                                SemanticValueKind::LanguageDefined(name) if matches!(name.as_ref(), "go.defer_capture" | "go.assignment_conversion"))
                            && semantics.value(*target).expect("owned flow target").kind
                                != SemanticValueKind::Return)
                        {
                            return Err(Failure::Incomplete);
                        }
                        // A frozen Go defer operand copies the value, so it
                        // retains publication dependence even without an alias
                        // certificate for the copied representation.
                        graph.edge(Node::Value(id, *source), Node::Value(id, *target), request)?;
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } => {
                        graph.edge(
                            Node::Contents(id, *location),
                            Node::Value(id, *result),
                            request,
                        )?;
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        graph.edge(
                            Node::Value(id, *value),
                            Node::Contents(id, *location),
                            request,
                        )?;
                        if !matches!(
                            semantics
                                .memory_location(*location)
                                .expect("owned store")
                                .kind,
                            MemoryLocationKind::LexicalCell { .. }
                                | MemoryLocationKind::Capture { .. }
                        ) {
                            graph.boundary(Node::Value(id, *value), request)?;
                        }
                    }
                    SemanticEffect::CallableCreation { result, callable }
                    | SemanticEffect::CallableReference { result, callable } => {
                        if let Some(environment) = callable.environment {
                            let allocation = semantics
                                .allocation(environment)
                                .expect("owned callable environment");
                            graph.edge(
                                Node::Value(id, allocation.result),
                                Node::Value(id, *result),
                                request,
                            )?;
                        }
                        if let Some(receiver) = callable.bound_receiver {
                            receivers.insert(graph.node(Node::Value(id, receiver), request)?);
                            graph.edge(
                                Node::Value(id, receiver),
                                Node::Value(id, *result),
                                request,
                            )?;
                        }
                    }
                    SemanticEffect::ProcedureReturn { value: Some(value) }
                        if retained_return_destinations.contains_key(value) => {}
                    SemanticEffect::ProcedureReturn { value: Some(value) }
                    | SemanticEffect::Throw { value: Some(value) } => {
                        graph.boundary(Node::Value(id, *value), request)?;
                    }
                    SemanticEffect::Synchronization {
                        operation: SynchronizationOperation::ChannelSend,
                        ..
                    }
                    | SemanticEffect::AsyncSuspend { .. }
                    | SemanticEffect::AsyncResume { .. }
                    | SemanticEffect::ValueUse { .. } => return Err(Failure::Incomplete),
                    // The inventory above owns call and gap coverage. Capture
                    // dependence is added below even for an uninvoked closure.
                    SemanticEffect::Entry
                    | SemanticEffect::NormalExit
                    | SemanticEffect::ExceptionalExit
                    | SemanticEffect::Allocation { .. }
                    | SemanticEffect::CaptureBind { .. }
                    | SemanticEffect::Invoke { .. }
                    | SemanticEffect::CallContinuation { .. }
                    | SemanticEffect::Gap { .. }
                    | SemanticEffect::Synchronization { .. }
                    | SemanticEffect::ProcedureReturn { value: None }
                    | SemanticEffect::Throw { value: None } => {}
                }
            }
        }
        for capture in semantics.captures() {
            if !reference_evidence_is_complete(semantics, capture.evidence) {
                return Err(Failure::Incomplete);
            }
            let callable = Node::Value(id, capture.callable);
            let (contents, address) = match (&capture.mode, capture.captured) {
                (
                    CaptureMode::Value | CaptureMode::Move | CaptureMode::Receiver,
                    CaptureSource::Value(value),
                ) => (Node::Value(id, value), None),
                (
                    CaptureMode::SharedCell | CaptureMode::MutableCell,
                    CaptureSource::Location(location),
                ) => {
                    if !matches!(
                        semantics
                            .memory_location(location)
                            .expect("owned capture")
                            .kind,
                        MemoryLocationKind::LexicalCell { .. } | MemoryLocationKind::Capture { .. }
                    ) {
                        return Err(Failure::Incomplete);
                    }
                    (
                        Node::Contents(id, location),
                        Some(Node::CellAddress(id, location)),
                    )
                }
                _ => return Err(Failure::Incomplete),
            };
            graph.edge(contents, callable, request)?;
            if let Some(address) = address {
                graph.edge(address, callable, request)?;
            }
            let target = context
                .procedure
                .artifact()
                .procedure_handle(capture.target)
                .expect("owned capture target");
            for target_id in targets.get(&target).into_iter().flatten() {
                charge(request, 1)?;
                let destination = target
                    .semantics()
                    .memory_location(capture.destination)
                    .expect("owned capture destination");
                if !matches!(destination.kind, MemoryLocationKind::Capture { .. }) {
                    return Err(Failure::Incomplete);
                }
                let target_contents = Node::Contents(*target_id, capture.destination);
                graph.edge(contents, target_contents, request)?;
                if let Some(address) = address {
                    let target_address = Node::CellAddress(*target_id, capture.destination);
                    graph.edge(address, target_address, request)?;
                    graph.edge(target_address, address, request)?;
                    graph.edge(target_contents, contents, request)?;
                }
            }
        }
    }
    // Receiver adaptation may take an inline value's address implicitly.
    // Follow all retained dependencies, including operand temporaries and
    // projected fields, and expose the originating cells conservatively.
    // Add these edges after traversal so this remains a dependence walk over
    // the original graph, never an identity equation or a name-based alias.
    let mut receiver_addresses = Vec::new();
    for receiver in receivers {
        let mut visited = HashSet::default();
        let mut pending = vec![receiver];
        visited.insert(receiver);
        while let Some(node) = pending.pop() {
            charge(request, 1 + graph.predecessors[node].len())?;
            if let Some(address) = cell_addresses.get(&node) {
                receiver_addresses.push((*address, receiver));
            }
            for predecessor in &graph.predecessors[node] {
                if visited.insert(*predecessor) {
                    pending.push(*predecessor);
                }
            }
        }
    }
    for (address, receiver) in receiver_addresses {
        charge(request, 1)?;
        graph.predecessors[receiver].push(address);
    }
    let mut published = HashSet::default();
    let mut queue = VecDeque::new();
    for boundary in graph.boundaries {
        charge(request, 1)?;
        published.insert(boundary);
        queue.push_back(boundary);
    }
    while let Some(node) = queue.pop_front() {
        charge(request, 1)?;
        for predecessor in &graph.predecessors[node] {
            charge(request, 1)?;
            if published.insert(*predecessor) {
                queue.push_back(*predecessor);
            }
        }
    }
    let mut private = HashSet::default();
    for (family, node) in families {
        charge(request, 1)?;
        if !published.contains(&node) {
            private.insert(family);
        }
    }
    Ok(PrivateStorage { families: private })
}

fn charge(request: &mut SemanticRequest<'_>, nested_entries: usize) -> Result<(), Failure> {
    if request.cancellation.is_cancelled()
        || request
            .budget
            .charge(SemanticWork {
                nested_entries,
                ..SemanticWork::default()
            })
            .is_err()
    {
        Err(Failure::Budget)
    } else {
        Ok(())
    }
}
