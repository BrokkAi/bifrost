//! Re-evaluate the first search's supports. Topology is immutable; the
//! evidence on an existing summary edge can change after a path is blocked.

use super::*;

pub(super) fn item_edges(derivation: &Derivation) -> usize {
    match derivation {
        Derivation::Root => 0,
        Derivation::Step { hops, .. } => hops.len() + 1,
        Derivation::Summary(step) => step.annotations.len() + 4,
    }
}

pub(super) fn reach_edges(derivation: &ReachDerivation) -> usize {
    match derivation {
        ReachDerivation::Direct { hops, .. } => hops.len() + 1,
        ReachDerivation::Through { hops, .. } => hops.len() + 2,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Node {
    Item(usize),
    Reach(usize),
}

impl<Provider: CompositionProvider> Search<'_, Provider> {
    /// Supports and their edges each share the existing hop ceiling. An
    /// unrecordable support stops the baseline honestly, before witness
    /// selection can depend on it. No second discovery budget is created.
    pub(super) fn reserve_support(&mut self, edges: usize) -> bool {
        if self.recorded_supports >= self.budget.max_hops
            || self.recorded_edges.saturating_add(edges) > self.budget.max_hops
        {
            self.exhaust(BudgetLane::Hops);
            self.stopped = true;
            return false;
        }
        self.recorded_supports += 1;
        self.recorded_edges += edges;
        true
    }

    fn accepted_reaches(&self) -> Vec<usize> {
        self.reaches
            .iter()
            .enumerate()
            .filter_map(|(id, reach)| {
                if !reach.active {
                    return None;
                }
                let Root::Sink(sink) = reach.key.root else {
                    return None;
                };
                let accepted = self
                    .plan
                    .sink(sink)
                    .expect("a reach names a plan sink")
                    .accepted();
                reach
                    .key
                    .function
                    .apply(&self.sources[reach.key.source.index()].classes)
                    .intersects(accepted)
                    .then_some(id)
            })
            .collect()
    }

    fn chop(&self, reaches: &[usize]) -> std::collections::HashSet<DurableProcedureKey> {
        let mut chop = std::collections::HashSet::default();
        let mut seen = HashSet::default();
        let mut stack = reaches.iter().copied().map(Node::Reach).collect::<Vec<_>>();
        while let Some(node) = stack.pop() {
            if !seen.insert(node) {
                continue;
            }
            match node {
                Node::Item(id) => {
                    chop.insert(self.items[id].key.procedure.clone());
                    for alternative in &self.items[id].alternatives {
                        match alternative {
                            Derivation::Root => {}
                            Derivation::Step { next, .. } => stack.push(Node::Item(*next)),
                            Derivation::Summary(step) => {
                                stack.push(Node::Item(step.inner));
                                stack.push(Node::Item(step.next));
                            }
                        }
                    }
                }
                Node::Reach(id) => {
                    chop.insert(
                        self.sources[self.reaches[id].key.source.index()]
                            .point
                            .procedure()
                            .durable_key(),
                    );
                    for alternative in &self.reaches[id].alternatives {
                        match alternative {
                            ReachDerivation::Direct { next, .. } => stack.push(Node::Item(*next)),
                            ReachDerivation::Through { inner, next, .. } => {
                                stack.push(Node::Reach(*inner));
                                stack.push(Node::Item(*next));
                            }
                        }
                    }
                }
            }
        }
        chop
    }

    pub(super) fn refine(&mut self, request: &mut SemanticRequest<'_>) -> Result<(), ComposeError> {
        let candidates = self.accepted_reaches();
        self.baseline_candidate_pairs = candidates
            .iter()
            .map(|&id| {
                let key = &self.reaches[id].key;
                (key.source, key.root.clone())
            })
            .collect::<HashSet<_>>()
            .len();
        if candidates.is_empty() {
            return Ok(());
        }
        if request.cancellation.is_cancelled() {
            self.note(Incompleteness::Cancelled);
            // Cancellation does not refute any first-search derivation. Name
            // its already materialized source observations without projecting
            // more relations or asking the native resolver for more work.
            for pair in self.current_pairs() {
                let source = &self.sources[pair.source.index()];
                let endpoint = match &source.carrier {
                    ValueFlowCarrier::Value(value) => {
                        crate::analyzer::semantic::ValueFlowEndpoint::Value(value.clone())
                    }
                    ValueFlowCarrier::Port(port) => {
                        crate::analyzer::semantic::ValueFlowEndpoint::Port(port.clone())
                    }
                    ValueFlowCarrier::Location(_) => continue,
                };
                let Some(value) =
                    crate::analyzer::semantic::partial_flow::observation_value(&endpoint)
                else {
                    continue;
                };
                let observation = crate::analyzer::semantic::BarrierObservation::new(
                    source.point.clone(),
                    value,
                    match source.phase {
                        ValueFlowObservationPhase::BeforeEffects => {
                            crate::analyzer::semantic::ObservationPhase::BeforeEffects
                        }
                        ValueFlowObservationPhase::AfterEffects => {
                            crate::analyzer::semantic::ObservationPhase::AfterEffects
                        }
                    },
                );
                let mut checks = self
                    .provider
                    .value_type_barrier_checks(&[observation], request)
                    .map_err(provider_error)?;
                for check in &mut checks {
                    check.decision = crate::analyzer::semantic::ValueTypeBarrierDecision::Undecided(
                        crate::analyzer::semantic::ValueTypeBarrierReason::Cancelled,
                    );
                }
                let omitted_lower_bound = u64::from(checks.len() > 64);
                checks.truncate(64);
                self.barrier_notes
                    .push(super::super::ValueTypeBarrierFindingNotes {
                        source: source.origin.clone(),
                        sink: self
                            .plan
                            .value_flow()
                            .sink(pair.sink)
                            .expect("a pair sink is live")
                            .key()
                            .clone(),
                        checks,
                        omitted_lower_bound,
                    });
            }
            return Ok(());
        }
        let baseline_pairs = candidates
            .iter()
            .map(|&id| self.reaches[id].key.clone())
            .collect::<HashSet<_>>();
        let chop = self.chop(&candidates);
        debug_assert!(
            chop.iter()
                .all(|procedure| self.visited.contains(procedure))
        );
        self.chop_procedures = chop.len();
        self.refinement_chop = chop.clone();
        self.provider.filter_value_type_barriers(&chop);
        self.replay_filtered(request)?;
        self.refine_undecided_witnesses(&candidates, &chop, request)?;
        if request.cancellation.is_cancelled() {
            self.note(Incompleteness::Cancelled);
        }
        debug_assert!(
            self.accepted_reaches()
                .iter()
                .all(|&id| baseline_pairs.contains(&self.reaches[id].key))
        );
        Ok(())
    }

    /// Both removing strategies use this same fixed-topology algorithm.
    fn replay_filtered(&mut self, request: &mut SemanticRequest<'_>) -> Result<(), ComposeError> {
        let _timing = brokk_bifrost_analysis::profiling::scope("taint.barriers.replay");
        let mut cache = HashMap::default();
        let mut items = Vec::with_capacity(self.items.len());
        for id in 0..self.items.len() {
            let mut retained = Vec::new();
            for alternative in self.items[id].alternatives.clone() {
                if let Some(alternative) = self.refine_item(alternative, &mut cache, request)? {
                    retained.push(alternative);
                }
            }
            items.push(retained);
        }
        let mut reaches = Vec::with_capacity(self.reaches.len());
        for id in 0..self.reaches.len() {
            let mut retained = Vec::new();
            for alternative in self.reaches[id].alternatives.clone() {
                if let Some(alternative) = self.refine_reach(alternative, &mut cache, request)? {
                    retained.push(alternative);
                }
            }
            reaches.push(retained);
        }
        self.replay(&items, &reaches);
        Ok(())
    }

    fn refine_undecided_witnesses(
        &mut self,
        candidates: &[usize],
        global_chop: &std::collections::HashSet<DurableProcedureKey>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(), ComposeError> {
        let lenient = self.current_pairs();
        let mut selected = Vec::new();
        for pair in lenient {
            if !pair.paths.iter().any(|(hops, _)| {
                super::super::labels::hops_function(hops, self.plan.universe())
                    .apply(&self.sources[pair.source.index()].classes)
                    .intersects(
                        self.plan
                            .sink(pair.sink)
                            .expect("a pair sink is live")
                            .accepted(),
                    )
            }) {
                continue;
            }
            self.provider.filter_value_type_barriers(global_chop);
            let mut notes = Vec::new();
            let mut omitted = 0;
            for (hops, _) in &pair.paths {
                for check in self.witness_checks(hops, request)? {
                    if !matches!(
                        check.decision,
                        crate::analyzer::semantic::ValueTypeBarrierDecision::Undecided(_)
                    ) || notes.contains(&check)
                    {
                        continue;
                    }
                    if notes.len() < 64 {
                        notes.push(check);
                    } else {
                        omitted = 1;
                    }
                }
            }
            if notes.is_empty() && omitted == 0 {
                self.strict_pairs.push(pair.clone());
                selected.push(pair);
                continue;
            }
            let roots = candidates
                .iter()
                .copied()
                .filter(|&id| {
                    self.reaches[id].key.source == pair.source
                        && self.reaches[id].key.root == Root::Sink(pair.sink)
                })
                .collect::<Vec<_>>();
            let chop = self.chop(&roots);
            self.refinement_chop = chop.clone();
            self.strict_replays += 1;
            self.provider.strict_value_type_barriers(&chop);
            self.replay_filtered(request)?;
            let strict = self.current_pairs().into_iter().find(|candidate| {
                candidate.source == pair.source
                    && candidate.sink == pair.sink
                    && candidate.paths.iter().any(|(hops, _)| {
                        super::super::labels::hops_function(hops, self.plan.universe())
                            .apply(&self.sources[pair.source.index()].classes)
                            .intersects(
                                self.plan
                                    .sink(pair.sink)
                                    .expect("a pair sink is live")
                                    .accepted(),
                            )
                    })
            });
            if let Some(strict) = strict {
                self.strict_pairs.push(strict);
            }
            self.barrier_notes
                .push(super::super::ValueTypeBarrierFindingNotes {
                    source: self.sources[pair.source.index()].origin.clone(),
                    sink: self
                        .plan
                        .value_flow()
                        .sink(pair.sink)
                        .expect("a pair sink is live")
                        .key()
                        .clone(),
                    checks: notes,
                    omitted_lower_bound: omitted,
                });
            selected.push(pair);
        }
        self.provider.filter_value_type_barriers(global_chop);
        self.refinement_chop = global_chop.clone();
        self.refined_pairs = Some(selected);
        Ok(())
    }

    fn witness_checks(
        &self,
        hops: &[Hop],
        request: &mut SemanticRequest<'_>,
    ) -> Result<Vec<super::super::ValueTypeBarrierCheck>, ComposeError> {
        use crate::analyzer::semantic::{BarrierObservation, ObservationPhase};
        let mut checks = Vec::new();
        for hop in hops {
            let (procedure, from, to, stored) = match hop {
                Hop::Stored {
                    procedure,
                    from,
                    to,
                    ..
                } => (
                    procedure,
                    Endpoint::Port(from.clone()),
                    Endpoint::Port(to.clone()),
                    true,
                ),
                Hop::Interior {
                    procedure,
                    from,
                    to,
                    ..
                } => (procedure, from.clone(), to.clone(), false),
                _ => {
                    for (procedure, port) in boundary_ports(hop) {
                        checks.extend(
                            self.provider
                                .value_type_barrier_port_checks(procedure, port, request)
                                .map_err(provider_error)?,
                        );
                    }
                    continue;
                }
            };
            let seed = super::super::report::interior_seed(&self.sources, &from)
                .expect("a recorded seed is a source or port");
            let (observations, target) = match &to {
                Endpoint::Sink(sink) => (
                    vec![super::super::report::interior_observation(self.plan, *sink)],
                    InteriorTarget::Observation(0),
                ),
                Endpoint::Location(location) => (
                    vec![InteriorObservation::Location(location.clone())],
                    InteriorTarget::Observation(0),
                ),
                Endpoint::Port(port) => (Vec::new(), InteriorTarget::Port(port.clone())),
                Endpoint::Source(_) => unreachable!("a recorded output is not a source"),
            };
            let flows = if stored {
                self.provider.stored_interior_flows(
                    procedure,
                    &[seed],
                    &observations,
                    true,
                    request,
                )
            } else {
                self.provider
                    .interior_flows(procedure, &[seed], &observations, true, request)
            }
            .map_err(provider_error)?;
            let mut values = Vec::new();
            if let Some(steps) = flows
                .flows
                .iter()
                .find(|flow| flow.seed == 0 && flow.target == target)
                .and_then(|flow| flow.witness.as_deref())
            {
                for step in steps {
                    let point = flows
                        .procedure
                        .point_handle(step.point)
                        .expect("a witness point is live");
                    if let Some(value) = step.source {
                        values.push(BarrierObservation::new(
                            point.clone(),
                            value,
                            ObservationPhase::BeforeEffects,
                        ));
                    }
                    if let Some(value) = step.target {
                        values.push(BarrierObservation::new(point, value, step.phase));
                    }
                }
            }
            checks.extend(
                self.provider
                    .value_type_barrier_checks(&values, request)
                    .map_err(provider_error)?,
            );
        }
        Ok(checks)
    }

    fn refine_item(
        &mut self,
        alternative: Derivation,
        cache: &mut HashMap<Hop, Option<Hop>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Derivation>, ComposeError> {
        Ok(match alternative {
            Derivation::Root => Some(Derivation::Root),
            Derivation::Step { hops, next } => self
                .refine_hops(hops, cache, request)?
                .map(|hops| Derivation::Step { hops, next }),
            Derivation::Summary(step) => {
                let mut step = *step;
                let Some(caller) = self.refine_hop(step.caller, cache, request)? else {
                    return Ok(None);
                };
                let Some(callee) = self.refine_hop(step.callee, cache, request)? else {
                    return Ok(None);
                };
                let Some(annotations) = self.refine_hops(step.annotations, cache, request)? else {
                    return Ok(None);
                };
                step.caller = caller;
                step.callee = callee;
                step.annotations = annotations;
                Some(Derivation::Summary(Box::new(step)))
            }
        })
    }

    fn refine_reach(
        &mut self,
        alternative: ReachDerivation,
        cache: &mut HashMap<Hop, Option<Hop>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<ReachDerivation>, ComposeError> {
        Ok(match alternative {
            ReachDerivation::Direct { hops, next } => self
                .refine_hops(hops, cache, request)?
                .map(|hops| ReachDerivation::Direct { hops, next }),
            ReachDerivation::Through { inner, hops, next } => self
                .refine_hops(hops, cache, request)?
                .map(|hops| ReachDerivation::Through { inner, hops, next }),
        })
    }

    fn refine_hops(
        &mut self,
        hops: Vec<Hop>,
        cache: &mut HashMap<Hop, Option<Hop>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Vec<Hop>>, ComposeError> {
        let mut retained = Vec::with_capacity(hops.len());
        for hop in hops {
            let Some(hop) = self.refine_hop(hop, cache, request)? else {
                return Ok(None);
            };
            retained.push(hop);
        }
        Ok(Some(retained))
    }

    fn refined_quality(
        &mut self,
        procedure: &DurableProcedureKey,
        uncertain: bool,
        crossed: &[Box<[CallSiteId]>],
        request: &mut SemanticRequest<'_>,
    ) -> Result<(HopQuality, Box<[CallSiteId]>), ComposeError> {
        let extra = crossed
            .iter()
            .flat_map(|class| class.iter())
            .copied()
            .filter(|call| !self.dispatches.contains_key(&(procedure.clone(), *call)))
            .collect::<HashSet<_>>();
        self.extra_proof_lookups += extra.len();
        // This only reads continuation evidence. It never calls descend,
        // process_item or add_item, hence cannot expand the frozen topology.
        self.flow_quality(procedure, uncertain, crossed, request)
    }

    fn refine_hop(
        &mut self,
        hop: Hop,
        cache: &mut HashMap<Hop, Option<Hop>>,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Hop>, ComposeError> {
        if let Some(retained) = cache.get(&hop) {
            return Ok(retained.clone());
        }
        for (procedure, port) in boundary_ports(&hop) {
            if !self.refinement_chop.contains(procedure) {
                continue;
            }
            let checks = self
                .provider
                .value_type_barrier_port_checks(procedure, port, request)
                .map_err(provider_error)?;
            if checks
                .iter()
                .any(|check| !self.provider.permits_value_type_barrier(check.decision))
            {
                cache.insert(hop, None);
                return Ok(None);
            }
        }
        if let Hop::Stored { procedure, .. } | Hop::Interior { procedure, .. } = &hop
            && !self.refinement_chop.contains(procedure)
        {
            return Ok(Some(hop));
        }
        let retained = match &hop {
            Hop::Stored {
                procedure,
                from,
                to,
                ..
            } => {
                let partial = self
                    .provider
                    .partial_flows(procedure, request)
                    .map_err(provider_error)?;
                let flow = partial.flows.iter().find(|flow| {
                    &partial.ports[flow.from.index()] == from
                        && &partial.ports[flow.to.index()] == to
                });
                match flow {
                    None => None,
                    Some(flow) => {
                        let (quality, crossed) = self.refined_quality(
                            procedure,
                            flow.uncertain,
                            &flow.crossed,
                            request,
                        )?;
                        Some(Hop::Stored {
                            procedure: procedure.clone(),
                            from: from.clone(),
                            to: to.clone(),
                            quality,
                            crossed,
                        })
                    }
                }
            }
            Hop::Interior {
                procedure,
                from,
                to,
                ..
            } => {
                let seed = match from {
                    Endpoint::Source(id) => {
                        let source = &self.sources[id.index()];
                        InteriorSeed::Source {
                            point: source.point.id(),
                            phase: source.phase,
                            carrier: source.carrier.clone(),
                        }
                    }
                    Endpoint::Port(port) => InteriorSeed::Port(port.clone()),
                    _ => unreachable!("an interior seed is a source or input port"),
                };
                let observations = match to {
                    Endpoint::Sink(id) => {
                        let sink = self
                            .plan
                            .value_flow()
                            .sink(*id)
                            .expect("a recorded sink is in its plan");
                        vec![InteriorObservation::Sink {
                            point: sink.point().id(),
                            phase: sink.phase(),
                            carrier: sink.carrier().clone(),
                        }]
                    }
                    Endpoint::Location(location) => {
                        vec![InteriorObservation::Location(location.clone())]
                    }
                    Endpoint::Port(_) => Vec::new(),
                    Endpoint::Source(_) => unreachable!("an interior output is not a source"),
                };
                let flows = self
                    .provider
                    .interior_flows(procedure, &[seed], &observations, false, request)
                    .map_err(provider_error)?;
                let incomplete = !matches!(flows.completeness, Completeness::Complete);
                if let Completeness::Incomplete { reason } = flows.completeness {
                    self.note(Incompleteness::Interior {
                        procedure: procedure.clone(),
                        reason,
                    });
                }
                let flow = flows.flows.iter().find(|flow| match (&flow.target, to) {
                    (InteriorTarget::Port(port), Endpoint::Port(target)) => port == target,
                    (InteriorTarget::Observation(0), Endpoint::Sink(_) | Endpoint::Location(_)) => {
                        true
                    }
                    _ => false,
                });
                match flow {
                    // An unavailable projection cannot prove a barrier killed
                    // the original path. Keep its positive evidence partial.
                    None if incomplete => {
                        let Hop::Interior {
                            procedure,
                            from,
                            to,
                            crossed,
                            ..
                        } = &hop
                        else {
                            unreachable!("this branch refines an interior edge")
                        };
                        Some(Hop::Interior {
                            procedure: procedure.clone(),
                            from: from.clone(),
                            to: to.clone(),
                            quality: HopQuality::UNCERTAIN,
                            crossed: crossed.clone(),
                        })
                    }
                    None => None,
                    Some(flow) => {
                        let (quality, crossed) = self.refined_quality(
                            procedure,
                            flow.uncertain,
                            &flow.crossed,
                            request,
                        )?;
                        Some(Hop::Interior {
                            procedure: procedure.clone(),
                            from: from.clone(),
                            to: to.clone(),
                            quality,
                            crossed,
                        })
                    }
                }
            }
            _ => Some(hop.clone()),
        };
        if retained
            .as_ref()
            .is_some_and(|retained| retained.quality() != hop.quality())
            && self.changed_edges.insert(hop.clone())
        {
            self.changed_edge_qualities += 1;
        }
        cache.insert(hop, retained.clone());
        Ok(retained)
    }

    /// Least fixpoint of the retained supports, with the original context and
    /// label-function keys. Only grounded supports become witnesses; cycles
    /// alone cannot manufacture a path. No provider lookup happens here.
    fn replay(&mut self, items: &[Vec<Derivation>], reaches: &[Vec<ReachDerivation>]) {
        let mut dependents: HashMap<Node, Vec<(Node, usize)>> = HashMap::default();
        let mut queue = std::collections::VecDeque::new();
        let mut queued = HashSet::default();
        for (id, alternatives) in items.iter().enumerate() {
            for (index, alternative) in alternatives.iter().enumerate() {
                let owner = (Node::Item(id), index);
                let dependencies = match alternative {
                    Derivation::Root => Vec::new(),
                    Derivation::Step { next, .. } => vec![Node::Item(*next)],
                    Derivation::Summary(step) => {
                        vec![Node::Item(step.inner), Node::Item(step.next)]
                    }
                };
                for dependency in dependencies {
                    dependents.entry(dependency).or_default().push(owner);
                }
                queue.push_back(owner);
                queued.insert(owner);
            }
        }
        for (id, alternatives) in reaches.iter().enumerate() {
            for (index, alternative) in alternatives.iter().enumerate() {
                let owner = (Node::Reach(id), index);
                let dependencies = match alternative {
                    ReachDerivation::Direct { next, .. } => vec![Node::Item(*next)],
                    ReachDerivation::Through { inner, next, .. } => {
                        vec![Node::Reach(*inner), Node::Item(*next)]
                    }
                };
                for dependency in dependencies {
                    dependents.entry(dependency).or_default().push(owner);
                }
                queue.push_back(owner);
                queued.insert(owner);
            }
        }
        for item in &mut self.items {
            item.active = false;
            item.quality = HopQuality::UNCERTAIN;
        }
        for reach in &mut self.reaches {
            reach.active = false;
            reach.quality = HopQuality::UNCERTAIN;
        }
        while let Some((node, index)) = queue.pop_front() {
            queued.remove(&(node, index));
            let changed = match node {
                Node::Item(id) => {
                    let alternative = &items[id][index];
                    let quality = match alternative {
                        Derivation::Root => Some(self.items[id].root_quality),
                        Derivation::Step { hops, next } => self.items[*next]
                            .active
                            .then(|| Hop::path_quality(hops).conjoin(self.items[*next].quality)),
                        Derivation::Summary(step) => (self.items[step.inner].active
                            && self.items[step.next].active)
                            .then(|| {
                                step.caller
                                    .quality()
                                    .conjoin(step.callee.quality())
                                    .conjoin(Hop::path_quality(&step.annotations))
                                    .conjoin(self.items[step.inner].quality)
                                    .conjoin(self.items[step.next].quality)
                            }),
                    };
                    let Some(quality) = quality else {
                        continue;
                    };
                    let item = &mut self.items[id];
                    if !item.active {
                        item.active = true;
                        item.quality = quality;
                        item.derivations = Derivations::new(quality, alternative.clone());
                        true
                    } else if item
                        .derivations
                        .improve(item.quality, quality, alternative.clone())
                    {
                        item.quality = item.quality.join(quality);
                        true
                    } else {
                        false
                    }
                }
                Node::Reach(id) => {
                    let alternative = &reaches[id][index];
                    let quality = match alternative {
                        ReachDerivation::Direct { hops, next } => {
                            self.items[*next].active.then(|| {
                                Hop::path_quality(hops)
                                    .conjoin(self.items[*next].quality)
                                    .conjoin(
                                        match self.sources[self.reaches[id].key.source.index()]
                                            .evidence
                                        {
                                            EndpointEvidence::Known(quality) => quality,
                                            EndpointEvidence::Unknown => HopQuality::CERTAIN,
                                        },
                                    )
                            })
                        }
                        ReachDerivation::Through { inner, hops, next } => {
                            (self.reaches[*inner].active && self.items[*next].active).then(|| {
                                Hop::path_quality(hops)
                                    .conjoin(self.reaches[*inner].quality)
                                    .conjoin(self.items[*next].quality)
                            })
                        }
                    };
                    let Some(quality) = quality else {
                        continue;
                    };
                    let reach = &mut self.reaches[id];
                    if !reach.active {
                        reach.active = true;
                        reach.quality = quality;
                        reach.derivations = Derivations::new(quality, alternative.clone());
                        true
                    } else if reach
                        .derivations
                        .improve(reach.quality, quality, alternative.clone())
                    {
                        reach.quality = reach.quality.join(quality);
                        true
                    } else {
                        false
                    }
                }
            };
            if changed {
                for &dependent in dependents.get(&node).into_iter().flatten() {
                    if queued.insert(dependent) {
                        queue.push_back(dependent);
                    }
                }
            }
        }
    }
}

fn boundary_ports(hop: &Hop) -> Vec<(&DurableProcedureKey, &PartialFlowPort)> {
    match hop {
        Hop::Caller {
            call,
            callee,
            actual,
            formal,
            ..
        } => vec![(&call.0, actual), (callee, formal)],
        Hop::Callee {
            call,
            callee,
            from,
            to,
            ..
        } => {
            let mut ports = vec![(callee, from)];
            if let Endpoint::Port(to) = to {
                ports.push((&call.0, to));
            }
            ports
        }
        Hop::Model {
            call,
            actual,
            result,
            ..
        } => vec![(&call.0, actual), (&call.0, result)],
        Hop::Unmodeled {
            call,
            input,
            output,
        } => vec![(&call.0, input), (&call.0, output)],
        Hop::Closure {
            parent,
            closure,
            binding,
            slot,
            ..
        } => vec![(parent, binding), (closure, slot)],
        _ => Vec::new(),
    }
}
