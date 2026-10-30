//! Stage 3 of the composition: turn labeled paths into the
//! [`TaintFindingReport`] the policy layer already projects. Witnesses are
//! rebuilt per procedure by the provider's witness-recording interior runs.

use std::sync::Arc;

use crate::analyzer::semantic::icfg::invoked_call_at;
use crate::analyzer::semantic::{
    ControlEdgeKind, EvidenceCompleteness, IcfgEdgeKind, ProcedureHandle, ProofStatus,
    SemanticRequest,
};
use crate::dataflow::{
    FactId, PathQuality, PathQualityFrontier, SolverBudgetDimension, SolverBudgetExceeded,
    SolverTermination, SummaryWitness, SummaryWitnessStep, SummaryWitnessStepKind,
    WitnessReconstructionWork,
};
use crate::hash::HashMap;
use crate::taint::{
    TaintAnalysisPlan, TaintFact, TaintFinding, TaintFindingReport, TaintOriginFindingEvidence,
    TaintOriginStatus, TaintSummaryResult,
};
use crate::value_flow::{
    AuthoredArmClosure, DurableCallSiteKey, DurableProcedureKey, ValueFlowSinkId,
};

use super::graph::{ComposedSourceId, Endpoint, Hop, HopQuality};
use super::labels::LabeledPath;
use super::provider::{
    BoundSource, CompositionProvider, InteriorObservation, InteriorSeed, InteriorTarget,
};
use super::search::{BudgetLane, Incompleteness, SearchOutcome, provider_error};
use super::{ComposeError, CompositionBudget};

/// The fact every composed witness step names: a composition tracks no
/// per-carrier facts.
const ZERO_FACT: usize = 0;

pub(super) fn build_report<Provider: CompositionProvider>(
    plan: &TaintAnalysisPlan,
    provider: &Provider,
    budget: CompositionBudget,
    outcome: &SearchOutcome,
    labeled: Vec<LabeledPath>,
    request: &mut SemanticRequest<'_>,
) -> Result<(TaintFindingReport, Vec<Incompleteness>), ComposeError> {
    let termination = termination(budget, &outcome.incomplete);
    let complete = outcome.incomplete.is_empty() && outcome.sanitizers_resolved;
    // A composition that rests on an authored external summary is not
    // derived-complete. When it is otherwise complete it is proven only by
    // authored summaries, with the closures that decided it (#1916, #2342),
    // as the ICFG engine's run is.
    let authored_models = provider.authored_models();
    let derived_complete = complete && authored_models.is_empty();
    let authored = (complete && !authored_models.is_empty()).then(|| {
        let mut closures = Vec::new();
        for closure in authored_models.into_iter().flatten() {
            if !closures.contains(&closure) {
                closures.push(closure);
            }
        }
        closures
    });
    let mut witnesses = WitnessBuilder {
        plan,
        sources: &outcome.sources,
        provider,
        handles: HashMap::default(),
    };
    let mut by_sink: Vec<(ValueFlowSinkId, Vec<LabeledPath>)> = Vec::new();
    for path in labeled {
        match by_sink.iter_mut().find(|(sink, _)| *sink == path.sink) {
            Some((_, paths)) => paths.push(path),
            None => by_sink.push((path.sink, vec![path])),
        }
    }
    by_sink.sort_by_key(|(sink, _)| *sink);
    let mut findings = Vec::new();
    let mut finding_incompleteness = Vec::new();
    for (sink, paths) in by_sink {
        let mut classes = plan.universe().empty_set();
        let mut qualities = PathQualityFrontier::default();
        let mut by_source: Vec<(ComposedSourceId, Vec<&LabeledPath>)> = Vec::new();
        for path in &paths {
            classes = classes.union(&path.reached);
            if path.quality.proven && path.quality.complete && !path.quality.is_certain() {
                qualities.insert(PathQuality::PROVEN_PARTIAL);
                qualities.insert(PathQuality::UNPROVEN_COMPLETE);
            } else {
                qualities.insert(path_quality(path.quality));
            }
            match by_source
                .iter_mut()
                .find(|(source, _)| *source == path.source)
            {
                Some((_, grouped)) => grouped.push(path),
                None => by_source.push((path.source, vec![path])),
            }
        }
        let mut witness_unavailable = false;
        let mut evidence = Vec::new();
        for (source, grouped) in by_source {
            let binding = &outcome.sources[source.index()];
            let mut contributed = plan.universe().empty_set();
            let mut reached = plan.universe().empty_set();
            let mut retained = Vec::new();
            let mut closures = Vec::new();
            for path in &grouped {
                contributed = contributed.union(&path.contributed);
                reached = reached.union(&path.reached);
                match witnesses.witness(path, request)? {
                    Some(witness) => retained.push(Arc::new(witness)),
                    None => witness_unavailable = true,
                }
                for closure in path_closures(plan, provider, path)? {
                    if !closures.contains(&closure) {
                        closures.push(closure);
                    }
                }
            }
            // The search's table holds the plan's sources first; a source
            // after them was matched on the frontier, and the plan cannot
            // answer its specification.
            let frontier_source = (source.index() >= plan.sources().len())
                .then(|| (binding.phase, binding.carrier.clone()));
            evidence.push(TaintOriginFindingEvidence::composed(
                binding.origin.clone(),
                contributed,
                reached,
                retained,
                grouped.iter().any(|path| path.quality.is_certain()),
                closures,
                frontier_source,
            ));
        }
        evidence.sort_by(|left, right| left.origin().cmp(right.origin()));
        let proven = qualities.has_proven_path() && termination.is_fixed_point();
        // A finding is complete when the run is derived-complete and one of
        // its paths is complete, or when every origin has a certain path:
        // one proven and complete at every hop, where a complete, exactly
        // bound authored model closes its call (#5218). This is the
        // ICFG engine's rule in `collect_taint_findings_with_limits`; an
        // incomplete run keeps a finding complete only through a certain
        // path. The ICFG engine checks certainty on retained witnesses, so it
        // also needs them; the composition checks it on the paths themselves.
        let certain = termination.is_fixed_point()
            && !evidence.is_empty()
            && evidence
                .iter()
                .all(TaintOriginFindingEvidence::has_certain_path);
        let finding_complete = (derived_complete && qualities.has_complete_path()) || certain;
        if !finding_complete {
            for path in &paths {
                for call in path_calls(plan, path)? {
                    if let Some(model) = provider.model(&call)
                        && (model.authored.is_some() || !model.quality().complete)
                    {
                        let cause = Incompleteness::Dispatch {
                            call,
                            reason: "reported path crosses an authored or partial external model"
                                .into(),
                        };
                        if !finding_incompleteness.contains(&cause) {
                            finding_incompleteness.push(cause);
                        }
                    }
                }
            }
        }
        findings.push(
            TaintFinding::composed(
                plan,
                sink,
                classes,
                qualities,
                proven,
                finding_complete,
                TaintOriginStatus::composed(evidence, witness_unavailable),
            )
            .map_err(ComposeError::Report)?,
        );
    }
    let result = TaintSummaryResult::composed(
        plan,
        vec![TaintFact::zero()],
        termination,
        derived_complete,
        authored,
    );
    Ok((
        TaintFindingReport::composed(result, findings),
        finding_incompleteness,
    ))
}

/// Calls crossed by the path, including its sink's dispatch obligation.
fn path_calls(
    plan: &TaintAnalysisPlan,
    path: &LabeledPath,
) -> Result<Vec<DurableCallSiteKey>, ComposeError> {
    let sink = plan
        .value_flow()
        .sink(path.sink)
        .expect("a path names a sink of its plan");
    let sink_call = invoked_call_at(sink.point())
        .map_err(provider_error)?
        .map(|call| (sink.point().procedure().durable_key(), call));
    Ok(path
        .hops
        .iter()
        .flat_map(|hop| match hop {
            Hop::Model { call, .. } => vec![call.clone()],
            Hop::Interior {
                procedure, crossed, ..
            }
            | Hop::Stored {
                procedure, crossed, ..
            } => crossed
                .iter()
                .map(|&call| (procedure.clone(), call))
                .collect(),
            _ => Vec::new(),
        })
        .chain(sink_call)
        .collect())
}

/// The authored closures one path depends on: those of every model it
/// takes, of every call its stored and interior flows cross, and of the
/// sink's own call, as the ICFG engine's `witness_arm_closures` reads them
/// from a witness's call steps.
fn path_closures<Provider: CompositionProvider>(
    plan: &TaintAnalysisPlan,
    provider: &Provider,
    path: &LabeledPath,
) -> Result<Vec<AuthoredArmClosure>, ComposeError> {
    let calls = path_calls(plan, path)?;
    let mut closures = Vec::new();
    for call in calls {
        let authored = provider.model(&call).and_then(|model| model.authored);
        for closure in authored.into_iter().flatten() {
            if !closures.contains(&closure) {
                closures.push(closure);
            }
        }
    }
    Ok(closures)
}

/// The solver termination a composition reports: cancelled, a budget lane
/// exhausted, or a fixed point.
fn termination(budget: CompositionBudget, incomplete: &[Incompleteness]) -> SolverTermination {
    if incomplete.contains(&Incompleteness::Cancelled) {
        return SolverTermination::Cancelled;
    }
    let exhausted = incomplete.iter().find_map(|reason| match reason {
        Incompleteness::Budget(lane) => Some(*lane),
        _ => None,
    });
    match exhausted {
        Some(BudgetLane::Procedures) => {
            SolverTermination::ExceededBudget(SolverBudgetExceeded::new(
                SolverBudgetDimension::ProviderMaterializations,
                budget.max_procedures,
                budget.max_procedures.saturating_add(1),
            ))
        }
        Some(BudgetLane::Hops) => SolverTermination::ExceededBudget(SolverBudgetExceeded::new(
            SolverBudgetDimension::PropagatedOutputs,
            budget.max_hops,
            budget.max_hops.saturating_add(1),
        )),
        Some(BudgetLane::CallersPerProcedure) => {
            SolverTermination::ExceededBudget(SolverBudgetExceeded::new(
                SolverBudgetDimension::IncomingCalls,
                budget.max_callers_per_procedure,
                budget.max_callers_per_procedure.saturating_add(1),
            ))
        }
        None => SolverTermination::FixedPoint,
    }
}

struct WitnessBuilder<'a, Provider> {
    plan: &'a TaintAnalysisPlan,
    /// The search's source table.
    sources: &'a [BoundSource],
    provider: &'a Provider,
    /// Live handles of procedures a witness run has served.
    handles: HashMap<DurableProcedureKey, ProcedureHandle>,
}

impl<Provider: CompositionProvider> WitnessBuilder<'_, Provider> {
    /// The witness of one path: the recorded steps of every interior and
    /// stored hop, and a call or return step at every caller and callee hop.
    /// `None` when a hop's steps cannot be recorded.
    fn witness(
        &mut self,
        path: &LabeledPath,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<SummaryWitness>, ComposeError> {
        self.provider
            .prepare_value_type_witness(&self.sources[path.source.index()], path.sink);
        // Record the interior runs first: they also give the live handles
        // that the call and return steps of the second pass name.
        let mut recorded = Vec::with_capacity(path.hops.len());
        for hop in &path.hops {
            let steps = match hop {
                Hop::Interior {
                    procedure,
                    from,
                    to,
                    ..
                } => self.interior_steps(procedure, from, to, request)?,
                Hop::Stored {
                    procedure,
                    from,
                    to,
                    ..
                } => self.stored_steps(procedure, from, to, request)?,
                _ => Some(Vec::new()),
            };
            let Some(steps) = steps else {
                return Ok(None);
            };
            recorded.push(steps);
        }
        let mut steps = Vec::new();
        for (hop, recorded) in path.hops.iter().zip(recorded) {
            steps.extend(recorded);
            let (Hop::Caller { call, .. } | Hop::Callee { call, .. }) = hop else {
                continue;
            };
            let Some(handle) = self.handles.get(&call.0) else {
                return Ok(None);
            };
            let (Some(site), Some(call_handle)) = (
                handle.semantics().call_site(call.1),
                handle.call_site_handle(call.1),
            ) else {
                return Ok(None);
            };
            let Some(point) = handle.point_handle(site.point) else {
                return Ok(None);
            };
            let kind = if matches!(hop, Hop::Caller { .. }) {
                IcfgEdgeKind::Call
            } else if matches!(
                hop,
                Hop::Callee {
                    from:
                        crate::analyzer::semantic::partial_flow::PartialFlowPort::ExceptionalReturn,
                    ..
                }
            ) {
                IcfgEdgeKind::ExceptionalReturn
            } else {
                IcfgEdgeKind::NormalReturn
            };
            steps.push(step(
                SummaryWitnessStepKind::Edge(kind),
                point,
                Some(call_handle),
                hop.quality(),
            ));
        }
        // Reconstruction follows the proven derivation when there is one.
        // Completeness supplied only by another alternative does not make
        // that retained path certain.
        let quality = if path.quality.proven && !path.quality.is_certain() {
            PathQuality::PROVEN_PARTIAL
        } else {
            path_quality(path.quality)
        };
        let retained_bytes = std::mem::size_of::<SummaryWitness>()
            .saturating_add(std::mem::size_of_val(steps.as_slice()));
        let emitted = steps.len();
        Ok(Some(SummaryWitness::from_parts(
            steps,
            quality,
            None,
            0,
            false,
            retained_bytes,
            WitnessReconstructionWork::new(0, emitted),
        )))
    }

    fn stored_steps(
        &mut self,
        procedure: &DurableProcedureKey,
        from: &crate::analyzer::semantic::partial_flow::PartialFlowPort,
        to: &crate::analyzer::semantic::partial_flow::PartialFlowPort,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Vec<SummaryWitnessStep>>, ComposeError> {
        let flows = self
            .provider
            .stored_interior_flows(
                procedure,
                &[InteriorSeed::Port(from.clone())],
                &[],
                true,
                request,
            )
            .map_err(provider_error)?;
        self.recorded_steps(procedure, flows, &InteriorTarget::Port(to.clone()))
    }

    fn recorded_steps(
        &mut self,
        procedure: &DurableProcedureKey,
        flows: super::InteriorFlows,
        target: &InteriorTarget,
    ) -> Result<Option<Vec<SummaryWitnessStep>>, ComposeError> {
        self.handles
            .insert(procedure.clone(), flows.procedure.clone());
        let Some(recorded) = flows
            .flows
            .iter()
            .find(|flow| flow.seed == 0 && &flow.target == target)
            .and_then(|flow| flow.witness.as_deref())
        else {
            return Ok(None);
        };
        let mut steps = Vec::new();
        for (index, recorded) in recorded.iter().enumerate() {
            let Some(point) = flows.procedure.point_handle(recorded.point) else {
                return Ok(None);
            };
            let kind = if index == 0 {
                SummaryWitnessStepKind::Seed
            } else {
                SummaryWitnessStepKind::Edge(IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Normal))
            };
            steps.push(step(kind, point, None, HopQuality::CERTAIN));
        }
        Ok(Some(steps))
    }

    /// The recorded steps of one interior run of `procedure` from `from` to
    /// `to`.
    fn interior_steps(
        &mut self,
        procedure: &DurableProcedureKey,
        from: &Endpoint,
        to: &Endpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<Vec<SummaryWitnessStep>>, ComposeError> {
        let Some(seed) = interior_seed(self.sources, from) else {
            return Ok(None);
        };
        let (observations, target) = match to {
            Endpoint::Sink(sink) => (
                vec![interior_observation(self.plan, *sink)],
                InteriorTarget::Observation(0),
            ),
            Endpoint::Location(location) => (
                vec![InteriorObservation::Location(location.clone())],
                InteriorTarget::Observation(0),
            ),
            Endpoint::Port(port) => (Vec::new(), InteriorTarget::Port(port.clone())),
            Endpoint::Source(_) => return Ok(None),
        };
        let flows = self
            .provider
            .interior_flows(procedure, &[seed], &observations, true, request)
            .map_err(provider_error)?;
        self.recorded_steps(procedure, flows, &target)
    }
}

/// The seed of an interior run that starts at `from`.
pub(super) fn interior_seed(sources: &[BoundSource], from: &Endpoint) -> Option<InteriorSeed> {
    match from {
        Endpoint::Port(port) => Some(InteriorSeed::Port(port.clone())),
        Endpoint::Source(source) => {
            let source = &sources[source.index()];
            Some(InteriorSeed::Source {
                point: source.point.id(),
                phase: source.phase,
                carrier: source.carrier.clone(),
            })
        }
        Endpoint::Sink(_) | Endpoint::Location(_) => None,
    }
}

pub(super) fn interior_observation(
    plan: &TaintAnalysisPlan,
    sink: ValueFlowSinkId,
) -> InteriorObservation {
    let spec = plan
        .value_flow()
        .sink(sink)
        .expect("a path names a sink of its plan");
    InteriorObservation::Sink {
        point: spec.point().id(),
        phase: spec.phase(),
        carrier: spec.carrier().clone(),
    }
}

/// The quality a finding's path-quality frontier records for a composed
/// path. A composed path's quality is axis by axis (see [`HopQuality`]), and
/// a finding reads the frontier's axes separately, so the mapping keeps both
/// answers.
fn path_quality(quality: HopQuality) -> PathQuality {
    match (quality.proven, quality.complete) {
        (true, true) => PathQuality::PROVEN_COMPLETE,
        (true, false) => PathQuality::PROVEN_PARTIAL,
        (false, true) => PathQuality::UNPROVEN_COMPLETE,
        (false, false) => PathQuality::UNPROVEN_PARTIAL,
    }
}

fn step(
    kind: SummaryWitnessStepKind,
    point: crate::analyzer::semantic::ProgramPointHandle,
    origin: Option<crate::analyzer::semantic::CallSiteHandle>,
    quality: HopQuality,
) -> SummaryWitnessStep {
    let fact = FactId::new(u32::try_from(ZERO_FACT).expect("the zero fact id fits u32"));
    SummaryWitnessStep::new(
        kind,
        point,
        None,
        origin,
        None,
        if quality.proven {
            ProofStatus::Proven
        } else {
            ProofStatus::Unproven("composed path crosses an unproven hop".into())
        },
        if quality.complete {
            EvidenceCompleteness::Complete
        } else {
            EvidenceCompleteness::Partial("composed path crosses a partial hop".into())
        },
        fact,
        fact,
    )
}
