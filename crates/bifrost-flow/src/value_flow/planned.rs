//! Value-flow direction planning over one shared bounded ICFG snapshot.
//!
//! This module owns the value-flow-specific binding layer around the generic
//! data-flow planner.  It maps every source and sink observation in a resolved
//! [`ValueFlowPlan`] to all matching context-expanded nodes in one immutable
//! [`IcfgSnapshot`], then estimates and selects a direction from the request's
//! owned query-plan configuration.
//!
//! Dispatch keeps the existing direction-specific evidence contracts: forward
//! solves retain summary results and backward solves retain snapshot results.
//! Both routes publish one canonical meeting view in the shared planned-result
//! envelope without rebuilding a supplied snapshot.

use std::{error::Error, fmt};

use crate::analyzer::semantic::{
    IcfgNodeId, IcfgProvider, IcfgSnapshot, OracleLimits, ProcedureHandle, ProgramPointHandle,
    SemanticBudget, SemanticWork,
};
use crate::dataflow::{
    DataflowDirection, DataflowDirectionCapabilities, DataflowDirectionEstimate,
    DataflowDirectionPlan, DataflowDirectionPlanningError, DataflowDirectionRequirements,
    DataflowRequest, IcfgInputStatus, IcfgSolveInput, NormalizedWitnessAvailability,
    NormalizedWitnessUnavailableReason, PathQualityFrontier, PlannedDataflowCompletion,
    PlannedDataflowResult, SnapshotReplayProvider, WitnessRetentionLimits,
    plan_snapshot_dataflow_direction, snapshot_node_ids_for_points,
};

use super::{
    BackwardValueFlowResult, ValueFlowMayStatus, ValueFlowPlan, ValueFlowSinkId,
    ValueFlowSolveError, ValueFlowSourceId, ValueFlowSummaryResult,
    backward_client::BackwardValueFlowSolveError, result::meeting_may_status,
};

/// The context-expanded snapshot nodes bound to a plan's source and sink observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowSnapshotObservationBindings {
    source_nodes: Box<[IcfgNodeId]>,
    sink_nodes: Box<[IcfgNodeId]>,
}

impl ValueFlowSnapshotObservationBindings {
    pub const fn source_nodes(&self) -> &[IcfgNodeId] {
        &self.source_nodes
    }

    pub const fn sink_nodes(&self) -> &[IcfgNodeId] {
        &self.sink_nodes
    }
}

/// Value-flow-specific direction plan and its shared-snapshot observation
/// bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowDirectionPlan {
    dataflow: DataflowDirectionPlan,
    bindings: ValueFlowSnapshotObservationBindings,
}

impl ValueFlowDirectionPlan {
    pub const fn direction(&self) -> DataflowDirection {
        self.dataflow.direction()
    }

    pub const fn dataflow_plan(&self) -> DataflowDirectionPlan {
        self.dataflow
    }

    pub const fn reason(&self) -> crate::dataflow::DataflowDirectionSelectionReason {
        self.dataflow.reason()
    }

    pub const fn estimate(&self) -> DataflowDirectionEstimate {
        self.dataflow.estimate()
    }

    pub const fn bindings(&self) -> &ValueFlowSnapshotObservationBindings {
        &self.bindings
    }

    pub const fn source_nodes(&self) -> &[IcfgNodeId] {
        self.bindings.source_nodes()
    }

    pub const fn sink_nodes(&self) -> &[IcfgNodeId] {
        self.bindings.sink_nodes()
    }
}

/// One canonical value-flow meeting independent of solver direction.
///
/// Forward summary entries and backward context-local rows are deliberately
/// omitted from this identity.  They remain available through the evidence
/// enum; the canonical finding is only the stable source/sink observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowCanonicalMeeting {
    source: ValueFlowSourceId,
    sink: ValueFlowSinkId,
    path_qualities: PathQualityFrontier,
    may: ValueFlowMayStatus,
    uncertain: bool,
}

impl ValueFlowCanonicalMeeting {
    pub const fn source(&self) -> ValueFlowSourceId {
        self.source
    }

    pub const fn sink(&self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }

    pub const fn may_status(&self) -> ValueFlowMayStatus {
        self.may
    }

    pub const fn is_uncertain(&self) -> bool {
        self.uncertain
    }
}

/// Direction-specific value-flow evidence retained by a planned solve.
///
/// Forward evidence retains summary results, including query-local contextual
/// capture execution. Backward
/// evidence retains the native root-scoped snapshot result and reverse-call
/// index; it is never coerced into a summary result.
#[derive(Debug, Clone)]
pub enum ValueFlowPlannedEvidence {
    Forward(ValueFlowSummaryResult),
    Backward(BackwardValueFlowResult),
}

pub type ValueFlowPlannedResult =
    PlannedDataflowResult<ValueFlowCanonicalMeeting, ValueFlowPlannedEvidence>;

/// Failures from a planned value-flow solve remain direction- and input-aware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowPlannedSolveError {
    Forward(ValueFlowSolveError),
    Backward(BackwardValueFlowSolveError),
    WrongDirection {
        selected: DataflowDirection,
        expected: DataflowDirection,
    },
    UnsupportedOutputContract {
        capability: crate::dataflow::DataflowDirectionCapability,
    },
    WitnessRetentionRequired,
}

impl fmt::Display for ValueFlowPlannedSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward(error) => error.fmt(formatter),
            Self::Backward(error) => error.fmt(formatter),
            Self::WrongDirection { selected, expected } => write!(
                formatter,
                "planned value-flow solve selected {selected:?}, but this adapter requires {expected:?}"
            ),
            Self::UnsupportedOutputContract { capability } => write!(
                formatter,
                "planned value-flow input solve does not provide {capability}"
            ),
            Self::WitnessRetentionRequired => formatter
                .write_str("planned value-flow witnesses require enabled witness retention"),
        }
    }
}

impl Error for ValueFlowPlannedSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Forward(error) => Some(error),
            Self::Backward(error) => Some(error),
            Self::WrongDirection { .. }
            | Self::UnsupportedOutputContract { .. }
            | Self::WitnessRetentionRequired => None,
        }
    }
}

impl From<BackwardValueFlowSolveError> for ValueFlowPlannedSolveError {
    fn from(error: BackwardValueFlowSolveError) -> Self {
        Self::Backward(error)
    }
}

impl From<ValueFlowSolveError> for ValueFlowPlannedSolveError {
    fn from(error: ValueFlowSolveError) -> Self {
        Self::Forward(error)
    }
}

impl ValueFlowPlannedSolveError {
    const fn wrong_direction(selected: DataflowDirection, expected: DataflowDirection) -> Self {
        Self::WrongDirection { selected, expected }
    }
}

/// Dispatch exactly the direction selected by the value-flow direction plan.
///
/// Forward dispatch retains the existing summary result; backward dispatch
/// consumes the supplied snapshot input with the native backward solver.
/// Neither route materializes a second ICFG snapshot.
#[allow(clippy::too_many_arguments)]
pub fn solve_value_flow_planned<Provider>(
    direction_plan: &ValueFlowDirectionPlan,
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &ValueFlowPlan,
    input: IcfgSolveInput<'_>,
    snapshot_work: SemanticWork,
    witness_retention: WitnessRetentionLimits,
    oracle_limits: OracleLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowPlannedResult, ValueFlowPlannedSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    match direction_plan.direction() {
        DataflowDirection::Forward => solve_value_flow_planned_forward(
            direction_plan,
            root,
            provider,
            plan,
            input,
            snapshot_work,
            witness_retention,
            oracle_limits,
            semantic_budget,
            request,
        ),
        DataflowDirection::Backward => {
            solve_value_flow_planned_backward(direction_plan, plan, input, snapshot_work, request)
        }
    }
}

/// Solve the selected backward value-flow direction over the supplied input.
///
/// Forward summary dispatch deliberately has a separate adapter below: the
/// current summary solver accepts a provider and owns its summary evidence,
/// while this function must consume the already-built snapshot exactly once.
pub fn solve_value_flow_planned_backward(
    direction_plan: &ValueFlowDirectionPlan,
    plan: &ValueFlowPlan,
    input: IcfgSolveInput<'_>,
    snapshot_work: SemanticWork,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowPlannedResult, ValueFlowPlannedSolveError> {
    if direction_plan.direction() != DataflowDirection::Backward {
        return Err(ValueFlowPlannedSolveError::wrong_direction(
            direction_plan.direction(),
            DataflowDirection::Backward,
        ));
    }
    reject_unsupported_output_contract(direction_plan)?;
    let result = super::backward_client::solve_value_flow_backward_on_input(
        plan,
        input,
        snapshot_work,
        request,
    )?;
    let findings = canonical_backward_findings(result.meetings());
    let native = result.result();
    let completion = PlannedDataflowCompletion::new(
        native.coverage().input_status(),
        native.termination(),
        result.is_complete(),
    );
    Ok(PlannedDataflowResult::new(
        direction_plan.dataflow_plan(),
        snapshot_work,
        result.work(),
        completion,
        findings,
        ValueFlowPlannedEvidence::Backward(result),
        NormalizedWitnessAvailability::Unavailable(
            NormalizedWitnessUnavailableReason::BackwardSolverUnsupported,
        ),
    ))
}

/// Solve the selected forward value-flow direction over the supplied input.
///
/// Native argument-callable proof selects contextual summary capture execution
/// under the supplied oracle limits. Other inputs retain ordinary summary
/// execution. Both routes replay the paid root snapshot and retain its status;
/// projection selection, capture projection, and propagation share one budget.
#[allow(clippy::too_many_arguments)]
pub fn solve_value_flow_planned_forward<Provider>(
    direction_plan: &ValueFlowDirectionPlan,
    root: &ProcedureHandle,
    provider: &Provider,
    plan: &ValueFlowPlan,
    input: IcfgSolveInput<'_>,
    snapshot_work: SemanticWork,
    witness_retention: WitnessRetentionLimits,
    oracle_limits: OracleLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<ValueFlowPlannedResult, ValueFlowPlannedSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    if direction_plan.direction() != DataflowDirection::Forward {
        return Err(ValueFlowPlannedSolveError::wrong_direction(
            direction_plan.direction(),
            DataflowDirection::Forward,
        ));
    }
    if direction_plan
        .dataflow_plan()
        .requirements()
        .normalized_witnesses
        && !witness_retention.is_enabled()
    {
        return Err(ValueFlowPlannedSolveError::WitnessRetentionRequired);
    }
    if root != plan.root() {
        return Err(ValueFlowSolveError::RootMismatch.into());
    }
    let initial_work = request.budget.used();
    let mut has_argument_captures = plan.has_contextual_bindings();
    for node in input.snapshot().nodes() {
        super::client::charge_capture_projection(request).map_err(ValueFlowSolveError::from)?;
        if node.argument_callable().is_some() {
            has_argument_captures = true;
            break;
        }
    }
    let mut summary = if has_argument_captures {
        super::client::solve_value_flow_summaries_on_snapshot(
            provider,
            plan,
            input,
            oracle_limits,
            witness_retention,
            semantic_budget,
            request,
        )?
    } else {
        let replay = SnapshotReplayProvider::new(provider, input);
        super::client::solve_value_flow_with_witnesses(
            root,
            &replay,
            plan,
            witness_retention,
            semantic_budget,
            request,
        )?
    };
    summary.set_query_work(request.budget.used().saturating_sub(initial_work));
    adapt_value_flow_summary_result_with_witness_retention(
        direction_plan,
        summary,
        witness_retention,
        snapshot_work,
        input.status(),
    )
}

fn adapt_value_flow_summary_result_with_witness_retention(
    direction_plan: &ValueFlowDirectionPlan,
    summary: ValueFlowSummaryResult,
    witness_retention: WitnessRetentionLimits,
    snapshot_work: SemanticWork,
    input_status: IcfgInputStatus,
) -> Result<ValueFlowPlannedResult, ValueFlowPlannedSolveError> {
    if direction_plan.direction() != DataflowDirection::Forward {
        return Err(ValueFlowPlannedSolveError::wrong_direction(
            direction_plan.direction(),
            DataflowDirection::Forward,
        ));
    }
    let native = summary.result();
    let findings = canonical_summary_findings(summary.meetings());
    let completion = PlannedDataflowCompletion::new(
        input_status.merge(native.coverage().semantic_status()),
        native.termination(),
        summary.is_complete(),
    );
    let witnesses = if !witness_retention.is_enabled() {
        NormalizedWitnessAvailability::Unavailable(
            NormalizedWitnessUnavailableReason::RetentionDisabled,
        )
    } else if native.witness_retention_truncated() {
        NormalizedWitnessAvailability::Unavailable(
            NormalizedWitnessUnavailableReason::RetentionTruncated,
        )
    } else {
        NormalizedWitnessAvailability::Available
    };
    Ok(PlannedDataflowResult::new(
        direction_plan.dataflow_plan(),
        snapshot_work.conservative_add(native.semantic_work()),
        native.work(),
        completion,
        findings,
        ValueFlowPlannedEvidence::Forward(summary),
        witnesses,
    ))
}

fn reject_unsupported_output_contract(
    direction_plan: &ValueFlowDirectionPlan,
) -> Result<(), ValueFlowPlannedSolveError> {
    if let Some(capability) = direction_plan
        .dataflow_plan()
        .requirements()
        .unsupported_backward_output()
    {
        return Err(ValueFlowPlannedSolveError::UnsupportedOutputContract { capability });
    }
    Ok(())
}

fn canonical_summary_findings(
    meetings: &[super::ValueFlowMeeting],
) -> Box<[ValueFlowCanonicalMeeting]> {
    canonicalize_findings_from(meetings, |meeting| {
        canonical_meeting(
            meeting.source(),
            meeting.sink(),
            meeting.path_qualities(),
            meeting.may_status(),
            meeting.is_uncertain(),
        )
    })
}

fn canonical_backward_findings(
    meetings: &[super::BackwardValueFlowMeeting],
) -> Box<[ValueFlowCanonicalMeeting]> {
    canonicalize_findings_from(meetings, |meeting| {
        let uncertain = meeting.is_uncertain();
        canonical_meeting(
            meeting.source(),
            meeting.sink(),
            meeting.path_qualities(),
            meeting_may_status(uncertain, meeting.path_qualities()),
            uncertain,
        )
    })
}

fn canonical_meeting(
    source: ValueFlowSourceId,
    sink: ValueFlowSinkId,
    path_qualities: PathQualityFrontier,
    may: ValueFlowMayStatus,
    uncertain: bool,
) -> ValueFlowCanonicalMeeting {
    ValueFlowCanonicalMeeting {
        source,
        sink,
        path_qualities,
        may,
        uncertain,
    }
}

fn canonicalize_findings_from<T>(
    meetings: &[T],
    to_finding: impl FnMut(&T) -> ValueFlowCanonicalMeeting,
) -> Box<[ValueFlowCanonicalMeeting]> {
    canonicalize_findings(meetings.iter().map(to_finding).collect())
}

fn canonicalize_findings(
    mut findings: Vec<ValueFlowCanonicalMeeting>,
) -> Box<[ValueFlowCanonicalMeeting]> {
    findings.sort_by_key(|finding| (finding.source, finding.sink));
    let mut canonical: Vec<ValueFlowCanonicalMeeting> = Vec::with_capacity(findings.len());
    for finding in findings {
        if let Some(previous) = canonical.last_mut()
            && previous.source == finding.source
            && previous.sink == finding.sink
        {
            for quality in finding.path_qualities.iter() {
                previous.path_qualities.insert(quality);
            }
            previous.uncertain |= finding.uncertain;
            previous.may = meeting_may_status(previous.uncertain, previous.path_qualities);
        } else {
            canonical.push(finding);
        }
    }
    canonical.into_boxed_slice()
}

/// A value-flow observation could not be bound to the shared snapshot, or the
/// requested direction lacked a required semantic capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowDirectionPlanError {
    MissingSourceObservation {
        source: ValueFlowSourceId,
        point: ProgramPointHandle,
    },
    MissingSinkObservation {
        sink: ValueFlowSinkId,
        point: ProgramPointHandle,
    },
    Planning(DataflowDirectionPlanningError),
}

impl fmt::Display for ValueFlowDirectionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSourceObservation { source, point } => write!(
                formatter,
                "value-flow source {source:?} is not present in the shared ICFG snapshot at {point:?}"
            ),
            Self::MissingSinkObservation { sink, point } => write!(
                formatter,
                "value-flow sink {sink:?} is not present in the shared ICFG snapshot at {point:?}"
            ),
            Self::Planning(error) => error.fmt(formatter),
        }
    }
}

impl Error for ValueFlowDirectionPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Planning(error) => Some(error),
            Self::MissingSourceObservation { .. } | Self::MissingSinkObservation { .. } => None,
        }
    }
}

impl From<DataflowDirectionPlanningError> for ValueFlowDirectionPlanError {
    fn from(error: DataflowDirectionPlanningError) -> Self {
        Self::Planning(error)
    }
}

/// Plan one value-flow query against an already materialized shared snapshot.
///
/// Existing callers that leave [`DataflowRequest`] at its default receive
/// conservative `Auto` planning.  Explicit `Backward` remains typed
/// unsupported when this plan's reverse semantic inputs are incomplete;
/// backward reusable summaries and normalized witnesses are never claimed as
/// capabilities here.
pub fn plan_value_flow_direction(
    request: &DataflowRequest<'_>,
    plan: &ValueFlowPlan,
    snapshot: &IcfgSnapshot,
) -> Result<ValueFlowDirectionPlan, ValueFlowDirectionPlanError> {
    plan_value_flow_direction_with_requirements(
        request,
        plan,
        snapshot,
        DataflowDirectionRequirements::none(),
    )
}

/// Plan one value-flow query while retaining caller-selected output
/// requirements such as reusable summaries or normalized witnesses.
///
/// A bounded snapshot and complete reverse semantics are always required by
/// this adapter.  They are augmented here rather than left to callers, so an
/// omitted requirement can never accidentally enable an incomplete backward
/// value-flow query.
pub fn plan_value_flow_direction_with_requirements(
    request: &DataflowRequest<'_>,
    plan: &ValueFlowPlan,
    snapshot: &IcfgSnapshot,
    output_requirements: DataflowDirectionRequirements,
) -> Result<ValueFlowDirectionPlan, ValueFlowDirectionPlanError> {
    let bindings = bind_observations(plan, snapshot)?;
    let mut capabilities = DataflowDirectionCapabilities::current();
    capabilities.backward_reverse_semantics_complete = plan.discovery_complete();
    let requirements = output_requirements
        .with_bounded_snapshot(true)
        .with_complete_reverse_semantics(true);
    let dataflow = plan_snapshot_dataflow_direction(
        request,
        snapshot,
        bindings.source_nodes(),
        bindings.sink_nodes(),
        plan.forward_transfer_fanout_estimate(),
        plan.backward_transfer_fanout_estimate(),
        plan.sources().len(),
        plan.sinks().len(),
        capabilities,
        requirements,
    )?;
    Ok(ValueFlowDirectionPlan { dataflow, bindings })
}

fn bind_observations(
    plan: &ValueFlowPlan,
    snapshot: &IcfgSnapshot,
) -> Result<ValueFlowSnapshotObservationBindings, ValueFlowDirectionPlanError> {
    let mut source_nodes = Vec::new();
    for (source, spec) in plan.sources() {
        let nodes = snapshot_node_ids_for_points(snapshot, std::slice::from_ref(&spec.point()));
        if nodes.is_empty() {
            return Err(ValueFlowDirectionPlanError::MissingSourceObservation {
                source,
                point: spec.point().clone(),
            });
        }
        source_nodes.extend(nodes);
    }

    let mut sink_nodes = Vec::new();
    for (sink, spec) in plan.sinks() {
        let nodes = snapshot_node_ids_for_points(snapshot, std::slice::from_ref(&spec.point()));
        if nodes.is_empty() {
            return Err(ValueFlowDirectionPlanError::MissingSinkObservation {
                sink,
                point: spec.point().clone(),
            });
        }
        sink_nodes.extend(nodes);
    }

    source_nodes.sort_unstable();
    source_nodes.dedup();
    sink_nodes.sort_unstable();
    sink_nodes.dedup();
    Ok(ValueFlowSnapshotObservationBindings {
        source_nodes: source_nodes.into_boxed_slice(),
        sink_nodes: sink_nodes.into_boxed_slice(),
    })
}
