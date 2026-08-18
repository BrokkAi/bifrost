use std::sync::Arc;

use crate::analyzer::dataflow::{
    PathQuality, PathQualityFrontier, SummaryDataflowResult, SummaryEntry, SummaryWitness,
    SummaryWitnessError, WitnessReconstructionLimits,
};
use crate::analyzer::semantic::ProgramPointHandle;

use super::{
    AuthoredArmClosure, ValueFlowFact, ValueFlowPlan, ValueFlowSinkId, ValueFlowSolveError,
    ValueFlowSourceId, client::ValueFlowUncertainty,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFlowMayStatus {
    Proven,
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFlowMustStatus {
    NotEstablished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowMeeting {
    source: ValueFlowSourceId,
    sink: ValueFlowSinkId,
    entry: SummaryEntry,
    point: ProgramPointHandle,
    path_qualities: PathQualityFrontier,
    may: ValueFlowMayStatus,
    must: ValueFlowMustStatus,
    uncertainty: ValueFlowUncertainty,
    reached_index: usize,
    owner: Arc<()>,
}

impl ValueFlowMeeting {
    pub const fn source(&self) -> ValueFlowSourceId {
        self.source
    }

    pub const fn sink(&self) -> ValueFlowSinkId {
        self.sink
    }

    pub const fn entry(&self) -> &SummaryEntry {
        &self.entry
    }

    pub const fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub const fn path_qualities(&self) -> PathQualityFrontier {
        self.path_qualities
    }

    pub const fn may_status(&self) -> ValueFlowMayStatus {
        self.may
    }

    pub const fn must_status(&self) -> ValueFlowMustStatus {
        self.must
    }

    pub const fn is_uncertain(&self) -> bool {
        !self.uncertainty.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFlowSinkOutcome<'result> {
    Reached(Box<[&'result ValueFlowMeeting]>),
    NotReached,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct ValueFlowSummaryResult {
    result: SummaryDataflowResult<ValueFlowFact>,
    meetings: Box<[ValueFlowMeeting]>,
    discovery_complete: bool,
    proven_by_authored_summaries: bool,
    authored_arm_closures: Box<[AuthoredArmClosure]>,
    owner: Arc<()>,
}

impl ValueFlowSummaryResult {
    pub(crate) fn from_result(
        plan: &ValueFlowPlan,
        result: SummaryDataflowResult<ValueFlowFact>,
    ) -> Result<Self, ValueFlowSolveError> {
        let mut meetings = Vec::new();
        for (reached_index, reached) in result.reached().iter().enumerate() {
            let fact = *result
                .fact(reached.fact())
                .ok_or(ValueFlowSolveError::InvalidResult)?;
            let (Some(source), Some(sink)) = (fact.source(), fact.sink()) else {
                continue;
            };
            if plan.source(source).is_none() || plan.sink(sink).is_none() {
                return Err(ValueFlowSolveError::InvalidResult);
            }
            let may = if fact.uncertainty().is_empty()
                && reached.path_qualities().iter().any(PathQuality::is_proven)
            {
                ValueFlowMayStatus::Proven
            } else {
                ValueFlowMayStatus::Unproven
            };
            meetings.push(ValueFlowMeeting {
                source,
                sink,
                entry: reached.entry().clone(),
                point: reached.point().clone(),
                path_qualities: reached.path_qualities(),
                may,
                must: ValueFlowMustStatus::NotEstablished,
                uncertainty: fact.uncertainty(),
                reached_index,
                owner: Arc::clone(plan.owner()),
            });
        }
        // `execution_result_complete` embeds typed discovery closure (#1952):
        // an open snapshot keeps the run incomplete unless its residual
        // refinement calls are fully modeled by this result's boundaries, so
        // absence of a meeting never reads as a clean negative past an open
        // discovery input.
        let discovery_complete = plan.execution_result_complete(&result);
        // Mirrors the taint layer (#1916): the run is not derived-complete, yet
        // accepting authored-complete external summaries closes it.
        let proven_by_authored_summaries = !discovery_complete
            && plan.execution_result_complete_accepting_authored_summaries(&result);
        // Record what proved a residual-arm closure only when such a closure
        // decided the run (#2342). A derived-complete run closed nothing this
        // way, and a run that stayed inconclusive concluded nothing to explain.
        let authored_arm_closures = if proven_by_authored_summaries {
            plan.authored_arm_closures(&result).into_boxed_slice()
        } else {
            Box::default()
        };
        Ok(Self {
            result,
            meetings: meetings.into_boxed_slice(),
            discovery_complete,
            proven_by_authored_summaries,
            authored_arm_closures,
            owner: Arc::clone(plan.owner()),
        })
    }

    pub const fn result(&self) -> &SummaryDataflowResult<ValueFlowFact> {
        &self.result
    }

    pub fn meetings(&self) -> &[ValueFlowMeeting] {
        &self.meetings
    }

    pub fn is_complete(&self) -> bool {
        self.discovery_complete
    }

    /// Whether the run is not derived-complete, but every open boundary is
    /// closed by an authored-complete external procedure summary (#1916).
    /// Mutually exclusive with `is_complete`.
    pub fn is_proven_by_authored_summaries(&self) -> bool {
        self.proven_by_authored_summaries
    }

    /// The authored external summaries that closed a residual dispatch arm in
    /// this run (#2342), so a consumer can state what proved the closure.
    /// Empty unless `is_proven_by_authored_summaries` holds.
    pub fn authored_arm_closures(&self) -> &[AuthoredArmClosure] {
        &self.authored_arm_closures
    }

    pub fn sink_outcome(&self, sink: ValueFlowSinkId) -> ValueFlowSinkOutcome<'_> {
        let meetings = self
            .meetings
            .iter()
            .filter(|meeting| meeting.sink == sink)
            .collect::<Vec<_>>();
        if !meetings.is_empty() {
            ValueFlowSinkOutcome::Reached(meetings.into_boxed_slice())
        } else if self.is_complete() {
            ValueFlowSinkOutcome::NotReached
        } else {
            ValueFlowSinkOutcome::Inconclusive
        }
    }

    pub fn witness_for_meeting(
        &self,
        meeting: &ValueFlowMeeting,
        quality: PathQuality,
        limits: WitnessReconstructionLimits,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        if !self.meetings.iter().any(|candidate| {
            Arc::ptr_eq(&candidate.owner, &self.owner)
                && Arc::ptr_eq(&candidate.owner, &meeting.owner)
                && candidate.reached_index == meeting.reached_index
                && candidate.source == meeting.source
                && candidate.sink == meeting.sink
        }) {
            return Err(SummaryWitnessError::TargetNotInResult);
        }
        self.result
            .witness_for_reached_index(meeting.reached_index, quality, limits)
    }
}
