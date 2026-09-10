use std::sync::Arc;

use crate::hash::HashSet;

use crate::analyzer::semantic::ProgramPointHandle;
use crate::dataflow::{
    PathQuality, PathQualityFrontier, SummaryDataflowResult, SummaryEntry, SummaryWitness,
    SummaryWitnessError, WitnessReconstructionLimits,
};

use super::{
    AuthoredArmClosure, ValueFlowFact, ValueFlowPlan, ValueFlowSinkId, ValueFlowSolveError,
    ValueFlowSourceId, client::ValueFlowUncertainty,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFlowMayStatus {
    Proven,
    Unproven,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowMeeting {
    source: ValueFlowSourceId,
    sink: ValueFlowSinkId,
    entry: SummaryEntry,
    point: ProgramPointHandle,
    path_qualities: PathQualityFrontier,
    may: ValueFlowMayStatus,
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
        // Record what proved an authored boundary closure only when such a
        // closure decided the run (#2342). A derived-complete run closed nothing
        // this way, and a run that stayed inconclusive concluded nothing to
        // explain.
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

    /// The authored external summaries that closed a dispatch boundary in this
    /// run (#2342), so a consumer can state what proved the closure.
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
            .witness_for_reached_index(meeting.reached_index, quality, 0, limits)
    }

    /// A source-to-meeting path, including the caller contexts that supplied
    /// the value to a callee. The local witness API above deliberately remains
    /// available for consumers that work with procedure-relative path edges.
    /// Caller search and all reconstruction share one expansion/step budget.
    pub fn source_witness_for_meeting(
        &self,
        meeting: &ValueFlowMeeting,
        quality: PathQuality,
        limits: WitnessReconstructionLimits,
    ) -> Result<SummaryWitness, SummaryWitnessError> {
        let local = self.witness_for_meeting(meeting, quality, limits)?;
        if local.steps().is_empty() {
            return Ok(local);
        }
        let mut expansions = local.work().evidence_expansions();
        // Each node stores its next edge toward the meeting. A breadth-first
        // search selects one deterministic, cycle-free retained caller chain.
        // Entry identity includes the exact source-sensitive fact, so paths
        // from an unrelated value cannot be spliced into this witness.
        let mut nodes = vec![(meeting.entry(), None)];
        let mut seen = HashSet::default();
        seen.insert(meeting.entry());
        let mut cursor = 0;
        loop {
            let Some(&(entry, _)) = nodes.get(cursor) else {
                return Err(SummaryWitnessError::InvalidEvidence(
                    "source witness has no retained seed caller context",
                ));
            };
            if self.result.fact(entry.entry_fact()) == Some(&ValueFlowFact::zero()) {
                break;
            }
            for incoming in self.result.incoming_calls_for(entry) {
                if expansions == limits.max_expansions() {
                    return Ok(SummaryWitness::reconstruction_expansion_marker(
                        quality, expansions,
                    ));
                }
                expansions += 1;
                // A caller prefix can be weaker than the locally Proven
                // meeting (for example an open constructor boundary). Keep
                // that evidence and let path composition conjoin its quality;
                // do not mistake an unavailable strong prefix for no path.
                let call_quality = PathQuality::ALL
                    .into_iter()
                    .find(|quality| incoming.path_qualities().contains(*quality))
                    .expect("a retained incoming call has at least one path quality");
                if seen.insert(incoming.caller()) {
                    nodes.push((incoming.caller(), Some((cursor, incoming, call_quality))));
                }
            }
            cursor += 1;
        }

        let mut prefix: Option<SummaryWitness> = None;
        while let Some((next, incoming, call_quality)) = nodes[cursor].1 {
            let remaining = limits.max_expansions().saturating_sub(expansions);
            if remaining == 0 {
                return Ok(SummaryWitness::reconstruction_expansion_marker(
                    quality, expansions,
                ));
            }
            let call = self.result.witness_for_incoming_call(
                incoming,
                call_quality,
                WitnessReconstructionLimits::new(limits.max_steps(), remaining)
                    .expect("positive remaining reconstruction limits"),
            )?;
            expansions = expansions.saturating_add(call.work().evidence_expansions());
            let composed = match prefix {
                None => call,
                Some(prefix) => {
                    if call.steps().is_empty() {
                        return Ok(call.with_expansion_work(expansions));
                    }
                    prefix
                        .joined_at_call(&call, limits.max_steps())
                        .expect("nonempty caller paths join at their exact entry")
                }
            };
            if composed.truncated() {
                return Ok(composed.with_expansion_work(expansions));
            }
            prefix = Some(composed);
            cursor = next;
        }
        let witness = match prefix {
            Some(prefix) => prefix
                .joined_at_call(&local, limits.max_steps())
                .expect("complete caller and local witnesses have retained steps"),
            None => local,
        };
        Ok(witness.with_expansion_work(expansions))
    }
}
