//! Direction-independent taint findings and native planned evidence.

use std::{collections::BTreeMap, error::Error, fmt};

use crate::analyzer::semantic::{IcfgProvider, ProcedureHandle, SemanticBudget, SemanticWork};
use crate::dataflow::{
    DataflowDirection, DataflowDirectionCapability, DataflowDirectionPlan, DataflowRequest,
    IcfgSolveInput, NormalizedWitnessAvailability, NormalizedWitnessUnavailableReason,
    PlannedDataflowCompletion, PlannedDataflowResult, WitnessReconstructionLimits,
    WitnessRetentionLimits,
};
use crate::value_flow::ValueFlowEventKey;

use super::{
    SourceClassId, SourceEventKey, TaintAnalysisPlan, TaintBackwardResult, TaintFindingError,
    TaintSolveError, TaintSummaryResult,
};

/// One stable source/sink/class observation independent of solver direction.
///
/// Source and sink event keys are used instead of run-local dense IDs, while
/// the class is retained by its stable policy identity. `uncertain` preserves
/// incomplete evidence without turning an uncertain hit into a clean finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaintCanonicalFinding {
    source: SourceEventKey,
    sink: ValueFlowEventKey,
    class: SourceClassId,
    uncertain: bool,
}

impl TaintCanonicalFinding {
    pub const fn source(&self) -> &SourceEventKey {
        &self.source
    }

    pub const fn sink(&self) -> &ValueFlowEventKey {
        &self.sink
    }

    pub const fn class(&self) -> &SourceClassId {
        &self.class
    }

    pub const fn is_uncertain(&self) -> bool {
        self.uncertain
    }
}

/// Native evidence retained by one planned taint solve.
#[derive(Debug, Clone)]
pub enum TaintPlannedEvidence {
    Forward(Box<TaintSummaryResult>),
    Backward(Box<TaintBackwardResult>),
}

impl TaintPlannedEvidence {
    pub const fn direction(&self) -> DataflowDirection {
        match self {
            Self::Forward(_) => DataflowDirection::Forward,
            Self::Backward(_) => DataflowDirection::Backward,
        }
    }
}

/// The shared result envelope specialized for taint findings and evidence.
pub type TaintPlannedResult =
    crate::dataflow::PlannedDataflowResult<TaintCanonicalFinding, TaintPlannedEvidence>;

/// Failures from planned taint dispatch retain the native solver or finding
/// error instead of downgrading an unsupported output to an empty result.
#[derive(Debug)]
pub enum TaintPlannedSolveError {
    Forward(TaintSolveError),
    Backward(TaintSolveError),
    Findings(TaintFindingError),
    UnsupportedOutputContract {
        capability: DataflowDirectionCapability,
    },
    WitnessRetentionRequired,
}

impl fmt::Display for TaintPlannedSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward(error) => error.fmt(formatter),
            Self::Backward(error) => error.fmt(formatter),
            Self::Findings(error) => error.fmt(formatter),
            Self::UnsupportedOutputContract { capability } => write!(
                formatter,
                "planned taint solve does not provide {capability}"
            ),
            Self::WitnessRetentionRequired => formatter
                .write_str("planned forward taint findings require enabled witness retention"),
        }
    }
}

impl Error for TaintPlannedSolveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Forward(error) | Self::Backward(error) => Some(error),
            Self::Findings(error) => Some(error),
            Self::UnsupportedOutputContract { .. } | Self::WitnessRetentionRequired => None,
        }
    }
}

impl From<TaintFindingError> for TaintPlannedSolveError {
    fn from(error: TaintFindingError) -> Self {
        Self::Findings(error)
    }
}

/// Execute exactly the direction selected by the shared planner over one
/// already-built ICFG input.
///
/// Forward dispatch replays the supplied snapshot through the existing IDE
/// summary solver, preserving [`TaintSummaryResult`] as native evidence. The
/// replay provider returns the supplied snapshot with zero semantic work, so
/// the shared snapshot charge is reported only in the planned result envelope.
/// Backward dispatch calls the taint demand solver directly on the supplied
/// input. No branch constructs another snapshot or invokes both solvers.
#[allow(clippy::too_many_arguments)]
pub fn solve_taint_planned<Provider>(
    plan: DataflowDirectionPlan,
    input: IcfgSolveInput<'_>,
    snapshot_work: SemanticWork,
    root: &ProcedureHandle,
    provider: &Provider,
    taint_plan: &TaintAnalysisPlan,
    witness_retention: WitnessRetentionLimits,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TaintPlannedResult, TaintPlannedSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    match plan.direction() {
        DataflowDirection::Forward => {
            if !witness_retention.is_enabled() {
                return Err(TaintPlannedSolveError::WitnessRetentionRequired);
            }
            let result = super::client::solve_taint_batch_with_witnesses_on_input(
                root,
                provider,
                taint_plan,
                input,
                witness_retention,
                semantic_budget,
                request,
            )
            .map_err(TaintPlannedSolveError::Forward)?;
            let findings = canonical_taint_findings_from_forward(
                taint_plan,
                &result,
                WitnessReconstructionLimits::default(),
            )?;
            let completion = PlannedDataflowCompletion::new(
                input.status(),
                result.termination(),
                result.is_complete(),
            );
            let witnesses = if result.result().fact_result().witness_retention_truncated() {
                NormalizedWitnessAvailability::Unavailable(
                    NormalizedWitnessUnavailableReason::RetentionTruncated,
                )
            } else {
                NormalizedWitnessAvailability::Available
            };
            Ok(PlannedDataflowResult::new(
                plan,
                snapshot_work,
                result.work(),
                completion,
                findings,
                TaintPlannedEvidence::Forward(Box::new(result)),
                witnesses,
            ))
        }
        DataflowDirection::Backward => {
            reject_backward_output_requirements(plan)?;
            let result = super::client::solve_taint_batch_backward_on_input(
                root,
                taint_plan,
                input,
                snapshot_work,
                request,
            )
            .map_err(TaintPlannedSolveError::Backward)?;
            let findings = canonical_taint_findings_from_backward(taint_plan, &result)?;
            let completion = PlannedDataflowCompletion::new(
                input.status(),
                result.termination(),
                result.is_complete(),
            );
            Ok(PlannedDataflowResult::new(
                plan,
                snapshot_work,
                result.work(),
                completion,
                findings,
                TaintPlannedEvidence::Backward(Box::new(result)),
                NormalizedWitnessAvailability::Unavailable(
                    NormalizedWitnessUnavailableReason::BackwardSolverUnsupported,
                ),
            ))
        }
    }
}

fn reject_backward_output_requirements(
    plan: DataflowDirectionPlan,
) -> Result<(), TaintPlannedSolveError> {
    let requirements = plan.requirements();
    if requirements.reusable_summaries {
        return Err(TaintPlannedSolveError::UnsupportedOutputContract {
            capability: DataflowDirectionCapability::ReusableSummaries,
        });
    }
    if requirements.normalized_witnesses {
        return Err(TaintPlannedSolveError::UnsupportedOutputContract {
            capability: DataflowDirectionCapability::NormalizedWitnesses,
        });
    }
    Ok(())
}

/// Canonicalize forward-summary evidence into stable source/sink/class hits.
///
/// Source attribution is owned by the summary witness collector. If witness
/// retention is disabled, the native finding report remains valid but cannot
/// manufacture source identities; it therefore yields no source-attributed
/// canonical hit rather than guessing one.
pub fn canonical_taint_findings_from_forward(
    plan: &TaintAnalysisPlan,
    result: &TaintSummaryResult,
    witness_limits: WitnessReconstructionLimits,
) -> Result<Box<[TaintCanonicalFinding]>, TaintFindingError> {
    let report = super::collect_taint_findings(plan, result.clone(), usize::MAX, witness_limits)?;
    let mut merged = BTreeMap::<(SourceEventKey, ValueFlowEventKey, SourceClassId), bool>::new();
    for finding in report.findings() {
        for evidence in finding.origins().evidence() {
            for class in plan
                .universe()
                .stable_classes(evidence.classes())
                .map_err(|_| TaintFindingError::InvalidResult)?
            {
                let key = (
                    evidence.origin().clone(),
                    finding.key().sink().clone(),
                    class.clone(),
                );
                let uncertain = !finding.is_proven();
                merged
                    .entry(key)
                    .and_modify(|current| *current |= uncertain)
                    .or_insert(uncertain);
            }
        }
    }
    Ok(merged
        .into_iter()
        .map(|((source, sink, class), uncertain)| TaintCanonicalFinding {
            source,
            sink,
            class,
            uncertain,
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

/// Canonicalize backward snapshot hits into stable source/sink/class hits.
pub fn canonical_taint_findings_from_backward(
    plan: &TaintAnalysisPlan,
    result: &TaintBackwardResult,
) -> Result<Box<[TaintCanonicalFinding]>, TaintFindingError> {
    let result_uncertain = !result.is_complete();
    let mut merged = BTreeMap::<(SourceEventKey, ValueFlowEventKey, SourceClassId), bool>::new();
    for hit in result.hits() {
        let source = plan
            .sources()
            .iter()
            .find(|binding| binding.source() == hit.source())
            .ok_or(TaintFindingError::InvalidResult)?
            .origin()
            .clone();
        let sink = plan
            .value_flow()
            .sink(hit.sink())
            .ok_or(TaintFindingError::InvalidResult)?
            .key()
            .clone();
        let class = plan
            .universe()
            .classes()
            .get(usize::from(hit.class_index()))
            .cloned()
            .ok_or(TaintFindingError::InvalidResult)?;
        let key = (source, sink, class);
        merged
            .entry(key)
            .and_modify(|current| *current |= result_uncertain || hit.is_uncertain())
            .or_insert(result_uncertain || hit.is_uncertain());
    }
    Ok(merged
        .into_iter()
        .map(|((source, sink, class), uncertain)| TaintCanonicalFinding {
            source,
            sink,
            class,
            uncertain,
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}
