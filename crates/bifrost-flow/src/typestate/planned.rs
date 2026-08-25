//! Exact-one-solver typestate dispatch over one supplied ICFG snapshot.

use std::fmt;

use crate::analyzer::semantic::{IcfgProvider, ProcedureHandle, SemanticBudget, SemanticWork};
use crate::dataflow::{
    DataflowDirection, DataflowDirectionPlan, DataflowDirectionPlanningError, DataflowRequest,
    IcfgSolveInput, NormalizedWitnessAvailability, NormalizedWitnessUnavailableReason,
    PlannedDataflowCompletion, PlannedDataflowResult, SnapshotReplayProvider,
};

use super::client::{
    TypestateBackwardDemand, TypestateBackwardResult, TypestateBackwardSolveError, TypestateFact,
    TypestateSolveError, TypestateSummaryResult, solve_typestate_backward_on_snapshot,
    solve_typestate_with_summaries,
};
use super::{CompiledProtocol, TypestateBindingPlan};

/// A stable typestate reached observation independent of solver direction.
///
/// Context-specific rows that agree on the same semantic point and protocol
/// fact are intentionally canonicalized together. Direction-specific context
/// and call evidence remain available through [`TypestatePlannedEvidence`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypestateCanonicalObservation {
    point: crate::analyzer::semantic::ProgramPointHandle,
    fact: TypestateFact,
}

impl TypestateCanonicalObservation {
    pub fn point(&self) -> &crate::analyzer::semantic::ProgramPointHandle {
        &self.point
    }

    pub const fn fact(&self) -> TypestateFact {
        self.fact
    }
}

/// Native evidence retained by one planned typestate run.
#[derive(Debug, Clone)]
pub enum TypestatePlannedEvidence {
    Forward(TypestateSummaryResult),
    Backward(TypestateBackwardResult),
}

impl TypestatePlannedEvidence {
    pub const fn direction(&self) -> DataflowDirection {
        match self {
            Self::Forward(_) => DataflowDirection::Forward,
            Self::Backward(_) => DataflowDirection::Backward,
        }
    }
}

/// The shared result envelope specialized for typestate observations and
/// native direction-specific evidence.
pub type TypestatePlannedResult =
    PlannedDataflowResult<TypestateCanonicalObservation, TypestatePlannedEvidence>;

/// Errors from typestate planned dispatch.
#[derive(Debug)]
pub enum TypestatePlannedSolveError {
    Planning(DataflowDirectionPlanningError),
    Forward(TypestateSolveError),
    Backward(TypestateBackwardSolveError),
}

impl fmt::Display for TypestatePlannedSolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planning(error) => error.fmt(formatter),
            Self::Forward(error) => error.fmt(formatter),
            Self::Backward(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TypestatePlannedSolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Planning(error) => Some(error),
            Self::Forward(error) => Some(error),
            Self::Backward(error) => Some(error),
        }
    }
}

impl From<DataflowDirectionPlanningError> for TypestatePlannedSolveError {
    fn from(error: DataflowDirectionPlanningError) -> Self {
        Self::Planning(error)
    }
}

impl From<TypestateSolveError> for TypestatePlannedSolveError {
    fn from(error: TypestateSolveError) -> Self {
        Self::Forward(error)
    }
}

impl From<TypestateBackwardSolveError> for TypestatePlannedSolveError {
    fn from(error: TypestateBackwardSolveError) -> Self {
        Self::Backward(error)
    }
}

/// Execute the selected typestate direction exactly once over `input`.
///
/// Forward dispatch replays the supplied immutable snapshot through the
/// existing summary solver, so the summary route retains its native reusable
/// evidence without asking the semantic provider to materialize a second
/// graph. Backward dispatch uses the snapshot demand adapter directly. The
/// selected branch is the only solver invoked.
#[allow(clippy::too_many_arguments)]
pub fn solve_typestate_planned<Provider>(
    plan: DataflowDirectionPlan,
    input: IcfgSolveInput<'_>,
    snapshot_work: SemanticWork,
    root: &ProcedureHandle,
    entry_facts: &[TypestateFact],
    demands: &[TypestateBackwardDemand],
    provider: &Provider,
    protocol: &CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_budget: &mut SemanticBudget,
    request: &mut DataflowRequest<'_>,
) -> Result<TypestatePlannedResult, TypestatePlannedSolveError>
where
    Provider: IcfgProvider + ?Sized,
{
    match plan.direction() {
        DataflowDirection::Forward => {
            let replay = SnapshotReplayProvider::new(provider, input);
            let result = solve_typestate_with_summaries(
                root,
                entry_facts,
                &replay,
                protocol,
                bindings,
                semantic_budget,
                request,
            )?;
            let findings = canonical_summary_findings(&result);
            let completion = PlannedDataflowCompletion::new(
                input.status(),
                result.result().termination(),
                result.is_complete(),
            );
            let witnesses = if result.result().witness_retention_truncated() {
                NormalizedWitnessAvailability::Unavailable(
                    NormalizedWitnessUnavailableReason::RetentionTruncated,
                )
            } else {
                NormalizedWitnessAvailability::Available
            };
            Ok(PlannedDataflowResult::new(
                plan,
                snapshot_work,
                result.result().work(),
                completion,
                findings,
                TypestatePlannedEvidence::Forward(result),
                witnesses,
            ))
        }
        DataflowDirection::Backward => {
            let result = solve_typestate_backward_on_snapshot(
                root,
                demands,
                input,
                snapshot_work,
                protocol,
                bindings,
                request,
            )?;
            let findings = canonical_backward_findings(&result);
            let completion = PlannedDataflowCompletion::new(
                input.status(),
                result.result().termination(),
                result.is_complete(),
            );
            Ok(PlannedDataflowResult::new(
                plan,
                snapshot_work,
                result.result().work(),
                completion,
                findings,
                TypestatePlannedEvidence::Backward(result),
                NormalizedWitnessAvailability::Unavailable(
                    NormalizedWitnessUnavailableReason::BackwardSolverUnsupported,
                ),
            ))
        }
    }
}

fn canonical_summary_findings(
    result: &TypestateSummaryResult,
) -> Box<[TypestateCanonicalObservation]> {
    let mut findings = result
        .result()
        .reached()
        .iter()
        .filter_map(|reached| {
            result.result().fact(reached.fact()).copied().map(|fact| {
                TypestateCanonicalObservation {
                    point: reached.point().clone(),
                    fact,
                }
            })
        })
        .collect::<Vec<_>>();
    canonicalize_findings(&mut findings);
    findings.into_boxed_slice()
}

fn canonical_backward_findings(
    result: &TypestateBackwardResult,
) -> Box<[TypestateCanonicalObservation]> {
    let mut findings = result
        .result()
        .reached()
        .iter()
        .filter_map(|reached| {
            let fact = result.result().fact(reached.fact()).copied()?;
            let point = result
                .result()
                .snapshot()
                .node(reached.node())?
                .point()
                .clone();
            Some(TypestateCanonicalObservation { point, fact })
        })
        .collect::<Vec<_>>();
    canonicalize_findings(&mut findings);
    findings.into_boxed_slice()
}

fn canonicalize_findings(findings: &mut Vec<TypestateCanonicalObservation>) {
    findings.sort_by(|left, right| {
        left.point
            .durable_key()
            .cmp(&right.point.durable_key())
            .then_with(|| left.fact.cmp(&right.fact))
    });
    findings.dedup();
}
