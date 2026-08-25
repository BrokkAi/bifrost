use crate::finding::{BoundedWitness, WitnessStep, WitnessStepKind};
use crate::finding_identity::WitnessId;
use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_flow::dataflow::{SummaryWitness, SummaryWitnessStepKind};

pub(super) fn project_summary_witness(
    workspace: &WorkspaceAnalyzer,
    witness: &SummaryWitness,
    id: WitnessId,
    max_steps: usize,
    max_bytes: usize,
    labels: impl Fn(&SummaryWitnessStepKind) -> (WitnessStepKind, &'static str),
) -> Result<Option<BoundedWitness>, String> {
    let mut steps = Vec::new();
    for step in witness.steps().iter().take(max_steps) {
        let (kind, label) = labels(&step.kind());
        steps.push(
            WitnessStep::try_new(
                kind,
                Some(super::semantic_identity::policy_location(
                    workspace,
                    super::semantic_identity::program_point_locator(step.source()),
                )?),
                label,
                Vec::new(),
            )
            .map_err(|error| error.to_string())?,
        );
        let candidate = BoundedWitness::try_new(id.clone(), steps.clone(), true, 1)
            .map_err(|error| error.to_string())?;
        if usize::try_from(candidate.retained_bytes()).unwrap_or(usize::MAX) > max_bytes {
            steps.pop();
            break;
        }
    }
    if steps.is_empty() {
        return Ok(None);
    }
    // Internal truncation always carries a positive omitted lower bound, and
    // unretained sibling alternatives do not make this witness incomplete, so
    // no omitted step is fabricated here.
    let omitted = witness
        .omitted_steps_lower_bound()
        .saturating_add(witness.steps().len().saturating_sub(steps.len()));
    BoundedWitness::try_new(
        id,
        steps,
        omitted > 0,
        u64::try_from(omitted).unwrap_or(u64::MAX),
    )
    .map(Some)
    .map_err(|error| error.to_string())
}
