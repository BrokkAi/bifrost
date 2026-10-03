//! Indexed source-owned demand inventory. Query results live for one demand.
use super::super::*;

pub(crate) fn terminal_halves(
    ready: &ReadySelectedResolution<'_, '_>,
    demands: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Vec<CandidatePathIdentity>> {
    let persisted = ready.lexical_source();
    let mut identities = Vec::new();
    let mut collect = |halves: &[SelectedRootPathHalf]| {
        for half in halves {
            if let SelectedRootPathHalf::Import {
                identity, demand, ..
            }
            | SelectedRootPathHalf::Reference {
                identity, demand, ..
            } = half
                && demands.contains(demand)
            {
                identities.push(*identity);
            }
        }
        Ok(!cancellation.is_cancelled())
    };
    let outcome = persisted.visit_root_import_half_pages_for_demands(
        demands,
        cancellation,
        &mut crate::analyzer::resolution::FactPageVisitor::new(&mut collect),
    )?;
    if outcome.is_cancelled() {
        return Ok(Vec::new());
    }
    // The indexed reader includes ordinary and active stage terminal halves.
    identities.sort_unstable();
    identities.dedup();
    Ok(identities)
}
