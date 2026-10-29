//! Trial definition points over the request's selected Python environment.

use super::definition_lookup::resolve_definition_bounded;
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionResolution, cancelled, exceeded_budget,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

/// Always return the native answer under the trial, including native refusals.
pub fn trial_definition(query: BoundedReceiverQuery<'_>) -> Option<DefinitionResolution> {
    if !super::super::trial_native_python_selected() {
        return None;
    }
    Some(match resolve_definition_bounded(query) {
        BoundedResolution::Complete { value, .. } => value.into(),
        BoundedResolution::Exceeded { limit, .. } => exceeded_budget(
            limit,
            format!(
                "Python definition resolution exceeded its {} budget",
                limit.as_str()
            ),
        )
        .into(),
        BoundedResolution::Cancelled { .. } => {
            cancelled("Python definition resolution was cancelled").into()
        }
    })
}
