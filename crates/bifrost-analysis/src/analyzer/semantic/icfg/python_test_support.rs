use crate::analyzer::semantic::SemanticBudget;
use crate::analyzer::semantic::icfg::WorkspaceIcfgProvider;
use crate::analyzer::semantic::icfg::*;
use crate::analyzer::semantic::ids::CallSiteId;
use crate::analyzer::semantic::ir::artifact::ProcedureHandle;
use crate::analyzer::semantic::provider::SemanticRequest;
use crate::cancellation::CancellationToken;
#[doc(hidden)]
pub fn assert_failed_transfer_retry_pays_source(
    provider: &WorkspaceIcfgProvider<'_>,
    caller: &ProcedureHandle,
    retry_call: CallSiteId,
    source_len: usize,
    cancellation: &CancellationToken,
) {
    let session = provider
        .outcome_cache
        .dispatch_sessions
        .lock()
        .expect("query-local dispatch session cache is not poisoned")
        .values()
        .next()
        .cloned()
        .expect("failed transfer leaves a retryable empty session");
    assert!(
        !session
            .lock()
            .expect("prepared dispatch session is not poisoned")
            .retains_exact_source(),
        "syntax charged only to a failed transfer cannot remain published",
    );

    let mut retry_budget = SemanticBudget::default();
    let retry = provider
        .call_transfers(
            caller,
            retry_call,
            &mut SemanticRequest::new(&mut retry_budget, cancellation),
        )
        .expect("retry after a failed call-transfer projection");
    assert!(retry.available_value().is_some(), "{retry:#?}");
    assert_eq!(retry.work().source_bytes, source_len);
    assert_eq!(
        retry_budget.used().source_bytes,
        retry_budget.root_work_peak().source_bytes + source_len,
    );
    assert_eq!(retry_budget.resident().source_bytes, source_len);
}
