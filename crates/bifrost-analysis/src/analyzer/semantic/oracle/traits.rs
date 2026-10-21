use crate::analyzer::semantic::ir::CallSiteHandle;
use crate::analyzer::semantic::oracle::dispatch::DispatchResult;
use crate::analyzer::semantic::oracle::model::OracleCallContext;
use crate::analyzer::semantic::provider::{
    SemanticOutcome, SemanticProviderError, SemanticRequest,
};
// Keep the old overlay path even when consumers use the root re-export.
#[allow(unused_imports)]
pub use brokk_bifrost_semantic::analyzer::semantic::oracle::traits::*;
/// Location-first whole-program dispatch over one exact semantic call site.
pub trait DispatchOracle {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError>;
    /// Resolve under an exact bounded caller suffix. Providers that do not
    /// consume contextual proof retain their context-independent answer.
    fn resolve_call_in_context(
        &self,
        call: &CallSiteHandle,
        _context: &OracleCallContext,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.resolve_call(call, request)
    }
}
