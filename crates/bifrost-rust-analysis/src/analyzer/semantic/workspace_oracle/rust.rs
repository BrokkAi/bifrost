//! Rust-only semantic-model APIs used by authored Rust policy packs.

use crate::analyzer::rust::std_types::rust_std_builtin_call as classify_rust_std_builtin_call;

pub use crate::analyzer::rust::std_types::RustStdBuiltinCall;

pub use crate::analyzer::rust::std_types::RustStdBuiltinTransfer;

use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_source_for_procedure;

use brokk_bifrost_semantic::analyzer::semantic::ir::CallSiteHandle;

use crate::analyzer::semantic::SemanticProviderError;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
/// The reviewed Rust std operation a call site invokes, when the resolver or
/// the call's literal structure proves its identity (#3757).
///
/// The operations are the in-code std fact table's: Bifrost-authored facts
/// that a caller may install as curated call models at the derived tier. An
/// unavailable source answers `None`, which leaves the call to its ordinary
/// resolution and models.
pub fn rust_std_builtin_call(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
) -> Result<Option<RustStdBuiltinCall>, SemanticProviderError> {
    let procedure = call.procedure();
    if procedure.artifact().key().language() != LanguageDialect::Standard(Language::Rust) {
        return Ok(None);
    }
    let Some(row) = procedure.semantics().call_site(call.id()) else {
        return Ok(None);
    };
    let Some(mapping) = procedure.semantics().source_mapping(row.source) else {
        return Ok(None);
    };
    let Some((file, source)) = exact_source_for_procedure(workspace, procedure, usize::MAX)? else {
        return Ok(None);
    };
    let span = mapping.locator.anchor().span();
    Ok(classify_rust_std_builtin_call(
        workspace.analyzer(),
        &file,
        &source,
        span.start_byte() as usize..span.end_byte() as usize,
    ))
}
