//! Rust-only semantic-model APIs used by authored Rust policy packs.

use crate::analyzer::rust::std_types::rust_std_builtin_call as classify_rust_std_builtin_call;

pub use crate::analyzer::rust::std_types::RustStdBuiltinCall;

pub use crate::analyzer::rust::std_types::RustStdBuiltinTransfer;

#[doc(hidden)]
pub use crate::analyzer::rust::std_types::{
    RustCloneCertificate, RustCloneImplementation, RustCloneIncomplete, RustCloneProof,
    RustCloneVerdict, RustModelDeclaration,
};

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

/// A declared local/parameter String identity, without inferred call results.
pub(crate) fn rust_std_direct_string_receiver(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
) -> Result<bool, SemanticProviderError> {
    let procedure = call.procedure();
    if procedure.artifact().key().language() != LanguageDialect::Standard(Language::Rust) {
        return Ok(false);
    }
    let Some(row) = procedure.semantics().call_site(call.id()) else {
        return Ok(false);
    };
    let Some(mapping) = procedure.semantics().source_mapping(row.source) else {
        return Ok(false);
    };
    let Some((file, source)) = exact_source_for_procedure(workspace, procedure, usize::MAX)? else {
        return Ok(false);
    };
    let span = mapping.locator.anchor().span();
    Ok(
        crate::analyzer::rust::std_types::rust_std_direct_string_receiver(
            workspace.analyzer(),
            &file,
            &source,
            span.start_byte() as usize..span.end_byte() as usize,
        ),
    )
}

/// Whether a Rust call site is a method-call `clone` whose selection is proven
/// to be std::clone::Clone's, on the receiver's own type (#11547). Internal
/// engine API for policy consumers, not a product surface.
///
/// Only `RustCloneVerdict::Certified` names the selected implementation. It
/// does not prove that the implementation copies the receiver's state: a
/// custom `impl Clone` may return anything, and a derived one calls the
/// fields' own `Clone`. The consumer establishes copy semantics separately.
/// The proof carries the reads it depended on in `receipt`; replay it into
/// the consumer's own query with `QueryReadReceipt::replay`. A call site
/// outside Rust, or without a source mapping, is `NotClone`; an unavailable
/// exact source is an operational `ProofStopped`.
#[doc(hidden)]
pub fn rust_clone_certificate(
    workspace: &WorkspaceAnalyzer,
    call: &CallSiteHandle,
) -> Result<RustCloneProof, SemanticProviderError> {
    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
    let analyzer = workspace.analyzer();
    let empty = |verdict| {
        let ((), receipt) = QueryReadReceipt::capture(analyzer, || ());
        RustCloneProof { verdict, receipt }
    };
    let procedure = call.procedure();
    if procedure.artifact().key().language() != LanguageDialect::Standard(Language::Rust) {
        return Ok(empty(RustCloneVerdict::NotClone));
    }
    let Some(row) = procedure.semantics().call_site(call.id()) else {
        return Ok(empty(RustCloneVerdict::NotClone));
    };
    let Some(mapping) = procedure.semantics().source_mapping(row.source) else {
        return Ok(empty(RustCloneVerdict::NotClone));
    };
    let Some((file, source)) = exact_source_for_procedure(workspace, procedure, usize::MAX)? else {
        return Ok(crate::analyzer::rust::std_types::rust_clone_source_unavailable(analyzer));
    };
    let span = mapping.locator.anchor().span();
    Ok(
        crate::analyzer::rust::std_types::rust_modeled_clone_certificate(
            analyzer,
            &file,
            &source,
            span.start_byte() as usize..span.end_byte() as usize,
        ),
    )
}
