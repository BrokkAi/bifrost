//! Policy-independent contracts for classifying a value observation's type.
//!
//! Predicates describe types, not call transfers. A language proves their
//! meaning through `LanguageSupport`; flow engines decide whether a result
//! stops the policy's flow. These types store no cross-request answers.

pub use brokk_bifrost_semantic::analyzer::semantic::value_type_barriers::*;
/// Open a language's context once for a policy request, after chop discovery.
pub fn open_value_type_barrier_context<'a>(
    language: crate::analyzer::Language,
    analyzer: &'a dyn crate::analyzer::IAnalyzer,
    cancellation: &crate::CancellationToken,
) -> Result<
    Option<Box<dyn ValueTypeBarrierContext + 'a>>,
    crate::analyzer::semantic::SemanticProviderError,
> {
    let Some(support) = crate::analyzer::languages::language_support_for_hook(
        language,
        "value_type_barrier_context",
    ) else {
        return Ok(None);
    };
    support.value_type_barrier_context(analyzer, cancellation)
}

/// Dispatch a query-local observation without depending on language internals.
pub fn evaluate_value_type_barrier(
    language: crate::analyzer::Language,
    analyzer: &dyn crate::analyzer::IAnalyzer,
    observation: &BarrierObservation,
    predicate: ValueTypePredicate,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<ValueTypeBarrierDecision, crate::analyzer::semantic::SemanticProviderError> {
    let Some(support) =
        crate::analyzer::languages::language_support_for_hook(language, "value_type_barrier")
    else {
        return Ok(ValueTypeBarrierDecision::Undecided(
            ValueTypeBarrierReason::UnsupportedLanguage,
        ));
    };
    support.value_type_barrier(analyzer, observation, predicate, request)
}

use crate::analyzer::semantic::SemanticRequest;
use ValueTypeBarrierReason::{BudgetExceeded, Cancelled, UnavailableObservation};
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

/// Retain only the source files this request demanded, under its byte budget.
pub fn prepare_value_type_barrier_source<
    A: crate::analyzer::tree_sitter_analyzer::LanguageAdapter,
>(
    inner: &crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer<A>,
    syntax: &mut HashMap<ProjectFile, Arc<PreparedSyntaxTree>>,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
) -> Result<Arc<PreparedSyntaxTree>, ValueTypeBarrierReason> {
    if let Some(prepared) = syntax.get(file) {
        return Ok(Arc::clone(prepared));
    }
    let scope = crate::analyzer::i_analyzer::AnalyzerQueryScope::new(inner);
    let prepared = match inner.prepared_syntax_limited_cancellable(
        scope.token(),
        file,
        request.budget.remaining().source_bytes,
        Some(request.cancellation),
    ) {
        crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome::Available(
            _,
            prepared,
        ) => prepared,
        crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome::Cancelled => {
            return Err(Cancelled);
        }
        crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome::Exceeded(_) => {
            return Err(BudgetExceeded);
        }
        crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome::Unavailable
        | crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome::Refused(_) => {
            return Err(UnavailableObservation);
        }
    };
    if request
        .budget
        .admit_source(&prepared, prepared.source().len())
        .is_err()
    {
        return Err(BudgetExceeded);
    }
    syntax.insert(file.clone(), Arc::clone(&prepared));
    Ok(prepared)
}
