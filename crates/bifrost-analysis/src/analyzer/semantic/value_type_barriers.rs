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
