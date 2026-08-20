use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::kotlin::KotlinAnalyzer;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, KotlinDefinitionProvider, KotlinTypeLookupResolution, ResolutionSession,
    kotlin_type_lookup_resolution_in_session,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{BoundedDefinitionLookup, IAnalyzer, ProjectFile, resolve_analyzer};
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use tree_sitter::Tree;

/// Bounded Kotlin type resolution, serving both `get_type_by_location` and the
/// receiver-query path (issues #1238, #1242): one resolver, so a receiver query
/// and a type request cannot disagree about what a Kotlin expression's type is.
///
/// The type itself is worked out by the definition resolver, which already
/// knows how to type a Kotlin expression; this turns the fully-qualified name
/// it returns into indexed declarations, or explains why there is none.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_kotlin_type_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "kotlin_analyzer_unavailable",
            "Kotlin analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_type(
            "kotlin_parse_failed",
            "Kotlin source could not be parsed",
        ));
    };
    let support = KotlinDefinitionProvider::new(kotlin, &session);
    let resolution = kotlin_type_lookup_resolution_in_session(
        analyzer,
        token,
        &support,
        &session,
        file,
        source,
        tree.root_node(),
        site,
    );
    let outcome = kotlin_type_outcome(&support, site, resolution);
    session.finish(outcome)
}

fn kotlin_type_outcome(
    support: &dyn BoundedDefinitionLookup,
    site: &ResolvedReferenceSite,
    resolution: Option<KotlinTypeLookupResolution>,
) -> TypeLookupOutcome {
    match resolution {
        Some(KotlinTypeLookupResolution::Type { fqn, target_kind }) => {
            let candidates = support.fqn_in_any_language(&fqn);
            if candidates.is_empty() {
                return no_type(
                    "no_indexed_type_definition",
                    format!("`{fqn}` resolved as a Kotlin type but has no indexed definition"),
                );
            }
            candidates_outcome_with_target_kind(fqn, candidates, target_kind)
        }
        Some(KotlinTypeLookupResolution::InappropriateSymbolContext) => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
        None => no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a proven Kotlin type at this location",
                site.text
            ),
        ),
    }
}
