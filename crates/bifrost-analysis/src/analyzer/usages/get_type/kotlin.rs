use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    KotlinTypeLookupResolution, kotlin_type_lookup_resolution,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{BoundedDefinitionLookup, IAnalyzer, ProjectFile};
use tree_sitter::Tree;

/// Answer `get_type_by_location` for Kotlin (issue #1238).
///
/// The type itself is worked out by the definition resolver, which already
/// knows how to type a Kotlin expression; this turns the fully-qualified name
/// it returns into indexed declarations, or explains why there is none.
pub(crate) fn resolve_kotlin_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("kotlin_parse_failed", "Kotlin source could not be parsed");
    };
    let Some(resolution) =
        kotlin_type_lookup_resolution(analyzer, support, file, source, tree.root_node(), site)
    else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a proven Kotlin type at this location",
                site.text
            ),
        );
    };
    match resolution {
        KotlinTypeLookupResolution::Type { fqn, target_kind } => {
            let candidates = support.fqn_in_any_language(&fqn);
            if candidates.is_empty() {
                return no_type(
                    "no_indexed_type_definition",
                    format!("`{fqn}` resolved as a Kotlin type but has no indexed definition"),
                );
            }
            candidates_outcome_with_target_kind(fqn, candidates, target_kind)
        }
        KotlinTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}
