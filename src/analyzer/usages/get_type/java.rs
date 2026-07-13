use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    JavaTypeLookupResolution, java_type_lookup_resolution,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{BoundedDefinitionLookup, IAnalyzer, ProjectFile};
use tree_sitter::Tree;

pub(super) fn resolve_java_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("java_parse_failed", "Java source could not be parsed");
    };
    let Some(resolution) =
        java_type_lookup_resolution(analyzer, file, source, tree.root_node(), site)
    else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Java type",
                site.text
            ),
        );
    };
    match resolution {
        JavaTypeLookupResolution::Type { fqn, target_kind } => {
            let candidates = support.fqn(&fqn);
            if candidates.is_empty() {
                return no_type(
                    "no_indexed_type_definition",
                    format!("`{fqn}` resolved as a Java type but has no indexed definition"),
                );
            }
            candidates_outcome_with_target_kind(fqn, candidates, target_kind)
        }
        JavaTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}
