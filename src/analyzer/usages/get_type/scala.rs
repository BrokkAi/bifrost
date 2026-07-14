use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    ScalaTypeLookupResolution, scala_type_lookup_resolution,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    BoundedDefinitionLookup, IAnalyzer, ProjectFile, ScalaAnalyzer, resolve_analyzer,
};
use tree_sitter::Tree;

pub(super) fn resolve_scala_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(_scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_type(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_type("scala_parse_failed", "Scala source could not be parsed");
    };
    let Some(resolution) =
        scala_type_lookup_resolution(analyzer, support, file, source, tree.root_node(), site)
    else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Scala type",
                site.text
            ),
        );
    };
    match resolution {
        ScalaTypeLookupResolution::Type { fqn, target_kind } => {
            let candidates = support.fqn(&fqn);
            if candidates.is_empty() {
                return no_type(
                    "no_indexed_type_definition",
                    format!("`{fqn}` resolved as a Scala type but has no indexed definition"),
                );
            }
            candidates_outcome_with_target_kind(fqn, candidates, target_kind)
        }
        ScalaTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}
