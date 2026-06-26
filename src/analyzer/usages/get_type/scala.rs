use super::{TypeBatchContext, TypeLookupOutcome, candidates_outcome, no_type};
use crate::analyzer::usages::get_definition::scala_type_lookup_fqn;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile, ScalaAnalyzer, resolve_analyzer};
use tree_sitter::Tree;

pub(super) fn resolve_scala_type(
    analyzer: &dyn IAnalyzer,
    context: &mut TypeBatchContext,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_type(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_type("scala_parse_failed", "Scala source could not be parsed");
    };
    let support = analyzer.definition_lookup_index();
    let types = context.scala_project_types(scala);
    let Some(fqn) = scala_type_lookup_fqn(
        analyzer,
        support,
        types.as_ref(),
        file,
        source,
        tree.root_node(),
        site,
    ) else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Scala type",
                site.text
            ),
        );
    };
    let candidates = support.fqn(&fqn);
    if candidates.is_empty() {
        return no_type(
            "no_indexed_type_definition",
            format!("`{fqn}` resolved as a Scala type but has no indexed definition"),
        );
    }
    candidates_outcome(fqn, candidates)
}
