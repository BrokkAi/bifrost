use super::{TypeLookupOutcome, candidates_outcome, no_type};
use crate::analyzer::usages::get_definition::java_type_lookup_fqn;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile};
use tree_sitter::Tree;

pub(super) fn resolve_java_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("java_parse_failed", "Java source could not be parsed");
    };
    let Some(fqn) = java_type_lookup_fqn(analyzer, file, source, tree.root_node(), site) else {
        return no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported explicit Java type",
                site.text
            ),
        );
    };
    let candidates = analyzer.definition_lookup_index().fqn(&fqn);
    if candidates.is_empty() {
        return no_type(
            "no_indexed_type_definition",
            format!("`{fqn}` resolved as a Java type but has no indexed definition"),
        );
    }
    candidates_outcome(fqn, candidates)
}
