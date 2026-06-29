use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    CSharpTypeLookupResolution, csharp_type_lookup_resolution,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile};
use tree_sitter::Tree;

pub(super) fn resolve_csharp_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("csharp_parse_failed", "C# source could not be parsed");
    };
    let support = analyzer.definition_lookup_index();
    let Some(resolution) =
        csharp_type_lookup_resolution(analyzer, support, file, source, tree.root_node(), site)
    else {
        return no_type(
            "no_explicit_type",
            format!("`{}` does not have a supported explicit C# type", site.text),
        );
    };
    match resolution {
        CSharpTypeLookupResolution::Type {
            fqn,
            candidates,
            target_kind,
        } => candidates_outcome_with_target_kind(fqn, candidates, target_kind),
        CSharpTypeLookupResolution::InappropriateSymbolContext => no_type(
            "inappropriate_symbol_context",
            format!(
                "`{}` is a callable declaration name, not a type-bearing expression",
                site.text
            ),
        ),
    }
}
