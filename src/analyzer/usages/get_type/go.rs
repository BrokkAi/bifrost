use super::{TypeLookupDiagnostic, TypeLookupOutcome, candidates_outcome, no_type};
use crate::analyzer::usages::get_definition::{
    GoTypeLookupResolutionKind, go_type_lookup_resolution,
};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile};
use tree_sitter::Tree;

pub(super) fn resolve_go_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("go_parse_failed", "Go source could not be parsed");
    };
    let support = analyzer.definition_lookup_index();
    let Some(resolution) =
        go_type_lookup_resolution(analyzer, support, file, source, tree.root_node(), site)
    else {
        return no_type(
            "go_no_supported_type",
            format!("`{}` does not have a supported explicit Go type", site.text),
        );
    };

    let candidates = support.fqn(&resolution.fqn);
    if candidates.is_empty() {
        return no_type(
            "go_no_indexed_type_definition",
            format!(
                "`{}` resolved as a Go type but has no indexed definition",
                resolution.fqn
            ),
        );
    }

    let mut outcome = candidates_outcome(resolution.fqn, candidates);
    if resolution.kind == GoTypeLookupResolutionKind::InterfaceMethodOwner {
        outcome.diagnostics.push(TypeLookupDiagnostic {
            kind: "go_interface_method_owner".to_string(),
            message: "selected Go interface method belongs to this interface type".to_string(),
        });
    }
    outcome
}
