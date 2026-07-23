use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, PythonDefinitionProvider, ResolutionSession,
    python_type_lookup_resolution_bounded,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, resolve_analyzer};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(crate) fn resolve_python_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_type(
            "python_parse_failed",
            "Python source could not be parsed",
        ));
    };
    let support = PythonDefinitionProvider::new(python, &session);
    let Some(resolution) =
        python_type_lookup_resolution_bounded(&support, file, source, tree.root_node(), site)
    else {
        return session.finish(no_type(
            "python_dynamic_receiver_unsupported",
            format!(
                "`{}` has no structurally proven Python type; untyped values, dynamic attributes, descriptors, decorators, and metaclasses remain open",
                site.text
            ),
        ));
    };
    let fqn = resolution.unit.fq_name();
    session.finish(candidates_outcome_with_target_kind(
        fqn,
        vec![resolution.unit],
        resolution.target_kind,
    ))
}
