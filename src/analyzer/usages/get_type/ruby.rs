use super::{TypeLookupOutcome, candidates_outcome_with_target_kind, no_type};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, ResolutionSession, RubyDefinitionProvider,
    ruby_type_lookup_resolution_bounded,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{
    BoundedDefinitionLookup, IAnalyzer, ProjectFile, RubyAnalyzer, resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(crate) fn resolve_ruby_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "ruby_analyzer_unavailable",
            "Ruby analyzer is unavailable",
        ));
    };
    let Some(tree) = tree else {
        return session.finish(no_type(
            "ruby_parse_failed",
            "Ruby source could not be parsed",
        ));
    };
    let support = RubyDefinitionProvider::new(ruby, &session);
    let Some(resolution) =
        ruby_type_lookup_resolution_bounded(&support, file, source, tree.root_node(), site)
    else {
        return session.finish(no_type(
            "ruby_dynamic_receiver_unsupported",
            format!(
                "`{}` has no structurally proven Ruby type; dynamic dispatch, metaprogramming, inheritance, mixins, refinements, and method_missing remain open",
                site.text
            ),
        ));
    };
    let candidates = support.fqn(&resolution.fqn);
    if candidates.is_empty() {
        return session.finish(no_type(
            "ruby_no_indexed_type_definition",
            format!(
                "`{}` resolved as a Ruby type but has no exact indexed definition",
                resolution.fqn
            ),
        ));
    }
    let outcome =
        candidates_outcome_with_target_kind(resolution.fqn, candidates, resolution.target_kind);
    session.finish(outcome)
}
