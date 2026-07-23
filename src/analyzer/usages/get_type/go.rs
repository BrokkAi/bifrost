use super::{
    TypeLookupDiagnostic, TypeLookupOutcome, candidates_outcome_with_target_kind, no_type,
};
use crate::analyzer::usages::get_definition::{
    AnalyzerGoDefinitionProvider, BoundedResolution, GoDefinitionProvider,
    GoTypeLookupResolutionKind, ResolutionSession, go_type_lookup_resolution,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{GoAnalyzer, IAnalyzer, ProjectFile, resolve_analyzer};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(super) fn resolve_go_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return no_type("go_analyzer_unavailable", "Go analyzer is unavailable");
    };
    let support = AnalyzerGoDefinitionProvider::new(go);
    resolve_go_type_with_provider(analyzer, &support, file, source, tree, site)
}

pub(crate) fn resolve_go_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return session.finish(no_type(
            "go_analyzer_unavailable",
            "Go analyzer is unavailable",
        ));
    };
    let support = AnalyzerGoDefinitionProvider::bounded(go, &session);
    let outcome = resolve_go_type_with_provider(analyzer, &support, file, source, tree, site);
    session.finish(outcome)
}

fn resolve_go_type_with_provider(
    analyzer: &dyn IAnalyzer,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("go_parse_failed", "Go source could not be parsed");
    };
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

    if resolution.kind == GoTypeLookupResolutionKind::InterfaceMethodOwner {
        let Some(member_name) = resolution.member_name else {
            return no_type(
                "go_interface_method_owner_missing_member",
                "Go interface method owner lookup did not include the selected method name",
            );
        };
        let mut outcome = candidates_outcome_with_target_kind(
            resolution.fqn,
            candidates,
            TypeLookupTargetKind::MemberOwner { member_name },
        );
        outcome.diagnostics.push(TypeLookupDiagnostic {
            kind: "go_interface_method_owner".to_string(),
            message: "selected Go interface method belongs to this interface type".to_string(),
        });
        return outcome;
    }
    candidates_outcome_with_target_kind(
        resolution.fqn,
        candidates,
        TypeLookupTargetKind::ValueExpression,
    )
}
