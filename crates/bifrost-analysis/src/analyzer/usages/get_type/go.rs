use super::{
    TypeLookupDiagnostic, TypeLookupOutcome, candidates_outcome_with_target_kind,
    exact_semantic_model_type_outcome, no_type,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, GoDefinitionProvider, GoTypeLookupResolutionKind, go_type_lookup_resolution,
    with_bounded_go_definition_provider,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use tree_sitter::Tree;

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_go_type_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    with_bounded_go_definition_provider(
        analyzer,
        budget,
        cancellation,
        || no_type("go_analyzer_unavailable", "Go analyzer is unavailable"),
        |support| resolve_go_type_with_provider(analyzer, token, support, file, source, tree, site),
    )
}

fn resolve_go_type_with_provider(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn GoDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(tree) = tree else {
        return no_type("go_parse_failed", "Go source could not be parsed");
    };
    let Some(resolution) = go_type_lookup_resolution(
        analyzer,
        token,
        support,
        file,
        source,
        tree.root_node(),
        site,
    ) else {
        return no_type(
            "go_no_supported_type",
            format!("`{}` does not have a supported explicit Go type", site.text),
        );
    };

    let result_fqn = resolution.result_fqn();
    let candidates = support.fqn(&resolution.fqn);
    if candidates.is_empty() {
        if let Some(mut outcome) = exact_semantic_model_type_outcome(
            analyzer,
            file,
            Language::Go,
            &resolution.fqn,
            TypeLookupTargetKind::ValueExpression,
        ) {
            for ty in &mut outcome.types {
                ty.fqn.clone_from(&result_fqn);
            }
            return outcome;
        }
        return no_type(
            "go_no_indexed_type_definition",
            format!(
                "`{}` resolved as a Go type but has no indexed definition",
                result_fqn
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
            result_fqn,
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
        result_fqn,
        candidates,
        TypeLookupTargetKind::ValueExpression,
    )
}
