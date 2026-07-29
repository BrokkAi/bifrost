use super::{
    TypeLookupDiagnostic, TypeLookupOutcome, TypeLookupStatus, TypeLookupType, no_type, sort_units,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, ResolutionSession, cpp_type_lookup_resolution_in_session,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{CppAnalyzer, IAnalyzer, ProjectFile};
use crate::cancellation::CancellationToken;
use tree_sitter::Tree;

pub(crate) fn resolve_cpp_type_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    if !CppAnalyzer::receiver_query_supported(file) {
        return session.finish(TypeLookupOutcome {
            status: TypeLookupStatus::UnsupportedLanguage,
            reference: None,
            types: Vec::new(),
            diagnostics: vec![TypeLookupDiagnostic {
                kind: "cpp_c_receiver_unsupported".to_string(),
                message: "bounded receiver traversal is intentionally unsupported for plain C"
                    .to_string(),
            }],
            target_kind: TypeLookupTargetKind::ValueExpression,
        });
    }
    let Some(tree) = tree else {
        return session.finish(no_type(
            "cpp_parse_failed",
            "C++ source could not be parsed",
        ));
    };
    let Some(mut resolution) =
        cpp_type_lookup_resolution_in_session(analyzer, file, source, tree, site, &session)
    else {
        return session.finish(no_type(
            "no_explicit_type",
            format!(
                "`{}` does not have a supported structured C++ type",
                site.text
            ),
        ));
    };
    sort_units(&mut resolution.candidates);
    resolution.candidates.dedup();
    let status = if resolution.ambiguous {
        TypeLookupStatus::Ambiguous
    } else {
        TypeLookupStatus::Resolved
    };
    session.finish(TypeLookupOutcome {
        status,
        reference: None,
        types: vec![TypeLookupType {
            fqn: resolution.fqn,
            definitions: resolution.candidates,
        }],
        diagnostics: if status == TypeLookupStatus::Ambiguous {
            vec![TypeLookupDiagnostic {
                kind: "cpp_open_or_ambiguous_type".to_string(),
                message:
                    "C++ receiver type has multiple identities or crosses an open template boundary"
                        .to_string(),
            }]
        } else {
            Vec::new()
        },
        target_kind: resolution.target_kind,
    })
}
