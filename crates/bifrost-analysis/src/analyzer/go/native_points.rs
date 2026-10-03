//! Go selected-context entry point, exercised before production cutover.

use super::GoAnalyzer;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::native_points::{
    NativePointContext, resolve_native_definition_bounded, resolve_native_type_bounded,
    unavailable_definition, unavailable_type,
};
use crate::analyzer::resolve_analyzer;
use crate::analyzer::store::resolution_operation::{
    GoDotImportContext, GoExternalPackageProvenance, GoSelectedExternalImport,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, DefinitionLookupStatus, ExactExternalCallProof,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

#[derive(Debug, Clone)]
pub(crate) struct GoNativeDefinitionResolution {
    pub(crate) outcome: DefinitionLookupOutcome,
    #[allow(dead_code)]
    pub(crate) exact_external_call: Option<ExactExternalCallProof>,
}

fn go_add_resolution_work(
    mut first: ReceiverAnalysisWork,
    second: ReceiverAnalysisWork,
) -> ReceiverAnalysisWork {
    first.setup_nodes = first.setup_nodes.saturating_add(second.setup_nodes);
    first.summary_expansions = first
        .summary_expansions
        .saturating_add(second.summary_expansions);
    first.scope_nodes = first.scope_nodes.saturating_add(second.scope_nodes);
    first
}

pub(crate) fn resolve_go_definition_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<DefinitionLookupOutcome> {
    match resolve_go_definition_with_evidence_bounded(query, after_open) {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value: value.outcome,
            work,
        },
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

pub(crate) fn resolve_go_definition_with_evidence_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<GoNativeDefinitionResolution> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: GoNativeDefinitionResolution {
                outcome: unavailable_definition(
                    query.site,
                    "native_analyzer_unavailable",
                    "Go analyzer is unavailable".into(),
                ),
                exact_external_call: None,
            },
            work: ReceiverAnalysisWork::default(),
        };
    };
    let mut selected_imports = Vec::new();
    let overlay = query.analyzer.semantic_model_overlay();
    match resolve_native_definition_bounded(
        &go.inner,
        query,
        |operation, path, cancellation| {
            prepare_context(
                go,
                operation,
                path,
                cancellation,
                overlay.as_deref(),
                &mut selected_imports,
            )
        },
        after_open,
    ) {
        BoundedResolution::Complete { value, work } => {
            if query.cancellation.is_some_and(|token| token.is_cancelled()) {
                return BoundedResolution::Cancelled { work };
            }
            let mut outcome = value;
            let mut exact_external_call = None;
            let external_projection_unavailable = outcome.status
                == DefinitionLookupStatus::Unavailable
                && outcome.diagnostics.iter().any(|diagnostic| {
                    diagnostic.kind == "native_definition_projection_unavailable"
                });
            if (matches!(
                outcome.status,
                DefinitionLookupStatus::Resolved
                    | DefinitionLookupStatus::Incomplete
                    | DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            ) || external_projection_unavailable)
                && !selected_imports.is_empty()
            {
                let parsed_tree = query
                    .tree
                    .is_none()
                    .then(|| crate::analyzer::usages::get_definition::parse_go_tree(query.source))
                    .flatten();
                if let Some(tree) = query.tree.or(parsed_tree.as_ref()) {
                    let query_with_tree = BoundedReceiverQuery {
                        tree: Some(tree),
                        ..query
                    };
                    let external_session =
                        crate::analyzer::usages::get_definition::resolution_session::ResolutionSession::bounded(
                            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                                max_scope_nodes: query.budget.max_scope_nodes.saturating_sub(work.scope_nodes),
                                max_summary_expansions: query.budget.max_summary_expansions.saturating_sub(work.summary_expansions),
                                ..query.budget
                            },
                            query.cancellation,
                        );
                    let selector = brokk_bifrost_go::graph::reference::go_selector_descriptor(
                        tree.root_node(),
                        query.site,
                    );
                    let external = selector.as_ref().and_then(|selector| {
                        if !matches!(selector.base.kind(), "identifier" | "package_identifier") {
                            return None;
                        }
                        if selector.focus_segment == 0 {
                            selected_imports.iter().find_map(|selected| {
                                crate::analyzer::usages::get_definition::go_native_external_import_binding_resolution(
                                    query_with_tree,
                                    go,
                                    &external_session,
                                    selected,
                                )
                                .map(|outcome| (outcome, None))
                            })
                        } else if selector.focus_segment == 1 {
                            selected_imports.iter().find_map(|selected| {
                                crate::analyzer::usages::get_definition::go_native_external_package_member_resolution(
                                    query_with_tree,
                                    go,
                                    &external_session,
                                    selected,
                                )
                            })
                        } else {
                            None
                        }
                    });
                    if let Some((external_outcome, proof)) = external {
                        outcome = external_outcome;
                        exact_external_call = proof;
                    } else if let Some((external_outcome, proof)) =
                        crate::analyzer::usages::get_definition::go_native_external_receiver_call_resolution(
                            query_with_tree,
                            &external_session,
                            &selected_imports,
                        )
                    {
                        outcome = external_outcome;
                        exact_external_call = Some(proof);
                    }
                    match external_session.finish((outcome, exact_external_call)) {
                        BoundedResolution::Complete {
                            value: (outcome, exact_external_call),
                            work: external_work,
                        } => {
                            return BoundedResolution::Complete {
                                value: GoNativeDefinitionResolution {
                                    outcome,
                                    exact_external_call,
                                },
                                work: go_add_resolution_work(work, external_work),
                            };
                        }
                        BoundedResolution::Exceeded {
                            limit,
                            work: external_work,
                        } => {
                            return BoundedResolution::Exceeded {
                                limit,
                                work: go_add_resolution_work(work, external_work),
                            };
                        }
                        BoundedResolution::Cancelled {
                            work: external_work,
                        } => {
                            return BoundedResolution::Cancelled {
                                work: go_add_resolution_work(work, external_work),
                            };
                        }
                    }
                }
            }
            BoundedResolution::Complete {
                value: GoNativeDefinitionResolution {
                    outcome,
                    exact_external_call,
                },
                work,
            }
        }
        BoundedResolution::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled { work },
    }
}

pub(crate) fn resolve_go_type_bounded(
    query: BoundedReceiverQuery<'_>,
    after_open: impl FnOnce(),
) -> BoundedResolution<TypeLookupOutcome> {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(query.analyzer) else {
        return BoundedResolution::Complete {
            value: unavailable_type(
                query.site,
                "native_analyzer_unavailable",
                "Go analyzer is unavailable".into(),
            ),
            work: ReceiverAnalysisWork::default(),
        };
    };
    let mut selected_imports = Vec::new();
    let overlay = query.analyzer.semantic_model_overlay();
    resolve_native_type_bounded(
        &go.inner,
        query,
        |operation, path, cancellation| {
            prepare_context(
                go,
                operation,
                path,
                cancellation,
                overlay.as_deref(),
                &mut selected_imports,
            )
        },
        after_open,
    )
}

fn prepare_context(
    go: &GoAnalyzer,
    operation: &crate::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    path: &str,
    cancellation: &crate::CancellationToken,
    overlay: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
    selected_imports: &mut Vec<GoSelectedExternalImport>,
) -> crate::analyzer::store::Result<NativePointContext> {
    let snapshots = go.inner.selected_workspace_snapshots();
    let (Some(snapshot), Some(profile)) = (snapshots.get("go"), go.native_context_profile()) else {
        return Ok(NativePointContext::Unavailable);
    };
    let Some(context) = go
        .inner
        .analyzer_store()
        .selected_go_context(snapshot, &profile)?
    else {
        return Ok(NativePointContext::Unavailable);
    };
    let context_id = context.context_id;
    Ok(
        match operation.go_selected_import_context(context_id, path, cancellation)? {
            GoDotImportContext::Ready(context) => {
                *selected_imports =
                    operation.go_selected_external_imports(context_id, path, cancellation)?;
                let packages =
                    crate::analyzer::go::package_identity::GoOverlayPackages::new(overlay);
                for import_path in
                    operation.go_selected_unresolved_imports(context_id, path, cancellation)?
                {
                    if selected_imports
                        .iter()
                        .any(|selected| selected.source_spelling == import_path)
                    {
                        continue;
                    }
                    let Some(identity) = packages.modeled_package_identity(&import_path) else {
                        continue;
                    };
                    selected_imports.push(GoSelectedExternalImport {
                        source_spelling: import_path.clone(),
                        import_path,
                        package_name: identity.package_name,
                        provenance: GoExternalPackageProvenance::SemanticModel {
                            symbol_id: identity.symbol_id,
                            pack_id: identity.pack_id,
                            pack_digest: identity.pack_digest,
                            record_id: identity.record_id,
                        },
                    });
                }
                NativePointContext::Ready(context)
            }
            GoDotImportContext::Unavailable => NativePointContext::Unavailable,
            GoDotImportContext::Cancelled => NativePointContext::Cancelled,
        },
    )
}

#[cfg(test)]
#[path = "native_points/tests.rs"]
mod tests;

/// The rollout probe's view of the native Go point resolver.
pub(crate) struct GoNativeRolloutPoints;

impl crate::analyzer::languages::StructuralReceiverResolver for GoNativeRolloutPoints {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome> {
        resolve_go_type_bounded(query, || {})
    }

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        resolve_go_definition_bounded(query, || {})
    }
}
