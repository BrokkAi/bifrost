//! Trial-only native usage graph over one selected Python environment.
use super::{
    PythonAnalyzer,
    native_request::{PythonNativeOpen, open_python_native_request},
};
use brokk_bifrost_analysis::analyzer::languages::{
    EdgePassId, LanguageEdgeFailure, NativeMethodOverride, NativeWorkspaceGraphProvider,
};
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::Result;
use brokk_bifrost_analysis::analyzer::store_bridge::{
    native_graph::project_native_workspace_graph, python_graph::stage_python_graph_units,
};
use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;
use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome as Outcome;
use brokk_bifrost_analysis::analyzer::{IAnalyzer, ProjectFile};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::{cancellation::CancellationToken, hash::HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};

static REQUESTS: AtomicUsize = AtomicUsize::new(0);
/// Constant-size proof that the selected native provider executed.
#[doc(hidden)]
pub fn python_native_graph_requests_for_test() -> usize {
    REQUESTS.load(Ordering::Relaxed)
}

pub(super) struct PythonNativeWorkspaceGraphProvider;
impl NativeWorkspaceGraphProvider for PythonNativeWorkspaceGraphProvider {
    fn id(&self) -> EdgePassId {
        EdgePassId::Python
    }
    fn input_failure(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        let python = resolve_analyzer::<PythonAnalyzer>(analyzer)?;
        let missing = files
            .iter()
            .filter(|file| {
                brokk_bifrost_core::analyzer::common::language_for_file(file)
                    == brokk_bifrost_core::analyzer::Language::Python
                    && !python.inner.is_analyzed(file)
            })
            .cloned()
            .collect::<Vec<_>>();
        (!missing.is_empty()).then_some(LanguageEdgeFailure {
            reason: "selected Python source publication is unavailable",
            files: missing,
        })
    }
    fn method_override(
        &self,
        analyzer: &dyn IAnalyzer,
        method: &brokk_bifrost_analysis::analyzer::CodeUnit,
        cancellation: &CancellationToken,
    ) -> NativeMethodOverride {
        use brokk_bifrost_analysis::analyzer::usages::python_class_hierarchy::{
            PythonHierarchyReason, PythonOverrideOutcome,
        };
        let Some(provider) = analyzer.python_class_hierarchy_provider_for(method) else {
            return NativeMethodOverride::Incomplete {
                reason_kind: "method_override_incomplete",
                reason: "selected Python class hierarchy provider unavailable".into(),
            };
        };
        let answer = provider.method_override(method, Some(cancellation));
        match answer.outcome {
            PythonOverrideOutcome::Overrides => NativeMethodOverride::Overrides(
                answer
                    .target
                    .expect("complete override names its base method"),
            ),
            PythonOverrideOutcome::NoOverride => NativeMethodOverride::NoOverride,
            PythonOverrideOutcome::Unsupported
                if matches!(
                    answer.reason,
                    Some(
                        PythonHierarchyReason::NotClass | PythonHierarchyReason::NotEffectiveMember
                    )
                ) =>
            {
                NativeMethodOverride::NoOverride
            }
            _ => NativeMethodOverride::Incomplete {
                reason_kind: if answer.reason == Some(PythonHierarchyReason::VisitLimit) {
                    "method_override_limit"
                } else {
                    "method_override_incomplete"
                },
                reason: format!(
                    "Python upward override relation: {:?}, {:?}",
                    answer.outcome, answer.reason
                ),
            },
        }
    }

    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<Outcome> {
        self.project_graph(analyzer, files, cancellation, |_| {})
    }

    fn project_dead_code(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<Outcome> {
        self.project_graph(analyzer, files, cancellation, |builder| {
            builder.nominate_overrides(analyzer, self, cancellation);
        })
    }
}

impl PythonNativeWorkspaceGraphProvider {
    fn project_graph(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
        finish: impl FnOnce(&mut brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::NativeWorkspaceGraphBuilder),
    ) -> Result<Outcome> {
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
            return Ok(Outcome::Unavailable(
                "selected Python analyzer is unavailable".into(),
            ));
        };
        let generation = analyzer.project().analysis_generation();
        let mut request = match open_python_native_request(python, cancellation)? {
            PythonNativeOpen::Ready(request) => request,
            PythonNativeOpen::Cancelled => return Ok(Outcome::Cancelled),
            PythonNativeOpen::Unavailable { kind, message } => {
                return Ok(Outcome::Unavailable(format!("{kind}: {message}")));
            }
        };
        let (obligations, mut unplaced) = request
            .operation
            .python_graph_input_evidence(&request.environment, cancellation)?;
        unplaced.sort();
        unplaced.dedup();
        let callers = HashSet::from_iter(files.iter().cloned());
        let mut relative_import_routes = Vec::new();
        let outcome = project_native_workspace_graph(
            analyzer,
            &mut request.operation,
            &callers,
            UsageEcosystem::Python,
            cancellation,
            |operation, builder| {
                if !unplaced.is_empty() {
                    builder.note_scope_obligation(brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::WorkspaceUsageGraphScopeObligation {
                        code: "python_unknown_placement".into(),
                        message: format!("python_unknown_placement:{unplaced:?}"),
                    });
                }
                let staged = stage_python_graph_units(
                    operation,
                    analyzer,
                    request.environment,
                    files,
                    python.inner.analyzer_config().parallelism(),
                    cancellation,
                    &mut |source, edges| {
                        relative_import_routes.extend(
                            operation.python_graph_relative_import_routes(
                                &request.environment,
                                source.answers(),
                            )?,
                        );
                        builder.stage_batch(
                            analyzer,
                            source,
                            edges,
                            edges.edges().iter().cloned(),
                            cancellation,
                        );
                        Ok(())
                    },
                )?;
                for label in obligations {
                    let kind = label
                        .split_once(':')
                        .map_or(label.as_str(), |(kind, _)| kind)
                        .to_owned();
                    if kind == "python_unknown_placement"
                        || relative_import_routes
                            .iter()
                            .any(|(_, _, gap_label)| gap_label == &label)
                    {
                        continue;
                    }
                    if super::query_reason_is_scope(&kind) {
                        builder.note_scope_obligation(brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::WorkspaceUsageGraphScopeObligation {
                            code: kind,
                            message: label,
                        });
                        continue;
                    }
                    builder.note_incomplete_reason(EdgeIncompleteReason::UsageAnalysisFailed {
                        reason_kind: kind,
                        reason: label,
                    });
                }
                finish(builder);
                Ok(staged)
            },
        )?;
        if cancellation.is_cancelled() {
            return Ok(Outcome::Cancelled);
        }
        if analyzer.project().analysis_generation() != generation {
            return Ok(Outcome::Stale);
        }
        Ok(match outcome {
            Outcome::Complete(mut projection) => {
                relative_import_routes.sort();
                relative_import_routes.dedup();
                projection.relative_import_routes = relative_import_routes;
                if projection
                    .relative_import_routes
                    .iter()
                    .all(|(_, gap, _)| gap.is_none())
                {
                    Outcome::Complete(projection)
                } else {
                    Outcome::Incomplete(projection)
                }
            }
            Outcome::Incomplete(mut projection) => {
                relative_import_routes.sort();
                relative_import_routes.dedup();
                projection.relative_import_routes = relative_import_routes;
                Outcome::Incomplete(projection)
            }
            other => other,
        })
    }
}
