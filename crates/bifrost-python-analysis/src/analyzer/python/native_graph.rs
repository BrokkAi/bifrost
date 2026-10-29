//! Trial-only native usage graph over one selected Python environment.
use super::{
    PythonAnalyzer,
    native_request::{PythonNativeOpen, open_python_native_request},
};
use brokk_bifrost_analysis::analyzer::languages::{
    EdgePassId, LanguageEdgeFailure, NativeWorkspaceGraphProvider,
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
    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
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
        let (obligations, _) = request
            .operation
            .python_graph_input_evidence(&request.environment, cancellation)?;
        let callers = HashSet::from_iter(files.iter().cloned());
        let outcome = project_native_workspace_graph(
            analyzer,
            &mut request.operation,
            &callers,
            UsageEcosystem::Python,
            cancellation,
            |operation, builder| {
                for label in obligations {
                    let kind = label
                        .split_once(':')
                        .map_or(label.as_str(), |(kind, _)| kind)
                        .to_owned();
                    builder.note_incomplete_reason(EdgeIncompleteReason::UsageAnalysisFailed {
                        reason_kind: kind,
                        reason: label,
                    });
                }
                stage_python_graph_units(
                    operation,
                    analyzer,
                    request.environment,
                    files,
                    cancellation,
                    &mut |source, edges| {
                        builder.stage_batch(
                            analyzer,
                            source,
                            edges,
                            edges.edges().iter().cloned(),
                            cancellation,
                        );
                        Ok(())
                    },
                )
            },
        )?;
        if cancellation.is_cancelled() {
            return Ok(Outcome::Cancelled);
        }
        if analyzer.project().analysis_generation() != generation {
            return Ok(Outcome::Stale);
        }
        Ok(outcome)
    }
}
