//! Request-local selection of the production Python environment.

pub(crate) mod definition_lookup;
pub mod definitions;

use super::{PythonAnalyzer, native_environment::python_environment_root};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::native_points::open_native_point_operation;
use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;
use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::PythonSummaryProfile;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperation, SelectedResolutionOperationOpenOutcome,
};
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError, WorkspaceSnapshotId};

pub(super) type PythonEnvironmentReconcileState =
    Option<std::result::Result<WorkspaceSnapshotId, (WorkspaceSnapshotId, String)>>;

pub use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::PythonSelectedEnvironment;

pub struct PythonNativeRequest<'a> {
    pub operation: Box<SelectedResolutionOperation<'a, 'a>>,
    pub environment: PythonSelectedEnvironment,
}

/// Unavailable kinds: python_environment_unreconciled,
/// python_environment_unavailable, native_unavailable, and native_stale.
pub enum PythonNativeOpen<'a> {
    Ready(PythonNativeRequest<'a>),
    Unavailable { kind: &'static str, message: String },
    Cancelled,
}

fn workspace_profile(
    python: &PythonAnalyzer,
    cancellation: &CancellationToken,
) -> PythonSummaryProfile {
    super::runtime_artifact::python_production_summary_profile(
        python.inner.project(),
        None,
        &DependencyPackLimits::default(),
        Some(cancellation),
    )
    .expect("Workspace authority does not verify an external runtime")
}

impl PythonAnalyzer {
    /// Return only the reconcile outcome for this exact selected snapshot.
    pub(super) fn reconcile_outcome_for(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Option<std::result::Result<(), String>> {
        match self
            .native_environment_reconcile
            .read()
            .expect("Python reconcile lock poisoned")
            .as_ref()
        {
            Some(Ok(completed)) if completed == snapshot => Some(Ok(())),
            Some(Err((failed, message))) if failed == snapshot => Some(Err(message.clone())),
            _ => None,
        }
    }

    /// Publish coordinated native fixture inputs without selecting native product dispatch.
    /// Differential tests use it to keep a legacy product oracle while the native
    /// side reads the same store; it goes away with the trial selector.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn prepare_native_environment_for_test(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
        use brokk_bifrost_core::analyzer::Language;

        let snapshots = self.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("python").expect("selected Python snapshot");
        let project = self.inner.project();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(
                &brokk_bifrost_analysis::analyzer::parser_language_for(Language::Python)
                    .expect("Python grammar"),
            )
            .expect("compatible Python grammar");
        for file in project.analyzable_files(Language::Python)? {
            let source = project.read_source(&file)?;
            let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())?;
            let tree = parser.parse(&source, None).expect("Python fixture tree");
            let mut parsed =
                brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
                    project, &file, &source, &tree,
                );
            parsed.add_file_scope(&file, &source);
            let state = TreeSitterAnalyzer::<super::PythonAdapter>::file_state_from_parsed(
                source,
                parsed,
                false,
                Some(Vec::new()),
                true,
            );
            self.inner
                .analyzer_store()
                .write_parsed_blob_at_generation(
                    &file,
                    oid,
                    "python",
                    snapshot.generation,
                    self.inner.adapter(),
                    &state,
                )?;
        }
        self.reconcile_native_environment(cancellation)
    }

    pub(super) fn reconcile_native_environment(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let snapshots = self.inner.selected_workspace_snapshots();
        let snapshot = snapshots.get("python").expect("selected Python snapshot");
        *self
            .native_environment_reconcile
            .write()
            .expect("Python reconcile lock poisoned") = None;
        // The inner build flushes native blob rows before cold reconciliation.
        // WorkspaceAnalyzer updates every delegate before invoking this hook,
        // so reconciliation reads the fully published selected snapshot.
        let receipt = self.inner.analyzer_store().reconcile_python_environment(
            snapshot,
            workspace_profile(self, cancellation),
            python_environment_root(self.inner.project().root().to_owned()),
            cancellation,
        );
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(error) => {
                *self
                    .native_environment_reconcile
                    .write()
                    .expect("Python reconcile lock poisoned") =
                    Some(Err((snapshot.clone(), error.to_string())));
                return Err(error);
            }
        };
        let state = if !receipt.failed.is_empty() {
            eprintln!(
                "python.unit_summary_failed: Python unit summaries were not published for {:?}",
                receipt.failed
            );
            Some(Err((
                snapshot.clone(),
                format!(
                    "Python environment failed for snapshot {snapshot:?}: {:?}",
                    receipt.failed
                ),
            )))
        } else if receipt.cancelled {
            None
        } else {
            Some(Ok(snapshot.clone()))
        };
        *self
            .native_environment_reconcile
            .write()
            .expect("Python reconcile lock poisoned") = state;
        Ok(())
    }
}

pub fn open_python_native_request<'a>(
    python: &'a PythonAnalyzer,
    cancellation: &CancellationToken,
) -> std::result::Result<PythonNativeOpen<'a>, StoreError> {
    if cancellation.is_cancelled() {
        return Ok(PythonNativeOpen::Cancelled);
    }
    let profile = workspace_profile(python, cancellation);
    let snapshots = python.inner.selected_workspace_snapshots();
    let snapshot = snapshots.get("python").expect("selected Python snapshot");
    match python.reconcile_outcome_for(snapshot) {
        Some(Ok(())) => {}
        Some(Err(message)) => {
            return Ok(PythonNativeOpen::Unavailable {
                kind: "python_environment_unavailable",
                message,
            });
        }
        None => {
            return Ok(PythonNativeOpen::Unavailable {
                kind: "python_environment_unreconciled",
                message: format!(
                    "Python environment has not been reconciled for snapshot {snapshot:?}, Workspace profile {profile:?}"
                ),
            });
        }
    }
    let Some(summary) = python
        .inner
        .analyzer_store()
        .python_selected_summary(snapshot, &profile)?
    else {
        return Ok(PythonNativeOpen::Unavailable {
            kind: "python_environment_unavailable",
            message: format!(
                "Python environment unavailable for snapshot {snapshot:?}, Workspace profile {profile:?}"
            ),
        });
    };
    let operation = match open_native_point_operation(&python.inner, cancellation)? {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => operation,
        SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
            return Ok(PythonNativeOpen::Unavailable {
                kind: "native_unavailable",
                message: format!("{reason:?}"),
            });
        }
        SelectedResolutionOperationOpenOutcome::Stale(reason) => {
            return Ok(PythonNativeOpen::Unavailable {
                kind: "native_stale",
                message: format!("{reason:?}"),
            });
        }
        SelectedResolutionOperationOpenOutcome::Cancelled => {
            return Ok(PythonNativeOpen::Cancelled);
        }
    };
    Ok(PythonNativeOpen::Ready(PythonNativeRequest {
        operation,
        environment: PythonSelectedEnvironment {
            summary,
            python_version: profile.python_version,
        },
    }))
}
