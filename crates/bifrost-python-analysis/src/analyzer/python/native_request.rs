//! Request-local selection of the production Python environment.

pub(crate) mod definition_lookup;

use super::{PythonAnalyzer, native_environment::python_environment_root};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::native_points::open_native_point_operation_with_services;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;
use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::PythonSummaryProfile;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperation, SelectedResolutionOperationOpenOutcome,
};
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError, WorkspaceSnapshotId};
use brokk_bifrost_analysis::analyzer::{AuthorityInputs, FactSubject, Language};

pub(super) type PythonEnvironmentReconcileState =
    Option<std::result::Result<WorkspaceSnapshotId, (WorkspaceSnapshotId, String)>>;

pub use brokk_bifrost_analysis::analyzer::store::python_unit_summaries::PythonSelectedEnvironment;

pub struct PythonNativeRequest<'a> {
    pub snapshot: WorkspaceSnapshotId,
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
) -> std::result::Result<
    PythonSummaryProfile,
    super::runtime_artifact::PythonDeclaredEnvironmentError,
> {
    super::runtime_artifact::python_production_summary_profile(
        python.inner.project(),
        None, // A declared runtime is not yet consulted.
        &DependencyPackLimits::default(),
        Some(cancellation),
    )
}

/// The selected summary id of one (snapshot, profile) is plain data, but every
/// point operation of a request used to re-read it from the store (six
/// statements per open). Follow the Java import-context memo: a hit restores
/// the id and replays the read receipt of the cold lookup, so the caller's
/// ledger records the same reads; a cold lookup publishes; every refusal falls
/// back to the cold lookup. One slot, so the memo never grows with the
/// workspace; it dies with the analyzer's query read cache.
#[derive(Default)]
pub(super) struct PythonSelectedSummaryRequestMemo {
    published: std::sync::Mutex<Option<std::sync::Arc<PublishedSelectedSummary>>>,
    #[cfg(test)]
    pub(super) hits: std::sync::atomic::AtomicUsize,
}

/// Everything the store lookup depends on. The snapshot and profile are its
/// arguments; the language content and project generation are the identities
/// the sibling Python request memos also key on.
#[derive(PartialEq, Eq)]
struct PythonSelectedSummaryKey {
    snapshot: WorkspaceSnapshotId,
    profile: PythonSummaryProfile,
    language_content: StableDigest,
    project_generation: u64,
}

struct PublishedSelectedSummary {
    key: PythonSelectedSummaryKey,
    summary: i64,
    receipt: brokk_bifrost_analysis::analyzer::common::QueryCacheBuildReceipt,
}

fn selected_summary(
    python: &PythonAnalyzer,
    snapshot: &WorkspaceSnapshotId,
    profile: &PythonSummaryProfile,
) -> Result<Option<i64>> {
    let store = python.inner.analyzer_store();
    let Some(memo) = python.active_query_request_memo::<PythonSelectedSummaryRequestMemo>() else {
        return store.python_selected_summary(snapshot, profile);
    };
    let key = PythonSelectedSummaryKey {
        snapshot: snapshot.clone(),
        profile: profile.clone(),
        language_content: python.inner.language_content_identity(),
        project_generation: python.inner.project().analysis_generation(),
    };
    let published = memo
        .published
        .lock()
        .expect("Python selected summary memo poisoned")
        .clone();
    if let Some(published) = published.filter(|published| published.key == key) {
        #[cfg(test)]
        memo.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        published.receipt.replay();
        return Ok(Some(published.summary));
    }
    let (summary, receipt) =
        brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(python, || {
            store.python_selected_summary(snapshot, profile)
        });
    let summary = summary?;
    // An absent summary is not retained: reconciliation may publish it later.
    // A lookup that depended on budget or cancellation, or whose reads cannot
    // be replayed, is never retained either.
    if let Some(summary) = summary
        && !receipt.has_execution_dependences()
        && receipt.unattributed_reads() == 0
    {
        *memo
            .published
            .lock()
            .expect("Python selected summary memo poisoned") =
            Some(std::sync::Arc::new(PublishedSelectedSummary {
                key,
                summary,
                receipt,
            }));
    }
    Ok(summary)
}

/// The memo answers readiness, not the contents of the selected source summary.
/// Equal ready answers may therefore survive edits whose semantic reads replay.
pub(super) fn reconcile_outcome_answer<T, E>(
    outcome: Option<&std::result::Result<T, E>>,
) -> Option<StableDigest> {
    match outcome {
        Some(Ok(_)) => Some(StableDigest::sha256(b"python-reconcile-ready-v1")),
        None => Some(StableDigest::sha256(b"python-reconcile-unready-v1")),
        // Diagnostics can contain checkout paths and positions. As with Go's
        // selection errors, failed readiness cannot certify a reusable answer.
        Some(Err(_)) => None,
    }
}

fn reconcile_inputs(answer: Option<StableDigest>) -> AuthorityInputs<'static> {
    match answer {
        Some(answer) => AuthorityInputs::Fact {
            language: Language::Python,
            subject: FactSubject::Named {
                name: "reconcile".into(),
            },
            answer,
        },
        None => AuthorityInputs::Unnamed,
    }
}

impl PythonAnalyzer {
    /// Return only the reconcile outcome for this exact selected snapshot.
    pub(super) fn reconcile_outcome_for(
        &self,
        snapshot: &WorkspaceSnapshotId,
    ) -> Option<std::result::Result<(), String>> {
        self.native_environment_reconcile.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| match memo
                .read()
                .expect("Python reconcile lock poisoned")
                .as_ref()
            {
                Some(Ok(completed)) if completed == snapshot => Some(Ok(())),
                Some(Err((failed, message))) if failed == snapshot => Some(Err(message.clone())),
                _ => None,
            },
            // Readiness is guarded by the selected source/configuration snapshot
            // and the workspace summary profile. Installed runtime/provider proof
            // is checked separately by environment binding authority.
            |outcome| reconcile_inputs(reconcile_outcome_answer(outcome.as_ref())),
        )
    }

    fn set_reconcile_state(&self, state: PythonEnvironmentReconcileState) {
        let answer = reconcile_outcome_answer(state.as_ref());
        self.native_environment_reconcile.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| *memo.write().expect("Python reconcile lock poisoned") = state,
            |_| reconcile_inputs(answer),
        );
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
            let mut parsed = brokk_bifrost_python::declarations::parse_python_file(
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
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "python"),
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
        self.set_reconcile_state(None);
        // The inner build flushes native blob rows before cold reconciliation.
        // WorkspaceAnalyzer updates every delegate before invoking this hook,
        // so reconciliation reads the fully published selected snapshot.
        let receipt = self.inner.analyzer_store().reconcile_python_environment(
            snapshot,
            workspace_profile(self, cancellation)
                .map_err(|error| StoreError::new(error.to_string()))?,
            python_environment_root(self.inner.project().root().to_owned()),
            cancellation,
        );
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(error) => {
                self.set_reconcile_state(Some(Err((snapshot.clone(), error.to_string()))));
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
        self.set_reconcile_state(state);
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
    let profile = match workspace_profile(python, cancellation) {
        Ok(profile) => profile,
        Err(error) => {
            return Ok(PythonNativeOpen::Unavailable {
                kind: "python_environment_unavailable",
                message: error.to_string(),
            });
        }
    };
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
    let Some(summary) = selected_summary(python, snapshot, &profile)? else {
        return Ok(PythonNativeOpen::Unavailable {
            kind: "python_environment_unavailable",
            message: format!(
                "Python environment unavailable for snapshot {snapshot:?}, Workspace profile {profile:?}"
            ),
        });
    };
    let operation =
        match open_native_point_operation_with_services(&python.inner, python, cancellation)? {
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
        snapshot: snapshot.clone(),
        operation,
        environment: PythonSelectedEnvironment {
            summary,
            python_version: profile.python_version,
        },
    }))
}

// The operation borrows its caller's services for the lifetime of this request.
// Forward through the engine adapter so language-hook dispatch has one owner.
impl brokk_bifrost_core::analyzer::memo_attribution::ReadReuseRefusal for PythonAnalyzer {
    fn refuse_read_reuse(&self) {
        // PythonAnalyzer's concrete inner analyzer owns the shared recorder
        // override; forward to it rather than the IAnalyzer default no-op.
        brokk_bifrost_analysis::analyzer::IAnalyzer::refuse_read_reuse(&self.inner);
    }

    fn record_language_scope_read(&self, language: Language) {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        IAnalyzer::record_read(
            &self.inner,
            IAnalyzer::workspace_scope_read_key(&self.inner, &[language]),
        );
    }
}

impl brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedAnalyzerServices
    for PythonAnalyzer
{
    fn admit_selected_external_binding(
        &self,
        request: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedExternalBindingRequest<'_>,
        cancellation: &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedExternalBindingRead
    {
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services(self)
            .admit_selected_external_binding(request, cancellation)
    }
    fn declarations_named(
        &self,
        file: &brokk_bifrost_analysis::analyzer::ProjectFile,
        name: &str,
    ) -> Vec<brokk_bifrost_analysis::analyzer::CodeUnit> {
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services(self)
            .declarations_named(file, name)
    }
    fn verified_declaration(
        &self,
        expected: &brokk_bifrost_analysis::analyzer::CodeUnit,
    ) -> Option<brokk_bifrost_analysis::analyzer::CodeUnit> {
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services(self)
            .verified_declaration(expected)
    }
    fn external_inventory_providers(&self) -> Vec<String> {
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services(self)
            .external_inventory_providers()
    }
    fn active_models(
        &self,
    ) -> Option<
        std::sync::Arc<
            brokk_bifrost_analysis::analyzer::store::active_models::ResolvedActiveSemanticModels,
        >,
    > {
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services(self)
            .active_models()
    }
    fn model_authority(&self) -> Option<std::sync::Arc<dyn brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedModelAuthority + Send + Sync>>{
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services(self)
            .model_authority()
    }
}
