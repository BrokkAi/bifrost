use crate::CancellationToken;
use crate::analyzer::store::python_runtime::test_support::*;
use crate::analyzer::store::python_runtime::*;
use crate::analyzer::store::{AnalyzerStore, WorkspaceId};
use std::path::PathBuf;
use std::sync::Arc;
#[test]
fn existing_projection_lease_drop_reclaims_provider_acquisition() {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(
        AnalyzerStore::open_persistent(&temp.path().join("analyzer-cache.sqlite")).unwrap(),
    );
    let workspace_id = WorkspaceId("d".repeat(64));
    let snapshot =
        empty_python_snapshot(&store, &workspace_id, "python-runtime-projection-lease-v1");
    let (mut declared_environment, project_config) = declared_environment_fixture();
    declared_environment.root_slots.truncate(1);
    let publication = store
        .publish_python_runtime_providers(
            &snapshot,
            None,
            [0x44; 32],
            vec![PythonRuntimeEnvironmentInput {
                source_scope: PathBuf::from("."),
                status: PythonRuntimeStatus::Incomplete,
                diagnostic: None,
                artifacts: Vec::new(),
                frontiers: Vec::new(),
                declared_environment: Some(declared_environment),
                project_config: Some(project_config),
            }],
            &CancellationToken::default(),
        )
        .unwrap();

    let lease =
        crate::analyzer::workspace::WorkspaceProjectionLease::new(Arc::clone(&store), workspace_id);
    drop(lease);
    let reclaimed =
        store.with_python_runtime_acquisition(publication.acquisition_id, &snapshot, |_| Ok(()));
    assert!(reclaimed.is_err_and(|error| error.is_stale_generation()));
    store
        .read_source_transaction("python", snapshot.generation, |tx| {
            for table in [
                "python_runtime_declared_environments",
                "python_runtime_declared_roots",
                "python_runtime_declared_inputs",
                "python_runtime_declared_extras",
            ] {
                let count: i64 = tx
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "lease reclamation must cascade to {table}");
            }
            Ok(())
        })
        .unwrap();
}
