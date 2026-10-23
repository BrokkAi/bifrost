use crate::analyzer::Language;
#[cfg(test)]
#[cfg(not(test))]
use crate::analyzer::resolution::ResolutionLookupSemanticRecipe;
use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason, SemanticId};

use crate::analyzer::store::{
    AnalyzerStore, PersistBatchTargets, WorkspaceConfigurationInput, WorkspaceFileRow, WorkspaceId,
};
use crate::analyzer::store_support::rust_root_test_support::parsed_operation_state;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
use git2::{ObjectType, Oid};

use crate::analyzer::store::WorkspacePackageFileRow;
#[cfg(test)]
#[cfg(not(test))]
use crate::analyzer::store::resolution_operation::java_reverse_rows::{
    JvmReverseCandidateOutcome, JvmReverseConfirmed,
};
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;

#[doc(hidden)]
pub const JAVA_ROOT_CONSUMER_PATH: &str = "src/use/Use.java";
#[doc(hidden)]
pub const JAVA_ROOT_PROVIDER_PATH: &str = "src/dep/Target.java";
#[doc(hidden)]
pub const JAVA_ROOT_DECOY_PATH: &str = "src/decoy/Target.java";
#[doc(hidden)]
pub const JAVA_ROOT_SOURCES: [(&str, &str); 3] = [
    (
        JAVA_ROOT_CONSUMER_PATH,
        "package use; import dep.Target; class Use { Target field; }",
    ),
    (
        JAVA_ROOT_PROVIDER_PATH,
        "package dep; public class Target {}",
    ),
    (
        JAVA_ROOT_DECOY_PATH,
        "package decoy; public class Target {}",
    ),
];

#[doc(hidden)]
pub fn assert_java_import_route_proof_delta(
    actual: &ResolutionCompletion,
    expected: &ResolutionCompletion,
    source_reference: SemanticId,
    implicit_project: bool,
) -> bool {
    if implicit_project
        && matches!(actual, ResolutionCompletion::Complete)
        && matches!(expected, ResolutionCompletion::Incomplete(_))
    {
        return true;
    }
    let (ResolutionCompletion::Incomplete(actual), ResolutionCompletion::Incomplete(expected)) =
        (actual, expected)
    else {
        panic!(
            "selected Java route changed completion outside an implicit project: actual {actual:?}, expected {expected:?}"
        )
    };
    assert!(
        actual.iter().all(|reason| expected.contains(reason)),
        "persisted Java route proof must only discharge oracle evidence: actual {actual:?}, expected {expected:?}"
    );
    let removed = expected
        .iter()
        .filter(|reason| !actual.contains(reason))
        .collect::<Vec<_>>();
    assert!(
        removed.len() <= 1,
        "only one import-site gap may be discharged"
    );
    let Some(removed) = removed.first() else {
        return false;
    };
    assert!(matches!(
        **removed,
        ResolutionIncompleteReason::UnsupportedSemantic(site)
            if site.ordinal() == source_reference.ordinal()
    ));
    true
}

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn publish_shared_jvm_consumer<A: LanguageAdapter>(
    store: &AnalyzerStore,
    root: &std::path::Path,
    workspace: &WorkspaceId,
    path: &str,
    source: &str,
    storage: &str,
    language: Language,
    adapter: &A,
    configuration: &[WorkspaceConfigurationInput],
) -> (
    crate::analyzer::store::WorkspaceSnapshotId,
    FileResolutionFacts,
) {
    let generation = store
        .ensure_language_epoch_value(storage, "j0-private-member-consumer-v1")
        .unwrap();
    store
        .ensure_resolution_producer_epoch(storage, language)
        .unwrap();
    let (state, facts) = parsed_operation_state(root, path, source, adapter);
    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
    let package = state.package_name.clone();
    let prepared =
        AnalyzerStore::prepare_parsed_blob(oid, storage, generation, adapter, state).unwrap();
    let (outcomes, _) =
        store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert!(
        outcomes.iter().all(|outcome| outcome.error.is_none()),
        "{outcomes:?}"
    );
    let snapshot = store
        .sync_workspace_inputs_for_workspace(
            workspace,
            storage,
            generation,
            &[WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid: oid,
            }],
            &[],
            &[],
            &[WorkspacePackageFileRow {
                package_name: package,
                rel_path: path.to_owned(),
            }],
            &[],
            &[],
            configuration,
            &[],
        )
        .unwrap();
    (snapshot, facts)
}

// Omit the owner projection before publication. The package-object case
// exercises the shared missing-source branch while retaining semantic binding.

#[cfg(test)]
# [cfg (not (test))] use crate :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: operation_fixture_support :: { mount_lookup , assert_empty_context_metrics } ;
