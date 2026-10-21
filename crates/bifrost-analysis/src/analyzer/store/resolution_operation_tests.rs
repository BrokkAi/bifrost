#[cfg(any(test, feature = "test-support"))]
pub(super) use super::selected_sql_trace::context_publication_work;
#[cfg(test)]
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;

#[cfg(any(test, feature = "test-support"))]
#[path = "native_query_plan_tests.rs"]
#[doc(hidden)]
pub mod native_query_plan_tests;

#[cfg(test)]
#[path = "resolution_operation_go_member_tests.rs"]
mod go_member_tests;
#[cfg(test)]
#[path = "resolution_operation_go_spelling_tests.rs"]
mod go_spelling_tests;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

#[cfg(test)]
use brokk_bifrost_test_macros::hardwon;

#[cfg(test)]
use git2::ObjectType;

#[cfg(test)]
use git2::Oid;

#[cfg(test)]
use rusqlite::params;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
use std::collections::BTreeSet;

use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use std::rc::Rc;

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use std::sync::atomic::Ordering;

#[cfg(test)]
use crate::CancellationToken;

#[cfg(test)]
use crate::analyzer::java::JavaAdapter;

#[cfg(test)]
use crate::analyzer::resolution::FactReferenceBatchAnswer;

#[cfg(test)]
use crate::analyzer::resolution::FactResolutionBatchSummary;

#[cfg(test)]
use crate::analyzer::resolution::FactReverseResolutionMetrics;

#[cfg(test)]
use crate::analyzer::resolution::LoweredSemanticRole;

#[cfg(test)]
use crate::analyzer::resolution::PreloadedFactResolutionService;

#[cfg(test)]
use crate::analyzer::resolution::SelectedFactOperationBlueprintConstruction;

#[cfg(test)]
use crate::analyzer::resolution::SelectedResolutionContextSet;

#[cfg(test)]
use crate::analyzer::resolution::SelectedResolutionContextValidationOutcome;

#[cfg(test)]
use crate::analyzer::resolution::SelectedSemanticLocator;

#[cfg(test)]
use crate::analyzer::resolution::SelectedTypedFactSource;

#[cfg(test)]
use crate::analyzer::Language;

#[cfg(test)]
use crate::analyzer::OverlayProject;

#[cfg(test)]
use crate::analyzer::Project;

#[cfg(test)]
use crate::analyzer::ProjectFile;

#[cfg(test)]
use crate::analyzer::store::file_state::FileState;

#[cfg(test)]
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

#[cfg(test)]
use super::super::AnalyzerStore;

#[cfg(test)]
use super::super::GenerationId;

#[cfg(test)]
use super::super::PersistBatchTargets;

#[cfg(test)]
use super::super::Result;

#[cfg(test)]
use super::super::StoreError;

#[cfg(test)]
use super::super::WorkspaceConfigurationInput;

#[cfg(test)]
use super::super::WorkspaceFileRow;

#[cfg(test)]
use super::super::WorkspaceId;

#[cfg(test)]
use super::super::WorkspaceSnapshots;

#[cfg(test)]
use super::super::resolution_selection::SelectedResolutionContentMountRequest;

#[cfg(test)]
use super::super::resolution_selection::SelectedResolutionLanguage;

#[cfg(test)]
use super::super::resolution_selection::SelectedResolutionOverlayMask;

#[cfg(test)]
use super::super::resolution_selection::SelectedResolutionStale;

#[cfg(test)]
use super::super::resolution_selection::SelectedResolutionUnavailable;

use super::*;

#[cfg(test)]
#[path = "resolution_operation_reverse_tests.rs"]
mod reverse_query_tests;

#[cfg(test)]
#[path = "resolution_operation_privacy_tests.rs"]
mod privacy_tests;

#[cfg(test)]
const WORKSPACE_ID: &str = "7171717171717171717171717171717171717171717171717171717171717171";
#[cfg(test)]
const SOURCE_PATH: &str = "src/A_Source.java";
#[cfg(test)]
const PROVIDER_PATH: &str = "src/B_Provider.java";
#[cfg(test)]
const REMOVED_PATH: &str = "src/C_Removed.java";
#[cfg(test)]
const SECOND_REPLACEMENT_PATH: &str = "src/D_Replacement.java";

#[cfg(test)]
/// The git blob oid of `RICH_JAVA_SOURCE`, which every persisted Java mount in
/// these fixtures carries.
///
/// A persisted mount's blob oid is the oid of the bytes on disk, and the lazy
/// interior rehashes the file it reads to prove it still has the selected
/// revision's source. A synthetic oid therefore reads as a changed file.
fn persisted_oid() -> Oid {
    Oid::hash_object(ObjectType::Blob, RICH_JAVA_SOURCE.as_bytes())
        .expect("hash the operation fixture source")
}

#[cfg(test)]
const RICH_JAVA_SOURCE: &str = r#"
package com.acme;
import dep.A;
import dep.*;
import static dep.Owner.FIELD;
import static dep.Owner.*;

public class Outer extends HierarchyBase {
    public class Nested {}
    public static int FIELD;
    public int qualifiedField;

    public static int method(int parameter) {
        return parameter;
    }

    public int use(A value) {
        int sourceOrderLocal = FIELD;
        this.qualifiedField = sourceOrderLocal;
        return method(value.hashCode());
    }
}
"#;

// Actual provider text replaces the former package/binder fact mutation.
#[cfg(test)]
const PROVIDER_JAVA_SOURCE: &str = r#"
package dep;
import dep.A;
import dep.*;
import static dep.Owner.FIELD;
import static dep.Owner.*;

public class Owner extends HierarchyBase {
    public class Nested {}
    public static int FIELD;
    public int qualifiedField;

    public static int method(int parameter) {
        return parameter;
    }

    public int use(A value) {
        int sourceOrderLocal = FIELD;
        this.qualifiedField = sourceOrderLocal;
        return method(value.hashCode());
    }
}
"#;

#[cfg(test)]
fn parsed_java_state(
    project_root: &Path,
    relative_path: &str,
) -> (Arc<FileState>, FileResolutionFacts) {
    parsed_operation_state(project_root, relative_path, RICH_JAVA_SOURCE, &JavaAdapter)
}

#[cfg(test)]
use super::selected_sql_trace::*;

#[cfg(test)]
struct ResolutionOperationFixture {
    store: AnalyzerStore,
    _project_root: tempfile::TempDir,
    project: MutableGenerationProject,
    workspace_id: WorkspaceId,
    snapshots: WorkspaceSnapshots,
    languages: Vec<SelectedResolutionLanguage>,
    generation: GenerationId,
    source_facts: FileResolutionFacts,
    provider_facts: FileResolutionFacts,
}

#[cfg(test)]
impl ResolutionOperationFixture {
    fn new() -> Self {
        let project_root = tempfile::tempdir().expect("operation test project root");
        let project = MutableGenerationProject::new(project_root.path(), Language::Java);
        let store = AnalyzerStore::open_ephemeral().expect("operation test store");
        let generation = store
            .ensure_language_epoch_value("java", "resolution-operation-test-v1")
            .expect("operation test language epoch");
        store
            .ensure_resolution_producer_epoch("java", Language::Java)
            .expect("operation test producer epoch");

        let (state, source_facts) = parsed_java_state(project_root.path(), SOURCE_PATH);
        let (_, provider_facts) = parsed_operation_source_state(
            project_root.path(),
            PROVIDER_PATH,
            PROVIDER_JAVA_SOURCE,
            &JavaAdapter,
        );
        let prepared = AnalyzerStore::prepare_parsed_blob(
            persisted_oid(),
            "java",
            generation,
            &JavaAdapter,
            state,
        )
        .expect("prepare operation Java blob through the production path");
        let (outcomes, _) =
            store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
        let workspace_id = WorkspaceId(WORKSPACE_ID.to_owned());
        let file_versions = [
            SOURCE_PATH,
            PROVIDER_PATH,
            REMOVED_PATH,
            SECOND_REPLACEMENT_PATH,
        ]
        .into_iter()
        .enumerate()
        .map(|(ordinal, path)| {
            (
                path.to_owned(),
                persisted_oid().to_string(),
                format!("{:064x}", ordinal + 1),
            )
        })
        .collect();
        let snapshots = persist_test_workspace_snapshot(
            &store,
            &workspace_id,
            "java",
            generation,
            file_versions,
        );
        Self {
            store,
            _project_root: project_root,
            project,
            workspace_id,
            snapshots,
            languages: vec![SelectedResolutionLanguage::new("java", Language::Java)],
            generation,
            source_facts,
            provider_facts,
        }
    }

    fn provider_replacement(&self) -> SelectedResolutionContentMountRequest {
        self.counterfactual_content(PROVIDER_PATH, RICH_JAVA_SOURCE, PROVIDER_JAVA_SOURCE)
    }

    fn published_content(&self, path: &str, source: &str) -> SelectedResolutionContentMountRequest {
        use super::super::resolution_publication::ResolutionContentPublicationOutcome;
        let (state, _) =
            parsed_operation_source_state(self._project_root.path(), path, source, &JavaAdapter);
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
            .expect("hash actual Java fixture content");
        let prepared =
            AnalyzerStore::prepare_parsed_blob(oid, "java", self.generation, &JavaAdapter, state)
                .expect("prepare actual Java fixture content");
        let ResolutionContentPublicationOutcome::Ready(content) = self
            .store
            .publish_selected_parsed_content(
                self.snapshots.get("java").expect("captured Java owner"),
                path,
                prepared,
                &CancellationToken::default(),
            )
            .expect("publish complete Java fixture content")
        else {
            panic!("uncancelled actual Java fixture publication must succeed");
        };
        content_mount_request(content.into_parts().0, path, oid)
    }

    fn live_content(&self, path: &str, source: &str) -> SelectedResolutionContentMountRequest {
        self.published_content(path, source)
            .with_live_overlay_content_digest(
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes()),
            )
    }

    fn counterfactual_content(
        &self,
        path: &str,
        original: &str,
        source: &str,
    ) -> SelectedResolutionContentMountRequest {
        counterfactual_content_mount(self.published_content(path, source), original)
    }

    fn content_mount(&self, path: &str) -> SelectedResolutionContentMountRequest {
        use super::super::resolution_publication::{
            ResolutionContentInput, ResolutionContentPublicationOutcome,
        };
        let outcome = self
            .store
            .admit_cached_selected_content(
                &self.snapshots["java"],
                path,
                persisted_oid(),
                &ResolutionContentInput::Parsed {
                    content_oid: persisted_oid(),
                    semantic_language: Language::Java,
                },
                &CancellationToken::default(),
            )
            .unwrap();
        let ResolutionContentPublicationOutcome::Ready(content) = outcome else {
            panic!("real content fixture publication: {outcome:?}");
        };
        content_mount_request(content.into_parts().0, path, persisted_oid())
    }

    fn second_replacement(&self) -> SelectedResolutionContentMountRequest {
        self.counterfactual_content(SECOND_REPLACEMENT_PATH, RICH_JAVA_SOURCE, RICH_JAVA_SOURCE)
    }

    fn parity_masks(&self) -> Vec<SelectedResolutionOverlayMask> {
        vec![
            SelectedResolutionOverlayMask::replacement("java", PROVIDER_PATH),
            SelectedResolutionOverlayMask::removal("java", REMOVED_PATH),
            SelectedResolutionOverlayMask::removal("java", SECOND_REPLACEMENT_PATH),
        ]
    }

    fn two_replacement_masks(&self) -> Vec<SelectedResolutionOverlayMask> {
        vec![
            SelectedResolutionOverlayMask::replacement("java", PROVIDER_PATH),
            SelectedResolutionOverlayMask::removal("java", REMOVED_PATH),
            SelectedResolutionOverlayMask::replacement("java", SECOND_REPLACEMENT_PATH),
        ]
    }

    fn open<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        replacements: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
        self.store.open_selected_resolution_operation(
            selected_operation_input(
                &self.project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
                replacements,
            ),
            cancellation,
        )
    }

    fn open_ready<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        replacements: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        open_ready_operation(
            &self.store,
            selected_operation_input(
                &self.project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
                replacements,
            ),
            cancellation,
        )
    }

    fn open_with_project<'a>(
        &'a self,
        project: &'a dyn Project,
        masks: &'a [SelectedResolutionOverlayMask],
        replacements: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
        self.store.open_selected_resolution_operation(
            selected_operation_input(
                project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
                replacements,
            ),
            cancellation,
        )
    }

    fn open_with_project_and_content_mounts<'a>(
        &'a self,
        project: &'a dyn Project,
        masks: &'a [SelectedResolutionOverlayMask],
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOpenOutcome<'a, 'a>> {
        self.store.open_selected_resolution_operation(
            selected_operation_input(
                project,
                &self.workspace_id,
                &self.snapshots,
                &self.languages,
                masks,
                content_mounts,
            ),
            cancellation,
        )
    }

    fn open_parity_ready<'a>(
        &'a self,
        masks: &'a [SelectedResolutionOverlayMask],
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'a, 'a> {
        self.open_ready(masks, vec![self.provider_replacement()], cancellation)
    }
}

#[cfg(test)]
fn test_oid(ordinal: u64) -> Oid {
    Oid::from_str(&format!("{ordinal:040x}")).expect("test OID")
}

#[cfg(test)]
fn provider_method_site(facts: &FileResolutionFacts) -> ResolutionSiteId {
    facts
        .member_owners
        .iter()
        .find(|member| member.kind == ResolutionMemberKind::Method)
        .expect("rich provider static method")
        .member
}

#[cfg(test)]
fn contexts_for(
    _fixture: &ResolutionOperationFixture,
    mounts: &[SelectedResolutionOperationMount],
) -> SelectedResolutionContextSet {
    // A context set is sparse, so a context with no relation and no inventory
    // evidence is empty whatever the operation selected.
    SelectedResolutionContextSet::new(
        SelectedContextIdentities::new(),
        Vec::new(),
        mounts.len(),
        &mount_lookup(mounts),
    )
    .expect("exact Java operation context set")
}

#[cfg(test)]
struct PreloadedOracle {
    service: PreloadedFactResolutionService,
    point_reference: crate::analyzer::resolution::SemanticId,
    reverse_definition: crate::analyzer::resolution::SemanticId,
    source_fragment: crate::analyzer::resolution::BindingFragmentId,
    provider_fragment: crate::analyzer::resolution::BindingFragmentId,
}

#[cfg(test)]
impl PreloadedOracle {
    fn from_operation(
        fixture: &ResolutionOperationFixture,
        operation: &SelectedResolutionOperation<'_, '_>,
    ) -> Self {
        assert_eq!(operation.mount_table().mount_count(), 2);
        let lowered = operation
            .mounts()
            .unwrap()
            .iter()
            .map(|mount| {
                let facts = match mount.persisted_relative_path() {
                    SOURCE_PATH => &fixture.source_facts,
                    PROVIDER_PATH => &fixture.provider_facts,
                    path => panic!("unexpected parity mount {path:?}"),
                };
                (mount.persisted_relative_path().to_owned(), {
                    let artifact =
                        crate::analyzer::resolution::lower_resolution_facts_for_selection(
                            mount.fragment(),
                            &operation.ready.shared_names(),
                            Language::Java,
                            facts,
                        );
                    crate::analyzer::resolution::record_fixture_selected_identity_catalog(
                        artifact.identities(),
                        operation
                            .ready
                            .inventory
                            .mount_record_by_ordinal(mount.ordinal())
                            .unwrap()
                            .fragment_digest()
                            .as_bytes(),
                    );
                    artifact
                })
            })
            .collect::<Vec<_>>();
        let source = lowered
            .iter()
            .find(|(path, _)| path == SOURCE_PATH)
            .expect("persisted source artifact");
        let provider = lowered
            .iter()
            .find(|(path, _)| path == PROVIDER_PATH)
            .expect("transient provider artifact");
        let point_site = site_for_identifier(
            &fixture.source_facts,
            "method",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        let definition_site = provider_method_site(&fixture.provider_facts);
        let point_reference = semantic_at(&source.1, point_site, LoweredSemanticRole::Reference);
        let reverse_definition = semantic_at(
            &provider.1,
            definition_site,
            LoweredSemanticRole::Definition,
        );
        let source_fragment = source.1.lexical().fragment();
        let provider_fragment = provider.1.lexical().fragment();
        let mut service = PreloadedFactResolutionService::from_lowered_fragments(
            lowered
                .iter()
                .map(|(_, artifact)| artifact.lexical().clone()),
            lowered.iter().map(|(_, artifact)| artifact.typed().clone()),
        );
        // The persisted operation reads Java inheritance declarations from its
        // indexed source rows. Install the same facts from the lowered member
        // scopes so the preloaded oracle runs the same Java hierarchy replay.
        // These fixtures author classes only, each in one known package.
        let mut declarations = Vec::new();
        for (path, artifact) in &lowered {
            let (text, package) = match path.as_str() {
                SOURCE_PATH => (RICH_JAVA_SOURCE, "com.acme"),
                PROVIDER_PATH => (PROVIDER_JAVA_SOURCE, "dep"),
                path => panic!("unexpected parity mount {path:?}"),
            };
            assert!(text.contains(&format!("package {package};")), "{path}");
            assert!(!text.contains("interface"), "{path}");
            declarations.extend(
                artifact
                    .typed()
                    .member_scopes()
                    .iter()
                    .filter(|row| row.is_type_body())
                    .map(
                        |row| crate::analyzer::resolution::JavaInheritanceDeclaration {
                            definition: row.definition(),
                            name: String::new(),
                            package: Some(package.to_owned()),
                            kind:
                                crate::analyzer::resolution::JavaInheritanceDeclarationKind::Type {
                                    is_interface: false,
                                    is_singleton: false,
                                },
                        },
                    ),
            );
        }
        service.set_java_inheritance_metadata(declarations);
        Self {
            service,
            point_reference,
            reverse_definition,
            source_fragment,
            provider_fragment,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedBatches {
    batches: Vec<FactReferenceBatchAnswer>,
    summary: FactResolutionBatchSummary,
}

#[cfg(test)]
#[derive(Default)]
struct StagerState {
    staged: Vec<FactReferenceBatchAnswer>,
    rollback_count: usize,
    publish_count: usize,
}

#[cfg(test)]
type StageHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(test)]
fn stage_test_batch(
    state: &Rc<RefCell<StagerState>>,
    first_stage_hook: &mut Option<StageHook>,
    batch: &FactReferenceBatchAnswer,
) -> Result<()> {
    state.borrow_mut().staged.push(batch.clone());
    if let Some(hook) = first_stage_hook.take() {
        hook()?;
    }
    Ok(())
}

#[cfg(test)]
fn rollback_test_batches(state: &Rc<RefCell<StagerState>>) {
    let mut state = state.borrow_mut();
    state.staged.clear();
    state.rollback_count += 1;
}

#[cfg(test)]
struct RollbackStager {
    state: Rc<RefCell<StagerState>>,
    first_stage_hook: Option<StageHook>,
    published: bool,
}

#[cfg(test)]
impl RollbackStager {
    fn new() -> (Self, Rc<RefCell<StagerState>>) {
        Self::with_first_stage_hook(Box::new(|| Ok(())))
    }

    fn with_first_stage_hook(first_stage_hook: StageHook) -> (Self, Rc<RefCell<StagerState>>) {
        let state = Rc::new(RefCell::new(StagerState::default()));
        (
            Self {
                state: Rc::clone(&state),
                first_stage_hook: Some(first_stage_hook),
                published: false,
            },
            state,
        )
    }
}

#[cfg(test)]
impl SelectedResolutionBroadStager for RollbackStager {
    type Published = PublishedBatches;

    fn stage(&mut self, batch: &FactReferenceBatchAnswer) -> Result<()> {
        stage_test_batch(&self.state, &mut self.first_stage_hook, batch)
    }

    fn publish(mut self, summary: FactResolutionBatchSummary) -> Result<Self::Published> {
        let batches = {
            let mut state = self.state.borrow_mut();
            state.publish_count += 1;
            std::mem::take(&mut state.staged)
        };
        self.published = true;
        Ok(PublishedBatches { batches, summary })
    }
}

#[cfg(test)]
impl Drop for RollbackStager {
    fn drop(&mut self) {
        if !self.published {
            rollback_test_batches(&self.state);
        }
    }
}

#[cfg(test)]
struct CountRollbackStager {
    state: Rc<RefCell<StagerState>>,
    first_stage_hook: Option<StageHook>,
    published: bool,
}

#[cfg(test)]
impl CountRollbackStager {
    fn with_first_stage_hook(first_stage_hook: StageHook) -> (Self, Rc<RefCell<StagerState>>) {
        let state = Rc::new(RefCell::new(StagerState::default()));
        (
            Self {
                state: Rc::clone(&state),
                first_stage_hook: Some(first_stage_hook),
                published: false,
            },
            state,
        )
    }
}

#[cfg(test)]
impl SelectedResolutionBroadStager for CountRollbackStager {
    type Published = usize;

    fn stage(&mut self, batch: &FactReferenceBatchAnswer) -> Result<()> {
        stage_test_batch(&self.state, &mut self.first_stage_hook, batch)
    }

    fn publish(mut self, _summary: FactResolutionBatchSummary) -> Result<Self::Published> {
        let reference_count = {
            let mut state = self.state.borrow_mut();
            state.publish_count += 1;
            let reference_count = state.staged.iter().map(|batch| batch.answers().len()).sum();
            state.staged.clear();
            reference_count
        };
        self.published = true;
        Ok(reference_count)
    }
}

#[cfg(test)]
impl Drop for CountRollbackStager {
    fn drop(&mut self) {
        if !self.published {
            rollback_test_batches(&self.state);
        }
    }
}

#[cfg(test)]
fn dispatch_usize(
    native: Result<SelectedResolutionOperationOutcome<usize>>,
    cancellation: &CancellationToken,
    legacy: impl FnOnce() -> Result<usize>,
) -> Result<SelectedResolutionOperationResult<usize>> {
    native?.with_legacy(cancellation, legacy)
}

#[cfg(test)]
fn canonical_broad_rows(
    batches: &[FactReferenceBatchAnswer],
) -> Vec<(
    crate::analyzer::resolution::BindingFragmentId,
    crate::analyzer::resolution::SemanticId,
    crate::analyzer::resolution::FactResolutionAnswer,
)> {
    let mut rows = batches
        .iter()
        .flat_map(|batch| {
            batch.answers().iter().map(|answer| {
                (
                    batch.fragment(),
                    answer.reference(),
                    answer.answer().clone(),
                )
            })
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|(fragment, reference, _)| (*fragment, *reference));
    rows
}

#[cfg(test)]
fn assert_semantic_summary_eq(
    actual: &FactResolutionBatchSummary,
    expected: &FactResolutionBatchSummary,
) {
    assert_eq!(actual.completion(), expected.completion());
    assert_eq!(
        actual.reference_enumeration_completion(),
        expected.reference_enumeration_completion()
    );
    assert_eq!(actual.reference_count(), expected.reference_count());
    assert_eq!(actual.batch_count(), expected.batch_count());
}

#[test]
fn published_replacements_are_exact_sorted_dense_mounts() {
    let fixture = ResolutionOperationFixture::new();
    let masks = fixture.two_replacement_masks();
    let cancellation = CancellationToken::default();

    let first = fixture.open_ready(
        &masks,
        vec![fixture.second_replacement(), fixture.provider_replacement()],
        &cancellation,
    );
    let first_mounts = first.mounts().unwrap().to_vec();
    assert_eq!(
        first_mounts
            .iter()
            .map(|mount| {
                (
                    mount.ordinal().get(),
                    mount.persisted_relative_path(),
                    mount.storage_language(),
                    mount.semantic_language(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (0, SOURCE_PATH, "java", Language::Java),
            (1, PROVIDER_PATH, "java", Language::Java),
            (2, SECOND_REPLACEMENT_PATH, "java", Language::Java),
        ]
    );
    assert!(
        first_mounts
            .iter()
            .all(|mount| mount.persisted_relative_path() != REMOVED_PATH),
        "a removal owns no selected ordinal"
    );
    drop(first);

    let permuted = fixture.open_ready(
        &masks,
        vec![fixture.provider_replacement(), fixture.second_replacement()],
        &cancellation,
    );
    assert_eq!(permuted.mounts().unwrap(), first_mounts.as_slice());
    drop(permuted);

    assert!(matches!(
        fixture
            .open(&masks, vec![fixture.provider_replacement()], &cancellation)
            .unwrap(),
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientReplacement {
                storage_language,
                persisted_relative_path
            }
        ) if storage_language == "java" && persisted_relative_path == SECOND_REPLACEMENT_PATH
    ));
    assert!(matches!(
        fixture.open(
            &masks,
            vec![
                fixture.provider_replacement(),
                fixture.second_replacement(),
                fixture.counterfactual_content(
                    "src/E_Extra.java",
                    RICH_JAVA_SOURCE,
                    RICH_JAVA_SOURCE,
                ),
            ],
            &cancellation,
        ).unwrap(),
        SelectedResolutionOperationOpenOutcome::Unavailable(
            SelectedResolutionUnavailable::MissingTransientOverlayInput {
                storage_language,
                persisted_relative_path,
            }
        ) if storage_language == "java" && persisted_relative_path == "src/E_Extra.java"
    ));
    assert_store_error_contains(
        fixture.open(
            &masks,
            vec![
                fixture.provider_replacement(),
                fixture.provider_replacement(),
                fixture.second_replacement(),
            ],
            &cancellation,
        ),
        "duplicate selected resolution content mount",
    );
}

#[test]
fn selected_operation_requires_the_live_overlay_digest_and_rejects_clear() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let original = "class Provider {}\n";
    let changed = "class ProviderChanged {}\n";
    assert!(overlay.set(file.abs_path(), original.to_owned()));
    let original_digest =
        brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];

    assert!(overlay.set(file.abs_path(), changed.to_owned()));
    let stale = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![fixture.live_content(PROVIDER_PATH, original)],
            &CancellationToken::default(),
        )
        .expect("stale overlay preflight must not fail the store call");
    assert!(matches!(
        stale,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: Some(_),
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == original_digest
    ));

    assert!(overlay.set(file.abs_path(), original.to_owned()));
    assert!(overlay.clear(&file.abs_path()));
    let cleared = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![fixture.live_content(PROVIDER_PATH, original)],
            &CancellationToken::default(),
        )
        .expect("cleared overlay preflight must not fail the store call");
    assert!(matches!(
        cleared,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: None,
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == original_digest
    ));
}

#[test]
fn selected_operation_accepts_a_matching_cached_content_mount_authority() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let result = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("matching cached content authority must not fail the store call");
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = result else {
        panic!("matching cached content authority must open Ready")
    };
    let provider = operation
        .mounts()
        .unwrap()
        .iter()
        .find(|mount| mount.persisted_relative_path() == PROVIDER_PATH)
        .expect("cached provider mount");
    let selected = operation
        .ready
        .inventory
        .mount_record_by_ordinal(provider.ordinal())
        .unwrap();
    assert!(selected.file_version_id().is_none());
    assert_eq!(selected.blob_oid(), persisted_oid());
}

#[test]
fn selected_operation_rejects_cached_content_authority_before_sql_when_wrong_or_cleared() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];

    begin_production_selected_sql_trace(&fixture.store);
    let wrong = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest([0x5a; 32]),
            ],
            &CancellationToken::default(),
        )
        .expect("wrong cached content authority must not fail the store call");
    let wrong_cost = finish_production_selected_sql_trace(&fixture.store);
    assert_eq!(wrong_cost.statement_count(), 0);
    assert!(matches!(
        wrong,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: Some(_),
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == [0x5a; 32]
    ));

    assert!(overlay.clear(&file.abs_path()));
    begin_production_selected_sql_trace(&fixture.store);
    let cleared = fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("cleared cached content authority must not fail the store call");
    let cleared_cost = finish_production_selected_sql_trace(&fixture.store);
    assert_eq!(cleared_cost.statement_count(), 0);
    assert!(matches!(
        cleared,
        SelectedResolutionOperationOpenOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: None,
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == digest
    ));
}

#[test]
fn selected_operation_rechecks_cached_content_authority_at_final_boundary() {
    let fixture = ResolutionOperationFixture::new();
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    let changed = "class ProviderChanged {}\n";
    fixture.project.set_overlay_content(file.clone(), source);
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let operation = match fixture
        .open_with_project_and_content_mounts(
            &fixture.project,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("matching cached content authority must open")
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        _ => panic!("matching cached content authority must open Ready"),
    };
    let mut ready = operation.ready;
    fixture.project.set_overlay_content(file, changed);
    assert_eq!(fixture.project.analysis_generation(), 0);
    let result = ready.finish(
        (),
        &ResolutionCompletion::Complete,
        &CancellationToken::default(),
    );
    assert!(matches!(
        result.unwrap(),
        SelectedResolutionOperationOutcome::Stale(
            SelectedResolutionStale::TransientOverlayChanged {
                storage_language,
                persisted_relative_path,
                expected_content_digest,
                actual_content_digest: Some(_),
            }
        ) if storage_language == "java"
            && persisted_relative_path == PROVIDER_PATH
            && expected_content_digest == digest
    ));
}

#[test]
fn selected_operation_revalidates_cached_content_publication_before_native() {
    let fixture = ResolutionOperationFixture::new();
    let overlay = OverlayProject::new(Arc::new(fixture.project.clone()));
    let file = ProjectFile::new(fixture._project_root.path(), PROVIDER_PATH);
    let source = "class Provider {}\n";
    assert!(overlay.set(file.abs_path(), source.to_owned()));
    let digest = brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes());
    let masks = [SelectedResolutionOverlayMask::replacement(
        "java",
        PROVIDER_PATH,
    )];
    let operation = match fixture
        .open_with_project_and_content_mounts(
            &overlay,
            &masks,
            vec![
                fixture
                    .content_mount(PROVIDER_PATH)
                    .with_live_overlay_content_digest(digest),
            ],
            &CancellationToken::default(),
        )
        .expect("matching cached content authority must open")
    {
        SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
        _ => panic!("matching cached content authority must open Ready"),
    };
    let mut ready = operation.ready;
    fixture.store.conn.execute(|conn| {
        conn.execute(
            "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
            [persisted_oid().to_string()],
        )
        .unwrap();
    });
    let result = ready.finish(
        (),
        &ResolutionCompletion::Complete,
        &CancellationToken::default(),
    );
    assert!(matches!(
        result.unwrap(),
        SelectedResolutionOperationOutcome::Stale(SelectedResolutionStale::MountInventoryChanged)
    ));
}

#[test]
fn cancelled_or_final_stale_broad_attempt_rolls_back_and_retries_exactly() {
    let fixture = ResolutionOperationFixture::new();
    let masks = fixture.parity_masks();
    let oracle_token = CancellationToken::default();
    let oracle_operation = fixture.open_parity_ready(&masks, &oracle_token);
    let oracle = PreloadedOracle::from_operation(&fixture, &oracle_operation);
    drop(oracle_operation);
    let mut expected_batches = Vec::new();
    let expected_summary = oracle
        .service
        .stage_all_reference_batches(2, &oracle_token, &mut |batch| {
            expected_batches.push(batch.clone());
            Ok(())
        })
        .unwrap();

    let stale_token = CancellationToken::default();
    let stale_operation = fixture.open_parity_ready(&masks, &stale_token);
    let stale_placements = contexts_for(&fixture, stale_operation.mounts().unwrap());
    let generation = fixture.project.generation_handle();
    let (stale_stager, stale_state) = RollbackStager::with_first_stage_hook(Box::new(move || {
        generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }));
    let mut metrics = SelectedResolutionContextMetrics;
    let stale = stale_operation
        .stage_selected_reference_batches(
            stale_placements,
            2,
            &stale_token,
            &mut metrics,
            stale_stager,
        )
        .unwrap();
    assert!(matches!(
        stale,
        SelectedResolutionOperationOutcome::Stale(
            SelectedResolutionStale::TransientAnalysisGeneration {
                expected: 0,
                actual: 1
            }
        )
    ));
    assert_eq!(stale_state.borrow().rollback_count, 1);
    assert_eq!(stale_state.borrow().publish_count, 0);
    assert!(stale_state.borrow().staged.is_empty());

    let retry_token = CancellationToken::default();
    let retry_operation = fixture.open_parity_ready(&masks, &retry_token);
    let retry_placements = contexts_for(&fixture, retry_operation.mounts().unwrap());
    let (retry_stager, retry_state) = RollbackStager::new();
    let mut metrics = SelectedResolutionContextMetrics;
    let retry = retry_operation
        .stage_selected_reference_batches(
            retry_placements,
            2,
            &retry_token,
            &mut metrics,
            retry_stager,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(retry) = retry else {
        panic!("unchanged retry after final stale must publish natively")
    };
    assert_eq!(retry_state.borrow().rollback_count, 0);
    assert_eq!(retry_state.borrow().publish_count, 1);
    assert_semantic_summary_eq(&retry.summary, &expected_summary);
    assert_eq!(
        canonical_broad_rows(&retry.batches),
        canonical_broad_rows(&expected_batches)
    );

    let cancelled_token = CancellationToken::default();
    let cancelled_operation = fixture.open_parity_ready(&masks, &cancelled_token);
    let cancelled_placements = contexts_for(&fixture, cancelled_operation.mounts().unwrap());
    let cancellation_trigger = cancelled_token.clone();
    let (cancelled_stager, cancelled_state) =
        RollbackStager::with_first_stage_hook(Box::new(move || {
            cancellation_trigger.cancel();
            Ok(())
        }));
    let mut metrics = SelectedResolutionContextMetrics;
    let cancelled = cancelled_operation
        .stage_selected_reference_batches(
            cancelled_placements,
            2,
            &cancelled_token,
            &mut metrics,
            cancelled_stager,
        )
        .unwrap();
    assert!(matches!(
        cancelled,
        SelectedResolutionOperationOutcome::Cancelled(_)
    ));
    assert_eq!(cancelled_state.borrow().rollback_count, 1);
    assert_eq!(cancelled_state.borrow().publish_count, 0);
    assert!(cancelled_state.borrow().staged.is_empty());

    let cancellation_retry_token = CancellationToken::default();
    let cancellation_retry_operation = fixture.open_parity_ready(&masks, &cancellation_retry_token);
    let cancellation_retry_placements =
        contexts_for(&fixture, cancellation_retry_operation.mounts().unwrap());
    let (cancellation_retry_stager, cancellation_retry_state) = RollbackStager::new();
    let mut metrics = SelectedResolutionContextMetrics;
    let cancellation_retry = cancellation_retry_operation
        .stage_selected_reference_batches(
            cancellation_retry_placements,
            2,
            &cancellation_retry_token,
            &mut metrics,
            cancellation_retry_stager,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(cancellation_retry) = cancellation_retry else {
        panic!("unchanged retry after cancellation must publish natively")
    };
    assert_eq!(cancellation_retry_state.borrow().rollback_count, 0);
    assert_eq!(cancellation_retry_state.borrow().publish_count, 1);
    assert_semantic_summary_eq(&cancellation_retry.summary, &expected_summary);
    assert_eq!(
        canonical_broad_rows(&cancellation_retry.batches),
        canonical_broad_rows(&expected_batches)
    );
}

#[test]
fn fallback_is_whole_operation_only_for_unavailable_or_stale() {
    let fixture = ResolutionOperationFixture::new();
    let effects = Rc::new(RefCell::new(Vec::new()));
    let cancellation = CancellationToken::default();
    let empty_snapshots = WorkspaceSnapshots::default();
    let empty_masks = Vec::new();
    let initial_unavailable = fixture
        .store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                &fixture.project,
                &fixture.workspace_id,
                &empty_snapshots,
                &fixture.languages,
                &empty_masks,
            ),
            &cancellation,
        )
        .unwrap();
    let unavailable_effects = Rc::clone(&effects);
    let initial_unavailable = initial_unavailable
        .with_legacy(&cancellation, move || {
            unavailable_effects.borrow_mut().push("initial-unavailable");
            Ok(11_usize)
        })
        .unwrap();
    assert!(matches!(
        initial_unavailable,
        SelectedResolutionOperationOpenResult::Legacy {
            value: 11,
            reason: SelectedResolutionFallbackReason::Unavailable(
                SelectedResolutionUnavailable::MissingWorkspaceSnapshot { .. }
            )
        }
    ));

    let stale_masks = fixture.parity_masks();
    let stale_input = SelectedResolutionOperationInput::new(
        &fixture.project,
        &fixture.workspace_id,
        &fixture.snapshots,
        &fixture.languages,
        &stale_masks,
    )
    .with_content_mounts(vec![fixture.counterfactual_content(
        PROVIDER_PATH,
        RICH_JAVA_SOURCE,
        PROVIDER_JAVA_SOURCE,
    )]);
    fixture.project.advance();
    let initial_stale = fixture
        .store
        .open_selected_resolution_operation(stale_input, &cancellation)
        .unwrap();
    let stale_effects = Rc::clone(&effects);
    let initial_stale = initial_stale
        .with_legacy(&cancellation, move || {
            stale_effects.borrow_mut().push("initial-stale");
            Ok(12_usize)
        })
        .unwrap();
    assert!(matches!(
        initial_stale,
        SelectedResolutionOperationOpenResult::Legacy {
            value: 12,
            reason: SelectedResolutionFallbackReason::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: 0,
                    actual: 1
                }
            )
        }
    ));

    let final_stale_operation = fixture.open_parity_ready(&stale_masks, &cancellation);
    let final_stale_placements = contexts_for(&fixture, final_stale_operation.mounts().unwrap());
    let generation = fixture.project.generation_handle();
    let (final_stale_stager, final_stale_state) =
        CountRollbackStager::with_first_stage_hook(Box::new(move || {
            generation.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
    let mut metrics = SelectedResolutionContextMetrics;
    let final_stale = final_stale_operation.stage_selected_reference_batches(
        final_stale_placements,
        2,
        &cancellation,
        &mut metrics,
        final_stale_stager,
    );
    let final_stale_effects = Rc::clone(&effects);
    let observed_final_stale_state = Rc::clone(&final_stale_state);
    let final_stale = dispatch_usize(final_stale, &cancellation, move || {
        let state = observed_final_stale_state.borrow();
        assert_eq!(state.rollback_count, 1);
        assert_eq!(state.publish_count, 0);
        assert!(state.staged.is_empty());
        drop(state);
        final_stale_effects.borrow_mut().push("final-stale");
        Ok(13)
    })
    .unwrap();
    assert!(matches!(
        final_stale,
        SelectedResolutionOperationResult::Legacy {
            value: 13,
            reason: SelectedResolutionFallbackReason::Stale(
                SelectedResolutionStale::TransientAnalysisGeneration {
                    expected: 1,
                    actual: 2
                }
            )
        }
    ));

    let cancelled_token = CancellationToken::default();
    let cancelled_operation = fixture.open_parity_ready(&stale_masks, &cancelled_token);
    let cancelled_placements = contexts_for(&fixture, cancelled_operation.mounts().unwrap());
    let cancellation_trigger = cancelled_token.clone();
    let (cancelled_stager, cancelled_state) =
        CountRollbackStager::with_first_stage_hook(Box::new(move || {
            cancellation_trigger.cancel();
            Ok(())
        }));
    let mut metrics = SelectedResolutionContextMetrics;
    let cancelled = cancelled_operation.stage_selected_reference_batches(
        cancelled_placements,
        2,
        &cancelled_token,
        &mut metrics,
        cancelled_stager,
    );
    let cancelled_effects = Rc::clone(&effects);
    let cancelled = dispatch_usize(cancelled, &cancelled_token, move || {
        cancelled_effects.borrow_mut().push("forbidden-cancelled");
        Ok(14)
    })
    .unwrap();
    assert!(matches!(
        cancelled,
        SelectedResolutionOperationResult::Cancelled(_)
    ));
    assert_eq!(cancelled_state.borrow().rollback_count, 1);
    assert_eq!(cancelled_state.borrow().publish_count, 0);

    let error_token = CancellationToken::default();
    let error_operation = fixture.open_parity_ready(&stale_masks, &error_token);
    let error_placements = contexts_for(&fixture, error_operation.mounts().unwrap());
    let (error_stager, error_state) = CountRollbackStager::with_first_stage_hook(Box::new(|| {
        Err(StoreError::new("injected broad staging failure"))
    }));
    let mut metrics = SelectedResolutionContextMetrics;
    let error_attempt = error_operation.stage_selected_reference_batches(
        error_placements,
        2,
        &error_token,
        &mut metrics,
        error_stager,
    );
    let error_effects = Rc::clone(&effects);
    let error = dispatch_usize(error_attempt, &error_token, move || {
        error_effects.borrow_mut().push("forbidden-error");
        Ok(15)
    });
    let error = match error {
        Err(error) => error,
        Ok(_) => panic!("store errors are direct and cannot authorize legacy"),
    };
    assert!(error.to_string().contains("injected broad staging failure"));
    assert_eq!(error_state.borrow().rollback_count, 1);
    assert_eq!(error_state.borrow().publish_count, 0);

    let native_token = CancellationToken::default();
    let native_operation = fixture.open_parity_ready(&stale_masks, &native_token);
    let native_placements = contexts_for(&fixture, native_operation.mounts().unwrap());
    let (native_stager, native_state) =
        CountRollbackStager::with_first_stage_hook(Box::new(|| Ok(())));
    let mut metrics = SelectedResolutionContextMetrics;
    let native = native_operation.stage_selected_reference_batches(
        native_placements,
        2,
        &native_token,
        &mut metrics,
        native_stager,
    );
    let native_effects = Rc::clone(&effects);
    let native = dispatch_usize(native, &native_token, move || {
        native_effects.borrow_mut().push("forbidden-native");
        Ok(16)
    })
    .unwrap();
    assert!(matches!(
        native,
        SelectedResolutionOperationResult::Native(reference_count) if reference_count > 0
    ));
    assert_eq!(native_state.borrow().rollback_count, 0);
    assert_eq!(native_state.borrow().publish_count, 1);
    assert_eq!(
        effects.borrow().as_slice(),
        ["initial-unavailable", "initial-stale", "final-stale"]
    );
}

/// A crate stage checks each mount's publication once
/// (`resolution_authority::AuthorityValidations`). A republication after that
/// check is not seen by the stage's later reads of the mount, but the graph
/// build's `finish_native` still ends the request `Stale`.
#[test]
fn a_republication_during_a_crate_stage_still_ends_stale() {
    use super::super::resolution_authority::SelectedResolutionAuthority;
    let fixture = ResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let mut operation = fixture.open_ready(&[], Vec::new(), &cancellation);
    {
        let _memos = operation.crate_stage_memos().unwrap();
        let inventory = &operation.ready.inventory;
        let authority = SelectedResolutionAuthority::new(
            inventory.connection(),
            inventory.shared_name_table(),
            inventory.requested_mount_rows(),
            inventory.persisted_mount_count(),
            inventory.authority_validations(),
            inventory.authority_request_memo(),
        );
        let mount = inventory.mounts().unwrap()[0].clone();
        assert_eq!(
            authority.ensure_authority(&mount, &cancellation).unwrap(),
            Some(())
        );
        let blob = mount.blob_id();
        let republished = fixture.store.conn.execute(move |conn| {
            conn.execute(
                "UPDATE resolution_fragment_interiors SET publication_state = 'building' \
                 WHERE blob_id = ?1",
                [blob],
            )
            .unwrap()
        });
        assert_eq!(republished, 1);
        assert_eq!(
            authority.ensure_authority(&mount, &cancellation).unwrap(),
            Some(()),
            "the stage relies on its first check of the mount"
        );
    }
    let outcome = operation
        .finish_native((), &ResolutionCompletion::Complete, &cancellation)
        .unwrap();
    match outcome {
        SelectedResolutionOperationOutcome::Stale(reason) => {
            assert_eq!(reason, SelectedResolutionStale::MountInventoryChanged)
        }
        _ => panic!("a republication during the stage must end Stale"),
    }
}

#[test]
fn selected_operation_memoizes_published_authority_identities_and_site_rows() {
    use super::super::resolution_authority::SelectedResolutionAuthority;

    let fixture = ResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    begin_production_selected_sql_trace(&fixture.store);
    let mut operation_costs = Vec::new();
    for _ in 0..2 {
        let operation = fixture.open_ready(&[], Vec::new(), &cancellation);
        let inventory = &operation.ready.inventory;
        let mount = inventory.mounts().unwrap()[0].clone();
        let (node_key, semantic_key, site_key) = inventory
            .connection()
            .query_row(
                "SELECT (SELECT local_key FROM resolution_node_catalog WHERE blob_id=?1 ORDER BY local_key LIMIT 1), (SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND identity_digest IS NOT NULL ORDER BY local_key LIMIT 1), (SELECT site FROM resolution_sites WHERE blob_id=?1 AND role=1 ORDER BY site LIMIT 1)",
                [mount.blob_id()],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .unwrap();
        let node_key = u32::try_from(node_key.expect("fixture node identity"))
            .expect("fixture node key fits u32");
        let semantic_key = u32::try_from(semantic_key.expect("fixture semantic identity"))
            .expect("fixture semantic key fits u32");
        let site_key = u32::try_from(site_key.expect("fixture definition site"))
            .expect("fixture site key fits u32");
        let _setup = checkpoint_production_selected_sql_trace();

        let authority = SelectedResolutionAuthority::from_selection(inventory);
        let node = BindingNodeId::local(mount.ordinal().get(), node_key);
        let node_first = authority
            .node_catalog_provenance(node, &cancellation)
            .unwrap();
        let node_second = authority
            .node_catalog_provenance(node, &cancellation)
            .unwrap();
        assert!(node_first.as_ref().is_some_and(Option::is_some));
        assert_eq!(node_first, node_second);

        let semantic = SemanticId::local(mount.ordinal().get(), semantic_key);
        let semantic_first = authority
            .semantic_catalog_provenance(semantic, &cancellation)
            .unwrap();
        let semantic_second = authority
            .semantic_catalog_provenance(semantic, &cancellation)
            .unwrap();
        assert!(semantic_first.as_ref().is_some_and(Option::is_some));
        assert_eq!(semantic_first, semantic_second);

        let lexical = operation.ready.lexical_source();
        let requests = [
            (
                mount.ordinal(),
                BindingNodeId::local(mount.ordinal().get(), site_key),
            ),
            (
                mount.ordinal(),
                BindingNodeId::local(mount.ordinal().get(), u32::MAX),
            ),
        ];
        let sites_first = lexical
            .definition_source_sites(&requests, &cancellation)
            .unwrap()
            .unwrap();
        let sites_second = lexical
            .definition_source_sites(&requests, &cancellation)
            .unwrap()
            .unwrap();
        assert_eq!(sites_first[0], Some(ResolutionSiteId::new(site_key)));
        assert_eq!(sites_first[1], None);
        assert_eq!(sites_first, sites_second);
        operation_costs.push(checkpoint_production_selected_sql_trace());
    }
    let _cleanup = finish_production_selected_sql_trace(&fixture.store);

    for cost in operation_costs {
        let executions = |prefix: &str| {
            cost.statements
                .iter()
                .filter(|sql| sql.starts_with(prefix))
                .count()
        };
        assert_eq!(
            executions("SELECT 1 FROM resolution_fragment_interiors"),
            1,
            "one published mount is checked once per operation: {:?}",
            cost.statements
        );
        assert_eq!(
            executions("SELECT identity_digest FROM resolution_node_catalog"),
            1,
            "one node identity is read once per operation: {:?}",
            cost.statements
        );
        assert_eq!(
            executions("SELECT identity_digest, shared_identity FROM resolution_semantic_catalog"),
            1,
            "one semantic identity is read once per operation: {:?}",
            cost.statements
        );
        assert_eq!(
            executions("SELECT site, role, namespace, site_kind"),
            1,
            "positive and negative site keys share one memoized batch read per operation: {:?}",
            cost.statements
        );
    }
}

/// A crate stage holds one read transaction on its reader. Temp writes nest
/// in it as savepoints, the request's own publication is seen only after the
/// stage's snapshot is renewed, and the reader leaves the stage outside any
/// transaction.
#[test]
fn a_crate_stage_reads_one_snapshot_and_renews_it_around_a_publication() {
    let fixture = ResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&[], Vec::new(), &cancellation);
    let inventory = &operation.ready.inventory;
    let digest = [0x5a_u8; 32];
    let seen = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row(
            "SELECT count(*) FROM resolution_identities WHERE identity_digest = ?1",
            [digest.as_slice()],
            |row| row.get(0),
        )
        .unwrap()
    };
    {
        let _memos = operation.crate_stage_memos().unwrap();
        assert!(!inventory.connection().is_autocommit());
        assert_eq!(seen(inventory.connection()), 0);
        inventory
            .with_owned_temp_transaction(|conn| {
                conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS stage_probe(value INTEGER)")?;
                conn.execute("INSERT INTO temp.stage_probe VALUES(1)", [])?;
                Ok(
                    super::super::resolution_selection::SelectedResolutionTempTransaction::Commit(
                        (),
                    ),
                )
            })
            .unwrap();
        assert!(
            !inventory.connection().is_autocommit(),
            "a temp write is a savepoint inside the stage"
        );
        fixture.store.conn.execute(move |conn| {
            conn.execute(
                "INSERT INTO resolution_identities(identity_digest) VALUES(?1)",
                [digest.as_slice()],
            )
            .unwrap();
        });
        assert_eq!(
            seen(inventory.connection()),
            0,
            "the stage reads its own snapshot"
        );
        inventory.pause_stage_read().unwrap();
        inventory.resume_stage_read().unwrap();
        assert_eq!(
            seen(inventory.connection()),
            1,
            "the renewed snapshot sees it"
        );
    }
    assert!(inventory.connection().is_autocommit());
    let probe: i64 = inventory
        .connection()
        .query_row("SELECT count(*) FROM temp.stage_probe", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(probe, 1, "the stage committed its temp write");
}

#[cfg(test)]
#[path = "resolution_operation_java_tests.rs"]
mod java_query_tests;

// A completed answer must remain valid across fresh solve arenas while a
// smaller budget or cancelled request cannot borrow its completion.

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_root_test_support {
    use super::*;

    use super::super::super::AnalyzerStore;

    use super::super::super::Result;

    use super::super::super::WorkspaceFileRow;

    use super::super::super::WorkspaceId;

    use super::super::super::WorkspaceSnapshots;

    use super::super::super::resolution_selection::SelectedResolutionContentMountRequest;

    use super::super::super::resolution_selection::SelectedResolutionLanguage;

    use super::super::super::resolution_selection::SelectedResolutionOverlayMask;

    use crate::CancellationToken;

    use crate::analyzer::Language;

    use crate::analyzer::Project;

    use crate::analyzer::ProjectFile;

    use crate::analyzer::TestProject;

    use crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog;

    use crate::analyzer::resolution::LoweredSemanticRole;

    use crate::analyzer::resolution::SelectedSemanticLocator;

    use crate::analyzer::store::file_state::FileState;

    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use crate::analyzer::tree_sitter_analyzer::ParsedFile;

    use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

    use brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent;

    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    use git2::Oid;

    use std::collections::BTreeSet;

    use std::path::Path;

    use std::sync::Arc;

    use std::sync::Mutex;

    use std::sync::atomic::AtomicU64;

    use std::sync::atomic::Ordering;

    use tree_sitter::Parser;

    #[doc(hidden)]
    pub fn selected_operation_input<'project, 'selection>(
        project: &'project dyn Project,
        workspace_id: &'selection WorkspaceId,
        snapshots: &'selection WorkspaceSnapshots,
        languages: &'selection [SelectedResolutionLanguage],
        overlay_masks: &'selection [SelectedResolutionOverlayMask],
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
    ) -> SelectedResolutionOperationInput<'project, 'selection> {
        SelectedResolutionOperationInput::new(
            project,
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
        )
        .with_content_mounts(content_mounts)
    }
    #[doc(hidden)]
    pub fn open_ready_operation<'store, 'project, 'selection>(
        store: &'store AnalyzerStore,
        input: SelectedResolutionOperationInput<'project, 'selection>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'store, 'project> {
        match store
            .open_selected_resolution_operation(input, cancellation)
            .expect("open selected resolution test operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            outcome => panic!("selected resolution test operation must be Ready: {outcome:?}"),
        }
    }
    #[doc(hidden)]
    pub fn content_mount_request(
        publication: super::super::super::resolution_publication::ResolutionContentWitness,
        path: &str,
        blob_oid: Oid,
    ) -> SelectedResolutionContentMountRequest {
        SelectedResolutionContentMountRequest::new(
            publication,
            WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
    #[doc(hidden)]
    pub fn counterfactual_content_mount(
        content: SelectedResolutionContentMountRequest,
        original: &str,
    ) -> SelectedResolutionContentMountRequest {
        content.with_counterfactual_base_content_digest(
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes()),
        )
    }
    #[derive(Clone)]
    #[doc(hidden)]
    pub struct MutableGenerationProject {
        delegate: TestProject,
        generation: Arc<AtomicU64>,
        overlay_content: Arc<Mutex<Option<Arc<WorkspaceOverlayContent>>>>,
    }
    impl MutableGenerationProject {
        #[doc(hidden)]
        pub fn new(root: &Path, language: Language) -> Self {
            Self {
                delegate: TestProject::new(root, language),
                generation: Arc::new(AtomicU64::new(0)),
                overlay_content: Arc::new(Mutex::new(None)),
            }
        }

        pub(super) fn generation_handle(&self) -> Arc<AtomicU64> {
            Arc::clone(&self.generation)
        }

        pub(super) fn advance(&self) {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }

        #[doc(hidden)]
        pub fn set_overlay_content(&self, file: ProjectFile, content: &str) {
            let digest =
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(content.as_bytes());
            let overlay = Arc::new(WorkspaceOverlayContent::new([(file, digest)]));
            *self
                .overlay_content
                .lock()
                .expect("operation test overlay lock") = Some(overlay);
        }
    }
    impl Project for MutableGenerationProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn analysis_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
            self.overlay_content
                .lock()
                .expect("operation test overlay lock")
                .clone()
        }
    }
    #[doc(hidden)]
    pub fn parsed_operation_state<A: LanguageAdapter>(
        project_root: &Path,
        relative_path: &str,
        source: &str,
        adapter: &A,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
        file.write(source).expect("write operation source");
        parsed_operation_source_state(project_root, relative_path, source, adapter)
    }
    /// Parse unsaved content without replacing the selected disk baseline.
    #[doc(hidden)]
    pub fn parsed_operation_source_state<A: LanguageAdapter>(
        project_root: &Path,
        relative_path: &str,
        source: &str,
        adapter: &A,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
        let source = source.to_owned();
        let mut parser = Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .expect("set Go grammar");
        let tree = parser
            .parse(&source, None)
            .expect("parse Go operation source");
        let mut parsed: ParsedFile = adapter.parse_file(&file, &source, &tree);
        parsed.add_file_scope(&file, &source);
        let contains_tests = adapter.contains_tests(&file, &source, &tree, &parsed);
        let state = Arc::new(TreeSitterAnalyzer::<A>::file_state_from_parsed(
            source,
            parsed,
            contains_tests,
            Some(Vec::new()),
            true,
        ));
        let facts = state.resolution_facts.clone();
        (state, facts)
    }
    #[doc(hidden)]
    pub fn site_for_identifier(
        facts: &FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        try_site_for_identifier(facts, spelling, role, namespace)
            .unwrap_or_else(|| panic!("fixture identifier {role:?} {namespace:?} {spelling:?}"))
    }
    pub(super) fn try_site_for_identifier(
        facts: &FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> Option<ResolutionSiteId> {
        facts
            .identifiers_named(spelling, role, namespace)
            .into_iter()
            .next()
            .map(|identifier| identifier.site)
    }
    #[doc(hidden)]
    pub fn locator(
        path: &str,
        site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> SelectedSemanticLocator {
        SelectedSemanticLocator::new("java", path, site, role)
    }
    #[doc(hidden)]
    pub fn semantic_at(
        artifact: &LoweredResolutionFactsWithIdentityCatalog,
        site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> crate::analyzer::resolution::SemanticId {
        crate::analyzer::resolution::test_support::lowered_semantic_at(
            artifact.lexical().semantics(),
            site,
            role,
        )
    }
    #[doc(hidden)]
    pub fn assert_store_error_contains<T>(result: Result<T>, needle: &str) {
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected store error containing {needle:?}"),
        };
        assert!(
            error.to_string().contains(needle),
            "unexpected store error: {error}"
        );
    }
    #[doc(hidden)]
    pub fn with_operation_lexical<T>(
        operation: &SelectedResolutionOperation<'_, '_>,
        inspect: impl FnOnce(
            &SelectedResolutionLexicalSource<'_, '_>,
            &SelectedResolutionLexicalSource<'_, '_>,
        ) -> T,
    ) -> T {
        let source = operation.ready.lexical_source();
        inspect(&source, &source)
    }
}

#[cfg(test)]
use crate::analyzer::store::resolution_operation::resolution_operation_tests_go_support::go_extraction_support_11::*;

#[cfg(test)]
use self::rust_root_test_support::counterfactual_content_mount;
