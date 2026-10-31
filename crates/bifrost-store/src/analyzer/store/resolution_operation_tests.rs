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

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

#[cfg(any(test, feature = "test-support"))]
use git2::ObjectType;

#[cfg(any(test, feature = "test-support"))]
use git2::Oid;

#[cfg(any(test, feature = "test-support"))]
use std::cell::RefCell;

use std::path::Path;

#[cfg(any(test, feature = "test-support"))]
use std::path::PathBuf;

#[cfg(any(test, feature = "test-support"))]
use std::rc::Rc;

#[cfg(any(test, feature = "test-support"))]
use crate::CancellationToken;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::FactReferenceBatchAnswer;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::FactResolutionBatchSummary;

#[cfg(any(test, feature = "test-support"))]
use super::super::Result;

use super::*;

#[cfg(test)]
#[path = "resolution_operation_reverse_tests.rs"]
mod reverse_query_tests;

#[cfg(test)]
#[path = "resolution_operation_privacy_tests.rs"]
mod privacy_tests;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const WORKSPACE_ID: &str = "7171717171717171717171717171717171717171717171717171717171717171";
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const SOURCE_PATH: &str = "src/A_Source.java";
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const PROVIDER_PATH: &str = "src/B_Provider.java";
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const REMOVED_PATH: &str = "src/C_Removed.java";
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const SECOND_REPLACEMENT_PATH: &str = "src/D_Replacement.java";

#[cfg(any(test, feature = "test-support"))]
/// The git blob oid of `RICH_JAVA_SOURCE`, which every persisted Java mount in
/// these fixtures carries.
///
/// A persisted mount's blob oid is the oid of the bytes on disk, and the lazy
/// interior rehashes the file it reads to prove it still has the selected
/// revision's source. A synthetic oid therefore reads as a changed file.
#[doc(hidden)]
pub fn persisted_oid() -> Oid {
    Oid::hash_object(ObjectType::Blob, RICH_JAVA_SOURCE.as_bytes())
        .expect("hash the operation fixture source")
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const RICH_JAVA_SOURCE: &str = r#"
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
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const PROVIDER_JAVA_SOURCE: &str = r#"
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
fn test_oid(ordinal: u64) -> Oid {
    Oid::from_str(&format!("{ordinal:040x}")).expect("test OID")
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn provider_method_site(facts: &FileResolutionFacts) -> ResolutionSiteId {
    facts
        .member_owners
        .iter()
        .find(|member| member.kind == ResolutionMemberKind::Method)
        .expect("rich provider static method")
        .member
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct PublishedBatches {
    #[doc(hidden)]
    pub batches: Vec<FactReferenceBatchAnswer>,
    #[doc(hidden)]
    pub summary: FactResolutionBatchSummary,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
#[doc(hidden)]
pub struct StagerState {
    #[doc(hidden)]
    pub staged: Vec<FactReferenceBatchAnswer>,
    #[doc(hidden)]
    pub rollback_count: usize,
    #[doc(hidden)]
    pub publish_count: usize,
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub type StageHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
fn rollback_test_batches(state: &Rc<RefCell<StagerState>>) {
    let mut state = state.borrow_mut();
    state.staged.clear();
    state.rollback_count += 1;
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct RollbackStager {
    state: Rc<RefCell<StagerState>>,
    first_stage_hook: Option<StageHook>,
    published: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl RollbackStager {
    #[doc(hidden)]
    pub fn new() -> (Self, Rc<RefCell<StagerState>>) {
        Self::with_first_stage_hook(Box::new(|| Ok(())))
    }

    #[doc(hidden)]
    pub fn with_first_stage_hook(first_stage_hook: StageHook) -> (Self, Rc<RefCell<StagerState>>) {
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
impl Drop for RollbackStager {
    fn drop(&mut self) {
        if !self.published {
            rollback_test_batches(&self.state);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct CountRollbackStager {
    state: Rc<RefCell<StagerState>>,
    first_stage_hook: Option<StageHook>,
    published: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl CountRollbackStager {
    #[doc(hidden)]
    pub fn with_first_stage_hook(first_stage_hook: StageHook) -> (Self, Rc<RefCell<StagerState>>) {
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
impl Drop for CountRollbackStager {
    fn drop(&mut self) {
        if !self.published {
            rollback_test_batches(&self.state);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn dispatch_usize(
    native: Result<SelectedResolutionOperationOutcome<usize>>,
    cancellation: &CancellationToken,
    legacy: impl FnOnce() -> Result<usize>,
) -> Result<SelectedResolutionOperationResult<usize>> {
    native?.with_legacy(cancellation, legacy)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn canonical_broad_rows(
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_semantic_summary_eq(
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

// A completed answer must remain valid across fresh solve arenas while a
// smaller budget or cancelled request cannot borrow its completion.

#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_rust::selected_context::{RustCallerTargetKind, RustCallerTargetProfile};
#[cfg(any(test, feature = "test-support"))]
impl SelectedResolutionOperation<'_, '_> {
    #[doc(hidden)]
    pub fn rust_test_crate_context(
        &self,
        profile: RustCallerTargetProfile,
        cancellation: &CancellationToken,
    ) -> Result<SelectedRustFileContextOutcome> {
        let root = if profile.target_kind == RustCallerTargetKind::Detached {
            profile.target_root.clone()
        } else {
            profile
                .manifest_path
                .parent()
                .expect("manifest directory")
                .join(&profile.target_root)
        };
        self.rust_context_for_file(&root, cancellation)
    }
}

#[cfg(test)]
mod native_demand_installer_tests {
    use super::*;
    use crate::analyzer::resolution::{
        DemandReferenceKey, DemandRelationKey, DemandRootDiscovery, DemandRootProvider, RootClosure,
    };
    use crate::analyzer::store::language_support::{StoreLanguageSupport, neutral_fixture};
    use std::cell::Cell;

    thread_local! {
        static BUILDS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
        static RUNS: Cell<usize> = const { Cell::new(0) };
        static CANCEL: Cell<bool> = const { Cell::new(false) };
        static UNAVAILABLE: Cell<bool> = const { Cell::new(false) };
    }
    struct FakeInstaller;
    impl StoreLanguageSupport for FakeInstaller {
        fn demand_installer(&self) -> Option<NativeDemandInstaller> {
            Some(NativeDemandInstaller(&FakeInstaller))
        }
    }
    impl DemandInstall for FakeInstaller {
        fn prepare_caller(
            &self,
            _: &SelectedResolutionOperation<'_, '_>,
            caller: &Path,
            _: &CancellationToken,
            _: Option<&ResolutionSession>,
        ) -> Result<NativeDemandPreparationOutcome> {
            BUILDS.with(|builds| builds.borrow_mut().push(caller.to_path_buf()));
            Ok(if CANCEL.get() {
                NativeDemandPreparationOutcome::Cancelled
            } else if UNAVAILABLE.get() {
                NativeDemandPreparationOutcome::Unavailable
            } else {
                NativeDemandPreparationOutcome::Ready(Arc::new(()))
            })
        }
        fn run_point(
            &self,
            preparation: &dyn std::any::Any,
            request: NativeDemandPointRequest<'_, '_, '_>,
            run: &mut NativeDemandCallback<'_>,
        ) -> Result<()> {
            assert!(preparation.is::<()>());
            RUNS.set(RUNS.get() + 1);
            request.blueprint.with_forward_operation_in_session(
                request.lexical,
                request.paths,
                request.typed,
                request.cancellation,
                request.session,
                |operation| run(operation, &mut FakeInstaller),
            )
        }
    }
    impl DemandRootProvider for FakeInstaller {
        fn discover(&mut self, _: &DemandRelationKey) -> Result<DemandRootDiscovery> {
            Ok(DemandRootDiscovery::AlreadyReady {
                completion: ResolutionCompletion::Complete,
            })
        }
        fn close(
            &mut self,
            _: &DemandRelationKey,
            _: &[(DemandReferenceKey, &FactResolutionAnswer)],
        ) -> Result<RootClosure> {
            Ok(RootClosure::Published(ResolutionCompletion::Complete))
        }
    }

    #[test]
    fn native_demand_installer_runs_generic_points_and_retains_only_one_caller() {
        let _rules = neutral_fixture::demand_installer_fixture(Language::Go, &FakeInstaller);
        let (store, workspace, snapshots) =
            crate::analyzer::store::resolution_selection::tests::qualifier_completion_gap_fixture();
        let root = tempfile::tempdir().unwrap();
        let project = crate::analyzer::project::TestProject::new(root.path(), Language::Go);
        let cancellation = CancellationToken::new();
        let languages = [
            crate::analyzer::store::resolution_selection::SelectedResolutionLanguage::new(
                "go",
                Language::Go,
            ),
        ];
        let SelectedResolutionOperationOpenOutcome::Ready(mut operation) = store
            .open_selected_resolution_operation(
                SelectedResolutionOperationInput::new(
                    &project,
                    &workspace,
                    &snapshots,
                    &languages,
                    &[],
                ),
                &cancellation,
            )
            .unwrap()
        else {
            panic!("fixture opens");
        };
        // One test-only reference over the real selected store; no language parser is registered.
        operation.ready.inventory.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,zeroblob(32),zeroblob(32))", [])?;
            let producer = connection.last_insert_rowid();
            connection.execute("INSERT INTO temp.selected_resolution_stage_nodes(node,kind,kind_semantic_key) VALUES(0,8,0)", [])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_node_owners(producer_id,node) VALUES(?1,0)", [producer])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_semantics(host_ordinal,producer_id,sequence,semantic_key,node,source_site,role,namespace,start_byte,end_byte,owner_kind) VALUES(0,?1,0,0,0,0,0,0,0,1,0)", [producer])?;
            Ok(())
        }).unwrap();
        let session = ResolutionSession::unbounded();
        let locator = SelectedSemanticLocator::for_reference_range("go", "fixture.go", 0, 1);
        let callbacks = Cell::new(0);
        for _ in 0..2 {
            let context = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let result = operation
                .resolve_reference_with_projection(
                    NativeReferenceQuery {
                        context,
                        locator: &locator,
                        cancellation: &cancellation,
                        context_metrics: &mut SelectedResolutionContextMetrics,
                        session: &session,
                        artifacts: None,
                        go_demand: None,
                        selected_import_gap: None,
                        go_receiver_overlay: None,
                        query_result_slot: None,
                        point_metrics: None,
                    },
                    |_, _, _, _| {
                        callbacks.set(callbacks.get() + 1);
                        Ok(())
                    },
                )
                .unwrap();
            assert!(matches!(
                result,
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(()))
            ));
        }
        assert_eq!((RUNS.get(), callbacks.get()), (2, 2));
        let installer = crate::analyzer::store::store_language_support(Language::Go)
            .unwrap()
            .demand_installer()
            .unwrap();
        for caller in ["other.go", "fixture.go"] {
            assert!(matches!(
                operation
                    .native_demand_preparation(
                        installer,
                        Language::Go,
                        Path::new(caller),
                        &cancellation,
                        &session
                    )
                    .unwrap(),
                NativeDemandPreparationOutcome::Ready(_)
            ));
        }
        CANCEL.set(true);
        for _ in 0..2 {
            assert!(matches!(
                operation
                    .native_demand_preparation(
                        installer,
                        Language::Go,
                        Path::new("cancel.go"),
                        &cancellation,
                        &session
                    )
                    .unwrap(),
                NativeDemandPreparationOutcome::Cancelled
            ));
        }
        CANCEL.set(false);
        assert!(matches!(
            operation
                .native_demand_preparation(
                    installer,
                    Language::Go,
                    Path::new("cancel.go"),
                    &cancellation,
                    &session
                )
                .unwrap(),
            NativeDemandPreparationOutcome::Ready(_)
        ));
        BUILDS.with(|builds| {
            assert_eq!(
                *builds.borrow(),
                [
                    "fixture.go",
                    "other.go",
                    "fixture.go",
                    "cancel.go",
                    "cancel.go",
                    "cancel.go"
                ]
                .map(PathBuf::from)
            )
        });
        UNAVAILABLE.set(true);
        let context = operation
            .empty_contexts(&ResolutionCompletion::Complete)
            .unwrap();
        let outcome = operation
            .resolve_reference_with_projection(
                NativeReferenceQuery {
                    context,
                    locator: &locator,
                    cancellation: &cancellation,
                    context_metrics: &mut SelectedResolutionContextMetrics,
                    session: &session,
                    artifacts: None,
                    go_demand: None,
                    selected_import_gap: None,
                    go_receiver_overlay: None,
                    query_result_slot: None,
                    point_metrics: None,
                },
                |_, _, _, _| -> Result<()> { panic!("unavailable preparation must not resolve") },
            )
            .unwrap();
        assert!(matches!(outcome,
            SelectedResolutionOperationOutcome::Unavailable(
                SelectedResolutionUnavailable::NativeDemandUnavailable { storage_language, persisted_relative_path }
            ) if storage_language == "go" && persisted_relative_path == "fixture.go"
        ));
        assert_eq!(
            RUNS.get(),
            2,
            "unavailable preparation must not run the installer"
        );
        UNAVAILABLE.set(false);
        // Source references ordinarily have local identities. Exercise the generic
        // arm's missing-ordinal contract with an operation-local staged reference.
        let reference = SemanticId::for_test("reference without an ordinal");
        assert!(reference.ordinal().is_none());
        let key = crate::analyzer::store::resolution_stage::codec::encode_semantic(reference);
        operation
            .ready
            .inventory
            .with_owned_temp_write(|connection| {
                connection.execute(
                    "UPDATE temp.selected_resolution_stage_semantics SET semantic_key=?1",
                    [key],
                )?;
                connection.execute(
                    "UPDATE temp.selected_resolution_stage_nodes SET kind_semantic_key=?1",
                    [key],
                )?;
                Ok(())
            })
            .unwrap();
        let builds_before = BUILDS.with(|builds| builds.borrow().clone());
        for has_installer in [true, false] {
            let _plain_rules =
                (!has_installer).then(|| neutral_fixture::neutral_rules_fixture(&[Language::Go]));
            let context = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let outcome = operation
                .resolve_reference_with_projection(
                    NativeReferenceQuery {
                        context,
                        locator: &locator,
                        cancellation: &cancellation,
                        context_metrics: &mut SelectedResolutionContextMetrics,
                        session: &session,
                        artifacts: None,
                        go_demand: None,
                        selected_import_gap: None,
                        go_receiver_overlay: None,
                        query_result_slot: None,
                        point_metrics: None,
                    },
                    |_, _, _, _| {
                        callbacks.set(callbacks.get() + 1);
                        Ok(())
                    },
                )
                .unwrap();
            if has_installer {
                assert!(matches!(outcome,
                    SelectedResolutionOperationOutcome::Unavailable(
                        SelectedResolutionUnavailable::NativeDemandUnavailable { storage_language, persisted_relative_path }
                    ) if storage_language == "go" && persisted_relative_path == "fixture.go"
                ));
                assert_eq!(
                    callbacks.get(),
                    2,
                    "ordinal-free installer references must refuse before projection"
                );
            } else {
                assert!(matches!(
                    outcome,
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(())
                    )
                ));
                assert_eq!(
                    callbacks.get(),
                    3,
                    "without an installer the plain projection must run"
                );
            }
            assert_eq!(RUNS.get(), 2);
            BUILDS.with(|builds| {
                assert_eq!(
                    *builds.borrow(),
                    builds_before,
                    "ordinal-free references must not prepare an installer"
                )
            });
        }
    }
}
