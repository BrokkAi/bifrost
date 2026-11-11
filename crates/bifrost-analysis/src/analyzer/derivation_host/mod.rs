pub mod authority;
mod base_inputs;
mod capture;
pub mod read_frame;
mod unit_kinds;
pub use base_inputs::VerifyHeadIdentityBaseInputs;
pub use capture::AnalyzerCapture;
pub use unit_kinds::{RustUnitSetKind, UnitSummaryKind};

use brokk_bifrost_core::retention_budget::RetentionBudget;
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    Demanded, DerivationAuthority, DerivationEngine, DerivationKind, DerivationKindId,
    DerivationQuestion, DerivationRevision, Handle, OutputIdentity, ReplayedDemand,
    UnavailableCause,
};
use brokk_bifrost_store::analyzer::store::reader_binding::ReaderBinding;
use brokk_bifrost_store::analyzer::store::resolution_operation::SelectedResolutionOperation;
use brokk_bifrost_store::analyzer::store::resolution_operation::rust_selected_operation_active;
use brokk_bifrost_store::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use crate::analyzer::IAnalyzer;
use crate::analyzer::i_analyzer::{
    AnalyzerQueryScope, QueryReadIncomplete, capture_query_reads_deferred,
};
use authority::AnalyzerAuthority;
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::attribution::{self, CoverageClass};
use brokk_bifrost_store::analyzer::store::WorkspaceSnapshotId;
use brokk_bifrost_store::analyzer::store::resolution::resolution_bundle_epoch;
use brokk_bifrost_store::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION;
use brokk_bifrost_store::analyzer::store::unit_summaries::{
    UnitLive, UnitSummaryReconciliation, live_rust_unit_set, live_unit_summary,
};

#[derive(Clone, Copy)]
struct HostPointers {
    analyzer: *const dyn IAnalyzer,
    inventory: Option<*const SelectedResolutionMountInventory<'static>>,
    binding: Option<*const ReaderBinding>,
    operation: Option<*const SelectedResolutionOperation<'static, 'static>>,
}
thread_local! {
    static HOST: RefCell<Vec<HostPointers>> = const { RefCell::new(Vec::new()) };
}

struct HostGuard {
    _frame: Option<read_frame::DemandFrame>,
}
impl HostGuard {
    fn enter(
        analyzer: &dyn IAnalyzer,
        inventory: &SelectedResolutionMountInventory<'_>,
        binding: &ReaderBinding,
    ) -> Self {
        // The guard is dropped before either borrowed value can be dropped.
        let analyzer =
            unsafe { std::mem::transmute::<&dyn IAnalyzer, &'static dyn IAnalyzer>(analyzer) };
        let inventory = unsafe {
            std::mem::transmute::<
                &SelectedResolutionMountInventory<'_>,
                &'static SelectedResolutionMountInventory<'static>,
            >(inventory)
        };
        HOST.with(|host| {
            host.borrow_mut().push(HostPointers {
                analyzer,
                inventory: Some(inventory),
                binding: Some(binding),
                operation: None,
            })
        });
        let identity = read_frame::ReadFrameIdentity {
            analyzer: analyzer as *const dyn IAnalyzer as *const () as usize,
            store: inventory.store_identity(),
            selection: Some(inventory.fingerprint()),
            query_domain: crate::analyzer::i_analyzer::current_request_cache_domain().unwrap_or(0),
            operation: None,
            snapshot: selected_rust_snapshot(inventory).ok(),
        };
        Self {
            _frame: Some(read_frame::DemandFrame::enter(identity, inventory)),
        }
    }
    fn enter_operation(
        analyzer: &dyn IAnalyzer,
        operation: &SelectedResolutionOperation<'_, '_>,
        binding: &ReaderBinding,
    ) -> Self {
        let mut guard = Self::enter(analyzer, &operation.ready.inventory, binding);
        // The demand's operation identity is only required by questions that
        // explicitly name an operation.
        let identity = read_frame::ReadFrameIdentity {
            analyzer: analyzer as *const dyn IAnalyzer as *const () as usize,
            store: operation.ready.inventory.store_identity(),
            selection: Some(operation.ready.inventory.fingerprint()),
            query_domain: crate::analyzer::i_analyzer::current_request_cache_domain().unwrap_or(0),
            operation: Some(operation as *const _ as usize),
            snapshot: selected_rust_snapshot(&operation.ready.inventory).ok(),
        };
        guard._frame.take();
        guard._frame = Some(read_frame::DemandFrame::enter(
            identity,
            &operation.ready.inventory,
        ));
        let operation = unsafe {
            std::mem::transmute::<
                &SelectedResolutionOperation<'_, '_>,
                &'static SelectedResolutionOperation<'static, 'static>,
            >(operation)
        };
        HOST.with(|host| {
            host.borrow_mut()
                .last_mut()
                .expect("host just entered")
                .operation = Some(operation);
        });
        guard
    }
    #[cfg(any(test, feature = "test-support"))]
    fn enter_test(analyzer: &dyn IAnalyzer) -> Self {
        let analyzer =
            unsafe { std::mem::transmute::<&dyn IAnalyzer, &'static dyn IAnalyzer>(analyzer) };
        HOST.with(|host| {
            host.borrow_mut().push(HostPointers {
                analyzer,
                inventory: None,
                binding: None,
                operation: None,
            })
        });
        Self { _frame: None }
    }
}
impl Drop for HostGuard {
    fn drop(&mut self) {
        HOST.with(|host| {
            host.borrow_mut().pop().expect("derivation host underflow");
        });
    }
}

fn current_host() -> HostPointers {
    // Copy the pointers out so the borrow ends before `f` runs: a nested
    // demand inside `f` pushes onto the same stack.
    HOST.with(|host| *host.borrow().last().expect("outside derivation demand"))
}

/// Run `f` with the analyzer of the current demand. The reference cannot
/// escape `f`, so it never outlives the demand that holds the borrow.
pub fn with_current_analyzer<T>(f: impl FnOnce(&dyn IAnalyzer) -> T) -> T {
    let analyzer = current_host().analyzer;
    // SAFETY: HostGuard pops the pointer before the borrowed analyzer can drop.
    f(unsafe { &*analyzer })
}

/// Run `f` with the selected inventory the current demand reads through.
pub fn with_bound_inventory<T>(f: impl FnOnce(&SelectedResolutionMountInventory<'_>) -> T) -> T {
    let inventory = current_host()
        .inventory
        .expect("demand has no bound inventory");
    // SAFETY: HostGuard pops the pointer before the borrowed inventory can drop.
    f(unsafe { &*inventory })
}

/// Whether the head verifier accepts `read` against `analyzer`, through
/// `unchanged` and `unchanged_without_stage`, outside any demand.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn head_read_verifies_for_test(
    analyzer: &dyn IAnalyzer,
    read: &brokk_bifrost_semantic::analyzer::semantic::read_ledger::ReadKey,
) -> (bool, bool) {
    use brokk_bifrost_semantic::analyzer::semantic::derivation::BaseInputs;
    let _host = HostGuard::enter_test(analyzer);
    let binding = ReaderBinding::unestablished();
    let base = VerifyHeadIdentityBaseInputs;
    (
        base.unchanged(read, &binding, &binding, &AnalyzerAuthority::Main),
        base.unchanged_without_stage(read, &binding, &binding, &AnalyzerAuthority::Main),
    )
}

/// Run `f` with the reader binding the current demand was bound under. The
/// engine checks at capture end that the binding is still current, so a
/// compute reads the binding without running SQL.
pub fn with_bound_binding<T>(f: impl FnOnce(&ReaderBinding) -> T) -> T {
    let binding = current_host().binding.expect("demand has no bound binding");
    // SAFETY: HostGuard pops the pointer before the borrowed binding can drop.
    f(unsafe { &*binding })
}

/// Run `f` with the operation the current demand reads through. Access is
/// shared only: the demand holds a lease on the operation's inventory, so
/// nothing reached from a demand may replace or move it.
pub fn with_bound_operation<T>(f: impl FnOnce(&SelectedResolutionOperation<'_, '_>) -> T) -> T {
    let operation = current_host()
        .operation
        .expect("demand has no bound operation");
    // SAFETY: HostGuard pops the pointer before the borrowed operation can drop.
    f(unsafe { &*operation })
}

fn binding_remains_current() -> bool {
    let host = current_host();
    match (host.inventory, host.binding) {
        (Some(inventory), Some(binding)) => {
            unsafe { &*inventory }.derivation_read_still_bound(unsafe { &*binding })
        }
        _ => true,
    }
}

pub struct AnalyzerDerivations {
    engine: DerivationEngine<ReaderBinding, AnalyzerAuthority>,
    declared_route_recipes: Mutex<Vec<(Language, Option<RouteRecipeOpener>)>>,
}

pub type RouteRecipeOpener = fn(
    &dyn IAnalyzer,
    &mut dyn FnMut(&SelectedResolutionMountInventory<'_>),
) -> Result<(), UnavailableCause>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMissing {
    ActiveSelection,
    NoRecipe,
    RecipeUnavailable,
    InvalidQuestion,
    /// The kind is computed only on a lent in-memory operation, which replay
    /// does not have.
    MemoryOnly,
    Refused,
    ChangedHead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayResult {
    Identity(OutputIdentity),
    Missing(ReplayMissing),
}

impl AnalyzerDerivations {
    pub fn new(budget: &RetentionBudget) -> Self {
        let engine = DerivationEngine::new(
            budget,
            Arc::new(AnalyzerCapture::<ReaderBinding, AnalyzerAuthority>::new()),
            Arc::new(VerifyHeadIdentityBaseInputs),
        );
        register_rust_unit_kinds(
            &engine,
            UnitSummaryKind {
                read: Arc::new(read_unit_summary),
            },
            RustUnitSetKind {
                read: Arc::new(read_rust_unit_set),
            },
        );
        let derivations = Self {
            engine,
            declared_route_recipes: Mutex::new(Vec::new()),
        };
        for support in crate::analyzer::languages::registered_language_supports() {
            support.register_derivation_kinds(&derivations);
        }
        derivations
    }

    /// Test-only host with all engine and language kinds, but no declared recipes.
    /// Tests use it to retain a demand whose read cannot be persisted.
    /// Production code must not call this constructor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn without_declared_recipes(budget: &RetentionBudget) -> Self {
        let derivations = Self::new(budget);
        derivations
            .declared_route_recipes
            .lock()
            .expect("recipe registry poisoned")
            .clear();
        derivations
    }

    pub fn register_declared_route_recipe(&self, language: Language) {
        self.declared_route_recipes
            .lock()
            .expect("recipe registry poisoned")
            .push((language, None));
    }

    pub fn register_declared_route_recipe_opener(
        &self,
        language: Language,
        open: RouteRecipeOpener,
    ) {
        self.declared_route_recipes
            .lock()
            .expect("recipe registry poisoned")
            .push((language, Some(open)));
    }

    pub fn registered_question_shapes(
        &self,
    ) -> Vec<brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily>
    {
        self.engine.registered_question_shapes()
    }
    pub fn register<D: DerivationKind>(&self, kind: D) {
        self.engine.register(kind);
    }

    pub fn replay(
        &self,
        analyzer: &dyn IAnalyzer,
        kind: DerivationKindId,
        question: &DerivationQuestion,
    ) -> ReplayResult {
        use ReplayMissing as Missing;
        // Decided before any compute can run: a memory-only kind has no bound
        // operation here, and its compute would panic without one.
        if brokk_bifrost_semantic::analyzer::semantic::read_ledger::PersistedDerivationFamily::of(
            kind.0,
        )
        .is_some_and(|family| family.memory_only)
        {
            return ReplayResult::Missing(Missing::MemoryOnly);
        }
        if read_frame::active() || rust_selected_operation_active() {
            return ReplayResult::Missing(Missing::ActiveSelection);
        }
        let Some(language) = question.language.as_ref() else {
            return ReplayResult::Missing(Missing::NoRecipe);
        };
        let opener = self
            .declared_route_recipes
            .lock()
            .expect("recipe registry poisoned")
            .iter()
            .find(|(registered, open)| registered == language && open.is_some())
            .and_then(|(_, open)| *open);
        let Some(opener) = opener else {
            return ReplayResult::Missing(Missing::NoRecipe);
        };
        let before = analyzer.selected_workspace_snapshots_for_reads();
        let mut result = ReplayResult::Missing(Missing::RecipeUnavailable);
        let opened = opener(analyzer, &mut |inventory| {
            let matches_head = before.as_ref().is_some_and(|snapshots| {
                inventory.languages().is_ok_and(|languages| {
                    languages.iter().all(|selected| {
                        snapshots
                            .values()
                            .any(|snapshot| snapshot == &selected.snapshot_id())
                    })
                })
            });
            if !matches_head {
                result = ReplayResult::Missing(Missing::ChangedHead);
                return;
            }
            let _lease = match inventory.derivation_read() {
                Ok(lease) => lease,
                Err(_) => return,
            };
            let Ok(binding) = inventory.derivation_reader_binding() else {
                return;
            };
            if !matches!(
                AnalyzerAuthority::for_binding(&binding),
                AnalyzerAuthority::Main
            ) || !inventory.proves_declared_rust_route_recipe(&binding)
            {
                return;
            }
            let _host = HostGuard::enter(analyzer, inventory, &binding);
            let ((answer, reasons), receipt) = capture_query_reads_deferred(analyzer, || {
                let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
                let answer =
                    self.engine
                        .replay(kind, question, binding.clone(), AnalyzerAuthority::Main);
                (answer, scope.captured_read_incompleteness())
            });
            let unstable_reason = reasons.iter().any(|reason| {
                !matches!(
                    reason,
                    QueryReadIncomplete::ArtifactUnavailable(_)
                        | QueryReadIncomplete::SemanticEvidenceGap(_)
                )
            });
            if receipt.reuse_refused()
                || receipt.persistence_refusals() != 0
                || receipt.unattributed_reads() != 0
                || receipt.execution_dependences() != 0
                || unstable_reason
                || !inventory.derivation_read_still_bound(&binding)
            {
                result = ReplayResult::Missing(Missing::Refused);
                return;
            }
            result = match answer {
                ReplayedDemand::Available {
                    identity,
                    retained: true,
                    ..
                } => ReplayResult::Identity(identity),
                ReplayedDemand::Unavailable(UnavailableCause::ValidationFailed) => {
                    ReplayResult::Missing(Missing::InvalidQuestion)
                }
                _ => ReplayResult::Missing(Missing::Refused),
            };
        });
        if opened.is_err() {
            return ReplayResult::Missing(Missing::RecipeUnavailable);
        }
        if before.is_none() || before != analyzer.selected_workspace_snapshots_for_reads() {
            return ReplayResult::Missing(Missing::ChangedHead);
        }
        result
    }

    pub fn demand<D: DerivationKind>(
        &self,
        analyzer: &dyn IAnalyzer,
        inventory: &SelectedResolutionMountInventory<'_>,
        key: &D::Key,
    ) -> Demanded<D::Output> {
        // The lease holds this demand's read snapshot; a store error opening
        // it, or reading the binding, makes the demand unavailable.
        let _lease = match inventory.derivation_read() {
            Ok(lease) => lease,
            Err(error) => {
                return Demanded::Unavailable(UnavailableCause::Failed(error.to_string().into()));
            }
        };
        let binding = match inventory.derivation_reader_binding() {
            Ok(binding) => binding,
            Err(error) => {
                return Demanded::Unavailable(UnavailableCause::Failed(error.to_string().into()));
            }
        };
        let authority = AnalyzerAuthority::for_binding(&binding);
        let _host = HostGuard::enter(analyzer, inventory, &binding);
        let admitted = matches!(authority, AnalyzerAuthority::Main)
            && D::question(key).language.as_ref().is_some_and(|language| {
                self.declared_route_recipes
                    .lock()
                    .expect("recipe registry poisoned")
                    .iter()
                    .any(|(registered, _)| registered == language)
            })
            && inventory.proves_declared_rust_route_recipe(&binding);
        let answer = self.engine.demand::<D>(key, binding, authority);
        if matches!(&answer, Demanded::Available { value, .. } if !admitted || !matches!(value, Handle::Retained(_)))
        {
            crate::analyzer::i_analyzer::record_persistence_refusals(analyzer, 1);
        }
        answer
    }

    pub fn demand_in_operation<D: DerivationKind>(
        &self,
        analyzer: &dyn IAnalyzer,
        operation: &SelectedResolutionOperation<'_, '_>,
        key: &D::Key,
    ) -> Demanded<D::Output> {
        let inventory = &operation.ready.inventory;
        let _lease = match inventory.derivation_read() {
            Ok(lease) => lease,
            Err(error) => {
                return Demanded::Unavailable(UnavailableCause::Failed(error.to_string().into()));
            }
        };
        let binding = match inventory.derivation_reader_binding() {
            Ok(binding) => binding,
            Err(error) => {
                return Demanded::Unavailable(UnavailableCause::Failed(error.to_string().into()));
            }
        };
        let authority = AnalyzerAuthority::for_binding(&binding);
        let _host = HostGuard::enter_operation(analyzer, operation, &binding);
        self.engine.demand::<D>(key, binding, authority)
    }

    pub fn try_reuse_in_operation<D: DerivationKind>(
        &self,
        analyzer: &dyn IAnalyzer,
        operation: &SelectedResolutionOperation<'_, '_>,
        authority: AnalyzerAuthority,
        key: &D::Key,
    ) -> Option<Demanded<D::Output>> {
        let inventory = &operation.ready.inventory;
        let _lease = inventory.derivation_read().ok()?;
        let binding = inventory.reader_binding().ok()?;
        let _host = HostGuard::enter_operation(analyzer, operation, &binding);
        self.engine.try_reuse::<D>(key, binding, authority)
    }

    /// Forget the unit derivations a reconcile pass changed: every Rust unit
    /// whose live output changed, appeared or closed, and the unit set when
    /// membership changed. Correctness does not depend on it (the unit kinds
    /// recompute on every new binding); it frees their entries early.
    pub fn forget_rust_units(&self, report: &UnitSummaryReconciliation) {
        let rust = |keys: &[(String, [u8; 32])]| {
            keys.iter()
                .filter(|(lang, _)| lang == "rust")
                .map(|(_, key)| *key)
                .collect::<Vec<_>>()
        };
        let added = rust(&report.added);
        let closed = rust(&report.closed);
        for key in rust(&report.output_changed)
            .iter()
            .chain(&added)
            .chain(&closed)
        {
            self.engine.forget::<UnitSummaryKind>(key);
        }
        if !added.is_empty() || !closed.is_empty() {
            self.engine.forget::<RustUnitSetKind>(&0);
        }
    }

    pub fn counters(
        &self,
        kind: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId,
    ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::KindCounters {
        self.engine.counters(kind)
    }
}

pub fn rust_route_question_identity(
    analyzer: &dyn IAnalyzer,
    store: &brokk_bifrost_store::analyzer::store::AnalyzerStore,
    snapshot: WorkspaceSnapshotId,
) -> read_frame::ReadFrameIdentity {
    read_frame::ReadFrameIdentity {
        analyzer: analyzer as *const dyn IAnalyzer as *const () as usize,
        store: store as *const _ as usize,
        selection: None,
        query_domain: crate::analyzer::i_analyzer::current_request_cache_domain().unwrap_or(0),
        operation: None,
        snapshot: Some(snapshot),
    }
}

pub fn selected_rust_snapshot(
    inventory: &SelectedResolutionMountInventory<'_>,
) -> Result<WorkspaceSnapshotId, String> {
    inventory
        .languages()
        .map_err(|error| error.to_string())?
        .iter()
        .find(|language| language.semantic_language() == Language::Rust)
        .map(|language| language.snapshot_id())
        .ok_or_else(|| "no selected Rust snapshot".to_string())
}

fn read_unit_summary(key: &[u8; 32]) -> Result<UnitLive, String> {
    let _scope = attribution::enter_scope("unit_summary", CoverageClass::RecomputeOnCurrency);
    with_bound_inventory(|inventory| {
        live_unit_summary(
            inventory.connection(),
            &selected_rust_snapshot(inventory)?,
            key,
            resolution_bundle_epoch(Language::Rust),
            RUST_UNIT_SUMMARY_DERIVATION_VERSION,
        )
        .map_err(|error| error.to_string())
    })
}

fn read_rust_unit_set() -> Result<Vec<(String, [u8; 32])>, String> {
    let _scope = attribution::enter_scope("rust_unit_set", CoverageClass::RecomputeOnCurrency);
    with_bound_inventory(|inventory| {
        live_rust_unit_set(
            inventory.connection(),
            &selected_rust_snapshot(inventory)?,
            resolution_bundle_epoch(Language::Rust),
        )
        .map_err(|error| error.to_string())
    })
}

/// Register the two Rust predicates in dependency order. Other languages wait
/// until their question fields determine the exact live-summary predicate.
pub fn register_rust_unit_kinds<R: DerivationRevision, A: DerivationAuthority>(
    engine: &DerivationEngine<R, A>,
    unit_summary: UnitSummaryKind,
    unit_set: RustUnitSetKind,
) {
    engine.register(unit_summary);
    engine.register(unit_set);
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    struct ModelsRead;

    impl DerivationKind for ModelsRead {
        type Key = u8;
        type Output = String;
        const ID: DerivationKindId = DerivationKindId("test:models_read:v1");
        const STRATUM: u16 = 0;
        const VERIFY: Verification = Verification::BaseInputs;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];

        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<String> {
            let value = with_current_analyzer(|analyzer| {
                analyzer
                    .semantic_model_overlay()
                    .map(|overlay| overlay.active_model_set_hash().to_owned())
                    .unwrap_or_else(|| "no-models".to_owned())
            });
            Computed::Available {
                value,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &String, hash: &mut CanonicalHasher) {
            hash.value(value.as_bytes());
        }
    }

    #[test]
    #[hardwon(
        "#9755: a derivation computed before models were acquired verified after acquisition"
    )]
    fn models_read_base_input_invalidates_when_models_are_acquired_and_removed() {
        use crate::analyzer::semantic_model::SemanticModelOverlay;
        use crate::analyzer::semantic_model::runtime::resolved_active_models_fixture;
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let analyzer = MultiAnalyzer::default();
        let budget = RetentionBudget::new(1_000_000);
        let host = AnalyzerDerivations::new(&budget);
        host.engine.register(ModelsRead);
        let overlay = Arc::new(
            SemanticModelOverlay::build(
                &analyzer,
                &Arc::new(resolved_active_models_fixture("test:models-read", vec![])),
                &crate::CancellationToken::default(),
                u64::MAX,
                &budget,
            )
            .unwrap(),
        );
        let demand = |selected| {
            let inventory = fixture.open_ready(&[]);
            let _scope = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, selected);
            match host.demand::<ModelsRead>(&analyzer, &inventory, &0) {
                Demanded::Available { value, .. } => value.to_string(),
                Demanded::Unavailable(cause) => panic!("models read unavailable: {cause:?}"),
            }
        };
        // The entry keeps its reads in its own capture frame, so the absence
        // marker is shown by behavior: phase (c) recomputes only if it was
        // recorded.
        let cold_none = demand(None);
        assert_eq!(cold_none, "no-models");
        let after_first = host.counters(ModelsRead::ID);
        assert_eq!(demand(None), cold_none);
        let unchanged = host.counters(ModelsRead::ID);
        assert_eq!(unchanged.recomputed, after_first.recomputed);
        assert_eq!(
            unchanged.verified_unchanged,
            after_first.verified_unchanged + 1
        );
        let warm_models = demand(Some(overlay.clone()));
        let acquired = host.counters(ModelsRead::ID);
        assert_eq!(acquired.recomputed, unchanged.recomputed + 1);
        let cold_models = {
            let cold_host = AnalyzerDerivations::new(&budget);
            cold_host.engine.register(ModelsRead);
            let cold_inventory = fixture.open_ready(&[]);
            let _scope = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, Some(overlay));
            match cold_host.demand::<ModelsRead>(&analyzer, &cold_inventory, &0) {
                Demanded::Available { value, .. } => value.to_string(),
                Demanded::Unavailable(cause) => panic!("cold models read unavailable: {cause:?}"),
            }
        };
        assert_eq!(warm_models, cold_models);
        assert_ne!(warm_models, cold_none);
        assert_eq!(demand(None), cold_none);
        let removed = host.counters(ModelsRead::ID);
        assert_eq!(removed.recomputed, acquired.recomputed + 1);
        // A model set pinned without an overlay: the overlay still reads as
        // absent, but the absence the entry recorded no longer holds, so it
        // must not verify.
        let snapshot = crate::analyzer::semantic_model::runtime::snapshot_without_overlay_fixture(
            "test:models-read-snapshot",
        );
        {
            let inventory = fixture.open_ready(&[]);
            let _overlay = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, None);
            let _snapshot =
                AnalyzerQueryScope::with_active_semantic_model_snapshot(&analyzer, Some(snapshot));
            assert!(matches!(
                host.demand::<ModelsRead>(&analyzer, &inventory, &0),
                Demanded::Available { .. }
            ));
        }
        assert_eq!(
            host.counters(ModelsRead::ID).recomputed,
            removed.recomputed + 1
        );
    }

    use crate::analyzer::MultiAnalyzer;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::store_support::selection_test_support::SelectionFixture;
    use crate::analyzer::{AnalyzerQueryScope, ReadLedger};
    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
    use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_semantic::analyzer::semantic::derivation::{
        Computed, DerivationFrame, DerivationKindId, DerivationQuestion, NotReusableCause,
        ReuseValidity, Verification,
    };
    use brokk_bifrost_store::analyzer::store::resolution_operation::SelectedResolutionOperationInput;
    use brokk_bifrost_store::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;
    use brokk_bifrost_test_macros::hardwon;

    struct BaseInputProbe;

    impl DerivationKind for BaseInputProbe {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:head_identity_base_input:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];

        fn question(key: &u8) -> DerivationQuestion {
            DerivationQuestion {
                language: None,
                subject: None,
                rel_path: None,
                name: Some(key.to_string().into()),
            }
        }
        fn key_from_question(question: &DerivationQuestion) -> Option<u8> {
            question.name.as_deref()?.parse().ok()
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            key: &u8,
        ) -> Computed<u8> {
            super::with_current_analyzer(|analyzer| {
                if *key == 0 {
                    assert!(analyzer.semantic_model_overlay().is_some());
                } else {
                    analyzer.record_read(crate::analyzer::read_ledger::ReadKey::Configuration(
                        crate::analyzer::semantic::ids::StableDigest::sha256("test:config"),
                    ));
                }
            });
            Computed::Available {
                value: *key,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    #[test]
    fn head_identity_base_reads_verify_and_other_reads_recompute() {
        use crate::analyzer::semantic_model::SemanticModelOverlay;
        use crate::analyzer::semantic_model::runtime::resolved_active_models_fixture;
        let analyzer = MultiAnalyzer::default();
        let budget = RetentionBudget::new(1_000_000);
        let host = AnalyzerDerivations::new(&budget);
        host.register(BaseInputProbe);
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let overlay = |hash: &str| {
            let active = Arc::new(resolved_active_models_fixture(hash, vec![]));
            Arc::new(
                SemanticModelOverlay::build(
                    &analyzer,
                    &active,
                    &crate::CancellationToken::default(),
                    u64::MAX,
                    &budget,
                )
                .unwrap(),
            )
        };
        let first = overlay("test:first");
        let second = overlay("test:second");
        // A request pins its snapshot and overlay together; the Models read
        // verifies only while both name the recorded set.
        let demand = |key, selected: Arc<SemanticModelOverlay>| {
            let _snapshot = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                &analyzer,
                Some(
                    crate::analyzer::semantic_model::runtime::snapshot_without_overlay_fixture(
                        selected.active_model_set_hash(),
                    ),
                ),
            );
            let _scope = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, Some(selected));
            let inventory = fixture.open_ready(&[]);
            assert!(matches!(
                host.demand::<BaseInputProbe>(&analyzer, &inventory, &key),
                Demanded::Available { .. }
            ));
        };
        demand(0, first.clone());
        demand(0, first);
        assert_eq!(host.counters(BaseInputProbe::ID).verified_unchanged, 1);
        assert_eq!(host.counters(BaseInputProbe::ID).recomputed, 1);
        demand(0, second);
        assert_eq!(host.counters(BaseInputProbe::ID).recomputed, 2);
        demand(1, overlay("test:second"));
        demand(1, overlay("test:second"));
        assert_eq!(host.counters(BaseInputProbe::ID).recomputed, 4);
    }

    #[test]
    fn main_only_verification_agrees_with_head_identity() {
        use crate::analyzer::semantic_model::SemanticModelOverlay;
        use crate::analyzer::semantic_model::runtime::resolved_active_models_fixture;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::BaseInputs;
        let analyzer = MultiAnalyzer::default();
        let budget = RetentionBudget::new(1_000_000);
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let binding = fixture.open_ready(&[]).reader_binding().unwrap();
        let overlay = |hash: &str| {
            let active = Arc::new(resolved_active_models_fixture(hash, vec![]));
            Arc::new(
                SemanticModelOverlay::build(
                    &analyzer,
                    &active,
                    &crate::CancellationToken::default(),
                    u64::MAX,
                    &budget,
                )
                .unwrap(),
            )
        };
        let first = overlay("test:first");
        let models = crate::analyzer::read_ledger::ReadKey::Models(
            crate::analyzer::i_analyzer::active_model_digest(first.active_model_set_hash()),
        );
        let configuration = crate::analyzer::read_ledger::ReadKey::Configuration(
            crate::analyzer::semantic::ids::StableDigest::sha256("test:config"),
        );
        for (selected, models_unchanged) in [(first.clone(), true), (overlay("test:second"), false)]
        {
            let _snapshot = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                &analyzer,
                Some(
                    crate::analyzer::semantic_model::runtime::snapshot_without_overlay_fixture(
                        selected.active_model_set_hash(),
                    ),
                ),
            );
            let _scope = AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, Some(selected));
            let _host = HostGuard::enter_test(&analyzer);
            for (read, unchanged) in [(&models, models_unchanged), (&configuration, false)] {
                let authority = AnalyzerAuthority::Main;
                let base = VerifyHeadIdentityBaseInputs;
                assert_eq!(
                    base.unchanged(read, &binding, &binding, &authority),
                    unchanged,
                    "{read:?}"
                );
                assert_eq!(
                    base.unchanged_without_stage(read, &binding, &binding, &authority),
                    unchanged,
                    "{read:?}"
                );
            }
        }
    }

    #[test]
    #[hardwon(
        "#9737: a derivation demanded on a helper thread under a carried frame dropped its lookup"
    )]
    fn helper_thread_derivation_lookup_reaches_carried_ledger_only() {
        use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{LookupKind, ReadKey};

        let analyzer = Arc::new(MultiAnalyzer::default());
        let ledger = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer.as_ref(), ledger.clone());
        let carried = CarriedContext::current();
        let demand = |analyzer: Arc<MultiAnalyzer>| {
            let fixture = SelectionFixture::with_blob_writer(
                AnalyzerStore::open_ephemeral().unwrap(),
                0,
                "rust",
                Language::Rust,
                false,
                false,
                |_, _, _, _, _| {},
            );
            let inventory = fixture.open_ready(&[]);
            inventory.stamp_declared_rust_route_recipe();
            let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
            host.register_declared_route_recipe(Language::Rust);
            assert!(matches!(
                host.demand::<RustUnitSetKind>(analyzer.as_ref(), &inventory, &0),
                Demanded::Available { .. }
            ));
        };
        let unframed_analyzer = analyzer.clone();
        std::thread::spawn(move || demand(unframed_analyzer))
            .join()
            .unwrap();
        assert!(
            ledger.keys().is_empty(),
            "unframed demand reached another reader"
        );

        let framed_analyzer = analyzer.clone();
        std::thread::spawn(move || carried.run(|| demand(framed_analyzer)))
            .join()
            .unwrap();
        assert!(ledger.keys().iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                kind: LookupKind::Derivation(RustUnitSetKind::ID),
                ..
            }
        )));
    }

    #[test]
    fn unproved_rust_route_recipe_refuses_read_on_fill_and_hit() {
        use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{LookupKind, ReadKey};

        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let inventory = fixture.open_ready(&[]);
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.register_declared_route_recipe(Language::Rust);
        for _ in 0..2 {
            let ledger = Arc::new(ReadLedger::new());
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            assert!(matches!(
                host.demand::<RustUnitSetKind>(&analyzer, &inventory, &0),
                Demanded::Available { .. }
            ));
            assert!(!ledger.reuse_refused());
            assert_eq!(ledger.persistence_refusals(), 1);
            assert!(ledger.keys().iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(RustUnitSetKind::ID),
                    ..
                }
            )));
        }
        inventory.stamp_declared_rust_route_recipe();
        let ledger = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        assert!(matches!(
            host.demand::<RustUnitSetKind>(&analyzer, &inventory, &0),
            Demanded::Available { .. }
        ));
        assert!(!ledger.reuse_refused());
        assert_eq!(ledger.persistence_refusals(), 0);
        assert!(ledger.keys().iter().any(|key| matches!(
            key,
            ReadKey::Lookup {
                kind: LookupKind::Derivation(RustUnitSetKind::ID),
                ..
            }
        )));
    }

    #[test]
    #[hardwon(
        "#9737: a nested ledger hid a derivation persistence refusal from its outer consumer"
    )]
    fn derivation_refusal_reaches_nested_and_outer_ledgers() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let inventory = fixture.open_ready(&[]);
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.register_declared_route_recipe(Language::Rust);
        for _ in 0..2 {
            let outer = Arc::new(ReadLedger::new());
            let inner = Arc::new(ReadLedger::new());
            let _outer = AnalyzerQueryScope::with_read_ledger(&analyzer, outer.clone());
            {
                let _inner = AnalyzerQueryScope::with_read_ledger(&analyzer, inner.clone());
                assert!(matches!(
                    host.demand::<RustUnitSetKind>(&analyzer, &inventory, &0),
                    Demanded::Available { .. }
                ));
            }
            assert_eq!(inner.persistence_refusals(), 1);
            assert_eq!(outer.persistence_refusals(), 1);
            assert_eq!(inner.keys(), outer.keys());
        }
    }

    #[test]
    fn stamped_rust_route_recipe_records_read_on_fill_and_hit() {
        use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{LookupKind, ReadKey};

        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let inventory = fixture.open_ready(&[]);
        inventory.stamp_declared_rust_route_recipe();
        let _lease = inventory.derivation_read().unwrap().unwrap();
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.register_declared_route_recipe(Language::Rust);
        for _ in 0..2 {
            let ledger = Arc::new(ReadLedger::new());
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            assert!(matches!(
                host.demand::<RustUnitSetKind>(&analyzer, &inventory, &0),
                Demanded::Available {
                    value: Handle::Retained(_),
                    ..
                }
            ));
            assert_eq!(ledger.persistence_refusals(), 0);
            assert!(!ledger.reuse_refused());
            assert!(ledger.keys().iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    kind: LookupKind::Derivation(RustUnitSetKind::ID),
                    ..
                }
            )));
        }
        let counters = host.counters(RustUnitSetKind::ID);
        assert_eq!((counters.recomputed, counters.current_hits), (1, 1));
    }

    #[test]
    fn stamped_rust_route_recipe_refuses_unproved_stage_on_fill_and_hit() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let inventory = fixture.open_ready(&[]);
        inventory.stamp_declared_rust_route_recipe();
        let lease = inventory.derivation_read().unwrap().unwrap();
        inventory
            .with_owned_temp_write(|conn| {
                Ok(conn.execute_batch("CREATE TEMP TABLE derivation_recipe_stage(value INTEGER)")?)
            })
            .unwrap();
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.register_declared_route_recipe(Language::Rust);
        for _ in 0..2 {
            let ledger = Arc::new(ReadLedger::new());
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            assert!(matches!(
                host.demand::<RustUnitSetKind>(&analyzer, &inventory, &0),
                Demanded::Available { .. }
            ));
            assert_eq!(ledger.persistence_refusals(), 1);
            assert!(!ledger.keys().is_empty());
        }
        host.engine.register(LeafRouteRead);
        host.engine.register(NestedRouteRead);
        let ledger = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        assert!(matches!(
            host.demand::<NestedRouteRead>(&analyzer, &inventory, &0),
            Demanded::Available { .. }
        ));
        // One refusal from the host (the test kind is not an admitted recipe)
        // and one from the engine (the parent read a lookup of a kind outside
        // the persisted codec).
        assert_eq!(ledger.persistence_refusals(), 2);
        assert!(!ledger.keys().is_empty());
        drop(lease);
    }

    struct LeafRouteRead;
    struct OuterHostRead {
        inner: Arc<AnalyzerDerivations>,
    }
    impl DerivationKind for OuterHostRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:outer_host_read:v1");
        const STRATUM: u16 = 1;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[(LeafRouteRead::ID, 0)];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            let value = with_current_analyzer(|analyzer| {
                with_bound_inventory(|inventory| {
                    match self.inner.demand::<LeafRouteRead>(analyzer, inventory, &0) {
                        Demanded::Available { value, .. } => *value,
                        Demanded::Unavailable(cause) => panic!("inner demand failed: {cause:?}"),
                    }
                })
            });
            Computed::Available {
                value,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    #[test]
    fn nested_host_refusal_replays_on_retained_outer_hit() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let inventory = fixture.open_ready(&[]);
        inventory.stamp_declared_rust_route_recipe();
        let analyzer = MultiAnalyzer::default();
        let budget = RetentionBudget::new(1_000_000);
        let inner = Arc::new(AnalyzerDerivations::new(&budget));
        inner.engine.register(LeafRouteRead);
        let outer = AnalyzerDerivations::new(&budget);
        outer.register_declared_route_recipe(Language::Rust);
        outer.engine.register(LeafRouteRead);
        outer.engine.register(OuterHostRead { inner });
        for _ in 0..2 {
            let ledger = Arc::new(ReadLedger::new());
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            assert!(matches!(
                outer.demand::<OuterHostRead>(&analyzer, &inventory, &0),
                Demanded::Available {
                    value: Handle::Retained(_),
                    validity: ReuseValidity::Reusable,
                    ..
                }
            ));
            assert_eq!(ledger.persistence_refusals(), 1);
            assert!(!ledger.reuse_refused());
        }
        let counters = outer.counters(OuterHostRead::ID);
        assert_eq!(counters.recomputed, 1);
        assert_eq!(counters.current_hits + counters.verified_unchanged, 1);
    }

    #[test]
    fn request_owned_child_refuses_persistence_without_invalidating_parent() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let inventory = fixture.open_ready(&[]);
        inventory.stamp_declared_rust_route_recipe();
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1));
        host.register_declared_route_recipe(Language::Rust);
        host.engine.register(LeafRouteRead);
        host.engine.register(NestedRouteRead);
        let ledger = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
        assert!(matches!(
            host.demand::<NestedRouteRead>(&analyzer, &inventory, &0),
            Demanded::Available {
                value: Handle::RequestOwned(_),
                validity: ReuseValidity::Reusable,
                ..
            }
        ));
        // The host refuses the request-owned answer; the engine also refuses
        // the parent, which read a lookup of a kind outside the persisted codec.
        assert_eq!(ledger.persistence_refusals(), 2);
    }

    impl DerivationKind for LeafRouteRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:leaf_route_read:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            Computed::Available {
                value: 1,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    struct NestedRouteRead;
    impl DerivationKind for NestedRouteRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:nested_route_read:v1");
        const STRATUM: u16 = 1;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[(LeafRouteRead::ID, 0)];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            frame: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            let value = match frame.demand::<LeafRouteRead>(&0) {
                Demanded::Available { value, .. } => *value,
                Demanded::Unavailable(_) => {
                    return Computed::Unavailable(UnavailableCause::ChildUnavailable);
                }
            };
            Computed::Available {
                value,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    struct OperationRead;
    impl DerivationKind for OperationRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:bound_operation_read:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            let count = with_bound_operation(|outer| {
                let count = outer.ready.inventory.languages().unwrap().len() as u8;
                with_bound_operation(|inner| {
                    assert!(std::ptr::eq(outer, inner));
                });
                count
            });
            Computed::Available {
                value: count,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    struct StageRead;
    impl DerivationKind for StageRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:crate_stage_read:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            with_bound_operation(|operation| {
                let inventory = &operation.ready.inventory;
                let analyzer = with_current_analyzer(|analyzer| {
                    analyzer as *const dyn IAnalyzer as *const () as usize
                });
                let question = read_frame::ReadFrameIdentity {
                    analyzer,
                    store: inventory.store_identity(),
                    selection: Some(inventory.fingerprint()),
                    query_domain: crate::analyzer::i_analyzer::current_request_cache_domain()
                        .unwrap_or(0),
                    operation: None,
                    snapshot: selected_rust_snapshot(inventory).ok(),
                };
                let before = read_frame::unframed_route_questions_for_test();
                assert_eq!(
                    read_frame::with_read_frame(
                        &question,
                        || panic!("demand frame opened another selection"),
                        |selected| selected.fingerprint(),
                    )
                    .unwrap(),
                    question.selection.unwrap(),
                );
                assert_eq!(read_frame::unframed_route_questions_for_test(), before);
                let binding = inventory.reader_binding().unwrap();
                {
                    let _stage = operation.crate_stage_memos().unwrap();
                    assert!(!inventory.connection().is_autocommit());
                }
                assert!(!inventory.connection().is_autocommit());
                assert_eq!(inventory.reader_binding().unwrap(), binding);
            });
            Computed::Available {
                value: 1,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    #[test]
    fn operation_demand_reads_its_inventory() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let languages = [fixture.language()];
        let input = SelectedResolutionOperationInput::new(
            &project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &languages,
            &[],
        );
        let operation = crate::analyzer::store_support::test_support::operation_fixture_support::open_ready_operation(
            &fixture.store,
            input,
            &crate::CancellationToken::default(),
        );
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.engine.register(OperationRead);
        assert!(
            matches!(host.demand_in_operation::<OperationRead>(&analyzer, &operation, &0), Demanded::Available { value, .. } if *value == 1)
        );
    }

    // The check is a debug assertion in ReadySelectedResolution's Drop, so
    // the measure profile (release with debug assertions off) cannot run it.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "operation read frame outlived its operation")]
    fn operation_read_frame_must_end_before_operation() {
        use super::read_frame::{OperationReadFrame, ReadFrameIdentity};
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let languages = [fixture.language()];
        let input = SelectedResolutionOperationInput::new(
            &project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &languages,
            &[],
        );
        let operation = crate::analyzer::store_support::test_support::operation_fixture_support::open_ready_operation(
            &fixture.store, input, &crate::CancellationToken::default(),
        );
        let analyzer = MultiAnalyzer::default();
        let identity = ReadFrameIdentity {
            analyzer: &analyzer as *const _ as usize,
            store: &fixture.store as *const _ as usize,
            selection: Some(operation.ready.inventory.fingerprint()),
            query_domain: 1,
            operation: Some(&operation as *const _ as usize),
            snapshot: None,
        };
        let _frame = OperationReadFrame::enter(identity, &operation).unwrap();
        drop(operation);
    }

    #[test]
    #[should_panic(expected = "no read frame may span a writer loan")]
    fn operation_read_frame_must_end_before_writer_loan() {
        use super::read_frame::{OperationReadFrame, ReadFrameIdentity};
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let languages = [fixture.language()];
        let input = SelectedResolutionOperationInput::new(
            &project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &languages,
            &[],
        );
        let mut operation = crate::analyzer::store_support::test_support::operation_fixture_support::open_ready_operation(
            &fixture.store, input, &crate::CancellationToken::default(),
        );
        let analyzer = MultiAnalyzer::default();
        let identity = ReadFrameIdentity {
            analyzer: &analyzer as *const _ as usize,
            store: &fixture.store as *const _ as usize,
            selection: Some(operation.ready.inventory.fingerprint()),
            query_domain: 1,
            operation: Some(&operation as *const _ as usize),
            snapshot: None,
        };
        let _frame = OperationReadFrame::enter(identity, &operation).unwrap();
        let _inventory = std::rc::Rc::get_mut(&mut operation.ready.inventory)
            .expect("no read frame may span a writer loan");
    }

    #[test]
    fn operation_read_frame_reuses_only_matching_identity_and_unwinds() {
        use super::read_frame::{ReadFrameIdentity, with_operation_read_frame, with_read_frame};
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let languages = [fixture.language()];
        let input = SelectedResolutionOperationInput::new(
            &project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &languages,
            &[],
        );
        let mut operation = crate::analyzer::store_support::test_support::operation_fixture_support::open_ready_operation(
            &fixture.store, input, &crate::CancellationToken::default(),
        );
        let analyzer = MultiAnalyzer::default();
        let identity = ReadFrameIdentity {
            analyzer: &analyzer as *const _ as usize,
            store: &fixture.store as *const _ as usize,
            selection: Some(operation.ready.inventory.fingerprint()),
            query_domain: 1,
            operation: Some(&operation as *const _ as usize),
            snapshot: None,
        };
        let before = super::read_frame::unframed_route_questions_for_test();
        {
            let _frame =
                super::read_frame::OperationReadFrame::enter(identity.clone(), &operation).unwrap();
            let _mutable_operation = &mut operation;
            let mut question = identity.clone();
            question.operation = None;
            assert_eq!(
                with_read_frame(
                    &question,
                    || panic!("guard opened another inventory"),
                    |inventory| inventory.fingerprint()
                )
                .unwrap(),
                identity.selection.unwrap(),
            );
            assert_eq!(
                super::read_frame::unframed_route_questions_for_test(),
                before
            );
        }
        assert_eq!(super::read_frame::read_frame_depth_for_test(), 0);
        with_operation_read_frame(identity.clone(), &operation, || {
            let mut question = identity.clone();
            question.operation = None;
            assert_eq!(
                with_read_frame(
                    &question,
                    || panic!("operation frame opened selection for question"),
                    |inventory| inventory.fingerprint()
                )
                .unwrap(),
                identity.selection.unwrap(),
            );
            assert_eq!(
                with_read_frame(
                    &identity,
                    || panic!("matching frame opened selection"),
                    |inventory| inventory.fingerprint()
                )
                .unwrap(),
                identity.selection.unwrap(),
            );
            let other_store = AnalyzerStore::open_ephemeral().unwrap();
            let mut foreign = question.clone();
            foreign.store = &other_store as *const _ as usize;
            assert!(
                with_read_frame(
                    &foreign,
                    || panic!("foreign store opened selection"),
                    |_| ()
                )
                .is_err()
            );
            let mut other = identity.clone();
            other.query_domain += 1;
            assert!(with_read_frame(&other, || panic!("nested selected open"), |_| ()).is_err());
        })
        .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_operation_read_frame(identity.clone(), &operation, || panic!("unwind guard"))
                .unwrap();
        }));
        assert!(result.is_err());
        assert!(with_read_frame(&identity, || panic!("unframed selected open"), |_| ()).is_err());
        drop(operation);
        let mut unframed = identity.clone();
        unframed.operation = None;
        let before = super::read_frame::unframed_route_questions_for_test();
        let answer = with_read_frame(
            &unframed,
            || {
                use brokk_bifrost_store::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
                match fixture.store.open_selected_resolution_mount_inventory(
                    &fixture.workspace_id,
                    &fixture.snapshots,
                    &languages,
                    &[],
                    &crate::CancellationToken::default(),
                ).unwrap() {
                    SelectedResolutionMountInventoryOutcome::Ready(inventory) => Ok(*inventory),
                    _ => panic!("fixture selection unavailable"),
                }
            },
            |inventory| inventory.fingerprint(),
        ).unwrap();
        assert_eq!(answer, unframed.selection.unwrap());
        assert_eq!(
            super::read_frame::unframed_route_questions_for_test(),
            before + 1
        );
    }

    #[test]
    fn question_without_selection_matches_only_its_snapshot_and_domain() {
        use super::read_frame::ReadFrameIdentity;
        let frame = ReadFrameIdentity {
            analyzer: 1,
            store: 2,
            selection: Some([3; 32]),
            query_domain: 4,
            operation: None,
            snapshot: Some(crate::analyzer::store::WorkspaceSnapshotId {
                workspace_id: crate::analyzer::store::WorkspaceId("question-control".to_string()),
                lang: "rust".to_string(),
                generation: crate::analyzer::store::GenerationId(1),
                revision: 1,
            }),
        };
        let mut question = frame.clone();
        question.selection = None;
        assert!(frame.matches_question(&question));
        question.query_domain = 5;
        assert!(!frame.matches_question(&question));
        question.query_domain = 4;
        question.snapshot.as_mut().unwrap().revision = 2;
        assert!(!frame.matches_question(&question));
        question.snapshot = frame.snapshot.clone();
        question.analyzer = 9;
        assert!(!frame.matches_question(&question));
        question.analyzer = 1;
        question.store = 9;
        assert!(!frame.matches_question(&question));
    }

    #[test]
    fn rayon_read_frame_is_removed_after_callback_and_unwind() {
        use super::read_frame::{
            ReadFrameIdentity, read_frame_depth_for_test, with_query_read_frame, with_read_frame,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;
        let identity = ReadFrameIdentity {
            analyzer: 1,
            store: 2,
            selection: Some([3; 32]),
            query_domain: 4,
            operation: None,
            snapshot: None,
        };
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        pool.install(|| {
            with_query_read_frame(
                identity.clone(),
                || Err::<SelectedResolutionMountInventory<'_>, _>(UnavailableCause::Cancelled),
                || {
                    assert!(matches!(
                        with_read_frame(&identity, || panic!("frame opened twice"), |_| ()),
                        Err(UnavailableCause::Cancelled)
                    ))
                },
            );
            assert_eq!(read_frame_depth_for_test(), 0);
            let first = std::panic::catch_unwind(|| {
                with_query_read_frame(
                    identity.clone(),
                    || Err::<SelectedResolutionMountInventory<'_>, _>(UnavailableCause::Cancelled),
                    || panic!("worker unwind"),
                );
            });
            assert!(first.is_err());
            assert_eq!(read_frame_depth_for_test(), 0);
            assert!(matches!(
                with_read_frame(
                    &identity,
                    || Err::<SelectedResolutionMountInventory<'_>, _>(
                        UnavailableCause::ValidationFailed
                    ),
                    |_| ()
                ),
                Err(UnavailableCause::ValidationFailed)
            ));
        });
    }

    #[test]
    fn query_frame_reuses_selected_operation_frame() {
        use super::read_frame::{
            ReadFrameIdentity, read_frame_depth_for_test, with_query_read_frame,
        };
        use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;
        let operation = ReadFrameIdentity {
            analyzer: 1,
            store: 2,
            selection: Some([3; 32]),
            query_domain: 4,
            operation: Some(5),
            snapshot: None,
        };
        let mut query = operation.clone();
        query.selection = None;
        query.operation = None;
        with_query_read_frame(
            operation,
            || Err::<SelectedResolutionMountInventory<'_>, _>(UnavailableCause::Cancelled),
            || {
                with_query_read_frame(
                    query,
                    || panic!("nested query opened another selection"),
                    || assert_eq!(read_frame_depth_for_test(), 1),
                );
            },
        );
        assert_eq!(read_frame_depth_for_test(), 0);
    }

    #[test]
    fn crate_stage_borrows_lease_read_and_ends_once() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let languages = [fixture.language()];
        let input = SelectedResolutionOperationInput::new(
            &project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &languages,
            &[],
        );
        let operation = crate::analyzer::store_support::test_support::operation_fixture_support::open_ready_operation(
            &fixture.store,
            input,
            &crate::CancellationToken::default(),
        );
        let inventory: &SelectedResolutionMountInventory<'_> =
            unsafe { &*(&*operation.ready.inventory as *const _) };
        let lease = inventory.derivation_read().unwrap().unwrap();
        let binding = inventory.reader_binding().unwrap();
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.engine.register(StageRead);
        assert!(
            matches!(host.demand_in_operation::<StageRead>(&analyzer, &operation, &0), Demanded::Available { value, .. } if *value == 1)
        );
        assert_eq!(inventory.reader_binding().unwrap(), binding);
        assert!(!inventory.connection().is_autocommit());
        drop(lease);
        assert!(inventory.connection().is_autocommit());
        assert_ne!(inventory.reader_binding().unwrap(), binding);
    }

    #[test]
    fn demand_after_temp_write_in_crate_stage_is_unproved() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let root = tempfile::tempdir().unwrap();
        let project = TestProject::new(root.path(), Language::Rust);
        let languages = [fixture.language()];
        let input = SelectedResolutionOperationInput::new(
            &project,
            &fixture.workspace_id,
            &fixture.snapshots,
            &languages,
            &[],
        );
        let operation = crate::analyzer::store_support::test_support::operation_fixture_support::open_ready_operation(
            &fixture.store,
            input,
            &crate::CancellationToken::default(),
        );
        let inventory = &*operation.ready.inventory;
        let _stage = operation.crate_stage_memos().unwrap();
        inventory
            .with_owned_temp_write(|conn| {
                Ok(conn.execute_batch("CREATE TEMP TABLE derivation_stage_probe(value INTEGER)")?)
            })
            .unwrap();
        assert_eq!(
            AnalyzerAuthority::for_binding(&inventory.reader_binding().unwrap()),
            AnalyzerAuthority::UnprovedStage
        );
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        let outcome = host.demand::<RustUnitSetKind>(&analyzer, inventory, &0);
        let validity = match outcome {
            Demanded::Available { validity, .. } => validity,
            Demanded::Unavailable(_) => panic!("unavailable"),
        };
        assert_eq!(
            validity,
            ReuseValidity::NotReusable(NotReusableCause::UnprovedStage)
        );
    }

    struct PauseRead;
    impl DerivationKind for PauseRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:pause_read:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            // Attribute the SQL so only the binding check can refuse reuse.
            let _scope =
                attribution::enter_scope("pause_probe", CoverageClass::RecomputeOnCurrency);
            with_bound_inventory(|inventory| {
                inventory.pause_stage_read().unwrap();
                inventory.resume_stage_read().unwrap();
            });
            Computed::Available {
                value: 1,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    #[test]
    fn pause_during_demand_refuses_retention() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.engine.register(PauseRead);
        let read = fixture.open_ready(&[]);
        match host.demand::<PauseRead>(&analyzer, &read, &0) {
            Demanded::Available {
                value:
                    brokk_bifrost_semantic::analyzer::semantic::derivation::Handle::RequestOwned(_),
                validity: ReuseValidity::NotReusable(_),
                ..
            } => {}
            _ => panic!("paused demand must be request owned"),
        }
    }

    struct DirectStageWriteRead;
    impl DerivationKind for DirectStageWriteRead {
        type Key = u8;
        type Output = u8;
        const ID: DerivationKindId = DerivationKindId("test:direct_stage_write_read:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(q: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(q)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<u8> {
            // A direct temp write keeps the read transaction open, so only the
            // stage epoch records that later reads saw different content. The
            // SQL is attributed so only the binding check can refuse reuse.
            let _scope = attribution::enter_scope(
                "direct_stage_write_probe",
                CoverageClass::RecomputeOnCurrency,
            );
            with_bound_inventory(|inventory| {
                inventory
                    .with_owned_temp_write(|conn| {
                        Ok(conn.execute_batch(
                            "CREATE TEMP TABLE derivation_demand_probe(value INTEGER)",
                        )?)
                    })
                    .unwrap();
            });
            Computed::Available {
                value: 1,
                complete: true,
                validity: ReuseValidity::Reusable,
            }
        }
        fn output_projection(value: &u8, hash: &mut CanonicalHasher) {
            hash.value(&[*value]);
        }
    }

    #[test]
    #[hardwon("#9737: a direct stage write inside a demand left its binding current")]
    fn direct_stage_write_during_demand_refuses_retention() {
        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let analyzer = MultiAnalyzer::default();
        let host = AnalyzerDerivations::new(&RetentionBudget::new(1_000_000));
        host.engine.register(DirectStageWriteRead);
        let read = fixture.open_ready(&[]);
        match host.demand::<DirectStageWriteRead>(&analyzer, &read, &0) {
            Demanded::Available {
                value:
                    brokk_bifrost_semantic::analyzer::semantic::derivation::Handle::RequestOwned(_),
                validity: ReuseValidity::NotReusable(_),
                ..
            } => {}
            _ => panic!("a demand that wrote its stage must be request owned"),
        }
    }

    struct UnitSetParent {
        gate: Option<Arc<Gate>>,
    }
    struct Gate {
        first: std::sync::atomic::AtomicBool,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl DerivationKind for UnitSetParent {
        type Key = u8;
        type Output = [u8; 32];
        const ID: DerivationKindId = DerivationKindId("test:rust_unit_set_parent:v1");
        const STRATUM: u16 = 1;
        const CHILDREN: &'static [(DerivationKindId, u16)] =
            &[(RustUnitSetKind::ID, RustUnitSetKind::STRATUM)];
        fn question(_: &u8) -> DerivationQuestion {
            RustUnitSetKind::question(&0)
        }
        fn key_from_question(question: &DerivationQuestion) -> Option<u8> {
            RustUnitSetKind::key_from_question(question)
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            frame: &mut DerivationFrame<'_, R, A>,
            _: &u8,
        ) -> Computed<[u8; 32]> {
            if let Some(gate) = &self.gate
                && gate.first.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                gate.entered.send(()).unwrap();
                gate.release.lock().unwrap().recv().unwrap();
            }
            match frame.demand::<RustUnitSetKind>(&0) {
                Demanded::Available { value, .. } => Computed::Available {
                    value: *value,
                    complete: true,
                    validity: ReuseValidity::Reusable,
                },
                Demanded::Unavailable(cause) => Computed::Unavailable(cause),
            }
        }
        fn output_projection(value: &[u8; 32], hash: &mut CanonicalHasher) {
            hash.value(value);
        }
    }

    #[test]
    fn real_selected_reader_demands_are_root_local() {
        let fixture = || {
            SelectionFixture::with_blob_writer(
                AnalyzerStore::open_ephemeral().unwrap(),
                0,
                "rust",
                Language::Rust,
                false,
                false,
                |_, _, _, _, _| {},
            )
        };
        let mut first = fixture();
        let second = fixture();
        let analyzer = MultiAnalyzer::default();
        let budget = RetentionBudget::new(1_000_000);
        let first_host = AnalyzerDerivations::new(&budget);
        let second_host = AnalyzerDerivations::new(&budget);
        first_host.engine.register(UnitSetParent { gate: None });
        first_host.register_declared_route_recipe(Language::Rust);
        second_host.engine.register(UnitSetParent { gate: None });
        second_host.register_declared_route_recipe(Language::Rust);
        let read = first.open_ready(&[]);
        read.stamp_declared_rust_route_recipe();
        let initial = match first_host.demand::<UnitSetParent>(&analyzer, &read, &0) {
            Demanded::Available { value, .. } => *value,
            Demanded::Unavailable(cause) => panic!("initial unit set unavailable: {cause:?}"),
        };
        drop(read);
        // A main-database edit outside the selected Rust inputs moves currency.
        first.store.conn.execute(|conn| {
            conn.execute_batch("CREATE TABLE derivation_unrelated_edit(value INTEGER)")
                .unwrap();
        });
        let read = first.open_ready(&[]);
        read.stamp_declared_rust_route_recipe();
        let unchanged = match first_host.demand::<UnitSetParent>(&analyzer, &read, &0) {
            Demanded::Available { value, .. } => *value,
            Demanded::Unavailable(cause) => panic!("unchanged unit set unavailable: {cause:?}"),
        };
        assert_eq!(initial, unchanged);
        let counters = first_host.counters(RustUnitSetKind::ID);
        assert_eq!(counters.current_hits, 0);
        assert_eq!(counters.recomputed, 2);
        assert_eq!(first_host.counters(UnitSetParent::ID).verified_unchanged, 1);
        assert_eq!(first_host.counters(UnitSetParent::ID).recomputed, 1);
        drop(read);
        let generation = first.snapshots["rust"].generation.get();
        let epoch = resolution_bundle_epoch(Language::Rust).to_owned();
        first.store.conn.execute(move |conn| {
            use rusqlite::params;
            let unit_key = [7_u8; 32];
            conn.execute("INSERT INTO workspace_revisions(workspace_id,lang,generation,revision) SELECT workspace_id,lang,generation,2 FROM workspace_revisions WHERE lang='rust' AND revision=1", []).unwrap();
            conn.execute("UPDATE workspace_heads SET revision=2 WHERE lang='rust'", []).unwrap();
            conn.execute(
                "INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,output_digest,publication_state)
                 VALUES(1001,'rust','rust_crate',?1,?1,?2,?3,1,?1,'complete')",
                params![unit_key, epoch, RUST_UNIT_SUMMARY_DERIVATION_VERSION],
            ).unwrap();
            conn.execute(
                "INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,profile_digest)
                 VALUES(?1,'rust',?2,?3,2,1001,zeroblob(32))",
                params![crate::analyzer::store_support::selection_test_support::WORKSPACE_ID, generation, unit_key],
            ).unwrap();
            conn.execute(
                "INSERT INTO rust_crate_topologies(topology_id,topology_digest,crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,export_surface_digest,publication_state)
                 VALUES(1001,?1,?1,'rust-resolution-epoch','lib','added','2021','std',jsonb('[]'),1,?1,'complete')",
                params![unit_key],
            ).unwrap();
            conn.execute(
                "INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,manifest_file_version_id,topology_id)
                 VALUES(?1,'rust',?2,?3,2,1001,NULL,1001)",
                params![crate::analyzer::store_support::selection_test_support::WORKSPACE_ID, generation, unit_key],
            ).unwrap();
        });
        first.snapshots.get_mut("rust").unwrap().revision = 2;
        let changed = first.open_ready(&[]);
        changed.stamp_declared_rust_route_recipe();
        let changed_digest = match first_host.demand::<UnitSetParent>(&analyzer, &changed, &0) {
            Demanded::Available { value, .. } => *value,
            Demanded::Unavailable(cause) => panic!("changed unit set unavailable: {cause:?}"),
        };
        assert_ne!(initial, changed_digest);
        assert_eq!(first_host.counters(RustUnitSetKind::ID).recomputed, 3);
        assert_eq!(first_host.counters(UnitSetParent::ID).recomputed, 2);
        drop(changed);
        let changed = first.open_ready(&[]);
        changed.stamp_declared_rust_route_recipe();
        let lease = changed.derivation_read().unwrap();
        let binding = changed.reader_binding().unwrap();
        let authority = AnalyzerAuthority::for_binding(&binding);
        let host = HostGuard::enter(&analyzer, &changed, &binding);
        for key in [[7; 32], [8; 32]] {
            assert!(matches!(
                first_host.engine.demand::<UnitSummaryKind>(
                    &key,
                    binding.clone(),
                    authority.clone()
                ),
                Demanded::Available { .. }
            ));
        }
        first_host
            .engine
            .demand::<RustUnitSetKind>(&0, binding.clone(), authority.clone());
        let before_changed = first_host.counters(UnitSummaryKind::ID);
        let before_set = first_host.counters(RustUnitSetKind::ID);
        let mut report = UnitSummaryReconciliation::default();
        report.output_changed = vec![("rust".to_string(), [7; 32])];
        report.closed = vec![("rust".to_string(), [9; 32])];
        first_host.forget_rust_units(&report);
        for key in [[7; 32], [8; 32]] {
            assert!(matches!(
                first_host.engine.demand::<UnitSummaryKind>(
                    &key,
                    binding.clone(),
                    authority.clone()
                ),
                Demanded::Available { .. }
            ));
        }
        first_host
            .engine
            .demand::<RustUnitSetKind>(&0, binding, authority);
        let after_changed = first_host.counters(UnitSummaryKind::ID);
        assert_eq!(after_changed.recomputed, before_changed.recomputed + 1);
        assert_eq!(after_changed.current_hits, before_changed.current_hits + 1);
        assert_eq!(
            first_host.counters(RustUnitSetKind::ID).recomputed,
            before_set.recomputed + 1
        );
        drop(host);
        drop(lease);
        drop(changed);
        let other = second.open_ready(&[]);
        other.stamp_declared_rust_route_recipe();
        assert!(matches!(
            second_host.demand::<UnitSetParent>(&analyzer, &other, &0),
            Demanded::Available { .. }
        ));
        assert_eq!(second_host.counters(RustUnitSetKind::ID).current_hits, 0);
        assert_eq!(second_host.counters(UnitSetParent::ID).recomputed, 1);
        assert_eq!(
            second_host.counters(UnitSetParent::ID).verified_unchanged,
            0
        );

        let overlay = first.open_ready(&[SelectedResolutionOverlayMask::removal(
            "rust",
            "src/0000.rs",
        )]);
        for _ in 0..2 {
            let ledger = Arc::new(ReadLedger::new());
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, ledger.clone());
            assert!(matches!(
                first_host.demand::<RustUnitSetKind>(&analyzer, &overlay, &0),
                Demanded::Available {
                    value: Handle::RequestOwned(_),
                    ..
                }
            ));
            assert_eq!(ledger.persistence_refusals(), 1);
        }
        drop(overlay);
    }

    #[test]
    fn interleaved_selected_readers_keep_their_own_answers() {
        use crate::CancellationToken;
        use brokk_bifrost_store::analyzer::store::resolution_selection::SelectedResolutionMountInventoryOutcome;
        use std::sync::{Mutex, atomic::AtomicBool, mpsc};

        let fixture = SelectionFixture::with_blob_writer(
            AnalyzerStore::open_ephemeral().unwrap(),
            0,
            "rust",
            Language::Rust,
            false,
            false,
            |_, _, _, _, _| {},
        );
        let a = fixture.snapshots.clone();
        let mut b = a.clone();
        b.get_mut("rust").unwrap().revision = 2;
        let generation = a["rust"].generation.get();
        let epoch = resolution_bundle_epoch(Language::Rust).to_owned();
        fixture.store.conn.execute(move |conn| {
            use rusqlite::params;
            let unit_key = [7_u8; 32];
            conn.execute("INSERT INTO workspace_revisions(workspace_id,lang,generation,revision) SELECT workspace_id,lang,generation,2 FROM workspace_revisions WHERE lang='rust' AND revision=1", []).unwrap();
            conn.execute("UPDATE workspace_heads SET revision=2 WHERE lang='rust'", []).unwrap();
            conn.execute("INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_version,complete,output_digest,publication_state) VALUES(1001,'rust','rust_crate',?1,?1,?2,?3,1,?1,'complete')", params![unit_key, epoch, RUST_UNIT_SUMMARY_DERIVATION_VERSION]).unwrap();
            conn.execute("INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,profile_digest) VALUES(?1,'rust',?2,?3,2,1001,zeroblob(32))", params![crate::analyzer::store_support::selection_test_support::WORKSPACE_ID, generation, unit_key]).unwrap();
            conn.execute("INSERT INTO rust_crate_topologies(topology_id,topology_digest,crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,export_surface_digest,publication_state) VALUES(1001,?1,?1,'rust-resolution-epoch','lib','added','2021','std',jsonb('[]'),1,?1,'complete')", params![unit_key]).unwrap();
            conn.execute("INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,manifest_file_version_id,topology_id) VALUES(?1,'rust',?2,?3,2,1001,NULL,1001)", params![crate::analyzer::store_support::selection_test_support::WORKSPACE_ID, generation, unit_key]).unwrap();
        });
        let analyzer = MultiAnalyzer::default();
        let budget = RetentionBudget::new(1_000_000);
        let host = AnalyzerDerivations::new(&budget);
        host.engine.register(UnitSetParent { gate: None });
        host.register_declared_route_recipe(Language::Rust);
        let open = |snapshots| match fixture
            .store
            .open_selected_resolution_mount_inventory(
                &fixture.workspace_id,
                snapshots,
                &[fixture.language()],
                &[],
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(ready) => {
                ready.stamp_declared_rust_route_recipe();
                ready
            }
            _ => panic!("selection unavailable"),
        };
        let answer = |host: &AnalyzerDerivations, snapshots| {
            let reader = open(snapshots);
            match host.demand::<UnitSetParent>(&analyzer, &reader, &0) {
                Demanded::Available {
                    value, identity, ..
                } => (*value, identity),
                Demanded::Unavailable(cause) => panic!("parent unavailable: {cause:?}"),
            }
        };
        let fresh_a = AnalyzerDerivations::new(&budget);
        fresh_a.engine.register(UnitSetParent { gate: None });
        fresh_a.register_declared_route_recipe(Language::Rust);
        let fresh_b = AnalyzerDerivations::new(&budget);
        fresh_b.engine.register(UnitSetParent { gate: None });
        fresh_b.register_declared_route_recipe(Language::Rust);
        let expected_a = answer(&fresh_a, &a);
        let expected_b = answer(&fresh_b, &b);
        assert_ne!(expected_a, expected_b);
        assert_eq!(answer(&host, &a), expected_a);
        assert_eq!(answer(&host, &b), expected_b);
        assert_eq!(answer(&host, &a), expected_a);
        let parent = host.counters(UnitSetParent::ID);
        assert_eq!(parent.recomputed, 3);
        assert_eq!(parent.current_hits, 0);
        assert_eq!(parent.verified_unchanged, 0);
        let reader = open(&a);
        let lease = reader.derivation_read().unwrap().unwrap();
        let first = host.demand::<UnitSetParent>(&analyzer, &reader, &0);
        let second = host.demand::<UnitSetParent>(&analyzer, &reader, &0);
        for result in [first, second] {
            match result {
                Demanded::Available {
                    value, identity, ..
                } => assert_eq!((*value, identity), expected_a),
                Demanded::Unavailable(cause) => panic!("pinned A unavailable: {cause:?}"),
            }
        }
        assert_eq!(host.counters(UnitSetParent::ID).current_hits, 1);
        drop(lease);
        drop(reader);

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let concurrent = AnalyzerDerivations::new(&budget);
        concurrent.register_declared_route_recipe(Language::Rust);
        concurrent.engine.register(UnitSetParent {
            gate: Some(Arc::new(Gate {
                first: AtomicBool::new(true),
                entered: entered_tx,
                release: Mutex::new(release_rx),
            })),
        });
        std::thread::scope(|scope| {
            let a_thread = scope.spawn(|| answer(&concurrent, &a));
            entered_rx.recv().unwrap();
            let b_answer = answer(&concurrent, &b);
            assert_eq!(b_answer, expected_b);
            release_tx.send(()).unwrap();
            assert_eq!(a_thread.join().unwrap(), expected_a);
        });
        let counters = concurrent.counters(UnitSetParent::ID);
        assert_eq!(counters.recomputed, 2);
        // A's late completion is retained at A. B's next demand sees A's
        // different child identity and recomputes at B.
        assert_eq!(counters.not_retainable, 0);
        assert_eq!(answer(&concurrent, &b), expected_b);
        assert_eq!(concurrent.counters(UnitSetParent::ID).recomputed, 3);
    }
}
