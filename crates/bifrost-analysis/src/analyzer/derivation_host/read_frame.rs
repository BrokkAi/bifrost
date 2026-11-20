//! Scoped selected reads for route questions on the current thread.
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use brokk_bifrost_semantic::analyzer::semantic::derivation::UnavailableCause;
use brokk_bifrost_store::analyzer::store::WorkspaceSnapshotId;
use brokk_bifrost_store::analyzer::store::resolution_operation::{
    SelectedResolutionOperation, rust_selected_operation_active,
};
use brokk_bifrost_store::analyzer::store::resolution_selection::{
    DerivationReadLease, SelectedResolutionMountInventory,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadFrameIdentity {
    pub analyzer: usize,
    pub store: usize,
    pub selection: Option<[u8; 32]>,
    pub query_domain: u64,
    pub operation: Option<usize>,
    pub snapshot: Option<WorkspaceSnapshotId>,
}

impl ReadFrameIdentity {
    pub(crate) fn matches_question(&self, question: &Self) -> bool {
        self.analyzer == question.analyzer
            && self.store == question.store
            && question
                .selection
                .is_none_or(|selection| self.selection == Some(selection))
            && self.query_domain == question.query_domain
            && self.snapshot == question.snapshot
            && question
                .operation
                .is_none_or(|operation| self.operation == Some(operation))
    }
}

trait FrameSource {
    fn inventory(
        &self,
    ) -> Result<*const SelectedResolutionMountInventory<'static>, UnavailableCause>;
}

struct FrameEntry {
    identity: ReadFrameIdentity,
    source: *const dyn FrameSource,
}
thread_local! {
    static FRAMES: RefCell<Vec<FrameEntry>> = const { RefCell::new(Vec::new()) };
}
// Test-support only: how many route questions this thread has opened without
// a read frame. It is per thread because the tests that read it assert that a
// question *they* ask does or does not open one, and a process-wide count let a
// test running beside them move it when the suite ran threaded. Production
// never reads it, so production does not keep it either.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static UNFRAMED_ROUTE_QUESTIONS: Cell<usize> = const { Cell::new(0) };
}

pub fn active() -> bool {
    FRAMES.with(|frames| !frames.borrow().is_empty())
}

#[cfg(any(test, feature = "test-support"))]
pub fn unframed_route_questions_for_test() -> usize {
    UNFRAMED_ROUTE_QUESTIONS.with(Cell::get)
}

#[cfg(any(test, feature = "test-support"))]
pub fn read_frame_depth_for_test() -> usize {
    FRAMES.with(|frames| frames.borrow().len())
}

pub(super) struct FrameGuard;
impl FrameGuard {
    fn enter(identity: ReadFrameIdentity, source: &dyn FrameSource) -> Self {
        // The guard pops this pointer before the source's scope ends.
        let source =
            unsafe { std::mem::transmute::<&dyn FrameSource, &'static dyn FrameSource>(source) };
        FRAMES.with(|frames| frames.borrow_mut().push(FrameEntry { identity, source }));
        Self
    }
}

pub(super) struct DemandFrame {
    // Drop the frame before its borrowed source.
    _guard: FrameGuard,
    _source: Box<BorrowedSource<'static, 'static>>,
}

impl DemandFrame {
    pub(super) fn enter(
        identity: ReadFrameIdentity,
        inventory: &SelectedResolutionMountInventory<'_>,
    ) -> Self {
        let source = Box::new(BorrowedSource(unsafe {
            std::mem::transmute::<
                &SelectedResolutionMountInventory<'_>,
                &'static SelectedResolutionMountInventory<'static>,
            >(inventory)
        }));
        let guard = FrameGuard::enter(identity, source.as_ref());
        Self {
            _guard: guard,
            _source: source,
        }
    }
}
impl Drop for FrameGuard {
    fn drop(&mut self) {
        FRAMES.with(|frames| {
            frames.borrow_mut().pop().expect("read frame underflow");
        });
    }
}

struct BorrowedSource<'a, 'store>(&'a SelectedResolutionMountInventory<'store>);
impl FrameSource for BorrowedSource<'_, '_> {
    fn inventory(
        &self,
    ) -> Result<*const SelectedResolutionMountInventory<'static>, UnavailableCause> {
        Ok(unsafe {
            std::mem::transmute::<
                *const SelectedResolutionMountInventory<'_>,
                *const SelectedResolutionMountInventory<'static>,
            >(self.0 as *const _)
        })
    }
}

struct LazySource<'store, F> {
    open: RefCell<Option<F>>,
    inventory: RefCell<Option<Box<SelectedResolutionMountInventory<'store>>>>,
    lease: RefCell<Option<DerivationReadLease<'static, 'static>>>,
    failed: RefCell<Option<UnavailableCause>>,
    opening: Cell<bool>,
    selection: Option<[u8; 32]>,
}
impl<'store, F> FrameSource for LazySource<'store, F>
where
    F: FnOnce() -> Result<SelectedResolutionMountInventory<'store>, UnavailableCause>,
{
    fn inventory(
        &self,
    ) -> Result<*const SelectedResolutionMountInventory<'static>, UnavailableCause> {
        if let Some(cause) = self.failed.borrow().as_ref() {
            return Err(cause.clone());
        }
        if let Some(inventory) = self.inventory.borrow().as_ref() {
            return Ok(unsafe {
                std::mem::transmute::<
                    *const SelectedResolutionMountInventory<'_>,
                    *const SelectedResolutionMountInventory<'static>,
                >(inventory.as_ref() as *const _)
            });
        }
        if self.opening.replace(true) {
            return Err(UnavailableCause::ValidationFailed);
        }
        let result = self
            .open
            .borrow_mut()
            .take()
            .expect("query opener consumed")();
        self.opening.set(false);
        match result {
            Ok(inventory)
                if self
                    .selection
                    .is_none_or(|selection| inventory.fingerprint() == selection) =>
            {
                let boxed = Box::new(inventory);
                let ptr = boxed.as_ref() as *const SelectedResolutionMountInventory<'store>;
                *self.inventory.borrow_mut() = Some(boxed);
                // The box is stable and Drop releases this lease before the box.
                let lease = match unsafe { &*ptr }.derivation_read() {
                    Ok(lease) => lease,
                    Err(error) => {
                        let cause = binding_unavailable(error);
                        *self.failed.borrow_mut() = Some(cause.clone());
                        return Err(cause);
                    }
                };
                *self.lease.borrow_mut() = lease.map(|lease| unsafe {
                    std::mem::transmute::<
                        DerivationReadLease<'_, '_>,
                        DerivationReadLease<'static, 'static>,
                    >(lease)
                });
                Ok(unsafe {
                    std::mem::transmute::<
                        *const SelectedResolutionMountInventory<'_>,
                        *const SelectedResolutionMountInventory<'static>,
                    >(ptr)
                })
            }
            Ok(_) => {
                *self.failed.borrow_mut() = Some(UnavailableCause::ValidationFailed);
                Err(UnavailableCause::ValidationFailed)
            }
            Err(cause) => {
                *self.failed.borrow_mut() = Some(cause.clone());
                Err(cause)
            }
        }
    }
}
impl<F> Drop for LazySource<'_, F> {
    fn drop(&mut self) {
        self.lease.get_mut().take();
        self.inventory.get_mut().take();
    }
}

pub struct OperationReadFrame<'store> {
    // Drop order is explicit: pop before releasing the source and its lease.
    _guard: FrameGuard,
    _source: Box<BorrowedSource<'static, 'static>>,
    _lease: Option<DerivationReadLease<'static, 'static>>,
    _inventory: Rc<SelectedResolutionMountInventory<'store>>,
}

impl<'store> OperationReadFrame<'store> {
    pub fn enter(
        identity: ReadFrameIdentity,
        operation: &SelectedResolutionOperation<'store, '_>,
    ) -> Result<Self, UnavailableCause> {
        assert_eq!(
            identity.selection,
            Some(operation.ready.inventory.fingerprint())
        );
        assert_eq!(identity.store, operation.ready.inventory.store_identity());
        assert_eq!(identity.operation, Some(operation as *const _ as usize));
        let inventory = Rc::clone(&operation.ready.inventory);
        let ptr = Rc::as_ptr(&inventory);
        let lease = unsafe { &*ptr }
            .derivation_read()
            .map_err(binding_unavailable)?
            .map(|lease| unsafe {
                std::mem::transmute::<
                    DerivationReadLease<'_, '_>,
                    DerivationReadLease<'static, 'static>,
                >(lease)
            });
        let source = Box::new(BorrowedSource(unsafe {
            std::mem::transmute::<
                &SelectedResolutionMountInventory<'store>,
                &SelectedResolutionMountInventory<'static>,
            >(&*ptr)
        }));
        let guard = FrameGuard::enter(identity, source.as_ref());
        Ok(Self {
            _guard: guard,
            _source: source,
            _lease: lease,
            _inventory: inventory,
        })
    }
}

pub fn with_operation_read_frame<T>(
    identity: ReadFrameIdentity,
    operation: &SelectedResolutionOperation<'_, '_>,
    f: impl FnOnce() -> T,
) -> Result<T, UnavailableCause> {
    let _frame = OperationReadFrame::enter(identity, operation)?;
    Ok(f())
}

/// Lend an explicitly opened Main inventory while an owner prefills needed files.
/// This must run before entering the unit's selected operation.
pub fn with_main_route_read_frame<T>(
    identity: ReadFrameIdentity,
    inventory: &SelectedResolutionMountInventory<'_>,
    run: impl FnOnce() -> T,
) -> Result<T, UnavailableCause> {
    if rust_selected_operation_active() {
        return Err(UnavailableCause::MissingOperationReadFrame);
    }
    let _lease = inventory.derivation_read().map_err(binding_unavailable)?;
    if !inventory
        .derivation_reader_binding()
        .map_err(binding_unavailable)?
        .proves_main_selection()
    {
        return Err(UnavailableCause::ValidationFailed);
    }
    let _frame = DemandFrame::enter(identity, inventory);
    Ok(run())
}

/// Preserve typed request cancellation at selected-reader and binding boundaries.
#[doc(hidden)]
pub fn binding_unavailable(
    error: brokk_bifrost_store::analyzer::store::StoreError,
) -> UnavailableCause {
    if error.is_cancelled() {
        UnavailableCause::Cancelled
    } else {
        crate::analyzer::i_analyzer::record_store_error_on_current_contexts(error);
        UnavailableCause::StoreFailure
    }
}

// Only this private constructor grants the three named Main bridges:
// file_routes, certified package_question, and local-glob name absence.
// A distinct pooled Main reader uses the operation's identical pinned snapshots
// and empty masks/content mounts. Its stacked frame is popped before returning;
// the operation's TEMP scope is never changed. Main reads are captured separately
// by the caller and only their certified receipt is replayed into the operation.
struct MainRouteBridgeFrame {
    _frame: DemandFrame,
}
thread_local! {
    static MAIN_ROUTE_BRIDGE_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static PACKAGE_TOPOLOGY_BRIDGE_ACTIVE: Cell<bool> = const { Cell::new(false) };
    static LOCAL_GLOB_NAME_ABSENCE_BRIDGE_ACTIVE: Cell<bool> = const { Cell::new(false) };
}
impl MainRouteBridgeFrame {
    fn enter(
        identity: ReadFrameIdentity,
        inventory: &SelectedResolutionMountInventory<'_>,
    ) -> Result<Self, UnavailableCause> {
        MAIN_ROUTE_BRIDGE_ACTIVE.with(|active| assert!(!active.get(), "nested Main route bridge"));
        assert_eq!(
            inventory.store_identity(),
            identity.store,
            "Main bridge store identity"
        );
        assert_eq!(
            super::selected_rust_snapshot(inventory).ok(),
            identity.snapshot,
            "Main bridge pinned revision"
        );
        let binding = inventory
            .derivation_reader_binding()
            .map_err(binding_unavailable)?;
        if !binding.proves_main_selection() {
            return Err(UnavailableCause::Failed(
                format!("Main route reader binding rejected: {binding:?}; identity={identity:?}")
                    .into(),
            ));
        }
        let frame = DemandFrame::enter(identity, inventory);
        MAIN_ROUTE_BRIDGE_ACTIVE.with(|active| active.set(true));
        Ok(Self { _frame: frame })
    }
}
impl Drop for MainRouteBridgeFrame {
    fn drop(&mut self) {
        MAIN_ROUTE_BRIDGE_ACTIVE.with(|active| active.set(false));
    }
}

/// The file_routes entry point of the shared private bridge. The other named
/// entry points are package_question and local-glob name absence. All three
/// require their selected-content gate before Main and defer receipt replay.
pub fn with_file_routes_main_bridge<T>(
    identity: ReadFrameIdentity,
    inventory: &SelectedResolutionMountInventory<'_>,
    compute: impl FnOnce() -> T,
) -> Result<T, UnavailableCause> {
    let _lease = inventory.derivation_read().map_err(binding_unavailable)?;
    let _bridge = MainRouteBridgeFrame::enter(identity, inventory)?;
    Ok(compute())
}

/// The package_question entry point, limited to its three topology demands.
/// File/source macro identity reads stay outside this bridge. Incomplete or
/// uncovered questions must refuse; callers replay only the certified receipt.
pub fn with_package_topology_main_bridge<T>(
    identity: ReadFrameIdentity,
    inventory: &SelectedResolutionMountInventory<'_>,
    compute: impl FnOnce() -> T,
) -> Result<T, UnavailableCause> {
    let _lease = inventory.derivation_read().map_err(binding_unavailable)?;
    let _bridge = MainRouteBridgeFrame::enter(identity, inventory)?;
    struct PackageTopologyGuard;
    impl Drop for PackageTopologyGuard {
        fn drop(&mut self) {
            PACKAGE_TOPOLOGY_BRIDGE_ACTIVE.with(|active| active.set(false));
        }
    }
    PACKAGE_TOPOLOGY_BRIDGE_ACTIVE.with(|active| {
        assert!(!active.replace(true), "nested package topology bridge");
    });
    let _package = PackageTopologyGuard;
    Ok(compute())
}

/// The local-glob name-absence entry point. The caller requires exact selected
/// content for every input before opening Main, and replays only the receipt
/// of this named question after the operation's frame has been restored.
pub fn with_local_glob_name_absence_main_bridge<T>(
    identity: ReadFrameIdentity,
    inventory: &SelectedResolutionMountInventory<'_>,
    compute: impl FnOnce() -> T,
) -> Result<T, UnavailableCause> {
    if MAIN_ROUTE_BRIDGE_ACTIVE.with(Cell::get) {
        return Err(UnavailableCause::ValidationFailed);
    }
    let _lease = inventory.derivation_read().map_err(binding_unavailable)?;
    let _bridge = MainRouteBridgeFrame::enter(identity, inventory)?;
    struct LocalGlobGuard;
    impl Drop for LocalGlobGuard {
        fn drop(&mut self) {
            LOCAL_GLOB_NAME_ABSENCE_BRIDGE_ACTIVE.with(|active| active.set(false));
        }
    }
    LOCAL_GLOB_NAME_ABSENCE_BRIDGE_ACTIVE
        .with(|active| assert!(!active.replace(true), "nested local-glob bridge"));
    let _local_glob = LocalGlobGuard;
    Ok(compute())
}

pub(super) fn named_main_bridge_allows(
    kind: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId,
) -> bool {
    let package_allowed = PACKAGE_TOPOLOGY_BRIDGE_ACTIVE.with(|active| {
        !active.get()
            || matches!(
                kind.0,
                "derivation:rust_name_availability:v1"
                    | "derivation:rust_file_availability:v1"
                    | "derivation:rust_package_units:v1"
                    | "derivation:rust_file_units:v1"
                    | "derivation:rust_unit_package_rows:v1"
            )
    });
    package_allowed
        && LOCAL_GLOB_NAME_ABSENCE_BRIDGE_ACTIVE
            .with(|active| !active.get() || kind.0 == "derivation:rust_local_glob_name_absence:v1")
}

pub fn with_query_read_frame<'store, T, F>(
    identity: ReadFrameIdentity,
    open: F,
    f: impl FnOnce() -> T,
) -> T
where
    F: FnOnce() -> Result<SelectedResolutionMountInventory<'store>, UnavailableCause>,
{
    let reuse = FRAMES.with(|frames| {
        frames
            .borrow()
            .last()
            .map(|top| top.identity.matches_question(&identity))
            .unwrap_or(false)
    });
    if reuse {
        return f();
    }
    let source = LazySource {
        open: RefCell::new(Some(open)),
        inventory: RefCell::new(None),
        lease: RefCell::new(None),
        failed: RefCell::new(None),
        opening: Cell::new(false),
        selection: identity.selection,
    };
    let _guard = FrameGuard::enter(identity, &source);
    f()
}

pub fn with_read_frame<'store, T>(
    identity: &ReadFrameIdentity,
    open: impl FnOnce() -> Result<SelectedResolutionMountInventory<'store>, UnavailableCause>,
    f: impl FnOnce(&SelectedResolutionMountInventory<'_>) -> T,
) -> Result<T, UnavailableCause> {
    let source = FRAMES.with(|frames| {
        frames.borrow().last().and_then(|top| {
            top.identity
                .matches_question(identity)
                .then_some(top.source)
        })
    });
    if let Some(source) = source {
        // The frame guard owns the source through this call. The TLS borrow ended.
        let inventory = unsafe { &*source }.inventory()?;
        return Ok(f(unsafe { &*inventory }));
    }
    if rust_selected_operation_active() {
        return Err(UnavailableCause::MissingOperationReadFrame);
    }
    #[cfg(any(test, feature = "test-support"))]
    UNFRAMED_ROUTE_QUESTIONS.with(|count| count.set(count.get() + 1));
    let inventory = open()?;
    if identity
        .selection
        .is_some_and(|selection| inventory.fingerprint() != selection)
        || inventory.store_identity() != identity.store
    {
        return Err(UnavailableCause::ValidationFailed);
    }
    let _lease = inventory.derivation_read().map_err(binding_unavailable)?;
    Ok(f(&inventory))
}
