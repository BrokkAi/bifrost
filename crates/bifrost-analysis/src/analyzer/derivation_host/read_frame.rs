//! Scoped selected reads for route questions on the current thread.
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
static UNFRAMED_ROUTE_QUESTIONS: AtomicUsize = AtomicUsize::new(0);

pub fn active() -> bool {
    FRAMES.with(|frames| !frames.borrow().is_empty())
}

#[cfg(any(test, feature = "test-support"))]
pub fn unframed_route_questions_for_test() -> usize {
    UNFRAMED_ROUTE_QUESTIONS.load(Ordering::Relaxed)
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
                        let cause = UnavailableCause::Failed(error.to_string().into());
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
            .map_err(|error| UnavailableCause::Failed(error.to_string().into()))?
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
        return Err(UnavailableCause::ValidationFailed);
    }
    UNFRAMED_ROUTE_QUESTIONS.fetch_add(1, Ordering::Relaxed);
    let inventory = open()?;
    if identity
        .selection
        .is_some_and(|selection| inventory.fingerprint() != selection)
        || inventory.store_identity() != identity.store
    {
        return Err(UnavailableCause::ValidationFailed);
    }
    let _lease = inventory
        .derivation_read()
        .map_err(|error| UnavailableCause::Failed(error.to_string().into()))?;
    Ok(f(&inventory))
}
