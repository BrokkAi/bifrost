//! Query-owned worker operations and canonical answer transport.
//!
//! Each worker opens and finishes its own reader from the parent's captured
//! authority. Answers contain owned checked evidence, never reader handles or
//! supplemental catalogs. Runtime aliases cross with their content digests;
//! the parent re-interns those digests in deterministic caller-supplied order.

use super::SpliceMount;
use super::{
    BindingFragmentId, BindingNodeId, FactResolutionAnswer, PartialPathId, ResolutionCompletion,
    ResolutionIdentityDigestKey as Key, ResolutionIdentityTranslation, SemanticId,
    SharedNameInterner, StackVariableId,
};
use crate::CancellationToken;
use crate::analyzer::store::resolution_operation::{
    CapturedSelectedResolutionInput, SelectedResolutionOperation,
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::{AnalyzerStore, Result};
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;

/// A checked answer must visit every identity when translating and preserve
/// its stable locators, verdicts and other non-identity fields.
#[doc(hidden)]
pub trait WorkerAnswer: Sized + Send {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self;
}

struct IdentityTranslation<F>(F);

impl<F: Fn(Key) -> Key> ResolutionIdentityTranslation for IdentityTranslation<F> {
    fn semantic(&self, value: SemanticId) -> SemanticId {
        let Key::Semantic(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn node(&self, value: BindingNodeId) -> BindingNodeId {
        let Key::Node(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn path(&self, value: PartialPathId) -> PartialPathId {
        let Key::Path(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn fragment(&self, value: BindingFragmentId) -> BindingFragmentId {
        let Key::Fragment(value) = (self.0)(value.into()) else {
            unreachable!("identity translation preserves kind")
        };
        value
    }

    fn stack_variable(&self, _: StackVariableId) -> StackVariableId {
        unreachable!("checked worker evidence contains no stack variables")
    }
}

/// One answer's complete, query-local identity authority.
#[doc(hidden)]
pub struct TransportedAnswer<A> {
    answer: A,
    digests: Vec<(Key, [u8; 32])>,
}

impl<A: WorkerAnswer> TransportedAnswer<A> {
    pub(crate) fn answer(&self) -> &A {
        &self.answer
    }

    pub(crate) fn capture(
        selected: &SelectedResolutionOperation<'_, '_>,
        answer: A,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let keys = RefCell::new(HashSet::default());
        let answer = answer.translate(&IdentityTranslation(|key| {
            keys.borrow_mut().insert(key);
            key
        }));
        let mut digests = keys
            .into_inner()
            .into_iter()
            .map(|key| Ok((key, selected.identity_content_digest(key, cancellation)?)))
            .collect::<Result<Vec<_>>>()?;
        digests.sort_unstable_by_key(|(key, digest)| {
            (
                *digest,
                match key {
                    Key::Semantic(_) => 0,
                    Key::Node(_) => 1,
                    Key::Path(_) => 2,
                    Key::Fragment(_) => 3,
                },
            )
        });
        Ok(Self { answer, digests })
    }

    /// Stable locators supply any parent anchors. All other runtime numbers
    /// are freshly interned aliases; worker completion order transfers no ids.
    #[doc(hidden)]
    pub fn reintern(
        self,
        selected: &SelectedResolutionOperation<'_, '_>,
        anchors: impl IntoIterator<Item = (Key, Key)>,
        cancellation: &CancellationToken,
    ) -> Result<A> {
        let Self { answer, digests } = self;
        let mut aliases = HashMap::default();
        for (worker, parent) in anchors {
            if let Some(previous) = aliases.insert(worker, parent) {
                assert_eq!(previous, parent, "one worker alias has one parent anchor");
            }
        }
        for (key, digest) in digests {
            if let Some(parent) = aliases.get(&key).copied() {
                assert_eq!(
                    selected.identity_content_digest(parent, cancellation)?,
                    digest,
                    "a stable source locator identifies the same selected content"
                );
                continue;
            }
            let mapped = match key {
                Key::Semantic(id) if id.shared_name_id().is_some() => Key::Semantic(
                    SemanticId::shared_name(selected.worker_shared_names().intern(digest)),
                ),
                Key::Fragment(_) => {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                Key::Semantic(id)
                    if id.local_key().is_some_and(|key| {
                        i64::from(key) < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE
                    }) =>
                {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                Key::Node(id)
                    if id == BindingNodeId::universal_root()
                        || id.local_key().is_some_and(|key| {
                            i64::from(key)
                                < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE
                        }) =>
                {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                Key::Path(id)
                    if id.local_key().is_some_and(|key| {
                        i64::from(key) < crate::analyzer::resolution::SUPPLEMENTAL_LOCAL_KEY_BASE
                    }) =>
                {
                    assert_eq!(selected.identity_content_digest(key, cancellation)?, digest);
                    key
                }
                _ if key.operation_number().is_some() => {
                    let number = selected.worker_demand_state().intern_identity(digest);
                    match key {
                        Key::Semantic(_) => Key::Semantic(SemanticId::operation_local(number)),
                        Key::Node(_) => Key::Node(BindingNodeId::operation_local(number)),
                        Key::Path(_) => Key::Path(PartialPathId::operation_local(number)),
                        Key::Fragment(_) => unreachable!("fragments are selected content"),
                    }
                }
                Key::Semantic(_) => {
                    Key::Semantic(selected.worker_context_identities().semantic(digest))
                }
                Key::Node(_) => Key::Node(selected.worker_context_identities().node(digest)),
                Key::Path(_) => Key::Path(selected.worker_context_identities().path(digest)),
            };
            assert!(aliases.insert(key, mapped).is_none());
        }

        Ok(answer.translate(&IdentityTranslation(|key| {
            *aliases
                .get(&key)
                .expect("every checked identity carries its canonical digest")
        })))
    }
}

/// Called on the worker thread. The reader stays here through answer capture
/// and open/finish validation, including generation and overlay checks.
///
/// A callback's single-flight dependencies must build inline or independently
/// of the calling pool. Waiting here for work queued on this same bounded pool
/// can starve its builder. Selected forward resolution uses operation-owned
/// SQL reads and synchronous context construction, not whole-snapshot builders.
#[doc(hidden)]
pub fn run_selected_worker<'store, 'project, A: WorkerAnswer>(
    store: &'store AnalyzerStore,
    input: &CapturedSelectedResolutionInput<'project>,
    cancellation: &CancellationToken,
    work: impl FnOnce(
        &mut SelectedResolutionOperation<'store, 'project>,
    ) -> Result<SelectedResolutionOperationOutcome<A>>,
) -> Result<SelectedResolutionOperationOutcome<TransportedAnswer<A>>> {
    assert!(
        !store.uses_single_connection_reads(),
        "workers require independent readers"
    );
    let mut selected =
        match store.open_selected_resolution_operation(input.input(), cancellation)? {
            SelectedResolutionOperationOpenOutcome::Ready(selected) => *selected,
            SelectedResolutionOperationOpenOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
            SelectedResolutionOperationOpenOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionOperationOpenOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    super::cancelled_completion(),
                ));
            }
        };
    match work(&mut selected)? {
        SelectedResolutionOperationOutcome::Native(answer) => {
            let answer = TransportedAnswer::capture(&selected, answer, cancellation)?;
            selected.finish_worker_answer(answer, cancellation)
        }
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            Ok(SelectedResolutionOperationOutcome::Unavailable(reason))
        }
        SelectedResolutionOperationOutcome::Stale(reason) => {
            Ok(SelectedResolutionOperationOutcome::Stale(reason))
        }
        SelectedResolutionOperationOutcome::Cancelled(completion) => {
            Ok(SelectedResolutionOperationOutcome::Cancelled(completion))
        }
    }
}

/// Run query-owned items on long-lived selected readers. `dispatch_order` is a
/// permutation of item indices; returned final statuses follow `items` order.
/// `consume` runs on the calling thread and receives each Native payload once,
/// in item order, while workers are still running. Delivery is provisional:
/// reader finalization can replace already delivered slots with failures. The
/// caller must check every final status before publishing accumulated output.
/// Delivery stops at the first unsuccessful slot or consumer error.
/// A worker retires on its first non-Native item outcome. It fills the slots it
/// already filled and every unclaimed slot with that item's own outcome, so the
/// lowest-index failure always carries a real cause and outcome kind; each
/// failing item keeps its own failure. Empty slots were not dispatched before
/// the shared deadline or cancellation.
/// The owner must use its inline path for one worker or single-connection stores.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn schedule_selected_queue<I: Sync, A: WorkerAnswer>(
    store: &AnalyzerStore,
    input: &CapturedSelectedResolutionInput<'_>,
    items: &[I],
    dispatch_order: &[usize],
    worker_count: usize,
    cancellation: &CancellationToken,
    work: impl Fn(
        &mut SelectedResolutionOperation<'_, '_>,
        &I,
    ) -> Result<SelectedResolutionOperationOutcome<A>>
    + Sync,
    mut consume: impl FnMut(usize, TransportedAnswer<A>) -> Result<()>,
) -> Result<Vec<Option<Result<SelectedResolutionOperationOutcome<()>>>>> {
    use crate::analyzer::store::StoreError;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };

    assert!(worker_count > 0);
    assert!(
        !store.uses_single_connection_reads(),
        "queue workers require independent readers"
    );
    assert_eq!(items.len(), dispatch_order.len());
    let mut seen = vec![false; items.len()];
    for &index in dispatch_order {
        assert!(
            !std::mem::replace(&mut seen[index], true),
            "dispatch order is a permutation"
        );
    }
    crate::analyzer::ensure_global_rayon_pool();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::channel();
    let mut pending = (0..items.len()).map(|_| None).collect::<Vec<_>>();
    let mut delivered = 0;
    let mut delivery_stopped = false;
    let mut consumer_error = None;
    let results = items.iter().map(|_| Mutex::new(None)).collect::<Vec<_>>();
    // This marker lets run_selected_worker validate the entire reader after all
    // item answers have been captured on it. It carries no identities itself.
    struct Finished;
    impl WorkerAnswer for Finished {
        fn translate(self, _: &impl ResolutionIdentityTranslation) -> Self {
            self
        }
    }
    rayon::in_place_scope(|scope| {
        for _ in 0..worker_count.min(items.len()) {
            if cancellation.soft_deadline_passed() {
                break;
            }
            let next = &next;
            let results = &results;
            let work = &work;
            let stop = &stop;
            let sender = sender.clone();
            scope.spawn(move |_| {
                let mut claimed = Vec::new();
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_selected_worker(store, input, cancellation, |operation| {
                        while !stop.load(Ordering::Relaxed)
                            && !cancellation.soft_deadline_passed()
                            && !cancellation.is_cancelled()
                        {
                            let position = next.fetch_add(1, Ordering::Relaxed);
                            let Some(&index) = dispatch_order.get(position) else {
                                break;
                            };
                            claimed.push(index);
                            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                || match work(operation, &items[index])? {
                                    SelectedResolutionOperationOutcome::Native(answer) => {
                                        Ok(SelectedResolutionOperationOutcome::Native(
                                            TransportedAnswer::capture(
                                                operation,
                                                answer,
                                                cancellation,
                                            )?,
                                        ))
                                    }
                                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                                        Ok(SelectedResolutionOperationOutcome::Unavailable(reason))
                                    }
                                    SelectedResolutionOperationOutcome::Stale(reason) => {
                                        Ok(SelectedResolutionOperationOutcome::Stale(reason))
                                    }
                                    SelectedResolutionOperationOutcome::Cancelled(completion) => {
                                        Ok(SelectedResolutionOperationOutcome::Cancelled(
                                            completion,
                                        ))
                                    }
                                },
                            ))
                            .unwrap_or_else(|panic| {
                                Err(StoreError::new(format!(
                                    "selected worker panicked for item {index}: {}",
                                    brokk_bifrost_core::panic_report::panic_payload_message(
                                        panic.as_ref()
                                    ),
                                )))
                            });
                            let (status, answer, retirement) = match result {
                                Ok(SelectedResolutionOperationOutcome::Native(answer)) => (
                                    Ok(SelectedResolutionOperationOutcome::Native(())),
                                    Some(answer),
                                    None,
                                ),
                                Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => (
                                    Ok(SelectedResolutionOperationOutcome::Unavailable(
                                        reason.clone(),
                                    )),
                                    None,
                                    Some(Ok(SelectedResolutionOperationOutcome::Unavailable(
                                        reason,
                                    ))),
                                ),
                                Ok(SelectedResolutionOperationOutcome::Stale(reason)) => (
                                    Ok(SelectedResolutionOperationOutcome::Stale(reason.clone())),
                                    None,
                                    Some(Ok(SelectedResolutionOperationOutcome::Stale(reason))),
                                ),
                                Ok(SelectedResolutionOperationOutcome::Cancelled(completion)) => (
                                    Ok(SelectedResolutionOperationOutcome::Cancelled(
                                        completion.clone(),
                                    )),
                                    None,
                                    Some(Ok(SelectedResolutionOperationOutcome::Cancelled(
                                        completion,
                                    ))),
                                ),
                                Err(error) => (Err(error.clone()), None, Some(Err(error))),
                            };
                            *results[index].lock().expect("worker result lock") = Some(status);
                            assert!(
                                sender.send((index, answer)).is_ok(),
                                "queue owner is receiving"
                            );
                            if let Some(retirement) = retirement {
                                // Retire with this item's own outcome. The slots this
                                // worker already filled lose their unvalidated answers,
                                // so they must carry the real cause and outcome kind;
                                // a generic error would turn an Unavailable or Stale
                                // item into a request error only when W > 1.
                                return retirement;
                            }
                        }
                        Ok(SelectedResolutionOperationOutcome::Native(Finished))
                    })
                }))
                .unwrap_or_else(|panic| {
                    Err(StoreError::new(format!(
                        "selected worker panicked: {}",
                        brokk_bifrost_core::panic_report::panic_payload_message(panic.as_ref()),
                    )))
                });
                if matches!(outcome, Ok(SelectedResolutionOperationOutcome::Native(_))) {
                    return;
                }
                // Open, item, and finish failures share retirement: claim the
                // remaining queue so failure leaves no undispatched slots.
                while let Some(&index) = dispatch_order.get(next.fetch_add(1, Ordering::Relaxed)) {
                    claimed.push(index);
                }
                for index in claimed {
                    let failure = match &outcome {
                        Err(error) => Err(error.clone()),
                        Ok(SelectedResolutionOperationOutcome::Unavailable(reason)) => Ok(
                            SelectedResolutionOperationOutcome::Unavailable(reason.clone()),
                        ),
                        Ok(SelectedResolutionOperationOutcome::Stale(reason)) => {
                            Ok(SelectedResolutionOperationOutcome::Stale(reason.clone()))
                        }
                        Ok(SelectedResolutionOperationOutcome::Cancelled(completion)) => Ok(
                            SelectedResolutionOperationOutcome::Cancelled(completion.clone()),
                        ),
                        Ok(SelectedResolutionOperationOutcome::Native(_)) => unreachable!(),
                    };
                    let mut slot = results[index].lock().expect("worker result lock");
                    // Keep a job's own error: reader finalization must not hide
                    // an earlier indexed failure discovered by that job.
                    if matches!(
                        &*slot,
                        None | Some(Ok(SelectedResolutionOperationOutcome::Native(_)))
                    ) {
                        *slot = Some(failure);
                        assert!(
                            sender.send((index, None)).is_ok(),
                            "queue owner is receiving"
                        );
                    }
                }
            });
        }
        drop(sender);
        loop {
            // A pool-thread caller must let queued workers run, even when the
            // pool has only one thread. When no pool work is queued it waits
            // briefly rather than spinning a core. Outside the pool, it blocks.
            let message = if rayon::current_thread_index().is_some() {
                match receiver.try_recv() {
                    Ok(message) => message,
                    Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {
                        if matches!(rayon::yield_now(), Some(rayon::Yield::Executed)) {
                            continue;
                        }
                        match receiver.recv_timeout(std::time::Duration::from_millis(1)) {
                            Ok(message) => message,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                }
            } else {
                match receiver.recv() {
                    Ok(message) => message,
                    Err(_) => break,
                }
            };
            let (index, answer) = message;
            if delivery_stopped {
                continue;
            }
            if index < delivered {
                // A late reader failure invalidates even an imported prefix.
                assert!(answer.is_none());
                delivery_stopped = true;
                pending.clear();
                continue;
            }
            pending[index] = Some(answer);
            while let Some(answer) = pending[delivered].take() {
                let Some(answer) = answer else {
                    delivery_stopped = true;
                    pending.clear();
                    break;
                };
                if let Err(error) = consume(delivered, answer) {
                    stop.store(true, Ordering::Relaxed);
                    consumer_error = Some(error);
                    delivery_stopped = true;
                    pending.clear();
                    break;
                }
                delivered += 1;
                if delivered == items.len() {
                    break;
                }
            }
        }
    });
    if let Some(error) = consumer_error {
        return Err(error);
    }
    Ok(results
        .into_iter()
        .map(|slot| slot.into_inner().expect("worker result lock"))
        .collect())
}

/// Capture leaf authority before a forward stage is cleaned up. The selected
/// owner keeps these bounded digests in its query-owned authority memo.
pub(crate) fn forward_identity_digests(
    operation: &super::FactResolutionOperation<'_>,
    answer: &FactResolutionAnswer,
    enumeration: &ResolutionCompletion,
) -> Result<Vec<(Key, [u8; 32])>> {
    let keys = RefCell::new(HashSet::default());
    let translation = IdentityTranslation(|key| {
        keys.borrow_mut().insert(key);
        key
    });
    // A rich incoming worker transports the whole forward answer, including
    // typed projections. Preserve every identity's authority before cleanup.
    drop(answer.clone().translate(&translation));
    drop(enumeration.splice(&translation));
    keys.into_inner()
        .into_iter()
        .map(|key| Ok((key, operation.identity_content_digest(key)?)))
        .collect()
}
