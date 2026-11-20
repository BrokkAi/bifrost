//! Context follows work handed from one thread to another. Core does not
//! know what the attribution frame contains; callers provide its type.
//! Request state travels in an independent slot; neither payload interprets
//! the other. Project-read suppression follows work through nested fan-outs.

use std::any::Any;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;

use super::reuse_verdict::{ExecutionCause, ReuseVerdict};

/// Monotone evidence owned by one evaluation, including nested captures.
#[derive(Default)]
pub struct EvaluationExecution {
    verdict: Mutex<ReuseVerdict>,
    selection_reads: Mutex<Option<Payload>>,
}

impl EvaluationExecution {
    /// The typed read vocabulary belongs to the analysis layer. Keep its
    /// evaluation-wide collector on this unshadowed slot without a core
    /// dependency on that vocabulary. One evaluation uses one collector type.
    pub fn selection_reads<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        let mut slot = self
            .selection_reads
            .lock()
            .expect("selection reads poisoned");
        let payload = slot.get_or_insert_with(|| Arc::new(T::default()));
        Arc::clone(payload)
            .downcast::<T>()
            .unwrap_or_else(|_| panic!("evaluation selection collector type changed"))
    }

    pub fn verdict(&self) -> ReuseVerdict {
        *self.verdict.lock().expect("evaluation verdict poisoned")
    }

    pub fn join(&self, verdict: ReuseVerdict) {
        self.verdict
            .lock()
            .expect("evaluation verdict poisoned")
            .join_in(verdict);
    }

    /// Start a fresh evaluation; nested read scopes inherit this collector.
    pub fn install(self: &Arc<Self>) -> CarriedContextGuard {
        let frame = CONTEXT.with(|stack| stack.borrow().last().and_then(|slot| slot.frame.clone()));
        push_slot(ContextSlot {
            frame,
            evaluation: Some(self.clone()),
            completion: current_completion(),
            refusal_observer: current_refusal_observer(),
            hypothesis: current_hypothesis(),
        })
    }
}

/// Access the evaluation independently of nested ledger attribution frames.
pub fn current_evaluation() -> Option<Arc<EvaluationExecution>> {
    CONTEXT.with(|stack| {
        stack
            .borrow()
            .last()
            .and_then(|slot| slot.evaluation.clone())
    })
}

/// Install a policy-owned completion boundary independently of read capture.
/// The owner retains the payload until evaluation finishes; transported work
/// observes the same boundary even when it replaces its attribution frame.
pub fn push_completion<T: Any + Send + Sync>(completion: Arc<T>) -> CarriedContextGuard {
    let mut slot = CONTEXT
        .with(|stack| stack.borrow().last().cloned())
        .unwrap_or(ContextSlot {
            frame: None,
            evaluation: None,
            completion: None,
            refusal_observer: None,
            hypothesis: None,
        });
    slot.completion = Some(completion);
    push_slot(slot)
}

/// Install a typed hypothesis the work inside the returned scope answers
/// under, independently of read capture and completion. Like a completion
/// boundary it follows transported work; a task carrying another context,
/// including one stolen onto this thread, observes that context's hypothesis
/// instead. Its concrete type is owned by the layer that interprets it.
pub fn push_hypothesis<T: Any + Send + Sync>(hypothesis: Arc<T>) -> CarriedContextGuard {
    let mut slot = CONTEXT
        .with(|stack| stack.borrow().last().cloned())
        .unwrap_or(ContextSlot {
            frame: None,
            evaluation: None,
            completion: None,
            hypothesis: None,
            refusal_observer: None,
        });
    slot.hypothesis = Some(hypothesis);
    push_slot(slot)
}

fn current_hypothesis() -> Option<Payload> {
    CONTEXT.with(|stack| {
        stack
            .borrow()
            .last()
            .and_then(|slot| slot.hypothesis.clone())
    })
}

/// The innermost hypothesis installed by [`push_hypothesis`], including on
/// transported work.
pub fn hypothesis<T: Any + Send + Sync>() -> Option<Arc<T>> {
    current_hypothesis().map(|payload| {
        payload
            .downcast()
            .unwrap_or_else(|_| panic!("unexpected carried hypothesis type"))
    })
}

fn current_completion() -> Option<Payload> {
    CONTEXT.with(|stack| {
        stack
            .borrow()
            .last()
            .and_then(|slot| slot.completion.clone())
    })
}

/// The innermost policy completion boundary, including transported work.
/// Its concrete type is owned by the layer implementing policy completion.
pub fn completion<T: Any + Send + Sync>() -> Option<Arc<T>> {
    current_completion().map(|payload| {
        payload
            .downcast()
            .unwrap_or_else(|_| panic!("unexpected carried completion type"))
    })
}

/// Install the caller's typed refusal observer without replacing read or
/// completion attribution. Transported work carries this same observer.
pub fn push_refusal_observer<T: Any + Send + Sync>(observer: Arc<T>) -> CarriedContextGuard {
    let mut slot = CONTEXT
        .with(|stack| stack.borrow().last().cloned())
        .unwrap_or(ContextSlot {
            frame: None,
            evaluation: None,
            completion: None,
            refusal_observer: None,
            hypothesis: None,
        });
    slot.refusal_observer = Some(observer);
    push_slot(slot)
}

fn current_refusal_observer() -> Option<Payload> {
    CONTEXT.with(|stack| {
        stack
            .borrow()
            .last()
            .and_then(|slot| slot.refusal_observer.clone())
    })
}

/// The current work's refusal observer, whose concrete type belongs to its
/// budget owner. An unrelated carried context masks this observer.
pub fn refusal_observer<T: Any + Send + Sync>() -> Option<Arc<T>> {
    current_refusal_observer().map(|observer| {
        observer
            .downcast()
            .unwrap_or_else(|_| panic!("unexpected carried refusal observer type"))
    })
}

/// Forward explicit or replayed evidence without changing ledger routing.
pub fn join_evaluation_verdict(verdict: ReuseVerdict) {
    CONTEXT.with(|stack| {
        if let Some(evaluation) = stack
            .borrow()
            .last()
            .and_then(|slot| slot.evaluation.as_ref())
        {
            evaluation.join(verdict);
        }
    });
}

/// Cross-check typed operational failures before their provenance becomes text.
/// Outside a policy evaluation there is no aggregate collector to check.
#[track_caller]
pub fn debug_assert_evaluation_execution_dependent() {
    #[cfg(debug_assertions)]
    CONTEXT.with(|stack| {
        if let Some(evaluation) = stack
            .borrow()
            .last()
            .and_then(|slot| slot.evaluation.as_ref())
        {
            debug_assert!(
                !evaluation.verdict().is_content(),
                "typed operational failure reached formatting with a Content evaluation verdict"
            );
        }
    });
}

#[derive(Clone)]
struct ContextSlot {
    frame: Option<Frame>,
    evaluation: Option<Arc<EvaluationExecution>>,
    completion: Option<Payload>,
    refusal_observer: Option<Payload>,
    hypothesis: Option<Payload>,
}

type Payload = Arc<dyn Any + Send + Sync>;

/// Read the request owner's operational completion without copying its state.
pub trait RequestCompletion: Any + Send + Sync {
    fn store_failed(&self) -> bool;
}

#[derive(Clone)]
struct RequestState {
    payload: Payload,
    completion: Option<Arc<dyn RequestCompletion>>,
}

/// The narrow operation core can perform on an opaque attribution frame.
pub trait ExecutionAttribution: Any + Send + Sync {
    fn mark_execution_dependent(&self);

    /// An execution dependence caused by a refused budget charge. A recipient
    /// that does not tell the causes apart records an ordinary dependence.
    fn mark_budget_refusal(&self) {
        self.mark_execution_dependent();
    }
}

#[derive(Clone)]
struct Frame {
    payload: Payload,
    execution: Option<Arc<dyn ExecutionAttribution>>,
}

/// Mark the observing thread's current capture, including transported work.
/// An absent or explicitly empty frame has no recipient.
#[track_caller]
pub fn mark_execution_dependent() {
    mark(std::panic::Location::caller(), "ambient", |attribution| {
        attribution.mark_execution_dependent();
    });
}

/// Mark the observing thread's current capture with an execution dependence
/// caused by a refused budget charge, so the capture can tell it from a
/// provider failure or a cancellation.
#[track_caller]
pub fn mark_budget_refusal() {
    mark(
        std::panic::Location::caller(),
        "ambient_budget",
        |attribution| {
            attribution.mark_budget_refusal();
        },
    );
}

/// [`mark_execution_dependent`] for a core observer (a cancellation token or
/// a limited counter), so the census can tell observations from hand marks.
#[track_caller]
pub(crate) fn mark_observed(route: &'static str) {
    mark(std::panic::Location::caller(), route, |attribution| {
        attribution.mark_execution_dependent();
    });
}

fn mark(
    origin: &'static std::panic::Location<'static>,
    route: &'static str,
    deliver: impl Fn(&dyn ExecutionAttribution),
) {
    let _census = super::execution_census::mark_scope(origin, route);
    join_evaluation_verdict(ReuseVerdict::ExecutionDependent(
        if route == "ambient_budget" {
            ExecutionCause::BudgetRefusal
        } else {
            ExecutionCause::Other
        },
    ));
    CONTEXT.with(|stack| {
        if let Some(frame) = stack.borrow().last().and_then(|slot| slot.frame.as_ref())
            && let Some(attribution) = &frame.execution
        {
            deliver(attribution.as_ref());
        }
    });
}

thread_local! {
    static CONTEXT: RefCell<Vec<ContextSlot>> = const { RefCell::new(Vec::new()) };
    static REQUEST_STATE: RefCell<Vec<Option<RequestState>>> = const { RefCell::new(Vec::new()) };
}

/// The context of the thread handing work to another thread.
#[derive(Clone)]
pub struct CarriedContext {
    slot: ContextSlot,
    request_state: Option<RequestState>,
    project_reads_suppressed: bool,
}

impl CarriedContext {
    pub fn current() -> Self {
        let project_reads_suppressed = super::project_reads::project_reads_suppressed();
        debug_assert!(
            project_reads_suppressed || !super::project_reads::project_getter_in_progress(),
            "a project getter must not hand work to another thread"
        );
        Self {
            slot: CONTEXT
                .with(|stack| stack.borrow().last().cloned())
                .unwrap_or(ContextSlot {
                    frame: None,
                    evaluation: None,
                    completion: None,
                    refusal_observer: None,
                    hypothesis: None,
                }),
            request_state: REQUEST_STATE.with(|stack| stack.borrow().last().cloned().flatten()),
            project_reads_suppressed,
        }
    }

    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = push_slot(self.slot.clone());
        let _request_state = push_request_slot(self.request_state.clone());
        super::project_reads::with_project_read_suppression(self.project_reads_suppressed, f)
    }
}

/// A scope on the thread that pushed the frame.
pub struct CarriedContextGuard {
    frame: Option<Frame>,
    depth: usize,
    // Like MutexGuard, this may be borrowed across threads but must be dropped
    // on the thread that installed it. The marker holds no actual lock.
    _thread: PhantomData<std::sync::MutexGuard<'static, ()>>,
}

pub fn push(frame: Option<Payload>) -> CarriedContextGuard {
    push_frame(frame.map(|payload| Frame {
        payload,
        execution: None,
    }))
}

pub fn push_with_execution_attribution<T: ExecutionAttribution>(
    frame: Arc<T>,
) -> CarriedContextGuard {
    push_frame(Some(Frame {
        payload: frame.clone(),
        execution: Some(frame),
    }))
}

fn push_frame(frame: Option<Frame>) -> CarriedContextGuard {
    let evaluation = CONTEXT.with(|stack| {
        stack
            .borrow()
            .last()
            .and_then(|slot| slot.evaluation.clone())
    });
    push_slot(ContextSlot {
        frame,
        evaluation,
        completion: current_completion(),
        refusal_observer: current_refusal_observer(),
        hypothesis: current_hypothesis(),
    })
}

fn push_slot(slot: ContextSlot) -> CarriedContextGuard {
    let frame = slot.frame.clone();
    let depth = CONTEXT.with(|stack| {
        let mut stack = stack.borrow_mut();
        stack.push(slot);
        stack.len()
    });
    CarriedContextGuard {
        frame,
        depth,
        _thread: PhantomData,
    }
}

/// None means no scope; Some(None) is an explicitly transported empty context.
/// A populated slot must hold the concrete frame type its consumer expects.
pub fn top<T: Any + Send + Sync>() -> Option<Option<Arc<T>>> {
    CONTEXT
        .with(|stack| stack.borrow().last().map(|slot| slot.frame.clone()))
        .map(|slot| {
            slot.map(|frame| {
                frame
                    .payload
                    .downcast()
                    .unwrap_or_else(|_| panic!("#7116: unexpected carried context frame type"))
            })
        })
}

/// Borrow the current frame without cloning its Arc. The callback must not
/// push or pop context scopes while the stack is borrowed.
/// None means no scope; Some(None) is a transported empty context.
pub fn with_top<T: Any + Send + Sync, R>(f: impl FnOnce(Option<Option<&T>>) -> R) -> R {
    CONTEXT.with(|stack| {
        let stack = stack.borrow();
        f(stack.last().map(|slot| {
            slot.frame.as_ref().map(|frame| {
                frame
                    .payload
                    .downcast_ref::<T>()
                    .expect("#7116: unexpected carried context frame type")
            })
        }))
    })
}

impl Drop for CarriedContextGuard {
    fn drop(&mut self) {
        CONTEXT.with(|stack| {
            let mut stack = stack.borrow_mut();
            assert_eq!(
                stack.len(),
                self.depth,
                "carried contexts must close in stack order"
            );
            let popped = stack.pop().expect("carried context stack underflow");
            assert!(
                match (&popped.frame, &self.frame) {
                    (Some(popped), Some(frame)) => Arc::ptr_eq(&popped.payload, &frame.payload),
                    (None, None) => true,
                    _ => false,
                },
                "carried context must pop its own frame"
            );
        });
    }
}

/// Request-owned state travels independently of read-attribution routing.
/// An empty slot masks any state already installed on the receiving thread.
pub fn push_request_state(state: Option<Payload>) -> RequestStateGuard {
    push_request_slot(state.map(|payload| RequestState {
        payload,
        completion: None,
    }))
}

/// Install the same allocation as opaque state and its completion observer.
pub fn push_request_state_with_completion<T: RequestCompletion>(
    state: Option<Arc<T>>,
) -> RequestStateGuard {
    push_request_slot(state.map(|state| RequestState {
        payload: state.clone(),
        completion: Some(state),
    }))
}

fn push_request_slot(state: Option<RequestState>) -> RequestStateGuard {
    let depth = REQUEST_STATE.with(|stack| {
        let mut stack = stack.borrow_mut();
        stack.push(state.clone());
        stack.len()
    });
    RequestStateGuard {
        state,
        depth,
        _thread: PhantomData,
    }
}

/// Current request state, without interpreting its opaque payload.
pub fn request_state<T: Any + Send + Sync>() -> Option<Arc<T>> {
    REQUEST_STATE
        .with(|stack| stack.borrow().last().cloned().flatten())
        .map(|state| {
            state
                .payload
                .downcast()
                .unwrap_or_else(|_| panic!("unexpected carried request state type"))
        })
}

/// A store failure belongs to the current request, including transported work.
pub fn request_store_failed() -> bool {
    REQUEST_STATE.with(|stack| {
        stack
            .borrow()
            .last()
            .and_then(Option::as_ref)
            .and_then(|state| state.completion.as_ref())
            .is_some_and(|completion| completion.store_failed())
    })
}

/// Restores the request state on the thread that installed it.
pub struct RequestStateGuard {
    state: Option<RequestState>,
    depth: usize,
    _thread: PhantomData<std::sync::MutexGuard<'static, ()>>,
}

impl Drop for RequestStateGuard {
    fn drop(&mut self) {
        REQUEST_STATE.with(|stack| {
            let mut stack = stack.borrow_mut();
            assert_eq!(
                stack.len(),
                self.depth,
                "request states must close in stack order"
            );
            let popped = stack.pop().expect("carried request state stack underflow");
            assert!(
                match (&popped, &self.state) {
                    (Some(popped), Some(state)) => Arc::ptr_eq(&popped.payload, &state.payload),
                    (None, None) => true,
                    _ => false,
                },
                "carried request state must pop its own frame"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::project_reads::{project_reads_suppressed, without_project_reads};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11775: a transported independent answer lost its request's operational store failure"
    )]
    fn request_completion_follows_transport_and_request_masking() {
        struct Completion(std::sync::atomic::AtomicBool);
        impl RequestCompletion for Completion {
            fn store_failed(&self) -> bool {
                self.0.load(std::sync::atomic::Ordering::Relaxed)
            }
        }
        let completion = Arc::new(Completion(std::sync::atomic::AtomicBool::new(false)));
        let _request = push_request_state_with_completion(Some(completion.clone()));
        let carried = CarriedContext::current();
        assert!(!request_store_failed());
        completion
            .0
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(request_store_failed());
        {
            let _empty = push_request_state(None);
            assert!(!request_store_failed());
        }
        assert!(request_store_failed());
        std::thread::spawn(move || carried.run(|| assert!(request_store_failed())))
            .join()
            .expect("transported completion worker");
        let _fresh = push_request_state_with_completion(Some(Arc::new(Completion(
            std::sync::atomic::AtomicBool::new(false),
        ))));
        assert!(!request_store_failed());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11534: policy completion must follow worker captures without leaking to siblings"
    )]
    fn completion_follows_transport_and_restores_siblings() {
        let outside = CarriedContext::current();
        let failed = Arc::new(Mutex::new(Vec::<String>::new()));
        {
            let _completion = push_completion(failed.clone());
            let execution = Arc::new(EvaluationExecution::default());
            let _execution = execution.install();
            let _capture = push(None);
            let carried = CarriedContext::current();
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    carried.run(|| {
                        completion::<Mutex<Vec<String>>>()
                            .unwrap()
                            .lock()
                            .unwrap()
                            .push("store failure".into());
                        outside.run(|| {
                            assert!(completion::<Mutex<Vec<String>>>().is_none());
                        });
                        assert!(Arc::ptr_eq(
                            &failed,
                            &completion::<Mutex<Vec<String>>>().unwrap()
                        ));
                    });
                });
            });
        }
        assert_eq!(*failed.lock().unwrap(), ["store failure"]);
        assert!(completion::<Mutex<Vec<String>>>().is_none());
        let healthy = Arc::new(Mutex::new(Vec::<String>::new()));
        let _completion = push_completion(healthy.clone());
        assert!(
            completion::<Mutex<Vec<String>>>()
                .unwrap()
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn evaluation_verdict_survives_empty_frames_and_isolates_transported_requests() {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let failed = Arc::new(EvaluationExecution::default());
        let healthy = Arc::new(EvaluationExecution::default());
        std::thread::scope(|scope| {
            for (evaluation, dependent) in [(failed.clone(), true), (healthy.clone(), false)] {
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let _evaluation = evaluation.install();
                    let _empty_capture = push(None);
                    let context = CarriedContext::current();
                    std::thread::scope(|worker| {
                        worker.spawn(|| {
                            context.run(|| {
                                barrier.wait();
                                if dependent {
                                    mark_execution_dependent();
                                }
                            })
                        });
                    });
                    assert_eq!(evaluation.verdict().is_content(), !dependent);
                });
            }
        });
        assert!(!failed.verdict().is_content());
        assert!(healthy.verdict().is_content());
        // Transporting no evaluation must mask a receiving worker's scope.
        let empty = CarriedContext::current();
        let _evaluation = healthy.install();
        empty.run(mark_execution_dependent);
        assert!(healthy.verdict().is_content());
    }

    #[test]
    fn unrelated_pool_work_does_not_inherit_project_read_suppression() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let context = CarriedContext::current();
        let state = Arc::new(String::from("receiving request"));
        let _state = push_request_state(Some(state.clone()));
        pool.install(|| {
            without_project_reads(|| {
                // A worker can service another request while a maintenance
                // task is suspended in Rayon. That request owns its state.
                let _state = push_request_state(Some(state.clone()));
                context.run(|| {
                    assert!(!project_reads_suppressed());
                    assert!(request_state::<String>().is_none());
                });
                assert!(Arc::ptr_eq(&state, &request_state::<String>().unwrap()));
                assert!(project_reads_suppressed());
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    context.run(|| panic!("injected transported task failure"));
                }));
                assert!(panic.is_err());
                assert!(Arc::ptr_eq(&state, &request_state::<String>().unwrap()));
                assert!(project_reads_suppressed());
            });
            assert!(!project_reads_suppressed());
        });
    }

    #[test]
    fn nested_pool_work_preserves_project_read_suppression() {
        let outer = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let inner = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let _frame = push(Some(Arc::new(42usize)));
        let state = Arc::new(String::from("owner request"));
        let _state = push_request_state(Some(state.clone()));
        let context = without_project_reads(CarriedContext::current);
        assert!(!project_reads_suppressed());
        outer.install(|| {
            assert!(!project_reads_suppressed());
            context.run(|| {
                assert!(project_reads_suppressed());
                assert_eq!(*top::<usize>().flatten().unwrap(), 42);
                assert!(Arc::ptr_eq(&state, &request_state::<String>().unwrap()));
                let nested = CarriedContext::current();
                inner.install(|| {
                    assert!(!project_reads_suppressed());
                    nested.run(|| {
                        assert!(project_reads_suppressed());
                        assert_eq!(*top::<usize>().flatten().unwrap(), 42);
                        assert!(Arc::ptr_eq(&state, &request_state::<String>().unwrap()));
                    });
                    assert!(!project_reads_suppressed());
                });
                assert!(project_reads_suppressed());
            });
            assert!(!project_reads_suppressed());
        });
        assert!(!project_reads_suppressed());
    }
}
