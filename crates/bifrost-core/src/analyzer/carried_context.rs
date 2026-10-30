//! Context follows work handed from one thread to another. Core does not
//! know what the attribution frame contains; callers provide its type.
//! Request state travels in an independent slot; neither payload interprets
//! the other. Project-read suppression follows work through nested fan-outs.

use std::any::Any;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;

type Frame = Arc<dyn Any + Send + Sync>;

thread_local! {
    static CONTEXT: RefCell<Vec<Option<Frame>>> = const { RefCell::new(Vec::new()) };
    static REQUEST_STATE: RefCell<Vec<Option<Frame>>> = const { RefCell::new(Vec::new()) };
}

/// The context of the thread handing work to another thread.
#[derive(Clone)]
pub struct CarriedContext {
    frame: Option<Frame>,
    request_state: Option<Frame>,
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
            frame: CONTEXT.with(|stack| stack.borrow().last().cloned().flatten()),
            request_state: REQUEST_STATE.with(|stack| stack.borrow().last().cloned().flatten()),
            project_reads_suppressed,
        }
    }

    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = push(self.frame.clone());
        let _request_state = push_request_state(self.request_state.clone());
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

pub fn push(frame: Option<Frame>) -> CarriedContextGuard {
    let depth = CONTEXT.with(|stack| {
        let mut stack = stack.borrow_mut();
        stack.push(frame.clone());
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
        .with(|stack| stack.borrow().last().cloned())
        .map(|slot| {
            slot.map(|frame| {
                frame
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
            slot.as_ref().map(|frame| {
                frame
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
                match (&popped, &self.frame) {
                    (Some(popped), Some(frame)) => Arc::ptr_eq(popped, frame),
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
pub fn push_request_state(state: Option<Frame>) -> RequestStateGuard {
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
                .downcast()
                .unwrap_or_else(|_| panic!("unexpected carried request state type"))
        })
}

/// Restores the request state on the thread that installed it.
pub struct RequestStateGuard {
    state: Option<Frame>,
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
                    (Some(popped), Some(state)) => Arc::ptr_eq(popped, state),
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
