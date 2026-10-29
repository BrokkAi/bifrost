//! Context follows work handed from one thread to another. Core does not
//! know what the context contains; callers provide a typed frame.

use std::any::Any;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;

type Frame = Arc<dyn Any + Send + Sync>;

thread_local! {
    static CONTEXT: RefCell<Vec<Option<Frame>>> = const { RefCell::new(Vec::new()) };
}

/// The context of the thread handing work to another thread.
#[derive(Clone)]
pub struct CarriedContext(Option<Frame>);

impl CarriedContext {
    pub fn current() -> Self {
        Self(CONTEXT.with(|stack| stack.borrow().last().cloned().flatten()))
    }

    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = push(self.0.clone());
        f()
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
