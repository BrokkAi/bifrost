//! Thread-local attribution of SQLite statements to derivation captures.
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConnectionTag(u64);
impl ConnectionTag {
    pub const NONE: Self = Self(0);
    pub fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(
            NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .expect("connection tags exhausted"),
        )
    }
}

pub trait AttributionFrame: Send + Sync {
    fn mark_unattributed(
        &self,
        statement: &str,
        family: Option<&'static str>,
        connection: ConnectionTag,
    );
    /// A statement under this frame escaped attribution. Must not panic.
    fn mark_lost(&self) {
        self.mark_unattributed("", None, ConnectionTag::NONE);
    }
}

/// Sees every statement that starts on its thread, and on helper threads that
/// enter a context carried from it, whatever scopes or frames are open. Scopes
/// and frames decide attribution; an observer only watches.
pub trait StatementObserver: Send + Sync {
    fn statement(&self, sql: &str);

    /// Whether store writes must not be dispatched while this observer is
    /// registered, because the work it watches must publish nothing.
    fn forbids_store_writes(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageClass {
    ExactKeys,
    DeclaredInputs,
    RecomputeOnCurrency,
}

#[derive(Clone)]
struct Scope {
    family: &'static str,
    class: CoverageClass,
}

#[derive(Clone, Default)]
pub struct AttributionContext {
    frames: Vec<Arc<dyn AttributionFrame>>,
    scopes: Vec<Scope>,
    families: Vec<&'static str>,
    observers: Vec<Arc<dyn StatementObserver>>,
    classifier_depth: usize,
}

thread_local! {
    static CONTEXT: RefCell<AttributionContext> = RefCell::new(AttributionContext::default());
    static LOST_STATEMENTS: Cell<u64> = const { Cell::new(0) };
}

/// Record that a statement escaped attribution because the dispatcher caught
/// a panic. Every frame of the thread's current context refuses retention,
/// including frames a worker entered through a carried context; the
/// thread-local count covers a context that cannot be borrowed here.
pub fn statement_lost() {
    let marked = CONTEXT.with(|context| {
        context.try_borrow().map(|context| {
            for frame in &context.frames {
                frame.mark_lost();
            }
        })
    });
    if marked.is_err() {
        LOST_STATEMENTS.with(|lost| lost.set(lost.get().saturating_add(1)));
    }
}
pub fn lost_statements() -> u64 {
    LOST_STATEMENTS.with(Cell::get)
}

pub struct FrameGuard;
pub struct ClassifierGuard {
    _thread: std::marker::PhantomData<*const ()>,
}
pub fn classifier_statements() -> ClassifierGuard {
    CONTEXT.with(|context| context.borrow_mut().classifier_depth += 1);
    ClassifierGuard {
        _thread: std::marker::PhantomData,
    }
}
impl Drop for ClassifierGuard {
    fn drop(&mut self) {
        CONTEXT.with(|context| context.borrow_mut().classifier_depth -= 1);
    }
}
pub struct ScopeGuard;
/// Pops the label it pushed. It is not `Send`: a label belongs to the thread
/// that opened it, and guards must drop in the reverse order of their entry.
pub struct FamilyGuard {
    label: &'static str,
    depth: usize,
    _thread: std::marker::PhantomData<*const ()>,
}
pub struct ObserverGuard {
    observer: Arc<dyn StatementObserver>,
}
pub struct ContextGuard {
    previous: AttributionContext,
}

pub fn enter_frame(frame: Arc<dyn AttributionFrame>) -> FrameGuard {
    CONTEXT.with(|context| context.borrow_mut().frames.push(frame));
    FrameGuard
}

impl Drop for FrameGuard {
    fn drop(&mut self) {
        CONTEXT.with(|context| {
            assert!(
                context.borrow_mut().frames.pop().is_some(),
                "attribution frame underflow"
            );
        });
    }
}

/// Observe every statement until the guard drops. Guards drop in reverse order
/// of entry, like frames and scopes.
pub fn observe_statements(observer: Arc<dyn StatementObserver>) -> ObserverGuard {
    CONTEXT.with(|context| context.borrow_mut().observers.push(observer.clone()));
    ObserverGuard { observer }
}

/// The innermost open scope's family and the number of frames on this thread,
/// so a test-support census can tell which path would attribute a statement.
#[cfg(any(test, feature = "test-support"))]
pub fn attribution_position_for_test() -> (Option<&'static str>, usize) {
    CONTEXT.with(|context| {
        let context = context.borrow();
        (
            context.scopes.last().map(|scope| scope.family),
            context.frames.len(),
        )
    })
}

/// Whether an observer registered on this thread forbids store writes.
pub fn store_writes_forbidden() -> bool {
    CONTEXT.with(|context| {
        context
            .borrow()
            .observers
            .iter()
            .any(|observer| observer.forbids_store_writes())
    })
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        CONTEXT.with(|context| {
            let popped = context
                .borrow_mut()
                .observers
                .pop()
                .expect("attribution observer underflow");
            assert!(
                Arc::ptr_eq(&popped, &self.observer),
                "attribution observers drop in reverse order of entry"
            );
        });
    }
}

pub fn enter_scope(family: &'static str, class: CoverageClass) -> ScopeGuard {
    CONTEXT.with(|context| context.borrow_mut().scopes.push(Scope { family, class }));
    ScopeGuard
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        CONTEXT.with(|context| {
            assert!(
                context.borrow_mut().scopes.pop().is_some(),
                "attribution scope underflow"
            );
        });
    }
}

/// Label unscoped statements for the innermost derivation capture. A label
/// supplies no coverage by itself.
pub fn statement_family(label: &'static str) -> FamilyGuard {
    let depth = CONTEXT.with(|context| {
        let mut context = context.borrow_mut();
        context.families.push(label);
        context.families.len() - 1
    });
    FamilyGuard {
        label,
        depth,
        _thread: std::marker::PhantomData,
    }
}

impl Drop for FamilyGuard {
    fn drop(&mut self) {
        CONTEXT.with(|context| {
            let mut context = context.borrow_mut();
            assert!(
                context.families.len() == self.depth + 1
                    && context.families.last() == Some(&self.label),
                "statement family {:?} at depth {} dropped out of order: {:?}",
                self.label,
                self.depth,
                context.families
            );
            context.families.pop();
        });
    }
}

/// Whether a capture frame is active on this thread, opened here or carried
/// in. Only a derivation capture opens frames. A family scope alone does not
/// count: code outside any demand attributes its SQL with scopes too.
pub fn capture_frame_active() -> bool {
    CONTEXT.with(|context| !context.borrow().frames.is_empty())
}

pub fn current_context() -> AttributionContext {
    CONTEXT.with(|context| context.borrow().clone())
}

impl AttributionContext {
    /// Enter this context on the current thread. Observers already active here
    /// stay active: entering a context never hides statements from them.
    pub fn enter(&self) -> ContextGuard {
        let previous = CONTEXT.with(|context| {
            let mut entered = self.clone();
            // Classifier suppression belongs to the thread running the
            // classifier. A context captured inside a classifier region and
            // entered elsewhere must still mark that thread's statements.
            entered.classifier_depth = context.borrow().classifier_depth;
            for observer in &context.borrow().observers {
                if !entered
                    .observers
                    .iter()
                    .any(|known| Arc::ptr_eq(known, observer))
                {
                    entered.observers.push(observer.clone());
                }
            }
            context.replace(entered)
        });
        ContextGuard { previous }
    }
}

impl Drop for ContextGuard {
    fn drop(&mut self) {
        CONTEXT.with(|context| {
            context.replace(std::mem::take(&mut self.previous));
        });
    }
}

pub fn statement_started(sql: &str, connection: ConnectionTag) {
    CONTEXT.with(|context| {
        let context = context.borrow();
        for observer in &context.observers {
            observer.statement(sql);
        }
        if context.scopes.is_empty() && context.classifier_depth == 0 {
            if let Some(frame) = context.frames.last() {
                frame.mark_unattributed(sql, context.families.last().copied(), connection);
            }
        } else {
            debug_assert!(context.scopes.iter().all(|scope| !scope.family.is_empty()));
            let _ = context.scopes.last().map(|scope| scope.class);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9755: a lost statement on a worker never reached the capturing frame"
    )]
    fn lost_statement_on_a_worker_reaches_the_carried_frame() {
        struct Lost(std::sync::atomic::AtomicBool);
        impl AttributionFrame for Lost {
            fn mark_unattributed(&self, _: &str, _: Option<&'static str>, _: ConnectionTag) {}
            fn mark_lost(&self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let frame = Arc::new(Lost(std::sync::atomic::AtomicBool::new(false)));
        let _frame = enter_frame(frame.clone());
        let carried = current_context();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _context = carried.enter();
                    statement_lost();
                })
                .join()
                .unwrap();
        });
        assert!(frame.0.load(Ordering::Relaxed));
    }

    struct Counter(AtomicUsize);
    impl AttributionFrame for Counter {
        fn mark_unattributed(&self, _statement: &str, _: Option<&'static str>, _: ConnectionTag) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct Labels(std::sync::Mutex<Vec<Option<&'static str>>>);
    impl AttributionFrame for Labels {
        fn mark_unattributed(
            &self,
            _statement: &str,
            family: Option<&'static str>,
            _: ConnectionTag,
        ) {
            self.0.lock().unwrap().push(family);
        }
    }

    #[test]
    fn the_innermost_family_label_decides() {
        let frame = Arc::new(Labels(std::sync::Mutex::new(Vec::new())));
        let _frame = enter_frame(frame.clone());
        statement_started("SELECT 1", ConnectionTag::NONE);
        let outer = statement_family("outer");
        statement_started("SELECT 2", ConnectionTag::NONE);
        {
            let _inner = statement_family("inner");
            statement_started("SELECT 3", ConnectionTag::NONE);
        }
        statement_started("SELECT 4", ConnectionTag::NONE);
        drop(outer);
        statement_started("SELECT 5", ConnectionTag::NONE);
        assert_eq!(
            *frame.0.lock().unwrap(),
            [None, Some("outer"), Some("inner"), Some("outer"), None]
        );
    }

    #[test]
    fn classifier_statements_skip_capture_but_reach_observers() {
        let frame = Arc::new(Counter(AtomicUsize::new(0)));
        struct Observer(AtomicUsize);
        impl StatementObserver for Observer {
            fn statement(&self, _: &str) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let observer = Arc::new(Observer(AtomicUsize::new(0)));
        let _frame = enter_frame(frame.clone());
        let _observer = observe_statements(observer.clone());
        let _classifier = classifier_statements();
        statement_started("PRAGMA temp.schema_version", ConnectionTag::NONE);
        assert_eq!(frame.0.load(Ordering::Relaxed), 0);
        assert_eq!(observer.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[should_panic(expected = "dropped out of order")]
    fn a_family_label_dropped_out_of_order_panics() {
        let outer = statement_family("outer");
        let _inner = statement_family("inner");
        drop(outer);
    }

    #[test]
    fn nested_frames_and_scopes() {
        let outer = Arc::new(Counter(AtomicUsize::new(0)));
        let inner = Arc::new(Counter(AtomicUsize::new(0)));
        let _outer = enter_frame(outer.clone());
        statement_started("SELECT 1", ConnectionTag::NONE);
        {
            let _inner = enter_frame(inner.clone());
            statement_started("SELECT 2", ConnectionTag::NONE);
            let _scope = enter_scope("test", CoverageClass::ExactKeys);
            statement_started("SELECT 3", ConnectionTag::NONE);
        }
        statement_started("SELECT 4", ConnectionTag::NONE);
        assert_eq!(outer.0.load(Ordering::Relaxed), 2);
        assert_eq!(inner.0.load(Ordering::Relaxed), 1);
    }

    struct Seen(std::sync::Mutex<Vec<String>>);
    impl StatementObserver for Seen {
        fn statement(&self, sql: &str) {
            self.0.lock().unwrap().push(sql.to_owned());
        }
    }

    #[test]
    fn observers_see_statements_that_scopes_and_frames_hide() {
        let seen = Arc::new(Seen(std::sync::Mutex::new(Vec::new())));
        let frame = Arc::new(Counter(AtomicUsize::new(0)));
        let _observer = observe_statements(seen.clone());
        {
            let _scope = enter_scope("test", CoverageClass::ExactKeys);
            statement_started("under a scope", ConnectionTag::NONE);
        }
        {
            let _frame = enter_frame(frame.clone());
            let _scope = enter_scope("test", CoverageClass::DeclaredInputs);
            statement_started("under a nested frame and scope", ConnectionTag::NONE);
        }
        {
            let _context = AttributionContext::default().enter();
            statement_started("in an entered context", ConnectionTag::NONE);
        }
        assert_eq!(
            *seen.0.lock().unwrap(),
            [
                "under a scope",
                "under a nested frame and scope",
                "in an entered context"
            ]
        );
        assert_eq!(frame.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn only_an_observer_that_forbids_them_forbids_store_writes() {
        struct Forbids;
        impl StatementObserver for Forbids {
            fn statement(&self, _: &str) {}
            fn forbids_store_writes(&self) -> bool {
                true
            }
        }
        let _watching = observe_statements(Arc::new(Seen(std::sync::Mutex::new(Vec::new()))));
        assert!(!store_writes_forbidden());
        {
            let _forbidding = observe_statements(Arc::new(Forbids));
            assert!(store_writes_forbidden());
        }
        assert!(!store_writes_forbidden());
    }

    #[test]
    fn observers_reach_helper_threads_only_through_a_carried_context() {
        let seen = Arc::new(Seen(std::sync::Mutex::new(Vec::new())));
        let _observer = observe_statements(seen.clone());
        let context = current_context();
        std::thread::spawn(|| statement_started("not carried", ConnectionTag::NONE))
            .join()
            .unwrap();
        std::thread::spawn(move || {
            let _context = context.enter();
            statement_started("carried", ConnectionTag::NONE);
        })
        .join()
        .unwrap();
        assert_eq!(*seen.0.lock().unwrap(), ["carried"]);
    }

    #[test]
    fn delegated_context_is_explicit() {
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let _frame = enter_frame(counter.clone());
        let context = current_context();
        std::thread::spawn(|| statement_started("untransported", ConnectionTag::NONE))
            .join()
            .unwrap();
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        std::thread::spawn(move || {
            let _context = context.enter();
            statement_started("transported", ConnectionTag::NONE);
        })
        .join()
        .unwrap();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod sqlite_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Counter(AtomicUsize);
    impl AttributionFrame for Counter {
        fn mark_unattributed(&self, _: &str, _: Option<&'static str>, _: ConnectionTag) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn subscriber_drop_keeps_statement_guard() {
        let conn = crate::cache_db::open_in_memory_store_connection().unwrap();
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let observed = Arc::new(AtomicUsize::new(0));
        let _frame = enter_frame(counter.clone());
        let subscription = crate::cache_db::sql_profile::subscribe_test_statements(
            &conn,
            Arc::new({
                let observed = observed.clone();
                move |_| {
                    observed.fetch_add(1, Ordering::Relaxed);
                }
            }),
        );
        conn.execute_batch("SELECT 1").unwrap();
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        assert_eq!(observed.load(Ordering::Relaxed), 1);
        {
            let _scope = enter_scope("test", CoverageClass::ExactKeys);
            conn.execute_batch("SELECT 2").unwrap();
        }
        assert_eq!(counter.0.load(Ordering::Relaxed), 1);
        drop(subscription);
        conn.execute_batch("SELECT 3").unwrap();
        assert_eq!(counter.0.load(Ordering::Relaxed), 2);
        assert_eq!(observed.load(Ordering::Relaxed), 2);
    }
}
