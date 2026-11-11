//! Analyzer read capture for demand-driven derivations.
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_core::attribution::{self, AttributionFrame, ConnectionTag};
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    CaptureHook, CaptureReceipt, DerivationAuthority, DerivationRevision, NotReusableCause,
};
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::ReadKey;

use crate::analyzer::QueryReadIncomplete;
use crate::analyzer::i_analyzer::{AnalyzerQueryScope, capture_query_reads_deferred};

/// A capture bound to the analyzer recording view of one workspace generation.
pub struct AnalyzerCapture<R, A> {
    types: PhantomData<fn(R, A)>,
}

impl<R, A> AnalyzerCapture<R, A> {
    pub fn new() -> Self {
        Self { types: PhantomData }
    }
}

impl<R, A> Default for AnalyzerCapture<R, A> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct ReportedCauses {
    execution: Vec<NotReusableCause>,
    refusal: Vec<NotReusableCause>,
}
thread_local! {
    static CAUSES: RefCell<Vec<Arc<std::sync::Mutex<ReportedCauses>>>> = const { RefCell::new(Vec::new()) };
}
struct CauseGuard;
impl CauseGuard {
    fn enter(causes: Arc<std::sync::Mutex<ReportedCauses>>) -> Self {
        CAUSES.with(|stack| stack.borrow_mut().push(causes));
        Self
    }
}
impl Drop for CauseGuard {
    fn drop(&mut self) {
        CAUSES.with(|stack| {
            stack
                .borrow_mut()
                .pop()
                .expect("capture cause stack underflow");
        });
    }
}
struct CaptureFrame {
    unattributed: AtomicUsize,
}
impl AttributionFrame for CaptureFrame {
    fn mark_unattributed(&self, _: &str, _: Option<&'static str>, _: ConnectionTag) {
        self.unattributed.fetch_add(1, Ordering::Relaxed);
    }
}

impl<R: DerivationRevision, A: DerivationAuthority> CaptureHook<R, A> for AnalyzerCapture<R, A> {
    fn capture(&self, _revision: &R, _authority: &A, work: &mut dyn FnMut()) -> CaptureReceipt {
        let frame = Arc::new(CaptureFrame {
            unattributed: AtomicUsize::new(0),
        });
        let causes = Arc::new(std::sync::Mutex::new(ReportedCauses::default()));
        let ((reasons, ()), reads) = super::with_current_analyzer(|analyzer| {
            capture_query_reads_deferred(analyzer, || {
                let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
                let _frame = attribution::enter_frame(frame.clone());
                let _causes = CauseGuard::enter(causes.clone());
                let lost_before = attribution::lost_statements();
                work();
                if attribution::lost_statements() != lost_before {
                    frame.unattributed.fetch_add(1, Ordering::Relaxed);
                }
                (scope.captured_read_incompleteness(), ())
            })
        });
        let unstable_reason = reasons.iter().any(|reason| {
            !matches!(
                reason,
                QueryReadIncomplete::ArtifactUnavailable(_)
                    | QueryReadIncomplete::SemanticEvidenceGap(_)
            )
        });
        let stable_reasons = reasons
            .into_iter()
            .filter_map(|reason| match reason {
                QueryReadIncomplete::ArtifactUnavailable(value) => {
                    Some(format!("artifact\0{value}"))
                }
                QueryReadIncomplete::SemanticEvidenceGap(value) => Some(format!("gap\0{value}")),
                // StructureUnavailable includes a mount-bearing file; refusing reuse
                // avoids persisting an incomplete reason that cannot be replayed here.
                _ => None,
            })
            .collect();
        let unattributed = reads.unattributed_reads() + frame.unattributed.load(Ordering::Relaxed);
        let reported = causes.lock().expect("capture causes poisoned");
        let mut reuse_refusals = reported.refusal.clone();
        if reads.reuse_refused() || unstable_reason || !super::binding_remains_current() {
            reuse_refusals.push(NotReusableCause::InvalidDependencyEvidence);
        }
        let mut execution_dependences = reported.execution.clone();
        execution_dependences.extend(
            (execution_dependences.len()..reads.execution_dependences())
                .map(|_| NotReusableCause::ExecutionDependent),
        );
        CaptureReceipt {
            reads: reads.unordered_keys(),
            unattributed,
            execution_dependences,
            reuse_refusals,
            persistence_refusals: reads.persistence_refusals(),
            stable_reasons,
        }
    }

    fn report_unattributed(&self) {
        super::with_current_analyzer(|analyzer| analyzer.record_unattributed_read());
    }
    fn report_execution_dependence(&self, cause: NotReusableCause) {
        CAUSES.with(|stack| {
            if let Some(causes) = stack.borrow().last() {
                causes
                    .lock()
                    .expect("capture causes poisoned")
                    .execution
                    .push(cause);
            }
        });
        super::with_current_analyzer(|analyzer| analyzer.mark_execution_dependent());
    }
    fn report_reuse_refusal(&self, cause: NotReusableCause) {
        CAUSES.with(|stack| {
            if let Some(causes) = stack.borrow().last() {
                causes
                    .lock()
                    .expect("capture causes poisoned")
                    .refusal
                    .push(cause);
            }
        });
        super::with_current_analyzer(|analyzer| analyzer.refuse_read_reuse());
    }
    fn report_persistence_refusals(&self, count: usize) {
        if count > 0 {
            super::with_current_analyzer(|analyzer| {
                crate::analyzer::i_analyzer::record_persistence_refusals(analyzer, count);
            });
        }
    }
    fn replay_reasons(&self, reasons: &[String]) {
        for reason in reasons {
            if let Some(value) = reason.strip_prefix("artifact\0") {
                super::with_current_analyzer(|analyzer| {
                    analyzer.record_query_incomplete(QueryReadIncomplete::ArtifactUnavailable(
                        value.into(),
                    ))
                });
            } else if let Some(value) = reason.strip_prefix("gap\0") {
                super::with_current_analyzer(|analyzer| {
                    analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                        value.into(),
                    ))
                });
            } else {
                super::with_current_analyzer(|analyzer| analyzer.refuse_read_reuse());
            }
        }
    }
    fn record(&self, read: ReadKey) {
        // Record only into a ledger frame, whether this thread opened it or
        // carried it from the thread that handed the work over. With no frame,
        // the analyzer's broadcast fallback would put this lookup into a
        // concurrent reader's ledger.
        if crate::analyzer::i_analyzer::attribution_ledger_frame_active() {
            super::with_current_analyzer(|analyzer| analyzer.record_read(read));
        }
    }
    fn cancelled(&self) -> bool {
        super::with_current_analyzer(|analyzer| {
            analyzer
                .active_query_cancellation()
                .is_some_and(|token| token.is_cancelled())
        })
    }
}

// Absorbing funnel scopes plug in above capture_query_reads_deferred; their
// admission and replay proof is a separate slice.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerQueryScope, IAnalyzer, MultiAnalyzer, ReadLedger};
    use brokk_bifrost_core::attribution::{CoverageClass, current_context, enter_scope};
    use brokk_bifrost_semantic::analyzer::semantic::derivation::{
        DerivationKindId, DerivationQuestion,
    };
    use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;
    use brokk_bifrost_semantic::analyzer::semantic::read_ledger::{LookupKind, LookupQuestion};
    use brokk_bifrost_test_macros::hardwon;

    #[derive(Clone, Copy, Eq, PartialEq, Hash)]
    struct TestBinding;
    impl brokk_bifrost_core::retention_budget::RetainedBytes for TestBinding {
        fn retained_bytes(&self) -> usize {
            std::mem::size_of::<Self>()
        }
    }
    impl DerivationRevision for TestBinding {
        fn is_established(&self) -> bool {
            true
        }
    }
    impl DerivationAuthority for TestBinding {
        fn retention_refusal(&self) -> Option<NotReusableCause> {
            None
        }
    }
    #[test]
    fn derivation_capture_shadows_parent_and_replays_channels() {
        let analyzer: Arc<dyn IAnalyzer> = Arc::new(MultiAnalyzer::default());
        let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
        let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
        let parent = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer.as_ref(), parent.clone());
        let inner = ReadKey::Configuration(StableDigest::sha256(b"inner"));
        let lookup = ReadKey::lookup(
            LookupKind::Derivation(DerivationKindId("test:derivation:v1")),
            LookupQuestion::Derivation(DerivationQuestion {
                language: None,
                subject: None,
                rel_path: None,
                name: None,
            }),
            StableDigest::sha256(b"answer"),
        );
        let receipt = capture.capture(&TestBinding, &TestBinding, &mut || {
            capture.record(inner.clone());
            capture.report_unattributed();
            capture.report_execution_dependence(NotReusableCause::Cancelled);
            capture.report_reuse_refusal(NotReusableCause::LimitReached);
            capture.report_persistence_refusals(1);
            capture.replay_reasons(&["gap\0partial".to_string()]);
        });
        assert_eq!(receipt.reads.as_slice(), std::slice::from_ref(&inner));
        assert_eq!(receipt.unattributed, 1);
        assert!(
            receipt
                .execution_dependences
                .contains(&NotReusableCause::Cancelled)
        );
        assert!(
            receipt
                .reuse_refusals
                .contains(&NotReusableCause::LimitReached)
        );
        assert_eq!(receipt.stable_reasons, ["gap\0partial"]);
        assert_eq!(receipt.persistence_refusals, 1);
        assert_eq!(parent.persistence_refusals(), 0);
        assert!(!parent.keys().contains(&inner));
        capture.record(lookup.clone());
        assert_eq!(parent.keys().len(), 1);
        assert!(parent.keys().contains(&lookup));
        capture.replay_reasons(&receipt.stable_reasons);
        capture.report_persistence_refusals(receipt.persistence_refusals);
        assert_eq!(parent.persistence_refusals(), 1);
        assert!(parent.unattributed_reads() == 0);
        assert!(parent.execution_dependences() == 0);
    }

    #[test]
    fn sql_attribution_uses_frame_and_delegated_context() {
        let analyzer: Arc<dyn IAnalyzer> = Arc::new(MultiAnalyzer::default());
        let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
        let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
        let conn = brokk_bifrost_core::cache_db::open_in_memory_store_connection().unwrap();
        let unscoped = capture.capture(&TestBinding, &TestBinding, &mut || {
            conn.execute_batch("SELECT 1").unwrap();
            let carried = current_context();
            std::thread::spawn(move || {
                let _context = carried.enter();
                attribution::statement_started("delegated statement", ConnectionTag::NONE);
            })
            .join()
            .unwrap();
        });
        assert_eq!(unscoped.unattributed, 2);
        let scoped = capture.capture(&TestBinding, &TestBinding, &mut || {
            let _scope = enter_scope("test", CoverageClass::ExactKeys);
            conn.execute_batch("SELECT 2").unwrap();
        });
        assert_eq!(scoped.unattributed, 0);
    }
    #[test]
    #[hardwon("#9755: a panicking trace listener lost a statement during capture")]
    fn lost_statement_refuses_capture() {
        let analyzer: Arc<dyn IAnalyzer> = Arc::new(MultiAnalyzer::default());
        let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
        let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
        let receipt = capture.capture(&TestBinding, &TestBinding, &mut || {
            attribution::statement_lost();
        });
        assert_eq!(receipt.unattributed, 1);
    }
}
