//! Analyzer read capture for demand-driven derivations.
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict;
use brokk_bifrost_core::attribution::{self, AttributionFrame, ConnectionTag};
use brokk_bifrost_semantic::analyzer::semantic::derivation::{
    CaptureHook, CaptureReceipt, DerivationAuthority, DerivationRevision, NotReusableCause,
    UnstableReasons,
};
use brokk_bifrost_semantic::analyzer::semantic::read_ledger::ReadKey;

use crate::analyzer::QueryReadIncomplete;
use crate::analyzer::i_analyzer::{AnalyzerQueryScope, capture_query_reads_deferred};

// Decode only registered static labels. Never leak a decoded string into a
// process-lifetime reason; unknown labels fail closed.
fn proof_stop_label(value: &str) -> Option<&'static str> {
    crate::analyzer::i_analyzer::DETERMINISTIC_PROOF_STOP_LABELS
        .iter()
        .copied()
        .find(|label| *label == value)
}

pub(super) fn stable_reason(reason: &QueryReadIncomplete) -> Option<String> {
    // String receipts cannot replay lookup provenance (#11525).
    if reason.lookup_provenance().is_some() {
        return None;
    }
    reason.stable_replay_reason()
}

// An evaluation that saw a reason no string can replay is execution dependent.
fn join_unstable_reason_verdict() {
    brokk_bifrost_core::analyzer::carried_context::join_evaluation_verdict(
        ReuseVerdict::ExecutionDependent(
            brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other,
        ),
    );
}

// Transient reasons keep cancellation tied to the leader's own request.
// Unstable reasons refuse reuse; followers record their own reasons while
// recomputing instead of replaying this payload (#11525, #13102).
#[derive(Debug)]
struct ReplayableReasons(Vec<QueryReadIncomplete>);
impl UnstableReasons for ReplayableReasons {
    fn belongs_to_leader_request(&self) -> bool {
        self.0
            .iter()
            .any(QueryReadIncomplete::belongs_to_leader_request)
    }
}

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
        let unstable_reason = reasons.iter().any(|reason| stable_reason(reason).is_none());
        if unstable_reason {
            join_unstable_reason_verdict();
        }
        let stable_reasons = reasons.iter().filter_map(stable_reason).collect();
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
            unstable_reasons: unstable_reason
                .then(|| Arc::new(ReplayableReasons(reasons)) as Arc<dyn UnstableReasons>),
            explicit_verdict: reads.explicit_verdict(),
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
    fn report_verdict(&self, verdict: ReuseVerdict) {
        super::with_current_analyzer(|analyzer| analyzer.join_reuse_verdict(verdict));
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
            } else if let Some(label) = reason.strip_prefix("proof\0").and_then(proof_stop_label) {
                super::with_current_analyzer(|analyzer| {
                    analyzer.record_query_incomplete(QueryReadIncomplete::ProofStopped {
                        reason: label,
                        cause: None,
                    })
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

    struct StopKind {
        calls: Arc<AtomicUsize>,
        cause: Option<crate::analyzer::read_ledger::DerivationExecutionCause>,
        label: Option<&'static str>,
    }
    impl brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind for StopKind {
        type Key = String;
        type Output = String;
        const ID: DerivationKindId = DerivationKindId("test:stable-proof-stop:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &String) -> DerivationQuestion {
            DerivationQuestion {
                language: None,
                subject: None,
                rel_path: None,
                name: None,
            }
        }
        fn key_from_question(_: &DerivationQuestion) -> Option<String> {
            Some(String::new())
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationFrame<
                '_,
                R,
                A,
            >,
            _: &String,
        ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::Computed<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            super::super::with_current_analyzer(|analyzer| {
                analyzer.record_query_incomplete(QueryReadIncomplete::ProofStopped {
                    reason: self.label.unwrap_or_else(|| {
                        if self.cause
                            == Some(
                                crate::analyzer::read_ledger::DerivationExecutionCause::Provider,
                            )
                        {
                            "analyzer_unavailable"
                        } else {
                            "depth_limit"
                        }
                    }),
                    cause: self.cause,
                });
            });
            brokk_bifrost_semantic::analyzer::semantic::derivation::Computed::Available {
                value: "unknown".into(),
                complete: self.cause.is_none(),
                validity:
                    brokk_bifrost_semantic::analyzer::semantic::derivation::ReuseValidity::Reusable,
                // As real producers do: the computation claims a content
                // verdict, so an operational stop must be refused through the
                // captured reason, not through the producer's own verdict.
                reuse: brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
            }
        }
        fn output_projection(
            value: &String,
            hash: &mut brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher,
        ) {
            hash.value(value.as_bytes());
        }
    }
    struct NoInputs;
    impl
        brokk_bifrost_semantic::analyzer::semantic::derivation::BaseInputs<TestBinding, TestBinding>
        for NoInputs
    {
        fn unchanged(
            &self,
            _: &ReadKey,
            _: &TestBinding,
            _: &TestBinding,
            _: &TestBinding,
        ) -> bool {
            true
        }
    }

    #[test]
    #[hardwon(
        "#11145: derivations refused deterministic proof stops and recomputed on every request"
    )]
    fn deterministic_proof_stop_is_retained_and_replayed() {
        use crate::analyzer::read_ledger::DerivationExecutionCause;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            Demanded, DerivationEngine, Handle,
        };
        for cause in [
            None,
            Some(DerivationExecutionCause::Budget),
            Some(DerivationExecutionCause::Provider),
        ] {
            let analyzer = MultiAnalyzer::default();
            let _host = super::super::HostGuard::enter_test(&analyzer);
            let calls = Arc::new(AtomicUsize::new(0));
            let engine = DerivationEngine::new(
                &RetentionBudget::new(1_000_000),
                Arc::new(AnalyzerCapture::new()),
                Arc::new(NoInputs),
            );
            engine.register(StopKind {
                calls: calls.clone(),
                cause,
                label: None,
            });
            let mut answers = Vec::new();
            for _ in 0..2 {
                let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                let Demanded::Available {
                    value, complete, ..
                } = engine.demand::<StopKind>(&String::new(), TestBinding, TestBinding)
                else {
                    panic!("stop should return a value")
                };
                assert_eq!(matches!(value, Handle::Retained(_)), cause.is_none());
                answers.push((
                    value.to_string(),
                    complete,
                    scope.captured_read_incompleteness(),
                ));
            }
            assert_eq!(answers[0], answers[1]);
            assert!(!answers[0].1);
            assert_eq!(
                answers[0].2,
                [QueryReadIncomplete::ProofStopped {
                    reason: if cause == Some(DerivationExecutionCause::Provider) {
                        "analyzer_unavailable"
                    } else {
                        "depth_limit"
                    },
                    cause
                }]
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if cause.is_none() { 1 } else { 2 }
            );
        }
    }
    type TestEngine = brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationEngine<
        TestBinding,
        TestBinding,
    >;
    // A test kind whose first computation waits until another demand has
    // joined its flight, then records the reasons `reasons(call)` names.
    struct FlightKind {
        engine: Arc<std::sync::OnceLock<std::sync::Weak<TestEngine>>>,
        calls: Arc<AtomicUsize>,
        entered: Arc<std::sync::atomic::AtomicBool>,
        reasons: fn(usize) -> Vec<QueryReadIncomplete>,
        complete: bool,
    }
    impl brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKind for FlightKind {
        type Key = String;
        type Output = String;
        const ID: DerivationKindId = DerivationKindId("test:flight-typed-reasons:v1");
        const STRATUM: u16 = 0;
        const CHILDREN: &'static [(DerivationKindId, u16)] = &[];
        fn question(_: &String) -> DerivationQuestion {
            DerivationQuestion {
                language: None,
                subject: None,
                rel_path: None,
                name: None,
            }
        }
        fn key_from_question(_: &DerivationQuestion) -> Option<String> {
            Some(String::new())
        }
        fn compute<R: DerivationRevision, A: DerivationAuthority>(
            &self,
            _: &mut brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationFrame<
                '_,
                R,
                A,
            >,
            _: &String,
        ) -> brokk_bifrost_semantic::analyzer::semantic::derivation::Computed<String> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.entered.store(true, Ordering::SeqCst);
                let engine = self
                    .engine
                    .get()
                    .and_then(std::sync::Weak::upgrade)
                    .unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while engine.followers_joined() == 0 {
                    assert!(std::time::Instant::now() < deadline, "no follower joined");
                    std::thread::yield_now();
                }
            }
            super::super::with_current_analyzer(|analyzer| {
                for reason in (self.reasons)(call) {
                    analyzer.record_query_incomplete(reason);
                }
            });
            brokk_bifrost_semantic::analyzer::semantic::derivation::Computed::Available {
                value: format!("call {call}"),
                complete: self.complete,
                validity:
                    brokk_bifrost_semantic::analyzer::semantic::derivation::ReuseValidity::Reusable,
                reuse: ReuseVerdict::Content,
            }
        }
        fn output_projection(
            value: &String,
            hash: &mut brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher,
        ) {
            hash.value(value.as_bytes());
        }
    }

    // What one caller can see of a demand: the answer, its reuse state, and the
    // incompleteness, ledger refusal and evaluation verdict on its own thread.
    #[derive(Debug, PartialEq)]
    struct Observed {
        value: String,
        complete: bool,
        retained: bool,
        reuse_refused: bool,
        reasons: Vec<String>,
        verdict: ReuseVerdict,
    }

    // Runs one leader and one follower on one flight. Returns what each saw
    // and how many times the computation ran.
    fn flight_wave(
        reasons: fn(usize) -> Vec<QueryReadIncomplete>,
        complete: bool,
    ) -> (Observed, Observed, usize) {
        use crate::analyzer::EvaluationExecution;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            Demanded, DerivationEngine, Handle,
        };
        let analyzer = Arc::new(MultiAnalyzer::default());
        let engine: Arc<TestEngine> = Arc::new(DerivationEngine::new(
            &RetentionBudget::new(1_000_000),
            Arc::new(AnalyzerCapture::new()),
            Arc::new(NoInputs),
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let weak_engine = Arc::new(std::sync::OnceLock::new());
        weak_engine.set(Arc::downgrade(&engine)).unwrap();
        engine.register(FlightKind {
            engine: weak_engine,
            calls: calls.clone(),
            entered: entered.clone(),
            reasons,
            complete,
        });
        let demand = || {
            let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
            let evaluation = Arc::new(EvaluationExecution::default());
            let _evaluation = evaluation.install();
            let ledger = Arc::new(ReadLedger::new());
            let _ledger = AnalyzerQueryScope::with_read_ledger(analyzer.as_ref(), ledger.clone());
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(analyzer.as_ref());
            let Demanded::Available {
                value,
                complete,
                validity,
                ..
            } = engine.demand::<FlightKind>(&String::new(), TestBinding, TestBinding)
            else {
                panic!("the kind should return a value")
            };
            // In recorded order: completion keeps the first reason, so the
            // follower must see the leader's order, not only its set.
            let reasons = scope
                .captured_read_incompleteness()
                .iter()
                .map(|reason| format!("{reason:?}"))
                .collect::<Vec<_>>();
            Observed {
                value: value.to_string(),
                complete,
                retained: matches!(value, Handle::Retained(_)),
                reuse_refused: ledger.reuse_refused()
                    && matches!(
                        validity,
                        brokk_bifrost_semantic::analyzer::semantic::derivation::ReuseValidity::NotReusable(_)
                    ),
                reasons,
                verdict: evaluation.verdict(),
            }
        };
        let (leader, follower) = std::thread::scope(|threads| {
            let leader = threads.spawn(demand);
            while !entered.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            let follower = threads.spawn(demand);
            (leader.join().unwrap(), follower.join().unwrap())
        });
        (leader, follower, calls.load(Ordering::SeqCst))
    }
    #[test]
    #[hardwon(
        "#11525: a singleflight follower lost the typed incompleteness reasons its leader recorded"
    )]
    fn follower_of_unretained_flight_replays_the_leaders_typed_reasons() {
        use crate::analyzer::ProjectFile;
        fn structure(_: usize) -> Vec<QueryReadIncomplete> {
            vec![QueryReadIncomplete::StructureUnavailable(ProjectFile::new(
                std::env::current_dir().unwrap(),
                "Lookup.java",
            ))]
        }
        // A stable reason beside an unstable one: each caller records both once.
        fn mixed(call: usize) -> Vec<QueryReadIncomplete> {
            let mut reasons = structure(call);
            reasons.push(QueryReadIncomplete::ArtifactUnavailable("jar".into()));
            reasons
        }
        fn stable(_: usize) -> Vec<QueryReadIncomplete> {
            vec![QueryReadIncomplete::ArtifactUnavailable("jar".into())]
        }
        fn nothing(_: usize) -> Vec<QueryReadIncomplete> {
            Vec::new()
        }
        // Only the first computation is cancelled: the leader's request ended.
        fn cancelled_once(call: usize) -> Vec<QueryReadIncomplete> {
            if call == 0 {
                vec![QueryReadIncomplete::Cancelled]
            } else {
                Vec::new()
            }
        }
        // Producer flag true and false: neither may make the answer complete.
        for (reasons, complete) in [
            (structure as fn(usize) -> _, true),
            (structure, false),
            (mixed, true),
        ] {
            let (leader, follower, calls) = flight_wave(reasons, complete);
            assert_eq!(calls, 2);
            assert_eq!(leader.value, "call 0");
            assert_eq!(follower.value, "call 1");
            // Completion presents reasons in canonical order, independent of
            // the order the leader recorded them (95797831e8).
            let mut canonical = reasons(0);
            canonical.sort_by_cached_key(QueryReadIncomplete::answer_order_key);
            let expected = canonical
                .iter()
                .map(|reason| format!("{reason:?}"))
                .collect::<Vec<_>>();
            assert_eq!(leader.reasons, expected);
            assert_eq!(follower.reasons, leader.reasons);
            for observed in [&leader, &follower] {
                assert!(!observed.complete && !observed.retained && observed.reuse_refused);
                assert_eq!(
                    observed.verdict,
                    ReuseVerdict::ExecutionDependent(
                        brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::Other
                    )
                );
            }
        }
        // Stable evidence remains shareable: verify and replay it exactly once.
        let (leader, follower, calls) = flight_wave(stable, true);
        assert_eq!(calls, 1);
        assert_eq!(follower, leader);
        assert_eq!(leader.reasons, ["ArtifactUnavailable(\"jar\")"]);
        assert!(!leader.complete && leader.retained && !leader.reuse_refused);
        assert_eq!(leader.verdict, ReuseVerdict::Content);
        // No reasons: the producer's flag stands and the answer is retained.
        let (leader, follower, calls) = flight_wave(nothing, true);
        assert_eq!(calls, 1);
        assert_eq!(follower, leader);
        assert!(leader.complete && leader.retained && !leader.reuse_refused);
        assert!(leader.reasons.is_empty());
        // The leader's cancellation says nothing about a live follower, which
        // computes the answer itself.
        let (leader, follower, calls) = flight_wave(cancelled_once, true);
        assert_eq!(calls, 2);
        assert_eq!(leader.reasons, ["Cancelled"]);
        assert_eq!(follower.value, "call 1");
        assert!(follower.complete && follower.reasons.is_empty());
    }
    #[test]
    #[hardwon(
        "#11510: an unsupported-semantic definition stop was Provider, so every unit that consumed one was refused"
    )]
    fn certified_proof_stop_is_retained_and_replayed_cold_equals_warm() {
        use crate::analyzer::read_ledger::DerivationExecutionCause;
        use brokk_bifrost_core::retention_budget::RetentionBudget;
        use brokk_bifrost_semantic::analyzer::semantic::derivation::{
            Demanded, DerivationEngine, Handle,
        };
        const LABEL: &str = "depth_limit";
        // The stop is retained only with no execution cause, and the typed
        // incompleteness is the same on the cold fill and the warm hit.
        for cause in [
            None,
            Some(DerivationExecutionCause::Budget),
            Some(DerivationExecutionCause::Provider),
        ] {
            let analyzer = MultiAnalyzer::default();
            let _host = super::super::HostGuard::enter_test(&analyzer);
            let calls = Arc::new(AtomicUsize::new(0));
            let engine = DerivationEngine::new(
                &RetentionBudget::new(1_000_000),
                Arc::new(AnalyzerCapture::new()),
                Arc::new(NoInputs),
            );
            engine.register(StopKind {
                calls: calls.clone(),
                cause,
                label: Some(LABEL),
            });
            let mut answers = Vec::new();
            for _ in 0..2 {
                let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
                let Demanded::Available {
                    value, complete, ..
                } = engine.demand::<StopKind>(&String::new(), TestBinding, TestBinding)
                else {
                    panic!("stop should return a value")
                };
                assert_eq!(matches!(value, Handle::Retained(_)), cause.is_none());
                answers.push((
                    value.to_string(),
                    complete,
                    scope.captured_read_incompleteness(),
                ));
            }
            assert_eq!(answers[0], answers[1], "cold equals warm for {cause:?}");
            assert!(!answers[0].1, "the answer keeps its incompleteness");
            assert_eq!(
                answers[0].2,
                [QueryReadIncomplete::ProofStopped {
                    reason: LABEL,
                    cause
                }]
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if cause.is_none() { 1 } else { 2 },
                "only the cause-free stop is served from the receipt: {cause:?}"
            );
        }
    }

    #[test]
    #[hardwon("#11510: an older binary must refuse a proof-stop label it does not register")]
    fn a_label_missing_from_the_registry_is_refused_on_replay() {
        // Uncertified UnsupportedSemantic labels are refused, even without
        // an execution cause. The generic machinery only admits registered
        // labels whose producers have actually been certified.
        let label = "depth_limit";
        assert!(
            !crate::analyzer::i_analyzer::DETERMINISTIC_PROOF_STOP_LABELS
                .contains(&"resolution_unsupported_semantic")
        );
        for unknown in [
            "resolution_unsupported_semantic",
            "resolution_unsupported_semantic_next",
            "resolution_not_in_the_registry",
        ] {
            let analyzer: Arc<dyn IAnalyzer> = Arc::new(MultiAnalyzer::default());
            let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
            let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
            let parent = Arc::new(ReadLedger::new());
            let _scope = AnalyzerQueryScope::with_read_ledger(analyzer.as_ref(), parent.clone());
            capture.replay_reasons(&[format!("proof\0{unknown}")]);
            assert!(parent.reuse_refused(), "{unknown} must not be replayed");
        }
        let analyzer: Arc<dyn IAnalyzer> = Arc::new(MultiAnalyzer::default());
        let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
        let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
        let parent = Arc::new(ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(analyzer.as_ref(), parent.clone());
        capture.replay_reasons(&[format!("proof\0{label}")]);
        assert!(!parent.reuse_refused(), "the registered label replays");
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
    #[hardwon("#10984: attributed gaps cannot enter derivation string receipts without provenance")]
    fn attributed_gap_refuses_derivation_capture_and_preserves_leader_completion() {
        use crate::analyzer::ProjectFile;
        use crate::analyzer::i_analyzer::QueryLookupProvenance;

        let analyzer = MultiAnalyzer::default();
        let _host = super::super::HostGuard::enter_test(&analyzer);
        let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
        let outer = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        let gap = QueryReadIncomplete::SemanticEvidenceGap("missing external type".into())
            .attributed(QueryLookupProvenance {
                file: ProjectFile::new(std::env::current_dir().unwrap(), "Lookup.java"),
                byte_span: 12..19,
                name: "Missing".into(),
                tier: "same-package",
            });
        let receipt = capture.capture(&TestBinding, &TestBinding, &mut || {
            analyzer.record_query_incomplete(gap.clone());
        });
        assert_eq!(
            receipt.reuse_refusals,
            [NotReusableCause::InvalidDependencyEvidence]
        );
        assert!(receipt.stable_reasons.is_empty());
        assert_eq!(outer.captured_read_incompleteness(), [gap]);
        let plain = capture.capture(&TestBinding, &TestBinding, &mut || {
            analyzer.record_query_incomplete(QueryReadIncomplete::ArtifactUnavailable(
                "artifact".into(),
            ));
            analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                "partial".into(),
            ));
        });
        assert!(plain.reuse_refusals.is_empty());
        assert_eq!(plain.stable_reasons, ["artifact\0artifact", "gap\0partial"]);
    }

    #[test]
    fn sql_attribution_uses_frame_and_delegated_context() {
        let analyzer: Arc<dyn IAnalyzer> = Arc::new(MultiAnalyzer::default());
        let _host = super::super::HostGuard::enter_test(analyzer.as_ref());
        let capture = AnalyzerCapture::<TestBinding, TestBinding>::new();
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        brokk_bifrost_core::cache_db::sql_profile::install_catalog_session(&conn);
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
