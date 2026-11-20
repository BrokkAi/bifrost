use crate::analyzer::query_batch::LimitedQueryRows;
use crate::analyzer::reuse_verdict::{CarriesReuseVerdict, ExecutionCause, ReuseVerdict};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use std::cell::RefCell;

#[derive(Debug)]
pub enum BoundedResolution<T> {
    Complete {
        value: T,
        work: ReceiverAnalysisWork,
    },
    Exceeded {
        limit: ReceiverBudgetLimit,
        work: ReceiverAnalysisWork,
    },
    Unavailable {
        reason: &'static str,
        work: ReceiverAnalysisWork,
    },
    Cancelled {
        work: ReceiverAnalysisWork,
    },
}

impl<T> BoundedResolution<T> {
    /// Transform only a completed value, retaining work and terminal outcomes.
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> BoundedResolution<U> {
        match self {
            Self::Complete { value, work } => BoundedResolution::Complete {
                value: map(value),
                work,
            },
            Self::Exceeded { limit, work } => BoundedResolution::Exceeded { limit, work },
            Self::Unavailable { reason, work } => BoundedResolution::Unavailable { reason, work },
            Self::Cancelled { work } => BoundedResolution::Cancelled { work },
        }
    }

    pub fn work(&self) -> ReceiverAnalysisWork {
        match self {
            Self::Complete { work, .. }
            | Self::Exceeded { work, .. }
            | Self::Unavailable { work, .. }
            | Self::Cancelled { work } => *work,
        }
    }
}

/// The reasons a session reports through [`ResolutionSession::mark_unavailable`].
/// Each is execution dependent, as the budget stops they replaced were: the
/// incompleteness may come from the files or providers a request happened to
/// see. A reason outside this list is not a session stop.
pub const SESSION_UNAVAILABLE_REASONS: [&str; 5] = [
    "provider_rows_incomplete",
    "csharp_unresolved_ancestry",
    "csharp_unseeded_variable_declarator",
    "php_source_facts_unavailable",
    "ruby_cross_language_lookup",
];

/// An exceeded, cancelled or store-failed resolution is execution dependent;
/// [`ResolutionSession::finish`] marks these. A complete value can
/// still depend on a caller's cancellation, which only the session's own
/// verdict reports.
impl<T> CarriesReuseVerdict for BoundedResolution<T> {
    fn reuse_verdict(&self) -> ReuseVerdict {
        match self {
            Self::Unavailable {
                reason: "native_store_error",
                ..
            } => ReuseVerdict::ExecutionDependent(ExecutionCause::Other),
            Self::Unavailable { reason, .. } if SESSION_UNAVAILABLE_REASONS.contains(reason) => {
                ReuseVerdict::ExecutionDependent(ExecutionCause::Other)
            }
            Self::Complete { .. } | Self::Unavailable { .. } => ReuseVerdict::Content,
            Self::Exceeded { .. } | Self::Cancelled { .. } => {
                ReuseVerdict::ExecutionDependent(ExecutionCause::Other)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ResolutionStop {
    Exceeded(ReceiverBudgetLimit),
    Cancelled,
    StoreFailure,
    /// The session cannot prove its answer. This is a terminal fact about the
    /// input, not a work refusal.
    Unavailable(&'static str),
}

#[derive(Debug, Clone, Copy, Default)]
struct ResolutionState {
    work: ReceiverAnalysisWork,
    stop: Option<ResolutionStop>,
    /// Joined at every ambient mark this session makes.
    reuse: ReuseVerdict,
}

impl ResolutionState {
    fn for_request(work: ReceiverAnalysisWork) -> Self {
        let mut state = Self {
            work,
            ..Self::default()
        };
        if crate::analyzer::carried_context::request_store_failed() {
            state.stop = Some(ResolutionStop::StoreFailure);
            state.join_execution_dependence();
        }
        state
    }

    /// Mark the ambient capture and keep the same verdict for the caller.
    #[track_caller]
    fn join_execution_dependence(&mut self) {
        crate::analyzer::carried_context::mark_execution_dependent();
        self.reuse
            .join_in(ReuseVerdict::ExecutionDependent(ExecutionCause::Other));
    }
}

/// One selected owner frontier in a request's expansion budget. The number
/// is an operation-local alias, never canonical content or a persisted key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionOwnerFrontier(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallCancelled;

impl CarriesReuseVerdict for CallCancelled {
    fn reuse_verdict(&self) -> ReuseVerdict {
        ReuseVerdict::ExecutionDependent(ExecutionCause::Other)
    }
}

impl ResolutionOwnerFrontier {
    pub const fn new(operation_alias: u64) -> Self {
        Self(operation_alias)
    }
}

/// Work and cancellation state shared by one bounded exact-resolution request.
///
/// An unbounded session preserves the ordinary lookup APIs without charging.
/// A bounded session records every resolver-owned syntax/candidate step and
/// hierarchy expansion. Once stopped, all subsequent helpers become no-ops and
/// [`Self::finish`] returns the terminal condition instead of any partial value.
pub struct ResolutionSession {
    budget: Option<ReceiverAnalysisBudget>,
    total_work_limit: Option<usize>,
    cancellation: Option<CancellationToken>,
    call_cancellation: RefCell<Vec<CancellationToken>>,
    state: RefCell<ResolutionState>,
    expanded_owners: RefCell<HashSet<ResolutionOwnerFrontier>>,
}

impl ResolutionSession {
    /// Observe a caller's cancellation only for the duration of this work.
    pub fn with_call_cancellation<R>(
        &self,
        call: &CancellationToken,
        work: impl FnOnce() -> R,
    ) -> Result<R, CallCancelled> {
        struct Restore<'a>(&'a RefCell<Vec<CancellationToken>>);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.0.borrow_mut().pop().expect("call cancellation scope");
            }
        }
        self.call_cancellation.borrow_mut().push(call.clone());
        let restore = Restore(&self.call_cancellation);
        let result = work();
        // Observe all active callers while the scope still holds their tokens.
        let cancelled = self
            .call_cancellation
            .borrow()
            .iter()
            .fold(false, |cancelled, token| cancelled | token.is_cancelled());
        if cancelled {
            self.join_execution_dependence();
        }
        drop(restore);
        if cancelled {
            Err(CallCancelled)
        } else {
            Ok(result)
        }
    }

    pub fn unbounded() -> Self {
        Self {
            budget: None,
            total_work_limit: None,
            cancellation: None,
            call_cancellation: RefCell::new(Vec::new()),
            state: RefCell::new(ResolutionState::for_request(ReceiverAnalysisWork::default())),
            expanded_owners: RefCell::default(),
        }
    }

    pub fn bounded(
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        Self {
            budget: Some(budget),
            total_work_limit: None,
            cancellation: Some(
                cancellation.map_or_else(CancellationToken::new, |token| token.child()),
            ),
            call_cancellation: RefCell::new(Vec::new()),
            state: RefCell::new(ResolutionState::for_request(ReceiverAnalysisWork::default())),
            expanded_owners: RefCell::default(),
        }
    }

    /// Start a bounded request with an additional cap shared by all work axes.
    pub fn bounded_with_total_work(
        budget: ReceiverAnalysisBudget,
        total_work_limit: usize,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        Self {
            budget: Some(budget),
            total_work_limit: Some(total_work_limit),
            cancellation: Some(
                cancellation.map_or_else(CancellationToken::new, |token| token.child()),
            ),
            call_cancellation: RefCell::new(Vec::new()),
            state: RefCell::new(ResolutionState::for_request(ReceiverAnalysisWork::default())),
            expanded_owners: RefCell::default(),
        }
    }

    /// Start an independent bounded request after work shared by its batch.
    ///
    /// The shared work counts against this request's own budget, but its stop
    /// state and cancellation token do not. One locator can therefore exhaust
    /// its remaining allowance without cancelling its siblings.
    pub fn bounded_after_shared_work(
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
        shared_work: ReceiverAnalysisWork,
    ) -> Self {
        assert!(shared_work.summary_expansions <= budget.max_summary_expansions);
        assert!(shared_work.resolution_rounds <= budget.max_resolution_rounds);
        assert!(shared_work.hierarchy_order_steps <= budget.max_hierarchy_order_work);
        Self {
            budget: Some(budget),
            total_work_limit: None,
            cancellation: Some(
                cancellation.map_or_else(CancellationToken::new, |token| token.child()),
            ),
            call_cancellation: RefCell::new(Vec::new()),
            state: RefCell::new(ResolutionState::for_request(shared_work)),
            expanded_owners: RefCell::default(),
        }
    }

    /// Run one resolution against a bounded session and return its terminal outcome.
    pub fn run_bounded<T>(
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
        resolve: impl FnOnce(&Self) -> T,
    ) -> BoundedResolution<T> {
        let session = Self::bounded(budget, cancellation);
        let value = resolve(&session);
        session.finish(value)
    }

    /// Run a query through `session` when present, otherwise run it unbounded.
    pub fn query_with_optional_session<T>(
        session: Option<&Self>,
        query: impl FnOnce() -> T,
    ) -> Option<T> {
        match session {
            Some(session) => session.query(query),
            None => Some(query()),
        }
    }

    /// Run a limited row query when `session` is present, with an unbounded fallback.
    pub fn query_limited_rows_with_optional_session<T>(
        session: Option<&Self>,
        limited_query: impl FnOnce(usize) -> LimitedQueryRows<T>,
        unbounded_query: impl FnOnce() -> Vec<T>,
    ) -> Vec<T> {
        match session {
            Some(session) => session.query_limited_rows(limited_query),
            None => unbounded_query(),
        }
    }

    /// Charge one scope step when a session is present; absent sessions are unbounded.
    pub fn scope_step_with_optional_session(session: Option<&Self>) -> bool {
        session.is_none_or(Self::scope_step)
    }

    /// The terminal status together with the value built before it. A caller
    /// that can state its partial result as incomplete keeps the finished work
    /// instead of discarding it as [`Self::finish`] does.
    pub fn finish_keeping<T>(&self, value: T) -> (BoundedResolution<()>, T) {
        (self.finish(()), value)
    }

    pub fn finish<T>(&self, value: T) -> BoundedResolution<T> {
        self.observe_store_failure();
        self.observe_cancellation();
        let state = {
            let mut state = self.state.borrow_mut();
            if state.stop.is_some() {
                state.join_execution_dependence();
            }
            *state
        };
        match state.stop {
            Some(ResolutionStop::Exceeded(limit)) => BoundedResolution::Exceeded {
                limit,
                work: state.work,
            },
            Some(ResolutionStop::Cancelled) => BoundedResolution::Cancelled { work: state.work },
            Some(ResolutionStop::StoreFailure) => BoundedResolution::Unavailable {
                reason: "native_store_error",
                work: state.work,
            },
            Some(ResolutionStop::Unavailable(reason)) => BoundedResolution::Unavailable {
                reason,
                work: state.work,
            },
            None => BoundedResolution::Complete {
                value,
                work: state.work,
            },
        }
    }

    /// Independent cap for optional hierarchy ordering, never an aggregate stop.
    pub fn hierarchy_order_limit(&self) -> usize {
        self.budget.map_or(
            super::receiver_analysis::DEFAULT_RECEIVER_MAX_HIERARCHY_ORDER_STEPS,
            |budget| budget.max_hierarchy_order_steps,
        )
    }

    /// Count one scope step. Visiting syntax and rows is work and never
    /// refuses (#13216): only cancellation, a deadline or the opt-in aggregate
    /// work cap stops a session.
    pub fn scope_step(&self) -> bool {
        match self.admit() {
            Admission::Settled(admitted) => admitted,
            Admission::Open(mut state, _) => {
                state.work.scope_nodes += 1;
                true
            }
        }
    }

    pub fn hierarchy_order_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::HierarchyOrderSteps)
    }

    pub fn hierarchy_order_steps(&self, count: usize) -> bool {
        if self.budget.is_none()
            && self.cancellation.is_none()
            && self.call_cancellation.borrow().is_empty()
        {
            return true;
        }
        (0..count).all(|_| self.hierarchy_order_step())
    }

    /// Charge copied scope operands without walking a no-op unbounded session.
    /// Bounded sessions retain exactly the per-step cancellation cadence.
    pub fn scope_steps(&self, count: usize) -> bool {
        if self.budget.is_none()
            && self.cancellation.is_none()
            && self.call_cancellation.borrow().is_empty()
        {
            return true;
        }
        (0..count).all(|_| self.scope_step())
    }

    /// Replay finished nested work into this session, stopping at the first refusal.
    pub fn charge_work(&self, work: &ReceiverAnalysisWork) -> bool {
        // A replay into a session that is already cancelled or stopped is
        // refused, even with no work to charge; the first stop stays latched
        // and this check charges no budget.
        if !self.observe_cancellation() {
            return false;
        }
        if self.budget.is_none()
            && self.cancellation.is_none()
            && self.call_cancellation.borrow().is_empty()
        {
            return true;
        }
        let ReceiverAnalysisWork {
            // Setup work is tracked before a resolution session begins.
            setup_nodes: _,
            scope_nodes,
            summary_expansions,
            resolution_rounds,
            hierarchy_order_steps,
        } = *work;
        self.scope_steps(scope_nodes)
            && (0..summary_expansions).all(|_| self.summary_step())
            && (0..resolution_rounds).all(|_| self.round_step())
            && self.hierarchy_order_steps(hierarchy_order_steps)
    }

    pub fn summary_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::SummaryExpansions)
    }

    /// Expand one selected owner frontier once in this request. The identity
    /// comes from the caller's selected source, never from a spelling. This
    /// set dies with the session and cannot exceed its summary allowance.
    pub fn summary_expansion(&self, owner: ResolutionOwnerFrontier) -> bool {
        if self.budget.is_none() {
            return self.observe_cancellation();
        }
        if !self.observe_cancellation() {
            return false;
        }
        let mut expanded = self.expanded_owners.borrow_mut();
        if expanded.contains(&owner) {
            return true;
        }
        if !self.summary_step() {
            return false;
        }
        expanded.insert(owner);
        true
    }

    /// Solver convergence and lexical worklist rounds are iteration work,
    /// not owner expansions, and have their own independent allowance.
    pub fn round_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::ResolutionRounds)
    }

    pub fn query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        self.observe_store_failure();
        if !self.scope_step() {
            return None;
        }
        let value = query();
        self.observe_store_failure();
        self.observe_cancellation().then_some(value)
    }

    pub fn summary_query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        self.observe_store_failure();
        if !self.summary_step() {
            return None;
        }
        let value = query();
        self.observe_store_failure();
        self.observe_cancellation().then_some(value)
    }

    pub fn query_optional<T>(&self, query: impl FnOnce() -> Option<T>) -> Option<T> {
        let value = self.query(query)??;
        self.scope_step().then_some(value)
    }

    pub fn query_rows<T>(&self, query: impl FnOnce() -> Vec<T>) -> Vec<T> {
        let Some(rows) = self.query(query) else {
            return Vec::new();
        };
        self.track_rows(rows)
    }

    /// Runs a provider query and counts the rows it inspects as scope steps.
    ///
    /// The lookahead limit is unlimited unless an explicit total-work cap is
    /// set; scope steps themselves never refuse. An incomplete batch is the
    /// provider's own incompleteness (omitted files, an unreadable blob): the
    /// session stops as `Unavailable("provider_rows_incomplete")`, which is
    /// execution dependent. Provider-reported source rows are counted even when
    /// liveness filtering produces fewer `rows`; live-path expansion is
    /// counted via `rows.len()`.
    pub fn query_limited_rows<T>(
        &self,
        query: impl FnOnce(usize) -> LimitedQueryRows<T>,
    ) -> Vec<T> {
        self.observe_store_failure();
        if !self.scope_step() {
            return Vec::new();
        }
        let limit = self.scope_lookahead_limit();
        let batch = query(limit);
        self.observe_store_failure();
        if !self.observe_cancellation() {
            return Vec::new();
        }
        let charged_rows = batch.inspected.max(batch.rows.len());
        for _ in 0..charged_rows {
            if !self.scope_step() {
                return Vec::new();
            }
        }
        if !batch.complete {
            // The lookahead is `usize::MAX` unless an opt-in total-work cap
            // limits it, and a capped lookahead reaches the provider's limit
            // only after the charge loop above has already stopped on
            // `TotalWork`. An incomplete batch that survives the loop is
            // therefore the provider's own incompleteness (omitted workspace
            // files, an unreadable blob), which is not a budget stop.
            self.mark_unavailable("provider_rows_incomplete");
            return Vec::new();
        }
        batch.rows
    }

    pub fn summary_rows<T>(&self, query: impl FnOnce() -> Vec<T>) -> Vec<T> {
        let Some(rows) = self.summary_query(query) else {
            return Vec::new();
        };
        self.track_rows(rows)
    }

    pub fn track_rows<T>(&self, rows: Vec<T>) -> Vec<T> {
        if self.budget.is_none()
            && self.cancellation.is_none()
            && self.call_cancellation.borrow().is_empty()
        {
            return if matches!(self.state.borrow().stop, Some(ResolutionStop::StoreFailure)) {
                Vec::new()
            } else {
                rows
            };
        }
        for _ in &rows {
            if !self.scope_step() {
                return Vec::new();
            }
        }
        rows
    }

    pub fn observe_cancellation(&self) -> bool {
        if self.budget.is_none()
            && self.cancellation.is_none()
            && self.call_cancellation.borrow().is_empty()
        {
            return !matches!(self.state.borrow().stop, Some(ResolutionStop::StoreFailure));
        }
        let mut state = self.state.borrow_mut();
        if state.stop.is_none()
            && self
                .cancellation
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
        {
            state.stop = Some(ResolutionStop::Cancelled);
        }
        if state.stop.is_some() {
            state.join_execution_dependence();
        }
        let call_cancelled = self
            .call_cancellation
            .borrow()
            .iter()
            .any(CancellationToken::is_cancelled);
        if call_cancelled {
            state.join_execution_dependence();
        }
        state.stop.is_none() && !call_cancelled
    }

    /// Whether a budget stop or cancellation has already ended this session.
    /// Unlike [`Self::observe_cancellation`], this neither observes the token
    /// nor marks the capture.
    pub fn is_stopped(&self) -> bool {
        self.state.borrow().stop.is_some()
    }

    pub fn cancellation(&self) -> Option<&CancellationToken> {
        self.cancellation.as_ref()
    }

    #[track_caller]
    fn join_execution_dependence(&self) {
        self.state.borrow_mut().join_execution_dependence();
    }

    /// The exact remaining allowance for a demand answer memo. A stopped
    /// session still has to pass observe_cancellation before using this value.
    pub fn remaining_budget(&self) -> Option<ReceiverAnalysisBudget> {
        self.budget.map(|budget| {
            let state = self.state.borrow();
            let mut budget = budget.remaining_after(&state.work);
            if let Some(total_work_limit) = self.total_work_limit {
                let remaining_total = total_work_limit.saturating_sub(total_work(&state.work));
                budget.max_hierarchy_order_work =
                    budget.max_hierarchy_order_work.min(remaining_total);
                budget.max_summary_expansions = budget.max_summary_expansions.min(remaining_total);
                budget.max_resolution_rounds = budget.max_resolution_rounds.min(remaining_total);
            }
            budget
        })
    }

    /// The budget fields that define a question, as opposed to its work
    /// allowances: receiver context depth and the target cap. They are constant
    /// for a session, so a memo key may bind them.
    pub fn question_parameters(&self) -> Option<(usize, usize)> {
        self.budget
            .map(|budget| (budget.context_depth, budget.max_targets))
    }

    /// Preserve a nested resolver's terminal budget reason in this request.
    pub fn mark_exceeded(&self, limit: ReceiverBudgetLimit) {
        self.stop(ResolutionStop::Exceeded(limit));
    }

    /// A provider failed during this session; later reads cannot recover it.
    pub fn mark_store_failure(&self) {
        self.stop(ResolutionStop::StoreFailure);
    }

    fn observe_store_failure(&self) {
        if crate::analyzer::carried_context::request_store_failed() {
            self.mark_store_failure();
        }
    }

    /// The row limit handed to a provider query: unlimited, except that an
    /// explicit total-work cap bounds it to the remaining work plus one row.
    /// Scope steps have no allowance of their own.
    pub fn scope_lookahead_limit(&self) -> usize {
        self.remaining_scope_steps().saturating_add(1)
    }

    /// Stop the session because it cannot prove its answer. The incompleteness
    /// is reported as `BoundedResolution::Unavailable` with `reason`.
    pub fn mark_unavailable(&self, reason: &'static str) {
        assert!(
            SESSION_UNAVAILABLE_REASONS.contains(&reason),
            "unregistered session stop reason {reason}"
        );
        self.stop(ResolutionStop::Unavailable(reason));
    }

    fn remaining_scope_steps(&self) -> usize {
        let state = self.state.borrow();
        if state.stop.is_some() {
            return 0;
        }
        self.total_work_limit.map_or(usize::MAX, |limit| {
            limit.saturating_sub(total_work(&state.work))
        })
    }

    fn stop(&self, stop: ResolutionStop) {
        let mut state = self.state.borrow_mut();
        state.join_execution_dependence();
        if state.stop.is_none() {
            state.stop = Some(stop);
            drop(state);
            if matches!(
                stop,
                ResolutionStop::Exceeded(_) | ResolutionStop::Unavailable(_)
            ) && let Some(cancellation) = self.cancellation.as_ref()
            {
                cancellation.cancel();
            }
        }
    }

    /// The checks every step shares: store failure, cancellation and the opt-in
    /// aggregate work cap. `Open` hands back the session state for the caller
    /// to add its own work to.
    fn admit(&self) -> Admission<'_> {
        if self.budget.is_none()
            && self.cancellation.is_none()
            && self.call_cancellation.borrow().is_empty()
        {
            return Admission::Settled(!matches!(
                self.state.borrow().stop,
                Some(ResolutionStop::StoreFailure)
            ));
        }
        if !self.observe_cancellation() {
            return Admission::Settled(false);
        }
        let Some(budget) = self.budget else {
            return Admission::Settled(true);
        };
        let mut state = self.state.borrow_mut();
        if let Some(Err(refused)) = self.total_work_limit.map(|maximum| {
            crate::analyzer::work_budget::LimitedCounter::from_usage(
                total_work(&state.work),
                maximum,
            )
            .try_allow(1)
        }) {
            state.reuse.join_in(refused.reuse_verdict());
            state.stop = Some(ResolutionStop::Exceeded(ReceiverBudgetLimit::TotalWork));
            drop(state);
            self.cancellation
                .as_ref()
                .expect("a bounded session has an operation cancellation token")
                .cancel();
            return Admission::Settled(false);
        }
        Admission::Open(state, budget)
    }

    fn charge(&self, limit: ReceiverBudgetLimit) -> bool {
        let (mut state, budget) = match self.admit() {
            Admission::Settled(admitted) => return admitted,
            Admission::Open(state, budget) => (state, budget),
        };
        let (used, maximum) = match limit {
            ReceiverBudgetLimit::SummaryExpansions => (
                &mut state.work.summary_expansions,
                budget.max_summary_expansions,
            ),
            ReceiverBudgetLimit::ResolutionRounds => (
                &mut state.work.resolution_rounds,
                budget.max_resolution_rounds,
            ),
            ReceiverBudgetLimit::HierarchyOrderSteps => (
                &mut state.work.hierarchy_order_steps,
                budget.max_hierarchy_order_work,
            ),
            ReceiverBudgetLimit::TotalWork => unreachable!("aggregate work is checked above"),
            ReceiverBudgetLimit::ResidentRows => {
                unreachable!("residency is admitted by the semantic budget")
            }
        };
        if let Err(refused) =
            crate::analyzer::work_budget::LimitedCounter::from_usage(*used, maximum).try_allow(1)
        {
            state.reuse.join_in(refused.reuse_verdict());
            state.stop = Some(ResolutionStop::Exceeded(limit));
            drop(state);
            self.cancellation
                .as_ref()
                .expect("a bounded session has an operation cancellation token")
                .cancel();
            false
        } else {
            *used += 1;
            true
        }
    }
}

enum Admission<'a> {
    /// The step is already decided.
    Settled(bool),
    Open(
        std::cell::RefMut<'a, ResolutionState>,
        ReceiverAnalysisBudget,
    ),
}

/// Every execution dependence this session has marked so far: its stops,
/// refused limits and observed caller cancellations. A caller joins it into
/// the answer it builds from the session's lookups.
impl CarriesReuseVerdict for ResolutionSession {
    fn reuse_verdict(&self) -> ReuseVerdict {
        self.state.borrow().reuse
    }
}

fn total_work(work: &ReceiverAnalysisWork) -> usize {
    work.charged_total()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#11775: a workspace-status store failure allowed a repeated lookup to recover in the same request"
    )]
    fn store_failure_stops_provider_retries_and_unbounded_sessions() {
        use crate::analyzer::carried_context::{
            RequestCompletion, push_request_state_with_completion,
        };
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Completion(AtomicBool);
        impl RequestCompletion for Completion {
            fn store_failed(&self) -> bool {
                self.0.load(Ordering::Relaxed)
            }
        }
        let owner = Arc::new(Completion(AtomicBool::new(false)));
        let _request = push_request_state_with_completion(Some(owner.clone()));
        let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        assert!(
            session
                .query(|| {
                    owner.0.store(true, Ordering::Relaxed);
                    1
                })
                .is_none()
        );
        assert!(
            session
                .query(|| panic!("failed request retried its provider"))
                .is_none()
        );
        let result = session.finish(());
        assert!(matches!(
            result,
            BoundedResolution::Unavailable {
                reason: "native_store_error",
                ..
            }
        ));
        assert_eq!(
            result.reuse_verdict(),
            ReuseVerdict::ExecutionDependent(ExecutionCause::Other)
        );
        let repeated = ResolutionSession::unbounded();
        assert!(
            repeated
                .query(|| panic!("new session ignored the failed request"))
                .is_none()
        );
        assert!(matches!(
            repeated.finish(()),
            BoundedResolution::Unavailable {
                reason: "native_store_error",
                ..
            }
        ));
        let _fresh =
            push_request_state_with_completion(Some(Arc::new(Completion(AtomicBool::new(false)))));
        let fresh = ResolutionSession::unbounded();
        assert_eq!(fresh.query(|| 7), Some(7));
        assert!(matches!(
            fresh.finish(()),
            BoundedResolution::Complete { value: (), .. }
        ));
        fresh.mark_store_failure();
        assert!(
            fresh
                .query(|| panic!("explicit store stop was ignored without a budget"))
                .is_none()
        );
    }

    #[test]
    fn call_cancellation_does_not_latch_operation_stop() {
        let operation = CancellationToken::new();
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&operation));
        let caller = CancellationToken::new();
        assert_eq!(
            session.with_call_cancellation(&caller, || {
                assert!(session.scope_step());
                caller.cancel();
                assert!(!session.scope_step());
                assert!(!session.charge_work(&ReceiverAnalysisWork::default()));
                "apparently complete"
            }),
            Err(CallCancelled)
        );
        let late = CancellationToken::new();
        assert_eq!(
            session.with_call_cancellation(&late, || {
                late.cancel();
                "apparently complete"
            }),
            Err(CallCancelled)
        );
        let fresh = CancellationToken::new();
        assert_eq!(
            session.with_call_cancellation(&fresh, || {
                assert!(session.scope_step());
                "complete"
            }),
            Ok("complete")
        );
        assert!(
            matches!(session.finish(()), BoundedResolution::Complete { work, .. } if work.scope_nodes == 2)
        );

        operation.cancel();
        assert_eq!(
            session.with_call_cancellation(&fresh, || assert!(!session.scope_step())),
            Ok(())
        );
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
    }

    #[test]
    fn outer_call_cancellation_stops_nested_work_and_restores_scope() {
        let operation = CancellationToken::new();
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&operation));
        let outer = CancellationToken::new();
        let inner = CancellationToken::new();
        assert_eq!(
            session.with_call_cancellation(&outer, || {
                assert!(session.scope_step());
                assert_eq!(
                    session.with_call_cancellation(&inner, || {
                        assert!(session.scope_step());
                        outer.cancel();
                        assert!(!session.scope_step());
                        assert!(!session.observe_cancellation());
                    }),
                    Err(CallCancelled)
                );
                assert!(!session.scope_step());
            }),
            Err(CallCancelled)
        );
        assert_eq!(
            session.with_call_cancellation(&inner, || assert!(session.scope_step())),
            Ok(())
        );
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Complete { work, .. } if work.scope_nodes == 3
        ));
    }

    #[test]
    #[hardwon("#5658: a zero-work replay into a cancelled or stopped session was admitted")]
    fn charge_work_refuses_a_cancelled_or_stopped_session_even_with_no_work() {
        let none = ReceiverAnalysisWork::default();

        let fresh = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
        assert!(fresh.charge_work(&none));
        assert!(matches!(
            fresh.finish(()),
            BoundedResolution::Complete { work, .. } if work == none
        ));

        let caller = CancellationToken::new();
        let cancelled =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&caller));
        caller.cancel();
        assert!(!cancelled.charge_work(&none));
        assert!(matches!(
            cancelled.finish(()),
            BoundedResolution::Cancelled { .. }
        ));

        let token = CancellationToken::new();
        let token_only = ResolutionSession {
            cancellation: Some(token.clone()),
            ..ResolutionSession::unbounded()
        };
        assert!(token_only.charge_work(&none));
        token.cancel();
        assert!(!token_only.charge_work(&none));

        let stopped =
            ResolutionSession::bounded_with_total_work(ReceiverAnalysisBudget::default(), 1, None);
        assert!(stopped.scope_step());
        assert!(!stopped.scope_step());
        assert!(!stopped.charge_work(&none));
        assert!(matches!(
            stopped.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::TotalWork,
                ..
            }
        ));
    }

    #[test]
    fn charge_work_replays_hierarchy_and_stops_at_allowance() {
        let unbounded = ResolutionSession::unbounded();
        assert!(unbounded.charge_work(&ReceiverAnalysisWork {
            summary_expansions: usize::MAX,
            resolution_rounds: usize::MAX,
            ..ReceiverAnalysisWork::default()
        }));
        assert_eq!(unbounded.finish(()).work(), ReceiverAnalysisWork::default());

        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_hierarchy_order_work: 2,
                ..ReceiverAnalysisBudget::default()
            },
            None,
        );
        let work = ReceiverAnalysisWork {
            hierarchy_order_steps: 3,
            ..ReceiverAnalysisWork::default()
        };
        assert!(!session.charge_work(&work));
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::HierarchyOrderSteps,
                work: ReceiverAnalysisWork {
                    hierarchy_order_steps: 2,
                    ..
                },
            }
        ));
    }

    #[test]
    fn hierarchy_and_scope_exhaust_independently_and_count_toward_total() {
        let unbounded = ResolutionSession::unbounded();
        assert!(unbounded.hierarchy_order_step());
        assert!(unbounded.hierarchy_order_steps(2));
        assert_eq!(unbounded.finish(()).work(), ReceiverAnalysisWork::default());
        let budget = ReceiverAnalysisBudget {
            max_hierarchy_order_work: 1,
            ..ReceiverAnalysisBudget::default()
        };
        let hierarchy = ResolutionSession::bounded(budget, None);
        assert!(hierarchy.hierarchy_order_step());
        assert!(!hierarchy.hierarchy_order_step());
        assert!(matches!(
            hierarchy.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::HierarchyOrderSteps,
                ..
            }
        ));
        // Scope steps are telemetry: they count and never refuse (#13216).
        let scope = ResolutionSession::bounded(budget, None);
        for _ in 0..100 {
            assert!(scope.scope_step());
        }
        assert!(scope.scope_steps(1_000));
        assert!(matches!(
            scope.finish(()),
            BoundedResolution::Complete {
                work: ReceiverAnalysisWork {
                    scope_nodes: 1_100,
                    ..
                },
                ..
            }
        ));
        let total = ResolutionSession::bounded_with_total_work(budget, 2, None);
        assert!(total.hierarchy_order_step());
        assert!(total.scope_step());
        assert!(!total.summary_step());
        assert!(matches!(
            total.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::TotalWork,
                work: ReceiverAnalysisWork {
                    hierarchy_order_steps: 1,
                    scope_nodes: 1,
                    ..
                }
            }
        ));
    }

    #[test]
    fn distinct_owners_and_resolution_rounds_have_independent_limits() {
        let caller = CancellationToken::new();
        let budget = ReceiverAnalysisBudget {
            max_summary_expansions: 1,
            max_resolution_rounds: 2,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, Some(&caller));
        assert!(session.summary_expansion(ResolutionOwnerFrontier::new(1)));
        assert!(session.round_step());
        assert!(session.summary_expansion(ResolutionOwnerFrontier::new(1)));
        assert!(session.round_step());
        assert!(!session.round_step());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ResolutionRounds,
                work: ReceiverAnalysisWork {
                    summary_expansions: 1,
                    resolution_rounds: 2,
                    ..
                },
            }
        ));
        assert_eq!(
            ReceiverBudgetLimit::ResolutionRounds.as_str(),
            "resolution_rounds"
        );
        assert!(!caller.is_cancelled());

        let sibling = ResolutionSession::bounded(budget, Some(&caller));
        assert!(sibling.summary_expansion(ResolutionOwnerFrontier::new(1)));
        assert!(!sibling.summary_expansion(ResolutionOwnerFrontier::new(2)));
        assert!(matches!(
            sibling.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::SummaryExpansions,
                work: ReceiverAnalysisWork {
                    summary_expansions: 1,
                    resolution_rounds: 0,
                    ..
                },
            }
        ));
        assert!(!caller.is_cancelled());
    }

    #[test]
    fn every_session_unavailable_stop_is_execution_dependent() {
        for reason in SESSION_UNAVAILABLE_REASONS {
            let session = ResolutionSession::unbounded();
            session.mark_unavailable(reason);
            let result = session.finish(());
            assert!(matches!(
                result,
                BoundedResolution::Unavailable { reason: seen, .. } if seen == reason
            ));
            assert_eq!(
                result.reuse_verdict(),
                ReuseVerdict::ExecutionDependent(ExecutionCause::Other),
                "{reason}"
            );
        }
    }

    #[test]
    fn budget_stop_cancels_only_the_operation_token() {
        let caller = CancellationToken::new();
        let session = ResolutionSession::bounded_with_total_work(
            ReceiverAnalysisBudget::default(),
            0,
            Some(&caller),
        );

        assert!(!session.scope_step());
        assert!(
            session
                .cancellation()
                .expect("bounded session token")
                .is_cancelled()
        );
        assert!(!caller.is_cancelled());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::TotalWork,
                work: ReceiverAnalysisWork { scope_nodes: 0, .. }
            }
        ));
    }

    #[test]
    fn shared_work_counts_against_independent_locator_budgets() {
        let caller = CancellationToken::new();
        let budget = ReceiverAnalysisBudget {
            max_summary_expansions: 2,
            ..ReceiverAnalysisBudget::default()
        };
        let setup = ResolutionSession::bounded(budget, Some(&caller));
        assert!(setup.summary_step());
        let shared_work = setup.finish(()).work();

        let exhausted =
            ResolutionSession::bounded_after_shared_work(budget, Some(&caller), shared_work);
        assert!(exhausted.summary_step());
        assert!(!exhausted.summary_step());
        assert!(matches!(
            exhausted.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::SummaryExpansions,
                work: ReceiverAnalysisWork {
                    summary_expansions: 2,
                    ..
                }
            }
        ));

        let sibling =
            ResolutionSession::bounded_after_shared_work(budget, Some(&caller), shared_work);
        assert!(sibling.summary_step());
        assert!(!sibling.cancellation().unwrap().is_cancelled());
        assert!(!caller.is_cancelled());
    }

    #[test]
    #[hardwon("#5511: repeated modeled bases could exceed every independently bounded work axis")]
    fn aggregate_work_cap_bounds_mixed_axes_and_provider_rows() {
        let caller = CancellationToken::new();
        let budget = ReceiverAnalysisBudget {
            max_summary_expansions: 8,
            max_resolution_rounds: 8,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded_with_total_work(budget, 3, Some(&caller));
        assert!(session.scope_step());
        assert!(session.summary_step());
        assert!(session.round_step());
        assert_eq!(
            session.finish(()).work(),
            ReceiverAnalysisWork {
                setup_nodes: 0,
                scope_nodes: 1,
                summary_expansions: 1,
                resolution_rounds: 1,
                hierarchy_order_steps: 0,
            }
        );
        assert!(!session.scope_step());
        assert!(!session.summary_step());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::TotalWork,
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    scope_nodes: 1,
                    summary_expansions: 1,
                    resolution_rounds: 1,
                    hierarchy_order_steps: 0,
                }
            }
        ));
        assert!(!caller.is_cancelled());

        let projected = ResolutionSession::bounded_with_total_work(budget, 5, None);
        assert!(projected.round_step());
        assert_eq!(
            projected.remaining_budget().unwrap().max_resolution_rounds,
            4,
            "opted-in projections subtract rounds already spent"
        );

        let row_session = ResolutionSession::bounded_with_total_work(budget, 2, None);
        assert!(row_session.summary_step());
        let rows = row_session.query_limited_rows(|limit| {
            assert_eq!(limit, 1, "one aggregate lookahead row is allowed");
            LimitedQueryRows::incomplete(Vec::<()>::new(), 1)
        });
        assert!(rows.is_empty());
        assert!(matches!(
            row_session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::TotalWork,
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    scope_nodes: 1,
                    summary_expansions: 1,
                    resolution_rounds: 0,
                    hierarchy_order_steps: 0,
                }
            }
        ));

        let legacy = ResolutionSession::bounded(budget, None);
        assert!(legacy.round_step());
        assert_eq!(
            legacy.remaining_budget().unwrap().max_resolution_rounds,
            budget.max_resolution_rounds - 1,
            "every projected axis subtracts work already spent"
        );
        assert_eq!(ReceiverBudgetLimit::TotalWork.as_str(), "total_work");

        let tight_axis = ResolutionSession::bounded_with_total_work(
            ReceiverAnalysisBudget {
                max_summary_expansions: 1,
                ..budget
            },
            9,
            None,
        );
        assert!(tight_axis.summary_step());
        assert!(!tight_axis.summary_step());
        assert!(matches!(
            tight_axis.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::SummaryExpansions,
                ..
            }
        ));

        let cancelled_caller = CancellationToken::new();
        let cancelled =
            ResolutionSession::bounded_with_total_work(budget, 9, Some(&cancelled_caller));
        cancelled_caller.cancel();
        assert!(!cancelled.scope_step());
        assert!(matches!(
            cancelled.finish(()),
            BoundedResolution::Cancelled {
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    scope_nodes: 0,
                    summary_expansions: 0,
                    resolution_rounds: 0,
                    hierarchy_order_steps: 0,
                }
            }
        ));

        let zero = ResolutionSession::bounded_with_total_work(budget, 0, None);
        let mut queried = false;
        let rows = zero.query_limited_rows(|_| {
            queried = true;
            LimitedQueryRows::complete(Vec::<()>::new(), 0)
        });
        assert!(rows.is_empty());
        assert!(
            !queried,
            "zero aggregate allowance must stop before provider work"
        );
        assert!(matches!(
            zero.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::TotalWork,
                work: ReceiverAnalysisWork {
                    setup_nodes: 0,
                    scope_nodes: 0,
                    summary_expansions: 0,
                    resolution_rounds: 0,
                    hierarchy_order_steps: 0,
                }
            }
        ));
    }

    /// Counts the ambient marks that reach one capture, as a read ledger does.
    #[derive(Default)]
    struct CountingCapture {
        execution: std::sync::atomic::AtomicUsize,
        budget: std::sync::atomic::AtomicUsize,
    }

    impl crate::analyzer::carried_context::ExecutionAttribution for CountingCapture {
        fn mark_execution_dependent(&self) {
            self.execution
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        fn mark_budget_refusal(&self) {
            self.mark_execution_dependent();
            self.budget
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// The verdict a value returns while its ambient marks still decide must
    /// be exactly the verdict those marks imply, or removing the marks would
    /// change which answers are kept.
    fn assert_verdict_matches_ambient(
        case: &str,
        produce: impl FnOnce() -> crate::analyzer::reuse_verdict::ReuseVerdict,
    ) {
        let capture = std::sync::Arc::new(CountingCapture::default());
        let guard = crate::analyzer::carried_context::push_with_execution_attribution(
            std::sync::Arc::clone(&capture),
        );
        let explicit = produce();
        drop(guard);
        let ambient = crate::analyzer::reuse_verdict::ReuseVerdict::from_counts(
            capture.execution.load(std::sync::atomic::Ordering::Relaxed),
            capture.budget.load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(explicit, ambient, "{case}");
    }

    #[test]
    fn core_refusal_verdicts_equal_their_ambient_marks() {
        use crate::analyzer::usages::receiver_analysis::{
            ReceiverAnalysisBudgetTracker, ReceiverAnalysisOutcome, ReceiverAnalysisReport,
        };
        use crate::analyzer::work_budget::LimitedCounter;

        assert_verdict_matches_ambient("complete session", || {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            assert!(session.scope_step());
            let finished = session.finish(());
            session.reuse_verdict().join(finished.reuse_verdict())
        });
        assert_verdict_matches_ambient("summary limit", || {
            let session = ResolutionSession::bounded(
                ReceiverAnalysisBudget {
                    max_summary_expansions: 0,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            );
            assert!(!session.summary_step());
            let finished = session.finish(());
            assert!(matches!(finished, BoundedResolution::Exceeded { .. }));
            session.reuse_verdict().join(finished.reuse_verdict())
        });
        assert_verdict_matches_ambient("total work limit", || {
            let session = ResolutionSession::bounded_with_total_work(
                ReceiverAnalysisBudget::default(),
                0,
                None,
            );
            assert!(!session.round_step());
            session.reuse_verdict()
        });
        assert_verdict_matches_ambient("nested exceeded", || {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            session.mark_exceeded(ReceiverBudgetLimit::SummaryExpansions);
            session.reuse_verdict()
        });
        assert_verdict_matches_ambient("operation cancelled", || {
            let operation = CancellationToken::new();
            let session =
                ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&operation));
            operation.cancel();
            assert!(!session.observe_cancellation());
            session.reuse_verdict()
        });
        assert_verdict_matches_ambient("caller cancelled", || {
            let session = ResolutionSession::bounded(ReceiverAnalysisBudget::default(), None);
            let caller = CancellationToken::new();
            let result = session.with_call_cancellation(&caller, || caller.cancel());
            let refused = result.expect_err("caller cancelled");
            session.reuse_verdict().join(refused.reuse_verdict())
        });
        assert_verdict_matches_ambient("limited counter", || {
            LimitedCounter::from_usage(1, 1)
                .try_allow(1)
                .expect_err("over the limit")
                .reuse_verdict()
        });
        assert_verdict_matches_ambient("tracker limit and truncation", || {
            let mut tracker = ReceiverAnalysisBudgetTracker::new(ReceiverAnalysisBudget {
                max_summary_expansions: 0,
                max_targets: 1,
                ..ReceiverAnalysisBudget::default()
            });
            assert!(tracker.record_summary_expansion().is_err());
            let report = tracker.report(ReceiverAnalysisOutcome::Ambiguous(vec![1, 2]));
            tracker.reuse_verdict().join(report.reuse_verdict())
        });
        assert_verdict_matches_ambient("truncated cached report", || {
            ReceiverAnalysisReport::without_work(
                ReceiverAnalysisOutcome::Precise(vec![1, 2]),
                ReceiverAnalysisBudget {
                    max_targets: 1,
                    ..ReceiverAnalysisBudget::default()
                },
            )
            .reuse_verdict()
        });
    }
}
