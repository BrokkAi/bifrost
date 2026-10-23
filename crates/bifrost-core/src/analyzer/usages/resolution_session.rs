use crate::analyzer::query_batch::LimitedQueryRows;
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
    Cancelled {
        work: ReceiverAnalysisWork,
    },
}

impl<T> BoundedResolution<T> {
    pub fn work(&self) -> ReceiverAnalysisWork {
        match self {
            Self::Complete { work, .. }
            | Self::Exceeded { work, .. }
            | Self::Cancelled { work } => *work,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ResolutionStop {
    Exceeded(ReceiverBudgetLimit),
    Cancelled,
}

#[derive(Debug, Clone, Copy, Default)]
struct ResolutionState {
    work: ReceiverAnalysisWork,
    stop: Option<ResolutionStop>,
}

/// One selected owner frontier in a request's expansion budget. The number
/// is an operation-local alias, never canonical content or a persisted key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolutionOwnerFrontier(u64);

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
    state: RefCell<ResolutionState>,
    expanded_owners: RefCell<HashSet<ResolutionOwnerFrontier>>,
}

impl ResolutionSession {
    pub fn unbounded() -> Self {
        Self {
            budget: None,
            total_work_limit: None,
            cancellation: None,
            state: RefCell::new(ResolutionState::default()),
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
            state: RefCell::new(ResolutionState::default()),
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
            state: RefCell::new(ResolutionState::default()),
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
        assert!(shared_work.scope_nodes <= budget.max_scope_nodes);
        assert!(shared_work.summary_expansions <= budget.max_summary_expansions);
        assert!(shared_work.resolution_rounds <= budget.max_resolution_rounds);
        Self {
            budget: Some(budget),
            total_work_limit: None,
            cancellation: Some(
                cancellation.map_or_else(CancellationToken::new, |token| token.child()),
            ),
            state: RefCell::new(ResolutionState {
                work: shared_work,
                stop: None,
            }),
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

    pub fn finish<T>(&self, value: T) -> BoundedResolution<T> {
        self.observe_cancellation();
        let state = *self.state.borrow();
        match state.stop {
            Some(ResolutionStop::Exceeded(limit)) => BoundedResolution::Exceeded {
                limit,
                work: state.work,
            },
            Some(ResolutionStop::Cancelled) => BoundedResolution::Cancelled { work: state.work },
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

    pub fn scope_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::ScopeNodes)
    }

    /// Charge copied scope operands without walking a no-op unbounded session.
    /// Bounded sessions retain exactly the per-step cancellation cadence.
    pub fn scope_steps(&self, count: usize) -> bool {
        if self.budget.is_none() && self.cancellation.is_none() {
            return true;
        }
        (0..count).all(|_| self.scope_step())
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
        if !self.scope_step() {
            return None;
        }
        let value = query();
        self.observe_cancellation().then_some(value)
    }

    pub fn summary_query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        if !self.summary_step() {
            return None;
        }
        let value = query();
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

    /// Runs a provider query whose source-row inspection is capped before it
    /// allocates the complete result set.
    ///
    /// The provider receives one lookahead row beyond the remaining scope
    /// budget. Seeing that row proves exhaustion without silently truncating a
    /// complete answer. Provider-reported source rows are charged even when
    /// liveness filtering produces fewer `rows`; live-path expansion is
    /// charged via `rows.len()`.
    pub fn query_limited_rows<T>(
        &self,
        query: impl FnOnce(usize) -> LimitedQueryRows<T>,
    ) -> Vec<T> {
        if !self.scope_step() {
            return Vec::new();
        }
        let limit = self.scope_lookahead_limit();
        let batch = query(limit);
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
            self.mark_scope_incomplete();
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
        if self.budget.is_none() && self.cancellation.is_none() {
            return rows;
        }
        for _ in &rows {
            if !self.scope_step() {
                return Vec::new();
            }
        }
        rows
    }

    pub fn observe_cancellation(&self) -> bool {
        if self.budget.is_none() && self.cancellation.is_none() {
            return true;
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
        state.stop.is_none()
    }

    pub fn cancellation(&self) -> Option<&CancellationToken> {
        self.cancellation.as_ref()
    }

    /// The exact remaining allowance for a demand answer memo. A stopped
    /// session still has to pass observe_cancellation before using this value.
    pub fn remaining_budget(&self) -> Option<ReceiverAnalysisBudget> {
        self.budget.map(|mut budget| {
            let state = self.state.borrow();
            budget.max_scope_nodes = budget
                .max_scope_nodes
                .saturating_sub(state.work.scope_nodes);
            budget.max_summary_expansions = budget
                .max_summary_expansions
                .saturating_sub(state.work.summary_expansions);
            if let Some(total_work_limit) = self.total_work_limit {
                let remaining_total = total_work_limit.saturating_sub(total_work(&state.work));
                budget.max_scope_nodes = budget.max_scope_nodes.min(remaining_total);
                budget.max_summary_expansions = budget.max_summary_expansions.min(remaining_total);
                budget.max_resolution_rounds = budget
                    .max_resolution_rounds
                    .saturating_sub(state.work.resolution_rounds)
                    .min(remaining_total);
            }
            budget
        })
    }

    /// Maximum provider rows needed to either consume the remaining scope
    /// budget or observe the first row that proves exhaustion.
    pub fn scope_lookahead_limit(&self) -> usize {
        self.remaining_scope_steps().saturating_add(1)
    }

    pub fn mark_scope_incomplete(&self) {
        let limit = self.scope_binding_limit();
        self.stop(ResolutionStop::Exceeded(limit));
    }

    fn remaining_scope_steps(&self) -> usize {
        let state = self.state.borrow();
        if state.stop.is_some() {
            return 0;
        }
        self.budget.map_or(usize::MAX, |budget| {
            let axis_remaining = budget
                .max_scope_nodes
                .saturating_sub(state.work.scope_nodes);
            self.total_work_limit.map_or(axis_remaining, |limit| {
                axis_remaining.min(limit.saturating_sub(total_work(&state.work)))
            })
        })
    }

    fn scope_binding_limit(&self) -> ReceiverBudgetLimit {
        let Some(budget) = self.budget else {
            return ReceiverBudgetLimit::ScopeNodes;
        };
        let state = self.state.borrow();
        let axis_remaining = budget
            .max_scope_nodes
            .saturating_sub(state.work.scope_nodes);
        match self.total_work_limit {
            Some(limit) if limit.saturating_sub(total_work(&state.work)) <= axis_remaining => {
                ReceiverBudgetLimit::TotalWork
            }
            _ => ReceiverBudgetLimit::ScopeNodes,
        }
    }

    fn stop(&self, stop: ResolutionStop) {
        let mut state = self.state.borrow_mut();
        if state.stop.is_none() {
            state.stop = Some(stop);
            drop(state);
            if matches!(stop, ResolutionStop::Exceeded(_))
                && let Some(cancellation) = self.cancellation.as_ref()
            {
                cancellation.cancel();
            }
        }
    }

    fn charge(&self, limit: ReceiverBudgetLimit) -> bool {
        if self.budget.is_none() && self.cancellation.is_none() {
            return true;
        }
        if !self.observe_cancellation() {
            return false;
        }
        let Some(budget) = self.budget else {
            return true;
        };
        let mut state = self.state.borrow_mut();
        if self
            .total_work_limit
            .is_some_and(|maximum| total_work(&state.work) >= maximum)
        {
            state.stop = Some(ResolutionStop::Exceeded(ReceiverBudgetLimit::TotalWork));
            drop(state);
            self.cancellation
                .as_ref()
                .expect("a bounded session has an operation cancellation token")
                .cancel();
            return false;
        }
        let (used, maximum) = match limit {
            ReceiverBudgetLimit::ScopeNodes => {
                (&mut state.work.scope_nodes, budget.max_scope_nodes)
            }
            ReceiverBudgetLimit::SummaryExpansions => (
                &mut state.work.summary_expansions,
                budget.max_summary_expansions,
            ),
            ReceiverBudgetLimit::ResolutionRounds => (
                &mut state.work.resolution_rounds,
                budget.max_resolution_rounds,
            ),
            ReceiverBudgetLimit::TotalWork => unreachable!("aggregate work is checked above"),
        };
        if *used == maximum {
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

fn total_work(work: &ReceiverAnalysisWork) -> usize {
    work.scope_nodes
        .saturating_add(work.summary_expansions)
        .saturating_add(work.resolution_rounds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

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
    #[hardwon("011426732633: bulk scope resolution failed to charge bounded work")]
    fn bulk_scope_charges_preserve_budgets_and_skip_unbounded_work() {
        let unbounded = ResolutionSession::unbounded();
        assert!(unbounded.scope_steps(usize::MAX));
        assert_eq!(unbounded.finish(()).work(), ReceiverAnalysisWork::default());
        for count in 0..=5 {
            let budget = ReceiverAnalysisBudget {
                max_scope_nodes: 3,
                ..ReceiverAnalysisBudget::default()
            };
            let bulk = ResolutionSession::bounded(budget, None);
            let individual = ResolutionSession::bounded(budget, None);
            assert_eq!(
                bulk.scope_steps(count),
                (0..count).all(|_| individual.scope_step())
            );
            assert_eq!(bulk.finish(()).work(), individual.finish(()).work());
            assert_eq!(
                bulk.cancellation().unwrap().is_cancelled(),
                individual.cancellation().unwrap().is_cancelled()
            );
        }
        let caller = CancellationToken::new();
        let cancelled =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&caller));
        caller.cancel();
        assert!(!cancelled.scope_steps(1));
        assert!(matches!(
            cancelled.finish(()),
            BoundedResolution::Cancelled { .. }
        ));
    }
    #[test]
    fn budget_stop_cancels_only_the_operation_token() {
        let caller = CancellationToken::new();
        let session = ResolutionSession::bounded(
            ReceiverAnalysisBudget {
                max_scope_nodes: 0,
                ..ReceiverAnalysisBudget::default()
            },
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
                limit: ReceiverBudgetLimit::ScopeNodes,
                work: ReceiverAnalysisWork { scope_nodes: 0, .. }
            }
        ));
    }

    #[test]
    fn shared_work_counts_against_independent_locator_budgets() {
        let caller = CancellationToken::new();
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 2,
            ..ReceiverAnalysisBudget::default()
        };
        let setup = ResolutionSession::bounded(budget, Some(&caller));
        assert!(setup.scope_step());
        let shared_work = setup.finish(()).work();

        let exhausted =
            ResolutionSession::bounded_after_shared_work(budget, Some(&caller), shared_work);
        assert!(exhausted.scope_step());
        assert!(!exhausted.scope_step());
        assert!(matches!(
            exhausted.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work: ReceiverAnalysisWork { scope_nodes: 2, .. }
            }
        ));

        let sibling =
            ResolutionSession::bounded_after_shared_work(budget, Some(&caller), shared_work);
        assert!(sibling.scope_step());
        assert!(!sibling.cancellation().unwrap().is_cancelled());
        assert!(!caller.is_cancelled());
    }

    #[test]
    #[hardwon("#5511: repeated modeled bases could exceed every independently bounded work axis")]
    fn aggregate_work_cap_bounds_mixed_axes_and_provider_rows() {
        let caller = CancellationToken::new();
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 8,
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
                }
            }
        ));

        let legacy = ResolutionSession::bounded(budget, None);
        assert!(legacy.round_step());
        assert_eq!(
            legacy.remaining_budget().unwrap().max_resolution_rounds,
            budget.max_resolution_rounds,
            "legacy constructors retain their existing round projection"
        );
        assert_eq!(ReceiverBudgetLimit::TotalWork.as_str(), "total_work");

        let tight_axis = ResolutionSession::bounded_with_total_work(
            ReceiverAnalysisBudget {
                max_scope_nodes: 1,
                ..budget
            },
            9,
            None,
        );
        assert!(tight_axis.scope_step());
        assert!(!tight_axis.scope_step());
        assert!(matches!(
            tight_axis.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
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
                }
            }
        ));
    }
}
