use crate::analyzer::query_batch::LimitedQueryRows;
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
};
use crate::cancellation::CancellationToken;
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

/// Work and cancellation state shared by one bounded exact-resolution request.
///
/// An unbounded session preserves the ordinary lookup APIs without charging.
/// A bounded session records every resolver-owned syntax/candidate step and
/// hierarchy expansion. Once stopped, all subsequent helpers become no-ops and
/// [`Self::finish`] returns the terminal condition instead of any partial value.
pub struct ResolutionSession {
    budget: Option<ReceiverAnalysisBudget>,
    cancellation: Option<CancellationToken>,
    state: RefCell<ResolutionState>,
}

impl ResolutionSession {
    pub fn unbounded() -> Self {
        Self {
            budget: None,
            cancellation: None,
            state: RefCell::new(ResolutionState::default()),
        }
    }

    pub fn bounded(
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        Self {
            budget: Some(budget),
            cancellation: Some(
                cancellation.map_or_else(CancellationToken::new, |token| token.child()),
            ),
            state: RefCell::new(ResolutionState::default()),
        }
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
        let limit = self.remaining_scope_steps().saturating_add(1);
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
            self.stop(ResolutionStop::Exceeded(ReceiverBudgetLimit::ScopeNodes));
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

    /// Maximum provider rows needed to either consume the remaining scope
    /// budget or observe the first row that proves exhaustion.
    pub fn scope_lookahead_limit(&self) -> usize {
        self.remaining_scope_steps().saturating_add(1)
    }

    pub fn mark_scope_incomplete(&self) {
        self.stop(ResolutionStop::Exceeded(ReceiverBudgetLimit::ScopeNodes));
    }

    fn remaining_scope_steps(&self) -> usize {
        let state = self.state.borrow();
        if state.stop.is_some() {
            return 0;
        }
        self.budget.map_or(usize::MAX, |budget| {
            budget
                .max_scope_nodes
                .saturating_sub(state.work.scope_nodes)
        })
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
        let (used, maximum) = match limit {
            ReceiverBudgetLimit::ScopeNodes => {
                (&mut state.work.scope_nodes, budget.max_scope_nodes)
            }
            ReceiverBudgetLimit::SummaryExpansions => (
                &mut state.work.summary_expansions,
                budget.max_summary_expansions,
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
}
