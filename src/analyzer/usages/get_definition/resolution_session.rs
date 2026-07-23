use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisWork, ReceiverBudgetLimit,
};
use crate::cancellation::CancellationToken;
use std::cell::RefCell;

#[derive(Debug)]
pub(crate) enum BoundedResolution<T> {
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
    pub(crate) fn work(&self) -> ReceiverAnalysisWork {
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
pub(crate) struct ResolutionSession {
    budget: Option<ReceiverAnalysisBudget>,
    cancellation: Option<CancellationToken>,
    state: RefCell<ResolutionState>,
}

impl ResolutionSession {
    pub(crate) fn unbounded() -> Self {
        Self {
            budget: None,
            cancellation: None,
            state: RefCell::new(ResolutionState::default()),
        }
    }

    pub(crate) fn bounded(
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        Self {
            budget: Some(budget),
            cancellation: cancellation.cloned(),
            state: RefCell::new(ResolutionState::default()),
        }
    }

    pub(crate) fn finish<T>(&self, value: T) -> BoundedResolution<T> {
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

    pub(crate) fn scope_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::ScopeNodes)
    }

    pub(crate) fn summary_step(&self) -> bool {
        self.charge(ReceiverBudgetLimit::SummaryExpansions)
    }

    pub(crate) fn query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        if !self.scope_step() {
            return None;
        }
        let value = query();
        self.observe_cancellation().then_some(value)
    }

    pub(crate) fn summary_query<T>(&self, query: impl FnOnce() -> T) -> Option<T> {
        if !self.summary_step() {
            return None;
        }
        let value = query();
        self.observe_cancellation().then_some(value)
    }

    pub(crate) fn query_optional<T>(&self, query: impl FnOnce() -> Option<T>) -> Option<T> {
        let value = self.query(query)??;
        self.scope_step().then_some(value)
    }

    pub(crate) fn query_rows<T>(&self, query: impl FnOnce() -> Vec<T>) -> Vec<T> {
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
    pub(crate) fn query_limited_rows<T>(
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

    pub(crate) fn summary_rows<T>(&self, query: impl FnOnce() -> Vec<T>) -> Vec<T> {
        let Some(rows) = self.summary_query(query) else {
            return Vec::new();
        };
        self.track_rows(rows)
    }

    pub(crate) fn track_rows<T>(&self, rows: Vec<T>) -> Vec<T> {
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

    pub(crate) fn observe_cancellation(&self) -> bool {
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

    pub(crate) fn mark_scope_incomplete(&self) {
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
            false
        } else {
            *used += 1;
            true
        }
    }
}
