//! Request-local data-flow work budgets.

use std::{error::Error, fmt};

use crate::analyzer::semantic::CancellationToken;
use crate::analyzer::work_budget::{BudgetLedger, WorkBudgetExceeded, define_work_dimensions};

define_work_dimensions! {
    /// One independently limited source of solver growth.
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum SolverBudgetDimension;
    /// Work performed or limits applied by one bounded data-flow solve.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SolverWork;
    all: pub(crate) [5];
    InternedFacts => interned_facts = 100_000,
    ReachedStates => reached_states = 1_000_000,
    FlowEvaluations => flow_evaluations = 4_000_000,
    CallbackRows => callback_rows = 4_000_000,
    PropagatedOutputs => propagated_outputs = 4_000_000,
}

/// Exact failed solver-budget charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SolverBudgetExceeded {
    dimension: SolverBudgetDimension,
    limit: usize,
    attempted: usize,
}

impl SolverBudgetExceeded {
    pub const fn dimension(self) -> SolverBudgetDimension {
        self.dimension
    }

    pub const fn limit(self) -> usize {
        self.limit
    }

    pub const fn attempted(self) -> usize {
        self.attempted
    }
}

impl From<WorkBudgetExceeded<SolverBudgetDimension>> for SolverBudgetExceeded {
    fn from(exceeded: WorkBudgetExceeded<SolverBudgetDimension>) -> Self {
        Self {
            dimension: exceeded.dimension(),
            limit: exceeded.limit(),
            attempted: exceeded.attempted(),
        }
    }
}

impl fmt::Display for SolverBudgetExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "solver budget {} exceeded: attempted {}, limit {}",
            self.dimension.label(),
            self.attempted,
            self.limit
        )
    }
}

impl Error for SolverBudgetExceeded {}

/// Five-dimensional request-local work budget.
///
/// `callback_rows` is the single deterministic cap for each unique seed or
/// transfer relation collected from clients. If a complete relation fits that
/// cap, the kernel sorts it and atomically checks the exact fact, state,
/// callback-row, and propagated-output charge. Problem implementations must
/// still stop emitting when requested and return cooperatively to bound their
/// own CPU work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolverBudget {
    ledger: BudgetLedger<SolverWork>,
}

impl SolverBudget {
    pub const fn new(limits: SolverWork) -> Self {
        Self {
            ledger: BudgetLedger::new(limits, SolverWork::uniform(0)),
        }
    }

    pub const fn uniform(limit: usize) -> Self {
        Self::new(SolverWork::uniform(limit))
    }

    pub const fn limits(&self) -> SolverWork {
        self.ledger.limits()
    }

    pub const fn used(&self) -> SolverWork {
        self.ledger.used()
    }

    pub const fn remaining(&self) -> SolverWork {
        self.limits().saturating_sub(self.used())
    }

    /// Check one atomic charge without mutating this budget.
    pub fn check(&self, work: SolverWork) -> Result<(), SolverBudgetExceeded> {
        self.ledger.check(work).map_err(Into::into)
    }

    /// Atomically charge work; a failed charge leaves the budget unchanged.
    pub fn charge(&mut self, work: SolverWork) -> Result<(), SolverBudgetExceeded> {
        self.ledger.charge(work).map_err(Into::into)
    }

    /// Clone and charge this budget, returning a staged value for later commit.
    pub(crate) fn staged_charge(&self, work: SolverWork) -> Result<Self, SolverBudgetExceeded> {
        self.ledger
            .staged_charge(work)
            .map(|ledger| Self { ledger })
            .map_err(Into::into)
    }
}

impl Default for SolverBudget {
    fn default() -> Self {
        Self::new(SolverWork::default_limits())
    }
}

/// Borrowed controls for one data-flow solve.
#[derive(Debug)]
pub struct DataflowRequest<'request> {
    pub budget: &'request mut SolverBudget,
    pub cancellation: &'request CancellationToken,
}

impl<'request> DataflowRequest<'request> {
    pub const fn new(
        budget: &'request mut SolverBudget,
        cancellation: &'request CancellationToken,
    ) -> Self {
        Self {
            budget,
            cancellation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_budget_charge_is_atomic_and_identifies_dimension() {
        let mut budget = SolverBudget::new(SolverWork {
            interned_facts: 2,
            reached_states: 10,
            flow_evaluations: 10,
            callback_rows: 10,
            propagated_outputs: 10,
        });
        budget
            .charge(SolverWork {
                interned_facts: 2,
                ..SolverWork::default()
            })
            .unwrap();
        let before = budget.used();

        let exceeded = budget
            .charge(SolverWork {
                interned_facts: 1,
                ..SolverWork::default()
            })
            .unwrap_err();

        assert_eq!(exceeded.dimension(), SolverBudgetDimension::InternedFacts);
        assert_eq!(exceeded.limit(), 2);
        assert_eq!(exceeded.attempted(), 3);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn staged_charge_does_not_mutate_source_budget() {
        let budget = SolverBudget::uniform(4);

        let staged = budget
            .staged_charge(SolverWork {
                reached_states: 3,
                ..SolverWork::default()
            })
            .unwrap();

        assert_eq!(budget.used(), SolverWork::default());
        assert_eq!(staged.used().reached_states, 3);
        assert_eq!(staged.used().saturating_sub(budget.used()), staged.used());
    }
}
