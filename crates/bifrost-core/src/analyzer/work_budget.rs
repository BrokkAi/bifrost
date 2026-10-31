//! Shared multidimensional work-budget accounting.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One fixed set of independently measured work dimensions.
pub trait BudgetWork: Copy {
    type Dimension: Copy + 'static;

    const DIMENSIONS: &'static [Self::Dimension];

    fn get(self, dimension: Self::Dimension) -> usize;
    fn checked_add(self, other: Self) -> Option<Self>;
}

/// A budget work shape with a constant all-zero value.
pub trait ZeroBudgetWork: BudgetWork {
    const ZERO: Self;
}

/// Exact failed charge reported by the shared ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkBudgetExceeded<Dimension> {
    dimension: Dimension,
    limit: usize,
    attempted: usize,
}

impl<Dimension: Copy> WorkBudgetExceeded<Dimension> {
    pub const fn dimension(self) -> Dimension {
        self.dimension
    }

    pub const fn limit(self) -> usize {
        self.limit
    }

    pub const fn attempted(self) -> usize {
        self.attempted
    }
}

/// Atomic accounting shared by semantic materialization and data-flow solves.
#[derive(Debug, Clone)]
pub struct BudgetLedger<Work> {
    limits: Work,
    used: Work,
    refusals: Arc<AtomicUsize>,
}

impl<Work: PartialEq> PartialEq for BudgetLedger<Work> {
    fn eq(&self, other: &Self) -> bool {
        self.limits == other.limits && self.used == other.used
    }
}
impl<Work: Eq> Eq for BudgetLedger<Work> {}

impl<Work> BudgetLedger<Work> {
    pub fn new(limits: Work, used: Work) -> Self {
        Self {
            limits,
            used,
            refusals: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Failed checks, including those on discarded staging copies. This
    /// observation is monotonic and never refunded with resident usage.
    pub fn refusal_count(&self) -> usize {
        self.refusals.load(Ordering::Relaxed)
    }

    /// Replace resident usage while preserving the logical budget's failures.
    pub fn with_used(&self, used: Work) -> Self
    where
        Work: Clone,
    {
        Self {
            limits: self.limits.clone(),
            used,
            refusals: Arc::clone(&self.refusals),
        }
    }

    #[track_caller]
    pub fn record_refusal(&self) {
        super::carried_context::mark_execution_dependent();
        let origin = std::panic::Location::caller();
        crate::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=budget:{} observation=refusal",
                origin.file(),
                origin.line(),
                std::any::type_name::<Work>()
            )
        });
        self.refusals.fetch_add(1, Ordering::Relaxed);
    }
}

impl<Work> BudgetLedger<Work>
where
    Work: ZeroBudgetWork,
{
    /// Create a ledger with the work shape's all-zero usage value.
    pub fn with_zero_usage(limits: Work) -> Self {
        Self::new(limits, Work::ZERO)
    }
}

impl<Work> BudgetLedger<Work>
where
    Work: BudgetWork,
{
    pub const fn limits(&self) -> Work {
        self.limits
    }

    pub const fn used(&self) -> Work {
        self.used
    }

    pub fn check(&self, work: Work) -> Result<(), WorkBudgetExceeded<Work::Dimension>> {
        for &dimension in Work::DIMENSIONS {
            let limit = self.limits.get(dimension);
            let Some(attempted) = self.used.get(dimension).checked_add(work.get(dimension)) else {
                self.record_refusal();
                return Err(WorkBudgetExceeded {
                    dimension,
                    limit,
                    attempted: usize::MAX,
                });
            };
            if attempted > limit {
                self.record_refusal();
                return Err(WorkBudgetExceeded {
                    dimension,
                    limit,
                    attempted,
                });
            }
        }
        Ok(())
    }

    pub fn charge(&mut self, work: Work) -> Result<(), WorkBudgetExceeded<Work::Dimension>> {
        self.check(work)?;
        self.used = self
            .used
            .checked_add(work)
            .expect("validated work-budget charge cannot overflow");
        Ok(())
    }

    pub fn staged_charge(&self, work: Work) -> Result<Self, WorkBudgetExceeded<Work::Dimension>> {
        let mut staged = self.clone();
        staged.charge(work)?;
        Ok(staged)
    }
}

#[macro_export]
macro_rules! define_work_dimensions {
    (
        $(#[$dimension_attribute:meta])*
        $dimension_visibility:vis enum $dimension:ident;
        $(#[$work_attribute:meta])*
        $work_visibility:vis struct $work:ident;
        all: $all_visibility:vis [$count:expr];
        $($variant:ident => $field:ident = $default_limit:expr),+ $(,)?
    ) => {
        $(#[$dimension_attribute])*
        $dimension_visibility enum $dimension {
            $($variant),+
        }

        impl $dimension {
            $all_visibility const ALL: [Self; $count] = [
                $(Self::$variant),+
            ];

            /// Every internal dimension label, in declaration order. Public
            /// diagnostic vocabularies may project these dimensions onto a
            /// smaller set of lanes.
            #[allow(dead_code)]
            pub const LABELS: &'static [&'static str] = &[$(stringify!($field)),+];

            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($field)),+
                }
            }
        }

        $(#[$work_attribute])*
        $work_visibility struct $work {
            $(pub $field: usize),+
        }

        impl $work {
            pub const fn uniform(value: usize) -> Self {
                Self {
                    $($field: value),+
                }
            }

            pub const fn get(self, dimension: $dimension) -> usize {
                match dimension {
                    $($dimension::$variant => self.$field),+
                }
            }

            pub const fn default_limits() -> Self {
                Self {
                    $($field: $default_limit),+
                }
            }

            /// Combine corresponding dimensions with the same operation.
            #[allow(dead_code)]
            pub fn zip_with(self, other: Self, f: impl Fn(usize, usize) -> usize) -> Self {
                Self {
                    $($field: f(self.$field, other.$field)),+
                }
            }

            pub fn checked_add(self, other: Self) -> Option<Self> {
                Some(Self {
                    $($field: self.$field.checked_add(other.$field)?),+
                })
            }

            #[allow(dead_code)]
            pub const fn is_empty(&self) -> bool {
                $(self.$field == 0)&&+
            }

            #[allow(dead_code)]
            pub const fn saturating_add(self, other: Self) -> Self {
                Self {
                    $($field: self.$field.saturating_add(other.$field)),+
                }
            }

            pub const fn saturating_sub(self, other: Self) -> Self {
                Self {
                    $($field: self.$field.saturating_sub(other.$field)),+
                }
            }
        }

        impl $crate::analyzer::work_budget::BudgetWork for $work {
            type Dimension = $dimension;

            const DIMENSIONS: &'static [Self::Dimension] = &$dimension::ALL;

            fn get(self, dimension: Self::Dimension) -> usize {
                self.get(dimension)
            }

            fn checked_add(self, other: Self) -> Option<Self> {
                self.checked_add(other)
            }
        }

        impl $crate::analyzer::work_budget::ZeroBudgetWork for $work {
            const ZERO: Self = Self::uniform(0);
        }
    };
}

pub use crate::define_work_dimensions;

#[cfg(test)]
mod tests {
    use super::*;

    define_work_dimensions! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum TestDimension;
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        struct TestWork;
        all: [2];
        Rows => rows = 4,
        Bytes => bytes = 8,
    }

    #[test]
    fn failed_charge_is_atomic_and_reports_the_first_dimension() {
        let mut ledger = BudgetLedger::new(TestWork::default_limits(), TestWork::default());
        ledger.charge(TestWork { rows: 4, bytes: 1 }).unwrap();
        let before = ledger.used();

        let exceeded = ledger.charge(TestWork { rows: 1, bytes: 20 }).unwrap_err();

        assert_eq!(exceeded.dimension(), TestDimension::Rows);
        assert_eq!(exceeded.limit(), 4);
        assert_eq!(exceeded.attempted(), 5);
        assert_eq!(ledger.used(), before);
        assert_eq!(ledger.refusal_count(), 1);
        let staged = ledger.clone();
        assert!(
            staged
                .check(TestWork {
                    rows: usize::MAX,
                    bytes: 0
                })
                .is_err()
        );
        assert_eq!(ledger.refusal_count(), 2);
        assert_eq!(ledger.with_used(TestWork::default()).refusal_count(), 2);
        assert_eq!(ledger.limits().bytes, 8);
        assert_eq!(TestDimension::Bytes.label(), "bytes");
        assert_eq!(
            TestWork::uniform(3).saturating_sub(TestWork { rows: 1, bytes: 2 }),
            TestWork { rows: 2, bytes: 1 }
        );
    }
}

/// The ledger against a field-by-field oracle written out by hand for a
/// three-dimension work shape, so the last dimension is checked as well as the
/// first. The macro's labels and limit helpers are unused here.
#[cfg(test)]
#[allow(dead_code)]
mod work_budget_properties {
    use proptest::prelude::*;

    use super::*;

    define_work_dimensions! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Dimension;
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        struct Work;
        all: [3];
        Rows => rows = 0,
        Bytes => bytes = 0,
        Nodes => nodes = 0,
    }

    /// Small values make every comparison likely; values near `usize::MAX`
    /// make the sum overflow.
    fn amount() -> impl Strategy<Value = usize> {
        prop_oneof![4 => 0usize..6, 1 => (0usize..3).prop_map(|less| usize::MAX - less)]
    }

    fn work() -> impl Strategy<Value = Work> {
        (amount(), amount(), amount()).prop_map(|(rows, bytes, nodes)| Work { rows, bytes, nodes })
    }

    /// The first dimension, in declaration order, whose usage plus work
    /// overflows or exceeds its limit.
    fn expected_exceeded(
        limits: Work,
        used: Work,
        work: Work,
    ) -> Option<WorkBudgetExceeded<Dimension>> {
        [
            (Dimension::Rows, limits.rows, used.rows, work.rows),
            (Dimension::Bytes, limits.bytes, used.bytes, work.bytes),
            (Dimension::Nodes, limits.nodes, used.nodes, work.nodes),
        ]
        .into_iter()
        .find_map(|(dimension, limit, used, work)| {
            let sum = used.checked_add(work);
            let attempted = sum.unwrap_or(usize::MAX);
            (sum.is_none() || attempted > limit).then_some(WorkBudgetExceeded {
                dimension,
                limit,
                attempted,
            })
        })
    }

    proptest! {
        #[test]
        fn check_and_charge_match_the_fieldwise_oracle(
            limits in work(),
            used in work(),
            work in work(),
        ) {
            let expected = expected_exceeded(limits, used, work);
            let ledger = BudgetLedger::new(limits, used);
            prop_assert_eq!(ledger.check(work).err(), expected);

            let mut charged = ledger.clone();
            let staged = ledger.staged_charge(work);
            match expected {
                Some(exceeded) => {
                    prop_assert_eq!(charged.charge(work), Err(exceeded));
                    prop_assert_eq!(charged.used(), used);
                    prop_assert_eq!(staged, Err(exceeded));
                }
                None => {
                    prop_assert_eq!(charged.charge(work), Ok(()));
                    let sum = Work {
                        rows: used.rows + work.rows,
                        bytes: used.bytes + work.bytes,
                        nodes: used.nodes + work.nodes,
                    };
                    prop_assert_eq!(charged.used(), sum);
                    prop_assert_eq!(staged.map(|staged| staged.used()), Ok(sum));
                }
            }
            prop_assert_eq!(charged.limits(), limits);
            prop_assert_eq!(ledger.used(), used);
        }
    }
}

/// A query-local scalar allowance. Refusal is an execution input even when
/// the caller catches it and returns a useful fallback.
#[derive(Debug, Clone, Copy)]
pub struct LimitedCounter {
    used: usize,
    limit: usize,
}

impl LimitedCounter {
    pub fn from_usage(used: usize, limit: usize) -> Self {
        Self { used, limit }
    }

    pub fn allows(&self, additional: usize) -> bool {
        let fits = self
            .used
            .checked_add(additional)
            .is_some_and(|used| used <= self.limit);
        if !fits {
            super::carried_context::mark_execution_dependent();
        }
        fits
    }

    pub fn charge(&mut self, additional: usize) -> bool {
        if !self.allows(additional) {
            return false;
        }
        self.used += additional;
        true
    }

    pub fn used(&self) -> usize {
        self.used
    }
}
