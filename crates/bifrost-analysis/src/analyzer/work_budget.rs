//! Shared multidimensional work-budget accounting.

/// One fixed set of independently measured work dimensions.
pub(crate) trait BudgetWork: Copy {
    type Dimension: Copy + 'static;

    const DIMENSIONS: &'static [Self::Dimension];

    fn get(self, dimension: Self::Dimension) -> usize;
    fn checked_add(self, other: Self) -> Option<Self>;
}

/// Exact failed charge reported by the shared ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WorkBudgetExceeded<Dimension> {
    dimension: Dimension,
    limit: usize,
    attempted: usize,
}

impl<Dimension: Copy> WorkBudgetExceeded<Dimension> {
    pub(crate) const fn dimension(self) -> Dimension {
        self.dimension
    }

    pub(crate) const fn limit(self) -> usize {
        self.limit
    }

    pub(crate) const fn attempted(self) -> usize {
        self.attempted
    }
}

/// Atomic accounting shared by semantic materialization and data-flow solves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetLedger<Work> {
    limits: Work,
    used: Work,
}

impl<Work> BudgetLedger<Work> {
    pub(crate) const fn new(limits: Work, used: Work) -> Self {
        Self { limits, used }
    }
}

impl<Work> BudgetLedger<Work>
where
    Work: BudgetWork,
{
    pub(crate) const fn limits(&self) -> Work {
        self.limits
    }

    pub(crate) const fn used(&self) -> Work {
        self.used
    }

    pub(crate) fn check(&self, work: Work) -> Result<(), WorkBudgetExceeded<Work::Dimension>> {
        for &dimension in Work::DIMENSIONS {
            let limit = self.limits.get(dimension);
            let Some(attempted) = self.used.get(dimension).checked_add(work.get(dimension)) else {
                return Err(WorkBudgetExceeded {
                    dimension,
                    limit,
                    attempted: usize::MAX,
                });
            };
            if attempted > limit {
                return Err(WorkBudgetExceeded {
                    dimension,
                    limit,
                    attempted,
                });
            }
        }
        Ok(())
    }

    pub(crate) fn charge(&mut self, work: Work) -> Result<(), WorkBudgetExceeded<Work::Dimension>> {
        self.check(work)?;
        self.used = self
            .used
            .checked_add(work)
            .expect("validated work-budget charge cannot overflow");
        Ok(())
    }

    pub(crate) fn staged_charge(
        &self,
        work: Work,
    ) -> Result<Self, WorkBudgetExceeded<Work::Dimension>> {
        let mut staged = self.clone();
        staged.charge(work)?;
        Ok(staged)
    }
}

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

            pub(crate) const fn default_limits() -> Self {
                Self {
                    $($field: $default_limit),+
                }
            }

            pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
                Some(Self {
                    $($field: self.$field.checked_add(other.$field)?),+
                })
            }

            pub(crate) const fn saturating_sub(self, other: Self) -> Self {
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
    };
}

pub(crate) use define_work_dimensions;

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
        assert_eq!(ledger.limits().bytes, 8);
        assert_eq!(TestDimension::Bytes.label(), "bytes");
        assert_eq!(
            TestWork::uniform(3).saturating_sub(TestWork { rows: 1, bytes: 2 }),
            TestWork { rows: 2, bytes: 1 }
        );
    }
}
