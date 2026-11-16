//! Counts for bounded evidence, with explicit exactness.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OmissionExactness {
    Exact,
    LowerBound,
}

/// A count of omitted values. A lower bound never claims an exact total.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct OmissionCount {
    count: u64,
    exactness: OmissionExactness,
}

impl Default for OmissionCount {
    fn default() -> Self {
        Self::exact(0)
    }
}

impl OmissionCount {
    pub const fn exact(count: u64) -> Self {
        Self {
            count,
            exactness: OmissionExactness::Exact,
        }
    }

    pub const fn lower_bound(count: u64) -> Self {
        Self {
            count,
            exactness: OmissionExactness::LowerBound,
        }
    }

    pub const fn count(self) -> u64 {
        self.count
    }

    pub const fn exactness(self) -> OmissionExactness {
        self.exactness
    }

    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Combine disjoint omissions, retaining the weaker count guarantee.
    pub fn combined(self, other: Self) -> Self {
        match self.count.checked_add(other.count) {
            Some(count)
                if self.exactness == OmissionExactness::Exact
                    && other.exactness == OmissionExactness::Exact =>
            {
                Self::exact(count)
            }
            Some(count) => Self::lower_bound(count),
            None => Self::lower_bound(u64::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11267: upstream source omissions lost their count guarantee during projection")]
    fn omission_count_preserves_exactness_and_saturates_as_a_lower_bound() {
        for (left, right, expected) in [
            (
                OmissionCount::exact(2),
                OmissionCount::exact(3),
                OmissionCount::exact(5),
            ),
            (
                OmissionCount::lower_bound(1),
                OmissionCount::exact(3),
                OmissionCount::lower_bound(4),
            ),
            (
                OmissionCount::exact(3),
                OmissionCount::lower_bound(1),
                OmissionCount::lower_bound(4),
            ),
            (
                OmissionCount::exact(u64::MAX),
                OmissionCount::exact(1),
                OmissionCount::lower_bound(u64::MAX),
            ),
        ] {
            assert_eq!(left.combined(right), expected);
            let json = serde_json::to_vec(&expected).unwrap();
            assert_eq!(
                serde_json::from_slice::<OmissionCount>(&json).unwrap(),
                expected
            );
        }
    }
}
