//! Structured, query-local C and C++ range facts.
//!
//! These rows deliberately describe only the bounded facts needed by the
//! direct CodeQL parity slice. They are not a general range-analysis graph:
//! each fact is anchored at one source range and keeps the evidence that made
//! the result precise.

use super::Range;

/// The direction established by a loop's condition or update expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppLoopDirection {
    Increasing,
    Decreasing,
}

/// Storage shape of a constant calendar-sized array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppArrayStorage {
    FixedArray,
    VectorConstructor,
}

/// One structured C/C++ range fact proved from one source tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppRangeFact {
    /// The source buffer's fixed extent exceeds the destination extent passed
    /// to `strncpy`.
    BadStrncpySize {
        range: Range,
        destination_extent: u64,
        source_extent: u64,
    },
    /// A loop condition advances toward its bound while its update moves away
    /// from it, or the converse.
    InconsistentLoopDirection {
        range: Range,
        condition: CppLoopDirection,
        update: CppLoopDirection,
    },
    /// A fixed array or vector constructor is allocated with the calendar
    /// constant 365.
    UnsafeArrayExtent {
        range: Range,
        extent: u64,
        storage: CppArrayStorage,
    },
    /// A direct `ntohl` result is used as a raw array-bound argument.
    NetworkToHostFunctionAsArrayBound { range: Range },
}

impl CppRangeFact {
    pub fn range(&self) -> Range {
        match self {
            Self::BadStrncpySize { range, .. }
            | Self::InconsistentLoopDirection { range, .. }
            | Self::UnsafeArrayExtent { range, .. }
            | Self::NetworkToHostFunctionAsArrayBound { range } => *range,
        }
    }
}

/// Outcome of one bounded fact lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppRangeFactOutcome {
    Proven(CppRangeFact),
    NotApplicable,
    Incomplete(&'static str),
}
