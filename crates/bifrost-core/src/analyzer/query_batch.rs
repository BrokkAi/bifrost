//! A capped batch of provider-produced rows.
//!
//! Every bounded query in the analyzer answers with the rows it managed to
//! materialize plus enough bookkeeping for the caller to tell "there is nothing
//! there" apart from "I stopped looking": `inspected` counts source rows
//! examined, and `complete` is false whenever the provider hit its cap or
//! observed cancellation.
//!
//! It lives in core because it is the return vocabulary of the language-side
//! bounded lookups, not just of the store: a language crate that answers a
//! budgeted question has to name this type without naming
//! `brokk-bifrost-analysis`.

/// Evidence that a provider could not enumerate its full input domain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum QueryIncompleteReason {
    WorkspaceFileOmission(super::project::WorkspaceFileOmission),
}

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryBatch<T> {
    pub rows: Vec<T>,
    pub inspected: usize,
    pub complete: bool,
    /// Known causes, when available; capped batches may have no detailed cause.
    pub incomplete_reasons: Vec<QueryIncompleteReason>,
}

impl<T> QueryBatch<T> {
    pub fn complete(rows: Vec<T>, inspected: usize) -> Self {
        Self {
            rows,
            inspected,
            complete: true,
            incomplete_reasons: Vec::new(),
        }
    }

    pub fn incomplete(rows: Vec<T>, inspected: usize) -> Self {
        Self {
            rows,
            inspected,
            complete: false,
            incomplete_reasons: Vec::new(),
        }
    }

    pub fn merge(mut self, other: Self) -> Self {
        self.rows.extend(other.rows);
        self.inspected = self.inspected.saturating_add(other.inspected);
        self.complete &= other.complete;
        self.incomplete_reasons.extend(other.incomplete_reasons);
        self
    }
}

/// A provider-owned row batch whose work was capped before materialization.
///
/// `inspected` counts source rows examined, which can differ from `rows.len()`
/// after liveness filtering or one persisted blob expanding to multiple live
/// workspace paths. `complete` is false whenever the provider stopped at its
/// supplied cap or observed cancellation, so bounded callers never mistake a
/// partial batch for an authoritative miss.
pub type LimitedQueryRows<T> = QueryBatch<T>;
