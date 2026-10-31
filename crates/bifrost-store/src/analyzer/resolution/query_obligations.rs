//! Selected-environment assumptions, independent of binding completeness.

use std::collections::BTreeSet;
use std::fmt;

/// One stable selected-environment assumption used by a resolution query.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryObligation {
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

impl QueryObligation {
    pub fn new(
        kind: impl Into<String>,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for QueryObligation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{}:{}:{}", self.kind, self.subject, self.detail)
    }
}

/// A sorted, deduplicated, union-only ledger for one logical query.
///
/// An obligation is attached to every answer that relied on it, and to no
/// answer outside the root's demanded cone. Over-attachment inside the cone
/// (for example, a rejected overload's parameter type) is deterministic and
/// errs toward reporting, the correct direction for an obligation.
///
/// Evaluators use one set per reference, slot and memo node: memo hits skip
/// hooks, so only a recomputed node is reset. Publication unions the active
/// cone's node sets after its fixed point; no dependency edges are needed.
///
/// This is independent of every `ResolutionCompletion` axis. In particular,
/// a positive binding does not discharge an unacquired environment inventory.
/// There is deliberately no `Default` implementation: every constructor must
/// name an empty ledger or carry the ledger of its consumed evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryObligations(BTreeSet<QueryObligation>);

impl QueryObligations {
    pub const fn empty() -> Self {
        Self(BTreeSet::new())
    }

    pub fn insert(&mut self, obligation: QueryObligation) {
        self.0.insert(obligation);
    }

    pub fn union(&mut self, other: &Self) {
        self.0.extend(other.0.iter().cloned());
    }

    pub fn iter(&self) -> impl Iterator<Item = &QueryObligation> {
        self.0.iter()
    }

    pub(crate) fn clone_with_poll(&self, cancelled: &mut impl FnMut() -> bool) -> Option<Self> {
        let mut copied = Self::empty();
        for obligation in &self.0 {
            if cancelled() {
                return None;
            }
            copied.insert(obligation.clone());
        }
        Some(copied)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A node in one evaluator's cone. Memos have their own identity because a
/// skipped computation must retain its scope until that memo is recomputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum QueryNode {
    Reference(super::SemanticId),
    Slot(super::SemanticId),
    Lexical(super::SemanticId),
    Suffix(super::SemanticId),
    /// Query-local hierarchy sources are insert-once and are never reset.
    Hierarchy(super::SemanticId),
}

/// Per-node sets survive hook-skipping memo hits across rounds. Only a
/// recomputed node is reset. The active nodes of the published round define
/// the cone; neither sets nor activity participate in value equality.
#[derive(Debug, Clone)]
pub(crate) struct NodeQueryObligations {
    sets: crate::hash::HashMap<QueryNode, QueryObligations>,
    active: crate::hash::HashSet<QueryNode>,
}

impl NodeQueryObligations {
    pub(crate) fn empty() -> Self {
        Self {
            sets: crate::hash::HashMap::default(),
            active: crate::hash::HashSet::default(),
        }
    }

    pub(crate) fn begin_round(&mut self) {
        self.active.clear();
    }

    pub(crate) fn recompute(&mut self, node: QueryNode) {
        self.active.insert(node);
        self.sets.insert(node, QueryObligations::empty());
    }

    pub(crate) fn node(&mut self, node: QueryNode) -> &mut QueryObligations {
        self.active.insert(node);
        self.sets
            .entry(node)
            .or_insert_with(QueryObligations::empty)
    }

    pub(crate) fn scope(&self, node: QueryNode) -> QueryObligations {
        self.sets
            .get(&node)
            .cloned()
            .unwrap_or_else(QueryObligations::empty)
    }

    pub(crate) fn published(&self) -> QueryObligations {
        let mut result = QueryObligations::empty();
        for node in &self.active {
            if let Some(obligations) = self.sets.get(node) {
                result.union(obligations);
            }
        }
        result
    }
}

/// Closed scope travels with its value. A consumer cannot extract the value
/// without recording its obligations, including when a memo skips the hook.
#[derive(Debug, Clone)]
pub(crate) struct ClosedQueryValue<T> {
    value: T,
    obligations: QueryObligations,
}

impl<T> ClosedQueryValue<T> {
    pub(crate) fn new(value: T, obligations: QueryObligations) -> Self {
        Self { value, obligations }
    }
    pub(crate) fn read<'a>(&'a self, consumer: &mut QueryObligations) -> &'a T {
        consumer.union(&self.obligations);
        &self.value
    }
}

/// A provider assumption whose binding boundary remains open until the
/// reference's own target survives shared per-reference refinement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingQueryObligation {
    pub(crate) reason: super::SemanticId,
    pub(crate) obligation: QueryObligation,
}

/// Test-only observations of publication paths carrying a nonempty scope.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod replay_observations {
    use super::QueryObligations;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy, Debug)]
    pub enum Path {
        Fresh,
        Lexical,
        Suffix,
        CompletedRoot,
        ReverseRestart,
    }
    static COUNTS: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];
    pub fn counts() -> [usize; 5] {
        std::array::from_fn(|index| COUNTS[index].load(Ordering::Relaxed))
    }
    pub(crate) fn record(path: Path, scope: &QueryObligations) {
        if !scope.is_empty() {
            COUNTS[path as usize].fetch_add(1, Ordering::Relaxed);
        }
    }
}
