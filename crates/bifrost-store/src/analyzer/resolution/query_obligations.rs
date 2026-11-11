//! Selected-environment assumptions, independent of binding completeness.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;

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

    pub(crate) fn contains(&self, obligation: &QueryObligation) -> bool {
        self.0.contains(obligation)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum QueryNode {
    Reference(super::SemanticId),
    Slot(super::SemanticId),
    Lexical(super::SemanticId),
    Suffix(super::SemanticId),
    /// Query-local hierarchy sources are insert-once and are never reset.
    Hierarchy(super::SemanticId),
    /// Recording-only marker for a read of the published node set.
    All,
}

type RecordingStack = Rc<RefCell<Vec<(usize, crate::hash::HashSet<QueryNode>)>>>;

/// Per-node sets survive hook-skipping memo hits across rounds. Only a
/// recomputed node is reset. The active nodes of the published round define
/// the cone; neither sets nor activity participate in value equality.
#[derive(Debug, Clone)]
pub(crate) struct NodeQueryObligations {
    sets: crate::hash::HashMap<QueryNode, QueryObligations>,
    /// The cone that published() reads. Inside a round it is the previous
    /// round's cone plus every node visited so far: a rerunning item may not
    /// have reached its nodes yet, and a reader must not miss them.
    active: crate::hash::HashSet<QueryNode>,
    /// The cone at the end of the previous round.
    previous_active: crate::hash::HashSet<QueryNode>,
    /// Nodes this round carried for clean items or visited while rerunning;
    /// the cone at the end of the round.
    visited: crate::hash::HashSet<QueryNode>,
    changed: Vec<QueryNode>,
    changed_seen: crate::hash::HashSet<QueryNode>,
    recompute_previous: crate::hash::HashMap<QueryNode, Option<QueryObligations>>,
    recording: RecordingStack,
    recording_next: Cell<usize>,
    item_evaluations: Rc<Cell<usize>>,
}

impl NodeQueryObligations {
    pub(crate) fn ordered_sets_with_poll(
        &self,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Option<Box<[(QueryNode, bool, QueryObligations)]>> {
        let mut nodes = self.sets.keys().copied().collect::<Vec<_>>();
        nodes.sort_unstable();
        let mut result = Vec::with_capacity(nodes.len());
        for node in nodes {
            if cancelled() {
                return None;
            }
            result.push((
                node,
                self.active.contains(&node),
                self.sets[&node].clone_with_poll(cancelled)?,
            ));
        }
        Some(result.into_boxed_slice())
    }

    pub(crate) fn empty() -> Self {
        Self {
            sets: crate::hash::HashMap::default(),
            active: crate::hash::HashSet::default(),
            previous_active: crate::hash::HashSet::default(),
            visited: crate::hash::HashSet::default(),
            changed: Vec::new(),
            changed_seen: crate::hash::HashSet::default(),
            recompute_previous: crate::hash::HashMap::default(),
            recording: Rc::new(RefCell::new(Vec::new())),
            recording_next: Cell::new(0),
            item_evaluations: Rc::new(Cell::new(0)),
        }
    }

    pub(crate) fn evaluating_item(&self) -> ItemEvaluationGuard {
        self.item_evaluations.set(self.item_evaluations.get() + 1);
        ItemEvaluationGuard(Rc::clone(&self.item_evaluations))
    }

    pub(crate) fn begin_round(&mut self) {
        self.previous_active.clone_from(&self.active);
        self.visited.clear();
    }

    /// Recorded reads cover nodes a clean item used but does not own. A clean
    /// reference also owns four ID-keyed nodes, including nodes written outside
    /// its read window, so carry both from the preceding round.
    pub(crate) fn carry_nodes(
        &mut self,
        nodes: impl IntoIterator<Item = QueryNode>,
        references: impl IntoIterator<Item = super::SemanticId>,
    ) {
        self.visited.extend(
            nodes
                .into_iter()
                .filter(|node| self.previous_active.contains(node)),
        );
        for reference in references {
            for node in [
                QueryNode::Reference(reference),
                QueryNode::Lexical(reference),
                QueryNode::Suffix(reference),
                QueryNode::Hierarchy(reference),
            ] {
                if self.previous_active.contains(&node) {
                    self.visited.insert(node);
                }
            }
        }
    }

    /// Ends the round's cone: it becomes the nodes this round carried or
    /// visited. A node with obligations that entered or left the cone changes
    /// published() although no set changed, so it queues the whole-set change.
    /// Each published() read in the round saw the previous cone plus the nodes
    /// visited before it, so every difference between what a reader saw and the
    /// new cone is such an entry or exit. A rerunning item's node never leaves
    /// and returns inside the round, so it cannot wake its own reader.
    pub(crate) fn end_round(&mut self) {
        std::mem::swap(&mut self.active, &mut self.visited);
        self.visited.clear();
        let changed = self
            .active
            .symmetric_difference(&self.previous_active)
            .any(|node| self.sets.get(node).is_some_and(|set| !set.is_empty()));
        if changed && self.changed_seen.insert(QueryNode::All) {
            self.changed.push(QueryNode::All);
        }
    }

    fn changed(&mut self, node: QueryNode) {
        debug_assert_ne!(node, QueryNode::All);
        if self.changed_seen.insert(node) {
            self.changed.push(node);
        }
    }

    pub(crate) fn drain_changed(&mut self) -> impl Iterator<Item = QueryNode> + '_ {
        self.changed_seen.clear();
        self.changed.drain(..).filter(|node| {
            if *node == QueryNode::All {
                return true;
            }
            self.recompute_previous.remove(node).is_none_or(|previous| {
                previous.unwrap_or_else(QueryObligations::empty)
                    != self
                        .sets
                        .get(node)
                        .cloned()
                        .unwrap_or_else(QueryObligations::empty)
            })
        })
    }

    pub(crate) fn has_changes(&self) -> bool {
        !self.changed.is_empty()
    }

    pub(crate) fn has_open_recording(&self) -> bool {
        !self.recording.borrow().is_empty()
    }

    pub(crate) fn begin_recording(&self) -> QueryNodeRecordingGuard {
        let id = self.recording_next.get();
        self.recording_next.set(id + 1);
        self.recording
            .borrow_mut()
            .push((id, crate::hash::HashSet::default()));
        QueryNodeRecordingGuard {
            recording: Rc::clone(&self.recording),
            id,
        }
    }

    pub(crate) fn take_recorded(&self) -> crate::hash::HashSet<QueryNode> {
        let mut recording = self.recording.borrow_mut();
        let reads = recording.pop().expect("recording window is open").1;
        if let Some((_, parent)) = recording.last_mut() {
            parent.extend(reads.iter().copied());
        }
        reads
    }

    fn record(&self, node: QueryNode) {
        debug_assert!(
            self.item_evaluations.get() == 0 || self.has_open_recording(),
            "query node access during item evaluation needs a recording window: {node:?}"
        );
        for (_, reads) in self.recording.borrow_mut().iter_mut() {
            reads.insert(node);
        }
    }

    pub(crate) fn recompute(&mut self, node: QueryNode) {
        self.record(node);
        self.active.insert(node);
        self.visited.insert(node);
        let previous = self.sets.insert(node, QueryObligations::empty());
        self.recompute_previous.entry(node).or_insert(previous);
        self.changed(node);
    }

    pub(crate) fn node(&mut self, node: QueryNode) -> QueryObligationWriteGuard<'_> {
        self.record(node);
        self.active.insert(node);
        self.visited.insert(node);
        let (sets, changed, seen) = (&mut self.sets, &mut self.changed, &mut self.changed_seen);
        let value = sets.entry(node).or_insert_with(QueryObligations::empty);
        QueryObligationWriteGuard {
            node,
            previous_len: value.0.len(),
            value,
            changed,
            seen,
        }
    }

    pub(crate) fn scope(&self, node: QueryNode) -> QueryObligations {
        self.record(node);
        self.sets
            .get(&node)
            .cloned()
            .unwrap_or_else(QueryObligations::empty)
    }

    pub(crate) fn published(&self) -> QueryObligations {
        // After a semi-naive round, this is the full pass's published union of
        // targets, completion, and obligations, including disappearance and
        // late arrival: clean references carry owned ID-keyed nodes even when
        // written outside their read window; recorded reads carry other nodes
        // they used but do not own.
        self.record(QueryNode::All);
        let mut result = QueryObligations::empty();
        for node in &self.active {
            if let Some(obligations) = self.sets.get(node) {
                result.union(obligations);
            }
        }
        result
    }
}

pub(crate) struct QueryNodeRecordingGuard {
    recording: RecordingStack,
    id: usize,
}

impl QueryNodeRecordingGuard {
    pub(crate) fn take_recorded(&self) -> crate::hash::HashSet<QueryNode> {
        let mut recording = self.recording.borrow_mut();
        let (id, reads) = recording.pop().expect("recording window is open");
        assert_eq!(id, self.id, "recording windows close in stack order");
        if let Some((_, parent)) = recording.last_mut() {
            parent.extend(reads.iter().copied());
        }
        reads
    }
}

impl Drop for QueryNodeRecordingGuard {
    fn drop(&mut self) {
        let mut recording = self.recording.borrow_mut();
        if recording.iter().any(|(id, _)| *id == self.id) {
            let (id, reads) = recording.pop().expect("recording window is open");
            assert_eq!(id, self.id, "recording windows close in stack order");
            if let Some((_, parent)) = recording.last_mut() {
                parent.extend(reads);
            }
        }
    }
}

pub(crate) struct ItemEvaluationGuard(Rc<Cell<usize>>);

impl Drop for ItemEvaluationGuard {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

pub(crate) struct QueryObligationWriteGuard<'a> {
    node: QueryNode,
    previous_len: usize,
    value: &'a mut QueryObligations,
    changed: &'a mut Vec<QueryNode>,
    seen: &'a mut crate::hash::HashSet<QueryNode>,
}

impl Deref for QueryObligationWriteGuard<'_> {
    type Target = QueryObligations;
    fn deref(&self) -> &Self::Target {
        self.value
    }
}
impl DerefMut for QueryObligationWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
    }
}
impl Drop for QueryObligationWriteGuard<'_> {
    fn drop(&mut self) {
        let len = self.value.0.len();
        debug_assert!(len >= self.previous_len, "obligation guard only adds");
        if len > self.previous_len && self.seen.insert(self.node) {
            self.changed.push(self.node);
        }
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

    /// Construct a closed answer carrier for cross-crate cache boundary tests.
    pub fn answer_for_cache_test(
        obligations: QueryObligations,
    ) -> super::super::FactResolutionAnswer {
        let mut answer = super::super::fact_resolution::incomplete_fact_resolution_answer(
            None,
            super::super::ResolutionCompletion::Complete,
            &crate::CancellationToken::new(),
        );
        answer.query_obligations = obligations;
        answer
    }

    /// Exercise the evaluator's actual closed-value consumer at a crate boundary.
    pub fn read_closed_answer_for_cache_test(
        answer: super::super::FactResolutionAnswer,
        consumer: &mut QueryObligations,
    ) -> super::super::FactResolutionAnswer {
        let obligations = answer.query_obligations.clone();
        super::ClosedQueryValue::new(answer, obligations)
            .read(consumer)
            .clone()
    }

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
