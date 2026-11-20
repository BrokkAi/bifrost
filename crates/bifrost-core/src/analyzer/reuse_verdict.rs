//! Whether an answer may be reused, as a value the computation returns.
//!
//! A capture's ledger decides whether its answer is kept. Today producers tell
//! it through ambient marks; this verdict is the explicit replacement, joined
//! along the call path from the producer that stopped to the capture boundary.

/// Why an answer depends on execution state. Variants are ordered from most
/// to least stable; [`ReuseVerdict::join`] keeps the less stable cause (#9947).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionCause {
    /// A deterministic terminal result cap, reusable only under its recorded grant.
    ConfiguredCap,
    /// A refused budget charge. A rerun from the same state repeats it.
    BudgetRefusal,
    /// An input this request pinned but a later request cannot verify, such
    /// as a JVM dependency selection read through explicitly configured jars
    /// (#14322). The request reads one snapshot of it, so the answer holds for
    /// the rest of that request and for no other.
    RequestPinned,
    /// Any other execution dependence: a provider or store failure, a fixed
    /// work limit, a deadline, a cancellation, a generation change. Finer causes
    /// are later, additive work.
    Other,
}

/// `Content` when the answer is a function of the inputs it read, otherwise
/// the least stable execution cause it depended on. The derived order is the
/// join order: `Content` lowest, then each cause in [`ExecutionCause`] order.
#[must_use = "a reuse verdict decides whether an answer may be kept"]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReuseVerdict {
    #[default]
    Content,
    ExecutionDependent(ExecutionCause),
}

impl ReuseVerdict {
    /// The less stable of the two verdicts.
    pub fn join(self, other: Self) -> Self {
        self.max(other)
    }

    pub fn join_in(&mut self, other: Self) {
        *self = self.join(other);
    }

    pub const fn is_content(self) -> bool {
        matches!(self, Self::Content)
    }

    /// Whether the answer holds for the rest of the request that computed it:
    /// it is content, or it depends only on inputs that request pinned.
    pub const fn holds_for_request(self) -> bool {
        matches!(
            self,
            Self::Content | Self::ExecutionDependent(ExecutionCause::RequestPinned)
        )
    }

    /// The verdict the ambient execution-dependence counts imply: `budget` of
    /// the `execution` dependences were refused budget charges and `pinned`
    /// were request-pinned inputs.
    pub const fn from_counts(execution: usize, budget: usize, pinned: usize) -> Self {
        if execution == 0 {
            Self::Content
        } else if budget.saturating_add(pinned) < execution {
            Self::ExecutionDependent(ExecutionCause::Other)
        } else if pinned > 0 {
            Self::ExecutionDependent(ExecutionCause::RequestPinned)
        } else {
            Self::ExecutionDependent(ExecutionCause::BudgetRefusal)
        }
    }

    /// Debug builds stop when `self`, an explicit verdict, is stricter than
    /// `ambient`, the one today's counts imply. A weaker explicit verdict is
    /// expected while producers migrate; a stricter one is a dependence the
    /// ambient channel missed, which would persist an execution-dependent
    /// answer, or a migration error.
    #[track_caller]
    pub fn debug_assert_not_stricter_than(self, ambient: Self) {
        // Configured caps have no legacy execution count; admission checks their binding.
        debug_assert!(
            self == Self::ExecutionDependent(ExecutionCause::ConfiguredCap)
                || self.join(ambient) == ambient,
            "explicit reuse verdict {self:?} is stricter than the ambient {ambient:?}"
        );
    }

    pub const fn cause(self) -> Option<ExecutionCause> {
        match self {
            Self::Content => None,
            Self::ExecutionDependent(cause) => Some(cause),
        }
    }
}

/// A value admitted for reuse. Only `admit` constructs this proof.
#[derive(Clone, Debug)]
pub struct Admitted<T>(T);

impl<T> Admitted<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Admitted<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Whether the consumer validates the configured retention cap on replay.
#[derive(Clone, Copy, Debug)]
pub enum CapBinding {
    Unbound,
    RecordedGrant,
}

/// What an aggregate evaluation's selection-authority reads allow (#11482).
///
/// A selection read answers a question that discovery or the environment
/// decides, which the committed tree and the evaluation key do not fix. A
/// writer states whether every one was recorded as a named, persistable key; a
/// replay states whether every recorded one was recomputed to its recorded
/// answer against an authority that can speak for the base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionEvidence {
    /// The value is not an aggregate evaluation. A unit's ordinary read set
    /// carries any selection read it consumed.
    NotApplicable,
    Complete,
    Incomplete,
}

/// How a recorded selection read relates to the committed tree it was taken
/// over, and so what can verify it when the head differs from that tree (#11607).
///
/// The class is a property of the read family or subject. A family or subject
/// with no declared class is `TreeDependent`, so a newly declared selection
/// family fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionClass {
    /// A function of configuration and the environment only. The head's
    /// authority answers it, whatever tree the head holds.
    EnvironmentOnly,
    /// A function of the exported tree, the configuration and the code. It has
    /// no environment input, so a row that was produced over an export of the
    /// key's tree already holds the answer and nothing needs recomputing.
    ExportDetermined,
    /// A tree part (the coordinates the manifests declare) and an environment
    /// part (what those coordinates resolve to here). The tree part is
    /// `ExportDetermined` and recorded with the read; the environment part is
    /// recomputed against the head from the recorded tree part.
    Split,
    /// Also a function of tree content, with no recorded tree part. Only a head
    /// that is the base tree can answer it.
    TreeDependent,
}

/// What an aggregate evaluation's analyzer was built over (#11607).
///
/// A revision export holds only the tracked regular files of one tree, so a
/// read taken over it is a function of that tree. A live worktree also holds
/// untracked files, restore output and uncommitted edits. The export's tree is
/// recorded so that replay can check it is the key's tree through the same
/// admission as the write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionView {
    /// An export of the workspace subtree with this tree id, holding no gitlink
    /// (a submodule entry is classified by the live checkout's state).
    Export { tree_oid: Box<str> },
    /// A live worktree: its reads hold only while the head is the base tree.
    Worktree,
}

impl SelectionView {
    /// Whether this view is an export of exactly `tree_oid`.
    pub fn is_export_of(&self, tree_oid: &str) -> bool {
        matches!(self, Self::Export { tree_oid: exported } if &**exported == tree_oid)
    }
}

/// The shared admission boundary for units and aggregate evaluations, on write
/// and on replay.
pub fn admit<T>(
    binding: CapBinding,
    value: T,
    explicit: ReuseVerdict,
    collected: ReuseVerdict,
    selection: SelectionEvidence,
) -> Option<Admitted<T>> {
    let verdict = explicit.join(collected);
    let content = verdict.is_content()
        || matches!(
            (verdict, binding),
            (
                ReuseVerdict::ExecutionDependent(ExecutionCause::ConfiguredCap),
                CapBinding::RecordedGrant
            )
        );
    (content && selection != SelectionEvidence::Incomplete).then_some(Admitted(value))
}

/// Implemented by every outcome type that can carry an execution dependence.
pub trait CarriesReuseVerdict {
    fn reuse_verdict(&self) -> ReuseVerdict;
}

/// A value with the verdict of the computation that produced it, for result
/// types that cannot hold one themselves: a semantic outcome's variant does
/// not say which cause stopped it, and a replayed outcome carries no mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judged<T> {
    pub value: T,
    pub reuse: ReuseVerdict,
}

impl<T> CarriesReuseVerdict for Judged<T> {
    fn reuse_verdict(&self) -> ReuseVerdict {
        self.reuse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ReuseVerdict; 5] = [
        ReuseVerdict::Content,
        ReuseVerdict::ExecutionDependent(ExecutionCause::ConfiguredCap),
        ReuseVerdict::ExecutionDependent(ExecutionCause::BudgetRefusal),
        ReuseVerdict::ExecutionDependent(ExecutionCause::RequestPinned),
        ReuseVerdict::ExecutionDependent(ExecutionCause::Other),
    ];

    // The ledger and the policy split rely on these laws: a join that is not
    // a semilattice would make the persisted decision depend on the order in
    // which nested captures forward their verdicts.
    #[test]
    fn join_is_a_bounded_semilattice_with_other_absorbing() {
        let other = ReuseVerdict::ExecutionDependent(ExecutionCause::Other);
        for a in ALL {
            assert_eq!(a.join(a), a);
            assert_eq!(a.join(ReuseVerdict::Content), a);
            assert_eq!(a.join(other), other);
            for b in ALL {
                assert_eq!(a.join(b), b.join(a));
                for c in ALL {
                    assert_eq!(a.join(b).join(c), a.join(b.join(c)));
                }
            }
        }
    }
}
