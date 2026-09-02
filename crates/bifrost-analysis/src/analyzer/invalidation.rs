//! The typed vocabulary for why one derived artifact was invalidated or retained (#2449).
//!
//! Bifrost derives many artifacts from source: semantic IR artifacts, reusable
//! procedure summaries, flow snapshots, policy reports. Each of them answers
//! the same question after an edit -- "may I reuse what I already have?" -- and
//! before this module each of them answered it privately, in a boolean, with no
//! way to state *why*. A cache that can only say "miss" cannot be measured, and
//! a cache that cannot be measured cannot be made incremental: the difference
//! between "the file I derived this from changed" and "a procedure I call was
//! recompiled but produced the same summary" is exactly the difference between
//! work that must happen and work that must not.
//!
//! This module is the shared answer. It is deliberately small: one identity
//! type, one verdict, and two closed reason vocabularies. Every reason names
//! the artifact it is about and the input that moved, so a reason is
//! self-explaining in a log line without the reader holding any other context.
//!
//! Identity here is always a [`StableDigest`]. That is a deliberate constraint
//! rather than an encoding convenience:
//!
//! - No absolute path enters an identity. #2529 removed the absolute project
//!   root from workspace content identity, and that is settled: two byte-equal
//!   checkouts at different directories must produce equal invalidation
//!   reasons.
//! - No global workspace generation enters an identity. A generation counter
//!   makes every artifact in the workspace look changed after any edit, which
//!   is the defect #2449 exists to remove, so a reason must never be able to
//!   name one.
//!
//! Slice 1 (this module plus the reverse-dependency index in
//! `brokk_bifrost_flow::dataflow::reusable_summary`) does not re-key any cache.
//! It defines the vocabulary and proves it on the one layer whose artifacts
//! already name their inputs. Later milestones adopt it; the doc comment on
//! each variant states when that variant applies, so adoption does not require
//! re-deciding what a reason means.

use std::fmt;

use crate::analyzer::semantic::StableDigest;

/// What kind of derived artifact one verdict is about.
///
/// The kind is carried beside the fingerprint rather than folded into it so a
/// diagnostic can say what moved without resolving the digest, and so two
/// different artifact families can never compare equal by digest collision of
/// their domain-separated inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DerivedArtifactKind {
    /// One mounted immutable semantic IR artifact, identified by
    /// `SemanticArtifactKey::fingerprint`.
    SemanticArtifact,
    /// One reusable procedure summary, identified by
    /// `ProcedureSummaryKey::fingerprint`.
    ProcedureSummary,
    /// One content-keyed value-flow or taint snapshot.
    FlowSnapshot,
    /// One canonical policy report.
    PolicyReport,
    /// One snapshot-owned complete derived query layer, such as the
    /// project-local direct import topology.
    DerivedQueryLayer,
    /// One complete workspace usage-ranking graph, scoped to the ecosystems it
    /// was built for.
    WorkspaceUsageGraph,
    /// One immutable structural posting index for a single language.
    StructuralIndex,
    /// One policy evaluation unit, identified by the digest of the read set it
    /// recorded.
    ///
    /// A unit is derived from its recorded inputs exactly as an IR artifact is
    /// derived from a file revision, so a verdict about one is the same kind of
    /// statement; naming it by its read-set digest is checkout-independent
    /// because every read key is.
    PolicyEvaluationUnit,
}

impl DerivedArtifactKind {
    /// The stable label used in diagnostics and, later, in persisted rows.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::SemanticArtifact => "semantic_artifact",
            Self::ProcedureSummary => "procedure_summary",
            Self::FlowSnapshot => "flow_snapshot",
            Self::PolicyReport => "policy_report",
            Self::DerivedQueryLayer => "derived_query_layer",
            Self::WorkspaceUsageGraph => "workspace_usage_graph",
            Self::StructuralIndex => "structural_index",
            Self::PolicyEvaluationUnit => "policy_evaluation_unit",
        }
    }
}

/// The checkout-independent identity of one derived artifact.
///
/// Construct it from the artifact family's own fingerprint. Do not invent a
/// fingerprint here: an identity a verdict names must be the same identity the
/// cache is keyed by, or the verdict describes an artifact nobody holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivedArtifactId {
    kind: DerivedArtifactKind,
    fingerprint: StableDigest,
}

impl DerivedArtifactId {
    pub const fn new(kind: DerivedArtifactKind, fingerprint: StableDigest) -> Self {
        Self { kind, fingerprint }
    }

    pub const fn semantic_artifact(fingerprint: StableDigest) -> Self {
        Self::new(DerivedArtifactKind::SemanticArtifact, fingerprint)
    }

    pub const fn procedure_summary(fingerprint: StableDigest) -> Self {
        Self::new(DerivedArtifactKind::ProcedureSummary, fingerprint)
    }

    pub const fn kind(self) -> DerivedArtifactKind {
        self.kind
    }

    pub const fn fingerprint(self) -> StableDigest {
        self.fingerprint
    }
}

impl fmt::Display for DerivedArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}",
            self.kind.stable_label(),
            self.fingerprint
        )
    }
}

/// The budget regime one derived artifact was produced under.
///
/// A bounded derivation's absences are budget artifacts, not proofs, so a
/// bounded result must not answer a request that asked for an exhaustive one.
/// The reverse direction is fine: an exhaustive result satisfies a bounded
/// request. This is the same rule `ValueFlowCache` already applies by refusing
/// to retain `ExceededBudget` and `Cancelled` outcomes; naming it here lets a
/// cache that *does* retain bounded results say why it declined to reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetMode {
    /// The derivation ran to completion within its limits.
    Exhaustive,
    /// The derivation stopped at a caller-supplied work limit.
    Bounded,
}

impl BudgetMode {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::Bounded => "bounded",
        }
    }
}

/// Why one derived artifact may not be reused.
///
/// Every variant names the artifact the verdict is about, plus the identity of
/// the one input whose movement forced the verdict. Where a variant carries a
/// pair, both halves identify that input -- never the artifact itself -- so a
/// reader can diff them without knowing which family produced the reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvalidationReason {
    /// The artifact's own source content changed.
    ///
    /// Applies when the artifact is derived directly from bytes -- a semantic
    /// IR artifact from a file revision, a policy report from a document. The
    /// digests are the content identities of that input before and after.
    /// This is the only reason that needs no dependency graph to establish, so
    /// it is the one a cache may reach for without consulting any index.
    InputContentChanged {
        artifact: DerivedArtifactId,
        before: StableDigest,
        after: StableDigest,
    },
    /// One named dependency artifact this artifact consumed moved.
    ///
    /// Applies when a reverse-dependency walk reached this artifact from a
    /// dependency whose recomputed output is *not* byte-equal to the output
    /// this artifact consumed. `dependency` names the dependency as this
    /// artifact recorded it and `recomputed` names what recomputation
    /// published in its place, so the pair is the before and after without
    /// needing a separate digest for either. When the dependency's output *is*
    /// byte-equal, the verdict is
    /// [`RetentionReason::DependencyOutputUnchanged`] instead, and telling
    /// those two apart is the whole point of recording reverse dependencies.
    DependencyArtifactChanged {
        artifact: DerivedArtifactId,
        dependency: DerivedArtifactId,
        recomputed: DerivedArtifactId,
    },
    /// One named input this artifact read moved, and the input is not itself a
    /// derived artifact.
    ///
    /// Applies when a recorded read is verified against what changed rather
    /// than against a recomputed dependency: a name-keyed index entry a changed
    /// blob rewrote, a whole-language scope whose content identity moved. There
    /// is no dependency [`DerivedArtifactId`] to name, so the input is named by
    /// the canonical digest of the read key that recorded it -- which is
    /// exactly the identity the reader wrote down.
    DependencyChanged {
        artifact: DerivedArtifactId,
        dependency: StableDigest,
    },
    /// The artifact's dependency closure fingerprint moved.
    ///
    /// Applies when the *set* of dependencies changed -- one was added,
    /// removed, or replaced -- rather than one member of a fixed set moving.
    /// A cache keyed on a closure fingerprint (`SummaryDependencyFingerprint`,
    /// `SemanticArtifactKey::dependencies`) reports this without needing to
    /// know which member is responsible; a caller that wants the member asks
    /// the reverse index and gets [`Self::DependencyArtifactChanged`].
    DependencyFingerprintChanged {
        artifact: DerivedArtifactId,
        before: StableDigest,
        after: StableDigest,
    },
    /// The schema or implementation that produced the artifact moved.
    ///
    /// Applies to a version bump the source did not cause: an adapter
    /// semantics version, an IR version, a summary schema version, a policy
    /// report schema version. Every artifact of the family rotates together,
    /// so a consumer seeing this must not attribute the invalidation to any
    /// edit. The digests identify the epoch before and after.
    EpochChanged {
        artifact: DerivedArtifactId,
        before: StableDigest,
        after: StableDigest,
    },
    /// The retained artifact was produced under a weaker budget than the
    /// request needs.
    ///
    /// Applies when identities agree but reuse would silently answer an
    /// exhaustive question with a bounded result. It is not an edit and no
    /// input moved; recomputation under the stronger budget is the repair.
    BudgetModeDiffers {
        artifact: DerivedArtifactId,
        retained: BudgetMode,
        requested: BudgetMode,
    },
    /// No reverse-dependency evidence exists for this artifact, so the answer
    /// must widen to recomputation.
    ///
    /// Applies when a consumer asked which artifacts depend on this one and
    /// the index holds nothing about it -- it was never published, the
    /// repository was cleared, or its family records no reverse edges. This is
    /// deliberately an invalidation and not a retention: an empty answer from
    /// an index that was never populated is indistinguishable from an empty
    /// answer that was proved, and treating the first as the second is exactly
    /// how an incremental run publishes a stale clean verdict.
    ReverseDependencyEvidenceMissing { artifact: DerivedArtifactId },
    /// The analyzer could not state the content identity this artifact would
    /// have to be keyed by, so the answer must widen to recomputation.
    ///
    /// Applies to the #2449 workspace-scope caches: a snapshot with no
    /// per-language content identity -- an analyzer that publishes none, a
    /// composite whose delegate cannot answer, a third-party structural
    /// provider -- cannot prove that a retained value was derived from the
    /// content in front of it. Like
    /// [`Self::ReverseDependencyEvidenceMissing`], this is deliberately an
    /// invalidation: the absence of evidence is not evidence that nothing
    /// moved, and reusing here would answer a question about content the cache
    /// has never seen. The artifact is named by its request shape with an
    /// unattested content identity, because that is exactly what is known.
    ContentIdentityEvidenceMissing { artifact: DerivedArtifactId },
    /// Nothing is retained under this artifact's identity, so there is nothing
    /// to reuse and the derivation must run.
    ///
    /// Applies to a content-keyed cache whose key is exact. A miss there is not
    /// evidence that some named input moved: it is the absence of a retained
    /// value for the content in front of the caller -- a cold cache, a value
    /// the byte budget retired, or content this process has genuinely not seen.
    /// The identity inside the artifact names that content, so a log of
    /// verdicts still says which content each rebuild was for, and no producer
    /// has to invent a "previous" digest it does not hold.
    NoRetainedArtifact { artifact: DerivedArtifactId },
}

impl InvalidationReason {
    /// The artifact this reason is about.
    pub const fn artifact(&self) -> DerivedArtifactId {
        match self {
            Self::InputContentChanged { artifact, .. }
            | Self::DependencyArtifactChanged { artifact, .. }
            | Self::DependencyChanged { artifact, .. }
            | Self::DependencyFingerprintChanged { artifact, .. }
            | Self::EpochChanged { artifact, .. }
            | Self::BudgetModeDiffers { artifact, .. }
            | Self::ReverseDependencyEvidenceMissing { artifact }
            | Self::ContentIdentityEvidenceMissing { artifact }
            | Self::NoRetainedArtifact { artifact } => *artifact,
        }
    }

    /// The stable label of this reason, for diagnostics and persisted rows.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::InputContentChanged { .. } => "input_content_changed",
            Self::DependencyArtifactChanged { .. } => "dependency_artifact_changed",
            Self::DependencyChanged { .. } => "dependency_changed",
            Self::DependencyFingerprintChanged { .. } => "dependency_fingerprint_changed",
            Self::EpochChanged { .. } => "epoch_changed",
            Self::BudgetModeDiffers { .. } => "budget_mode_differs",
            Self::ReverseDependencyEvidenceMissing { .. } => "reverse_dependency_evidence_missing",
            Self::ContentIdentityEvidenceMissing { .. } => "content_identity_evidence_missing",
            Self::NoRetainedArtifact { .. } => "no_retained_artifact",
        }
    }
}

impl fmt::Display for InvalidationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputContentChanged {
                artifact,
                before,
                after,
            } => write!(
                formatter,
                "{artifact} is invalid: its source content moved from {before} to {after}"
            ),
            Self::DependencyArtifactChanged {
                artifact,
                dependency,
                recomputed,
            } => write!(
                formatter,
                "{artifact} is invalid: dependency {dependency} was recomputed to {recomputed} with a changed output"
            ),
            Self::DependencyChanged {
                artifact,
                dependency,
            } => write!(
                formatter,
                "{artifact} is invalid: the input it recorded as {dependency} moved"
            ),
            Self::DependencyFingerprintChanged {
                artifact,
                before,
                after,
            } => write!(
                formatter,
                "{artifact} is invalid: its dependency closure moved from {before} to {after}"
            ),
            Self::EpochChanged {
                artifact,
                before,
                after,
            } => write!(
                formatter,
                "{artifact} is invalid: its producing epoch moved from {before} to {after}"
            ),
            Self::BudgetModeDiffers {
                artifact,
                retained,
                requested,
            } => write!(
                formatter,
                "{artifact} is invalid: retained under a {} budget, requested {}",
                retained.stable_label(),
                requested.stable_label()
            ),
            Self::ReverseDependencyEvidenceMissing { artifact } => write!(
                formatter,
                "{artifact} is invalid: no reverse-dependency evidence exists, so the answer widens"
            ),
            Self::ContentIdentityEvidenceMissing { artifact } => write!(
                formatter,
                "{artifact} is invalid: the analyzer states no content identity for its scope, so the answer widens"
            ),
            Self::NoRetainedArtifact { artifact } => write!(
                formatter,
                "{artifact} is invalid: nothing is retained for this content, so it must be derived"
            ),
        }
    }
}

/// Why one derived artifact may be reused unchanged.
///
/// A retention is a positive claim and needs evidence, which is why there are
/// only two ways to earn one. Neither may be inferred from the absence of an
/// invalidation reason: see
/// [`InvalidationReason::ReverseDependencyEvidenceMissing`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionReason {
    /// Every recorded input identity is byte-equal to the one the artifact was
    /// derived from.
    ///
    /// Applies to the ordinary cache hit: the key matched, so by construction
    /// nothing the key covers moved.
    InputsUnchanged { artifact: DerivedArtifactId },
    /// A dependency's identity moved, but the output this artifact consumed
    /// from it is byte-equal, so nothing this artifact reads actually changed.
    ///
    /// Applies to the case #2449 exists for: a comment, a rename of a local, a
    /// reformat inside a callee's body rotates that callee's content identity
    /// and therefore its artifact key, while the summary the caller consumed is
    /// unchanged. A cache keyed only on identity must invalidate the caller
    /// here; a cache that consults the recomputed dependency's *output* must
    /// not. `dependency` names the dependency as this artifact recorded it.
    DependencyOutputUnchanged {
        artifact: DerivedArtifactId,
        dependency: DerivedArtifactId,
    },
}

impl RetentionReason {
    /// The artifact this reason is about.
    pub const fn artifact(&self) -> DerivedArtifactId {
        match self {
            Self::InputsUnchanged { artifact }
            | Self::DependencyOutputUnchanged { artifact, .. } => *artifact,
        }
    }

    /// The stable label of this reason, for diagnostics and persisted rows.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::InputsUnchanged { .. } => "inputs_unchanged",
            Self::DependencyOutputUnchanged { .. } => "dependency_output_unchanged",
        }
    }
}

impl fmt::Display for RetentionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputsUnchanged { artifact } => {
                write!(formatter, "{artifact} is retained: no recorded input moved")
            }
            Self::DependencyOutputUnchanged {
                artifact,
                dependency,
            } => write!(
                formatter,
                "{artifact} is retained: dependency {dependency} was recomputed to a byte-equal output"
            ),
        }
    }
}

/// The reuse verdict for one derived artifact, with the reason that earned it.
///
/// A verdict is always one of the two; there is no third "unknown" state,
/// because a consumer that does not know must widen and say why with
/// [`InvalidationReason::ReverseDependencyEvidenceMissing`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactVerdict {
    Retained(RetentionReason),
    Invalidated(InvalidationReason),
}

impl ArtifactVerdict {
    /// The artifact this verdict is about.
    pub const fn artifact(&self) -> DerivedArtifactId {
        match self {
            Self::Retained(reason) => reason.artifact(),
            Self::Invalidated(reason) => reason.artifact(),
        }
    }

    /// Whether the artifact may be reused without recomputation.
    pub const fn is_retained(&self) -> bool {
        matches!(self, Self::Retained(_))
    }

    /// The stable label of the reason that earned this verdict.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Retained(reason) => reason.stable_label(),
            Self::Invalidated(reason) => reason.stable_label(),
        }
    }
}

impl fmt::Display for ArtifactVerdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retained(reason) => reason.fmt(formatter),
            Self::Invalidated(reason) => reason.fmt(formatter),
        }
    }
}

/// A bounded record of the verdicts one cache reached.
///
/// A cache that re-keys on content (#2449) has to be able to answer "why did
/// that rebuild happen?" without a debugger. Two totals answer it in
/// aggregate, and the last [`Self::MAX_RECENT`] verdicts answer it in detail;
/// the ring is bounded because a long-lived analyzer reaches a verdict on every
/// query and an unbounded log would be a leak. The log is deliberately not a
/// metric export: it is the evidence surface a diagnostic or a test reads.
#[derive(Debug, Default)]
pub struct ArtifactVerdictLog {
    state: std::sync::Mutex<ArtifactVerdictLogState>,
}

#[derive(Debug, Default)]
struct ArtifactVerdictLogState {
    retained: u64,
    invalidated: u64,
    recent: std::collections::VecDeque<ArtifactVerdict>,
}

impl ArtifactVerdictLog {
    pub const MAX_RECENT: usize = 64;

    pub fn record(&self, verdict: ArtifactVerdict) {
        let mut state = self.state.lock().expect("artifact verdict log poisoned");
        if verdict.is_retained() {
            state.retained = state.retained.saturating_add(1);
        } else {
            state.invalidated = state.invalidated.saturating_add(1);
        }
        if state.recent.len() == Self::MAX_RECENT {
            state.recent.pop_front();
        }
        state.recent.push_back(verdict);
    }

    /// How many reuse decisions this cache has earned, and how many rebuilds it
    /// has forced.
    pub fn totals(&self) -> (u64, u64) {
        let state = self.state.lock().expect("artifact verdict log poisoned");
        (state.retained, state.invalidated)
    }

    /// The most recent verdicts, oldest first.
    pub fn recent(&self) -> Vec<ArtifactVerdict> {
        let state = self.state.lock().expect("artifact verdict log poisoned");
        state.recent.iter().cloned().collect()
    }
}
