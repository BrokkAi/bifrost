use crate::analyzer::semantic::StableDigest;
use std::fmt;

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
