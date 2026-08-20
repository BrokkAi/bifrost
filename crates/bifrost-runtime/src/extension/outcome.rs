use super::{
    ApiStability, ExtensionApiVersion, ExtensionCapabilityId, ExtensionLimitValues,
    SemanticRelationBoundaryKind, SourceSpan, WorkspaceGeneration,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExtensionCompletion {
    Complete,
    Ambiguous,
    Unknown,
    Unsupported {
        capability: ExtensionCapabilityId,
    },
    Unproven,
    /// A caller-supplied limit stopped the work. `limit` names the dimension
    /// that was actually exhausted (`max_edges`, `max_nodes`,
    /// `max_traversal_steps`, ...), so a caller knows which number to raise;
    /// when several were exhausted it names the first one hit and the result's
    /// own boundary list enumerates the rest.
    Truncated {
        limit: Box<str>,
    },
    /// Analysis reached a genuine edge of what it can know while every
    /// caller-supplied limit still had room (#2412). Asking again with larger
    /// limits returns the same answer; the kinds say what kind of edge it was.
    ///
    /// Distinct from [`Self::Truncated`], which is caller-actionable. When both
    /// happened, `Truncated` is reported and the frontier kinds remain visible
    /// in the result value's boundary list.
    FrontierBounded {
        kinds: Box<[SemanticRelationBoundaryKind]>,
    },
    ExceededBudget {
        dimension: Box<str>,
    },
    Cancelled,
}

/// Which rungs of the information-cost ladder (issue #2414) the work behind one
/// result actually consulted.
///
/// Each field counts crossings of that tier's storage funnel observed while the
/// operation's request scope was open. **Zero means the tier was not
/// consulted**, which is the point: a consumer can see that an answer stopped
/// at the import rung and never reached the supertype or usage-graph rungs, and
/// so knows what kind of degradation it is looking at. The counts are advisory
/// (read relaxed, and a warm cache legitimately answers without a crossing);
/// they bound what was consulted from above, never from below.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionTierReport {
    /// Per-file tree-sitter parses.
    pub syntax: u64,
    /// Store reads of a file's import statements.
    pub imports: u64,
    /// Store reads of a code unit's raw supertypes.
    pub supertypes: u64,
    /// Builds of the whole-workspace usage/definition index.
    pub usage_graph: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionDiagnostic {
    pub code: Box<str>,
    pub message: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceSpan>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionWork {
    pub result_items: u64,
    pub result_bytes: u64,
    pub semantic_nodes: u64,
    pub semantic_edges: u64,
    pub source_bytes: u64,
    pub traversal_steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionResultMetadata {
    pub api: ExtensionApiVersion,
    pub operation: ExtensionCapabilityId,
    pub stability: ApiStability,
    pub generation: WorkspaceGeneration,
    pub diagnostics: Box<[ExtensionDiagnostic]>,
    pub work: ExtensionWork,
    /// The information tiers this operation's analysis consulted (#2414).
    /// Defaults to all-zero, which reads as "no tier crossing observed".
    #[serde(default)]
    pub tiers: ExtensionTierReport,
    pub limits: ExtensionLimitValues,
    pub provenance: Box<[Box<str>]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionOutcome<T> {
    pub completion: ExtensionCompletion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    pub metadata: ExtensionResultMetadata,
}
