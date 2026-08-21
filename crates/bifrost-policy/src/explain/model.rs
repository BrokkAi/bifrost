//! The versioned, bounded explanation schema.
//!
//! Everything a `why` or `why-not` answer publishes lives here: the node tree,
//! its stable content-derived identifiers, the explicit limits that bound it,
//! and the truncation record that states, in the crate's `*_truncated` plus
//! `omitted_*_lower_bound` convention, what the limits removed.
//!
//! # Determinism
//!
//! Two explanations built from the same inputs serialize to byte-identical
//! JSON. Nothing in the serialized model derives from a process-local counter,
//! an address, a clock, or an iteration order over a hash container: node order
//! is producer order, and a node identifier is a hash of the node's structural
//! position, its own content, and its children's identifiers.

use std::fmt;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::definition::{PolicyAnalysisType, PolicyId};
use crate::finding::{PolicyIncompleteReason, PolicySourceLocation};
use crate::finding_identity::PolicyFindingId;
use crate::identity::PolicySemanticHash;
use crate::retained::{RetainedSize, retained_extra};

use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePathError;

/// The versioned format tag every explanation document carries.
pub const POLICY_EXPLANATION_FORMAT: &str = "bifrost_policy_explanation/v1";

/// Domain separator for node identifiers. Changing the node encoding requires
/// changing this string and the format tag together.
const NODE_ID_DOMAIN: &[u8] = b"bifrost-policy-explanation-node/v1";

/// Bytes retained from a SHA-256 node digest. 128 bits is far past the
/// collision budget of a tree bounded at a few hundred nodes.
const NODE_ID_BYTES: usize = 16;

/// Which question an explanation answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationQuestion {
    /// Why does this finding exist? Projected from retained evidence only.
    Why,
    /// Why is this candidate not reported? Answered by bounded prefix
    /// re-execution of the policy selector.
    WhyNot,
}

impl ExplanationQuestion {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Why => "why",
            Self::WhyNot => "why_not",
        }
    }
}

/// What one explanation node stands for.
///
/// The five kinds slice 1 fixed are joined by one relational kind in slice 2.
/// A kind is presentation-independent: a consumer groups and filters on it
/// without parsing prose.
///
/// # Additive vocabulary
///
/// `relation_binding` was added after `bifrost_policy_explanation/v1` shipped.
/// The addition is strictly additive -- no existing node changed kind, shape,
/// or identity, and no previously emitted document contains the new tag -- so
/// the format string stays `v1` (see the ExecPlan Decision Log for issue 2439
/// slices 2-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationNodeKind {
    /// One analyzer row: a seed row, a step result, the `via` row a step
    /// travelled through, or one representative row behind an assertion.
    SourceFact,
    /// One stage of the selector pipeline: the plan source, or one typed step.
    SelectorStage,
    /// One authored relational row binding: a named relation and what its
    /// executed query said. Its children are that binding's selector stages.
    RelationBinding,
    /// One authored assertion and the verdict its aggregate produced.
    Assertion,
    /// What the run's coverage does or does not license.
    CoverageObligation,
    /// The root of the projection: the finding that exists, or the candidate
    /// that does not.
    FindingProjection,
}

impl ExplanationNodeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SourceFact => "source_fact",
            Self::SelectorStage => "selector_stage",
            Self::RelationBinding => "relation_binding",
            Self::Assertion => "assertion",
            Self::CoverageObligation => "coverage_obligation",
            Self::FindingProjection => "finding_projection",
        }
    }
}

/// What one node concluded.
///
/// `Unknown` is deliberately not a flavour of `Failed`: it states that the
/// analyzer could not decide, so a consumer must not read it as evidence of
/// absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationOutcome {
    /// The stage held, or the fact is present.
    Satisfied,
    /// The stage did not hold, and the analyzer's answer was trustworthy
    /// enough to say so.
    Failed,
    /// The analyzer could not decide. Never evidence of absence.
    Unknown,
}

impl ExplanationOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

/// A stable, content-derived node identifier.
///
/// The identifier is the first 16 bytes of a domain-separated SHA-256 over, in
/// order: the node's structural path from the root (its sibling index at each
/// level), its kind, outcome, label, expected and actual strings, exact
/// location, incomplete reasons, own truncation record, and the identifiers of
/// its retained children. Equal identifiers therefore mean equal subtrees at
/// equal positions, and no identifier depends on anything process-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExplanationNodeId([u8; NODE_ID_BYTES]);

impl ExplanationNodeId {
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_BYTES] {
        &self.0
    }
}

impl fmt::Display for ExplanationNodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ExplanationNodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl RetainedSize for ExplanationNodeId {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

/// One node of a bounded explanation tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExplanationNode {
    id: ExplanationNodeId,
    kind: ExplanationNodeKind,
    outcome: ExplanationOutcome,
    /// A short, stable, snake_case identifier for this node's role: a query
    /// step operation, a row domain, or a fixed structural label.
    label: String,
    /// What the policy asked for at this node, when stating it adds anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    /// What the analyzer actually reported at this node.
    #[serde(skip_serializing_if = "Option::is_none")]
    actual: Option<String>,
    /// The exact source location this node is about, where one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<PolicySourceLocation>,
    /// Why an `Unknown` outcome could not be decided, mapped from the query's
    /// own completion through the evaluator's existing mapping.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<PolicyIncompleteReason>,
    children: Vec<ExplanationNode>,
    children_truncated: bool,
    omitted_children_lower_bound: u64,
}

impl ExplanationNode {
    pub const fn id(&self) -> ExplanationNodeId {
        self.id
    }
    pub const fn kind(&self) -> ExplanationNodeKind {
        self.kind
    }
    pub const fn outcome(&self) -> ExplanationOutcome {
        self.outcome
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn expected(&self) -> Option<&str> {
        self.expected.as_deref()
    }
    pub fn actual(&self) -> Option<&str> {
        self.actual.as_deref()
    }
    pub const fn location(&self) -> Option<&PolicySourceLocation> {
        self.location.as_ref()
    }
    pub fn reasons(&self) -> &[PolicyIncompleteReason] {
        &self.reasons
    }
    pub fn children(&self) -> &[ExplanationNode] {
        &self.children
    }
    pub const fn children_truncated(&self) -> bool {
        self.children_truncated
    }
    pub const fn omitted_children_lower_bound(&self) -> u64 {
        self.omitted_children_lower_bound
    }

    /// Every node of this subtree in deterministic pre-order.
    pub fn walk(&self) -> Vec<&Self> {
        let mut nodes = Vec::new();
        self.push_walk(&mut nodes);
        nodes
    }

    fn push_walk<'a>(&'a self, nodes: &mut Vec<&'a Self>) {
        nodes.push(self);
        for child in &self.children {
            child.push_walk(nodes);
        }
    }
}

impl RetainedSize for ExplanationNode {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.label.capacity())
            .saturating_add(self.expected.as_ref().map_or(0, String::capacity))
            .saturating_add(self.actual.as_ref().map_or(0, String::capacity))
            .saturating_add(self.location.as_ref().map_or(0, retained_extra))
            .saturating_add(
                self.reasons
                    .capacity()
                    .saturating_mul(size_of::<PolicyIncompleteReason>()),
            )
            .saturating_add(retained_extra(&self.children))
    }
}

/// What an explanation is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExplanationSubject {
    /// A retained finding, addressed by its stable identity.
    Finding {
        finding_id: PolicyFindingId,
        location: PolicySourceLocation,
    },
    /// One explicit candidate position the caller nominated.
    Candidate {
        path: String,
        byte_start: u64,
        byte_end: u64,
    },
}

impl RetainedSize for ExplanationSubject {
    fn retained_size(&self) -> usize {
        size_of::<Self>().saturating_add(match self {
            Self::Finding { location, .. } => retained_extra(location),
            Self::Candidate { path, .. } => path.capacity(),
        })
    }
}

/// What the explicit limits removed from this explanation.
///
/// Each pair follows the crate's `*_truncated` plus `omitted_*_lower_bound`
/// convention: the flag is true exactly when the lower bound is non-zero, and
/// the bound is a lower bound because a dropped subtree is only counted as far
/// as it was built.
///
/// `omitted_nodes_lower_bound` counts every node dropped for any reason. The
/// depth, byte, and text pairs then name the specific limit that did the
/// dropping, so a caller can raise the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct ExplanationTruncation {
    nodes_truncated: bool,
    omitted_nodes_lower_bound: u64,
    depth_truncated: bool,
    omitted_depth_levels_lower_bound: u64,
    bytes_truncated: bool,
    omitted_bytes_lower_bound: u64,
    text_truncated: bool,
    omitted_text_bytes_lower_bound: u64,
}

impl ExplanationTruncation {
    pub const fn nodes_truncated(&self) -> bool {
        self.nodes_truncated
    }
    pub const fn omitted_nodes_lower_bound(&self) -> u64 {
        self.omitted_nodes_lower_bound
    }
    pub const fn depth_truncated(&self) -> bool {
        self.depth_truncated
    }
    pub const fn omitted_depth_levels_lower_bound(&self) -> u64 {
        self.omitted_depth_levels_lower_bound
    }
    pub const fn bytes_truncated(&self) -> bool {
        self.bytes_truncated
    }
    pub const fn omitted_bytes_lower_bound(&self) -> u64 {
        self.omitted_bytes_lower_bound
    }
    pub const fn text_truncated(&self) -> bool {
        self.text_truncated
    }
    pub const fn omitted_text_bytes_lower_bound(&self) -> u64 {
        self.omitted_text_bytes_lower_bound
    }

    /// True when any limit removed anything.
    pub const fn is_truncated(&self) -> bool {
        self.nodes_truncated || self.depth_truncated || self.bytes_truncated || self.text_truncated
    }

    fn omit_nodes(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.nodes_truncated = true;
        self.omitted_nodes_lower_bound = self.omitted_nodes_lower_bound.saturating_add(count);
    }

    fn omit_depth_levels(&mut self, levels: u64) {
        if levels == 0 {
            return;
        }
        self.depth_truncated = true;
        self.omitted_depth_levels_lower_bound = self.omitted_depth_levels_lower_bound.max(levels);
    }

    fn omit_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes_truncated = true;
        self.omitted_bytes_lower_bound = self.omitted_bytes_lower_bound.saturating_add(bytes);
    }

    fn omit_text_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.text_truncated = true;
        self.omitted_text_bytes_lower_bound =
            self.omitted_text_bytes_lower_bound.saturating_add(bytes);
    }
}

impl RetainedSize for ExplanationTruncation {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
    }
}

/// A complete explanation document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyExplanation {
    format: &'static str,
    question: ExplanationQuestion,
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    subject: ExplanationSubject,
    outcome: ExplanationOutcome,
    node_count: u64,
    root: ExplanationNode,
    truncation: ExplanationTruncation,
}

impl PolicyExplanation {
    pub const fn format(&self) -> &'static str {
        self.format
    }
    pub const fn question(&self) -> ExplanationQuestion {
        self.question
    }
    pub const fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }
    pub const fn policy_hash(&self) -> PolicySemanticHash {
        self.policy_hash
    }
    pub const fn analysis_type(&self) -> PolicyAnalysisType {
        self.analysis_type
    }
    pub const fn subject(&self) -> &ExplanationSubject {
        &self.subject
    }
    /// The root node's outcome, lifted so a caller can decide without walking.
    pub const fn outcome(&self) -> ExplanationOutcome {
        self.outcome
    }
    pub const fn node_count(&self) -> u64 {
        self.node_count
    }
    pub const fn root(&self) -> &ExplanationNode {
        &self.root
    }
    pub const fn truncation(&self) -> &ExplanationTruncation {
        &self.truncation
    }

    /// Every retained node in deterministic pre-order, root first.
    pub fn nodes(&self) -> Vec<&ExplanationNode> {
        self.root.walk()
    }

    /// Serialize to canonical JSON. Field order is declaration order, so two
    /// equal explanations render byte-identically.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("the explanation model is serializable")
    }
}

impl RetainedSize for PolicyExplanation {
    fn retained_size(&self) -> usize {
        size_of::<Self>()
            .saturating_add(retained_extra(&self.policy_id))
            .saturating_add(retained_extra(&self.subject))
            .saturating_add(retained_extra(&self.root))
    }
}

/// Explicit bounds on one explanation.
///
/// Every bound is enforced by construction, and every enforcement is reported
/// through [`ExplanationTruncation`]. A caller that raises a bound gets more
/// nodes; a caller that lowers one gets a smaller but still well-formed and
/// still honestly-labelled document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplanationLimits {
    max_nodes: usize,
    max_depth: usize,
    max_children_per_node: usize,
    max_retained_bytes: usize,
    max_text_bytes: usize,
    max_prefix_executions: usize,
}

impl Default for ExplanationLimits {
    fn default() -> Self {
        Self {
            max_nodes: 256,
            max_depth: 8,
            max_children_per_node: 64,
            max_retained_bytes: 64 * 1024,
            max_text_bytes: 512,
            // MAX_QUERY_STEPS is 16, so one selector's source plus every step
            // fits in 17 executions. A relational plan's row bindings share
            // this one total, so the default holds three full-depth bindings
            // and truncates honestly beyond that.
            max_prefix_executions: 64,
        }
    }
}

impl ExplanationLimits {
    /// The root counts as depth 1, so `max_depth` is a level count.
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }
    pub const fn max_nodes(&self) -> usize {
        self.max_nodes
    }
    pub const fn max_children_per_node(&self) -> usize {
        self.max_children_per_node
    }
    pub const fn max_retained_bytes(&self) -> usize {
        self.max_retained_bytes
    }
    pub const fn max_text_bytes(&self) -> usize {
        self.max_text_bytes
    }
    /// How many bounded prefix queries `why-not` may execute.
    pub const fn max_prefix_executions(&self) -> usize {
        self.max_prefix_executions
    }

    #[must_use]
    pub const fn with_max_nodes(mut self, value: usize) -> Self {
        self.max_nodes = value;
        self
    }
    #[must_use]
    pub const fn with_max_depth(mut self, value: usize) -> Self {
        self.max_depth = value;
        self
    }
    #[must_use]
    pub const fn with_max_children_per_node(mut self, value: usize) -> Self {
        self.max_children_per_node = value;
        self
    }
    #[must_use]
    pub const fn with_max_retained_bytes(mut self, value: usize) -> Self {
        self.max_retained_bytes = value;
        self
    }
    #[must_use]
    pub const fn with_max_text_bytes(mut self, value: usize) -> Self {
        self.max_text_bytes = value;
        self
    }
    #[must_use]
    pub const fn with_max_prefix_executions(mut self, value: usize) -> Self {
        self.max_prefix_executions = value;
        self
    }
}

/// Which explicit bound could not accommodate even the mandatory root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationBudgetLimit {
    Nodes,
    Depth,
    RetainedBytes,
    PrefixExecutions,
}

impl ExplanationBudgetLimit {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nodes => "max_nodes",
            Self::Depth => "max_depth",
            Self::RetainedBytes => "max_retained_bytes",
            Self::PrefixExecutions => "max_prefix_executions",
        }
    }
}

/// The analysis families [`super::explain_finding`] can answer `why` for.
///
/// Published as data so a caller -- and the adapter-unavailable error itself --
/// can state what *is* supported instead of only what is not.
pub const WHY_ADAPTER_ANALYSIS_TYPES: &[PolicyAnalysisType] =
    &[PolicyAnalysisType::Match, PolicyAnalysisType::Assertion];

/// The analysis families [`super::explain_candidate`] can answer `why-not` for.
pub const WHY_NOT_ADAPTER_ANALYSIS_TYPES: &[PolicyAnalysisType] =
    &[PolicyAnalysisType::Match, PolicyAnalysisType::Assertion];

/// Why an explanation could not be produced.
///
/// Every variant is a stated, recoverable condition. In particular, asking for
/// an explanation of a policy family whose adapter is not written yet is an
/// error value, never a panic (issue 2439).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    /// No retained finding in the run carries this identity.
    FindingNotFound { finding: PolicyFindingId },
    /// This policy family has no explanation adapter for this question yet.
    ///
    /// `supported` names the families that *do* have one, so a caller learns
    /// the whole answer from one error rather than by probing.
    ExplanationAdapterUnavailable {
        analysis_type: PolicyAnalysisType,
        question: ExplanationQuestion,
        supported: Vec<PolicyAnalysisType>,
    },
    /// The loaded match policy carries no `/analysis/selector`.
    SelectorUnavailable,
    /// The loaded assertion policy carries no relational row plan, so it has
    /// no row bindings a candidate could be tested against.
    RelationalPlanUnavailable,
    /// The relational plan names a binding whose resolved selector is missing.
    BindingSelectorUnavailable { binding: String },
    /// The nominated candidate path is not a workspace-relative path.
    CandidateOutsideWorkspace {
        path: String,
        reason: WorkspaceRelativePathError,
    },
    /// The nominated candidate range ends before it starts.
    ReversedCandidateRange { start: u64, end: u64 },
    /// The limits cannot hold even the mandatory root of an explanation.
    BudgetExhausted { limit: ExplanationBudgetLimit },
    /// The host could not load, select, or evaluate the policy an explanation
    /// was requested for. The message is diagnostic text, never parsed.
    PolicyUnavailable { message: String },
    /// The selection named more than one policy. An explanation is about one
    /// policy, so the caller must narrow it.
    AmbiguousPolicySelection { selected: usize },
}

impl ExplainError {
    /// The adapter-unavailable condition for one question, carrying the list
    /// of families that question *does* support.
    pub fn adapter_unavailable(
        analysis_type: PolicyAnalysisType,
        question: ExplanationQuestion,
    ) -> Self {
        let supported = match question {
            ExplanationQuestion::Why => WHY_ADAPTER_ANALYSIS_TYPES,
            ExplanationQuestion::WhyNot => WHY_NOT_ADAPTER_ANALYSIS_TYPES,
        };
        Self::ExplanationAdapterUnavailable {
            analysis_type,
            question,
            supported: supported.to_vec(),
        }
    }
}

impl fmt::Display for ExplainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FindingNotFound { finding } => {
                write!(
                    formatter,
                    "the run retains no finding with identity {finding}"
                )
            }
            Self::ExplanationAdapterUnavailable {
                analysis_type,
                question,
                supported,
            } => {
                let supported = supported
                    .iter()
                    .map(|analysis_type| analysis_type.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    formatter,
                    "a {} explanation adapter for {} policies is not yet implemented; \
                     supported analysis types: {supported}",
                    question.label(),
                    analysis_type.label()
                )
            }
            Self::SelectorUnavailable => {
                formatter.write_str("the loaded match policy carries no resolved selector")
            }
            Self::RelationalPlanUnavailable => {
                formatter.write_str("the loaded assertion policy carries no relational row plan")
            }
            Self::BindingSelectorUnavailable { binding } => write!(
                formatter,
                "the relational plan's binding `{binding}` carries no resolved selector"
            ),
            Self::CandidateOutsideWorkspace { path, reason } => write!(
                formatter,
                "candidate path {path:?} is not inside the workspace: {reason}"
            ),
            Self::ReversedCandidateRange { start, end } => write!(
                formatter,
                "candidate byte range start {start} exceeds end {end}"
            ),
            Self::BudgetExhausted { limit } => write!(
                formatter,
                "the explanation limit {} cannot hold a minimal explanation",
                limit.label()
            ),
            Self::PolicyUnavailable { message } => write!(
                formatter,
                "the policy an explanation was requested for is unavailable: {message}"
            ),
            Self::AmbiguousPolicySelection { selected } => write!(
                formatter,
                "an explanation is about one policy, but the selection named {selected}"
            ),
        }
    }
}

impl std::error::Error for ExplainError {}

/// An unbounded node under construction. Producers build these freely; the
/// limits are applied once, in [`build_explanation`].
#[derive(Debug, Clone)]
pub(super) struct RawNode {
    pub(super) kind: ExplanationNodeKind,
    pub(super) outcome: ExplanationOutcome,
    pub(super) label: String,
    pub(super) expected: Option<String>,
    pub(super) actual: Option<String>,
    pub(super) location: Option<PolicySourceLocation>,
    pub(super) reasons: Vec<PolicyIncompleteReason>,
    pub(super) children: Vec<RawNode>,
    /// Set by a producer when the *source* it projected was itself truncated,
    /// for example a finding whose retained provenance was cut short. The
    /// limits below may add to it; they never clear it.
    pub(super) children_truncated: bool,
    pub(super) omitted_children_lower_bound: u64,
}

impl RawNode {
    pub(super) fn new(
        kind: ExplanationNodeKind,
        outcome: ExplanationOutcome,
        label: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            outcome,
            label: label.into(),
            expected: None,
            actual: None,
            location: None,
            reasons: Vec::new(),
            children: Vec::new(),
            children_truncated: false,
            omitted_children_lower_bound: 0,
        }
    }

    #[must_use]
    pub(super) fn with_expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    #[must_use]
    pub(super) fn with_actual(mut self, actual: impl Into<String>) -> Self {
        self.actual = Some(actual.into());
        self
    }

    #[must_use]
    pub(super) fn with_location(mut self, location: Option<PolicySourceLocation>) -> Self {
        self.location = location;
        self
    }

    #[must_use]
    pub(super) fn with_reasons(mut self, mut reasons: Vec<PolicyIncompleteReason>) -> Self {
        reasons.sort();
        reasons.dedup();
        self.reasons = reasons;
        self
    }

    #[must_use]
    pub(super) fn with_source_truncation(mut self, truncated: bool, omitted: u64) -> Self {
        self.children_truncated |= truncated;
        self.omitted_children_lower_bound =
            self.omitted_children_lower_bound.saturating_add(omitted);
        self
    }

    pub(super) fn push_child(&mut self, child: Self) {
        self.children.push(child);
    }

    fn subtree_nodes(&self) -> u64 {
        self.children.iter().fold(1, |total, child| {
            total.saturating_add(child.subtree_nodes())
        })
    }

    fn subtree_depth(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(Self::subtree_depth)
            .max()
            .unwrap_or(0)
    }

    fn own_bytes(&self) -> usize {
        size_of::<ExplanationNode>()
            .saturating_add(self.label.len())
            .saturating_add(self.expected.as_ref().map_or(0, String::len))
            .saturating_add(self.actual.as_ref().map_or(0, String::len))
            .saturating_add(self.location.as_ref().map_or(0, |location| {
                size_of::<PolicySourceLocation>().saturating_add(location.path().len())
            }))
            .saturating_add(
                self.reasons
                    .len()
                    .saturating_mul(size_of::<PolicyIncompleteReason>()),
            )
    }

    fn subtree_bytes(&self) -> u64 {
        self.children.iter().fold(
            u64::try_from(self.own_bytes()).unwrap_or(u64::MAX),
            |total, child| total.saturating_add(child.subtree_bytes()),
        )
    }
}

/// Apply the limits, then mint identifiers.
pub(super) fn build_explanation(
    question: ExplanationQuestion,
    policy_id: PolicyId,
    policy_hash: PolicySemanticHash,
    analysis_type: PolicyAnalysisType,
    subject: ExplanationSubject,
    root: RawNode,
    limits: &ExplanationLimits,
) -> Result<PolicyExplanation, ExplainError> {
    if limits.max_nodes == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::Nodes,
        });
    }
    if limits.max_depth == 0 {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::Depth,
        });
    }
    let outcome = root.outcome;
    let mut bounded = Bounded {
        limits,
        nodes_used: 0,
        bytes_used: 0,
        truncation: ExplanationTruncation::default(),
    };
    let Some(retained) = bounded.retain(root, 1) else {
        return Err(ExplainError::BudgetExhausted {
            limit: ExplanationBudgetLimit::RetainedBytes,
        });
    };
    let truncation = bounded.truncation;
    let node_count = u64::try_from(bounded.nodes_used).unwrap_or(u64::MAX);
    let root = assign_ids(retained, &mut Vec::new());
    Ok(PolicyExplanation {
        format: POLICY_EXPLANATION_FORMAT,
        question,
        policy_id,
        policy_hash,
        analysis_type,
        subject,
        outcome,
        node_count,
        root,
        truncation,
    })
}

/// A node that survived the limits but has no identifier yet.
#[derive(Debug)]
struct RetainedRaw {
    kind: ExplanationNodeKind,
    outcome: ExplanationOutcome,
    label: String,
    expected: Option<String>,
    actual: Option<String>,
    location: Option<PolicySourceLocation>,
    reasons: Vec<PolicyIncompleteReason>,
    children: Vec<RetainedRaw>,
    children_truncated: bool,
    omitted_children_lower_bound: u64,
}

struct Bounded<'a> {
    limits: &'a ExplanationLimits,
    nodes_used: usize,
    bytes_used: usize,
    truncation: ExplanationTruncation,
}

impl Bounded<'_> {
    /// Retain one node and, recursively, as much of its subtree as the limits
    /// allow. Returns `None` when this node itself could not be retained; the
    /// caller then records the loss against its own child counters.
    fn retain(&mut self, mut node: RawNode, depth: usize) -> Option<RetainedRaw> {
        if depth > self.limits.max_depth {
            self.truncation.omit_nodes(node.subtree_nodes());
            self.truncation.omit_depth_levels(
                u64::try_from(
                    depth
                        .saturating_add(node.subtree_depth())
                        .saturating_sub(1)
                        .saturating_sub(self.limits.max_depth),
                )
                .unwrap_or(u64::MAX),
            );
            return None;
        }
        if self.nodes_used >= self.limits.max_nodes {
            self.truncation.omit_nodes(node.subtree_nodes());
            return None;
        }
        self.truncate_text(&mut node.label);
        if let Some(expected) = node.expected.as_mut() {
            self.truncate_text(expected);
        }
        if let Some(actual) = node.actual.as_mut() {
            self.truncate_text(actual);
        }
        let own_bytes = node.own_bytes();
        if self.bytes_used.saturating_add(own_bytes) > self.limits.max_retained_bytes {
            self.truncation.omit_nodes(node.subtree_nodes());
            self.truncation.omit_bytes(node.subtree_bytes());
            return None;
        }
        self.nodes_used = self.nodes_used.saturating_add(1);
        self.bytes_used = self.bytes_used.saturating_add(own_bytes);

        let mut children_truncated = node.children_truncated;
        let mut omitted_children = node.omitted_children_lower_bound;
        let mut children = Vec::new();
        for (index, child) in node.children.into_iter().enumerate() {
            if index >= self.limits.max_children_per_node {
                children_truncated = true;
                omitted_children = omitted_children.saturating_add(1);
                self.truncation.omit_nodes(child.subtree_nodes());
                continue;
            }
            match self.retain(child, depth.saturating_add(1)) {
                Some(child) => children.push(child),
                None => {
                    children_truncated = true;
                    omitted_children = omitted_children.saturating_add(1);
                }
            }
        }
        Some(RetainedRaw {
            kind: node.kind,
            outcome: node.outcome,
            label: node.label,
            expected: node.expected,
            actual: node.actual,
            location: node.location,
            reasons: node.reasons,
            children,
            children_truncated,
            omitted_children_lower_bound: omitted_children,
        })
    }

    fn truncate_text(&mut self, text: &mut String) {
        if text.len() <= self.limits.max_text_bytes {
            return;
        }
        let mut cut = self.limits.max_text_bytes;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        let omitted = u64::try_from(text.len().saturating_sub(cut)).unwrap_or(u64::MAX);
        text.truncate(cut);
        self.truncation.omit_text_bytes(omitted);
    }
}

fn assign_ids(mut node: RetainedRaw, path: &mut Vec<u32>) -> ExplanationNode {
    let raw_children = std::mem::take(&mut node.children);
    let mut children = Vec::with_capacity(raw_children.len());
    for (index, child) in raw_children.into_iter().enumerate() {
        path.push(u32::try_from(index).unwrap_or(u32::MAX));
        children.push(assign_ids(child, path));
        path.pop();
    }
    let id = node_id(path, &node, &children);
    ExplanationNode {
        id,
        kind: node.kind,
        outcome: node.outcome,
        label: node.label,
        expected: node.expected,
        actual: node.actual,
        location: node.location,
        reasons: node.reasons,
        children,
        children_truncated: node.children_truncated,
        omitted_children_lower_bound: node.omitted_children_lower_bound,
    }
}

fn node_id(path: &[u32], node: &RetainedRaw, children: &[ExplanationNode]) -> ExplanationNodeId {
    let mut hasher = Sha256::new();
    hasher.update(NODE_ID_DOMAIN);
    write_len(&mut hasher, path.len());
    for index in path {
        hasher.update(index.to_be_bytes());
    }
    write_field(&mut hasher, node.kind.label().as_bytes());
    write_field(&mut hasher, node.outcome.label().as_bytes());
    write_field(&mut hasher, node.label.as_bytes());
    write_optional_field(&mut hasher, node.expected.as_deref());
    write_optional_field(&mut hasher, node.actual.as_deref());
    match &node.location {
        Some(location) => {
            hasher.update([1u8]);
            write_field(&mut hasher, location.path().as_bytes());
            match location.byte_span() {
                Some(span) => {
                    hasher.update([1u8]);
                    hasher.update(span.start().to_be_bytes());
                    hasher.update(span.end().to_be_bytes());
                }
                None => hasher.update([0u8]),
            }
            match location.region() {
                Some(region) => {
                    hasher.update([1u8]);
                    hasher.update(region.start_line().to_be_bytes());
                    hasher.update(region.start_column().to_be_bytes());
                    hasher.update(region.end_line().to_be_bytes());
                    hasher.update(region.end_column().to_be_bytes());
                }
                None => hasher.update([0u8]),
            }
        }
        None => hasher.update([0u8]),
    }
    write_len(&mut hasher, node.reasons.len());
    for reason in &node.reasons {
        write_field(&mut hasher, reason.label().as_bytes());
    }
    hasher.update([u8::from(node.children_truncated)]);
    hasher.update(node.omitted_children_lower_bound.to_be_bytes());
    write_len(&mut hasher, children.len());
    for child in children {
        hasher.update(child.id.as_bytes());
    }
    let digest = hasher.finalize();
    let mut id = [0u8; NODE_ID_BYTES];
    id.copy_from_slice(&digest[..NODE_ID_BYTES]);
    ExplanationNodeId(id)
}

fn write_len(hasher: &mut Sha256, len: usize) {
    hasher.update(u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes());
}

fn write_field(hasher: &mut Sha256, bytes: &[u8]) {
    write_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn write_optional_field(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            write_field(hasher, value.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}
