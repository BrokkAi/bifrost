use super::*;
use schemars::JsonSchema;

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryProcedure {
    pub id: String,
    pub artifact_id: String,
    pub path: String,
    pub language: &'static str,
    /// The artifact's exact parser and semantic dialect (for example `cpp-c`).
    pub dialect: &'static str,
    pub procedure_kind: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryProgramPoint {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<CodeQueryProgramPointBoundary>,
    pub event_count: usize,
    pub evidence: CodeQuerySemanticEvidence,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryControlEdge {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub edge_kind: &'static str,
    pub source: CodeQueryProgramPointRef,
    pub target: CodeQueryProgramPointRef,
    pub evidence: CodeQuerySemanticEvidence,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTypestateSubject {
    pub class: String,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryTypestateFindingKind {
    ErrorTransition {
        event: String,
        from_state: String,
        to_state: String,
    },
    TerminalExpectation {
        expectation: String,
        actual_states: Vec<String>,
    },
}

impl CodeQueryTypestateFindingKind {
    pub(super) fn presentation_label(&self) -> String {
        match self {
            Self::ErrorTransition {
                event,
                from_state,
                to_state,
            } => format!("{event}: {from_state} -> {to_state}"),
            Self::TerminalExpectation {
                expectation,
                actual_states,
            } => format!("{expectation}: actual {}", actual_states.join(", ")),
        }
    }
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryTypestateCertainty {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    May,
    Must,
    Inconclusive,
}

impl CodeQueryTypestateCertainty {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::May => "may",
            Self::Must => "must",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryTypestateUncertainty {
    AmbiguousDispatch,
    UnknownCall,
    ExternalCall,
    Escape,
    IncompleteAnalysis,
    UnmatchedEvent,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTypestateFinding {
    pub id: String,
    pub protocol_ref: String,
    pub protocol_hash: String,
    pub binding_plan_hash: String,
    pub subject: CodeQueryTypestateSubject,
    pub finding_kind: CodeQueryTypestateFindingKind,
    pub certainty: CodeQueryTypestateCertainty,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub path_proven: bool,
    pub path_complete: bool,
    pub analysis_complete: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub uncertainty: Vec<CodeQueryTypestateUncertainty>,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub abstained: bool,
    pub retained_witnesses: usize,
    pub omitted_witnesses: usize,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryTypestateWitnessStepKind {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Seed,
    Edge {
        edge_kind: &'static str,
    },
    EndSummaryGap {
        return_kind: &'static str,
    },
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTypestateWitnessStep {
    pub kind: CodeQueryTypestateWitnessStepKind,
    pub source: CodeQuerySourceSite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<CodeQuerySourceSite>,
    pub evidence: CodeQuerySemanticEvidence,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTypestateWitness {
    pub id: String,
    pub finding_id: String,
    pub protocol_ref: String,
    pub protocol_hash: String,
    pub binding_plan_hash: String,
    pub subject: CodeQueryTypestateSubject,
    pub witness_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_state: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub uncertainty: Vec<CodeQueryTypestateUncertainty>,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub abstained: bool,
    pub steps: Vec<CodeQueryTypestateWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub retention_truncated: bool,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowReachability {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Reached,
    NotReached,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowCertainty {
    Exact,
    May,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowStatus {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Complete,
    Partial,
    Ambiguous,
    Unknown,
    Unproven,
    Unsupported,
    SemanticBudgetExhausted,
    SolverBudgetExhausted,
    SemanticCancelled,
    SolverCancelled,
    QueryCancelled,
}

impl CodeQueryFlowStatus {
    /// The stable public flow-row status domain. These labels describe the
    /// client-visible outcome rather than mirroring the internal solver enum.
    pub const LABELS: &'static [&'static str] = &[
        "complete",
        "partial",
        "ambiguous",
        "unknown",
        "unproven",
        "unsupported",
        "semantic_budget_exhausted",
        "solver_budget_exhausted",
        "semantic_cancelled",
        "solver_cancelled",
        "query_cancelled",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
            Self::Unproven => "unproven",
            Self::Unsupported => "unsupported",
            Self::SemanticBudgetExhausted => "semantic_budget_exhausted",
            Self::SolverBudgetExhausted => "solver_budget_exhausted",
            Self::SemanticCancelled => "semantic_cancelled",
            Self::SolverCancelled => "solver_cancelled",
            Self::QueryCancelled => "query_cancelled",
        }
    }
}

impl Serialize for CodeQueryFlowStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.label())
    }
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFlowEvent {
    pub id: String,
    pub site: CodeQueryFlowSymbolSite,
    pub path: String,
    pub range: CodeQueryRange,
    pub phase: &'static str,
    pub ordinal: u32,
    pub carrier: CodeQueryFlowCarrierSymbol,
}

/// One stable source-backed locator used by a public value-flow symbol.
///
/// `id` deliberately omits the workspace mount and every run-local dense ID.
/// The declaration path retains enough structure to distinguish anonymous or
/// same-named declarations that share a source range.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFlowSymbolSite {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub declaration: Vec<CodeQueryFlowDeclarationSegment>,
    pub role: &'static str,
    pub start_byte: u32,
    pub end_byte: u32,
    pub occurrence: u32,
    pub range: CodeQueryRange,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFlowDeclarationSegment {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_byte: u32,
    pub end_byte: u32,
    pub occurrence: u32,
    pub sibling_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowPortSymbol {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    IndexedNormalReturn { ordinal: u32 },
    ExceptionalReturn,
    Capture { slot: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowSelectorSymbol {
    Field {
        field: CodeQueryFlowSymbolSite,
    },
    Property {
        key: String,
    },
    ExactIndex {
        index: Box<CodeQueryFlowCarrierSymbol>,
    },
    ConstantIndex {
        /// Decimal magnitude. A string preserves every IR-supported `u128`
        /// value across JSON implementations without precision loss.
        index: String,
    },
    AnyIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowCarrierSymbol {
    Value {
        id: String,
        site: CodeQueryFlowSymbolSite,
        role: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ordinal: Option<u32>,
    },
    Port {
        id: String,
        procedure: CodeQueryFlowSymbolSite,
        port: CodeQueryFlowPortSymbol,
    },
    Allocation {
        id: String,
        site: CodeQueryFlowSymbolSite,
    },
    CallResult {
        id: String,
        call: CodeQueryFlowSymbolSite,
        result: Box<CodeQueryFlowCarrierSymbol>,
        callee: CodeQueryFlowSymbolSite,
    },
    ScopedRoot {
        id: String,
        root_kind: &'static str,
        site: CodeQueryFlowSymbolSite,
    },
    RuntimeObject {
        id: String,
        runtime_profile_digest: String,
        realm: String,
        exposure_id: String,
        container_member: String,
        state_boundary: String,
        refinement_identity: String,
        active_model_set_hash: String,
        manifest_digest: String,
        shard_id: String,
        behavior_id: String,
        activation_source: String,
    },
    Location {
        id: String,
        root: Box<CodeQueryFlowCarrierSymbol>,
        selectors: Vec<CodeQueryFlowSelectorSymbol>,
        exact: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowFactSymbol {
    Zero,
    Carrier {
        source: Box<CodeQueryFlowEvent>,
        carrier: Box<CodeQueryFlowCarrierSymbol>,
        #[serde(skip_serializing_if = "is_false")]
        #[schemars(default)]
        uncertain: bool,
    },
    Meeting {
        source: Box<CodeQueryFlowEvent>,
        sink: Box<CodeQueryFlowEvent>,
        #[serde(skip_serializing_if = "is_false")]
        #[schemars(default)]
        uncertain: bool,
    },
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFlowEndpoint {
    pub id: String,
    pub plan_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CodeQueryFlowEvent>,
    pub sink: CodeQueryFlowEvent,
    pub reachability: CodeQueryFlowReachability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certainty: Option<CodeQueryFlowCertainty>,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub ambiguous: bool,
    pub status: CodeQueryFlowStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub path_qualities: Vec<CodeQuerySemanticEvidence>,
    pub retained_witnesses: usize,
    pub omitted_witnesses: usize,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryFlowWitnessStepKind {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Seed,
    Edge {
        edge_kind: &'static str,
    },
    EndSummaryGap {
        return_kind: &'static str,
    },
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFlowWitnessStep {
    pub kind: CodeQueryFlowWitnessStepKind,
    pub source: CodeQuerySourceSite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_symbol: Option<CodeQueryFlowSymbolSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_symbol: Option<CodeQueryFlowSymbolSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_symbol: Option<CodeQueryFlowSymbolSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<CodeQueryFlowFactSymbol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<CodeQueryFlowFactSymbol>,
    pub evidence: CodeQuerySemanticEvidence,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFlowWitness {
    pub id: String,
    pub endpoint_id: String,
    pub plan_ref: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub retention_truncated: bool,
}

/// One class atom that reached one member-access receiver when class-set
/// propagation ran from the query's input procedure. `origin` is `workspace`
/// for a workspace class, `external` for a semantic-pack class, or
/// `unknown:<reason>` for a value the engine could not classify; an unknown
/// origin carries no `class`, and a row whose `status` is not `known` carries
/// no proof.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryClassSetRow {
    pub id: String,
    pub file: String,
    pub range: CodeQueryRange,
    pub member: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    pub origin: String,
    pub status: &'static str,
    /// True when membership follows only from guarding an unmodeled producer.
    /// Absent for unknown atoms; false does not prove full path feasibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_only: Option<bool>,
}

/// A member access whose receiver may hold a class that does not declare the
/// member. `origin_file`/`origin_range` name the site that introduced the
/// class; `caller` is the root procedure the propagation ran from;
/// `witness_steps` counts the retained path steps.
///
/// `proof` is `proven` when the receiver class set is fully known, and
/// `conditional` when the class certainly reaches the access and lacks the
/// member while an allowed remainder stays open. Remainders may include other
/// unclassified receiver values, listed global writes whose receiver and name
/// are unbounded, or a declared parameter admitted by a single closed
/// workspace-class annotation. The row lists its `remainders` (empty for a
/// proven row) and states the assumptions in `condition` as one plain sentence.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryAbsentMemberFinding {
    pub id: String,
    pub file: String,
    pub range: CodeQueryRange,
    pub member: String,
    pub class: String,
    pub origin_file: String,
    pub origin_range: CodeQueryRange,
    pub caller: String,
    pub witness_steps: usize,
    pub proof: &'static str,
    pub remainders: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Later accesses made unreachable by the reported access raising.
    pub also_fails_at: Vec<String>,
    /// Exact byte and display locations retained for policy related locations.
    #[serde(skip)]
    #[schemars(skip)]
    pub(crate) also_fails_at_locations: Vec<CodeQuerySourceSpan>,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryAbsentMemberWitnessStatus {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Available,
    Truncated,
    Unavailable,
}

impl CodeQueryAbsentMemberWitnessStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Truncated => "truncated",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One bounded retained path (or an explicit unavailable marker) for an
/// absent-member finding. The finding itself remains independently Proven;
/// `witness_status` describes only this evidence sidecar.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryAbsentMemberWitness {
    pub id: String,
    pub finding_id: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub retention_truncated: bool,
    pub witness_status: CodeQueryAbsentMemberWitnessStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

/// One bounded source occurrence contributing to an aggregated taint sink.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTaintOrigin {
    pub id: String,
    pub event_id: String,
    pub labels: Vec<String>,
    pub site: CodeQuerySourceSite,
}

/// One bounded witness owned by an aggregated taint finding.
///
/// Steps reuse the source-backed flow witness representation. The envelope is
/// taint-specific because one finding can aggregate several origins and is not
/// itself a registered value-flow endpoint.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTaintWitness {
    pub id: String,
    pub finding_id: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub retention_truncated: bool,
    /// Stable label of the exact first cause when `truncated` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation_cause: Option<String>,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryTaintProjectionLimits {
    pub max_origins_per_finding: usize,
    pub max_witnesses_per_finding: usize,
    pub max_steps_per_witness: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTaintProjectionLimits {
    pub const fn new(
        max_origins_per_finding: usize,
        max_witnesses_per_finding: usize,
        max_steps_per_witness: usize,
        max_witness_bytes: usize,
    ) -> Self {
        Self {
            max_origins_per_finding,
            max_witnesses_per_finding,
            max_steps_per_witness,
            max_witness_bytes,
        }
    }
}

/// Diagnostic-neutral public projection of one retained taint finding.
///
/// Flow witness steps deliberately reuse [`CodeQueryFlowWitnessStep`]; this
/// envelope adds only taint-specific aggregation that a flow endpoint cannot
/// represent.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTaintFinding {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub sink_event_id: String,
    pub sink: CodeQuerySourceSite,
    pub reached_labels: Vec<String>,
    pub origins: Vec<CodeQueryTaintOrigin>,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub origins_truncated: bool,
    pub witnesses: Vec<CodeQueryTaintWitness>,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub witnesses_truncated: bool,
    pub evidence: CodeQuerySemanticEvidence,
    #[serde(skip_serializing_if = "is_false")]
    #[schemars(default)]
    pub ambiguous: bool,
}

/// The scope-free content of one taint finding: its sink site, reached labels,
/// and each origin's site and labels.
pub type CodeQueryTaintFindingKey = (
    CodeQuerySourceSite,
    Vec<String>,
    Vec<(CodeQuerySourceSite, Vec<String>)>,
);

impl CodeQueryTaintFinding {
    /// Identifies one leak across projections. The `id` fields are not usable
    /// for this: they hash the projection scope, which names one root's
    /// propagation semantics, so each root that reaches a sink gives it a
    /// different id.
    pub fn content_key(&self) -> CodeQueryTaintFindingKey {
        let mut origins = self
            .origins
            .iter()
            .map(|origin| (origin.site.clone(), origin.labels.clone()))
            .collect::<Vec<_>>();
        origins.sort();
        (self.sink.clone(), self.reached_labels.clone(), origins)
    }
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryProgramPointRef {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<CodeQueryProgramPointBoundary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryProgramPointBoundary {
    Entry,
    NormalExit,
    ExceptionalExit,
}

impl CodeQueryProgramPointBoundary {
    /// The label a point with no boundary role publishes: it is neither the
    /// entry nor either exit, so it lies in the procedure's interior.
    pub const INTERIOR: &'static str = "interior";

    /// The value domain of the `program_point.boundary` row column: the three
    /// boundary labels plus the interior label an absent boundary renders as
    /// (issue #2515). A relational policy compares the column against a bare
    /// label, so the label an absent boundary takes has to be in the domain.
    pub const LABELS: &'static [&'static str] =
        &["entry", "normal_exit", "exceptional_exit", Self::INTERIOR];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::NormalExit => "normal_exit",
            Self::ExceptionalExit => "exceptional_exit",
        }
    }

    /// The row label of an optional boundary: the boundary's own label, or
    /// `interior` when the point carries none.
    pub const fn row_label(boundary: Option<Self>) -> &'static str {
        match boundary {
            Some(boundary) => boundary.label(),
            None => Self::INTERIOR,
        }
    }
}

/// One control relation between two program points of one procedure (#2443).
///
/// `source` and `target` are rendered inline for the same reason a flow
/// relation renders its endpoints: a relation is unreadable without knowing
/// which two points it names. Their `id` fields are the same wire ids the
/// `program_point` rows publish, which is what a policy joins on.
///
/// `exit_partition` is not decoration. Postdominance and control dependence
/// mean different things over different exit universes, and the derivation
/// computes exactly one of them, so the row states which. Dominance,
/// reachability and loop membership are forward claims that do not depend on
/// the exits; they carry the same label because they were computed over the
/// same single whole-procedure universe, never as a claim about exits.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryControlRelation {
    pub id: String,
    /// The wire identity of the procedure whose control-flow graph the relation
    /// is drawn in; equal to a `procedure` row's `id`.
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    /// The relation's own display anchor: its target point.
    pub range: CodeQueryRange,
    /// `dominates`, `postdominates`, `control_depends_on`, `reachable`, or
    /// `in_loop`.
    pub relation: &'static str,
    /// `exact` when the relation holds on every path, `may` otherwise.
    pub certainty: &'static str,
    /// The exit universe a backward claim was computed against.
    pub exit_partition: &'static str,
    pub source: CodeQueryProgramPointRef,
    pub target: CodeQueryProgramPointRef,
    /// The branch edge whose outcome governs the target, present exactly for a
    /// `control_depends_on` row; equal to a `control_edge` row's `id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controlling_edge_id: Option<String>,
    /// `complete` or `partial`, from the derivation's own account of *this
    /// row's own relation*.
    pub completeness: &'static str,
    /// The relations the derivation does not answer for. Empty exactly when the
    /// whole derivation is complete.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub uncovered_relations: Vec<&'static str>,
    pub generation: u64,
}

/// One ordered relation between arms of a structural `if`.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryBranchRelation {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub owner_id: String,
    pub owner_range: CodeQueryRange,
    pub earlier_range: CodeQueryRange,
    pub later_range: CodeQueryRange,
    pub earlier_ordinal: usize,
    pub later_ordinal: usize,
    pub relation: &'static str,
    pub verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<&'static str>,
}

/// One exact Java source loop and its own repeat-edge proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryLoopReason {
    Source { detail: String },
    Flow { detail: String },
    SourceJoin { stage: String },
    GuardEvidence,
    ControlEvidence,
    IntentionalConstantFalseDo,
    UnreachableBody,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryLoopRelation {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_range: Option<CodeQueryRange>,
    pub loop_kind: &'static str,
    /// `proven`, `excluded`, or `open`.
    pub verdict: &'static str,
    /// Specific source joins, flow gaps, or deliberate exclusion evidence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub reasons: Vec<CodeQueryLoopReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repeat_edge_id: Option<String>,
}

/// One AST-occurrence keyed C++ expression fact. Optional fields are unknown
/// for the selected syntax, never a negative claim.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryCppExpression {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_text: Option<String>,
    pub type_form: &'static str,
    pub signedness: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width_bits: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub literal_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integer_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_extent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_is_reference: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_by_value: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_field_width: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_field_anonymous: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_scoped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_initializer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_has_implicit_before_nonreference: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_top_level_const: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_function: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_function_const: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_size_exact: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizeof_operand_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizeof_operand_is_parameter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sizeof_has_side_effect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_has_short_ancestor: Option<bool>,
    pub completeness: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness_reason: Option<String>,
}

/// One exact catch handler and its immediate body shape.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryFailureHandlerState {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub catch_ast_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_range: Option<CodeQueryRange>,
    pub verdict: &'static str,
    pub proof: &'static str,
    pub coverage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The canonical caught type, when C# resolution proved one. Other
    /// handler languages leave this field null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caught_type: Option<String>,
    /// `system_exception`, `not_system_exception`, or `unknown` for C#.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caught_type_relation: Option<&'static str>,
    /// Whether the C# catch clause has a `when` filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_filter: Option<bool>,
    /// Whether the handler does not rethrow, or rethrows bare/the caught
    /// variable. Other handler languages leave this field null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rethrow_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throw_relation: Option<&'static str>,
}

/// One exact Java syntax statement and its procedure entry reachability.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryStatementReachability {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub statement_kind: &'static str,
    /// `reachable`, `unreachable`, or `open`.
    pub verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One cleanup region's effect on a pending abrupt transfer.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryPendingCleanupFlow {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub cleanup_id: String,
    pub cleanup_kind: &'static str,
    pub pending_kind: &'static str,
    pub source: CodeQueryProgramPointRef,
    pub target: CodeQueryProgramPointRef,
    pub verdict: &'static str,
    pub proof: &'static str,
    pub coverage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One query-derived Python rule fact. `relation` selects which optional
/// columns carry meaning; common source identity and proof/coverage columns
/// remain available to every relation.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryPythonRuleFact {
    pub id: String,
    pub relation: &'static str,
    pub owner_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub outcome: &'static str,
    pub proof: &'static str,
    pub completeness: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_value_returns: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub none_returns: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_return_statements: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallthrough_none_returns: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_returns: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_async: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_generator: Option<bool>,
    /// Whether this assertion is enclosed by a CodeQL-style Python test scope.
    /// `unknown` means an enclosing class identity could not be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_scope: Option<&'static str>,
    /// Whether this assertion is a direct statement in the terminal `else`
    /// suite of an `elif` chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_elif_else: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuple_return_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distinct_tuple_arities: Option<usize>,
    /// Sorted, distinct exact arities observed on complete tuple returns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuple_return_arities: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_target_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_arity_match: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixed_tuple_arities: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_contract: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_use: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callable_evaluation_time: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_equivalent: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returns_receiver: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raised_expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operand_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_exception: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_is_public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docstring_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docstring_value: Option<String>,
    /// Exact source comment lines in a selected Python commented-out-code block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_block_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_block_lines: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines_of_code: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decorator_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_override: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_property_accessor: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_method_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_inheritance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_subclasses: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_special_method: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_decorated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_probable_mixin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_stateful: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_top_level: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cyclomatic_complexity: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variable_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_global: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_nonlocal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_builtin: Option<bool>,
    /// Positive-only selector for a builtin identifier that is exactly the
    /// `function` child of a Python call expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_callee: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_read: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_order: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_definition: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub definition_is_unused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotated_assignment: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_abstract: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_overriding_method: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_overridden_method: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_scope: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_main_guard: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimizing_parameter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_assignment: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_scope_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_has_definition_outside_main: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_has_deletion: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_has_import: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_is_pytest_fixture: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_has_body_read: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_policy_excluded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_loop_reused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_loop_has_outer_use: Option<bool>,
}

/// A source-backed Rust raw-pointer safety result derived from the shared
/// pointer-provenance solver.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryRustPointerFinding {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub relation: &'static str,
    pub origin_id: String,
    pub origin_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalidation_cause: Option<&'static str>,
    pub access_kind: &'static str,
    pub strength: &'static str,
    pub path_proven: bool,
    pub bounds: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_extent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_width: Option<String>,
    pub proof: &'static str,
    pub completeness: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One normalized branch condition of one procedure (#2443 slice 2).
///
/// The row projects a `guard_facts` row of the semantic IR without deriving
/// anything: the lowerer decided what the condition means, and this is that
/// decision made joinable. `point` is rendered inline for the same reason a
/// control relation renders its endpoints -- a guard is unreadable without the
/// decision it sits on -- and its `id` is the wire id a `program_point` row
/// publishes.
///
/// The edge and target columns are the reason the row exists. A constant
/// condition keeps only one arm after lowering folds the other away, so the
/// absent columns are exactly the evidence that a branch could not execute;
/// nothing else in the frozen artifact records it.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryGuard {
    pub id: String,
    /// The wire identity of the procedure the decision belongs to; equal to a
    /// `procedure` row's `id`.
    pub procedure_id: String,
    pub path: String,
    pub language: &'static str,
    /// The guard's own display anchor: the condition's decision point.
    pub range: CodeQueryRange,
    pub point: CodeQueryProgramPointRef,
    /// `constant_boolean`, `null_comparison`, `constant_equality`,
    /// `ordered_integer_comparison`, `instance_of`, `has_member`, or `opaque`.
    pub predicate: &'static str,
    /// For a constant condition, the value it always takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constant: Option<bool>,
    /// For a null comparison, whether a null subject takes the true edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub null_on_true: Option<bool>,
    /// For a null comparison, the program point entered when the subject is
    /// null. Equal to either `true_target_id` or `false_target_id` according
    /// to `null_on_true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub null_target_id: Option<String>,
    /// For a comparison against a constant, whether the comparison is an
    /// inequality rather than an equality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equality_negated: Option<bool>,
    /// The ordered relation between the subject and `constant_value`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integer_relation: Option<&'static str>,
    /// The procedure-local value ID of the constant in a constant comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constant_value: Option<u64>,
    /// The procedure-local value constrained by an instance/member predicate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guarded_value: Option<u64>,
    /// The procedure-local value denoting the class operand of `instance_of`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes_value: Option<u64>,
    /// The procedure-local value denoting the member operand of `has_member`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_value: Option<u64>,
    /// The stable structured-syntax digest for an opaque predicate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque_digest: Option<u64>,
    /// The procedure-local value the condition tests, when the predicate names
    /// one. Absent for a constant condition, which tests nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_value: Option<u64>,
    /// The successor taken when the condition holds; equal to a `control_edge`
    /// row's `id`. Absent when lowering emitted no such edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub true_edge_id: Option<String>,
    /// The program point entered when the condition holds; equal to a
    /// `program_point` row's `id`. Absent with `true_edge_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub true_target_id: Option<String>,
    /// The successor taken when the condition does not hold; equal to a
    /// `control_edge` row's `id`. Absent when lowering emitted no such edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub false_edge_id: Option<String>,
    /// The program point entered when the condition does not hold; equal to a
    /// `program_point` row's `id`. Absent with `false_edge_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub false_target_id: Option<String>,
    /// `proven` or `unproven`, from the guard's own IR evidence row.
    pub proof: &'static str,
    /// `complete` or `partial`, from the guard's own IR evidence row.
    pub completeness: &'static str,
}

/// One normal result port of one exact semantic call site.
///
/// `site_id` joins back to the structural `call_shape` row. `call_id` keeps
/// path-specialized semantic executions distinct, while `ordinal` and
/// `value_id` expose the language-level result position and its procedure-local
/// value identity for joins with state events.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryCallResult {
    pub id: String,
    pub site_id: String,
    pub site_ast_id: String,
    pub call_id: String,
    pub procedure_id: String,
    pub point_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub ordinal: u64,
    pub value_id: u64,
    pub proof: &'static str,
    pub completeness: &'static str,
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CodeQuerySemanticEvidence {
    pub proof: CodeQuerySemanticProof,
    pub completeness: CodeQuerySemanticCompleteness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl CodeQuerySemanticEvidence {
    pub fn new(
        proof: CodeQuerySemanticProof,
        completeness: CodeQuerySemanticCompleteness,
        reason: Option<String>,
    ) -> Self {
        Self {
            proof,
            completeness,
            reason,
        }
    }

    pub(crate) fn from_axis_reasons(
        proof: CodeQuerySemanticProof,
        completeness: CodeQuerySemanticCompleteness,
        proof_reason: Option<String>,
        completeness_reason: Option<String>,
    ) -> Self {
        let reason = match (proof_reason, completeness_reason) {
            (None, None) => None,
            (Some(reason), None) | (None, Some(reason)) => Some(reason),
            (Some(proof_reason), Some(completeness_reason))
                if proof_reason == completeness_reason =>
            {
                Some(proof_reason)
            }
            (Some(proof_reason), Some(completeness_reason)) => Some(format!(
                "proof: {proof_reason}; completeness: {completeness_reason}"
            )),
        };
        Self {
            proof,
            completeness,
            reason,
        }
    }
}

pub(in crate::structural::search) fn public_semantic_evidence(
    proven: bool,
    complete: bool,
    proof_reason: Option<String>,
    completeness_reason: Option<String>,
) -> CodeQuerySemanticEvidence {
    CodeQuerySemanticEvidence::from_axis_reasons(
        if proven {
            CodeQuerySemanticProof::Proven
        } else {
            CodeQuerySemanticProof::Unproven
        },
        if complete {
            CodeQuerySemanticCompleteness::Complete
        } else {
            CodeQuerySemanticCompleteness::Partial
        },
        proof_reason,
        completeness_reason,
    )
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQuerySemanticProof {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Proven,
    Unproven,
}

impl CodeQuerySemanticProof {
    pub const LABELS: &'static [&'static str] = &["proven", "unproven"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Unproven => "unproven",
        }
    }
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQuerySemanticCompleteness {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Complete,
    Partial,
}

impl CodeQuerySemanticCompleteness {
    pub const LABELS: &'static [&'static str] = &["complete", "partial"];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}

/// One query-local impl parameter and its exact source anchor.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryRustMarkerImpl {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub impl_range: CodeQueryRange,
    #[serde(rename = "trait")]
    pub trait_kind: &'static str,
    pub trait_proof: &'static str,
    pub self_proof: &'static str,
    pub impl_coverage: &'static str,
    pub parameter: Option<String>,
    pub declaration_parameter_ordinal: Option<u64>,
    pub mapping_proof: &'static str,
    pub has_send_bound: bool,
    pub has_sync_bound: bool,
    pub bounds: Vec<String>,
    pub bounds_proof: &'static str,
    pub stored: bool,
    pub shared_ref_only: bool,
    pub shared_access: &'static str,
    pub uses: Vec<CodeQueryRustMarkerUse>,
    pub uses_proof: &'static str,
    pub completeness: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryRustMarkerUse {
    pub field: String,
    pub wrappers: Vec<String>,
}
