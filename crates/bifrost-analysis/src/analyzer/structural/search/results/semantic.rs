use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryProcedure {
    pub id: String,
    pub artifact_id: String,
    pub path: String,
    pub language: &'static str,
    pub procedure_kind: &'static str,
    pub range: CodeQueryRange,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateSubject {
    pub class: String,
    pub identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryTypestateCertainty {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryTypestateUncertainty {
    AmbiguousDispatch,
    UnknownCall,
    ExternalCall,
    Escape,
    IncompleteAnalysis,
    UnmatchedEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub uncertainty: Vec<CodeQueryTypestateUncertainty>,
    #[serde(skip_serializing_if = "is_false")]
    pub abstained: bool,
    pub retained_witnesses: usize,
    pub omitted_witnesses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryTypestateWitnessStepKind {
    Seed,
    Edge { edge_kind: &'static str },
    EndSummaryGap { return_kind: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTypestateWitnessStep {
    pub kind: CodeQueryTypestateWitnessStepKind,
    pub source: CodeQuerySourceSite,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQuerySourceSite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<CodeQuerySourceSite>,
    pub evidence: CodeQuerySemanticEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub quality: CodeQuerySemanticEvidence,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uncertainty: Vec<CodeQueryTypestateUncertainty>,
    #[serde(skip_serializing_if = "is_false")]
    pub abstained: bool,
    pub steps: Vec<CodeQueryTypestateWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub retention_truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowReachability {
    Reached,
    NotReached,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowCertainty {
    Exact,
    May,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowMustStatus {
    NotEstablished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowCompletion {
    Complete,
    Incomplete,
    BudgetExhausted,
    Cancelled,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryFlowSolverTermination {
    FixedPoint,
    BudgetExhausted,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowDeclarationSegment {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_byte: u32,
    pub end_byte: u32,
    pub occurrence: u32,
    pub sibling_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowPortSymbol {
    Receiver,
    Parameter { ordinal: u32 },
    NormalReturn,
    ExceptionalReturn,
    Capture { slot: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowSelectorSymbol {
    Field {
        field: CodeQueryFlowSymbolSite,
    },
    ExactIndex {
        index: Box<CodeQueryFlowCarrierSymbol>,
    },
    AnyIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    Location {
        id: String,
        root: Box<CodeQueryFlowCarrierSymbol>,
        selectors: Vec<CodeQueryFlowSelectorSymbol>,
        exact: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeQueryFlowFactSymbol {
    Zero,
    Carrier {
        source: Box<CodeQueryFlowEvent>,
        carrier: Box<CodeQueryFlowCarrierSymbol>,
        #[serde(skip_serializing_if = "is_false")]
        uncertain: bool,
    },
    Meeting {
        source: Box<CodeQueryFlowEvent>,
        sink: Box<CodeQueryFlowEvent>,
        #[serde(skip_serializing_if = "is_false")]
        uncertain: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowEndpoint {
    pub id: String,
    pub plan_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CodeQueryFlowEvent>,
    pub sink: CodeQueryFlowEvent,
    pub reachability: CodeQueryFlowReachability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certainty: Option<CodeQueryFlowCertainty>,
    pub must: CodeQueryFlowMustStatus,
    #[serde(skip_serializing_if = "is_false")]
    pub ambiguous: bool,
    pub completion: CodeQueryFlowCompletion,
    pub semantic_status: &'static str,
    pub solver_termination: CodeQueryFlowSolverTermination,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_qualities: Vec<CodeQuerySemanticEvidence>,
    pub retained_witnesses: usize,
    pub omitted_witnesses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CodeQueryFlowWitnessStepKind {
    Seed,
    Edge { edge_kind: &'static str },
    EndSummaryGap { return_kind: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryFlowWitness {
    pub id: String,
    pub endpoint_id: String,
    pub plan_ref: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub quality: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub retention_truncated: bool,
}

/// One bounded source occurrence contributing to an aggregated taint sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryTaintWitness {
    pub id: String,
    pub finding_id: String,
    pub witness_index: usize,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub quality: CodeQuerySemanticEvidence,
    pub steps: Vec<CodeQueryFlowWitnessStep>,
    pub retained_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    pub omitted_steps_lower_bound: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub alternatives_truncated: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub retention_truncated: bool,
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub origins_truncated: bool,
    pub witnesses: Vec<CodeQueryTaintWitness>,
    #[serde(skip_serializing_if = "is_false")]
    pub witnesses_truncated: bool,
    pub evidence: CodeQuerySemanticEvidence,
    #[serde(skip_serializing_if = "is_false")]
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryProgramPointRef {
    pub id: String,
    pub procedure_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<CodeQueryProgramPointBoundary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryProgramPointBoundary {
    Entry,
    NormalExit,
    ExceptionalExit,
}

impl CodeQueryProgramPointBoundary {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::NormalExit => "normal_exit",
            Self::ExceptionalExit => "exceptional_exit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticEvidence {
    pub proof: CodeQuerySemanticProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_reason: Option<String>,
    pub completeness: CodeQuerySemanticCompleteness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness_reason: Option<String>,
}

impl CodeQuerySemanticEvidence {
    pub const fn status_label(&self) -> &'static str {
        match (self.proof, self.completeness) {
            (CodeQuerySemanticProof::Proven, CodeQuerySemanticCompleteness::Complete) => {
                "proven/complete"
            }
            (CodeQuerySemanticProof::Proven, CodeQuerySemanticCompleteness::Partial) => {
                "proven/partial"
            }
            (CodeQuerySemanticProof::Unproven, CodeQuerySemanticCompleteness::Complete) => {
                "unproven/complete"
            }
            (CodeQuerySemanticProof::Unproven, CodeQuerySemanticCompleteness::Partial) => {
                "unproven/partial"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQuerySemanticProof {
    Proven,
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQuerySemanticCompleteness {
    Complete,
    Partial,
}
