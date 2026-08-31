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
    IndexedNormalReturn { ordinal: u32 },
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
    /// Stable label of the exact first cause when `truncated` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation_cause: Option<String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub uncovered_relations: Vec<&'static str>,
    pub generation: u64,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// `constant_boolean`, `null_comparison`, `constant_equality`, or
    /// `opaque`.
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
    /// The procedure-local value ID of the constant in a constant comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constant_value: Option<u64>,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
