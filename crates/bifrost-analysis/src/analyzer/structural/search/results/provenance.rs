use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQuerySourceSite {
    pub path: String,
    pub range: CodeQueryRange,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenance {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub branch: Vec<usize>,
    pub seed: CodeQueryResultRef,
    pub steps: Vec<CodeQueryProvenanceStep>,
}

#[derive(Debug, Serialize)]
pub struct CodeQueryProvenanceStep {
    pub op: &'static str,
    pub result: CodeQueryResultRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<CodeQueryResultRef>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result_type", rename_all = "snake_case")]
pub enum CodeQueryResultRef {
    StructuralMatch {
        path: String,
        kind: &'static str,
        start_line: usize,
        end_line: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_range: Option<CodeQueryRange>,
    },
    Declaration {
        path: String,
        kind: &'static str,
        fq_name: String,
        start_line: usize,
        end_line: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_range: Option<CodeQueryRange>,
    },
    Procedure {
        id: String,
        path: String,
        procedure_kind: &'static str,
        range: CodeQueryRange,
    },
    FlowEndpoint {
        id: String,
        plan_ref: String,
        path: String,
        range: CodeQueryRange,
    },
    FlowWitness {
        id: String,
        endpoint_id: String,
        path: String,
        range: CodeQueryRange,
    },
    TaintFinding {
        id: String,
        path: String,
        range: CodeQueryRange,
    },
    ProgramPoint {
        id: String,
        procedure_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        boundary: Option<CodeQueryProgramPointBoundary>,
    },
    ControlEdge {
        id: String,
        procedure_id: String,
        path: String,
        range: CodeQueryRange,
        edge_kind: &'static str,
        source_id: String,
        target_id: String,
    },
    TypestateFinding {
        id: String,
        path: String,
        range: CodeQueryRange,
        protocol_ref: String,
    },
    TypestateWitness {
        id: String,
        finding_id: String,
        path: String,
        range: CodeQueryRange,
    },
    File {
        path: String,
    },
    ReferenceSite {
        path: String,
        range: CodeQueryRange,
        target_fq_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        usage_kind: Option<&'static str>,
        proof: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_kind: Option<&'static str>,
    },
    CallSite {
        path: String,
        range: CodeQueryRange,
        caller_fq_name: String,
        callee_fq_name: String,
        proof: &'static str,
    },
    ExpressionSite {
        path: String,
        range: CodeQueryRange,
        input_kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_name: Option<String>,
    },
    ReceiverAnalysis {
        path: String,
        range: CodeQueryRange,
        analysis_kind: &'static str,
        outcome: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        capture: Option<String>,
    },
    ReceiverOutcome {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        outcome: &'static str,
        coverage: &'static str,
    },
    ReceiverEvidence {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        evidence_kind: &'static str,
    },
    CallShape {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        call_kind: &'static str,
        coverage: &'static str,
    },
    CallArgumentGroup {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        kind: &'static str,
    },
    CallArgument {
        id: String,
        group_id: String,
        path: String,
        range: CodeQueryRange,
        argument_index: usize,
    },
    Occurrence {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        class: &'static str,
        role: &'static str,
        namespace: &'static str,
    },
    LexicalScope {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        index: u32,
    },
    Binding {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        name: String,
        kind: &'static str,
    },
    ResolutionCandidate {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        tier: Option<&'static str>,
        outcome: &'static str,
    },
    ReferenceEdge {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        target_fq_name: String,
        provenance: &'static str,
    },
    QualifiedPath {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        segment_count: u32,
    },
    PathSegment {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        ordinal: u32,
        text: String,
    },
    GenerationSite {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        kind: &'static str,
    },
    Export {
        id: String,
        path: String,
        range: CodeQueryRange,
        form: &'static str,
        exported_name: String,
    },
    DeclarationState {
        id: String,
        path: String,
        fq_name: String,
        origin: &'static str,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCapture {
    pub name: String,
    pub text: String,
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    /// Content-scoped identity of the captured facts-arena node, equal to the
    /// `ast_id` of every occurrence row at that node. Absent only when the
    /// capture came from a match whose facts identity was unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct CodeQueryRange {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}
