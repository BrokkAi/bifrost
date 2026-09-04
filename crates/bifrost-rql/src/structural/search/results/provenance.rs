use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQuerySourceSite {
    pub path: String,
    pub range: CodeQueryRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryProvenance {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub branch: Vec<usize>,
    pub seed: CodeQueryResultRef,
    pub steps: Vec<CodeQueryProvenanceStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryProvenanceStep {
    pub op: &'static str,
    pub result: CodeQueryResultRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<CodeQueryResultRef>,
}

#[derive(Debug, Clone, Serialize)]
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
    JsxAttributeValue {
        id: String,
        ast_id: String,
        path: String,
        range: CodeQueryRange,
        element_identity: &'static str,
        coverage: &'static str,
    },
    ReceiverAnalysis {
        path: String,
        range: CodeQueryRange,
        analysis_kind: &'static str,
        outcome: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        capture: Option<String>,
    },
    MemberTargetAnalysis {
        site_id: String,
        path: String,
        receiver_range: CodeQueryRange,
        outcome: &'static str,
        coverage: &'static str,
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
    FieldWriteValue {
        id: String,
        assignment_ast_id: String,
        rhs_ast_id: String,
        receiver_identity_id: String,
        member_target_id: String,
        path: String,
        range: CodeQueryRange,
        proof: &'static str,
        completeness: &'static str,
        coverage: &'static str,
    },
    DispatchOutcome {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        outcome: &'static str,
        coverage: &'static str,
    },
    DispatchTarget {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        ordinal: usize,
        dispatch: &'static str,
    },
    MemberFamily {
        id: String,
        member_id: String,
        path: String,
        range: CodeQueryRange,
        outcome: &'static str,
        coverage: &'static str,
    },
    MemberFamilyEdge {
        id: String,
        member_id: String,
        path: String,
        range: CodeQueryRange,
        ordinal: usize,
        relation: &'static str,
    },
    CallShape {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        call_kind: &'static str,
        coverage: &'static str,
    },
    CallResult {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        ordinal: u64,
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
    CallBinding {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        semantic_target_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_origin: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        receiver_type_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pack_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_record_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_activation_status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_activation_source_kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_activation_source_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_origin: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_proof: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_completeness: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        binding_kind: Option<&'static str>,
        mapping: &'static str,
        coverage: &'static str,
    },
    CallEffect {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        effect_id: Option<String>,
        derivation: &'static str,
        coverage: &'static str,
    },
    CallResultContract {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_ordinal: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        condition_result_ordinal: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        predicate: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_success_predicate: Option<&'static str>,
        coverage: &'static str,
    },
    ResultContractUse {
        id: String,
        acquisition_id: String,
        path: String,
        range: CodeQueryRange,
        use_kind: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_ordinal: Option<u32>,
        applicability: &'static str,
        guard: &'static str,
        coverage: &'static str,
    },
    ResultContractFailureUse {
        id: String,
        acquisition_id: String,
        path: String,
        range: CodeQueryRange,
        provenance: &'static str,
        consumer: &'static str,
        coverage: &'static str,
    },
    NilnessOperation {
        id: String,
        path: String,
        range: CodeQueryRange,
        use_kind: &'static str,
        fact: &'static str,
        coverage: &'static str,
    },
    SwitchCoverage {
        id: String,
        path: String,
        range: CodeQueryRange,
        verdict: &'static str,
        proof: &'static str,
    },
    ConcurrentAccessConflict {
        id: String,
        path: String,
        range: CodeQueryRange,
        ordering: &'static str,
        protection: &'static str,
        proof: &'static str,
    },
    ClassSetRow {
        id: String,
        path: String,
        range: CodeQueryRange,
        member: String,
        status: &'static str,
    },
    AbsentMemberFinding {
        id: String,
        path: String,
        range: CodeQueryRange,
        member: String,
        class: String,
    },
    DetachedTaskTransfer {
        id: String,
        path: String,
        range: CodeQueryRange,
        role: &'static str,
        timing: &'static str,
        coverage: &'static str,
    },
    ProcedureEffect {
        id: String,
        procedure_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        effect_id: Option<String>,
        derivation: &'static str,
        coverage: &'static str,
    },
    CallableSignature {
        id: String,
        declaration_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        role: &'static str,
        coverage: &'static str,
    },
    SignatureParameter {
        id: String,
        signature_id: String,
        path: String,
        range: CodeQueryRange,
        parameter_index: usize,
    },
    DecoratedParameter {
        id: String,
        parameter_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        decorator_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        decorator_range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_ordinal: Option<usize>,
        binding_status: &'static str,
        coverage: &'static str,
    },
    CallableApplicability {
        id: String,
        site_ast_id: String,
        path: String,
        range: CodeQueryRange,
        ordinal: usize,
        verdict: &'static str,
        selected: bool,
    },
    OverloadSelection {
        id: String,
        site_ast_id: String,
        path: String,
        range: CodeQueryRange,
        resolution: &'static str,
    },
    MemberSelection {
        id: String,
        site_ast_id: String,
        path: String,
        range: CodeQueryRange,
        outcome: &'static str,
        coverage: &'static str,
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
    CandidateHop {
        id: String,
        candidate_id: String,
        path: String,
        range: CodeQueryRange,
        hop: usize,
        relation: &'static str,
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
    StateEvent {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_id: Option<String>,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        event_class: &'static str,
    },
    FlowRelation {
        id: String,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        relation: &'static str,
        certainty: &'static str,
    },
    ControlRelation {
        id: String,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        relation: &'static str,
        certainty: &'static str,
        exit_partition: &'static str,
    },
    Guard {
        id: String,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        predicate: &'static str,
    },
    RewritePath {
        id: String,
        path: String,
        range: CodeQueryRange,
        domain: &'static str,
        outcome: &'static str,
    },
    /// A topology row's reference names the build file that justifies it and
    /// carries no range: the build readers derive a declaration from a build
    /// model, not from a byte span, so a range here would be invented.
    SourceSet {
        id: String,
        path: String,
        name: String,
    },
    BuildTarget {
        id: String,
        path: String,
        name: String,
    },
    TopologyEdge {
        id: String,
        path: String,
        from_name: String,
        to_name: String,
        scope: &'static str,
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

impl CodeQueryResultRef {
    /// The public wire label of this reference's family: the same
    /// `snake_case` tag its serialization carries.
    ///
    /// Stated once here, beside the enum it describes, so no consumer
    /// restates all 63 variant names and drifts from the wire form.
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::StructuralMatch { .. } => "structural_match",
            Self::Declaration { .. } => "declaration",
            Self::Procedure { .. } => "procedure",
            Self::FlowEndpoint { .. } => "flow_endpoint",
            Self::FlowWitness { .. } => "flow_witness",
            Self::TaintFinding { .. } => "taint_finding",
            Self::ProgramPoint { .. } => "program_point",
            Self::ControlEdge { .. } => "control_edge",
            Self::TypestateFinding { .. } => "typestate_finding",
            Self::TypestateWitness { .. } => "typestate_witness",
            Self::File { .. } => "file",
            Self::ReferenceSite { .. } => "reference_site",
            Self::CallSite { .. } => "call_site",
            Self::ExpressionSite { .. } => "expression_site",
            Self::JsxAttributeValue { .. } => "jsx_attribute_value",
            Self::ReceiverAnalysis { .. } => "receiver_analysis",
            Self::MemberTargetAnalysis { .. } => "member_target_analysis",
            Self::ReceiverOutcome { .. } => "receiver_outcome",
            Self::ReceiverEvidence { .. } => "receiver_evidence",
            Self::FieldWriteValue { .. } => "field_write_value",
            Self::DispatchOutcome { .. } => "dispatch_outcome",
            Self::DispatchTarget { .. } => "dispatch_target",
            Self::MemberFamily { .. } => "member_family",
            Self::MemberFamilyEdge { .. } => "member_family_edge",
            Self::CallShape { .. } => "call_shape",
            Self::CallResult { .. } => "call_result",
            Self::CallArgumentGroup { .. } => "call_argument_group",
            Self::CallArgument { .. } => "call_argument",
            Self::CallBinding { .. } => "call_binding",
            Self::CallEffect { .. } => "call_effect",
            Self::CallResultContract { .. } => "call_result_contract",
            Self::ResultContractUse { .. } => "result_contract_use",
            Self::ResultContractFailureUse { .. } => "result_contract_failure_use",
            Self::NilnessOperation { .. } => "nilness_operation",
            Self::SwitchCoverage { .. } => "switch_coverage",
            Self::ConcurrentAccessConflict { .. } => "concurrent_access_conflict",
            Self::ClassSetRow { .. } => "class_set_row",
            Self::AbsentMemberFinding { .. } => "absent_member_finding",
            Self::DetachedTaskTransfer { .. } => "detached_task_transfer",
            Self::ProcedureEffect { .. } => "procedure_effect",
            Self::CallableSignature { .. } => "callable_signature",
            Self::SignatureParameter { .. } => "signature_parameter",
            Self::DecoratedParameter { .. } => "decorated_parameter",
            Self::CallableApplicability { .. } => "callable_applicability",
            Self::OverloadSelection { .. } => "overload_selection",
            Self::MemberSelection { .. } => "member_selection",
            Self::Occurrence { .. } => "occurrence",
            Self::LexicalScope { .. } => "lexical_scope",
            Self::Binding { .. } => "binding",
            Self::ResolutionCandidate { .. } => "resolution_candidate",
            Self::CandidateHop { .. } => "candidate_hop",
            Self::ReferenceEdge { .. } => "reference_edge",
            Self::StateEvent { .. } => "state_event",
            Self::FlowRelation { .. } => "flow_relation",
            Self::ControlRelation { .. } => "control_relation",
            Self::Guard { .. } => "guard",
            Self::RewritePath { .. } => "rewrite_path",
            Self::SourceSet { .. } => "source_set",
            Self::BuildTarget { .. } => "build_target",
            Self::TopologyEdge { .. } => "topology_edge",
            Self::QualifiedPath { .. } => "qualified_path",
            Self::PathSegment { .. } => "path_segment",
            Self::GenerationSite { .. } => "generation_site",
            Self::Export { .. } => "export",
            Self::DeclarationState { .. } => "declaration_state",
        }
    }

    /// The workspace-relative path this reference is about. Every family
    /// carries exactly one, which is why a consumer can compare it against
    /// the evidence file without knowing the family.
    pub fn path(&self) -> &str {
        match self {
            Self::StructuralMatch { path, .. }
            | Self::Declaration { path, .. }
            | Self::Procedure { path, .. }
            | Self::FlowEndpoint { path, .. }
            | Self::FlowWitness { path, .. }
            | Self::TaintFinding { path, .. }
            | Self::ProgramPoint { path, .. }
            | Self::ControlEdge { path, .. }
            | Self::TypestateFinding { path, .. }
            | Self::TypestateWitness { path, .. }
            | Self::File { path }
            | Self::ReferenceSite { path, .. }
            | Self::CallSite { path, .. }
            | Self::ExpressionSite { path, .. }
            | Self::JsxAttributeValue { path, .. }
            | Self::ReceiverAnalysis { path, .. }
            | Self::MemberTargetAnalysis { path, .. }
            | Self::ReceiverOutcome { path, .. }
            | Self::ReceiverEvidence { path, .. }
            | Self::FieldWriteValue { path, .. }
            | Self::DispatchOutcome { path, .. }
            | Self::DispatchTarget { path, .. }
            | Self::MemberFamily { path, .. }
            | Self::MemberFamilyEdge { path, .. }
            | Self::CallShape { path, .. }
            | Self::CallResult { path, .. }
            | Self::CallArgumentGroup { path, .. }
            | Self::CallArgument { path, .. }
            | Self::CallBinding { path, .. }
            | Self::CallEffect { path, .. }
            | Self::CallResultContract { path, .. }
            | Self::ResultContractUse { path, .. }
            | Self::ResultContractFailureUse { path, .. }
            | Self::NilnessOperation { path, .. }
            | Self::SwitchCoverage { path, .. }
            | Self::ConcurrentAccessConflict { path, .. }
            | Self::ClassSetRow { path, .. }
            | Self::AbsentMemberFinding { path, .. }
            | Self::DetachedTaskTransfer { path, .. }
            | Self::ProcedureEffect { path, .. }
            | Self::CallableSignature { path, .. }
            | Self::SignatureParameter { path, .. }
            | Self::DecoratedParameter { path, .. }
            | Self::CallableApplicability { path, .. }
            | Self::OverloadSelection { path, .. }
            | Self::MemberSelection { path, .. }
            | Self::Occurrence { path, .. }
            | Self::LexicalScope { path, .. }
            | Self::Binding { path, .. }
            | Self::ResolutionCandidate { path, .. }
            | Self::CandidateHop { path, .. }
            | Self::ReferenceEdge { path, .. }
            | Self::StateEvent { path, .. }
            | Self::FlowRelation { path, .. }
            | Self::ControlRelation { path, .. }
            | Self::Guard { path, .. }
            | Self::RewritePath { path, .. }
            | Self::SourceSet { path, .. }
            | Self::BuildTarget { path, .. }
            | Self::TopologyEdge { path, .. }
            | Self::QualifiedPath { path, .. }
            | Self::PathSegment { path, .. }
            | Self::GenerationSite { path, .. }
            | Self::Export { path, .. }
            | Self::DeclarationState { path, .. } => path,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CodeQueryRange {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}
