use super::*;
use crate::query::QueryValueKind as QueryKind;
use schemars::JsonSchema;

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
pub struct CodeQuerySourceSite {
    pub path: String,
    pub range: CodeQueryRange,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CodeQueryProvenance {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub branch: Vec<usize>,
    pub seed: CodeQueryResultRef,
    pub steps: Vec<CodeQueryProvenanceStep>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CodeQueryProvenanceStep {
    pub op: &'static str,
    pub result: CodeQueryResultRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<CodeQueryResultRef>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
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
        site_id: Option<String>,
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
    AbsentMemberWitness {
        id: String,
        finding_id: String,
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
    PointsToCandidate {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
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
    RuntimeKeyedReadValue {
        id: String,
        path: String,
        range: CodeQueryRange,
        outcome: &'static str,
        proof: &'static str,
        completeness: &'static str,
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
    PythonHierarchyFact {
        id: String,
        root_id: String,
        declaration_id: Option<String>,
        owner_id: Option<String>,
        target_id: Option<String>,
        target_owner_id: Option<String>,
        ancestry_basis: crate::analyzer::usages::python_class_hierarchy::PythonAncestryBasis,
        path: String,
        range: CodeQueryRange,
        fact_kind: &'static str,
        outcome: &'static str,
        coverage: &'static str,
        reason: Option<&'static str>,
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
    ResultSubjectUse {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        origin_id: Option<String>,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        range: Option<CodeQueryRange>,
        proof: &'static str,
        completeness: &'static str,
        outcome: CodeQueryResultSubjectOutcome,
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
    CallResultObligation {
        id: String,
        site_id: String,
        path: String,
        range: CodeQueryRange,
        #[serde(skip_serializing_if = "Option::is_none")]
        obligation_kind: Option<&'static str>,
        result_use: &'static str,
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
    AssignmentRelation {
        id: String,
        procedure_id: String,
        path: String,
        range: CodeQueryRange,
        verdict: &'static str,
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
        site_id: String,
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
        site_id: String,
        path: String,
        range: CodeQueryRange,
        role: &'static str,
        coverage: &'static str,
    },
    LiteralOccurrence {
        id: String,
        path: String,
        range: CodeQueryRange,
        kind: &'static str,
        coverage: &'static str,
    },
    CallableMetrics {
        id: String,
        callable_id: Option<String>,
        site_id: String,
        path: String,
        range: CodeQueryRange,
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
    BindingInitializerCall {
        id: String,
        establishment_event_id: String,
        site_ast_id: String,
        path: String,
        range: CodeQueryRange,
        initializer_role: &'static str,
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
    BranchRelation {
        id: String,
        path: String,
        range: CodeQueryRange,
        owner_id: String,
        relation: &'static str,
        verdict: &'static str,
    },
    LoopRelation {
        id: String,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        loop_kind: &'static str,
        verdict: &'static str,
    },
    CppExpression {
        id: String,
        path: String,
        range: CodeQueryRange,
        kind: &'static str,
    },
    FailureHandlerState {
        id: String,
        path: String,
        range: CodeQueryRange,
        catch_ast_id: String,
        verdict: &'static str,
    },
    StatementReachability {
        id: String,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        statement_kind: &'static str,
        verdict: &'static str,
    },
    PendingCleanupFlow {
        id: String,
        path: String,
        range: CodeQueryRange,
        procedure_id: String,
        cleanup_kind: &'static str,
        pending_kind: &'static str,
        verdict: &'static str,
    },
    PythonRuleFact {
        id: String,
        path: String,
        range: CodeQueryRange,
        relation: &'static str,
        outcome: &'static str,
    },
    RustPointerFinding {
        id: String,
        path: String,
        range: CodeQueryRange,
        relation: &'static str,
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
    DependencyEvidence {
        id: String,
        path: String,
    },
    ConfigurationFact {
        id: String,
        fact_id: String,
        path: String,
        range: CodeQueryRange,
    },
    CrossDomain {
        id: String,
        operator: &'static str,
        domain: &'static str,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        range: Option<CodeQueryRange>,
    },
}

impl CodeQueryResultRef {
    /// The public wire label of this reference's family: the same
    /// `snake_case` tag its serialization carries.
    ///
    /// `QueryValueKind` owns the label mapping shared with query execution.
    pub const fn kind_label(&self) -> &'static str {
        self.query_value_kind().label()
    }

    const fn query_value_kind(&self) -> QueryKind {
        match self {
            Self::StructuralMatch { .. } => QueryKind::StructuralMatch,
            Self::Declaration { .. } => QueryKind::Declaration,
            Self::Procedure { .. } => QueryKind::Procedure,
            Self::FlowEndpoint { .. } => QueryKind::FlowEndpoint,
            Self::FlowWitness { .. } => QueryKind::FlowWitness,
            Self::AbsentMemberWitness { .. } => QueryKind::AbsentMemberWitness,
            Self::TaintFinding { .. } => QueryKind::TaintFinding,
            Self::ProgramPoint { .. } => QueryKind::ProgramPoint,
            Self::ControlEdge { .. } => QueryKind::ControlEdge,
            Self::TypestateFinding { .. } => QueryKind::TypestateFinding,
            Self::TypestateWitness { .. } => QueryKind::TypestateWitness,
            Self::File { .. } => QueryKind::File,
            Self::ReferenceSite { .. } => QueryKind::ReferenceSite,
            Self::CallSite { .. } => QueryKind::CallSite,
            Self::ExpressionSite { .. } => QueryKind::ExpressionSite,
            Self::JsxAttributeValue { .. } => QueryKind::JsxAttributeValue,
            Self::ReceiverAnalysis { .. } => QueryKind::ReceiverAnalysis,
            Self::MemberTargetAnalysis { .. } => QueryKind::MemberTargetAnalysis,
            Self::ReceiverOutcome { .. } => QueryKind::ReceiverOutcome,
            Self::ReceiverEvidence { .. } => QueryKind::ReceiverEvidence,
            Self::PointsToCandidate { .. } => QueryKind::PointsToCandidate,
            Self::FieldWriteValue { .. } => QueryKind::FieldWriteValue,
            Self::RuntimeKeyedReadValue { .. } => QueryKind::KeyedReadValue,
            Self::DispatchOutcome { .. } => QueryKind::DispatchOutcome,
            Self::DispatchTarget { .. } => QueryKind::DispatchTarget,
            Self::MemberFamily { .. } => QueryKind::MemberFamily,
            Self::MemberFamilyEdge { .. } => QueryKind::MemberFamilyEdge,
            Self::PythonHierarchyFact { .. } => QueryKind::PythonHierarchyFact,
            Self::CallShape { .. } => QueryKind::CallShape,
            Self::CallResult { .. } => QueryKind::CallResult,
            Self::ResultSubjectUse { .. } => QueryKind::ResultSubjectUse,
            Self::CallArgumentGroup { .. } => QueryKind::CallArgumentGroup,
            Self::CallArgument { .. } => QueryKind::CallArgument,
            Self::CallBinding { .. } => QueryKind::CallBinding,
            Self::CallEffect { .. } => QueryKind::CallEffect,
            Self::CallResultContract { .. } => QueryKind::CallResultContract,
            Self::CallResultObligation { .. } => QueryKind::CallResultObligation,
            Self::ResultContractUse { .. } => QueryKind::ResultContractUse,
            Self::ResultContractFailureUse { .. } => QueryKind::ResultContractFailureUse,
            Self::NilnessOperation { .. } => QueryKind::NilnessOperation,
            Self::SwitchCoverage { .. } => QueryKind::SwitchCoverage,
            Self::AssignmentRelation { .. } => QueryKind::AssignmentRelation,
            Self::ClassSetRow { .. } => QueryKind::ClassSetRow,
            Self::AbsentMemberFinding { .. } => QueryKind::AbsentMemberFinding,
            Self::DetachedTaskTransfer { .. } => QueryKind::DetachedTaskTransfer,
            Self::ProcedureEffect { .. } => QueryKind::ProcedureEffect,
            Self::CallableSignature { .. } => QueryKind::CallableSignature,
            Self::LiteralOccurrence { .. } => QueryKind::LiteralOccurrence,
            Self::CallableMetrics { .. } => QueryKind::CallableMetrics,
            Self::SignatureParameter { .. } => QueryKind::SignatureParameter,
            Self::DecoratedParameter { .. } => QueryKind::DecoratedParameter,
            Self::CallableApplicability { .. } => QueryKind::CallableApplicability,
            Self::OverloadSelection { .. } => QueryKind::OverloadSelection,
            Self::MemberSelection { .. } => QueryKind::MemberSelection,
            Self::Occurrence { .. } => QueryKind::Occurrence,
            Self::LexicalScope { .. } => QueryKind::LexicalScope,
            Self::Binding { .. } => QueryKind::Binding,
            Self::ResolutionCandidate { .. } => QueryKind::ResolutionCandidate,
            Self::CandidateHop { .. } => QueryKind::CandidateHop,
            Self::ReferenceEdge { .. } => QueryKind::ReferenceEdge,
            Self::StateEvent { .. } => QueryKind::StateEvent,
            Self::BindingInitializerCall { .. } => QueryKind::BindingInitializerCall,
            Self::FlowRelation { .. } => QueryKind::FlowRelation,
            Self::ControlRelation { .. } => QueryKind::ControlRelation,
            Self::BranchRelation { .. } => QueryKind::BranchRelation,
            Self::LoopRelation { .. } => QueryKind::LoopRelation,
            Self::CppExpression { .. } => QueryKind::CppExpression,
            Self::FailureHandlerState { .. } => QueryKind::FailureHandlerState,
            Self::StatementReachability { .. } => QueryKind::StatementReachability,
            Self::PendingCleanupFlow { .. } => QueryKind::PendingCleanupFlow,
            Self::PythonRuleFact { .. } => QueryKind::PythonRuleFact,
            Self::RustPointerFinding { .. } => QueryKind::RustPointerFinding,
            Self::Guard { .. } => QueryKind::Guard,
            Self::RewritePath { .. } => QueryKind::RewritePath,
            Self::SourceSet { .. } => QueryKind::SourceSet,
            Self::BuildTarget { .. } => QueryKind::BuildTarget,
            Self::TopologyEdge { .. } => QueryKind::TopologyEdge,
            Self::QualifiedPath { .. } => QueryKind::QualifiedPath,
            Self::PathSegment { .. } => QueryKind::PathSegment,
            Self::GenerationSite { .. } => QueryKind::GenerationSite,
            Self::Export { .. } => QueryKind::Export,
            Self::DeclarationState { .. } => QueryKind::DeclarationState,
            Self::DependencyEvidence { .. } => QueryKind::DependencyEvidence,
            Self::ConfigurationFact { .. } => QueryKind::ConfigurationFact,
            Self::CrossDomain { .. } => QueryKind::CrossDomain,
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
            | Self::AbsentMemberWitness { path, .. }
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
            | Self::PointsToCandidate { path, .. }
            | Self::FieldWriteValue { path, .. }
            | Self::RuntimeKeyedReadValue { path, .. }
            | Self::DispatchOutcome { path, .. }
            | Self::DispatchTarget { path, .. }
            | Self::MemberFamily { path, .. }
            | Self::MemberFamilyEdge { path, .. }
            | Self::PythonHierarchyFact { path, .. }
            | Self::CallShape { path, .. }
            | Self::CallResult { path, .. }
            | Self::ResultSubjectUse { path, .. }
            | Self::CallArgumentGroup { path, .. }
            | Self::CallArgument { path, .. }
            | Self::CallBinding { path, .. }
            | Self::CallEffect { path, .. }
            | Self::CallResultContract { path, .. }
            | Self::CallResultObligation { path, .. }
            | Self::ResultContractUse { path, .. }
            | Self::ResultContractFailureUse { path, .. }
            | Self::NilnessOperation { path, .. }
            | Self::SwitchCoverage { path, .. }
            | Self::AssignmentRelation { path, .. }
            | Self::ClassSetRow { path, .. }
            | Self::AbsentMemberFinding { path, .. }
            | Self::DetachedTaskTransfer { path, .. }
            | Self::ProcedureEffect { path, .. }
            | Self::CallableSignature { path, .. }
            | Self::LiteralOccurrence { path, .. }
            | Self::CallableMetrics { path, .. }
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
            | Self::BindingInitializerCall { path, .. }
            | Self::FlowRelation { path, .. }
            | Self::ControlRelation { path, .. }
            | Self::BranchRelation { path, .. }
            | Self::LoopRelation { path, .. }
            | Self::CppExpression { path, .. }
            | Self::FailureHandlerState { path, .. }
            | Self::StatementReachability { path, .. }
            | Self::PendingCleanupFlow { path, .. }
            | Self::PythonRuleFact { path, .. }
            | Self::RustPointerFinding { path, .. }
            | Self::Guard { path, .. }
            | Self::RewritePath { path, .. }
            | Self::SourceSet { path, .. }
            | Self::BuildTarget { path, .. }
            | Self::TopologyEdge { path, .. }
            | Self::QualifiedPath { path, .. }
            | Self::PathSegment { path, .. }
            | Self::GenerationSite { path, .. }
            | Self::Export { path, .. }
            | Self::DeclarationState { path, .. }
            | Self::DependencyEvidence { path, .. }
            | Self::ConfigurationFact { path, .. }
            | Self::CrossDomain { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
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

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct CodeQueryRange {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}
