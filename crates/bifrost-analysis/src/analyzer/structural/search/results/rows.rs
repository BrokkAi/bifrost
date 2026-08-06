use super::*;

#[derive(Debug)]
pub struct DetailedCodeQueryResult {
    pub result: CodeQueryResult,
    pub work: CodeQueryExecutionWork,
    pub evidence: Vec<DetailedCodeQueryEvidence>,
    pub profile: Option<QueryExecutionProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryEvidence {
    pub result_index: usize,
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub file: ProjectFile,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub stable_owner_candidate: Option<CodeQueryStableOwnerCandidate>,
    pub identities: DetailedCodeQueryProvenanceIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
    pub provenance: Vec<DetailedCodeQueryProvenanceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryProvenanceEvidence {
    pub branch: Vec<usize>,
    pub seed: DetailedCodeQueryProvenanceRefEvidence,
    pub steps: Vec<DetailedCodeQueryProvenanceStepEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryProvenanceStepEvidence {
    pub op: String,
    pub result: DetailedCodeQueryProvenanceRefEvidence,
    pub via: Option<DetailedCodeQueryProvenanceRefEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryProvenanceRefEvidence {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub file: ProjectFile,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub display_range: Option<CodeQueryRange>,
    pub identities: DetailedCodeQueryProvenanceIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedCodeQueryProvenanceIdentities {
    None,
    Primary(Option<DetailedCodeQueryIdentityCandidate>),
    ReferenceTarget(Option<DetailedCodeQueryIdentityCandidate>),
    Call {
        caller: Option<DetailedCodeQueryIdentityCandidate>,
        callee: Option<DetailedCodeQueryIdentityCandidate>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryIdentityCandidate {
    pub file: ProjectFile,
    pub candidate: CodeQueryStableOwnerCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeQueryStableOwnerCandidate {
    pub namespace: String,
    pub derivation: CodeQueryStableOwnerDerivation,
    pub semantic_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeQueryStableOwnerDerivation {
    AnalyzerDeclarationId,
    CanonicalAstIdentity,
    SemanticWireId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetailedCodeQueryDomain {
    StructuralMatch,
    Declaration,
    Procedure,
    ProgramPoint,
    ControlEdge,
    TypestateFinding,
    TypestateWitness,
    FlowEndpoint,
    FlowWitness,
    TaintFinding,
    File,
    ReferenceSite,
    CallSite,
    ExpressionSite,
    ReceiverAnalysis,
    ReceiverOutcome,
    CallShape,
    CallArgumentGroup,
    CallArgument,
    ReceiverEvidence,
    MemberSelection,
    Occurrence,
    LexicalScope,
    Binding,
    ResolutionCandidate,
    GenerationSite,
    Export,
    DeclarationState,
    ReferenceEdge,
    QualifiedPath,
    PathSegment,
}

pub const ALL_DETAILED_CODE_QUERY_DOMAINS: &[DetailedCodeQueryDomain] = &[
    DetailedCodeQueryDomain::StructuralMatch,
    DetailedCodeQueryDomain::Declaration,
    DetailedCodeQueryDomain::Procedure,
    DetailedCodeQueryDomain::ProgramPoint,
    DetailedCodeQueryDomain::ControlEdge,
    DetailedCodeQueryDomain::TypestateFinding,
    DetailedCodeQueryDomain::TypestateWitness,
    DetailedCodeQueryDomain::FlowEndpoint,
    DetailedCodeQueryDomain::FlowWitness,
    DetailedCodeQueryDomain::TaintFinding,
    DetailedCodeQueryDomain::File,
    DetailedCodeQueryDomain::ReferenceSite,
    DetailedCodeQueryDomain::CallSite,
    DetailedCodeQueryDomain::ExpressionSite,
    DetailedCodeQueryDomain::ReceiverAnalysis,
    DetailedCodeQueryDomain::ReceiverOutcome,
    DetailedCodeQueryDomain::CallShape,
    DetailedCodeQueryDomain::CallArgumentGroup,
    DetailedCodeQueryDomain::CallArgument,
    DetailedCodeQueryDomain::ReceiverEvidence,
    DetailedCodeQueryDomain::MemberSelection,
    DetailedCodeQueryDomain::Occurrence,
    DetailedCodeQueryDomain::LexicalScope,
    DetailedCodeQueryDomain::Binding,
    DetailedCodeQueryDomain::ResolutionCandidate,
    DetailedCodeQueryDomain::GenerationSite,
    DetailedCodeQueryDomain::Export,
    DetailedCodeQueryDomain::DeclarationState,
    DetailedCodeQueryDomain::ReferenceEdge,
    DetailedCodeQueryDomain::QualifiedPath,
    DetailedCodeQueryDomain::PathSegment,
];

/// The scalar type of one stable, addressable CodeQuery row field.
///
/// These types deliberately exclude source ranges and rendered text. Ranges
/// are locations rather than identities, and presentation strings are not
/// safe correlation keys for policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeQueryRowScalarType {
    StableId,
    String,
    Integer,
    Boolean,
    ConstrainedEnum,
    DeclarationIdentity,
}

/// Declarative schema for one addressable field on a detailed result domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeQueryRowField {
    pub name: &'static str,
    pub scalar_type: CodeQueryRowScalarType,
    pub nullable: bool,
}

impl CodeQueryRowField {
    const fn required(name: &'static str, scalar_type: CodeQueryRowScalarType) -> Self {
        Self {
            name,
            scalar_type,
            nullable: false,
        }
    }

    const fn optional(name: &'static str, scalar_type: CodeQueryRowScalarType) -> Self {
        Self {
            name,
            scalar_type,
            nullable: true,
        }
    }
}

macro_rules! code_query_row_fields {
    ($($field:expr),* $(,)?) => {{
        const FIELDS: &[CodeQueryRowField] = &[$($field),*];
        FIELDS
    }};
}

/// One borrowed scalar projected from a public CodeQuery result row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeQueryRowScalarRef<'a> {
    StableId(&'a str),
    String(&'a str),
    Integer(u64),
    Boolean(bool),
    ConstrainedEnum(&'a str),
    DeclarationIdentity(&'a str),
}

impl CodeQueryRowScalarRef<'_> {
    pub const fn scalar_type(self) -> CodeQueryRowScalarType {
        match self {
            Self::StableId(_) => CodeQueryRowScalarType::StableId,
            Self::String(_) => CodeQueryRowScalarType::String,
            Self::Integer(_) => CodeQueryRowScalarType::Integer,
            Self::Boolean(_) => CodeQueryRowScalarType::Boolean,
            Self::ConstrainedEnum(_) => CodeQueryRowScalarType::ConstrainedEnum,
            Self::DeclarationIdentity(_) => CodeQueryRowScalarType::DeclarationIdentity,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeQueryRowFieldError {
    domain: DetailedCodeQueryDomain,
    field: String,
}

impl CodeQueryRowFieldError {
    pub const fn domain(&self) -> DetailedCodeQueryDomain {
        self.domain
    }

    pub fn field(&self) -> &str {
        &self.field
    }
}

impl std::fmt::Display for CodeQueryRowFieldError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "field `{}` is not registered for CodeQuery domain `{}`",
            self.field,
            self.domain.label()
        )
    }
}

impl std::error::Error for CodeQueryRowFieldError {}

/// A typed borrowed view over one public CodeQuery result row.
#[derive(Debug, Clone, Copy)]
pub struct CodeQueryRowRef<'a> {
    value: &'a CodeQueryResultValue,
}

impl DetailedCodeQueryDomain {
    pub const fn from_query_value_kind(kind: QueryValueKind) -> Self {
        match kind {
            QueryValueKind::StructuralMatch => Self::StructuralMatch,
            QueryValueKind::Declaration => Self::Declaration,
            QueryValueKind::Procedure => Self::Procedure,
            QueryValueKind::ProgramPoint => Self::ProgramPoint,
            QueryValueKind::ControlEdge => Self::ControlEdge,
            QueryValueKind::TypestateFinding => Self::TypestateFinding,
            QueryValueKind::TypestateWitness => Self::TypestateWitness,
            QueryValueKind::FlowEndpoint => Self::FlowEndpoint,
            QueryValueKind::FlowWitness => Self::FlowWitness,
            QueryValueKind::TaintFinding => Self::TaintFinding,
            QueryValueKind::ReferenceSite => Self::ReferenceSite,
            QueryValueKind::CallSite => Self::CallSite,
            QueryValueKind::ExpressionSite => Self::ExpressionSite,
            QueryValueKind::ReceiverAnalysis => Self::ReceiverAnalysis,
            QueryValueKind::ReceiverOutcome => Self::ReceiverOutcome,
            QueryValueKind::CallShape => Self::CallShape,
            QueryValueKind::CallArgumentGroup => Self::CallArgumentGroup,
            QueryValueKind::CallArgument => Self::CallArgument,
            QueryValueKind::ReceiverEvidence => Self::ReceiverEvidence,
            QueryValueKind::MemberSelection => Self::MemberSelection,
            QueryValueKind::Occurrence => Self::Occurrence,
            QueryValueKind::LexicalScope => Self::LexicalScope,
            QueryValueKind::Binding => Self::Binding,
            QueryValueKind::ResolutionCandidate => Self::ResolutionCandidate,
            QueryValueKind::GenerationSite => Self::GenerationSite,
            QueryValueKind::Export => Self::Export,
            QueryValueKind::DeclarationState => Self::DeclarationState,
            QueryValueKind::QualifiedPath => Self::QualifiedPath,
            QueryValueKind::PathSegment => Self::PathSegment,
            QueryValueKind::ReferenceEdge => Self::ReferenceEdge,
            QueryValueKind::File => Self::File,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::StructuralMatch => "structural_match",
            Self::Declaration => "declaration",
            Self::Procedure => "procedure",
            Self::ProgramPoint => "program_point",
            Self::ControlEdge => "control_edge",
            Self::TypestateFinding => "typestate_finding",
            Self::TypestateWitness => "typestate_witness",
            Self::FlowEndpoint => "flow_endpoint",
            Self::FlowWitness => "flow_witness",
            Self::TaintFinding => "taint_finding",
            Self::File => "file",
            Self::ReferenceSite => "reference_site",
            Self::CallSite => "call_site",
            Self::ExpressionSite => "expression_site",
            Self::ReceiverAnalysis => "receiver_analysis",
            Self::ReceiverOutcome => "receiver_outcome",
            Self::CallShape => "call_shape",
            Self::CallArgumentGroup => "call_argument_group",
            Self::CallArgument => "call_argument",
            Self::ReceiverEvidence => "receiver_evidence",
            Self::MemberSelection => "member_selection",
            Self::Occurrence => "occurrence",
            Self::LexicalScope => "lexical_scope",
            Self::Binding => "binding",
            Self::ResolutionCandidate => "resolution_candidate",
            Self::GenerationSite => "generation_site",
            Self::Export => "export",
            Self::DeclarationState => "declaration_state",
            Self::QualifiedPath => "qualified_path",
            Self::PathSegment => "path_segment",
            Self::ReferenceEdge => "reference_edge",
        }
    }

    /// The complete stable scalar surface addressable by relational policy
    /// evaluation for this domain.
    pub fn row_fields(self) -> &'static [CodeQueryRowField] {
        use CodeQueryRowScalarType as Scalar;
        match self {
            Self::StructuralMatch => code_query_row_fields![
                CodeQueryRowField::optional("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("kind", Scalar::ConstrainedEnum),
            ],
            Self::Declaration => code_query_row_fields![
                CodeQueryRowField::optional("id", Scalar::DeclarationIdentity),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("fq_name", Scalar::String),
            ],
            Self::Procedure => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("artifact_id", Scalar::StableId),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("procedure_kind", Scalar::ConstrainedEnum),
            ],
            Self::ProgramPoint => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("procedure_id", Scalar::StableId),
                CodeQueryRowField::required("event_count", Scalar::Integer),
            ],
            Self::ControlEdge => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("procedure_id", Scalar::StableId),
                CodeQueryRowField::required("edge_kind", Scalar::ConstrainedEnum),
            ],
            Self::TypestateFinding => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("protocol_ref", Scalar::StableId),
                CodeQueryRowField::required("path_proven", Scalar::Boolean),
                CodeQueryRowField::required("path_complete", Scalar::Boolean),
                CodeQueryRowField::required("analysis_complete", Scalar::Boolean),
                CodeQueryRowField::required("abstained", Scalar::Boolean),
            ],
            Self::TypestateWitness => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("finding_id", Scalar::StableId),
                CodeQueryRowField::required("witness_index", Scalar::Integer),
                CodeQueryRowField::required("truncated", Scalar::Boolean),
            ],
            Self::FlowEndpoint => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("plan_ref", Scalar::StableId),
                CodeQueryRowField::required("ambiguous", Scalar::Boolean),
                CodeQueryRowField::required("semantic_status", Scalar::ConstrainedEnum),
            ],
            Self::FlowWitness => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("endpoint_id", Scalar::StableId),
                CodeQueryRowField::required("witness_index", Scalar::Integer),
                CodeQueryRowField::required("truncated", Scalar::Boolean),
            ],
            Self::TaintFinding => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("sink_event_id", Scalar::StableId),
                CodeQueryRowField::required("origins_truncated", Scalar::Boolean),
                CodeQueryRowField::required("witnesses_truncated", Scalar::Boolean),
                CodeQueryRowField::required("ambiguous", Scalar::Boolean),
            ],
            Self::File => code_query_row_fields![
                CodeQueryRowField::required("path", Scalar::String),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("package_fq", Scalar::String),
                CodeQueryRowField::optional("package_syntactic", Scalar::Boolean),
            ],
            Self::ReferenceSite => code_query_row_fields![
                CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::required("usage_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("proof", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("reference_kind", Scalar::ConstrainedEnum),
            ],
            Self::CallSite => code_query_row_fields![
                CodeQueryRowField::optional("caller_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::optional("callee_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::required("call_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("proof", Scalar::ConstrainedEnum),
            ],
            Self::ExpressionSite => code_query_row_fields![
                CodeQueryRowField::required("input_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("parameter_index", Scalar::Integer),
                CodeQueryRowField::optional("parameter_name", Scalar::String),
            ],
            Self::ReceiverAnalysis => code_query_row_fields![
                CodeQueryRowField::required("site_id", Scalar::StableId),
                CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                CodeQueryRowField::required("analysis_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("outcome", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("capture", Scalar::String),
            ],
            Self::ReceiverOutcome => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("site_id", Scalar::StableId),
                CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                CodeQueryRowField::required("analysis_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("outcome", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("coverage", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("candidate_count", Scalar::Integer),
                CodeQueryRowField::required("candidates_truncated", Scalar::Boolean),
                CodeQueryRowField::optional("semantic_unsupported", Scalar::ConstrainedEnum),
            ],
            Self::ReceiverEvidence => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("site_id", Scalar::StableId),
                CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                CodeQueryRowField::optional("parent_evidence_id", Scalar::StableId),
                CodeQueryRowField::required("ordinal", Scalar::Integer),
                CodeQueryRowField::required("chain_hop", Scalar::Integer),
                CodeQueryRowField::required("evidence_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("declaration_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::optional("factory_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::required("proof", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("completeness", Scalar::ConstrainedEnum),
            ],
            Self::CallShape => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("site_id", Scalar::StableId),
                CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                CodeQueryRowField::required("call_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("coverage", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("group_count", Scalar::Integer),
            ],
            Self::CallArgumentGroup => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("site_id", Scalar::StableId),
                CodeQueryRowField::required("group_index", Scalar::Integer),
                CodeQueryRowField::required("kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("argument_count", Scalar::Integer),
            ],
            Self::CallArgument => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("group_id", Scalar::StableId),
                CodeQueryRowField::required("site_id", Scalar::StableId),
                CodeQueryRowField::required("argument_index", Scalar::Integer),
                CodeQueryRowField::optional("name", Scalar::String),
                CodeQueryRowField::required("spread", Scalar::Boolean),
            ],
            Self::MemberSelection => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                CodeQueryRowField::required("member", Scalar::String),
                CodeQueryRowField::required("role", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("outcome", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("selected_count", Scalar::Integer),
                CodeQueryRowField::required("candidate_count", Scalar::Integer),
                CodeQueryRowField::required("trace_completeness", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("coverage", Scalar::ConstrainedEnum),
            ],
            Self::Occurrence => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("ast_id", Scalar::StableId),
                CodeQueryRowField::required("class", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("role", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("namespace", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("target_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::required("target_count", Scalar::Integer),
            ],
            Self::LexicalScope => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("index", Scalar::Integer),
                CodeQueryRowField::optional("kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("parent_index", Scalar::Integer),
            ],
            Self::Binding => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::optional("reached_from_ast_id", Scalar::StableId),
                CodeQueryRowField::required("name", Scalar::String),
                CodeQueryRowField::required("kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("hoisting", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("namespace", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("declaring_scope_index", Scalar::Integer),
                CodeQueryRowField::required("visibility", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("shadowed", Scalar::Boolean),
            ],
            Self::ResolutionCandidate => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("ast_id", Scalar::StableId),
                CodeQueryRowField::required("ordinal", Scalar::Integer),
                CodeQueryRowField::optional("tier", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("outcome", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("rejection_reason", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("boundary", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("visibility", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("trace_completeness", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("candidate_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("candidate_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::optional("canonical_member_id", Scalar::StableId),
            ],
            Self::GenerationSite => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("path", Scalar::String),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("input", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("generated_count", Scalar::Integer),
            ],
            Self::Export => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("path", Scalar::String),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("form", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("exported_name", Scalar::String),
                CodeQueryRowField::optional("target_fq_name", Scalar::String),
            ],
            Self::DeclarationState => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("path", Scalar::String),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("fq_name", Scalar::String),
                CodeQueryRowField::required("unit_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("origin", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("declaration_only", Scalar::Boolean),
                CodeQueryRowField::required("config_gated", Scalar::Boolean),
            ],
            Self::QualifiedPath => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required("ast_id", Scalar::StableId),
                CodeQueryRowField::required("segment_count", Scalar::Integer),
            ],
            Self::PathSegment => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("path_ast_id", Scalar::StableId),
                CodeQueryRowField::required("ordinal", Scalar::Integer),
                CodeQueryRowField::required("text", Scalar::String),
                CodeQueryRowField::optional("namespace", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("generic_arity", Scalar::Integer),
                CodeQueryRowField::optional("resolution_status", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("target_count", Scalar::Integer),
            ],
            Self::ReferenceEdge => code_query_row_fields![
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::optional("ast_id", Scalar::StableId),
                CodeQueryRowField::required("language", Scalar::ConstrainedEnum),
                CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                CodeQueryRowField::optional("reference_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("proof", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("usage_kind", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("site_class", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("owner_relation", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("edge_provenance", Scalar::ConstrainedEnum),
                CodeQueryRowField::required("generation", Scalar::Integer),
            ],
        }
    }
}

impl CodeQueryResultValue {
    pub fn row(&self) -> CodeQueryRowRef<'_> {
        CodeQueryRowRef { value: self }
    }

    /// The exact display region of this row's own source anchor. `None` when
    /// the row has no source region of its own (a file row, or an evidence row
    /// whose location is its site's outcome row).
    pub fn display_range(&self) -> Option<CodeQueryRange> {
        match self {
            Self::StructuralMatch { value } => value.node_range,
            Self::Declaration { value } => value.node_range,
            Self::Procedure { value } => Some(value.range),
            Self::ProgramPoint { value } => Some(value.range),
            Self::ControlEdge { value } => Some(value.range),
            Self::TypestateFinding { value } => Some(value.range),
            Self::TypestateWitness { value } => Some(value.range),
            Self::FlowEndpoint { value } => Some(value.range),
            Self::FlowWitness { value } => Some(value.range),
            Self::TaintFinding { value } => Some(value.range),
            Self::File { .. } | Self::ReceiverEvidence { .. } => None,
            Self::ReferenceSite { value } => Some(value.range),
            Self::CallSite { value } => Some(value.range),
            Self::ExpressionSite { value } => Some(value.range),
            Self::ReceiverAnalysis { value } => Some(value.range),
            Self::ReceiverOutcome { value } => Some(value.range),
            Self::MemberSelection { value } => Some(value.range),
            Self::CallShape { value } => Some(value.range),
            Self::CallArgumentGroup { value } => Some(value.range),
            Self::CallArgument { value } => Some(value.range),
            Self::Occurrence { value } => Some(value.range),
            Self::LexicalScope { value } => Some(value.range),
            Self::Binding { value } => Some(value.range),
            Self::ResolutionCandidate { value } => Some(value.range),
            Self::GenerationSite { value } => Some(value.range),
            Self::Export { value } => Some(value.range),
            Self::DeclarationState { value } => value.range,
            Self::ReferenceEdge { value } => Some(value.range),
            Self::QualifiedPath { value } => Some(value.range),
            Self::PathSegment { value } => Some(value.range),
        }
    }

    pub const fn detailed_domain(&self) -> DetailedCodeQueryDomain {
        match self {
            Self::StructuralMatch { .. } => DetailedCodeQueryDomain::StructuralMatch,
            Self::Declaration { .. } => DetailedCodeQueryDomain::Declaration,
            Self::Procedure { .. } => DetailedCodeQueryDomain::Procedure,
            Self::ProgramPoint { .. } => DetailedCodeQueryDomain::ProgramPoint,
            Self::ControlEdge { .. } => DetailedCodeQueryDomain::ControlEdge,
            Self::TypestateFinding { .. } => DetailedCodeQueryDomain::TypestateFinding,
            Self::TypestateWitness { .. } => DetailedCodeQueryDomain::TypestateWitness,
            Self::FlowEndpoint { .. } => DetailedCodeQueryDomain::FlowEndpoint,
            Self::FlowWitness { .. } => DetailedCodeQueryDomain::FlowWitness,
            Self::TaintFinding { .. } => DetailedCodeQueryDomain::TaintFinding,
            Self::File { .. } => DetailedCodeQueryDomain::File,
            Self::ReferenceSite { .. } => DetailedCodeQueryDomain::ReferenceSite,
            Self::CallSite { .. } => DetailedCodeQueryDomain::CallSite,
            Self::ExpressionSite { .. } => DetailedCodeQueryDomain::ExpressionSite,
            Self::ReceiverAnalysis { .. } => DetailedCodeQueryDomain::ReceiverAnalysis,
            Self::ReceiverOutcome { .. } => DetailedCodeQueryDomain::ReceiverOutcome,
            Self::ReceiverEvidence { .. } => DetailedCodeQueryDomain::ReceiverEvidence,
            Self::CallShape { .. } => DetailedCodeQueryDomain::CallShape,
            Self::CallArgumentGroup { .. } => DetailedCodeQueryDomain::CallArgumentGroup,
            Self::CallArgument { .. } => DetailedCodeQueryDomain::CallArgument,
            Self::MemberSelection { .. } => DetailedCodeQueryDomain::MemberSelection,
            Self::Occurrence { .. } => DetailedCodeQueryDomain::Occurrence,
            Self::LexicalScope { .. } => DetailedCodeQueryDomain::LexicalScope,
            Self::Binding { .. } => DetailedCodeQueryDomain::Binding,
            Self::ResolutionCandidate { .. } => DetailedCodeQueryDomain::ResolutionCandidate,
            Self::GenerationSite { .. } => DetailedCodeQueryDomain::GenerationSite,
            Self::Export { .. } => DetailedCodeQueryDomain::Export,
            Self::DeclarationState { .. } => DetailedCodeQueryDomain::DeclarationState,
            Self::QualifiedPath { .. } => DetailedCodeQueryDomain::QualifiedPath,
            Self::PathSegment { .. } => DetailedCodeQueryDomain::PathSegment,
            Self::ReferenceEdge { .. } => DetailedCodeQueryDomain::ReferenceEdge,
        }
    }
}

impl<'a> CodeQueryRowRef<'a> {
    pub const fn domain(self) -> DetailedCodeQueryDomain {
        self.value.detailed_domain()
    }

    pub fn fields(self) -> &'static [CodeQueryRowField] {
        self.domain().row_fields()
    }

    pub fn field(
        self,
        name: &str,
    ) -> Result<Option<CodeQueryRowScalarRef<'a>>, CodeQueryRowFieldError> {
        let Some(schema) = self.fields().iter().find(|field| field.name == name) else {
            return Err(CodeQueryRowFieldError {
                domain: self.domain(),
                field: name.to_string(),
            });
        };
        let value = project_code_query_row_field(self.value, name);
        debug_assert!(
            value.is_none() || value.is_some_and(|value| value.scalar_type() == schema.scalar_type),
            "registered CodeQuery row field projector returned the wrong scalar type"
        );
        debug_assert!(
            schema.nullable || value.is_some(),
            "required CodeQuery row field projector returned no value"
        );
        Ok(value)
    }
}

#[allow(clippy::too_many_lines)]
fn project_code_query_row_field<'a>(
    value: &'a CodeQueryResultValue,
    name: &str,
) -> Option<CodeQueryRowScalarRef<'a>> {
    use CodeQueryRowScalarRef as Scalar;
    match (value, name) {
        (CodeQueryResultValue::StructuralMatch { value }, "id") => {
            value.id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::StructuralMatch { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::StructuralMatch { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::StructuralMatch { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::Declaration { value }, "id") => {
            value.id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::Declaration { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::Declaration { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::Declaration { value }, "fq_name") => {
            Some(Scalar::String(&value.fq_name))
        }
        (CodeQueryResultValue::Procedure { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::Procedure { value }, "artifact_id") => {
            Some(Scalar::StableId(&value.artifact_id))
        }
        (CodeQueryResultValue::Procedure { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::Procedure { value }, "procedure_kind") => {
            Some(Scalar::ConstrainedEnum(value.procedure_kind))
        }
        (CodeQueryResultValue::ProgramPoint { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::ProgramPoint { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::ProgramPoint { value }, "event_count") => {
            Some(Scalar::Integer(value.event_count as u64))
        }
        (CodeQueryResultValue::ControlEdge { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::ControlEdge { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::ControlEdge { value }, "edge_kind") => {
            Some(Scalar::ConstrainedEnum(value.edge_kind))
        }
        (CodeQueryResultValue::TypestateFinding { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::TypestateFinding { value }, "protocol_ref") => {
            Some(Scalar::StableId(&value.protocol_ref))
        }
        (CodeQueryResultValue::TypestateFinding { value }, "path_proven") => {
            Some(Scalar::Boolean(value.path_proven))
        }
        (CodeQueryResultValue::TypestateFinding { value }, "path_complete") => {
            Some(Scalar::Boolean(value.path_complete))
        }
        (CodeQueryResultValue::TypestateFinding { value }, "analysis_complete") => {
            Some(Scalar::Boolean(value.analysis_complete))
        }
        (CodeQueryResultValue::TypestateFinding { value }, "abstained") => {
            Some(Scalar::Boolean(value.abstained))
        }
        (CodeQueryResultValue::TypestateWitness { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::TypestateWitness { value }, "finding_id") => {
            Some(Scalar::StableId(&value.finding_id))
        }
        (CodeQueryResultValue::TypestateWitness { value }, "witness_index") => {
            Some(Scalar::Integer(value.witness_index as u64))
        }
        (CodeQueryResultValue::TypestateWitness { value }, "truncated") => {
            Some(Scalar::Boolean(value.truncated))
        }
        (CodeQueryResultValue::FlowEndpoint { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::FlowEndpoint { value }, "plan_ref") => {
            Some(Scalar::StableId(&value.plan_ref))
        }
        (CodeQueryResultValue::FlowEndpoint { value }, "ambiguous") => {
            Some(Scalar::Boolean(value.ambiguous))
        }
        (CodeQueryResultValue::FlowEndpoint { value }, "semantic_status") => {
            Some(Scalar::ConstrainedEnum(value.semantic_status))
        }
        (CodeQueryResultValue::FlowWitness { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::FlowWitness { value }, "endpoint_id") => {
            Some(Scalar::StableId(&value.endpoint_id))
        }
        (CodeQueryResultValue::FlowWitness { value }, "witness_index") => {
            Some(Scalar::Integer(value.witness_index as u64))
        }
        (CodeQueryResultValue::FlowWitness { value }, "truncated") => {
            Some(Scalar::Boolean(value.truncated))
        }
        (CodeQueryResultValue::TaintFinding { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::TaintFinding { value }, "sink_event_id") => {
            Some(Scalar::StableId(&value.sink_event_id))
        }
        (CodeQueryResultValue::TaintFinding { value }, "origins_truncated") => {
            Some(Scalar::Boolean(value.origins_truncated))
        }
        (CodeQueryResultValue::TaintFinding { value }, "witnesses_truncated") => {
            Some(Scalar::Boolean(value.witnesses_truncated))
        }
        (CodeQueryResultValue::TaintFinding { value }, "ambiguous") => {
            Some(Scalar::Boolean(value.ambiguous))
        }
        (CodeQueryResultValue::File { value }, "path") => Some(Scalar::String(&value.path)),
        (CodeQueryResultValue::File { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::File { value }, "package_fq") => {
            value.package_fq.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::File { value }, "package_syntactic") => {
            value.package_syntactic.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::ReferenceSite { value }, "target_id") => {
            value.target.id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::ReferenceSite { value }, "usage_kind") => {
            Some(Scalar::ConstrainedEnum(value.usage_kind))
        }
        (CodeQueryResultValue::ReferenceSite { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ReferenceSite { value }, "reference_kind") => {
            value.reference_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallSite { value }, "caller_id") => {
            value.caller.id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::CallSite { value }, "callee_id") => {
            value.callee.id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::CallSite { value }, "call_kind") => {
            Some(Scalar::ConstrainedEnum(value.call_kind))
        }
        (CodeQueryResultValue::CallSite { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ExpressionSite { value }, "input_kind") => {
            Some(Scalar::ConstrainedEnum(value.input_kind))
        }
        (CodeQueryResultValue::ExpressionSite { value }, "parameter_index") => value
            .parameter_index
            .map(|index| Scalar::Integer(index as u64)),
        (CodeQueryResultValue::ExpressionSite { value }, "parameter_name") => {
            value.parameter_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ReceiverAnalysis { value }, "analysis_kind") => {
            Some(Scalar::ConstrainedEnum(value.analysis_kind))
        }
        (CodeQueryResultValue::ReceiverAnalysis { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::ReceiverAnalysis { value }, "site_ast_id") => {
            value.site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ReceiverAnalysis { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::ReceiverAnalysis { value }, "capture") => {
            value.capture.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "site_ast_id") => {
            value.site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "analysis_kind") => {
            Some(Scalar::ConstrainedEnum(value.analysis_kind))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "candidate_count") => {
            Some(Scalar::Integer(value.candidate_count as u64))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "candidates_truncated") => {
            Some(Scalar::Boolean(value.candidates_truncated))
        }
        (CodeQueryResultValue::ReceiverOutcome { value }, "semantic_unsupported") => {
            value.semantic_unsupported.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallShape { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CallShape { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallShape { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallShape { value }, "call_kind") => {
            Some(Scalar::ConstrainedEnum(value.call_kind))
        }
        (CodeQueryResultValue::CallShape { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallShape { value }, "group_count") => {
            Some(Scalar::Integer(value.group_count as u64))
        }
        (CodeQueryResultValue::CallArgumentGroup { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallArgumentGroup { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallArgumentGroup { value }, "group_index") => {
            Some(Scalar::Integer(value.group_index as u64))
        }
        (CodeQueryResultValue::CallArgumentGroup { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::CallArgumentGroup { value }, "argument_count") => {
            Some(Scalar::Integer(value.argument_count as u64))
        }
        (CodeQueryResultValue::CallArgument { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CallArgument { value }, "group_id") => {
            Some(Scalar::StableId(&value.group_id))
        }
        (CodeQueryResultValue::CallArgument { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallArgument { value }, "argument_index") => {
            Some(Scalar::Integer(value.argument_index as u64))
        }
        (CodeQueryResultValue::CallArgument { value }, "name") => {
            value.name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallArgument { value }, "spread") => {
            Some(Scalar::Boolean(value.spread))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "site_ast_id") => {
            value.site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "parent_evidence_id") => {
            value.parent_evidence_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "chain_hop") => {
            Some(Scalar::Integer(value.chain_hop as u64))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "evidence_kind") => {
            Some(Scalar::ConstrainedEnum(value.evidence_kind))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "declaration_id") => value
            .declaration_id
            .as_deref()
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::ReceiverEvidence { value }, "factory_id") => {
            value.factory_id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::MemberSelection { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::MemberSelection { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::MemberSelection { value }, "member") => {
            Some(Scalar::String(&value.member))
        }
        (CodeQueryResultValue::MemberSelection { value }, "role") => {
            Some(Scalar::ConstrainedEnum(value.role))
        }
        (CodeQueryResultValue::MemberSelection { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::MemberSelection { value }, "selected_count") => {
            Some(Scalar::Integer(value.selected_count as u64))
        }
        (CodeQueryResultValue::MemberSelection { value }, "candidate_count") => {
            Some(Scalar::Integer(value.candidate_count as u64))
        }
        (CodeQueryResultValue::MemberSelection { value }, "trace_completeness") => {
            Some(Scalar::ConstrainedEnum(value.trace_completeness))
        }
        (CodeQueryResultValue::MemberSelection { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::Occurrence { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::Occurrence { value }, "ast_id") => {
            Some(Scalar::StableId(&value.ast_id))
        }
        (CodeQueryResultValue::Occurrence { value }, "class") => {
            Some(Scalar::ConstrainedEnum(value.class))
        }
        (CodeQueryResultValue::Occurrence { value }, "role") => {
            Some(Scalar::ConstrainedEnum(value.role))
        }
        (CodeQueryResultValue::Occurrence { value }, "namespace") => {
            Some(Scalar::ConstrainedEnum(value.namespace))
        }
        (CodeQueryResultValue::Occurrence { value }, "target_kind") => {
            let kind = match &value.target {
                CodeQueryOccurrenceTarget::None => "none",
                CodeQueryOccurrenceTarget::Resolved { .. } => "resolved",
                CodeQueryOccurrenceTarget::Lexical { .. } => "lexical",
                CodeQueryOccurrenceTarget::Unresolved { .. } => "unresolved",
            };
            Some(Scalar::ConstrainedEnum(kind))
        }
        (CodeQueryResultValue::Occurrence { value }, "target_id") => match &value.target {
            CodeQueryOccurrenceTarget::Resolved { units } if units.len() == 1 => {
                units[0].id.as_deref().map(Scalar::DeclarationIdentity)
            }
            _ => None,
        },
        (CodeQueryResultValue::Occurrence { value }, "target_count") => {
            let count = match &value.target {
                CodeQueryOccurrenceTarget::Resolved { units } => units.len(),
                CodeQueryOccurrenceTarget::Lexical { .. } => 1,
                CodeQueryOccurrenceTarget::None | CodeQueryOccurrenceTarget::Unresolved { .. } => 0,
            };
            Some(Scalar::Integer(count as u64))
        }
        (CodeQueryResultValue::LexicalScope { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::LexicalScope { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::LexicalScope { value }, "index") => {
            Some(Scalar::Integer(u64::from(value.index)))
        }
        (CodeQueryResultValue::LexicalScope { value }, "kind") => {
            value.kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::LexicalScope { value }, "parent_index") => value
            .parent_index
            .map(|index| Scalar::Integer(u64::from(index))),
        (CodeQueryResultValue::Binding { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::Binding { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Binding { value }, "reached_from_ast_id") => {
            value.reached_from_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Binding { value }, "name") => Some(Scalar::String(&value.name)),
        (CodeQueryResultValue::Binding { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::Binding { value }, "hoisting") => {
            Some(Scalar::ConstrainedEnum(value.hoisting))
        }
        (CodeQueryResultValue::Binding { value }, "namespace") => {
            Some(Scalar::ConstrainedEnum(value.namespace))
        }
        (CodeQueryResultValue::Binding { value }, "declaring_scope_index") => {
            Some(Scalar::Integer(u64::from(value.declaring_scope_index)))
        }
        (CodeQueryResultValue::Binding { value }, "visibility") => {
            Some(Scalar::ConstrainedEnum(value.visibility))
        }
        (CodeQueryResultValue::Binding { value }, "shadowed") => {
            Some(Scalar::Boolean(value.shadowed))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "ast_id") => {
            Some(Scalar::StableId(&value.ast_id))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "tier") => {
            value.tier.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "rejection_reason") => {
            value.rejection_reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "boundary") => {
            Some(Scalar::ConstrainedEnum(value.boundary))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "visibility") => {
            Some(Scalar::ConstrainedEnum(value.visibility))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "trace_completeness") => {
            Some(Scalar::ConstrainedEnum(value.trace_completeness))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "candidate_kind") => {
            Some(Scalar::ConstrainedEnum(value.candidate.label()))
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "canonical_member_id") => {
            value.canonical_member_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "candidate_id") => {
            match &value.candidate {
                CodeQueryCandidateRef::Unit { unit } => {
                    unit.id.as_deref().map(Scalar::DeclarationIdentity)
                }
                _ => None,
            }
        }
        (CodeQueryResultValue::GenerationSite { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::GenerationSite { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::GenerationSite { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::GenerationSite { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::GenerationSite { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::GenerationSite { value }, "input") => {
            Some(Scalar::ConstrainedEnum(value.input))
        }
        (CodeQueryResultValue::GenerationSite { value }, "generated_count") => {
            Some(Scalar::Integer(value.generated_count as u64))
        }
        (CodeQueryResultValue::Export { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::Export { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Export { value }, "path") => Some(Scalar::String(&value.path)),
        (CodeQueryResultValue::Export { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::Export { value }, "form") => {
            Some(Scalar::ConstrainedEnum(value.form))
        }
        (CodeQueryResultValue::Export { value }, "exported_name") => {
            Some(Scalar::String(&value.exported_name))
        }
        (CodeQueryResultValue::Export { value }, "target_fq_name") => {
            value.target_fq_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DeclarationState { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::DeclarationState { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DeclarationState { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::DeclarationState { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::DeclarationState { value }, "fq_name") => {
            Some(Scalar::String(&value.fq_name))
        }
        (CodeQueryResultValue::DeclarationState { value }, "unit_kind") => {
            Some(Scalar::ConstrainedEnum(value.unit_kind))
        }
        (CodeQueryResultValue::DeclarationState { value }, "origin") => {
            Some(Scalar::ConstrainedEnum(value.origin))
        }
        (CodeQueryResultValue::DeclarationState { value }, "declaration_only") => {
            Some(Scalar::Boolean(value.declaration_only))
        }
        (CodeQueryResultValue::DeclarationState { value }, "config_gated") => {
            Some(Scalar::Boolean(value.config_gated))
        }
        (CodeQueryResultValue::QualifiedPath { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::QualifiedPath { value }, "ast_id") => {
            Some(Scalar::StableId(&value.ast_id))
        }
        (CodeQueryResultValue::QualifiedPath { value }, "segment_count") => {
            Some(Scalar::Integer(u64::from(value.segment_count)))
        }
        (CodeQueryResultValue::PathSegment { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::PathSegment { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PathSegment { value }, "path_ast_id") => {
            Some(Scalar::StableId(&value.path_ast_id))
        }
        (CodeQueryResultValue::PathSegment { value }, "ordinal") => {
            Some(Scalar::Integer(u64::from(value.ordinal)))
        }
        (CodeQueryResultValue::PathSegment { value }, "text") => Some(Scalar::String(&value.text)),
        (CodeQueryResultValue::PathSegment { value }, "namespace") => {
            value.namespace.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PathSegment { value }, "generic_arity") => value
            .generic_arity
            .map(|arity| Scalar::Integer(u64::from(arity))),
        (CodeQueryResultValue::PathSegment { value }, "resolution_status") => {
            value.resolution_status.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PathSegment { value }, "target_count") => value
            .target_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::ReferenceEdge { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::ReferenceEdge { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "target_id") => {
            value.target.id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "reference_kind") => {
            value.reference_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "usage_kind") => {
            Some(Scalar::ConstrainedEnum(value.usage_kind))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "site_class") => {
            Some(Scalar::ConstrainedEnum(value.site_class))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "owner_relation") => {
            Some(Scalar::ConstrainedEnum(value.owner_relation))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "edge_provenance") => {
            Some(Scalar::ConstrainedEnum(value.provenance))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "generation") => {
            Some(Scalar::Integer(value.generation))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedCodeQueryKey {
    StructuralMatch {
        kind: String,
        analyzer_id: Option<String>,
    },
    Declaration {
        kind: String,
        fq_name: String,
        analyzer_id: Option<String>,
    },
    Procedure {
        id: String,
    },
    ProgramPoint {
        id: String,
        procedure_id: String,
    },
    ControlEdge {
        id: String,
        procedure_id: String,
    },
    TypestateFinding {
        id: String,
    },
    TypestateWitness {
        id: String,
        finding_id: String,
    },
    FlowEndpoint {
        id: String,
    },
    FlowWitness {
        id: String,
        endpoint_id: String,
    },
    TaintFinding {
        id: String,
    },
    File,
    ReferenceSite {
        target_id: Option<String>,
        target_fq_name: String,
    },
    CallSite {
        caller_fq_name: String,
        callee_fq_name: String,
    },
    ExpressionSite {
        input_kind: String,
        parameter_index: Option<u32>,
        parameter_name: Option<String>,
    },
    ReceiverAnalysis {
        analysis_kind: String,
        outcome: String,
        capture: Option<String>,
    },
    ReceiverOutcome {
        id: String,
        site_id: String,
    },
    ReceiverEvidence {
        id: String,
        site_id: String,
    },
    CallShape {
        id: String,
        site_id: String,
    },
    CallArgumentGroup {
        id: String,
        site_id: String,
    },
    CallArgument {
        id: String,
        group_id: String,
    },
    MemberSelection {
        id: String,
        site_ast_id: String,
    },
    Occurrence {
        id: String,
        ast_id: String,
        role: String,
    },
    LexicalScope {
        id: String,
        ast_id: Option<String>,
        index: u32,
    },
    Binding {
        id: String,
        ast_id: Option<String>,
        name: String,
    },
    ResolutionCandidate {
        id: String,
        ast_id: String,
        ordinal: usize,
    },
    GenerationSite {
        id: String,
        ast_id: Option<String>,
        kind: String,
    },
    Export {
        id: String,
        form: String,
        exported_name: String,
    },
    DeclarationState {
        id: String,
        fq_name: String,
        origin: String,
    },
    ReferenceEdge {
        id: String,
        ast_id: Option<String>,
        target_fq_name: String,
        provenance: String,
    },
    QualifiedPath {
        id: String,
        ast_id: String,
    },
    PathSegment {
        id: String,
        ast_id: Option<String>,
        ordinal: u32,
    },
}

impl DetailedCodeQueryResult {
    pub(in super::super) fn assert_invariants(&self) {
        if let Some(profile) = &self.profile {
            assert!(
                profile.peak_concurrency >= 1,
                "an executed CodeQuery profile must observe at least one active operator"
            );
            assert!(
                !profile.operators.is_empty(),
                "an executed CodeQuery profile must contain operator observations"
            );
        }
        assert_eq!(
            self.result.results.len(),
            self.evidence.len(),
            "detailed CodeQuery evidence must stay aligned with public results"
        );
        assert!(
            self.work.pipeline_rows
                >= u64::try_from(self.evidence.len())
                    .expect("usize fits in u64 on supported targets"),
            "retained CodeQuery results cannot exceed directly tracked pipeline rows"
        );
        for (result_index, evidence) in self.evidence.iter().enumerate() {
            let result = &self.result.results[result_index];
            assert_eq!(
                evidence.result_index, result_index,
                "detailed CodeQuery evidence index must equal its vector index"
            );
            if let Some((expected_domain, expected_key)) = detailed_semantic_identity(&result.value)
            {
                assert_eq!(evidence.domain, expected_domain);
                assert_eq!(evidence.key, expected_key);
            }
            assert!(
                matches!(
                    (evidence.domain, &evidence.key),
                    (
                        DetailedCodeQueryDomain::StructuralMatch,
                        DetailedCodeQueryKey::StructuralMatch { .. }
                    ) | (
                        DetailedCodeQueryDomain::Declaration,
                        DetailedCodeQueryKey::Declaration { .. }
                    ) | (
                        DetailedCodeQueryDomain::Procedure,
                        DetailedCodeQueryKey::Procedure { .. }
                    ) | (
                        DetailedCodeQueryDomain::ProgramPoint,
                        DetailedCodeQueryKey::ProgramPoint { .. }
                    ) | (
                        DetailedCodeQueryDomain::ControlEdge,
                        DetailedCodeQueryKey::ControlEdge { .. }
                    ) | (
                        DetailedCodeQueryDomain::TypestateFinding,
                        DetailedCodeQueryKey::TypestateFinding { .. }
                    ) | (
                        DetailedCodeQueryDomain::TypestateWitness,
                        DetailedCodeQueryKey::TypestateWitness { .. }
                    ) | (
                        DetailedCodeQueryDomain::FlowEndpoint,
                        DetailedCodeQueryKey::FlowEndpoint { .. }
                    ) | (
                        DetailedCodeQueryDomain::FlowWitness,
                        DetailedCodeQueryKey::FlowWitness { .. }
                    ) | (
                        DetailedCodeQueryDomain::TaintFinding,
                        DetailedCodeQueryKey::TaintFinding { .. }
                    ) | (DetailedCodeQueryDomain::File, DetailedCodeQueryKey::File)
                        | (
                            DetailedCodeQueryDomain::ReferenceSite,
                            DetailedCodeQueryKey::ReferenceSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::CallSite,
                            DetailedCodeQueryKey::CallSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ExpressionSite,
                            DetailedCodeQueryKey::ExpressionSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ReceiverAnalysis,
                            DetailedCodeQueryKey::ReceiverAnalysis { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ReceiverOutcome,
                            DetailedCodeQueryKey::ReceiverOutcome { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ReceiverEvidence,
                            DetailedCodeQueryKey::ReceiverEvidence { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::CallShape,
                            DetailedCodeQueryKey::CallShape { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::CallArgumentGroup,
                            DetailedCodeQueryKey::CallArgumentGroup { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::CallArgument,
                            DetailedCodeQueryKey::CallArgument { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::MemberSelection,
                            DetailedCodeQueryKey::MemberSelection { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::Occurrence,
                            DetailedCodeQueryKey::Occurrence { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::LexicalScope,
                            DetailedCodeQueryKey::LexicalScope { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::Binding,
                            DetailedCodeQueryKey::Binding { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ResolutionCandidate,
                            DetailedCodeQueryKey::ResolutionCandidate { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::GenerationSite,
                            DetailedCodeQueryKey::GenerationSite { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::Export,
                            DetailedCodeQueryKey::Export { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::DeclarationState,
                            DetailedCodeQueryKey::DeclarationState { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::ReferenceEdge,
                            DetailedCodeQueryKey::ReferenceEdge { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::QualifiedPath,
                            DetailedCodeQueryKey::QualifiedPath { .. }
                        )
                        | (
                            DetailedCodeQueryDomain::PathSegment,
                            DetailedCodeQueryKey::PathSegment { .. }
                        )
                ),
                "detailed CodeQuery domain and typed key must agree"
            );
            if evidence.source_slice_sha256.is_some() {
                assert!(
                    evidence.byte_span.is_some(),
                    "a source-slice digest requires a byte span"
                );
            }
            if evidence.domain == DetailedCodeQueryDomain::File {
                assert!(evidence.byte_span.is_none());
                assert!(evidence.source_slice_sha256.is_none());
                assert!(evidence.stable_owner_candidate.is_none());
            }
            if let Some(candidate) = &evidence.stable_owner_candidate {
                assert!(!candidate.namespace.is_empty());
                assert!(!candidate.semantic_key.is_empty());
                match candidate.derivation {
                    CodeQueryStableOwnerDerivation::AnalyzerDeclarationId
                    | CodeQueryStableOwnerDerivation::CanonicalAstIdentity
                    | CodeQueryStableOwnerDerivation::SemanticWireId => {}
                }
            }
            if let Some(wire_id) = semantic_wire_id(&evidence.key) {
                let candidate = evidence
                    .stable_owner_candidate
                    .as_ref()
                    .expect("semantic CodeQuery evidence requires its wire identity");
                assert_eq!(
                    candidate.derivation,
                    CodeQueryStableOwnerDerivation::SemanticWireId
                );
                assert_eq!(candidate.semantic_key, wire_id);
            }
            assert_detailed_terminal_identities(evidence.domain, &evidence.identities);
            let _ = &evidence.file;
            assert_eq!(
                result.provenance.len(),
                evidence.provenance.len(),
                "detailed provenance must align with public provenance"
            );
            for (public, detailed) in result.provenance.iter().zip(&evidence.provenance) {
                assert_eq!(public.branch, detailed.branch);
                assert_eq!(public.steps.len(), detailed.steps.len());
                assert_detailed_provenance_ref(&detailed.seed);
                for (public_step, detailed_step) in public.steps.iter().zip(&detailed.steps) {
                    assert_eq!(public_step.op, detailed_step.op);
                    assert_eq!(public_step.via.is_some(), detailed_step.via.is_some());
                    assert_detailed_provenance_ref(&detailed_step.result);
                    if let Some(via) = &detailed_step.via {
                        assert_detailed_provenance_ref(via);
                    }
                }
            }
        }
    }
}

fn detailed_semantic_identity(
    value: &CodeQueryResultValue,
) -> Option<(DetailedCodeQueryDomain, DetailedCodeQueryKey)> {
    match value {
        CodeQueryResultValue::Procedure { value } => Some((
            DetailedCodeQueryDomain::Procedure,
            DetailedCodeQueryKey::Procedure {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::ProgramPoint { value } => Some((
            DetailedCodeQueryDomain::ProgramPoint,
            DetailedCodeQueryKey::ProgramPoint {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::ControlEdge { value } => Some((
            DetailedCodeQueryDomain::ControlEdge,
            DetailedCodeQueryKey::ControlEdge {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::TypestateFinding { value } => Some((
            DetailedCodeQueryDomain::TypestateFinding,
            DetailedCodeQueryKey::TypestateFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::TypestateWitness { value } => Some((
            DetailedCodeQueryDomain::TypestateWitness,
            DetailedCodeQueryKey::TypestateWitness {
                id: value.id.clone(),
                finding_id: value.finding_id.clone(),
            },
        )),
        CodeQueryResultValue::FlowEndpoint { value } => Some((
            DetailedCodeQueryDomain::FlowEndpoint,
            DetailedCodeQueryKey::FlowEndpoint {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::FlowWitness { value } => Some((
            DetailedCodeQueryDomain::FlowWitness,
            DetailedCodeQueryKey::FlowWitness {
                id: value.id.clone(),
                endpoint_id: value.endpoint_id.clone(),
            },
        )),
        CodeQueryResultValue::TaintFinding { value } => Some((
            DetailedCodeQueryDomain::TaintFinding,
            DetailedCodeQueryKey::TaintFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::StructuralMatch { .. }
        | CodeQueryResultValue::Declaration { .. }
        | CodeQueryResultValue::File { .. }
        | CodeQueryResultValue::ReferenceSite { .. }
        | CodeQueryResultValue::CallSite { .. }
        | CodeQueryResultValue::ExpressionSite { .. }
        | CodeQueryResultValue::ReceiverAnalysis { .. }
        | CodeQueryResultValue::ReceiverOutcome { .. }
        | CodeQueryResultValue::ReceiverEvidence { .. }
        | CodeQueryResultValue::CallShape { .. }
        | CodeQueryResultValue::CallArgumentGroup { .. }
        | CodeQueryResultValue::CallArgument { .. }
        | CodeQueryResultValue::MemberSelection { .. }
        | CodeQueryResultValue::Occurrence { .. }
        | CodeQueryResultValue::LexicalScope { .. }
        | CodeQueryResultValue::Binding { .. }
        | CodeQueryResultValue::ResolutionCandidate { .. }
        | CodeQueryResultValue::GenerationSite { .. }
        | CodeQueryResultValue::Export { .. }
        | CodeQueryResultValue::DeclarationState { .. }
        | CodeQueryResultValue::ReferenceEdge { .. } => None,
        CodeQueryResultValue::QualifiedPath { .. } | CodeQueryResultValue::PathSegment { .. } => {
            None
        }
    }
}

fn assert_detailed_provenance_ref(evidence: &DetailedCodeQueryProvenanceRefEvidence) {
    if evidence.source_slice_sha256.is_some() {
        assert!(evidence.byte_span.is_some());
        assert!(evidence.display_range.is_some());
    }
    if evidence.domain == DetailedCodeQueryDomain::File {
        assert!(evidence.byte_span.is_none());
        assert!(evidence.display_range.is_none());
        assert!(evidence.source_slice_sha256.is_none());
        assert!(matches!(
            evidence.identities,
            DetailedCodeQueryProvenanceIdentities::None
        ));
    }
}

fn assert_detailed_terminal_identities(
    domain: DetailedCodeQueryDomain,
    identities: &DetailedCodeQueryProvenanceIdentities,
) {
    assert!(matches!(
        (domain, identities),
        (
            DetailedCodeQueryDomain::StructuralMatch
                | DetailedCodeQueryDomain::Declaration
                | DetailedCodeQueryDomain::Procedure
                | DetailedCodeQueryDomain::ProgramPoint
                | DetailedCodeQueryDomain::ControlEdge
                | DetailedCodeQueryDomain::TypestateFinding
                | DetailedCodeQueryDomain::TypestateWitness
                | DetailedCodeQueryDomain::FlowEndpoint
                | DetailedCodeQueryDomain::FlowWitness
                | DetailedCodeQueryDomain::TaintFinding,
            DetailedCodeQueryProvenanceIdentities::Primary(_),
        ) | (
            DetailedCodeQueryDomain::File
                | DetailedCodeQueryDomain::ExpressionSite
                | DetailedCodeQueryDomain::ReceiverAnalysis
                | DetailedCodeQueryDomain::ReceiverOutcome
                | DetailedCodeQueryDomain::ReceiverEvidence
                | DetailedCodeQueryDomain::CallShape
                | DetailedCodeQueryDomain::CallArgumentGroup
                | DetailedCodeQueryDomain::CallArgument
                | DetailedCodeQueryDomain::MemberSelection
                // An occurrence's identity is its own content-scoped digest,
                // carried in the typed key rather than in a semantic-artifact
                // identity candidate. The three lexical-environment domains
                // are identified the same way, for the same reason.
                | DetailedCodeQueryDomain::Occurrence
                | DetailedCodeQueryDomain::LexicalScope
                | DetailedCodeQueryDomain::Binding
                | DetailedCodeQueryDomain::ResolutionCandidate
                // The three materialization domains are identified by their
                // own content-scoped digests too (#1476).
                | DetailedCodeQueryDomain::GenerationSite
                | DetailedCodeQueryDomain::Export
                | DetailedCodeQueryDomain::DeclarationState
                // The identity-route domains carry their digests the same
                // way (#1475).
                // A reference edge's identity is its own content-scoped
                // digest, carried in the typed key like the environment
                // domains above.
                | DetailedCodeQueryDomain::ReferenceEdge
                // A path and its segments are likewise identified by their
                // own content-scoped digests in the typed key.
                | DetailedCodeQueryDomain::QualifiedPath
                | DetailedCodeQueryDomain::PathSegment,
            DetailedCodeQueryProvenanceIdentities::None,
        ) | (
            DetailedCodeQueryDomain::ReferenceSite,
            DetailedCodeQueryProvenanceIdentities::ReferenceTarget(_),
        ) | (
            DetailedCodeQueryDomain::CallSite,
            DetailedCodeQueryProvenanceIdentities::Call { .. },
        )
    ));
}

fn semantic_wire_id(key: &DetailedCodeQueryKey) -> Option<&str> {
    match key {
        DetailedCodeQueryKey::Procedure { id }
        | DetailedCodeQueryKey::ProgramPoint { id, .. }
        | DetailedCodeQueryKey::ControlEdge { id, .. }
        | DetailedCodeQueryKey::TypestateFinding { id }
        | DetailedCodeQueryKey::TypestateWitness { id, .. }
        | DetailedCodeQueryKey::FlowEndpoint { id }
        | DetailedCodeQueryKey::FlowWitness { id, .. }
        | DetailedCodeQueryKey::TaintFinding { id } => Some(id),
        DetailedCodeQueryKey::StructuralMatch { .. }
        | DetailedCodeQueryKey::Declaration { .. }
        | DetailedCodeQueryKey::File
        | DetailedCodeQueryKey::ReferenceSite { .. }
        | DetailedCodeQueryKey::CallSite { .. }
        | DetailedCodeQueryKey::ExpressionSite { .. }
        | DetailedCodeQueryKey::ReceiverAnalysis { .. }
        | DetailedCodeQueryKey::ReceiverOutcome { .. }
        | DetailedCodeQueryKey::ReceiverEvidence { .. }
        | DetailedCodeQueryKey::CallShape { .. }
        | DetailedCodeQueryKey::CallArgumentGroup { .. }
        | DetailedCodeQueryKey::CallArgument { .. }
        | DetailedCodeQueryKey::MemberSelection { .. }
        | DetailedCodeQueryKey::Occurrence { .. }
        | DetailedCodeQueryKey::LexicalScope { .. }
        | DetailedCodeQueryKey::Binding { .. }
        | DetailedCodeQueryKey::ResolutionCandidate { .. }
        | DetailedCodeQueryKey::GenerationSite { .. }
        | DetailedCodeQueryKey::Export { .. }
        | DetailedCodeQueryKey::DeclarationState { .. }
        | DetailedCodeQueryKey::ReferenceEdge { .. } => None,
        DetailedCodeQueryKey::QualifiedPath { .. } | DetailedCodeQueryKey::PathSegment { .. } => {
            None
        }
    }
}
