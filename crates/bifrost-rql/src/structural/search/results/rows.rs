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

/// The value domain of one `ConstrainedEnum` row field: every label the
/// producing vocabulary can write.
///
/// A relational policy compares an enum-typed column against a bare label. With
/// the domain published, an unknown label is an authoring error the loader
/// rejects, instead of a filter that matches nothing and reports a clean run
/// forever (issue #2515).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeQueryEnumDomain {
    /// Every label the producer can write, in the producing vocabulary's own
    /// declaration order.
    Labels(&'static [&'static str]),
    /// The producer's vocabulary is genuinely not a finite enumerated set, so
    /// no literal can be rejected. The reason is recorded so the exemption is a
    /// decision rather than an omission.
    Unenumerable(&'static str),
}

impl CodeQueryEnumDomain {
    /// The labels a literal is checked against, or `None` when the domain is
    /// explicitly not enumerable.
    pub const fn labels(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Labels(labels) => Some(labels),
            Self::Unenumerable(_) => None,
        }
    }

    /// Whether `label` is a value this field can actually hold.
    pub fn admits(self, label: &str) -> bool {
        match self {
            Self::Labels(labels) => labels.contains(&label),
            Self::Unenumerable(_) => true,
        }
    }
}

/// Declarative schema for one addressable field on a detailed result domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeQueryRowField {
    pub name: &'static str,
    pub scalar_type: CodeQueryRowScalarType,
    pub nullable: bool,
    /// Present exactly for a [`CodeQueryRowScalarType::ConstrainedEnum`] field,
    /// which is enforced at compile time by the constructors below.
    pub value_domain: Option<CodeQueryEnumDomain>,
}

impl CodeQueryRowField {
    /// A required field of a scalar type that carries no value domain.
    ///
    /// The assertion runs during const evaluation, so an enum-typed field
    /// declared through this constructor fails to compile rather than reaching
    /// policy validation with no domain to check against.
    pub const fn required(name: &'static str, scalar_type: CodeQueryRowScalarType) -> Self {
        assert!(
            !matches!(scalar_type, CodeQueryRowScalarType::ConstrainedEnum),
            "a ConstrainedEnum row field must declare its value domain"
        );
        Self {
            name,
            scalar_type,
            nullable: false,
            value_domain: None,
        }
    }

    pub const fn optional(name: &'static str, scalar_type: CodeQueryRowScalarType) -> Self {
        assert!(
            !matches!(scalar_type, CodeQueryRowScalarType::ConstrainedEnum),
            "a ConstrainedEnum row field must declare its value domain"
        );
        Self {
            name,
            scalar_type,
            nullable: true,
            value_domain: None,
        }
    }

    /// A required enum field over a finite label set.
    pub const fn required_enum(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self {
            name,
            scalar_type: CodeQueryRowScalarType::ConstrainedEnum,
            nullable: false,
            value_domain: Some(CodeQueryEnumDomain::Labels(labels)),
        }
    }

    /// An optional enum field over a finite label set.
    pub const fn optional_enum(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self {
            name,
            scalar_type: CodeQueryRowScalarType::ConstrainedEnum,
            nullable: true,
            value_domain: Some(CodeQueryEnumDomain::Labels(labels)),
        }
    }

    /// A required enum field whose producer's vocabulary cannot be enumerated.
    /// `reason` states why, and no literal over it is ever rejected.
    pub const fn required_open_enum(name: &'static str, reason: &'static str) -> Self {
        Self {
            name,
            scalar_type: CodeQueryRowScalarType::ConstrainedEnum,
            nullable: false,
            value_domain: Some(CodeQueryEnumDomain::Unenumerable(reason)),
        }
    }

    /// An optional enum field whose producer's vocabulary cannot be enumerated.
    pub const fn optional_open_enum(name: &'static str, reason: &'static str) -> Self {
        Self {
            name,
            scalar_type: CodeQueryRowScalarType::ConstrainedEnum,
            nullable: true,
            value_domain: Some(CodeQueryEnumDomain::Unenumerable(reason)),
        }
    }
}

/// The published value domain of every enum-typed row field, named once here so
/// the registry below reads as data (issue #2515).
///
/// Each name resolves to the vocabulary its *producer* writes from. Where the
/// producer is a typed enum, that enum's own `LABELS` const is used, so the
/// registry cannot drift from the values a row can hold. Where the producer
/// mints bare strings at a render site, the exact literal set is recorded
/// beside that site and re-exported here rather than restated.
mod value_domain {
    use super::super::super::decorator_binding;
    use super::{NormalizedKind, ReceiverQueryOperation, UsageHitKind};
    use crate::analyzer::CodeUnitType;
    use crate::analyzer::semantic::CandidateCoverage;
    use crate::analyzer::semantic::capabilities::SemanticCapability;
    use crate::analyzer::semantic::provider::SemanticBudgetDimension;
    use crate::analyzer::semantic::{
        ControlEdgeKind, DispatchBoundaryKind, EvidenceCompleteness, ProcedureKind, ProofStatus,
    };
    use crate::analyzer::usages::call_binding::{
        CallBindingCoverage, CallBindingKind, CallBindingMapping, CallBindingReason,
    };
    use crate::analyzer::usages::effects::{
        EffectCertainty, EffectClassification, EffectCoverage, EffectDerivation, EffectProof,
        EffectReason, EffectTiming,
    };
    use crate::analyzer::usages::get_definition::trace::TraceCompleteness;
    use crate::structural::search::results::environment::CodeQueryCandidateRef;
    use crate::structural::search::{dispatch, member_family, receiver, render};
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::structural::callable::{
        ApplicabilityVerdict, ArgumentListKind, CallKind, CallShapeCoverage,
        CallableRejectionReason, DeclarationRole, ReceiverContract, SelectionResolution,
        SignatureCoverage,
    };
    use brokk_bifrost_core::analyzer::structural::control_relation::{
        ControlExitPartition, ControlRelationKind,
    };
    use brokk_bifrost_core::analyzer::structural::edges::{OwnerRelation, SiteClass};
    use brokk_bifrost_core::analyzer::structural::flow_state::{
        FlowCertainty, FlowRelation, FlowSubjectKind, StateEventClass,
    };
    use brokk_bifrost_core::analyzer::structural::materialization::{
        DeclarationOrigin, ExportForm, GenerationInputClass, GenerationKind,
    };
    use brokk_bifrost_core::analyzer::structural::occurrences::{
        Namespace, OccurrenceClass, OccurrenceRole,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::{
        BindingKind, BoundaryStatus, CandidateOutcome, DeclaredVisibility, HierarchyRelation,
        HoistingClass, MemberDispatchTier, MemberFamilyCapability, MemberFamilyOutcome,
        MemberFamilyReason, MethodFamilyRelation, PrecedenceTier, RejectionReason,
    };
    use brokk_bifrost_core::analyzer::structural::rewrite_path::{
        RewriteDomainKind, RewriteOutcomeKind,
    };
    use brokk_bifrost_core::analyzer::structural::routes::SegmentResolutionStatus;
    use brokk_bifrost_flow::dataflow::SemanticInputStatus;

    pub(super) const LANGUAGE: &[&str] = Language::CONFIG_LABELS;
    pub(super) const STRUCTURAL_KIND: &[&str] = NormalizedKind::LABELS;
    pub(super) const CODE_UNIT_KIND: &[&str] = CodeUnitType::DISPLAY_LOWERCASE_LABELS;

    /// `declaration.kind` is refined to a normalized structural kind when the
    /// seed's own span matched the declaration exactly, and otherwise falls
    /// back to the code unit's coarse type, so the field's domain is the union
    /// of both vocabularies. A unit test pins the union against its two parts.
    pub(super) const DECLARATION_KIND: &[&str] = &[
        "declaration",
        "callable",
        "function",
        "method",
        "constructor",
        "lambda",
        "class",
        "import",
        "call",
        "assignment",
        "field_access",
        "identifier",
        "literal",
        "string_literal",
        "numeric_literal",
        "boolean_literal",
        "null_literal",
        "collection_literal",
        "jsx_element",
        "jsx_attribute",
        "jsx_spread_attribute",
        "object_property",
        "computed_property",
        "spread_element",
        "return",
        "throw",
        "catch",
        "if",
        "loop",
        "for_loop",
        "while_loop",
        "decorator",
        "parameter",
        "block",
        "field",
        "module",
        "macro",
        "file scope",
    ];

    /// The five shapes of `occurrence.target`, decided in the projector itself
    /// because the public row carries the target as a tagged union rather than
    /// as a label.
    pub(super) const OCCURRENCE_TARGET_KIND: &[&str] =
        &["none", "resolved", "lexical", "unresolved", "not_derived"];

    pub(super) const PROCEDURE_KIND: &[&str] = ProcedureKind::LABELS;
    pub(super) const CONTROL_EDGE_KIND: &[&str] = ControlEdgeKind::LABELS;
    pub(super) const SEMANTIC_STATUS: &[&str] = SemanticInputStatus::LABELS;
    pub(super) const SEMANTIC_CAPABILITY: &[&str] = SemanticCapability::LABELS;
    pub(super) const SEMANTIC_BUDGET_DIMENSION: &[&str] = SemanticBudgetDimension::LABELS;

    pub(super) const USAGE_KIND: &[&str] = UsageHitKind::WIRE_LABELS;
    pub(super) const USAGE_PROOF: &[&str] = brokk_bifrost_rql::schema::USAGE_PROOF_LABELS;
    pub(super) const REFERENCE_KIND: &[&str] = brokk_bifrost_rql::schema::REFERENCE_KIND_LABELS;
    pub(super) const CALL_SYNTAX_KIND: &[&str] = render::CALL_SYNTAX_KIND_LABELS;
    pub(super) const EXPRESSION_INPUT_KIND: &[&str] = render::EXPRESSION_INPUT_KIND_LABELS;
    pub(super) const JSX_ELEMENT_IDENTITY: &[&str] = &["intrinsic", "component", "unknown"];
    pub(super) const JSX_ATTRIBUTE_KIND: &[&str] = &["jsx_attribute", "jsx_spread_attribute"];
    pub(super) const JSX_VALUE_COVERAGE: &[&str] = &["complete", "incomplete"];

    pub(super) const RECEIVER_ANALYSIS_KIND: &[&str] = ReceiverQueryOperation::LABELS;
    pub(super) const RECEIVER_OUTCOME: &[&str] = render::RECEIVER_OUTCOME_LABELS;
    pub(super) const RECEIVER_COVERAGE: &[&str] = render::RECEIVER_COVERAGE_LABELS;
    pub(super) const RECEIVER_EVIDENCE_KIND: &[&str] = receiver::RECEIVER_EVIDENCE_KIND_LABELS;
    pub(super) const RECEIVER_EVIDENCE_PROOF: &[&str] = render::RECEIVER_EVIDENCE_PROOF_LABELS;

    pub(super) const DISPATCH_OUTCOME: &[&str] = dispatch::DISPATCH_OUTCOME_LABELS;
    pub(super) const DISPATCH_ARM: &[&str] = dispatch::DISPATCH_ARM_LABELS;
    pub(super) const CANDIDATE_COVERAGE: &[&str] = CandidateCoverage::LABELS;
    pub(super) const EVIDENCE_PROOF: &[&str] = ProofStatus::LABELS;
    pub(super) const EVIDENCE_COMPLETENESS: &[&str] = EvidenceCompleteness::LABELS;
    pub(super) const DISPATCH_BOUNDARY_KIND: &[&str] = DispatchBoundaryKind::LABELS;

    pub(super) const MEMBER_FAMILY_OUTCOME: &[&str] = MemberFamilyOutcome::LABELS;
    pub(super) const MEMBER_FAMILY_REASON: &[&str] = MemberFamilyReason::LABELS;
    pub(super) const MEMBER_FAMILY_CAPABILITY: &[&str] = MemberFamilyCapability::LABELS;
    pub(super) const MEMBER_FAMILY_COVERAGE: &[&str] = member_family::MEMBER_FAMILY_COVERAGE_LABELS;
    pub(super) const MEMBER_FAMILY_RELATION: &[&str] = MethodFamilyRelation::LABELS;
    pub(super) const MEMBER_FAMILY_EDGE_PROOF: &[&str] =
        member_family::MEMBER_FAMILY_EDGE_PROOF_LABELS;
    pub(super) const MEMBER_FAMILY_EDGE_COMPLETENESS: &[&str] =
        render::MEMBER_FAMILY_EDGE_COMPLETENESS_LABELS;

    pub(super) const CALL_KIND: &[&str] = CallKind::LABELS;
    pub(super) const CALL_SHAPE_COVERAGE: &[&str] = CallShapeCoverage::LABELS;
    pub(super) const ARGUMENT_LIST_KIND: &[&str] = ArgumentListKind::LABELS;
    pub(super) const CALL_BINDING_KIND: &[&str] = CallBindingKind::LABELS;
    pub(super) const CALL_BINDING_MAPPING: &[&str] = CallBindingMapping::LABELS;
    pub(super) const CALL_BINDING_REASON: &[&str] = CallBindingReason::LABELS;
    pub(super) const CALL_BINDING_COVERAGE: &[&str] = CallBindingCoverage::LABELS;

    pub(super) const EFFECT_CLASSIFICATION: &[&str] = EffectClassification::LABELS;
    pub(super) const EFFECT_TIMING: &[&str] = EffectTiming::LABELS;
    pub(super) const EFFECT_CERTAINTY: &[&str] = EffectCertainty::LABELS;
    pub(super) const EFFECT_PROOF: &[&str] = EffectProof::LABELS;
    pub(super) const EFFECT_DERIVATION: &[&str] = EffectDerivation::LABELS;
    pub(super) const EFFECT_REASON: &[&str] = EffectReason::LABELS;
    pub(super) const EFFECT_COVERAGE: &[&str] = EffectCoverage::LABELS;

    pub(super) const SIGNATURE_COVERAGE: &[&str] = SignatureCoverage::LABELS;
    pub(super) const DECORATOR_BINDING_STATUS: &[&str] = decorator_binding::BINDING_STATUS;
    pub(super) const DECORATOR_COMPLETION: &[&str] = decorator_binding::COMPLETION;
    pub(super) const DECORATOR_COVERAGE: &[&str] = decorator_binding::COVERAGE;
    pub(super) const DECORATOR_BOUNDARY: &[&str] = BoundaryStatus::LABELS;
    pub(super) const DECLARATION_ROLE: &[&str] = DeclarationRole::LABELS;
    pub(super) const RECEIVER_CONTRACT: &[&str] = ReceiverContract::LABELS;
    pub(super) const APPLICABILITY_VERDICT: &[&str] = ApplicabilityVerdict::LABELS;
    pub(super) const CALLABLE_REJECTION_REASON: &[&str] = CallableRejectionReason::LABELS;
    pub(super) const PRECEDENCE_TIER: &[&str] = PrecedenceTier::LABELS;
    pub(super) const SELECTION_RESOLUTION: &[&str] = SelectionResolution::LABELS;

    pub(super) const MEMBER_SELECTION_OUTCOME: &[&str] = render::MEMBER_SELECTION_OUTCOME_LABELS;
    pub(super) const MEMBER_SELECTION_TRACE_COMPLETENESS: &[&str] =
        render::MEMBER_SELECTION_TRACE_COMPLETENESS_LABELS;
    pub(super) const MEMBER_SELECTION_COVERAGE: &[&str] = render::MEMBER_SELECTION_COVERAGE_LABELS;

    pub(super) const OCCURRENCE_CLASS: &[&str] = OccurrenceClass::LABELS;
    pub(super) const OCCURRENCE_ROLE: &[&str] = OccurrenceRole::LABELS;
    pub(super) const NAMESPACE: &[&str] = Namespace::LABELS;

    pub(super) const BINDING_KIND: &[&str] = BindingKind::LABELS;
    pub(super) const HOISTING_CLASS: &[&str] = HoistingClass::LABELS;
    pub(super) const DECLARED_VISIBILITY: &[&str] = DeclaredVisibility::LABELS;

    pub(super) const CANDIDATE_OUTCOME: &[&str] = CandidateOutcome::LABELS;
    pub(super) const REJECTION_REASON: &[&str] = RejectionReason::LABELS;
    pub(super) const BOUNDARY_STATUS: &[&str] = BoundaryStatus::LABELS;
    pub(super) const TRACE_COMPLETENESS: &[&str] = TraceCompleteness::LABELS;
    pub(super) const CANDIDATE_KIND: &[&str] = CodeQueryCandidateRef::LABELS;
    pub(super) const MEMBER_DISPATCH_TIER: &[&str] = MemberDispatchTier::LABELS;
    pub(super) const HIERARCHY_RELATION: &[&str] = HierarchyRelation::LABELS;

    pub(super) const GENERATION_KIND: &[&str] = GenerationKind::LABELS;
    pub(super) const GENERATION_INPUT: &[&str] = GenerationInputClass::LABELS;
    pub(super) const EXPORT_FORM: &[&str] = ExportForm::LABELS;
    pub(super) const DECLARATION_ORIGIN: &[&str] = DeclarationOrigin::LABELS;
    pub(super) const SEGMENT_RESOLUTION_STATUS: &[&str] = SegmentResolutionStatus::LABELS;

    pub(super) const SITE_CLASS: &[&str] = SiteClass::LABELS;
    pub(super) const OWNER_RELATION: &[&str] = OwnerRelation::LABELS;
    pub(super) const EDGE_PROVENANCE: &[&str] =
        brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance::LABELS;

    pub(super) const STATE_EVENT_CLASS: &[&str] = StateEventClass::LABELS;
    pub(super) const FLOW_SUBJECT: &[&str] = FlowSubjectKind::LABELS;
    pub(super) const FLOW_RELATION: &[&str] = FlowRelation::LABELS;
    pub(super) const FLOW_CERTAINTY: &[&str] = FlowCertainty::LABELS;
    pub(super) const FLOW_STATE_COMPLETENESS: &[&str] =
        crate::structural::search::flow_state::FLOW_STATE_COMPLETENESS_LABELS;

    /// The four guard predicates the semantic IR publishes (#2443). The
    /// producer is the IR enum itself, so a row column cannot drift from the
    /// value a lowerer writes.
    pub(super) const GUARD_PREDICATE: &[&str] = crate::analyzer::semantic::GuardPredicate::LABELS;

    pub(super) const CONTROL_RELATION: &[&str] = ControlRelationKind::LABELS;
    pub(super) const CONTROL_EXIT_PARTITION: &[&str] = ControlExitPartition::LABELS;
    pub(super) const CONTROL_RELATION_COMPLETENESS: &[&str] =
        crate::structural::search::control_relations::CONTROL_RELATION_COMPLETENESS_LABELS;
    /// The three boundary roles plus the `interior` label an absent boundary
    /// renders as; the producer is the row projector, and the exact literal set
    /// lives beside the enum it extends rather than being restated here.
    pub(super) const PROGRAM_POINT_BOUNDARY: &[&str] = super::CodeQueryProgramPointBoundary::LABELS;

    /// The two topology vocabularies the row surface publishes (#2448). Both
    /// come from the frozen topology types, so a row column cannot drift from
    /// the value its producer writes.
    pub(super) const TOPOLOGY_COMPLETENESS: &[&str] =
        crate::analyzer::topology::TopologyCompleteness::LABELS;
    pub(super) const DEPENDENCY_SCOPE: &[&str] = crate::analyzer::topology::DependencyScope::LABELS;

    pub(super) const REWRITE_DOMAIN: &[&str] = RewriteDomainKind::LABELS;
    pub(super) const REWRITE_OUTCOME: &[&str] = RewriteOutcomeKind::LABELS;
    pub(super) const REWRITE_PATH_COMPLETENESS: &[&str] =
        crate::structural::search::rewrite_paths::REWRITE_PATH_COMPLETENESS_LABELS;
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

/// Declare one detailed row domain, once (issue #2498).
///
/// Adding a domain used to mean editing roughly eleven exhaustive-match sites
/// across four crates. Two of them drifted silently: the hand-mirrored
/// `ALL_DETAILED_CODE_QUERY_DOMAINS` slice, and the `(domain, provenance
/// identities)` allow-list, which a new domain missed without a compile error
/// and failed only at run time inside a detailed query that returned the row.
///
/// One entry below now derives all of it: the enum variant, the mirror slice,
/// the label, the `QueryValueKind` mapping, the addressable field surface, the
/// display anchor, the domain a typed key addresses, and the terminal identity
/// shape.
///
/// What it deliberately does not derive is per-domain *data*. The projector's
/// field expressions, `detailed_semantic_identity` and `semantic_wire_id` each
/// read fields that differ per row, and each is an exhaustive match that a new
/// domain cannot pass without a compile error. Collapsing them into this macro
/// would trade a mechanical list for a table of expressions, which is not the
/// drift this removes.
///
/// `display_range` takes its binding from the caller because macro hygiene
/// would otherwise hide a binding the macro introduced from the caller's
/// expression.
macro_rules! detailed_row_domains {
    (
        // The five declared types the registry ties together, named so a test
        // can instantiate the whole registry over a toy domain and prove that
        // one entry really is the only declaration site.
        domain: $domain:ident,
        all: $all:ident,
        key: $key:ident,
        row: $row:ident,
        kind: $kind:ident,
        $(
        $variant:ident => $label:literal {
            display_range: |$value:pat_param| $range:expr,
            identities: $identities:ident,
            fields: [$($field:expr),* $(,)?],
        },
        )+
    ) => {
        /// One addressable public result shape. Every detailed evidence row,
        /// typed key, and relational row relation is scoped by one of these.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $domain {
            $($variant,)+
        }

        /// Every domain, in declaration order.
        pub const $all: &[$domain] = &[$($domain::$variant,)+];

        impl $domain {
            pub const fn from_query_value_kind(kind: $kind) -> Self {
                match kind {
                    $($kind::$variant => Self::$variant,)+
                }
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            /// The complete stable scalar surface addressable by relational
            /// policy evaluation for this domain.
            pub fn row_fields(self) -> &'static [CodeQueryRowField] {
                #[allow(unused_imports)]
                use CodeQueryRowScalarType as Scalar;
                match self {
                    $(Self::$variant => code_query_row_fields![$($field),*],)+
                }
            }

            /// The provenance identities every terminal row of this domain
            /// carries. Declared with the domain, so a new domain cannot reach
            /// a run-time assertion with no entry.
            const fn terminal_identities(self) -> DetailedTerminalIdentities {
                match self {
                    $(Self::$variant => DetailedTerminalIdentities::$identities,)+
                }
            }
        }

        impl $key {
            /// The domain this typed key addresses.
            pub const fn domain(&self) -> $domain {
                match self {
                    $(Self::$variant { .. } => $domain::$variant,)+
                }
            }
        }

        impl $row {
            /// The exact display region of this row's own source anchor. `None`
            /// when the row has no source region of its own (a file row, or an
            /// evidence row whose location is its site's outcome row).
            pub fn display_range(&self) -> Option<CodeQueryRange> {
                match self {
                    $(Self::$variant { value: $value } => $range,)+
                }
            }

            pub const fn detailed_domain(&self) -> $domain {
                match self {
                    $(Self::$variant { .. } => $domain::$variant,)+
                }
            }
        }
    };
}

/// The display anchor of a row whose claim is about a whole build file
/// (#2448): its first line.
///
/// A topology row states what one build file declares. The topology vocabulary
/// deliberately records no position inside that file, and recovering one would
/// mean locating the declaration by scanning the build file's text -- the
/// lexical inference the module exists to refuse. The first line names the file
/// without claiming a position within it, and `BUILD_FILE_ANCHOR_SPAN` is the
/// matching empty byte span, so a finding on a topology row is a file-level
/// finding that still carries a location a renderer can print.
pub(in super::super) const BUILD_FILE_ANCHOR_RANGE: CodeQueryRange = CodeQueryRange {
    start_line: 1,
    start_column: 1,
    end_line: 1,
    end_column: 1,
};

/// The byte span that pairs with [`BUILD_FILE_ANCHOR_RANGE`].
pub(in super::super) const BUILD_FILE_ANCHOR_SPAN: std::ops::Range<usize> = 0..0;

/// Which provenance identities a terminal row of one domain carries.
///
/// This is the shape only; the identity values themselves travel on the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailedTerminalIdentities {
    None,
    Primary,
    ReferenceTarget,
    Call,
}

impl DetailedTerminalIdentities {
    fn of(identities: &DetailedCodeQueryProvenanceIdentities) -> Self {
        match identities {
            DetailedCodeQueryProvenanceIdentities::None => Self::None,
            DetailedCodeQueryProvenanceIdentities::Primary(_) => Self::Primary,
            DetailedCodeQueryProvenanceIdentities::ReferenceTarget(_) => Self::ReferenceTarget,
            DetailedCodeQueryProvenanceIdentities::Call { .. } => Self::Call,
        }
    }
}

detailed_row_domains! {
    domain: DetailedCodeQueryDomain,
    all: ALL_DETAILED_CODE_QUERY_DOMAINS,
    key: DetailedCodeQueryKey,
    row: CodeQueryResultValue,
    kind: QueryValueKind,

    StructuralMatch => "structural_match" {
        display_range: |value| value.node_range,
        identities: Primary,
        fields: [
                    CodeQueryRowField::optional("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("kind", value_domain::STRUCTURAL_KIND),
        ],
    },
    Declaration => "declaration" {
        display_range: |value| value.node_range,
        identities: Primary,
        fields: [
                    CodeQueryRowField::optional("id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("kind", value_domain::DECLARATION_KIND),
                    CodeQueryRowField::required("fq_name", Scalar::String),
        ],
    },
    Procedure => "procedure" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("artifact_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("procedure_kind", value_domain::PROCEDURE_KIND),
        ],
    },
    ProgramPoint => "program_point" {
        display_range: |value| Some(value.range),
        identities: Primary,
        // `boundary` is required and total (#2443): a point with no boundary
        // role is `interior`, so a policy can name the entry point or exclude
        // the exits without reading a null.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "boundary",
                        value_domain::PROGRAM_POINT_BOUNDARY
                    ),
                    CodeQueryRowField::required("event_count", Scalar::Integer),
        ],
    },
    ControlEdge => "control_edge" {
        display_range: |value| Some(value.range),
        identities: Primary,
        // `source_id`/`target_id` are the endpoint points' own wire ids, which
        // the row already renders inline; publishing them as columns is what
        // lets an edge row and a control-relation row join by id (#2443).
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("edge_kind", value_domain::CONTROL_EDGE_KIND),
                    CodeQueryRowField::required("source_id", Scalar::StableId),
                    CodeQueryRowField::required("target_id", Scalar::StableId),
        ],
    },
    TypestateFinding => "typestate_finding" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("protocol_ref", Scalar::StableId),
                    CodeQueryRowField::required("path_proven", Scalar::Boolean),
                    CodeQueryRowField::required("path_complete", Scalar::Boolean),
                    CodeQueryRowField::required("analysis_complete", Scalar::Boolean),
                    CodeQueryRowField::required("abstained", Scalar::Boolean),
        ],
    },
    TypestateWitness => "typestate_witness" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("finding_id", Scalar::StableId),
                    CodeQueryRowField::required("witness_index", Scalar::Integer),
                    CodeQueryRowField::required("truncated", Scalar::Boolean),
        ],
    },
    FlowEndpoint => "flow_endpoint" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("plan_ref", Scalar::StableId),
                    CodeQueryRowField::required("ambiguous", Scalar::Boolean),
                    CodeQueryRowField::required_enum("semantic_status", value_domain::SEMANTIC_STATUS),
        ],
    },
    FlowWitness => "flow_witness" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("endpoint_id", Scalar::StableId),
                    CodeQueryRowField::required("witness_index", Scalar::Integer),
                    CodeQueryRowField::required("truncated", Scalar::Boolean),
        ],
    },
    TaintFinding => "taint_finding" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("sink_event_id", Scalar::StableId),
                    CodeQueryRowField::required("origins_truncated", Scalar::Boolean),
                    CodeQueryRowField::required("witnesses_truncated", Scalar::Boolean),
                    CodeQueryRowField::required("ambiguous", Scalar::Boolean),
        ],
    },
    File => "file" {
        display_range: |_value| None,
        identities: None,
        fields: [
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::optional("package_fq", Scalar::String),
                    CodeQueryRowField::optional("package_syntactic", Scalar::Boolean),
        ],
    },
    ReferenceSite => "reference_site" {
        display_range: |value| Some(value.range),
        identities: ReferenceTarget,
        fields: [
                    CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("usage_kind", value_domain::USAGE_KIND),
                    CodeQueryRowField::required_enum("proof", value_domain::USAGE_PROOF),
                    CodeQueryRowField::optional_enum("reference_kind", value_domain::REFERENCE_KIND),
        ],
    },
    CallSite => "call_site" {
        display_range: |value| Some(value.range),
        identities: Call,
        fields: [
                    CodeQueryRowField::optional("caller_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("callee_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("call_kind", value_domain::CALL_SYNTAX_KIND),
                    CodeQueryRowField::required_enum("proof", value_domain::USAGE_PROOF),
        ],
    },
    ExpressionSite => "expression_site" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required_enum("input_kind", value_domain::EXPRESSION_INPUT_KIND),
                    CodeQueryRowField::optional("parameter_index", Scalar::Integer),
                    CodeQueryRowField::optional("parameter_name", Scalar::String),
        ],
    },
    JsxAttributeValue => "jsx_attribute_value" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("element_identity", value_domain::JSX_ELEMENT_IDENTITY),
                    CodeQueryRowField::optional("element_name", Scalar::String),
                    CodeQueryRowField::required_enum("attribute_kind", value_domain::JSX_ATTRIBUTE_KIND),
                    CodeQueryRowField::optional("attribute_name", Scalar::String),
                    CodeQueryRowField::optional("property_name", Scalar::String),
                    CodeQueryRowField::required_enum("coverage", value_domain::JSX_VALUE_COVERAGE),
                    CodeQueryRowField::optional("reason", Scalar::String),
                    CodeQueryRowField::optional("component_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("attribute_target_id", Scalar::DeclarationIdentity),
        ],
    },
    ReceiverAnalysis => "receiver_analysis" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "analysis_kind",
                        value_domain::RECEIVER_ANALYSIS_KIND
                    ),
                    CodeQueryRowField::required_enum("outcome", value_domain::RECEIVER_OUTCOME),
                    CodeQueryRowField::optional("capture", Scalar::String),
        ],
    },
    ReceiverOutcome => "receiver_outcome" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "analysis_kind",
                        value_domain::RECEIVER_ANALYSIS_KIND
                    ),
                    CodeQueryRowField::required_enum("outcome", value_domain::RECEIVER_OUTCOME),
                    CodeQueryRowField::required_enum("coverage", value_domain::RECEIVER_COVERAGE),
                    CodeQueryRowField::required("candidate_count", Scalar::Integer),
                    CodeQueryRowField::required("candidates_truncated", Scalar::Boolean),
                    CodeQueryRowField::optional_enum(
                        "semantic_unsupported",
                        value_domain::SEMANTIC_CAPABILITY
                    ),
        ],
    },
    CallShape => "call_shape" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("call_kind", value_domain::CALL_KIND),
                    CodeQueryRowField::required_enum("coverage", value_domain::CALL_SHAPE_COVERAGE),
                    CodeQueryRowField::required("group_count", Scalar::Integer),
        ],
    },
    CallArgumentGroup => "call_argument_group" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("group_index", Scalar::Integer),
                    CodeQueryRowField::required_enum("kind", value_domain::ARGUMENT_LIST_KIND),
                    CodeQueryRowField::required("argument_count", Scalar::Integer),
        ],
    },
    CallArgument => "call_argument" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("group_id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("argument_index", Scalar::Integer),
                    CodeQueryRowField::optional("name", Scalar::String),
                    CodeQueryRowField::required("spread", Scalar::Boolean),
        ],
    },
    CallBinding => "call_binding" {
        display_range: |value| Some(value.range),
        identities: None,
        // Issue #2438, completed by #2499. The surface carries every column
        // the relation was specified with, including `conversion`, which no
        // language adapter publishes yet: a language that gains the fact
        // adds a value, not a column.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("group_id", Scalar::StableId),
                    CodeQueryRowField::optional("argument_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("semantic_target_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("dispatch_outcome", value_domain::DISPATCH_OUTCOME),
                    CodeQueryRowField::required_enum("dispatch_coverage", value_domain::CANDIDATE_COVERAGE),
                    CodeQueryRowField::optional_enum("dispatch_proof", value_domain::EVIDENCE_PROOF),
                    CodeQueryRowField::optional_enum(
                        "dispatch_completeness",
                        value_domain::EVIDENCE_COMPLETENESS,
                    ),
                    CodeQueryRowField::required("dispatch_target_count", Scalar::Integer),
                    CodeQueryRowField::required("dispatch_targets_truncated", Scalar::Boolean),
                    CodeQueryRowField::optional("signature_id", Scalar::StableId),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("actual_index", Scalar::Integer),
                    CodeQueryRowField::optional("actual_name", Scalar::String),
                    CodeQueryRowField::optional("formal_index", Scalar::Integer),
                    CodeQueryRowField::optional("formal_name", Scalar::String),
                    CodeQueryRowField::optional_enum("binding_kind", value_domain::CALL_BINDING_KIND),
                    CodeQueryRowField::optional_open_enum(
                        "conversion",
                        "the conversion vocabulary is each language's own (Java widening \
                         and boxing, Rust deref and unsizing coercions, TypeScript \
                         structural assignability) and no adapter publishes one yet, so \
                         enumerating it here would be a table with no producer",
                    ),
                    CodeQueryRowField::required_enum("mapping", value_domain::CALL_BINDING_MAPPING),
                    CodeQueryRowField::optional_enum("reason", value_domain::CALL_BINDING_REASON),
                    CodeQueryRowField::required_enum("coverage", value_domain::CALL_BINDING_COVERAGE),
                    CodeQueryRowField::required("actual_count", Scalar::Integer),
                    CodeQueryRowField::required("bound_count", Scalar::Integer),
                    CodeQueryRowField::required("terminal", Scalar::Boolean),
        ],
    },
    CallEffect => "call_effect" {
        display_range: |value| Some(value.range),
        // An effect row is identified by its own content-scoped digest
        // over the site or procedure identity and the effect id, so it
        // carries no semantic-artifact identity candidate (#2437).
        identities: None,
        // Issue #2437. One row per (call site, dispatch arm, declared
        // effect), plus the mandatory terminal row that states a site whose
        // effects could not be established. `coverage` is the site's, so a
        // single row is enough to reject an absence claim.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_id", Scalar::StableId),
                    CodeQueryRowField::optional("callee_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("callee_symbol", Scalar::String),
                    CodeQueryRowField::optional("effect_id", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "classification",
                        value_domain::EFFECT_CLASSIFICATION
                    ),
                    CodeQueryRowField::optional_enum("timing", value_domain::EFFECT_TIMING),
                    CodeQueryRowField::optional_enum("certainty", value_domain::EFFECT_CERTAINTY),
                    CodeQueryRowField::optional_enum("proof", value_domain::EFFECT_PROOF),
                    CodeQueryRowField::required_enum("derivation", value_domain::EFFECT_DERIVATION),
                    CodeQueryRowField::optional_enum("reason", value_domain::EFFECT_REASON),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("summary_id", Scalar::String),
                    CodeQueryRowField::required("arm_count", Scalar::Integer),
                    CodeQueryRowField::required("modeled_arm_count", Scalar::Integer),
                    CodeQueryRowField::required("terminal", Scalar::Boolean),
        ],
    },
    ProcedureEffect => "procedure_effect" {
        display_range: |value| Some(value.range),
        identities: None,
        // Issue #2437. One row per (procedure, effect id), plus the
        // mandatory terminal row. The witness columns are a bounded,
        // deterministic chain of `call_shape` site identities, so a policy
        // reaches the exact direct effect by joining ids.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required("procedure_name", Scalar::String),
                    CodeQueryRowField::optional("effect_id", Scalar::String),
                    CodeQueryRowField::optional_enum(
                        "classification",
                        value_domain::EFFECT_CLASSIFICATION
                    ),
                    CodeQueryRowField::optional_enum("certainty", value_domain::EFFECT_CERTAINTY),
                    CodeQueryRowField::optional_enum("timing", value_domain::EFFECT_TIMING),
                    CodeQueryRowField::optional("depth", Scalar::Integer),
                    CodeQueryRowField::required_enum("derivation", value_domain::EFFECT_DERIVATION),
                    CodeQueryRowField::optional_enum("reason", value_domain::EFFECT_REASON),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::required("witness_available", Scalar::Boolean),
                    CodeQueryRowField::required("witness_steps", Scalar::Integer),
                    CodeQueryRowField::optional("witness_site_id", Scalar::StableId),
                    CodeQueryRowField::optional("witness_effect_site_id", Scalar::StableId),
                    CodeQueryRowField::optional("witness_chain", Scalar::String),
                    CodeQueryRowField::required("witness_truncated", Scalar::Boolean),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("summary_id", Scalar::String),
                    CodeQueryRowField::required("terminal", Scalar::Boolean),
        ],
    },
    CallableSignature => "callable_signature" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("declaration_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required_enum("coverage", value_domain::SIGNATURE_COVERAGE),
                    CodeQueryRowField::required_enum("role", value_domain::DECLARATION_ROLE),
                    CodeQueryRowField::optional("required_arity", Scalar::Integer),
                    CodeQueryRowField::optional("total_arity", Scalar::Integer),
                    CodeQueryRowField::required("repeated", Scalar::Boolean),
                    CodeQueryRowField::required("generic_arity", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "receiver_contract",
                        value_domain::RECEIVER_CONTRACT
                    ),
                    CodeQueryRowField::optional("return_type", Scalar::String),
                    CodeQueryRowField::required("declaration_only", Scalar::Boolean),
                    CodeQueryRowField::required("parameter_count", Scalar::Integer),
        ],
    },
    SignatureParameter => "signature_parameter" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("signature_id", Scalar::StableId),
                    CodeQueryRowField::required("parameter_index", Scalar::Integer),
                    CodeQueryRowField::required("label", Scalar::String),
                    CodeQueryRowField::optional("declared_type", Scalar::String),
                    CodeQueryRowField::optional("optional", Scalar::Boolean),
                    CodeQueryRowField::optional("repeated", Scalar::Boolean),
        ],
    },
    DecoratedParameter => "decorated_parameter" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("parameter_id", Scalar::StableId),
                    CodeQueryRowField::optional("decorator_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::optional("owner_id", Scalar::StableId),
                    CodeQueryRowField::optional("procedure_id", Scalar::StableId),
                    CodeQueryRowField::optional("parameter_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("port_id", Scalar::StableId),
                    CodeQueryRowField::required("decorator_name", Scalar::String),
                    CodeQueryRowField::optional("local_name", Scalar::String),
                    CodeQueryRowField::optional("imported_name", Scalar::String),
                    CodeQueryRowField::optional("module", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "binding_status",
                        value_domain::DECORATOR_BINDING_STATUS
                    ),
                    CodeQueryRowField::required_enum(
                        "boundary",
                        value_domain::DECORATOR_BOUNDARY
                    ),
                    CodeQueryRowField::required_enum(
                        "completion",
                        value_domain::DECORATOR_COMPLETION
                    ),
                    CodeQueryRowField::required_enum(
                        "coverage",
                        value_domain::DECORATOR_COVERAGE
                    ),
                    CodeQueryRowField::optional("reason", Scalar::String),
                    CodeQueryRowField::required("terminal", Scalar::Boolean),
        ],
    },
    CallableApplicability => "callable_applicability" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required_enum("verdict", value_domain::APPLICABILITY_VERDICT),
                    CodeQueryRowField::optional_enum("reason", value_domain::CALLABLE_REJECTION_REASON),
                    CodeQueryRowField::optional_enum("tier", value_domain::PRECEDENCE_TIER),
                    CodeQueryRowField::required("selected", Scalar::Boolean),
                    // The candidate declaration's identity, so an applicability row
                    // joins to the `callable_signature` row of the very callable it
                    // judged. Absent when the resolver weighed something that is not
                    // an indexed declaration (a lexical binder, an import route, an
                    // external target), exactly as the `candidates` domain reports.
                    CodeQueryRowField::optional("candidate_id", Scalar::DeclarationIdentity),
        ],
    },
    OverloadSelection => "overload_selection" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("resolution", value_domain::SELECTION_RESOLUTION),
                    CodeQueryRowField::required("supported", Scalar::Boolean),
                    CodeQueryRowField::required("considered_count", Scalar::Integer),
                    CodeQueryRowField::required("applicable_count", Scalar::Integer),
                    CodeQueryRowField::required("inapplicable_count", Scalar::Integer),
                    CodeQueryRowField::required("unknown_count", Scalar::Integer),
        ],
    },
    ReceiverEvidence => "receiver_evidence" {
        display_range: |_value| None,
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("parent_evidence_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required("chain_hop", Scalar::Integer),
                    CodeQueryRowField::required_enum(
                        "evidence_kind",
                        value_domain::RECEIVER_EVIDENCE_KIND
                    ),
                    CodeQueryRowField::optional("declaration_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("factory_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("proof", value_domain::RECEIVER_EVIDENCE_PROOF),
                    CodeQueryRowField::required_enum("completeness", value_domain::RECEIVER_COVERAGE),
        ],
    },
    MemberSelection => "member_selection" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("member", Scalar::String),
                    CodeQueryRowField::required_enum("role", value_domain::OCCURRENCE_ROLE),
                    CodeQueryRowField::required_enum("outcome", value_domain::MEMBER_SELECTION_OUTCOME),
                    CodeQueryRowField::required("selected_count", Scalar::Integer),
                    CodeQueryRowField::required("candidate_count", Scalar::Integer),
                    CodeQueryRowField::required_enum(
                        "trace_completeness",
                        value_domain::MEMBER_SELECTION_TRACE_COMPLETENESS
                    ),
                    CodeQueryRowField::required_enum(
                        "coverage",
                        value_domain::MEMBER_SELECTION_COVERAGE
                    ),
        ],
    },
    DispatchOutcome => "dispatch_outcome" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("outcome", value_domain::DISPATCH_OUTCOME),
                    CodeQueryRowField::required_enum("coverage", value_domain::CANDIDATE_COVERAGE),
                    CodeQueryRowField::required("call_site_count", Scalar::Integer),
                    CodeQueryRowField::required("target_count", Scalar::Integer),
                    CodeQueryRowField::required("targets_truncated", Scalar::Boolean),
                    CodeQueryRowField::optional_enum(
                        "semantic_unsupported",
                        value_domain::SEMANTIC_CAPABILITY
                    ),
                    CodeQueryRowField::optional_enum(
                        "exceeded_limit",
                        value_domain::SEMANTIC_BUDGET_DIMENSION
                    ),
        ],
    },
    DispatchTarget => "dispatch_target" {
        display_range: |_value| None,
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required("target_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_declaration_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("proof", value_domain::EVIDENCE_PROOF),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::EVIDENCE_COMPLETENESS
                    ),
                    CodeQueryRowField::required_enum("coverage", value_domain::CANDIDATE_COVERAGE),
                    CodeQueryRowField::required_enum("dispatch", value_domain::DISPATCH_ARM),
                    CodeQueryRowField::optional_enum(
                        "boundary_kind",
                        value_domain::DISPATCH_BOUNDARY_KIND
                    ),
        ],
    },
    MemberFamily => "member_family" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("member_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("outcome", value_domain::MEMBER_FAMILY_OUTCOME),
                    CodeQueryRowField::optional_enum("reason", value_domain::MEMBER_FAMILY_REASON),
                    CodeQueryRowField::required_enum(
                        "capability",
                        value_domain::MEMBER_FAMILY_CAPABILITY
                    ),
                    CodeQueryRowField::required_enum("coverage", value_domain::MEMBER_FAMILY_COVERAGE),
                    CodeQueryRowField::optional("family_id", Scalar::StableId),
                    CodeQueryRowField::required("overrides_count", Scalar::Integer),
                    CodeQueryRowField::required("implements_count", Scalar::Integer),
                    CodeQueryRowField::required("overridden_by_count", Scalar::Integer),
                    CodeQueryRowField::required("implemented_by_count", Scalar::Integer),
                    CodeQueryRowField::required("edge_count", Scalar::Integer),
                    CodeQueryRowField::required("root_count", Scalar::Integer),
                    CodeQueryRowField::optional("member_declaration_id", Scalar::DeclarationIdentity),
        ],
    },
    MemberFamilyEdge => "member_family_edge" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("member_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required("target_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("relation", value_domain::MEMBER_FAMILY_RELATION),
                    CodeQueryRowField::optional("family_id", Scalar::StableId),
                    CodeQueryRowField::required("hierarchy_depth", Scalar::Integer),
                    CodeQueryRowField::required_enum("proof", value_domain::MEMBER_FAMILY_EDGE_PROOF),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::MEMBER_FAMILY_EDGE_COMPLETENESS
                    ),
                    CodeQueryRowField::required_enum("coverage", value_domain::MEMBER_FAMILY_COVERAGE),
                    CodeQueryRowField::optional("target_declaration_id", Scalar::DeclarationIdentity),
        ],
    },
    Occurrence => "occurrence" {
        display_range: |value| Some(value.range),
        // An occurrence's identity is its own content-scoped digest,
        // carried in the typed key rather than in a semantic-artifact
        // identity candidate. The three lexical-environment domains
        // are identified the same way, for the same reason.
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("class", value_domain::OCCURRENCE_CLASS),
                    CodeQueryRowField::required_enum("role", value_domain::OCCURRENCE_ROLE),
                    CodeQueryRowField::required_enum("namespace", value_domain::NAMESPACE),
                    CodeQueryRowField::required_enum(
                        "target_kind",
                        value_domain::OCCURRENCE_TARGET_KIND
                    ),
                    CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                    // Absent when the query ran with identity-only occurrence
                    // derivation: a row whose targets were never derived has no
                    // target count, and the registry must not promise one. The
                    // always-on projection check found this registration lying
                    // (issue #2498).
                    CodeQueryRowField::optional("target_count", Scalar::Integer),
        ],
    },
    LexicalScope => "lexical_scope" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("index", Scalar::Integer),
                    CodeQueryRowField::optional_enum("kind", value_domain::STRUCTURAL_KIND),
                    CodeQueryRowField::optional("parent_index", Scalar::Integer),
        ],
    },
    Binding => "binding" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("reached_from_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("name", Scalar::String),
                    CodeQueryRowField::required_enum("kind", value_domain::BINDING_KIND),
                    CodeQueryRowField::required_enum("hoisting", value_domain::HOISTING_CLASS),
                    CodeQueryRowField::required_enum("namespace", value_domain::NAMESPACE),
                    CodeQueryRowField::required("declaring_scope_index", Scalar::Integer),
                    CodeQueryRowField::required_enum("visibility", value_domain::DECLARED_VISIBILITY),
                    CodeQueryRowField::required("shadowed", Scalar::Boolean),
        ],
    },
    ResolutionCandidate => "resolution_candidate" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::optional_enum("tier", value_domain::PRECEDENCE_TIER),
                    CodeQueryRowField::required_enum("outcome", value_domain::CANDIDATE_OUTCOME),
                    CodeQueryRowField::optional_enum(
                        "rejection_reason",
                        value_domain::REJECTION_REASON
                    ),
                    CodeQueryRowField::required_enum("boundary", value_domain::BOUNDARY_STATUS),
                    CodeQueryRowField::required_enum("visibility", value_domain::DECLARED_VISIBILITY),
                    CodeQueryRowField::required_enum(
                        "trace_completeness",
                        value_domain::TRACE_COMPLETENESS
                    ),
                    CodeQueryRowField::required_enum("candidate_kind", value_domain::CANDIDATE_KIND),
                    CodeQueryRowField::optional("candidate_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("canonical_member_id", Scalar::StableId),
                    CodeQueryRowField::optional("owner_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("hierarchy_depth", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "dispatch_tier",
                        value_domain::MEMBER_DISPATCH_TIER
                    ),
                    CodeQueryRowField::optional_enum(
                        "applicability",
                        value_domain::APPLICABILITY_VERDICT
                    ),
        ],
    },
    CandidateHop => "candidate_hop" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("candidate_id", Scalar::StableId),
                    CodeQueryRowField::required("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("hop", Scalar::Integer),
                    CodeQueryRowField::required_enum("relation", value_domain::HIERARCHY_RELATION),
                    CodeQueryRowField::optional("from_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("to_id", Scalar::DeclarationIdentity),
        ],
    },
    GenerationSite => "generation_site" {
        display_range: |value| Some(value.range),
        // The three materialization domains are identified by their
        // own content-scoped digests too (#1476).
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("kind", value_domain::GENERATION_KIND),
                    CodeQueryRowField::required_enum("input", value_domain::GENERATION_INPUT),
                    CodeQueryRowField::required("generated_count", Scalar::Integer),
        ],
    },
    Export => "export" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("form", value_domain::EXPORT_FORM),
                    CodeQueryRowField::required("exported_name", Scalar::String),
                    CodeQueryRowField::optional("target_fq_name", Scalar::String),
        ],
    },
    DeclarationState => "declaration_state" {
        display_range: |value| value.range,
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required("fq_name", Scalar::String),
                    CodeQueryRowField::required_enum("unit_kind", value_domain::CODE_UNIT_KIND),
                    CodeQueryRowField::required_enum("origin", value_domain::DECLARATION_ORIGIN),
                    CodeQueryRowField::required("declaration_only", Scalar::Boolean),
                    CodeQueryRowField::required("config_gated", Scalar::Boolean),
        ],
    },
    ReferenceEdge => "reference_edge" {
        display_range: |value| Some(value.range),
        // The identity-route domains carry their digests the same
        // way (#1475).
        // A reference edge's identity is its own content-scoped
        // digest, carried in the typed key like the environment
        // domains above.
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional_enum("reference_kind", value_domain::REFERENCE_KIND),
                    CodeQueryRowField::required_enum("proof", value_domain::USAGE_PROOF),
                    CodeQueryRowField::required_enum("usage_kind", value_domain::USAGE_KIND),
                    CodeQueryRowField::required_enum("site_class", value_domain::SITE_CLASS),
                    CodeQueryRowField::required_enum("owner_relation", value_domain::OWNER_RELATION),
                    CodeQueryRowField::required_enum("edge_provenance", value_domain::EDGE_PROVENANCE),
                    CodeQueryRowField::required("generation", Scalar::Integer),
        ],
    },
    StateEvent => "state_event" {
        display_range: |value| Some(value.range),
        // A state event and a flow relation are identified by their
        // own content-scoped digests in the typed key too; neither is
        // artifact-backed, so neither carries a semantic identity
        // (#1480).
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("event_class", value_domain::STATE_EVENT_CLASS),
                    CodeQueryRowField::required_enum("subject", value_domain::FLOW_SUBJECT),
                    CodeQueryRowField::optional("member", Scalar::String),
                    CodeQueryRowField::required("subject_value", Scalar::Integer),
                    CodeQueryRowField::required("program_point", Scalar::Integer),
                    CodeQueryRowField::required("program_point_id", Scalar::StableId),
                    CodeQueryRowField::required("value", Scalar::Integer),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::FLOW_STATE_COMPLETENESS
                    ),
                    CodeQueryRowField::required("generation", Scalar::Integer),
        ],
    },
    FlowRelation => "flow_relation" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("relation", value_domain::FLOW_RELATION),
                    CodeQueryRowField::required_enum("certainty", value_domain::FLOW_CERTAINTY),
                    CodeQueryRowField::required("source_id", Scalar::StableId),
                    CodeQueryRowField::required("target_id", Scalar::StableId),
                    CodeQueryRowField::optional("source_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::FLOW_STATE_COMPLETENESS
                    ),
                    CodeQueryRowField::required("generation", Scalar::Integer),
        ],
    },
    ControlRelation => "control_relation" {
        display_range: |value| Some(value.range),
        // A control relation is identified by its own content-scoped digest
        // over the procedure, the relation and the endpoint wire ids; it is not
        // artifact-backed, so it carries no semantic identity candidate.
        identities: None,
        // Issue #2443. `source_id` and `target_id` are `program_point` row ids
        // and `controlling_edge_id` is a `control_edge` row id, so every join
        // this domain takes part in is id equality. `exit_partition` states the
        // exit universe a backward claim was computed against.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("relation", value_domain::CONTROL_RELATION),
                    CodeQueryRowField::required_enum("certainty", value_domain::FLOW_CERTAINTY),
                    CodeQueryRowField::required_enum(
                        "exit_partition",
                        value_domain::CONTROL_EXIT_PARTITION
                    ),
                    CodeQueryRowField::required("source_id", Scalar::StableId),
                    CodeQueryRowField::required("target_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "source_boundary",
                        value_domain::PROGRAM_POINT_BOUNDARY
                    ),
                    CodeQueryRowField::required_enum(
                        "target_boundary",
                        value_domain::PROGRAM_POINT_BOUNDARY
                    ),
                    CodeQueryRowField::optional("controlling_edge_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::CONTROL_RELATION_COMPLETENESS
                    ),
                    CodeQueryRowField::required("generation", Scalar::Integer),
        ],
    },
    Guard => "guard" {
        display_range: |value| Some(value.range),
        // A guard is identified by its own content-scoped digest over the
        // procedure and the program point it sits on; the IR row it projects
        // is addressed by that point, not by a semantic identity of its own.
        identities: None,
        // Issue #2443 slice 2. `point_id` is a `program_point` row id and both
        // edge columns are `control_edge` row ids, so every join this domain
        // takes part in is id equality. An absent edge column is the honest
        // shape of a folded arm: the predicate still states the condition was
        // constant, and the missing successor is why that matters.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required("point_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("predicate", value_domain::GUARD_PREDICATE),
                    CodeQueryRowField::optional("subject_value", Scalar::Integer),
                    CodeQueryRowField::optional("true_edge_id", Scalar::StableId),
                    CodeQueryRowField::optional("false_edge_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("proof", value_domain::EVIDENCE_PROOF),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::EVIDENCE_COMPLETENESS
                    ),
        ],
    },
    RewritePath => "rewrite_path" {
        display_range: |value| Some(value.range),
        // A rewrite path is identified by its own content-scoped
        // digest over the domain, origin and derivation (#1480).
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("domain", value_domain::REWRITE_DOMAIN),
                    CodeQueryRowField::required("origin_specifier", Scalar::String),
                    CodeQueryRowField::required("declared_bound", Scalar::Integer),
                    CodeQueryRowField::required("step_count", Scalar::Integer),
                    CodeQueryRowField::required_enum("outcome", value_domain::REWRITE_OUTCOME),
                    CodeQueryRowField::optional("fixed_point", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::REWRITE_PATH_COMPLETENESS
                    ),
                    CodeQueryRowField::required("generation", Scalar::Integer),
        ],
    },
    QualifiedPath => "qualified_path" {
        display_range: |value| Some(value.range),
        // A path and its segments are likewise identified by their
        // own content-scoped digests in the typed key.
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("segment_count", Scalar::Integer),
        ],
    },
    PathSegment => "path_segment" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("path_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required("text", Scalar::String),
                    CodeQueryRowField::optional_enum("namespace", value_domain::NAMESPACE),
                    CodeQueryRowField::optional("generic_arity", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "resolution_status",
                        value_domain::SEGMENT_RESOLUTION_STATUS
                    ),
                    CodeQueryRowField::optional("target_count", Scalar::Integer),
        ],
    },
    // The three project-topology domains (#2448). All three are statements a
    // build file makes, and the topology vocabulary records no position inside
    // that file, so all three anchor at its first line: naming a region inside
    // the pom would mean guessing where the declaration sits, which is the
    // lexical inference the topology module exists to refuse. `build_file` is
    // the column that carries the claim. None is artifact-backed, so none
    // carries a semantic identity candidate.
    SourceSet => "source_set" {
        display_range: |_value| Some(BUILD_FILE_ANCHOR_RANGE),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("name", Scalar::String),
                    CodeQueryRowField::optional("target_id", Scalar::StableId),
                    CodeQueryRowField::required("build_file", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::TOPOLOGY_COMPLETENESS
                    ),
        ],
    },
    BuildTarget => "build_target" {
        display_range: |_value| Some(BUILD_FILE_ANCHOR_RANGE),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("name", Scalar::String),
                    CodeQueryRowField::optional("build_project_id", Scalar::StableId),
                    CodeQueryRowField::required("build_file", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::TOPOLOGY_COMPLETENESS
                    ),
        ],
    },
    TopologyEdge => "topology_edge" {
        display_range: |_value| Some(BUILD_FILE_ANCHOR_RANGE),
        identities: None,
        // `from_id` and `to_id` are `build_target` row ids, so an architecture
        // rule joins a target to its dependencies by id equality. `scope` is
        // the same seven-label vocabulary a resolved external dependency
        // carries.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("from_id", Scalar::StableId),
                    CodeQueryRowField::optional("to_id", Scalar::StableId),
                    CodeQueryRowField::required("from_name", Scalar::String),
                    CodeQueryRowField::required("to_name", Scalar::String),
                    CodeQueryRowField::required_enum("scope", value_domain::DEPENDENCY_SCOPE),
                    CodeQueryRowField::required("build_file", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::TOPOLOGY_COMPLETENESS
                    ),
        ],
    },
}

impl CodeQueryResultValue {
    pub fn row(&self) -> CodeQueryRowRef<'_> {
        CodeQueryRowRef { value: self }
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
            "required CodeQuery row field `{}.{}` projected no value",
            self.domain().label(),
            schema.name
        );
        debug_assert!(
            field_value_is_in_domain(*schema, value),
            "CodeQuery row field `{}.{}` projected a value outside its registered domain: {value:?}",
            self.domain().label(),
            schema.name
        );
        Ok(value)
    }
}

/// Whether one projected scalar respects the value domain its field declares.
///
/// Enum-typed fields are the only ones with a domain, and an absent optional
/// value is always in domain. This is the producer-side half of issue #2515:
/// the loader rejects a policy literal that no row can hold, and this rejects a
/// producer that writes a label the registry does not publish.
pub fn field_value_is_in_domain(
    field: CodeQueryRowField,
    value: Option<CodeQueryRowScalarRef<'_>>,
) -> bool {
    let (Some(domain), Some(CodeQueryRowScalarRef::ConstrainedEnum(label))) =
        (field.value_domain, value)
    else {
        return true;
    };
    domain.admits(label)
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
        (CodeQueryResultValue::ProgramPoint { value }, "boundary") => Some(
            Scalar::ConstrainedEnum(CodeQueryProgramPointBoundary::row_label(value.boundary)),
        ),
        (CodeQueryResultValue::ControlEdge { value }, "source_id") => {
            Some(Scalar::StableId(&value.source.id))
        }
        (CodeQueryResultValue::ControlEdge { value }, "target_id") => {
            Some(Scalar::StableId(&value.target.id))
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
        (CodeQueryResultValue::JsxAttributeValue { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "ast_id") => {
            Some(Scalar::StableId(&value.ast_id))
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "element_identity") => {
            Some(Scalar::ConstrainedEnum(value.element_identity))
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "element_name") => {
            value.element_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "attribute_kind") => {
            Some(Scalar::ConstrainedEnum(value.attribute_kind))
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "attribute_name") => {
            value.attribute_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "property_name") => {
            value.property_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "reason") => {
            value.reason.map(Scalar::String)
        }
        (CodeQueryResultValue::JsxAttributeValue { value }, "component_id") => value
            .component
            .as_ref()
            .and_then(|target| target.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::JsxAttributeValue { value }, "attribute_target_id") => value
            .attribute_target
            .as_ref()
            .and_then(|target| target.id.as_deref())
            .map(Scalar::DeclarationIdentity),
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
        (CodeQueryResultValue::CallableSignature { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallableSignature { value }, "declaration_id") => value
            .declaration
            .id
            .as_deref()
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallableSignature { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::CallableSignature { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallableSignature { value }, "role") => {
            Some(Scalar::ConstrainedEnum(value.role))
        }
        (CodeQueryResultValue::CallableSignature { value }, "required_arity") => value
            .required_arity
            .map(|arity| Scalar::Integer(arity as u64)),
        (CodeQueryResultValue::CallableSignature { value }, "total_arity") => {
            value.total_arity.map(|arity| Scalar::Integer(arity as u64))
        }
        (CodeQueryResultValue::CallableSignature { value }, "repeated") => {
            Some(Scalar::Boolean(value.repeated))
        }
        (CodeQueryResultValue::CallableSignature { value }, "generic_arity") => {
            Some(Scalar::Integer(value.generic_arity as u64))
        }
        (CodeQueryResultValue::CallableSignature { value }, "receiver_contract") => {
            value.receiver_contract.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallableSignature { value }, "return_type") => {
            value.return_type.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallableSignature { value }, "declaration_only") => {
            Some(Scalar::Boolean(value.declaration_only))
        }
        (CodeQueryResultValue::CallableSignature { value }, "parameter_count") => {
            Some(Scalar::Integer(value.parameter_count as u64))
        }
        (CodeQueryResultValue::CallableApplicability { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallableApplicability { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallableApplicability { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::CallableApplicability { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::CallableApplicability { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallableApplicability { value }, "tier") => {
            value.tier.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallableApplicability { value }, "selected") => {
            Some(Scalar::Boolean(value.selected))
        }
        (CodeQueryResultValue::CallableApplicability { value }, "candidate_id") => {
            match &value.candidate {
                CodeQueryCandidateRef::Unit { unit } => {
                    unit.id.as_deref().map(Scalar::DeclarationIdentity)
                }
                _ => None,
            }
        }
        (CodeQueryResultValue::OverloadSelection { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "resolution") => {
            Some(Scalar::ConstrainedEnum(value.resolution))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "supported") => {
            Some(Scalar::Boolean(value.supported))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "considered_count") => {
            Some(Scalar::Integer(value.considered_count as u64))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "applicable_count") => {
            Some(Scalar::Integer(value.applicable_count as u64))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "inapplicable_count") => {
            Some(Scalar::Integer(value.inapplicable_count as u64))
        }
        (CodeQueryResultValue::OverloadSelection { value }, "unknown_count") => {
            Some(Scalar::Integer(value.unknown_count as u64))
        }
        (CodeQueryResultValue::SignatureParameter { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::SignatureParameter { value }, "signature_id") => {
            Some(Scalar::StableId(&value.signature_id))
        }
        (CodeQueryResultValue::SignatureParameter { value }, "parameter_index") => {
            Some(Scalar::Integer(value.parameter_index as u64))
        }
        (CodeQueryResultValue::SignatureParameter { value }, "label") => {
            Some(Scalar::String(&value.label))
        }
        (CodeQueryResultValue::SignatureParameter { value }, "declared_type") => {
            value.declared_type.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::SignatureParameter { value }, "optional") => {
            value.optional.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::SignatureParameter { value }, "repeated") => {
            value.repeated.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "parameter_id") => {
            Some(Scalar::StableId(&value.parameter_id))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "decorator_id") => {
            value.decorator_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "owner_id") => {
            value.owner_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "procedure_id") => {
            value.procedure_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "parameter_ordinal") => value
            .parameter_ordinal
            .map(|ordinal| Scalar::Integer(ordinal as u64)),
        (CodeQueryResultValue::DecoratedParameter { value }, "port_id") => {
            value.port_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "decorator_name") => {
            Some(Scalar::String(&value.decorator_name))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "local_name") => {
            value.local_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "imported_name") => {
            value.imported_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "module") => {
            value.module.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "binding_status") => {
            Some(Scalar::ConstrainedEnum(value.binding_status))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "boundary") => {
            Some(Scalar::ConstrainedEnum(value.boundary))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "completion") => {
            Some(Scalar::ConstrainedEnum(value.completion))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "reason") => {
            value.reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DecoratedParameter { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::CallBinding { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CallBinding { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallBinding { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallBinding { value }, "group_id") => {
            value.group_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "argument_id") => {
            value.argument_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "target_id") => value
            .target
            .as_ref()
            .and_then(|target| target.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallBinding { value }, "semantic_target_id") => {
            value.semantic_target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "dispatch_outcome") => {
            Some(Scalar::ConstrainedEnum(value.dispatch_outcome))
        }
        (CodeQueryResultValue::CallBinding { value }, "dispatch_coverage") => {
            Some(Scalar::ConstrainedEnum(value.dispatch_coverage))
        }
        (CodeQueryResultValue::CallBinding { value }, "dispatch_proof") => {
            value.dispatch_proof.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "dispatch_completeness") => {
            value.dispatch_completeness.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "dispatch_target_count") => {
            Some(Scalar::Integer(value.dispatch_target_count as u64))
        }
        (CodeQueryResultValue::CallBinding { value }, "dispatch_targets_truncated") => {
            Some(Scalar::Boolean(value.dispatch_targets_truncated))
        }
        (CodeQueryResultValue::CallBinding { value }, "signature_id") => {
            value.signature_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "actual_index") => value
            .actual_index
            .map(|index| Scalar::Integer(index as u64)),
        (CodeQueryResultValue::CallBinding { value }, "actual_name") => {
            value.actual_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "formal_index") => value
            .formal_index
            .map(|index| Scalar::Integer(index as u64)),
        (CodeQueryResultValue::CallBinding { value }, "formal_name") => {
            value.formal_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "binding_kind") => {
            value.binding_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "conversion") => {
            value.conversion.as_deref().map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "mapping") => {
            Some(Scalar::ConstrainedEnum(value.mapping))
        }
        (CodeQueryResultValue::CallBinding { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallBinding { value }, "actual_count") => {
            Some(Scalar::Integer(value.actual_count as u64))
        }
        (CodeQueryResultValue::CallBinding { value }, "bound_count") => {
            Some(Scalar::Integer(value.bound_count as u64))
        }
        (CodeQueryResultValue::CallBinding { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::CallEffect { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CallEffect { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallEffect { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallEffect { value }, "target_id") => {
            value.target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallEffect { value }, "callee_id") => value
            .callee
            .as_ref()
            .and_then(|callee| callee.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallEffect { value }, "callee_symbol") => {
            value.callee_symbol.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallEffect { value }, "effect_id") => {
            value.effect_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallEffect { value }, "classification") => {
            Some(Scalar::ConstrainedEnum(value.classification))
        }
        (CodeQueryResultValue::CallEffect { value }, "timing") => {
            value.timing.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallEffect { value }, "certainty") => {
            value.certainty.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallEffect { value }, "proof") => {
            value.proof.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallEffect { value }, "derivation") => {
            Some(Scalar::ConstrainedEnum(value.derivation))
        }
        (CodeQueryResultValue::CallEffect { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallEffect { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallEffect { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallEffect { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallEffect { value }, "summary_id") => {
            value.summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallEffect { value }, "arm_count") => {
            Some(Scalar::Integer(value.arm_count as u64))
        }
        (CodeQueryResultValue::CallEffect { value }, "modeled_arm_count") => {
            Some(Scalar::Integer(value.modeled_arm_count as u64))
        }
        (CodeQueryResultValue::CallEffect { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "procedure_id") => {
            Some(Scalar::DeclarationIdentity(&value.procedure_id))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "procedure_name") => {
            Some(Scalar::String(&value.procedure_name))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "effect_id") => {
            value.effect_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "classification") => {
            value.classification.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "certainty") => {
            value.certainty.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "timing") => {
            value.timing.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "depth") => {
            value.depth.map(|depth| Scalar::Integer(depth as u64))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "derivation") => {
            Some(Scalar::ConstrainedEnum(value.derivation))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "witness_available") => {
            Some(Scalar::Boolean(value.witness_available))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "witness_steps") => {
            Some(Scalar::Integer(value.witness_steps as u64))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "witness_site_id") => {
            value.witness_site_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "witness_effect_site_id") => value
            .witness_effect_site_id
            .as_deref()
            .map(Scalar::StableId),
        (CodeQueryResultValue::ProcedureEffect { value }, "witness_chain") => {
            value.witness_chain.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "witness_truncated") => {
            Some(Scalar::Boolean(value.witness_truncated))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "summary_id") => {
            value.summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::CallArgument { value }, "spread") => {
            Some(Scalar::Boolean(value.spread))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "site_ast_id") => {
            value.site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "call_site_count") => {
            Some(Scalar::Integer(value.call_site_count as u64))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "target_count") => {
            Some(Scalar::Integer(value.target_count as u64))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "targets_truncated") => {
            Some(Scalar::Boolean(value.targets_truncated))
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "semantic_unsupported") => {
            value.semantic_unsupported.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::DispatchOutcome { value }, "exceeded_limit") => {
            value.exceeded_limit.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::DispatchTarget { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::DispatchTarget { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "site_ast_id") => {
            value.site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DispatchTarget { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "target_id") => {
            Some(Scalar::StableId(&value.target_id))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "target_declaration_id") => value
            .target_declaration
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::DispatchTarget { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "dispatch") => {
            Some(Scalar::ConstrainedEnum(value.dispatch))
        }
        (CodeQueryResultValue::DispatchTarget { value }, "boundary_kind") => {
            value.boundary_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::MemberFamily { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::MemberFamily { value }, "member_id") => {
            Some(Scalar::StableId(&value.member_id))
        }
        (CodeQueryResultValue::MemberFamily { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::MemberFamily { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::MemberFamily { value }, "capability") => {
            Some(Scalar::ConstrainedEnum(value.capability))
        }
        (CodeQueryResultValue::MemberFamily { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::MemberFamily { value }, "family_id") => {
            value.family_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::MemberFamily { value }, "overrides_count") => {
            Some(Scalar::Integer(value.overrides_count as u64))
        }
        (CodeQueryResultValue::MemberFamily { value }, "implements_count") => {
            Some(Scalar::Integer(value.implements_count as u64))
        }
        (CodeQueryResultValue::MemberFamily { value }, "overridden_by_count") => {
            Some(Scalar::Integer(value.overridden_by_count as u64))
        }
        (CodeQueryResultValue::MemberFamily { value }, "implemented_by_count") => {
            Some(Scalar::Integer(value.implemented_by_count as u64))
        }
        (CodeQueryResultValue::MemberFamily { value }, "edge_count") => {
            Some(Scalar::Integer(value.edge_count as u64))
        }
        (CodeQueryResultValue::MemberFamily { value }, "root_count") => {
            Some(Scalar::Integer(value.root_count as u64))
        }
        (CodeQueryResultValue::MemberFamily { value }, "member_declaration_id") => value
            .member
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::MemberFamilyEdge { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "member_id") => {
            Some(Scalar::StableId(&value.member_id))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "target_id") => {
            Some(Scalar::StableId(&value.target_id))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "family_id") => {
            value.family_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "hierarchy_depth") => {
            Some(Scalar::Integer(value.hierarchy_depth as u64))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::MemberFamilyEdge { value }, "target_declaration_id") => value
            .target
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref())
            .map(Scalar::DeclarationIdentity),
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
                CodeQueryOccurrenceTarget::NotDerived => "not_derived",
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
                // No attempt was made, so there is no count to report. Zero
                // would be the answer for "resolved to nothing", which is a
                // different statement.
                CodeQueryOccurrenceTarget::NotDerived => return None,
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
        (CodeQueryResultValue::ResolutionCandidate { value }, "owner_id") => value
            .owner
            .as_ref()
            .and_then(|owner| owner.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::ResolutionCandidate { value }, "hierarchy_depth") => value
            .hierarchy_depth
            .map(|depth| Scalar::Integer(depth as u64)),
        (CodeQueryResultValue::ResolutionCandidate { value }, "dispatch_tier") => {
            value.dispatch_tier.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResolutionCandidate { value }, "applicability") => {
            value.applicability.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CandidateHop { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CandidateHop { value }, "candidate_id") => {
            Some(Scalar::StableId(&value.candidate_id))
        }
        (CodeQueryResultValue::CandidateHop { value }, "ast_id") => {
            Some(Scalar::StableId(&value.ast_id))
        }
        (CodeQueryResultValue::CandidateHop { value }, "hop") => {
            Some(Scalar::Integer(value.hop as u64))
        }
        (CodeQueryResultValue::CandidateHop { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::CandidateHop { value }, "from_id") => value
            .from
            .as_ref()
            .and_then(|unit| unit.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CandidateHop { value }, "to_id") => value
            .to
            .as_ref()
            .and_then(|unit| unit.id.as_deref())
            .map(Scalar::DeclarationIdentity),
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
        (CodeQueryResultValue::StateEvent { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::StateEvent { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::StateEvent { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::StateEvent { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::StateEvent { value }, "event_class") => {
            Some(Scalar::ConstrainedEnum(value.event_class))
        }
        (CodeQueryResultValue::StateEvent { value }, "subject") => {
            Some(Scalar::ConstrainedEnum(value.subject))
        }
        (CodeQueryResultValue::StateEvent { value }, "member") => {
            value.member.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::StateEvent { value }, "subject_value") => {
            Some(Scalar::Integer(value.subject_value as u64))
        }
        (CodeQueryResultValue::StateEvent { value }, "program_point") => {
            Some(Scalar::Integer(value.program_point as u64))
        }
        (CodeQueryResultValue::StateEvent { value }, "program_point_id") => {
            Some(Scalar::StableId(&value.program_point_id))
        }
        (CodeQueryResultValue::StateEvent { value }, "value") => {
            Some(Scalar::Integer(value.value as u64))
        }
        (CodeQueryResultValue::StateEvent { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::StateEvent { value }, "generation") => {
            Some(Scalar::Integer(value.generation))
        }
        (CodeQueryResultValue::RewritePath { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::RewritePath { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::RewritePath { value }, "domain") => {
            Some(Scalar::ConstrainedEnum(value.domain))
        }
        (CodeQueryResultValue::RewritePath { value }, "origin_specifier") => {
            Some(Scalar::String(&value.origin_specifier))
        }
        (CodeQueryResultValue::RewritePath { value }, "declared_bound") => {
            Some(Scalar::Integer(value.declared_bound as u64))
        }
        (CodeQueryResultValue::RewritePath { value }, "step_count") => {
            Some(Scalar::Integer(value.step_count as u64))
        }
        (CodeQueryResultValue::RewritePath { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::RewritePath { value }, "fixed_point") => {
            value.fixed_point.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RewritePath { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::RewritePath { value }, "generation") => {
            Some(Scalar::Integer(value.generation))
        }
        (CodeQueryResultValue::FlowRelation { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::FlowRelation { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::FlowRelation { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::FlowRelation { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::FlowRelation { value }, "certainty") => {
            Some(Scalar::ConstrainedEnum(value.certainty))
        }
        (CodeQueryResultValue::FlowRelation { value }, "source_id") => {
            Some(Scalar::StableId(&value.source.id))
        }
        (CodeQueryResultValue::FlowRelation { value }, "target_id") => {
            Some(Scalar::StableId(&value.target.id))
        }
        (CodeQueryResultValue::FlowRelation { value }, "source_ast_id") => {
            value.source.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::FlowRelation { value }, "target_ast_id") => {
            value.target.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::FlowRelation { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::FlowRelation { value }, "generation") => {
            Some(Scalar::Integer(value.generation))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "generation") => {
            Some(Scalar::Integer(value.generation))
        }
        (CodeQueryResultValue::ControlRelation { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ControlRelation { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::ControlRelation { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::ControlRelation { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::ControlRelation { value }, "certainty") => {
            Some(Scalar::ConstrainedEnum(value.certainty))
        }
        (CodeQueryResultValue::ControlRelation { value }, "exit_partition") => {
            Some(Scalar::ConstrainedEnum(value.exit_partition))
        }
        (CodeQueryResultValue::ControlRelation { value }, "source_id") => {
            Some(Scalar::StableId(&value.source.id))
        }
        (CodeQueryResultValue::ControlRelation { value }, "target_id") => {
            Some(Scalar::StableId(&value.target.id))
        }
        (CodeQueryResultValue::ControlRelation { value }, "source_boundary") => {
            Some(Scalar::ConstrainedEnum(
                CodeQueryProgramPointBoundary::row_label(value.source.boundary),
            ))
        }
        (CodeQueryResultValue::ControlRelation { value }, "target_boundary") => {
            Some(Scalar::ConstrainedEnum(
                CodeQueryProgramPointBoundary::row_label(value.target.boundary),
            ))
        }
        (CodeQueryResultValue::ControlRelation { value }, "controlling_edge_id") => {
            value.controlling_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ControlRelation { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::ControlRelation { value }, "generation") => {
            Some(Scalar::Integer(value.generation))
        }
        (CodeQueryResultValue::Guard { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::Guard { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::Guard { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::Guard { value }, "point_id") => {
            Some(Scalar::StableId(&value.point.id))
        }
        (CodeQueryResultValue::Guard { value }, "predicate") => {
            Some(Scalar::ConstrainedEnum(value.predicate))
        }
        (CodeQueryResultValue::Guard { value }, "subject_value") => {
            value.subject_value.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "true_edge_id") => {
            value.true_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Guard { value }, "false_edge_id") => {
            value.false_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Guard { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::Guard { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::SourceSet { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::SourceSet { value }, "name") => Some(Scalar::String(&value.name)),
        (CodeQueryResultValue::SourceSet { value }, "target_id") => {
            value.target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::SourceSet { value }, "build_file") => {
            Some(Scalar::String(&value.build_file))
        }
        (CodeQueryResultValue::SourceSet { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::BuildTarget { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::BuildTarget { value }, "name") => Some(Scalar::String(&value.name)),
        (CodeQueryResultValue::BuildTarget { value }, "build_project_id") => {
            value.build_project_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::BuildTarget { value }, "build_file") => {
            Some(Scalar::String(&value.build_file))
        }
        (CodeQueryResultValue::BuildTarget { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::TopologyEdge { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::TopologyEdge { value }, "from_id") => {
            Some(Scalar::StableId(&value.from_id))
        }
        (CodeQueryResultValue::TopologyEdge { value }, "to_id") => {
            value.to_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::TopologyEdge { value }, "from_name") => {
            Some(Scalar::String(&value.from_name))
        }
        (CodeQueryResultValue::TopologyEdge { value }, "to_name") => {
            Some(Scalar::String(&value.to_name))
        }
        (CodeQueryResultValue::TopologyEdge { value }, "scope") => {
            Some(Scalar::ConstrainedEnum(value.scope))
        }
        (CodeQueryResultValue::TopologyEdge { value }, "build_file") => {
            Some(Scalar::String(&value.build_file))
        }
        (CodeQueryResultValue::TopologyEdge { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
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
    JsxAttributeValue {
        id: String,
        ast_id: String,
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
    DispatchOutcome {
        id: String,
        site_id: String,
    },
    DispatchTarget {
        id: String,
        site_id: String,
        ordinal: usize,
    },
    MemberFamily {
        id: String,
        member_id: String,
    },
    MemberFamilyEdge {
        id: String,
        member_id: String,
        ordinal: usize,
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
    CallBinding {
        id: String,
        site_id: String,
    },
    CallEffect {
        id: String,
        site_id: String,
    },
    ProcedureEffect {
        id: String,
        procedure_id: String,
    },
    CallableSignature {
        id: String,
        declaration_id: String,
    },
    CallableApplicability {
        id: String,
        site_ast_id: String,
    },
    OverloadSelection {
        id: String,
        site_ast_id: String,
    },
    SignatureParameter {
        id: String,
        signature_id: String,
    },
    DecoratedParameter {
        id: String,
        parameter_id: String,
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
    CandidateHop {
        id: String,
        candidate_id: String,
        hop: usize,
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
    StateEvent {
        id: String,
        ast_id: Option<String>,
        procedure_id: String,
        event_class: String,
    },
    FlowRelation {
        id: String,
        procedure_id: String,
        relation: String,
        certainty: String,
    },
    ControlRelation {
        id: String,
        procedure_id: String,
        relation: String,
        certainty: String,
    },
    Guard {
        id: String,
        procedure_id: String,
        point_id: String,
        predicate: String,
    },
    RewritePath {
        id: String,
        domain: String,
        origin_specifier: String,
        outcome: String,
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
    SourceSet {
        id: String,
        name: String,
    },
    BuildTarget {
        id: String,
        name: String,
    },
    TopologyEdge {
        id: String,
        from_name: String,
        to_name: String,
        scope: String,
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
            #[cfg(debug_assertions)]
            assert_row_projects_its_registered_surface(&result.value);
            if let Some((expected_domain, expected_key)) = detailed_semantic_identity(&result.value)
            {
                assert_eq!(evidence.domain, expected_domain);
                assert_eq!(evidence.key, expected_key);
            }
            assert_eq!(
                evidence.domain,
                evidence.key.domain(),
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

/// Every field the registry declares for this row's domain projects, with the
/// declared scalar type, the declared nullability, and a value inside the
/// declared enum domain.
///
/// This is the schema/projector reconciliation of issue #2498, run on every row
/// of every detailed query rather than only on the fields a caller happens to
/// ask for. It is compiled out of release builds, so every test in the tree --
/// whichever domains it produces -- proves the registry against real rows at no
/// production cost.
#[cfg(debug_assertions)]
fn assert_row_projects_its_registered_surface(value: &CodeQueryResultValue) {
    let row = value.row();
    let domain = row.domain();
    for field in domain.row_fields() {
        // `field` itself asserts the scalar type, the nullability and the
        // value domain; reaching every registered name is what this adds.
        row.field(field.name)
            .unwrap_or_else(|error| panic!("registered field must project: {error}"));
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
        | CodeQueryResultValue::JsxAttributeValue { .. }
        | CodeQueryResultValue::ReceiverAnalysis { .. }
        | CodeQueryResultValue::ReceiverOutcome { .. }
        | CodeQueryResultValue::ReceiverEvidence { .. }
        | CodeQueryResultValue::DispatchOutcome { .. }
        | CodeQueryResultValue::DispatchTarget { .. }
        | CodeQueryResultValue::MemberFamily { .. }
        | CodeQueryResultValue::MemberFamilyEdge { .. }
        | CodeQueryResultValue::CallShape { .. }
        | CodeQueryResultValue::CallArgumentGroup { .. }
        | CodeQueryResultValue::CallArgument { .. }
        | CodeQueryResultValue::CallBinding { .. }
        | CodeQueryResultValue::CallEffect { .. }
        | CodeQueryResultValue::ProcedureEffect { .. }
        | CodeQueryResultValue::CallableSignature { .. }
        | CodeQueryResultValue::SignatureParameter { .. }
        | CodeQueryResultValue::DecoratedParameter { .. }
        | CodeQueryResultValue::CallableApplicability { .. }
        | CodeQueryResultValue::OverloadSelection { .. }
        | CodeQueryResultValue::MemberSelection { .. }
        | CodeQueryResultValue::Occurrence { .. }
        | CodeQueryResultValue::LexicalScope { .. }
        | CodeQueryResultValue::Binding { .. }
        | CodeQueryResultValue::ResolutionCandidate { .. }
        | CodeQueryResultValue::CandidateHop { .. }
        | CodeQueryResultValue::GenerationSite { .. }
        | CodeQueryResultValue::Export { .. }
        | CodeQueryResultValue::DeclarationState { .. }
        | CodeQueryResultValue::ReferenceEdge { .. }
        | CodeQueryResultValue::StateEvent { .. }
        | CodeQueryResultValue::FlowRelation { .. }
        | CodeQueryResultValue::ControlRelation { .. }
        | CodeQueryResultValue::Guard { .. }
        | CodeQueryResultValue::SourceSet { .. }
        | CodeQueryResultValue::BuildTarget { .. }
        | CodeQueryResultValue::TopologyEdge { .. }
        | CodeQueryResultValue::RewritePath { .. } => None,
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

/// Every terminal row of one domain carries exactly the identity shape that
/// domain declares. The table lives beside the domain's own declaration, so a
/// new domain cannot reach this assertion without one.
fn assert_detailed_terminal_identities(
    domain: DetailedCodeQueryDomain,
    identities: &DetailedCodeQueryProvenanceIdentities,
) {
    assert_eq!(
        DetailedTerminalIdentities::of(identities),
        domain.terminal_identities(),
        "domain `{}` carries the wrong provenance identities: {identities:?}",
        domain.label()
    );
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
        | DetailedCodeQueryKey::JsxAttributeValue { .. }
        | DetailedCodeQueryKey::ReceiverAnalysis { .. }
        | DetailedCodeQueryKey::ReceiverOutcome { .. }
        | DetailedCodeQueryKey::ReceiverEvidence { .. }
        | DetailedCodeQueryKey::DispatchOutcome { .. }
        | DetailedCodeQueryKey::DispatchTarget { .. }
        | DetailedCodeQueryKey::MemberFamily { .. }
        | DetailedCodeQueryKey::MemberFamilyEdge { .. }
        | DetailedCodeQueryKey::CallShape { .. }
        | DetailedCodeQueryKey::CallArgumentGroup { .. }
        | DetailedCodeQueryKey::CallArgument { .. }
        | DetailedCodeQueryKey::CallBinding { .. }
        | DetailedCodeQueryKey::CallEffect { .. }
        | DetailedCodeQueryKey::ProcedureEffect { .. }
        | DetailedCodeQueryKey::CallableSignature { .. }
        | DetailedCodeQueryKey::SignatureParameter { .. }
        | DetailedCodeQueryKey::DecoratedParameter { .. }
        | DetailedCodeQueryKey::CallableApplicability { .. }
        | DetailedCodeQueryKey::OverloadSelection { .. }
        | DetailedCodeQueryKey::MemberSelection { .. }
        | DetailedCodeQueryKey::Occurrence { .. }
        | DetailedCodeQueryKey::LexicalScope { .. }
        | DetailedCodeQueryKey::Binding { .. }
        | DetailedCodeQueryKey::ResolutionCandidate { .. }
        | DetailedCodeQueryKey::CandidateHop { .. }
        | DetailedCodeQueryKey::GenerationSite { .. }
        | DetailedCodeQueryKey::Export { .. }
        | DetailedCodeQueryKey::DeclarationState { .. }
        | DetailedCodeQueryKey::ReferenceEdge { .. }
        | DetailedCodeQueryKey::StateEvent { .. }
        | DetailedCodeQueryKey::FlowRelation { .. }
        | DetailedCodeQueryKey::ControlRelation { .. }
        | DetailedCodeQueryKey::Guard { .. }
        | DetailedCodeQueryKey::SourceSet { .. }
        | DetailedCodeQueryKey::BuildTarget { .. }
        | DetailedCodeQueryKey::TopologyEdge { .. }
        | DetailedCodeQueryKey::RewritePath { .. } => None,
        DetailedCodeQueryKey::QualifiedPath { .. } | DetailedCodeQueryKey::PathSegment { .. } => {
            None
        }
    }
}

/// Issue #2498's acceptance, executed: adding a domain touches one declaration
/// site plus its producer.
///
/// The registry macro is instantiated a second time over a toy domain whose
/// producer is the `ToyRow`/`ToyKey` pair declared here. One entry -- one
/// variant name, one label, one display anchor, one identity shape, one field
/// list -- derives the enum, the mirror slice, the label table, the value-kind
/// mapping, the field surface, the identity shape, the key's domain, the row's
/// display anchor, and the row's domain. Nine tables, no second edit.
///
/// Before this, the same nine lived in nine hand-written exhaustive matches,
/// two of which -- the mirror slice and the identity allow-list -- a new domain
/// could miss without a compile error.
#[cfg(test)]
mod toy_domain {
    use super::*;

    /// The producer half: a row shape and the typed key that addresses it.
    /// Real domains declare these in the analyzer that emits them.
    #[derive(Debug)]
    pub enum ToyRow {
        Widget { value: ToyWidget },
    }

    #[derive(Debug)]
    pub struct ToyWidget {
        pub range: CodeQueryRange,
    }

    #[derive(Debug)]
    pub enum ToyKey {
        Widget {
            #[allow(dead_code)]
            id: String,
        },
    }

    #[derive(Debug, Clone, Copy)]
    pub enum ToyKind {
        Widget,
    }

    detailed_row_domains! {
        domain: ToyDomain,
        all: ALL_TOY_DOMAINS,
        key: ToyKey,
        row: ToyRow,
        kind: ToyKind,

        Widget => "widget" {
            display_range: |value| Some(value.range),
            identities: None,
            fields: [
                CodeQueryRowField::required("id", Scalar::StableId),
                CodeQueryRowField::required_enum("kind", &["round", "square"]),
            ],
        },
    }

    #[test]
    fn one_declaration_site_derives_every_registry_table() {
        let range = CodeQueryRange {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
        };
        let row = ToyRow::Widget {
            value: ToyWidget { range },
        };
        let key = ToyKey::Widget {
            id: "widget-1".to_string(),
        };

        assert_eq!(ALL_TOY_DOMAINS, &[ToyDomain::Widget]);
        assert_eq!(ToyDomain::Widget.label(), "widget");
        assert_eq!(
            ToyDomain::from_query_value_kind(ToyKind::Widget),
            ToyDomain::Widget
        );
        assert_eq!(
            ToyDomain::Widget.terminal_identities(),
            DetailedTerminalIdentities::None
        );
        assert_eq!(key.domain(), ToyDomain::Widget);
        assert_eq!(row.detailed_domain(), ToyDomain::Widget);
        assert_eq!(row.display_range(), Some(range));

        let fields = ToyDomain::Widget.row_fields();
        assert_eq!(
            fields.iter().map(|field| field.name).collect::<Vec<_>>(),
            ["id", "kind"]
        );
        assert_eq!(
            fields[1].value_domain,
            Some(CodeQueryEnumDomain::Labels(&["round", "square"])),
            "an enum field carries its value domain through the same entry"
        );
    }
}
