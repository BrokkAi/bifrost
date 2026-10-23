use super::*;
use crate::analyzer::semantic::{
    DurablePortIdentity, ProcedureLocalLocator, RuntimeKeyedReadEndpoint,
    SemanticArtifactLeaseCharge, ValueId,
};

#[derive(Debug)]
pub struct DetailedCodeQueryResult {
    pub result: CodeQueryResult,
    pub work: CodeQueryExecutionWork,
    /// The budgeted lanes `work` does not publish, for a caller that merges
    /// several executions and must see every cumulative cap.
    pub budgeted_work: CodeQueryBudgetedWork,
    pub evidence: Vec<DetailedCodeQueryEvidence>,
    pub profile: Option<QueryExecutionProfile>,
    pub(in crate::structural::search) semantic_receipt: Option<CodeQuerySemanticReceipt>,
}

/// Identity-preserving semantic charge produced by an opted-in detailed
/// query.
///
/// Policy compilation is a semantic consumer after endpoint selection. It
/// needs the budget's artifact/file identities; flattening this value to
/// public work counters would make the compiler pay those materializations
/// again. Receipt-enabled result-contract windows also retain the exact
/// complete artifact dependency allocations behind usable rows. The policy
/// consumer must either atomically admit those dependencies under its own
/// physical-memory authority or drop the receipt.
pub struct CodeQuerySemanticReceipt {
    budget: SemanticBudgetCharge,
    execution_before: SemanticExecutionBudgetSnapshot,
    execution_charge: SemanticExecutionBudgetCharge,
    artifact_charge: SemanticArtifactLeaseCharge,
}

impl CodeQuerySemanticReceipt {
    pub(crate) fn new(
        budget: SemanticBudgetCharge,
        execution_before: SemanticExecutionBudgetSnapshot,
        execution_charge: SemanticExecutionBudgetCharge,
        artifact_charge: SemanticArtifactLeaseCharge,
    ) -> Self {
        Self {
            budget,
            execution_before,
            execution_charge,
            artifact_charge,
        }
    }

    pub fn budget_charge(&self) -> &SemanticBudgetCharge {
        &self.budget
    }

    pub fn into_parts(
        self,
    ) -> (
        SemanticBudgetCharge,
        SemanticExecutionBudgetSnapshot,
        SemanticExecutionBudgetCharge,
        SemanticArtifactLeaseCharge,
    ) {
        (
            self.budget,
            self.execution_before,
            self.execution_charge,
            self.artifact_charge,
        )
    }
}

impl std::fmt::Debug for CodeQuerySemanticReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodeQuerySemanticReceipt")
            .field("budget", &self.budget)
            .field("execution_before", &self.execution_before)
            .field("execution_charge", &self.execution_charge)
            .field("artifact_dependency_count", &self.artifact_charge.len())
            .field(
                "artifact_dependency_retained_bytes",
                &self.artifact_charge.retained_bytes(),
            )
            .finish()
    }
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
    /// Runtime-only semantic identity for one exact decorated-parameter row.
    ///
    /// The locator and durable port identity retain no artifact materialization
    /// or other runtime allocation. The corresponding artifact dependency is
    /// carried by `CodeQuerySemanticReceipt` when this is populated.
    pub decorated_parameter: Option<DetailedCodeQueryDecoratedParameterEvidence>,
    /// Runtime-only exact endpoint retained for policy matched-value binding.
    /// This is never serialized or carried by a reusable unit product.
    pub runtime_keyed_read: Option<RuntimeKeyedReadEndpoint>,
}

/// Exact semantic selection evidence for a decorated parameter.
///
/// This is intentionally outside the serializable row model. A policy
/// consumer may use the procedure-local value locator and port identity after
/// continuing the semantic artifact receipt; it must not join the row through
/// ranges, names, decorator text, or syntax ordinals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedCodeQueryDecoratedParameterEvidence {
    pub procedure_id: String,
    pub value_id: String,
    pub port_id: String,
    pub value_locator: ProcedureLocalLocator<ValueId>,
    pub port: DurablePortIdentity,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CodeQueryStableOwnerCandidate {
    Declaration {
        namespace: String,
        id: String,
    },
    Derived {
        namespace: String,
        derivation: CodeQueryStableOwnerDerivation,
        semantic_key: String,
    },
}

impl<'de> Deserialize<'de> for CodeQueryStableOwnerCandidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DeclarationWire {
            namespace: String,
            id: String,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DerivedWire {
            namespace: String,
            derivation: CodeQueryStableOwnerDerivation,
            semantic_key: String,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Declaration(DeclarationWire),
            Derived(DerivedWire),
        }

        match Wire::deserialize(deserializer)? {
            Wire::Declaration(wire) => Ok(Self::Declaration {
                namespace: wire.namespace,
                id: wire.id,
            }),
            Wire::Derived(wire) => Ok(Self::Derived {
                namespace: wire.namespace,
                derivation: wire.derivation,
                semantic_key: wire.semantic_key,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryStableOwnerDerivation {
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
    StringList,
    IntegerList,
    Integer,
    Boolean,
    ConstrainedEnum,
    DeclarationIdentity,
}

impl CodeQueryRowScalarType {
    /// Whether a literal of the given scalar type can address this field.
    /// String literals can address identity-bearing scalar values by spelling.
    pub const fn accepts_literal_type(self, literal_type: Self) -> bool {
        matches!(
            (self, literal_type),
            (
                Self::String | Self::StableId | Self::DeclarationIdentity,
                Self::String
            ) | (Self::StringList, Self::StringList)
                | (Self::IntegerList, Self::IntegerList)
                | (Self::Integer, Self::Integer)
                | (Self::Boolean, Self::Boolean)
                | (Self::ConstrainedEnum, Self::ConstrainedEnum)
        )
    }

    /// Stable public spelling used by row-schema catalogs and diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::StableId => "stable_id",
            Self::String => "string",
            Self::StringList => "string_list",
            Self::IntegerList => "integer_list",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::ConstrainedEnum => "constrained_enum",
            Self::DeclarationIdentity => "declaration_identity",
        }
    }
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
    /// Short editor help for Python facts added to the queryable row schema.
    /// The source parser attaches this text to matching `filter` field names.
    pub fn rql_help_for_name(name: &str) -> Option<&'static str> {
        match name {
            "base_branch_definition_count" => Some(
                "Number of distinct same-name member declarations found under resolved direct base branches.",
            ),
            "has_strict_ordering" => {
                Some("Whether the class's effective C3 method set defines __lt__ or __gt__.")
            }
            "has_non_strict_ordering" => {
                Some("Whether the class's effective C3 method set defines __le__ or __ge__.")
            }
            "total_ordering_decorator" => Some(
                "Whether the class has a directly recognized functools.total_ordering decorator.",
            ),
            "inherited_ne_present" => {
                Some("Whether the class inherits an effective __ne__ implementation.")
            }
            "inherited_ne_delegates" => Some(
                "Whether every effective inherited __ne__ implementation is recognized as delegating to __eq__.",
            ),
            "returns_receiver" => Some(
                "Whether the selected iterator return expression is exactly the receiver parameter.",
            ),
            "target_non_trivial" => Some(
                "Whether the lifecycle target method has a non-trivial body under CodeQL's MethodCallOrder predicate.",
            ),
            "target_reads_self" => Some(
                "Whether the dispatched subclass override reads its receiver as an attribute receiver or call argument.",
            ),
            "special_method_status" => {
                Some("Arity compatibility status for a recognized Python special-method protocol.")
            }
            _ => None,
        }
    }

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
        Self::required_constrained_enum(name, CodeQueryEnumDomain::Labels(labels))
    }

    const fn required_constrained_enum(
        name: &'static str,
        value_domain: CodeQueryEnumDomain,
    ) -> Self {
        Self {
            name,
            scalar_type: CodeQueryRowScalarType::ConstrainedEnum,
            nullable: false,
            value_domain: Some(value_domain),
        }
    }

    /// An optional enum field over a finite label set.
    pub const fn optional_enum(name: &'static str, labels: &'static [&'static str]) -> Self {
        Self::optional_constrained_enum(name, CodeQueryEnumDomain::Labels(labels))
    }

    const fn optional_constrained_enum(
        name: &'static str,
        value_domain: CodeQueryEnumDomain,
    ) -> Self {
        Self {
            name,
            scalar_type: CodeQueryRowScalarType::ConstrainedEnum,
            nullable: true,
            value_domain: Some(value_domain),
        }
    }

    /// A required enum field whose producer's vocabulary cannot be enumerated.
    /// `reason` states why, and no literal over it is ever rejected.
    pub const fn required_open_enum(name: &'static str, reason: &'static str) -> Self {
        Self::required_constrained_enum(name, CodeQueryEnumDomain::Unenumerable(reason))
    }

    /// An optional enum field whose producer's vocabulary cannot be enumerated.
    pub const fn optional_open_enum(name: &'static str, reason: &'static str) -> Self {
        Self::optional_constrained_enum(name, CodeQueryEnumDomain::Unenumerable(reason))
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
    use super::{
        CodeQueryResultSubjectOutcome, NormalizedKind, ReceiverQueryOperation, UsageHitKind,
    };
    use crate::analyzer::CodeUnitType;
    use crate::analyzer::semantic::CandidateCoverage;
    use crate::analyzer::semantic::capabilities::SemanticCapability;
    use crate::analyzer::semantic::provider::SemanticBudgetLane;
    use crate::analyzer::semantic::{
        ControlEdgeKind, DispatchBoundaryKind, EvidenceCompleteness, ExecutionTiming,
        ProcedureKind, ProofStatus,
    };
    use crate::analyzer::structural::materialization::SourceExportBindingKind;
    use crate::analyzer::usages::call_binding::{
        CallBindingCoverage, CallBindingKind, CallBindingMapping, CallBindingReason,
    };
    use crate::analyzer::usages::effects::{
        EffectCertainty, EffectClassification, EffectCoverage, EffectDerivation, EffectProof,
        EffectReason, EffectTiming,
    };
    use crate::analyzer::usages::get_definition::trace::TraceCompleteness;
    use crate::query::{FailureUseConsumer, FailureUseProvenance};
    use crate::structural::search::results::environment::CodeQueryCandidateRef;
    use crate::structural::search::{
        CodeQueryFlowStatus, dispatch, member_family, receiver, render,
    };
    use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect};
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
        FlowCertainty, FlowRelation, FlowSubjectKind, StateEventClass, StateEventReadCause,
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
    use brokk_bifrost_flow::type_flow::{AbsentMemberProof, ClassSetStatus};

    pub(super) const LANGUAGE: &[&str] = Language::CONFIG_LABELS;
    pub(super) const LANGUAGE_DIALECT: &[&str] = LanguageDialect::STABLE_LABELS;
    pub(super) const STRUCTURAL_KIND: &[&str] = NormalizedKind::LABELS;
    pub(super) const PYTHON_IMPORT_FORM: &[&str] = &["import", "from"];
    pub(super) const PYTHON_IMPORT_TARGET_STATUS: &[&str] = &[
        "resolved_local",
        "no_workspace_target",
        "ambiguous",
        "unavailable",
        "mixed",
    ];
    pub(super) const PYTHON_IMPORT_EXPORT_STATE: &[&str] = &[
        "not_wildcard",
        "absent",
        "listed",
        "unreadable",
        "unresolved",
        "ambiguous",
        "unavailable",
        "mixed",
    ];
    pub(super) const PYTHON_IMPORT_CYCLE_STATE: &[&str] = &["cyclic", "incomplete"];
    pub(super) const CODE_UNIT_KIND: &[&str] = CodeUnitType::DISPLAY_LOWERCASE_LABELS;

    /// `declaration.kind` is refined to a normalized declaration kind when the
    /// seed's own span matched the declaration exactly, and otherwise falls
    /// back to the code unit's coarse type. Keep this domain to the values
    /// those two producers can emit, not every normalized syntax kind.
    pub(super) const DECLARATION_KIND: &[&str] = &[
        "callable",
        "function",
        "method",
        "constructor",
        "lambda",
        "class",
        "import",
        "parameter",
        "module",
        "field",
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
    pub(super) const FLOW_STATUS: &[&str] = CodeQueryFlowStatus::LABELS;
    pub(super) const SEMANTIC_CAPABILITY: &[&str] = SemanticCapability::LABELS;
    pub(super) const SEMANTIC_BUDGET_LANE: &[&str] = SemanticBudgetLane::LABELS;

    pub(super) const USAGE_KIND: &[&str] = UsageHitKind::WIRE_LABELS;
    pub(super) const USAGE_PROOF: &[&str] = brokk_bifrost_rql::schema::USAGE_PROOF_LABELS;
    pub(super) const REFERENCE_KIND: &[&str] = brokk_bifrost_rql::schema::REFERENCE_KIND_LABELS;
    pub(super) const CALL_SYNTAX_KIND: &[&str] = render::CALL_SYNTAX_KIND_LABELS;
    pub(super) const CALL_RECEIVER_KIND: &[&str] = &["implicit", "this", "explicit", "unknown"];
    pub(super) const EXPRESSION_INPUT_KIND: &[&str] = render::EXPRESSION_INPUT_KIND_LABELS;
    pub(super) const JSX_ELEMENT_IDENTITY: &[&str] = &["intrinsic", "component", "unknown"];
    pub(super) const JSX_ATTRIBUTE_KIND: &[&str] = &["jsx_attribute", "jsx_spread_attribute"];
    pub(super) const JSX_VALUE_COVERAGE: &[&str] = &["complete", "incomplete"];

    pub(super) const RECEIVER_ANALYSIS_KIND: &[&str] = ReceiverQueryOperation::LABELS;
    pub(super) const RECEIVER_OUTCOME: &[&str] = render::RECEIVER_OUTCOME_LABELS;
    pub(super) const RECEIVER_COVERAGE: &[&str] = render::RECEIVER_COVERAGE_LABELS;
    pub(super) const RECEIVER_EVIDENCE_KIND: &[&str] = receiver::RECEIVER_EVIDENCE_KIND_LABELS;
    pub(super) const RECEIVER_EVIDENCE_PROOF: &[&str] = render::RECEIVER_EVIDENCE_PROOF_LABELS;
    pub(super) const FIELD_WRITE_PROOF: &[&str] = &["precise"];
    pub(super) const FIELD_WRITE_COMPLETENESS: &[&str] = &["complete"];
    pub(super) const FIELD_WRITE_COVERAGE: &[&str] = &["exhaustive"];
    pub(super) const RUNTIME_KEY_KIND: &[&str] = &["property", "index", "unknown"];
    pub(super) const RUNTIME_SOURCE_ORIGIN: &[&str] =
        &["pristine_runtime_input", "mutated", "indeterminate"];
    pub(super) const RUNTIME_READ_OUTCOME: &[&str] =
        &["endpoint", "conclusive_exclusion", "incomplete"];
    pub(super) const RUNTIME_READ_PROOF: &[&str] = ProofStatus::LABELS;
    pub(super) const RUNTIME_READ_COMPLETENESS: &[&str] = EvidenceCompleteness::LABELS;

    pub(super) const DISPATCH_OUTCOME: &[&str] = dispatch::DISPATCH_OUTCOME_LABELS;
    pub(super) const DISPATCH_ARM: &[&str] = dispatch::DISPATCH_ARM_LABELS;
    pub(super) const CANDIDATE_COVERAGE: &[&str] = CandidateCoverage::LABELS;
    pub(super) const EVIDENCE_PROOF: &[&str] = ProofStatus::LABELS;
    pub(super) const EVIDENCE_COMPLETENESS: &[&str] = EvidenceCompleteness::LABELS;
    pub(super) const MODEL_ORIGIN: &[&str] = &[
        "workspace_source",
        "exact_generated_output",
        "dependency_source",
        "dependency_binary",
        "prebuilt_api_index",
        "declarative_model",
    ];
    pub(super) const MODEL_PROOF: &[&str] = &["authored_anchor", "exact_artifact", "pack_fact"];
    pub(super) const MODEL_COMPLETENESS: &[&str] = &["partial", "complete"];
    pub(super) const TARGET_ORIGIN: &[&str] = &["source", "semantic_model"];
    pub(super) const SELECTOR_PROOF: &[&str] = &["derived", "authored_summary"];
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
    pub(super) const PYTHON_HIERARCHY_FACT_KIND: &[&str] =
        super::super::python_class_hierarchy::PYTHON_HIERARCHY_FACT_KIND_LABELS;
    pub(super) const PYTHON_HIERARCHY_OUTCOME: &[&str] =
        super::super::python_class_hierarchy::PYTHON_HIERARCHY_OUTCOME_LABELS;
    pub(super) const PYTHON_HIERARCHY_REASON: &[&str] =
        super::super::python_class_hierarchy::PYTHON_HIERARCHY_REASON_LABELS;
    pub(super) const PYTHON_BASE_RESOLUTION: &[&str] =
        super::super::python_class_hierarchy::PYTHON_BASE_RESOLUTION_LABELS;
    pub(super) const PYTHON_HIERARCHY_COVERAGE: &[&str] =
        super::super::python_class_hierarchy::PYTHON_HIERARCHY_COVERAGE_LABELS;
    pub(super) const PYTHON_SPECIAL_METHOD_STATUS: &[&str] = &[
        "compatible",
        "too_few",
        "too_many",
        "required_optional_second",
        "required_optional_third",
        "placeholder",
        "incomplete",
    ];

    pub(super) const CALL_KIND: &[&str] = CallKind::LABELS;
    pub(super) const CALL_SHAPE_COVERAGE: &[&str] = CallShapeCoverage::LABELS;
    pub(super) const ARGUMENT_LIST_KIND: &[&str] = ArgumentListKind::LABELS;
    pub(super) const CALL_BINDING_KIND: &[&str] = CallBindingKind::LABELS;
    pub(super) const CALL_BINDING_MAPPING: &[&str] = CallBindingMapping::LABELS;
    pub(super) const CALL_BINDING_REASON: &[&str] = CallBindingReason::LABELS;
    pub(super) const CALL_BINDING_COVERAGE: &[&str] = CallBindingCoverage::LABELS;

    pub(super) const EFFECT_CLASSIFICATION: &[&str] = EffectClassification::LABELS;
    pub(super) const EFFECT_TIMING: &[&str] = EffectTiming::LABELS;
    pub(super) const EXECUTION_TIMING: &[&str] = ExecutionTiming::LABELS;
    pub(super) const EFFECT_CERTAINTY: &[&str] = EffectCertainty::LABELS;
    pub(super) const EFFECT_PROOF: &[&str] = EffectProof::LABELS;
    pub(super) const EFFECT_DERIVATION: &[&str] = EffectDerivation::LABELS;
    pub(super) const EFFECT_REASON: &[&str] = EffectReason::LABELS;
    pub(super) const EFFECT_COVERAGE: &[&str] = EffectCoverage::LABELS;
    pub(super) const RESULT_CONTRACT_PREDICATE: &[&str] = &[
        "null",
        "non_null",
        "true",
        "false",
        "eof",
        "nonzero",
        "minus_one",
    ];
    pub(super) const PYTHON_RULE_RELATION: &[&str] = &[
        "documentation",
        "useless_class",
        "attribute_shadows_method",
        "modification_of_default_value",
        "procedure_return_profile",
        "assertion_context",
        "implicit_string_concatenation",
        "undefined_placeholder_variable",
        "call_result_use",
        "tuple_return_groups",
        "lambda_forwarding",
        "iterator_return_protocol",
        "builtin_identity",
        "raise_not_implemented",
        "illegal_raise",
        "unexpected_raise_in_special_method",
        "str_format_missing_argument",
        "str_format_missing_named_argument",
        "str_format_mixed_fields",
        "str_format_surplus_argument",
        "str_format_surplus_named_argument",
        "percent_format_wrong_arguments",
        "percent_format_unsupported_character",
        "percent_format_not_mapping",
        "url_construction",
        "unsafe_cyclic_import",
        "commented_out_code_block",
        "overly_complex_delete",
        "lexical_variable",
        "lexical_variable_definition",
        "lexical_variable_use",
        "lexical_variable_peer",
        "nested_loop_same_variable",
    ];
    pub(super) const RUST_POINTER_RELATION: &[&str] =
        &["access_after_lifetime_ended", "access_invalid_pointer"];
    pub(super) const RUST_POINTER_ORIGIN_KIND: &[&str] = &["stack_place", "allocation"];
    pub(super) const RUST_POINTER_INVALIDATION_CAUSE: &[&str] = &[
        "deallocated",
        "owner_dropped",
        "ownership_transferred",
        "possible_reallocation",
    ];
    pub(super) const RUST_POINTER_ACCESS_KIND: &[&str] = &["read", "write", "read_write"];
    pub(super) const RUST_POINTER_STRENGTH: &[&str] = &["must", "may"];
    pub(super) const RUST_POINTER_BOUNDS: &[&str] = &[
        "in_bounds",
        "out_of_bounds",
        "may_be_out_of_bounds",
        "incomplete",
    ];
    pub(super) const RUST_POINTER_PROOF: &[&str] = &["proven", "unproven"];
    pub(super) const RUST_POINTER_COMPLETENESS: &[&str] = &["complete", "partial"];
    pub(super) const PYTHON_RULE_OUTCOME: &[&str] = &[
        "mixed_returns",
        "uniform_returns",
        "mixed_tuple_arities",
        "uniform_tuple_arities",
        "forwarded",
        "changed",
        "consumed",
        "discarded",
        "may_be_uninitialized",
        "iterator",
        "non_iterator",
        "builtin",
        "shadowed",
        "legal",
        "illegal",
        "allowed",
        "unexpected",
        "issue",
        "no_issue",
        "full_control",
        "partial_control",
        "unknown",
        "open",
        "excluded",
        "variable",
        "definition",
        "use",
        "peer",
        "loop_pair",
        "code",
    ];
    pub(super) const PYTHON_RULE_PROOF: &[&str] = &["proven", "best_effort", "none"];
    pub(super) const PYTHON_RULE_COMPLETENESS: &[&str] = &["complete", "partial"];
    pub(super) const PYTHON_TRI_STATE: &[&str] = &["yes", "no", "unknown"];
    pub(super) const PYTHON_CALLABLE_EVALUATION_TIME: &[&str] =
        &["stable_at_creation", "invocation", "unknown"];
    pub(super) const PYTHON_VARIABLE_SCOPE_KIND: &[&str] =
        &["module", "function", "class", "comprehension"];
    pub(super) const PYTHON_VARIABLE_DEFINITION_KIND: &[&str] = &[
        "assignment",
        "parameter",
        "loop_target",
        "import",
        "augmented",
        "del",
        "with_target",
        "except_target",
        "function_declaration",
        "class_declaration",
        "pattern_target",
    ];
    pub(super) const PYTHON_VARIABLE_REACHABILITY: &[&str] = &["reachable", "unreachable", "open"];
    pub(super) const PYTHON_VARIABLE_ACCESS_KIND: &[&str] = &["read", "write"];
    pub(super) const PYTHON_RETURN_CONTRACT: &[&str] = &[
        "always_none",
        "explicit_none",
        "may_return_value",
        "unknown",
    ];
    pub(super) const PYTHON_RESULT_USE: &[&str] = &["consumed", "discarded", "unknown"];
    pub(super) const RESULT_USE_VALIDATION: &[&str] =
        &["unused", "satisfied", "violated", "unknown"];
    pub(super) const RESULT_OBLIGATION_KIND: &[&str] = &[
        "pure_transformation_value",
        "fallible_status",
        "must_use_value",
    ];
    pub(super) const RESULT_OBLIGATION_PROVENANCE: &[&str] = &["reviewed", "native"];
    pub(super) const RESULT_OBLIGATION_BASIS: &[&str] = &[
        "static_signature",
        "dispatch_agreement",
        "builtin_receiver_assumption",
        "libc_standard_declaration",
        "python_stdlib_function",
        "exact_literal_receiver",
    ];
    pub(super) const RESULT_OBLIGATION_USE: &[&str] = &[
        "discarded",
        "other_context",
        "consumed",
        "intentional_discard",
        "open",
        "unknown",
    ];
    pub(super) const RESULT_OBLIGATION_RESULT_USE_DETAIL: &[&str] = &[
        "go_blank_assignment",
        "rust_let_underscore",
        "rust_drop",
        "cpp_void_cast",
        "javascript_void",
        "csharp_discard_assignment",
        "missing_call",
        "ambiguous_call",
        "recovered_syntax",
        "deferred_context",
        "unsupported_syntax",
        "unclassified_syntax",
        "missing_result_port",
    ];
    pub(super) const RESULT_OBLIGATION_REASON: &[&str] = &[
        "unsupported_language",
        "result_use_unclassified",
        "go_blank_assignment",
        "rust_let_underscore",
        "rust_drop",
        "cpp_void_cast",
        "javascript_void",
        "csharp_discard_assignment",
        "missing_call",
        "ambiguous_call",
        "recovered_syntax",
        "deferred_context",
        "unsupported_syntax",
        "unclassified_syntax",
        "missing_result_port",
        "dispatch_unresolved",
        "dispatch_interrupted",
        "dispatch_truncated",
        "dispatch_open",
        "target_unresolved",
        "artifact_unselected",
        "model_unavailable",
        "model_conflict",
        "obligation_unavailable",
        "obligation_conflict",
        "native_signature_unknown",
        "native_target_unknown",
        "native_rust_analyzer",
        "native_target_language",
        "native_target_source",
        "native_target_declaration",
        "native_trait_signature_unknown",
        "native_trait_signature_source",
        "native_trait_signature_declaration",
        "native_return_type_depth",
        "native_return_type_source",
        "native_return_type_declaration",
        "native_return_type_unknown",
        "native_return_type_unresolved",
        "native_std_type_unmodeled",
        "native_excluded_stdlib_never_error",
    ];
    pub(super) const RESULT_SUBJECT_OUTCOME: &[&str] = CodeQueryResultSubjectOutcome::LABELS;
    pub(super) const RESULT_CONTRACT_USE_KIND: &[&str] = &[
        "dereference",
        "field",
        "index",
        "receiver_call",
        "call_argument",
    ];
    pub(super) const RESULT_CONTRACT_USE_TIMING: &[&str] = &["direct", "deferred", "captured"];
    pub(super) const OPERATION_APPLICABILITY: &[&str] = &["required", "not_required", "unknown"];
    pub(super) const RESULT_USE_GUARD: &[&str] =
        &["guarded", "unguarded", "not_applicable", "unknown"];
    pub(super) const FAILURE_USE_PROVENANCE: &[&str] = FailureUseProvenance::LABELS;
    pub(super) const FAILURE_USE_CONSUMER: &[&str] = FailureUseConsumer::LABELS;
    pub(super) const NILNESS_FACT: &[&str] = &[
        "unreachable",
        "nil",
        "non_nil",
        "maybe_nil",
        "true",
        "false",
        "either_boolean",
        "exact_integer",
        "non_exact_integer",
        "unknown",
    ];
    pub(super) const NILNESS_ORIGIN: &[&str] = &["result_contract", "scalar_refinement"];
    pub(super) const NILNESS_PROOF: &[&str] = &["exact", "unknown"];
    pub(super) const NILNESS_REASON: &[&str] = &["scalar_fact_unknown"];
    pub(super) const SWITCH_KIND: &[&str] = &["expression", "expressionless", "type"];
    pub(super) const SWITCH_SELECTOR_DOMAIN: &[&str] = &["boolean", "open"];
    pub(super) const SWITCH_VERDICT: &[&str] = &["exhaustive", "non_exhaustive", "unknown"];
    pub(super) const CLASS_SET_STATUS: &[&str] = ClassSetStatus::LABELS;
    pub(super) const ABSENT_MEMBER_PROOF: &[&str] = AbsentMemberProof::LABELS;
    pub(super) const ABSENT_MEMBER_WITNESS_STATUS: &[&str] =
        &["available", "truncated", "unavailable"];
    pub(super) const SWITCH_PROOF: &[&str] = &["exact", "unknown"];
    pub(super) const SWITCH_REASON: &[&str] = &[
        "type_switch",
        "boolean_case_missing",
        "case_domain_open",
        "selector_domain_open",
        "expressionless_without_default",
    ];
    pub(super) const ASSIGNMENT_RELATION_KIND: &[&str] = &[
        "self_assignment",
        "self_initializer",
        "failed_swap",
        "overwritten_unread",
    ];
    pub(super) const ASSIGNMENT_STORAGE_KIND: &[&str] = &[
        "ordinary_local",
        "nonlocal",
        "volatile",
        "atomic",
        "compound",
        "indirect",
        "member",
        "element",
        "unknown",
    ];
    pub(super) const ASSIGNMENT_VERDICT: &[&str] = &[
        "self_assignment",
        "self_initializer",
        "failed_swap",
        "overwritten_unread",
        "different",
        "excluded",
        "unknown",
    ];
    pub(super) const ASSIGNMENT_PROOF: &[&str] = &["exact", "unknown"];
    pub(super) const DETACHED_TRANSFER_ROLE: &[&str] = &["receiver", "argument", "capture"];
    pub(super) const DETACHED_TRANSFER_TIMING: &[&str] = &["different_task"];
    pub(super) const DETACHED_TRANSFER_PROOF: &[&str] = &["exact", "unknown"];
    pub(super) const DETACHED_TRANSFER_COVERAGE: &[&str] = &["exhaustive", "open"];
    pub(super) const OBJECT_CARDINALITY: &[&str] = &["singleton", "summary", "unknown"];
    pub(super) const DETACHED_TRANSFER_REASON: &[&str] = &[
        "heap_provider_failed",
        "heap_result_unavailable",
        "object_set_open",
        "object_identity_absent",
        "object_identity_ambiguous",
        "object_identity_unproven",
    ];

    pub(super) const SIGNATURE_COVERAGE: &[&str] = SignatureCoverage::LABELS;
    pub(super) const LITERAL_OCCURRENCE_KIND: &[&str] = &[
        "string",
        "integer",
        "boolean",
        "null",
        "numeric",
        "character",
        "collection",
        "unsupported",
    ];
    pub(super) const LITERAL_OCCURRENCE_SCOPE_KIND: &[&str] = &["file", "module", "callable"];
    pub(super) const LITERAL_OCCURRENCE_COVERAGE: &[&str] = &["exact", "incomplete"];
    pub(super) const CALLABLE_METRICS_COVERAGE: &[&str] = &["exact", "incomplete", "unrecorded"];
    pub(super) const PYTHON_METHOD_KIND: &[&str] = &["instance", "static", "class", "unknown"];
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
    pub(super) const EXPORT_DEFINITION_STATUS: &[&str] = &["defined", "undefined", "unknown"];
    pub(super) const EXPORT_BINDING_KIND: &[&str] = SourceExportBindingKind::LABELS;
    pub(super) const DECLARATION_ORIGIN: &[&str] = DeclarationOrigin::LABELS;
    pub(super) const SEGMENT_RESOLUTION_STATUS: &[&str] = SegmentResolutionStatus::LABELS;

    pub(super) const SITE_CLASS: &[&str] = SiteClass::LABELS;
    pub(super) const OWNER_RELATION: &[&str] = OwnerRelation::LABELS;
    pub(super) const EDGE_PROVENANCE: &[&str] =
        brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance::LABELS;

    pub(super) const STATE_EVENT_CLASS: &[&str] = StateEventClass::LABELS;
    pub(super) const STATE_EVENT_READ_CAUSE: &[&str] = StateEventReadCause::LABELS;
    pub(super) const BINDING_INITIALIZER_CALL_ROLE: &[&str] = &["result", "receiver"];
    pub(super) const FLOW_SUBJECT: &[&str] = FlowSubjectKind::LABELS;
    pub(super) const FLOW_RELATION: &[&str] = FlowRelation::LABELS;
    pub(super) const FLOW_CERTAINTY: &[&str] = FlowCertainty::LABELS;
    pub(super) const FLOW_STATE_COMPLETENESS: &[&str] =
        crate::structural::search::flow_state::FLOW_STATE_COMPLETENESS_LABELS;

    /// The four guard predicates the semantic IR publishes (#2443). The
    /// producer is the IR enum itself, so a row column cannot drift from the
    /// value a lowerer writes.
    pub(super) const GUARD_PREDICATE: &[&str] = crate::analyzer::semantic::GuardPredicate::LABELS;

    pub(super) const BRANCH_RELATION: &[&str] = &[
        "identical_bodies",
        "repeated_condition",
        "contradictory_condition",
        "subsumed_condition",
        "redundant_boolean_return",
        "empty_arm",
    ];
    pub(super) const BRANCH_VERDICT: &[&str] = &["proven", "distinct", "open"];
    pub(super) const LOOP_KIND: &[&str] = &["while", "for", "do"];
    pub(super) const LOOP_VERDICT: &[&str] = &["proven", "excluded", "open"];
    pub(super) const STATEMENT_KIND: &[&str] = &[
        "block",
        "expression",
        "local_declaration",
        "constructor_invocation",
        "return",
        "throw",
        "yield",
        "break",
        "continue",
        "if",
        "while",
        "do",
        "for",
        "enhanced_for",
        "for_in",
        "switch",
        "try",
        "try_with_resources",
        "synchronized",
        "labeled",
        "assert",
        "empty",
        "with",
        "delete",
        "import",
        "debugger",
        "goto",
        "using",
        "lock",
        "fixed",
        "checked",
        "unsafe",
        "fallthrough",
        "defer",
        "go",
    ];
    pub(super) const STATEMENT_VERDICT: &[&str] = &["reachable", "unreachable", "open"];
    pub(super) const BRANCH_REASON: &[&str] = &[
        "syntax_recovery",
        "missing_branch_field",
        "lexical_binding_unavailable",
        "non_local_reference",
        "distinct_binding",
        "effectful_body",
        "effectful_condition",
        "unsupported_condition",
        "comparison_budget",
        "member_resolution_unavailable",
        "ambiguous_member",
        "deferred_body",
        "snapshot_mismatch",
        "source_limit",
        "cancelled",
        "syntax_unavailable",
        "unsupported_predicate",
        "unproven_guard",
        "partial_guard",
        "missing_arm",
        "unreachable_decision",
        "unknown_scalar",
        "partial_procedure",
        "partial_producer",
        "inexact_source",
        "stale_source",
        "work_limit",
        "no_enclosing_procedure",
        "ambiguous_procedure",
        "ambiguous_guard",
        "incomplete_condition",
        "unqualified_continuation",
    ];
    pub(super) const BRANCH_ORIENTATION: &[&str] = &[
        "condition",
        "negated_condition",
        "always_false",
        "always_true",
    ];
    pub(super) const CONTROL_RELATION: &[&str] = ControlRelationKind::LABELS;
    pub(super) const CONTROL_EXIT_PARTITION: &[&str] = ControlExitPartition::LABELS;
    pub(super) const CONTROL_RELATION_COMPLETENESS: &[&str] =
        crate::structural::search::control_relations::CONTROL_RELATION_COMPLETENESS_LABELS;

    /// The configuration-fact vocabularies the row surface publishes
    /// (#3277). Each folds the exact labels its producing enum writes, so a
    /// row column cannot drift from the value ingestion produces.
    pub(super) const CONFIGURATION_FORMAT: &[&str] = &["yaml", "toml", "json", "xml", "properties"];
    pub(super) const CONFIGURATION_NODE_KIND: &[&str] = &[
        "document", "object", "section", "sequence", "member", "scalar",
    ];
    pub(super) const CONFIGURATION_ROLE: &[&str] = &[
        "object-member",
        "table-entry",
        "property",
        "xml-attribute",
        "xml-element",
    ];
    pub(super) const CONFIGURATION_SCALAR_KIND: &[&str] = &[
        "string", "boolean", "integer", "decimal", "null", "url", "duration", "opaque",
    ];
    pub(super) const CONFIGURATION_PROVENANCE: &[&str] = &["authored"];
    pub(super) const CONFIGURATION_COMPLETENESS: &[&str] = &["complete", "incomplete"];
    pub(super) const CROSS_DOMAIN_OPERATOR: &[&str] =
        super::super::super::cross_domain::CROSS_DOMAIN_OPERATOR_LABELS;
    pub(super) const CROSS_DOMAIN_ROW_DOMAIN: &[&str] =
        super::super::super::cross_domain::CROSS_DOMAIN_ROW_DOMAIN_LABELS;
    pub(super) const CROSS_DOMAIN_RELATION: &[&str] =
        super::super::super::cross_domain::CROSS_DOMAIN_RELATION_LABELS;
    pub(super) const CROSS_DOMAIN_BINDING: &[&str] =
        super::super::super::cross_domain::CrossDomainBinding::LABELS;
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
    StringList(&'a [String]),
    IntegerList(&'a [u64]),
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
            Self::StringList(_) => CodeQueryRowScalarType::StringList,
            Self::IntegerList(_) => CodeQueryRowScalarType::IntegerList,
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
    unknown_reason: Option<CodeQueryRowFieldUnknownReason>,
}

/// Missing evidence for a registered field is not an absent optional value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryRowFieldUnknownReason {
    CallConversion(crate::analyzer::usages::call_conversion::ConversionUnknown),
}

impl CodeQueryRowFieldError {
    /// The refusal any reader of a row's field surface raises for a field the
    /// row's domain does not declare.
    ///
    /// Named here rather than built at each reader, because a projection of a
    /// row must refuse exactly what the row itself refuses.
    pub fn unregistered(domain: DetailedCodeQueryDomain, field: &str) -> Self {
        Self {
            domain,
            field: field.to_string(),
            unknown_reason: None,
        }
    }

    pub fn unknown(
        domain: DetailedCodeQueryDomain,
        field: &str,
        reason: CodeQueryRowFieldUnknownReason,
    ) -> Self {
        Self {
            domain,
            field: field.to_owned(),
            unknown_reason: Some(reason),
        }
    }

    pub const fn unknown_reason(&self) -> Option<CodeQueryRowFieldUnknownReason> {
        self.unknown_reason
    }

    pub const fn domain(&self) -> DetailedCodeQueryDomain {
        self.domain
    }

    pub fn field(&self) -> &str {
        &self.field
    }
}

impl std::fmt::Display for CodeQueryRowFieldError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(reason) = self.unknown_reason {
            return write!(
                formatter,
                "field `{}.{}` has unknown evidence: {reason:?}",
                self.domain.label(),
                self.field,
            );
        }
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

macro_rules! detailed_query_kind_pattern {
    ($kind:ident, RuntimeKeyedReadValue) => {
        $kind::KeyedReadValue
    };
    ($kind:ident, $variant:ident) => {
        $kind::$variant
    };
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
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $domain {
            $($variant,)+
        }

        /// Every domain, in declaration order.
        pub const $all: &[$domain] = &[$($domain::$variant,)+];

        impl $domain {
            pub const fn from_query_value_kind(kind: $kind) -> Self {
                match kind {
                    $(detailed_query_kind_pattern!($kind, $variant) => Self::$variant,)+
                }
            }

            /// The query planner's typed endpoint corresponding to this public
            /// row domain.
            pub const fn query_value_kind(self) -> $kind {
                match self {
                    $(Self::$variant => detailed_query_kind_pattern!($kind, $variant),)+
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
                    CodeQueryRowField::optional("parent_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("left_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("right_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("object_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("object_name", Scalar::String),
                    CodeQueryRowField::optional("callee_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("receiver_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("enclosing_callable_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("name", Scalar::String),
                    CodeQueryRowField::optional("string_value", Scalar::String),
                    CodeQueryRowField::optional("construct", Scalar::String),
                    CodeQueryRowField::optional_enum("occurrence_role", value_domain::OCCURRENCE_ROLE),
                    CodeQueryRowField::optional("element_index", Scalar::Integer),
                    CodeQueryRowField::optional("element_count", Scalar::Integer),
                    CodeQueryRowField::optional("is_last_element", Scalar::Boolean),
                    CodeQueryRowField::optional("parameter_index", Scalar::Integer),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("kind", value_domain::STRUCTURAL_KIND),
                    CodeQueryRowField::optional("python_import_complete", Scalar::Boolean),
                    CodeQueryRowField::optional_enum("python_import_form", value_domain::PYTHON_IMPORT_FORM),
                    CodeQueryRowField::optional("python_import_module", Scalar::String),
                    CodeQueryRowField::optional("python_import_name", Scalar::String),
                    CodeQueryRowField::optional("python_import_alias", Scalar::String),
                    CodeQueryRowField::optional("python_import_modules", Scalar::StringList),
                    CodeQueryRowField::optional("python_import_names", Scalar::StringList),
                    CodeQueryRowField::optional("python_import_aliases", Scalar::StringList),
                    CodeQueryRowField::optional("python_import_wildcard", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_module_scope", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_source_order", Scalar::Integer),
                    CodeQueryRowField::optional("python_import_in_import_error_handler", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_in_main_guard", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_target_paths", Scalar::StringList),
                    CodeQueryRowField::optional_enum("python_import_target_status", value_domain::PYTHON_IMPORT_TARGET_STATUS),
                    CodeQueryRowField::optional("python_import_repeated", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_duplicate", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_mixed_form", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_own_module", Scalar::Boolean),
                    CodeQueryRowField::optional("python_import_polluting", Scalar::Boolean),
                    CodeQueryRowField::optional_enum("python_import_export_state", value_domain::PYTHON_IMPORT_EXPORT_STATE),
                    CodeQueryRowField::optional_enum("python_import_cycle_state", value_domain::PYTHON_IMPORT_CYCLE_STATE),
        ],
    },
    Declaration => "declaration" {
        display_range: |value| value.node_range,
        identities: Primary,
        fields: [
                    CodeQueryRowField::optional("id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("site_id", Scalar::StableId),
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
                    CodeQueryRowField::required_enum("dialect", value_domain::LANGUAGE_DIALECT),
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
                    CodeQueryRowField::required_enum("status", value_domain::FLOW_STATUS),
                    CodeQueryRowField::optional("reason", Scalar::String),
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
    ClassSetRow => "class_set_row" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("member", Scalar::String),
                    CodeQueryRowField::optional("class", Scalar::String),
                    CodeQueryRowField::optional("guard_only", Scalar::Boolean),
                    CodeQueryRowField::required_open_enum(
                        "origin",
                        "an unknown origin embeds the engine's unknown:<reason> label, and the type-flow reason vocabulary grows with the language adapters"
                    ),
                    CodeQueryRowField::required_enum("status", value_domain::CLASS_SET_STATUS),
        ],
    },
    AbsentMemberFinding => "absent_member_finding" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("member", Scalar::String),
                    CodeQueryRowField::required("class", Scalar::String),
                    CodeQueryRowField::required("caller", Scalar::String),
                    CodeQueryRowField::required("witness_steps", Scalar::Integer),
                    CodeQueryRowField::required_enum("proof", value_domain::ABSENT_MEMBER_PROOF),
                    CodeQueryRowField::optional("condition", Scalar::String),
                    CodeQueryRowField::required("also_fails_at", Scalar::StringList),
        ],
    },
    AbsentMemberWitness => "absent_member_witness" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("finding_id", Scalar::StableId),
                    CodeQueryRowField::required("witness_index", Scalar::Integer),
                    CodeQueryRowField::required("retained_bytes", Scalar::Integer),
                    CodeQueryRowField::required("truncated", Scalar::Boolean),
                    CodeQueryRowField::required("omitted_steps_lower_bound", Scalar::Integer),
                    CodeQueryRowField::required("alternatives_truncated", Scalar::Boolean),
                    CodeQueryRowField::required("retention_truncated", Scalar::Boolean),
                    CodeQueryRowField::required_enum(
                        "witness_status",
                        value_domain::ABSENT_MEMBER_WITNESS_STATUS
                    ),
                    CodeQueryRowField::optional("unavailable_reason", Scalar::String),
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
    DependencyEvidence => "dependency_evidence" {
        display_range: |value| value.range,
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("path", Scalar::String),
            CodeQueryRowField::required("ecosystem", Scalar::String),
            CodeQueryRowField::required("package", Scalar::String),
            CodeQueryRowField::required("evidence_kind", Scalar::String),
            CodeQueryRowField::optional("version_requirement", Scalar::String),
            CodeQueryRowField::optional("exact_version", Scalar::String),
            CodeQueryRowField::optional("source", Scalar::String),
            CodeQueryRowField::optional("locator", Scalar::String),
            CodeQueryRowField::optional("declared_by", Scalar::StableId),
            CodeQueryRowField::required("scope", Scalar::String),
            CodeQueryRowField::required("source_digest", Scalar::String),
            CodeQueryRowField::required("start_byte", Scalar::Integer),
            CodeQueryRowField::required("end_byte", Scalar::Integer),
            CodeQueryRowField::required("complete", Scalar::Boolean),
        ],
    },
    ConfigurationFact => "configuration_fact" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("fact_id", Scalar::StableId),
                    CodeQueryRowField::optional("parent_id", Scalar::StableId),
                    CodeQueryRowField::optional("value_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("format", value_domain::CONFIGURATION_FORMAT),
                    CodeQueryRowField::required_enum("node_kind", value_domain::CONFIGURATION_NODE_KIND),
                    CodeQueryRowField::optional_enum("role", value_domain::CONFIGURATION_ROLE),
                    CodeQueryRowField::optional_enum("scalar_kind", value_domain::CONFIGURATION_SCALAR_KIND),
                    CodeQueryRowField::optional("value", Scalar::String),
                    CodeQueryRowField::required_enum("provenance", value_domain::CONFIGURATION_PROVENANCE),
                    CodeQueryRowField::required_enum("completeness", value_domain::CONFIGURATION_COMPLETENESS),
                    CodeQueryRowField::optional("key", Scalar::String),
                    CodeQueryRowField::optional("occurrence", Scalar::Integer),
                    CodeQueryRowField::optional("index", Scalar::Integer),
                    CodeQueryRowField::required("route", Scalar::String),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
        ],
    },
    CrossDomain => "cross_domain" {
        display_range: |value| value.range,
        identities: None,
        // Issue #3284. `domain` is the required discriminator; the code and
        // configuration columns are present exactly when the row carries
        // that side. `configuration_id` equals the configuration fact row's
        // `id`, so a plan can join the two by stable key.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required_enum("operator", value_domain::CROSS_DOMAIN_OPERATOR),
                    CodeQueryRowField::required_enum("domain", value_domain::CROSS_DOMAIN_ROW_DOMAIN),
                    CodeQueryRowField::optional_enum("relation", value_domain::CROSS_DOMAIN_RELATION),
                    CodeQueryRowField::optional_enum("binding", value_domain::CROSS_DOMAIN_BINDING),
                    CodeQueryRowField::optional("key", Scalar::String),
                    CodeQueryRowField::optional("code_id", Scalar::StableId),
                    CodeQueryRowField::optional("code_path", Scalar::String),
                    CodeQueryRowField::optional("configuration_id", Scalar::StableId),
                    CodeQueryRowField::optional("configuration_path", Scalar::String),
                    CodeQueryRowField::optional("mitigated", Scalar::Boolean),
                    CodeQueryRowField::optional("dependency_id", Scalar::StableId),
                    CodeQueryRowField::optional("owner", Scalar::StableId),
                    CodeQueryRowField::optional("mapping_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
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
                    CodeQueryRowField::optional("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("program_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("caller_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("callee_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("call_kind", value_domain::CALL_SYNTAX_KIND),
                    CodeQueryRowField::required_enum("proof", value_domain::USAGE_PROOF),
                    CodeQueryRowField::required_enum(
                        "receiver_kind",
                        value_domain::CALL_RECEIVER_KIND
                    ),
                    CodeQueryRowField::optional("argument_identity", Scalar::StableId),
                    CodeQueryRowField::optional("caller_parameter_identity", Scalar::StableId),
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
    MemberTargetAnalysis => "member_target_analysis" {
        display_range: |value| Some(value.receiver_range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("outcome", value_domain::RECEIVER_OUTCOME),
                    CodeQueryRowField::optional("capture", Scalar::String),
                    CodeQueryRowField::required_enum("coverage", value_domain::RECEIVER_COVERAGE),
                    CodeQueryRowField::required("target_count", Scalar::Integer),
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
    FieldWriteValue => "field_write_value" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("write_site_id", Scalar::StableId),
                    CodeQueryRowField::required("assignment_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("left_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("receiver_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("member_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("rhs_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("receiver_identity_id", Scalar::StableId),
                    CodeQueryRowField::required("member_target_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("proof", value_domain::FIELD_WRITE_PROOF),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::FIELD_WRITE_COMPLETENESS
                    ),
                    CodeQueryRowField::required_enum(
                        "coverage",
                        value_domain::FIELD_WRITE_COVERAGE
                    ),
        ],
    },
    RuntimeKeyedReadValue => "keyed_read_value" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("runtime", Scalar::String),
                    CodeQueryRowField::required("global", Scalar::String),
                    CodeQueryRowField::required("container", Scalar::String),
                    CodeQueryRowField::required_enum("key_kind", value_domain::RUNTIME_KEY_KIND),
                    CodeQueryRowField::optional("property", Scalar::String),
                    CodeQueryRowField::optional("index", Scalar::Integer),
                    CodeQueryRowField::required_enum("source_origin", value_domain::RUNTIME_SOURCE_ORIGIN),
                    CodeQueryRowField::required_enum("outcome", value_domain::RUNTIME_READ_OUTCOME),
                    CodeQueryRowField::required_enum("proof", value_domain::RUNTIME_READ_PROOF),
                    CodeQueryRowField::required_enum("completeness", value_domain::RUNTIME_READ_COMPLETENESS),
                    CodeQueryRowField::optional("active_model_set_hash", Scalar::String),
                    CodeQueryRowField::optional("refinement_identity", Scalar::String),
                    CodeQueryRowField::optional("exposure_id", Scalar::StableId),
                    CodeQueryRowField::optional("behavior_id", Scalar::StableId),
                    CodeQueryRowField::required("conclusive_exclusion", Scalar::Boolean),
                    CodeQueryRowField::required("terminal", Scalar::Boolean),
        ],
    },
    CallShape => "call_shape" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("callee_name", Scalar::String),
                    CodeQueryRowField::optional("resolved_external_callee", Scalar::String),
                    CodeQueryRowField::required_enum("callee_provenance", &["caller_supplied", "local_closure", "declared", "unknown", "unsupported"]),
                    CodeQueryRowField::optional("callee_supplier", Scalar::String),
                    CodeQueryRowField::required_enum("callee_type_shape", brokk_bifrost_core::analyzer::structural::callable::CalleeTypeShape::LABELS),
                    CodeQueryRowField::required("callee_bounds", Scalar::StringList),
                    CodeQueryRowField::required_enum("call_kind", value_domain::CALL_KIND),
                    CodeQueryRowField::required_enum("coverage", value_domain::CALL_SHAPE_COVERAGE),
                    CodeQueryRowField::required("group_count", Scalar::Integer),
                    CodeQueryRowField::required("argument_count", Scalar::Integer),
        ],
    },
    CallResult => "call_result" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("call_id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required("point_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required("value_id", Scalar::Integer),
                    CodeQueryRowField::required_enum("proof", value_domain::EVIDENCE_PROOF),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::EVIDENCE_COMPLETENESS
                    ),
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
                    CodeQueryRowField::optional("literal_value", Scalar::String),
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
                    CodeQueryRowField::optional("program_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("group_id", Scalar::StableId),
                    CodeQueryRowField::optional("argument_id", Scalar::StableId),
                    CodeQueryRowField::optional("binding_id", Scalar::StableId),
                    CodeQueryRowField::optional("literal_value", Scalar::String),
                    CodeQueryRowField::optional("path_identity", Scalar::String),
                    CodeQueryRowField::optional("target_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("declared_target_id", Scalar::StableId),
                    CodeQueryRowField::optional("semantic_target_id", Scalar::StableId),
                    CodeQueryRowField::optional_enum("target_origin", value_domain::TARGET_ORIGIN),
                    CodeQueryRowField::required_enum("dispatch_outcome", value_domain::DISPATCH_OUTCOME),
                    CodeQueryRowField::required_enum("dispatch_coverage", value_domain::CANDIDATE_COVERAGE),
                    CodeQueryRowField::optional_enum("dispatch_proof", value_domain::EVIDENCE_PROOF),
                    CodeQueryRowField::optional_enum(
                        "dispatch_completeness",
                        value_domain::EVIDENCE_COMPLETENESS,
                    ),
                    CodeQueryRowField::required("dispatch_target_count", Scalar::Integer),
                    CodeQueryRowField::required("dispatch_targets_truncated", Scalar::Boolean),
                    CodeQueryRowField::required("selector_exact", Scalar::Boolean),
                    CodeQueryRowField::optional_enum("selector_proof", value_domain::SELECTOR_PROOF),
                    CodeQueryRowField::optional("selector_summary_id", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_model_id", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_pack_id", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_active_set_hash", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_pack_digest", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_pack_version", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_record_id", Scalar::String),
                    CodeQueryRowField::optional_enum("selector_summary_origin", value_domain::MODEL_ORIGIN),
                    CodeQueryRowField::optional_enum("selector_summary_model_proof", value_domain::MODEL_PROOF),
                    CodeQueryRowField::optional_enum("selector_summary_completeness", value_domain::MODEL_COMPLETENESS),
                    CodeQueryRowField::optional("selector_summary_producer", Scalar::String),
                    CodeQueryRowField::optional("selector_summary_producer_version", Scalar::String),
                    CodeQueryRowField::optional("signature_id", Scalar::StableId),
                    CodeQueryRowField::optional("model_callable_id", Scalar::StableId),
                    CodeQueryRowField::optional("formal_layout_id", Scalar::StableId),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("receiver_type_id", Scalar::StableId),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("model_active_set_hash", Scalar::String),
                    CodeQueryRowField::optional("model_pack_digest", Scalar::String),
                    CodeQueryRowField::optional("model_pack_version", Scalar::String),
                    CodeQueryRowField::optional("model_record_id", Scalar::String),
                    CodeQueryRowField::optional("model_activation_status", Scalar::String),
                    CodeQueryRowField::optional("model_activation_reason", Scalar::String),
                    CodeQueryRowField::optional("model_activation_source_kind", Scalar::String),
                    CodeQueryRowField::optional("model_activation_source_id", Scalar::String),
                    CodeQueryRowField::optional_enum("model_origin", value_domain::MODEL_ORIGIN),
                    CodeQueryRowField::optional_enum("model_proof", value_domain::MODEL_PROOF),
                    CodeQueryRowField::optional_enum(
                        "model_completeness",
                        value_domain::MODEL_COMPLETENESS,
                    ),
                    CodeQueryRowField::optional("model_ambiguous", Scalar::Boolean),
                    CodeQueryRowField::optional("model_producer", Scalar::String),
                    CodeQueryRowField::optional("model_producer_version", Scalar::String),
                    CodeQueryRowField::optional("actual_index", Scalar::Integer),
                    CodeQueryRowField::optional("actual_name", Scalar::String),
                    CodeQueryRowField::optional("formal_index", Scalar::Integer),
                    CodeQueryRowField::optional("formal_name", Scalar::String),
                    CodeQueryRowField::optional_enum("binding_kind", value_domain::CALL_BINDING_KIND),
                    CodeQueryRowField::optional_enum(
                        "conversion",
                        crate::analyzer::usages::call_conversion::ConversionKind::LABELS,
                    ),
                    CodeQueryRowField::required_enum(
                        "conversion_status", &["proven", "unknown", "not_applicable"],
                    ),
                    CodeQueryRowField::optional_enum(
                        "conversion_reason",
                        crate::analyzer::usages::call_conversion::ConversionUnknown::LABELS,
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
                    CodeQueryRowField::optional_enum(
                        "execution_timing",
                        value_domain::EXECUTION_TIMING
                    ),
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
    CallResultContract => "call_result_contract" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_id", Scalar::StableId),
                    CodeQueryRowField::optional("callee_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::optional("callee_symbol", Scalar::String),
                    CodeQueryRowField::optional("result_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("condition_result_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "predicate",
                        value_domain::RESULT_CONTRACT_PREDICATE
                    ),
                    CodeQueryRowField::optional_enum(
                        "result_success_predicate",
                        value_domain::RESULT_CONTRACT_PREDICATE
                    ),
                    CodeQueryRowField::optional_enum("proof", value_domain::EFFECT_PROOF),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::optional_enum("reason", value_domain::EFFECT_REASON),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("summary_id", Scalar::String),
                    CodeQueryRowField::required("arm_count", Scalar::Integer),
                    CodeQueryRowField::required("modeled_arm_count", Scalar::Integer),
                    CodeQueryRowField::required("terminal", Scalar::Boolean),
                    CodeQueryRowField::optional("result_use_count", Scalar::Integer),
                    CodeQueryRowField::optional(
                        "unguarded_result_use_count",
                        Scalar::Integer
                    ),
                    CodeQueryRowField::optional_enum(
                        "use_validation",
                        value_domain::RESULT_USE_VALIDATION
                    ),
                    CodeQueryRowField::optional_enum(
                        "use_validation_coverage",
                        value_domain::EFFECT_COVERAGE
                    ),
                    CodeQueryRowField::required("success_guard_count", Scalar::Integer),
                    CodeQueryRowField::required("fresh_allocation", Scalar::Boolean),
                    CodeQueryRowField::required("member_contract_count", Scalar::Integer),
        ],
    },
    CallResultObligation => "call_result_obligation" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("site_id", Scalar::StableId),
            CodeQueryRowField::required("site_ast_id", Scalar::StableId),
            CodeQueryRowField::optional("result_ordinal", Scalar::Integer),
            CodeQueryRowField::optional_enum("obligation_kind", value_domain::RESULT_OBLIGATION_KIND),
            CodeQueryRowField::optional_enum("failure_predicate", value_domain::RESULT_CONTRACT_PREDICATE),
            CodeQueryRowField::optional_enum("provenance", value_domain::RESULT_OBLIGATION_PROVENANCE),
            CodeQueryRowField::optional_enum("obligation_basis", value_domain::RESULT_OBLIGATION_BASIS),
            CodeQueryRowField::required_enum("result_use", value_domain::RESULT_OBLIGATION_USE),
            CodeQueryRowField::optional_enum(
                "result_use_detail",
                value_domain::RESULT_OBLIGATION_RESULT_USE_DETAIL,
            ),
            CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
            CodeQueryRowField::optional_enum("reason", value_domain::RESULT_OBLIGATION_REASON),
            CodeQueryRowField::optional("pack_id", Scalar::String),
            CodeQueryRowField::optional("model_id", Scalar::String),
            CodeQueryRowField::optional("summary_id", Scalar::String),
            CodeQueryRowField::required("arm_count", Scalar::Integer),
            CodeQueryRowField::required("modeled_arm_count", Scalar::Integer),
            CodeQueryRowField::required("terminal", Scalar::Boolean),
        ],
    },
    ResultSubjectUse => "result_subject_use" {
        display_range: |value| value.receiver_range,
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::optional("origin_id", Scalar::StableId),
            CodeQueryRowField::optional("subject_id", Scalar::StableId),
            CodeQueryRowField::optional("artifact_id", Scalar::StableId),
            CodeQueryRowField::optional("procedure_id", Scalar::StableId),
            CodeQueryRowField::optional("receiver_call_id", Scalar::StableId),
            CodeQueryRowField::optional("receiver_site_id", Scalar::StableId),
            CodeQueryRowField::optional("receiver_site_ast_id", Scalar::StableId),
            CodeQueryRowField::optional("receiver_point_id", Scalar::StableId),
            CodeQueryRowField::required("path", Scalar::String),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("proof", value_domain::EVIDENCE_PROOF),
            CodeQueryRowField::required_enum("completeness", value_domain::EVIDENCE_COMPLETENESS),
            CodeQueryRowField::required_enum("outcome", value_domain::RESULT_SUBJECT_OUTCOME),
            CodeQueryRowField::optional_open_enum("reason", "normal-result subject outcome reasons"),
        ],
    },
    ResultContractUse => "result_contract_use" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("acquisition_id", Scalar::StableId),
                    CodeQueryRowField::required("acquisition_site_id", Scalar::StableId),
                    CodeQueryRowField::required("acquisition_site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("operation_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("operation_site_id", Scalar::StableId),
                    CodeQueryRowField::optional("operation_site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("result_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("condition_result_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "acquisition_predicate",
                        value_domain::RESULT_CONTRACT_PREDICATE
                    ),
                    CodeQueryRowField::optional_enum(
                        "result_success_predicate",
                        value_domain::RESULT_CONTRACT_PREDICATE
                    ),
                    CodeQueryRowField::optional_enum(
                        "required_predicate",
                        value_domain::RESULT_CONTRACT_PREDICATE
                    ),
                    CodeQueryRowField::required_enum(
                        "use_kind",
                        value_domain::RESULT_CONTRACT_USE_KIND
                    ),
                    CodeQueryRowField::required_enum(
                        "timing",
                        value_domain::RESULT_CONTRACT_USE_TIMING
                    ),
                    CodeQueryRowField::required_enum(
                        "applicability",
                        value_domain::OPERATION_APPLICABILITY
                    ),
                    CodeQueryRowField::required_enum(
                        "guard",
                        value_domain::RESULT_USE_GUARD
                    ),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::optional("member", Scalar::String),
                    CodeQueryRowField::optional("parameter_count", Scalar::Integer),
                    CodeQueryRowField::optional("parameter_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("summary_id", Scalar::String),
        ],
    },
    ResultContractFailureUse => "result_contract_failure_use" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("acquisition_id", Scalar::StableId),
                    CodeQueryRowField::required("acquisition_site_id", Scalar::StableId),
                    CodeQueryRowField::required("acquisition_site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required("condition_result_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("condition_value_id", Scalar::Integer),
                    CodeQueryRowField::optional("failure_edge_id", Scalar::StableId),
                    CodeQueryRowField::required("consumer_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("consumer_call_id", Scalar::StableId),
                    CodeQueryRowField::optional("consumer_site_id", Scalar::StableId),
                    CodeQueryRowField::optional("consumer_site_ast_id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("operand_value_id", Scalar::Integer),
                    CodeQueryRowField::optional("binding_value_id", Scalar::Integer),
                    CodeQueryRowField::optional("establishment_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("establishment_value_id", Scalar::Integer),
                    CodeQueryRowField::required_enum(
                        "failure_provenance",
                        value_domain::FAILURE_USE_PROVENANCE
                    ),
                    CodeQueryRowField::required_enum(
                        "consumer",
                        value_domain::FAILURE_USE_CONSUMER
                    ),
                    CodeQueryRowField::optional("argument_ordinal", Scalar::Integer),
                    CodeQueryRowField::required_enum("proof", value_domain::EFFECT_PROOF),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("summary_id", Scalar::String),
        ],
    },
    NilnessOperation => "nilness_operation" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required("operation_point_id", Scalar::StableId),
                    CodeQueryRowField::required("subject_value_id", Scalar::Integer),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "use_kind",
                        value_domain::RESULT_CONTRACT_USE_KIND
                    ),
                    CodeQueryRowField::required_enum("fact", value_domain::NILNESS_FACT),
                    CodeQueryRowField::required_enum("origin", value_domain::NILNESS_ORIGIN),
                    CodeQueryRowField::required_enum("proof", value_domain::NILNESS_PROOF),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::optional_enum("reason", value_domain::NILNESS_REASON),
        ],
    },
    SwitchCoverage => "switch_coverage" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required("switch_fact_id", Scalar::Integer),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("kind", value_domain::SWITCH_KIND),
                    CodeQueryRowField::optional("selector_value_id", Scalar::Integer),
                    CodeQueryRowField::required_enum(
                        "selector_domain",
                        value_domain::SWITCH_SELECTOR_DOMAIN
                    ),
                    CodeQueryRowField::required("case_count", Scalar::Integer),
                    CodeQueryRowField::required("has_true_case", Scalar::Boolean),
                    CodeQueryRowField::required("has_false_case", Scalar::Boolean),
                    CodeQueryRowField::required("default_present", Scalar::Boolean),
                    CodeQueryRowField::required_enum("verdict", value_domain::SWITCH_VERDICT),
                    CodeQueryRowField::required_enum("proof", value_domain::SWITCH_PROOF),
                    CodeQueryRowField::optional_enum("reason", value_domain::SWITCH_REASON),
        ],
    },
    AssignmentRelation => "assignment_relation" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::optional("assignment_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_value_id", Scalar::Integer),
                    CodeQueryRowField::optional("rhs_value_id", Scalar::Integer),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("relation_kind", value_domain::ASSIGNMENT_RELATION_KIND),
                    CodeQueryRowField::required_enum("storage_kind", value_domain::ASSIGNMENT_STORAGE_KIND),
                    CodeQueryRowField::required_enum("verdict", value_domain::ASSIGNMENT_VERDICT),
                    CodeQueryRowField::required_enum("proof", value_domain::ASSIGNMENT_PROOF),
                    CodeQueryRowField::required_enum("coverage", value_domain::EFFECT_COVERAGE),
                    CodeQueryRowField::optional("reason", Scalar::String),
        ],
    },
    DetachedTaskTransfer => "detached_task_transfer" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_id", Scalar::StableId),
                    CodeQueryRowField::required("call_id", Scalar::StableId),
                    CodeQueryRowField::required("call_point_id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "role",
                        value_domain::DETACHED_TRANSFER_ROLE
                    ),
                    CodeQueryRowField::optional("ordinal", Scalar::Integer),
                    CodeQueryRowField::required("value_id", Scalar::StableId),
                    CodeQueryRowField::optional("object_id", Scalar::String),
                    CodeQueryRowField::optional_enum(
                        "object_cardinality",
                        value_domain::OBJECT_CARDINALITY
                    ),
                    CodeQueryRowField::required_enum(
                        "timing",
                        value_domain::DETACHED_TRANSFER_TIMING
                    ),
                    CodeQueryRowField::required_enum(
                        "proof",
                        value_domain::DETACHED_TRANSFER_PROOF
                    ),
                    CodeQueryRowField::required_enum(
                        "coverage",
                        value_domain::DETACHED_TRANSFER_COVERAGE
                    ),
                    CodeQueryRowField::optional_enum(
                        "reason",
                        value_domain::DETACHED_TRANSFER_REASON
                    ),
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
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("procedure_name", Scalar::String),
                    CodeQueryRowField::optional("effect_id", Scalar::String),
                    CodeQueryRowField::optional_enum(
                        "classification",
                        value_domain::EFFECT_CLASSIFICATION
                    ),
                    CodeQueryRowField::optional_enum("certainty", value_domain::EFFECT_CERTAINTY),
                    CodeQueryRowField::optional_enum("timing", value_domain::EFFECT_TIMING),
                    CodeQueryRowField::optional_enum(
                        "execution_timing",
                        value_domain::EXECUTION_TIMING
                    ),
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
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("ordinal", Scalar::Integer),
                    CodeQueryRowField::required_enum("coverage", value_domain::SIGNATURE_COVERAGE),
                    CodeQueryRowField::required_enum("role", value_domain::DECLARATION_ROLE),
                    CodeQueryRowField::optional("first_parameter", Scalar::String),
                    CodeQueryRowField::optional("required_arity", Scalar::Integer),
                    CodeQueryRowField::optional("total_arity", Scalar::Integer),
                    CodeQueryRowField::required("repeated", Scalar::Boolean),
                    CodeQueryRowField::required("generic_arity", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "receiver_contract",
                        value_domain::RECEIVER_CONTRACT
                    ),
                    CodeQueryRowField::optional_enum(
                        "python_method_kind",
                        value_domain::PYTHON_METHOD_KIND
                    ),
                    CodeQueryRowField::optional("python_owner_is_metaclass", Scalar::Boolean),
                    CodeQueryRowField::optional("python_owner_is_zope_interface", Scalar::Boolean),
                    CodeQueryRowField::optional("python_used_in_class_body", Scalar::Boolean),
                    CodeQueryRowField::optional("python_no_args_with_decorator", Scalar::Boolean),
                    CodeQueryRowField::optional("return_type", Scalar::String),
                    CodeQueryRowField::required("declaration_only", Scalar::Boolean),
                    CodeQueryRowField::required("parameter_count", Scalar::Integer),
                    CodeQueryRowField::optional_enum(
                        "special_method_status",
                        value_domain::PYTHON_SPECIAL_METHOD_STATUS
                    ),
        ],
    },
    LiteralOccurrence => "literal_occurrence" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("scope_id", Scalar::StableId),
                    CodeQueryRowField::required_enum(
                        "scope_kind",
                        value_domain::LITERAL_OCCURRENCE_SCOPE_KIND
                    ),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum(
                        "kind",
                        value_domain::LITERAL_OCCURRENCE_KIND
                    ),
                    CodeQueryRowField::optional("identity", Scalar::String),
                    CodeQueryRowField::required_enum(
                        "coverage",
                        value_domain::LITERAL_OCCURRENCE_COVERAGE
                    ),
                    CodeQueryRowField::required("trivial", Scalar::Boolean),
                    CodeQueryRowField::optional("parent_call_id", Scalar::StableId),
                    CodeQueryRowField::optional("argument_index", Scalar::Integer),
        ],
    },
    CallableMetrics => "callable_metrics" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("callable_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::required_enum("coverage", value_domain::CALLABLE_METRICS_COVERAGE),
                    CodeQueryRowField::optional("max_nesting", Scalar::Integer),
                    CodeQueryRowField::optional("cognitive_complexity", Scalar::Integer),
                    CodeQueryRowField::optional("owned_body_span_lines", Scalar::Integer),
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
                    CodeQueryRowField::optional("value_id", Scalar::StableId),
                    CodeQueryRowField::optional("parameter_ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("port_id", Scalar::StableId),
                    CodeQueryRowField::required("decorator_name", Scalar::String),
                    CodeQueryRowField::optional("annotation_type_id", Scalar::StableId),
                    CodeQueryRowField::optional("annotation_type_name", Scalar::String),
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
        display_range: |value| Some(value.range),
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
                    CodeQueryRowField::optional("model_id", Scalar::String),
                    CodeQueryRowField::optional("pack_id", Scalar::String),
                    CodeQueryRowField::optional("factory_id", Scalar::DeclarationIdentity),
                    CodeQueryRowField::required_enum("proof", value_domain::RECEIVER_EVIDENCE_PROOF),
                    CodeQueryRowField::required_enum("completeness", value_domain::RECEIVER_COVERAGE),
        ],
    },
    PointsToCandidate => "points_to_candidate" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("site_id", Scalar::StableId),
                    CodeQueryRowField::optional("program_point_id", Scalar::StableId),
                    CodeQueryRowField::required("candidate_index", Scalar::Integer),
                    CodeQueryRowField::optional("object_id", Scalar::String),
                    CodeQueryRowField::optional_enum(
                        "object_cardinality",
                        value_domain::OBJECT_CARDINALITY
                    ),
                    CodeQueryRowField::required_enum("proof", value_domain::EVIDENCE_PROOF),
                    CodeQueryRowField::required_enum(
                        "completeness",
                        value_domain::EVIDENCE_COMPLETENESS
                    ),
                    CodeQueryRowField::required_enum("coverage", value_domain::CANDIDATE_COVERAGE),
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
                        value_domain::SEMANTIC_BUDGET_LANE
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
                    CodeQueryRowField::optional("target_fq_name", Scalar::String),
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
    PythonHierarchyFact => "python_hierarchy_fact" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("root_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("fact_kind", value_domain::PYTHON_HIERARCHY_FACT_KIND),
                    CodeQueryRowField::required_enum("outcome", value_domain::PYTHON_HIERARCHY_OUTCOME),
                    CodeQueryRowField::optional_enum("reason", value_domain::PYTHON_HIERARCHY_REASON),
                    CodeQueryRowField::required_enum("coverage", value_domain::PYTHON_HIERARCHY_COVERAGE),
                    CodeQueryRowField::optional("ordinal", Scalar::Integer),
                    CodeQueryRowField::optional("base_spelling", Scalar::String),
                    CodeQueryRowField::optional_enum("base_resolution", value_domain::PYTHON_BASE_RESOLUTION),
                    CodeQueryRowField::optional("root_declaration_id", Scalar::StableId),
                    CodeQueryRowField::optional("declaration_id", Scalar::StableId),
                    CodeQueryRowField::optional("owner_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_id", Scalar::StableId),
                    CodeQueryRowField::optional("target_owner_id", Scalar::StableId),
                    CodeQueryRowField::optional("member_name", Scalar::String),
                    CodeQueryRowField::optional("mro_rank", Scalar::Integer),
                    CodeQueryRowField::optional("target_non_trivial", Scalar::Boolean),
                    CodeQueryRowField::optional("target_reads_self", Scalar::Boolean),
                    CodeQueryRowField::optional("base_branch_definition_count", Scalar::Integer),
                    CodeQueryRowField::optional("has_strict_ordering", Scalar::Boolean),
                    CodeQueryRowField::optional("has_non_strict_ordering", Scalar::Boolean),
                    CodeQueryRowField::optional("total_ordering_decorator", Scalar::Boolean),
                    CodeQueryRowField::optional("inherited_ne_present", Scalar::Boolean),
                    CodeQueryRowField::optional("inherited_ne_delegates", Scalar::Boolean),
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
                    CodeQueryRowField::optional_enum(
                        "definition_status",
                        value_domain::EXPORT_DEFINITION_STATUS
                    ),
                    CodeQueryRowField::optional("definition_binding_name", Scalar::String),
                    CodeQueryRowField::optional_enum(
                        "definition_binding_kind",
                        value_domain::EXPORT_BINDING_KIND
                    ),
                    CodeQueryRowField::optional("definition_binding_start_byte", Scalar::Integer),
                    CodeQueryRowField::optional("definition_binding_end_byte", Scalar::Integer),
                    CodeQueryRowField::optional("definition_binding_start_line", Scalar::Integer),
                    CodeQueryRowField::optional("definition_binding_start_column", Scalar::Integer),
                    CodeQueryRowField::optional("definition_binding_end_line", Scalar::Integer),
                    CodeQueryRowField::optional("definition_binding_end_column", Scalar::Integer),
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
        // Issue #2751. Both source-side columns come from `EdgeSite`, which
        // every producer fills: `path` is the site file the reference is
        // spelled in, and `source_id` is the identity of the declaration
        // lexically enclosing it, absent exactly when the producer could not
        // name one. Without them a relational plan can read which declaration
        // an edge points at but nothing about where the reference lives, so no
        // plan could fold edges by referencing file or referencing declaration.
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::optional("ast_id", Scalar::StableId),
                    CodeQueryRowField::required("path", Scalar::String),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
                    CodeQueryRowField::optional("source_id", Scalar::DeclarationIdentity),
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
                    CodeQueryRowField::optional_enum(
                        "read_cause",
                        value_domain::STATE_EVENT_READ_CAUSE,
                    ),
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
    BindingInitializerCall => "binding_initializer_call" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
                    CodeQueryRowField::required("id", Scalar::StableId),
                    CodeQueryRowField::required("establishment_event_id", Scalar::StableId),
                    CodeQueryRowField::required("site_ast_id", Scalar::StableId),
                    CodeQueryRowField::required_enum("initializer_role", value_domain::BINDING_INITIALIZER_CALL_ROLE),
                    CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
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
    FailureHandlerState => "failure_handler_state" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("catch_ast_id", Scalar::StableId),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("verdict", &["empty", "nonempty", "unknown"]),
            CodeQueryRowField::required_enum("proof", &["exact", "unknown"]),
            CodeQueryRowField::required_enum("coverage", &["exhaustive", "incomplete"]),
            CodeQueryRowField::optional_enum("reason", &[
                "unsupported_language", "syntax_unavailable", "source_limit",
                "snapshot_mismatch", "cancelled", "syntax_recovery", "missing_body",
                "missing_try_body", "caught_type_unresolved", "caught_type_ambiguous",
                "caught_type_hierarchy_unknown"
            ]),
            CodeQueryRowField::optional("caught_type", Scalar::DeclarationIdentity),
            CodeQueryRowField::optional_enum(
                "caught_type_relation",
                &["system_exception", "not_system_exception", "unknown"],
            ),
            CodeQueryRowField::optional("has_filter", Scalar::Boolean),
            CodeQueryRowField::optional_enum(
                "rethrow_kind",
                &["none", "bare", "caught_variable", "both", "unknown"],
            ),
        ],
    },
    BranchRelation => "branch_relation" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("owner_id", Scalar::StableId),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("relation", value_domain::BRANCH_RELATION),
            CodeQueryRowField::required_enum("verdict", value_domain::BRANCH_VERDICT),
            CodeQueryRowField::optional_enum("reason", value_domain::BRANCH_REASON),
            CodeQueryRowField::optional_enum("orientation", value_domain::BRANCH_ORIENTATION),
            CodeQueryRowField::required("earlier_ordinal", Scalar::Integer),
            CodeQueryRowField::required("later_ordinal", Scalar::Integer),
        ],
    },
    LoopRelation => "loop_relation" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("procedure_id", Scalar::StableId),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("loop_kind", value_domain::LOOP_KIND),
            CodeQueryRowField::required_enum("verdict", value_domain::LOOP_VERDICT),
            CodeQueryRowField::optional("repeat_edge_id", Scalar::StableId),
        ],
    },
    CppExpression => "cpp_expression" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_open_enum(
                "kind",
                "C++ expression kinds are adapter-owned and may grow with grammar support"
            ),
            CodeQueryRowField::optional("name", Scalar::String),
            CodeQueryRowField::optional("type_text", Scalar::String),
            CodeQueryRowField::required_open_enum(
                "type_form",
                "C++ written type forms are adapter-owned"
            ),
            CodeQueryRowField::required_open_enum(
                "signedness",
                "C++ signedness is exact only for selected scalar spellings"
            ),
            CodeQueryRowField::optional("width_bits", Scalar::Integer),
            CodeQueryRowField::optional("literal_text", Scalar::String),
            CodeQueryRowField::optional("integer_value", Scalar::String),
            CodeQueryRowField::optional("array_extent", Scalar::Integer),
            CodeQueryRowField::optional("array_is_reference", Scalar::Boolean),
            CodeQueryRowField::optional("parameter_by_value", Scalar::Boolean),
            CodeQueryRowField::optional("bit_field_width", Scalar::Integer),
            CodeQueryRowField::optional("bit_field_anonymous", Scalar::Boolean),
            CodeQueryRowField::optional("enum_scoped", Scalar::Boolean),
            CodeQueryRowField::optional("enum_ordinal", Scalar::Integer),
            CodeQueryRowField::optional("enum_value", Scalar::String),
            CodeQueryRowField::optional("has_initializer", Scalar::Boolean),
            CodeQueryRowField::optional(
                "enum_has_implicit_before_nonreference",
                Scalar::Boolean
            ),
            CodeQueryRowField::optional("return_top_level_const", Scalar::Boolean),
            CodeQueryRowField::optional("member_function", Scalar::Boolean),
            CodeQueryRowField::optional("member_function_const", Scalar::Boolean),
            CodeQueryRowField::optional("type_size_bytes", Scalar::Integer),
            CodeQueryRowField::optional("type_size_exact", Scalar::Boolean),
            CodeQueryRowField::optional_enum(
                "sizeof_operand_kind",
                &["type", "expression"]
            ),
            CodeQueryRowField::optional("sizeof_operand_is_parameter", Scalar::Boolean),
            CodeQueryRowField::optional("sizeof_has_side_effect", Scalar::Boolean),
            CodeQueryRowField::optional("loop_has_short_ancestor", Scalar::Boolean),
            CodeQueryRowField::required_enum(
                "completeness",
                &["complete", "open"]
            ),
            CodeQueryRowField::optional("completeness_reason", Scalar::String),
        ],
    },
    StatementReachability => "statement_reachability" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("procedure_id", Scalar::StableId),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("statement_kind", value_domain::STATEMENT_KIND),
            CodeQueryRowField::required_enum("verdict", value_domain::STATEMENT_VERDICT),
            CodeQueryRowField::optional("reason", Scalar::String),
        ],
    },
    PendingCleanupFlow => "pending_cleanup_flow" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("procedure_id", Scalar::StableId),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required("cleanup_id", Scalar::StableId),
            CodeQueryRowField::required_enum(
                "cleanup_kind",
                &["finally", "ensure", "defer", "using", "with", "raii_drop"],
            ),
            CodeQueryRowField::required_enum(
                "pending_kind",
                &["return", "throw", "break", "continue"],
            ),
            CodeQueryRowField::required("source_id", Scalar::StableId),
            CodeQueryRowField::required("target_id", Scalar::StableId),
            CodeQueryRowField::required_enum(
                "verdict",
                &["overrides", "preserves", "unknown"],
            ),
            CodeQueryRowField::required_enum("proof", &["exact", "unknown"]),
            CodeQueryRowField::required_enum("coverage", &["exhaustive", "incomplete"]),
            CodeQueryRowField::optional("reason", Scalar::String),
        ],
    },
    PythonRuleFact => "python_rule_fact" {
        display_range: |value| Some(value.range),
        identities: None,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required_enum("relation", value_domain::PYTHON_RULE_RELATION),
            CodeQueryRowField::optional("owner_id", Scalar::StableId),
            CodeQueryRowField::required("path", Scalar::String),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("outcome", value_domain::PYTHON_RULE_OUTCOME),
            CodeQueryRowField::required_enum("proof", value_domain::PYTHON_RULE_PROOF),
            CodeQueryRowField::required_enum("completeness", value_domain::PYTHON_RULE_COMPLETENESS),
            CodeQueryRowField::optional("reason", Scalar::String),
            CodeQueryRowField::optional("explicit_value_returns", Scalar::Integer),
            CodeQueryRowField::optional("none_returns", Scalar::Integer),
            CodeQueryRowField::optional("explicit_return_statements", Scalar::Integer),
            CodeQueryRowField::optional("fallthrough_none_returns", Scalar::Integer),
            CodeQueryRowField::optional("mixed_returns", Scalar::Boolean),
            CodeQueryRowField::optional("is_async", Scalar::Boolean),
            CodeQueryRowField::optional("is_generator", Scalar::Boolean),
            CodeQueryRowField::optional_enum("test_scope", value_domain::PYTHON_TRI_STATE),
            CodeQueryRowField::optional_enum(
                "terminal_elif_else",
                value_domain::PYTHON_TRI_STATE,
            ),
            CodeQueryRowField::optional("tuple_return_count", Scalar::Integer),
            CodeQueryRowField::optional("distinct_tuple_arities", Scalar::Integer),
            CodeQueryRowField::optional("tuple_return_arities", Scalar::IntegerList),
            CodeQueryRowField::optional("assignment_target_count", Scalar::Integer),
            CodeQueryRowField::optional_enum(
                "assignment_arity_match",
                value_domain::PYTHON_TRI_STATE,
            ),
            CodeQueryRowField::optional("mixed_tuple_arities", Scalar::Boolean),
            CodeQueryRowField::optional("annotated", Scalar::Boolean),
            CodeQueryRowField::optional_enum("return_contract", value_domain::PYTHON_RETURN_CONTRACT),
            CodeQueryRowField::optional_enum("result_use", value_domain::PYTHON_RESULT_USE),
            CodeQueryRowField::optional("forwarded", Scalar::Boolean),
            CodeQueryRowField::optional_enum(
                "callable_evaluation_time",
                value_domain::PYTHON_CALLABLE_EVALUATION_TIME,
            ),
            CodeQueryRowField::optional_enum("default_equivalent", value_domain::PYTHON_TRI_STATE),
            CodeQueryRowField::optional("target_id", Scalar::StableId),
            CodeQueryRowField::optional("returns_receiver", Scalar::Boolean),
            CodeQueryRowField::optional("parameter_count", Scalar::Integer),
            CodeQueryRowField::optional("scope_is_public", Scalar::Boolean),
            CodeQueryRowField::optional("docstring_present", Scalar::Boolean),
            CodeQueryRowField::optional("docstring_value", Scalar::String),
            CodeQueryRowField::optional("comment_block_text", Scalar::String),
            CodeQueryRowField::optional("comment_block_lines", Scalar::StringList),
            CodeQueryRowField::optional("lines_of_code", Scalar::Integer),
            CodeQueryRowField::optional("decorator_count", Scalar::Integer),
            CodeQueryRowField::optional("is_override", Scalar::Boolean),
            CodeQueryRowField::optional("is_property_accessor", Scalar::Boolean),
            CodeQueryRowField::optional("public_method_count", Scalar::Integer),
            CodeQueryRowField::optional("has_inheritance", Scalar::Boolean),
            CodeQueryRowField::optional("has_subclasses", Scalar::Boolean),
            CodeQueryRowField::optional("has_special_method", Scalar::Boolean),
            CodeQueryRowField::optional("is_decorated", Scalar::Boolean),
            CodeQueryRowField::optional("is_probable_mixin", Scalar::Boolean),
            CodeQueryRowField::optional("is_stateful", Scalar::Boolean),
            CodeQueryRowField::optional("is_top_level", Scalar::Boolean),
            CodeQueryRowField::optional("cyclomatic_complexity", Scalar::Integer),
            CodeQueryRowField::optional("url_prefix", Scalar::String),
            CodeQueryRowField::optional("variable_id", Scalar::StableId),
            CodeQueryRowField::optional("name", Scalar::String),
            CodeQueryRowField::optional_enum("scope_kind", value_domain::PYTHON_VARIABLE_SCOPE_KIND),
            CodeQueryRowField::optional("is_global", Scalar::Boolean),
            CodeQueryRowField::optional("is_nonlocal", Scalar::Boolean),
            CodeQueryRowField::optional("is_builtin", Scalar::Boolean),
            CodeQueryRowField::optional("call_callee", Scalar::Boolean),
            CodeQueryRowField::optional("has_read", Scalar::Boolean),
            CodeQueryRowField::optional_enum(
                "definition_kind",
                value_domain::PYTHON_VARIABLE_DEFINITION_KIND,
            ),
            CodeQueryRowField::optional("definition_order", Scalar::Integer),
            CodeQueryRowField::optional("first_definition", Scalar::Boolean),
            CodeQueryRowField::optional("definition_is_unused", Scalar::Boolean),
            CodeQueryRowField::optional("annotation_only", Scalar::Boolean),
            CodeQueryRowField::optional("annotated_assignment", Scalar::Boolean),
            CodeQueryRowField::optional("is_abstract", Scalar::Boolean),
            CodeQueryRowField::optional("is_overriding_method", Scalar::Boolean),
            CodeQueryRowField::optional("is_overridden_method", Scalar::Boolean),
            CodeQueryRowField::optional_enum(
                "reachability",
                value_domain::PYTHON_VARIABLE_REACHABILITY,
            ),
            CodeQueryRowField::optional_enum(
                "access_kind",
                value_domain::PYTHON_VARIABLE_ACCESS_KIND,
            ),
            CodeQueryRowField::optional("nested_scope", Scalar::Boolean),
            CodeQueryRowField::optional("in_main_guard", Scalar::Boolean),
            CodeQueryRowField::optional("optimizing_parameter", Scalar::Boolean),
            CodeQueryRowField::optional("self_assignment", Scalar::Boolean),
            CodeQueryRowField::optional_enum(
                "related_scope_kind",
                value_domain::PYTHON_VARIABLE_SCOPE_KIND,
            ),
            CodeQueryRowField::optional("related_has_definition_outside_main", Scalar::Boolean),
            CodeQueryRowField::optional("related_has_deletion", Scalar::Boolean),
            CodeQueryRowField::optional("related_has_import", Scalar::Boolean),
            CodeQueryRowField::optional("related_is_pytest_fixture", Scalar::Boolean),
            CodeQueryRowField::optional("loop_has_body_read", Scalar::Boolean),
            CodeQueryRowField::optional("loop_policy_excluded", Scalar::Boolean),
            CodeQueryRowField::optional("nested_loop_reused", Scalar::Boolean),
            CodeQueryRowField::optional("nested_loop_has_outer_use", Scalar::Boolean),
        ],
    },
    RustMarkerImpl => "rust_marker_impl" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("path", Scalar::String),
            CodeQueryRowField::required("language", Scalar::String),
            CodeQueryRowField::required("trait", Scalar::String),
            CodeQueryRowField::required("trait_proof", Scalar::String),
            CodeQueryRowField::required("self_proof", Scalar::String),
            CodeQueryRowField::required("impl_coverage", Scalar::String),
            CodeQueryRowField::required("mapping_proof", Scalar::String),
            CodeQueryRowField::required("has_send_bound", Scalar::Boolean),
            CodeQueryRowField::required("has_sync_bound", Scalar::Boolean),
            CodeQueryRowField::required("bounds", Scalar::StringList),
            CodeQueryRowField::required("bounds_proof", Scalar::String),
            CodeQueryRowField::required("stored", Scalar::Boolean),
            CodeQueryRowField::required("shared_ref_only", Scalar::Boolean),
            CodeQueryRowField::required("shared_access", Scalar::String),
            CodeQueryRowField::required("uses_proof", Scalar::String),
            CodeQueryRowField::required("completeness", Scalar::String),
            CodeQueryRowField::optional("parameter", Scalar::String),
            CodeQueryRowField::optional("declaration_parameter_ordinal", Scalar::Integer),
        ],
    },
    RustPointerFinding => "rust_pointer_finding" {
        display_range: |value| Some(value.range),
        identities: Primary,
        fields: [
            CodeQueryRowField::required("id", Scalar::StableId),
            CodeQueryRowField::required("path", Scalar::String),
            CodeQueryRowField::required_enum("language", value_domain::LANGUAGE),
            CodeQueryRowField::required_enum("relation", value_domain::RUST_POINTER_RELATION),
            CodeQueryRowField::required("origin_id", Scalar::StableId),
            CodeQueryRowField::required_enum("origin_kind", value_domain::RUST_POINTER_ORIGIN_KIND),
            CodeQueryRowField::optional_enum("invalidation_cause", value_domain::RUST_POINTER_INVALIDATION_CAUSE),
            CodeQueryRowField::required_enum("access_kind", value_domain::RUST_POINTER_ACCESS_KIND),
            CodeQueryRowField::required_enum("strength", value_domain::RUST_POINTER_STRENGTH),
            CodeQueryRowField::required("path_proven", Scalar::Boolean),
            CodeQueryRowField::required_enum("bounds", value_domain::RUST_POINTER_BOUNDS),
            CodeQueryRowField::optional("byte_offset", Scalar::String),
            CodeQueryRowField::optional("byte_extent", Scalar::String),
            CodeQueryRowField::optional("access_width", Scalar::String),
            CodeQueryRowField::required_enum("proof", value_domain::RUST_POINTER_PROOF),
            CodeQueryRowField::required_enum("completeness", value_domain::RUST_POINTER_COMPLETENESS),
            CodeQueryRowField::optional("reason", Scalar::String),
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
                    CodeQueryRowField::optional("constant", Scalar::Boolean),
                    CodeQueryRowField::optional("null_on_true", Scalar::Boolean),
                    CodeQueryRowField::optional("null_target_id", Scalar::StableId),
                    CodeQueryRowField::optional("equality_negated", Scalar::Boolean),
                    CodeQueryRowField::optional_enum(
                        "integer_relation",
                        &["less_than", "less_than_or_equal", "greater_than", "greater_than_or_equal"]
                    ),
                    CodeQueryRowField::optional("constant_value", Scalar::Integer),
                    CodeQueryRowField::optional("guarded_value", Scalar::Integer),
                    CodeQueryRowField::optional("classes_value", Scalar::Integer),
                    CodeQueryRowField::optional("member_value", Scalar::Integer),
                    CodeQueryRowField::optional("opaque_digest", Scalar::Integer),
                    CodeQueryRowField::optional("subject_value", Scalar::Integer),
                    CodeQueryRowField::optional("true_edge_id", Scalar::StableId),
                    CodeQueryRowField::optional("true_target_id", Scalar::StableId),
                    CodeQueryRowField::optional("false_edge_id", Scalar::StableId),
                    CodeQueryRowField::optional("false_target_id", Scalar::StableId),
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

    /// Read a scalar, preserving the distinction between an absent optional
    /// value (`Ok(None)`) and unavailable proof (`Err` with `unknown_reason`).
    pub fn field(
        self,
        name: &str,
    ) -> Result<Option<CodeQueryRowScalarRef<'a>>, CodeQueryRowFieldError> {
        let Some(schema) = self.fields().iter().find(|field| field.name == name) else {
            return Err(CodeQueryRowFieldError::unregistered(self.domain(), name));
        };
        if name == "conversion"
            && let CodeQueryResultValue::CallBinding { value } = self.value
            && let Some(reason) = value.conversion_reason
        {
            return Err(CodeQueryRowFieldError::unknown(
                self.domain(),
                name,
                CodeQueryRowFieldUnknownReason::CallConversion(reason),
            ));
        }
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
        (CodeQueryResultValue::StructuralMatch { value }, "parent_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.parent_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "left_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.left_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "right_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.right_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "object_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.object_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "object_name") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.object_name.as_deref())
            .map(Scalar::String),
        (CodeQueryResultValue::StructuralMatch { value }, "callee_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.callee_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "receiver_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.receiver_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "enclosing_callable_ast_id") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.enclosing_callable_ast_id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::StructuralMatch { value }, "name") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.name.as_deref())
            .map(Scalar::String),
        (CodeQueryResultValue::StructuralMatch { value }, "string_value") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.string_value.as_deref())
            .map(Scalar::String),
        (CodeQueryResultValue::StructuralMatch { value }, "construct") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.construct.as_deref())
            .map(Scalar::String),
        (CodeQueryResultValue::StructuralMatch { value }, "occurrence_role") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.occurrence_role)
            .map(Scalar::ConstrainedEnum),
        (CodeQueryResultValue::StructuralMatch { value }, "element_index") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.element_index)
            .map(|index| Scalar::Integer(index as u64)),
        (CodeQueryResultValue::StructuralMatch { value }, "element_count") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.element_count)
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::StructuralMatch { value }, "is_last_element") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.is_last_element)
            .map(Scalar::Boolean),
        (CodeQueryResultValue::StructuralMatch { value }, "parameter_index") => value
            .relations
            .as_deref()
            .and_then(|relations| relations.parameter_index)
            .map(|index| Scalar::Integer(index as u64)),
        (CodeQueryResultValue::StructuralMatch { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::StructuralMatch { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_complete") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::Boolean(site.complete)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_form") => value
            .python_import
            .as_ref()
            .and_then(|site| site.form.map(Scalar::ConstrainedEnum)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_module") => value
            .python_import
            .as_ref()
            .and_then(|site| site.module.as_deref().map(Scalar::String)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_name") => value
            .python_import
            .as_ref()
            .and_then(|site| site.name.as_deref().map(Scalar::String)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_alias") => value
            .python_import
            .as_ref()
            .and_then(|site| site.alias.as_deref().map(Scalar::String)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_modules") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::StringList(&site.modules)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_names") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::StringList(&site.names)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_aliases") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::StringList(&site.aliases)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_wildcard") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::Boolean(site.wildcard)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_module_scope") => value
            .python_import
            .as_ref()
            .and_then(|site| site.module_scope.map(Scalar::Boolean)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_source_order") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::Integer(site.source_order)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_target_paths") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::StringList(&site.target_paths)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_target_status") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::ConstrainedEnum(site.target_status)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_repeated") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::Boolean(site.repeated)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_duplicate") => value
            .python_import
            .as_ref()
            .and_then(|site| site.duplicate.map(Scalar::Boolean)),
        (
            CodeQueryResultValue::StructuralMatch { value },
            "python_import_in_import_error_handler",
        ) => value
            .python_import
            .as_ref()
            .and_then(|site| site.in_import_error_handler.map(Scalar::Boolean)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_in_main_guard") => value
            .python_import
            .as_ref()
            .and_then(|site| site.in_main_guard.map(Scalar::Boolean)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_mixed_form") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::Boolean(site.mixed_form)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_own_module") => value
            .python_import
            .as_ref()
            .and_then(|site| site.own_module.map(Scalar::Boolean)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_polluting") => value
            .python_import
            .as_ref()
            .and_then(|site| site.polluting.map(Scalar::Boolean)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_export_state") => value
            .python_import
            .as_ref()
            .map(|site| Scalar::ConstrainedEnum(site.export_state)),
        (CodeQueryResultValue::StructuralMatch { value }, "python_import_cycle_state") => value
            .python_import
            .as_ref()
            .and_then(|site| site.cycle_state.map(Scalar::ConstrainedEnum)),
        (CodeQueryResultValue::Declaration { value }, "id") => {
            value.id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::Declaration { value }, "site_id") => {
            value.site_id.as_deref().map(Scalar::StableId)
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
        (CodeQueryResultValue::Procedure { value }, "dialect") => {
            Some(Scalar::ConstrainedEnum(value.dialect))
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
        (CodeQueryResultValue::FlowEndpoint { value }, "status") => {
            Some(Scalar::ConstrainedEnum(value.status.label()))
        }
        (CodeQueryResultValue::FlowEndpoint { value }, "reason") => {
            value.reason.as_deref().map(Scalar::String)
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
        (CodeQueryResultValue::ClassSetRow { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::ClassSetRow { value }, "member") => {
            Some(Scalar::String(&value.member))
        }
        (CodeQueryResultValue::ClassSetRow { value }, "class") => {
            value.class.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ClassSetRow { value }, "origin") => {
            Some(Scalar::ConstrainedEnum(&value.origin))
        }
        (CodeQueryResultValue::ClassSetRow { value }, "guard_only") => {
            value.guard_only.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::ClassSetRow { value }, "status") => {
            Some(Scalar::ConstrainedEnum(value.status))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "member") => {
            Some(Scalar::String(&value.member))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "class") => {
            Some(Scalar::String(&value.class))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "caller") => {
            Some(Scalar::String(&value.caller))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "witness_steps") => {
            Some(Scalar::Integer(value.witness_steps as u64))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "condition") => {
            value.condition.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::AbsentMemberFinding { value }, "also_fails_at") => {
            Some(Scalar::StringList(&value.also_fails_at))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "finding_id") => {
            Some(Scalar::StableId(&value.finding_id))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "witness_index") => {
            Some(Scalar::Integer(value.witness_index as u64))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "retained_bytes") => {
            Some(Scalar::Integer(value.retained_bytes as u64))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "truncated") => {
            Some(Scalar::Boolean(value.truncated))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "omitted_steps_lower_bound") => {
            Some(Scalar::Integer(value.omitted_steps_lower_bound as u64))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "alternatives_truncated") => {
            Some(Scalar::Boolean(value.alternatives_truncated))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "retention_truncated") => {
            Some(Scalar::Boolean(value.retention_truncated))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "witness_status") => {
            Some(Scalar::ConstrainedEnum(value.witness_status.as_str()))
        }
        (CodeQueryResultValue::AbsentMemberWitness { value }, "unavailable_reason") => {
            value.unavailable_reason.as_deref().map(Scalar::String)
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
        (CodeQueryResultValue::CallSite { value }, "site_id") => {
            value.site_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallSite { value }, "program_point_id") => {
            value.program_point_id.as_deref().map(Scalar::StableId)
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
        (CodeQueryResultValue::CallSite { value }, "receiver_kind") => {
            Some(Scalar::ConstrainedEnum(value.receiver_kind))
        }
        (CodeQueryResultValue::CallSite { value }, "argument_identity") => {
            value.argument_identity.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallSite { value }, "caller_parameter_identity") => value
            .caller_parameter_identity
            .as_deref()
            .map(Scalar::StableId),
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
        (CodeQueryResultValue::MemberTargetAnalysis { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::MemberTargetAnalysis { value }, "site_ast_id") => {
            value.site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::MemberTargetAnalysis { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::MemberTargetAnalysis { value }, "capture") => {
            value.capture.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::MemberTargetAnalysis { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::MemberTargetAnalysis { value }, "target_count") => {
            Some(Scalar::Integer(value.member_targets.len() as u64))
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
        (CodeQueryResultValue::FieldWriteValue { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "write_site_id") => {
            Some(Scalar::StableId(&value.write_site_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "assignment_ast_id") => {
            Some(Scalar::StableId(&value.assignment_ast_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "left_ast_id") => {
            Some(Scalar::StableId(&value.left_ast_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "receiver_ast_id") => {
            Some(Scalar::StableId(&value.receiver_ast_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "member_ast_id") => {
            Some(Scalar::StableId(&value.member_ast_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "rhs_ast_id") => {
            Some(Scalar::StableId(&value.rhs_ast_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "receiver_identity_id") => {
            Some(Scalar::StableId(&value.receiver_identity_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "member_target_id") => {
            Some(Scalar::StableId(&value.member_target_id))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::FieldWriteValue { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "runtime") => {
            Some(Scalar::String(&value.runtime))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "global") => {
            Some(Scalar::String(&value.global))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "container") => {
            Some(Scalar::String(&value.container))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "key_kind") => {
            Some(Scalar::ConstrainedEnum(value.key_kind))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "property") => {
            value.property.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "index") => {
            value.index.map(Scalar::Integer)
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "source_origin") => {
            Some(Scalar::ConstrainedEnum(value.source_origin))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "active_model_set_hash") => {
            value.active_model_set_hash.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "refinement_identity") => {
            value.refinement_identity.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "exposure_id") => {
            value.exposure_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "behavior_id") => {
            value.behavior_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "conclusive_exclusion") => {
            Some(Scalar::Boolean(value.conclusive_exclusion))
        }
        (CodeQueryResultValue::RuntimeKeyedReadValue { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::CallShape { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CallShape { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallShape { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallShape { value }, "callee_provenance") => {
            Some(Scalar::ConstrainedEnum(value.callee_provenance))
        }
        (CodeQueryResultValue::CallShape { value }, "callee_supplier") => {
            value.callee_supplier.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallShape { value }, "callee_type_shape") => {
            Some(Scalar::ConstrainedEnum(value.callee_type_shape))
        }
        (CodeQueryResultValue::CallShape { value }, "callee_bounds") => {
            Some(Scalar::StringList(&value.callee_bounds))
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
        (CodeQueryResultValue::CallShape { value }, "callee_name") => {
            value.callee_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallShape { value }, "resolved_external_callee") => value
            .resolved_external_callee
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallShape { value }, "argument_count") => {
            Some(Scalar::Integer(value.argument_count as u64))
        }
        (CodeQueryResultValue::CallResult { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CallResult { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallResult { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallResult { value }, "call_id") => {
            Some(Scalar::StableId(&value.call_id))
        }
        (CodeQueryResultValue::CallResult { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::CallResult { value }, "point_id") => {
            Some(Scalar::StableId(&value.point_id))
        }
        (CodeQueryResultValue::CallResult { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::CallResult { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal))
        }
        (CodeQueryResultValue::CallResult { value }, "value_id") => {
            Some(Scalar::Integer(value.value_id))
        }
        (CodeQueryResultValue::CallResult { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::CallResult { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
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
        (CodeQueryResultValue::CallArgument { value }, "literal_value") => {
            value.literal_value.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallableSignature { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallableSignature { value }, "declaration_id") => value
            .declaration
            .id
            .as_deref()
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallableSignature { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallableSignature { value }, "ordinal") => {
            Some(Scalar::Integer(value.ordinal as u64))
        }
        (CodeQueryResultValue::CallableSignature { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallableSignature { value }, "role") => {
            Some(Scalar::ConstrainedEnum(value.role))
        }
        (CodeQueryResultValue::CallableSignature { value }, "first_parameter") => {
            value.first_parameter.as_deref().map(Scalar::String)
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
        (CodeQueryResultValue::CallableSignature { value }, "python_method_kind") => {
            value.python_method_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallableSignature { value }, "python_owner_is_metaclass") => {
            value.python_owner_is_metaclass.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CallableSignature { value }, "python_owner_is_zope_interface") => {
            value.python_owner_is_zope_interface.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CallableSignature { value }, "python_used_in_class_body") => {
            value.python_used_in_class_body.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CallableSignature { value }, "python_no_args_with_decorator") => {
            value.python_no_args_with_decorator.map(Scalar::Boolean)
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
        (CodeQueryResultValue::CallableSignature { value }, "special_method_status") => {
            value.special_method_status.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "scope_id") => {
            Some(Scalar::StableId(&value.scope_id))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "scope_kind") => {
            Some(Scalar::ConstrainedEnum(value.scope_kind))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "identity") => {
            value.identity.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "trivial") => {
            Some(Scalar::Boolean(value.trivial))
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "parent_call_id") => {
            value.parent_call_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::LiteralOccurrence { value }, "argument_index") => value
            .argument_index
            .map(|index| Scalar::Integer(index as u64)),
        (CodeQueryResultValue::CallableMetrics { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallableMetrics { value }, "callable_id") => value
            .callable_id
            .as_deref()
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallableMetrics { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallableMetrics { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::CallableMetrics { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::CallableMetrics { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallableMetrics { value }, "max_nesting") => value
            .max_nesting
            .map(|metric| Scalar::Integer(metric as u64)),
        (CodeQueryResultValue::CallableMetrics { value }, "cognitive_complexity") => value
            .cognitive_complexity
            .map(|metric| Scalar::Integer(metric as u64)),
        (CodeQueryResultValue::CallableMetrics { value }, "owned_body_span_lines") => value
            .owned_body_span_lines
            .map(|metric| Scalar::Integer(metric as u64)),
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
        (CodeQueryResultValue::DecoratedParameter { value }, "value_id") => {
            value.value_id.as_deref().map(Scalar::StableId)
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
        (CodeQueryResultValue::DecoratedParameter { value }, "annotation_type_id") => value
            .annotation_type
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref())
            .map(Scalar::StableId),
        (CodeQueryResultValue::DecoratedParameter { value }, "annotation_type_name") => value
            .annotation_type
            .as_ref()
            .map(|declaration| Scalar::String(&declaration.fq_name)),
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
        (CodeQueryResultValue::CallBinding { value }, "program_point_id") => {
            value.program_point_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "group_id") => {
            value.group_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "argument_id") => {
            value.argument_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "binding_id") => {
            value.binding_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "literal_value") => {
            value.literal_value.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "path_identity") => {
            value.path_identity.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "target_id") => value
            .target
            .as_ref()
            .and_then(|target| target.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallBinding { value }, "declared_target_id") => {
            value.declared_target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "semantic_target_id") => {
            value.semantic_target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_callable_id") => {
            value.model_callable_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "formal_layout_id") => {
            value.formal_layout_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "target_origin") => {
            value.target_origin.map(Scalar::ConstrainedEnum)
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
        (CodeQueryResultValue::CallBinding { value }, "selector_exact") => {
            Some(Scalar::Boolean(value.selector_exact))
        }
        (CodeQueryResultValue::CallBinding { value }, "selector_proof") => {
            value.selector_proof.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_id") => {
            value.selector_summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_model_id") => value
            .selector_summary_model_id
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_pack_id") => value
            .selector_summary_pack_id
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_active_set_hash") => value
            .selector_summary_active_set_hash
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_pack_digest") => value
            .selector_summary_pack_digest
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_pack_version") => value
            .selector_summary_pack_version
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_record_id") => value
            .selector_summary_record_id
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_origin") => {
            value.selector_summary_origin.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_model_proof") => value
            .selector_summary_model_proof
            .map(Scalar::ConstrainedEnum),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_completeness") => value
            .selector_summary_completeness
            .map(Scalar::ConstrainedEnum),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_producer") => value
            .selector_summary_producer
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "selector_summary_producer_version") => value
            .selector_summary_producer_version
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "signature_id") => {
            value.signature_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "receiver_type_id") => {
            value.receiver_type_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallBinding { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_active_set_hash") => {
            value.model_active_set_hash.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_pack_digest") => {
            value.model_pack_digest.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_pack_version") => {
            value.model_pack_version.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_record_id") => {
            value.model_record_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_activation_status") => {
            value.model_activation_status.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_activation_reason") => {
            value.model_activation_reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_activation_source_kind") => value
            .model_activation_source_kind
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "model_activation_source_id") => value
            .model_activation_source_id
            .as_deref()
            .map(Scalar::String),
        (CodeQueryResultValue::CallBinding { value }, "model_origin") => {
            value.model_origin.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_proof") => {
            value.model_proof.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_completeness") => {
            value.model_completeness.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_ambiguous") => {
            value.model_ambiguous.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_producer") => {
            value.model_producer.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallBinding { value }, "model_producer_version") => {
            value.model_producer_version.as_deref().map(Scalar::String)
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
        (CodeQueryResultValue::CallBinding { value }, "conversion_status") => {
            Some(Scalar::ConstrainedEnum(value.conversion_status))
        }
        (CodeQueryResultValue::CallBinding { value }, "conversion_reason") => value
            .conversion_reason
            .map(|reason| Scalar::ConstrainedEnum(reason.label())),
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
        (CodeQueryResultValue::CallEffect { value }, "execution_timing") => {
            value.execution_timing.map(Scalar::ConstrainedEnum)
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
        (CodeQueryResultValue::CallResultContract { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallResultContract { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallResultContract { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallResultContract { value }, "target_id") => {
            value.target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CallResultContract { value }, "callee_id") => value
            .callee
            .as_ref()
            .and_then(|callee| callee.id.as_deref())
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::CallResultContract { value }, "callee_symbol") => {
            value.callee_symbol.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultContract { value }, "result_ordinal") => value
            .result_ordinal
            .map(|ordinal| Scalar::Integer(u64::from(ordinal))),
        (CodeQueryResultValue::CallResultContract { value }, "condition_result_ordinal") => value
            .condition_result_ordinal
            .map(|ordinal| Scalar::Integer(u64::from(ordinal))),
        (CodeQueryResultValue::CallResultContract { value }, "predicate") => {
            value.predicate.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultContract { value }, "result_success_predicate") => {
            value.result_success_predicate.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultContract { value }, "proof") => {
            value.proof.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultContract { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallResultContract { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultContract { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultContract { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultContract { value }, "summary_id") => {
            value.summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultContract { value }, "arm_count") => {
            Some(Scalar::Integer(value.arm_count as u64))
        }
        (CodeQueryResultValue::CallResultContract { value }, "modeled_arm_count") => {
            Some(Scalar::Integer(value.modeled_arm_count as u64))
        }
        (CodeQueryResultValue::CallResultContract { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::CallResultContract { value }, "result_use_count") => value
            .result_use_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::CallResultContract { value }, "unguarded_result_use_count") => value
            .unguarded_result_use_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::CallResultContract { value }, "use_validation") => {
            value.use_validation.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultContract { value }, "use_validation_coverage") => {
            value.use_validation_coverage.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultContract { value }, "success_guard_count") => {
            Some(Scalar::Integer(value.success_guard_count as u64))
        }
        (CodeQueryResultValue::CallResultContract { value }, "fresh_allocation") => {
            Some(Scalar::Boolean(value.fresh_allocation))
        }
        (CodeQueryResultValue::CallResultContract { value }, "member_contract_count") => {
            Some(Scalar::Integer(value.member_contract_count as u64))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "result_ordinal") => value
            .result_ordinal
            .map(|ordinal| Scalar::Integer(ordinal as u64)),
        (CodeQueryResultValue::CallResultObligation { value }, "obligation_kind") => {
            value.obligation_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "failure_predicate") => {
            value.failure_predicate.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "provenance") => {
            value.provenance.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "obligation_basis") => {
            value.obligation_basis.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "result_use") => {
            Some(Scalar::ConstrainedEnum(value.result_use))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "result_use_detail") => {
            value.result_use_detail.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "summary_id") => {
            value.summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CallResultObligation { value }, "arm_count") => {
            Some(Scalar::Integer(value.arm_count as u64))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "modeled_arm_count") => {
            Some(Scalar::Integer(value.modeled_arm_count as u64))
        }
        (CodeQueryResultValue::CallResultObligation { value }, "terminal") => {
            Some(Scalar::Boolean(value.terminal))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "origin_id") => value
            .origin
            .as_ref()
            .map(|origin| Scalar::StableId(&origin.id)),
        (CodeQueryResultValue::ResultSubjectUse { value }, "subject_id") => {
            value.subject_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "artifact_id") => {
            value.artifact_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "procedure_id") => {
            value.procedure_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "receiver_call_id") => {
            value.receiver_call_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "receiver_site_id") => {
            value.receiver_site_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "receiver_site_ast_id") => {
            value.receiver_site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "receiver_point_id") => {
            value.receiver_point_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome.label()))
        }
        (CodeQueryResultValue::ResultSubjectUse { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "acquisition_id") => {
            Some(Scalar::StableId(&value.acquisition_id))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "acquisition_site_id") => {
            Some(Scalar::StableId(&value.acquisition_site_id))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "acquisition_site_ast_id") => {
            Some(Scalar::StableId(&value.acquisition_site_ast_id))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "operation_point_id") => {
            Some(Scalar::StableId(&value.operation_point_id))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "operation_site_id") => {
            value.operation_site_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "operation_site_ast_id") => {
            value.operation_site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "result_ordinal") => {
            Some(Scalar::Integer(u64::from(value.result_ordinal)))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "condition_result_ordinal") => value
            .condition_result_ordinal
            .map(|ordinal| Scalar::Integer(u64::from(ordinal))),
        (CodeQueryResultValue::ResultContractUse { value }, "acquisition_predicate") => {
            value.acquisition_predicate.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "result_success_predicate") => {
            value.result_success_predicate.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "required_predicate") => {
            value.required_predicate.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "use_kind") => {
            Some(Scalar::ConstrainedEnum(value.use_kind))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "timing") => {
            Some(Scalar::ConstrainedEnum(value.timing))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "applicability") => {
            Some(Scalar::ConstrainedEnum(value.applicability))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "guard") => {
            Some(Scalar::ConstrainedEnum(value.guard))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::ResultContractUse { value }, "member") => {
            value.member.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "parameter_count") => value
            .parameter_count
            .map(|count| Scalar::Integer(u64::from(count))),
        (CodeQueryResultValue::ResultContractUse { value }, "parameter_ordinal") => value
            .parameter_ordinal
            .map(|ordinal| Scalar::Integer(u64::from(ordinal))),
        (CodeQueryResultValue::ResultContractUse { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ResultContractUse { value }, "summary_id") => {
            value.summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "acquisition_id") => {
            Some(Scalar::StableId(&value.acquisition_id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "acquisition_site_id") => {
            Some(Scalar::StableId(&value.acquisition_site_id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "acquisition_site_ast_id") => {
            Some(Scalar::StableId(&value.acquisition_site_ast_id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "condition_result_ordinal") => {
            Some(Scalar::Integer(u64::from(value.condition_result_ordinal)))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "condition_value_id") => {
            value.condition_value_id.map(Scalar::Integer)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "failure_edge_id") => {
            value.failure_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "consumer_point_id") => {
            Some(Scalar::StableId(&value.consumer_point_id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "consumer_call_id") => {
            value.consumer_call_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "consumer_site_id") => {
            value.consumer_site_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "consumer_site_ast_id") => {
            value.consumer_site_ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "operand_value_id") => {
            Some(Scalar::Integer(value.operand_value_id))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "binding_value_id") => {
            value.binding_value_id.map(Scalar::Integer)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "establishment_point_id") => {
            value
                .establishment_point_id
                .as_deref()
                .map(Scalar::StableId)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "establishment_value_id") => {
            value.establishment_value_id.map(Scalar::Integer)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "failure_provenance") => {
            Some(Scalar::ConstrainedEnum(value.failure_provenance))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "consumer") => {
            Some(Scalar::ConstrainedEnum(value.consumer))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "argument_ordinal") => value
            .argument_ordinal
            .map(|ordinal| Scalar::Integer(u64::from(ordinal))),
        (CodeQueryResultValue::ResultContractFailureUse { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ResultContractFailureUse { value }, "summary_id") => {
            value.summary_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::NilnessOperation { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "operation_point_id") => {
            Some(Scalar::StableId(&value.operation_point_id))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "subject_value_id") => {
            Some(Scalar::Integer(value.subject_value_id))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::NilnessOperation { value }, "use_kind") => {
            Some(Scalar::ConstrainedEnum(value.use_kind))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "fact") => {
            Some(Scalar::ConstrainedEnum(value.fact))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "origin") => {
            Some(Scalar::ConstrainedEnum(value.origin))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::NilnessOperation { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::SwitchCoverage { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "switch_fact_id") => {
            Some(Scalar::Integer(u64::from(value.switch_fact_id)))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "selector_value_id") => {
            value.selector_value_id.map(Scalar::Integer)
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "selector_domain") => {
            Some(Scalar::ConstrainedEnum(value.selector_domain))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "case_count") => {
            Some(Scalar::Integer(value.case_count as u64))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "has_true_case") => {
            Some(Scalar::Boolean(value.has_true_case))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "has_false_case") => {
            Some(Scalar::Boolean(value.has_false_case))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "default_present") => {
            Some(Scalar::Boolean(value.default_present))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::SwitchCoverage { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "assignment_point_id") => {
            value.assignment_point_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "target_value_id") => {
            value.target_value_id.map(Scalar::Integer)
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "rhs_value_id") => {
            value.rhs_value_id.map(Scalar::Integer)
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "relation_kind") => {
            Some(Scalar::ConstrainedEnum(value.relation_kind))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "storage_kind") => {
            Some(Scalar::ConstrainedEnum(value.storage_kind))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::AssignmentRelation { value }, "reason") => {
            value.reason.map(Scalar::String)
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "call_id") => {
            Some(Scalar::StableId(&value.call_id))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "call_point_id") => {
            Some(Scalar::StableId(&value.call_point_id))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "ast_id") => {
            value.ast_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "role") => {
            Some(Scalar::ConstrainedEnum(value.role))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "ordinal") => value
            .ordinal
            .map(|ordinal| Scalar::Integer(u64::from(ordinal))),
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "value_id") => {
            Some(Scalar::StableId(&value.value_id))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "object_id") => {
            value.object_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "object_cardinality") => {
            value.object_cardinality.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "timing") => {
            Some(Scalar::ConstrainedEnum(value.timing))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::DetachedTaskTransfer { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "procedure_id") => {
            Some(Scalar::DeclarationIdentity(&value.procedure_id))
        }
        (CodeQueryResultValue::ProcedureEffect { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
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
        (CodeQueryResultValue::ProcedureEffect { value }, "execution_timing") => {
            value.execution_timing.map(Scalar::ConstrainedEnum)
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
        (CodeQueryResultValue::DispatchTarget { value }, "target_fq_name") => {
            value.target_fq_name.as_deref().map(Scalar::String)
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
        (CodeQueryResultValue::PythonHierarchyFact { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "root_id") => {
            Some(Scalar::StableId(&value.root_id))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "fact_kind") => {
            Some(Scalar::ConstrainedEnum(value.fact_kind))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "ordinal") => {
            value.ordinal.map(|ordinal| Scalar::Integer(ordinal as u64))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "base_spelling") => {
            value.base_spelling.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "base_resolution") => {
            value.base_resolution.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "root_declaration_id") => {
            value.root_declaration_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "declaration_id") => {
            value.declaration_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "owner_id") => {
            value.owner_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "target_id") => {
            value.target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "target_owner_id") => {
            value.target_owner_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "member_name") => {
            value.member_name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "mro_rank") => {
            value.mro_rank.map(|rank| Scalar::Integer(rank as u64))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "target_non_trivial") => {
            value.target_non_trivial.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "target_reads_self") => {
            value.target_reads_self.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "base_branch_definition_count") => {
            value
                .base_branch_definition_count
                .map(|count| Scalar::Integer(count as u64))
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "has_strict_ordering") => {
            value.has_strict_ordering.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "has_non_strict_ordering") => {
            value.has_non_strict_ordering.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "total_ordering_decorator") => {
            value.total_ordering_decorator.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "inherited_ne_present") => {
            value.inherited_ne_present.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonHierarchyFact { value }, "inherited_ne_delegates") => {
            value.inherited_ne_delegates.map(Scalar::Boolean)
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
        (CodeQueryResultValue::ReceiverEvidence { value }, "model_id") => {
            value.model_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "pack_id") => {
            value.pack_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "factory_id") => {
            value.factory_id.as_deref().map(Scalar::DeclarationIdentity)
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::ReceiverEvidence { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "site_id") => {
            Some(Scalar::StableId(&value.site_id))
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "program_point_id") => {
            value.program_point_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "candidate_index") => {
            Some(Scalar::Integer(value.candidate_index as u64))
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "object_id") => {
            value.object_id.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "object_cardinality") => {
            value.object_cardinality.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::PointsToCandidate { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
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
        (CodeQueryResultValue::Export { value }, "definition_status") => value
            .local_definition
            .as_ref()
            .map(|definition| Scalar::ConstrainedEnum(definition.status())),
        (CodeQueryResultValue::Export { value }, "definition_binding_name") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::String(&binding.name)),
        (CodeQueryResultValue::Export { value }, "definition_binding_kind") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::ConstrainedEnum(&binding.kind)),
        (CodeQueryResultValue::Export { value }, "definition_binding_start_byte") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::Integer(binding.start_byte as u64)),
        (CodeQueryResultValue::Export { value }, "definition_binding_end_byte") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::Integer(binding.end_byte as u64)),
        (CodeQueryResultValue::Export { value }, "definition_binding_start_line") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::Integer(binding.range.start_line as u64)),
        (CodeQueryResultValue::Export { value }, "definition_binding_start_column") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::Integer(binding.range.start_column as u64)),
        (CodeQueryResultValue::Export { value }, "definition_binding_end_line") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::Integer(binding.range.end_line as u64)),
        (CodeQueryResultValue::Export { value }, "definition_binding_end_column") => value
            .local_definition
            .as_ref()
            .and_then(|definition| definition.binding())
            .map(|binding| Scalar::Integer(binding.range.end_column as u64)),
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
        (CodeQueryResultValue::ReferenceEdge { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::ReferenceEdge { value }, "source_id") => value
            .enclosing_declaration
            .as_ref()
            .and_then(|declaration| declaration.id.as_deref())
            .map(Scalar::DeclarationIdentity),
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
        (CodeQueryResultValue::StateEvent { value }, "read_cause") => {
            value.read_cause.map(Scalar::ConstrainedEnum)
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
        (CodeQueryResultValue::BindingInitializerCall { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::BindingInitializerCall { value }, "establishment_event_id") => {
            Some(Scalar::StableId(&value.establishment_event_id))
        }
        (CodeQueryResultValue::BindingInitializerCall { value }, "site_ast_id") => {
            Some(Scalar::StableId(&value.site_ast_id))
        }
        (CodeQueryResultValue::BindingInitializerCall { value }, "initializer_role") => {
            Some(Scalar::ConstrainedEnum(value.initializer_role))
        }
        (CodeQueryResultValue::BindingInitializerCall { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
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
        (CodeQueryResultValue::FailureHandlerState { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "catch_ast_id") => {
            Some(Scalar::StableId(&value.catch_ast_id))
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "caught_type") => value
            .caught_type
            .as_deref()
            .map(Scalar::DeclarationIdentity),
        (CodeQueryResultValue::FailureHandlerState { value }, "caught_type_relation") => {
            value.caught_type_relation.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "has_filter") => {
            value.has_filter.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::FailureHandlerState { value }, "rethrow_kind") => {
            value.rethrow_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::BranchRelation { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::BranchRelation { value }, "owner_id") => {
            Some(Scalar::StableId(&value.owner_id))
        }
        (CodeQueryResultValue::BranchRelation { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::BranchRelation { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::BranchRelation { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::BranchRelation { value }, "reason") => {
            value.reason.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::BranchRelation { value }, "orientation") => {
            value.orientation.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::BranchRelation { value }, "earlier_ordinal") => {
            Some(Scalar::Integer(value.earlier_ordinal as u64))
        }
        (CodeQueryResultValue::BranchRelation { value }, "later_ordinal") => {
            Some(Scalar::Integer(value.later_ordinal as u64))
        }
        (CodeQueryResultValue::LoopRelation { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::LoopRelation { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::LoopRelation { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::LoopRelation { value }, "loop_kind") => {
            Some(Scalar::ConstrainedEnum(value.loop_kind))
        }
        (CodeQueryResultValue::LoopRelation { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::LoopRelation { value }, "repeat_edge_id") => {
            value.repeat_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CppExpression { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CppExpression { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::CppExpression { value }, "kind") => {
            Some(Scalar::ConstrainedEnum(value.kind))
        }
        (CodeQueryResultValue::CppExpression { value }, "name") => {
            value.name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CppExpression { value }, "type_text") => {
            value.type_text.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CppExpression { value }, "type_form") => {
            Some(Scalar::ConstrainedEnum(value.type_form))
        }
        (CodeQueryResultValue::CppExpression { value }, "signedness") => {
            Some(Scalar::ConstrainedEnum(value.signedness))
        }
        (CodeQueryResultValue::CppExpression { value }, "width_bits") => {
            value.width_bits.map(u64::from).map(Scalar::Integer)
        }
        (CodeQueryResultValue::CppExpression { value }, "literal_text") => {
            value.literal_text.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CppExpression { value }, "integer_value") => {
            value.integer_value.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CppExpression { value }, "array_extent") => {
            value.array_extent.map(Scalar::Integer)
        }
        (CodeQueryResultValue::CppExpression { value }, "array_is_reference") => {
            value.array_is_reference.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "parameter_by_value") => {
            value.parameter_by_value.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "bit_field_width") => {
            value.bit_field_width.map(Scalar::Integer)
        }
        (CodeQueryResultValue::CppExpression { value }, "bit_field_anonymous") => {
            value.bit_field_anonymous.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "enum_scoped") => {
            value.enum_scoped.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "enum_ordinal") => {
            value.enum_ordinal.map(u64::from).map(Scalar::Integer)
        }
        (CodeQueryResultValue::CppExpression { value }, "enum_value") => {
            value.enum_value.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CppExpression { value }, "has_initializer") => {
            value.has_initializer.map(Scalar::Boolean)
        }
        (
            CodeQueryResultValue::CppExpression { value },
            "enum_has_implicit_before_nonreference",
        ) => value
            .enum_has_implicit_before_nonreference
            .map(Scalar::Boolean),
        (CodeQueryResultValue::CppExpression { value }, "return_top_level_const") => {
            value.return_top_level_const.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "member_function") => {
            value.member_function.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "member_function_const") => {
            value.member_function_const.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "type_size_bytes") => {
            value.type_size_bytes.map(Scalar::Integer)
        }
        (CodeQueryResultValue::CppExpression { value }, "type_size_exact") => {
            value.type_size_exact.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "sizeof_operand_kind") => {
            value.sizeof_operand_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CppExpression { value }, "sizeof_operand_is_parameter") => {
            value.sizeof_operand_is_parameter.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "sizeof_has_side_effect") => {
            value.sizeof_has_side_effect.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "loop_has_short_ancestor") => {
            value.loop_has_short_ancestor.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CppExpression { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::CppExpression { value }, "completeness_reason") => {
            value.completeness_reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::StatementReachability { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::StatementReachability { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::StatementReachability { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::StatementReachability { value }, "statement_kind") => {
            Some(Scalar::ConstrainedEnum(value.statement_kind))
        }
        (CodeQueryResultValue::StatementReachability { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::StatementReachability { value }, "reason") => {
            value.reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "procedure_id") => {
            Some(Scalar::StableId(&value.procedure_id))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "cleanup_id") => {
            Some(Scalar::StableId(&value.cleanup_id))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "cleanup_kind") => {
            Some(Scalar::ConstrainedEnum(value.cleanup_kind))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "pending_kind") => {
            Some(Scalar::ConstrainedEnum(value.pending_kind))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "source_id") => {
            Some(Scalar::StableId(&value.source.id))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "target_id") => {
            Some(Scalar::StableId(&value.target.id))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "verdict") => {
            Some(Scalar::ConstrainedEnum(value.verdict))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "coverage") => {
            Some(Scalar::ConstrainedEnum(value.coverage))
        }
        (CodeQueryResultValue::PendingCleanupFlow { value }, "reason") => {
            value.reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::PythonRuleFact { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "owner_id") => {
            value.owner_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "outcome") => {
            Some(Scalar::ConstrainedEnum(value.outcome))
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "reason") => {
            value.reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::RustMarkerImpl { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "language") => {
            Some(Scalar::String(value.language))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "trait") => {
            Some(Scalar::String(value.trait_kind))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "trait_proof") => {
            Some(Scalar::String(value.trait_proof))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "self_proof") => {
            Some(Scalar::String(value.self_proof))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "impl_coverage") => {
            Some(Scalar::String(value.impl_coverage))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "mapping_proof") => {
            Some(Scalar::String(value.mapping_proof))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "has_send_bound") => {
            Some(Scalar::Boolean(value.has_send_bound))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "has_sync_bound") => {
            Some(Scalar::Boolean(value.has_sync_bound))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "bounds") => {
            Some(Scalar::StringList(&value.bounds))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "bounds_proof") => {
            Some(Scalar::String(value.bounds_proof))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "stored") => {
            Some(Scalar::Boolean(value.stored))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "shared_access") => {
            Some(Scalar::String(value.shared_access))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "shared_ref_only") => {
            Some(Scalar::Boolean(value.shared_ref_only))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "uses_proof") => {
            Some(Scalar::String(value.uses_proof))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "completeness") => {
            Some(Scalar::String(value.completeness))
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "parameter") => {
            value.parameter.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RustMarkerImpl { value }, "declaration_parameter_ordinal") => {
            value.declaration_parameter_ordinal.map(Scalar::Integer)
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "language") => {
            Some(Scalar::ConstrainedEnum(value.language))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "relation") => {
            Some(Scalar::ConstrainedEnum(value.relation))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "origin_id") => {
            Some(Scalar::StableId(&value.origin_id))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "origin_kind") => {
            Some(Scalar::ConstrainedEnum(value.origin_kind))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "invalidation_cause") => {
            value.invalidation_cause.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "access_kind") => {
            Some(Scalar::ConstrainedEnum(value.access_kind))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "strength") => {
            Some(Scalar::ConstrainedEnum(value.strength))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "path_proven") => {
            Some(Scalar::Boolean(value.path_proven))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "bounds") => {
            Some(Scalar::ConstrainedEnum(value.bounds))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "byte_offset") => {
            value.byte_offset.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "byte_extent") => {
            value.byte_extent.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "access_width") => {
            value.access_width.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "proof") => {
            Some(Scalar::ConstrainedEnum(value.proof))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::RustPointerFinding { value }, "reason") => {
            value.reason.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "explicit_value_returns") => value
            .explicit_value_returns
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "none_returns") => value
            .none_returns
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "explicit_return_statements") => value
            .explicit_return_statements
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "fallthrough_none_returns") => value
            .fallthrough_none_returns
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "mixed_returns") => {
            value.mixed_returns.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_async") => {
            value.is_async.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_generator") => {
            value.is_generator.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "test_scope") => {
            value.test_scope.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "terminal_elif_else") => {
            value.terminal_elif_else.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "tuple_return_count") => value
            .tuple_return_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "distinct_tuple_arities") => value
            .distinct_tuple_arities
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "tuple_return_arities") => value
            .tuple_return_arities
            .as_deref()
            .map(Scalar::IntegerList),
        (CodeQueryResultValue::PythonRuleFact { value }, "assignment_target_count") => value
            .assignment_target_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "assignment_arity_match") => {
            value.assignment_arity_match.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "mixed_tuple_arities") => {
            value.mixed_tuple_arities.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "annotated") => {
            value.annotated.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "return_contract") => {
            value.return_contract.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "result_use") => {
            value.result_use.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "forwarded") => {
            value.forwarded.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "callable_evaluation_time") => {
            value.callable_evaluation_time.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "default_equivalent") => {
            value.default_equivalent.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "target_id") => {
            value.target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "returns_receiver") => {
            value.returns_receiver.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "parameter_count") => value
            .parameter_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "scope_is_public") => {
            value.scope_is_public.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "docstring_present") => {
            value.docstring_present.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "docstring_value") => {
            value.docstring_value.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "comment_block_text") => {
            value.comment_block_text.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "comment_block_lines") => {
            value.comment_block_lines.as_deref().map(Scalar::StringList)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "lines_of_code") => value
            .lines_of_code
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "decorator_count") => value
            .decorator_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "is_override") => {
            value.is_override.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_property_accessor") => {
            value.is_property_accessor.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "public_method_count") => value
            .public_method_count
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "has_inheritance") => {
            value.has_inheritance.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "has_subclasses") => {
            value.has_subclasses.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "has_special_method") => {
            value.has_special_method.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_decorated") => {
            value.is_decorated.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_probable_mixin") => {
            value.is_probable_mixin.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_stateful") => {
            value.is_stateful.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_top_level") => {
            value.is_top_level.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "cyclomatic_complexity") => value
            .cyclomatic_complexity
            .map(|count| Scalar::Integer(count as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "url_prefix") => {
            value.url_prefix.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "variable_id") => {
            value.variable_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "name") => {
            value.name.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "scope_kind") => {
            value.scope_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_global") => {
            value.is_global.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_nonlocal") => {
            value.is_nonlocal.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_builtin") => {
            value.is_builtin.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "call_callee") => {
            value.call_callee.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "has_read") => {
            value.has_read.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "definition_kind") => {
            value.definition_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "definition_order") => value
            .definition_order
            .map(|order| Scalar::Integer(order as u64)),
        (CodeQueryResultValue::PythonRuleFact { value }, "first_definition") => {
            value.first_definition.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "definition_is_unused") => {
            value.definition_is_unused.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "annotation_only") => {
            value.annotation_only.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "annotated_assignment") => {
            value.annotated_assignment.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_abstract") => {
            value.is_abstract.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_overriding_method") => {
            value.is_overriding_method.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "is_overridden_method") => {
            value.is_overridden_method.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "reachability") => {
            value.reachability.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "access_kind") => {
            value.access_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "nested_scope") => {
            value.nested_scope.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "in_main_guard") => {
            value.in_main_guard.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "optimizing_parameter") => {
            value.optimizing_parameter.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "self_assignment") => {
            value.self_assignment.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "related_scope_kind") => {
            value.related_scope_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "related_has_definition_outside_main") => {
            value
                .related_has_definition_outside_main
                .map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "related_has_deletion") => {
            value.related_has_deletion.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "related_has_import") => {
            value.related_has_import.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "related_is_pytest_fixture") => {
            value.related_is_pytest_fixture.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "loop_has_body_read") => {
            value.loop_has_body_read.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "loop_policy_excluded") => {
            value.loop_policy_excluded.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "nested_loop_reused") => {
            value.nested_loop_reused.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::PythonRuleFact { value }, "nested_loop_has_outer_use") => {
            value.nested_loop_has_outer_use.map(Scalar::Boolean)
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
        (CodeQueryResultValue::Guard { value }, "constant") => value.constant.map(Scalar::Boolean),
        (CodeQueryResultValue::Guard { value }, "null_on_true") => {
            value.null_on_true.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::Guard { value }, "null_target_id") => {
            value.null_target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Guard { value }, "equality_negated") => {
            value.equality_negated.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::Guard { value }, "integer_relation") => {
            value.integer_relation.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::Guard { value }, "constant_value") => {
            value.constant_value.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "guarded_value") => {
            value.guarded_value.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "classes_value") => {
            value.classes_value.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "member_value") => {
            value.member_value.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "opaque_digest") => {
            value.opaque_digest.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "subject_value") => {
            value.subject_value.map(Scalar::Integer)
        }
        (CodeQueryResultValue::Guard { value }, "true_edge_id") => {
            value.true_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Guard { value }, "true_target_id") => {
            value.true_target_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Guard { value }, "false_edge_id") => {
            value.false_edge_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::Guard { value }, "false_target_id") => {
            value.false_target_id.as_deref().map(Scalar::StableId)
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
        (CodeQueryResultValue::DependencyEvidence { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "ecosystem") => {
            Some(Scalar::String(&value.ecosystem))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "package") => {
            Some(Scalar::String(&value.package))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "evidence_kind") => {
            Some(Scalar::String(&value.evidence_kind))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "scope") => {
            Some(Scalar::String(&value.scope))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "source_digest") => {
            Some(Scalar::String(&value.source_digest))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "version_requirement") => {
            value.version_requirement.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "exact_version") => {
            value.exact_version.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "source") => {
            value.source.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "locator") => {
            value.locator.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "declared_by") => {
            value.declared_by.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "start_byte") => {
            Some(Scalar::Integer(value.start_byte as u64))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "end_byte") => {
            Some(Scalar::Integer(value.end_byte as u64))
        }
        (CodeQueryResultValue::DependencyEvidence { value }, "complete") => {
            Some(Scalar::Boolean(value.complete))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "id") => {
            Some(Scalar::StableId(&value.id))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "fact_id") => {
            Some(Scalar::StableId(&value.fact_id))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "parent_id") => {
            value.parent_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "value_id") => {
            value.value_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "path") => {
            Some(Scalar::String(&value.path))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "format") => {
            Some(Scalar::ConstrainedEnum(value.format))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "node_kind") => {
            Some(Scalar::ConstrainedEnum(value.node_kind))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "role") => {
            value.role.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "scalar_kind") => {
            value.scalar_kind.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "value") => {
            value.value.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "provenance") => {
            Some(Scalar::ConstrainedEnum(value.provenance))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "completeness") => {
            Some(Scalar::ConstrainedEnum(value.completeness))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "key") => {
            value.key.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "occurrence") => value
            .occurrence
            .map(|occurrence| Scalar::Integer(u64::from(occurrence))),
        (CodeQueryResultValue::ConfigurationFact { value }, "index") => {
            value.index.map(|index| Scalar::Integer(u64::from(index)))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "route") => {
            Some(Scalar::String(&value.route))
        }
        (CodeQueryResultValue::ConfigurationFact { value }, "ordinal") => {
            Some(Scalar::Integer(u64::from(value.ordinal)))
        }
        (CodeQueryResultValue::CrossDomain { value }, "id") => Some(Scalar::StableId(&value.id)),
        (CodeQueryResultValue::CrossDomain { value }, "operator") => {
            Some(Scalar::ConstrainedEnum(value.operator))
        }
        (CodeQueryResultValue::CrossDomain { value }, "domain") => {
            Some(Scalar::ConstrainedEnum(value.domain))
        }
        (CodeQueryResultValue::CrossDomain { value }, "relation") => {
            value.relation.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CrossDomain { value }, "binding") => {
            value.binding.map(Scalar::ConstrainedEnum)
        }
        (CodeQueryResultValue::CrossDomain { value }, "key") => {
            value.key.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CrossDomain { value }, "code_id") => {
            value.code_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CrossDomain { value }, "mitigated") => {
            value.mitigated.map(Scalar::Boolean)
        }
        (CodeQueryResultValue::CrossDomain { value }, "dependency_id") => {
            value.dependency_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CrossDomain { value }, "owner") => {
            value.owner.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CrossDomain { value }, "mapping_id") => {
            value.mapping_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CrossDomain { value }, "code_path") => {
            value.code_path.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CrossDomain { value }, "configuration_id") => {
            value.configuration_id.as_deref().map(Scalar::StableId)
        }
        (CodeQueryResultValue::CrossDomain { value }, "configuration_path") => {
            value.configuration_path.as_deref().map(Scalar::String)
        }
        (CodeQueryResultValue::CrossDomain { value }, "path") => Some(Scalar::String(&value.path)),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key_domain", rename_all = "snake_case")]
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
    ClassSetRow {
        id: String,
    },
    AbsentMemberFinding {
        id: String,
    },
    AbsentMemberWitness {
        id: String,
        finding_id: String,
    },
    TaintFinding {
        id: String,
    },
    File,
    DependencyEvidence {
        id: String,
        ecosystem: String,
        package: String,
        evidence_kind: String,
        scope: String,
        source_digest: String,
        version_requirement: Option<String>,
        exact_version: Option<String>,
        source: Option<String>,
        declared_by: Option<String>,
    },
    ConfigurationFact {
        id: String,
        fact_id: String,
    },
    CrossDomain {
        id: String,
        code_id: Option<String>,
        configuration_id: Option<String>,
    },
    ReferenceSite {
        target_id: Option<String>,
        target_fq_name: String,
    },
    CallSite {
        site_id: Option<String>,
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
    MemberTargetAnalysis {
        site_id: String,
    },
    ReceiverOutcome {
        id: String,
        site_id: String,
    },
    ReceiverEvidence {
        id: String,
        site_id: String,
    },
    PointsToCandidate {
        id: String,
        site_id: String,
    },
    FieldWriteValue {
        id: String,
        assignment_ast_id: String,
        rhs_ast_id: String,
        receiver_identity_id: String,
        member_target_id: String,
    },
    RuntimeKeyedReadValue {
        id: String,
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
    PythonHierarchyFact {
        id: String,
        root_id: String,
        declaration_id: Option<String>,
        owner_id: Option<String>,
        target_id: Option<String>,
        target_owner_id: Option<String>,
        fact_kind: String,
        outcome: String,
        coverage: String,
        reason: Option<String>,
        ancestry_basis: crate::analyzer::usages::python_class_hierarchy::PythonAncestryBasis,
    },
    CallShape {
        id: String,
        site_id: String,
    },
    CallResult {
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
    CallResultContract {
        id: String,
        site_id: String,
    },
    CallResultObligation {
        id: String,
        site_id: String,
    },
    ResultSubjectUse {
        id: String,
    },
    ResultContractUse {
        id: String,
        acquisition_id: String,
    },
    ResultContractFailureUse {
        id: String,
        acquisition_id: String,
    },
    NilnessOperation {
        id: String,
        procedure_id: String,
    },
    SwitchCoverage {
        id: String,
        procedure_id: String,
    },
    AssignmentRelation {
        id: String,
        procedure_id: String,
    },
    DetachedTaskTransfer {
        id: String,
        procedure_id: String,
    },
    ProcedureEffect {
        id: String,
        procedure_id: String,
        site_id: String,
    },
    CallableSignature {
        id: String,
        declaration_id: String,
        site_id: String,
    },
    LiteralOccurrence {
        id: String,
    },
    CallableMetrics {
        id: String,
        callable_id: Option<String>,
        site_id: String,
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
        local_definition: Option<DetailedCodeQueryExportLocalDefinition>,
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
    BindingInitializerCall {
        id: String,
        establishment_event_id: String,
        site_ast_id: String,
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
    BranchRelation {
        id: String,
        owner_id: String,
        relation: String,
        verdict: String,
    },
    LoopRelation {
        id: String,
        procedure_id: String,
    },
    CppExpression {
        id: String,
    },
    FailureHandlerState {
        id: String,
        catch_ast_id: String,
        verdict: String,
    },
    StatementReachability {
        id: String,
        procedure_id: String,
    },
    PendingCleanupFlow {
        id: String,
        procedure_id: String,
    },
    PythonRuleFact {
        id: String,
        relation: String,
    },
    RustMarkerImpl {
        id: String,
    },
    RustPointerFinding {
        id: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DetailedCodeQueryExportLocalDefinition {
    Defined {
        binding_name: String,
        binding_kind: String,
        start_byte: usize,
        end_byte: usize,
        range: CodeQueryRange,
    },
    Undefined,
    Unknown,
}

impl DetailedCodeQueryResult {
    pub fn take_semantic_receipt(&mut self) -> Option<CodeQuerySemanticReceipt> {
        self.semantic_receipt.take()
    }

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
                match candidate {
                    CodeQueryStableOwnerCandidate::Declaration { namespace, id } => {
                        assert!(!namespace.is_empty());
                        assert!(id.starts_with("decl:v1:"));
                    }
                    CodeQueryStableOwnerCandidate::Derived {
                        namespace,
                        derivation,
                        semantic_key,
                    } => {
                        assert!(!namespace.is_empty());
                        assert!(!semantic_key.is_empty());
                        match derivation {
                            CodeQueryStableOwnerDerivation::CanonicalAstIdentity
                            | CodeQueryStableOwnerDerivation::SemanticWireId => {}
                        }
                    }
                }
            }
            if let Some(wire_id) = semantic_wire_id(&evidence.key) {
                let candidate = evidence
                    .stable_owner_candidate
                    .as_ref()
                    .expect("semantic CodeQuery evidence requires its wire identity");
                assert!(matches!(
                    candidate,
                    CodeQueryStableOwnerCandidate::Derived {
                        derivation: CodeQueryStableOwnerDerivation::SemanticWireId,
                        semantic_key,
                        ..
                    } if semantic_key == wire_id
                ));
            }
            if let Some(sidecar) = &evidence.decorated_parameter {
                let CodeQueryResultValue::DecoratedParameter { value } = &result.value else {
                    panic!("decorated-parameter sidecar must accompany a decorated row");
                };
                assert_eq!(evidence.domain, DetailedCodeQueryDomain::DecoratedParameter);
                assert_eq!(
                    sidecar.procedure_id,
                    value.procedure_id.as_deref().unwrap_or_default()
                );
                assert_eq!(
                    sidecar.value_id,
                    value.value_id.as_deref().unwrap_or_default()
                );
                assert_eq!(
                    sidecar.port_id,
                    value.port_id.as_deref().unwrap_or_default()
                );
                assert_eq!(value.completion, "complete");
                assert_eq!(value.coverage, "complete");
                assert!(matches!(
                    sidecar.port,
                    crate::analyzer::semantic::DurablePortIdentity::Parameter { ordinal }
                        if value.parameter_ordinal == Some(ordinal as usize)
                ));
            } else if evidence.domain != DetailedCodeQueryDomain::DecoratedParameter {
                // The sidecar is deliberately scoped to the exact decorated
                // parameter result family and never leaks through another
                // detailed evidence constructor.
                assert!(evidence.decorated_parameter.is_none());
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
        if let Err(error) = row.field(field.name) {
            assert!(
                error.unknown_reason().is_some(),
                "registered field must project a value or typed unknown: {error}"
            );
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
        CodeQueryResultValue::CallResult { value } => Some((
            DetailedCodeQueryDomain::CallResult,
            DetailedCodeQueryKey::CallResult {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
        )),
        CodeQueryResultValue::CallResultContract { value } => Some((
            DetailedCodeQueryDomain::CallResultContract,
            DetailedCodeQueryKey::CallResultContract {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
        )),
        CodeQueryResultValue::CallResultObligation { value } => Some((
            DetailedCodeQueryDomain::CallResultObligation,
            DetailedCodeQueryKey::CallResultObligation {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
        )),
        CodeQueryResultValue::ResultSubjectUse { value } => Some((
            DetailedCodeQueryDomain::ResultSubjectUse,
            DetailedCodeQueryKey::ResultSubjectUse {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::ResultContractUse { value } => Some((
            DetailedCodeQueryDomain::ResultContractUse,
            DetailedCodeQueryKey::ResultContractUse {
                id: value.id.clone(),
                acquisition_id: value.acquisition_id.clone(),
            },
        )),
        CodeQueryResultValue::ResultContractFailureUse { value } => Some((
            DetailedCodeQueryDomain::ResultContractFailureUse,
            DetailedCodeQueryKey::ResultContractFailureUse {
                id: value.id.clone(),
                acquisition_id: value.acquisition_id.clone(),
            },
        )),
        CodeQueryResultValue::NilnessOperation { value } => Some((
            DetailedCodeQueryDomain::NilnessOperation,
            DetailedCodeQueryKey::NilnessOperation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::SwitchCoverage { value } => Some((
            DetailedCodeQueryDomain::SwitchCoverage,
            DetailedCodeQueryKey::SwitchCoverage {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::AssignmentRelation { value } => Some((
            DetailedCodeQueryDomain::AssignmentRelation,
            DetailedCodeQueryKey::AssignmentRelation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::LoopRelation { value } => Some((
            DetailedCodeQueryDomain::LoopRelation,
            DetailedCodeQueryKey::LoopRelation {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::CppExpression { value } => Some((
            DetailedCodeQueryDomain::CppExpression,
            DetailedCodeQueryKey::CppExpression {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::StatementReachability { value } => Some((
            DetailedCodeQueryDomain::StatementReachability,
            DetailedCodeQueryKey::StatementReachability {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::PendingCleanupFlow { value } => Some((
            DetailedCodeQueryDomain::PendingCleanupFlow,
            DetailedCodeQueryKey::PendingCleanupFlow {
                id: value.id.clone(),
                procedure_id: value.procedure_id.clone(),
            },
        )),
        CodeQueryResultValue::PythonRuleFact { value } => Some((
            DetailedCodeQueryDomain::PythonRuleFact,
            DetailedCodeQueryKey::PythonRuleFact {
                id: value.id.clone(),
                relation: value.relation.to_string(),
            },
        )),
        CodeQueryResultValue::RustMarkerImpl { value } => Some((
            DetailedCodeQueryDomain::RustMarkerImpl,
            DetailedCodeQueryKey::RustMarkerImpl {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::RustPointerFinding { value } => Some((
            DetailedCodeQueryDomain::RustPointerFinding,
            DetailedCodeQueryKey::RustPointerFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::DetachedTaskTransfer { value } => Some((
            DetailedCodeQueryDomain::DetachedTaskTransfer,
            DetailedCodeQueryKey::DetachedTaskTransfer {
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
        CodeQueryResultValue::ClassSetRow { value } => Some((
            DetailedCodeQueryDomain::ClassSetRow,
            DetailedCodeQueryKey::ClassSetRow {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::AbsentMemberFinding { value } => Some((
            DetailedCodeQueryDomain::AbsentMemberFinding,
            DetailedCodeQueryKey::AbsentMemberFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::AbsentMemberWitness { value } => Some((
            DetailedCodeQueryDomain::AbsentMemberWitness,
            DetailedCodeQueryKey::AbsentMemberWitness {
                id: value.id.clone(),
                finding_id: value.finding_id.clone(),
            },
        )),
        CodeQueryResultValue::TaintFinding { value } => Some((
            DetailedCodeQueryDomain::TaintFinding,
            DetailedCodeQueryKey::TaintFinding {
                id: value.id.clone(),
            },
        )),
        CodeQueryResultValue::DependencyEvidence { value } => Some((
            DetailedCodeQueryDomain::DependencyEvidence,
            DetailedCodeQueryKey::DependencyEvidence {
                id: value.id.clone(),
                ecosystem: value.ecosystem.clone(),
                package: value.package.clone(),
                evidence_kind: value.evidence_kind.clone(),
                scope: value.scope.clone(),
                source_digest: value.source_digest.clone(),
                version_requirement: value.version_requirement.clone(),
                exact_version: value.exact_version.clone(),
                source: value.source.clone(),
                declared_by: value.declared_by.clone(),
            },
        )),
        CodeQueryResultValue::ConfigurationFact { value } => Some((
            DetailedCodeQueryDomain::ConfigurationFact,
            DetailedCodeQueryKey::ConfigurationFact {
                id: value.id.clone(),
                fact_id: value.fact_id.clone(),
            },
        )),
        CodeQueryResultValue::PointsToCandidate { value } => Some((
            DetailedCodeQueryDomain::PointsToCandidate,
            DetailedCodeQueryKey::PointsToCandidate {
                id: value.id.clone(),
                site_id: value.site_id.clone(),
            },
        )),
        CodeQueryResultValue::CrossDomain { value } => Some((
            DetailedCodeQueryDomain::CrossDomain,
            DetailedCodeQueryKey::CrossDomain {
                id: value.id.clone(),
                code_id: value.code_id.clone(),
                configuration_id: value.configuration_id.clone(),
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
        | CodeQueryResultValue::MemberTargetAnalysis { .. }
        | CodeQueryResultValue::ReceiverOutcome { .. }
        | CodeQueryResultValue::ReceiverEvidence { .. }
        | CodeQueryResultValue::FieldWriteValue { .. }
        | CodeQueryResultValue::RuntimeKeyedReadValue { .. }
        | CodeQueryResultValue::DispatchOutcome { .. }
        | CodeQueryResultValue::DispatchTarget { .. }
        | CodeQueryResultValue::MemberFamily { .. }
        | CodeQueryResultValue::MemberFamilyEdge { .. }
        | CodeQueryResultValue::PythonHierarchyFact { .. }
        | CodeQueryResultValue::CallShape { .. }
        | CodeQueryResultValue::CallArgumentGroup { .. }
        | CodeQueryResultValue::CallArgument { .. }
        | CodeQueryResultValue::CallBinding { .. }
        | CodeQueryResultValue::CallEffect { .. }
        | CodeQueryResultValue::ProcedureEffect { .. }
        | CodeQueryResultValue::CallableSignature { .. }
        | CodeQueryResultValue::LiteralOccurrence { .. }
        | CodeQueryResultValue::CallableMetrics { .. }
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
        | CodeQueryResultValue::BindingInitializerCall { .. }
        | CodeQueryResultValue::FlowRelation { .. }
        | CodeQueryResultValue::ControlRelation { .. }
        | CodeQueryResultValue::BranchRelation { .. }
        | CodeQueryResultValue::FailureHandlerState { .. }
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
        | DetailedCodeQueryKey::CallResult { id, .. }
        | DetailedCodeQueryKey::ResultSubjectUse { id }
        | DetailedCodeQueryKey::TypestateFinding { id }
        | DetailedCodeQueryKey::TypestateWitness { id, .. }
        | DetailedCodeQueryKey::FlowEndpoint { id }
        | DetailedCodeQueryKey::FlowWitness { id, .. }
        | DetailedCodeQueryKey::AbsentMemberWitness { id, .. }
        | DetailedCodeQueryKey::TaintFinding { id }
        | DetailedCodeQueryKey::RustMarkerImpl { id }
        | DetailedCodeQueryKey::RustPointerFinding { id } => Some(id),
        DetailedCodeQueryKey::StructuralMatch { .. }
        | DetailedCodeQueryKey::Declaration { .. }
        | DetailedCodeQueryKey::File
        | DetailedCodeQueryKey::DependencyEvidence { .. }
        | DetailedCodeQueryKey::ConfigurationFact { .. }
        | DetailedCodeQueryKey::CrossDomain { .. }
        | DetailedCodeQueryKey::ReferenceSite { .. }
        // A call-site ID identifies the row, while its stable owner candidate
        // is the enclosing caller declaration.
        | DetailedCodeQueryKey::CallSite { .. }
        | DetailedCodeQueryKey::ExpressionSite { .. }
        | DetailedCodeQueryKey::JsxAttributeValue { .. }
        | DetailedCodeQueryKey::ReceiverAnalysis { .. }
        | DetailedCodeQueryKey::MemberTargetAnalysis { .. }
        | DetailedCodeQueryKey::ReceiverOutcome { .. }
        | DetailedCodeQueryKey::ReceiverEvidence { .. }
        | DetailedCodeQueryKey::PointsToCandidate { .. }
        | DetailedCodeQueryKey::FieldWriteValue { .. }
        | DetailedCodeQueryKey::RuntimeKeyedReadValue { .. }
        | DetailedCodeQueryKey::DispatchOutcome { .. }
        | DetailedCodeQueryKey::DispatchTarget { .. }
        | DetailedCodeQueryKey::MemberFamily { .. }
        | DetailedCodeQueryKey::MemberFamilyEdge { .. }
        | DetailedCodeQueryKey::PythonHierarchyFact { .. }
        | DetailedCodeQueryKey::CallShape { .. }
        | DetailedCodeQueryKey::CallArgumentGroup { .. }
        | DetailedCodeQueryKey::CallArgument { .. }
        | DetailedCodeQueryKey::CallBinding { .. }
        | DetailedCodeQueryKey::CallEffect { .. }
        | DetailedCodeQueryKey::CallResultContract { .. }
        | DetailedCodeQueryKey::CallResultObligation { .. }
        | DetailedCodeQueryKey::ResultContractUse { .. }
        | DetailedCodeQueryKey::ResultContractFailureUse { .. }
        | DetailedCodeQueryKey::NilnessOperation { .. }
        | DetailedCodeQueryKey::SwitchCoverage { .. }
        | DetailedCodeQueryKey::AssignmentRelation { .. }
        | DetailedCodeQueryKey::LoopRelation { .. }
        | DetailedCodeQueryKey::CppExpression { .. }
        | DetailedCodeQueryKey::StatementReachability { .. }
        | DetailedCodeQueryKey::PendingCleanupFlow { .. }
        // This query-derived id is not a semantic IR wire identity.
        | DetailedCodeQueryKey::PythonRuleFact { .. }
        | DetailedCodeQueryKey::ClassSetRow { .. }
        | DetailedCodeQueryKey::AbsentMemberFinding { .. }
        | DetailedCodeQueryKey::DetachedTaskTransfer { .. }
        | DetailedCodeQueryKey::ProcedureEffect { .. }
        | DetailedCodeQueryKey::CallableSignature { .. }
        | DetailedCodeQueryKey::LiteralOccurrence { .. }
        | DetailedCodeQueryKey::CallableMetrics { .. }
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
        | DetailedCodeQueryKey::BindingInitializerCall { .. }
        | DetailedCodeQueryKey::FlowRelation { .. }
        | DetailedCodeQueryKey::ControlRelation { .. }
        | DetailedCodeQueryKey::BranchRelation { .. }
        | DetailedCodeQueryKey::FailureHandlerState { .. }
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
        assert!(matches!(
            ToyDomain::Widget.query_value_kind(),
            ToyKind::Widget
        ));
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

#[cfg(test)]
mod registry {
    use super::*;

    /// #2956: the class-set Unknown reasons (`unknown:<label>` origins) are
    /// row values behind a registered open enum, so renaming `budget` to
    /// `solver_budget` and adding `semantic_budget`/`incomplete_root` moves
    /// no query's parse and the RQL schema version stays 1. Closing this enum
    /// would be the schema-version event.
    #[test]
    fn class_set_row_origin_is_an_open_enum_and_status_stays_closed() {
        use brokk_bifrost_flow::type_flow::ClassSetStatus;

        let fields = DetailedCodeQueryDomain::ClassSetRow.row_fields();
        let origin = fields
            .iter()
            .find(|field| field.name == "origin")
            .expect("class_set_row registers its origin field");
        assert!(
            matches!(
                origin.value_domain,
                Some(CodeQueryEnumDomain::Unenumerable(_))
            ),
            "the unknown:<reason> vocabulary grows with the language adapters: {origin:?}",
        );
        let status = fields
            .iter()
            .find(|field| field.name == "status")
            .expect("class_set_row registers its status field");
        assert_eq!(
            status.value_domain,
            Some(CodeQueryEnumDomain::Labels(ClassSetStatus::LABELS)),
            "the closed status vocabulary is unchanged",
        );
    }
}
