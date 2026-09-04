//! Declarative metadata for the public CodeQuery/RQL vocabulary.
//!
//! The registries in this module are deliberately executable metadata: parser
//! and validator dispatch use the generated enums, while the REPL and editor
//! use the same signatures and descriptions. Adding an entry without help or
//! a value shape is therefore a macro error, and every handler must match the
//! generated enum exhaustively.

use brokk_bifrost_core::analyzer::structural::control_relation::{
    ALL_CONTROL_EXIT_PARTITIONS, ALL_CONTROL_RELATION_KINDS, ControlExitPartition,
    ControlRelationKind,
};
use brokk_bifrost_core::analyzer::structural::flow_state::{
    ALL_FLOW_CERTAINTIES, ALL_FLOW_RELATIONS, ALL_FLOW_SUBJECT_KINDS, ALL_STATE_EVENT_CLASSES,
    FlowCertainty, FlowRelation, FlowSubjectKind, StateEventClass,
};
use brokk_bifrost_core::analyzer::structural::materialization::ALL_DECLARATION_ORIGINS;
use brokk_bifrost_core::analyzer::structural::occurrences::{
    ALL_NAMESPACES, ALL_OCCURRENCE_CLASSES, ALL_OCCURRENCE_ROLES,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    ALL_BINDING_KINDS, ALL_BOUNDARY_STATUSES, ALL_HOISTING_CLASSES, ALL_PRECEDENCE_TIERS,
    ALL_REJECTION_REASONS,
};
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    ALL_REWRITE_DOMAIN_KINDS, ALL_REWRITE_OUTCOME_KINDS, RewriteDomainKind, RewriteOutcomeKind,
};
use brokk_bifrost_core::analyzer::usages::model::{
    ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof,
};
use brokk_bifrost_core::schema_version::{
    SchemaVersionDescriptor, SchemaVersionRegistry, SchemaVersionResolution,
    UnsupportedSchemaVersion,
};
use std::sync::OnceLock;

use super::ir::{
    CandidateOutcomeLabel, FailureUseConsumer, FailureUseProvenance, JsxElementIdentity,
    MAX_CAPTURE_LENGTH, MAX_KWARG_NAME_LENGTH, SCHEMA_VERSION, UNATTRIBUTED_TIER_LABEL,
};

/// The single RQL schema version. The pre-1.0 lineage (versions 2 through 13,
/// every step auto-compatible with the next) carried no information, so it
/// was collapsed to this one version. Mint a new version only when an
/// existing query stops parsing or changes meaning.
const RQL_SCHEMA_VERSION: u32 = 1;
const RQL_SCHEMA_VERSIONS: &[SchemaVersionDescriptor] =
    &[SchemaVersionDescriptor::new(RQL_SCHEMA_VERSION, None, true)];

const _: () = assert!(RQL_SCHEMA_VERSION as u64 == SCHEMA_VERSION);

static RQL_SCHEMA_VERSION_REGISTRY: OnceLock<SchemaVersionRegistry> = OnceLock::new();

pub(crate) fn rql_schema_version_registry() -> &'static SchemaVersionRegistry {
    RQL_SCHEMA_VERSION_REGISTRY.get_or_init(|| {
        SchemaVersionRegistry::new(RQL_SCHEMA_VERSIONS)
            .expect("the compiled-in RQL schema lineage must be valid")
    })
}

pub fn supported_query_schema_versions() -> Vec<u64> {
    RQL_SCHEMA_VERSIONS
        .iter()
        .map(|descriptor| descriptor.version as u64)
        .collect()
}

pub fn resolve_rql_schema_version(
    authored_version: Option<u32>,
) -> Result<SchemaVersionResolution, UnsupportedSchemaVersion> {
    rql_schema_version_registry().resolve(authored_version)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueShape {
    Query,
    QueryList,
    QuerySteps,
    Pattern,
    PatternList,
    PatternMap,
    String,
    ParameterName,
    CaptureName,
    RegexString,
    StringList,
    StringPredicate,
    RegexPredicate,
    KindList,
    DeclaredVisibilityList,
    LanguageList,
    PositiveInteger,
    NonNegativeInteger,
    Arity,
    ResultDetail,
    ExecutionMode,
    SchemaVersion,
    TrueBoolean,
    ReferenceKindList,
    UsageProof,
    UsageSurface,
    CallTraversalCompleteness,
    ProtocolRef,
    ValueFlowPlanRef,
    TaintResultRef,
    OccurrenceFilter,
    OccurrenceClassList,
    OccurrenceRoleList,
    NamespaceList,
    ScopeFilter,
    BindingFilter,
    PathFilter,
    BindingKindList,
    BindingNameList,
    HoistingClassList,
    PrecedenceTierList,
    CandidateOutcomeList,
    BoundaryStatusList,
    GenerationSiteFilter,
    ExportFilter,
    GenerationKindList,
    GenerationInputList,
    ExportFormList,
    ExportNameList,
    DeclarationOriginList,
    Boolean,
    UsageKindList,
    OwnerRelationList,
    SiteClassList,
    StateEventClassList,
    FlowSubjectKindList,
    FlowRelationList,
    FlowCertaintyList,
    FailureUseProvenanceList,
    FailureUseConsumerList,
    RewriteDomainList,
    RewriteOutcomeList,
    ControlRelationKindList,
    ControlExitPartitionList,
    JsxElementIdentity,
}

impl ValueShape {
    pub fn description(self) -> &'static str {
        match self {
            Self::Query => "a query",
            Self::QueryList => "two or more compatible typed queries",
            Self::QuerySteps => "an ordered list of query steps",
            Self::Pattern => "a pattern",
            Self::PatternList => "a list/vector of patterns",
            Self::PatternMap => "a map of names to patterns",
            Self::String => "a string",
            Self::ParameterName => "a non-empty parameter name",
            Self::CaptureName => "a non-empty declared capture name",
            Self::RegexString => "a regular expression string",
            Self::StringList => "one or more strings",
            Self::StringPredicate => "an exact string or regex predicate",
            Self::RegexPredicate => "a regex predicate object",
            Self::KindList => "a normalized kind or list of kinds",
            Self::DeclaredVisibilityList => {
                "a declared-visibility label or list of labels (public, protected, internal, package_private, private, crate_or_module, unknown)"
            }
            Self::LanguageList => "one or more language labels",
            Self::PositiveInteger => "a positive integer",
            Self::NonNegativeInteger => "a non-negative integer",
            Self::Arity => "an exact non-negative count, or :min/:max argument-count bounds",
            Self::ResultDetail => "compact or full",
            Self::ExecutionMode => "results, explain, or profile",
            Self::SchemaVersion => "a supported schema version",
            Self::TrueBoolean => "the boolean true",
            Self::ReferenceKindList => "one or more structured reference kinds",
            Self::UsageProof => "proven or unproven",
            Self::UsageSurface => "external_usages or lsp_references",
            Self::CallTraversalCompleteness => "exhaustive or proven_subset",
            Self::ProtocolRef => "a bounded protocol reference in namespace:name form",
            Self::ValueFlowPlanRef => "a bounded value-flow plan reference in namespace:name form",
            Self::TaintResultRef => {
                "a bounded retained taint result reference in namespace:name form"
            }
            Self::OccurrenceFilter => "an occurrence class/role/namespace filter object",
            Self::OccurrenceClassList => "one or more occurrence classes",
            Self::OccurrenceRoleList => "one or more occurrence roles",
            Self::NamespaceList => "one or more naming namespaces",
            Self::ScopeFilter => "a lexical scope kind filter object",
            Self::BindingFilter => "a binding kind/name/hoisting filter object",
            Self::PathFilter => "a qualified path min-segments filter object",
            Self::BindingKindList => "one or more binding kinds",
            Self::BindingNameList => "one or more exact binding names",
            Self::HoistingClassList => "one or more hoisting classes",
            Self::PrecedenceTierList => "one or more precedence tiers, or unattributed",
            Self::CandidateOutcomeList => {
                "one or more candidate outcomes or typed rejection reasons"
            }
            Self::BoundaryStatusList => "one or more resolution boundary statuses",
            Self::GenerationSiteFilter => "a generation-site kind/input filter object",
            Self::ExportFilter => "an export form/name filter object",
            Self::GenerationKindList => "one or more generation kinds",
            Self::GenerationInputList => "literal or dynamic",
            Self::ExportFormList => "one or more export forms",
            Self::ExportNameList => "one or more exact exported names",
            Self::DeclarationOriginList => "one or more declaration origins",
            Self::Boolean => "a boolean",
            Self::UsageKindList => "one or more usage kinds",
            Self::OwnerRelationList => "one or more owner relations",
            Self::SiteClassList => "use_site or declaration_site",
            Self::StateEventClassList => "one or more state-event classes",
            Self::FlowSubjectKindList => "binding or property",
            Self::FlowRelationList => "one or more flow relations",
            Self::FlowCertaintyList => "exact or may",
            Self::FailureUseProvenanceList => "one or more failure-use provenance classes",
            Self::FailureUseConsumerList => "one or more failure-use consumer classes",
            Self::RewriteDomainList => "one or more rewrite domains",
            Self::RewriteOutcomeList => "converged, cycle, or exceeded-budget",
            Self::ControlRelationKindList => "one or more control relations",
            Self::ControlExitPartitionList => "one or more control exit partitions",
            Self::JsxElementIdentity => "intrinsic, component, or unknown",
        }
    }

    pub fn string_length_bounds(self) -> Option<(usize, usize)> {
        match self {
            Self::ParameterName => Some((1, MAX_KWARG_NAME_LENGTH)),
            Self::CaptureName => Some((1, MAX_CAPTURE_LENGTH)),
            Self::ProtocolRef => Some((3, crate::refs::MAX_PROTOCOL_REF_BYTES)),
            Self::ValueFlowPlanRef => Some((3, crate::refs::MAX_VALUE_FLOW_PLAN_REF_BYTES)),
            Self::TaintResultRef => Some((3, crate::refs::MAX_TAINT_RESULT_REF_BYTES)),
            _ => None,
        }
    }

    pub fn accepts_string(self, value: &str) -> bool {
        self.string_length_bounds()
            .is_none_or(|(minimum, maximum)| value.len() >= minimum && value.len() <= maximum)
    }
}

/// The guarantee an author requests from one call-graph traversal.
///
/// An exhaustive traversal supports a negative conclusion. A proven subset
/// intentionally reports only resolvable proven caller edges and therefore
/// supports positive findings but never the assertion that all callers were
/// found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CallTraversalCompleteness {
    #[default]
    Exhaustive,
    ProvenSubset,
}

impl CallTraversalCompleteness {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::ProvenSubset => "proven_subset",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RqlFormClass {
    Wrapper,
    Predicate,
}

/// Selects whether a CodeQuery returns ordinary results, a plan explanation,
/// or results accompanied by an execution profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CodeQueryExecutionMode {
    #[default]
    Results,
    Explain,
    Profile,
}

pub const ALL_CODE_QUERY_EXECUTION_MODES: &[CodeQueryExecutionMode] = &[
    CodeQueryExecutionMode::Results,
    CodeQueryExecutionMode::Explain,
    CodeQueryExecutionMode::Profile,
];

impl CodeQueryExecutionMode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Results => "results",
            Self::Explain => "explain",
            Self::Profile => "profile",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        ALL_CODE_QUERY_EXECUTION_MODES
            .iter()
            .copied()
            .find(|mode| mode.label() == label)
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Results => "Execute the query and return its ordinary typed results.",
            Self::Explain => "Lower and select the query plan without executing it.",
            Self::Profile => {
                "Execute the query and return its typed results with operator-level measurements."
            }
        }
    }
}

macro_rules! query_step_ops {
    ($($variant:ident {
        shape: $shape:ident,
        label: $label:literal,
        signature: $signature:literal,
        description: $description:literal
        $(, semantic: [$($semantic:ident),*])?
        $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum QueryStepOp {
            $($variant,)+
        }

        pub const ALL_QUERY_STEP_OPS: &[QueryStepOp] = &[
            $(QueryStepOp::$variant,)+
        ];

        impl QueryStepOp {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }

            pub const fn semantic_facets(self) -> &'static [QuerySemanticFacet] {
                match self {
                    $(Self::$variant => &[$($(QuerySemanticFacet::$semantic),*)?],)+
                }
            }

            /// How this step's driver reaches the rows it emits, which is what
            /// decides whether an execution over one seed file can produce the
            /// same rows as the whole execution restricted to that file.
            ///
            /// Assigned once here from the driver survey
            /// (`.agents/docs/rql-seed-partition-map-2026-09.md`, section 2),
            /// so a new step declares its shape beside its signature instead
            /// of leaving a partition rule to infer one.
            pub const fn shape(self) -> QueryStepShape {
                match self {
                    $(Self::$variant => QueryStepShape::$shape,)+
                }
            }

            pub fn allows_hierarchy_options(self) -> bool {
                matches!(self, Self::Supertypes | Self::Subtypes)
            }

            pub fn allows_reference_options(self) -> bool {
                matches!(self, Self::ReferencesOf | Self::UsedBy | Self::Uses)
            }

            pub fn allows_call_options(self) -> bool {
                matches!(self, Self::Callers | Self::Callees)
            }

            pub fn allows_call_site_options(self) -> bool {
                matches!(self, Self::CallSitesTo | Self::CallSitesFrom)
            }

            pub fn allows_receiver_options(self) -> bool {
                matches!(
                    self,
                    Self::ReceiverTargets | Self::PointsTo | Self::MemberTargets
                )
            }

            pub fn allows_field_write_value_options(self) -> bool {
                matches!(self, Self::FieldWriteValue)
            }

            /// Whether this operation's rows come from an analysis a host
            /// registered rather than from the workspace alone.
            ///
            /// The four are the protocol, plan and taint runners and the
            /// witness projection over their findings. Each reads the
            /// interprocedural graph, the summary repository and the
            /// registration itself through funnels that record no read key,
            /// so a per-seed unit over one would publish a read set that names
            /// none of what decided its rows; a plan containing one is
            /// classified `Whole` (`PlanPartitioning::classify`).
            pub fn is_registration_dependent(self) -> bool {
                matches!(
                    self,
                    Self::Typestate | Self::ValueFlow | Self::Taint | Self::Witness
                )
            }

            pub fn allows_typestate_options(self) -> bool {
                matches!(self, Self::Typestate)
            }

            pub fn allows_value_flow_options(self) -> bool {
                matches!(self, Self::ValueFlow)
            }

            pub fn allows_taint_options(self) -> bool {
                matches!(self, Self::Taint)
            }

            pub fn allows_witness_options(self) -> bool {
                matches!(self, Self::Witness)
            }

            pub fn allows_occurrence_options(self) -> bool {
                matches!(self, Self::OccurrencesOf | Self::OccurrencesIn)
            }

            pub fn allows_binding_options(self) -> bool {
                matches!(self, Self::BindingsIn)
            }

            pub fn allows_decorator_binding_options(self) -> bool {
                matches!(self, Self::DecoratorBindings)
            }

            pub fn allows_candidate_options(self) -> bool {
                matches!(self, Self::CandidatesOf)
            }

            pub fn allows_edge_options(self) -> bool {
                matches!(self, Self::EdgesOf | Self::EdgesFrom)
            }

            pub fn allows_state_event_options(self) -> bool {
                matches!(self, Self::StateEventsOf)
            }

            pub fn allows_flow_relation_options(self) -> bool {
                matches!(self, Self::FlowRelationsOf)
            }

            pub fn allows_rewrite_path_options(self) -> bool {
                matches!(self, Self::RewritePathsOf)
            }

            pub fn allows_control_relation_options(self) -> bool {
                matches!(self, Self::ControlRelations)
            }

            pub fn allows_binding_of_options(self) -> bool {
                matches!(self, Self::BindingOf)
            }

            pub fn allows_segment_options(self) -> bool {
                matches!(self, Self::SegmentsOf)
            }
        }
    };
}

/// How one step's driver reaches the rows it emits.
///
/// This is a statement about the step's inputs, not about its cost: a
/// derived-value step is one whose answer is a whole-workspace relation (the
/// import topology, the usage or call scan, the type hierarchy, dispatch, the
/// build topology, or a prepared analysis context), which is exactly the shape
/// that lets a query seeded in one file report a row about another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryStepShape {
    /// The driver reads only the input row's own file, facts, and handles.
    RowLocal,
    /// The driver sorts its whole input row vector by artifact file and opens
    /// one per-file semantic window (the #2586 per-file enclosure batching).
    /// The sort is stable over seed-major input, so every within-file order
    /// the row ordinals depend on is still seed order.
    Batched,
    /// The driver's answer is a whole-workspace derived value. Seed-partitioned
    /// execution keeps such a step whole-workspace: the unit's recorded reads
    /// carry the derived value, so any change that rotates it invalidates the
    /// unit.
    DerivedValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuerySemanticFacet {
    Procedures,
    Dispatch,
    ProgramPoints,
    ControlEdges,
    SwitchFacts,
    Typestate,
    Concurrency,
    ValueFlow,
    Taint,
}

query_step_ops! {
    EnclosingDecl { shape: RowLocal, label: "enclosing_decl", signature: "structural_match -> declaration", description: "Map structural matches to their smallest real enclosing declarations." }
    ProcedureOf { shape: RowLocal, label: "procedure_of", signature: "structural_match|declaration -> procedure", description: "Resolve each source-backed input to its smallest enclosing executable procedure.", semantic: [Procedures] }
    CfgEntry { shape: RowLocal, label: "cfg_entry", signature: "procedure -> program_point", description: "Return the validated entry program point of each procedure.", semantic: [Procedures, ProgramPoints] }
    CfgExits { shape: RowLocal, label: "cfg_exits", signature: "procedure -> program_point", description: "Return the validated normal and exceptional exit program points of each procedure.", semantic: [Procedures, ProgramPoints] }
    CfgSuccessorEdges { shape: RowLocal, label: "cfg_successor_edges", signature: "program_point -> control_edge", description: "Return one-hop outgoing control edges from each program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    CfgPredecessorEdges { shape: RowLocal, label: "cfg_predecessor_edges", signature: "program_point -> control_edge", description: "Return one-hop incoming control edges to each program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    CfgEdgeSource { shape: RowLocal, label: "cfg_edge_source", signature: "control_edge -> program_point", description: "Project each control edge to its source program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    CfgEdgeTarget { shape: RowLocal, label: "cfg_edge_target", signature: "control_edge -> program_point", description: "Project each control edge to its target program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    Typestate { shape: DerivedValue, label: "typestate", signature: "procedure -> typestate_finding", description: "Run one registered diagnostic-neutral typestate analysis for the exact procedure root.", semantic: [Procedures, Typestate] }
    ConcurrentAccessConflicts { shape: DerivedValue, label: "concurrent_access_conflicts", signature: "procedure -> concurrent_access_conflict", description: "Build a bounded spawn-rooted task slice and project ordinary accesses to the same location that may execute concurrently, retaining conflict, ordered, and protected verdicts with explicit ordering, protection, proof, and coverage.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges, Concurrency] }
    ValueFlow { shape: DerivedValue, label: "value_flow", signature: "procedure -> flow_endpoint", description: "Run one registered diagnostic-neutral value-flow plan for the exact procedure root.", semantic: [Procedures, ValueFlow] }
    ClassSet { shape: DerivedValue, label: "class_set", signature: "procedure -> class_set_row", description: "Propagate constructor, literal, and declared classes through every call reachable from the procedure and report, for each member access, the classes its receiver may hold. A row whose status is not known carries no proof.", semantic: [Procedures, Dispatch, ValueFlow] }
    AbsentMember { shape: DerivedValue, label: "absent_member", signature: "procedure -> absent_member_finding", description: "Report member accesses whose receiver class set is fully known and contains a class that does not declare the member, with the site that introduced the class.", semantic: [Procedures, Dispatch, ValueFlow] }
    Taint { shape: DerivedValue, label: "taint", signature: "procedure -> taint_finding", description: "Project findings retained by one host-registered production taint result for the exact procedure root.", semantic: [Procedures, Taint] }
    Witness { shape: DerivedValue, label: "witness", signature: "typestate_finding|flow_endpoint -> typestate_witness|flow_witness", description: "Project bounded retained evidence from each typestate finding or reached flow endpoint without rerunning analysis." }
    FileOf { shape: RowLocal, label: "file_of", signature: "structural_match|declaration|procedure|program_point|control_edge|typestate_finding|typestate_witness|flow_endpoint|flow_witness|taint_finding|reference_site|call_site|expression_site|jsx_attribute_value|receiver_analysis|member_target_analysis|receiver_outcome|receiver_evidence|field_write_value|call_shape|call_argument_group|call_argument|call_binding|call_effect|call_result_contract|result_contract_use|result_contract_failure_use|procedure_effect|callable_signature|signature_parameter|decorated_parameter|callable_applicability|overload_selection|dispatch_outcome|dispatch_target|member_family|member_family_edge|state_event -> file", description: "Map structural matches, declarations, procedures, program points, control edges, typestate findings, typestate witnesses, flow endpoints, flow witnesses, taint findings, reference sites, call sites, expression sites, exact JSX attribute operands, receiver analyses, member-target analyses, receiver outcomes, receiver evidence, exact field-write operands, call-shape rows, call-result-contract rows, typed result-contract operation and failure-use rows, callable-signature rows, decorated-parameter rows, callable-applicability rows, overload-selection rows, dispatch rows, method-family rows, or state-event rows to their workspace files." }
    ImportsOf { shape: RowLocal, label: "imports_of", signature: "file -> file", description: "Traverse one direct project-local import edge forward." }
    ImportersOf { shape: DerivedValue, label: "importers_of", signature: "file -> file", description: "Traverse one direct project-local import edge backward." }
    Supertypes { shape: DerivedValue, label: "supertypes", signature: "declaration -> declaration", description: "Traverse indexed supertypes from supported type declarations." }
    Subtypes { shape: DerivedValue, label: "subtypes", signature: "declaration -> declaration", description: "Traverse indexed subtypes from supported type declarations." }
    Members { shape: RowLocal, label: "members", signature: "declaration -> declaration", description: "Return direct indexed members of type declarations." }
    Owner { shape: RowLocal, label: "owner", signature: "declaration -> declaration", description: "Return the exact indexed declaring type of member declarations." }
    ReferencesOf { shape: DerivedValue, label: "references_of", signature: "declaration -> reference_site", description: "Return resolved source reference sites for exact indexed declarations." }
    UsedBy { shape: DerivedValue, label: "used_by", signature: "declaration -> declaration", description: "Return exact declarations containing references to each input declaration." }
    Uses { shape: RowLocal, label: "uses", signature: "declaration -> declaration", description: "Return exact declarations referenced by each input declaration." }
    Callers { shape: DerivedValue, label: "callers", signature: "declaration -> declaration", description: "Traverse resolved incoming call edges to caller declarations, optionally to a bounded depth." }
    Callees { shape: RowLocal, label: "callees", signature: "declaration -> declaration", description: "Traverse resolved outgoing call edges to callee declarations, optionally to a bounded depth." }
    CallSitesTo { shape: DerivedValue, label: "call_sites_to", signature: "declaration -> call_site", description: "Return structured call sites whose resolved callee is each input declaration." }
    CallSitesFrom { shape: RowLocal, label: "call_sites_from", signature: "declaration -> call_site", description: "Return structured call sites lexically owned by each input declaration." }
    CallInput { shape: RowLocal, label: "call_input", signature: "call_site -> expression_site", description: "Project one direct receiver or formal-parameter input from each call site." }
    JsxAttributeValue { shape: RowLocal, label: "jsx_attribute_value", signature: "structural_match -> jsx_attribute_value", description: "Project the exact normalized expression operand of JSX attributes, with intrinsic/component/unknown element identity and explicit incompleteness for unresolved semantic cases." }
    ReceiverTargets { shape: DerivedValue, label: "receiver_targets", signature: "structural_match|reference_site|call_site|expression_site|occurrence -> receiver_analysis", description: "Analyze a bounded receiver value using adapter-provided structured facts." }
    PointsTo { shape: DerivedValue, label: "points_to", signature: "structural_match|reference_site|expression_site|occurrence -> receiver_analysis", description: "Analyze bounded value provenance using adapter-provided structured facts." }
    MemberTargets { shape: DerivedValue, label: "member_targets", signature: "structural_match|reference_site|occurrence -> member_target_analysis", description: "Resolve exact static member identities together with the receiver owner and model provenance used by bounded structured receiver analysis." }
    FieldWriteValue { shape: RowLocal, label: "field_write_value", signature: "member_target_analysis -> field_write_value", description: "Project the exact right-hand expression of a simple assignment whose static member and receiver identities were proven by member_targets, optionally retaining only exact receiver/member identities." }
    ReceiverOutcome { shape: RowLocal, label: "receiver_outcome", signature: "receiver_analysis|member_target_analysis -> receiver_outcome", description: "Project the mandatory terminal outcome row for each receiver or member-target analysis." }
    ReceiverEvidence { shape: RowLocal, label: "receiver_evidence", signature: "receiver_analysis -> receiver_evidence", description: "Project zero or more parent-linked typed receiver evidence rows." }
    CallShape { shape: RowLocal, label: "call_shape", signature: "structural_match|call_site|occurrence -> call_shape", description: "Project the mandatory structured call-shape outcome row for each exact call site, including its structurally decoded callee token and written argument count when available." }
    CallResults { shape: RowLocal, label: "call_results", signature: "call_shape -> call_result", description: "Project the ordered normal result ports of each exact semantic call represented by a call-shape row. Each row carries the structural site identity, semantic call and procedure identities, zero-based result ordinal, procedure-local value identity, result point, and evidence quality so it can join assignments and guards without inferring source order.", semantic: [Procedures, ProgramPoints] }
    CallArgumentGroups { shape: RowLocal, label: "call_argument_groups", signature: "call_shape -> call_argument_group", description: "Project the ordered argument-list group rows of each call shape." }
    CallArguments { shape: RowLocal, label: "call_arguments", signature: "call_argument_group -> call_argument", description: "Project the ordered argument rows of each argument-list group." }
    CallEffects { shape: RowLocal, label: "call_effects", signature: "call_shape -> call_effect", description: "Project the direct effect rows of each call shape: one row per (dispatch arm, declared effect) for every callee an active semantic-model pack declares effects for, carrying the effect id, the pack-authored timing, additive canonical execution timing, the certainty meet of the declaration and the dispatch proof, and the pack provenance. At least one row per call shape, so an unresolved, unmodeled or unsupported dispatch states that instead of answering empty. The callee set and its proof are the dispatch oracle's own answer; nothing is re-derived here.", semantic: [Procedures] }
    ResultContractCalls { shape: Batched, label: "result_contract_calls", signature: "call_shape -> call_shape", description: "Retain call shapes whose exhaustively resolved canonical dispatch arms unanimously select an activated semantic-model summary with at least one reviewed result contract. This lightweight positive candidate discovery uses structural call shapes, exact definition resolution (including Go package, bound-receiver, and conservative method-expression applicability), and activated model keys without materializing procedure semantics: conclusively unmodeled calls are omitted, while conflicts or interrupted dispatch make the query incomplete." }
    CallResultContracts { shape: Batched, label: "call_result_contracts", signature: "call_shape -> call_result_contract", description: "Project reviewed validity contracts for a call's normal results from the unique activated semantic-model summary for every possible dispatch arm. A positive row identifies the protected result ordinal and either a predicate over a separate condition result or a direct result-success predicate, derives only the exact normalized success-guard edges needed to instantiate that contract, counts reviewed member contracts, and reports whether every modeled arm declares a fresh allocation at that indexed result. It does not inspect resource-sensitive uses. At least one row per call shape; unresolved dispatch or conflicting models produce an explicit terminal row and incomplete query rather than an empty answer.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    ResultContractUses { shape: Batched, label: "result_contract_uses", signature: "call_result_contract -> call_result_contract", description: "Summarize operation-sensitive uses of each positive call-result-contract row while preserving acquisition identity. This optional enrichment counts every exact structured operation, reports the lower bound of reviewed required operations proved unguarded, and carries aggregate use-validation coverage. Terminal rows pass through unchanged; incomplete structured use evidence makes only this relation incomplete.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    ResultContractOperationUses { shape: Batched, label: "result_contract_operation_uses", signature: "call_result_contract -> result_contract_use", description: "Project one typed row per structured operation on a protected result. Intrinsic dereference, field, and index operations are required uses. Receiver calls use exact complete member operation contracts. Exact positional call arguments use complete possible-target procedure-entry preconditions and carry parameter_ordinal. Missing, conflicting, expanded, or ambiguous operation evidence stays open. Each row is anchored at the operation and carries its acquisition identity, exact applicability, timing, required predicate, and guarded, unguarded, not_applicable, or unknown verdict.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    ResultContractFailureUses { shape: Batched, label: "result_contract_failure_uses", signature: "call_result_contract -> result_contract_failure_use", description: "Project structured values returned or passed to calls inside the exact failure arm of a reviewed conditional result contract. Each row compares the operand's exact reaching binding/value provenance with the paired condition result and classifies condition_result, distinct_zero_binding, distinct_binding, independent, or unknown. Exact normalized failure-edge confinement and complete structured identity are required for closed proof; ambiguity remains an open unknown row.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    NilnessOperations { shape: RowLocal, label: "nilness_operations", signature: "procedure -> nilness_operation", description: "Project source-backed pointer operations with their procedure-local scalar nilness fact. Explicit dereferences and implicit pointer field loads or stores are intrinsic operations; receiver calls are included only when exhaustive reviewed models require a non-null receiver. Unsupported identity or scalar evidence stays explicit and open rather than becoming a finding.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    SwitchCoverage { shape: RowLocal, label: "switch_coverage", signature: "procedure -> switch_coverage", description: "Project one source-backed coverage verdict for each switch. An explicit default is exhaustive; an exact Boolean expression selector is exhaustive only with both literal cases and non-exhaustive when a complete literal case set omits either value. Expressionless switches without default, type switches, open selector domains, and nonliteral case sets remain unknown.", semantic: [Procedures, ProgramPoints, ControlEdges, SwitchFacts] }
    DetachedTaskTransfers { shape: RowLocal, label: "detached_task_transfers", signature: "procedure -> detached_task_transfer", description: "Project receiver, argument, and exact local closure-capture values copied into calls whose semantic invocation mode is detached and whose execution timing is different_task. Each row carries stable value identity and an exact abstract-object identity when the heap oracle proves one closed candidate; absent, ambiguous, open, or unproven object sets remain explicit open terminal rows.", semantic: [Procedures, ProgramPoints] }
    ProcedureEffects { shape: RowLocal, label: "procedure_effects", signature: "declaration -> procedure_effect", description: "Summarize the effects of each procedure over its reachable call graph: one row per (procedure, effect id), classified direct or transitive, with the hop count, the certainty and timing carried along the attributing chain, a bounded witness chain of call-site identities, and the coverage that says whether an absent effect is proven absent or merely unseen. At least one row per declaration. The walk is a bounded deterministic fixpoint over the same dispatch answers call_effects publishes.", semantic: [Procedures] }
    CallBindings { shape: RowLocal, label: "call_bindings", signature: "call_shape -> call_binding", description: "Project the normalized actual-to-formal binding rows of each call shape: one row per written actual, carrying the call-shape argument identity it binds, the formal ordinal and name it was bound to, the binding kind, this row's mapping status, and the whole call's partition coverage. Beside them, a row for each fact no written actual accounts for: the receiver the call is made against, an argument the language supplies with no syntax, and a formal that no actual passed but whose declaration carries a default. Coverage describes the written actuals alone. Exact receiver rows carry a stable declaring-type identity. Selector proof is separate from runtime dispatch: it is derived for exact dispatch or for a resolver-proven receiverless external static target whose unique complete model supplies exact formals. It can also be authored-summary proof when a unique complete exact-member summary explicitly covers the sole unresolved override residual; full activated provenance is retained. Workspace arms, ambiguous overloads, partial or conflicting models, unproven owner identity, instance boundaries without a contract, other boundary kinds, and truncation remain inexact. The semantic dispatch identity, proof, completeness, and candidate coverage are still carried unchanged from the bounded dispatch answer. A source declaration is only an optional materialized view. At least one row per call shape, so an unreadable shape, an unresolved or ambiguous callee, unrecorded formals, or a call that binds nothing each state that instead of answering empty. The callee is the one the production definition resolver binds; no overload is re-decided here.", semantic: [Procedures, Dispatch] }
    CallableSignature { shape: RowLocal, label: "callable_signature", signature: "declaration -> callable_signature", description: "Project the mandatory callable-signature rows of each declaration from the persisted signature contract: one row per persisted signature entry, so an overload set separates into one row per overload." }
    SignatureParameters { shape: RowLocal, label: "signature_parameters", signature: "callable_signature -> signature_parameter", description: "Project the ordered declared parameter rows of each callable signature." }
    DecoratorBindings { shape: Batched, label: "decorator_bindings", signature: "structural_match -> decorated_parameter", description: "Project one typed decorator-binding row for each decorator applied to a parameter match. Semantic parameter identity is used only when an exact structural source identity selects one Parameter value; otherwise the row retains only a syntax explanation and explicitly incomplete coverage.", semantic: [Procedures] }
    CallableApplicability { shape: DerivedValue, label: "callable_applicability", signature: "occurrence -> callable_applicability", description: "Project one applicability row per candidate callable the production resolver considered for each reference occurrence: the verdict, the typed callable rejection reason when inapplicable, the precedence tier, and whether the resolver bound it. A candidate the resolver refused stays visible with its reason, so a losing overload is evidence rather than an absence." }
    OverloadSelection { shape: DerivedValue, label: "overload_selection", signature: "occurrence -> overload_selection", description: "Project the mandatory overload-selection summary row for each reference occurrence: resolved_unique, ambiguous, unresolved, or unknown_shape, with the verdict counts it was computed from. Exactly one row per occurrence, and candidate order can never influence it -- zero applicable candidates stay unresolved and several equal winners stay ambiguous." }
    MemberSelection { shape: DerivedValue, label: "member_selection", signature: "occurrence -> member_selection", description: "Project the mandatory member-selection summary row for each reference occurrence, from the production resolver's own candidate trace." }
    DispatchOutcome { shape: DerivedValue, label: "dispatch_outcome", signature: "structural_match|call_site|reference_site|occurrence -> dispatch_outcome", description: "Project the mandatory bounded-dispatch outcome row for each input site: the semantic outcome, the candidate coverage, and the retained target count. Exactly one row per input site, so an unknown, unsupported, over-budget, or cancelled dispatch is stated rather than silently empty.", semantic: [Procedures, Dispatch] }
    DispatchTargets { shape: DerivedValue, label: "dispatch_targets", signature: "structural_match|call_site|reference_site|occurrence -> dispatch_target", description: "Project zero or more bounded dispatch target rows for each input site, one per retained dispatch candidate plus one per boundary arm that names a target. Each row keeps the oracle's own proof, completeness, and candidate coverage, so a proven target in an exhaustive set stays distinguishable from an open may-dispatch arm.", semantic: [Procedures, Dispatch] }
    MemberFamily { shape: DerivedValue, label: "member_family", signature: "declaration -> member_family", description: "Project the mandatory canonical method-family outcome row for each member declaration: the family id when the analyzer proves the family, the typed reason when it cannot, the per-relation edge counts, and the coverage. Exactly one row per input declaration, so an unsupported language or an unprovable overload identity is stated rather than silently empty." }
    FamilyEdges { shape: DerivedValue, label: "family_edges", signature: "declaration -> member_family_edge", description: "Project the typed method-family edges of each member declaration: the forward overrides/implements edges the analyzer proves, plus the bounded inversion of those same edges as overridden_by/implemented_by. Emitted only from a proven family, so an unproven or unsupported member yields no edge row and its outcome row says why." }
    OccurrencesOf { shape: DerivedValue, label: "occurrences_of", signature: "declaration -> occurrence", description: "Return the declaration-name occurrence of each declaration plus every reference-class occurrence resolving to it." }
    OccurrencesIn { shape: RowLocal, label: "occurrences_in", signature: "structural_match|file -> occurrence", description: "Return classified identifier occurrences lexically inside each structural match or file." }
    OccurrenceTarget { shape: DerivedValue, label: "occurrence_target", signature: "occurrence -> declaration", description: "Project the resolved semantic targets of reference-class occurrences." }
    ScopeOf { shape: RowLocal, label: "scope_of", signature: "binding|occurrence|structural_match -> lexical_scope", description: "Return the innermost lexical scope that owns each binding, occurrence, or structural match." }
    ScopeAncestors { shape: RowLocal, label: "scope_ancestors", signature: "lexical_scope -> lexical_scope", description: "Return the enclosing lexical scopes of each scope, innermost first, excluding the scope itself." }
    BindingsIn { shape: RowLocal, label: "bindings_in", signature: "lexical_scope|structural_match -> binding", description: "Return the bindings declared in each lexical scope, or in the scopes inside each structural match." }
    BindingOf { shape: RowLocal, label: "binding_of", signature: "occurrence -> binding", description: "Return the binding of the occurrence's name that is in effect at its exact position." }
    BindingOccurrence { shape: RowLocal, label: "binding_occurrence", signature: "binding -> occurrence", description: "Return the binder-class occurrence row of each binding's declaring token." }
    CandidatesOf { shape: DerivedValue, label: "candidates_of", signature: "occurrence -> resolution_candidate", description: "Return the candidates the resolver considered for each reference-class occurrence, with tier, outcome, and boundary." }
    CandidateHierarchy { shape: DerivedValue, label: "candidate_hierarchy", signature: "occurrence -> candidate_hop", description: "Return the exact hierarchy hops each traced member candidate of a reference occurrence was found through. A depth-zero candidate contributes no hop, and a candidate the resolver recorded without member attribution contributes none either -- absence here is unattributed, never a claim that no hierarchy was walked; the mandatory outcome story is member_selection's." }
    CandidateTarget { shape: DerivedValue, label: "candidate_target", signature: "resolution_candidate -> declaration", description: "Project the workspace declarations of unit-backed resolution candidates." }
    EdgesOf { shape: DerivedValue, label: "edges_of", signature: "declaration -> reference_edge", description: "Return the canonical inverse reference edges of each declaration: every usage site the usage index enumerates, with kind, proof, usage kind, and owner relation." }
    EdgesFrom { shape: RowLocal, label: "edges_from", signature: "occurrence -> reference_edge", description: "Return the canonical forward reference edges of each occurrence: the resolver's own resolved targets for that exact token, with kind, proof, usage kind, and owner relation." }
    EdgeTarget { shape: DerivedValue, label: "edge_target", signature: "reference_edge -> declaration", description: "Project each reference edge to its exact indexed target declaration." }
    StateEventsOf { shape: RowLocal, label: "state_events_of", signature: "procedure|declaration -> state_event", description: "Derive the flow-sensitive state events of each procedure from the production semantic IR: every establishment, kill, and read of a binding or of a property of a canonical binding base, anchored to a program point of that procedure's control-flow graph. Source order and containment are never evidence; an axis the lowering does not model is reported incomplete rather than approximated.", semantic: [Procedures, ProgramPoints] }
    FlowRelationsOf { shape: RowLocal, label: "flow_relations_of", signature: "state_event|procedure -> flow_relation", description: "Derive the flow relations between the state events of each procedure: reaching-definition, dominance, and same-evaluation, each with exact or may certainty. Seeded from a state event, only the relations incident to that event are returned. Budget exhaustion emits no rows and an explicit incomplete diagnostic; it is never reported as an absent relation.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    FlowSource { shape: RowLocal, label: "flow_source", signature: "flow_relation -> state_event", description: "Project each flow relation to its source state event: the establishment or kill end." }
    FlowTarget { shape: RowLocal, label: "flow_target", signature: "flow_relation -> state_event", description: "Project each flow relation to its target state event: the read end." }
    ControlRelations { shape: RowLocal, label: "control_relations", signature: "procedure -> control_relation", description: "Derive the control relations of each procedure from the shared control-flow algorithms over the production semantic IR: dominance, postdominance, control dependence, entry reachability, and loop membership between the procedure's own program points, joined by the same stable ids the program_point and control_edge rows publish. Every row states the exit partition its claim was computed against, so a backward claim can never be read as a claim about a partition that was not computed. Budget exhaustion or cancellation emits no row for the affected relation and an explicit incomplete diagnostic; it is never reported as an absent relation.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    GuardsOf { shape: RowLocal, label: "guards_of", signature: "procedure -> guard", description: "Return the normalized branch conditions the language adapter recorded for each procedure: which decision point each guard sits on, what its condition was normalized to -- a compile-time constant, a null comparison, a comparison against a constant, or an explicitly opaque condition -- and the stable ids of the true and false successor edges and target points. A constant condition is published even when lowering folded its dead arm away, which is the only place that evidence survives. An empty answer means the adapter records no guard facts for this language, which its own guard_facts capability states.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    TargetOf { shape: DerivedValue, label: "target_of", signature: "file -> build_target", description: "Return the build target each file compiles into, as the workspace's own build files declare it. Ownership comes from build evidence alone: a file no read build file claims produces no row, and a build model this workspace cannot read produces an explicit incomplete diagnostic rather than an empty answer that reads as \"no target\"." }
    SourceSetOf { shape: DerivedValue, label: "source_set_of", signature: "file -> source_set", description: "Return the declared compilation input set each file belongs to, with the build file that fixes the layout. A file two declared source sets both claim is reported ambiguous rather than assigned to whichever was read first." }
    TopologyEdgesOf { shape: DerivedValue, label: "topology_edges_of", signature: "build_target -> topology_edge", description: "Return the dependencies each build target declares on other targets of the same workspace, each carrying its build-declared scope and the build file that declares it. The absence of an edge is only publishable when the topology it was read from is complete, which the row's own completeness column states." }
    RewritePathsOf { shape: RowLocal, label: "rewrite_paths_of", signature: "file -> rewrite_path", description: "Enumerate the bounded rewrite chases each file engages in a declared finite rewrite domain: the ordered steps a production analysis took, the bound the domain declared for itself, and the terminal outcome -- converged with its fixed point, cycle with the ordered repeated-state witness, or exceeded-budget with the work performed. Budget exhaustion is absence of evidence, never a proven cycle and never a clean convergence." }
    SegmentsOf { shape: RowLocal, label: "segments_of", signature: "qualified_path -> path_segment", description: "Return each path's ordered segment rows with decoded text, spelled generic arity, and (with :resolved true) each segment's own prefix resolution." }
    SegmentTarget { shape: DerivedValue, label: "segment_target", signature: "path_segment -> declaration", description: "Project the workspace declarations each path segment's own position resolves to." }
    Generates { shape: RowLocal, label: "generates", signature: "generation_site -> declaration_state", description: "Return the declaration-state rows of the declarations each generation site materializes." }
    GeneratedBy { shape: RowLocal, label: "generated_by", signature: "declaration|declaration_state -> generation_site", description: "Return the generation site that materialized each generated declaration." }
    DeclarationStateOf { shape: RowLocal, label: "declaration_state_of", signature: "declaration -> declaration_state", description: "Return each declaration's state row: origin, declaration-only flag, and configuration gate." }
    ImplementationOf { shape: RowLocal, label: "implementation_of", signature: "declaration_state|declaration -> declaration", description: "Return the runnable implementation a declaration-only signature links to." }
    StubsOf { shape: RowLocal, label: "stubs_of", signature: "declaration -> declaration_state", description: "Return the declaration-only stub state rows whose implementation link resolves to each declaration; composed with except, this lists the stubs no implementation answers." }
    ExportTarget { shape: DerivedValue, label: "export_target", signature: "export -> declaration", description: "Project the declaration an export row materialized, where the analyzer models one." }
}

/// The generated step reference: one line per registry step, in
/// [`ALL_QUERY_STEP_OPS`] order, spelled `label (input -> output): meaning`.
///
/// This is the only step reference Bifrost publishes to a caller. The MCP
/// `query_code` `steps` parameter schema carries it, and `bifrost --help
/// query_code` prints it out of that same schema, so a step added to the
/// registry above documents itself on both surfaces and no help text anywhere
/// repeats the vocabulary.
pub fn query_step_reference() -> String {
    let mut reference = String::new();
    for op in ALL_QUERY_STEP_OPS {
        if !reference.is_empty() {
            reference.push('\n');
        }
        reference.push_str(op.label());
        reference.push_str(" (");
        reference.push_str(op.signature());
        reference.push_str("): ");
        reference.push_str(op.description());
    }
    reference
}

macro_rules! rql_form_description {
    ($description:literal) => {
        $description
    };
    (($step:path)) => {
        $step.description()
    };
}

macro_rules! rql_form_step {
    () => {
        None
    };
    ($step:ident) => {
        Some(QueryStepOp::$step)
    };
}

macro_rules! rql_forms {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        class: $class:ident,
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:tt
        $(, step: $step:ident)?
        $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RqlForm {
            $($variant,)+
        }

        pub const ALL_RQL_FORMS: &[RqlForm] = &[
            $(RqlForm::$variant,)+
        ];

        impl RqlForm {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($primary $(| $alias)* => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn class(self) -> RqlFormClass {
                match self {
                    $(Self::$variant => RqlFormClass::$class,)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => rql_form_description!($description),)+
                }
            }

            pub const fn query_step_op(self) -> Option<QueryStepOp> {
                match self {
                    $(Self::$variant => rql_form_step!($($step)?),)+
                }
            }

            /// Return the pattern property lowered by a predicate form.
            ///
            /// Keeping this match exhaustive makes adding a form require an
            /// explicit lowering decision rather than relying on coincidental
            /// equality between two registry labels.
            pub fn property(self) -> Option<RqlProperty> {
                match self {
                    Self::Where
                    | Self::Language
                    | Self::Limit
                    | Self::ResultDetail
                    | Self::Explain
                    | Self::Profile
                    | Self::Inside
                    | Self::InsideDecl
                    | Self::NotInside
                    | Self::Union
                    | Self::Intersect
                    | Self::Except
                    | Self::EnclosingDecl
                    | Self::ProcedureOf
                    | Self::CfgEntry
                    | Self::CfgExits
                    | Self::CfgSuccessorEdges
                    | Self::CfgPredecessorEdges
                    | Self::CfgEdgeSource
                    | Self::CfgEdgeTarget
                    | Self::Typestate
                    | Self::ConcurrentAccessConflicts
                    | Self::ValueFlow
                    | Self::ClassSet
                    | Self::AbsentMember
                    | Self::Taint
                    | Self::Witness
                    | Self::FileOf
                    | Self::ImportsOf
                    | Self::ImportersOf
                    | Self::Supertypes
                    | Self::Subtypes
                    | Self::Members
                    | Self::Owner
                    | Self::ReferencesOf
                    | Self::UsedBy
                    | Self::Uses
                    | Self::Callers
                    | Self::Callees
                    | Self::CallSitesTo
                    | Self::CallSitesFrom
                    | Self::CallInput
                    | Self::JsxAttributeValue
                    | Self::ReceiverTargets
                    | Self::PointsTo
                    | Self::MemberTargets
                    | Self::FieldWriteValue
                    | Self::ReceiverOutcome
                    | Self::ReceiverEvidence
                    | Self::CallShape
                    | Self::CallResults
                    | Self::CallArgumentGroups
                    | Self::CallArguments
                    | Self::CallBindings
                    | Self::CallEffects
                    | Self::ResultContractCalls
                    | Self::CallResultContracts
                    | Self::ResultContractUses
                    | Self::ResultContractOperationUses
                    | Self::ResultContractFailureUses
                    | Self::NilnessOperations
                    | Self::SwitchCoverage
                    | Self::DetachedTaskTransfers
                    | Self::ProcedureEffects
                    | Self::CallableSignature
                    | Self::SignatureParameters
                    | Self::DecoratorBindings
                    | Self::CallableApplicability
                    | Self::OverloadSelection
                    | Self::MemberSelection
                    | Self::DispatchOutcome
                    | Self::DispatchTargets
                    | Self::MemberFamily
                    | Self::FamilyEdges
                    | Self::Occurrences
                    | Self::OccurrencesOf
                    | Self::OccurrencesIn
                    | Self::OccurrenceTarget
                    | Self::Scopes
                    | Self::Bindings
                    | Self::Paths
                    | Self::SegmentsOf
                    | Self::SegmentTarget
                    | Self::ScopeOf
                    | Self::ScopeAncestors
                    | Self::BindingsIn
                    | Self::BindingOf
                    | Self::BindingOccurrence
                    | Self::CandidatesOf
                    | Self::CandidateHierarchy
                    | Self::GenerationSites
                    | Self::Exports
                    | Self::Generates
                    | Self::GeneratedBy
                    | Self::DeclarationStateOf
                    | Self::ImplementationOf
                    | Self::StubsOf
                    | Self::ExportTarget
                    | Self::CandidateTarget
                    | Self::EdgesOf
                    | Self::EdgesFrom
                    | Self::EdgeTarget
                    | Self::StateEventsOf
                    | Self::FlowRelationsOf
                    | Self::FlowSource
                    | Self::FlowTarget
                    | Self::ControlRelations
                    | Self::TargetOf
                    | Self::SourceSetOf
                    | Self::TopologyEdgesOf
                    | Self::GuardsOf
                    | Self::RewritePathsOf => None,
                    Self::Name => Some(RqlProperty::Name),
                    Self::NameRegex => Some(RqlProperty::NameRegex),
                    Self::TextRegex => Some(RqlProperty::TextRegex),
                    Self::BooleanValue => Some(RqlProperty::BooleanValue),
                    Self::Capture => Some(RqlProperty::Capture),
                    Self::Has => Some(RqlProperty::Has),
                    Self::NotHas => Some(RqlProperty::NotHas),
                    Self::NotKind => Some(RqlProperty::NotKind),
                    Self::Arity => Some(RqlProperty::Arity),
                    Self::Visibility => Some(RqlProperty::Visibility),
                    Self::ParameterType => Some(RqlProperty::ParameterType),
                    Self::ParameterTypeRegex => Some(RqlProperty::ParameterTypeRegex),
                }
            }
        }
    };
}

rql_forms! {
    Where {
        labels: ["where"],
        class: Wrapper,
        shape: StringList,
        signature: "(where \"glob\" ... query)",
        description: "Restrict the query to workspace-relative path globs.",
    }
    Language {
        labels: ["language", "languages"],
        class: Wrapper,
        shape: LanguageList,
        signature: "(language label ... query)",
        description: "Restrict the query to one or more analyzer languages.",
    }
    Limit {
        labels: ["limit"],
        class: Wrapper,
        shape: PositiveInteger,
        signature: "(limit count query)",
        description: "Set the maximum number of matches returned by query_code.",
    }
    ResultDetail {
        labels: ["result-detail", "result_detail"],
        class: Wrapper,
        shape: ResultDetail,
        signature: "(result-detail compact|full query)",
        description: "Choose compact output or full capture and source details.",
    }
    Explain {
        labels: ["explain"],
        class: Wrapper,
        shape: Query,
        signature: "(explain query)",
        description: "Lower and select the logical and physical plans without executing the query.",
    }
    Profile {
        labels: ["profile"],
        class: Wrapper,
        shape: Query,
        signature: "(profile query)",
        description: "Execute the query and include operator timing, work, cache, waiting, and concurrency measurements.",
    }
    Inside {
        labels: ["inside"],
        class: Wrapper,
        shape: Pattern,
        signature: "(inside container-pattern query)",
        description: "Require the root match to be lexically inside a matching container.",
    }
    InsideDecl {
        labels: ["inside-decl", "inside_decl"],
        class: Wrapper,
        shape: Pattern,
        signature: "(inside-decl container-pattern query)",
        description: "Require the root match to be inside a matching container without crossing a callable declaration.",
    }
    NotInside {
        labels: ["not-inside"],
        class: Wrapper,
        shape: Pattern,
        signature: "(not-inside container-pattern query)",
        description: "Exclude root matches lexically inside a matching container.",
    }
    Union {
        labels: ["union"],
        class: Wrapper,
        shape: QueryList,
        signature: "(union query query ...)",
        description: "Return each compatible typed endpoint reached by any branch.",
    }
    Intersect {
        labels: ["intersect"],
        class: Wrapper,
        shape: QueryList,
        signature: "(intersect query query ...)",
        description: "Return compatible typed endpoints reached by every branch.",
    }
    Except {
        labels: ["except"],
        class: Wrapper,
        shape: QueryList,
        signature: "(except query query ...)",
        description: "Return first-branch endpoints not reached by any later branch.",
    }
    EnclosingDecl {
        labels: ["enclosing-decl"],
        class: Wrapper,
        shape: Query,
        signature: "(enclosing-decl query)",
        description: (QueryStepOp::EnclosingDecl),
        step: EnclosingDecl,
    }
    ProcedureOf {
        labels: ["procedure-of", "procedure_of"],
        class: Wrapper,
        shape: Query,
        signature: "(procedure-of query)",
        description: (QueryStepOp::ProcedureOf),
        step: ProcedureOf,
    }
    CfgEntry {
        labels: ["cfg-entry", "cfg_entry"],
        class: Wrapper,
        shape: Query,
        signature: "(cfg-entry query)",
        description: (QueryStepOp::CfgEntry),
        step: CfgEntry,
    }
    CfgExits {
        labels: ["cfg-exits", "cfg_exits"],
        class: Wrapper,
        shape: Query,
        signature: "(cfg-exits query)",
        description: (QueryStepOp::CfgExits),
        step: CfgExits,
    }
    CfgSuccessorEdges {
        labels: ["cfg-successor-edges", "cfg_successor_edges"],
        class: Wrapper,
        shape: Query,
        signature: "(cfg-successor-edges query)",
        description: (QueryStepOp::CfgSuccessorEdges),
        step: CfgSuccessorEdges,
    }
    CfgPredecessorEdges {
        labels: ["cfg-predecessor-edges", "cfg_predecessor_edges"],
        class: Wrapper,
        shape: Query,
        signature: "(cfg-predecessor-edges query)",
        description: (QueryStepOp::CfgPredecessorEdges),
        step: CfgPredecessorEdges,
    }
    CfgEdgeSource {
        labels: ["cfg-edge-source", "cfg_edge_source"],
        class: Wrapper,
        shape: Query,
        signature: "(cfg-edge-source query)",
        description: (QueryStepOp::CfgEdgeSource),
        step: CfgEdgeSource,
    }
    CfgEdgeTarget {
        labels: ["cfg-edge-target", "cfg_edge_target"],
        class: Wrapper,
        shape: Query,
        signature: "(cfg-edge-target query)",
        description: (QueryStepOp::CfgEdgeTarget),
        step: CfgEdgeTarget,
    }
    Typestate {
        labels: ["typestate"],
        class: Wrapper,
        shape: Query,
        signature: "(typestate :protocol-ref namespace:name query)",
        description: (QueryStepOp::Typestate),
        step: Typestate,
    }
    ConcurrentAccessConflicts {
        labels: ["concurrent-access-conflicts", "concurrent_access_conflicts"],
        class: Wrapper,
        shape: Query,
        signature: "(concurrent-access-conflicts query)",
        description: (QueryStepOp::ConcurrentAccessConflicts),
        step: ConcurrentAccessConflicts,
    }
    ValueFlow {
        labels: ["value-flow", "value_flow"],
        class: Wrapper,
        shape: Query,
        signature: "(value-flow :plan-ref namespace:name query)",
        description: (QueryStepOp::ValueFlow),
        step: ValueFlow,
    }
    ClassSet {
        labels: ["class-set", "class_set"],
        class: Wrapper,
        shape: Query,
        signature: "(class-set query)",
        description: (QueryStepOp::ClassSet),
        step: ClassSet,
    }
    AbsentMember {
        labels: ["absent-member", "absent_member"],
        class: Wrapper,
        shape: Query,
        signature: "(absent-member query)",
        description: (QueryStepOp::AbsentMember),
        step: AbsentMember,
    }
    Taint {
        labels: ["taint"],
        class: Wrapper,
        shape: Query,
        signature: "(taint :taint-ref namespace:name query)",
        description: (QueryStepOp::Taint),
        step: Taint,
    }
    Witness {
        labels: ["witness"],
        class: Wrapper,
        shape: Query,
        signature: "(witness [:max-steps count] [:max-bytes count] query)",
        description: (QueryStepOp::Witness),
        step: Witness,
    }
    FileOf {
        labels: ["file-of"],
        class: Wrapper,
        shape: Query,
        signature: "(file-of query)",
        description: (QueryStepOp::FileOf),
        step: FileOf,
    }
    ImportsOf {
        labels: ["imports-of"],
        class: Wrapper,
        shape: Query,
        signature: "(imports-of query)",
        description: (QueryStepOp::ImportsOf),
        step: ImportsOf,
    }
    ImportersOf {
        labels: ["importers-of"],
        class: Wrapper,
        shape: Query,
        signature: "(importers-of query)",
        description: (QueryStepOp::ImportersOf),
        step: ImportersOf,
    }
    Supertypes {
        labels: ["supertypes"],
        class: Wrapper,
        shape: Query,
        signature: "(supertypes [:depth count | :transitive true] query)",
        description: (QueryStepOp::Supertypes),
        step: Supertypes,
    }
    Subtypes {
        labels: ["subtypes"],
        class: Wrapper,
        shape: Query,
        signature: "(subtypes [:depth count | :transitive true] query)",
        description: (QueryStepOp::Subtypes),
        step: Subtypes,
    }
    Members {
        labels: ["members"],
        class: Wrapper,
        shape: Query,
        signature: "(members query)",
        description: (QueryStepOp::Members),
        step: Members,
    }
    Owner {
        labels: ["owner"],
        class: Wrapper,
        shape: Query,
        signature: "(owner query)",
        description: (QueryStepOp::Owner),
        step: Owner,
    }
    ReferencesOf {
        labels: ["references-of"],
        class: Wrapper,
        shape: Query,
        signature: "(references-of [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] query)",
        description: (QueryStepOp::ReferencesOf),
        step: ReferencesOf,
    }
    UsedBy {
        labels: ["used-by"],
        class: Wrapper,
        shape: Query,
        signature: "(used-by [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] query)",
        description: (QueryStepOp::UsedBy),
        step: UsedBy,
    }
    Uses {
        labels: ["uses"],
        class: Wrapper,
        shape: Query,
        signature: "(uses [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] query)",
        description: (QueryStepOp::Uses),
        step: Uses,
    }
    Callers {
        labels: ["callers"],
        class: Wrapper,
        shape: Query,
        signature: "(callers [:depth count] [:proof proven|unproven] query)",
        description: (QueryStepOp::Callers),
        step: Callers,
    }
    Callees {
        labels: ["callees"],
        class: Wrapper,
        shape: Query,
        signature: "(callees [:depth count] [:proof proven|unproven] query)",
        description: (QueryStepOp::Callees),
        step: Callees,
    }
    CallSitesTo {
        labels: ["call-sites-to", "call_sites_to"],
        class: Wrapper,
        shape: Query,
        signature: "(call-sites-to [:proof proven|unproven] query)",
        description: (QueryStepOp::CallSitesTo),
        step: CallSitesTo,
    }
    CallSitesFrom {
        labels: ["call-sites-from", "call_sites_from"],
        class: Wrapper,
        shape: Query,
        signature: "(call-sites-from [:proof proven|unproven] query)",
        description: (QueryStepOp::CallSitesFrom),
        step: CallSitesFrom,
    }
    CallInput {
        labels: ["call-input", "call_input"],
        class: Wrapper,
        shape: Query,
        signature: "(call-input (:receiver true | :parameter-index index | :parameter-name name) query)",
        description: (QueryStepOp::CallInput),
        step: CallInput,
    }
    JsxAttributeValue {
        labels: ["jsx-attribute-value", "jsx_attribute_value"],
        class: Wrapper,
        shape: Query,
        signature: "(jsx-attribute-value [:identity intrinsic|component|unknown] [:element-name name] [:property-name name] query)",
        description: (QueryStepOp::JsxAttributeValue),
        step: JsxAttributeValue,
    }
    ReceiverTargets {
        labels: ["receiver-targets", "receiver_targets"],
        class: Wrapper,
        shape: Query,
        signature: "(receiver-targets [:capture name] query)",
        description: (QueryStepOp::ReceiverTargets),
        step: ReceiverTargets,
    }
    PointsTo {
        labels: ["points-to", "points_to"],
        class: Wrapper,
        shape: Query,
        signature: "(points-to [:capture name] query)",
        description: (QueryStepOp::PointsTo),
        step: PointsTo,
    }
    MemberTargets {
        labels: ["member-targets", "member_targets"],
        class: Wrapper,
        shape: Query,
        signature: "(member-targets [:capture name] query)",
        description: (QueryStepOp::MemberTargets),
        step: MemberTargets,
    }
    FieldWriteValue {
        labels: ["field-write-value", "field_write_value"],
        class: Wrapper,
        shape: Query,
        signature: "(field-write-value [:receiver-identity-id id] [:member-target-id id] query)",
        description: (QueryStepOp::FieldWriteValue),
        step: FieldWriteValue,
    }
    ReceiverOutcome {
        labels: ["receiver-outcome", "receiver_outcome"],
        class: Wrapper,
        shape: Query,
        signature: "(receiver-outcome query)",
        description: (QueryStepOp::ReceiverOutcome),
        step: ReceiverOutcome,
    }
    ReceiverEvidence {
        labels: ["receiver-evidence", "receiver_evidence"],
        class: Wrapper,
        shape: Query,
        signature: "(receiver-evidence query)",
        description: (QueryStepOp::ReceiverEvidence),
        step: ReceiverEvidence,
    }
    CallShape {
        labels: ["call-shape", "call_shape"],
        class: Wrapper,
        shape: Query,
        signature: "(call-shape query)",
        description: (QueryStepOp::CallShape),
        step: CallShape,
    }
    CallResults {
        labels: ["call-results", "call_results"],
        class: Wrapper,
        shape: Query,
        signature: "(call-results query)",
        description: (QueryStepOp::CallResults),
        step: CallResults,
    }
    CallArgumentGroups {
        labels: ["call-argument-groups", "call_argument_groups"],
        class: Wrapper,
        shape: Query,
        signature: "(call-argument-groups query)",
        description: (QueryStepOp::CallArgumentGroups),
        step: CallArgumentGroups,
    }
    CallArguments {
        labels: ["call-arguments", "call_arguments"],
        class: Wrapper,
        shape: Query,
        signature: "(call-arguments query)",
        description: (QueryStepOp::CallArguments),
        step: CallArguments,
    }
    CallBindings {
        labels: ["call-bindings", "call_bindings"],
        class: Wrapper,
        shape: Query,
        signature: "(call-bindings query)",
        description: (QueryStepOp::CallBindings),
        step: CallBindings,
    }
    CallEffects {
        labels: ["call-effects", "call_effects"],
        class: Wrapper,
        shape: Query,
        signature: "(call-effects query)",
        description: (QueryStepOp::CallEffects),
        step: CallEffects,
    }
    ResultContractCalls {
        labels: ["result-contract-calls", "result_contract_calls"],
        class: Wrapper,
        shape: Query,
        signature: "(result-contract-calls query)",
        description: (QueryStepOp::ResultContractCalls),
        step: ResultContractCalls,
    }
    CallResultContracts {
        labels: ["call-result-contracts", "call_result_contracts"],
        class: Wrapper,
        shape: Query,
        signature: "(call-result-contracts query)",
        description: (QueryStepOp::CallResultContracts),
        step: CallResultContracts,
    }
    ResultContractUses {
        labels: ["result-contract-uses", "result_contract_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(result-contract-uses query)",
        description: (QueryStepOp::ResultContractUses),
        step: ResultContractUses,
    }
    ResultContractOperationUses {
        labels: ["result-contract-operation-uses", "result_contract_operation_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(result-contract-operation-uses query)",
        description: (QueryStepOp::ResultContractOperationUses),
        step: ResultContractOperationUses,
    }
    ResultContractFailureUses {
        labels: ["result-contract-failure-uses", "result_contract_failure_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(result-contract-failure-uses [:provenance [condition-result ...]] [:consumer [return ...]] query)",
        description: (QueryStepOp::ResultContractFailureUses),
        step: ResultContractFailureUses,
    }
    NilnessOperations {
        labels: ["nilness-operations", "nilness_operations"],
        class: Wrapper,
        shape: Query,
        signature: "(nilness-operations query)",
        description: (QueryStepOp::NilnessOperations),
        step: NilnessOperations,
    }
    SwitchCoverage {
        labels: ["switch-coverage", "switch_coverage"],
        class: Wrapper,
        shape: Query,
        signature: "(switch-coverage query)",
        description: (QueryStepOp::SwitchCoverage),
        step: SwitchCoverage,
    }
    DetachedTaskTransfers {
        labels: ["detached-task-transfers", "detached_task_transfers"],
        class: Wrapper,
        shape: Query,
        signature: "(detached-task-transfers query)",
        description: (QueryStepOp::DetachedTaskTransfers),
        step: DetachedTaskTransfers,
    }
    ProcedureEffects {
        labels: ["procedure-effects", "procedure_effects"],
        class: Wrapper,
        shape: Query,
        signature: "(procedure-effects query)",
        description: (QueryStepOp::ProcedureEffects),
        step: ProcedureEffects,
    }
    CallableSignature {
        labels: ["callable-signature", "callable_signature"],
        class: Wrapper,
        shape: Query,
        signature: "(callable-signature query)",
        description: (QueryStepOp::CallableSignature),
        step: CallableSignature,
    }
    SignatureParameters {
        labels: ["signature-parameters", "signature_parameters"],
        class: Wrapper,
        shape: Query,
        signature: "(signature-parameters query)",
        description: (QueryStepOp::SignatureParameters),
        step: SignatureParameters,
    }
    DecoratorBindings {
        labels: ["decorator-bindings", "decorator_bindings"],
        class: Wrapper,
        shape: Query,
        signature: "(decorator-bindings [:module module] [:imported-name name] query)",
        description: (QueryStepOp::DecoratorBindings),
        step: DecoratorBindings,
    }
    CallableApplicability {
        labels: ["callable-applicability", "callable_applicability"],
        class: Wrapper,
        shape: Query,
        signature: "(callable-applicability query)",
        description: (QueryStepOp::CallableApplicability),
        step: CallableApplicability,
    }
    OverloadSelection {
        labels: ["overload-selection", "overload_selection"],
        class: Wrapper,
        shape: Query,
        signature: "(overload-selection query)",
        description: (QueryStepOp::OverloadSelection),
        step: OverloadSelection,
    }
    MemberSelection {
        labels: ["member-selection", "member_selection"],
        class: Wrapper,
        shape: Query,
        signature: "(member-selection query)",
        description: (QueryStepOp::MemberSelection),
        step: MemberSelection,
    }
    DispatchOutcome {
        labels: ["dispatch-outcome", "dispatch_outcome"],
        class: Wrapper,
        shape: Query,
        signature: "(dispatch-outcome query)",
        description: (QueryStepOp::DispatchOutcome),
        step: DispatchOutcome,
    }
    DispatchTargets {
        labels: ["dispatch-targets", "dispatch_targets"],
        class: Wrapper,
        shape: Query,
        signature: "(dispatch-targets query)",
        description: (QueryStepOp::DispatchTargets),
        step: DispatchTargets,
    }
    MemberFamily {
        labels: ["member-family", "member_family"],
        class: Wrapper,
        shape: Query,
        signature: "(member-family query)",
        description: (QueryStepOp::MemberFamily),
        step: MemberFamily,
    }
    FamilyEdges {
        labels: ["family-edges", "family_edges"],
        class: Wrapper,
        shape: Query,
        signature: "(family-edges query)",
        description: (QueryStepOp::FamilyEdges),
        step: FamilyEdges,
    }
    Occurrences {
        labels: ["occurrences", "occurrence"],
        class: Wrapper,
        shape: Query,
        signature: "(occurrences [:class ...] [:role ...] [:namespace ...])",
        description: "Seed classified identifier occurrences directly from workspace facts.",
    }
    OccurrencesOf {
        labels: ["occurrences-of", "occurrences_of"],
        class: Wrapper,
        shape: Query,
        signature: "(occurrences-of [:class ...] [:role ...] [:namespace ...] query)",
        description: (QueryStepOp::OccurrencesOf),
        step: OccurrencesOf,
    }
    OccurrencesIn {
        labels: ["occurrences-in", "occurrences_in"],
        class: Wrapper,
        shape: Query,
        signature: "(occurrences-in [:class ...] [:role ...] [:namespace ...] query)",
        description: (QueryStepOp::OccurrencesIn),
        step: OccurrencesIn,
    }
    OccurrenceTarget {
        labels: ["occurrence-target", "occurrence_target"],
        class: Wrapper,
        shape: Query,
        signature: "(occurrence-target query)",
        description: (QueryStepOp::OccurrenceTarget),
        step: OccurrenceTarget,
    }
    Scopes {
        labels: ["scopes", "scope"],
        class: Wrapper,
        shape: Query,
        signature: "(scopes [:kind ...])",
        description: "Seed lexical scope rows directly from workspace facts.",
    }
    Bindings {
        labels: ["bindings", "binding"],
        class: Wrapper,
        shape: Query,
        signature: "(bindings [:kind ...] [:name ...] [:hoisting ...])",
        description: "Seed lexical binding rows directly from workspace facts.",
    }
    Paths {
        labels: ["paths", "path"],
        class: Wrapper,
        shape: Query,
        signature: "(paths [:min-segments N])",
        description: "Seed qualified-path rows directly from workspace facts.",
    }
    SegmentsOf {
        labels: ["segments-of", "segments_of"],
        class: Wrapper,
        shape: Query,
        signature: "(segments-of [:resolved true] query)",
        description: (QueryStepOp::SegmentsOf),
        step: SegmentsOf,
    }
    SegmentTarget {
        labels: ["segment-target", "segment_target"],
        class: Wrapper,
        shape: Query,
        signature: "(segment-target query)",
        description: (QueryStepOp::SegmentTarget),
        step: SegmentTarget,
    }
    ScopeOf {
        labels: ["scope-of", "scope_of"],
        class: Wrapper,
        shape: Query,
        signature: "(scope-of query)",
        description: (QueryStepOp::ScopeOf),
        step: ScopeOf,
    }
    ScopeAncestors {
        labels: ["scope-ancestors", "scope_ancestors"],
        class: Wrapper,
        shape: Query,
        signature: "(scope-ancestors query)",
        description: (QueryStepOp::ScopeAncestors),
        step: ScopeAncestors,
    }
    BindingsIn {
        labels: ["bindings-in", "bindings_in"],
        class: Wrapper,
        shape: Query,
        signature: "(bindings-in [:kind ...] [:name ...] [:hoisting ...] query)",
        description: (QueryStepOp::BindingsIn),
        step: BindingsIn,
    }
    BindingOf {
        labels: ["binding-of", "binding_of"],
        class: Wrapper,
        shape: Query,
        signature: "(binding-of [:include-shadowed true] query)",
        description: (QueryStepOp::BindingOf),
        step: BindingOf,
    }
    BindingOccurrence {
        labels: ["binding-occurrence", "binding_occurrence"],
        class: Wrapper,
        shape: Query,
        signature: "(binding-occurrence query)",
        description: (QueryStepOp::BindingOccurrence),
        step: BindingOccurrence,
    }
    CandidatesOf {
        labels: ["candidates-of", "candidates_of"],
        class: Wrapper,
        shape: Query,
        signature: "(candidates-of [:tier ...] [:outcome ...] [:boundary ...] query)",
        description: (QueryStepOp::CandidatesOf),
        step: CandidatesOf,
    }
    CandidateHierarchy {
        labels: ["candidate-hierarchy", "candidate_hierarchy"],
        class: Wrapper,
        shape: Query,
        signature: "(candidate-hierarchy query)",
        description: (QueryStepOp::CandidateHierarchy),
        step: CandidateHierarchy,
    }
    CandidateTarget {
        labels: ["candidate-target", "candidate_target"],
        class: Wrapper,
        shape: Query,
        signature: "(candidate-target query)",
        description: (QueryStepOp::CandidateTarget),
        step: CandidateTarget,
    }
    GenerationSites {
        labels: ["generation-sites", "generation_sites"],
        class: Wrapper,
        shape: Query,
        signature: "(generation-sites [:kind ...] [:input ...])",
        description: "Seed generation-site rows directly from recorded materialization provenance.",
    }
    Exports {
        labels: ["exports", "export"],
        class: Wrapper,
        shape: Query,
        signature: "(exports [:form ...] [:name ...])",
        description: "Seed export rows directly from recorded materialization provenance.",
    }
    Generates {
        labels: ["generates"],
        class: Wrapper,
        shape: Query,
        signature: "(generates query)",
        description: (QueryStepOp::Generates),
        step: Generates,
    }
    GeneratedBy {
        labels: ["generated-by", "generated_by"],
        class: Wrapper,
        shape: Query,
        signature: "(generated-by query)",
        description: (QueryStepOp::GeneratedBy),
        step: GeneratedBy,
    }
    DeclarationStateOf {
        labels: ["declaration-state-of", "declaration_state_of"],
        class: Wrapper,
        shape: Query,
        signature: "(declaration-state-of [:origin ...] [:declaration-only true] [:config-gated true] query)",
        description: (QueryStepOp::DeclarationStateOf),
        step: DeclarationStateOf,
    }
    ImplementationOf {
        labels: ["implementation-of", "implementation_of"],
        class: Wrapper,
        shape: Query,
        signature: "(implementation-of query)",
        description: (QueryStepOp::ImplementationOf),
        step: ImplementationOf,
    }
    StubsOf {
        labels: ["stubs-of", "stubs_of"],
        class: Wrapper,
        shape: Query,
        signature: "(stubs-of query)",
        description: (QueryStepOp::StubsOf),
        step: StubsOf,
    }
    ExportTarget {
        labels: ["export-target", "export_target"],
        class: Wrapper,
        shape: Query,
        signature: "(export-target query)",
        description: (QueryStepOp::ExportTarget),
        step: ExportTarget,
    }
    EdgesOf {
        labels: ["edges-of", "edges_of"],
        class: Wrapper,
        shape: Query,
        signature: "(edges-of [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] [:usage [...]] [:relation [...]] [:site-class [...]] query)",
        description: (QueryStepOp::EdgesOf),
        step: EdgesOf,
    }
    EdgesFrom {
        labels: ["edges-from", "edges_from"],
        class: Wrapper,
        shape: Query,
        signature: "(edges-from [:reference-kinds [...]] [:proof proven|unproven] [:surface external-usages|lsp-references] [:usage [...]] [:relation [...]] [:site-class [...]] query)",
        description: (QueryStepOp::EdgesFrom),
        step: EdgesFrom,
    }
    EdgeTarget {
        labels: ["edge-target", "edge_target"],
        class: Wrapper,
        shape: Query,
        signature: "(edge-target query)",
        description: (QueryStepOp::EdgeTarget),
        step: EdgeTarget,
    }
    StateEventsOf {
        labels: ["state-events-of", "state_events_of"],
        class: Wrapper,
        shape: Query,
        signature: "(state-events-of [:class [establish|kill|read ...]] [:subject [binding|property ...]] query)",
        description: (QueryStepOp::StateEventsOf),
        step: StateEventsOf,
    }
    FlowRelationsOf {
        labels: ["flow-relations-of", "flow_relations_of"],
        class: Wrapper,
        shape: Query,
        signature: "(flow-relations-of [:relation [reaching|dominates|same-evaluation ...]] [:certainty [exact|may ...]] query)",
        description: (QueryStepOp::FlowRelationsOf),
        step: FlowRelationsOf,
    }
    FlowSource {
        labels: ["flow-source", "flow_source"],
        class: Wrapper,
        shape: Query,
        signature: "(flow-source query)",
        description: (QueryStepOp::FlowSource),
        step: FlowSource,
    }
    FlowTarget {
        labels: ["flow-target", "flow_target"],
        class: Wrapper,
        shape: Query,
        signature: "(flow-target query)",
        description: (QueryStepOp::FlowTarget),
        step: FlowTarget,
    }
    ControlRelations {
        labels: ["control-relations", "control_relations"],
        class: Wrapper,
        shape: Query,
        signature: "(control-relations [:relation [dominates|postdominates|control-depends-on|reachable|in-loop ...]] [:exit-partition [normal-and-exceptional ...]] query)",
        description: (QueryStepOp::ControlRelations),
        step: ControlRelations,
    }
    GuardsOf {
        labels: ["guards-of", "guards_of"],
        class: Wrapper,
        shape: Query,
        signature: "(guards-of query)",
        description: (QueryStepOp::GuardsOf),
        step: GuardsOf,
    }
    TargetOf {
        labels: ["target-of", "target_of"],
        class: Wrapper,
        shape: Query,
        signature: "(target-of query)",
        description: (QueryStepOp::TargetOf),
        step: TargetOf,
    }
    SourceSetOf {
        labels: ["source-set-of", "source_set_of"],
        class: Wrapper,
        shape: Query,
        signature: "(source-set-of query)",
        description: (QueryStepOp::SourceSetOf),
        step: SourceSetOf,
    }
    TopologyEdgesOf {
        labels: ["topology-edges-of", "topology_edges_of"],
        class: Wrapper,
        shape: Query,
        signature: "(topology-edges-of query)",
        description: (QueryStepOp::TopologyEdgesOf),
        step: TopologyEdgesOf,
    }
    RewritePathsOf {
        labels: ["rewrite-paths-of", "rewrite_paths_of"],
        class: Wrapper,
        shape: Query,
        signature: "(rewrite-paths-of [:domain [rust-import-alias ...]] [:outcome [converged|cycle|exceeded-budget ...]] query)",
        description: (QueryStepOp::RewritePathsOf),
        step: RewritePathsOf,
    }
    Name {
        labels: ["name"],
        class: Predicate,
        shape: String,
        signature: "(name \"exactName\")",
        description: "Match a node's normalized name exactly.",
    }
    NameRegex {
        labels: ["name/regex"],
        class: Predicate,
        shape: String,
        signature: "(name/regex \"pattern\")",
        description: "Match a node's normalized name with a regular expression.",
    }
    TextRegex {
        labels: ["text/regex"],
        class: Predicate,
        shape: String,
        signature: "(text/regex \"pattern\")",
        description: "Match a node's source text with a regular expression.",
    }
    BooleanValue {
        labels: ["boolean-value", "boolean_value"],
        class: Predicate,
        shape: Boolean,
        signature: "(boolean-value true|false)",
        description: "Match a boolean literal by its normalized language-neutral value.",
    }
    Capture {
        labels: ["capture"],
        class: Predicate,
        shape: String,
        signature: "(capture \"label\")",
        description: "Capture the matching node under a result label.",
    }
    Has {
        labels: ["has"],
        class: Predicate,
        shape: Pattern,
        signature: "(has descendant-pattern)",
        description: "Require a matching descendant somewhere below this pattern.",
    }
    NotHas {
        labels: ["not-has", "not_has"],
        class: Predicate,
        shape: Pattern,
        signature: "(not-has descendant-pattern)",
        description: "Exclude nodes that contain a matching descendant.",
    }
    NotKind {
        labels: ["not-kind", "not_kind"],
        class: Predicate,
        shape: KindList,
        signature: "(not-kind kind|[kinds...])",
        description: "Exclude one or more normalized kinds using subtype-aware matching.",
    }
    Arity {
        labels: ["arity"],
        class: Predicate,
        shape: Arity,
        signature: "(arity count | :min count :max count)",
        description: "Match a call by its positional argument count, or a collection literal by its element count: an exact count, or inclusive :min/:max bounds.",
    }
    Visibility {
        labels: ["visibility"],
        class: Predicate,
        shape: DeclaredVisibilityList,
        signature: "(visibility public|[public protected ...])",
        description: "Match a callable declaration by the visibility its adapter recorded from modifiers. unknown means the adapter looked and could not classify; it is never equal to public.",
    }
    ParameterType {
        labels: ["parameter-type", "parameter_type"],
        class: Predicate,
        shape: String,
        signature: "(parameter-type \"String\")",
        description: "Match a callable that has a parameter whose recorded type spelling equals this string. The spelling is a discriminator, not a resolved type identity.",
    }
    ParameterTypeRegex {
        labels: ["parameter-type/regex", "parameter_type/regex"],
        class: Predicate,
        shape: String,
        signature: "(parameter-type/regex \"pattern\")",
        description: "Match a callable that has a parameter whose recorded type spelling matches this regular expression.",
    }
}

macro_rules! rql_properties {
    ($($variant:ident {
        labels: [$primary:literal $(, $alias:literal)* $(,)?],
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal,
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RqlProperty {
            $($variant,)+
        }

        pub const ALL_RQL_PROPERTIES: &[RqlProperty] = &[
            $(RqlProperty::$variant,)+
        ];

        impl RqlProperty {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($primary $(| $alias)* => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $primary,)+
                }
            }

            pub fn labels(self) -> &'static [&'static str] {
                match self {
                    $(Self::$variant => &[$primary $(, $alias)*],)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

rql_properties! {
    Name {
        labels: ["name"],
        shape: String,
        signature: ":name \"exactName\"",
        description: "Match the normalized name exactly.",
    }
    NameRegex {
        labels: ["name/regex"],
        shape: RegexString,
        signature: ":name/regex \"pattern\"",
        description: "Match the normalized name with a regular expression.",
    }
    TextRegex {
        labels: ["text/regex"],
        shape: RegexString,
        signature: ":text/regex \"pattern\"",
        description: "Match source text with a regular expression.",
    }
    BooleanValue {
        labels: ["boolean-value", "boolean_value"],
        shape: Boolean,
        signature: ":boolean-value true|false",
        description: "Match a boolean literal by its normalized language-neutral value.",
    }
    Capture {
        labels: ["capture"],
        shape: String,
        signature: ":capture \"label\"",
        description: "Capture the matching node under a result label.",
    }
    NotKind {
        labels: ["not-kind", "not_kind"],
        shape: KindList,
        signature: ":not-kind kind|[kinds...]",
        description: "Exclude one or more normalized kinds.",
    }
    Arity {
        labels: ["arity"],
        shape: Arity,
        signature: ":arity count",
        description: "Match a call by its exact positional argument count, or a collection literal by its exact element count.",
    }
    Visibility {
        labels: ["visibility"],
        shape: DeclaredVisibilityList,
        signature: ":visibility public|[public protected ...]",
        description: "Match a callable declaration by recorded modifier visibility.",
    }
    ParameterType {
        labels: ["parameter-type", "parameter_type"],
        shape: String,
        signature: ":parameter-type \"String\"",
        description: "Match a callable that has a parameter whose recorded type spelling equals this string.",
    }
    ParameterTypeRegex {
        labels: ["parameter-type/regex", "parameter_type/regex"],
        shape: RegexString,
        signature: ":parameter-type/regex \"pattern\"",
        description: "Match a callable that has a parameter whose recorded type spelling matches this regular expression.",
    }
    Has {
        labels: ["has"],
        shape: Pattern,
        signature: ":has pattern",
        description: "Require a matching descendant.",
    }
    NotHas {
        labels: ["not-has", "not_has"],
        shape: Pattern,
        signature: ":not-has pattern",
        description: "Exclude nodes containing a matching descendant.",
    }
}

macro_rules! json_fields {
    ($name:ident, $all:ident, $($variant:ident {
        label: $label:literal,
        shape: $shape:ident,
        signature: $signature:literal,
        description: $description:literal $(,)?
    })+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[
            $($name::$variant,)+
        ];

        impl $name {
            pub fn from_label(label: &str) -> Option<Self> {
                match label {
                    $($label => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }

            pub fn value_shape(self) -> ValueShape {
                match self {
                    $(Self::$variant => ValueShape::$shape,)+
                }
            }

            pub fn signature(self) -> &'static str {
                match self {
                    $(Self::$variant => $signature,)+
                }
            }

            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)+
                }
            }
        }
    };
}

json_fields! {
    QueryField,
    ALL_QUERY_FIELDS,
    Where { label: "where", shape: StringList, signature: "\"where\": [\"glob\", ...]", description: "Restrict the query to workspace-relative path globs." }
    Languages { label: "languages", shape: LanguageList, signature: "\"languages\": [\"rust\", ...]", description: "Restrict the query to analyzer languages." }
    Match { label: "match", shape: Pattern, signature: "\"match\": { pattern }", description: "Define the required root structural pattern." }
    Union { label: "union", shape: QueryList, signature: "\"union\": [{ query }, { query }, ...]", description: "Combine compatible typed endpoints reached by any branch." }
    Intersect { label: "intersect", shape: QueryList, signature: "\"intersect\": [{ query }, { query }, ...]", description: "Keep compatible typed endpoints reached by every branch." }
    Except { label: "except", shape: QueryList, signature: "\"except\": [{ query }, { query }, ...]", description: "Keep first-branch endpoints absent from every later branch." }
    Inside { label: "inside", shape: Pattern, signature: "\"inside\": { pattern }", description: "Require the root match to be inside a matching container." }
    InsideDecl { label: "inside_decl", shape: Pattern, signature: "\"inside_decl\": { pattern }", description: "Require the root match to be inside a matching container without crossing a callable declaration." }
    NotInside { label: "not_inside", shape: Pattern, signature: "\"not_inside\": { pattern }", description: "Exclude root matches inside a matching container." }
    Steps { label: "steps", shape: QuerySteps, signature: "\"steps\": [{ \"op\": \"file_of\" }, ...]", description: "Apply ordered typed transformations to structural matches." }
    Limit { label: "limit", shape: PositiveInteger, signature: "\"limit\": positive integer", description: "Set the maximum number of matches returned." }
    ResultDetail { label: "result_detail", shape: ResultDetail, signature: "\"result_detail\": \"compact\" | \"full\"", description: "Choose compact output or full capture and source details." }
    ExecutionMode { label: "execution_mode", shape: ExecutionMode, signature: "\"execution_mode\": \"results\" | \"explain\" | \"profile\"", description: "Return ordinary results, explain the selected plan without execution, or execute with an operator profile." }
    SchemaVersion { label: "schema_version", shape: SchemaVersion, signature: "\"schema_version\": supported positive integer", description: "Pin one exact CodeQuery schema version; omission selects the compatible lineage head." }
    Occurrences { label: "occurrences", shape: OccurrenceFilter, signature: "\"occurrences\": { \"class\": [...], \"role\": [...], \"namespace\": [...] }", description: "Seed classified identifier occurrences directly from workspace facts." }
    Scopes { label: "scopes", shape: ScopeFilter, signature: "\"scopes\": { \"kind\": [...] }", description: "Seed lexical scope rows directly from workspace facts." }
    Bindings { label: "bindings", shape: BindingFilter, signature: "\"bindings\": { \"kind\": [...], \"name\": [...], \"hoisting\": [...] }", description: "Seed lexical binding rows directly from workspace facts." }
    Paths { label: "paths", shape: PathFilter, signature: "\"paths\": { \"min_segments\": N }", description: "Seed qualified-path rows directly from workspace facts." }
    GenerationSites { label: "generation_sites", shape: GenerationSiteFilter, signature: "\"generation_sites\": { \"kind\": [...], \"input\": [...] }", description: "Seed generation-site rows directly from recorded materialization provenance." }
    Exports { label: "exports", shape: ExportFilter, signature: "\"exports\": { \"form\": [...], \"name\": [...] }", description: "Seed export rows directly from recorded materialization provenance." }
}

json_fields! {
    QueryStepField,
    ALL_QUERY_STEP_FIELDS,
    Op { label: "op", shape: String, signature: "\"op\": \"step_name\"", description: "Select the typed pipeline transformation." }
    Depth { label: "depth", shape: PositiveInteger, signature: "\"depth\": positive integer", description: "Traverse all hierarchy edges from distance one through this depth." }
    Transitive { label: "transitive", shape: TrueBoolean, signature: "\"transitive\": true", description: "Traverse the complete indexed hierarchy under the execution budget." }
    ReferenceKinds { label: "reference_kinds", shape: ReferenceKindList, signature: "\"reference_kinds\": [\"field_write\", ...]", description: "Restrict traversal to structured source-reference kinds." }
    Proof { label: "proof", shape: UsageProof, signature: "\"proof\": \"proven\" | \"unproven\"", description: "Restrict traversal to one usage-proof tier." }
    Completeness { label: "completeness", shape: CallTraversalCompleteness, signature: "\"completeness\": \"exhaustive\" | \"proven_subset\"", description: "Require exhaustive call discovery or intentionally report only resolved proven callers." }
    Surface { label: "surface", shape: UsageSurface, signature: "\"surface\": \"external_usages\" | \"lsp_references\"", description: "Choose the external-usage or editor-visible reference surface." }
    Receiver { label: "receiver", shape: TrueBoolean, signature: "\"receiver\": true", description: "Select the explicit base or receiver expression of a call site." }
    ParameterIndex { label: "parameter_index", shape: NonNegativeInteger, signature: "\"parameter_index\": non-negative integer", description: "Select a zero-based formal parameter slot, excluding receiver-bound parameters." }
    ParameterName { label: "parameter_name", shape: ParameterName, signature: "\"parameter_name\": \"name\"", description: "Select a formal parameter slot by its declared name." }
    Identity { label: "identity", shape: JsxElementIdentity, signature: "\"identity\": \"intrinsic\" | \"component\" | \"unknown\"", description: "Restrict JSX value rows to one semantic element identity." }
    ElementName { label: "element_name", shape: String, signature: "\"element_name\": \"name\"", description: "Restrict JSX value rows to one exact unqualified element tag name." }
    PropertyName { label: "property_name", shape: String, signature: "\"property_name\": \"name\"", description: "Restrict JSX value rows to one exact JSX attribute or object-property name." }
    Capture { label: "capture", shape: CaptureName, signature: "\"capture\": \"declared_name\"", description: "Analyze every unique range bound to a declared positive structural capture." }
    ReceiverIdentityId { label: "receiver_identity_id", shape: String, signature: "\"receiver_identity_id\": \"stable-id\"", description: "Retain field-write rows whose already-proven receiver identity equals this exact analyzer or semantic-model identity." }
    MemberTargetId { label: "member_target_id", shape: String, signature: "\"member_target_id\": \"stable-id\"", description: "Retain field-write rows whose already-proven static member identity equals this exact analyzer or semantic-model identity." }
    ProtocolRef { label: "protocol_ref", shape: ProtocolRef, signature: "\"protocol_ref\": \"namespace:name\"", description: "Select one host-registered compiled protocol and binding plan." }
    PlanRef { label: "plan_ref", shape: ValueFlowPlanRef, signature: "\"plan_ref\": \"namespace:name\"", description: "Select one host-registered immutable value-flow plan." }
    TaintRef { label: "taint_ref", shape: TaintResultRef, signature: "\"taint_ref\": \"namespace:name\"", description: "Select one host-registered immutable retained production taint result." }
    MaxSteps { label: "max_steps", shape: NonNegativeInteger, signature: "\"max_steps\": non-negative integer", description: "Further cap retained witness steps without rerunning analysis." }
    MaxBytes { label: "max_bytes", shape: NonNegativeInteger, signature: "\"max_bytes\": non-negative integer", description: "Further cap retained witness bytes without rerunning analysis." }
    OccurrenceClasses { label: "class", shape: OccurrenceClassList, signature: "\"class\": [\"declaration\", ...]", description: "Restrict occurrence rows to one or more occurrence classes." }
    OccurrenceRoles { label: "role", shape: OccurrenceRoleList, signature: "\"role\": [\"binder\", ...]", description: "Restrict occurrence rows to one or more syntactic occurrence roles." }
    OccurrenceNamespaces { label: "namespace", shape: NamespaceList, signature: "\"namespace\": [\"type\", ...]", description: "Restrict occurrence rows to one or more naming namespaces." }
    BindingKinds { label: "kind", shape: BindingKindList, signature: "\"kind\": [\"local\", ...]", description: "Restrict binding rows to one or more binder kinds." }
    BindingNames { label: "name", shape: BindingNameList, signature: "\"name\": [\"rows\", ...]", description: "Restrict binding rows to one or more exact bound names." }
    BindingHoisting { label: "hoisting", shape: HoistingClassList, signature: "\"hoisting\": [\"scope_wide\", ...]", description: "Restrict binding rows to one or more hoisting classes." }
    DecoratorModule { label: "module", shape: String, signature: "\"module\": \"@scope/package\"", description: "Restrict decorator-binding rows to one exact imported module target." }
    DecoratorImportedName { label: "imported_name", shape: String, signature: "\"imported_name\": \"Query\"", description: "Restrict decorator-binding rows to one exact imported symbol name." }
    IncludeShadowed { label: "include_shadowed", shape: TrueBoolean, signature: "\"include_shadowed\": true", description: "Also return the bindings the binding-of answer shadows, instead of the winner alone." }
    Resolved { label: "resolved", shape: TrueBoolean, signature: "\"resolved\": true", description: "Derive each path segment's own prefix resolution so rows carry a status, targets, and a resolution-decided namespace." }
    CandidateTiers { label: "tier", shape: PrecedenceTierList, signature: "\"tier\": [\"lexical_binding\", \"unattributed\", ...]", description: "Restrict candidate rows to one or more precedence tiers, or to rows whose seam named none." }
    CandidateOutcomes { label: "outcome", shape: CandidateOutcomeList, signature: "\"outcome\": [\"selected\", \"shadowed_by_nearer\", ...]", description: "Restrict candidate rows to one or more coarse outcomes or typed rejection reasons." }
    CandidateBoundaries { label: "boundary", shape: BoundaryStatusList, signature: "\"boundary\": [\"workspace_local\", ...]", description: "Restrict candidate rows to one or more resolution boundary statuses." }
    DeclarationOrigins { label: "origin", shape: DeclarationOriginList, signature: "\"origin\": [\"generated\", ...]", description: "Restrict declaration-state rows to one or more origins." }
    DeclarationOnly { label: "declaration_only", shape: Boolean, signature: "\"declaration_only\": true | false", description: "Restrict declaration-state rows by their declaration-only flag." }
    ConfigGated { label: "config_gated", shape: Boolean, signature: "\"config_gated\": true | false", description: "Restrict declaration-state rows by their configuration gate." }
    EdgeUsageKinds { label: "usage", shape: UsageKindList, signature: "\"usage\": [\"reference\", \"self_receiver\", ...]", description: "Restrict edge rows to one or more usage kinds." }
    EdgeRelations { label: "relation", shape: OwnerRelationList, signature: "\"relation\": [\"same_owner\", ...]", description: "Restrict edge rows to one or more owner relations between the site's encloser and the target." }
    EdgeSiteClasses { label: "site_class", shape: SiteClassList, signature: "\"site_class\": [\"use_site\", ...]", description: "Restrict edge rows to use sites or declaration sites." }
    StateEventClasses { label: "event_class", shape: StateEventClassList, signature: "\"event_class\": [\"establish\", \"read\", ...]", description: "Restrict state-event rows to one or more event classes." }
    StateEventSubjects { label: "subject", shape: FlowSubjectKindList, signature: "\"subject\": [\"binding\", \"property\"]", description: "Restrict state-event rows to binding subjects or property subjects." }
    FlowRelations { label: "flow_relation", shape: FlowRelationList, signature: "\"flow_relation\": [\"reaching\", ...]", description: "Restrict flow-relation rows to one or more relations." }
    RewriteDomains { label: "domain", shape: RewriteDomainList, signature: "\"domain\": [\"rust_import_alias\"]", description: "Restrict rewrite-path rows to one or more declared rewrite domains." }
    RewriteOutcomes { label: "rewrite_outcome", shape: RewriteOutcomeList, signature: "\"rewrite_outcome\": [\"converged\", \"cycle\", \"exceeded_budget\"]", description: "Restrict rewrite-path rows to one or more terminal outcomes." }
    FlowCertainties { label: "certainty", shape: FlowCertaintyList, signature: "\"certainty\": [\"exact\", \"may\"]", description: "Restrict flow-relation rows to one or more certainties." }
    FailureUseProvenances { label: "provenance", shape: FailureUseProvenanceList, signature: "\"provenance\": [\"condition_result\", ...]", description: "Restrict failure-use rows to one or more structured provenance classes." }
    FailureUseConsumers { label: "consumer", shape: FailureUseConsumerList, signature: "\"consumer\": [\"return\", \"returned_call_argument\", \"call_argument\"]", description: "Restrict failure-use rows to one or more structured consumer classes." }
    ControlRelations { label: "control_relation", shape: ControlRelationKindList, signature: "\"control_relation\": [\"dominates\", ...]", description: "Restrict control-relation rows to one or more relations." }
    ControlExitPartitions { label: "exit_partition", shape: ControlExitPartitionList, signature: "\"exit_partition\": [\"normal_and_exceptional\"]", description: "Restrict control-relation rows to one or more exit partitions the claim was computed against." }
}

// The scope filter has exactly one axis, and its JSON key is `kind` -- the same
// spelling the binding filter uses for a different vocabulary. They therefore
// cannot share one label registry, and the scope axis gets its own rather than
// being renamed to something no author would guess.
json_fields! {
    ScopeFilterField,
    ALL_SCOPE_FILTER_FIELDS,
    ScopeKinds { label: "kind", shape: KindList, signature: "\"kind\": [\"block\", ...]", description: "Restrict lexical scope rows to one or more normalized anchor kinds." }
}

// The generation-site and export filters reuse the JSON spellings `kind` and
// `name` over their own vocabularies, so, exactly like the scope axis, each
// gets its own registry rather than a renamed label no author would guess.
json_fields! {
    GenerationSiteFilterField,
    ALL_GENERATION_SITE_FILTER_FIELDS,
    Kinds { label: "kind", shape: GenerationKindList, signature: "\"kind\": [\"accessor_macro\", ...]", description: "Restrict generation-site rows to one or more generation kinds." }
    Inputs { label: "input", shape: GenerationInputList, signature: "\"input\": [\"literal\", \"dynamic\"]", description: "Restrict generation-site rows by their input class." }
}

json_fields! {
    ExportFilterField,
    ALL_EXPORT_FILTER_FIELDS,
    Forms { label: "form", shape: ExportFormList, signature: "\"form\": [\"default_anonymous\", ...]", description: "Restrict export rows to one or more export forms." }
    Names { label: "name", shape: ExportNameList, signature: "\"name\": [\"default\", ...]", description: "Restrict export rows to one or more exact exported names." }
}

/// One RQL option owned by a typed query-step descriptor.
///
/// JSON field names, accepted RQL spellings, requiredness, value shape, and
/// help text all meet here so lowerers and editor validation cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryStepOption {
    field: QueryStepField,
    rql_labels: &'static [&'static str],
    required: bool,
}

impl QueryStepOption {
    const fn required(field: QueryStepField, rql_labels: &'static [&'static str]) -> Self {
        Self {
            field,
            rql_labels,
            required: true,
        }
    }

    const fn optional(field: QueryStepField, rql_labels: &'static [&'static str]) -> Self {
        Self {
            field,
            rql_labels,
            required: false,
        }
    }

    pub const fn field(self) -> QueryStepField {
        self.field
    }

    pub const fn rql_labels(self) -> &'static [&'static str] {
        self.rql_labels
    }

    pub const fn is_required(self) -> bool {
        self.required
    }

    pub fn accepts_rql_label(self, label: &str) -> bool {
        self.rql_labels.contains(&label)
    }
}

const TYPESTATE_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::ProtocolRef,
    &[":protocol-ref"],
)];
const VALUE_FLOW_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::PlanRef,
    &[":plan-ref", ":plan_ref"],
)];
const TAINT_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::TaintRef,
    &[":taint-ref", ":taint_ref"],
)];
const JSX_ATTRIBUTE_VALUE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::Identity, &[":identity"]),
    QueryStepOption::optional(
        QueryStepField::ElementName,
        &[":element-name", ":element_name"],
    ),
    QueryStepOption::optional(
        QueryStepField::PropertyName,
        &[":property-name", ":property_name"],
    ),
];
const FIELD_WRITE_VALUE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(
        QueryStepField::ReceiverIdentityId,
        &[":receiver-identity-id", ":receiver_identity_id"],
    ),
    QueryStepOption::optional(
        QueryStepField::MemberTargetId,
        &[":member-target-id", ":member_target_id"],
    ),
];
const WITNESS_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::MaxSteps, &[":max-steps"]),
    QueryStepOption::optional(QueryStepField::MaxBytes, &[":max-bytes"]),
];
/// Shared by the two occurrence-producing steps and by the `occurrences` seed,
/// so an author spells the same filter the same way wherever it appears.
pub const OCCURRENCE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::OccurrenceClasses, &[":class", ":classes"]),
    QueryStepOption::optional(QueryStepField::OccurrenceRoles, &[":role", ":roles"]),
    QueryStepOption::optional(
        QueryStepField::OccurrenceNamespaces,
        &[":namespace", ":namespaces"],
    ),
];

pub fn occurrence_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    OCCURRENCE_STEP_OPTIONS
        .iter()
        .copied()
        .find(|option| option.accepts_rql_label(label))
}

/// Shared by the `bindings` seed and the `bindings-in` step (#1474).
pub const BINDING_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::BindingKinds, &[":kind", ":kinds"]),
    QueryStepOption::optional(QueryStepField::BindingNames, &[":name", ":names"]),
    QueryStepOption::optional(QueryStepField::BindingHoisting, &[":hoisting"]),
];

/// Exact identity options of the `decorator-bindings` step.
pub const DECORATOR_BINDING_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::DecoratorModule, &[":module"]),
    QueryStepOption::optional(
        QueryStepField::DecoratorImportedName,
        &[":imported-name", ":imported_name"],
    ),
];

/// Options of the `candidates-of` step (#1474).
pub const CANDIDATE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::CandidateTiers, &[":tier", ":tiers"]),
    QueryStepOption::optional(
        QueryStepField::CandidateOutcomes,
        &[":outcome", ":outcomes"],
    ),
    QueryStepOption::optional(
        QueryStepField::CandidateBoundaries,
        &[":boundary", ":boundaries"],
    ),
];

/// Options of the `state-events-of` step (#1480).
pub const STATE_EVENT_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::StateEventClasses, &[":class", ":classes"]),
    QueryStepOption::optional(
        QueryStepField::StateEventSubjects,
        &[":subject", ":subjects"],
    ),
];

/// Options of the `flow-relations-of` step (#1480).
pub const FLOW_RELATION_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::FlowRelations, &[":relation", ":relations"]),
    QueryStepOption::optional(
        QueryStepField::FlowCertainties,
        &[":certainty", ":certainties"],
    ),
];

/// Options of the `result-contract-failure-uses` step (#2796).
pub const RESULT_CONTRACT_FAILURE_USE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(
        QueryStepField::FailureUseProvenances,
        &[":provenance", ":provenances"],
    ),
    QueryStepOption::optional(
        QueryStepField::FailureUseConsumers,
        &[":consumer", ":consumers"],
    ),
];

pub fn flow_state_option_for_rql_label(op: QueryStepOp, label: &str) -> Option<QueryStepOption> {
    op.options()
        .iter()
        .copied()
        .find(|option| option.accepts_rql_label(label))
}

/// Options of the `control-relations` step (#2443).
pub const CONTROL_RELATION_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(
        QueryStepField::ControlRelations,
        &[":relation", ":relations"],
    ),
    QueryStepOption::optional(
        QueryStepField::ControlExitPartitions,
        &[":exit-partition", ":exit_partition", ":exit-partitions"],
    ),
];

/// Options of the `rewrite-paths-of` step (#1480).
pub const REWRITE_PATH_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::RewriteDomains, &[":domain", ":domains"]),
    QueryStepOption::optional(QueryStepField::RewriteOutcomes, &[":outcome", ":outcomes"]),
];

/// Options of the `binding-of` step (#1474).
pub const BINDING_OF_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::optional(
    QueryStepField::IncludeShadowed,
    &[":include-shadowed", ":include_shadowed"],
)];

/// The single option of the `scopes` seed (#1474).
pub const SCOPE_SEED_RQL_LABELS: &[&str] = &[":kind", ":kinds"];

/// Options of the `declaration-state-of` step (#1476).
pub const DECLARATION_STATE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::DeclarationOrigins, &[":origin", ":origins"]),
    QueryStepOption::optional(
        QueryStepField::DeclarationOnly,
        &[":declaration-only", ":declaration_only"],
    ),
    QueryStepOption::optional(
        QueryStepField::ConfigGated,
        &[":config-gated", ":config_gated"],
    ),
];

pub fn declaration_state_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    DECLARATION_STATE_STEP_OPTIONS
        .iter()
        .copied()
        .find(|option| option.accepts_rql_label(label))
}

/// The RQL option spellings of the `generation-sites` seed (#1476), mapped to
/// their own field registry.
pub fn generation_site_field_for_rql_label(label: &str) -> Option<GenerationSiteFilterField> {
    match label {
        ":kind" | ":kinds" => Some(GenerationSiteFilterField::Kinds),
        ":input" | ":inputs" => Some(GenerationSiteFilterField::Inputs),
        _ => None,
    }
}

/// The RQL option spellings of the `exports` seed (#1476), mapped to their own
/// field registry.
pub fn export_field_for_rql_label(label: &str) -> Option<ExportFilterField> {
    match label {
        ":form" | ":forms" => Some(ExportFilterField::Forms),
        ":name" | ":names" => Some(ExportFilterField::Names),
        _ => None,
    }
}

pub fn binding_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    BINDING_STEP_OPTIONS
        .iter()
        .copied()
        .find(|option| option.accepts_rql_label(label))
}

pub fn candidate_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    CANDIDATE_STEP_OPTIONS
        .iter()
        .copied()
        .find(|option| option.accepts_rql_label(label))
}

impl QueryStepOp {
    pub const fn options(self) -> &'static [QueryStepOption] {
        match self {
            Self::Typestate => TYPESTATE_STEP_OPTIONS,
            Self::ValueFlow => VALUE_FLOW_STEP_OPTIONS,
            Self::Taint => TAINT_STEP_OPTIONS,
            Self::JsxAttributeValue => JSX_ATTRIBUTE_VALUE_STEP_OPTIONS,
            Self::FieldWriteValue => FIELD_WRITE_VALUE_STEP_OPTIONS,
            Self::Witness => WITNESS_STEP_OPTIONS,
            Self::OccurrencesOf | Self::OccurrencesIn => OCCURRENCE_STEP_OPTIONS,
            Self::BindingsIn => BINDING_STEP_OPTIONS,
            Self::DecoratorBindings => DECORATOR_BINDING_STEP_OPTIONS,
            Self::CandidatesOf => CANDIDATE_STEP_OPTIONS,
            Self::BindingOf => BINDING_OF_STEP_OPTIONS,
            Self::DeclarationStateOf => DECLARATION_STATE_STEP_OPTIONS,
            Self::StateEventsOf => STATE_EVENT_STEP_OPTIONS,
            Self::FlowRelationsOf => FLOW_RELATION_STEP_OPTIONS,
            Self::ResultContractFailureUses => RESULT_CONTRACT_FAILURE_USE_STEP_OPTIONS,
            Self::ControlRelations => CONTROL_RELATION_STEP_OPTIONS,
            Self::RewritePathsOf => REWRITE_PATH_STEP_OPTIONS,
            _ => &[],
        }
    }

    pub fn option_for_rql_label(self, label: &str) -> Option<QueryStepOption> {
        self.options()
            .iter()
            .copied()
            .find(|option| option.accepts_rql_label(label))
    }
}

pub const ALL_REFERENCE_KINDS: &[ReferenceKind] = &[
    ReferenceKind::MethodCall,
    ReferenceKind::ConstructorCall,
    ReferenceKind::FieldRead,
    ReferenceKind::FieldWrite,
    ReferenceKind::TypeReference,
    ReferenceKind::StaticReference,
    ReferenceKind::SuperCall,
    ReferenceKind::Inheritance,
];

/// The value domain the `reference_kind` row fields publish (issue #2515), in
/// [`ALL_REFERENCE_KINDS`] order. Pinned by a unit test.
pub const REFERENCE_KIND_LABELS: &[&str] = &[
    "method_call",
    "constructor_call",
    "field_read",
    "field_write",
    "type_reference",
    "static_reference",
    "super_call",
    "inheritance",
];

/// The value domain the `proof` row fields publish (issue #2515).
pub const USAGE_PROOF_LABELS: &[&str] = &["proven", "unproven"];

pub fn reference_kind_label(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::MethodCall => "method_call",
        ReferenceKind::ConstructorCall => "constructor_call",
        ReferenceKind::FieldRead => "field_read",
        ReferenceKind::FieldWrite => "field_write",
        ReferenceKind::TypeReference => "type_reference",
        ReferenceKind::StaticReference => "static_reference",
        ReferenceKind::SuperCall => "super_call",
        ReferenceKind::Inheritance => "inheritance",
    }
}

pub fn reference_kind_from_label(label: &str) -> Option<ReferenceKind> {
    ALL_REFERENCE_KINDS
        .iter()
        .copied()
        .find(|kind| reference_kind_label(*kind) == label)
}

/// The constrained-value vocabulary each occurrence filter axis accepts, in the
/// canonical registry order, so parser, validator, hover and completion all read
/// one table (the `ALL_REFERENCE_KINDS` shape).
pub fn occurrence_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::OccurrenceClasses => ALL_OCCURRENCE_CLASSES
            .iter()
            .map(|class| class.label())
            .collect(),
        QueryStepField::OccurrenceRoles => ALL_OCCURRENCE_ROLES
            .iter()
            .map(|role| role.label())
            .collect(),
        QueryStepField::OccurrenceNamespaces => ALL_NAMESPACES
            .iter()
            .map(|namespace| namespace.label())
            .collect(),
        _ => Vec::new(),
    }
}

/// The constrained-value vocabulary each lexical-environment filter axis
/// accepts, in canonical registry order, so parser, validator, hover and
/// completion all read one table (#1474).
///
/// The `:tier` axis additionally accepts [`UNATTRIBUTED_TIER_LABEL`], and the
/// `:outcome` axis accepts the two coarse outcomes plus every typed rejection
/// reason, because "rejected" and "rejected because shadowed" are both things an
/// author legitimately asks for.
pub fn environment_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::BindingKinds => ALL_BINDING_KINDS.iter().map(|kind| kind.label()).collect(),
        QueryStepField::BindingHoisting => ALL_HOISTING_CLASSES
            .iter()
            .map(|class| class.label())
            .collect(),
        QueryStepField::CandidateTiers => std::iter::once(UNATTRIBUTED_TIER_LABEL)
            .chain(ALL_PRECEDENCE_TIERS.iter().map(|tier| tier.label()))
            .collect(),
        QueryStepField::CandidateOutcomes => [
            CandidateOutcomeLabel::Selected.label(),
            CandidateOutcomeLabel::Rejected.label(),
        ]
        .into_iter()
        .chain(ALL_REJECTION_REASONS.iter().map(|reason| reason.label()))
        .collect(),
        QueryStepField::CandidateBoundaries => ALL_BOUNDARY_STATUSES
            .iter()
            .map(|status| status.label())
            .collect(),
        QueryStepField::DeclarationOrigins => ALL_DECLARATION_ORIGINS
            .iter()
            .map(|origin| origin.label())
            .collect(),
        _ => Vec::new(),
    }
}

/// The constrained-value vocabulary each flow-state filter axis accepts, in
/// canonical registry order, so parser, validator, hover and completion all
/// read one table (#1480, the `occurrence_filter_labels` shape).
pub fn flow_state_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::StateEventClasses => ALL_STATE_EVENT_CLASSES
            .iter()
            .map(|class| class.label())
            .collect(),
        QueryStepField::StateEventSubjects => ALL_FLOW_SUBJECT_KINDS
            .iter()
            .map(|kind| kind.label())
            .collect(),
        QueryStepField::FlowRelations => ALL_FLOW_RELATIONS
            .iter()
            .map(|relation| relation.label())
            .collect(),
        QueryStepField::FlowCertainties => ALL_FLOW_CERTAINTIES
            .iter()
            .map(|certainty| certainty.label())
            .collect(),
        _ => Vec::new(),
    }
}

/// The constrained-value vocabulary one *step option* axis accepts, whichever
/// row family owns it. Parser, validator, hover and completion all read this
/// one entry point, so a new constrained axis is spelled once (#1480).
pub fn constrained_step_option_labels(field: QueryStepField) -> Vec<&'static str> {
    let failure_use = failure_use_filter_labels(field);
    if !failure_use.is_empty() {
        return failure_use;
    }
    let flow_state = flow_state_filter_labels(field);
    if !flow_state.is_empty() {
        return flow_state;
    }
    let rewrite_path = rewrite_path_filter_labels(field);
    if !rewrite_path.is_empty() {
        return rewrite_path;
    }
    control_relation_filter_labels(field)
}

pub fn failure_use_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::FailureUseProvenances => FailureUseProvenance::ALL
            .iter()
            .map(|value| value.label())
            .collect(),
        QueryStepField::FailureUseConsumers => FailureUseConsumer::ALL
            .iter()
            .map(|value| value.label())
            .collect(),
        _ => Vec::new(),
    }
}

/// The constrained-value vocabulary each control-relation filter axis accepts,
/// in canonical registry order, so parser, validator, hover and completion all
/// read one table (#2443).
pub fn control_relation_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::ControlRelations => ALL_CONTROL_RELATION_KINDS
            .iter()
            .map(|relation| relation.label())
            .collect(),
        QueryStepField::ControlExitPartitions => ALL_CONTROL_EXIT_PARTITIONS
            .iter()
            .map(|partition| partition.label())
            .collect(),
        _ => Vec::new(),
    }
}

pub fn control_relation_kind_from_label(label: &str) -> Option<ControlRelationKind> {
    ControlRelationKind::from_label(label)
}

pub fn control_exit_partition_from_label(label: &str) -> Option<ControlExitPartition> {
    ControlExitPartition::from_label(label)
}

/// The constrained-value vocabulary each rewrite-path filter axis accepts, in
/// canonical registry order, so parser, validator, hover and completion all
/// read one table (#1480).
pub fn rewrite_path_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::RewriteDomains => ALL_REWRITE_DOMAIN_KINDS
            .iter()
            .map(|domain| domain.label())
            .collect(),
        QueryStepField::RewriteOutcomes => ALL_REWRITE_OUTCOME_KINDS
            .iter()
            .map(|outcome| outcome.label())
            .collect(),
        _ => Vec::new(),
    }
}

pub fn rewrite_domain_from_label(label: &str) -> Option<RewriteDomainKind> {
    RewriteDomainKind::from_label(label)
}

pub fn rewrite_outcome_from_label(label: &str) -> Option<RewriteOutcomeKind> {
    RewriteOutcomeKind::from_label(label)
}

pub fn state_event_class_from_label(label: &str) -> Option<StateEventClass> {
    StateEventClass::from_label(label)
}

pub fn flow_subject_kind_from_label(label: &str) -> Option<FlowSubjectKind> {
    FlowSubjectKind::from_label(label)
}

pub fn flow_relation_from_label(label: &str) -> Option<FlowRelation> {
    FlowRelation::from_label(label)
}

pub fn flow_certainty_from_label(label: &str) -> Option<FlowCertainty> {
    FlowCertainty::from_label(label)
}

pub fn usage_proof_label(proof: UsageProof) -> &'static str {
    match proof {
        UsageProof::Proven => "proven",
        UsageProof::Unproven => "unproven",
    }
}

pub fn jsx_element_identity_labels() -> Vec<&'static str> {
    JsxElementIdentity::ALL
        .iter()
        .map(|identity| identity.label())
        .collect()
}

pub fn jsx_element_identity_from_label(label: &str) -> Option<JsxElementIdentity> {
    JsxElementIdentity::from_label(label)
}

pub fn usage_proof_from_label(label: &str) -> Option<UsageProof> {
    match label {
        "proven" => Some(UsageProof::Proven),
        "unproven" => Some(UsageProof::Unproven),
        _ => None,
    }
}

pub fn call_traversal_completeness_from_label(label: &str) -> Option<CallTraversalCompleteness> {
    match label {
        "exhaustive" => Some(CallTraversalCompleteness::Exhaustive),
        "proven_subset" => Some(CallTraversalCompleteness::ProvenSubset),
        _ => None,
    }
}

pub fn usage_surface_label(surface: UsageHitSurface) -> &'static str {
    match surface {
        UsageHitSurface::ExternalUsages => "external_usages",
        UsageHitSurface::LspReferences => "lsp_references",
    }
}

pub fn usage_surface_from_label(label: &str) -> Option<UsageHitSurface> {
    match label {
        "external_usages" => Some(UsageHitSurface::ExternalUsages),
        "lsp_references" => Some(UsageHitSurface::LspReferences),
        _ => None,
    }
}

/// Every usage kind an edge filter can name, in wire-label order. The labels
/// are [`UsageHitKind::wire_label`]'s, so the query surface and the rendered
/// usage surface can never disagree about a spelling.
pub const ALL_USAGE_KINDS: &[UsageHitKind] = &[
    UsageHitKind::Reference,
    UsageHitKind::Import,
    UsageHitKind::Reexport,
    UsageHitKind::SelfReceiver,
    UsageHitKind::Definition,
    UsageHitKind::OverrideDeclaration,
];

pub fn usage_kind_from_label(label: &str) -> Option<UsageHitKind> {
    ALL_USAGE_KINDS
        .iter()
        .copied()
        .find(|kind| kind.wire_label() == label)
}

json_fields! {
    StringPredicateField,
    ALL_STRING_PREDICATE_FIELDS,
    Regex { label: "regex", shape: String, signature: "\"regex\": \"pattern\"", description: "Match the value with a regular expression." }
}

json_fields! {
    PatternField,
    ALL_PATTERN_FIELDS,
    Kind { label: "kind", shape: KindList, signature: "\"kind\": \"kind\" | [\"kinds\", ...]", description: "Match one or more normalized node kinds." }
    NotKind { label: "not_kind", shape: KindList, signature: "\"not_kind\": \"kind\" | [\"kinds\", ...]", description: "Exclude one or more normalized node kinds." }
    Name { label: "name", shape: StringPredicate, signature: "\"name\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match the node's normalized name." }
    Text { label: "text", shape: RegexPredicate, signature: "\"text\": { \"regex\": \"pattern\" }", description: "Match the node's source text with a regular expression." }
    BooleanValue { label: "boolean_value", shape: Boolean, signature: "\"boolean_value\": true | false", description: "Match a boolean literal by its normalized language-neutral value." }
    Capture { label: "capture", shape: String, signature: "\"capture\": \"label\"", description: "Capture the matching node under a result label." }
    Arity { label: "arity", shape: Arity, signature: "\"arity\": count | { \"min\": count, \"max\": count }", description: "Match a call by its positional argument count, or a collection literal by its element count: an exact count, or inclusive min/max bounds." }
    Visibility { label: "visibility", shape: DeclaredVisibilityList, signature: "\"visibility\": \"public\" | [\"public\", \"protected\", ...]", description: "Match a callable declaration by the visibility its adapter recorded from modifiers." }
    ParameterType { label: "parameter_type", shape: StringPredicate, signature: "\"parameter_type\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match a callable that has a parameter whose recorded type spelling satisfies this predicate. The spelling is a discriminator, not a resolved type identity." }
    Has { label: "has", shape: Pattern, signature: "\"has\": { pattern }", description: "Require a matching descendant." }
    NotHas { label: "not_has", shape: Pattern, signature: "\"not_has\": { pattern }", description: "Exclude nodes containing a matching descendant." }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use std::collections::HashSet;

    /// The `reference_kind` row fields publish this list as their value
    /// domain, so it must stay the exact image of `reference_kind_label` over
    /// the registry (issue #2515).
    #[test]
    fn every_reference_kind_label_is_published_in_registry_order() {
        let mapped = ALL_REFERENCE_KINDS
            .iter()
            .map(|kind| reference_kind_label(*kind))
            .collect::<Vec<_>>();
        assert_eq!(mapped, REFERENCE_KIND_LABELS);
    }

    #[test]
    fn rql_schema_lineage_defaults_to_the_head_and_accepts_exact_pins() {
        assert_eq!(
            resolve_rql_schema_version(None).unwrap(),
            SchemaVersionResolution {
                version: 1,
                origin: SchemaVersionOrigin::ImplicitCompatible,
            }
        );
        assert_eq!(
            resolve_rql_schema_version(Some(1)).unwrap(),
            SchemaVersionResolution {
                version: 1,
                origin: SchemaVersionOrigin::Explicit,
            }
        );

        for retired in [0, 2, 5, 13, 14] {
            let error = resolve_rql_schema_version(Some(retired)).unwrap_err();
            assert_eq!(error.requested, retired);
            assert_eq!(error.supported, vec![1]);
        }
    }

    #[test]
    fn schema_metadata_has_unique_spellings_and_help() {
        let mut forms = HashSet::new();
        for form in ALL_RQL_FORMS {
            assert!(!form.signature().is_empty());
            assert!(!form.description().is_empty());
            for label in form.labels() {
                assert!(forms.insert(*label), "duplicate form label {label}");
                assert_eq!(RqlForm::from_label(label), Some(*form));
            }
        }

        let mut step_ops = HashSet::new();
        for op in ALL_QUERY_STEP_OPS {
            assert!(step_ops.insert(op.label()), "duplicate query step op");
            assert!(!op.signature().is_empty());
            assert!(!op.description().is_empty());
            assert_eq!(QueryStepOp::from_label(op.label()), Some(*op));
        }
        for form in ALL_RQL_FORMS {
            let Some(op) = form.query_step_op() else {
                continue;
            };
            assert_eq!(form.description(), op.description());
            assert_eq!(
                ALL_RQL_FORMS
                    .iter()
                    .filter(|candidate| candidate.query_step_op() == Some(op))
                    .count(),
                1,
                "query step {} must have exactly one RQL wrapper",
                op.label()
            );
        }
        for op in ALL_QUERY_STEP_OPS {
            assert!(
                ALL_RQL_FORMS
                    .iter()
                    .any(|form| form.query_step_op() == Some(*op)),
                "query step {} is missing an RQL wrapper",
                op.label()
            );
        }

        let mut properties = HashSet::new();
        for property in ALL_RQL_PROPERTIES {
            assert!(!property.signature().is_empty());
            assert!(!property.description().is_empty());
            for label in property.labels() {
                assert!(
                    properties.insert(*label),
                    "duplicate property label {label}"
                );
                assert_eq!(RqlProperty::from_label(label), Some(*property));
            }
        }

        for field in ALL_QUERY_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(QueryField::from_label(field.label()), Some(*field));
        }
        for field in ALL_QUERY_STEP_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(QueryStepField::from_label(field.label()), Some(*field));
        }
        for field in ALL_PATTERN_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(PatternField::from_label(field.label()), Some(*field));
        }
        for field in ALL_STRING_PREDICATE_FIELDS {
            assert!(!field.signature().is_empty());
            assert!(!field.description().is_empty());
            assert_eq!(
                StringPredicateField::from_label(field.label()),
                Some(*field)
            );
        }
    }

    #[test]
    fn step_reference_is_exhaustive_over_the_registry() {
        let reference = query_step_reference();
        let lines: Vec<&str> = reference.lines().collect();
        assert_eq!(
            lines.len(),
            ALL_QUERY_STEP_OPS.len(),
            "the step reference must publish exactly one line per registry step"
        );
        // Registry order, so a caller reading the reference and a caller
        // reading the step enum see the same sequence.
        for (line, op) in lines.iter().zip(ALL_QUERY_STEP_OPS) {
            assert_eq!(
                *line,
                format!("{} ({}): {}", op.label(), op.signature(), op.description()),
                "step {} renders its own registry row",
                op.label()
            );
        }
    }

    #[test]
    fn execution_mode_metadata_round_trips_labels_and_help() {
        for mode in ALL_CODE_QUERY_EXECUTION_MODES {
            assert_eq!(
                CodeQueryExecutionMode::from_label(mode.label()),
                Some(*mode)
            );
            assert!(!mode.description().is_empty());
        }
        assert_eq!(
            CodeQueryExecutionMode::default(),
            CodeQueryExecutionMode::Results
        );
    }
}
