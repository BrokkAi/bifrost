//! Declarative metadata for the public CodeQuery/RQL vocabulary.
//!
//! The registries in this module are deliberately executable metadata: parser
//! and validator dispatch use the generated enums, while the REPL and editor
//! use the same signatures and descriptions. Adding an entry without help or
//! a value shape is therefore a macro error, and every handler must match the
//! generated enum exhaustively.

use crate::analyzer::structural::occurrences::{
    ALL_NAMESPACES, ALL_OCCURRENCE_CLASSES, ALL_OCCURRENCE_ROLES,
};
use crate::analyzer::structural::resolution::{
    ALL_BINDING_KINDS, ALL_BOUNDARY_STATUSES, ALL_HOISTING_CLASSES, ALL_PRECEDENCE_TIERS,
    ALL_REJECTION_REASONS,
};
use crate::analyzer::usages::{ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof};
use crate::schema_version::{
    SchemaVersionDescriptor, SchemaVersionRegistry, SchemaVersionResolution,
    UnsupportedSchemaVersion,
};
use std::sync::OnceLock;

use super::ir::{
    CandidateOutcomeLabel, MAX_CAPTURE_LENGTH, MAX_KWARG_NAME_LENGTH, SCHEMA_VERSION,
    UNATTRIBUTED_TIER_LABEL,
};

const RQL_INITIAL_SCHEMA_VERSION: u32 = 2;
const RQL_CFG_SCHEMA_VERSION: u32 = 3;
const RQL_TYPESTATE_SCHEMA_VERSION: u32 = 4;
const RQL_DECLARATION_CONTAINMENT_SCHEMA_VERSION: u32 = 5;
const RQL_VALUE_FLOW_SCHEMA_VERSION: u32 = 6;
const RQL_TAINT_SCHEMA_VERSION: u32 = 7;
/// Occurrence rows, the three occurrence steps, and capture AST ids (#1473).
const RQL_OCCURRENCE_SCHEMA_VERSION: u32 = 8;
/// Lexical scope, binding and resolution-candidate rows, their two seeds and
/// seven steps, and the package clause on the file row (#1474).
const RQL_RESOLUTION_SCHEMA_VERSION: u32 = 9;
/// Qualified-path and path-segment rows, the `paths` seed, and the
/// `segments-of`/`segment-target` steps (#1475).
const RQL_IDENTITY_SCHEMA_VERSION: u32 = 10;
/// Canonical reference-edge rows and the edges-of / edges-from / edge-target
/// steps (#1479). Version 11 because #1475 claimed 10 on a divergent branch,
/// the same renumbering the #1473/#1474 merge recorded for version 2.
const RQL_REFERENCE_EDGE_SCHEMA_VERSION: u32 = 11;
const RQL_SCHEMA_VERSIONS: &[SchemaVersionDescriptor] = &[
    SchemaVersionDescriptor::new(RQL_INITIAL_SCHEMA_VERSION, None, true),
    SchemaVersionDescriptor::new(
        RQL_CFG_SCHEMA_VERSION,
        Some(RQL_INITIAL_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_TYPESTATE_SCHEMA_VERSION,
        Some(RQL_CFG_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_DECLARATION_CONTAINMENT_SCHEMA_VERSION,
        Some(RQL_TYPESTATE_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_VALUE_FLOW_SCHEMA_VERSION,
        Some(RQL_DECLARATION_CONTAINMENT_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_TAINT_SCHEMA_VERSION,
        Some(RQL_VALUE_FLOW_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_OCCURRENCE_SCHEMA_VERSION,
        Some(RQL_TAINT_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_RESOLUTION_SCHEMA_VERSION,
        Some(RQL_OCCURRENCE_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_IDENTITY_SCHEMA_VERSION,
        Some(RQL_RESOLUTION_SCHEMA_VERSION),
        true,
    ),
    SchemaVersionDescriptor::new(
        RQL_REFERENCE_EDGE_SCHEMA_VERSION,
        Some(RQL_IDENTITY_SCHEMA_VERSION),
        true,
    ),
];

const _: () = assert!(RQL_REFERENCE_EDGE_SCHEMA_VERSION as u64 == SCHEMA_VERSION);

static RQL_SCHEMA_VERSION_REGISTRY: OnceLock<SchemaVersionRegistry> = OnceLock::new();

pub(crate) fn rql_schema_version_registry() -> &'static SchemaVersionRegistry {
    RQL_SCHEMA_VERSION_REGISTRY.get_or_init(|| {
        SchemaVersionRegistry::new(RQL_SCHEMA_VERSIONS)
            .expect("the compiled-in RQL schema lineage must be valid")
    })
}

pub(super) const fn oldest_rql_schema_version() -> u64 {
    RQL_SCHEMA_VERSIONS[0].version as u64
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
    LanguageList,
    PositiveInteger,
    NonNegativeInteger,
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
    UsageKindList,
    OwnerRelationList,
    SiteClassList,
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
            Self::LanguageList => "one or more language labels",
            Self::PositiveInteger => "a positive integer",
            Self::NonNegativeInteger => "a non-negative integer",
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
            Self::UsageKindList => "one or more usage kinds",
            Self::OwnerRelationList => "one or more owner relations",
            Self::SiteClassList => "use_site or declaration_site",
        }
    }

    pub fn string_length_bounds(self) -> Option<(usize, usize)> {
        match self {
            Self::ParameterName => Some((1, MAX_KWARG_NAME_LENGTH)),
            Self::CaptureName => Some((1, MAX_CAPTURE_LENGTH)),
            Self::ProtocolRef => Some((3, crate::analyzer::structural::MAX_PROTOCOL_REF_BYTES)),
            Self::ValueFlowPlanRef => {
                Some((3, crate::analyzer::structural::MAX_PROTOCOL_REF_BYTES))
            }
            Self::TaintResultRef => {
                Some((3, crate::analyzer::structural::MAX_TAINT_RESULT_REF_BYTES))
            }
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

macro_rules! minimum_schema_version {
    () => {
        RQL_INITIAL_SCHEMA_VERSION as u64
    };
    ($version:literal) => {
        $version
    };
}

macro_rules! query_step_ops {
    ($($variant:ident {
        label: $label:literal,
        signature: $signature:literal,
        description: $description:literal
        $(, semantic: [$($semantic:ident),*])?
        $(, since: $since:literal)?
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

            pub const fn minimum_schema_version(self) -> u64 {
                match self {
                    $(Self::$variant => minimum_schema_version!($($since)?),)+
                }
            }

            pub const fn semantic_facets(self) -> &'static [QuerySemanticFacet] {
                match self {
                    $(Self::$variant => &[$($(QuerySemanticFacet::$semantic),*)?],)+
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

            pub fn allows_candidate_options(self) -> bool {
                matches!(self, Self::CandidatesOf)
            }

            pub fn allows_edge_options(self) -> bool {
                matches!(self, Self::EdgesOf | Self::EdgesFrom)
            }

            pub fn allows_reaching_binding_options(self) -> bool {
                matches!(self, Self::ReachingBinding)
            }

            pub fn allows_segment_options(self) -> bool {
                matches!(self, Self::SegmentsOf)
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuerySemanticFacet {
    Procedures,
    ProgramPoints,
    ControlEdges,
    Typestate,
    ValueFlow,
    Taint,
}

query_step_ops! {
    EnclosingDecl { label: "enclosing_decl", signature: "structural_match -> declaration", description: "Map structural matches to their smallest real enclosing declarations." }
    ProcedureOf { label: "procedure_of", signature: "structural_match|declaration -> procedure", description: "Resolve each source-backed input to its smallest enclosing executable procedure.", semantic: [Procedures], since: 3, }
    CfgEntry { label: "cfg_entry", signature: "procedure -> program_point", description: "Return the validated entry program point of each procedure.", semantic: [Procedures, ProgramPoints], since: 3, }
    CfgExits { label: "cfg_exits", signature: "procedure -> program_point", description: "Return the validated normal and exceptional exit program points of each procedure.", semantic: [Procedures, ProgramPoints], since: 3, }
    CfgSuccessorEdges { label: "cfg_successor_edges", signature: "program_point -> control_edge", description: "Return one-hop outgoing control edges from each program point.", semantic: [Procedures, ProgramPoints, ControlEdges], since: 3, }
    CfgPredecessorEdges { label: "cfg_predecessor_edges", signature: "program_point -> control_edge", description: "Return one-hop incoming control edges to each program point.", semantic: [Procedures, ProgramPoints, ControlEdges], since: 3, }
    CfgEdgeSource { label: "cfg_edge_source", signature: "control_edge -> program_point", description: "Project each control edge to its source program point.", semantic: [Procedures, ProgramPoints, ControlEdges], since: 3, }
    CfgEdgeTarget { label: "cfg_edge_target", signature: "control_edge -> program_point", description: "Project each control edge to its target program point.", semantic: [Procedures, ProgramPoints, ControlEdges], since: 3, }
    Typestate { label: "typestate", signature: "procedure -> typestate_finding", description: "Run one registered diagnostic-neutral typestate analysis for the exact procedure root.", semantic: [Procedures, Typestate], since: 4, }
    ValueFlow { label: "value_flow", signature: "procedure -> flow_endpoint", description: "Run one registered diagnostic-neutral value-flow plan for the exact procedure root.", semantic: [Procedures, ValueFlow], since: 6, }
    Taint { label: "taint", signature: "procedure -> taint_finding", description: "Project findings retained by one host-registered production taint result for the exact procedure root.", semantic: [Procedures, Taint], since: 7, }
    Witness { label: "witness", signature: "typestate_finding|flow_endpoint -> typestate_witness|flow_witness", description: "Project bounded retained evidence from each typestate finding or reached flow endpoint without rerunning analysis.", since: 4, }
    FileOf { label: "file_of", signature: "structural_match|declaration|procedure|program_point|control_edge|typestate_finding|typestate_witness|flow_endpoint|flow_witness|taint_finding|reference_site|call_site|expression_site|receiver_analysis -> file", description: "Map structural matches, declarations, procedures, program points, control edges, typestate findings, typestate witnesses, flow endpoints, flow witnesses, taint findings, reference sites, call sites, expression sites, or receiver analyses to their workspace files." }
    ImportsOf { label: "imports_of", signature: "file -> file", description: "Traverse one direct project-local import edge forward." }
    ImportersOf { label: "importers_of", signature: "file -> file", description: "Traverse one direct project-local import edge backward." }
    Supertypes { label: "supertypes", signature: "declaration -> declaration", description: "Traverse indexed supertypes from supported type declarations." }
    Subtypes { label: "subtypes", signature: "declaration -> declaration", description: "Traverse indexed subtypes from supported type declarations." }
    Members { label: "members", signature: "declaration -> declaration", description: "Return direct indexed members of type declarations." }
    Owner { label: "owner", signature: "declaration -> declaration", description: "Return the exact indexed declaring type of member declarations." }
    ReferencesOf { label: "references_of", signature: "declaration -> reference_site", description: "Return resolved source reference sites for exact indexed declarations." }
    UsedBy { label: "used_by", signature: "declaration -> declaration", description: "Return exact declarations containing references to each input declaration." }
    Uses { label: "uses", signature: "declaration -> declaration", description: "Return exact declarations referenced by each input declaration." }
    Callers { label: "callers", signature: "declaration -> declaration", description: "Traverse resolved incoming call edges to caller declarations, optionally to a bounded depth." }
    Callees { label: "callees", signature: "declaration -> declaration", description: "Traverse resolved outgoing call edges to callee declarations, optionally to a bounded depth." }
    CallSitesTo { label: "call_sites_to", signature: "declaration -> call_site", description: "Return structured call sites whose resolved callee is each input declaration." }
    CallSitesFrom { label: "call_sites_from", signature: "declaration -> call_site", description: "Return structured call sites lexically owned by each input declaration." }
    CallInput { label: "call_input", signature: "call_site -> expression_site", description: "Project one direct receiver or formal-parameter input from each call site." }
    ReceiverTargets { label: "receiver_targets", signature: "structural_match|reference_site|call_site|expression_site -> receiver_analysis", description: "Analyze a bounded receiver value using adapter-provided structured facts." }
    PointsTo { label: "points_to", signature: "structural_match|reference_site|expression_site -> receiver_analysis", description: "Analyze bounded value provenance using adapter-provided structured facts." }
    MemberTargets { label: "member_targets", signature: "structural_match|reference_site -> receiver_analysis", description: "Resolve exact member declarations through bounded structured receiver facts." }
    OccurrencesOf { label: "occurrences_of", signature: "declaration -> occurrence", description: "Return the declaration-name occurrence of each declaration plus every reference-class occurrence resolving to it.", since: 8, }
    OccurrencesIn { label: "occurrences_in", signature: "structural_match|file -> occurrence", description: "Return classified identifier occurrences lexically inside each structural match or file.", since: 8, }
    OccurrenceTarget { label: "occurrence_target", signature: "occurrence -> declaration", description: "Project the resolved semantic targets of reference-class occurrences.", since: 8, }
    ScopeOf { label: "scope_of", signature: "binding|occurrence|structural_match -> lexical_scope", description: "Return the innermost lexical scope that owns each binding, occurrence, or structural match.", since: 9, }
    ScopeAncestors { label: "scope_ancestors", signature: "lexical_scope -> lexical_scope", description: "Return the enclosing lexical scopes of each scope, innermost first, excluding the scope itself.", since: 9, }
    BindingsIn { label: "bindings_in", signature: "lexical_scope|structural_match -> binding", description: "Return the bindings declared in each lexical scope, or in the scopes inside each structural match.", since: 9, }
    ReachingBinding { label: "reaching_binding", signature: "occurrence -> binding", description: "Return the binding of the occurrence's name that is in effect at its exact position.", since: 9, }
    BindingOccurrence { label: "binding_occurrence", signature: "binding -> occurrence", description: "Return the binder-class occurrence row of each binding's declaring token.", since: 9, }
    CandidatesOf { label: "candidates_of", signature: "occurrence -> resolution_candidate", description: "Return the candidates the resolver considered for each reference-class occurrence, with tier, outcome, and boundary.", since: 9, }
    CandidateTarget { label: "candidate_target", signature: "resolution_candidate -> declaration", description: "Project the workspace declarations of unit-backed resolution candidates.", since: 9, }
    EdgesOf { label: "edges_of", signature: "declaration -> reference_edge", description: "Return the canonical inverse reference edges of each declaration: every usage site the usage index enumerates, with kind, proof, usage kind, and owner relation.", since: 11, }
    EdgesFrom { label: "edges_from", signature: "occurrence -> reference_edge", description: "Return the canonical forward reference edges of each occurrence: the resolver's own resolved targets for that exact token, with kind, proof, usage kind, and owner relation.", since: 11, }
    EdgeTarget { label: "edge_target", signature: "reference_edge -> declaration", description: "Project each reference edge to its exact indexed target declaration.", since: 11, }
    SegmentsOf { label: "segments_of", signature: "qualified_path -> path_segment", description: "Return each path's ordered segment rows with decoded text, spelled generic arity, and (with :resolved true) each segment's own prefix resolution.", since: 10, }
    SegmentTarget { label: "segment_target", signature: "path_segment -> declaration", description: "Project the workspace declarations each path segment's own position resolves to.", since: 10, }
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

macro_rules! rql_form_minimum_schema_version {
    ($step:ident $(, $since:literal)?) => {
        QueryStepOp::$step.minimum_schema_version()
    };
    ($(, $since:literal)?) => {
        minimum_schema_version!($($since)?)
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
        $(, since: $since:literal)?
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

            pub const fn minimum_schema_version(self) -> u64 {
                match self {
                    $(Self::$variant => rql_form_minimum_schema_version!($($step)? $(, $since)?),)+
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
                    | Self::ValueFlow
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
                    | Self::ReceiverTargets
                    | Self::PointsTo
                    | Self::MemberTargets
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
                    | Self::ReachingBinding
                    | Self::BindingOccurrence
                    | Self::CandidatesOf
                    | Self::CandidateTarget
                    | Self::EdgesOf
                    | Self::EdgesFrom
                    | Self::EdgeTarget => None,
                    Self::Name => Some(RqlProperty::Name),
                    Self::NameRegex => Some(RqlProperty::NameRegex),
                    Self::TextRegex => Some(RqlProperty::TextRegex),
                    Self::Capture => Some(RqlProperty::Capture),
                    Self::Has => Some(RqlProperty::Has),
                    Self::NotHas => Some(RqlProperty::NotHas),
                    Self::NotKind => Some(RqlProperty::NotKind),
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
        since: 5,
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
    ValueFlow {
        labels: ["value-flow", "value_flow"],
        class: Wrapper,
        shape: Query,
        signature: "(value-flow :plan-ref namespace:name query)",
        description: (QueryStepOp::ValueFlow),
        step: ValueFlow,
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
    Occurrences {
        labels: ["occurrences", "occurrence"],
        class: Wrapper,
        shape: Query,
        signature: "(occurrences [:class ...] [:role ...] [:namespace ...])",
        description: "Seed classified identifier occurrences directly from workspace facts.",
        since: 8,
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
        since: 9,
    }
    Bindings {
        labels: ["bindings", "binding"],
        class: Wrapper,
        shape: Query,
        signature: "(bindings [:kind ...] [:name ...] [:hoisting ...])",
        description: "Seed lexical binding rows directly from workspace facts.",
        since: 9,
    }
    Paths {
        labels: ["paths", "path"],
        class: Wrapper,
        shape: Query,
        signature: "(paths [:min-segments N])",
        description: "Seed qualified-path rows directly from workspace facts.",
        since: 10,
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
    ReachingBinding {
        labels: ["reaching-binding", "reaching_binding"],
        class: Wrapper,
        shape: Query,
        signature: "(reaching-binding [:include-shadowed true] query)",
        description: (QueryStepOp::ReachingBinding),
        step: ReachingBinding,
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
    CandidateTarget {
        labels: ["candidate-target", "candidate_target"],
        class: Wrapper,
        shape: Query,
        signature: "(candidate-target query)",
        description: (QueryStepOp::CandidateTarget),
        step: CandidateTarget,
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
    Capture { label: "capture", shape: CaptureName, signature: "\"capture\": \"declared_name\"", description: "Analyze every unique range bound to a declared positive structural capture." }
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
    IncludeShadowed { label: "include_shadowed", shape: TrueBoolean, signature: "\"include_shadowed\": true", description: "Also return the bindings the reaching binding shadows, instead of the winner alone." }
    Resolved { label: "resolved", shape: TrueBoolean, signature: "\"resolved\": true", description: "Derive each path segment's own prefix resolution so rows carry a status, targets, and a resolution-decided namespace." }
    CandidateTiers { label: "tier", shape: PrecedenceTierList, signature: "\"tier\": [\"lexical_binding\", \"unattributed\", ...]", description: "Restrict candidate rows to one or more precedence tiers, or to rows whose seam named none." }
    CandidateOutcomes { label: "outcome", shape: CandidateOutcomeList, signature: "\"outcome\": [\"selected\", \"shadowed_by_nearer\", ...]", description: "Restrict candidate rows to one or more coarse outcomes or typed rejection reasons." }
    CandidateBoundaries { label: "boundary", shape: BoundaryStatusList, signature: "\"boundary\": [\"workspace_local\", ...]", description: "Restrict candidate rows to one or more resolution boundary statuses." }
    EdgeUsageKinds { label: "usage", shape: UsageKindList, signature: "\"usage\": [\"reference\", \"self_receiver\", ...]", description: "Restrict edge rows to one or more usage kinds." }
    EdgeRelations { label: "relation", shape: OwnerRelationList, signature: "\"relation\": [\"same_owner\", ...]", description: "Restrict edge rows to one or more owner relations between the site's encloser and the target." }
    EdgeSiteClasses { label: "site_class", shape: SiteClassList, signature: "\"site_class\": [\"use_site\", ...]", description: "Restrict edge rows to use sites or declaration sites." }
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

/// Options of the `reaching-binding` step (#1474).
pub const REACHING_BINDING_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::optional(
    QueryStepField::IncludeShadowed,
    &[":include-shadowed", ":include_shadowed"],
)];

/// The single option of the `scopes` seed (#1474).
pub const SCOPE_SEED_RQL_LABELS: &[&str] = &[":kind", ":kinds"];

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
            Self::Witness => WITNESS_STEP_OPTIONS,
            Self::OccurrencesOf | Self::OccurrencesIn => OCCURRENCE_STEP_OPTIONS,
            Self::BindingsIn => BINDING_STEP_OPTIONS,
            Self::CandidatesOf => CANDIDATE_STEP_OPTIONS,
            Self::ReachingBinding => REACHING_BINDING_STEP_OPTIONS,
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
        _ => Vec::new(),
    }
}

pub fn usage_proof_label(proof: UsageProof) -> &'static str {
    match proof {
        UsageProof::Proven => "proven",
        UsageProof::Unproven => "unproven",
    }
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
    Capture { label: "capture", shape: String, signature: "\"capture\": \"label\"", description: "Capture the matching node under a result label." }
    Has { label: "has", shape: Pattern, signature: "\"has\": { pattern }", description: "Require a matching descendant." }
    NotHas { label: "not_has", shape: Pattern, signature: "\"not_has\": { pattern }", description: "Exclude nodes containing a matching descendant." }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use std::collections::HashSet;

    #[test]
    fn rql_schema_lineage_defaults_to_the_head_and_accepts_exact_pins() {
        assert_eq!(
            resolve_rql_schema_version(None).unwrap(),
            SchemaVersionResolution {
                version: 11,
                origin: SchemaVersionOrigin::ImplicitCompatible,
            }
        );
        assert_eq!(
            resolve_rql_schema_version(Some(2)).unwrap(),
            SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            }
        );
        assert_eq!(
            resolve_rql_schema_version(Some(3)).unwrap(),
            SchemaVersionResolution {
                version: 3,
                origin: SchemaVersionOrigin::Explicit,
            }
        );
        assert_eq!(
            resolve_rql_schema_version(Some(4)).unwrap(),
            SchemaVersionResolution {
                version: 4,
                origin: SchemaVersionOrigin::Explicit,
            }
        );
        assert_eq!(
            resolve_rql_schema_version(Some(5)).unwrap(),
            SchemaVersionResolution {
                version: 5,
                origin: SchemaVersionOrigin::Explicit,
            }
        );
        assert_eq!(
            resolve_rql_schema_version(Some(6)).unwrap(),
            SchemaVersionResolution {
                version: 6,
                origin: SchemaVersionOrigin::Explicit,
            }
        );

        assert_eq!(
            resolve_rql_schema_version(Some(7)).unwrap(),
            SchemaVersionResolution {
                version: 7,
                origin: SchemaVersionOrigin::Explicit,
            }
        );

        assert_eq!(
            resolve_rql_schema_version(Some(8)).unwrap(),
            SchemaVersionResolution {
                version: 8,
                origin: SchemaVersionOrigin::Explicit,
            }
        );

        let error = resolve_rql_schema_version(Some(1)).unwrap_err();
        assert_eq!(error.requested, 1);
        assert_eq!(error.supported, vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn schema_metadata_has_unique_spellings_and_help() {
        let mut forms = HashSet::new();
        for form in ALL_RQL_FORMS {
            assert!(!form.signature().is_empty());
            assert!(!form.description().is_empty());
            assert!((2..=SCHEMA_VERSION).contains(&form.minimum_schema_version()));
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
            assert!((2..=SCHEMA_VERSION).contains(&op.minimum_schema_version()));
            assert_eq!(QueryStepOp::from_label(op.label()), Some(*op));
        }
        for form in ALL_RQL_FORMS {
            let Some(op) = form.query_step_op() else {
                continue;
            };
            assert_eq!(form.description(), op.description());
            assert_eq!(form.minimum_schema_version(), op.minimum_schema_version());
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
