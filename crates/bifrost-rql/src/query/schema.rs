//! Declarative metadata for the public CodeQuery/RQL vocabulary.
//!
//! The registries in this module are deliberately executable metadata: parser
//! and validator dispatch use the generated enums, while the REPL and editor
//! use the same signatures and descriptions. Adding an entry without help or
//! a value shape is therefore a macro error, and every handler must match the
//! generated enum exhaustively.

use brokk_bifrost_analysis::analyzer::common::find_by_label;
use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationMemberRole, ConfigurationScalarKind, ConfigurationValueProvenance,
};
use brokk_bifrost_core::analyzer::cpp_class_facts::CppClassFactKind;
use brokk_bifrost_core::analyzer::cpp_facts::CppProvenanceRule;
use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;
use brokk_bifrost_core::analyzer::structural::control_relation::{
    ALL_CONTROL_EXIT_PARTITIONS, ALL_CONTROL_RELATION_KINDS,
};
use brokk_bifrost_core::analyzer::structural::flow_state::{
    ALL_FLOW_CERTAINTIES, ALL_FLOW_RELATIONS, ALL_FLOW_SUBJECT_KINDS, ALL_STATE_EVENT_CLASSES,
    ALL_STATE_EVENT_READ_CAUSES,
};
use brokk_bifrost_core::analyzer::structural::materialization::{
    ALL_DECLARATION_ORIGINS, ALL_EXPORT_FORMS, ALL_GENERATION_INPUT_CLASSES, ALL_GENERATION_KINDS,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    ALL_NAMESPACES, ALL_OCCURRENCE_CLASSES, ALL_OCCURRENCE_ROLES,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    ALL_BINDING_KINDS, ALL_BOUNDARY_STATUSES, ALL_HOISTING_CLASSES, ALL_PRECEDENCE_TIERS,
    ALL_REJECTION_REASONS,
};
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    ALL_REWRITE_DOMAIN_KINDS, ALL_REWRITE_OUTCOME_KINDS,
};
use brokk_bifrost_core::analyzer::usages::model::{
    ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof,
};
use brokk_bifrost_core::schema_version::{
    SchemaVersionDescriptor, SchemaVersionRegistry, SchemaVersionResolution,
    UnsupportedSchemaVersion,
};
use std::sync::{LazyLock, OnceLock};

use super::ir::{
    AbsentMemberProofFilter, AssignmentRelationKind, CandidateOutcomeLabel, FILE_OF_INPUT_KINDS,
    FailureUseConsumer, FailureUseProvenance, JsxElementIdentity, MAX_CAPTURE_LENGTH,
    MAX_KWARG_NAME_LENGTH, SCHEMA_VERSION, UNATTRIBUTED_TIER_LABEL,
};

/// Metadata for an explicitly typed row literal, shared by lowering and help.
pub(crate) struct RowLiteralForm {
    pub label: &'static str,
    pub signature: &'static str,
    pub description: &'static str,
}

pub(crate) const ROW_ENUM_LITERAL: RowLiteralForm = RowLiteralForm {
    label: "enum",
    signature: "(enum LABEL)",
    description: "A constrained-enum row literal. Use this explicit form for labels such as true or false that otherwise denote Boolean literals.",
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

/// Fixed public language-family membership for the RQL schema lineage.
/// Changing an existing family's membership requires a new RQL schema version.
#[derive(Debug, Clone, Copy)]
pub struct LanguageFamily {
    pub label: &'static str,
    pub members: &'static [brokk_bifrost_core::analyzer::Language],
    pub schema_version: u32,
    pub signature: &'static str,
    pub description: &'static str,
}

pub const LANGUAGE_FAMILIES: &[LanguageFamily] = &[
    LanguageFamily {
        label: "jvm",
        members: &[
            brokk_bifrost_core::analyzer::Language::Java,
            brokk_bifrost_core::analyzer::Language::Kotlin,
            brokk_bifrost_core::analyzer::Language::Scala,
        ],
        schema_version: 1,
        signature: "jvm = [java kotlin scala]",
        description: "Fixed RQL schema-1 family for Java, Kotlin and Scala. Nested language scopes intersect these concrete languages.",
    },
    LanguageFamily {
        label: "js-ts",
        members: &[
            brokk_bifrost_core::analyzer::Language::JavaScript,
            brokk_bifrost_core::analyzer::Language::TypeScript,
        ],
        schema_version: 1,
        signature: "js-ts = [javascript typescript]",
        description: "Fixed RQL schema-1 family for JavaScript (including JSX) and TypeScript (including TSX). No language is inferred from workspace contents.",
    },
];

/// Expand concrete labels and fixed families, deduplicating in authored order.
pub fn expand_language_labels(
    labels: &[&str],
) -> Result<Vec<brokk_bifrost_core::analyzer::Language>, String> {
    use brokk_bifrost_core::analyzer::Language;
    let mut languages = Vec::new();
    for label in labels {
        let concrete;
        let members = if let Some(family) = LANGUAGE_FAMILIES
            .iter()
            .find(|family| family.label == *label)
        {
            assert_eq!(
                family.schema_version, RQL_SCHEMA_VERSION,
                "language family needs an explicit schema-version migration"
            );
            family.members
        } else {
            concrete = [Language::from_config_label(label)
                .ok_or_else(|| format!("unknown language label `{label}`"))?];
            &concrete
        };
        for language in members {
            if !languages.contains(language) {
                languages.push(*language);
            }
        }
    }
    Ok(languages)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFamily {
    Node,
    Python,
}

impl RuntimeFamily {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Python => "python",
        }
    }
}

/// The root binding a reviewed runtime publishes its process inputs on.
///
/// A root is a global object in one runtime and an imported standard-library
/// module in another. Which it is, and how a program binds the name, is the
/// frontend's proof; this vocabulary only names the reviewed root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeGlobal {
    Process,
    Os,
    Sys,
}

impl RuntimeGlobal {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Os => "os",
            Self::Sys => "sys",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeContainer {
    Env,
    Environ,
    Argv,
}

impl RuntimeContainer {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Environ => "environ",
            Self::Argv => "argv",
        }
    }
}

/// One reviewed runtime process-input container a keyed-read query may name.
///
/// The table is the whole accepted vocabulary for the `runtime`, `global`, and
/// `container` fields: a triple absent from it is a query error rather than an
/// empty result, so a policy cannot silently name a container no model
/// publishes. `key_kind` is the way the container's elements are addressed,
/// which is a property of the container rather than of the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeKeyedReadRoot {
    pub family: RuntimeFamily,
    pub global: RuntimeGlobal,
    pub container: RuntimeContainer,
    pub key_kind: RuntimeKeyKind,
}

pub const RUNTIME_KEYED_READ_ROOTS: [RuntimeKeyedReadRoot; 4] = [
    RuntimeKeyedReadRoot {
        family: RuntimeFamily::Node,
        global: RuntimeGlobal::Process,
        container: RuntimeContainer::Env,
        key_kind: RuntimeKeyKind::StaticProperty,
    },
    RuntimeKeyedReadRoot {
        family: RuntimeFamily::Node,
        global: RuntimeGlobal::Process,
        container: RuntimeContainer::Argv,
        key_kind: RuntimeKeyKind::StaticIndex,
    },
    RuntimeKeyedReadRoot {
        family: RuntimeFamily::Python,
        global: RuntimeGlobal::Os,
        container: RuntimeContainer::Environ,
        key_kind: RuntimeKeyKind::StaticProperty,
    },
    RuntimeKeyedReadRoot {
        family: RuntimeFamily::Python,
        global: RuntimeGlobal::Sys,
        container: RuntimeContainer::Argv,
        key_kind: RuntimeKeyKind::StaticIndex,
    },
];

impl RuntimeKeyedReadRoot {
    /// The reviewed row one query names, when the vocabulary has it.
    pub fn for_labels(runtime: &str, global: &str, container: &str) -> Option<&'static Self> {
        RUNTIME_KEYED_READ_ROOTS.iter().find(|root| {
            root.family.label() == runtime
                && root.global.label() == global
                && root.container.label() == container
        })
    }

    /// Every accepted runtime family, in table order.
    pub fn family_labels() -> Vec<&'static str> {
        distinct_labels(
            RUNTIME_KEYED_READ_ROOTS
                .iter()
                .map(|root| root.family.label()),
        )
    }

    /// Every root binding the named family publishes.
    pub fn global_labels(runtime: &str) -> Vec<&'static str> {
        distinct_labels(
            RUNTIME_KEYED_READ_ROOTS
                .iter()
                .filter(move |root| root.family.label() == runtime)
                .map(|root| root.global.label()),
        )
    }

    /// Every container the named family and root publish.
    pub fn container_labels(runtime: &str, global: &str) -> Vec<&'static str> {
        distinct_labels(
            RUNTIME_KEYED_READ_ROOTS
                .iter()
                .filter(move |root| root.family.label() == runtime && root.global.label() == global)
                .map(|root| root.container.label()),
        )
    }
}

fn distinct_labels(labels: impl Iterator<Item = &'static str>) -> Vec<&'static str> {
    let mut distinct: Vec<&'static str> = Vec::new();
    for label in labels {
        if !distinct.contains(&label) {
            distinct.push(label);
        }
    }
    distinct
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSourceOrigin {
    PristineInput,
}

impl RuntimeSourceOrigin {
    pub const fn label(self) -> &'static str {
        "pristine_input"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKeyKind {
    StaticProperty,
    StaticIndex,
}

impl RuntimeKeyKind {
    pub const ALL: [Self; 2] = [Self::StaticProperty, Self::StaticIndex];

    pub const fn label(self) -> &'static str {
        match self {
            Self::StaticProperty => "static-property",
            Self::StaticIndex => "static-index",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "static-property" | "static_property" => Some(Self::StaticProperty),
            "static-index" | "static_index" => Some(Self::StaticIndex),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTypeConstraintForm {
    AssignableTo,
}

impl ReceiverTypeConstraintForm {
    pub fn from_rql_label(label: &str) -> Option<Self> {
        matches!(label, "assignable-to" | "assignable_to").then_some(Self::AssignableTo)
    }

    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::AssignableTo => "assignable_to",
        }
    }

    pub const fn signature(self) -> &'static str {
        match self {
            Self::AssignableTo => "(assignable-to identity|\"qualified\")",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::AssignableTo => {
                "Require the named workspace receiver type or a descendant proven by its typed hierarchy."
            }
        }
    }
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
    CanonicalIntegerDecimal,
    ParameterName,
    CaptureName,
    RegexString,
    StringList,
    PathScope,
    StringPredicate,
    RegexPredicate,
    KindList,
    AssignmentSequenceKind,
    DeclaredVisibilityList,
    LanguageList,
    PositiveInteger,
    PermissionBitMask,
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
    ConfigurationFormatList,
    ConfigurationNodeKindList,
    ConfigurationRoleList,
    ConfigurationScalarKindList,
    ConfigurationKeyList,
    ConfigurationRouteList,
    ConfigurationFactOrdinalList,
    ConfigurationProvenanceList,
    ConfigurationCompletenessList,
    ConfigurationFactsFilter,
    CrossDomainCorrelation,
    CrossDomainRequirement,
    CrossDomainRelation,
    ConfigurationCodeRelation,
    CorrelationDocumentList,
    DependencyConfigurationRelation,
    CorrelationOverrideList,
    DependencyEvidenceFilter,
    Boolean,
    UsageKindList,
    OwnerRelationList,
    SiteClassList,
    StateEventClassList,
    StateEventReadCauseList,
    FlowSubjectKindList,
    FlowRelationList,
    FlowCertaintyList,
    FailureUseProvenanceList,
    FailureUseConsumerList,
    RewriteDomainList,
    RewriteOutcomeList,
    ControlRelationKindList,
    AssignmentRelationKindList,
    BranchRelationKindList,
    CppProvenanceRuleList,
    ControlExitPartitionList,
    JsxElementIdentity,
    RuntimeFamily,
    RuntimeGlobal,
    RuntimeContainer,
    RuntimeSourceOrigin,
    RuntimeKeyKind,
    CallIdentity,
    ReceiverTypeConstraint,
    CallProof,
    AbsentMemberProof,
    RowPredicates,
    RowProjectionColumns,
}

impl ValueShape {
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
    /// A typed cross-domain relation, valid only as the `:relation` of
    /// `correlate`. It is not a query and not a pattern property.
    Relation,
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
        signature: $signature:expr,
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
            /// Assigned once here so a new step declares its shape beside its
            /// signature instead of leaving a partition rule to infer one.
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

            /// Whether this operation can put its output rows in a file other
            /// than the file of the input row it read.
            ///
            /// A reverse relation (`call_sites_to`, `callers`, ...) yields the
            /// referrer of its input. A forward relation (`callees`, `uses`,
            /// `supertypes`, ...) yields the related declaration or site, not
            /// the input. A containment relation (`members`, `owner`) can cross
            /// files where a type and its members are declared apart (Rust
            /// impl blocks, C++ out-of-line definitions, partial classes). The
            /// build and generation relations yield rows that belong to build
            /// files or generation sites. Steps that stay in the input's file
            /// are not listed: `enclosing_decl`, `procedure_of`, filters,
            /// projections, and the facts the analyzer derives about the input
            /// itself (the Python hierarchy facts are located at their root).
            ///
            /// A consumer that evaluates a plan one seed file at a time and
            /// indexes the rows by the file they lie in would ask the wrong
            /// slice for these rows, so such a plan is not sliceable by file
            /// (`PlanPartitioning::restricts_to_seed_file`).
            pub fn rows_may_leave_seed_file(self) -> bool {
                matches!(
                    self,
                    // Reverse relations: the row is the referrer.
                    Self::Callers
                        | Self::CallSitesTo
                        | Self::ReferencesOf
                        | Self::UsedBy
                        | Self::OccurrencesOf
                        | Self::EdgesOf
                        | Self::FamilyEdges
                        | Self::ImportersOf
                        | Self::Subtypes
                        | Self::StubsOf
                        // Forward relations: the row is the related
                        // declaration, file or site.
                        | Self::Supertypes
                        | Self::Uses
                        | Self::Callees
                        | Self::ImplementationOf
                        | Self::ImportsOf
                        | Self::EdgeTarget
                        | Self::OccurrenceTarget
                        | Self::CandidateTarget
                        | Self::SegmentTarget
                        | Self::ExportTarget
                        | Self::DispatchTargets
                        // Containment that can be declared apart.
                        | Self::Members
                        | Self::Owner
                        // Rows that belong to generation sites and build files.
                        | Self::Generates
                        | Self::GeneratedBy
                        | Self::TargetOf
                        | Self::SourceSetOf
                        | Self::TopologyEdgesOf
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
    ValueFlow,
    Taint,
}

query_step_ops! {
    Filter { shape: RowLocal, label: "filter", signature: "row -> row", description: "Retain rows satisfying every typed predicate over the input row's public field schema." }
    Project { shape: RowLocal, label: "project", signature: "row -> projected_row", description: "Publish selected public row fields, optionally under new field names, while preserving the row's source and evidence anchor." }
    CaptureAnchor { shape: RowLocal, label: "anchor", signature: "structural_match -> structural_match", description: "For each distinct node bound to the named positive pattern capture, retain the structural match with that node's source range as its reported anchor." }
    ConfigurationAbsence { shape: RowLocal, label: "configuration_absence", signature: "configuration_fact -> configuration_fact", description: "Apply a document-scoped anti-join to configuration facts. The inner configuration-facts query must select document roots; the result is retained only when no authored fact in that same document matches the filter. Incomplete ingestion is never treated as absence." }
    StatementFacts { shape: RowLocal, label: "statement_facts", signature: "structural_match -> structural_match", description: "Retain structural matches for one registered CodeQL statement fact. Shared shapes are supplied by C++ and Java; goto and alloca require C++. Nested-loop binding proofs are shared by C++, C# and Java." }
    CppFacts { shape: RowLocal, label: "cpp_facts", signature: "structural_match -> structural_match", description: "Retain C++ structural matches that satisfy one registered CodeQL class-rule fact." }
    EnclosingDecl { shape: RowLocal, label: "enclosing_decl", signature: "structural_match|dispatch_target -> declaration", description: "Map source-backed matches and dispatch targets to their smallest real enclosing declarations." }
    ProcedureOf { shape: RowLocal, label: "procedure_of", signature: "structural_match|declaration -> procedure", description: "Resolve each source-backed input to its smallest enclosing executable procedure.", semantic: [Procedures] }
    ProgramPointOf { shape: RowLocal, label: "program_point_of", signature: "structural_match -> program_point", description: "Return the unique semantic program point mapped to a structural match; an absent or ambiguous mapping is incomplete.", semantic: [Procedures, ProgramPoints] }
    CfgEntry { shape: RowLocal, label: "cfg_entry", signature: "procedure -> program_point", description: "Return the validated entry program point of each procedure.", semantic: [Procedures, ProgramPoints] }
    CfgExits { shape: RowLocal, label: "cfg_exits", signature: "procedure -> program_point", description: "Return the validated normal and exceptional exit program points of each procedure.", semantic: [Procedures, ProgramPoints] }
    CfgSuccessorEdges { shape: RowLocal, label: "cfg_successor_edges", signature: "program_point -> control_edge", description: "Return one-hop outgoing control edges from each program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    CfgPredecessorEdges { shape: RowLocal, label: "cfg_predecessor_edges", signature: "program_point -> control_edge", description: "Return one-hop incoming control edges to each program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    CfgEdgeSource { shape: RowLocal, label: "cfg_edge_source", signature: "control_edge -> program_point", description: "Project each control edge to its source program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    CfgEdgeTarget { shape: RowLocal, label: "cfg_edge_target", signature: "control_edge -> program_point", description: "Project each control edge to its target program point.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    Typestate { shape: DerivedValue, label: "typestate", signature: "procedure -> typestate_finding", description: "Run one registered diagnostic-neutral typestate analysis for the exact procedure root.", semantic: [Procedures, Typestate] }
    ValueFlow { shape: DerivedValue, label: "value_flow", signature: "procedure -> flow_endpoint", description: "Run one registered diagnostic-neutral value-flow plan for the exact procedure root.", semantic: [Procedures, ValueFlow] }
    ClassSet { shape: DerivedValue, label: "class_set", signature: "procedure -> class_set_row", description: "Propagate constructor, literal, and declared classes through every call reachable from the procedure and report, for each member access, the classes its receiver may hold. A row whose status is not known carries no proof. Class rows include a Boolean guard_only: true means membership follows only from a guard on an unmodeled producer and cannot support an absent-member finding. False does not prove full runtime path feasibility.", semantic: [Procedures, Dispatch, ValueFlow] }
    AbsentMember { shape: DerivedValue, label: "absent_member", signature: "procedure -> absent_member_finding", description: "Report member accesses whose receiver class set contains a class admitted by an origin, where that class does not declare the member; include the site that introduced it. A class inferred only by guarding an unmodeled producer is insufficient. The conditional tier can retain other unclassified receiver values, or a listed global dynamic write only when every matching write has no receiver bound and an Any member-name set; its condition names the write sites. A DeclaredParameter origin is admitted only when its annotation resolves to one workspace class and the existing surface checks establish no workspace subclasses, unresolved or unmodeled external bases, or attribute hooks such as __getattr__, __getattribute__, and __setattr__. Its condition states the annotated type and that no workspace subclass exists. Each row states its proof tier and, for a conditional row, the remainders that keep the result conditional.", semantic: [Procedures, Dispatch, ValueFlow] }
    Taint { shape: DerivedValue, label: "taint", signature: "procedure -> taint_finding", description: "Project findings retained by one host-registered production taint result for the exact procedure root.", semantic: [Procedures, Taint] }
    Witness { shape: DerivedValue, label: "witness", signature: "typestate_finding|flow_endpoint|absent_member_finding -> typestate_witness|flow_witness|absent_member_witness", description: "Project bounded retained evidence from each typestate finding, reached flow endpoint, or absent-member finding without rerunning analysis." }
    FileOf { shape: RowLocal, label: "file_of", signature: file_of_input_signature(), description: "Map structural matches, declarations, procedures, program points, control edges, typed C++ expression rows, typestate findings, typestate witnesses, flow endpoints, flow witnesses, class-set rows, absent-member findings, absent-member witnesses, taint findings, reference sites, call sites, expression sites, exact JSX attribute operands, receiver analyses, member-target analyses, receiver outcomes, receiver evidence, exact field-write operands, call-shape rows, call-result-contract rows, reviewed result-obligation rows, typed result-contract operation and failure-use rows, callable-signature and callable-metrics rows, pending-cleanup-flow rows, decorated-parameter rows, callable-applicability rows, overload-selection rows, dispatch rows, method-family rows, Python hierarchy facts, failure-handler state rows, Rust pointer finding rows, or state-event rows to their workspace files." }
    ImportsOf { shape: RowLocal, label: "imports_of", signature: "file -> file", description: "Traverse one direct project-local import edge forward." }
    ImportersOf { shape: DerivedValue, label: "importers_of", signature: "file -> file", description: "Traverse one direct project-local import edge backward." }
    PythonImportSite { shape: RowLocal, label: "python_import_site", signature: "structural_match -> structural_match", description: "Enrich a Python import statement with parser-derived import leaves, local resolution, scope, repeated-group membership, the later-duplicate selector, exact except ImportError handler context, self-import, and __all__ facts." }
    PythonImportCycles { shape: RowLocal, label: "python_import_cycles", signature: "structural_match -> structural_match", description: "Annotate Python import sites with confirmed cycles from the persisted workspace file graph. Missing paths remain incomplete because unresolved, external, dynamic, and path-derived package identities are not authoritative." }
    PythonCommentedOutCode { shape: RowLocal, label: "python_commented_out_code", signature: "structural_match -> python_rule_fact", description: "Return one row for each Python comment block recognized by CodeQL's commented-out-code heuristics. The row preserves the full source span and exact comment lines; example-heavy, documentation-like, filler, path, URL, doctest, and end-of-line comments are excluded." }
    PythonUnsafeCyclicImport { shape: RowLocal, label: "python_unsafe_cyclic_import", signature: "structural_match -> python_rule_fact", description: "Report module-level Python member uses and from-imports reached through a persisted import cycle before the target module binds that name. Function-body uses are deferred, while guarded routes and dynamic module attributes remain typed incomplete." }
    PythonDocumentation { shape: RowLocal, label: "python_documentation", signature: "declaration -> python_rule_fact", description: "Report Python module, class, function, and method documentation facts, including public scope, decoded docstring, CodeQL-style code-line count, override status, property-accessor status, and typed incompleteness." }
    PythonUselessClass { shape: RowLocal, label: "python_useless_class", signature: "declaration -> python_rule_fact", description: "Report Python class method counts and the inheritance, subclass, special-method, decorator, mixin, statefulness, and top-level exclusions used by the useless-class policy, with typed incompleteness." }
    PythonAttributeShadowsMethod { shape: RowLocal, label: "python_attribute_shadows_method", signature: "declaration -> python_rule_fact", description: "Report a Python descendant method hidden by an attribute written through an ancestor initializer's self value. Uses complete C3 ancestry and direct declarations; unknown bases, dynamic setattr names, escaped self values, and unresolved local aliases remain typed incomplete." }
    PythonModificationOfDefaultValue { shape: RowLocal, label: "python_modification_of_default_value", signature: "declaration -> python_rule_fact", description: "Report local mutations that can reach a list, dictionary, or set parameter default through direct local aliases. Rebinding and known emptiness guards stop flow; unresolved escapes and conditional local flow remain typed incomplete." }
    PythonOverlyComplexDelete { shape: RowLocal, label: "python_overly_complex_delete", signature: "declaration -> python_rule_fact", description: "Report the reachable-block cyclomatic complexity of Python __del__ methods, pruning only exceptional paths and call continuations that exact semantic and handler evidence proves unlikely; unknown raised types retain their paths." , semantic: [Procedures, ProgramPoints, ControlEdges] }
    Supertypes { shape: DerivedValue, label: "supertypes", signature: "declaration -> declaration", description: "Traverse indexed supertypes from supported type declarations." }
    Subtypes { shape: DerivedValue, label: "subtypes", signature: "declaration -> declaration", description: "Traverse indexed subtypes from supported type declarations." }
    ClassHierarchy { shape: DerivedValue, label: "class_hierarchy", signature: "declaration -> python_hierarchy_fact", description: "Report each selected Python class's typed C3 hierarchy outcome and definite per-base inference_failure facts for unresolved or non-class bases, retaining reason and coverage." }
    ClassBases { shape: DerivedValue, label: "class_bases", signature: "declaration -> python_hierarchy_fact", description: "Return ordered Python runtime direct bases, including the implicit object base, retaining canonical source/external identity, model premises, and unresolved or non-class bases as typed facts." }
    ClassMro { shape: DerivedValue, label: "class_mro", signature: "declaration -> python_hierarchy_fact", description: "Return source and modeled external classes in a complete Python C3 linearization in MRO order with retained ancestry premises; incomplete hierarchies emit no partial MRO rows." }
    MroMembers { shape: DerivedValue, label: "mro_members", signature: "declaration -> python_hierarchy_fact", description: "Return known effective Python source members selected by C3 order, with owner and rank; unknown external member surfaces keep inventory, branch counts, and dependent protocol negatives open." }
    PythonOverrides { shape: DerivedValue, label: "python_overrides", signature: "declaration -> python_hierarchy_fact", description: "Return one typed outcome per Python method; an override row names the nearest inherited same-name method selected by C3." }
    PythonCallRelations { shape: DerivedValue, label: "python_call_relations", signature: "declaration -> python_hierarchy_fact", description: "Report exact Python superclass lifecycle calls and super/delete context checks using C3, call shapes, bindings, and bounded dispatch; open evidence stays incomplete.", semantic: [Procedures, Dispatch] }
    PythonOverrideSignatures { shape: DerivedValue, label: "python_override_signatures", signature: "declaration -> python_hierarchy_fact", description: "Join each Python override selected by C3 with every source and target callable-signature pair, retaining signature identity, arity, and coverage." }
    Members { shape: RowLocal, label: "members", signature: "declaration -> declaration", description: "Return direct indexed members of type declarations." }
    Owner { shape: RowLocal, label: "owner", signature: "declaration -> declaration", description: "Return the exact indexed declaring type of member declarations." }
    ReferencesOf { shape: DerivedValue, label: "references_of", signature: "declaration -> reference_site", description: "Return resolved source reference sites for exact indexed declarations." }
    UsedBy { shape: DerivedValue, label: "used_by", signature: "declaration -> declaration", description: "Return exact declarations containing references to each input declaration." }
    Uses { shape: RowLocal, label: "uses", signature: "declaration -> declaration", description: "Return exact declarations referenced by each input declaration." }
    Callers { shape: DerivedValue, label: "callers", signature: "declaration -> declaration", description: "Traverse resolved incoming call edges to caller declarations, optionally to a bounded depth." }
    Callees { shape: RowLocal, label: "callees", signature: "declaration -> declaration | procedure -> procedure", description: "Traverse resolved outgoing call edges from declarations. For an exact procedure row, also follow callback arguments only when the resolved callee body invokes the corresponding formal and points-to identity matches a source-backed callable creation." }
    CallSitesTo { shape: DerivedValue, label: "call_sites_to", signature: "declaration -> call_site", description: "Return structured call sites whose resolved callee is each input declaration, with semantic identity when available." }
    CallSitesFrom { shape: RowLocal, label: "call_sites_from", signature: "declaration -> call_site", description: "Return structured call sites lexically owned by each input declaration, with semantic identity when available." }
    CallInput { shape: RowLocal, label: "call_input", signature: "call_site -> expression_site", description: "Project one direct receiver or formal-parameter input from each call site." }
    JsxAttributeValue { shape: RowLocal, label: "jsx_attribute_value", signature: "structural_match -> jsx_attribute_value", description: "Project the exact normalized expression operand of JSX attributes, with intrinsic/component/unknown element identity and explicit incompleteness for unresolved semantic cases." }
    ReceiverTargets { shape: DerivedValue, label: "receiver_targets", signature: "structural_match|reference_site|call_site|expression_site|occurrence -> receiver_analysis", description: "Analyze a bounded receiver value using adapter-provided structured facts." }
    PointsTo { shape: DerivedValue, label: "points_to", signature: "structural_match|reference_site|expression_site|occurrence -> receiver_analysis", description: "Analyze bounded value provenance using adapter-provided structured facts." }
    MemberTargets { shape: DerivedValue, label: "member_targets", signature: "structural_match|reference_site|occurrence -> member_target_analysis", description: "Resolve exact static member identities together with the receiver owner and model provenance used by bounded structured receiver analysis." }
    KeyedReadValue { shape: DerivedValue, label: "keyed_read_value", signature: "structural_match -> keyed_read_value", description: "Resolve a runtime-root keyed load to its exact executable value observation under the active runtime model, retaining incomplete and exclusion evidence.", semantic: [Procedures, ProgramPoints, ValueFlow] }
    FieldWriteValue { shape: RowLocal, label: "field_write_value", signature: "member_target_analysis -> field_write_value", description: "Project the exact right-hand expression of a simple assignment whose static member and receiver identities were proven by member_targets, optionally retaining only exact receiver/member identities." }
    ReceiverOutcome { shape: RowLocal, label: "receiver_outcome", signature: "structural_match|reference_site|call_site|expression_site|occurrence|receiver_analysis|member_target_analysis -> receiver_outcome", description: "Analyze an ordinary call or member site directly, or project an existing receiver analysis, into its mandatory terminal outcome row." }
    ReceiverEvidence { shape: RowLocal, label: "receiver_evidence", signature: "structural_match|reference_site|call_site|expression_site|occurrence|receiver_analysis -> receiver_evidence", description: "Analyze an ordinary call or member site directly, or project an existing receiver analysis, into zero or more parent-linked evidence rows." }
    PointsToCandidates { shape: RowLocal, label: "points_to_candidates", signature: "receiver_analysis -> points_to_candidate", description: "Expand the exact semantic object candidates retained by points_to before receiver/type projection can merge them, preserving each candidate's stable object identity, cardinality, proof, completeness, and set coverage.", semantic: [Procedures, ProgramPoints] }
    CallShape { shape: RowLocal, label: "call_shape", signature: "structural_match|call_site|occurrence -> call_shape", description: "Project the mandatory structured call-shape outcome row for each exact call site, including its structurally decoded callee token and written argument count when available. Rust rows also publish callee_provenance (caller_supplied, local_closure, declared, unknown), callee_supplier (parameter ordinal, closure_parameter ordinal, or receiver), callee_type_shape and callee_bounds. Other languages state unsupported provenance." }
    ExactExternalCallee { shape: RowLocal, label: "exact_external_callee", signature: "call_shape -> call_shape", description: "Attach the canonical Python external callee proved by the language resolver for a call shape, when available. Import aliases are resolved from structured import bindings; no callee spelling is treated as proof." }
    CallResults { shape: RowLocal, label: "call_results", signature: "call_shape -> call_result", description: "Project the ordered normal result ports of each exact semantic call represented by a call-shape row. Each row carries the structural site identity, semantic call and procedure identities, zero-based result ordinal, procedure-local value identity, result point, and evidence quality so it can join assignments and guards without inferring source order.", semantic: [Procedures, ProgramPoints] }
    CallArgumentGroups { shape: RowLocal, label: "call_argument_groups", signature: "call_shape -> call_argument_group", description: "Project the ordered argument-list group rows of each call shape." }
    CallArguments { shape: RowLocal, label: "call_arguments", signature: "call_argument_group -> call_argument", description: "Project the ordered argument rows of each argument-list group." }
    CallEffects { shape: RowLocal, label: "call_effects", signature: "call_shape -> call_effect", description: "Project the direct effect rows of each call shape: one row per (dispatch arm, declared effect) for every callee an active semantic-model pack declares effects for, carrying the effect id, the pack-authored timing, additive canonical execution timing, the certainty meet of the declaration and the dispatch proof, and the pack provenance. At least one row per call shape, so an unresolved, unmodeled or unsupported dispatch states that instead of answering empty. The callee set and its proof are the dispatch oracle's own answer; nothing is re-derived here.", semantic: [Procedures] }
    ResultContractCalls { shape: Batched, label: "result_contract_calls", signature: "call_shape -> call_shape", description: "Retain call shapes whose exhaustively resolved canonical dispatch arms unanimously select an activated semantic-model summary with at least one reviewed result contract. This lightweight positive candidate discovery uses structural call shapes, exact definition resolution (including Go package, bound-receiver, and conservative method-expression applicability), and activated model keys without materializing procedure semantics: conclusively unmodeled calls are omitted, while conflicts or interrupted dispatch make the query incomplete." }
    CallResultContracts { shape: Batched, label: "call_result_contracts", signature: "call_shape -> call_result_contract", description: "Project reviewed validity contracts for a call's normal results from the unique activated semantic-model summary for every possible dispatch arm. A positive row identifies the protected result ordinal and either a predicate over a separate condition result or a direct result-success predicate, derives only the exact normalized success-guard edges needed to instantiate that contract, counts reviewed member contracts, and reports whether every modeled arm declares a fresh allocation at that indexed result. It does not inspect resource-sensitive uses. At least one row per call shape; unresolved dispatch or conflicting models produce an explicit terminal row and incomplete query rather than an empty answer.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    CallResultObligations { shape: Batched, label: "call_result_obligations", signature: "call_shape -> call_result_obligation", description: "Project exact per-port call-result-use classifications for languages with structured adapters. Java rows join discarded calls to reviewed return-use obligations from the selected JDK artifact, Python and TypeScript rows may join reviewed pure builtin string transformations under their explicitly stated builtin-receiver assumptions, JavaScript rows require an exact literal/template or builtin String constructor receiver, and PHP rows may join reviewed global-function transformations and false-status obligations only after resolver-proven global-function identity and activated declaration evidence. Go rows may join a native predeclared-error obligation, Rust rows may join native Result or must_use obligations proved from resolved declaration signatures, and C/C++ rows may join native must-use obligations proved from structurally selected nodiscard or warn_unused_result declaration and workspace type attributes. Every row publishes obligation provenance and basis when present; missing source, syntax, model, signature, attribute, or dispatch proof remains explicit in coverage and reason fields.", semantic: [Procedures, Dispatch] }
    ProcedureReturnProfile { shape: RowLocal, label: "procedure_return_profile", signature: "procedure -> python_rule_fact", description: "Project one typed Python callable return profile from reachable ProcedureReturn events and exact return syntax, including value/None counts, async/generator status, and explicit coverage.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    PythonIteratorReturnProtocol { shape: DerivedValue, label: "python_iterator_return_protocol", signature: "procedure -> python_rule_fact", description: "For each value returned by a Python __iter__ method, propagate its bounded runtime classes and check inherited __iter__ and __next__ members. Unknown or incomplete class sets stay open.", semantic: [Procedures, Dispatch, ValueFlow] }
    PythonBuiltinIdentity { shape: RowLocal, label: "python_builtin_identity", signature: "occurrence -> python_rule_fact", description: "Resolve one unqualified Python builtin-name occurrence against its exact lexical binding and the Python builtin inventory. A local or module binding is reported as a partial shadow; the optional call_callee field selects only the exact function child of a parsed call expression." }
    PythonUninitializedVariable { shape: RowLocal, label: "python_uninitialized_variable", signature: "occurrence -> python_rule_fact", description: "Join one exact Python value reference to its lexical binding and procedure-local CFG read. Emit a finding only when the binding may be uninitialized on a modeled path; module/class scopes, globals, builtins, closures and open flow identities remain incomplete.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    PythonVariableOf { shape: RowLocal, label: "python_variable_of", signature: "binding|occurrence -> python_rule_fact", description: "Map one Python lexical binding or identifier occurrence to its query-local lexical variable, grouping definitions and uses by resolved scope and name with global/nonlocal redirection." }
    PythonVariableDefinitions { shape: RowLocal, label: "python_variable_definitions", signature: "python_rule_fact -> python_rule_fact", description: "Return the source-ordered definitions of one Python lexical variable with definition kind, first-definition status, reachability, and variable identity." }
    PythonVariableUses { shape: RowLocal, label: "python_variable_uses", signature: "python_rule_fact -> python_rule_fact", description: "Return reads and writes of one Python lexical variable, including whether each use occurs in a nested scope." }
    PythonVariablePeers { shape: RowLocal, label: "python_variable_peers", signature: "python_rule_fact -> python_rule_fact", description: "Return same-name Python lexical variables from other scopes in the same file, preserving both variable identities and module-definition exclusion facts." }
    PythonVariableNestedLoops { shape: RowLocal, label: "python_variable_nested_loops", signature: "python_rule_fact -> python_rule_fact", description: "Return nested Python for-loop pairs that target one lexical variable, with outer-loop use and whether a later read observes the inner target after the inner loop." }
    PythonRaiseNotImplemented { shape: RowLocal, label: "python_raise_not_implemented", signature: "structural_match -> python_rule_fact", description: "Resolve the exact value raised by a Python raise statement and report the builtin NotImplemented singleton, a partial local shadow, or open identity. Supports direct and call-form raises and one exact same-block local alias; unresolved identity remains open." }
    CallResultUse { shape: RowLocal, label: "call_result_use", signature: "call_shape -> python_rule_fact", description: "Classify an exact Python call result as consumed, discarded, or open and include its resolved local callable return contract when proven. Module-level call use is structural and does not invent a module procedure.", semantic: [Procedures, Dispatch] }
    PythonAssertionContext { shape: RowLocal, label: "python_assertion_context", signature: "structural_match -> python_rule_fact", description: "Classify the enclosing Python assertion test scope and whether the assertion is a direct statement in the terminal else suite of an elif chain. Unresolved unittest inheritance remains unknown." }
    TupleReturnAssignment { shape: RowLocal, label: "tuple_return_assignment", signature: "structural_match -> python_rule_fact", description: "Resolve a direct Python tuple or list assignment from a local call and compare the exact return tuple arities with the direct assignment target count. Dynamic targets and incomplete return identities stay open.", semantic: [Procedures, Dispatch] }
    PythonImplicitStringConcatenation { shape: RowLocal, label: "python_implicit_string_concatenation", signature: "structural_match -> python_rule_fact", description: "Emit one Python rule-fact row per implicit string literal part inside a list element that is concatenated with another string constant. Each row is anchored on the literal part." }
    TupleReturnGroups { shape: RowLocal, label: "tuple_return_groups", signature: "procedure -> python_rule_fact", description: "Group exact Python tuple-return arities by callable, follow only supported local tuple identities, and preserve annotation exclusion and incomplete flow evidence.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    LambdaForwarding { shape: RowLocal, label: "lambda_forwarding", signature: "structural_match -> python_rule_fact", description: "Prove whether an exact Python lambda forwards its positional parameters unchanged to one exact local callable; changed arguments and unsupported or ambiguous forms remain explicit.", semantic: [Procedures, Dispatch] }
    PythonFormatIssues { shape: RowLocal, label: "python_format_issues", signature: "structural_match -> python_rule_fact", description: "Project typed Python brace-format and percent-format issue rows from exact call and binary-expression nodes. Format values and single-initializer aliases are resolved structurally; unsupported argument or value shapes remain typed incomplete." }
    PythonUrlConstruction { shape: RowLocal, label: "python_url_construction", signature: "structural_match -> python_rule_fact", description: "Project one typed URL-control fact per exact Python string-construction slot in concatenation, f-strings, percent formatting, and literal str.format calls. Decoded constant prefixes classify full versus partial URL control; unknown source shapes remain typed incomplete." }

    PythonRaiseLegality { shape: RowLocal, label: "python_raise_legality", signature: "structural_match -> python_rule_fact", description: "Classify the exact operand of a Python raise statement as a proven exception class/instance, a proven non-exception value, or open when resolver or hierarchy evidence is incomplete." }
    PythonSpecialMethodRaise { shape: RowLocal, label: "python_special_method_raise", signature: "structural_match -> python_rule_fact", description: "Compare an exact direct Python raise operand in a special method with CodeQL's documented exception families, retaining open results for incomplete CFG, hierarchy, handler, or inherited-method evidence.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    ResultContractUses { shape: Batched, label: "result_contract_uses", signature: "call_result_contract -> call_result_contract", description: "Summarize operation-sensitive uses of each positive call-result-contract row while preserving acquisition identity. This optional enrichment counts every exact structured operation, reports the lower bound of reviewed required operations proved unguarded, and carries aggregate use-validation coverage. Terminal rows pass through unchanged; incomplete structured use evidence makes only this relation incomplete.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    ResultSubjectUses { shape: Batched, label: "result_subject_uses", signature: "call_result -> result_subject_use", description: "Project procedure-local exact normal-result reference provenance to receiver uses. It makes no claim about freshness, non-nullness, distinctness, or provider behavior. Explicit terminal unknown rows pass through unchanged and preserve incomplete call-result discovery.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    ResultContractOperationUses { shape: Batched, label: "result_contract_operation_uses", signature: "call_result_contract -> result_contract_use", description: "Project one typed row per structured operation on a protected result. Intrinsic dereference, field, and index operations are required uses. Receiver calls use exact complete member operation contracts. Exact positional call arguments use complete possible-target procedure-entry preconditions and carry parameter_ordinal. Missing, conflicting, expanded, or ambiguous operation evidence stays open. Each row is anchored at the operation and carries its acquisition identity, exact applicability, timing, required predicate, and guarded, unguarded, not_applicable, or unknown verdict.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    ResultContractFailureUses { shape: Batched, label: "result_contract_failure_uses", signature: "call_result_contract -> result_contract_failure_use", description: "Project structured values returned or passed to calls inside the exact failure arm of a reviewed conditional result contract. Each row compares the operand's exact reaching binding/value provenance with the paired condition result and classifies condition_result, distinct_zero_binding, distinct_binding, independent, or unknown. Exact normalized failure-edge confinement and complete structured identity are required for closed proof; ambiguity remains an open unknown row.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    NilnessOperations { shape: RowLocal, label: "nilness_operations", signature: "procedure -> nilness_operation", description: "Project source-backed pointer operations with their procedure-local scalar nilness fact. Explicit dereferences and implicit pointer field loads or stores are intrinsic operations; receiver calls are included only when exhaustive reviewed models require a non-null receiver. Unsupported identity or scalar evidence stays explicit and open rather than becoming a finding. Only Go procedures are supported; for other languages the step yields no rows and the result carries an incomplete unsupported_structural_feature diagnostic.", semantic: [Procedures, Dispatch, ProgramPoints, ControlEdges] }
    SwitchCoverage { shape: RowLocal, label: "switch_coverage", signature: "procedure -> switch_coverage", description: "Project one source-backed coverage verdict for each switch. An explicit default is exhaustive; an exact Boolean expression selector is exhaustive only with both literal cases and non-exhaustive when a complete literal case set omits either value. Expressionless switches without default, type switches, open selector domains, and nonliteral case sets remain unknown.", semantic: [Procedures, ProgramPoints, ControlEdges, SwitchFacts] }
    AssignmentRelations { shape: RowLocal, label: "assignment_relations", signature: "procedure -> assignment_relation", description: "Project source-backed assignment and local-initializer relation rows by joining prepared syntax to exact local-binding, same-evaluation, and reaching-definition evidence. The default selects self-assignment; self-initializer and failed-swap are opt-in. Unsupported candidates, dialects, and selected relations report incomplete coverage rather than certifying absence.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    DetachedTaskTransfers { shape: RowLocal, label: "detached_task_transfers", signature: "procedure -> detached_task_transfer", description: "Project receiver, argument, and exact local closure-capture values copied into calls whose semantic invocation mode is detached and whose execution timing is different_task. Each row carries stable value identity and an exact abstract-object identity when the heap oracle proves one closed candidate; absent, ambiguous, open, or unproven object sets remain explicit open terminal rows.", semantic: [Procedures, ProgramPoints] }
    ProcedureEffects { shape: RowLocal, label: "procedure_effects", signature: "declaration|procedure -> procedure_effect", description: "Summarize the effects of each declaration or exact procedure row over its reachable call graph: one row per (procedure, effect id), classified direct or transitive, with the hop count, the certainty and timing carried along the attributing chain, a bounded witness chain of call-site identities, and the coverage that says whether an absent effect is proven absent or merely unseen. At least one row per input procedure. The walk is a bounded deterministic fixpoint over the same dispatch answers call_effects publishes.", semantic: [Procedures] }
    CallBindings { shape: RowLocal, label: "call_bindings", signature: "call_shape -> call_binding", description: "Project the normalized actual-to-formal binding rows of each call shape: one row per written actual, carrying the call-shape argument identity it binds, the formal ordinal and name it was bound to, the binding kind, this row's mapping status, and the whole call's partition coverage. Beside them, a row for each fact no written actual accounts for: the receiver the call is made against, an argument the language supplies with no syntax, and a formal that no actual passed but whose declaration carries a default. Coverage describes the written actuals alone. Exact receiver rows carry a stable declaring-type identity. Selector proof is separate from runtime dispatch: it is derived for exact dispatch or for a resolver-proven receiverless external static target whose unique complete model supplies exact formals. It can also be authored-summary proof when a unique complete exact-member summary explicitly covers the sole unresolved override residual; full activated provenance is retained. Workspace arms, ambiguous overloads, partial or conflicting models, unproven owner identity, instance boundaries without a contract, other boundary kinds, and truncation remain inexact. The semantic dispatch identity, proof, completeness, and candidate coverage are still carried unchanged from the bounded dispatch answer. A source declaration is only an optional materialized view. At least one row per call shape, so an unreadable shape, an unresolved or ambiguous callee, unrecorded formals, or a call that binds nothing each state that instead of answering empty. The callee is the one the production definition resolver binds; no overload is re-decided here.", semantic: [Procedures, Dispatch] }
    ResolvedCall { shape: RowLocal, label: "resolved_call", signature: "call_binding -> call_binding", description: "Retain call-binding rows that prove one resolved callable identity with exact or declared selector proof and an optional exact receiver-type identity. Qualified RQL locators are resolved only at a loaded-policy boundary." }
    ResolvedValue { shape: RowLocal, label: "resolved_value", signature: "call_binding|structural_match -> same row", description: "Retain a call actual, a Python decorator expression, or a Python/C# structured value node only when its selected non-call expression, class-constructor call, attribute name, or structured member expression resolves to the requested exact declaration identity. Unresolved, ambiguous, shadowed, unsupported, or budget-limited values make the query incomplete. Qualified locators are resolved at the loaded-policy boundary." }
    CallArgument { shape: RowLocal, label: "call_argument", signature: "call_binding -> call_binding", description: "Retain the source actual bound to one formal name or zero-based formal index, requiring exact mapping, exhaustive coverage, a non-terminal row, and argument identity." }
    CppBadStrncpySize { shape: RowLocal, label: "cpp_bad_strncpy_size", signature: "call_binding -> structural_match", description: "Retain source-backed C/C++ match rows for which a structurally resolved strncpy call passes a source fixed-array extent larger than the destination extent as its size argument. Compose this step after resolved-call and call-argument with the declared library identity; unresolved identity is never selected by callee name." }
    CppNetworkToHostFunctionAsArrayBound { shape: RowLocal, label: "cpp_network_to_host_function_as_array_bound", signature: "call_binding -> structural_match", description: "Retain source-backed C/C++ match rows for which a structurally resolved ntohl call is the direct bound argument of memcpy. Compose this step after resolved-call and call-argument with the declared library identity; unresolved identity is never selected by callee name." }
    CppNonConstantFormat { shape: RowLocal, label: "cpp_non_constant_format", signature: "call_binding -> structural_match", description: "Retain exact modeled C/C++ printf-family calls whose format argument is not a direct constant string literal, projected back to the source call seed. Unknown identifier value flow remains incomplete." }
    CppWrongNumberFormatArguments { shape: RowLocal, label: "cpp_wrong_number_format_arguments", signature: "call_binding -> structural_match", description: "Retain exact modeled C/C++ printf-family calls whose complete literal format requires more variadic arguments than the call supplies, projected back to the source call seed." }
    CppTooManyFormatArguments { shape: RowLocal, label: "cpp_too_many_format_arguments", signature: "call_binding -> structural_match", description: "Retain exact modeled C/C++ printf-family calls that supply more variadic arguments than their complete literal format consumes, projected back to the source call seed." }
    CppWrongTypeFormatArgument { shape: RowLocal, label: "cpp_wrong_type_format_argument", signature: "call_binding -> structural_match", description: "Retain exact modeled C/C++ printf-family calls whose structured literal or parameter type is incompatible with a parsed conversion directive, projected back to the source call seed." }
    CppNonPortablePrintf { shape: RowLocal, label: "cpp_non_portable_printf", signature: "call_binding -> structural_match", description: "Retain exact modeled C/C++ printf calls whose structured argument type depends on a non-portable integer width or pointer format contract, projected back to the source call seed." }
    CppOverflowingSnprintf { shape: RowLocal, label: "cpp_overflowing_snprintf", signature: "call_binding -> structural_match", description: "Retain modeled snprintf calls only when a future bounded destination-extent and return-flow producer proves overflow; missing extent or flow evidence is incomplete. Positive rows are projected back to the source call seed." }
    CallableSignature { shape: RowLocal, label: "callable_signature", signature: "declaration -> callable_signature", description: "Project the mandatory callable-signature rows of each declaration from the persisted signature contract: one row per persisted signature entry, so an overload set separates into one row per overload. Python special methods also carry a query-time protocol arity verdict derived from their prepared declaration body; placeholders and unavailable syntax are explicit." }
    LiteralOccurrences { shape: RowLocal, label: "literal_occurrences", signature: "structural_match -> literal_occurrence", description: "Project one query-local scalar literal occurrence for each selected literal fact. Decoded strings, signed integers, booleans and nulls carry typed identities; unsupported, floating-point, character, collection, or recovered values remain incomplete rows." }
    CallableMetrics { shape: RowLocal, label: "callable_metrics", signature: "declaration -> callable_metrics", description: "Project query-local structured cognitive complexity, maximum executable nesting, and owned executable span metrics for each source-backed callable. Incomplete parser or ownership evidence remains explicitly covered as incomplete." }
    SignatureParameters { shape: RowLocal, label: "signature_parameters", signature: "callable_signature -> signature_parameter", description: "Project the ordered declared parameter rows of each callable signature." }
    DecoratorBindings { shape: Batched, label: "decorator_bindings", signature: "structural_match -> decorated_parameter", description: "Project one typed decorator-binding row for each decorator applied to a parameter match. Semantic parameter identity is used only when an exact structural source identity selects one Parameter value; otherwise the row retains only a syntax explanation and explicitly incomplete coverage.", semantic: [Procedures] }
    CallableApplicability { shape: DerivedValue, label: "callable_applicability", signature: "occurrence -> callable_applicability", description: "Project one applicability row per candidate callable the production resolver considered for each reference occurrence: the verdict, the typed callable rejection reason when inapplicable, the precedence tier, and whether the resolver bound it. A candidate the resolver refused stays visible with its reason, so a losing overload is evidence rather than an absence." }
    OverloadSelection { shape: DerivedValue, label: "overload_selection", signature: "occurrence -> overload_selection", description: "Project the mandatory overload-selection summary row for each reference occurrence: resolved_unique, ambiguous, unresolved, or unknown_shape, with the verdict counts it was computed from. Exactly one row per occurrence, and candidate order can never influence it -- zero applicable candidates stay unresolved and several equal winners stay ambiguous." }
    MemberSelection { shape: DerivedValue, label: "member_selection", signature: "occurrence -> member_selection", description: "Project the mandatory member-selection summary row for each reference occurrence, from the production resolver's own candidate trace." }
    DispatchOutcome { shape: DerivedValue, label: "dispatch_outcome", signature: "structural_match|call_site|reference_site|occurrence -> dispatch_outcome", description: "Project the mandatory bounded-dispatch outcome row for each input site: the semantic outcome, the candidate coverage, and the retained target count. Exactly one row per input site, so an unknown, unsupported, over-budget, or cancelled dispatch is stated rather than silently empty.", semantic: [Procedures, Dispatch] }
    DispatchTargets { shape: DerivedValue, label: "dispatch_targets", signature: "structural_match|call_site|reference_site|occurrence -> dispatch_target", description: "Project zero or more bounded dispatch target rows for each input site, one per retained dispatch candidate plus one per boundary arm that names a target. Each row keeps the oracle's own proof, completeness, and candidate coverage, so a proven target in an exhaustive set stays distinguishable from an open may-dispatch arm.", semantic: [Procedures, Dispatch] }
    MemberFamily { shape: DerivedValue, label: "member_family", signature: "declaration -> member_family", description: "Project the mandatory canonical method-family outcome row for each member declaration: the family id when the analyzer proves the family, the typed reason and unread ancestors when it cannot, the per-relation edge counts, and whole-family plus directional coverage. Exactly one row per input declaration, so an unsupported language or an unprovable overload identity is stated rather than silently empty." }
    FamilyEdges { shape: DerivedValue, label: "family_edges", signature: "declaration -> member_family_edge", description: "Project the typed method-family edges of each member declaration: the forward overrides/implements edges the analyzer proves, plus the bounded inversion of those same edges as overridden_by/implemented_by. Retains established edges of incomplete families. Edge coverage follows its direction: ancestors for overrides/implements and descendants for overridden_by/implemented_by." }
    OccurrencesOf { shape: DerivedValue, label: "occurrences_of", signature: "declaration -> occurrence", description: "Return the declaration-name occurrence of each declaration plus every reference-class occurrence resolving to it." }
    OccurrencesIn { shape: RowLocal, label: "occurrences_in", signature: "structural_match|call_shape|lexical_scope|file -> occurrence", description: "Return classified identifier occurrences lexically inside each structural match or call shape, in the exact innermost lexical scope, or in the file." }
    OccurrenceTarget { shape: DerivedValue, label: "occurrence_target", signature: "occurrence -> declaration", description: "Project the resolved semantic targets of reference-class occurrences." }
    ScopeOf { shape: RowLocal, label: "scope_of", signature: "binding|occurrence|structural_match -> lexical_scope", description: "Return the innermost lexical scope that owns each binding, occurrence, or structural match." }
    ScopeAncestors { shape: RowLocal, label: "scope_ancestors", signature: "lexical_scope -> lexical_scope", description: "Return the enclosing lexical scopes of each scope, innermost first, excluding the scope itself." }
    BindingsIn { shape: RowLocal, label: "bindings_in", signature: "lexical_scope|structural_match -> binding", description: "Return the bindings declared in each lexical scope, or in the scopes inside each structural match." }
    BindingOf { shape: RowLocal, label: "binding_of", signature: "occurrence -> binding", description: "Return the binding in effect at a reference's exact position; a binder token preceding its own activation identifies its introduced binding instead." }
    BindingOccurrence { shape: RowLocal, label: "binding_occurrence", signature: "binding -> occurrence", description: "Return the binder-class occurrence row of each binding's declaring token." }
    BindingUses { shape: RowLocal, label: "binding_uses", signature: "binding -> occurrence", description: "Return reference occurrences whose exact lexical BindingOf result is this binding, deriving the join from per-file occurrence and binding facts." }
    PythonComparisonConstants { shape: RowLocal, label: "python_comparison_constants", signature: "comparison -> comparison", description: "Retain Python comparisons whose two AST operands are supported constants: scalar and parenthesized literals, constant tuples, constant string concatenation, and unary not, numeric signs, or bitwise inversion over constants. Direct assert tests and unsupported computed expressions are excluded." }
    PythonComparisonUsingIs { shape: RowLocal, label: "python_comparison_using_is", signature: "comparison -> comparison", description: "Retain Python is/is-not comparisons when a resolved operand has value equality through a builtin value type or an effective custom __eq__ in its complete MRO. Singleton identity checks and classes without custom equality are excluded; unresolved classes report incomplete." }
    PythonComparisonUsingIsNonPortable { shape: RowLocal, label: "python_comparison_using_is_non_portable", signature: "comparison -> comparison", description: "Retain Python is/is-not comparisons against integer or string literals that CPython interns but Python implementations do not universally intern. Universal singleton, empty-string, and zero identities are excluded; unresolved operand classes report incomplete." }
    IdenticalOperands { shape: RowLocal, label: "identical_operands", signature: "comparison -> comparison", description: "Retain Python comparisons whose bare-name operands resolve to one exact lexical binding, or whose static attribute paths have the same member segments and a root bound to that same identity. Unsupported computed operands are outside this relation; unresolved supported bindings make the query incomplete." }
    PythonMissingSelf { shape: RowLocal, label: "python_missing_self", signature: "comparison -> comparison", description: "Retain Python method comparisons of the same bare name when that name has no local binding or explicit global/nonlocal directive and a grammar-selected self.<name> access exists in the same class with self bound to a method parameter." }
    CandidatesOf { shape: DerivedValue, label: "candidates_of", signature: "occurrence -> resolution_candidate", description: "Return the candidates the resolver considered for each reference-class occurrence, with tier, outcome, and boundary." }
    CandidateHierarchy { shape: DerivedValue, label: "candidate_hierarchy", signature: "occurrence -> candidate_hop", description: "Return the exact hierarchy hops each traced member candidate of a reference occurrence was found through. A depth-zero candidate contributes no hop, and a candidate the resolver recorded without member attribution contributes none either -- absence here is unattributed, never a claim that no hierarchy was walked; the mandatory outcome story is member_selection's." }
    CandidateTarget { shape: DerivedValue, label: "candidate_target", signature: "resolution_candidate -> declaration", description: "Project the workspace declarations of unit-backed resolution candidates." }
    EdgesOf { shape: DerivedValue, label: "edges_of", signature: "declaration -> reference_edge", description: "Return the canonical inverse reference edges of each declaration: every usage site the usage index enumerates, with kind, proof, usage kind, and owner relation." }
    EdgesFrom { shape: RowLocal, label: "edges_from", signature: "occurrence -> reference_edge", description: "Return the canonical forward reference edges of each occurrence: the resolver's own resolved targets for that exact token, with kind, proof, usage kind, and owner relation." }
    EdgeTarget { shape: DerivedValue, label: "edge_target", signature: "reference_edge -> declaration", description: "Project each reference edge to its exact indexed target declaration." }
    StateEventsOf { shape: RowLocal, label: "state_events_of", signature: "procedure|declaration -> state_event", description: "Derive flow-sensitive state events from the production semantic IR. Synthetic reads at async suspension points identify either a modeled post-resume use or a Rust binding kept live by its lexical scope and CFG paths; scope-only reads are syntactic and do not prove a binding is non-Copy. Source order is never used as CFG evidence.", semantic: [Procedures, ProgramPoints] }
    BindingInitializerCallsOf { shape: RowLocal, label: "binding_initializer_calls_of", signature: "state_event -> binding_initializer_call", description: "For one Rust binding establishment, project exact call sites on the initializer result and method-receiver chain. The establishment event id and the call's site_ast_id are exposed as typed stable-id join keys; unsupported AST or semantic value links stay explicitly incomplete.", semantic: [Procedures] }
    FlowRelationsOf { shape: RowLocal, label: "flow_relations_of", signature: "state_event|procedure -> flow_relation", description: "Derive the flow relations between the state events of each procedure: reaching-definition, dominance, and same-evaluation, each with exact or may certainty. Seeded from a state event, only the relations incident to that event are returned. Budget exhaustion emits no rows and an explicit incomplete diagnostic; it is never reported as an absent relation.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    FlowSource { shape: RowLocal, label: "flow_source", signature: "flow_relation -> state_event", description: "Project each flow relation to its source state event: the establishment or kill end." }
    FlowTarget { shape: RowLocal, label: "flow_target", signature: "flow_relation -> state_event", description: "Project each flow relation to its target state event: the read end." }
    FailureHandlerState { shape: RowLocal, label: "failure_handler_state", signature: "structural_match -> failure_handler_state", description: "Classify the exact Java, JavaScript, TypeScript, C#, PHP, C++, Kotlin or Scala catch body, Python except body, Ruby rescue body, Rust-native Result::Err failure branch, or Go error/nil and recover failure branch from prepared syntax. Catch languages use catch seeds; Rust and Go use callable seeds and language-native branch hooks. Comments, empty statements, Python pass or ellipsis, Scala unit literals, Rust unit expressions, and direct discarded Go recover calls are no-ops. Scala catch expressions outside case blocks remain open. Exact Rust handler identities require the resolver to prove the standard Result variant; exact Go handler identities require the adapter to prove predeclared error or recover identities; Option arms, unproven Go bindings, and unresolved or macro token-tree shapes remain outside the exact result or open. Other languages produce an explicit unsupported unknown row. Empty verdicts require exact handler identity. A structurally nonempty native candidate with unproven handler identity has unknown proof, exhaustive coverage, and reason handler_identity_unproven. Empty candidates with unproven identity, recovered syntax, or unavailable bodies produce an explicit unknown row and incomplete coverage; this step makes no reachability claim." }
    BranchRelations { shape: RowLocal, label: "branch_relations", signature: "structural_match -> branch_relation", description: "Compare ordered arms of one structural if fact using exact parsed syntax and lexical binding identities. Rows state proven, distinct, or open with an explicit reason. Relation filtering applies before completeness is assessed, so unrelated open relations do not taint a selected family." }
    CppExpressions { shape: RowLocal, label: "cpp_expressions", signature: "structural_match -> cpp_expression", description: "Project typed, occurrence-keyed C++ expression facts from the exact source range, retaining scalar type, literal, array, bit-field, enum, signature, loop, and sizeof evidence with explicit open completeness." }
    CppInconsistentLoopDirection { shape: RowLocal, label: "cpp_inconsistent_loop_direction", signature: "structural_match -> structural_match", description: "Retain C/C++ for-loop matches whose structured comparison direction and update direction disagree for the same loop variable. Missing syntax is incomplete; no source-text loop parser or general range analysis is used." }
    CppUnsafeArrayForDaysOfTheYear { shape: RowLocal, label: "cpp_unsafe_array_for_days_of_the_year", signature: "structural_match -> structural_match", description: "Retain C/C++ numeric-literal matches where the structured literal 365 is a fixed array extent or vector-constructor extent. A literal with no such structured extent is not applicable." }
    CppProvenance { shape: RowLocal, label: "cpp_provenance", signature: "structural_match|call_binding -> structural_match", description: "Filter a C/C++ source-backed seed through one procedure-local typed provenance rule. The terminal row remains the original return, assignment, or call anchor; unsupported aliases and unresolved call identities remain incomplete.", semantic: [Procedures] }
    LoopRelations { shape: RowLocal, label: "loop_relations", signature: "procedure -> loop_relation", description: "For an exact Java source loop, prove whether its reachable body can reach its own repeat edge before exiting. Rows preserve source and control gaps as open rather than claiming a nonrepeating body.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    StatementReachability { shape: RowLocal, label: "statement_reachability", signature: "procedure -> statement_reachability", description: "Enumerate exact Java statement syntax and its producer-authored CFG entries. A statement is unreachable only when every entry is outside complete bounded entry reachability; source, control, and budget gaps remain open.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    PendingCleanupFlows { shape: RowLocal, label: "pending_cleanup_flows", signature: "procedure -> pending_cleanup_flow", description: "Derive the effect of each lowered finally, ensure, defer, using, with, or resource cleanup on a pending return, throw, break, or continue. Exact override and preservation rows are emitted only when the cleanup-local CFG is exhaustive; missing edges, gaps, mixed outcomes, and unsupported cleanup syntax are explicit unknown/incomplete evidence.", semantic: [Procedures, ProgramPoints, ControlEdges] }
    RustMarkerImplsOf { shape: DerivedValue, label: "rust_marker_impls_of", signature: "declaration -> rust_marker_impl", description: "Enumerate same-file Rust Send/Sync impl parameters, marker bounds, field wrapper uses, shared-reference access, and completeness proofs using bounded syntax and definition lookup.", semantic: [] }
    RustPointerFindings { shape: DerivedValue, label: "rust_pointer_findings", signature: "procedure -> rust_pointer_finding", description: "Run query-local Rust pointer provenance and project accesses whose same-origin scope-end, invalidation, or checked byte extent precedes the access. Rows retain must/may strength, path proof, bounds, and completeness; incomplete coverage stays diagnostic.", semantic: [Procedures, ValueFlow] }
    ControlRelations { shape: RowLocal, label: "control_relations", signature: "procedure -> control_relation", description: "Derive the control relations of each procedure from the shared control-flow algorithms over the production semantic IR: dominance, postdominance, control dependence, entry reachability, procedure-local CFG reachability, and loop membership between the procedure's own program points, joined by the same stable ids the program_point and control_edge rows publish. Every row states the exit partition its claim was computed against, so a backward claim can never be read as a claim about a partition that was not computed. Budget exhaustion or cancellation emits no row for the affected relation and an explicit incomplete diagnostic; it is never reported as an absent relation.", semantic: [Procedures, ProgramPoints, ControlEdges] }
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
    SelectedPropertyRelationsOf { shape: RowLocal, label: "selected_property_relations_of", signature: "program_point -> flow_relation", description: "Prove reaching relations for the unique property read at one exact program point. Coverage is scoped to its structured receiver, member, dependencies and every modeled endpoint; missing or ambiguous reads, relevant gaps, alias escape, runtime behavior, budgets and cancellation remain incomplete. Unknown stored values remain unknown. Whole-procedure flow coverage and existing postfilters are unchanged.", semantic: [Procedures, ProgramPoints, ControlEdges, ValueFlow] }
    ProgramPointById { shape: RowLocal, label: "program_point_by_id", signature: "procedure -> program_point", description: "Select one physical point by an observed content/environment-scoped public ID in the supplied current procedure. This does not claim exhaustive AST/read discovery or semantic-overlay freshness. Missing, stale, wrong-procedure, ambiguous or incomplete point selection remains incomplete; downstream proofs acquire current evidence.", semantic: [Procedures, ProgramPoints] }
}

/// The generated step reference: one line per registry step, in
/// [`ALL_QUERY_STEP_OPS`] order, spelled `label (input -> output): meaning`.
///
/// This is the only step reference Bifrost publishes to a caller. The MCP
/// `query_code` `steps` parameter schema carries it, and `bifrost --help
/// query_code` prints it out of that same schema, so a step added to the
/// registry above documents itself on both surfaces and no help text anywhere
/// repeats the vocabulary.
/// The `file_of` registry signature, spelled from [`FILE_OF_INPUT_KINDS`] so
/// the help text cannot name a different set than the transition accepts.
fn file_of_input_signature() -> &'static str {
    static SIGNATURE: LazyLock<String> = LazyLock::new(|| {
        let labels = FILE_OF_INPUT_KINDS
            .iter()
            .map(|kind| kind.label())
            .collect::<Vec<_>>();
        format!("{} -> file", labels.join("|"))
    });
    SIGNATURE.as_str()
}

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
                    | Self::Filter
                    | Self::Project
                    | Self::Anchor
                    | Self::CppFacts
                    | Self::EnclosingDecl
                    | Self::ProcedureOf
                    | Self::ProgramPointOf
                    | Self::ProgramPointById
                    | Self::CfgEntry
                    | Self::CfgExits
                    | Self::CfgSuccessorEdges
                    | Self::CfgPredecessorEdges
                    | Self::CfgEdgeSource
                    | Self::CfgEdgeTarget
                    | Self::Typestate
                    | Self::ValueFlow
                    | Self::RustMarkerImplsOf
                    | Self::RustPointerFindings
                    | Self::ClassSet
                    | Self::AbsentMember
                    | Self::Taint
                    | Self::Witness
                    | Self::FileOf
                    | Self::ImportsOf
                    | Self::ImportersOf
                    | Self::PythonImportSite
                    | Self::PythonImportCycles
                    | Self::Supertypes
                    | Self::Subtypes
                    | Self::ClassHierarchy
                    | Self::ClassBases
                      | Self::ClassMro
                      | Self::MroMembers
                      | Self::PythonOverrides
                      | Self::PythonCallRelations
                      | Self::PythonOverrideSignatures
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
                    | Self::KeyedReadValue
                    | Self::FieldWriteValue
                    | Self::ReceiverOutcome
                    | Self::ReceiverEvidence
                    | Self::PointsToCandidates
                    | Self::CallShape
                    | Self::ExactExternalCallee
                    | Self::CallResults
                    | Self::CallArgumentGroups
                    | Self::CallArguments
                    | Self::CallBindings
                    | Self::CppBadStrncpySize
                    | Self::CppNetworkToHostFunctionAsArrayBound
                    | Self::CppNonConstantFormat
                    | Self::CppWrongNumberFormatArguments
                    | Self::CppTooManyFormatArguments
                    | Self::CppWrongTypeFormatArgument
                    | Self::CppNonPortablePrintf
                    | Self::CppOverflowingSnprintf
                    | Self::CppInconsistentLoopDirection
                    | Self::CppUnsafeArrayForDaysOfTheYear
                    | Self::CppProvenance
                    | Self::ResolvedCall
                    | Self::ResolvedValue
                    | Self::CallArgument
                    | Self::CallEffects
                    | Self::ResultContractCalls
                    | Self::CallResultContracts
                    | Self::CallResultObligations
                    | Self::ProcedureReturnProfile
                    | Self::PythonIteratorReturnProtocol
                    | Self::PythonBuiltinIdentity
                    | Self::PythonUninitializedVariable
                    | Self::PythonRaiseNotImplemented
                    | Self::PythonUnsafeCyclicImport
                    | Self::PythonCommentedOutCode
                    | Self::PythonDocumentation
                    | Self::PythonUselessClass
                    | Self::PythonAttributeShadowsMethod
                    | Self::PythonModificationOfDefaultValue
                    | Self::PythonOverlyComplexDelete
                    | Self::CallResultUse
                    | Self::PythonAssertionContext
                    | Self::TupleReturnAssignment
                    | Self::PythonImplicitStringConcatenation
                    | Self::TupleReturnGroups
                    | Self::LambdaForwarding
                    | Self::PythonFormatIssues
                    | Self::PythonUrlConstruction

                    | Self::PythonRaiseLegality
                    | Self::PythonSpecialMethodRaise
                    | Self::ResultContractUses
                    | Self::ResultSubjectUses
                    | Self::ResultContractOperationUses
                    | Self::ResultContractFailureUses
                    | Self::NilnessOperations
                    | Self::SwitchCoverage
                    | Self::AssignmentRelations
                    | Self::DetachedTaskTransfers
                    | Self::ProcedureEffects
                    | Self::CallableSignature
                    | Self::LiteralOccurrences
                    | Self::CallableMetrics
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
                    | Self::BindingUses
                    | Self::PythonVariableOf
                    | Self::PythonVariableDefinitions
                    | Self::PythonVariableUses
                    | Self::PythonVariablePeers
                    | Self::PythonVariableNestedLoops
                    | Self::PythonComparisonConstants
                    | Self::PythonComparisonUsingIs
                    | Self::PythonComparisonUsingIsNonPortable
                    | Self::IdenticalOperands
                    | Self::PythonMissingSelf
                    | Self::CandidatesOf
                    | Self::CandidateHierarchy
                    | Self::GenerationSites
                    | Self::Exports
                    | Self::DependencyEvidence
                    | Self::ConfigurationFacts
                    | Self::ConfigurationAbsence
                    | Self::ConfigurationCode
                    | Self::Correlate
                    | Self::RequireBoth
                    | Self::ConfigurationKey
                    | Self::DependencyConfiguration
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
                    | Self::BindingInitializerCallsOf
                    | Self::SelectedPropertyRelationsOf
                    | Self::FlowRelationsOf
                    | Self::FlowSource
                    | Self::FlowTarget
                    | Self::ControlRelations
                    | Self::FailureHandlerState
                    | Self::BranchRelations
                    | Self::CppExpressions
                    | Self::LoopRelations
                    | Self::StatementReachability
                    | Self::PendingCleanupFlows
                    | Self::TargetOf
                    | Self::SourceSetOf
                    | Self::TopologyEdgesOf
                    | Self::GuardsOf
                    | Self::RewritePathsOf
                    | Self::StatementFacts => None,
                    Self::Name => Some(RqlProperty::Name),
                    Self::StringValue => Some(RqlProperty::StringValue),
                    Self::NameRegex => Some(RqlProperty::NameRegex),
                    Self::TextRegex => Some(RqlProperty::TextRegex),
                    Self::BooleanValue => Some(RqlProperty::BooleanValue),
                    Self::Async => Some(RqlProperty::Async),
                    Self::UnsafeContext => Some(RqlProperty::UnsafeContext),
                    Self::Modifier => Some(RqlProperty::Modifier),
                    Self::TypeKind => Some(RqlProperty::TypeKind),
                    Self::Parenthesized => Some(RqlProperty::Parenthesized),
                    Self::IntegerValue => Some(RqlProperty::IntegerValue),
                    Self::DuplicateKey => Some(RqlProperty::DuplicateKey),
                    Self::IntegerHasAnyBits => Some(RqlProperty::IntegerHasAnyBits),
                    Self::IntegerHasAllBits => Some(RqlProperty::IntegerHasAllBits),
                    Self::IntegerHasNoBits => Some(RqlProperty::IntegerHasNoBits),
                    Self::AssignmentTargetKind => Some(RqlProperty::AssignmentTargetKind),
                    Self::AssignmentValueKind => Some(RqlProperty::AssignmentValueKind),
                    Self::AssignmentTargetUnstarredCount => Some(RqlProperty::AssignmentTargetUnstarredCount),
                    Self::AssignmentValueUnstarredCount => Some(RqlProperty::AssignmentValueUnstarredCount),
                    Self::AssignmentTargetStarred => Some(RqlProperty::AssignmentTargetStarred),
                    Self::AssignmentValueStarred => Some(RqlProperty::AssignmentValueStarred),
                    Self::AssignmentUnstarredCountMismatch => Some(RqlProperty::AssignmentUnstarredCountMismatch),
                    Self::Index => Some(RqlProperty::Index),
                    Self::StringValueRegex => Some(RqlProperty::StringValueRegex),
                    Self::Not => Some(RqlProperty::Not),
                    Self::All => Some(RqlProperty::All),
                    Self::Any => Some(RqlProperty::Any),
                    Self::LocalValue => Some(RqlProperty::LocalValue),
                    Self::Capture => Some(RqlProperty::Capture),
                    Self::Has => Some(RqlProperty::Has),
                    Self::NotHas => Some(RqlProperty::NotHas),
                    Self::NotKind => Some(RqlProperty::NotKind),
                    Self::Arity => Some(RqlProperty::Arity),
                    Self::Visibility => Some(RqlProperty::Visibility),
                    Self::ParameterType => Some(RqlProperty::ParameterType),
                    Self::ParameterTypeRegex => Some(RqlProperty::ParameterTypeRegex),
                    Self::LanguageRule => Some(RqlProperty::LanguageRule),
                    Self::BodyState => Some(RqlProperty::BodyState),
                    Self::BodyOwner => Some(RqlProperty::BodyOwner),
                }
            }
        }
    };
}

rql_forms! {
    Where {
        labels: ["where"],
        class: Wrapper,
        shape: PathScope,
        signature: "(where \"glob\" ... query)",
        description: "Restrict the query to workspace-relative path globs. Globs in one wrapper are alternatives; repeated wrappers conjoin their groups and distribute over set-query seeds.",
    }
    Language {
        labels: ["language", "languages"],
        class: Wrapper,
        shape: LanguageList,
        signature: "(language label ... query)",
        description: "Restrict the query to concrete analyzer languages or fixed jvm/js-ts families. Repeated wrappers intersect their language sets; disjoint sets are errors.",
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
    CppFacts {
        labels: ["cpp-facts", "cpp_facts"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-facts :kind assignment-does-not-return-this|catch-by-value|constructor-delegation|constructor-used-as-copy-constructor|rule-of-three|rule-of-two|throwing-pointer|undisciplined-multiple-inheritance query)",
        description: (QueryStepOp::CppFacts),
        step: CppFacts,
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
        description: "Require the root match to be inside a matching container without crossing a callable declaration; Rust impl members and out-of-line C++ member definitions can also match their resolved owning type.",
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
        description: "Return each typed endpoint reached by any branch. Branches of different row kinds combine when only filter and project follow.",
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
    Filter {
        labels: ["filter"],
        class: Wrapper,
        shape: Query,
        signature: "(filter :where ((FIELD OP OPERAND) ...) query)",
        description: (QueryStepOp::Filter),
        step: Filter,
    }
    Project {
        labels: ["project"],
        class: Wrapper,
        shape: Query,
        signature: "(project :columns (FIELD|(FIELD NEW-FIELD) ...) query)",
        description: (QueryStepOp::Project),
        step: Project,
    }
    Anchor {
        labels: ["anchor"],
        class: Wrapper,
        shape: Query,
        signature: "(anchor :capture \"name\" query)",
        description: (QueryStepOp::CaptureAnchor),
        step: CaptureAnchor,
    }
    StatementFacts {
        labels: ["statement-facts", "statement_facts"],
        class: Wrapper,
        shape: Query,
        signature: "(statement-facts :kind alloca-in-loop|complex-block|complex-condition|empty-block|long-switch|missing-case-in-switch|nested-loops-with-same-variable|use-of-goto query)",
        description: (QueryStepOp::StatementFacts),
        step: StatementFacts,
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
    ProgramPointOf {
        labels: ["program-point-of", "program_point_of"],
        class: Wrapper,
        shape: Query,
        signature: "(program-point-of structural-query)",
        description: (QueryStepOp::ProgramPointOf),
        step: ProgramPointOf,
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
        signature: "(absent-member [:proof proven|conditional|any] query)",
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
    PythonImportSite {
        labels: ["python-import-site", "python_import_site"],
        class: Wrapper,
        shape: Query,
        signature: "(python-import-site query)",
        description: (QueryStepOp::PythonImportSite),
        step: PythonImportSite,
    }
    PythonImportCycles {
        labels: ["python-import-cycles", "python_import_cycles"],
        class: Wrapper,
        shape: Query,
        signature: "(python-import-cycles query)",
        description: (QueryStepOp::PythonImportCycles),
        step: PythonImportCycles,
    }
    PythonCommentedOutCode {
        labels: ["python-commented-out-code", "python_commented_out_code"],
        class: Wrapper,
        shape: Query,
        signature: "(python-commented-out-code query)",
        description: (QueryStepOp::PythonCommentedOutCode),
        step: PythonCommentedOutCode,
    }
    PythonUnsafeCyclicImport {
        labels: ["python-unsafe-cyclic-import", "python_unsafe_cyclic_import"],
        class: Wrapper,
        shape: Query,
        signature: "(python-unsafe-cyclic-import query)",
        description: (QueryStepOp::PythonUnsafeCyclicImport),
        step: PythonUnsafeCyclicImport,
    }
    Supertypes {
        labels: ["supertypes"],
        class: Wrapper,
        shape: Query,
        signature: "(supertypes [:depth count | :transitive true] query)",
        description: (QueryStepOp::Supertypes),
        step: Supertypes,
    }
    ClassHierarchy {
        labels: ["class-hierarchy", "class_hierarchy"],
        class: Wrapper,
        shape: Query,
        signature: "(class-hierarchy query)",
        description: (QueryStepOp::ClassHierarchy),
        step: ClassHierarchy,
    }
    ClassBases {
        labels: ["class-bases", "class_bases"],
        class: Wrapper,
        shape: Query,
        signature: "(class-bases query)",
        description: (QueryStepOp::ClassBases),
        step: ClassBases,
    }
    ClassMro {
        labels: ["class-mro", "class_mro"],
        class: Wrapper,
        shape: Query,
        signature: "(class-mro query)",
        description: (QueryStepOp::ClassMro),
        step: ClassMro,
    }
    MroMembers {
        labels: ["mro-members", "mro_members"],
        class: Wrapper,
        shape: Query,
        signature: "(mro-members query)",
        description: (QueryStepOp::MroMembers),
        step: MroMembers,
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
    KeyedReadValue {
        labels: ["keyed-read-value", "keyed_read_value"],
        class: Wrapper,
        shape: Query,
        signature: "(keyed-read-value :runtime node|python :global process|os|sys :container env|environ|argv [:property name | :index number | :key-kind static-property | :key-kind static-index [:index-min number] [:index-max number]] [:source-origin pristine_input] query)",
        description: (QueryStepOp::KeyedReadValue),
        step: KeyedReadValue,
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
    PointsToCandidates {
        labels: ["points-to-candidates", "points_to_candidates"],
        class: Wrapper,
        shape: Query,
        signature: "(points-to-candidates query)",
        description: (QueryStepOp::PointsToCandidates),
        step: PointsToCandidates,
    }
    CallShape {
        labels: ["call-shape", "call_shape"],
        class: Wrapper,
        shape: Query,
        signature: "(call-shape query)",
        description: (QueryStepOp::CallShape),
        step: CallShape,
    }
    ExactExternalCallee {
        labels: ["exact-external-callee", "exact_external_callee"],
        class: Wrapper,
        shape: Query,
        signature: "(exact-external-callee query)",
        description: (QueryStepOp::ExactExternalCallee),
        step: ExactExternalCallee,
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
    ResolvedCall {
        labels: ["resolved-call", "resolved_call"],
        class: Wrapper,
        shape: Query,
        signature: "(resolved-call :resolves-to identity|\"qualified\" :proof exact|declared [:receiver-type identity|\"qualified\"|(assignable-to identity|\"qualified\")] query)",
        description: (QueryStepOp::ResolvedCall),
        step: ResolvedCall,
    }
    ResolvedValue {
        labels: ["resolved-value", "resolved_value"],
        class: Wrapper,
        shape: Query,
        signature: "(resolved-value :resolves-to identity|\"qualified\" :proof exact query)",
        description: (QueryStepOp::ResolvedValue),
        step: ResolvedValue,
    }
    CallArgument {
        labels: ["call-argument", "call_argument"],
        class: Wrapper,
        shape: Query,
        signature: "(call-argument (:formal-name name | :formal-index index) query)",
        description: (QueryStepOp::CallArgument),
        step: CallArgument,
    }
    CppBadStrncpySize {
        labels: ["cpp-bad-strncpy-size", "cpp_bad_strncpy_size"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-bad-strncpy-size query)",
        description: (QueryStepOp::CppBadStrncpySize),
        step: CppBadStrncpySize,
    }
    CppNetworkToHostFunctionAsArrayBound {
        labels: ["cpp-network-to-host-function-as-array-bound", "cpp_network_to_host_function_as_array_bound"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-network-to-host-function-as-array-bound query)",
        description: (QueryStepOp::CppNetworkToHostFunctionAsArrayBound),
        step: CppNetworkToHostFunctionAsArrayBound,
    }
    CppNonConstantFormat {
        labels: ["cpp-non-constant-format", "cpp_non_constant_format"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-non-constant-format query)",
        description: (QueryStepOp::CppNonConstantFormat),
        step: CppNonConstantFormat,
    }
    CppWrongNumberFormatArguments {
        labels: ["cpp-wrong-number-format-arguments", "cpp_wrong_number_format_arguments"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-wrong-number-format-arguments query)",
        description: (QueryStepOp::CppWrongNumberFormatArguments),
        step: CppWrongNumberFormatArguments,
    }
    CppTooManyFormatArguments {
        labels: ["cpp-too-many-format-arguments", "cpp_too_many_format_arguments"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-too-many-format-arguments query)",
        description: (QueryStepOp::CppTooManyFormatArguments),
        step: CppTooManyFormatArguments,
    }
    CppWrongTypeFormatArgument {
        labels: ["cpp-wrong-type-format-argument", "cpp_wrong_type_format_argument"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-wrong-type-format-argument query)",
        description: (QueryStepOp::CppWrongTypeFormatArgument),
        step: CppWrongTypeFormatArgument,
    }
    CppNonPortablePrintf {
        labels: ["cpp-non-portable-printf", "cpp_non_portable_printf"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-non-portable-printf query)",
        description: (QueryStepOp::CppNonPortablePrintf),
        step: CppNonPortablePrintf,
    }
    CppOverflowingSnprintf {
        labels: ["cpp-overflowing-snprintf", "cpp_overflowing_snprintf"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-overflowing-snprintf query)",
        description: (QueryStepOp::CppOverflowingSnprintf),
        step: CppOverflowingSnprintf,
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
    CallResultObligations {
        labels: ["call-result-obligations", "call_result_obligations"],
        class: Wrapper,
        shape: Query,
        signature: "(call-result-obligations query)",
        description: (QueryStepOp::CallResultObligations),
        step: CallResultObligations,
    }
    ProcedureReturnProfile {
        labels: ["procedure-return-profile", "procedure_return_profile"],
        class: Wrapper,
        shape: Query,
        signature: "(procedure-return-profile query)",
        description: (QueryStepOp::ProcedureReturnProfile),
        step: ProcedureReturnProfile,
    }
    PythonIteratorReturnProtocol {
        labels: ["python-iterator-return-protocol", "python_iterator_return_protocol"],
        class: Wrapper,
        shape: Query,
        signature: "(python-iterator-return-protocol query)",
        description: (QueryStepOp::PythonIteratorReturnProtocol),
        step: PythonIteratorReturnProtocol,
    }
    PythonBuiltinIdentity {
        labels: ["python-builtin-identity", "python_builtin_identity"],
        class: Wrapper,
        shape: Query,
        signature: "(python-builtin-identity query)",
        description: (QueryStepOp::PythonBuiltinIdentity),
        step: PythonBuiltinIdentity,
    }
    PythonUninitializedVariable {
        labels: ["python-uninitialized-variable", "python_uninitialized_variable"],
        class: Wrapper,
        shape: Query,
        signature: "(python-uninitialized-variable query)",
        description: (QueryStepOp::PythonUninitializedVariable),
        step: PythonUninitializedVariable,
    }
    PythonVariableOf {
        labels: ["python-variable-of", "python_variable_of"],
        class: Wrapper,
        shape: Query,
        signature: "(python-variable-of query)",
        description: (QueryStepOp::PythonVariableOf),
        step: PythonVariableOf,
    }
    PythonVariableDefinitions {
        labels: ["python-variable-definitions", "python_variable_definitions"],
        class: Wrapper,
        shape: Query,
        signature: "(python-variable-definitions query)",
        description: (QueryStepOp::PythonVariableDefinitions),
        step: PythonVariableDefinitions,
    }
    PythonVariableUses {
        labels: ["python-variable-uses", "python_variable_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(python-variable-uses query)",
        description: (QueryStepOp::PythonVariableUses),
        step: PythonVariableUses,
    }
    PythonVariablePeers {
        labels: ["python-variable-peers", "python_variable_peers"],
        class: Wrapper,
        shape: Query,
        signature: "(python-variable-peers query)",
        description: (QueryStepOp::PythonVariablePeers),
        step: PythonVariablePeers,
    }
    PythonVariableNestedLoops {
        labels: ["python-variable-nested-loops", "python_variable_nested_loops"],
        class: Wrapper,
        shape: Query,
        signature: "(python-variable-nested-loops query)",
        description: (QueryStepOp::PythonVariableNestedLoops),
        step: PythonVariableNestedLoops,
    }
    PythonRaiseNotImplemented {
        labels: ["python-raise-not-implemented", "python_raise_not_implemented"],
        class: Wrapper,
        shape: Query,
        signature: "(python-raise-not-implemented query)",
        description: (QueryStepOp::PythonRaiseNotImplemented),
        step: PythonRaiseNotImplemented,
    }
    PythonDocumentation {
        labels: ["python-documentation", "python_documentation"],
        class: Wrapper,
        shape: Query,
        signature: "(python-documentation query)",
        description: (QueryStepOp::PythonDocumentation),
        step: PythonDocumentation,
    }
    PythonUselessClass {
        labels: ["python-useless-class", "python_useless_class"],
        class: Wrapper,
        shape: Query,
        signature: "(python-useless-class query)",
        description: (QueryStepOp::PythonUselessClass),
        step: PythonUselessClass,
    }
    PythonAttributeShadowsMethod {
        labels: ["python-attribute-shadows-method", "python_attribute_shadows_method"],
        class: Wrapper,
        shape: Query,
        signature: "(python-attribute-shadows-method query)",
        description: (QueryStepOp::PythonAttributeShadowsMethod),
        step: PythonAttributeShadowsMethod,
    }
    PythonModificationOfDefaultValue {
        labels: ["python-modification-of-default-value", "python_modification_of_default_value"],
        class: Wrapper,
        shape: Query,
        signature: "(python-modification-of-default-value query)",
        description: (QueryStepOp::PythonModificationOfDefaultValue),
        step: PythonModificationOfDefaultValue,
    }
    PythonOverlyComplexDelete {
        labels: ["python-overly-complex-delete", "python_overly_complex_delete"],
        class: Wrapper,
        shape: Query,
        signature: "(python-overly-complex-delete query)",
        description: (QueryStepOp::PythonOverlyComplexDelete),
        step: PythonOverlyComplexDelete,
    }
    CallResultUse {
        labels: ["call-result-use", "call_result_use"],
        class: Wrapper,
        shape: Query,
        signature: "(call-result-use query)",
        description: (QueryStepOp::CallResultUse),
        step: CallResultUse,
    }
    PythonAssertionContext {
        labels: ["python-assertion-context", "python_assertion_context"],
        class: Wrapper,
        shape: Query,
        signature: "(python-assertion-context query)",
        description: (QueryStepOp::PythonAssertionContext),
        step: PythonAssertionContext,
    }
    TupleReturnAssignment {
        labels: ["tuple-return-assignment", "tuple_return_assignment"],
        class: Wrapper,
        shape: Query,
        signature: "(tuple-return-assignment query)",
        description: (QueryStepOp::TupleReturnAssignment),
        step: TupleReturnAssignment,
    }
    PythonImplicitStringConcatenation {
        labels: ["python-implicit-string-concatenation", "python_implicit_string_concatenation"],
        class: Wrapper,
        shape: Query,
        signature: "(python-implicit-string-concatenation query)",
        description: (QueryStepOp::PythonImplicitStringConcatenation),
        step: PythonImplicitStringConcatenation,
    }
    TupleReturnGroups {
        labels: ["tuple-return-groups", "tuple_return_groups"],
        class: Wrapper,
        shape: Query,
        signature: "(tuple-return-groups query)",
        description: (QueryStepOp::TupleReturnGroups),
        step: TupleReturnGroups,
    }
    LambdaForwarding {
        labels: ["lambda-forwarding", "lambda_forwarding"],
        class: Wrapper,
        shape: Query,
        signature: "(lambda-forwarding query)",
        description: (QueryStepOp::LambdaForwarding),
        step: LambdaForwarding,
    }
    PythonFormatIssues {
        labels: ["python-format-issues", "python_format_issues"],
        class: Wrapper,
        shape: Query,
        signature: "(python-format-issues query)",
        description: (QueryStepOp::PythonFormatIssues),
        step: PythonFormatIssues,
    }
    PythonUrlConstruction {
        labels: ["python-url-construction", "python_url_construction"],
        class: Wrapper,
        shape: Query,
        signature: "(python-url-construction query)",
        description: (QueryStepOp::PythonUrlConstruction),
        step: PythonUrlConstruction,
    }
    PythonRaiseLegality {
        labels: ["python-raise-legality", "python_raise_legality"],
        class: Wrapper,
        shape: Query,
        signature: "(python-raise-legality query)",
        description: (QueryStepOp::PythonRaiseLegality),
        step: PythonRaiseLegality,
    }
    PythonSpecialMethodRaise {
        labels: ["python-special-method-raise", "python_special_method_raise"],
        class: Wrapper,
        shape: Query,
        signature: "(python-special-method-raise query)",
        description: (QueryStepOp::PythonSpecialMethodRaise),
        step: PythonSpecialMethodRaise,
    }
    ResultContractUses {
        labels: ["result-contract-uses", "result_contract_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(result-contract-uses query)",
        description: (QueryStepOp::ResultContractUses),
        step: ResultContractUses,
    }
    ResultSubjectUses {
        labels: ["result-subject-uses", "result_subject_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(result-subject-uses query)",
        description: (QueryStepOp::ResultSubjectUses),
        step: ResultSubjectUses,
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
    AssignmentRelations {
        labels: ["assignment-relations", "assignment_relations"],
        class: Wrapper,
        shape: Query,
        signature: "(assignment-relations [:relation [self-assignment|self-initializer|failed-swap ...]] query)",
        description: (QueryStepOp::AssignmentRelations),
        step: AssignmentRelations,
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
    LiteralOccurrences {
        labels: ["literal-occurrences", "literal_occurrences"],
        class: Wrapper,
        shape: Query,
        signature: "(literal-occurrences query)",
        description: (QueryStepOp::LiteralOccurrences),
        step: LiteralOccurrences,
    }
    CallableMetrics {
        labels: ["callable-metrics", "callable_metrics"],
        class: Wrapper,
        shape: Query,
        signature: "(callable-metrics query)",
        description: (QueryStepOp::CallableMetrics),
        step: CallableMetrics,
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
        signature: "(decorator-bindings [:module module] [:imported-name name] [:annotation-type fq-name] query)",
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
    PythonOverrides {
        labels: ["python-overrides", "python_overrides"],
        class: Wrapper,
        shape: Query,
        signature: "(python-overrides query)",
        description: (QueryStepOp::PythonOverrides),
        step: PythonOverrides,
    }
    PythonCallRelations {
        labels: ["python-call-relations", "python_call_relations"],
        class: Wrapper,
        shape: Query,
        signature: "(python-call-relations query)",
        description: (QueryStepOp::PythonCallRelations),
        step: PythonCallRelations,
    }
    PythonOverrideSignatures {
        labels: ["python-override-signatures", "python_override_signatures"],
        class: Wrapper,
        shape: Query,
        signature: "(python-override-signatures query)",
        description: (QueryStepOp::PythonOverrideSignatures),
        step: PythonOverrideSignatures,
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
    PythonComparisonConstants {
        labels: ["python-comparison-constants", "python_comparison_constants"],
        class: Wrapper,
        shape: Query,
        signature: "(python-comparison-constants query)",
        description: (QueryStepOp::PythonComparisonConstants),
        step: PythonComparisonConstants,
    }
    PythonComparisonUsingIs {
        labels: ["python-comparison-using-is", "python_comparison_using_is"],
        class: Wrapper,
        shape: Query,
        signature: "(python-comparison-using-is query)",
        description: (QueryStepOp::PythonComparisonUsingIs),
        step: PythonComparisonUsingIs,
    }
    PythonComparisonUsingIsNonPortable {
        labels: ["python-comparison-using-is-non-portable", "python_comparison_using_is_non_portable"],
        class: Wrapper,
        shape: Query,
        signature: "(python-comparison-using-is-non-portable query)",
        description: (QueryStepOp::PythonComparisonUsingIsNonPortable),
        step: PythonComparisonUsingIsNonPortable,
    }
    BindingOccurrence {
        labels: ["binding-occurrence", "binding_occurrence"],
        class: Wrapper,
        shape: Query,
        signature: "(binding-occurrence query)",
        description: (QueryStepOp::BindingOccurrence),
        step: BindingOccurrence,
    }
    BindingUses {
        labels: ["binding-uses", "binding_uses"],
        class: Wrapper,
        shape: Query,
        signature: "(binding-uses query)",
        description: (QueryStepOp::BindingUses),
        step: BindingUses,
    }
    IdenticalOperands {
        labels: ["identical-operands", "identical_operands"],
        class: Wrapper,
        shape: Query,
        signature: "(identical-operands query)",
        description: (QueryStepOp::IdenticalOperands),
        step: IdenticalOperands,
    }
    PythonMissingSelf {
        labels: ["python-missing-self", "python_missing_self"],
        class: Wrapper,
        shape: Query,
        signature: "(python-missing-self query)",
        description: (QueryStepOp::PythonMissingSelf),
        step: PythonMissingSelf,
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
    DependencyEvidence {
        labels: ["dependency-evidence", "dependency_evidence"],
        class: Wrapper,
        shape: DependencyEvidenceFilter,
        signature: "(dependency-evidence [:ecosystem ...] [:package ...] [:kind ...] [:exact-version ...] [:version-range ...] [:source ...] [:declared-by ...] [:scope ...])",
        description: "Read revision-selected static dependency file facts. Declarations, exact locks and unresolved associations remain separate; no dependency discovery or build runs during a query.",
    }
    ConfigurationFacts {
        labels: ["configuration-facts", "configuration_facts"],
        class: Wrapper,
        shape: ConfigurationFactsFilter,
        signature: "(configuration-facts [:format ...] [:node-kind ...] [:role ...] [:scalar-kind ...] [:key ...] [:value ...] [:value-ignore-case ...] [:value-lt ...] [:value-le ...] [:value-gt ...] [:value-ge ...] [:xml-parent-key ...] [:xml-preceding-sibling-key ...] [:xml-sibling-attribute-key ...] [:xml-sibling-attribute-value ...] [:xml-sibling-attribute-value-ignore-case ...] [:xml-reference-source-key ...] [:xml-reference-target-key ...] [:xml-reference-target-element-key ...] [:xml-reference-target-child-key ...] [:xml-peer-element-key ...] [:xml-peer-attribute-key ...] [:xml-peer-child-key ...] [:xml-peer-min-shared-children N] [:route ...] [:fact-ordinal ...] [:provenance ...] [:completeness ...])",
        description: "Seed authored configuration-document facts with exact key/value, numeric value, XML structure, route, node, provenance, and document-completeness constraints. Unsupported formats and recovered documents remain typed diagnostics instead of becoming clean empty answers.",
    }
    ConfigurationAbsence {
        labels: ["configuration-absence", "configuration_absence"],
        class: Wrapper,
        shape: Query,
        signature: "(configuration-absence [:format ...] [:node-kind ...] [:role ...] [:scalar-kind ...] [:key ...] [:value ...] [:value-ignore-case ...] [:value-lt ...] [:value-le ...] [:value-gt ...] [:value-ge ...] [:route ...] [:fact-ordinal ...] [:provenance ...] [:completeness ...] query)",
        description: "Apply a document-scoped anti-join to configuration facts. The inner configuration-facts query must select document roots; the result is retained only when no authored fact in that same document matches the filter. Incomplete ingestion is never treated as absence.",
        step: ConfigurationAbsence,
    }
    Correlate {
        labels: ["correlate"],
        class: Wrapper,
        shape: CrossDomainCorrelation,
        signature: "(correlate :relation (configuration-key :documents [\"path\" ...]) :code query :configuration query)",
        description: "Use a registered structural relation to pair code or dependency evidence with configuration facts. Dependency-configuration retains every dependency witness and proves mitigation only with complete applicability, version, precedence, and value evidence. Each cross_domain row retains exact input evidence and provenance; ordinary sets never combine code with configuration.",
    }
    RequireBoth {
        labels: ["require-both", "require_both"],
        class: Wrapper,
        shape: CrossDomainRequirement,
        signature: "(require-both :code query :configuration query)",
        description: "Require a programming-code query and a configuration query to both produce rows. Returns each contributing row tagged with its own domain, only when both are satisfied, and never pairs a code row with a configuration row. An empty side that was incomplete keeps the answer incomplete.",
    }
    ConfigurationKey {
        labels: ["configuration-key", "configuration_key"],
        class: Relation,
        shape: CorrelationDocumentList,
        signature: "(configuration-key :documents [\"path\" ...])",
        description: "Relate a plain string-literal argument bound to a resolver-proven callee (an expression_site row) to the .properties member whose single key segment equals that literal, inside one of the explicitly declared documents. Documents are exact paths, not globs; no name, spelling, file-name, or co-occurrence join is made.",
    }
    ConfigurationCode {
        labels: ["configuration-code", "configuration_code"],
        class: Relation,
        shape: ConfigurationCodeRelation,
        signature: "(configuration-code :match scalar-declaration|scalar-owner|scalar-member|same-project [:absence true|false])",
        description: "Relate an authored configuration scalar or document to a declaration or same-project code fact using a structured identity join. `absence true` is a fail-closed anti-join and never treats incomplete inputs as clean.",
    }
    DependencyConfiguration {
        labels: ["dependency-configuration", "dependency_configuration"],
        class: Relation,
        shape: DependencyConfigurationRelation,
        signature: "(dependency-configuration :owner \"topology-id\" :ecosystem npm|cargo :version-ranges [\"range\" ...] :documents [\"path.properties\" ...] :values [\"value\" ...] [:overrides [[\"lower\" \"higher\"] ...]])",
        description: "Keep each dependency witness and prove mitigation only for a complete locked or installed instance owned by the exact declared topology identity, in a supported ecosystem and version range, with a complete unique effective .properties value. Documents and lower-to-higher override edges are explicit reviewed applicability evidence; framework precedence, installation, runtime state, and member ownership are never guessed.",
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
        signature: "(state-events-of [:class [establish|kill|read ...]] [:subject [binding|property ...]] [:read-cause [post_resume_use|scope_end_drop ...]] query)",
        description: (QueryStepOp::StateEventsOf),
        step: StateEventsOf,
    }
    BindingInitializerCallsOf {
        labels: ["binding-initializer-calls-of", "binding_initializer_calls_of"],
        class: Wrapper,
        shape: Query,
        signature: "(binding-initializer-calls-of query)",
        description: (QueryStepOp::BindingInitializerCallsOf),
        step: BindingInitializerCallsOf,
    }
    SelectedPropertyRelationsOf {
        labels: ["selected-property-relations-of", "selected_property_relations_of"],
        class: Wrapper,
        shape: Query,
        signature: "(selected-property-relations-of program-point-query)",
        description: (QueryStepOp::SelectedPropertyRelationsOf),
        step: SelectedPropertyRelationsOf,
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
    FailureHandlerState {
        labels: ["failure-handler-state", "failure_handler_state"],
        class: Wrapper,
        shape: Query,
        signature: "(failure-handler-state query)",
        description: (QueryStepOp::FailureHandlerState),
        step: FailureHandlerState,
    }
    BranchRelations {
        labels: ["branch-relations", "branch_relations"],
        class: Wrapper,
        shape: Query,
        signature: "(branch-relations [:relation [identical-bodies|repeated-condition|contradictory-condition|subsumed-condition|empty-arm ...]] query)",
        description: (QueryStepOp::BranchRelations),
        step: BranchRelations,
    }
    CppExpressions {
        labels: ["cpp-expressions", "cpp_expressions"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-expressions query)",
        description: (QueryStepOp::CppExpressions),
        step: CppExpressions,
    }
    CppInconsistentLoopDirection {
        labels: ["cpp-inconsistent-loop-direction", "cpp_inconsistent_loop_direction"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-inconsistent-loop-direction query)",
        description: (QueryStepOp::CppInconsistentLoopDirection),
        step: CppInconsistentLoopDirection,
    }
    CppUnsafeArrayForDaysOfTheYear {
        labels: ["cpp-leap-year-unsafe-array-for-days-of-the-year", "cpp_unsafe_array_for_days_of_the_year"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-leap-year-unsafe-array-for-days-of-the-year query)",
        description: (QueryStepOp::CppUnsafeArrayForDaysOfTheYear),
        step: CppUnsafeArrayForDaysOfTheYear,
    }
    CppProvenance {
        labels: ["cpp-provenance", "cpp_provenance"],
        class: Wrapper,
        shape: Query,
        signature: "(cpp-provenance [:rule [incorrect-pointer-scaling-char|return-stack-allocated-memory|stack-address-escape|suspicious-pointer-scaling|suspicious-pointer-scaling-void|improper-null-termination ...]] query)",
        description: (QueryStepOp::CppProvenance),
        step: CppProvenance,
    }
    LoopRelations {
        labels: ["loop-relations", "loop_relations"],
        class: Wrapper,
        shape: Query,
        signature: "(loop-relations query)",
        description: (QueryStepOp::LoopRelations),
        step: LoopRelations,
    }
    StatementReachability {
        labels: ["statement-reachability", "statement_reachability"],
        class: Wrapper,
        shape: Query,
        signature: "(statement-reachability query)",
        description: (QueryStepOp::StatementReachability),
        step: StatementReachability,
    }
    PendingCleanupFlows {
        labels: ["pending-cleanup-flows", "pending_cleanup_flows"],
        class: Wrapper,
        shape: Query,
        signature: "(pending-cleanup-flows query)",
        description: (QueryStepOp::PendingCleanupFlows),
        step: PendingCleanupFlows,
    }
    RustMarkerImplsOf {
        labels: ["rust-marker-impls-of", "rust_marker_impls_of"],
        class: Wrapper,
        shape: Query,
        signature: "(rust-marker-impls-of declaration-query)",
        description: (QueryStepOp::RustMarkerImplsOf),
        step: RustMarkerImplsOf,
    }
    RustPointerFindings {
        labels: ["rust-pointer-findings", "rust_pointer_findings"],
        class: Wrapper,
        shape: Query,
        signature: "(rust-pointer-findings procedure-query)",
        description: (QueryStepOp::RustPointerFindings),
        step: RustPointerFindings,
    }
    ControlRelations {
        labels: ["control-relations", "control_relations"],
        class: Wrapper,
        shape: Query,
        signature: "(control-relations [:relation [dominates|postdominates|control-depends-on|reachable|reaches|in-loop ...]] [:exit-partition [normal-and-exceptional ...]] query)",
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
    StringValue {
        labels: ["value", "string-value", "string_value"],
        class: Predicate,
        shape: String,
        signature: "(string-value \"exactValue\")",
        description: "Match a string literal by its decoded value; unsupported or non-literal values remain incomplete.",
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
    UnsafeContext {
        labels: ["unsafe-context", "unsafe_context"],
        class: Predicate,
        shape: Boolean,
        signature: "(unsafe-context true|false)",
        description: "Match a Rust call by whether it is inside an unsafe block or unsafe function. Unsupported on other languages and on non-call patterns.",
    }
    Async {
        labels: ["async"],
        class: Predicate,
        shape: Boolean,
        signature: "(async true|false)",
        description: "Match a callable by its AST-backed async modifier.",
    }
    TypeKind {
        labels: ["type-kind", "type_kind"],
        class: Predicate,
        shape: String,
        signature: "(type-kind class|interface|enum|record|annotation)",
        description: "Match the persisted source form of a type declaration.",
    }
    Modifier {
        labels: ["modifier"],
        class: Predicate,
        shape: String,
        signature: "(modifier static|abstract|final|volatile|synchronized|transient|native|strictfp|default|sealed|non-sealed|public|protected|private)",
        description: "Match a declaration by a modifier read from its structured modifier nodes.",
    }
    DuplicateKey {
        labels: ["duplicate-key", "duplicate_key"],
        class: Predicate,
        shape: Boolean,
        signature: "(duplicate-key true|false)",
        description: "Match a Python dictionary entry by whether its decoded literal key repeats an earlier entry.",
    }
    Parenthesized {
        labels: ["parenthesized"],
        class: Predicate,
        shape: Boolean,
        signature: "(parenthesized true|false)",
        description: "Match a string-literal expression by whether its syntax is parenthesized.",
    }
    IntegerValue {
        labels: ["integer-value", "integer_value"],
        class: Predicate,
        shape: CanonicalIntegerDecimal,
        signature: "(integer-value \"canonicalDecimal\")",
        description: "Match an integer literal's exact canonical decimal value without narrowing it.",
    }
    IntegerHasAnyBits {
        labels: ["integer-has-any-bits", "integer_has_any_bits"],
        class: Predicate,
        shape: PermissionBitMask,
        signature: "(integer-has-any-bits positiveMask)",
        description: "Match an integer literal with at least one requested low bit set.",
    }
    IntegerHasAllBits {
        labels: ["integer-has-all-bits", "integer_has_all_bits"],
        class: Predicate,
        shape: PermissionBitMask,
        signature: "(integer-has-all-bits positiveMask)",
        description: "Match an integer literal with every requested low bit set.",
    }
    IntegerHasNoBits {
        labels: ["integer-has-no-bits", "integer_has_no_bits"],
        class: Predicate,
        shape: PermissionBitMask,
        signature: "(integer-has-no-bits positiveMask)",
        description: "Match an integer literal with none of the requested low bits set.",
    }
    AssignmentTargetKind {
        labels: ["assignment-target-kind", "assignment_target_kind"],
        class: Predicate,
        shape: AssignmentSequenceKind,
        signature: "(assignment-target-kind list|tuple)",
        description: "Match the direct target sequence kind of a tuple/list assignment.",
    }
    AssignmentValueKind {
        labels: ["assignment-value-kind", "assignment_value_kind"],
        class: Predicate,
        shape: AssignmentSequenceKind,
        signature: "(assignment-value-kind list|tuple)",
        description: "Match the direct value sequence kind of a tuple/list assignment.",
    }
    AssignmentTargetUnstarredCount {
        labels: ["assignment-target-unstarred-count", "assignment_target_unstarred_count"],
        class: Predicate,
        shape: NonNegativeInteger,
        signature: "(assignment-target-unstarred-count count)",
        description: "Match the number of non-starred direct target elements in a tuple/list assignment.",
    }
    AssignmentValueUnstarredCount {
        labels: ["assignment-value-unstarred-count", "assignment_value_unstarred_count"],
        class: Predicate,
        shape: NonNegativeInteger,
        signature: "(assignment-value-unstarred-count count)",
        description: "Match the number of non-starred direct value elements in a tuple/list assignment.",
    }
    AssignmentTargetStarred {
        labels: ["assignment-target-starred", "assignment_target_starred"],
        class: Predicate,
        shape: Boolean,
        signature: "(assignment-target-starred true|false)",
        description: "Match whether the direct target sequence has a starred element.",
    }
    AssignmentValueStarred {
        labels: ["assignment-value-starred", "assignment_value_starred"],
        class: Predicate,
        shape: Boolean,
        signature: "(assignment-value-starred true|false)",
        description: "Match whether the direct value sequence has a starred element.",
    }
    AssignmentUnstarredCountMismatch {
        labels: ["assignment-unstarred-count-mismatch", "assignment_unstarred_count_mismatch"],
        class: Predicate,
        shape: Boolean,
        signature: "(assignment-unstarred-count-mismatch true|false)",
        description: "Match whether the two direct sequence sides have different unstarred element counts.",
    }
    Index {
        labels: ["index"],
        class: Predicate,
        shape: NonNegativeInteger,
        signature: "(index zeroBasedPosition)",
        description: "Match a child at this exact zero-based position in its parent's ordered list role, such as elements.",
    }
    StringValueRegex {
        labels: ["value/regex", "string-value/regex", "string_value/regex"],
        class: Predicate,
        shape: RegexString,
        signature: "(value/regex \"pattern\")",
        description: "Match a normalized string literal's decoded value with a regular expression.",
    }
    Not {
        labels: ["not"],
        class: Predicate,
        shape: Pattern,
        signature: "(not pattern)",
        description: "Exclude nodes matching the nested pattern.",
    }
    All {
        labels: ["and"],
        class: Predicate,
        shape: PatternList,
        signature: "(and pattern ...)",
        description: "Require every nested pattern to match the same node.",
    }
    Any {
        labels: ["or"],
        class: Predicate,
        shape: PatternList,
        signature: "(or pattern ...)",
        description: "Require at least one nested pattern to match the same node.",
    }
    LocalValue {
        labels: ["local-value", "local_value"],
        class: Predicate,
        shape: Pattern,
        signature: "(local-value value-pattern)",
        description: "Match the unique direct function-local assignment value guaranteed before this read by unconditional or earlier same-suite execution.",
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
    LanguageRule {
        labels: ["language-rule", "language_rule"],
        class: Predicate,
        shape: String,
        signature: "(language-rule \"cpp/rule\"|\"cs/rule\"|\"java/rule\"|\"js/rule\")",
        description: "Apply one closed relation from the language-rule registry to the root structural seed; the id prefix selects its language.",
    }
    BodyState {
        labels: ["body-state", "body_state"],
        class: Predicate,
        shape: String,
        signature: "(body-state empty|comment-only|code)",
        description: "Match the structured state of a directly-owned branch or loop block.",
    }
    BodyOwner {
        labels: ["body-owner", "body_owner"],
        class: Predicate,
        shape: String,
        signature: "(body-owner if-consequence|if-alternative|loop-body)",
        description: "Restrict a body-state match to its structured if or loop owner role.",
    }
    ProgramPointById {
        labels: ["program-point-by-id", "program_point_by_id"],
        class: Wrapper,
        shape: Query,
        signature: "(program-point-by-id :id \"public-program-point-id\" procedure-query)",
        description: (QueryStepOp::ProgramPointById),
        step: ProgramPointById,
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
    StringValue {
        labels: ["value", "string-value", "string_value"],
        shape: String,
        signature: ":string-value \"exactValue\"",
        description: "Match a string literal by its decoded value; unsupported or non-literal values remain incomplete.",
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
    CommentBlockRegex {
        labels: ["comment-block/regex", "comment_block/regex"],
        shape: RegexString,
        signature: ":comment-block/regex \"pattern\"",
        description: "Match a comment using the source text of its maximal consecutive comment block.",
    }
    BooleanValue {
        labels: ["boolean-value", "boolean_value"],
        shape: Boolean,
        signature: ":boolean-value true|false",
        description: "Match a boolean literal by its normalized language-neutral value.",
    }
    UnsafeContext {
        labels: ["unsafe-context", "unsafe_context"],
        shape: Boolean,
        signature: ":unsafe-context true|false",
        description: "Match a Rust call by whether it is inside an unsafe block or unsafe function. Unsupported on other languages and on non-call patterns.",
    }
    Async {
        labels: ["async"],
        shape: Boolean,
        signature: ":async true|false",
        description: "Match a callable by its AST-backed async modifier.",
    }
    TypeKind {
        labels: ["type-kind", "type_kind"],
        shape: String,
        signature: ":type-kind class|interface|enum|record|annotation",
        description: "Match the persisted source form of a type declaration.",
    }
    Modifier {
        labels: ["modifier"],
        shape: String,
        signature: ":modifier static|abstract|final|volatile|synchronized|transient|native|strictfp|default|sealed|non-sealed|public|protected|private",
        description: "Match a declaration by a modifier read from its structured modifier nodes.",
    }
    DuplicateKey {
        labels: ["duplicate-key", "duplicate_key"],
        shape: Boolean,
        signature: ":duplicate-key true|false",
        description: "Match a Python dictionary entry by whether its decoded literal key repeats an earlier entry.",
    }
    Parenthesized {
        labels: ["parenthesized"],
        shape: Boolean,
        signature: ":parenthesized true|false",
        description: "Match a string-literal expression by whether its syntax is parenthesized.",
    }
    IntegerValue {
        labels: ["integer-value", "integer_value"],
        shape: CanonicalIntegerDecimal,
        signature: ":integer-value \"canonicalDecimal\"",
        description: "Match an integer literal's exact canonical decimal value without narrowing it.",
    }
    IntegerHasAnyBits {
        labels: ["integer-has-any-bits", "integer_has_any_bits"],
        shape: PermissionBitMask,
        signature: ":integer-has-any-bits positiveMask",
        description: "Match an integer literal with at least one requested low bit set.",
    }
    IntegerHasAllBits {
        labels: ["integer-has-all-bits", "integer_has_all_bits"],
        shape: PermissionBitMask,
        signature: ":integer-has-all-bits positiveMask",
        description: "Match an integer literal with every requested low bit set.",
    }
    IntegerHasNoBits {
        labels: ["integer-has-no-bits", "integer_has_no_bits"],
        shape: PermissionBitMask,
        signature: ":integer-has-no-bits positiveMask",
        description: "Match an integer literal with none of the requested low bits set.",
    }
    AssignmentTargetKind {
        labels: ["assignment-target-kind", "assignment_target_kind"],
        shape: AssignmentSequenceKind,
        signature: ":assignment-target-kind list|tuple",
        description: "Match the direct target sequence kind of a tuple/list assignment.",
    }
    AssignmentValueKind {
        labels: ["assignment-value-kind", "assignment_value_kind"],
        shape: AssignmentSequenceKind,
        signature: ":assignment-value-kind list|tuple",
        description: "Match the direct value sequence kind of a tuple/list assignment.",
    }
    AssignmentTargetUnstarredCount {
        labels: ["assignment-target-unstarred-count", "assignment_target_unstarred_count"],
        shape: NonNegativeInteger,
        signature: ":assignment-target-unstarred-count count",
        description: "Match the number of non-starred direct target elements in a tuple/list assignment.",
    }
    AssignmentValueUnstarredCount {
        labels: ["assignment-value-unstarred-count", "assignment_value_unstarred_count"],
        shape: NonNegativeInteger,
        signature: ":assignment-value-unstarred-count count",
        description: "Match the number of non-starred direct value elements in a tuple/list assignment.",
    }
    AssignmentTargetStarred {
        labels: ["assignment-target-starred", "assignment_target_starred"],
        shape: Boolean,
        signature: ":assignment-target-starred true|false",
        description: "Match whether the direct target sequence has a starred element.",
    }
    AssignmentValueStarred {
        labels: ["assignment-value-starred", "assignment_value_starred"],
        shape: Boolean,
        signature: ":assignment-value-starred true|false",
        description: "Match whether the direct value sequence has a starred element.",
    }
    AssignmentUnstarredCountMismatch {
        labels: ["assignment-unstarred-count-mismatch", "assignment_unstarred_count_mismatch"],
        shape: Boolean,
        signature: ":assignment-unstarred-count-mismatch true|false",
        description: "Match whether the two direct sequence sides have different unstarred element counts.",
    }
    Index {
        labels: ["index"],
        shape: NonNegativeInteger,
        signature: ":index zeroBasedPosition",
        description: "Match a child at this exact zero-based position in its parent's ordered list role, such as elements.",
    }
    StringValueRegex {
        labels: ["string-value/regex", "string_value/regex"],
        shape: RegexString,
        signature: ":string-value/regex \"pattern\"",
        description: "Match a normalized string literal's decoded value with a regular expression.",
    }
    Not {
        labels: ["not"],
        shape: Pattern,
        signature: ":not pattern",
        description: "Exclude nodes matching the nested pattern.",
    }
    All {
        labels: ["and"],
        shape: PatternList,
        signature: ":and [pattern ...]",
        description: "Require every nested pattern to match the same node.",
    }
    Any {
        labels: ["or"],
        shape: PatternList,
        signature: ":or [pattern ...]",
        description: "Require at least one nested pattern to match the same node.",
    }
    LocalValue {
        labels: ["local-value", "local_value"],
        shape: Pattern,
        signature: ":local-value pattern",
        description: "Match the unique direct function-local assignment value guaranteed before this read by unconditional or earlier same-suite execution.",
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
    LanguageRule {
        labels: ["language-rule", "language_rule"],
        shape: String,
        signature: ":language-rule \"cpp/rule\"|\"cs/rule\"|\"java/rule\"|\"js/rule\"",
        description: "Apply one closed relation from the language-rule registry to the root structural seed; the id prefix selects its language.",
    }
    BodyState {
        labels: ["body-state", "body_state"],
        shape: String,
        signature: ":body-state empty|comment-only|code",
        description: "Match the structured state of a directly-owned branch or loop block.",
    }
    BodyOwner {
        labels: ["body-owner", "body_owner"],
        shape: String,
        signature: ":body-owner if-consequence|if-alternative|loop-body",
        description: "Restrict a body-state match to its structured if or loop owner role.",
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
    Where { label: "where", shape: PathScope, signature: "\"where\": [\"glob\", ...] | [[\"glob\", ...], ...]", description: "Restrict the source relation to workspace-relative path globs; nested lists conjoin alternative-glob groups." }
    Languages { label: "languages", shape: LanguageList, signature: "\"languages\": [\"rust\", ...]", description: "Restrict the query to analyzer languages." }
    Match { label: "match", shape: Pattern, signature: "\"match\": { pattern }", description: "Define the required root structural pattern." }
    Union { label: "union", shape: QueryList, signature: "\"union\": [{ query }, { query }, ...]", description: "Combine typed endpoints reached by any branch; branches of different row kinds combine when only filter and project follow." }
    Intersect { label: "intersect", shape: QueryList, signature: "\"intersect\": [{ query }, { query }, ...]", description: "Keep compatible typed endpoints reached by every branch." }
    Except { label: "except", shape: QueryList, signature: "\"except\": [{ query }, { query }, ...]", description: "Keep first-branch endpoints absent from every later branch." }
    Inside { label: "inside", shape: Pattern, signature: "\"inside\": { pattern }", description: "Require the root match to be inside a matching container." }
    InsideDecl { label: "inside_decl", shape: Pattern, signature: "\"inside_decl\": { pattern }", description: "Require the root match to be inside a matching container without crossing a callable declaration; Rust impl members and out-of-line C++ member definitions can also match their resolved owning type." }
    NotInside { label: "not_inside", shape: Pattern, signature: "\"not_inside\": { pattern }", description: "Exclude root matches inside a matching container." }
    Steps { label: "steps", shape: QuerySteps, signature: "\"steps\": [{ \"op\": \"file_of\" }, ...]", description: "Apply ordered typed transformations to structural matches." }
    Limit { label: "limit", shape: PositiveInteger, signature: "\"limit\": positive integer", description: "Set the maximum number of matches returned." }
    ResultDetail { label: "result_detail", shape: ResultDetail, signature: "\"result_detail\": \"compact\" | \"full\"", description: "Choose compact output or full capture and source details." }
    ExecutionMode { label: "execution_mode", shape: ExecutionMode, signature: "\"execution_mode\": \"results\" | \"explain\" | \"profile\"", description: "Return ordinary results, explain the selected plan without execution, or execute with an operator profile." }
    SchemaVersion { label: "schema_version", shape: SchemaVersion, signature: "\"schema_version\": supported version string", description: "Pin one exact CodeQuery schema version; omission selects the compatible lineage head." }
    Occurrences { label: "occurrences", shape: OccurrenceFilter, signature: "\"occurrences\": { \"class\": [...], \"role\": [...], \"namespace\": [...] }", description: "Seed classified identifier occurrences directly from workspace facts." }
    Scopes { label: "scopes", shape: ScopeFilter, signature: "\"scopes\": { \"kind\": [...] }", description: "Seed lexical scope rows directly from workspace facts." }
    Bindings { label: "bindings", shape: BindingFilter, signature: "\"bindings\": { \"kind\": [...], \"name\": [...], \"hoisting\": [...] }", description: "Seed lexical binding rows directly from workspace facts." }
    Paths { label: "paths", shape: PathFilter, signature: "\"paths\": { \"min_segments\": N }", description: "Seed qualified-path rows directly from workspace facts." }
    GenerationSites { label: "generation_sites", shape: GenerationSiteFilter, signature: "\"generation_sites\": { \"kind\": [...], \"input\": [...] }", description: "Seed generation-site rows directly from recorded materialization provenance." }
    Exports { label: "exports", shape: ExportFilter, signature: "\"exports\": { \"form\": [...], \"name\": [...] }", description: "Seed export rows directly from recorded materialization provenance." }
    DependencyEvidence { label: "dependency_evidence", shape: DependencyEvidenceFilter, signature: "\"dependency_evidence\": { \"ecosystems\": [...], \"packages\": [...], \"kinds\": [...], \"exact_versions\": [...], \"version_ranges\": [...], \"sources\": [...], \"declared_by\": [...], \"scopes\": [...] }", description: "Read stored static dependency evidence with exact identity, ownership, scope and provenance. Uncertainty remains explicit." }
    ConfigurationFacts { label: "configuration_facts", shape: ConfigurationFactsFilter, signature: "\"configuration_facts\": { \"formats\": [...], \"node_kinds\": [...], \"roles\": [...], \"scalar_kinds\": [...], \"keys\": [...], \"values\": [...], \"values_ignore_case\": [...], \"value_lt\": \"number\", \"value_le\": \"number\", \"value_gt\": \"number\", \"value_ge\": \"number\", \"xml_parent_keys\": [...], \"xml_preceding_sibling_keys\": [...], \"xml_sibling_attribute_keys\": [...], \"xml_sibling_attribute_values\": [...], \"xml_sibling_attribute_values_ignore_case\": [...], \"xml_reference_source_keys\": [...], \"xml_reference_target_keys\": [...], \"xml_reference_target_element_keys\": [...], \"xml_reference_target_child_keys\": [...], \"xml_peer_element_keys\": [...], \"xml_peer_attribute_keys\": [...], \"xml_peer_child_keys\": [...], \"xml_peer_min_shared_children\": 3, \"routes\": [...], \"fact_ordinals\": [...], \"provenances\": [...], \"completenesses\": [...] }", description: "Seed authored configuration-document facts with exact key/value, XML structural relations, same-document references, peer child-set comparisons, route, node, provenance, and document-completeness constraints. Unsupported formats and recovered documents remain typed diagnostics instead of becoming clean empty answers." }
    Correlate { label: "correlate", shape: CrossDomainCorrelation, signature: "\"correlate\": { \"relation\": { \"configuration_key\": { \"documents\": [\"path\", ...] } }, \"code\": { query }, \"configuration\": { query } }", description: "Use a registered structural relation to pair input evidence, retaining dependency witnesses whenever mitigation cannot be proved." }
    RequireBoth { label: "require_both", shape: CrossDomainRequirement, signature: "\"require_both\": { \"code\": { query }, \"configuration\": { query } }", description: "Require a programming-code query and a configuration query to both produce rows, without pairing them." }
}

/// Every source a query plan can name, in the order the decoder reports them.
/// The first eleven are seeds; `union`, `intersect`, and `except` combine
/// branches. A plan node authors exactly one. The decoder's missing-source and
/// mutual-exclusion messages and the MCP `query_code` schema both read this
/// list, so a source added here reaches both.
pub const ALL_QUERY_PLAN_SOURCES: &[QueryField] = &[
    QueryField::Match,
    QueryField::Occurrences,
    QueryField::Scopes,
    QueryField::Bindings,
    QueryField::GenerationSites,
    QueryField::Exports,
    QueryField::DependencyEvidence,
    QueryField::ConfigurationFacts,
    QueryField::Correlate,
    QueryField::RequireBoth,
    QueryField::Paths,
    QueryField::Union,
    QueryField::Intersect,
    QueryField::Except,
];

json_fields! {
    QueryStepField,
    ALL_QUERY_STEP_FIELDS,
    Op { label: "op", shape: String, signature: "\"op\": \"step_name\"", description: "Select the typed pipeline transformation." }
    StatementFactKind { label: "statement_fact_kind", shape: String, signature: "\"statement_fact_kind\": \"alloca-in-loop\" | \"complex-block\" | \"complex-condition\" | \"empty-block\" | \"long-switch\" | \"missing-case-in-switch\" | \"nested-loops-with-same-variable\" | \"use-of-goto\"", description: "Select one registered CodeQL statement fact. Shared shapes are supplied by C++ and Java; goto and alloca require C++. Nested-loop binding proofs are shared by C++, C# and Java. The RQL spelling remains :kind." }
    CppFactKind { label: "cpp_fact_kind", shape: String, signature: "\"kind\": \"assignment-does-not-return-this\" | \"catch-by-value\" | \"constructor-delegation\" | \"constructor-used-as-copy-constructor\" | \"rule-of-three\" | \"rule-of-two\" | \"throwing-pointer\" | \"undisciplined-multiple-inheritance\"", description: "Select the registered C++ CodeQL class-rule fact." }
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
    Runtime { label: "runtime", shape: RuntimeFamily, signature: "\"runtime\": \"node\" | \"python\"", description: "Select the modeled runtime family." }
    Global { label: "global", shape: RuntimeGlobal, signature: "\"global\": \"process\" | \"os\" | \"sys\"", description: "Select the modeled runtime root binding: a global object, or a standard-library module a program imports." }
    Container { label: "container", shape: RuntimeContainer, signature: "\"container\": \"env\" | \"environ\" | \"argv\"", description: "Select the modeled container member published by that runtime root." }
    Property { label: "property", shape: String, signature: "\"property\": \"name\"", description: "Select one exact static property key." }
    Index { label: "index", shape: NonNegativeInteger, signature: "\"index\": non-negative integer", description: "Select one exact non-negative array index." }
    KeyKind { label: "key_kind", shape: RuntimeKeyKind, signature: "\"key_kind\": \"static-property\" | \"static-index\"", description: "Select a family of static property or index keys without naming one exact key." }
    IndexMin { label: "index_min", shape: NonNegativeInteger, signature: "\"index_min\": non-negative integer", description: "Set the inclusive minimum index accepted by a static-index key family." }
    IndexMax { label: "index_max", shape: NonNegativeInteger, signature: "\"index_max\": non-negative integer", description: "Set the inclusive maximum index accepted by a static-index key family." }
    SourceOrigin { label: "source_origin", shape: RuntimeSourceOrigin, signature: "\"source_origin\": \"pristine_input\"", description: "Require the modeled pristine runtime-input origin." }
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
    DecoratorAnnotationType { label: "annotation_type", shape: String, signature: "\"annotation_type\": \"org.example.Input\"", description: "Restrict decorator-binding rows to one exact resolved Java annotation type qualified name." }
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
    StateEventReadCauses { label: "read_cause", shape: StateEventReadCauseList, signature: "\"read_cause\": [\"post_resume_use\", \"scope_end_drop\"]", description: "Restrict synthetic suspension reads by why the binding is held in the future frame. `scope_end_drop` is syntactic liveness; combine it with initializer identity when selecting non-Copy resources." }
    FlowRelations { label: "flow_relation", shape: FlowRelationList, signature: "\"flow_relation\": [\"reaching\", ...]", description: "Restrict flow-relation rows to one or more relations." }
    RewriteDomains { label: "domain", shape: RewriteDomainList, signature: "\"domain\": [\"rust_import_alias\"]", description: "Restrict rewrite-path rows to one or more declared rewrite domains." }
    RewriteOutcomes { label: "rewrite_outcome", shape: RewriteOutcomeList, signature: "\"rewrite_outcome\": [\"converged\", \"cycle\", \"exceeded_budget\"]", description: "Restrict rewrite-path rows to one or more terminal outcomes." }
    FlowCertainties { label: "certainty", shape: FlowCertaintyList, signature: "\"certainty\": [\"exact\", \"may\"]", description: "Restrict flow-relation rows to one or more certainties." }
    FailureUseProvenances { label: "provenance", shape: FailureUseProvenanceList, signature: "\"provenance\": [\"condition_result\", ...]", description: "Restrict failure-use rows to one or more structured provenance classes." }
    FailureUseConsumers { label: "consumer", shape: FailureUseConsumerList, signature: "\"consumer\": [\"return\", \"returned_call_argument\", \"call_argument\"]", description: "Restrict failure-use rows to one or more structured consumer classes." }
    BranchRelations { label: "branch_relation", shape: BranchRelationKindList, signature: "\"branch_relation\": [\"identical_bodies\", ...]", description: "Restrict branch-relation rows to one or more relation families." }
    ControlRelations { label: "control_relation", shape: ControlRelationKindList, signature: "\"control_relation\": [\"dominates\", ...]", description: "Restrict control-relation rows to one or more relations." }
    AssignmentRelations { label: "assignment_relation", shape: AssignmentRelationKindList, signature: "\"assignment_relation\": [\"self_assignment\", \"self_initializer\", \"failed_swap\", \"overwritten_unread\"]", description: "Select assignment obligations before deriving coverage. With no selection, only self-assignment is derived. Self-initializer is currently a bounded C/C++ local declaration slice; overwritten-unread supports ordinary locals in C, C++, C#, Go, Java, JavaScript, Kotlin, PHP, Python, Ruby, Rust, Scala, and TypeScript." }
    CppProvenance { label: "cpp_provenance_rule", shape: CppProvenanceRuleList, signature: "\"cpp_provenance_rule\": [\"incorrect_pointer_scaling_char\", ...]", description: "Select direct C/C++ provenance rule families." }
    ControlExitPartitions { label: "exit_partition", shape: ControlExitPartitionList, signature: "\"exit_partition\": [\"normal_and_exceptional\"]", description: "Restrict control-relation rows to one or more exit partitions the claim was computed against." }
    ResolvesTo { label: "resolves_to", shape: CallIdentity, signature: "\"resolves_to\": { \"stable\" | \"qualified\" | \"workspace_declaration\" | \"active_semantic_model\": \"identity\" }", description: "Select one stable identity, qualified locator, or resolved typed identity." }
    CallProof { label: "call_proof", shape: CallProof, signature: "\"call_proof\": \"exact\" | \"declared\"", description: "Require exact selector proof or a complete declared semantic-model callable." }
    FindingProof { label: "finding_proof", shape: AbsentMemberProof, signature: "\"finding_proof\": \"proven\" | \"conditional\" | \"any\"", description: "Select absent-member findings by proof tier. proven (the default) keeps findings on a fully known receiver set with no remainder. conditional keeps a class that certainly reaches the access and lacks the member while other receiver values may remain unclassified; it also permits a listed global write only when every matching write has no receiver bound and an Any member-name set. A DeclaredParameter origin is conditional only when its annotation names one workspace class with no workspace subclass, unresolved or unmodeled external base, or attribute hook such as __getattr__, __getattribute__, or __setattr__; the condition states the annotated type and closed workspace hierarchy. any keeps both tiers." }
    ReceiverType { label: "receiver_type", shape: ReceiverTypeConstraint, signature: "\"receiver_type\": call identity | { \"assignable_to\": call identity, \"resolved_identities\": [\"stable-id\", ...] }", description: "Require one exact receiver-type identity or the inclusive workspace family rooted at one type." }
    FormalName { label: "formal_name", shape: ParameterName, signature: "\"formal_name\": \"name\"", description: "Select one exact declared formal name." }
    FormalIndex { label: "formal_index", shape: NonNegativeInteger, signature: "\"formal_index\": non-negative integer", description: "Select one zero-based formal index." }
    RowWhere { label: "where", shape: RowPredicates, signature: "\"where\": [{ \"field\": FIELD, \"op\": OP, ... }]", description: "State a bounded conjunction of typed predicates over this step's input row." }
    Columns { label: "columns", shape: RowProjectionColumns, signature: "\"columns\": [{ \"source\": FIELD, \"name\": NEW_FIELD }, ...]", description: "Select and optionally rename public input-row fields." }
    ProgramPointId { label: "id", shape: String, signature: "\"id\": \"public-program-point-id\"", description: "Select one exact public program-point identity." }
}

impl QueryStepField {
    /// The public JSON name for a step field.
    ///
    /// `kind` is already owned by the binding step in the shared field
    /// registry. C++ facts use the same JSON key in a different typed step,
    /// so the registry identity stays unique while this contextual name
    /// remains stable on the wire.
    pub fn json_label(self) -> &'static str {
        match self {
            Self::CppFactKind => "kind",
            _ => self.label(),
        }
    }
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

json_fields! {
    ConfigurationFactsFilterField,
    ALL_CONFIGURATION_FACTS_FILTER_FIELDS,
    Formats { label: "formats", shape: ConfigurationFormatList, signature: "\"formats\": [\"json\", ...]", description: "Restrict facts to one or more structured configuration formats." }
    NodeKinds { label: "node_kinds", shape: ConfigurationNodeKindList, signature: "\"node_kinds\": [\"member\", ...]", description: "Restrict facts to one or more configuration node kinds." }
    Roles { label: "roles", shape: ConfigurationRoleList, signature: "\"roles\": [\"object-member\", ...]", description: "Restrict member facts to one or more configuration roles." }
    ScalarKinds { label: "scalar_kinds", shape: ConfigurationScalarKindList, signature: "\"scalar_kinds\": [\"string\", ...]", description: "Restrict scalar facts to one or more scalar kinds." }
    Keys { label: "keys", shape: ConfigurationKeyList, signature: "\"keys\": [\"host\", ...]", description: "Restrict facts to one or more exact configuration keys." }
    Values { label: "values", shape: StringList, signature: "\"values\": [\"true\", ...]", description: "Restrict scalar-bearing facts to one or more exact decoded XML scalar values." }
    ValuesIgnoreCase { label: "values_ignore_case", shape: StringList, signature: "\"values_ignore_case\": [\"true\", ...]", description: "Restrict scalar-bearing facts to one or more decoded XML scalar values using case-insensitive equality." }
    ValueLt { label: "value_lt", shape: String, signature: "\"value_lt\": \"number\"", description: "Restrict scalar-bearing facts to finite numeric values less than the bound." }
    ValueLe { label: "value_le", shape: String, signature: "\"value_le\": \"number\"", description: "Restrict scalar-bearing facts to finite numeric values less than or equal to the bound." }
    ValueGt { label: "value_gt", shape: String, signature: "\"value_gt\": \"number\"", description: "Restrict scalar-bearing facts to finite numeric values greater than the bound." }
    ValueGe { label: "value_ge", shape: String, signature: "\"value_ge\": \"number\"", description: "Restrict scalar-bearing facts to finite numeric values greater than or equal to the bound." }
    XmlParentKeys { label: "xml_parent_keys", shape: StringList, signature: "\"xml_parent_keys\": [\"EditText\", ...]", description: "Restrict XML facts to those enclosed by an element with one of these exact names." }
    XmlPrecedingSiblingKeys { label: "xml_preceding_sibling_keys", shape: StringList, signature: "\"xml_preceding_sibling_keys\": [\"bean\", ...]", description: "Restrict XML facts to those with a preceding element sibling with one of these exact names." }
    XmlSiblingAttributeKeys { label: "xml_sibling_attribute_keys", shape: StringList, signature: "\"xml_sibling_attribute_keys\": [\"android:id\", ...]", description: "Restrict XML facts to those whose containing element has a sibling attribute with one of these exact names." }
    XmlSiblingAttributeValues { label: "xml_sibling_attribute_values", shape: StringList, signature: "\"xml_sibling_attribute_values\": [\"@+id/password\", ...]", description: "Restrict XML facts to those whose required sibling attribute has one of these exact decoded values." }
    XmlSiblingAttributeValuesIgnoreCase { label: "xml_sibling_attribute_values_ignore_case", shape: StringList, signature: "\"xml_sibling_attribute_values_ignore_case\": [\"true\", ...]", description: "Restrict XML facts to those whose required sibling attribute has one of these case-insensitive decoded values." }
    XmlReferenceSourceKeys { label: "xml_reference_source_keys", shape: StringList, signature: "\"xml_reference_source_keys\": [\"parent\", \"bean\", ...]", description: "Require same-document XML references whose source attribute key is one of these exact names." }
    XmlReferenceTargetKeys { label: "xml_reference_target_keys", shape: StringList, signature: "\"xml_reference_target_keys\": [\"id\", \"name\", ...]", description: "Identify same-document XML reference targets by one or more exact target attribute names." }
    XmlReferenceTargetElementKeys { label: "xml_reference_target_element_keys", shape: StringList, signature: "\"xml_reference_target_element_keys\": [\"bean\", ...]", description: "Restrict same-document XML reference targets to elements with one of these exact names." }
    XmlReferenceTargetChildKeys { label: "xml_reference_target_child_keys", shape: StringList, signature: "\"xml_reference_target_child_keys\": [\"property\", ...]", description: "Compare a selected XML child element with an equal child of its same-document reference target." }
    XmlPeerElementKeys { label: "xml_peer_element_keys", shape: StringList, signature: "\"xml_peer_element_keys\": [\"bean\", ...]", description: "Restrict the generic XML peer relation to elements with one of these exact names." }
    XmlPeerAttributeKeys { label: "xml_peer_attribute_keys", shape: StringList, signature: "\"xml_peer_attribute_keys\": [\"class\", ...]", description: "Require peer XML elements to share decoded values for these exact attribute names." }
    XmlPeerChildKeys { label: "xml_peer_child_keys", shape: StringList, signature: "\"xml_peer_child_keys\": [\"property\", ...]", description: "Compare these direct XML child element signatures between peer elements." }
    XmlPeerMinSharedChildren { label: "xml_peer_min_shared_children", shape: NonNegativeInteger, signature: "\"xml_peer_min_shared_children\": non-negative integer", description: "Require at least this many equal direct child signatures in the generic XML peer relation." }
    Routes { label: "routes", shape: ConfigurationRouteList, signature: "\"routes\": [[{ \"kind\": \"key\", \"key\": \"server\" }, ...], ...]", description: "Restrict facts to one or more exact-length ordered route alternatives; an empty route selects the document fact." }
    FactOrdinals { label: "fact_ordinals", shape: ConfigurationFactOrdinalList, signature: "\"fact_ordinals\": [0, ...]", description: "Select one or more zero-based fact occurrences, including duplicate-key occurrences." }
    Provenances { label: "provenances", shape: ConfigurationProvenanceList, signature: "\"provenances\": [\"authored\", ...]", description: "Restrict facts to one or more authored-value provenance classes." }
    Completenesses { label: "completenesses", shape: ConfigurationCompletenessList, signature: "\"completenesses\": [\"complete\", ...]", description: "Restrict facts to complete or recovered documents; recovery detail remains typed." }
}

json_fields! {
    CrossDomainField,
    ALL_CROSS_DOMAIN_FIELDS,
    Relation { label: "relation", shape: CrossDomainRelation, signature: "\"relation\": { \"configuration_key\": { \"documents\": [\"path\", ...] } }", description: "The registered structural relation that pairs evidence or retains an unmitigated dependency witness. Only correlate takes a relation." }
    Code { label: "code", shape: Query, signature: "\"code\": { query }", description: "The programming-code input query, or dependency_evidence input for dependency-configuration." }
    Configuration { label: "configuration", shape: Query, signature: "\"configuration\": { query }", description: "The configuration_fact input query." }
}

json_fields! {
    CrossDomainRelationField,
    ALL_CROSS_DOMAIN_RELATION_FIELDS,
    DependencyConfiguration { label: "dependency_configuration", shape: DependencyConfigurationRelation, signature: "\"dependency_configuration\": { \"owner\": \"topology-id\", \"ecosystem\": \"npm\", \"version_ranges\": [\"range\"], \"documents\": [\"path.properties\"], \"values\": [\"value\"], \"overrides\": [[\"lower\", \"higher\"]] }", description: "Prove a version-specific mitigation for an exactly owned dependency through explicit document applicability and acyclic precedence. Retain dependency witnesses when mitigation is not established." }
    ConfigurationKey { label: "configuration_key", shape: CorrelationDocumentList, signature: "\"configuration_key\": { \"documents\": [\"path\", ...] }", description: "Relate a plain string-literal argument bound to a resolver-proven callee to the .properties member whose single key segment equals it, inside an explicitly declared document." }
    ConfigurationCode { label: "configuration_code", shape: ConfigurationCodeRelation, signature: "\"configuration_code\": { \"match\": \"scalar-member\", \"absence\": true }", description: "Relate configuration scalar/document facts to code declarations or same-project code facts through a structured join. With absence true, emit only a complete configuration witness for which no complete code match exists." }
}

json_fields! {
    ConfigurationKeyRelationField,
    ALL_CONFIGURATION_KEY_RELATION_FIELDS,
    Documents { label: "documents", shape: CorrelationDocumentList, signature: "\"documents\": [\"src/main/resources/app.properties\", ...]", description: "Exact workspace-relative .properties document paths the binding reads. Globs, `.` and `..` segments, and undeclared documents never correlate." }
}

json_fields! {
    DependencyConfigurationRelationField,
    ALL_DEPENDENCY_CONFIGURATION_RELATION_FIELDS,
    Owner { label: "owner", shape: String, signature: "\"owner\": \"topology-id\"", description: "Exact nonempty declared_by topology identity of the consuming workspace package. Path proximity never establishes ownership." }
    Ecosystem { label: "ecosystem", shape: String, signature: "\"ecosystem\": \"npm\" | \"cargo\"", description: "Supported ecosystem for version-specific mitigation; exactly npm or cargo." }
    VersionRanges { label: "version_ranges", shape: StringList, signature: "\"version_ranges\": [\"range\", ...]", description: "One through 32 supported version ranges. Only complete locked or installed exact versions can satisfy them." }
    Documents { label: "documents", shape: CorrelationDocumentList, signature: "\"documents\": [\"app.properties\", ...]", description: "One through 32 exact workspace-relative .properties documents explicitly applicable to this owner." }
    Overrides { label: "overrides", shape: CorrelationOverrideList, signature: "\"overrides\": [[\"lower.properties\", \"higher.properties\"], ...]", description: "Up to 128 unique acyclic lower-to-higher precedence edges between declared documents. Omitted edges imply no precedence." }
    Values { label: "values", shape: StringList, signature: "\"values\": [\"true\", ...]", description: "One through 32 exact plain .properties scalar spellings that mitigate the selected dependency version. Escaped, continued, or interpolated values require supported binding evidence." }
}

json_fields! {
    ConfigurationCodeRelationField,
    ALL_CONFIGURATION_CODE_RELATION_FIELDS,
    Match { label: "match", shape: String, signature: "\"match\": \"scalar-declaration\" | \"scalar-owner\" | \"scalar-member\" | \"same-project\"", description: "Select the structured configuration-to-code join." }
    Absence { label: "absence", shape: Boolean, signature: "\"absence\": true | false", description: "Use a document-scoped anti-join. A negative row is emitted only when both the configuration document and code input are complete." }
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
const KEYED_READ_VALUE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::required(QueryStepField::Runtime, &[":runtime"]),
    QueryStepOption::required(QueryStepField::Global, &[":global"]),
    QueryStepOption::required(QueryStepField::Container, &[":container"]),
    QueryStepOption::optional(QueryStepField::Property, &[":property"]),
    QueryStepOption::optional(QueryStepField::Index, &[":index"]),
    QueryStepOption::optional(QueryStepField::KeyKind, &[":key-kind", ":key_kind"]),
    QueryStepOption::optional(QueryStepField::IndexMin, &[":index-min", ":index_min"]),
    QueryStepOption::optional(QueryStepField::IndexMax, &[":index-max", ":index_max"]),
    QueryStepOption::optional(
        QueryStepField::SourceOrigin,
        &[":source-origin", ":source_origin"],
    ),
];
const WITNESS_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(QueryStepField::MaxSteps, &[":max-steps"]),
    QueryStepOption::optional(QueryStepField::MaxBytes, &[":max-bytes"]),
];
const ABSENT_MEMBER_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::optional(
    QueryStepField::FindingProof,
    &[":proof"],
)];
const RESOLVED_CALL_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::required(
        QueryStepField::ResolvesTo,
        &[":resolves-to", ":resolves_to"],
    ),
    QueryStepOption::required(QueryStepField::CallProof, &[":proof"]),
    QueryStepOption::optional(
        QueryStepField::ReceiverType,
        &[":receiver-type", ":receiver_type"],
    ),
];
const RESOLVED_VALUE_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::required(
        QueryStepField::ResolvesTo,
        &[":resolves-to", ":resolves_to"],
    ),
    QueryStepOption::required(QueryStepField::CallProof, &[":proof"]),
];
const CALL_ARGUMENT_STEP_OPTIONS: &[QueryStepOption] = &[
    QueryStepOption::optional(
        QueryStepField::FormalName,
        &[":formal-name", ":formal_name"],
    ),
    QueryStepOption::optional(
        QueryStepField::FormalIndex,
        &[":formal-index", ":formal_index"],
    ),
];
const FILTER_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::RowWhere,
    &[":where"],
)];
const PROJECT_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::Columns,
    &[":columns"],
)];
const CAPTURE_ANCHOR_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::Capture,
    &[":capture"],
)];
const PROGRAM_POINT_BY_ID_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::ProgramPointId,
    &[":id"],
)];
const STATEMENT_FACTS_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::StatementFactKind,
    &[":kind"],
)];
const CPP_FACTS_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::required(
    QueryStepField::CppFactKind,
    &[":kind"],
)];
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

fn option_for_rql_label(options: &[QueryStepOption], label: &str) -> Option<QueryStepOption> {
    options
        .iter()
        .copied()
        .find(|option| option.accepts_rql_label(label))
}

pub fn occurrence_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    option_for_rql_label(OCCURRENCE_STEP_OPTIONS, label)
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
    QueryStepOption::optional(
        QueryStepField::DecoratorAnnotationType,
        &[":annotation-type", ":annotation_type"],
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
    QueryStepOption::optional(
        QueryStepField::StateEventReadCauses,
        &[":read-cause", ":read-causes"],
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

/// Options of the `branch-relations` step.
pub const BRANCH_RELATION_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::optional(
    QueryStepField::BranchRelations,
    &[":relation", ":relations"],
)];

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

pub const ASSIGNMENT_RELATION_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::optional(
    QueryStepField::AssignmentRelations,
    &[":relation", ":relations"],
)];

/// Options of the direct C/C++ provenance step.
pub const CPP_PROVENANCE_STEP_OPTIONS: &[QueryStepOption] = &[QueryStepOption::optional(
    QueryStepField::CppProvenance,
    &[":rule", ":rules"],
)];

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
    option_for_rql_label(DECLARATION_STATE_STEP_OPTIONS, label)
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

/// The RQL option spellings of the `configuration-facts` seed, mapped to its
/// own field registry.
pub fn configuration_facts_field_for_rql_label(
    label: &str,
) -> Option<ConfigurationFactsFilterField> {
    match label {
        ":format" | ":formats" => Some(ConfigurationFactsFilterField::Formats),
        ":node-kind" | ":node_kind" | ":node-kinds" | ":node_kinds" => {
            Some(ConfigurationFactsFilterField::NodeKinds)
        }
        ":role" | ":roles" => Some(ConfigurationFactsFilterField::Roles),
        ":scalar-kind" | ":scalar_kind" | ":scalar-kinds" | ":scalar_kinds" => {
            Some(ConfigurationFactsFilterField::ScalarKinds)
        }
        ":key" | ":keys" => Some(ConfigurationFactsFilterField::Keys),
        ":value" | ":values" => Some(ConfigurationFactsFilterField::Values),
        ":value-ignore-case"
        | ":value_ignore_case"
        | ":values-ignore-case"
        | ":values_ignore_case" => Some(ConfigurationFactsFilterField::ValuesIgnoreCase),
        ":value-lt" | ":value_lt" => Some(ConfigurationFactsFilterField::ValueLt),
        ":value-le" | ":value_le" => Some(ConfigurationFactsFilterField::ValueLe),
        ":value-gt" | ":value_gt" => Some(ConfigurationFactsFilterField::ValueGt),
        ":value-ge" | ":value_ge" => Some(ConfigurationFactsFilterField::ValueGe),
        ":xml-parent-key" | ":xml_parent_key" | ":xml-parent-keys" | ":xml_parent_keys" => {
            Some(ConfigurationFactsFilterField::XmlParentKeys)
        }
        ":xml-preceding-sibling-key"
        | ":xml_preceding_sibling_key"
        | ":xml-preceding-sibling-keys"
        | ":xml_preceding_sibling_keys" => {
            Some(ConfigurationFactsFilterField::XmlPrecedingSiblingKeys)
        }
        ":xml-sibling-attribute-key"
        | ":xml_sibling_attribute_key"
        | ":xml-sibling-attribute-keys"
        | ":xml_sibling_attribute_keys" => {
            Some(ConfigurationFactsFilterField::XmlSiblingAttributeKeys)
        }
        ":xml-sibling-attribute-value"
        | ":xml_sibling_attribute_value"
        | ":xml-sibling-attribute-values"
        | ":xml_sibling_attribute_values" => {
            Some(ConfigurationFactsFilterField::XmlSiblingAttributeValues)
        }
        ":xml-sibling-attribute-value-ignore-case"
        | ":xml_sibling_attribute_value_ignore_case"
        | ":xml-sibling-attribute-values-ignore-case"
        | ":xml_sibling_attribute_values_ignore_case" => {
            Some(ConfigurationFactsFilterField::XmlSiblingAttributeValuesIgnoreCase)
        }
        ":xml-reference-source-key"
        | ":xml_reference_source_key"
        | ":xml-reference-source-keys"
        | ":xml_reference_source_keys" => {
            Some(ConfigurationFactsFilterField::XmlReferenceSourceKeys)
        }
        ":xml-reference-target-key"
        | ":xml_reference_target_key"
        | ":xml-reference-target-keys"
        | ":xml_reference_target_keys" => {
            Some(ConfigurationFactsFilterField::XmlReferenceTargetKeys)
        }
        ":xml-reference-target-element-key"
        | ":xml_reference_target_element_key"
        | ":xml-reference-target-element-keys"
        | ":xml_reference_target_element_keys" => {
            Some(ConfigurationFactsFilterField::XmlReferenceTargetElementKeys)
        }
        ":xml-reference-target-child-key"
        | ":xml_reference_target_child_key"
        | ":xml-reference-target-child-keys"
        | ":xml_reference_target_child_keys" => {
            Some(ConfigurationFactsFilterField::XmlReferenceTargetChildKeys)
        }
        ":xml-peer-element-key"
        | ":xml_peer_element_key"
        | ":xml-peer-element-keys"
        | ":xml_peer_element_keys" => Some(ConfigurationFactsFilterField::XmlPeerElementKeys),
        ":xml-peer-attribute-key"
        | ":xml_peer_attribute_key"
        | ":xml-peer-attribute-keys"
        | ":xml_peer_attribute_keys" => Some(ConfigurationFactsFilterField::XmlPeerAttributeKeys),
        ":xml-peer-child-key"
        | ":xml_peer_child_key"
        | ":xml-peer-child-keys"
        | ":xml_peer_child_keys" => Some(ConfigurationFactsFilterField::XmlPeerChildKeys),
        ":xml-peer-min-shared-children" | ":xml_peer_min_shared_children" => {
            Some(ConfigurationFactsFilterField::XmlPeerMinSharedChildren)
        }
        ":route" | ":routes" => Some(ConfigurationFactsFilterField::Routes),
        ":fact-ordinal" | ":fact_ordinal" | ":fact-ordinals" | ":fact_ordinals" => {
            Some(ConfigurationFactsFilterField::FactOrdinals)
        }
        ":provenance" | ":provenances" => Some(ConfigurationFactsFilterField::Provenances),
        ":completeness" | ":completenesses" => Some(ConfigurationFactsFilterField::Completenesses),
        _ => None,
    }
}

/// The RQL option spellings of `correlate` and `require-both`.
pub fn cross_domain_field_for_rql_label(label: &str) -> Option<CrossDomainField> {
    match label {
        ":relation" => Some(CrossDomainField::Relation),
        ":code" => Some(CrossDomainField::Code),
        ":configuration" => Some(CrossDomainField::Configuration),
        _ => None,
    }
}

/// The RQL option spellings of the `configuration-key` relation.
pub fn configuration_key_relation_field_for_rql_label(
    label: &str,
) -> Option<ConfigurationKeyRelationField> {
    match label {
        ":documents" | ":document" => Some(ConfigurationKeyRelationField::Documents),
        _ => None,
    }
}

/// The RQL option spellings of the `configuration-code` relation.
pub fn configuration_code_relation_field_for_rql_label(
    label: &str,
) -> Option<ConfigurationCodeRelationField> {
    match label {
        ":match" => Some(ConfigurationCodeRelationField::Match),
        ":absence" => Some(ConfigurationCodeRelationField::Absence),
        _ => None,
    }
}

/// Accepted options of the dependency-configuration relation.
pub fn dependency_configuration_relation_field_for_rql_label(
    label: &str,
) -> Option<DependencyConfigurationRelationField> {
    match label {
        ":owner" => Some(DependencyConfigurationRelationField::Owner),
        ":ecosystem" => Some(DependencyConfigurationRelationField::Ecosystem),
        ":version-range" | ":version-ranges" | ":version_range" | ":version_ranges" => {
            Some(DependencyConfigurationRelationField::VersionRanges)
        }
        ":document" | ":documents" => Some(DependencyConfigurationRelationField::Documents),
        ":overrides" => Some(DependencyConfigurationRelationField::Overrides),
        ":value" | ":values" => Some(DependencyConfigurationRelationField::Values),
        _ => None,
    }
}

/// Canonical visible labels for the configuration member-role vocabulary.
pub fn configuration_member_role_label(role: ConfigurationMemberRole) -> &'static str {
    match role {
        ConfigurationMemberRole::ObjectMember => "object-member",
        ConfigurationMemberRole::TableEntry => "table-entry",
        ConfigurationMemberRole::Property => "property",
        ConfigurationMemberRole::XmlAttribute => "xml-attribute",
        ConfigurationMemberRole::XmlElement => "xml-element",
    }
}

pub fn configuration_member_role_from_label(label: &str) -> Option<ConfigurationMemberRole> {
    match label {
        "object_member" | "object-member" => Some(ConfigurationMemberRole::ObjectMember),
        "table_entry" | "table-entry" => Some(ConfigurationMemberRole::TableEntry),
        "property" => Some(ConfigurationMemberRole::Property),
        "xml_attribute" | "xml-attribute" => Some(ConfigurationMemberRole::XmlAttribute),
        "xml_element" | "xml-element" => Some(ConfigurationMemberRole::XmlElement),
        _ => None,
    }
}

pub fn configuration_scalar_kind_label(kind: ConfigurationScalarKind) -> &'static str {
    match kind {
        ConfigurationScalarKind::String => "string",
        ConfigurationScalarKind::Boolean => "boolean",
        ConfigurationScalarKind::Integer => "integer",
        ConfigurationScalarKind::Decimal => "decimal",
        ConfigurationScalarKind::Null => "null",
        ConfigurationScalarKind::Url => "url",
        ConfigurationScalarKind::Duration => "duration",
        ConfigurationScalarKind::Opaque => "opaque",
    }
}

pub fn configuration_scalar_kind_from_label(label: &str) -> Option<ConfigurationScalarKind> {
    match label {
        "string" => Some(ConfigurationScalarKind::String),
        "boolean" => Some(ConfigurationScalarKind::Boolean),
        "integer" => Some(ConfigurationScalarKind::Integer),
        "decimal" => Some(ConfigurationScalarKind::Decimal),
        "null" => Some(ConfigurationScalarKind::Null),
        "url" => Some(ConfigurationScalarKind::Url),
        "duration" => Some(ConfigurationScalarKind::Duration),
        "opaque" => Some(ConfigurationScalarKind::Opaque),
        _ => None,
    }
}

pub fn configuration_provenance_label(provenance: ConfigurationValueProvenance) -> &'static str {
    match provenance {
        ConfigurationValueProvenance::Authored => "authored",
    }
}

pub fn configuration_provenance_from_label(label: &str) -> Option<ConfigurationValueProvenance> {
    (label == "authored").then_some(ConfigurationValueProvenance::Authored)
}

pub fn binding_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    option_for_rql_label(BINDING_STEP_OPTIONS, label)
}

pub fn candidate_option_for_rql_label(label: &str) -> Option<QueryStepOption> {
    option_for_rql_label(CANDIDATE_STEP_OPTIONS, label)
}

impl QueryStepOp {
    pub const fn options(self) -> &'static [QueryStepOption] {
        match self {
            Self::Filter => FILTER_STEP_OPTIONS,
            Self::Project => PROJECT_STEP_OPTIONS,
            Self::CaptureAnchor => CAPTURE_ANCHOR_STEP_OPTIONS,
            Self::ProgramPointById => PROGRAM_POINT_BY_ID_STEP_OPTIONS,
            Self::StatementFacts => STATEMENT_FACTS_STEP_OPTIONS,
            Self::CppFacts => CPP_FACTS_STEP_OPTIONS,
            Self::Typestate => TYPESTATE_STEP_OPTIONS,
            Self::ValueFlow => VALUE_FLOW_STEP_OPTIONS,
            Self::Taint => TAINT_STEP_OPTIONS,
            Self::JsxAttributeValue => JSX_ATTRIBUTE_VALUE_STEP_OPTIONS,
            Self::FieldWriteValue => FIELD_WRITE_VALUE_STEP_OPTIONS,
            Self::KeyedReadValue => KEYED_READ_VALUE_STEP_OPTIONS,
            Self::Witness => WITNESS_STEP_OPTIONS,
            Self::ResolvedCall => RESOLVED_CALL_STEP_OPTIONS,
            Self::ResolvedValue => RESOLVED_VALUE_STEP_OPTIONS,
            Self::CallArgument => CALL_ARGUMENT_STEP_OPTIONS,
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
            Self::AssignmentRelations => ASSIGNMENT_RELATION_STEP_OPTIONS,
            Self::BranchRelations => BRANCH_RELATION_STEP_OPTIONS,
            Self::CppProvenance => CPP_PROVENANCE_STEP_OPTIONS,
            Self::RewritePathsOf => REWRITE_PATH_STEP_OPTIONS,
            Self::AbsentMember => ABSENT_MEMBER_STEP_OPTIONS,
            _ => &[],
        }
    }

    pub fn option_for_rql_label(self, label: &str) -> Option<QueryStepOption> {
        option_for_rql_label(self.options(), label)
    }
}

pub const ALL_REFERENCE_KINDS: &[ReferenceKind] = &[
    ReferenceKind::MethodCall,
    ReferenceKind::ConstructorCall,
    ReferenceKind::FieldRead,
    ReferenceKind::FieldWrite,
    ReferenceKind::TypeReference,
    ReferenceKind::SelfTypeAlias,
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
    "self_type_alias",
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
        ReferenceKind::SelfTypeAlias => "self_type_alias",
        ReferenceKind::StaticReference => "static_reference",
        ReferenceKind::SuperCall => "super_call",
        ReferenceKind::Inheritance => "inheritance",
    }
}

pub fn reference_kind_from_label(label: &str) -> Option<ReferenceKind> {
    find_by_label(
        ALL_REFERENCE_KINDS.iter().copied(),
        label,
        reference_kind_label,
    )
}

/// The `kind` axis of the generation-site seed, in canonical registry order.
pub fn generation_kind_labels() -> Vec<&'static str> {
    ALL_GENERATION_KINDS
        .iter()
        .map(|kind| kind.label())
        .collect()
}

/// The `input` axis of the generation-site seed, in canonical registry order.
pub fn generation_input_labels() -> Vec<&'static str> {
    ALL_GENERATION_INPUT_CLASSES
        .iter()
        .map(|input| input.label())
        .collect()
}

/// The `form` axis of the export seed, in canonical registry order. The `name`
/// axis is open and has no vocabulary.
pub fn export_form_labels() -> Vec<&'static str> {
    ALL_EXPORT_FORMS.iter().map(|form| form.label()).collect()
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
        QueryStepField::StateEventReadCauses => ALL_STATE_EVENT_READ_CAUSES
            .iter()
            .map(|cause| cause.label())
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
    if field == QueryStepField::StatementFactKind {
        return StatementFactKind::ALL
            .iter()
            .map(|kind| kind.label())
            .collect();
    }
    if field == QueryStepField::CppFactKind {
        return CppClassFactKind::ALL
            .iter()
            .map(|kind| kind.label())
            .collect();
    }
    if field == QueryStepField::KeyKind {
        return RuntimeKeyKind::ALL
            .iter()
            .map(|kind| kind.label())
            .collect();
    }
    if field == QueryStepField::FindingProof {
        return AbsentMemberProofFilter::ALL
            .iter()
            .map(|proof| proof.label())
            .collect();
    }
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
    if field == QueryStepField::AssignmentRelations {
        return [
            AssignmentRelationKind::SelfAssignment,
            AssignmentRelationKind::SelfInitializer,
            AssignmentRelationKind::FailedSwap,
            AssignmentRelationKind::OverwrittenUnread,
        ]
        .iter()
        .map(|kind| kind.label())
        .collect();
    }
    if field == QueryStepField::CppProvenance {
        return CppProvenanceRule::ALL
            .iter()
            .map(|rule| rule.label())
            .collect();
    }
    let branch = branch_relation_filter_labels(field);
    if !branch.is_empty() {
        return branch;
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

pub fn branch_relation_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    filter_field_labels(
        field,
        QueryStepField::BranchRelations,
        super::ir::BranchRelationKind::ALL,
        |kind| kind.label(),
    )
}

/// The constrained-value vocabulary each control-relation filter axis accepts,
/// in canonical registry order, so parser, validator, hover and completion all
/// read one table (#2443).
pub fn control_relation_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::ControlRelations => filter_field_labels(
            field,
            QueryStepField::ControlRelations,
            ALL_CONTROL_RELATION_KINDS,
            |relation| relation.label(),
        ),
        QueryStepField::ControlExitPartitions => filter_field_labels(
            field,
            QueryStepField::ControlExitPartitions,
            ALL_CONTROL_EXIT_PARTITIONS,
            |partition| partition.label(),
        ),
        _ => Vec::new(),
    }
}

fn filter_field_labels<T>(
    field: QueryStepField,
    expected: QueryStepField,
    values: &[T],
    label_for: impl Fn(&T) -> &'static str,
) -> Vec<&'static str> {
    if field == expected {
        values.iter().map(label_for).collect()
    } else {
        Vec::new()
    }
}

/// The constrained-value vocabulary each rewrite-path filter axis accepts, in
/// canonical registry order, so parser, validator, hover and completion all
/// read one table (#1480).
pub fn rewrite_path_filter_labels(field: QueryStepField) -> Vec<&'static str> {
    match field {
        QueryStepField::RewriteDomains => filter_field_labels(
            field,
            QueryStepField::RewriteDomains,
            ALL_REWRITE_DOMAIN_KINDS,
            |domain| domain.label(),
        ),
        QueryStepField::RewriteOutcomes => filter_field_labels(
            field,
            QueryStepField::RewriteOutcomes,
            ALL_REWRITE_OUTCOME_KINDS,
            |outcome| outcome.label(),
        ),
        _ => Vec::new(),
    }
}

pub fn usage_proof_label(proof: UsageProof) -> &'static str {
    match proof {
        UsageProof::Proven => "proven",
        UsageProof::Unproven => "unproven",
    }
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

const USAGE_HIT_SURFACE_LABELS: &[(UsageHitSurface, &str)] = &[
    (UsageHitSurface::ExternalUsages, "external_usages"),
    (UsageHitSurface::LspReferences, "lsp_references"),
];

pub fn usage_surface_label(surface: UsageHitSurface) -> &'static str {
    USAGE_HIT_SURFACE_LABELS
        .iter()
        .find_map(|(candidate, label)| (*candidate == surface).then_some(*label))
        .expect("every usage hit surface has a registered RQL label")
}

pub fn usage_surface_from_label(label: &str) -> Option<UsageHitSurface> {
    USAGE_HIT_SURFACE_LABELS
        .iter()
        .find_map(|(surface, candidate)| (*candidate == label).then_some(*surface))
}

/// Every usage kind an edge filter can name, in wire-label order. The labels
/// are [`UsageHitKind::wire_label`]'s, so the query surface and the rendered
/// usage surface can never disagree about a spelling.
pub const ALL_USAGE_KINDS: &[UsageHitKind] = &[
    UsageHitKind::Reference,
    UsageHitKind::Import,
    UsageHitKind::Reexport,
    UsageHitKind::SelfReceiver,
    UsageHitKind::DeclaredReference,
    UsageHitKind::Definition,
    UsageHitKind::OverrideDeclaration,
];

pub fn usage_kind_from_label(label: &str) -> Option<UsageHitKind> {
    find_by_label(
        ALL_USAGE_KINDS.iter().copied(),
        label,
        UsageHitKind::wire_label,
    )
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
    UnsafeContext { label: "unsafe_context", shape: Boolean, signature: "\"unsafe_context\": true | false", description: "Match Rust calls inside unsafe blocks or unsafe functions; unsupported on non-call patterns and other languages." }
    Async { label: "async", shape: Boolean, signature: "\"async\": true | false", description: "Match a callable by its AST-backed async modifier." }
    TypeKind { label: "type_kind", shape: String, signature: "\"type_kind\": \"class\" | \"interface\" | \"enum\" | \"record\" | \"annotation\"", description: "Match the persisted source form of a type declaration." }
    Modifier { label: "modifier", shape: String, signature: "\"modifier\": static|abstract|final|volatile|synchronized|transient|native|strictfp|default|sealed|non-sealed|public|protected|private", description: "Match a declaration by a modifier read from its structured modifier nodes." }
    StringValue { label: "string_value", shape: StringPredicate, signature: "\"string_value\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match a normalized string literal by its decoded value." }
    Text { label: "text", shape: RegexPredicate, signature: "\"text\": { \"regex\": \"pattern\" }", description: "Match the node's source text with a regular expression." }
    CommentBlockText { label: "comment_block_text", shape: RegexPredicate, signature: "\"comment_block_text\": { \"regex\": \"pattern\" }", description: "Match a comment using the source text of its maximal consecutive comment block." }
    BooleanValue { label: "boolean_value", shape: Boolean, signature: "\"boolean_value\": true | false", description: "Match a boolean literal by its normalized language-neutral value." }
    DuplicateKey { label: "duplicate_key", shape: Boolean, signature: "\"duplicate_key\": true | false", description: "Match a Python dictionary entry by whether its decoded literal key repeats an earlier entry." }
    Parenthesized { label: "parenthesized", shape: Boolean, signature: "\"parenthesized\": true | false", description: "Match a string-literal expression by whether its syntax is parenthesized." }
    IntegerValue { label: "integer_value", shape: CanonicalIntegerDecimal, signature: "\"integer_value\": \"canonicalDecimal\"", description: "Match an integer literal's exact canonical decimal value without narrowing it." }
    IntegerHasAnyBits { label: "integer_has_any_bits", shape: PermissionBitMask, signature: "\"integer_has_any_bits\": positive u32 mask", description: "Match an integer literal with at least one requested low bit set." }
    IntegerHasAllBits { label: "integer_has_all_bits", shape: PermissionBitMask, signature: "\"integer_has_all_bits\": positive u32 mask", description: "Match an integer literal with every requested low bit set." }
    IntegerHasNoBits { label: "integer_has_no_bits", shape: PermissionBitMask, signature: "\"integer_has_no_bits\": positive u32 mask", description: "Match an integer literal with none of the requested low bits set." }
    AssignmentTargetKind { label: "assignment_target_kind", shape: AssignmentSequenceKind, signature: "\"assignment_target_kind\": \"list\" | \"tuple\"", description: "Match the direct target sequence kind of a tuple/list assignment." }
    AssignmentValueKind { label: "assignment_value_kind", shape: AssignmentSequenceKind, signature: "\"assignment_value_kind\": \"list\" | \"tuple\"", description: "Match the direct value sequence kind of a tuple/list assignment." }
    AssignmentTargetUnstarredCount { label: "assignment_target_unstarred_count", shape: NonNegativeInteger, signature: "\"assignment_target_unstarred_count\": non-negative integer", description: "Match the number of non-starred direct target elements in a tuple/list assignment." }
    AssignmentValueUnstarredCount { label: "assignment_value_unstarred_count", shape: NonNegativeInteger, signature: "\"assignment_value_unstarred_count\": non-negative integer", description: "Match the number of non-starred direct value elements in a tuple/list assignment." }
    AssignmentTargetStarred { label: "assignment_target_starred", shape: Boolean, signature: "\"assignment_target_starred\": true | false", description: "Match whether the direct target sequence has a starred element." }
    AssignmentValueStarred { label: "assignment_value_starred", shape: Boolean, signature: "\"assignment_value_starred\": true | false", description: "Match whether the direct value sequence has a starred element." }
    AssignmentUnstarredCountMismatch { label: "assignment_unstarred_count_mismatch", shape: Boolean, signature: "\"assignment_unstarred_count_mismatch\": true | false", description: "Match whether the two direct sequence sides have different unstarred element counts." }
    Index { label: "index", shape: NonNegativeInteger, signature: "\"index\": non-negative integer", description: "Match a child at this exact zero-based position in its parent's ordered list role, such as elements." }
    Capture { label: "capture", shape: String, signature: "\"capture\": \"label\"", description: "Capture the matching node under a result label." }
    Arity { label: "arity", shape: Arity, signature: "\"arity\": count | { \"min\": count, \"max\": count }", description: "Match a call by its positional argument count, or a collection literal by its element count: an exact count, or inclusive min/max bounds." }
    Visibility { label: "visibility", shape: DeclaredVisibilityList, signature: "\"visibility\": \"public\" | [\"public\", \"protected\", ...]", description: "Match a callable declaration by the visibility its adapter recorded from modifiers." }
    ParameterType { label: "parameter_type", shape: StringPredicate, signature: "\"parameter_type\": \"exact\" | { \"regex\": \"pattern\" }", description: "Match a callable that has a parameter whose recorded type spelling satisfies this predicate. The spelling is a discriminator, not a resolved type identity." }
    Has { label: "has", shape: Pattern, signature: "\"has\": { pattern }", description: "Require a matching descendant." }
    NotHas { label: "not_has", shape: Pattern, signature: "\"not_has\": { pattern }", description: "Exclude nodes containing a matching descendant." }
    Not { label: "not", shape: Pattern, signature: "\"not\": { pattern }", description: "Exclude nodes matching the nested pattern." }
    All { label: "all", shape: PatternList, signature: "\"all\": [{ pattern }, ...]", description: "Require every nested pattern to match the same node." }
    Any { label: "any", shape: PatternList, signature: "\"any\": [{ pattern }, ...]", description: "Require at least one nested pattern to match the same node." }
    LocalValue { label: "local_value", shape: Pattern, signature: "\"local_value\": { pattern }", description: "Match the unique direct function-local assignment value guaranteed before this read by unconditional or earlier same-suite execution." }
    LanguageRule { label: "language_rule", shape: String, signature: "\"language_rule\": \"cpp/rule\" | \"cs/rule\" | \"java/rule\" | \"js/rule\"", description: "Apply one closed relation from the language-rule registry to the root structural seed; the id prefix selects its language." }
    BodyState { label: "body_state", shape: String, signature: "\"body_state\": \"empty\" | \"comment-only\" | \"code\"", description: "Match the structured state of a directly-owned branch or loop block." }
    BodyOwner { label: "body_owner", shape: String, signature: "\"body_owner\": \"if-consequence\" | \"if-alternative\" | \"loop-body\"", description: "Restrict a body-state match to its structured if or loop owner role." }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::HashSet;

    /// The `reference_kind` row fields publish this list as their value
    /// domain, so it must stay the exact image of `reference_kind_label` over
    /// the registry (issue #2515).
    #[test]
    #[hardwon(
        "#2515: The #2515 fix added value domains for enum predicates; this pins labels to the producer registry."
    )]
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

json_fields! {
 DependencyEvidenceFilterField,
 ALL_DEPENDENCY_EVIDENCE_FILTER_FIELDS,
 Ecosystems { label: "ecosystems", shape: StringList, signature: "\"ecosystems\": [\"...\"]", description: "Package ecosystem, currently cargo." }
 Packages { label: "packages", shape: StringList, signature: "\"packages\": [\"...\"]", description: "Exact package identities, independent of dependency aliases." }
 Kinds { label: "kinds", shape: StringList, signature: "\"kinds\": [\"...\"]", description: "declared, constraint, locked, installed or checksum file evidence." }
 ExactVersions { label: "exact_versions", shape: StringList, signature: "\"exact_versions\": [\"...\"]", description: "Exact recorded versions; declarations never supply an exact version." }
 VersionRanges { label: "version_ranges", shape: StringList, signature: "\"version_ranges\": [\"...\"]", description: "Version requirements matched against exact evidence using Cargo or npm semantics; requires exactly one supported ecosystem axis." }
 Sources { label: "sources", shape: StringList, signature: "\"sources\": [\"...\"]", description: "Exact source identities, including registry URL or git revision." }
 DeclaredBy { label: "declared_by", shape: StringList, signature: "\"declared_by\": [\"...\"]", description: "Established owning BuildProject IDs; lock co-occurrence never creates ownership." }
 Scopes { label: "scopes", shape: StringList, signature: "\"scopes\": [\"...\"]", description: "Recorded compile, test, unknown or other dependency scope, without enabled configuration inference." }
}
pub fn dependency_evidence_field_for_rql_label(
    label: &str,
) -> Option<DependencyEvidenceFilterField> {
    match label {
        ":ecosystem" | ":ecosystems" => Some(DependencyEvidenceFilterField::Ecosystems),
        ":package" | ":packages" => Some(DependencyEvidenceFilterField::Packages),
        ":kind" | ":kinds" => Some(DependencyEvidenceFilterField::Kinds),
        ":exact-version" | ":exact_versions" => Some(DependencyEvidenceFilterField::ExactVersions),
        ":version-range" | ":version_ranges" => Some(DependencyEvidenceFilterField::VersionRanges),
        ":source" | ":sources" => Some(DependencyEvidenceFilterField::Sources),
        ":declared-by" | ":declared_by" => Some(DependencyEvidenceFilterField::DeclaredBy),
        ":scope" | ":scopes" => Some(DependencyEvidenceFilterField::Scopes),
        _ => None,
    }
}

/// Source forms accepted by the declaration type-kind property.
pub(crate) const DECLARATION_TYPE_KINDS: &[&str] =
    &["class", "interface", "enum", "record", "annotation"];

#[cfg(test)]
mod authoring_tests;
