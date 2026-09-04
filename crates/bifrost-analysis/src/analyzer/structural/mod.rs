//! Normalized structural search (`query_code`, issue #328).
//!
//! Layering, language-independent unless noted:
//! - [`adapter_helpers`]: small shared mechanics for language adapters.
//! - `capabilities`: query feature requirements and capability diagnostics.
//! - [`kinds`]: the normalized node vocabulary with its subtype hierarchy,
//!   and the role-edge vocabulary.
//! - [`query`]: the canonical typed query IR and its JSON frontend.
//! - [`facts`]: the per-file fact arena the matcher runs over.
//! - [`spec`]: the per-language boundary — kind tables and AST-field role
//!   extraction (implementations live next to each language's analyzer,
//!   e.g. `src/analyzer/python/structural.rs`).
//! - [`extract`]: parse + normalize one file through a spec.
//! - [`matcher`]: pattern evaluation with captures and containment.
//! - [`occurrence_rows`]: per-file occurrence rows derived from the arena's
//!   occurrence roles plus definition resolution (issue #1473).
//! - [`lexical_environment`]: per-file scope, binding, import-binder and
//!   package rows, plus the binding-of algorithm over them (issue #1474).
//! - [`qualified_paths`]: per-file qualified-path and path-segment rows with
//!   opt-in per-segment prefix resolution (issue #1475).
//! - `flow_state`: per-procedure binding/property state events and the
//!   flow relations over the production CFG -- reaching definitions,
//!   dominance and same-evaluation (issue #1480).
//! - [`identity_routes`]: canonical identity projection, physical grouping,
//!   per-file route relation rows and the bounded route traversal (#1475).
//! - [`planner`]: positive-anchor candidate pruning (negation never prunes).
//! - [`provider`]: the capability trait analyzers expose, plus the
//!   source-hash-validated facts cache behind it.
//! - [`search`]: parallel workspace execution and the tool-facing output.
//!
//! See `.agents/plans/ISSUE_328_SEARCH_AST_EXECPLAN.md` for the original plan
//! and `.agents/plans/issue-449-query-code-reference.md` for the public rename.

pub(crate) mod adapter_helpers;
pub mod derived_cache;
pub mod extract;
pub mod facts;
pub mod identity_routes;
pub mod index;
pub mod index_query;
pub mod lexical_environment;
pub mod materialization_rows;
pub mod occurrence_rows;
pub mod provider;
pub mod qualified_paths;
pub mod reference_edges;
pub mod rewrite_paths;

// The normalized kind/role registry and the spec trait a language implements
// live in `brokk-bifrost-core`, below every grammar; only the engine that
// consumes them stays here. `adapter_helpers` is split rather than moved: its
// production mechanics went to core, its test assertions stayed (see that
// module).
pub use brokk_bifrost_core::analyzer::structural::{
    edges, kinds, materialization, occurrences, resolution, rewrite_path, routes, spec,
};

pub use edges::{
    ALL_EDGE_AXES, ALL_EDGE_PROVENANCES, ALL_OWNER_RELATIONS, ALL_SITE_CLASSES,
    DEEP_REFERENCE_EDGE_SUPPORT, EdgeAxis, EdgeProvenance, EdgeSupport,
    INVERSE_REFERENCE_EDGE_SUPPORT, NO_REFERENCE_EDGE_SUPPORT, OwnerRelation, ReferenceEdgeSupport,
    SiteClass,
};
pub use facts::{FileFacts, NormalizedNode, RoleTarget, Span};
pub use identity_routes::{
    IDENTITY_PRESERVING_HOPS, IDENTITY_ROUTE_PRODUCER_AXES, IdentityRoute, MAX_ROUTE_DEPTH,
    MAX_ROUTE_FAN_OUT, PhysicalOccurrence, RoundTripOutcome, RouteEndpoint, RouteProvenance,
    RouteRelationCompleteness, RouteRelationIncompleteReason, RouteRelationRow,
    RouteRelationsFileResult, RoutesCancelled, canonical_identity_of,
    file_supplies_route_relations, identity_routes_from, physical_occurrences,
    round_trip_from_site, route_relations_for_file,
};
pub use kinds::{ALL_KINDS, NormalizedKind, Role};
pub use lexical_environment::{
    BindingOfOutcome, BindingRow, ENVIRONMENT_PRODUCER_AXES, EnvironmentCompleteness,
    EnvironmentFileResult, EnvironmentIncompleteReason, ImportBinderDetail, PackageClauseRow,
    ScopeAnchor, ScopeRow, WILDCARD_IMPORT_NAME, binding_of, environment_for_file,
};
pub use materialization::{
    ALL_DECLARATION_ORIGINS, ALL_EXPORT_FORMS, ALL_GENERATION_INPUT_CLASSES, ALL_GENERATION_KINDS,
    ALL_MATERIALIZATION_AXES, CPP_MATERIALIZATION_SUPPORT, DeclarationMaterializationSupport,
    DeclarationOrigin, ExportForm, GenerationInputClass, GenerationKind,
    JS_TS_MATERIALIZATION_SUPPORT, MaterializationAxis, MaterializationSupport,
    NO_MATERIALIZATION_SUPPORT, PYTHON_MATERIALIZATION_SUPPORT, RUBY_MATERIALIZATION_SUPPORT,
};
pub use materialization_rows::{
    DeclarationStateRow, ExportRow, GenerationSiteRow, ImplementationLinkRow,
    MATERIALIZATION_PRODUCER_AXES, MaterializationCompleteness, MaterializationFileResult,
    MaterializationIncompleteReason, materialization_for_file,
};
pub use occurrence_rows::{
    OccurrenceCompleteness, OccurrenceDerivationOptions, OccurrenceFileResult,
    OccurrenceIncompleteReason, OccurrenceRow, OccurrenceTarget, OccurrencesCancelled,
    occurrences_for_file, occurrences_for_file_with_options,
    occurrences_for_file_with_options_roles_and_ast_ids,
};
pub use occurrences::{
    ALL_OCCURRENCE_ROLES, NO_OCCURRENCE_ROLE_SUPPORT, Namespace, OccurrenceClass, OccurrenceRole,
    OccurrenceRoleSupport, OccurrenceSupport, default_occurrence_namespace,
};
pub use provider::{StructuralFactProvider, StructuralFactSnapshotCache, StructuralFactsCache};
pub use qualified_paths::{
    PathSegmentRow, QUALIFIED_PATH_PRODUCER_AXES, QualifiedPathCompleteness,
    QualifiedPathDerivationOptions, QualifiedPathIncompleteReason, QualifiedPathRow,
    QualifiedPathsCancelled, QualifiedPathsFileResult, SegmentPrefixResolution,
    qualified_paths_for_file,
};
pub use resolution::{
    ALL_BINDING_KINDS, ALL_BOUNDARY_STATUSES, ALL_DECLARED_VISIBILITIES, ALL_ENVIRONMENT_AXES,
    ALL_HIERARCHY_RELATIONS, ALL_HOISTING_CLASSES, ALL_MEMBER_DISPATCH_TIERS, ALL_PRECEDENCE_TIERS,
    ALL_REJECTION_REASONS, BindingActivation, BindingKind, BoundaryStatus,
    CALLABLE_APPLICABILITY_ONLY_SUPPORT, CandidateOutcome, DEEP_LEXICAL_ENVIRONMENT_SUPPORT,
    DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_CALLABLE_APPLICABILITY,
    DEEP_LEXICAL_ENVIRONMENT_SUPPORT_WITH_REJECTIONS, DeclaredVisibility, EnvironmentAxis,
    EnvironmentSupport, HierarchyRelation, HoistingClass, LexicalEnvironmentSupport,
    MemberDispatchTier, NO_LEXICAL_ENVIRONMENT_SUPPORT, PrecedenceTier, RejectionReason,
};
pub use routes::{
    ALL_CANONICAL_SEGMENT_KINDS, ALL_IDENTITY_AXES, ALL_ROUTE_HOP_KINDS, ALL_ROUTE_TERMINATIONS,
    ALL_SEGMENT_RESOLUTION_STATUSES, CanonicalIdentity, CanonicalSegment, CanonicalSegmentKind,
    CuratedExportSurface, DEEP_IDENTITY_AXES, IdentityAxis, IdentityRouteSupport, IdentitySupport,
    NO_IDENTITY_ROUTE_SUPPORT, RouteHopKind, RouteTermination, SegmentResolutionStatus,
};
pub use spec::{RoleSink, StructuralSpec};
