use super::schema::{CallTraversalCompleteness, CodeQueryExecutionMode, QueryStepOp};
use crate::refs::{ProtocolRef, TaintResultRef, ValueFlowPlanRef};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::control_relation::{
    ControlExitPartition, ControlRelationKind,
};
use brokk_bifrost_core::analyzer::structural::edges::{OwnerRelation, SiteClass};
use brokk_bifrost_core::analyzer::structural::flow_state::{
    FlowCertainty, FlowRelation as FlowRelationLabel, FlowSubjectKind, StateEventClass,
};
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::materialization::{
    DeclarationOrigin, ExportForm, GenerationInputClass, GenerationKind,
};
use brokk_bifrost_core::analyzer::structural::occurrences::{
    ALL_OCCURRENCE_ROLES, Namespace, OccurrenceClass, OccurrenceRole,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BindingKind, BoundaryStatus, CandidateOutcome, DeclaredVisibility, HoistingClass,
    PrecedenceTier, RejectionReason,
};
use brokk_bifrost_core::analyzer::structural::rewrite_path::{
    RewriteDomainKind, RewriteOutcomeKind,
};
use brokk_bifrost_core::analyzer::usages::model::{
    ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof,
};
use regex::Regex;
use std::fmt;
use std::num::NonZeroUsize;

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
pub const MAX_WHERE_GLOBS: usize = 128;
pub const MAX_GLOB_LENGTH: usize = 1024;
pub const MAX_LANGUAGE_FILTERS: usize = 32;
pub const MAX_PATTERN_DEPTH: usize = 64;
pub const MAX_PATTERN_NODES: usize = 256;
pub const MAX_KIND_LIST_ENTRIES: usize = 32;
pub const MAX_ROLE_LIST_ENTRIES: usize = 64;
pub const MAX_KWARGS: usize = 64;
pub const MAX_STRING_PREDICATE_LENGTH: usize = 4096;
pub const MAX_CAPTURE_LENGTH: usize = 128;
pub const MAX_KWARG_NAME_LENGTH: usize = 128;
pub const MAX_QUERY_STEPS: usize = 16;
pub const MAX_QUERY_BRANCHES: usize = 16;
pub const MAX_QUERY_PLAN_DEPTH: usize = 16;
pub const MAX_QUERY_PLAN_NODES: usize = 64;
/// Upper bound on entries in one occurrence-seed constrained-value filter.
pub const MAX_OCCURRENCE_FILTER_ENTRIES: usize = 32;
/// Upper bound on entries in one lexical-environment constrained-value filter.
/// Shared by the scope, binding and candidate filters for the same reason the
/// occurrence bound exists: a filter is an author's enumeration, not a data set.
pub const MAX_ENVIRONMENT_FILTER_ENTRIES: usize = 32;
/// Upper bound on the length of one `:name` entry of a binding filter.
pub const MAX_BINDING_NAME_LENGTH: usize = 256;
/// Upper bound on one exact decorator-binding identity filter value.
pub const MAX_DECORATOR_BINDING_FILTER_LENGTH: usize = 4096;
/// The single supported CodeQuery/RQL schema version. The pre-1.0 lineage of
/// auto-compatible versions was collapsed to 1; a new version is minted only
/// when an existing query stops parsing or changes meaning.
///
/// A breaking rename made before RQL has any consumer outside this repository
/// does not mint a version either. Instead the renaming change migrates every
/// query written inside the repository -- policy packs, executable docs, test
/// fixtures, the MCP and Python surfaces, the editor grammar -- in the same
/// commit, so no reader is left holding an old spelling. Issue #1480 renamed
/// the lexical `reaching-binding` step to `binding-of` and the `assert-reaching`
/// policy family to `assert-binding-scope` under exactly this rule. Mint a
/// version once an out-of-repository consumer exists.
pub const SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryValueKind {
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
    ReferenceSite,
    CallSite,
    ExpressionSite,
    /// The exact normalized operand selected from a JSX attribute value.
    ///
    /// This is deliberately distinct from [`StructuralMatch`]: the terminal
    /// source range is the expression operand, not the enclosing attribute,
    /// which lets policy adapters use the row as a sink subject.
    JsxAttributeValue,
    ReceiverAnalysis,
    ReceiverOutcome,
    ReceiverEvidence,
    CallShape,
    CallArgumentGroup,
    CallArgument,
    CallBinding,
    CallEffect,
    ProcedureEffect,
    CallableSignature,
    SignatureParameter,
    DecoratedParameter,
    CallableApplicability,
    OverloadSelection,
    MemberSelection,
    DispatchOutcome,
    DispatchTarget,
    MemberFamily,
    MemberFamilyEdge,
    Occurrence,
    LexicalScope,
    Binding,
    ResolutionCandidate,
    CandidateHop,
    ReferenceEdge,
    StateEvent,
    FlowRelation,
    ControlRelation,
    Guard,
    SourceSet,
    BuildTarget,
    TopologyEdge,
    RewritePath,
    QualifiedPath,
    PathSegment,
    GenerationSite,
    Export,
    DeclarationState,
    File,
}

impl QueryValueKind {
    pub fn label(self) -> &'static str {
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
            Self::ReferenceSite => "reference_site",
            Self::CallSite => "call_site",
            Self::ExpressionSite => "expression_site",
            Self::JsxAttributeValue => "jsx_attribute_value",
            Self::ReceiverAnalysis => "receiver_analysis",
            Self::ReceiverOutcome => "receiver_outcome",
            Self::ReceiverEvidence => "receiver_evidence",
            Self::CallShape => "call_shape",
            Self::CallArgumentGroup => "call_argument_group",
            Self::CallArgument => "call_argument",
            Self::CallBinding => "call_binding",
            Self::CallEffect => "call_effect",
            Self::ProcedureEffect => "procedure_effect",
            Self::CallableSignature => "callable_signature",
            Self::SignatureParameter => "signature_parameter",
            Self::DecoratedParameter => "decorated_parameter",
            Self::CallableApplicability => "callable_applicability",
            Self::OverloadSelection => "overload_selection",
            Self::MemberSelection => "member_selection",
            Self::DispatchOutcome => "dispatch_outcome",
            Self::DispatchTarget => "dispatch_target",
            Self::MemberFamily => "member_family",
            Self::MemberFamilyEdge => "member_family_edge",
            Self::Occurrence => "occurrence",
            Self::LexicalScope => "lexical_scope",
            Self::Binding => "binding",
            Self::ResolutionCandidate => "resolution_candidate",
            Self::CandidateHop => "candidate_hop",
            Self::ReferenceEdge => "reference_edge",
            Self::StateEvent => "state_event",
            Self::FlowRelation => "flow_relation",
            Self::ControlRelation => "control_relation",
            Self::Guard => "guard",
            Self::SourceSet => "source_set",
            Self::BuildTarget => "build_target",
            Self::TopologyEdge => "topology_edge",
            Self::RewritePath => "rewrite_path",
            Self::QualifiedPath => "qualified_path",
            Self::PathSegment => "path_segment",
            Self::GenerationSite => "generation_site",
            Self::Export => "export",
            Self::DeclarationState => "declaration_state",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReferenceTraversalFilter {
    pub reference_kinds: Vec<ReferenceKind>,
    pub proof: Option<UsageProof>,
    pub surface: UsageHitSurface,
}

/// Constrained-value filter over canonical reference-edge rows.
///
/// Unlike [`ReferenceTraversalFilter`], `surface` is optional with no default:
/// the canonical edge domain's complete answer includes editor-only rows
/// (imports, self receivers, definition sites), and silently defaulting to the
/// external-usages surface would make the parity comparison's ground set a
/// filtered one without the author saying so.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EdgeFilter {
    pub reference_kinds: Vec<ReferenceKind>,
    pub proof: Option<UsageProof>,
    pub surface: Option<UsageHitSurface>,
    pub usage_kinds: Vec<UsageHitKind>,
    pub relations: Vec<OwnerRelation>,
    pub site_classes: Vec<SiteClass>,
}

impl EdgeFilter {
    pub fn is_empty(&self) -> bool {
        self.reference_kinds.is_empty()
            && self.proof.is_none()
            && self.surface.is_none()
            && self.usage_kinds.is_empty()
            && self.relations.is_empty()
            && self.site_classes.is_empty()
    }
}

/// Constrained-value filter over flow-sensitive state-event rows (#1480).
///
/// Both axes are enumerations the author writes, so an empty axis means "every
/// value", never "no value". A filter never turns an incomplete derivation into
/// a complete one: the diagnostics the derivation reports are emitted whether or
/// not a filter drops the row that would have carried them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateEventFilter {
    pub classes: Vec<StateEventClass>,
    pub subjects: Vec<FlowSubjectKind>,
}

impl StateEventFilter {
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.subjects.is_empty()
    }
}

/// Constrained-value filter over flow-relation rows (#1480).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlowRelationFilter {
    pub relations: Vec<FlowRelationLabel>,
    pub certainties: Vec<FlowCertainty>,
}

impl FlowRelationFilter {
    pub fn is_empty(&self) -> bool {
        self.relations.is_empty() && self.certainties.is_empty()
    }
}

/// Constrained-value filter over control-relation rows (#2443).
///
/// Both axes are enumerations the author writes, so an empty axis means "every
/// value", never "no value". A filter never turns an incomplete derivation into
/// a complete one: the diagnostics the derivation reports are emitted before any
/// filter runs, so a `:relation postdominates` filter that drops every row still
/// leaves the reason the row set is partial on the response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlRelationFilter {
    pub relations: Vec<ControlRelationKind>,
    pub exit_partitions: Vec<ControlExitPartition>,
}

impl ControlRelationFilter {
    pub fn is_empty(&self) -> bool {
        self.relations.is_empty() && self.exit_partitions.is_empty()
    }
}

/// Constrained-value filter over bounded rewrite-path rows (#1480).
///
/// Both axes are enumerations the author writes, so an empty axis means "every
/// value", never "no value". Filtering on `:outcome cycle` narrows the rows;
/// it never turns an incomplete derivation into a complete one, because the
/// derivation's diagnostics are emitted before any filter runs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RewritePathFilter {
    pub domains: Vec<RewriteDomainKind>,
    pub outcomes: Vec<RewriteOutcomeKind>,
}

impl RewritePathFilter {
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.outcomes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallTraversalFilter {
    pub depth: NonZeroUsize,
    pub proof: Option<UsageProof>,
    pub completeness: CallTraversalCompleteness,
}

impl Default for CallTraversalFilter {
    fn default() -> Self {
        Self {
            depth: NonZeroUsize::MIN,
            proof: None,
            completeness: CallTraversalCompleteness::Exhaustive,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallSiteTraversalFilter {
    pub proof: Option<UsageProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceiverTraversalFilter {
    pub capture: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsxElementIdentity {
    Intrinsic,
    Component,
    Unknown,
}

impl JsxElementIdentity {
    pub const ALL: [Self; 3] = [Self::Intrinsic, Self::Component, Self::Unknown];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Intrinsic => "intrinsic",
            Self::Component => "component",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "intrinsic" => Some(Self::Intrinsic),
            "component" => Some(Self::Component),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Filters for the typed JSX value projection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JsxAttributeValueTraversal {
    pub identity: Option<JsxElementIdentity>,
    pub element_name: Option<String>,
    pub property_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypestateTraversal {
    pub protocol_ref: ProtocolRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFlowTraversal {
    pub plan_ref: ValueFlowPlanRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTraversal {
    pub taint_ref: TaintResultRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WitnessTraversal {
    pub max_steps: Option<usize>,
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallInputSelector {
    Receiver,
    ParameterIndex(usize),
    ParameterName(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyTraversal {
    Direct,
    Depth(NonZeroUsize),
    Transitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStep {
    EnclosingDecl,
    ProcedureOf,
    CfgEntry,
    CfgExits,
    CfgSuccessorEdges,
    CfgPredecessorEdges,
    CfgEdgeSource,
    CfgEdgeTarget,
    Typestate(TypestateTraversal),
    ValueFlow(ValueFlowTraversal),
    Taint(TaintTraversal),
    Witness(WitnessTraversal),
    FileOf,
    ImportsOf,
    ImportersOf,
    Supertypes(HierarchyTraversal),
    Subtypes(HierarchyTraversal),
    Members,
    Owner,
    ReferencesOf(ReferenceTraversalFilter),
    UsedBy(ReferenceTraversalFilter),
    Uses(ReferenceTraversalFilter),
    Callers(CallTraversalFilter),
    Callees(CallTraversalFilter),
    CallSitesTo(CallSiteTraversalFilter),
    CallSitesFrom(CallSiteTraversalFilter),
    CallInput(CallInputSelector),
    JsxAttributeValue(JsxAttributeValueTraversal),
    ReceiverTargets(ReceiverTraversalFilter),
    PointsTo(ReceiverTraversalFilter),
    MemberTargets(ReceiverTraversalFilter),
    ReceiverOutcome,
    ReceiverEvidence,
    CallShape,
    CallArgumentGroups,
    CallArguments,
    CallBindings,
    CallEffects,
    ProcedureEffects,
    CallableSignature,
    SignatureParameters,
    DecoratorBindings(DecoratorBindingFilter),
    CallableApplicability,
    OverloadSelection,
    MemberSelection,
    DispatchOutcome,
    DispatchTargets,
    MemberFamily,
    FamilyEdges,
    OccurrencesOf(OccurrenceFilter),
    OccurrencesIn(OccurrenceFilter),
    OccurrenceTarget,
    ScopeOf,
    ScopeAncestors,
    BindingsIn(BindingFilter),
    BindingOf(BindingOfOptions),
    BindingOccurrence,
    CandidatesOf(CandidateFilter),
    CandidateHierarchy,
    CandidateTarget,
    EdgesOf(EdgeFilter),
    EdgesFrom(EdgeFilter),
    EdgeTarget,
    StateEventsOf(StateEventFilter),
    FlowRelationsOf(FlowRelationFilter),
    FlowSource,
    FlowTarget,
    ControlRelations(ControlRelationFilter),
    GuardsOf,
    TargetOf,
    SourceSetOf,
    TopologyEdgesOf,
    RewritePathsOf(RewritePathFilter),
    SegmentsOf(SegmentsOfOptions),
    SegmentTarget,
    Generates,
    GeneratedBy,
    DeclarationStateOf(DeclarationStateFilter),
    ImplementationOf,
    StubsOf,
    ExportTarget,
}

/// Constrained-value filter over lexical scope rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeFilter {
    /// Normalized kinds a scope's anchoring fact may carry. The synthesized
    /// file scope has no anchoring fact and therefore no kind, so a non-empty
    /// `kinds` never selects it -- which is the honest reading of "give me the
    /// block scopes".
    pub kinds: Vec<NormalizedKind>,
}

impl ScopeFilter {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    pub fn matches(&self, kind: Option<NormalizedKind>) -> bool {
        if self.kinds.is_empty() {
            return true;
        }
        kind.is_some_and(|kind| self.kinds.iter().any(|wanted| kind.satisfies(*wanted)))
    }
}

/// Constrained-value filter over binding rows.
///
/// `names` is an exact-match disjunction rather than a string predicate: a
/// binding name is an identifier the author already knows when they write the
/// filter, and admitting a regex here would add a second predicate dialect to
/// the row surface for no capability the `bindings-in` plus `where` composition
/// does not already give.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BindingFilter {
    pub kinds: Vec<BindingKind>,
    pub names: Vec<String>,
    pub hoisting: Vec<HoistingClass>,
}

/// Exact imported-module and imported-symbol filters for decorator-binding
/// rows. These are deliberately scalar exact strings: a policy needs to name
/// the resolved import identity, not approximate it with a local alias or a
/// second predicate dialect.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecoratorBindingFilter {
    pub module: Option<String>,
    pub imported_name: Option<String>,
}

impl DecoratorBindingFilter {
    pub fn is_empty(&self) -> bool {
        self.module.is_none() && self.imported_name.is_none()
    }
}

impl BindingFilter {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && self.names.is_empty() && self.hoisting.is_empty()
    }

    pub fn matches(&self, kind: BindingKind, name: &str, hoisting: HoistingClass) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&kind))
            && (self.names.is_empty() || self.names.iter().any(|wanted| wanted == name))
            && (self.hoisting.is_empty() || self.hoisting.contains(&hoisting))
    }
}

/// Constrained-value filter over resolution-candidate rows.
///
/// `unattributed_tier` is a filter value of its own rather than an absent
/// filter: the row tier is an `Option`, so "the seam could not name a tier" is a real answer an author
/// must be able to select, and it must never be confused with any named tier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CandidateFilter {
    pub tiers: Vec<PrecedenceTier>,
    /// `true` when the `:tier` filter listed the `unattributed` marker.
    pub unattributed_tier: bool,
    /// Coarse outcomes (`selected` / `rejected`) the row must be one of.
    pub outcomes: Vec<CandidateOutcomeLabel>,
    /// Typed rejection reasons the row must carry; implies `rejected`.
    pub rejection_reasons: Vec<RejectionReason>,
    pub boundaries: Vec<BoundaryStatus>,
}

/// The coarse two-value outcome vocabulary an author filters on. The typed
/// rejection reason is a separate axis, so `:outcome rejected` stays readable
/// while `:outcome shadowed_by_nearer` stays exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateOutcomeLabel {
    Selected,
    Rejected,
}

impl CandidateOutcomeLabel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::Rejected => "rejected",
        }
    }
}

/// The `unattributed` spelling of the `:tier` filter axis, which selects the
/// rows whose recording seam could not name a precedence tier.
pub const UNATTRIBUTED_TIER_LABEL: &str = "unattributed";

impl CandidateFilter {
    pub fn is_empty(&self) -> bool {
        self.tiers.is_empty()
            && !self.unattributed_tier
            && self.outcomes.is_empty()
            && self.rejection_reasons.is_empty()
            && self.boundaries.is_empty()
    }

    pub fn matches(
        &self,
        tier: Option<PrecedenceTier>,
        outcome: CandidateOutcome,
        boundary: BoundaryStatus,
    ) -> bool {
        let tier_ok = if self.tiers.is_empty() && !self.unattributed_tier {
            true
        } else {
            match tier {
                Some(tier) => self.tiers.contains(&tier),
                None => self.unattributed_tier,
            }
        };
        let coarse = match outcome {
            CandidateOutcome::Selected => CandidateOutcomeLabel::Selected,
            CandidateOutcome::Rejected(_) => CandidateOutcomeLabel::Rejected,
        };
        let outcome_ok = self.outcomes.is_empty() || self.outcomes.contains(&coarse);
        let reason_ok = self.rejection_reasons.is_empty()
            || outcome
                .rejection()
                .is_some_and(|reason| self.rejection_reasons.contains(&reason));
        tier_ok
            && outcome_ok
            && reason_ok
            && (self.boundaries.is_empty() || self.boundaries.contains(&boundary))
    }

    /// Whether this filter can only be answered by a trace that records
    /// rejections. A `SelectionOnly` trace answering it must report incomplete.
    pub fn depends_on_rejections(&self) -> bool {
        !self.rejection_reasons.is_empty()
            || self.outcomes.contains(&CandidateOutcomeLabel::Rejected)
    }
}

/// Constrained-value filter over generation-site rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GenerationSiteFilter {
    pub kinds: Vec<GenerationKind>,
    pub inputs: Vec<GenerationInputClass>,
}

impl GenerationSiteFilter {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && self.inputs.is_empty()
    }

    pub fn matches(&self, kind: GenerationKind, input: GenerationInputClass) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&kind))
            && (self.inputs.is_empty() || self.inputs.contains(&input))
    }
}

/// Constrained-value filter over export rows. `names` is an exact-match
/// disjunction for the same reason binding `:name` is: an exported name is an
/// identifier the author already knows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportFilter {
    pub forms: Vec<ExportForm>,
    pub names: Vec<String>,
}

impl ExportFilter {
    pub fn is_empty(&self) -> bool {
        self.forms.is_empty() && self.names.is_empty()
    }

    pub fn matches(&self, form: ExportForm, name: &str) -> bool {
        (self.forms.is_empty() || self.forms.contains(&form))
            && (self.names.is_empty() || self.names.iter().any(|wanted| wanted == name))
    }
}

/// Constrained-value filter over declaration-state rows. The two boolean axes
/// are three-valued: absent means "either".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeclarationStateFilter {
    pub origins: Vec<DeclarationOrigin>,
    pub declaration_only: Option<bool>,
    pub config_gated: Option<bool>,
}

impl DeclarationStateFilter {
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty() && self.declaration_only.is_none() && self.config_gated.is_none()
    }

    pub fn matches(
        &self,
        origin: DeclarationOrigin,
        declaration_only: bool,
        config_gated: bool,
    ) -> bool {
        (self.origins.is_empty() || self.origins.contains(&origin))
            && self
                .declaration_only
                .is_none_or(|wanted| wanted == declaration_only)
            && self
                .config_gated
                .is_none_or(|wanted| wanted == config_gated)
    }
}

/// Options of the `binding-of` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BindingOfOptions {
    /// Emit the shadowed bindings alongside the winner, so the multi-row
    /// answer that "more than one binding of this name is in effect" becomes
    /// visible rather than being collapsed to the winner.
    pub include_shadowed: bool,
}

/// The constrained-value filters shared by the occurrence seed and by the two
/// occurrence-producing steps. An empty vector means "unconstrained"; the
/// filters are conjunctive across axes and disjunctive within one axis.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OccurrenceFilter {
    pub classes: Vec<OccurrenceClass>,
    pub roles: Vec<OccurrenceRole>,
    pub namespaces: Vec<Namespace>,
}

impl OccurrenceFilter {
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.roles.is_empty() && self.namespaces.is_empty()
    }

    pub fn matches(
        &self,
        class: OccurrenceClass,
        role: OccurrenceRole,
        namespace: Namespace,
    ) -> bool {
        (self.classes.is_empty() || self.classes.contains(&class))
            && (self.roles.is_empty() || self.roles.contains(&role))
            && (self.namespaces.is_empty() || self.namespaces.contains(&namespace))
    }

    /// The occurrence roles this filter depends on being classified, which is
    /// what capability reporting needs in order to decide whether an empty
    /// answer is trustworthy. An unconstrained filter depends on every role.
    pub fn required_roles(&self) -> Vec<OccurrenceRole> {
        if !self.roles.is_empty() {
            return self.roles.clone();
        }
        if !self.classes.is_empty() {
            return ALL_OCCURRENCE_ROLES
                .iter()
                .copied()
                .filter(|role| self.classes.contains(&role.class()))
                .collect();
        }
        ALL_OCCURRENCE_ROLES.to_vec()
    }
}

/// A non-structural seed producing occurrence rows directly from workspace
/// facts.
///
/// There is deliberately no `inside`/`not_inside` here: lexical containment for
/// occurrences is expressed by `occurrences-in` over a structural query, so the
/// containment verifier exists exactly once (see the ExecPlan decision log).
#[derive(Debug, Clone, Default)]
pub struct OccurrenceSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: OccurrenceFilter,
}

impl OccurrenceSeed {
    /// Scan exactly the named workspace-relative files for the named roles.
    ///
    /// Paths are glob-escaped, so a file whose name contains `[`, `?` or `*`
    /// selects itself instead of a wider set. This is the shape a correlated
    /// join needs: the subject rows already named their files, and naming the
    /// roles is what narrows capability reporting to the roles actually being
    /// depended on.
    pub fn for_exact_paths<'a>(
        paths: impl IntoIterator<Item = &'a str>,
        roles: Vec<OccurrenceRole>,
    ) -> Result<Self, glob::PatternError> {
        Ok(Self {
            where_globs: exact_path_globs(paths)?,
            languages: Vec::new(),
            filter: OccurrenceFilter {
                classes: Vec::new(),
                roles,
                namespaces: Vec::new(),
            },
        })
    }
}

/// Glob patterns that select exactly the named workspace-relative files.
///
/// The escaping lives here rather than in each seed so a file whose name
/// contains `[`, `?` or `*` selects itself on every correlated surface.
pub fn exact_path_globs<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<glob::Pattern>, glob::PatternError> {
    paths
        .into_iter()
        .map(|path| glob::Pattern::new(&glob::Pattern::escape(path)))
        .collect()
}

/// A non-structural seed producing lexical scope rows directly from workspace
/// facts.
///
/// Like the occurrence seed it has no `inside`/`not_inside`: containment over
/// scope rows is `scope-of` and `scope-ancestors`, which are real steps, so the
/// containment verifier stays in one place.
#[derive(Debug, Clone, Default)]
pub struct ScopeSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: ScopeFilter,
}

impl ScopeSeed {
    /// Scan exactly the named workspace-relative files for every scope.
    pub fn for_exact_paths<'a>(
        paths: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, glob::PatternError> {
        Ok(Self {
            where_globs: exact_path_globs(paths)?,
            languages: Vec::new(),
            filter: ScopeFilter::default(),
        })
    }
}

/// Constrained-value filter over qualified-path rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathFilter {
    /// Keep only paths with at least this many segments. A path always has at
    /// least two (one segment is a bare identifier, not a path), so values
    /// below three never filter anything.
    pub min_segments: Option<u32>,
}

impl PathFilter {
    pub fn is_empty(&self) -> bool {
        self.min_segments.is_none()
    }
}

/// Options of the `segments-of` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentsOfOptions {
    /// Derive each segment's prefix resolution (one resolver batch per file)
    /// so rows carry a status, targets, and a resolution-decided namespace.
    /// Off by default: a query that never asks never pays.
    pub resolved: bool,
}

/// A non-structural seed producing qualified-path rows directly from
/// workspace facts (#1475).
#[derive(Debug, Clone, Default)]
pub struct PathSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: PathFilter,
}

impl PathSeed {
    /// Scan exactly the named workspace-relative files for every path.
    pub fn for_exact_paths<'a>(
        paths: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, glob::PatternError> {
        Ok(Self {
            where_globs: exact_path_globs(paths)?,
            languages: Vec::new(),
            filter: PathFilter::default(),
        })
    }
}

/// A non-structural seed producing binding rows directly from workspace facts.
#[derive(Debug, Clone, Default)]
pub struct BindingSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: BindingFilter,
}

/// A non-structural seed producing generation-site rows directly from
/// recorded materialization provenance (issue #1476).
#[derive(Debug, Clone, Default)]
pub struct GenerationSiteSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: GenerationSiteFilter,
}

impl GenerationSiteSeed {
    /// Scan exactly the named workspace-relative files for every site.
    pub fn for_exact_paths<'a>(
        paths: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, glob::PatternError> {
        Ok(Self {
            where_globs: exact_path_globs(paths)?,
            languages: Vec::new(),
            filter: GenerationSiteFilter::default(),
        })
    }
}

/// A non-structural seed producing export rows directly from recorded
/// materialization provenance (issue #1476).
#[derive(Debug, Clone, Default)]
pub struct ExportSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: ExportFilter,
}

impl QueryStep {
    pub fn label(&self) -> &'static str {
        self.op().label()
    }

    pub fn op(&self) -> QueryStepOp {
        match self {
            Self::EnclosingDecl => QueryStepOp::EnclosingDecl,
            Self::ProcedureOf => QueryStepOp::ProcedureOf,
            Self::CfgEntry => QueryStepOp::CfgEntry,
            Self::CfgExits => QueryStepOp::CfgExits,
            Self::CfgSuccessorEdges => QueryStepOp::CfgSuccessorEdges,
            Self::CfgPredecessorEdges => QueryStepOp::CfgPredecessorEdges,
            Self::CfgEdgeSource => QueryStepOp::CfgEdgeSource,
            Self::CfgEdgeTarget => QueryStepOp::CfgEdgeTarget,
            Self::Typestate(_) => QueryStepOp::Typestate,
            Self::ValueFlow(_) => QueryStepOp::ValueFlow,
            Self::Taint(_) => QueryStepOp::Taint,
            Self::Witness(_) => QueryStepOp::Witness,
            Self::FileOf => QueryStepOp::FileOf,
            Self::ImportsOf => QueryStepOp::ImportsOf,
            Self::ImportersOf => QueryStepOp::ImportersOf,
            Self::Supertypes(_) => QueryStepOp::Supertypes,
            Self::Subtypes(_) => QueryStepOp::Subtypes,
            Self::Members => QueryStepOp::Members,
            Self::Owner => QueryStepOp::Owner,
            Self::ReferencesOf(_) => QueryStepOp::ReferencesOf,
            Self::UsedBy(_) => QueryStepOp::UsedBy,
            Self::Uses(_) => QueryStepOp::Uses,
            Self::Callers(_) => QueryStepOp::Callers,
            Self::Callees(_) => QueryStepOp::Callees,
            Self::CallSitesTo(_) => QueryStepOp::CallSitesTo,
            Self::CallSitesFrom(_) => QueryStepOp::CallSitesFrom,
            Self::CallInput(_) => QueryStepOp::CallInput,
            Self::JsxAttributeValue(_) => QueryStepOp::JsxAttributeValue,
            Self::ReceiverTargets(_) => QueryStepOp::ReceiverTargets,
            Self::PointsTo(_) => QueryStepOp::PointsTo,
            Self::MemberTargets(_) => QueryStepOp::MemberTargets,
            Self::ReceiverOutcome => QueryStepOp::ReceiverOutcome,
            Self::ReceiverEvidence => QueryStepOp::ReceiverEvidence,
            Self::CallShape => QueryStepOp::CallShape,
            Self::CallArgumentGroups => QueryStepOp::CallArgumentGroups,
            Self::CallArguments => QueryStepOp::CallArguments,
            Self::CallBindings => QueryStepOp::CallBindings,
            Self::CallEffects => QueryStepOp::CallEffects,
            Self::ProcedureEffects => QueryStepOp::ProcedureEffects,
            Self::CallableSignature => QueryStepOp::CallableSignature,
            Self::SignatureParameters => QueryStepOp::SignatureParameters,
            Self::DecoratorBindings(_) => QueryStepOp::DecoratorBindings,
            Self::CallableApplicability => QueryStepOp::CallableApplicability,
            Self::OverloadSelection => QueryStepOp::OverloadSelection,
            Self::MemberSelection => QueryStepOp::MemberSelection,
            Self::DispatchOutcome => QueryStepOp::DispatchOutcome,
            Self::DispatchTargets => QueryStepOp::DispatchTargets,
            Self::MemberFamily => QueryStepOp::MemberFamily,
            Self::FamilyEdges => QueryStepOp::FamilyEdges,
            Self::OccurrencesOf(_) => QueryStepOp::OccurrencesOf,
            Self::OccurrencesIn(_) => QueryStepOp::OccurrencesIn,
            Self::OccurrenceTarget => QueryStepOp::OccurrenceTarget,
            Self::ScopeOf => QueryStepOp::ScopeOf,
            Self::ScopeAncestors => QueryStepOp::ScopeAncestors,
            Self::BindingsIn(_) => QueryStepOp::BindingsIn,
            Self::BindingOf(_) => QueryStepOp::BindingOf,
            Self::BindingOccurrence => QueryStepOp::BindingOccurrence,
            Self::CandidatesOf(_) => QueryStepOp::CandidatesOf,
            Self::CandidateHierarchy => QueryStepOp::CandidateHierarchy,
            Self::Generates => QueryStepOp::Generates,
            Self::GeneratedBy => QueryStepOp::GeneratedBy,
            Self::DeclarationStateOf(_) => QueryStepOp::DeclarationStateOf,
            Self::ImplementationOf => QueryStepOp::ImplementationOf,
            Self::StubsOf => QueryStepOp::StubsOf,
            Self::ExportTarget => QueryStepOp::ExportTarget,
            Self::CandidateTarget => QueryStepOp::CandidateTarget,
            Self::EdgesOf(_) => QueryStepOp::EdgesOf,
            Self::EdgesFrom(_) => QueryStepOp::EdgesFrom,
            Self::EdgeTarget => QueryStepOp::EdgeTarget,
            Self::StateEventsOf(_) => QueryStepOp::StateEventsOf,
            Self::FlowRelationsOf(_) => QueryStepOp::FlowRelationsOf,
            Self::FlowSource => QueryStepOp::FlowSource,
            Self::FlowTarget => QueryStepOp::FlowTarget,
            Self::ControlRelations(_) => QueryStepOp::ControlRelations,
            Self::GuardsOf => QueryStepOp::GuardsOf,
            Self::TargetOf => QueryStepOp::TargetOf,
            Self::SourceSetOf => QueryStepOp::SourceSetOf,
            Self::TopologyEdgesOf => QueryStepOp::TopologyEdgesOf,
            Self::RewritePathsOf(_) => QueryStepOp::RewritePathsOf,
            Self::SegmentsOf(_) => QueryStepOp::SegmentsOf,
            Self::SegmentTarget => QueryStepOp::SegmentTarget,
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match QueryStepOp::from_label(label)? {
            QueryStepOp::EnclosingDecl => Some(Self::EnclosingDecl),
            QueryStepOp::ProcedureOf => Some(Self::ProcedureOf),
            QueryStepOp::CfgEntry => Some(Self::CfgEntry),
            QueryStepOp::CfgExits => Some(Self::CfgExits),
            QueryStepOp::CfgSuccessorEdges => Some(Self::CfgSuccessorEdges),
            QueryStepOp::CfgPredecessorEdges => Some(Self::CfgPredecessorEdges),
            QueryStepOp::CfgEdgeSource => Some(Self::CfgEdgeSource),
            QueryStepOp::CfgEdgeTarget => Some(Self::CfgEdgeTarget),
            QueryStepOp::Typestate
            | QueryStepOp::ValueFlow
            | QueryStepOp::Taint
            | QueryStepOp::Witness => None,
            QueryStepOp::FileOf => Some(Self::FileOf),
            QueryStepOp::ImportsOf => Some(Self::ImportsOf),
            QueryStepOp::ImportersOf => Some(Self::ImportersOf),
            QueryStepOp::Supertypes => Some(Self::Supertypes(HierarchyTraversal::Direct)),
            QueryStepOp::Subtypes => Some(Self::Subtypes(HierarchyTraversal::Direct)),
            QueryStepOp::Members => Some(Self::Members),
            QueryStepOp::Owner => Some(Self::Owner),
            QueryStepOp::ReferencesOf => {
                Some(Self::ReferencesOf(ReferenceTraversalFilter::default()))
            }
            QueryStepOp::UsedBy => Some(Self::UsedBy(ReferenceTraversalFilter::default())),
            QueryStepOp::Uses => Some(Self::Uses(ReferenceTraversalFilter::default())),
            QueryStepOp::Callers => Some(Self::Callers(CallTraversalFilter::default())),
            QueryStepOp::Callees => Some(Self::Callees(CallTraversalFilter::default())),
            QueryStepOp::CallSitesTo => Some(Self::CallSitesTo(CallSiteTraversalFilter::default())),
            QueryStepOp::CallSitesFrom => {
                Some(Self::CallSitesFrom(CallSiteTraversalFilter::default()))
            }
            QueryStepOp::CallInput => Some(Self::CallInput(CallInputSelector::Receiver)),
            QueryStepOp::JsxAttributeValue => Some(Self::JsxAttributeValue(
                JsxAttributeValueTraversal::default(),
            )),
            QueryStepOp::ReceiverTargets => {
                Some(Self::ReceiverTargets(ReceiverTraversalFilter::default()))
            }
            QueryStepOp::PointsTo => Some(Self::PointsTo(ReceiverTraversalFilter::default())),
            QueryStepOp::MemberTargets => {
                Some(Self::MemberTargets(ReceiverTraversalFilter::default()))
            }
            QueryStepOp::ReceiverOutcome => Some(Self::ReceiverOutcome),
            QueryStepOp::ReceiverEvidence => Some(Self::ReceiverEvidence),
            QueryStepOp::CallShape => Some(Self::CallShape),
            QueryStepOp::CallArgumentGroups => Some(Self::CallArgumentGroups),
            QueryStepOp::CallArguments => Some(Self::CallArguments),
            QueryStepOp::CallBindings => Some(Self::CallBindings),
            QueryStepOp::CallEffects => Some(Self::CallEffects),
            QueryStepOp::ProcedureEffects => Some(Self::ProcedureEffects),
            QueryStepOp::CallableSignature => Some(Self::CallableSignature),
            QueryStepOp::SignatureParameters => Some(Self::SignatureParameters),
            QueryStepOp::DecoratorBindings => {
                Some(Self::DecoratorBindings(DecoratorBindingFilter::default()))
            }
            QueryStepOp::CallableApplicability => Some(Self::CallableApplicability),
            QueryStepOp::OverloadSelection => Some(Self::OverloadSelection),
            QueryStepOp::MemberSelection => Some(Self::MemberSelection),
            QueryStepOp::DispatchOutcome => Some(Self::DispatchOutcome),
            QueryStepOp::DispatchTargets => Some(Self::DispatchTargets),
            QueryStepOp::MemberFamily => Some(Self::MemberFamily),
            QueryStepOp::FamilyEdges => Some(Self::FamilyEdges),
            QueryStepOp::OccurrencesOf => Some(Self::OccurrencesOf(OccurrenceFilter::default())),
            QueryStepOp::OccurrencesIn => Some(Self::OccurrencesIn(OccurrenceFilter::default())),
            QueryStepOp::OccurrenceTarget => Some(Self::OccurrenceTarget),
            QueryStepOp::ScopeOf => Some(Self::ScopeOf),
            QueryStepOp::ScopeAncestors => Some(Self::ScopeAncestors),
            QueryStepOp::BindingsIn => Some(Self::BindingsIn(BindingFilter::default())),
            QueryStepOp::BindingOf => Some(Self::BindingOf(BindingOfOptions::default())),
            QueryStepOp::BindingOccurrence => Some(Self::BindingOccurrence),
            QueryStepOp::CandidatesOf => Some(Self::CandidatesOf(CandidateFilter::default())),
            QueryStepOp::CandidateHierarchy => Some(Self::CandidateHierarchy),
            QueryStepOp::CandidateTarget => Some(Self::CandidateTarget),
            QueryStepOp::EdgesOf => Some(Self::EdgesOf(EdgeFilter::default())),
            QueryStepOp::EdgesFrom => Some(Self::EdgesFrom(EdgeFilter::default())),
            QueryStepOp::EdgeTarget => Some(Self::EdgeTarget),
            QueryStepOp::StateEventsOf => Some(Self::StateEventsOf(StateEventFilter::default())),
            QueryStepOp::FlowRelationsOf => {
                Some(Self::FlowRelationsOf(FlowRelationFilter::default()))
            }
            QueryStepOp::FlowSource => Some(Self::FlowSource),
            QueryStepOp::FlowTarget => Some(Self::FlowTarget),
            QueryStepOp::TargetOf => Some(Self::TargetOf),
            QueryStepOp::SourceSetOf => Some(Self::SourceSetOf),
            QueryStepOp::TopologyEdgesOf => Some(Self::TopologyEdgesOf),
            QueryStepOp::GuardsOf => Some(Self::GuardsOf),
            QueryStepOp::ControlRelations => {
                Some(Self::ControlRelations(ControlRelationFilter::default()))
            }
            QueryStepOp::RewritePathsOf => Some(Self::RewritePathsOf(RewritePathFilter::default())),
            QueryStepOp::SegmentsOf => Some(Self::SegmentsOf(SegmentsOfOptions::default())),
            QueryStepOp::SegmentTarget => Some(Self::SegmentTarget),
            QueryStepOp::Generates => Some(Self::Generates),
            QueryStepOp::GeneratedBy => Some(Self::GeneratedBy),
            QueryStepOp::DeclarationStateOf => {
                Some(Self::DeclarationStateOf(DeclarationStateFilter::default()))
            }
            QueryStepOp::ImplementationOf => Some(Self::ImplementationOf),
            QueryStepOp::StubsOf => Some(Self::StubsOf),
            QueryStepOp::ExportTarget => Some(Self::ExportTarget),
        }
    }

    pub fn output_kind(&self, input: QueryValueKind) -> Option<QueryValueKind> {
        match (self, input) {
            (Self::EnclosingDecl, QueryValueKind::StructuralMatch) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::ProcedureOf, QueryValueKind::StructuralMatch | QueryValueKind::Declaration) => {
                Some(QueryValueKind::Procedure)
            }
            (Self::CfgEntry | Self::CfgExits, QueryValueKind::Procedure) => {
                Some(QueryValueKind::ProgramPoint)
            }
            (Self::CfgSuccessorEdges | Self::CfgPredecessorEdges, QueryValueKind::ProgramPoint) => {
                Some(QueryValueKind::ControlEdge)
            }
            (Self::CfgEdgeSource | Self::CfgEdgeTarget, QueryValueKind::ControlEdge) => {
                Some(QueryValueKind::ProgramPoint)
            }
            (Self::Typestate(_), QueryValueKind::Procedure) => {
                Some(QueryValueKind::TypestateFinding)
            }
            (Self::ValueFlow(_), QueryValueKind::Procedure) => Some(QueryValueKind::FlowEndpoint),
            (Self::Taint(_), QueryValueKind::Procedure) => Some(QueryValueKind::TaintFinding),
            (Self::Witness(_), QueryValueKind::TypestateFinding) => {
                Some(QueryValueKind::TypestateWitness)
            }
            (Self::Witness(_), QueryValueKind::FlowEndpoint) => Some(QueryValueKind::FlowWitness),
            (
                Self::FileOf,
                QueryValueKind::StructuralMatch
                | QueryValueKind::Declaration
                | QueryValueKind::Procedure
                | QueryValueKind::ProgramPoint
                | QueryValueKind::ControlEdge
                | QueryValueKind::TypestateFinding
                | QueryValueKind::TypestateWitness
                | QueryValueKind::FlowEndpoint
                | QueryValueKind::FlowWitness
                | QueryValueKind::TaintFinding
                | QueryValueKind::ReferenceSite
                | QueryValueKind::CallSite
                | QueryValueKind::ExpressionSite
                | QueryValueKind::JsxAttributeValue
                | QueryValueKind::ReceiverAnalysis
                | QueryValueKind::ReceiverOutcome
                | QueryValueKind::ReceiverEvidence
                | QueryValueKind::CallShape
                | QueryValueKind::CallArgumentGroup
                | QueryValueKind::CallArgument
                | QueryValueKind::CallBinding
                | QueryValueKind::CallEffect
                | QueryValueKind::ProcedureEffect
                | QueryValueKind::CallableSignature
                | QueryValueKind::SignatureParameter
                | QueryValueKind::DecoratedParameter
                | QueryValueKind::CallableApplicability
                | QueryValueKind::OverloadSelection
                | QueryValueKind::MemberSelection
                | QueryValueKind::DispatchOutcome
                | QueryValueKind::DispatchTarget
                | QueryValueKind::MemberFamily
                | QueryValueKind::MemberFamilyEdge
                | QueryValueKind::Occurrence
                | QueryValueKind::LexicalScope
                | QueryValueKind::Binding
                | QueryValueKind::QualifiedPath
                | QueryValueKind::PathSegment
                | QueryValueKind::StateEvent,
            ) => Some(QueryValueKind::File),
            (Self::ImportsOf | Self::ImportersOf, QueryValueKind::File) => {
                Some(QueryValueKind::File)
            }
            (
                Self::Supertypes(_) | Self::Subtypes(_) | Self::Members | Self::Owner,
                QueryValueKind::Declaration,
            ) => Some(QueryValueKind::Declaration),
            (Self::ReferencesOf(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::ReferenceSite)
            }
            (Self::UsedBy(_) | Self::Uses(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::Callers(_) | Self::Callees(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::CallSitesTo(_) | Self::CallSitesFrom(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::CallSite)
            }
            (Self::CallInput(_), QueryValueKind::CallSite) => Some(QueryValueKind::ExpressionSite),
            (Self::JsxAttributeValue(_), QueryValueKind::StructuralMatch) => {
                Some(QueryValueKind::JsxAttributeValue)
            }
            (
                Self::ReceiverTargets(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::CallSite
                | QueryValueKind::ExpressionSite
                | QueryValueKind::Occurrence,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (
                Self::PointsTo(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::ExpressionSite
                | QueryValueKind::Occurrence,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (
                Self::MemberTargets(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::Occurrence,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (Self::ReceiverOutcome, QueryValueKind::ReceiverAnalysis) => {
                Some(QueryValueKind::ReceiverOutcome)
            }
            (Self::ReceiverEvidence, QueryValueKind::ReceiverAnalysis) => {
                Some(QueryValueKind::ReceiverEvidence)
            }
            (
                Self::CallShape,
                QueryValueKind::StructuralMatch
                | QueryValueKind::CallSite
                | QueryValueKind::Occurrence,
            ) => Some(QueryValueKind::CallShape),
            (Self::CallArgumentGroups, QueryValueKind::CallShape) => {
                Some(QueryValueKind::CallArgumentGroup)
            }
            (Self::CallArguments, QueryValueKind::CallArgumentGroup) => {
                Some(QueryValueKind::CallArgument)
            }
            (Self::CallBindings, QueryValueKind::CallShape) => Some(QueryValueKind::CallBinding),
            (Self::CallEffects, QueryValueKind::CallShape) => Some(QueryValueKind::CallEffect),
            (Self::ProcedureEffects, QueryValueKind::Declaration) => {
                Some(QueryValueKind::ProcedureEffect)
            }
            (Self::CallableSignature, QueryValueKind::Declaration) => {
                Some(QueryValueKind::CallableSignature)
            }
            (Self::SignatureParameters, QueryValueKind::CallableSignature) => {
                Some(QueryValueKind::SignatureParameter)
            }
            (Self::DecoratorBindings(_), QueryValueKind::StructuralMatch) => {
                Some(QueryValueKind::DecoratedParameter)
            }
            (Self::CallableApplicability, QueryValueKind::Occurrence) => {
                Some(QueryValueKind::CallableApplicability)
            }
            (Self::OverloadSelection, QueryValueKind::Occurrence) => {
                Some(QueryValueKind::OverloadSelection)
            }
            (Self::MemberSelection, QueryValueKind::Occurrence) => {
                Some(QueryValueKind::MemberSelection)
            }
            (
                Self::DispatchOutcome,
                QueryValueKind::StructuralMatch
                | QueryValueKind::CallSite
                | QueryValueKind::ReferenceSite
                | QueryValueKind::Occurrence,
            ) => Some(QueryValueKind::DispatchOutcome),
            (
                Self::DispatchTargets,
                QueryValueKind::StructuralMatch
                | QueryValueKind::CallSite
                | QueryValueKind::ReferenceSite
                | QueryValueKind::Occurrence,
            ) => Some(QueryValueKind::DispatchTarget),
            (Self::MemberFamily, QueryValueKind::Declaration) => Some(QueryValueKind::MemberFamily),
            (Self::FamilyEdges, QueryValueKind::Declaration) => {
                Some(QueryValueKind::MemberFamilyEdge)
            }
            (Self::OccurrencesOf(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::Occurrence)
            }
            (Self::OccurrencesIn(_), QueryValueKind::StructuralMatch | QueryValueKind::File) => {
                Some(QueryValueKind::Occurrence)
            }
            (Self::OccurrenceTarget, QueryValueKind::Occurrence) => {
                Some(QueryValueKind::Declaration)
            }
            (
                Self::ScopeOf,
                QueryValueKind::Binding
                | QueryValueKind::Occurrence
                | QueryValueKind::StructuralMatch,
            ) => Some(QueryValueKind::LexicalScope),
            (Self::ScopeAncestors, QueryValueKind::LexicalScope) => {
                Some(QueryValueKind::LexicalScope)
            }
            (
                Self::BindingsIn(_),
                QueryValueKind::LexicalScope | QueryValueKind::StructuralMatch,
            ) => Some(QueryValueKind::Binding),
            (Self::BindingOf(_), QueryValueKind::Occurrence) => Some(QueryValueKind::Binding),
            (Self::BindingOccurrence, QueryValueKind::Binding) => Some(QueryValueKind::Occurrence),
            (Self::CandidatesOf(_), QueryValueKind::Occurrence) => {
                Some(QueryValueKind::ResolutionCandidate)
            }
            (Self::CandidateHierarchy, QueryValueKind::Occurrence) => {
                Some(QueryValueKind::CandidateHop)
            }
            (Self::SegmentsOf(_), QueryValueKind::QualifiedPath) => {
                Some(QueryValueKind::PathSegment)
            }
            (Self::SegmentTarget, QueryValueKind::PathSegment) => Some(QueryValueKind::Declaration),
            (Self::CandidateTarget, QueryValueKind::ResolutionCandidate) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::Generates, QueryValueKind::GenerationSite) => {
                Some(QueryValueKind::DeclarationState)
            }
            (Self::GeneratedBy, QueryValueKind::Declaration | QueryValueKind::DeclarationState) => {
                Some(QueryValueKind::GenerationSite)
            }
            (Self::DeclarationStateOf(_), QueryValueKind::Declaration) => {
                Some(QueryValueKind::DeclarationState)
            }
            (
                Self::ImplementationOf,
                QueryValueKind::Declaration | QueryValueKind::DeclarationState,
            ) => Some(QueryValueKind::Declaration),
            (Self::StubsOf, QueryValueKind::Declaration) => Some(QueryValueKind::DeclarationState),
            (Self::ExportTarget, QueryValueKind::Export) => Some(QueryValueKind::Declaration),
            (Self::EdgesOf(_), QueryValueKind::Declaration) => Some(QueryValueKind::ReferenceEdge),
            (Self::EdgesFrom(_), QueryValueKind::Occurrence) => Some(QueryValueKind::ReferenceEdge),
            (Self::EdgeTarget, QueryValueKind::ReferenceEdge) => Some(QueryValueKind::Declaration),
            (Self::StateEventsOf(_), QueryValueKind::Procedure | QueryValueKind::Declaration) => {
                Some(QueryValueKind::StateEvent)
            }
            (Self::FlowRelationsOf(_), QueryValueKind::StateEvent | QueryValueKind::Procedure) => {
                Some(QueryValueKind::FlowRelation)
            }
            (Self::FlowSource | Self::FlowTarget, QueryValueKind::FlowRelation) => {
                Some(QueryValueKind::StateEvent)
            }
            (Self::ControlRelations(_), QueryValueKind::Procedure) => {
                Some(QueryValueKind::ControlRelation)
            }
            (Self::GuardsOf, QueryValueKind::Procedure) => Some(QueryValueKind::Guard),
            // Project topology (#2448). A file's owner is what the build
            // declares about it, so both ownership steps are seeded from a
            // file, and the dependency step is seeded from the target whose
            // declared dependencies it returns.
            (Self::TargetOf, QueryValueKind::File) => Some(QueryValueKind::BuildTarget),
            (Self::SourceSetOf, QueryValueKind::File) => Some(QueryValueKind::SourceSet),
            (Self::TopologyEdgesOf, QueryValueKind::BuildTarget) => {
                Some(QueryValueKind::TopologyEdge)
            }
            (Self::RewritePathsOf(_), QueryValueKind::File) => Some(QueryValueKind::RewritePath),
            _ => None,
        }
    }
}

pub(super) fn validate_query_steps(
    steps: &[QueryStep],
    input: QueryValueKind,
    path: &str,
) -> Result<QueryValueKind, QueryError> {
    if steps.len() > MAX_QUERY_STEPS {
        return Err(QueryError::new(
            path,
            format!("at most {MAX_QUERY_STEPS} query steps are allowed"),
        ));
    }

    let mut value_kind = input;
    for (index, step) in steps.iter().enumerate() {
        let step_path = format!("{path}[{index}]");
        if let QueryStep::Callers(filter) | QueryStep::Callees(filter) = step
            && filter.completeness == CallTraversalCompleteness::ProvenSubset
        {
            if !matches!(step, QueryStep::Callers(_)) {
                return Err(QueryError::new(
                    format!("{step_path}.completeness"),
                    "proven_subset is currently supported only for callers",
                ));
            }
            if filter.proof != Some(UsageProof::Proven) {
                return Err(QueryError::new(
                    format!("{step_path}.completeness"),
                    "proven_subset requires proof to be proven",
                ));
            }
        }
        let expected_input = match step {
            QueryStep::EnclosingDecl => "structural_match",
            QueryStep::ProcedureOf => "structural_match or declaration",
            QueryStep::CfgEntry | QueryStep::CfgExits => "procedure",
            QueryStep::CfgSuccessorEdges | QueryStep::CfgPredecessorEdges => "program_point",
            QueryStep::CfgEdgeSource | QueryStep::CfgEdgeTarget => "control_edge",
            QueryStep::Typestate(_) => "procedure",
            QueryStep::ValueFlow(_) => "procedure",
            QueryStep::Taint(_) => "procedure",
            QueryStep::Witness(_) => "typestate_finding or flow_endpoint",
            QueryStep::FileOf => {
                "structural_match, declaration, procedure, program_point, control_edge, typestate_finding, typestate_witness, flow_endpoint, flow_witness, taint_finding, reference_site, call_site, expression_site, jsx_attribute_value, receiver_analysis, receiver_outcome, receiver_evidence, occurrence, lexical_scope, or binding"
            }
            QueryStep::ImportsOf | QueryStep::ImportersOf => "file",
            QueryStep::Supertypes(_)
            | QueryStep::Subtypes(_)
            | QueryStep::Members
            | QueryStep::Owner => "declaration",
            QueryStep::ReferencesOf(_) | QueryStep::UsedBy(_) | QueryStep::Uses(_) => "declaration",
            QueryStep::Callers(_)
            | QueryStep::Callees(_)
            | QueryStep::CallSitesTo(_)
            | QueryStep::CallSitesFrom(_) => "declaration",
            QueryStep::CallInput(_) => "call_site",
            QueryStep::JsxAttributeValue(_) => "structural_match",
            QueryStep::ReceiverTargets(_) => {
                "structural_match, reference_site, call_site, expression_site, or occurrence"
            }
            QueryStep::PointsTo(_) => {
                "structural_match, reference_site, expression_site, or occurrence"
            }
            QueryStep::MemberTargets(_) => "structural_match, reference_site, or occurrence",
            QueryStep::ReceiverOutcome | QueryStep::ReceiverEvidence => "receiver_analysis",
            QueryStep::CallShape => "structural_match, call_site, or occurrence",
            QueryStep::CallArgumentGroups => "call_shape",
            QueryStep::CallArguments => "call_argument_group",
            QueryStep::CallBindings => "call_shape",
            QueryStep::CallEffects => "call_shape",
            QueryStep::ProcedureEffects => "declaration",
            QueryStep::CallableSignature => "declaration",
            QueryStep::SignatureParameters => "callable_signature",
            QueryStep::DecoratorBindings(_) => "structural_match",
            QueryStep::CallableApplicability | QueryStep::OverloadSelection => "occurrence",
            QueryStep::MemberSelection => "occurrence",
            QueryStep::DispatchOutcome | QueryStep::DispatchTargets => {
                "structural_match, call_site, reference_site, or occurrence"
            }
            QueryStep::MemberFamily | QueryStep::FamilyEdges => "declaration",
            QueryStep::OccurrencesOf(_) => "declaration",
            QueryStep::OccurrencesIn(_) => "structural_match or file",
            QueryStep::OccurrenceTarget => "occurrence",
            QueryStep::ScopeOf => "binding, occurrence, or structural_match",
            QueryStep::ScopeAncestors => "lexical_scope",
            QueryStep::BindingsIn(_) => "lexical_scope or structural_match",
            QueryStep::BindingOf(_) => "occurrence",
            QueryStep::BindingOccurrence => "binding",
            QueryStep::CandidatesOf(_) => "occurrence",
            QueryStep::CandidateHierarchy => "occurrence",
            QueryStep::CandidateTarget => "resolution_candidate",
            QueryStep::EdgesOf(_) => "declaration",
            QueryStep::EdgesFrom(_) => "occurrence",
            QueryStep::EdgeTarget => "reference_edge",
            QueryStep::StateEventsOf(_) => "procedure or declaration",
            QueryStep::FlowRelationsOf(_) => "state_event or procedure",
            QueryStep::FlowSource | QueryStep::FlowTarget => "flow_relation",
            QueryStep::ControlRelations(_) => "procedure",
            QueryStep::GuardsOf => "procedure",
            QueryStep::TargetOf | QueryStep::SourceSetOf => "file",
            QueryStep::TopologyEdgesOf => "build_target",
            QueryStep::RewritePathsOf(_) => "file",
            QueryStep::SegmentsOf(_) => "qualified_path",
            QueryStep::SegmentTarget => "path_segment",
            QueryStep::Generates => "generation_site",
            QueryStep::GeneratedBy => "declaration or declaration_state",
            QueryStep::DeclarationStateOf(_) => "declaration",
            QueryStep::ImplementationOf => "declaration_state or declaration",
            QueryStep::StubsOf => "declaration",
            QueryStep::ExportTarget => "export",
        };
        value_kind = step.output_kind(value_kind).ok_or_else(|| {
            QueryError::new(
                step_path,
                format!(
                    "step {} requires {expected_input}, but the previous stage produces {}",
                    step.label(),
                    value_kind.label()
                ),
            )
        })?;
    }
    Ok(value_kind)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOperator {
    Union,
    Intersect,
    Except,
}

impl SetOperator {
    pub const ALL: [Self; 3] = [Self::Union, Self::Intersect, Self::Except];

    pub fn label(self) -> &'static str {
        match self {
            Self::Union => "union",
            Self::Intersect => "intersect",
            Self::Except => "except",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "union" => Some(Self::Union),
            "intersect" => Some(Self::Intersect),
            "except" => Some(Self::Except),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeQueryResultDetail {
    Compact,
    Full,
}

impl CodeQueryResultDetail {
    pub const ALL: [Self; 2] = [Self::Compact, Self::Full];

    pub fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Full => "full",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "compact" => Some(Self::Compact),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn is_compact(self) -> bool {
        matches!(self, Self::Compact)
    }
}

/// One structural seed before typed semantic pipeline transformations.
#[derive(Debug, Clone)]
pub struct CodeQuerySeed {
    /// Path globs relative to the workspace root; empty means all files.
    pub where_globs: Vec<glob::Pattern>,
    /// Language filter; empty means all languages with structural adapters.
    pub languages: Vec<Language>,
    pub root: Pattern,
    /// The root match must be lexically contained in a node matching this.
    pub inside: Option<Pattern>,
    /// The root match must be inside a matching ancestor without crossing an
    /// intervening callable declaration.
    pub inside_decl: Option<Pattern>,
    /// Verifier-only negative containment: never used for candidate pruning.
    pub not_inside: Option<Pattern>,
}

impl CodeQuerySeed {
    /// Whether any pattern in this seed filters on recorded callable
    /// visibility or parameter-type spellings.
    pub fn constrains_callable_signature(&self) -> bool {
        self.root.constrains_callable_signature()
            || self
                .inside
                .as_ref()
                .is_some_and(Pattern::constrains_callable_signature)
            || self
                .inside_decl
                .as_ref()
                .is_some_and(Pattern::constrains_callable_signature)
            || self
                .not_inside
                .as_ref()
                .is_some_and(Pattern::constrains_callable_signature)
    }

    /// Whether any pattern in this seed filters on an exact normalized
    /// boolean-literal value.
    pub fn constrains_boolean_value(&self) -> bool {
        self.root.constrains_boolean_value()
            || self
                .inside
                .as_ref()
                .is_some_and(Pattern::constrains_boolean_value)
            || self
                .inside_decl
                .as_ref()
                .is_some_and(Pattern::constrains_boolean_value)
            || self
                .not_inside
                .as_ref()
                .is_some_and(Pattern::constrains_boolean_value)
    }
}

/// The source of values entering one typed pipeline suffix.
#[derive(Debug, Clone)]
pub enum CodeQueryPlanSource {
    Seed(Box<CodeQuerySeed>),
    Occurrences(Box<OccurrenceSeed>),
    Scopes(Box<ScopeSeed>),
    Bindings(Box<BindingSeed>),
    Paths(Box<PathSeed>),
    GenerationSites(Box<GenerationSiteSeed>),
    Exports(Box<ExportSeed>),
    Set {
        op: SetOperator,
        branches: Vec<CodeQueryPlan>,
    },
}

/// A structural seed or compatible set composition followed by typed steps.
#[derive(Debug, Clone)]
pub struct CodeQueryPlan {
    pub source: CodeQueryPlanSource,
    pub steps: Vec<QueryStep>,
}

/// A canonical typed code query. Both JSON and RQL parse into this model.
#[derive(Debug, Clone)]
pub struct CodeQuery {
    pub schema_version: u64,
    pub plan: CodeQueryPlan,
    pub limit: usize,
    pub result_detail: CodeQueryResultDetail,
    pub execution_mode: CodeQueryExecutionMode,
}

impl CodeQuery {
    pub fn seed(&self) -> Option<&CodeQuerySeed> {
        match &self.plan.source {
            CodeQueryPlanSource::Seed(seed) => Some(seed),
            CodeQueryPlanSource::Occurrences(_)
            | CodeQueryPlanSource::Scopes(_)
            | CodeQueryPlanSource::Bindings(_)
            | CodeQueryPlanSource::Paths(_)
            | CodeQueryPlanSource::GenerationSites(_)
            | CodeQueryPlanSource::Exports(_)
            | CodeQueryPlanSource::Set { .. } => None,
        }
    }

    /// Validate the semantic pipeline independently of its JSON/RQL origin.
    /// Embedders may construct this public IR directly, so execution cannot
    /// rely solely on decoder validation.
    pub fn validate_steps(&self) -> Result<QueryValueKind, QueryError> {
        let mut nodes = 0;
        validate_plan(&self.plan, "", 0, &mut nodes).map(|domain| domain.kind)
    }
}

#[derive(Debug)]
struct ValidatedDomain {
    kind: QueryValueKind,
    captures: Option<std::collections::HashSet<String>>,
}

fn validate_plan(
    plan: &CodeQueryPlan,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<ValidatedDomain, QueryError> {
    if depth > MAX_QUERY_PLAN_DEPTH {
        return Err(QueryError::new(
            path,
            format!("query plan depth must be at most {MAX_QUERY_PLAN_DEPTH}"),
        ));
    }
    *nodes += 1;
    if *nodes > MAX_QUERY_PLAN_NODES {
        return Err(QueryError::new(
            path,
            format!("query plan may contain at most {MAX_QUERY_PLAN_NODES} nodes"),
        ));
    }

    let mut domain = match &plan.source {
        CodeQueryPlanSource::Seed(seed) => ValidatedDomain {
            kind: QueryValueKind::StructuralMatch,
            captures: Some(seed.positive_capture_names()),
        },
        CodeQueryPlanSource::Occurrences(_) => ValidatedDomain {
            kind: QueryValueKind::Occurrence,
            captures: None,
        },
        CodeQueryPlanSource::Paths(_) => ValidatedDomain {
            kind: QueryValueKind::QualifiedPath,
            captures: None,
        },
        CodeQueryPlanSource::Scopes(_) => ValidatedDomain {
            kind: QueryValueKind::LexicalScope,
            captures: None,
        },
        CodeQueryPlanSource::Bindings(_) => ValidatedDomain {
            kind: QueryValueKind::Binding,
            captures: None,
        },
        CodeQueryPlanSource::GenerationSites(_) => ValidatedDomain {
            kind: QueryValueKind::GenerationSite,
            captures: None,
        },
        CodeQueryPlanSource::Exports(_) => ValidatedDomain {
            kind: QueryValueKind::Export,
            captures: None,
        },
        CodeQueryPlanSource::Set { op, branches } => {
            let op_path = child_query_path(path, op.label());
            if branches.len() < 2 {
                return Err(QueryError::new(
                    &op_path,
                    format!("{} requires at least two branches", op.label()),
                ));
            }
            if branches.len() > MAX_QUERY_BRANCHES {
                return Err(QueryError::new(
                    &op_path,
                    format!("at most {MAX_QUERY_BRANCHES} branches are allowed"),
                ));
            }
            let mut branch_domains = Vec::with_capacity(branches.len());
            for (index, branch) in branches.iter().enumerate() {
                let branch_path = format!("{op_path}[{index}]");
                branch_domains.push(validate_plan(branch, &branch_path, depth + 1, nodes)?);
            }
            let expected = branch_domains[0].kind;
            for (index, branch) in branch_domains.iter().enumerate().skip(1) {
                if branch.kind != expected {
                    return Err(QueryError::new(
                        format!("{op_path}[{index}]"),
                        format!(
                            "{} branch produces {}, but the first branch produces {}",
                            op.label(),
                            branch.kind.label(),
                            expected.label()
                        ),
                    ));
                }
            }
            let captures = if expected == QueryValueKind::StructuralMatch {
                let mut common = branch_domains[0].captures.clone().unwrap_or_default();
                if *op != SetOperator::Except {
                    for branch in &branch_domains[1..] {
                        common.retain(|capture| {
                            branch
                                .captures
                                .as_ref()
                                .is_some_and(|captures| captures.contains(capture))
                        });
                    }
                }
                Some(common)
            } else {
                None
            };
            ValidatedDomain {
                kind: expected,
                captures,
            }
        }
    };

    let steps_path = child_query_path(path, "steps");
    let output = validate_query_steps(&plan.steps, domain.kind, &steps_path)?;
    let mut input = domain.kind;
    for (index, step) in plan.steps.iter().enumerate() {
        let filter = match step {
            QueryStep::ReceiverTargets(filter)
            | QueryStep::PointsTo(filter)
            | QueryStep::MemberTargets(filter) => filter,
            _ => {
                input = step
                    .output_kind(input)
                    .expect("typed steps were validated above");
                continue;
            }
        };
        if let Some(capture) = &filter.capture {
            let capture_path = format!("{steps_path}[{index}].capture");
            if input != QueryValueKind::StructuralMatch {
                return Err(QueryError::new(
                    capture_path,
                    "capture is allowed only when the preceding stage produces structural_match",
                ));
            }
            if capture.is_empty() {
                return Err(QueryError::new(
                    capture_path,
                    "capture name must not be empty",
                ));
            }
            if capture.len() > MAX_CAPTURE_LENGTH {
                return Err(QueryError::new(
                    capture_path,
                    format!("capture name must be at most {MAX_CAPTURE_LENGTH} bytes"),
                ));
            }
            if !domain
                .captures
                .as_ref()
                .is_some_and(|captures| captures.contains(capture))
            {
                return Err(QueryError::new(
                    capture_path,
                    format!(
                        "capture {capture:?} is not declared by a positive pattern in every contributing branch"
                    ),
                ));
            }
        }
        input = step
            .output_kind(input)
            .expect("typed steps were validated above");
    }
    domain.kind = output;
    if output != QueryValueKind::StructuralMatch {
        domain.captures = None;
    }
    Ok(domain)
}

fn child_query_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_string()
    } else {
        format!("{path}.{field}")
    }
}

impl CodeQuerySeed {
    fn positive_capture_names(&self) -> std::collections::HashSet<String> {
        let mut captures = std::collections::HashSet::new();
        let mut stack = vec![&self.root];
        if let Some(inside) = &self.inside {
            stack.push(inside);
        }
        if let Some(inside_decl) = &self.inside_decl {
            stack.push(inside_decl);
        }
        while let Some(pattern) = stack.pop() {
            if let Some(capture) = pattern.capture.as_deref() {
                captures.insert(capture.to_string());
            }
            if let Some(has) = pattern.has.as_deref() {
                stack.push(has);
            }
            for role in Role::single_target_roles() {
                if let Some(child) = pattern.single_role_pattern(*role) {
                    stack.push(child);
                }
            }
            for role in Role::list_target_roles() {
                stack.extend(pattern.list_role_patterns(*role));
            }
            stack.extend(pattern.kwargs.iter().map(|(_, pattern)| pattern));
        }
        captures
    }
}

/// Predicate over a string attribute of a fact (its name or source text).
#[derive(Debug, Clone)]
pub enum StringPredicate {
    Exact(String),
    Regex(Regex),
}

/// Upper bound on the alternation width `exact_alternatives` will expand.
/// Wider alternations stay opaque regexes: each alternative becomes a source
/// anchor and a posting lookup, so unbounded expansion would turn one
/// predicate into arbitrarily many index probes.
const MAX_EXACT_ALTERNATIVES: usize = 16;

impl StringPredicate {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            StringPredicate::Exact(expected) => value == expected,
            StringPredicate::Regex(regex) => regex.is_match(value),
        }
    }

    /// The finite set of values this predicate can match, when that set is
    /// statically evident: an exact name, or a fully anchored literal
    /// alternation such as `^(read|read_to_string)$`. Returns `None` for
    /// every other regex, in which case callers must treat the predicate as
    /// opaque (no pruning, no posting lookup). Alternatives are non-empty,
    /// sorted, and deduplicated.
    pub fn exact_alternatives(&self) -> Option<Vec<String>> {
        let mut alternatives = match self {
            StringPredicate::Exact(expected) => vec![expected.clone()],
            StringPredicate::Regex(regex) => regex_literal_alternatives(regex.as_str())?,
        };
        alternatives.sort_unstable();
        alternatives.dedup();
        Some(alternatives)
    }
}

/// Structural extraction of `^(a|b|...)$` (and the single-literal `^a$`) via
/// the regex HIR. Anything beyond start anchor + literal alternation + end
/// anchor (classes, repetition, case folding, inner anchors) yields `None`.
fn regex_literal_alternatives(pattern: &str) -> Option<Vec<String>> {
    use regex_syntax::hir::{Hir, HirKind, Look};

    fn literal_of(hir: &Hir) -> Option<String> {
        match hir.kind() {
            HirKind::Literal(literal) => String::from_utf8(literal.0.to_vec()).ok(),
            HirKind::Capture(capture) => literal_of(&capture.sub),
            HirKind::Concat(parts) => {
                let mut combined = String::new();
                for part in parts {
                    combined.push_str(&literal_of(part)?);
                }
                Some(combined)
            }
            _ => None,
        }
    }

    fn alternatives_of(hir: &Hir) -> Option<Vec<String>> {
        match hir.kind() {
            HirKind::Alternation(branches) => {
                if branches.len() > MAX_EXACT_ALTERNATIVES {
                    return None;
                }
                branches.iter().map(literal_of).collect()
            }
            HirKind::Capture(capture) => alternatives_of(&capture.sub),
            _ => literal_of(hir).map(|literal| vec![literal]),
        }
    }

    let hir = regex_syntax::Parser::new().parse(pattern).ok()?;
    let HirKind::Concat(parts) = hir.kind() else {
        return None;
    };
    let (first, rest) = parts.split_first()?;
    let (last, middle) = rest.split_last()?;
    if !matches!(first.kind(), HirKind::Look(Look::Start))
        || !matches!(last.kind(), HirKind::Look(Look::End))
    {
        return None;
    }
    let alternatives = match middle {
        [single] => alternatives_of(single)?,
        _ => vec![literal_of(&Hir::concat(middle.to_vec()))?],
    };
    if alternatives.iter().any(String::is_empty) {
        return None;
    }
    Some(alternatives)
}

/// Upper bound on either `:min`/`:max` bound of an arity constraint. Parameter
/// lists are small; the JVM itself caps a method at 255 parameters, so a bound
/// this generous rejects only nonsense while fitting every real callable.
pub const MAX_ARITY: u32 = 1024;

/// Constraint on the number of positional arguments a matched call passes (its
/// `args` count). Both bounds are inclusive; an absent bound is open on that
/// side. A constraint always fixes at least one bound -- an all-open constraint
/// would filter nothing -- and `min <= max` whenever both are present. Both
/// invariants are enforced at the decode boundary, so a constructed
/// `ArityConstraint` is always satisfiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArityConstraint {
    pub min: Option<u32>,
    pub max: Option<u32>,
}

impl ArityConstraint {
    /// Match exactly `count` positional arguments.
    pub fn exact(count: u32) -> Self {
        Self {
            min: Some(count),
            max: Some(count),
        }
    }

    /// Whether `arity` positional arguments satisfy the constraint.
    pub fn matches(&self, arity: usize) -> bool {
        let arity = arity as u64;
        self.min.is_none_or(|min| arity >= u64::from(min))
            && self.max.is_none_or(|max| arity <= u64::from(max))
    }
}

/// One node pattern. All fields optional; the *root* `match` pattern must
/// constrain at least one of kind/name/text (a wildcard root would match
/// every node in the workspace), while nested patterns may be capture-only
/// or empty (an empty `args` entry means "some argument exists").
#[derive(Debug, Clone, Default)]
pub struct Pattern {
    /// JSON `kind`: a union of kinds, each subtype-aware (`literal` matches
    /// `string_literal`; `["function", "method"]` matches either). Empty
    /// means unconstrained. There is deliberately no exact-match variant:
    /// leaf kinds are their own exact match, and "exactly an abstract kind"
    /// would only select facts from adapters too coarse to classify further —
    /// adapter precision is surfaced through diagnostics, not query
    /// semantics.
    pub kinds: Vec<NormalizedKind>,
    /// JSON `not_kind`: subtype-aware exclusion, verifier-only (never used
    /// for candidate pruning). `{"kind": "callable", "not_kind":
    /// ["constructor", "lambda"]}` matches named functions and methods.
    pub not_kinds: Vec<NormalizedKind>,
    pub name: Option<StringPredicate>,
    pub text: Option<StringPredicate>,
    /// Exact language-neutral value of a normalized boolean literal. This is
    /// semantic fact data, not a symbol name or a source-text predicate.
    pub boolean_value: Option<bool>,
    /// Constraint on the matched fact's positional-child count. `None`
    /// leaves arity unconstrained. Meaningful on `call` facts (`args` role
    /// edges) and `collection_literal` facts (`elements` role edges, #2647);
    /// a fact with neither edge family has arity 0.
    pub arity: Option<ArityConstraint>,
    /// Recorded modifier visibility of a callable declaration. Empty means
    /// unconstrained. A fact matches when its adapter-recorded visibility is
    /// one of these labels. `unknown` is a real recorded value, never equal
    /// to `public`.
    pub visibility: Vec<DeclaredVisibility>,
    /// Existential constraint on a callable's recorded parameter-type
    /// spellings. A fact matches when any parameter spelling satisfies the
    /// predicate. The spelling is a discriminator, not a resolved type.
    pub parameter_type: Option<StringPredicate>,
    pub capture: Option<String>,
    pub has: Option<Box<Pattern>>,
    /// Verifier-only: never used for candidate pruning.
    pub not_has: Option<Box<Pattern>>,
    // Role sub-patterns. Only valid when `kind` is declared and the role is
    // valid for at least one of its kinds (see `Role::valid_for`).
    pub callee: Option<Box<Pattern>>,
    pub receiver: Option<Box<Pattern>>,
    /// Each listed pattern must match some positional argument; matches must
    /// appear in argument order but need not be contiguous.
    pub args: Vec<Pattern>,
    /// Named/keyword arguments: each entry must match the value of the
    /// keyword argument with that name.
    pub kwargs: Vec<(String, Pattern)>,
    pub left: Option<Box<Pattern>>,
    pub right: Option<Box<Pattern>>,
    pub module: Option<Box<Pattern>>,
    /// Each listed pattern must match some decorator/annotation.
    pub decorators: Vec<Pattern>,
    pub object: Option<Box<Pattern>>,
    pub field: Option<Box<Pattern>>,
    /// The expression a for-each loop iterates.
    pub iterable: Option<Box<Pattern>>,
    /// Each listed pattern must match some element of a collection literal;
    /// matches must appear in element order but need not be contiguous.
    pub elements: Vec<Pattern>,
    /// The tag expression of a JSX element.
    pub tag: Option<Box<Pattern>>,
    /// Named and spread JSX attributes in source order.
    pub attributes: Vec<Pattern>,
    /// Source children of a JSX element in source order.
    pub children: Vec<Pattern>,
    /// The exact value expression of an attribute or object property.
    pub value: Option<Box<Pattern>>,
    /// The static key of an object property.
    pub key: Option<Box<Pattern>>,
}

impl Pattern {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
            && self.not_kinds.is_empty()
            && self.name.is_none()
            && self.text.is_none()
            && self.boolean_value.is_none()
            && self.arity.is_none()
            && self.visibility.is_empty()
            && self.parameter_type.is_none()
            && self.capture.is_none()
            && self.has.is_none()
            && self.not_has.is_none()
            && !self.constrains_roles()
    }

    fn constrains_roles(&self) -> bool {
        Role::single_target_roles()
            .iter()
            .any(|&role| self.single_role_pattern(role).is_some())
            || Role::list_target_roles()
                .iter()
                .any(|&role| !self.list_role_patterns(role).is_empty())
            || !self.kwargs.is_empty()
    }

    pub fn single_role_pattern(&self, role: Role) -> Option<&Pattern> {
        match role {
            Role::Callee => self.callee.as_deref(),
            Role::Receiver => self.receiver.as_deref(),
            Role::Left => self.left.as_deref(),
            Role::Right => self.right.as_deref(),
            Role::Module => self.module.as_deref(),
            Role::Object => self.object.as_deref(),
            Role::Field => self.field.as_deref(),
            Role::Iterable => self.iterable.as_deref(),
            Role::Tag => self.tag.as_deref(),
            Role::Value => self.value.as_deref(),
            Role::Key => self.key.as_deref(),
            Role::Arg
            | Role::Kwarg
            | Role::Decorator
            | Role::Element
            | Role::Attributes
            | Role::Children => None,
        }
    }

    pub fn list_role_patterns(&self, role: Role) -> &[Pattern] {
        match role {
            Role::Arg => &self.args,
            Role::Decorator => &self.decorators,
            Role::Element => &self.elements,
            Role::Attributes => &self.attributes,
            Role::Children => &self.children,
            Role::Callee
            | Role::Receiver
            | Role::Kwarg
            | Role::Left
            | Role::Right
            | Role::Module
            | Role::Object
            | Role::Field
            | Role::Iterable
            | Role::Tag
            | Role::Value
            | Role::Key => &[],
        }
    }

    pub fn has_role_constraints(&self) -> bool {
        self.constrains_roles()
    }

    /// Whether this pattern or any nested sub-pattern filters on recorded
    /// callable visibility or parameter-type spellings.
    pub fn constrains_callable_signature(&self) -> bool {
        if !self.visibility.is_empty() || self.parameter_type.is_some() {
            return true;
        }
        if self
            .has
            .as_deref()
            .is_some_and(Self::constrains_callable_signature)
            || self
                .not_has
                .as_deref()
                .is_some_and(Self::constrains_callable_signature)
        {
            return true;
        }
        for &role in Role::single_target_roles() {
            if self
                .single_role_pattern(role)
                .is_some_and(Self::constrains_callable_signature)
            {
                return true;
            }
        }
        for &role in Role::list_target_roles() {
            if self
                .list_role_patterns(role)
                .iter()
                .any(Self::constrains_callable_signature)
            {
                return true;
            }
        }
        self.kwargs
            .iter()
            .any(|(_, pattern)| pattern.constrains_callable_signature())
    }

    /// Whether this pattern or any nested sub-pattern filters on the exact
    /// normalized value of a boolean literal.
    pub fn constrains_boolean_value(&self) -> bool {
        if self.boolean_value.is_some() {
            return true;
        }
        if self
            .has
            .as_deref()
            .is_some_and(Self::constrains_boolean_value)
            || self
                .not_has
                .as_deref()
                .is_some_and(Self::constrains_boolean_value)
        {
            return true;
        }
        for &role in Role::single_target_roles() {
            if self
                .single_role_pattern(role)
                .is_some_and(Self::constrains_boolean_value)
            {
                return true;
            }
        }
        for &role in Role::list_target_roles() {
            if self
                .list_role_patterns(role)
                .iter()
                .any(Self::constrains_boolean_value)
            {
                return true;
            }
        }
        self.kwargs
            .iter()
            .any(|(_, pattern)| pattern.constrains_boolean_value())
    }
}

/// A query rejection, carrying the JSON path of the offending field so
/// callers (especially agents) can self-correct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub path: String,
    pub message: String,
}

impl QueryError {
    pub(super) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "invalid query: {}", self.message)
        } else {
            write!(f, "invalid query at {}: {}", self.path, self.message)
        }
    }
}

impl std::error::Error for QueryError {}
