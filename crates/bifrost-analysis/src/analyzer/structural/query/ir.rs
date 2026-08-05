use super::super::analysis_context::{ProtocolRef, TaintResultRef, ValueFlowPlanRef};
use super::super::edges::{OwnerRelation, SiteClass};
use super::super::kinds::{NormalizedKind, Role};
use super::super::occurrences::{ALL_OCCURRENCE_ROLES, Namespace, OccurrenceClass, OccurrenceRole};
use super::super::resolution::{
    BindingKind, BoundaryStatus, CandidateOutcome, HoistingClass, PrecedenceTier, RejectionReason,
};
use super::schema::{CallTraversalCompleteness, CodeQueryExecutionMode, QueryStepOp};
use crate::analyzer::Language;
use crate::analyzer::usages::{ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof};
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
pub const SCHEMA_VERSION: u64 = 10;
pub const DECLARATION_CONTAINMENT_SCHEMA_VERSION: u64 = 5;
pub const OCCURRENCE_SCHEMA_VERSION: u64 = 8;
/// Lexical scope, binding and resolution-candidate rows with their seeds and
/// seven steps (#1474).
pub const RESOLUTION_SCHEMA_VERSION: u64 = 9;
/// Canonical reference-edge rows with their forward and inverse projection
/// steps (#1479). Referenced by transports and tests that pin the minimum
/// version the edge domain requires.
pub const REFERENCE_EDGE_SCHEMA_VERSION: u64 = 10;

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
    ReceiverAnalysis,
    Occurrence,
    LexicalScope,
    Binding,
    ResolutionCandidate,
    ReferenceEdge,
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
            Self::ReceiverAnalysis => "receiver_analysis",
            Self::Occurrence => "occurrence",
            Self::LexicalScope => "lexical_scope",
            Self::Binding => "binding",
            Self::ResolutionCandidate => "resolution_candidate",
            Self::ReferenceEdge => "reference_edge",
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

    pub fn matches(
        &self,
        row: &crate::analyzer::structural::reference_edges::ReferenceEdgeRow,
    ) -> bool {
        (self.reference_kinds.is_empty()
            || row
                .reference_kind
                .is_some_and(|kind| self.reference_kinds.contains(&kind)))
            && self.proof.is_none_or(|proof| row.proof == proof)
            && self.surface.is_none_or(|surface| row.included_in(surface))
            && (self.usage_kinds.is_empty() || self.usage_kinds.contains(&row.usage_kind))
            && (self.relations.is_empty() || self.relations.contains(&row.owner_relation))
            && (self.site_classes.is_empty() || self.site_classes.contains(&row.site_class))
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
    ReceiverTargets(ReceiverTraversalFilter),
    PointsTo(ReceiverTraversalFilter),
    MemberTargets(ReceiverTraversalFilter),
    OccurrencesOf(OccurrenceFilter),
    OccurrencesIn(OccurrenceFilter),
    OccurrenceTarget,
    ScopeOf,
    ScopeAncestors,
    BindingsIn(BindingFilter),
    ReachingBinding(ReachingBindingOptions),
    BindingOccurrence,
    CandidatesOf(CandidateFilter),
    CandidateTarget,
    EdgesOf(EdgeFilter),
    EdgesFrom(EdgeFilter),
    EdgeTarget,
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
/// filter: [`crate::analyzer::usages::get_definition::TraceCandidate::tier`] is
/// an `Option`, so "the seam could not name a tier" is a real answer an author
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

/// Options of the `reaching-binding` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReachingBindingOptions {
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

/// A non-structural seed producing binding rows directly from workspace facts.
#[derive(Debug, Clone, Default)]
pub struct BindingSeed {
    pub where_globs: Vec<glob::Pattern>,
    pub languages: Vec<Language>,
    pub filter: BindingFilter,
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
            Self::ReceiverTargets(_) => QueryStepOp::ReceiverTargets,
            Self::PointsTo(_) => QueryStepOp::PointsTo,
            Self::MemberTargets(_) => QueryStepOp::MemberTargets,
            Self::OccurrencesOf(_) => QueryStepOp::OccurrencesOf,
            Self::OccurrencesIn(_) => QueryStepOp::OccurrencesIn,
            Self::OccurrenceTarget => QueryStepOp::OccurrenceTarget,
            Self::ScopeOf => QueryStepOp::ScopeOf,
            Self::ScopeAncestors => QueryStepOp::ScopeAncestors,
            Self::BindingsIn(_) => QueryStepOp::BindingsIn,
            Self::ReachingBinding(_) => QueryStepOp::ReachingBinding,
            Self::BindingOccurrence => QueryStepOp::BindingOccurrence,
            Self::CandidatesOf(_) => QueryStepOp::CandidatesOf,
            Self::CandidateTarget => QueryStepOp::CandidateTarget,
            Self::EdgesOf(_) => QueryStepOp::EdgesOf,
            Self::EdgesFrom(_) => QueryStepOp::EdgesFrom,
            Self::EdgeTarget => QueryStepOp::EdgeTarget,
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
            QueryStepOp::ReceiverTargets => {
                Some(Self::ReceiverTargets(ReceiverTraversalFilter::default()))
            }
            QueryStepOp::PointsTo => Some(Self::PointsTo(ReceiverTraversalFilter::default())),
            QueryStepOp::MemberTargets => {
                Some(Self::MemberTargets(ReceiverTraversalFilter::default()))
            }
            QueryStepOp::OccurrencesOf => Some(Self::OccurrencesOf(OccurrenceFilter::default())),
            QueryStepOp::OccurrencesIn => Some(Self::OccurrencesIn(OccurrenceFilter::default())),
            QueryStepOp::OccurrenceTarget => Some(Self::OccurrenceTarget),
            QueryStepOp::ScopeOf => Some(Self::ScopeOf),
            QueryStepOp::ScopeAncestors => Some(Self::ScopeAncestors),
            QueryStepOp::BindingsIn => Some(Self::BindingsIn(BindingFilter::default())),
            QueryStepOp::ReachingBinding => {
                Some(Self::ReachingBinding(ReachingBindingOptions::default()))
            }
            QueryStepOp::BindingOccurrence => Some(Self::BindingOccurrence),
            QueryStepOp::CandidatesOf => Some(Self::CandidatesOf(CandidateFilter::default())),
            QueryStepOp::CandidateTarget => Some(Self::CandidateTarget),
            QueryStepOp::EdgesOf => Some(Self::EdgesOf(EdgeFilter::default())),
            QueryStepOp::EdgesFrom => Some(Self::EdgesFrom(EdgeFilter::default())),
            QueryStepOp::EdgeTarget => Some(Self::EdgeTarget),
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
                | QueryValueKind::ReceiverAnalysis
                | QueryValueKind::Occurrence
                | QueryValueKind::LexicalScope
                | QueryValueKind::Binding,
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
            (
                Self::ReceiverTargets(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::CallSite
                | QueryValueKind::ExpressionSite,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (
                Self::PointsTo(_),
                QueryValueKind::StructuralMatch
                | QueryValueKind::ReferenceSite
                | QueryValueKind::ExpressionSite,
            ) => Some(QueryValueKind::ReceiverAnalysis),
            (
                Self::MemberTargets(_),
                QueryValueKind::StructuralMatch | QueryValueKind::ReferenceSite,
            ) => Some(QueryValueKind::ReceiverAnalysis),
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
            (Self::ReachingBinding(_), QueryValueKind::Occurrence) => Some(QueryValueKind::Binding),
            (Self::BindingOccurrence, QueryValueKind::Binding) => Some(QueryValueKind::Occurrence),
            (Self::CandidatesOf(_), QueryValueKind::Occurrence) => {
                Some(QueryValueKind::ResolutionCandidate)
            }
            (Self::CandidateTarget, QueryValueKind::ResolutionCandidate) => {
                Some(QueryValueKind::Declaration)
            }
            (Self::EdgesOf(_), QueryValueKind::Declaration) => Some(QueryValueKind::ReferenceEdge),
            (Self::EdgesFrom(_), QueryValueKind::Occurrence) => Some(QueryValueKind::ReferenceEdge),
            (Self::EdgeTarget, QueryValueKind::ReferenceEdge) => Some(QueryValueKind::Declaration),
            _ => None,
        }
    }
}

pub(super) fn validate_query_steps(
    steps: &[QueryStep],
    input: QueryValueKind,
    path: &str,
    schema_version: u64,
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
        let minimum_schema_version = step.op().minimum_schema_version();
        if schema_version < minimum_schema_version {
            return Err(QueryError::new(
                format!("{step_path}.op"),
                format!(
                    "query step {} requires schema version {minimum_schema_version}, but this query uses schema version {schema_version}",
                    step.label()
                ),
            ));
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
                "structural_match, declaration, procedure, program_point, control_edge, typestate_finding, typestate_witness, flow_endpoint, flow_witness, taint_finding, reference_site, call_site, expression_site, receiver_analysis, occurrence, lexical_scope, or binding"
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
            QueryStep::ReceiverTargets(_) => {
                "structural_match, reference_site, call_site, or expression_site"
            }
            QueryStep::PointsTo(_) => "structural_match, reference_site, or expression_site",
            QueryStep::MemberTargets(_) => "structural_match or reference_site",
            QueryStep::OccurrencesOf(_) => "declaration",
            QueryStep::OccurrencesIn(_) => "structural_match or file",
            QueryStep::OccurrenceTarget => "occurrence",
            QueryStep::ScopeOf => "binding, occurrence, or structural_match",
            QueryStep::ScopeAncestors => "lexical_scope",
            QueryStep::BindingsIn(_) => "lexical_scope or structural_match",
            QueryStep::ReachingBinding(_) => "occurrence",
            QueryStep::BindingOccurrence => "binding",
            QueryStep::CandidatesOf(_) => "occurrence",
            QueryStep::CandidateTarget => "resolution_candidate",
            QueryStep::EdgesOf(_) => "declaration",
            QueryStep::EdgesFrom(_) => "occurrence",
            QueryStep::EdgeTarget => "reference_edge",
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

/// The source of values entering one typed pipeline suffix.
#[derive(Debug, Clone)]
pub enum CodeQueryPlanSource {
    Seed(Box<CodeQuerySeed>),
    Occurrences(Box<OccurrenceSeed>),
    Scopes(Box<ScopeSeed>),
    Bindings(Box<BindingSeed>),
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
            | CodeQueryPlanSource::Set { .. } => None,
        }
    }

    /// Validate the semantic pipeline independently of its JSON/RQL origin.
    /// Embedders may construct this public IR directly, so execution cannot
    /// rely solely on decoder validation.
    pub fn validate_steps(&self) -> Result<QueryValueKind, QueryError> {
        let mut nodes = 0;
        validate_plan(&self.plan, "", 0, &mut nodes, self.schema_version).map(|domain| domain.kind)
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
    schema_version: u64,
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
        CodeQueryPlanSource::Seed(seed) => {
            if seed.inside_decl.is_some() && schema_version < DECLARATION_CONTAINMENT_SCHEMA_VERSION
            {
                return Err(QueryError::new(
                    child_query_path(path, "inside_decl"),
                    format!(
                        "inside_decl requires schema version {DECLARATION_CONTAINMENT_SCHEMA_VERSION}, but this query uses schema version {schema_version}"
                    ),
                ));
            }
            ValidatedDomain {
                kind: QueryValueKind::StructuralMatch,
                captures: Some(seed.positive_capture_names()),
            }
        }
        CodeQueryPlanSource::Occurrences(_) => {
            if schema_version < OCCURRENCE_SCHEMA_VERSION {
                return Err(QueryError::new(
                    child_query_path(path, "occurrences"),
                    format!(
                        "the occurrences source requires schema version {OCCURRENCE_SCHEMA_VERSION}, but this query uses schema version {schema_version}"
                    ),
                ));
            }
            ValidatedDomain {
                kind: QueryValueKind::Occurrence,
                captures: None,
            }
        }
        CodeQueryPlanSource::Scopes(_) | CodeQueryPlanSource::Bindings(_) => {
            let (label, kind) = match &plan.source {
                CodeQueryPlanSource::Scopes(_) => ("scopes", QueryValueKind::LexicalScope),
                _ => ("bindings", QueryValueKind::Binding),
            };
            if schema_version < RESOLUTION_SCHEMA_VERSION {
                return Err(QueryError::new(
                    child_query_path(path, label),
                    format!(
                        "the {label} source requires schema version {RESOLUTION_SCHEMA_VERSION}, but this query uses schema version {schema_version}"
                    ),
                ));
            }
            ValidatedDomain {
                kind,
                captures: None,
            }
        }
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
                branch_domains.push(validate_plan(
                    branch,
                    &branch_path,
                    depth + 1,
                    nodes,
                    schema_version,
                )?);
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
    let output = validate_query_steps(&plan.steps, domain.kind, &steps_path, schema_version)?;
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
    pub(crate) fn exact_alternatives(&self) -> Option<Vec<String>> {
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
}

impl Pattern {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
            && self.not_kinds.is_empty()
            && self.name.is_none()
            && self.text.is_none()
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

    pub(crate) fn single_role_pattern(&self, role: Role) -> Option<&Pattern> {
        match role {
            Role::Callee => self.callee.as_deref(),
            Role::Receiver => self.receiver.as_deref(),
            Role::Left => self.left.as_deref(),
            Role::Right => self.right.as_deref(),
            Role::Module => self.module.as_deref(),
            Role::Object => self.object.as_deref(),
            Role::Field => self.field.as_deref(),
            Role::Arg | Role::Kwarg | Role::Decorator => None,
        }
    }

    pub(crate) fn list_role_patterns(&self, role: Role) -> &[Pattern] {
        match role {
            Role::Arg => &self.args,
            Role::Decorator => &self.decorators,
            Role::Callee
            | Role::Receiver
            | Role::Kwarg
            | Role::Left
            | Role::Right
            | Role::Module
            | Role::Object
            | Role::Field => &[],
        }
    }

    pub(crate) fn has_role_constraints(&self) -> bool {
        self.constrains_roles()
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
