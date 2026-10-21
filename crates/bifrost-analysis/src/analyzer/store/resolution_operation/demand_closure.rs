//! Request-local vocabulary for shared root closure (#5658).
//!
//! No frame, cursor, proof or staged context belongs on a retained selection.
//! Shared discovery, export proof reduction and publication surround the
//! named-route/member adapter, which remains until shared traversal adoption.
#![allow(dead_code)] // Migration seam: production adoption follows the all-halves reader.

use crate::analyzer::resolution::DemandReferenceKey;
use crate::analyzer::resolution::DemandRelationKey;

use super::demand::ClosedRelations;
use super::demand::DemandLanguage;
use super::demand::LanguageClosure;
use super::demand::LanguageContextPreparation;
use super::demand::LanguagePrefixInputs;
use super::demand::LanguageRootDiscovery;

use super::source_demand::SourceDemandKey;

use super::*;

use crate::analyzer::resolution::BatchCandidateRequest;
use crate::analyzer::resolution::DemandClosureDischarges;
use crate::analyzer::resolution::DemandMemberSelection;
use crate::analyzer::resolution::DemandMemberSelectionOutcome;
use crate::analyzer::resolution::DemandMemberSelectionRequest;
use crate::analyzer::resolution::DemandRootUnavailableReason;
use crate::analyzer::resolution::DemandSelectedOverlayBlueprint;
use crate::analyzer::resolution::EndpointSignature;
use crate::analyzer::resolution::FactResolutionAnswer;
use crate::analyzer::resolution::LoweredMemberScopeProperty;
use crate::analyzer::resolution::PrecedenceStep;
use crate::analyzer::resolution::SelectedContextPathSource;
use crate::analyzer::resolution::SelectedJvmBridgeEvidence;
use crate::analyzer::resolution::StackPattern;

/// Every added observation has its own independent differential counter.
#[derive(Clone, Copy, Debug)]
pub(super) enum CloserWork {
    Definition,
    HydratedPath,
    Recipe,
    CompletionPacking,
    CompletionRewrite,
    Bridge,
    GeneratedPath,
    GeneratedHalf,
    Declaration,
    CoverageBranch,
    BlockedExport,
    ExportProof,
    ClassifiedDefinition,
    BridgeTarget,
    CandidateAuthority,
    DescriptorEvidence,
    InventoryDescriptor,
    InventoryReason,
    ContinuationPublication,
    AssociationPublication,
    CandidateClassification,
    PrefixAnswer,
    ContextInventoryReason,
    CandidateNode,
}
#[doc(hidden)]
pub const CLOSER_WORK_KINDS: usize = 24;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const CLOSER_WORK_LABELS: [&str; CLOSER_WORK_KINDS] = [
    "Definition",
    "HydratedPath",
    "Recipe",
    "CompletionPacking",
    "CompletionRewrite",
    "Bridge",
    "GeneratedPath",
    "GeneratedHalf",
    "Declaration",
    "CoverageBranch",
    "BlockedExport",
    "ExportProof",
    "ClassifiedDefinition",
    "BridgeTarget",
    "CandidateAuthority",
    "DescriptorEvidence",
    "InventoryDescriptor",
    "InventoryReason",
    "ContinuationPublication",
    "AssociationPublication",
    "CandidateClassification",
    "PrefixAnswer",
    "ContextInventoryReason",
    "CandidateNode",
];

pub(super) fn closer_step(
    session: &ResolutionSession,
    cancellation: &CancellationToken,
    work: CloserWork,
) -> bool {
    let _ = work;
    !cancellation.is_cancelled() && session.scope_step()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct HalfId(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct PlacementId(pub usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ContextId(pub usize);
pub(super) use crate::analyzer::resolution::EnvironmentId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ProofId(pub usize);

#[doc(hidden)]
pub struct RootFrame {
    pub(super) endpoint: EndpointSignature,
    pub(super) sources: Box<[RootSource]>,
    pub(super) halves: Vec<SelectedRootPathHalf>,
    pub(super) context: Option<ContextId>,
    pub(super) operands: Box<[PrefixOperand]>,
    pub(super) resolved_prefixes: Vec<ResolvedPrefixOperand>,
    pub(super) completion: ResolutionCompletion,
}

impl RootFrame {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(
        endpoint: EndpointSignature,
        sources: Box<[RootSource]>,
        halves: Vec<SelectedRootPathHalf>,
        context: Option<ContextId>,
        operands: Box<[PrefixOperand]>,
        resolved_prefixes: Vec<ResolvedPrefixOperand>,
        completion: ResolutionCompletion,
    ) -> Self {
        Self {
            endpoint,
            sources,
            halves,
            context,
            operands,
            resolved_prefixes,
            completion,
        }
    }
}

#[doc(hidden)]
pub enum RootSource {
    Positioned { key: SourceDemandKey, half: HalfId },
    Context(ContextId),
}

pub(super) use crate::analyzer::resolution::DemandReferenceKey as PrefixKey;

#[derive(Clone)]
#[doc(hidden)]
pub struct PrefixOperand {
    pub key: PrefixKey,
    pub source_halves: Box<[HalfId]>,
}

#[doc(hidden)]
pub struct PrefixAnswer<'a> {
    pub key: PrefixKey,
    pub answer: &'a FactResolutionAnswer,
}
/// An owned answer from an admitted operand's source envelope, without a
/// scheduler task. Both incidence and original answer metadata are retained.
#[doc(hidden)]
pub struct ResolvedPrefixOperand {
    pub operand: PrefixOperand,
    pub answer: FactResolutionAnswer,
}
#[doc(hidden)]
pub struct PrefixAnswers<'a> {
    pub entries: &'a [PrefixAnswer<'a>],
}

#[doc(hidden)]
pub struct RouteCursor {
    pub half: HalfId,
    pub placement: PlacementId,
    pub location: RouteLocation,
    /// Index into the original route; bridge construction keeps that route intact.
    pub consumed_prefix_segments: usize,
    pub namespace: ResolutionNamespace,
    pub proof: ProofId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[doc(hidden)]
pub enum RouteLocation {
    /// The selected unit and its stored container key. This key comes from
    /// relational rows, never from parsing a rendered source path.
    Container { unit: i64, container: String },
    Owner {
        definition: SemanticId,
        scope: Option<BindingNodeId>,
    },
}

/// A route walk carries only its caller's identity, never a root frame.
#[derive(Clone)]
#[doc(hidden)]
pub struct WalkCursor<T> {
    pub tag: T,
    pub location: RouteLocation,
    pub consumed_prefix_segments: usize,
    /// Original-route index at which this start first reads a segment.
    pub start_step: usize,
    pub namespace: ResolutionNamespace,
}

impl<T> WalkCursor<T> {
    pub fn container(tag: T, unit: i64, container: String, consumed: usize) -> Self {
        Self {
            tag,
            location: RouteLocation::Container { unit, container },
            consumed_prefix_segments: consumed,
            start_step: consumed,
            namespace: ResolutionNamespace::Type,
        }
    }
}

impl From<RouteCursor> for WalkCursor<(HalfId, PlacementId, ProofId)> {
    fn from(cursor: RouteCursor) -> Self {
        Self {
            tag: (cursor.half, cursor.placement, cursor.proof),
            start_step: cursor.consumed_prefix_segments,
            consumed_prefix_segments: cursor.consumed_prefix_segments,
            location: cursor.location,
            namespace: cursor.namespace,
        }
    }
}

#[doc(hidden)]
pub struct RouteStarts {
    pub locations: Vec<RouteLocation>,
    /// An anchor rule may consume an absolute head before ordinary traversal.
    pub consumed: usize,
}

/// One rank's evidence is retained even if its authoritative exact set is empty.
#[doc(hidden)]
pub struct RouteEdgeTier {
    pub edges: Vec<RouteLocation>,
    pub coverage: ResolutionCompletion,
    pub blockers: ResolutionCompletion,
    /// Independent alternatives continue to the next tier even when they bind.
    pub independent: bool,
    pub blocks_fallback: bool,
}
impl Default for RouteEdgeTier {
    fn default() -> Self {
        Self {
            edges: Vec::new(),
            coverage: ResolutionCompletion::Complete,
            blockers: ResolutionCompletion::Complete,
            independent: false,
            blocks_fallback: false,
        }
    }
}

/// Permanent frame-free route seam. Each caller supplies its request context
/// through the rules value: demand uses its frame, half, selected contexts and
/// prefix answers; eager traversal uses its requesting module and route.
/// The shared walker never sees a RootFrame and owns step scheduling, tier
/// selection and cursor deduplication. Rules read rows and classify evidence.
#[doc(hidden)]
pub trait RouteRules<T: Clone + Eq + std::hash::Hash> {
    fn root_starts(
        &self,
        start: &WalkCursor<T>,
        completion: &mut ResolutionCompletion,
    ) -> Result<RouteStarts>;
    fn route_tier(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
        tier: usize,
    ) -> Result<Option<RouteEdgeTier>>;
    fn dead_end(
        &self,
        cursor: &WalkCursor<T>,
        segment: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion>;
}

pub(super) fn walk_residual_route<T: Clone + Eq + std::hash::Hash>(
    rules: &impl RouteRules<T>,
    start: WalkCursor<T>,
    route: &[ResolutionLookupSemanticRecipe],
    completion: &mut ResolutionCompletion,
    cancellation: &CancellationToken,
) -> Result<Vec<WalkCursor<T>>> {
    let starts = rules.root_starts(&start, completion)?;
    let mut frontier = starts
        .locations
        .into_iter()
        .map(|location| WalkCursor {
            location,
            consumed_prefix_segments: start.consumed_prefix_segments + starts.consumed,
            ..start.clone()
        })
        .collect::<Vec<_>>();
    let mut reached = Vec::new();
    while !frontier.is_empty() {
        // Stable sorting preserves caller provenance at equal locations. The
        // cursor dedup identity remains independent of this visitation order.
        frontier.sort_by(|left, right| left.location.cmp(&right.location));
        let mut next = Vec::new();
        let mut seen = HashSet::default();
        for cursor in frontier {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let Some(segment) = route.get(cursor.consumed_prefix_segments) else {
                reached.push(cursor);
                continue;
            };
            let mut bound = false;
            let mut rank = 0;
            while let Some(tier) = rules.route_tier(&cursor, segment, rank)? {
                *completion = completion.combine(&tier.coverage).combine(&tier.blockers);
                let binding = !tier.edges.is_empty();
                for location in tier.edges {
                    // Dedup within a step only. Distinct start-step provenance
                    // must survive convergence until first-step rules expire.
                    let key = (
                        location.clone(),
                        cursor.consumed_prefix_segments + 1,
                        cursor.start_step,
                        cursor.tag.clone(),
                        cursor.namespace,
                    );
                    if seen.insert(key) {
                        next.push(WalkCursor {
                            location,
                            consumed_prefix_segments: cursor.consumed_prefix_segments + 1,
                            ..cursor.clone()
                        });
                    }
                }
                bound |= binding;
                if tier.blocks_fallback || (binding && !tier.independent) {
                    break;
                }
                rank += 1;
            }
            if !bound {
                *completion = completion.combine(&rules.dead_end(&cursor, segment)?);
            }
        }
        frontier = next;
    }
    Ok(reached)
}

pub(super) fn walk_container_route<T: Clone + Eq + std::hash::Hash>(
    rules: &impl RouteRules<T>,
    start: WalkCursor<T>,
    route: &[ResolutionLookupSemanticRecipe],
    completion: &mut ResolutionCompletion,
    cancellation: &CancellationToken,
) -> Result<Vec<(i64, String)>> {
    Ok(
        walk_residual_route(rules, start, route, completion, cancellation)?
            .into_iter()
            .map(|cursor| match cursor.location {
                RouteLocation::Container { unit, container } => (unit, container),
                RouteLocation::Owner { .. } => unreachable!("module route returns containers"),
            })
            .collect(),
    )
}

pub(super) struct LexicalRouteStarts {
    pub locations: Vec<(i64, String)>,
    pub scopes: Vec<u32>,
    pub blocks_fallback: bool,
}

/// Certified bindings have already selected their equal alternatives. An open
/// exact set blocks an outer level just as a binding does, even with no edges.
pub(super) fn select_lexical_route_starts(
    start: ResolutionScopeId,
    mut parent: impl FnMut(ResolutionScopeId) -> Result<Option<ResolutionScopeId>>,
    mut read: impl FnMut(ResolutionScopeId) -> Result<RouteEdgeTier>,
    completion: &mut ResolutionCompletion,
    cancellation: &CancellationToken,
) -> Result<LexicalRouteStarts> {
    let mut result = LexicalRouteStarts {
        locations: Vec::new(),
        scopes: Vec::new(),
        blocks_fallback: false,
    };
    let mut scope = Some(start);
    let mut seen = HashSet::default();
    while let Some(level) = scope {
        if cancellation.is_cancelled() {
            break;
        }
        assert!(
            seen.insert(level),
            "cyclic lexical lookup parents: {:?}",
            result.scopes
        );
        result.scopes.push(level.get());
        let tier = read(level)?;
        *completion = completion.combine(&tier.coverage).combine(&tier.blockers);
        let binding = !tier.edges.is_empty();
        result
            .locations
            .extend(tier.edges.into_iter().map(|location| match location {
                RouteLocation::Container { unit, container } => (unit, container),
                RouteLocation::Owner { .. } => unreachable!("module start names a container"),
            }));
        if binding || tier.blocks_fallback {
            result.blocks_fallback = true;
            break;
        }
        scope = parent(level)?;
    }
    Ok(result)
}

/// A declaration already proven by the language's selected-member reader.
/// It has no canonical root-export path identity.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct SelectedMemberTarget {
    pub fragment: BindingFragmentId,
    pub token: SemanticId,
    pub definition: BindingNodeId,
    pub lookup: ResolutionLookupSemanticRecipe,
    pub completion: ResolutionCompletion,
}

#[derive(Clone, Debug)]
pub(super) enum CandidateTarget {
    Export(SelectedRootPathHalf),
    Member(SelectedMemberTarget),
}

#[doc(hidden)]
pub struct ExportCandidate {
    target: CandidateTarget,
    #[doc(hidden)]
    pub authority: TargetAuthority,
    pub lookup: ResolutionLookupSemanticRecipe,
    pub proof: ProofId,
    pub definition: SemanticId,
    pub admission: crate::analyzer::resolution::BindingCandidateAdmission,
}
impl ExportCandidate {
    pub fn new(
        half: SelectedRootPathHalf,
        lookup: ResolutionLookupSemanticRecipe,
        proof: ProofId,
        definition: SemanticId,
    ) -> Self {
        let SelectedRootPathHalf::Export {
            identity,
            token,
            demand,
            definition: node,
            ..
        } = &half
        else {
            panic!("an export candidate requires canonical export authority: {half:?}");
        };
        let authority = TargetAuthority::Export(ExportAuthority {
            fragment: identity.fragment(),
            token: *token,
            demand: *demand,
            definition: *node,
        });
        Self {
            target: CandidateTarget::Export(half),
            authority,
            lookup,
            proof,
            definition,
            admission: crate::analyzer::resolution::BindingCandidateAdmission::Target,
        }
    }
    pub fn authority(&self) -> TargetAuthority {
        self.authority
    }
}

#[doc(hidden)]
pub enum CandidateDecision {
    Admit,
    Reject,
    Open(ResolutionCompletion),
}

/// The sealed export authority, independent of the installed path that proved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct ExportAuthority {
    pub fragment: BindingFragmentId,
    pub token: SemanticId,
    pub demand: SemanticId,
    pub definition: BindingNodeId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum TargetAuthority {
    Export(ExportAuthority),
    Member {
        fragment: BindingFragmentId,
        token: SemanticId,
        demand: SemanticId,
        definition: BindingNodeId,
    },
}
impl TargetAuthority {
    fn definition(self) -> BindingNodeId {
        match self {
            Self::Export(authority) => authority.definition,
            Self::Member { definition, .. } => definition,
        }
    }
}
impl std::hash::Hash for TargetAuthority {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            // Preserve existing export-group iteration and descriptor order.
            Self::Export(authority) => authority.hash(state),
            Self::Member {
                fragment,
                token,
                demand,
                definition,
            } => {
                "selected-member".hash(state);
                (fragment, token, demand, definition).hash(state);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum EvidenceOwner {
    Discovery,
    Source(HalfId),
    Inventory(HalfId),
    Placement(HalfId, PlacementId),
    Candidate(HalfId, TargetAuthority),
    Context(ContextId),
    ExportBranch(HalfId, PlacementId, BindingNodeId),
}
#[doc(hidden)]
pub struct Proof {
    pub owner: EvidenceOwner,
    /// AND dependencies. Proofs are appended after their prerequisites.
    pub required: Box<[ProofId]>,
    pub local: ResolutionCompletion,
}
#[doc(hidden)]
pub struct AuthorityProofs {
    pub owner: EvidenceOwner,
    /// OR alternatives for exactly this authority. Empty never proves absence.
    pub alternatives: Box<[ProofId]>,
}
#[derive(Default)]
#[doc(hidden)]
pub struct ProofFacts {
    pub proofs: Vec<Proof>,
    pub authorities: Vec<AuthorityProofs>,
}

impl ProofFacts {
    pub fn push(
        &mut self,
        owner: EvidenceOwner,
        local: ResolutionCompletion,
        required: Box<[ProofId]>,
    ) -> ProofId {
        let id = ProofId(self.proofs.len());
        assert!(required.iter().all(|prerequisite| prerequisite.0 < id.0));
        self.proofs.push(Proof {
            owner,
            local,
            required,
        });
        id
    }
}

/// The exact selected reader used for the shared scope batch and the half's
/// provenance queries. Reconstructing readers inside a hook would reset its
/// query-local validation and catalog memos.
#[doc(hidden)]
pub trait HalfSource {
    fn semantic_provenance(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<crate::analyzer::resolution::SelectedSemanticProvenance>>;
    fn node_is_scope_head_in(
        &self,
        scopes: &crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        node: BindingNodeId,
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
    ) -> bool;
}
impl HalfSource
    for crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource<'_, '_>
{
    fn semantic_provenance(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> Result<Option<crate::analyzer::resolution::SelectedSemanticProvenance>> {
        self.semantic_provenance(semantic, cancellation)
    }
    fn node_is_scope_head_in(
        &self,
        scopes: &crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        node: BindingNodeId,
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
    ) -> bool {
        self.node_is_scope_head_in(scopes, node, fragment, scope)
    }
}

pub(super) type ClosureTag = (HalfId, PlacementId, ProofId);

#[doc(hidden)]
pub struct SourceHalf {
    pub identity: CandidatePathIdentity,
    pub scope: BindingNodeId,
    pub token: SemanticId,
    pub demand: ResolutionLookupSemanticRecipe,
    pub route: Vec<ResolutionLookupSemanticRecipe>,
    pub anchor: ResolutionRootImportAnchor,
    pub anchor_semantic: SemanticId,
    pub prefix: Option<SemanticId>,
    pub prefix_scope_head: Option<BindingNodeId>,
    pub is_import: bool,
}

#[doc(hidden)]
pub struct PlacementFacts<T> {
    pub tag: ClosureTag,
    pub completion: ResolutionCompletion,
    pub targets: Vec<T>,
    pub members: Vec<SelectedRootBridgeDescriptor>,
}

#[doc(hidden)]
pub enum PlacementStart<M> {
    Route {
        cursor: WalkCursor<ClosureTag>,
        anchor: ResolutionRootImportAnchor,
    },
    Member(M),
}

/// A language may select a lexical head that is itself a one-step route.
/// The shared closer resolves it before asking for its residual starts.
#[doc(hidden)]
pub struct LexicalStartRequest {
    pub scope: ResolutionScopeId,
    pub lookup: ResolutionLookupSemanticRecipe,
}
#[doc(hidden)]
pub struct LexicalStartTier {
    pub tier: RouteEdgeTier,
    pub head: Option<(RouteLocation, ResolutionLookupSemanticRecipe)>,
}
#[doc(hidden)]
pub struct StartSelection {
    pub lexical: Option<LexicalStartRequest>,
    pub locations: Vec<RouteLocation>,
    pub scopes: Vec<u32>,
    pub blocks_fallback: bool,
    pub head: Option<ResolutionLookupSemanticRecipe>,
}
impl From<LexicalRouteStarts> for StartSelection {
    fn from(starts: LexicalRouteStarts) -> Self {
        Self {
            lexical: None,
            locations: starts
                .locations
                .into_iter()
                .map(|(unit, container)| RouteLocation::Container { unit, container })
                .collect(),
            scopes: starts.scopes,
            blocks_fallback: starts.blocks_fallback,
            head: None,
        }
    }
}
impl StartSelection {
    pub fn into_containers(self) -> impl Iterator<Item = (i64, String)> {
        self.locations.into_iter().map(|location| match location {
            RouteLocation::Container { unit, container } => (unit, container),
            RouteLocation::Owner { .. } => unreachable!("container rule selected an owner"),
        })
    }
}

/// All placements contribute to one source-half boundary decision. Losing
/// alternatives never turn an unasked placement into a negative witness.
#[doc(hidden)]
pub struct HalfObservation {
    pub completion: ResolutionCompletion,
    pub answered_placements: Vec<PlacementId>,
    pub reached: Vec<RouteLocation>,
    pub route_reached_a_target: bool,
}

#[doc(hidden)]
pub struct PlacementObservation {
    pub placement: PlacementId,
    pub completion: ResolutionCompletion,
    pub reached: Box<[RouteLocation]>,
}

#[doc(hidden)]
pub struct HalfBoundary {
    pub completion: ResolutionCompletion,
    pub associations: Vec<ContextAssociation>,
}

#[doc(hidden)]
pub struct EmptyHalf;
impl RouteRules<ClosureTag> for EmptyHalf {
    fn root_starts(
        &self,
        _: &WalkCursor<ClosureTag>,
        _: &mut ResolutionCompletion,
    ) -> Result<RouteStarts> {
        unreachable!()
    }
    fn route_tier(
        &self,
        _: &WalkCursor<ClosureTag>,
        _: &ResolutionLookupSemanticRecipe,
        _: usize,
    ) -> Result<Option<RouteEdgeTier>> {
        unreachable!()
    }
    fn dead_end(
        &self,
        _: &WalkCursor<ClosureTag>,
        _: &ResolutionLookupSemanticRecipe,
    ) -> Result<ResolutionCompletion> {
        unreachable!()
    }
}

/// Row reads and language decisions for one decoded source half. This value
/// lives for this close only. Shared code owns every placement, route and proof
/// loop; a hook cannot publish or register a relation.
#[doc(hidden)]
pub trait HalfRules {
    type Placement;
    type Target: Clone;
    type Member;
    fn prefix_has_targets(&self) -> bool {
        false
    }
    fn language(&self) -> Language {
        unreachable!()
    }
    fn placements(&mut self) -> Vec<Self::Placement> {
        unreachable!()
    }
    fn initial_completion(&self) -> ResolutionCompletion {
        ResolutionCompletion::Complete
    }
    fn placement(
        &self,
        _: &Self::Placement,
        _: ClosureTag,
    ) -> Option<PlacementFacts<Self::Target>> {
        unreachable!()
    }
    fn root_starts(
        &mut self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Vec<PlacementStart<Self::Member>>> {
        unreachable!()
    }
    fn route_rules<'a>(
        &'a self,
        _: &'a Self::Placement,
        _: ResolutionRootImportAnchor,
        _: &'a [ResolutionLookupSemanticRecipe],
    ) -> impl RouteRules<ClosureTag> + 'a {
        EmptyHalf
    }
    fn route_target(&self, _: RouteLocation) -> Self::Target {
        unreachable!()
    }
    fn member_bridges(
        &self,
        _: &Self::Placement,
        _: Self::Member,
        _: &ResolutionCompletion,
    ) -> Result<Vec<SelectedRootBridgeDescriptor>> {
        unreachable!()
    }
    fn prefix_selection(
        &mut self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<StartSelection>> {
        Ok(None)
    }
    fn prefix_starts(
        &mut self,
        _: &Self::Placement,
        _: StartSelection,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Vec<PlacementStart<Self::Member>>> {
        unreachable!()
    }
    fn import_targets(
        &mut self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<bool>> {
        Ok(Some(true))
    }
    fn canonical_targets(
        &self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<Vec<Self::Target>>> {
        Ok(None)
    }
    fn module_starts(
        &self,
        _: &Self::Placement,
        _: &PlacementFacts<Self::Target>,
    ) -> Vec<PlacementStart<Self::Member>> {
        Vec::new()
    }
    fn lexical_parent(
        &self,
        _: &Self::Placement,
        _: ResolutionScopeId,
    ) -> Result<Option<ResolutionScopeId>> {
        unreachable!("lexical starts require lookup ancestry")
    }
    fn lexical_tier(
        &self,
        _: &Self::Placement,
        _: ResolutionScopeId,
        _: &ResolutionLookupSemanticRecipe,
    ) -> Result<LexicalStartTier> {
        unreachable!("lexical starts require binding tiers")
    }
    fn lexical_selection(
        &self,
        _: &Self::Placement,
        _: &mut PlacementFacts<Self::Target>,
    ) -> Result<Option<StartSelection>> {
        Ok(None)
    }
    fn lexical_starts(
        &self,
        _: StartSelection,
        _: &PlacementFacts<Self::Target>,
    ) -> Vec<PlacementStart<Self::Member>> {
        unreachable!()
    }
    fn observe_targets(
        &mut self,
        _: &Self::Placement,
        _: &PlacementFacts<Self::Target>,
    ) -> Result<()> {
        Ok(())
    }
    fn select_targets(&self, _: &mut Vec<Self::Target>) -> Result<()> {
        Ok(())
    }
    fn target_location(&self, _: &Self::Target) -> RouteLocation {
        unreachable!()
    }
    fn exports(
        &self,
        _: &Self::Placement,
        _: Self::Target,
        _: &ResolutionCompletion,
    ) -> Result<Option<ExportHydration>> {
        unreachable!()
    }
    fn empty_target(&self, _: &Self::Placement, _: &Self::Target) -> Result<ResolutionCompletion> {
        unreachable!()
    }
    fn empty_placement(
        &mut self,
        _: &PlacementFacts<Self::Target>,
        _: &mut HalfObservation,
    ) -> Result<()> {
        Ok(())
    }
    fn boundary(&mut self, observation: &HalfObservation) -> Result<Option<HalfBoundary>> {
        Ok(Some(HalfBoundary {
            completion: observation.completion.clone(),
            associations: Vec::new(),
        }))
    }
}
impl HalfRules for EmptyHalf {
    type Placement = ();
    type Target = ();
    type Member = ();
}

#[doc(hidden)]
pub struct ClosureFacts<'a> {
    pub witness: &'a ClosureWitness,
    pub members: Option<&'a DemandMemberSelection>,
    pub generated: &'a [(CandidatePathIdentity, SourceDemandKey)],
    pub associations: &'a [ContextAssociation],
    pub prefixes: PrefixAnswers<'a>,
    pub halves: &'a [HalfClosureFacts],
    /// Namespace-classified exports, including precedence blockers, after authority grouping.
    pub candidates: &'a [ExportCandidate],
    pub context: Option<ContextId>,
    pub evidence: &'a ProofFacts,
}
#[doc(hidden)]
pub struct HalfClosureFacts {
    pub placements: Box<[PlacementObservation]>,
    pub completion: ResolutionCompletion,
    pub selected_targets: BTreeSet<SemanticId>,
    pub prefix_has_targets: bool,
    pub deferred_member_selection: bool,
    pub half: HalfId,
    pub answered_placements: Box<[PlacementId]>,
    pub reached: Box<[RouteLocation]>,
    pub accepted: Box<[TargetAuthority]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum BaseEligibility {
    Retain,
    Exclude,
}
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum ResultAuthority<'a> {
    Open,
    SelectedTargets(&'a BTreeSet<SemanticId>),
    AuthoritativeEmpty,
}

#[derive(Clone)]
#[doc(hidden)]
pub enum ContextAssociation {
    ExternalTypeImport {
        boundary: SemanticId,
        paths: Vec<Vec<String>>,
    },
    PreludeReference {
        reference: SemanticId,
        boundary: SemanticId,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RouteDisposition {
    Publish,
    RetainBase,
    /// Closed and incomplete, without publishing an inventory claim.
    ClosedIncomplete,
}

/// Readiness of a provider-backed root, before any half is closed.
#[allow(clippy::large_enum_variant)] // The temporary closed stage stays request-owned and inline.
#[doc(hidden)]
pub enum ProviderPreparation<K> {
    /// Temporary adoption seam: retires in J3. J3 is not complete while any
    /// language returns Closed. The hook stages rows and never publishes;
    /// witness, policy, registration and publication stay in publish_closure.
    Closed(Read<StagedClosure>),
    Prepared {
        key: K,
        completion: ResolutionCompletion,
    },
    Rows {
        mount: SelectedResolutionMountOrdinal,
    },
    Unavailable(ResolutionCompletion),
}

/// Request-owned inputs computed before registration and arena publication.
/// A base-ready root has no preparation; a publishing root has exactly one.
#[doc(hidden)]
pub enum StagedPreparation {
    Prepared(SelectedResolutionContextSet),
    Registered(SelectedFactOperationBlueprint),
}

#[doc(hidden)]
pub struct StagedClosure {
    pub disposition: RouteDisposition,
    pub base: BaseEligibility,
    pub completion: ResolutionCompletion,
    pub members: Option<DemandMemberSelection>,
    pub targets: Vec<TargetAuthority>,
    pub bridges: Vec<SelectedRootBridgeDescriptor>,
    pub witness: ClosureWitness,
    pub discharges: Option<DemandClosureDischarges>,
    pub preparation: Option<StagedPreparation>,
    pub endpoint_completion: Option<ResolutionCompletion>,
}

/// Truthful provider rows. The language owns production and readiness; the
/// closer owns placement proofs, authority grouping and bridge publication.
#[doc(hidden)]
pub struct ProviderRows {
    pub language: Language,
    pub exports: Vec<SelectedRootPathHalf>,
    pub recipe: ResolutionLookupSemanticRecipe,
    pub binding: ResolutionCompletion,
    pub context_completion: ResolutionCompletion,
    pub witness: bool,
    pub completion: ResolutionCompletion,
}

pub(super) struct RouteClosure<K = ()> {
    pub staged: Option<StagedClosure>,
    pub disposition: RouteDisposition,
    pub preparation: Option<K>,
    pub halves: Vec<HalfClosureFacts>,
    pub candidates: Vec<ExportCandidate>,
    pub evidence: ProofFacts,
    /// Operation-wide source evidence is never reduced with losing alternatives.
    pub completion: ResolutionCompletion,
    pub bridges: Vec<SelectedRootBridgeDescriptor>,
    pub associations: Vec<ContextAssociation>,
}

#[doc(hidden)]
pub struct ClosurePolicy {
    pub associations: Vec<ContextAssociation>,
    pub completion: ResolutionCompletion,
    pub base: BaseEligibility,
    // One canonical authority, carried by the existing scheduler discharge type.
    discharges: Option<DemandClosureDischarges>,
    pub generated: Box<[GeneratedContinuation]>,
}
impl ClosurePolicy {
    pub fn new(
        completion: ResolutionCompletion,
        base: BaseEligibility,
        discharges: DemandClosureDischarges,
        generated: Box<[GeneratedContinuation]>,
    ) -> Self {
        assert!(
            !discharges.authoritative_empty_result
                || discharges
                    .selected_targets
                    .as_ref()
                    .is_some_and(BTreeSet::is_empty)
        );
        assert!(
            discharges
                .selected_targets
                .as_ref()
                .is_none_or(|targets| !targets.is_empty() || discharges.authoritative_empty_result)
        );
        Self {
            associations: Vec::new(),
            completion,
            base,
            discharges: (discharges != DemandClosureDischarges::default()).then_some(discharges),
            generated,
        }
    }
    pub fn authority(&self) -> ResultAuthority<'_> {
        let Some(discharges) = &self.discharges else {
            return ResultAuthority::Open;
        };
        if discharges.authoritative_empty_result {
            ResultAuthority::AuthoritativeEmpty
        } else if let Some(targets) = &discharges.selected_targets {
            ResultAuthority::SelectedTargets(targets)
        } else {
            ResultAuthority::Open
        }
    }
    /// Presence is observable: an empty record still selects scheduler route refinement.
    pub fn preserve_discharge_record(&mut self) {
        self.discharges.get_or_insert_with(Default::default);
    }
    pub fn into_discharges(self) -> Option<DemandClosureDischarges> {
        self.discharges
    }
}
#[doc(hidden)]
pub struct GeneratedContinuation {
    pub candidate: CandidatePathIdentity,
    pub source: SourceDemandKey,
    pub base: BaseEligibility,
}

#[allow(clippy::large_enum_variant)] // Source-owned frames stay inline with the provider root.
#[doc(hidden)]
pub enum Admission {
    BaseOwned {
        completion: ResolutionCompletion,
        base: BaseEligibility,
    },
    SourceOwned(RootFrame),
    Unavailable {
        reason: DemandRootUnavailableReason,
        completion: ResolutionCompletion,
    },
}
#[doc(hidden)]
pub enum Read<T> {
    Ready {
        value: T,
        completion: ResolutionCompletion,
    },
    Unavailable {
        reason: DemandRootUnavailableReason,
        completion: ResolutionCompletion,
    },
    Cancelled(ResolutionCompletion),
}
impl<T> Read<T> {
    #[doc(hidden)]
    pub fn ready(value: T) -> Self {
        Self::Ready {
            value,
            completion: ResolutionCompletion::Complete,
        }
    }
}

#[allow(clippy::large_enum_variant)] // Keep source-owned admission frames inline.
#[doc(hidden)]
pub enum EndpointAdmission {
    Ready(ResolutionCompletion),
    Discover,
    Context(Admission),
}
#[doc(hidden)]
pub enum SourceScope {
    Unrestricted,
    /// Follow the source-provenance horizon as new mounts are demanded.
    DemandedMounts,
    Mounts(Box<[SelectedResolutionMountOrdinal]>),
    Cancelled(ResolutionCompletion),
}
/// Language decisions only. No hook owns a worklist, registration or publication.
/// Context derivation stages private data; it does not publish candidate cells.
#[doc(hidden)]
pub trait PublicationCertificate {
    /// Commit request evidence only; no derivation, cancellation or arena writes.
    fn publish(self);
}
impl PublicationCertificate for () {
    fn publish(self) {}
}

#[doc(hidden)]
pub struct PublicationMaterial<C> {
    pub registration: SelectedFactOperationBlueprint,
    pub certificate: Option<C>,
}

#[derive(Default)]
#[doc(hidden)]
pub struct ClosureWitness {
    pub discharged_provider_reasons: BTreeSet<SemanticId>,
    pub positive_binding_providers: BTreeMap<SemanticId, BTreeSet<SemanticId>>,
}
impl ClosureWitness {
    fn retain_read(read: Read<Self>, evidence: &mut ResolutionCompletion) -> Option<Self> {
        match read {
            Read::Ready { value, completion } => {
                *evidence = evidence.combine(&completion);
                Some(value)
            }
            Read::Unavailable { completion, .. } | Read::Cancelled(completion) => {
                *evidence = evidence.combine(&completion);
                None
            }
        }
    }
}
#[doc(hidden)]
pub struct BridgeMaterial {
    pub source_language: Language,
    pub target_language: Language,
    pub precedence: Option<PrecedenceStep>,
    pub candidate_origin_rank: Option<u32>,
    pub target_definition: Option<BindingNodeId>,
    pub cross_language_evidence: Option<SelectedJvmBridgeEvidence>,
}
impl BridgeMaterial {
    pub fn same_language(language: Language) -> Self {
        Self {
            source_language: language,
            target_language: language,
            precedence: None,
            candidate_origin_rank: None,
            target_definition: None,
            cross_language_evidence: None,
        }
    }
}
#[doc(hidden)]
pub struct PublicationDelta {
    pub relation: DemandSelectedOverlayBlueprint,
    pub paths: Vec<(CandidatePathIdentity, PartialPath)>,
}

#[doc(hidden)]
pub trait DemandRules {
    fn closure_witness(
        &mut self,
        _frame: &RootFrame,
        _prefixes: &PrefixAnswers<'_>,
        _members: Option<&DemandMemberSelection>,
    ) -> Result<Read<ClosureWitness>> {
        Ok(Read::ready(ClosureWitness::default()))
    }
    fn bridge_material(
        &self,
        _frame: &RootFrame,
        _source: &SelectedRootPathHalf,
        _export: &SelectedRootPathHalf,
        _target_demand: &ResolutionLookupSemanticRecipe,
        language: Language,
    ) -> Result<BridgeMaterial> {
        Ok(BridgeMaterial::same_language(language))
    }
    fn publication_delta(
        &mut self,
        _frame: &RootFrame,
        registration: &SelectedFactOperationBlueprint,
        paths: &dyn SelectedContextPathSource,
        cancellation: &CancellationToken,
    ) -> Result<Read<PublicationDelta>> {
        let relation = DemandSelectedOverlayBlueprint::new(registration.context_token());
        Ok(match relation.added_candidate_paths(paths, cancellation)? {
            Some(paths) => Read::ready(PublicationDelta { relation, paths }),
            None => Read::Cancelled(cancelled_completion()),
        })
    }

    type Half<'a>: HalfRules
    where
        Self: 'a;

    fn half_rows<'a>(
        &'a self,
        _source: &'a SourceHalf,
        _frame: &'a RootFrame,
        _scopes: &'a crate::analyzer::store::resolution_lexical::NodeSourceScopes,
        _lexical: &'a dyn HalfSource,
        _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<Self::Half<'a>>> {
        unreachable!("source rows require language rules")
    }

    type PreparationKey;
    type Certificate: PublicationCertificate;

    /// Project a validated request-owned blueprint without traversal, SQL
    /// derivation or charging. Missing promised preparation is an invariant
    /// failure. The shared publisher still enumerates its relation before policy.
    fn prepared_publication(&self, _key: &Self::PreparationKey) -> SelectedFactOperationBlueprint {
        unreachable!("a preparation key requires a publication consumer")
    }

    /// Called after the final cancellation boundary. The language returns the
    /// staged relations and evidence; the shared publisher owns arena mutation.
    fn publication(
        &self,
        _key: Option<&Self::PreparationKey>,
        registration: SelectedFactOperationBlueprint,
    ) -> PublicationMaterial<Self::Certificate> {
        PublicationMaterial {
            registration,
            certificate: None,
        }
    }

    /// Observe an existing closure milestone without charging or doing I/O.
    fn note_closure_work(&self, _milestone: &'static str) {}

    /// Commit memo-only language associations at the shared publication point.
    /// This runs after the final cancellation check and cannot fail.
    fn commit_associations(&self, associations: &[ContextAssociation]) {
        assert!(
            associations.is_empty(),
            "language associations require a commit callback"
        );
    }

    fn provider_preparation(
        &mut self,
        _frame: &RootFrame,
        _inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<Option<ProviderPreparation<Self::PreparationKey>>> {
        Ok(None)
    }

    fn provider_rows(
        &mut self,
        _frame: &RootFrame,
        _half: HalfId,
        _mount: SelectedResolutionMountOrdinal,
        _answers: &PrefixAnswers<'_>,
    ) -> Result<Read<ProviderRows>> {
        unreachable!("provider preparation requires a row reader")
    }

    fn describe_source(
        &mut self,
        endpoint: &EndpointSignature,
        source: Option<SourceDemandKey>,
        halves: Vec<SelectedRootPathHalf>,
        completion: ResolutionCompletion,
    ) -> Result<Read<Admission>>;
    fn root_starts<'a>(
        &self,
        rules: &mut Self::Half<'a>,
        owner: &<Self::Half<'a> as HalfRules>::Placement,
        facts: &mut PlacementFacts<<Self::Half<'a> as HalfRules>::Target>,
    ) -> Result<Vec<PlacementStart<<Self::Half<'a> as HalfRules>::Member>>>
    where
        Self: 'a,
    {
        HalfRules::root_starts(rules, owner, facts)
    }

    fn admit_endpoint(
        &mut self,
        endpoint: &EndpointSignature,
        already_published: bool,
    ) -> Result<Read<EndpointAdmission>> {
        Ok(Read::ready(
            if endpoint.node() != BindingNodeId::universal_root() || already_published {
                EndpointAdmission::Ready(ResolutionCompletion::Complete)
            } else {
                EndpointAdmission::Discover
            },
        ))
    }
    fn discovery_scope(&mut self, _endpoint: &EndpointSignature) -> Result<SourceScope> {
        Ok(SourceScope::Unrestricted)
    }
    fn context_identity(&self, _frame: &RootFrame) -> Option<ContextId> {
        None
    }
    fn derive_context(
        &mut self,
        _key: ContextId,
        _frame: &RootFrame,
    ) -> Result<Read<Option<SelectedResolutionContextSet>>> {
        Ok(Read::ready(None))
    }
    fn resolve_prefix_operands(
        &mut self,
        _frame: &mut RootFrame,
        _context: Option<&SelectedResolutionContextSet>,
    ) -> Result<Read<Vec<ResolvedPrefixOperand>>> {
        Ok(Read::ready(Vec::new()))
    }
    fn prefix_completion(&self, answer: &FactResolutionAnswer) -> ResolutionCompletion {
        answer.completion().clone()
    }
    fn compile_publication(
        &mut self,
        _frame: &RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        contexts: crate::analyzer::resolution::SelectedResolutionContextInputs,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<SelectedFactOperationBlueprintConstruction> {
        ready.collect_blueprint_in_session(contexts, cancellation, session)
    }
    fn register_publication(
        &mut self,
        _frame: &RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        registration: &SelectedFactOperationBlueprint,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
    ) -> Result<ContextRegistrationOutcome> {
        ready.register_context_cells_in_session(
            registration,
            SelectedContextRegistrationCells {
                shared: registration.shared_semantic_identities(),
                boundaries: registration.boundary_nodes(),
                gaps: registration.context_owned_gap_identities(),
            },
            cancellation,
            session,
        )
    }
    fn publication_context(
        &self,
        _frame: &RootFrame,
        ready: &ReadySelectedResolution<'_, '_>,
        inventory: &ResolutionCompletion,
    ) -> Result<SelectedResolutionContextSet> {
        let mounts = SelectedMountTable::new(&ready.inventory);
        empty_contexts_for(
            mounts,
            inventory,
            &selected_mount_lookup(mounts),
            ready.context_identities.clone(),
        )
    }
    fn prefix_operands(&self, frame: &RootFrame, caller: EnvironmentId) -> Vec<PrefixOperand> {
        frame
            .halves
            .iter()
            .enumerate()
            .filter_map(|(index, half)| {
                let SelectedRootPathHalf::Reference {
                    prefix_reference: Some(reference),
                    ..
                } = half
                else {
                    return None;
                };
                Some(PrefixOperand {
                    key: PrefixKey {
                        reference: *reference,
                        environment: caller,
                    },
                    source_halves: Box::new([HalfId(index)]),
                })
            })
            .collect()
    }
    fn prefix_environment(
        &self,
        _frame: &RootFrame,
        _operand: &PrefixOperand,
        _context: Option<&SelectedResolutionContextSet>,
        caller: EnvironmentId,
    ) -> EnvironmentId {
        caller
    }
    fn activation(&self, _frame: &RootFrame, _half: HalfId) -> CandidateDecision {
        CandidateDecision::Admit
    }
    fn admit_candidate(
        &self,
        _frame: &RootFrame,
        _cursor: &RouteCursor,
        _candidate: &ExportCandidate,
    ) -> CandidateDecision {
        CandidateDecision::Admit
    }
    fn closure_policy(
        &self,
        _frame: &RootFrame,
        facts: &ClosureFacts<'_>,
    ) -> Result<Read<ClosurePolicy>> {
        let targets: BTreeSet<_> = facts
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.admission
                    == crate::analyzer::resolution::BindingCandidateAdmission::Target
            })
            .map(|candidate| candidate.definition)
            .collect();
        let discharges = if targets.is_empty() {
            DemandClosureDischarges::default()
        } else {
            DemandClosureDischarges::default().with_selected_targets(targets)
        };
        Ok(Read::ready(ClosurePolicy::new(
            ResolutionCompletion::Complete,
            BaseEligibility::Retain,
            discharges,
            Box::new([]),
        )))
    }
    fn member_request(
        &self,
        _frame: &RootFrame,
        _answers: &PrefixAnswers<'_>,
    ) -> Result<Read<Option<DemandMemberSelectionRequest>>> {
        Ok(Read::ready(None))
    }
    fn selected_member_targets(
        &mut self,
        _frame: &RootFrame,
        _selection: &DemandMemberSelection,
    ) -> Result<Read<Vec<SelectedMemberTarget>>> {
        Ok(Read::ready(Vec::new()))
    }
    fn member_bridge_material(
        &self,
        _frame: &RootFrame,
        _source: &SelectedRootPathHalf,
        _target: &SelectedMemberTarget,
        language: Language,
    ) -> Result<BridgeMaterial> {
        Ok(BridgeMaterial::same_language(language))
    }
    /// The reverse pipeline retains incomplete inventory when the selected
    /// unit publishes reexports that these default edges cannot enumerate.
    fn reverse_export_edges(
        &mut self,
        _endpoint: &EndpointSignature,
    ) -> Result<Read<Vec<EndpointSignature>>> {
        Ok(Read::ready(Vec::new()))
    }
}

/// A finite, certified owner relation, distinct from receiver type values.
/// The language has already applied visibility and owner admissibility rules.
pub(super) struct AdmissibleMemberOwners {
    pub definitions: Vec<SemanticId>,
    pub lookup: SemanticId,
}

pub(super) struct ExactMemberSelection {
    pub owner: SemanticId,
    pub scope_head: BindingNodeId,
    pub override_target: Option<(BindingFragmentId, BindingNodeId)>,
}

/// Select an exact declaration within the supplied owners, without following
/// outward lexical paths or inventing hierarchy edges. Only a unique declaring
/// owner admits continuation. A unique override takes precedence over its
/// declaration; zero or multiple overrides retain that declaration's scope.
/// The language supplies impl-match facts only after the owner is selected.
pub(super) fn select_unique_exact_member(
    typed: &impl SelectedTypedFactSource,
    base: &impl BatchResolutionFragmentSource,
    mut owners: AdmissibleMemberOwners,
    cancellation: &CancellationToken,
    overrides: impl FnOnce(SemanticId) -> Result<Vec<(BindingFragmentId, BindingNodeId)>>,
) -> Result<Option<ExactMemberSelection>> {
    owners.definitions.sort_unstable();
    owners.definitions.dedup();
    let mut scopes = Vec::new();
    let mut collect = |rows: &[SelectedTypedRow<LoweredMemberScopeProperty>]| {
        for row in rows {
            scopes.push((row.row().definition(), row.row().scope_head()));
        }
        Ok(!cancellation.is_cancelled())
    };
    let outcome = typed.visit_member_scope_pages_for_definitions(
        TypedFactRequest::new(&owners.definitions),
        cancellation,
        &mut FactPageVisitor::new(&mut collect),
    )?;
    if outcome.is_cancelled() {
        return Ok(None);
    }
    scopes.sort_unstable();
    scopes.dedup();
    let mut binding = Vec::new();
    for (definition, scope_head) in scopes {
        let request = BatchCandidateRequest::new(
            0,
            EndpointSignature::new(
                scope_head,
                StackPattern::closed([owners.lookup]),
                StackPattern::closed([]),
            ),
        );
        let outcome =
            base.match_forward_candidates(std::slice::from_ref(&request), cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        // Candidate bucketing is coarse. Hydration proves the exact first
        // symbol, so a different member cannot introduce owner ambiguity.
        let candidates = outcome
            .matches()
            .iter()
            .map(|matched| matched.candidate())
            .collect::<Vec<_>>();
        let binds = base
            .hydrate_candidate_paths(&candidates, cancellation)?
            .into_iter()
            .any(|(_, path)| {
                path.start().node() == scope_head
                    && path
                        .start()
                        .symbols()
                        .fixed()
                        .first()
                        .is_some_and(|symbol| symbol.symbol() == owners.lookup)
            });
        if binds {
            binding.push((definition, scope_head));
        }
    }
    let [(owner, scope_head)] = binding.as_slice() else {
        return Ok(None);
    };
    let mut targets = overrides(*owner)?;
    targets.sort_unstable();
    targets.dedup();
    let override_target = match targets.as_slice() {
        [target] => Some(*target),
        _ => None,
    };
    Ok(Some(ExactMemberSelection {
        owner: *owner,
        scope_head: *scope_head,
        override_target,
    }))
}

#[doc = " The operation's one admitted caller environment. Distinct environments"]
#[doc = " require environment-bearing scheduler keys before their first adoption."]
pub(super) use crate::analyzer::resolution::CALLER_ENVIRONMENT;

#[doc(hidden)]
pub struct SharedDemand<'a, 'store, 'input, R> {
    pub rules: R,
    pub arena: &'a RefCell<ClosedRelations>,
    pub paths: &'a dyn SelectedContextPathSource,
    pub ready: &'a ReadySelectedResolution<'store, 'input>,
    pub base: &'a dyn BatchResolutionFragmentSource,
    pub session: &'a ResolutionSession,
    pub cancellation: &'a CancellationToken,
    pub completion: &'a ResolutionCompletion,
}
impl<R> DemandLanguage for SharedDemand<'_, '_, '_, R>
where
    R: DemandRules + DemandLanguage<RootQuestion = RootFrame>,
{
    type RootQuestion = RootFrame;
    type ContextKey = ContextId;
    type ContextData = Option<SelectedResolutionContextSet>;
    fn discover_root(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<LanguageRootDiscovery<RootFrame>> {
        discover_root(self, endpoint)
    }
    fn context_key(&self, frame: &RootFrame) -> Option<ContextId> {
        self.rules.context_identity(frame)
    }
    fn prepare_context(
        &mut self,
        key: &ContextId,
        frame: &RootFrame,
    ) -> Result<LanguageContextPreparation<Self::ContextData>> {
        Ok(match self.rules.derive_context(*key, frame)? {
            Read::Ready { value, completion } => LanguageContextPreparation::Ready {
                data: value,
                completion,
            },
            Read::Unavailable { completion, .. } => {
                LanguageContextPreparation::Unavailable(completion)
            }
            Read::Cancelled(completion) => LanguageContextPreparation::Cancelled(completion),
        })
    }
    fn prefix_inputs(
        &mut self,
        frame: &mut RootFrame,
        context: Option<&Self::ContextData>,
    ) -> Result<LanguagePrefixInputs> {
        prefix_inputs(&mut self.rules, frame, context.and_then(Option::as_ref))
    }
    fn member_selection(
        &mut self,
        frame: &RootFrame,
        _context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<DemandMemberSelectionOutcome> {
        let answers = prefix_answers(frame, inputs);
        Ok(
            match self
                .rules
                .member_request(frame, &PrefixAnswers { entries: &answers })?
            {
                Read::Ready { value, completion } => DemandMemberSelectionOutcome::Ready {
                    request: value,
                    completion,
                },
                Read::Unavailable { completion, .. } => {
                    DemandMemberSelectionOutcome::Unavailable(completion)
                }
                Read::Cancelled(completion) => DemandMemberSelectionOutcome::Cancelled(completion),
            },
        )
    }
    fn close_selected_members(
        &mut self,
        endpoint: &EndpointSignature,
        frame: &RootFrame,
        _context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        selection: &DemandMemberSelection,
    ) -> Result<LanguageClosure> {
        let evidence = frame
            .prefix_evidence_with(inputs, |answer| self.rules.prefix_completion(answer))
            .combine(&selection.completion);
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageClosure {
                completion: evidence.combine(&cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
        // Incomplete member inventory cannot certify a closed empty endpoint.
        if selection.completion != ResolutionCompletion::Complete {
            return Ok(LanguageClosure {
                completion: evidence,
                closed: false,
                discharges: None,
            });
        }
        let rows = match close_member_rows(self, frame, selection)? {
            Read::Ready { value, completion } => (value, evidence.combine(&completion)),
            Read::Unavailable { completion, .. } | Read::Cancelled(completion) => {
                return Ok(LanguageClosure {
                    completion: evidence.combine(&completion),
                    closed: false,
                    discharges: None,
                });
            }
        };
        publish_closure(
            self,
            endpoint,
            frame,
            inputs,
            rows.0,
            rows.1,
            Some(selection),
        )
    }
    fn close_root(
        &mut self,
        endpoint: &EndpointSignature,
        frame: &RootFrame,
        context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> Result<LanguageClosure> {
        self.close_root_with_member_completion(
            endpoint,
            frame,
            context,
            inputs,
            &ResolutionCompletion::Complete,
        )
    }
    fn close_root_with_member_completion(
        &mut self,
        endpoint: &EndpointSignature,
        frame: &RootFrame,
        _context: Option<&Self::ContextData>,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        member_completion: &ResolutionCompletion,
    ) -> Result<LanguageClosure> {
        let evidence = frame
            .prefix_evidence_with(inputs, |answer| self.rules.prefix_completion(answer))
            .combine(member_completion);
        if self.cancellation.is_cancelled() || !self.session.scope_step() {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
        close_root(self, endpoint, frame, inputs, member_completion)
    }
    fn reverse_dependencies(
        &mut self,
        endpoint: &EndpointSignature,
    ) -> Result<Vec<EndpointSignature>> {
        DemandLanguage::reverse_dependencies(&mut self.rules, endpoint)
    }
    fn close_reverse(&mut self, endpoint: &EndpointSignature) {
        DemandLanguage::close_reverse(&mut self.rules, endpoint);
    }
}

impl RootFrame {
    pub(super) fn positioned(
        endpoint: &EndpointSignature,
        source: SourceDemandKey,
        halves: Vec<SelectedRootPathHalf>,
    ) -> Self {
        Self {
            endpoint: endpoint.clone(),
            sources: (0..halves.len())
                .map(|index| RootSource::Positioned {
                    key: source,
                    half: HalfId(index),
                })
                .collect(),
            halves,
            context: None,
            operands: Box::new([]),
            resolved_prefixes: Vec::new(),
            completion: ResolutionCompletion::Complete,
        }
    }
    pub(super) fn prefix_evidence(
        &self,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    ) -> ResolutionCompletion {
        self.prefix_evidence_with(inputs, |answer| answer.completion().clone())
    }
    fn prefix_evidence_with(
        &self,
        inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
        completion: impl Fn(&FactResolutionAnswer) -> ResolutionCompletion,
    ) -> ResolutionCompletion {
        assert_eq!(
            self.operands.len(),
            inputs.len(),
            "prefix operands form an exact answer bijection"
        );
        let mut seen = HashSet::default();
        let mut evidence = self.completion.clone();
        for &(key, answer) in inputs {
            assert!(seen.insert(key), "duplicate prefix answer {key:?}");
            assert!(
                self.operands.iter().any(|operand| operand.key == key),
                "unexpected prefix answer {key:?}"
            );
            evidence = evidence.combine(&completion(answer));
        }
        for resolved in &self.resolved_prefixes {
            evidence = evidence.combine(&completion(&resolved.answer));
        }
        evidence
    }
}

pub(super) fn discover_root<R: DemandRules>(
    shared: &mut SharedDemand<'_, '_, '_, R>,
    endpoint: &EndpointSignature,
) -> Result<LanguageRootDiscovery<RootFrame>> {
    let stopped = || {
        shared
            .completion
            .combine(&crate::analyzer::resolution::cancelled_completion())
    };
    if shared.cancellation.is_cancelled() || !shared.session.scope_step() {
        return Ok(LanguageRootDiscovery::Cancelled(stopped()));
    }
    let (admission_completion, context) = match shared.rules.admit_endpoint(endpoint, false)? {
        Read::Ready {
            value: EndpointAdmission::Ready(completion),
            completion: admission,
        } => {
            return Ok(LanguageRootDiscovery::AlreadyReady {
                completion: completion.combine(&admission),
            });
        }
        Read::Ready {
            value: EndpointAdmission::Discover,
            completion,
        } => (completion, None),
        Read::Ready {
            value: EndpointAdmission::Context(source),
            completion,
        } => (completion, Some(source)),
        // Admission already classified this endpoint; do not add the source
        // reader's later cancellation checkpoint to an early admission return.
        Read::Unavailable { reason, completion } => {
            return Ok(LanguageRootDiscovery::Unavailable { reason, completion });
        }
        Read::Cancelled(completion) => return Ok(LanguageRootDiscovery::Cancelled(completion)),
    };
    // The reader applies the language horizon before intersecting this
    // admission scope. Unrestricted never widens a proved horizon.
    let result = if let Some(context) = context {
        Read::ready(context)
    } else {
        let mounts = match shared.rules.discovery_scope(endpoint)? {
            SourceScope::Unrestricted | SourceScope::DemandedMounts => None,
            SourceScope::Mounts(mounts) => Some(mounts.into_vec()),
            SourceScope::Cancelled(completion) => {
                return Ok(LanguageRootDiscovery::Cancelled(completion));
            }
        };
        match super::source_demand::root_source_set(
            shared.ready,
            shared.base,
            endpoint,
            mounts.as_deref(),
            shared.session,
            shared.cancellation,
        )? {
            Read::Ready {
                value: Some(source),
                completion,
            } => shared.rules.describe_source(
                endpoint,
                Some(source.key),
                source.halves.into_iter().map(|half| half.half).collect(),
                completion,
            )?,
            Read::Ready {
                value: None,
                completion,
            } => shared.rules.describe_source(
                endpoint,
                None,
                Vec::new(),
                shared.completion.combine(&completion),
            )?,
            Read::Unavailable { reason, completion } => Read::Unavailable { reason, completion },
            Read::Cancelled(completion) => Read::Cancelled(completion),
        }
    };
    let unavailable = |reason, completion: &ResolutionCompletion| {
        if shared.cancellation.is_cancelled() || !shared.session.observe_cancellation() {
            LanguageRootDiscovery::Cancelled(stopped())
        } else {
            LanguageRootDiscovery::Unavailable {
                reason,
                completion: completion.combine(&admission_completion),
            }
        }
    };
    Ok(match result {
        Read::Ready {
            value: Admission::SourceOwned(mut frame),
            completion,
        } => {
            frame.completion = frame
                .completion
                .combine(&admission_completion)
                .combine(&completion);
            LanguageRootDiscovery::Ready {
                completion: frame.completion.clone(),
                question: frame,
            }
        }
        Read::Ready {
            value: Admission::BaseOwned { completion, base },
            completion: read_completion,
        } => {
            // Base readiness certifies the universal base relation. Positioned
            // endpoints keep its existing readiness; source admission alone must
            // not manufacture a new per-endpoint marker.
            let key = DemandRelationKey::caller(endpoint.clone());
            let mut arena = shared.arena.borrow_mut();
            match base {
                BaseEligibility::Retain => {
                    if endpoint.node() == BindingNodeId::universal_root() {
                        arena.base_ready.insert(key);
                    }
                }
                BaseEligibility::Exclude => {
                    arena.excluded_base.insert(key);
                }
            }
            LanguageRootDiscovery::AlreadyReady {
                completion: completion
                    .combine(&admission_completion)
                    .combine(&read_completion),
            }
        }
        Read::Ready {
            value: Admission::Unavailable { reason, completion },
            completion: read_completion,
        } => unavailable(reason, &completion.combine(&read_completion)),
        Read::Unavailable { reason, completion } => unavailable(reason, &completion),
        Read::Cancelled(completion) => {
            LanguageRootDiscovery::Cancelled(completion.combine(&admission_completion))
        }
    })
}

pub(super) fn prefix_inputs<R: DemandRules>(
    rules: &mut R,
    frame: &mut RootFrame,
    context: Option<&SelectedResolutionContextSet>,
) -> Result<LanguagePrefixInputs> {
    let (resolved, prefix_completion) = match rules.resolve_prefix_operands(frame, context)? {
        Read::Ready { value, completion } => {
            frame.completion = frame.completion.combine(&completion);
            (value, completion)
        }
        Read::Unavailable { completion, .. } | Read::Cancelled(completion) => {
            return Ok(LanguagePrefixInputs {
                references: Vec::new(),
                completion,
            });
        }
    };
    let mut resolved_keys = HashSet::default();
    for answer in &resolved {
        assert!(
            resolved_keys.insert(answer.operand.key),
            "one owned answer per operand"
        );
        assert!(!answer.operand.source_halves.is_empty());
        assert!(
            answer
                .operand
                .source_halves
                .iter()
                .all(|half| half.0 < frame.halves.len())
        );
    }
    frame.resolved_prefixes = resolved;
    let mut operands: Vec<PrefixOperand> = Vec::new();
    let mut keys = HashMap::default();
    for mut operand in rules.prefix_operands(frame, CALLER_ENVIRONMENT) {
        operand.key.environment =
            rules.prefix_environment(frame, &operand, context, CALLER_ENVIRONMENT);
        if let Some(&index) = keys.get(&operand.key) {
            let existing: &mut PrefixOperand = &mut operands[index];
            let mut incidence = existing.source_halves.to_vec();
            incidence.extend(operand.source_halves.iter().copied());
            incidence.sort_unstable_by_key(|half| half.0);
            incidence.dedup();
            existing.source_halves = incidence.into_boxed_slice();
        } else {
            keys.insert(operand.key, operands.len());
            operands.push(operand);
        }
    }
    assert!(
        frame.resolved_prefixes.iter().all(|resolved| operands
            .iter()
            .any(|operand| operand.key == resolved.operand.key)),
        "owned answers name actual prefix operands"
    );
    operands.retain(|operand| {
        let Some(resolved) = frame
            .resolved_prefixes
            .iter()
            .find(|resolved| resolved.operand.key == operand.key)
        else {
            return true;
        };
        assert_eq!(
            resolved.operand.source_halves, operand.source_halves,
            "owned answers preserve aggregate half incidence"
        );
        false
    });
    operands.sort_unstable_by_key(|operand| operand.key.reference);
    let references = operands
        .iter()
        .map(|operand| {
            // Remote dependency tasks require environment-bearing scheduler keys.
            assert!(
                operand.key.environment == CALLER_ENVIRONMENT,
                "prefix reference {:?} has environment {:?}, scheduler caller environment {:?}",
                operand.key.reference,
                operand.key.environment,
                CALLER_ENVIRONMENT
            );
            operand.key
        })
        .collect();
    frame.operands = operands.into_boxed_slice();
    Ok(LanguagePrefixInputs {
        references,
        // Forward only the hook's new evidence: discovery already supplied
        // the plan's prior evidence. Closure reads its frame independently.
        completion: prefix_completion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analyzer::resolution::PartialPathId;
    use crate::analyzer::resolution::StackPattern;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5658: shared route traversal lost canonical frontier order"
    )]
    fn residual_frontiers_preserve_canonical_visit_order_and_cutoff_witness() {
        use std::cell::RefCell;

        struct Rows<'a> {
            visits: &'a RefCell<Vec<String>>,
            cancellation: &'a CancellationToken,
            stop_after: usize,
        }
        impl RouteRules<()> for Rows<'_> {
            fn root_starts(
                &self,
                start: &WalkCursor<()>,
                _: &mut ResolutionCompletion,
            ) -> Result<RouteStarts> {
                Ok(RouteStarts {
                    locations: vec![start.location.clone()],
                    consumed: 0,
                })
            }
            fn route_tier(
                &self,
                cursor: &WalkCursor<()>,
                _: &ResolutionLookupSemanticRecipe,
                rank: usize,
            ) -> Result<Option<RouteEdgeTier>> {
                if rank != 0 {
                    return Ok(None);
                }
                let RouteLocation::Container { unit, container } = &cursor.location else {
                    unreachable!()
                };
                self.visits.borrow_mut().push(container.clone());
                if self.visits.borrow().len() == self.stop_after {
                    self.cancellation.cancel();
                }
                Ok(Some(RouteEdgeTier {
                    edges: if container == "root" {
                        vec!["z", "a", "m"]
                            .into_iter()
                            .map(|container| RouteLocation::Container {
                                unit: *unit,
                                container: container.into(),
                            })
                            .collect()
                    } else {
                        vec![RouteLocation::Container {
                            unit: *unit,
                            container: "leaf".into(),
                        }]
                    },
                    ..RouteEdgeTier::default()
                }))
            }
            fn dead_end(
                &self,
                _: &WalkCursor<()>,
                _: &ResolutionLookupSemanticRecipe,
            ) -> Result<ResolutionCompletion> {
                unreachable!()
            }
        }
        let route = ["head", "tail"].map(|name| {
            ResolutionLookupSemanticRecipe::new(Language::Rust, ResolutionNamespace::Type, name)
        });
        for stop_after in [usize::MAX, 2] {
            let cancellation = CancellationToken::new();
            let visits = RefCell::new(Vec::new());
            let result = walk_residual_route(
                &Rows {
                    visits: &visits,
                    cancellation: &cancellation,
                    stop_after,
                },
                WalkCursor::container((), 1, "root".into(), 0),
                &route,
                &mut ResolutionCompletion::Complete,
                &cancellation,
            )
            .unwrap();
            let visits = visits.into_inner();
            if stop_after == usize::MAX {
                assert_eq!(visits, ["root", "a", "m", "z"]);
                assert_eq!(result.len(), 1);
            } else {
                assert_eq!(visits, ["root", "a"]);
                assert!(result.is_empty());
            }
            assert_eq!(
                visits[1], "a",
                "the first witness must use canonical location order"
            );
        }
    }

    struct PrefixRules;
    impl DemandRules for PrefixRules {
        type Half<'a>
            = EmptyHalf
        where
            Self: 'a;
        type PreparationKey = ();
        type Certificate = ();
        fn describe_source(
            &mut self,
            _: &EndpointSignature,
            _: Option<SourceDemandKey>,
            _: Vec<SelectedRootPathHalf>,
            _: ResolutionCompletion,
        ) -> Result<Read<Admission>> {
            unreachable!("this test starts after source discovery")
        }

        fn prefix_operands(&self, frame: &RootFrame, caller: EnvironmentId) -> Vec<PrefixOperand> {
            super::super::rust_prefix::rust_prefix_operands(frame, caller)
        }
    }

    fn frame() -> RootFrame {
        let fragment = BindingFragmentId::at_ordinal(1);
        let source = SourceDemandKey {
            fragment,
            token: SemanticId::for_test("token"),
            demand: SemanticId::for_test("demand"),
        };
        let half = |number, prefix| SelectedRootPathHalf::Reference {
            identity: CandidatePathIdentity::new(fragment, PartialPathId::context_local(number)),
            source_reference: BindingNodeId::for_test("reference"),
            source_scope_head: BindingNodeId::for_test("source-scope"),
            lexical_scope_head: Some(BindingNodeId::for_test("lexical-scope")),
            prefix_reference: Some(SemanticId::for_test(prefix)),
            owner_continued: false,
            route: Box::new([]),
            anchor: ResolutionRootImportAnchor::Lexical,
            anchor_semantic: SemanticId::for_test("anchor"),
            token: source.token,
            demand: source.demand,
        };
        RootFrame::positioned(
            &EndpointSignature::new(
                BindingNodeId::universal_root(),
                StackPattern::closed([]),
                StackPattern::closed([]),
            ),
            source,
            vec![
                half(1, "first-prefix"),
                half(2, "first-prefix"),
                half(3, "second-prefix"),
            ],
        )
    }

    #[test]
    fn shared_prefix_frame_keeps_all_halves_and_multiple_prefix_incidence() {
        let mut frame = frame();
        let inputs = prefix_inputs(&mut PrefixRules, &mut frame, None).unwrap();
        assert_eq!(frame.halves.len(), 3);
        assert_eq!(inputs.references.len(), 2);
        let operand = frame
            .operands
            .iter()
            .find(|operand| operand.key.reference == SemanticId::for_test("first-prefix"))
            .unwrap();
        assert_eq!(&*operand.source_halves, &[HalfId(0), HalfId(1)]);
        let operand = frame
            .operands
            .iter()
            .find(|operand| operand.key.reference == SemanticId::for_test("second-prefix"))
            .unwrap();
        assert_eq!(&*operand.source_halves, &[HalfId(2)]);
    }

    #[test]
    #[should_panic(expected = "scheduler caller environment EnvironmentId(0)")]
    fn shared_prefix_frame_rejects_a_second_scheduler_environment() {
        struct ForeignEnvironment;
        impl DemandRules for ForeignEnvironment {
            type Half<'a>
                = EmptyHalf
            where
                Self: 'a;
            type PreparationKey = ();
            type Certificate = ();
            fn describe_source(
                &mut self,
                _: &EndpointSignature,
                _: Option<SourceDemandKey>,
                _: Vec<SelectedRootPathHalf>,
                _: ResolutionCompletion,
            ) -> Result<Read<Admission>> {
                unreachable!()
            }

            fn prefix_environment(
                &self,
                _: &RootFrame,
                _: &PrefixOperand,
                _: Option<&SelectedResolutionContextSet>,
                _: EnvironmentId,
            ) -> EnvironmentId {
                EnvironmentId(1)
            }
        }
        prefix_inputs(&mut ForeignEnvironment, &mut frame(), None).unwrap();
    }
}

/// Distinct canonical-export and proven-member authorities to their proofs.
/// Each map belongs to exactly one source half. Pending inventory is separate.
pub(super) type TargetProofGroups = HashMap<
    TargetAuthority,
    (
        CandidateTarget,
        ResolutionLookupSemanticRecipe,
        ResolutionCompletion,
    ),
>;

pub(super) fn retain_export_proof(
    groups: &mut TargetProofGroups,
    mut export: SelectedRootPathHalf,
    lookup: ResolutionLookupSemanticRecipe,
    evidence: ResolutionCompletion,
) {
    let SelectedRootPathHalf::Export {
        identity,
        token,
        demand,
        definition,
        incomplete_reasons,
    } = &mut export
    else {
        unreachable!("only sealed exports have export authority");
    };
    // Export and installed-path evidence are AND dependencies of this proof.
    // Normalize them before reducing alternatives, so the first candidate's
    // incomplete export cannot contaminate a later complete proof.
    let evidence = if incomplete_reasons.is_empty() {
        evidence
    } else {
        evidence.combine(&ResolutionCompletion::incomplete(
            incomplete_reasons.iter().copied(),
        ))
    };
    *incomplete_reasons = Box::new([]);
    let key = TargetAuthority::Export(ExportAuthority {
        fragment: identity.fragment(),
        token: *token,
        demand: *demand,
        definition: *definition,
    });
    match groups.entry(key) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert((CandidateTarget::Export(export), lookup, evidence));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let previous = &mut entry.get_mut().2;
            *previous = if *previous == ResolutionCompletion::Complete
                || evidence == ResolutionCompletion::Complete
            {
                ResolutionCompletion::Complete
            } else {
                previous.combine(&evidence)
            };
        }
    }
}

pub(super) fn export_recipe(
    ready: &ReadySelectedResolution<'_, '_>,
    fragment: BindingFragmentId,
    semantic: SemanticId,
    cancellation: &CancellationToken,
    session: &ResolutionSession,
) -> Result<Option<ResolutionLookupSemanticRecipe>> {
    let request = SelectedLookupRecipeRequest { fragment, semantic };
    let SelectedLookupRecipeReadOutcome::Ready(rows) = ready
        .lexical_source()
        .lookup_semantic_recipes(&[request], cancellation, Some(session))?
    else {
        return Ok(None);
    };
    rows.into_vec()
        .pop()
        .flatten()
        .map(Some)
        .ok_or_else(|| StoreError::corrupt("sealed demand has no lookup recipe"))
}

pub(super) type HydratedExport = (
    SelectedRootPathHalf,
    ResolutionLookupSemanticRecipe,
    ResolutionCompletion,
);

#[doc(hidden)]
pub struct ExportHydration {
    pub exports: Vec<HydratedExport>,
    pub blockers: Vec<HydratedExport>,
    pub unstaged: ResolutionCompletion,
    pub coverage: ExportCoverage,
}

#[doc(hidden)]
pub struct ExportCoverage {
    pub unconditional: ResolutionCompletion,
    pub branches: Vec<(BindingNodeId, ResolutionCompletion)>,
}
impl Default for ExportCoverage {
    fn default() -> Self {
        Self {
            unconditional: ResolutionCompletion::Complete,
            branches: Vec::new(),
        }
    }
}
impl ExportCoverage {
    fn retain(
        &mut self,
        definition: BindingNodeId,
        outcome: &crate::analyzer::resolution::BatchCandidateCompletionOutcome,
    ) -> bool {
        self.unconditional = self
            .unconditional
            .combine(outcome.unconditional_completion());
        let [branch] = outcome.branch_completions() else {
            unreachable!("one definition request has exactly one coverage branch");
        };
        self.branches.push((definition, branch.clone()));
        !self
            .unconditional
            .contains_reason(ResolutionIncompleteReason::Cancelled)
    }
}

/// Hydration consumes the requested namespace, not a canonical lookup recipe.
/// Broad spelling demands may span Type and Value; each returned recipe still
/// has the one effective namespace enforced by its constructor.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn hydrate_exports(
    session: &ResolutionSession,
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    cancellation: &CancellationToken,
    definitions: Vec<BindingNodeId>,
    namespace: ResolutionNamespace,
    completion: &ResolutionCompletion,
    unstaged: ResolutionCompletion,
) -> Result<Option<ExportHydration>> {
    use crate::analyzer::resolution::{BatchCandidateRequest, StackPattern};
    let mut bridges = Vec::new();
    let mut path_completions = Vec::new();
    let mut cancelled = false;
    let mut coverage = ExportCoverage::default();
    for node in definitions {
        if !closer_step(session, cancellation, CloserWork::Definition) {
            return Ok(None);
        }
        let endpoint =
            EndpointSignature::new(node, StackPattern::closed([]), StackPattern::closed([]));
        let anchors = ready.lexical_source();
        let outcome = base.visit_reverse_candidate_match_pages(
            &[BatchCandidateRequest::new(0, endpoint)],
            cancellation,
            &mut |page| {
                let ids = page.iter().map(|row| row.candidate()).collect::<Vec<_>>();
                for (id, path) in base.hydrate_candidate_paths(&ids, cancellation)? {
                    if !closer_step(session, cancellation, CloserWork::HydratedPath) {
                        cancelled = true;
                        return Ok(false);
                    }
                    let Some(
                        export_half @ SelectedRootPathHalf::Export {
                            demand: export_demand,
                            ..
                        },
                    ) = classify_selected_root_path_half(&anchors, id, &path, cancellation)?
                    else {
                        continue;
                    };
                    let Some(target_demand) =
                        export_recipe(ready, id.fragment(), export_demand, cancellation, session)?
                    else {
                        cancelled = true;
                        return Ok(false);
                    };
                    path_completions.push(path.completion().clone());
                    bridges.push((export_half, target_demand, completion.clone()));
                }
                Ok(!cancellation.is_cancelled())
            },
        )?;
        if !coverage.retain(node, &outcome) || cancelled || !session.observe_cancellation() {
            return Ok(None);
        }
    }

    // Close export and installed-path evidence, preserving source coverage under
    // its own inventory/branch owners rather than absorbing it into each row.
    let mut completions = Vec::with_capacity(bridges.len() * 2);
    for ((half, _, _), path) in bridges.iter().zip(path_completions) {
        if !closer_step(session, cancellation, CloserWork::CompletionPacking) {
            return Ok(None);
        }
        let SelectedRootPathHalf::Export {
            incomplete_reasons, ..
        } = half
        else {
            unreachable!("export query collects export halves");
        };
        completions.push(if incomplete_reasons.is_empty() {
            ResolutionCompletion::Complete
        } else {
            ResolutionCompletion::incomplete(incomplete_reasons.iter().copied())
        });
        completions.push(path);
    }
    let Some(closed) = ready
        .lexical_source()
        .close_completions(&completions, cancellation)?
    else {
        return Ok(None);
    };
    let mut closed = closed.into_iter();
    let mut exports = Vec::new();
    let mut blockers = Vec::new();
    for (mut half, lookup, mut evidence) in bridges {
        if !closer_step(session, cancellation, CloserWork::CompletionRewrite) {
            return Ok(None);
        }
        let SelectedRootPathHalf::Export {
            incomplete_reasons, ..
        } = &mut half
        else {
            unreachable!("export query collects export halves");
        };
        *incomplete_reasons = match closed.next().expect("export completion") {
            ResolutionCompletion::Complete => Box::new([]),
            ResolutionCompletion::Incomplete(reasons) => reasons.iter().copied().collect(),
        };
        evidence = evidence.combine(&closed.next().expect("path completion"));
        match crate::analyzer::resolution::classify_binding_namespace(namespace, lookup.namespace())
        {
            crate::analyzer::resolution::BindingCandidateAdmission::Target => {
                exports.push((half, lookup, evidence))
            }
            crate::analyzer::resolution::BindingCandidateAdmission::WrongNamespaceBlocker => {
                blockers.push((half, lookup, evidence))
            }
        }
    }
    assert!(closed.next().is_none());
    Ok(Some(ExportHydration {
        exports,
        blockers,
        unstaged,
        coverage,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn export_bridges<R: DemandRules>(
    session: &ResolutionSession,
    cancellation: &CancellationToken,
    ready: &ReadySelectedResolution<'_, '_>,
    language: Language,
    rules: &R,
    frame: &RootFrame,
    half: &SelectedRootPathHalf,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    authorities: &TargetProofGroups,
) -> Result<Option<Vec<SelectedRootBridgeDescriptor>>> {
    let mut descriptors = Vec::with_capacity(authorities.len());
    for (target, target_demand, evidence) in authorities.values() {
        let CandidateTarget::Export(export_half) = target else {
            panic!("canonical export construction cannot consume a member target: {target:?}");
        };
        if !closer_step(session, cancellation, CloserWork::Bridge) {
            return Ok(None);
        }
        let material = rules.bridge_material(frame, half, export_half, target_demand, language)?;
        let descriptor = canonical_export_bridge(
            ready,
            half,
            route,
            demand,
            export_half,
            target_demand,
            evidence,
            &material,
        );
        descriptors.push(descriptor);
    }
    Ok(Some(descriptors))
}

#[allow(clippy::too_many_arguments)]
fn bridge_from_material(
    half: &SelectedRootPathHalf,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    target_fragment: BindingFragmentId,
    target_token: SemanticId,
    target_demand: &ResolutionLookupSemanticRecipe,
    evidence: &ResolutionCompletion,
    material: &BridgeMaterial,
) -> SelectedRootBridgeDescriptor {
    let (identity, token, anchor, anchor_semantic, prefix) = match half {
        SelectedRootPathHalf::Import {
            identity,
            token,
            anchor,
            anchor_semantic,
            ..
        } => (*identity, *token, *anchor, *anchor_semantic, None),
        SelectedRootPathHalf::Reference {
            identity,
            token,
            anchor,
            anchor_semantic,
            prefix_reference,
            ..
        } => (
            *identity,
            *token,
            *anchor,
            *anchor_semantic,
            *prefix_reference,
        ),
        SelectedRootPathHalf::Export { .. } => unreachable!("bridges start at source halves"),
    };
    let descriptor = if let Some(cross_language_evidence) = material.cross_language_evidence {
        SelectedRootBridgeDescriptor::from_selected_path_tokens_with_jvm_evidence(
            identity.fragment(),
            material.source_language,
            token,
            anchor,
            anchor_semantic,
            target_fragment,
            material.target_language,
            target_token,
            prefix,
            route.to_vec(),
            demand.clone(),
            target_demand.clone(),
            cross_language_evidence,
            evidence.clone(),
        )
    } else if let Some(prefix) = prefix {
        SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
            identity.fragment(),
            material.source_language,
            token,
            anchor,
            anchor_semantic,
            target_fragment,
            material.target_language,
            target_token,
            prefix,
            route.to_vec(),
            demand.clone(),
            target_demand.clone(),
            evidence.clone(),
        )
    } else {
        SelectedRootBridgeDescriptor::from_selected_path_tokens(
            identity.fragment(),
            material.source_language,
            token,
            anchor,
            anchor_semantic,
            target_fragment,
            material.target_language,
            target_token,
            route.to_vec(),
            demand.clone(),
            target_demand.clone(),
            evidence.clone(),
        )
    };
    descriptor
        .with_precedence(material.precedence)
        .with_candidate_origin_rank(material.candidate_origin_rank)
}

#[allow(clippy::too_many_arguments)]
fn canonical_export_bridge(
    ready: &ReadySelectedResolution<'_, '_>,
    half: &SelectedRootPathHalf,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    export: &SelectedRootPathHalf,
    lookup: &ResolutionLookupSemanticRecipe,
    evidence: &ResolutionCompletion,
    material: &BridgeMaterial,
) -> SelectedRootBridgeDescriptor {
    let SelectedRootPathHalf::Export {
        identity,
        token,
        definition,
        ..
    } = export
    else {
        panic!("canonical export construction requires export identity: {export:?}");
    };
    assert!(
        material
            .target_definition
            .is_none_or(|target| target == *definition)
    );
    bridge_from_material(
        half,
        route,
        demand,
        identity.fragment(),
        *token,
        lookup,
        evidence,
        material,
    )
    .with_selected_export(&ready.shared_names(), export)
}

fn proven_member_bridge(
    half: &SelectedRootPathHalf,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    member: &SelectedMemberTarget,
    material: &BridgeMaterial,
) -> SelectedRootBridgeDescriptor {
    assert_eq!(member.definition.ordinal(), Some(member.fragment.ordinal()));
    assert_eq!(member.token.ordinal(), Some(member.fragment.ordinal()));
    assert!(
        material
            .target_definition
            .is_none_or(|target| target == member.definition)
    );
    bridge_from_material(
        half,
        route,
        demand,
        member.fragment,
        member.token,
        &member.lookup,
        &member.completion,
        material,
    )
    .with_selected_member_definition(member.definition)
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(super) fn close_half_candidates(
    session: &ResolutionSession,
    cancellation: &CancellationToken,
    base: &dyn BatchResolutionFragmentSource,
    half: HalfId,
    descriptors: &[SelectedRootBridgeDescriptor],
    authorities: &TargetProofGroups,
    blockers: &TargetProofGroups,
    alternatives: &mut HashMap<TargetAuthority, Vec<ProofId>>,
    proofs: &mut ProofFacts,
) -> Result<Option<(Vec<ExportCandidate>, BTreeSet<SemanticId>)>> {
    let mut candidates = Vec::new();
    let mut selected_targets = BTreeSet::new();
    let mut nodes = Vec::new();
    for node in descriptors
        .iter()
        .filter_map(|bridge| bridge.target_definition())
        .chain(authorities.keys().map(|authority| authority.definition()))
        .chain(blockers.keys().map(|authority| authority.definition()))
    {
        if !closer_step(session, cancellation, CloserWork::CandidateNode) {
            return Ok(None);
        }
        nodes.push(node);
    }
    nodes.sort_unstable();
    nodes.dedup();
    let mut semantics = HashMap::default();
    for batch in nodes.chunks(crate::analyzer::resolution::MAX_SOURCE_ROWS_PER_BATCH) {
        if !closer_step(session, cancellation, CloserWork::CandidateClassification) {
            return Ok(None);
        }
        for classified in base.classify_endpoint_nodes(batch, cancellation)? {
            if !closer_step(session, cancellation, CloserWork::ClassifiedDefinition) {
                return Ok(None);
            }
            if let Some(semantic) = classified.definition() {
                semantics.insert(classified.node(), semantic);
            }
        }
    }
    if cancellation.is_cancelled() || !session.observe_cancellation() {
        return Ok(None);
    }
    for bridge in descriptors {
        if !closer_step(session, cancellation, CloserWork::BridgeTarget) {
            return Ok(None);
        }
        if let Some(node) = bridge.target_definition() {
            selected_targets.insert(
                *semantics
                    .get(&node)
                    .expect("selected bridge target has definition authority"),
            );
        }
    }
    for (groups, admission) in [
        (
            authorities,
            crate::analyzer::resolution::BindingCandidateAdmission::Target,
        ),
        (
            blockers,
            crate::analyzer::resolution::BindingCandidateAdmission::WrongNamespaceBlocker,
        ),
    ] {
        for (authority, (export, lookup, completion)) in groups {
            if !closer_step(session, cancellation, CloserWork::CandidateAuthority) {
                return Ok(None);
            }
            let owner = EvidenceOwner::Candidate(half, *authority);
            let proof = proofs.push(owner.clone(), completion.clone(), Box::new([]));
            let original = alternatives
                .remove(authority)
                .unwrap_or_else(|| vec![proof]);
            proofs.authorities.push(AuthorityProofs {
                owner,
                alternatives: original.into_boxed_slice(),
            });
            let semantic = *semantics
                .get(&authority.definition())
                .expect("sealed export has definition authority");
            if admission == crate::analyzer::resolution::BindingCandidateAdmission::Target {
                selected_targets.insert(semantic);
            }
            let mut candidate = match export {
                CandidateTarget::Export(export) => {
                    ExportCandidate::new(export.clone(), lookup.clone(), proof, semantic)
                }
                CandidateTarget::Member(member) => ExportCandidate {
                    target: CandidateTarget::Member(member.clone()),
                    authority: *authority,
                    lookup: lookup.clone(),
                    proof,
                    definition: semantic,
                    admission: crate::analyzer::resolution::BindingCandidateAdmission::Target,
                },
            };
            candidate.admission = admission;
            candidates.push(candidate);
        }
    }
    assert!(alternatives.is_empty());
    Ok(Some((candidates, selected_targets)))
}

#[doc(hidden)]
pub struct ClosedEndpointRegistration {
    pub(crate) blueprint: SelectedFactOperationBlueprint,
    pub(crate) completion: ResolutionCompletion,
}

#[derive(Default)]
#[doc(hidden)]
pub struct ContinuationRelations {
    #[doc(hidden)]
    pub endings: HashMap<(SemanticId, SemanticId), Vec<CandidatePathIdentity>>,
    #[doc(hidden)]
    pub suppressed: HashSet<CandidatePathIdentity>,
}
impl ClosedRelations {
    pub(crate) fn generated_base_completion(
        &self,
        endpoint: &EndpointSignature,
        session: &ResolutionSession,
    ) -> Option<(ResolutionCompletion, bool)> {
        let fixed = endpoint.symbols().fixed();
        let key = (fixed.first()?.symbol(), fixed.get(1)?.symbol());
        let mut completion: Option<ResolutionCompletion> = None;
        let mut use_base = None;
        for id in self.continuations.endings.get(&key)? {
            let path = &self.paths[id];
            if endpoint
                .can_concatenate_with_poll(path.end(), &mut || !session.scope_step())?
                .is_ok()
            {
                let candidate_uses_base = !self.continuations.suppressed.contains(id);
                assert!(
                    use_base.is_none_or(|previous| previous == candidate_uses_base),
                    "one generated endpoint cannot mix base and closed-empty authority"
                );
                use_base = Some(candidate_uses_base);
                completion = Some(completion.map_or_else(
                    || path.completion().clone(),
                    |previous| previous.combine(path.completion()),
                ));
            }
        }
        completion.map(|completion| (completion, use_base.unwrap()))
    }
}

fn source_recipe(
    shared: &SharedDemand<'_, '_, '_, impl DemandRules>,
    fragment: BindingFragmentId,
    semantic: SemanticId,
) -> Result<Option<ResolutionLookupSemanticRecipe>> {
    let request = SelectedLookupRecipeRequest { fragment, semantic };
    let SelectedLookupRecipeReadOutcome::Ready(rows) = shared
        .ready
        .lexical_source()
        .lookup_semantic_recipes(&[request], shared.cancellation, None)?
    else {
        return Ok(None);
    };
    rows.into_vec()
        .pop()
        .flatten()
        .map(Some)
        .ok_or_else(|| StoreError::corrupt("sealed demand has no lookup recipe"))
}

fn decode_source_half(
    shared: &SharedDemand<'_, '_, '_, impl DemandRules>,
    half: &SelectedRootPathHalf,
) -> Result<Option<SourceHalf>> {
    let (
        identity,
        scope,
        token,
        demand_id,
        route_ids,
        anchor,
        anchor_semantic,
        prefix,
        prefix_scope_head,
    ) = match half {
        SelectedRootPathHalf::Import {
            identity,
            source_scope_head,
            token,
            demand,
            route,
            anchor,
            anchor_semantic,
            ..
        } => (
            *identity,
            *source_scope_head,
            *token,
            *demand,
            route,
            *anchor,
            *anchor_semantic,
            None,
            None,
        ),
        SelectedRootPathHalf::Reference {
            identity,
            source_scope_head,
            token,
            demand,
            route,
            anchor,
            anchor_semantic,
            prefix_reference,
            lexical_scope_head,
            ..
        } => (
            *identity,
            *source_scope_head,
            *token,
            *demand,
            route,
            *anchor,
            *anchor_semantic,
            *prefix_reference,
            *lexical_scope_head,
        ),
        _ => unreachable!("one source endpoint plan contains only source halves"),
    };
    let Some(demand) = source_recipe(shared, identity.fragment(), demand_id)? else {
        return Ok(None);
    };
    let Some(route) = route_ids
        .iter()
        .map(|id| source_recipe(shared, identity.fragment(), *id))
        .collect::<Result<Option<Vec<_>>>>()?
    else {
        return Ok(None);
    };
    Ok(Some(SourceHalf {
        identity,
        scope,
        token,
        demand,
        route,
        anchor,
        anchor_semantic,
        prefix,
        prefix_scope_head,
        is_import: matches!(half, SelectedRootPathHalf::Import { .. }),
    }))
}

fn close_start_selection<H: HalfRules>(
    rules: &H,
    owner: &H::Placement,
    facts: &mut PlacementFacts<H::Target>,
    mut selection: StartSelection,
    cancellation: &CancellationToken,
) -> Result<StartSelection> {
    if let Some(request) = selection.lexical.take() {
        let selected = select_lexical_route_starts(
            request.scope,
            |scope| rules.lexical_parent(owner, scope),
            |scope| {
                let mut read = rules.lexical_tier(owner, scope, &request.lookup)?;
                if let Some((location, head)) = read.head {
                    let route = [head];
                    let cursor = WalkCursor {
                        tag: facts.tag,
                        location,
                        consumed_prefix_segments: 0,
                        start_step: 0,
                        namespace: route[0].namespace(),
                    };
                    let mut coverage = ResolutionCompletion::Complete;
                    read.tier.edges.extend(
                        walk_residual_route(
                            &rules.route_rules(owner, ResolutionRootImportAnchor::Lexical, &route),
                            cursor,
                            &route,
                            &mut coverage,
                            cancellation,
                        )?
                        .into_iter()
                        .map(|cursor| cursor.location),
                    );
                    read.tier.coverage = read.tier.coverage.combine(&coverage);
                }
                Ok(read.tier)
            },
            &mut facts.completion,
            cancellation,
        )?;
        selection = selected.into();
    }
    if let Some(head) = selection.head.take() {
        let route = [head];
        let mut locations = Vec::new();
        for location in selection.locations {
            let cursor = WalkCursor {
                tag: facts.tag,
                location,
                consumed_prefix_segments: 0,
                start_step: 0,
                namespace: route[0].namespace(),
            };
            locations.extend(
                walk_residual_route(
                    &rules.route_rules(owner, ResolutionRootImportAnchor::Lexical, &route),
                    cursor,
                    &route,
                    &mut facts.completion,
                    cancellation,
                )?
                .into_iter()
                .map(|cursor| cursor.location),
            );
        }
        selection.locations = locations;
    }
    Ok(selection)
}

fn close_placement_starts<H: HalfRules>(
    rules: &H,
    owner: &H::Placement,
    starts: Vec<PlacementStart<H::Member>>,
    facts: &mut PlacementFacts<H::Target>,
    route: &[ResolutionLookupSemanticRecipe],
    cancellation: &CancellationToken,
) -> Result<()> {
    for start in starts {
        match start {
            PlacementStart::Route { cursor, anchor } => {
                let reached = walk_residual_route(
                    &rules.route_rules(owner, anchor, route),
                    cursor,
                    route,
                    &mut facts.completion,
                    cancellation,
                )?;
                facts.targets.extend(
                    reached
                        .into_iter()
                        .map(|cursor| rules.route_target(cursor.location)),
                );
            }
            PlacementStart::Member(member) => {
                facts
                    .members
                    .extend(rules.member_bridges(owner, member, &facts.completion)?)
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn deadend_bridge(
    fragment: BindingFragmentId,
    language: Language,
    token: SemanticId,
    anchor: ResolutionRootImportAnchor,
    anchor_semantic: SemanticId,
    prefix: Option<SemanticId>,
    route: &[ResolutionLookupSemanticRecipe],
    demand: &ResolutionLookupSemanticRecipe,
    completion: ResolutionCompletion,
) -> SelectedRootBridgeDescriptor {
    if let Some(prefix) = prefix {
        SelectedRootBridgeDescriptor::from_selected_path_tokens_with_prefix(
            fragment,
            language,
            token,
            anchor,
            anchor_semantic,
            fragment,
            language,
            token,
            prefix,
            route.to_vec(),
            demand.clone(),
            demand.clone(),
            completion,
        )
    } else {
        SelectedRootBridgeDescriptor::from_selected_path_tokens(
            fragment,
            language,
            token,
            anchor,
            anchor_semantic,
            fragment,
            language,
            token,
            route.to_vec(),
            demand.clone(),
            demand.clone(),
            completion,
        )
    }
}

fn close_source_rows<R: DemandRules>(
    shared: &SharedDemand<'_, '_, '_, R>,
    plan: &RootFrame,
    inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
) -> Result<Option<RouteClosure<R::PreparationKey>>> {
    let lexical = shared.ready.lexical_source();
    let Some(scope_ordinals) = lexical.node_scope_ordinals(
        plan.halves
            .iter()
            .filter_map(|half| match half {
                SelectedRootPathHalf::Import {
                    source_scope_head, ..
                }
                | SelectedRootPathHalf::Reference {
                    source_scope_head, ..
                } => Some(*source_scope_head),
                SelectedRootPathHalf::Export { .. } => None,
            })
            .chain(plan.halves.iter().filter_map(|half| match half {
                SelectedRootPathHalf::Reference {
                    lexical_scope_head: Some(scope_head),
                    ..
                } => Some(*scope_head),
                _ => None,
            })),
        shared.cancellation,
    )?
    else {
        return Ok(None);
    };
    let mut descriptors = Vec::new();
    let mut associations = Vec::new();
    let mut half_facts = Vec::new();
    let mut candidates = Vec::new();
    let mut proofs = ProofFacts::default();
    let mut unconditional = ResolutionCompletion::Complete;
    for (half_index, half) in plan.halves.iter().enumerate() {
        let half_id = HalfId(half_index);
        let route_proof = proofs.push(
            EvidenceOwner::Source(half_id),
            ResolutionCompletion::Complete,
            Box::new([]),
        );
        let descriptor_start = descriptors.len();
        let Some(source) = decode_source_half(shared, half)? else {
            return Ok(None);
        };
        let Some(mut rules) =
            shared
                .rules
                .half_rows(&source, plan, &scope_ordinals, &lexical, inputs)?
        else {
            return Ok(None);
        };
        let mut observation = HalfObservation {
            completion: rules.initial_completion(),
            answered_placements: Vec::new(),
            reached: Vec::new(),
            route_reached_a_target: false,
        };
        let mut placement_observations = Vec::new();
        let mut alternatives: HashMap<_, Vec<_>> = HashMap::default();
        let mut blockers = TargetProofGroups::default();
        let mut authorities = TargetProofGroups::default();
        let mut member_bridges = Vec::new();
        let prefix_has_targets = rules.prefix_has_targets();
        for (index, owner) in rules.placements().into_iter().enumerate() {
            let placement = PlacementId(index);
            let Some(mut facts) = rules.placement(&owner, (half_id, placement, route_proof)) else {
                continue;
            };
            let starts = shared.rules.root_starts(&mut rules, &owner, &mut facts)?;
            close_placement_starts(
                &rules,
                &owner,
                starts,
                &mut facts,
                &source.route,
                shared.cancellation,
            )?;
            if let Some(selection) = rules.prefix_selection(&owner, &mut facts)? {
                let selection = close_start_selection(
                    &rules,
                    &owner,
                    &mut facts,
                    selection,
                    shared.cancellation,
                )?;
                let starts = rules.prefix_starts(&owner, selection, &mut facts)?;
                close_placement_starts(
                    &rules,
                    &owner,
                    starts,
                    &mut facts,
                    &source.route,
                    shared.cancellation,
                )?;
            }
            match rules.import_targets(&owner, &mut facts)? {
                Some(true) => {}
                Some(false) => continue,
                None => return Ok(None),
            }
            let canonical = rules.canonical_targets(&owner, &mut facts)?;
            let starts = rules.module_starts(&owner, &facts);
            close_placement_starts(
                &rules,
                &owner,
                starts,
                &mut facts,
                &source.route,
                shared.cancellation,
            )?;
            if let Some(selection) = rules.lexical_selection(&owner, &mut facts)? {
                let selection = close_start_selection(
                    &rules,
                    &owner,
                    &mut facts,
                    selection,
                    shared.cancellation,
                )?;
                let starts = rules.lexical_starts(selection, &facts);
                close_placement_starts(
                    &rules,
                    &owner,
                    starts,
                    &mut facts,
                    &source.route,
                    shared.cancellation,
                )?;
            }
            rules.observe_targets(&owner, &facts)?;
            if let Some(canonical) = canonical {
                facts.targets = canonical;
            }
            rules.select_targets(&mut facts.targets)?;
            observation.route_reached_a_target |= !facts.targets.is_empty();
            let before = authorities.len();
            let reached_start = observation.reached.len();
            for target in std::mem::take(&mut facts.targets) {
                observation.reached.push(rules.target_location(&target));
                let Some(ExportHydration {
                    exports,
                    blockers: blocked,
                    unstaged,
                    coverage,
                }) = rules.exports(&owner, target.clone(), &facts.completion)?
                else {
                    return Ok(None);
                };
                unconditional = unconditional.combine(&coverage.unconditional);
                proofs.push(
                    EvidenceOwner::Inventory(half_id),
                    coverage.unconditional,
                    Box::new([]),
                );
                for (definition, branch) in coverage.branches {
                    if !closer_step(
                        shared.session,
                        shared.cancellation,
                        CloserWork::CoverageBranch,
                    ) {
                        return Ok(None);
                    }
                    observation.completion = observation.completion.combine(&branch);
                    proofs.push(
                        EvidenceOwner::ExportBranch(half_id, placement, definition),
                        branch,
                        Box::new([]),
                    );
                }
                for (half, lookup, completion) in blocked {
                    if !closer_step(
                        shared.session,
                        shared.cancellation,
                        CloserWork::BlockedExport,
                    ) {
                        return Ok(None);
                    }
                    retain_export_proof(&mut blockers, half, lookup, completion);
                }
                observation.completion = observation.completion.combine(&unstaged);
                if exports.is_empty() {
                    observation.completion = observation
                        .completion
                        .combine(&rules.empty_target(&owner, &target)?)
                        .combine(&unstaged);
                }
                for (export, target_demand, evidence) in exports {
                    if !closer_step(shared.session, shared.cancellation, CloserWork::ExportProof) {
                        return Ok(None);
                    }
                    let SelectedRootPathHalf::Export {
                        identity,
                        token,
                        demand,
                        definition,
                        incomplete_reasons,
                    } = &export
                    else {
                        unreachable!()
                    };
                    let authority = TargetAuthority::Export(ExportAuthority {
                        fragment: identity.fragment(),
                        token: *token,
                        demand: *demand,
                        definition: *definition,
                    });
                    let local = if incomplete_reasons.is_empty() {
                        evidence.clone()
                    } else {
                        evidence.combine(&ResolutionCompletion::incomplete(
                            incomplete_reasons.iter().copied(),
                        ))
                    };
                    let placement_proof = proofs.push(
                        EvidenceOwner::Placement(half_id, placement),
                        facts.completion.clone(),
                        Box::new([]),
                    );
                    let proof = proofs.push(
                        EvidenceOwner::Candidate(half_id, authority),
                        local,
                        Box::new([placement_proof]),
                    );
                    alternatives.entry(authority).or_default().push(proof);
                    retain_export_proof(&mut authorities, export, target_demand, evidence);
                }
            }
            observation.answered_placements.push(placement);
            placement_observations.push(PlacementObservation {
                placement,
                completion: facts.completion.clone(),
                reached: observation.reached[reached_start..]
                    .to_vec()
                    .into_boxed_slice(),
            });
            member_bridges.append(&mut facts.members);
            if authorities.len() == before {
                rules.empty_placement(&facts, &mut observation)?;
            }
        }
        let Some(export_bridges) = export_bridges(
            shared.session,
            shared.cancellation,
            shared.ready,
            rules.language(),
            &shared.rules,
            plan,
            half,
            &source.route,
            &source.demand,
            &authorities,
        )?
        else {
            return Ok(None);
        };
        descriptors.extend(export_bridges);
        let published_member_bridge = !member_bridges.is_empty();
        descriptors.append(&mut member_bridges);
        if authorities.is_empty() && !published_member_bridge {
            let Some(boundary) = rules.boundary(&observation)? else {
                return Ok(None);
            };
            observation.completion = boundary.completion;
            associations.extend(boundary.associations);
            if observation.completion != ResolutionCompletion::Complete {
                descriptors.push(deadend_bridge(
                    source.identity.fragment(),
                    rules.language(),
                    source.token,
                    source.anchor,
                    source.anchor_semantic,
                    source.prefix,
                    &source.route,
                    &source.demand,
                    observation.completion.clone(),
                ));
            }
        }
        let accepted = authorities.keys().copied().collect();
        let Some((half_candidates, selected_targets)) = close_half_candidates(
            shared.session,
            shared.cancellation,
            shared.base,
            half_id,
            &descriptors[descriptor_start..],
            &authorities,
            &blockers,
            &mut alternatives,
            &mut proofs,
        )?
        else {
            return Ok(None);
        };
        candidates.extend(half_candidates);
        assert!(alternatives.is_empty());
        proofs.proofs[route_proof.0].local = observation.completion.clone();
        half_facts.push(HalfClosureFacts {
            half: half_id,
            answered_placements: observation.answered_placements.into_boxed_slice(),
            reached: observation.reached.into_boxed_slice(),
            placements: placement_observations.into_boxed_slice(),
            accepted,
            completion: observation.completion,
            selected_targets,
            prefix_has_targets,
            deferred_member_selection: false,
        });
    }
    Ok(Some(RouteClosure {
        staged: None,
        disposition: RouteDisposition::Publish,
        preparation: None,
        bridges: descriptors,
        associations,
        halves: half_facts,
        candidates,
        evidence: proofs,
        completion: unconditional,
    }))
}

fn close_provider_rows<R: DemandRules>(
    shared: &mut SharedDemand<'_, '_, '_, R>,
    frame: &RootFrame,
    inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    preparation: ProviderPreparation<R::PreparationKey>,
) -> Result<Option<RouteClosure<R::PreparationKey>>> {
    let mut route = RouteClosure {
        staged: None,
        disposition: RouteDisposition::Publish,
        preparation: None,
        halves: Vec::new(),
        candidates: Vec::new(),
        evidence: ProofFacts::default(),
        completion: ResolutionCompletion::Complete,
        bridges: Vec::new(),
        associations: Vec::new(),
    };
    let mount = match preparation {
        ProviderPreparation::Closed(read) => {
            let staged = match read {
                Read::Ready { value, completion } => {
                    route.completion = value.completion.combine(&completion);
                    value
                }
                Read::Cancelled(_) => return Ok(None),
                Read::Unavailable { completion, .. } => {
                    route.disposition = RouteDisposition::ClosedIncomplete;
                    route.completion = completion;
                    return Ok(Some(route));
                }
            };
            route.disposition = staged.disposition;
            // Staged row closure has already selected its exact authorities.
            // Preserve source incidence without inventing placement observations.
            assert!(
                frame.halves.len() <= 1,
                "staged row closure owns at most one source half"
            );
            route.halves = frame
                .halves
                .iter()
                .enumerate()
                .map(|(index, _)| HalfClosureFacts {
                    placements: Box::new([]),
                    completion: staged.completion.clone(),
                    selected_targets: staged
                        .discharges
                        .as_ref()
                        .and_then(|proof| proof.selected_targets.clone())
                        .unwrap_or_default(),
                    prefix_has_targets: inputs
                        .iter()
                        .any(|(_, answer)| !answer.binding().targets().is_empty()),
                    deferred_member_selection: false,
                    half: HalfId(index),
                    answered_placements: Box::new([]),
                    reached: Box::new([]),
                    accepted: staged.targets.clone().into_boxed_slice(),
                })
                .collect();
            route.staged = Some(staged);
            return Ok(Some(route));
        }
        ProviderPreparation::Prepared { key, completion } => {
            assert!(frame.halves.is_empty());
            route.preparation = Some(key);
            route.completion = completion;
            return Ok(Some(route));
        }
        ProviderPreparation::Unavailable(completion) => {
            route.disposition = RouteDisposition::ClosedIncomplete;
            route.completion = completion;
            return Ok(Some(route));
        }
        ProviderPreparation::Rows { mount } => mount,
    };
    let entries: Vec<_> = inputs
        .iter()
        .map(|(key, answer)| PrefixAnswer { key: *key, answer })
        .collect();
    let answers = PrefixAnswers { entries: &entries };
    for (index, half) in frame.halves.iter().enumerate() {
        let half_id = HalfId(index);
        let ProviderRows {
            language,
            exports,
            recipe,
            binding,
            context_completion,
            witness,
            completion,
        } = match shared
            .rules
            .provider_rows(frame, half_id, mount, &answers)?
        {
            Read::Ready { value, .. } => value,
            Read::Cancelled(_) => return Ok(None),
            Read::Unavailable { completion, .. } => {
                route.disposition = RouteDisposition::ClosedIncomplete;
                route.completion = completion;
                return Ok(Some(route));
            }
        };
        let mut placement_observations = Vec::new();
        let mut authorities = TargetProofGroups::default();
        let mut alternatives = HashMap::<_, Vec<_>>::default();
        for (placement, export) in exports.into_iter().enumerate() {
            placement_observations.push(PlacementObservation {
                placement: PlacementId(placement),
                completion: completion.clone(),
                reached: Box::new([]),
            });
            let proof = route.evidence.push(
                EvidenceOwner::Placement(half_id, PlacementId(placement)),
                completion.clone(),
                Box::new([]),
            );
            let SelectedRootPathHalf::Export {
                identity,
                token,
                demand,
                definition,
                ..
            } = &export
            else {
                unreachable!("export-only reader")
            };
            let authority = TargetAuthority::Export(ExportAuthority {
                fragment: identity.fragment(),
                token: *token,
                demand: *demand,
                definition: *definition,
            });
            alternatives.entry(authority).or_default().push(proof);
            retain_export_proof(&mut authorities, export, recipe.clone(), completion.clone());
        }
        let Some(bridges) = export_bridges(
            shared.session,
            shared.cancellation,
            shared.ready,
            language,
            &shared.rules,
            frame,
            half,
            &[],
            &recipe,
            &authorities,
        )?
        else {
            return Ok(None);
        };
        let accepted = authorities.keys().copied().collect();
        let Some((candidates, targets)) = close_half_candidates(
            shared.session,
            shared.cancellation,
            shared.base,
            half_id,
            &bridges,
            &authorities,
            &TargetProofGroups::default(),
            &mut alternatives,
            &mut route.evidence,
        )?
        else {
            return Ok(None);
        };
        route.evidence.push(
            EvidenceOwner::Source(half_id),
            binding.clone(),
            Box::new([]),
        );
        if !bridges.is_empty() {
            let owner = frame
                .context
                .map(EvidenceOwner::Context)
                .unwrap_or(EvidenceOwner::Inventory(half_id));
            let proof = route
                .evidence
                .push(owner.clone(), context_completion, Box::new([]));
            route.evidence.authorities.push(AuthorityProofs {
                owner,
                alternatives: Box::new([proof]),
            });
        }
        route.halves.push(HalfClosureFacts {
            placements: placement_observations.into_boxed_slice(),
            completion: completion.clone(),
            selected_targets: targets,
            prefix_has_targets: witness,
            deferred_member_selection: false,
            half: half_id,
            answered_placements: Box::new([]),
            reached: Box::new([]),
            accepted,
        });
        route.completion = route.completion.combine(&completion);
        route.candidates.extend(candidates);
        route.bridges.extend(bridges);
    }
    if route.bridges.is_empty() {
        route.disposition = RouteDisposition::RetainBase;
    }
    Ok(Some(route))
}

fn prefix_answers<'a>(
    frame: &'a RootFrame,
    inputs: &[(DemandReferenceKey, &'a FactResolutionAnswer)],
) -> Vec<PrefixAnswer<'a>> {
    inputs
        .iter()
        .map(|(key, answer)| PrefixAnswer { key: *key, answer })
        .chain(frame.resolved_prefixes.iter().map(|resolved| PrefixAnswer {
            key: resolved.operand.key,
            answer: &resolved.answer,
        }))
        .collect()
}

fn close_member_rows<R: DemandRules>(
    shared: &mut SharedDemand<'_, '_, '_, R>,
    frame: &RootFrame,
    selection: &DemandMemberSelection,
) -> Result<Read<RouteClosure<R::PreparationKey>>> {
    let (members, completion) = match shared.rules.selected_member_targets(frame, selection)? {
        Read::Ready { value, completion } => (value, completion),
        Read::Unavailable { reason, completion } => {
            return Ok(Read::Unavailable { reason, completion });
        }
        Read::Cancelled(completion) => return Ok(Read::Cancelled(completion)),
    };
    let mut route = RouteClosure {
        staged: None,
        disposition: RouteDisposition::Publish,
        preparation: None,
        halves: Vec::new(),
        candidates: Vec::new(),
        evidence: ProofFacts::default(),
        completion: selection.completion.combine(&completion),
        bridges: Vec::new(),
        associations: Vec::new(),
    };
    for (index, half) in frame.halves.iter().enumerate() {
        let Some(source) = decode_source_half(shared, half)? else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        let half_id = HalfId(index);
        let language = shared
            .ready
            .inventory
            .mount_record_for_fragment(source.identity.fragment())?
            .expect("member source is mounted")
            .semantic_language();
        let mut authorities = TargetProofGroups::default();
        let mut alternatives = HashMap::default();
        let mut bridges = Vec::new();
        for member in &members {
            if !closer_step(shared.session, shared.cancellation, CloserWork::ExportProof) {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let authority = TargetAuthority::Member {
                fragment: member.fragment,
                token: member.token,
                demand: member.lookup.semantic(&shared.ready.shared_names()),
                definition: member.definition,
            };
            let proof = route.evidence.push(
                EvidenceOwner::Candidate(half_id, authority),
                member.completion.clone(),
                Box::new([]),
            );
            alternatives
                .entry(authority)
                .or_insert_with(Vec::new)
                .push(proof);
            assert!(
                authorities
                    .insert(
                        authority,
                        (
                            CandidateTarget::Member(member.clone()),
                            member.lookup.clone(),
                            member.completion.clone()
                        )
                    )
                    .is_none(),
                "one proven member target per authority"
            );
            if !closer_step(shared.session, shared.cancellation, CloserWork::Bridge) {
                return Ok(Read::Cancelled(cancelled_completion()));
            }
            let material = shared
                .rules
                .member_bridge_material(frame, half, member, language)?;
            bridges.push(proven_member_bridge(
                half,
                &source.route,
                &source.demand,
                member,
                &material,
            ));
        }
        let accepted = authorities.keys().copied().collect();
        let Some((candidates, targets)) = close_half_candidates(
            shared.session,
            shared.cancellation,
            shared.base,
            half_id,
            &bridges,
            &authorities,
            &TargetProofGroups::default(),
            &mut alternatives,
            &mut route.evidence,
        )?
        else {
            return Ok(Read::Cancelled(cancelled_completion()));
        };
        route.candidates.extend(candidates);
        route.bridges.extend(bridges);
        route.halves.push(HalfClosureFacts {
            placements: Box::new([]),
            completion: route.completion.clone(),
            selected_targets: targets,
            prefix_has_targets: !selection.owners.is_empty(),
            deferred_member_selection: true,
            half: half_id,
            answered_placements: Box::new([]),
            reached: Box::new([]),
            accepted,
        });
    }
    Ok(Read::ready(route))
}

#[doc(hidden)]
pub fn close_root<R>(
    shared: &mut SharedDemand<'_, '_, '_, R>,
    endpoint: &EndpointSignature,
    plan: &RootFrame,
    inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    member_completion: &ResolutionCompletion,
) -> Result<LanguageClosure>
where
    R: DemandRules,
{
    if let Some(retained) = shared
        .arena
        .borrow()
        .registrations
        .get(&DemandRelationKey::caller(endpoint.clone()))
    {
        return Ok(LanguageClosure {
            completion: retained.completion.clone(),
            closed: true,
            discharges: None,
        });
    }
    let evidence = plan
        .prefix_evidence_with(inputs, |answer| shared.rules.prefix_completion(answer))
        .combine(member_completion);
    let closed_rows = match shared.rules.provider_preparation(plan, inputs)? {
        Some(ProviderPreparation::Closed(Read::Cancelled(completion))) => {
            return Ok(LanguageClosure {
                completion: evidence.combine(&completion),
                closed: false,
                discharges: None,
            });
        }
        Some(preparation) => close_provider_rows(shared, plan, inputs, preparation)?,
        None => close_source_rows(shared, plan, inputs)?,
    };
    let Some(rows) = closed_rows else {
        return Ok(LanguageClosure {
            completion: evidence.combine(&cancelled_completion()),
            closed: false,
            discharges: None,
        });
    };
    publish_closure(shared, endpoint, plan, inputs, rows, evidence, None)
}

fn publish_closure<R: DemandRules>(
    shared: &mut SharedDemand<'_, '_, '_, R>,
    endpoint: &EndpointSignature,
    plan: &RootFrame,
    inputs: &[(DemandReferenceKey, &FactResolutionAnswer)],
    rows: RouteClosure<R::PreparationKey>,
    mut evidence: ResolutionCompletion,
    members: Option<&DemandMemberSelection>,
) -> Result<LanguageClosure> {
    let RouteClosure {
        mut staged,
        disposition,
        preparation,
        bridges: descriptors,
        associations,
        halves,
        candidates,
        evidence: proofs,
        completion: route_completion,
    } = rows;
    let is_staged = staged.is_some();
    let endpoint_completion = staged
        .as_ref()
        .and_then(|stage| stage.endpoint_completion.clone());
    let staged_members = staged.as_mut().and_then(|stage| stage.members.take());
    let members = staged_members.as_ref().or(members);
    evidence = evidence.combine(&route_completion);
    if disposition != RouteDisposition::Publish {
        assert!(descriptors.is_empty() && preparation.is_none());
        let answers = prefix_answers(plan, inputs);
        let retained_witness =
            shared
                .rules
                .closure_witness(plan, &PrefixAnswers { entries: &answers }, members)?;
        let Some(witness) = ClosureWitness::retain_read(retained_witness, &mut evidence) else {
            return Ok(LanguageClosure {
                completion: evidence,
                closed: false,
                discharges: None,
            });
        };
        let facts = ClosureFacts {
            witness: &witness,
            members,
            generated: &[],
            associations: &associations,
            prefixes: PrefixAnswers { entries: &answers },
            halves: &halves,
            candidates: &candidates,
            context: plan.context,
            evidence: &proofs,
        };
        let policy = match shared.rules.closure_policy(plan, &facts)? {
            Read::Ready { value, completion } => {
                evidence = evidence.combine(&completion).combine(&value.completion);
                value
            }
            Read::Unavailable { completion, .. } | Read::Cancelled(completion) => {
                return Ok(LanguageClosure {
                    completion: evidence.combine(&completion),
                    closed: false,
                    discharges: None,
                });
            }
        };
        if shared.cancellation.is_cancelled() || !shared.session.observe_cancellation() {
            return Ok(LanguageClosure {
                completion: evidence.combine(&cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
        if disposition == RouteDisposition::RetainBase {
            assert!(policy.base == BaseEligibility::Retain);
            shared
                .arena
                .borrow_mut()
                .base_ready
                .insert(DemandRelationKey::caller(endpoint.clone()));
        } else {
            assert!(matches!(evidence, ResolutionCompletion::Incomplete(_)));
        }
        if let Some(completion) = endpoint_completion {
            assert!(
                shared
                    .arena
                    .borrow_mut()
                    .endpoint_completions
                    .insert(DemandRelationKey::caller(endpoint.clone()), completion)
                    .is_none()
            );
        }
        let discharges = policy.into_discharges();
        return Ok(LanguageClosure {
            completion: evidence,
            closed: true,
            discharges,
        });
    }
    let mount_table = SelectedMountTable::new(&shared.ready.inventory);
    for descriptor in descriptors.iter().filter(|_| !is_staged) {
        if !closer_step(
            shared.session,
            shared.cancellation,
            CloserWork::DescriptorEvidence,
        ) {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
        evidence = evidence.combine(descriptor.completion());
    }
    shared
        .rules
        .note_closure_work("demand_close_prefix_bridges");
    let staged_preparation = staged.as_mut().and_then(|stage| stage.preparation.take());
    let registration = if let Some(staged_preparation) = staged_preparation {
        match staged_preparation {
            StagedPreparation::Registered(registration) => registration,
            StagedPreparation::Prepared(contexts) => {
                let SelectedResolutionContextValidationOutcome::Ready(contexts) = contexts
                    .validate_exact_mounts_in_session(
                        mount_table.mount_count(),
                        &selected_mount_lookup(mount_table),
                        shared.cancellation,
                        shared.session,
                    )?
                else {
                    return Ok(LanguageClosure {
                        completion: evidence.combine(&cancelled_completion()),
                        closed: false,
                        discharges: None,
                    });
                };
                let SelectedFactOperationBlueprintConstruction::Ready(registration) =
                    shared.rules.compile_publication(
                        plan,
                        shared.ready,
                        contexts,
                        shared.session,
                        shared.cancellation,
                    )?
                else {
                    return Ok(LanguageClosure {
                        completion: evidence.combine(&cancelled_completion()),
                        closed: false,
                        discharges: None,
                    });
                };
                if matches!(
                    shared.rules.register_publication(
                        plan,
                        shared.ready,
                        &registration,
                        shared.session,
                        shared.cancellation
                    )?,
                    ContextRegistrationOutcome::Cancelled
                ) {
                    return Ok(LanguageClosure {
                        completion: evidence.combine(&cancelled_completion()),
                        closed: false,
                        discharges: None,
                    });
                }
                registration
            }
        }
    } else if let Some(key) = preparation.as_ref() {
        // The language already validated and compiled these request-owned
        // relations. Reconstructing them here would duplicate preparation work.
        assert!(descriptors.is_empty());
        assert!(plan.halves.is_empty());
        shared.rules.prepared_publication(key)
    } else {
        // Register with the existing selected owner, including exact local
        // anchor keys. Build the readable overlay and retained registration
        // once; subsequent requests reuse the closed endpoint relation.
        // Crate gap evidence is issued by this endpoint's row reader. Register
        // those identities with the context, just as the crate point reader
        // does; they have no persisted fragment-local semantic coordinate.
        let mut inventory_completion = shared.completion.combine(&route_completion);
        let mut owned_reasons = BTreeSet::new();
        for completion in std::iter::once(&route_completion)
            .chain(descriptors.iter().map(|descriptor| descriptor.completion()))
        {
            if !closer_step(
                shared.session,
                shared.cancellation,
                CloserWork::InventoryDescriptor,
            ) {
                return Ok(LanguageClosure {
                    completion: evidence
                        .combine(&crate::analyzer::resolution::cancelled_completion()),
                    closed: false,
                    discharges: None,
                });
            }
            if let ResolutionCompletion::Incomplete(reasons) = completion {
                for reason in reasons.iter() {
                    if !closer_step(
                        shared.session,
                        shared.cancellation,
                        CloserWork::InventoryReason,
                    ) {
                        return Ok(LanguageClosure {
                            completion: evidence
                                .combine(&crate::analyzer::resolution::cancelled_completion()),
                            closed: false,
                            discharges: None,
                        });
                    }
                    if let ResolutionIncompleteReason::UnsupportedSemantic(semantic) = reason
                        && !shared
                            .ready
                            .inventory
                            .mount_rebaser()
                            .borrow()
                            .issued_semantic(*semantic)
                    {
                        owned_reasons.insert(*semantic);
                        inventory_completion = inventory_completion
                            .combine(&ResolutionCompletion::incomplete([*reason]));
                    }
                }
            }
        }
        let selected_mount_of = selected_mount_lookup(mount_table);
        let mut contexts =
            shared
                .rules
                .publication_context(plan, shared.ready, &inventory_completion)?;
        for reason in owned_reasons {
            if !closer_step(
                shared.session,
                shared.cancellation,
                CloserWork::ContextInventoryReason,
            ) {
                return Ok(LanguageClosure {
                    completion: evidence
                        .combine(&crate::analyzer::resolution::cancelled_completion()),
                    closed: false,
                    discharges: None,
                });
            }
            contexts = contexts.with_context_owned_inventory_reason(reason);
        }
        let contexts = contexts.extend_root_bridges(
            descriptors,
            shared.cancellation,
            Some(shared.session),
            &selected_mount_of,
        )?;
        let Some(contexts) = contexts else {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        };
        let SelectedResolutionContextValidationOutcome::Ready(contexts) = contexts
            .validate_exact_mounts_in_session(
                mount_table.mount_count(),
                &selected_mount_lookup(mount_table),
                shared.cancellation,
                shared.session,
            )?
        else {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        };
        let SelectedFactOperationBlueprintConstruction::Ready(registration) =
            shared.rules.compile_publication(
                plan,
                shared.ready,
                contexts,
                shared.session,
                shared.cancellation,
            )?
        else {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        };
        if matches!(
            shared.rules.register_publication(
                plan,
                shared.ready,
                &registration,
                shared.session,
                shared.cancellation
            )?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
        registration
    };
    shared
        .rules
        .note_closure_work("demand_close_register_context");
    let publication_token = registration.context_token();
    let PublicationDelta { relation, paths } = match shared.rules.publication_delta(
        plan,
        &registration,
        shared.paths,
        shared.cancellation,
    )? {
        Read::Ready { value, completion } => {
            evidence = evidence.combine(&completion);
            value
        }
        Read::Unavailable { completion, .. } | Read::Cancelled(completion) => {
            return Ok(LanguageClosure {
                completion: evidence.combine(&completion),
                closed: false,
                discharges: None,
            });
        }
    };
    if !is_staged && (shared.cancellation.is_cancelled() || !shared.session.scope_step()) {
        return Ok(LanguageClosure {
            completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
            closed: false,
            discharges: None,
        });
    }
    let generated = if is_staged || preparation.is_some() {
        // Prepared context-only publication has no continuation endings.
        // Its blueprint already contains every import-binding extension.
        Some(Vec::new())
    } else {
        generated_base_endings(
            &paths,
            &plan.halves,
            Some((shared.session, shared.cancellation)),
        )
    };
    let Some(generated) = generated else {
        return Ok(LanguageClosure {
            completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
            closed: false,
            discharges: None,
        });
    };
    for _ in inputs.iter().filter(|_| !is_staged) {
        if !closer_step(
            shared.session,
            shared.cancellation,
            CloserWork::PrefixAnswer,
        ) {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
    }
    let answers = prefix_answers(plan, inputs);
    let witness =
        shared
            .rules
            .closure_witness(plan, &PrefixAnswers { entries: &answers }, members)?;
    let Some(witness) = ClosureWitness::retain_read(witness, &mut evidence) else {
        return Ok(LanguageClosure {
            completion: evidence,
            closed: false,
            discharges: None,
        });
    };
    let facts = ClosureFacts {
        witness: &witness,
        members,
        generated: &generated,
        associations: &associations,
        prefixes: PrefixAnswers { entries: &answers },
        halves: &halves,
        candidates: &candidates,
        context: plan.context,
        evidence: &proofs,
    };
    let (policy, policy_evidence) = match shared.rules.closure_policy(plan, &facts)? {
        Read::Ready { value, completion } => (value, completion),
        Read::Unavailable { completion, .. } | Read::Cancelled(completion) => {
            return Ok(LanguageClosure {
                completion: evidence.combine(&completion),
                closed: false,
                discharges: None,
            });
        }
    };
    evidence = evidence
        .combine(&policy.completion)
        .combine(&policy_evidence);
    // Account for bookkeeping before entering the non-interruptible commit.
    for _ in &policy.generated {
        if !closer_step(
            shared.session,
            shared.cancellation,
            CloserWork::ContinuationPublication,
        ) {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
    }
    for _ in &policy.associations {
        if !closer_step(
            shared.session,
            shared.cancellation,
            CloserWork::AssociationPublication,
        ) {
            return Ok(LanguageClosure {
                completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
                closed: false,
                discharges: None,
            });
        }
    }
    // The last cooperative boundary precedes every arena mutation. Publication
    // is atomic with respect to cancellation: never stop halfway through it.
    if shared.cancellation.is_cancelled()
        || !shared.session.observe_cancellation()
        || evidence.contains_reason(ResolutionIncompleteReason::Cancelled)
    {
        return Ok(LanguageClosure {
            completion: evidence.combine(&crate::analyzer::resolution::cancelled_completion()),
            closed: false,
            discharges: None,
        });
    }
    let PublicationMaterial {
        registration,
        certificate,
    } = shared.rules.publication(preparation.as_ref(), registration);
    assert_eq!(registration.context_token(), publication_token);
    {
        let mut arena = shared.arena.borrow_mut();
        assert!(!evidence.contains_reason(ResolutionIncompleteReason::Cancelled));
        if let Some(certificate) = certificate {
            certificate.publish();
        }
        arena.publish(DemandRelationKey::caller(endpoint.clone()), relation, paths);
        if let Some(completion) = endpoint_completion {
            assert!(
                arena
                    .endpoint_completions
                    .insert(DemandRelationKey::caller(endpoint.clone()), completion)
                    .is_none()
            );
        }
        assert!(
            arena
                .registrations
                .insert(
                    DemandRelationKey::caller(endpoint.clone()),
                    ClosedEndpointRegistration {
                        blueprint: registration,
                        completion: evidence.clone(),
                    }
                )
                .is_none(),
            "one endpoint closes once per retained selection"
        );
        for continuation in &policy.generated {
            let id = continuation.candidate;
            if continuation.base == BaseEligibility::Exclude {
                arena.continuations.suppressed.insert(id);
            }
            let fixed = arena.paths[&id].end().symbols().fixed();
            let key = (fixed[0].symbol(), fixed[1].symbol());
            let bucket = arena.continuations.endings.entry(key).or_default();
            if !bucket.contains(&id) {
                bucket.push(id);
            }
        }
        if policy.base == BaseEligibility::Exclude {
            arena
                .excluded_base
                .insert(DemandRelationKey::caller(endpoint.clone()));
        }
        shared.rules.commit_associations(&policy.associations);
    }
    shared.rules.note_closure_work("demand_close_published");
    let discharges = policy.into_discharges();
    Ok(LanguageClosure {
        completion: evidence,
        closed: true,
        discharges,
    })
}

pub(super) fn generated_base_endings(
    paths: &[(
        CandidatePathIdentity,
        crate::analyzer::resolution::PartialPath,
    )],
    halves: &[SelectedRootPathHalf],
    observation: Option<(&ResolutionSession, &CancellationToken)>,
) -> Option<Vec<(CandidatePathIdentity, SourceDemandKey)>> {
    let mut generated = Vec::new();
    for (id, path) in paths {
        if observation.is_some_and(|(session, cancellation)| {
            !closer_step(session, cancellation, CloserWork::GeneratedPath)
        }) {
            return None;
        }
        let mut matches = false;
        let candidate = (|| {
            if path.end().node() != BindingNodeId::universal_root() {
                return None;
            }
            // A root terminal the overlay compiler issued for one of this
            // relation's own source halves. Three conditions identify it,
            // and they are conditions rather than assertions because an
            // added path can also end at the universal root as an ordinary
            // bridge continuation: the canonical two-cell (demand, token)
            // terminal shape, a token that belongs to a sealed source half,
            // and a token that is not an Export half's, because no selected
            // bridge starts with this terminal lookup and token.
            //
            // The path's completion is deliberately not one of them. An
            // unresolved route says `UnsupportedSemantic(token)` and a route
            // whose prefix resolved exactly to a module-owned non-module
            // declaration is a complete negative continuation, and both are
            // root terminals of this relation. Whether the endpoint may then
            // read the base relation or is a closed empty is decided by
            // `generated_base_suppressed` from the prefix answers, which is
            // the only place that knows whether authority was established.
            let fixed = path.end().symbols().fixed();
            let [demand, token] = fixed else {
                return None;
            };
            let source = SourceDemandKey {
                fragment: id.fragment(),
                demand: demand.symbol(),
                token: token.symbol(),
            };
            for half in halves {
                if observation.is_some_and(|(session, cancellation)| {
                    !closer_step(session, cancellation, CloserWork::GeneratedHalf)
                }) {
                    return None;
                }
                matches = match half {
                    SelectedRootPathHalf::Import {
                        identity,
                        token,
                        demand,
                        ..
                    }
                    | SelectedRootPathHalf::Reference {
                        identity,
                        token,
                        demand,
                        ..
                    } => {
                        identity.fragment() == source.fragment
                            && *token == source.token
                            && *demand == source.demand
                    }
                    SelectedRootPathHalf::Export { .. } => false,
                };
                if matches {
                    break;
                }
            }
            matches.then_some((*id, source))
        })();
        if observation.is_some_and(|(session, cancellation)| {
            cancellation.is_cancelled() || !session.observe_cancellation()
        }) {
            return None;
        }
        if let Some(candidate) = candidate {
            generated.push(candidate);
        }
    }
    Some(generated)
}

pub(super) enum ExportDeclaration {
    SelectedSite {
        semantic: SemanticId,
        node: BindingNodeId,
    },
    GeneratedRange {
        mount: SelectedResolutionMountOrdinal,
        start: usize,
        end: usize,
    },
}

/// Resolve certified declaration authorities before reading canonical exports.
/// The iterator is lazy: language metadata reads retain their original order
/// relative to selected definition and generated-capsule reads.
pub(super) fn export_definitions<T>(
    session: &ResolutionSession,
    ready: &ReadySelectedResolution<'_, '_>,
    base: &dyn BatchResolutionFragmentSource,
    cancellation: &CancellationToken,
    declarations: impl IntoIterator<Item = Result<(ExportDeclaration, T)>>,
    mut missing: impl FnMut(T) -> Result<ResolutionCompletion>,
) -> Result<Option<(Vec<BindingNodeId>, ResolutionCompletion)>> {
    let mut definitions = Vec::new();
    let mut inventory = ResolutionCompletion::Complete;
    for declaration in declarations {
        if !closer_step(session, cancellation, CloserWork::Declaration) {
            return Ok(None);
        }
        let (declaration, provenance) = declaration?;
        match declaration {
            ExportDeclaration::SelectedSite { semantic, node } => {
                if let Some(actual) = base.lookup_definition_node(semantic, cancellation)? {
                    assert_eq!(actual, node);
                    definitions.push(actual);
                } else {
                    inventory = inventory.combine(&missing(provenance)?);
                }
            }
            ExportDeclaration::GeneratedRange { mount, start, end } => {
                let Some(staged) = ready.lexical_source().stage_definitions_at_range(
                    mount,
                    start,
                    end,
                    cancellation,
                )?
                else {
                    return Ok(None);
                };
                if staged.is_empty() {
                    inventory = inventory.combine(&missing(provenance)?);
                }
                definitions.extend(staged.into_iter().map(|(_, node)| node));
            }
        }
    }
    Ok(Some((definitions, inventory)))
}

#[cfg(test)]
mod export_proof_tests {
    use super::*;

    use crate::analyzer::resolution::PartialPathId;

    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#5658: first export evidence survived a later complete placement proof")]
    fn complete_placement_reduces_only_its_half_and_export_authority() {
        let fragment = BindingFragmentId::at_ordinal(1);
        let lookup = ResolutionLookupSemanticRecipe::new(
            Language::Rust,
            ResolutionNamespace::Type,
            "Chosen",
        );
        let gap = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
            "owned-export-gap",
        ));
        let other_gap = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::for_test(
            "other-placement-gap",
        ));
        let export = |definition, reasons: Box<[_]>| SelectedRootPathHalf::Export {
            identity: CandidatePathIdentity::new(fragment, PartialPathId::context_local(1)),
            token: SemanticId::for_test("export-token"),
            demand: SemanticId::for_test("export-demand"),
            definition: BindingNodeId::for_test(definition),
            incomplete_reasons: reasons,
        };
        let mut first_half = TargetProofGroups::default();
        let mut second_half = TargetProofGroups::default();
        retain_export_proof(
            &mut first_half,
            export("chosen", Box::new([gap])),
            lookup.clone(),
            ResolutionCompletion::Complete,
        );
        retain_export_proof(
            &mut second_half,
            export("chosen", Box::new([gap])),
            lookup.clone(),
            ResolutionCompletion::Complete,
        );
        retain_export_proof(
            &mut first_half,
            export("chosen", Box::new([])),
            lookup.clone(),
            ResolutionCompletion::Complete,
        );
        retain_export_proof(
            &mut first_half,
            export("chosen", Box::new([])),
            lookup.clone(),
            ResolutionCompletion::incomplete([other_gap]),
        );
        retain_export_proof(
            &mut first_half,
            export("other", Box::new([other_gap])),
            lookup,
            ResolutionCompletion::incomplete([gap]),
        );
        assert_eq!(first_half.len(), 2);
        for (authority, (half, _, completion)) in &first_half {
            let CandidateTarget::Export(SelectedRootPathHalf::Export {
                incomplete_reasons, ..
            }) = half
            else {
                unreachable!();
            };
            assert!(incomplete_reasons.is_empty());
            if authority.definition() == BindingNodeId::for_test("chosen") {
                assert_eq!(*completion, ResolutionCompletion::Complete);
            } else {
                assert_eq!(
                    *completion,
                    ResolutionCompletion::incomplete([gap, other_gap])
                );
            }
        }
        assert_eq!(
            second_half.values().next().unwrap().2,
            ResolutionCompletion::incomplete([gap])
        );
    }
}
