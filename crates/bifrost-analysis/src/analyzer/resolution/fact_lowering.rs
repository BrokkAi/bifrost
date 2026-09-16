//! File-local resolution facts lowered into compositional lexical paths.
//!
//! The lowerer consumes only [`FileResolutionFacts`]. It never reparses source
//! and never chooses a declaration for a reference. Instead, it builds one
//! immutable timeline per lexical scope. A reference pushes its effective
//! lookup key at the checkpoint active at its source position; binder paths
//! consume the same key at their activation checkpoint. Timeline and parent
//! paths preserve an arbitrary key, so the stitcher discovers targets from the
//! selected collection of fragments at query time.
//!
//! The returned artifact is operation-bounded. It can be consumed directly by
//! [`PreloadedFragment`] or normalized into SQL rows, and it retains explicit
//! coverage gaps alongside affirmative graph rows. It is not an arena or a
//! cache.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
    ResolutionBinderFact, ResolutionBinderKind, ResolutionCallableReceiverOrigin,
    ResolutionGapKind, ResolutionIdentifierRole, ResolutionImportRouteKind, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionNameId, ResolutionNamespace, ResolutionRootExportFact,
    ResolutionRootImportAnchor, ResolutionRootImportDemandFact, ResolutionRootImportFact,
    ResolutionRootReferenceFact, ResolutionScopeFact, ResolutionScopeId, ResolutionScopeKind,
    ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind, ResolutionTypeSlotId,
};
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

use crate::analyzer::structural::PrecedenceTier;
use crate::hash::{HashMap, HashSet};

use super::batch::FactReferenceSiteMetadata;
use super::engine::PreloadedFragment;
use super::local_identity::{
    ResolutionIdentityCatalogBuilder, ResolutionNodeIdentity, ResolutionPathIdentity,
    ResolutionSemanticIdentity, ResolutionStackVariableIdentity,
};
use super::model::{
    BindingFragmentId, BindingNodeId, BindingNodeKind, EndpointSignature, PartialPath,
    PartialPathId, PrecedenceStep, ResolutionCompletion, ResolutionIncompleteReason, SemanticId,
    StackPattern, StackVariableId, WitnessStep,
};
use super::{
    binder_namespace_is_declared, declaration_namespace_is_declared,
    producer_declares_definition_namespace,
};

use super::coverage::{
    LoweredCandidateDirection, LoweredCoverageGap, LoweringCoverageFrontier, LoweringGapOrigin,
};

/// Producer-owned graph domain for one definition semantic.
///
/// The source facts classify every definition, including declarations that
/// the external usage graph does not represent.  Keeping the out-of-domain
/// value explicit lets selected readers distinguish an intentional local or
/// pattern definition from an old row whose producer did not publish this
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactDefinitionGraphDomain {
    Type,
    Callable,
    Field,
    OutOfGraphDomain,
}

impl FactDefinitionGraphDomain {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Callable => "callable",
            Self::Field => "field",
            Self::OutOfGraphDomain => "out_of_graph_domain",
        }
    }
}

pub(crate) fn graph_definition_kind(
    kind: ResolutionSiteKind,
    member_owner: Option<ResolutionMemberOwnerFact>,
) -> FactDefinitionGraphDomain {
    match (kind, member_owner.map(|owner| owner.kind)) {
        (ResolutionSiteKind::TypeDeclaration, None | Some(ResolutionMemberKind::NestedType)) => {
            FactDefinitionGraphDomain::Type
        }
        (ResolutionSiteKind::CallableDeclaration, None | Some(ResolutionMemberKind::Method))
        | (
            ResolutionSiteKind::ConstructorDeclaration,
            None | Some(ResolutionMemberKind::Constructor),
        ) => FactDefinitionGraphDomain::Callable,
        (ResolutionSiteKind::ValueDeclaration, Some(ResolutionMemberKind::Field)) => {
            FactDefinitionGraphDomain::Field
        }
        _ => FactDefinitionGraphDomain::OutOfGraphDomain,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweredSemanticRole {
    Reference,
    Definition,
}

/// Stable correspondence between a file-local site and an engine identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredSemanticSite {
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    role: LoweredSemanticRole,
    semantic: SemanticId,
    node: BindingNodeId,
    site_metadata: Option<FactReferenceSiteMetadata>,
    definition_graph_domain: Option<FactDefinitionGraphDomain>,
}

impl LoweredSemanticSite {
    pub const fn site(&self) -> ResolutionSiteId {
        self.site
    }

    pub const fn namespace(&self) -> ResolutionNamespace {
        self.namespace
    }

    pub const fn role(&self) -> LoweredSemanticRole {
        self.role
    }

    pub const fn semantic(&self) -> SemanticId {
        self.semantic
    }

    pub const fn node(&self) -> BindingNodeId {
        self.node
    }

    pub const fn site_metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.site_metadata
    }

    /// Producer-owned graph-domain authority for this definition.
    ///
    /// Every declaration receives an explicit value, including definitions
    /// that are intentionally outside the usage graph. References have no
    /// definition domain and therefore return `None`.
    pub const fn definition_graph_domain(&self) -> Option<FactDefinitionGraphDomain> {
        self.definition_graph_domain
    }

    /// The source declaration containing this reference occurrence.
    ///
    /// This is independent of the lexical lookup scope. The outer option is
    /// `None` for a definition row or a partial producer that did not publish
    /// ownership. `Some(None)` explicitly means a reference outside any
    /// declaration, and `Some(Some(_))` names its containing definition.
    pub const fn reference_owner(&self) -> Option<Option<SemanticId>> {
        match self.site_metadata {
            Some(metadata) => metadata.reference_owner(),
            None => None,
        }
    }

    /// The source-syntax route that supplied a callable receiver.
    ///
    /// A partial producer may omit this metadata. The fact does not classify
    /// an explicit expression as a type or runtime receiver; that requires
    /// selected binding and type information.
    pub const fn callable_receiver_origin(&self) -> Option<ResolutionCallableReceiverOrigin> {
        match self.site_metadata {
            Some(metadata) => metadata.callable_receiver_origin(),
            None => None,
        }
    }
}

/// Immutable output of one file-local lowering operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredResolutionFragment {
    fragment: BindingFragmentId,
    language: Language,
    nodes: Vec<(BindingNodeId, BindingNodeKind)>,
    paths: Vec<(PartialPathId, PartialPath)>,
    semantics: Vec<LoweredSemanticSite>,
    gaps: Vec<LoweredCoverageGap>,
}

impl LoweredResolutionFragment {
    pub const fn fragment(&self) -> BindingFragmentId {
        self.fragment
    }

    /// The language that produced this fragment's effective lookup keys.
    ///
    /// Consumers that derive a secondary lookup index must use this value
    /// rather than infer a language from a selected path or file extension.
    pub const fn language(&self) -> Language {
        self.language
    }

    pub fn nodes(&self) -> &[(BindingNodeId, BindingNodeKind)] {
        &self.nodes
    }

    pub fn paths(&self) -> &[(PartialPathId, PartialPath)] {
        &self.paths
    }

    pub fn semantics(&self) -> &[LoweredSemanticSite] {
        &self.semantics
    }

    pub fn gaps(&self) -> &[LoweredCoverageGap] {
        &self.gaps
    }

    /// Consume the operation-local artifact without losing coverage metadata.
    ///
    /// The tuple intentionally makes gaps a mandatory return value. The
    /// preload adapter installs these rows with their owning fragment. A caller cannot
    /// obtain a `PreloadedFragment` through this API without also receiving
    /// the rows it must apply to fragment, enumeration, candidate, and type
    /// completion.
    pub fn into_preloaded_parts(self) -> (PreloadedFragment, Box<[LoweredCoverageGap]>) {
        let Self {
            fragment,
            nodes,
            paths,
            semantics,
            gaps,
            ..
        } = self;
        let mut reference_metadata = Vec::new();
        for semantic in semantics {
            if semantic.role != LoweredSemanticRole::Reference {
                continue;
            }
            reference_metadata.push((
                semantic.semantic,
                semantic
                    .site_metadata
                    .expect("every lowered reference has source-site metadata"),
            ));
        }
        (
            PreloadedFragment::new(fragment, nodes, paths)
                .with_reference_metadata(reference_metadata),
            gaps.into_boxed_slice(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedActivation {
    ScopeWide,
    SourceOrder(usize),
}

#[derive(Debug, Clone, Copy)]
struct SupportedBinder<'facts> {
    fact: &'facts ResolutionBinderFact,
    identifier: &'facts PositionedIdentifierFact,
    activation: SupportedActivation,
}

#[derive(Debug, Clone)]
struct ScopeTimeline {
    fact: ResolutionScopeFact,
    head: BindingNodeId,
    checkpoints: Vec<ActivationCheckpoint>,
}

impl ScopeTimeline {
    fn active_node_at(&self, position: usize) -> BindingNodeId {
        self.checkpoints
            .partition_point(|checkpoint| checkpoint.position <= position)
            .checked_sub(1)
            .map(|index| self.checkpoints[index].node)
            .unwrap_or(self.head)
    }

    fn checkpoint_at(&self, position: usize) -> &ActivationCheckpoint {
        let index = self
            .checkpoints
            .binary_search_by_key(&position, |checkpoint| checkpoint.position)
            .expect("supported source-order activation has a checkpoint");
        &self.checkpoints[index]
    }
}

#[derive(Debug, Clone, Copy)]
struct ActivationCheckpoint {
    position: usize,
    node: BindingNodeId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct GapSource {
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
}

struct LoweredScopeTimelines {
    timelines: HashMap<ResolutionScopeId, ScopeTimeline>,
    nodes: Vec<(BindingNodeId, BindingNodeKind)>,
    paths: Vec<(PartialPathId, PartialPath)>,
}

fn lower_scope_timelines_and_paths(
    identities: &mut ResolutionIdentityCatalogBuilder,
    index: &FactIndex<'_>,
    activation_positions: &HashMap<ResolutionScopeId, Vec<usize>>,
) -> LoweredScopeTimelines {
    let mut timelines = HashMap::default();
    let mut nodes = Vec::new();
    for scope in index.scopes_sorted() {
        let head = identities.node(scope_head_node_identity(scope.id));
        nodes.push((head, BindingNodeKind::Scope));
        let checkpoints = activation_positions
            .get(&scope.id)
            .into_iter()
            .flatten()
            .copied()
            .map(|position| {
                let node = identities.node(checkpoint_node_identity(scope.id, position));
                nodes.push((node, BindingNodeKind::Scope));
                ActivationCheckpoint { position, node }
            })
            .collect::<Vec<_>>();
        assert!(
            timelines
                .insert(
                    scope.id,
                    ScopeTimeline {
                        fact: scope,
                        head,
                        checkpoints,
                    },
                )
                .is_none()
        );
    }

    let mut paths = Vec::new();
    for timeline in timelines.values() {
        let mut previous = timeline.head;
        for checkpoint in &timeline.checkpoints {
            let id = identities.path(timeline_path_identity(
                timeline.fact.id,
                checkpoint.position,
            ));
            let variable = passthrough_variable(identities, id);
            paths.push((
                id,
                PartialPath::new(
                    open_endpoint(checkpoint.node, variable),
                    open_endpoint(previous, variable),
                    checkpoint_fallback_precedence(
                        identities,
                        timeline.fact.id,
                        checkpoint.position,
                    ),
                    [WitnessStep::Node(previous)],
                    ResolutionCompletion::Complete,
                ),
            ));
            previous = checkpoint.node;
        }

        if let Some(parent) = timeline.fact.parent {
            let parent_timeline = timelines
                .get(&parent)
                .expect("validated scope parent has a timeline");
            let parent_checkpoint = parent_timeline.active_node_at(timeline.fact.start_byte);
            let id = identities.path(parent_path_identity(timeline.fact.id));
            let variable = passthrough_variable(identities, id);
            paths.push((
                id,
                PartialPath::new(
                    open_endpoint(timeline.head, variable),
                    open_endpoint(parent_checkpoint, variable),
                    if timeline.fact.kind == ResolutionScopeKind::TypeBody {
                        type_body_enclosing_precedence(identities, timeline.fact.id)
                    } else {
                        scope_fallback_precedence(identities, timeline.fact.id)
                    },
                    [WitnessStep::Node(parent_checkpoint)],
                    ResolutionCompletion::Complete,
                ),
            ));
        }
    }
    LoweredScopeTimelines {
        timelines,
        nodes,
        paths,
    }
}

/// Lower one file's target-independent facts into compositional lexical paths.
///
/// `fragment` identifies the immutable file-local artifact. `language` is part
/// of effective lookup keys so equal spellings in unrelated language domains
/// never stitch. Entity, node, and path IDs include the fragment plus typed
/// local IDs and producer roles; reordering normalized input rows therefore
/// cannot change output identity or order.
pub fn lower_file_resolution_facts(
    fragment: BindingFragmentId,
    language: Language,
    facts: &FileResolutionFacts,
) -> LoweredResolutionFragment {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment);
    lower_file_resolution_facts_with_identities(&mut identities, language, facts)
}

pub(super) fn lower_file_resolution_facts_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> LoweredResolutionFragment {
    let fragment = identities.fragment();
    assert_ne!(language, Language::None, "resolution facts need a language");
    let index = FactIndex::new(facts);
    index.validate_scope_forest();

    let mut gap_sources = facts
        .gaps
        .iter()
        .map(|gap| GapSource {
            site: gap.site,
            origin: LoweringGapOrigin::Extracted(gap.kind),
        })
        .collect::<Vec<_>>();
    let mut reference_enumeration_sources = HashSet::default();
    for gap in &facts.reference_enumeration_gaps {
        let source = GapSource {
            site: gap.site,
            origin: LoweringGapOrigin::Extracted(gap.kind),
        };
        assert!(
            reference_enumeration_sources.insert(source),
            "duplicate reference-enumeration gap: {gap:?}"
        );
    }
    let mut supported_binders = Vec::new();
    let mut activation_positions: HashMap<ResolutionScopeId, Vec<usize>> = HashMap::default();
    let mut declarations_with_binders = HashSet::default();
    for binder in &facts.binders {
        let scope = index.scope(binder.scope);
        let declaration = index.site(binder.declaration);
        assert_eq!(
            declaration.scope, binder.scope,
            "binder declaration must be positioned in its binding scope: {binder:?}"
        );
        assert!(
            scope.start_byte <= binder.activation_start
                && binder.activation_start <= binder.activation_end
                && binder.activation_end <= scope.end_byte,
            "binder activation must be contained by its scope: {binder:?}, {scope:?}"
        );
        let identifier = index.declaration_identifier(binder.declaration);
        assert!(
            binder_namespace_is_declared(facts, *binder, identifier.namespace),
            "binder kind and declaration namespace disagree: {binder:?}, {identifier:?}"
        );
        declarations_with_binders.insert(binder.declaration);
        let activation = match binder.hoisting {
            HoistingClass::ScopeWide
                if binder.activation_start == scope.start_byte
                    && binder.activation_end == scope.end_byte =>
            {
                Some(SupportedActivation::ScopeWide)
            }
            HoistingClass::SourceOrder if binder.activation_end == scope.end_byte => {
                activation_positions
                    .entry(binder.scope)
                    .or_default()
                    .push(binder.activation_start);
                Some(SupportedActivation::SourceOrder(binder.activation_start))
            }
            _ => None,
        };
        if let Some(activation) = activation {
            supported_binders.push(SupportedBinder {
                fact: binder,
                identifier,
                activation,
            });
        } else {
            gap_sources.push(GapSource {
                site: binder.declaration,
                origin: LoweringGapOrigin::UnsupportedActivation(binder.hoisting),
            });
        }
    }

    let deferred_member_declarations = facts
        .deferred_member_owners
        .iter()
        .map(|owner| owner.member)
        .collect::<HashSet<_>>();
    for identifier in &facts.identifiers {
        if identifier.role == ResolutionIdentifierRole::Declaration
            && !declarations_with_binders.contains(&identifier.site)
            // An explicit member owner supplies a non-lexical binding route.
            // Missing lexical authority is a gap only for declarations that
            // have no such structured ownership, not for associated members.
            && !deferred_member_declarations.contains(&identifier.site)
        {
            gap_sources.push(GapSource {
                site: identifier.site,
                origin: LoweringGapOrigin::MissingBinder,
            });
        }
        if identifier.role == ResolutionIdentifierRole::Reference && identifier.qualifier.is_some()
        {
            gap_sources.push(GapSource {
                site: identifier.site,
                origin: LoweringGapOrigin::QualifiedReference,
            });
        }
    }
    gap_sources.sort_unstable();
    gap_sources.dedup();
    let point_gap_sources = gap_sources.iter().copied().collect::<HashSet<_>>();
    let mut coverage_gap_sources = gap_sources.clone();
    coverage_gap_sources.extend(reference_enumeration_sources.iter().copied());
    coverage_gap_sources.sort_unstable();
    coverage_gap_sources.dedup();

    for positions in activation_positions.values_mut() {
        positions.sort_unstable();
        positions.dedup();
    }

    let LoweredScopeTimelines {
        timelines,
        mut nodes,
        mut paths,
    } = lower_scope_timelines_and_paths(identities, &index, &activation_positions);

    let mut semantics = Vec::new();
    let mut semantic_by_site = HashMap::default();
    for identifier in index.identifiers_sorted() {
        let site = index.site(identifier.site);
        let (role, semantic, node, kind) = match identifier.role {
            ResolutionIdentifierRole::Reference => {
                let semantic = identities.semantic(reference_semantic_identity(identifier.site));
                let node = identities.node(reference_node_identity(identifier.site));
                (
                    LoweredSemanticRole::Reference,
                    semantic,
                    node,
                    BindingNodeKind::Reference(semantic),
                )
            }
            ResolutionIdentifierRole::Declaration => {
                let semantic = identities.semantic(definition_semantic_identity(identifier.site));
                let node = identities.node(definition_node_identity(identifier.site));
                (
                    LoweredSemanticRole::Definition,
                    semantic,
                    node,
                    BindingNodeKind::Definition(semantic),
                )
            }
        };
        assert!(
            semantic_by_site
                .insert((identifier.site, role), (semantic, node))
                .is_none(),
            "one semantic role per positioned site is required: {identifier:?}"
        );
        semantics.push(LoweredSemanticSite {
            site: identifier.site,
            namespace: identifier.namespace,
            role,
            semantic,
            node,
            site_metadata: (identifier.role == ResolutionIdentifierRole::Reference).then(|| {
                FactReferenceSiteMetadata::new(
                    identifier.site,
                    identifier.namespace,
                    site.kind,
                    site.start_byte,
                    site.end_byte,
                    identifier.qualifier.is_none()
                        && index.root_reference(identifier.site).is_none(),
                    index.reference_owner(identifier.site).map(|owner| {
                        owner.map(|owner| identities.semantic(definition_semantic_identity(owner)))
                    }),
                    index.callable_receiver_origin(identifier.site),
                )
            }),
            definition_graph_domain: (identifier.role == ResolutionIdentifierRole::Declaration)
                .then(|| {
                    graph_definition_kind(
                        site.kind,
                        index
                            .member_owner_by_declaration
                            .get(&identifier.site)
                            .copied(),
                    )
                }),
        });
        nodes.push((node, kind));
    }

    let reasons_by_site = gap_reasons_by_site(identities, &gap_sources);
    let mut forward_gap_endpoints = HashMap::default();

    for semantic in semantics
        .iter()
        .filter(|semantic| semantic.role == LoweredSemanticRole::Reference)
    {
        let identifier = index.reference_identifier(semantic.site);
        let site = index.site(semantic.site);
        let completion = completion_for_site(&reasons_by_site, semantic.site, lexical_gap);
        if index.root_reference(identifier.site).is_some() {
            // A root-qualified reference has an explicit source-owned route.
            // Its terminal semantic remains ordinary, but it must not also
            // publish a lexical route that could close through a local decoy.
            continue;
        }
        if identifier.qualifier.is_some() {
            let sink = identities.node(gap_sink_node_identity(
                semantic.site,
                b"qualified-reference",
            ));
            nodes.push((sink, BindingNodeKind::Scope));
            let id = identities.path(reference_gap_path_identity(semantic.site));
            paths.push((
                id,
                PartialPath::new(
                    closed_endpoint(semantic.node, []),
                    closed_endpoint(sink, []),
                    Vec::new(),
                    [WitnessStep::Node(sink)],
                    completion,
                ),
            ));
            continue;
        }

        let timeline = timelines
            .get(&site.scope)
            .expect("validated reference scope has a timeline");
        let checkpoint = timeline.active_node_at(site.start_byte);
        for &(route_ordinal, namespace) in lookup_routes(identifier.namespace) {
            let lookup =
                identities.lookup_semantic(language, namespace, index.name(identifier.name));
            let precedence =
                (identifier.namespace == ResolutionNamespace::TypeOrValue).then(|| {
                    identities.register_precedence_namespace(
                        PrecedenceStep {
                            tier: PrecedenceTier::LexicalBinding,
                            ordinal: route_ordinal,
                            semantic: semantic.semantic,
                        },
                        namespace,
                    )
                });
            let id = identities.path(reference_path_identity(semantic.site, namespace));
            paths.push((
                id,
                PartialPath::new(
                    closed_endpoint(semantic.node, []),
                    closed_endpoint(checkpoint, [lookup]),
                    precedence.into_iter().collect::<Vec<_>>(),
                    [WitnessStep::Node(checkpoint)],
                    completion.clone(),
                ),
            ));
        }
    }

    let supported_declarations = supported_binders
        .iter()
        .map(|binder| binder.fact.declaration)
        .collect::<HashSet<_>>();
    for binder in supported_binders {
        let timeline = timelines
            .get(&binder.fact.scope)
            .expect("validated binder scope has a timeline");
        let checkpoint = match binder.activation {
            SupportedActivation::ScopeWide => timeline.head,
            SupportedActivation::SourceOrder(position) => {
                let checkpoint = timeline.checkpoint_at(position);
                checkpoint.node
            }
        };
        let (definition, definition_node) = semantic_by_site
            .get(&(binder.fact.declaration, LoweredSemanticRole::Definition))
            .copied()
            .expect("binder declaration has a definition semantic");
        assert!(
            forward_gap_endpoints
                .insert(binder.fact.declaration, checkpoint)
                .is_none(),
            "one supported binder route per declaration is required"
        );
        let primary_namespace = effective_declaration_namespace(binder.identifier.namespace);
        let namespaces = std::iter::once(primary_namespace).chain(
            index
                .additional_definition_namespaces(binder.fact.declaration)
                .iter()
                .map(|fact| fact.namespace)
                .filter(|namespace| *namespace != primary_namespace),
        );
        for namespace in namespaces {
            let lookup =
                identities.lookup_semantic(language, namespace, index.name(binder.identifier.name));
            let identity = if namespace == primary_namespace {
                binder_path_identity(binder.fact.declaration)
            } else {
                additional_binder_path_identity(binder.fact.declaration, namespace)
            };
            let id = identities.path(identity);
            paths.push((
                id,
                PartialPath::new(
                    closed_endpoint(checkpoint, [lookup]),
                    closed_endpoint(definition_node, []),
                    binder_precedence(identities, timeline, &binder),
                    [WitnessStep::Node(definition_node)],
                    completion_for_site(&reasons_by_site, binder.fact.declaration, lexical_gap),
                ),
            ));
        }
        debug_assert_eq!(
            definition,
            definition_semantic(fragment, binder.fact.declaration)
        );
    }

    // A declaration whose binder route was withheld still contributes a
    // symbol-specific incomplete dead end. References to unrelated names in
    // the same scope do not compose with it.
    for semantic in semantics
        .iter()
        .filter(|semantic| semantic.role == LoweredSemanticRole::Definition)
    {
        if supported_declarations.contains(&semantic.site)
            || deferred_member_declarations.contains(&semantic.site)
        {
            continue;
        }
        let identifier = index.declaration_identifier(semantic.site);
        let site = index.site(semantic.site);
        let timeline = timelines
            .get(&site.scope)
            .expect("validated declaration scope has a timeline");
        let lookup = identities.lookup_semantic(
            language,
            effective_declaration_namespace(identifier.namespace),
            index.name(identifier.name),
        );
        let sink = identities.node(gap_sink_node_identity(semantic.site, b"missing-binder"));
        nodes.push((sink, BindingNodeKind::Scope));
        let id = identities.path(missing_binder_path_identity(semantic.site));
        assert!(
            forward_gap_endpoints
                .insert(semantic.site, timeline.head)
                .is_none(),
            "a withheld binder cannot also have a supported route"
        );
        paths.push((
            id,
            PartialPath::new(
                closed_endpoint(timeline.head, [lookup]),
                closed_endpoint(sink, [lookup]),
                Vec::new(),
                [WitnessStep::Node(sink)],
                completion_for_site(&reasons_by_site, semantic.site, |_| true),
            ),
        ));
    }

    lower_root_import_paths(identities, language, &index, &mut paths);
    lower_root_reference_paths(identities, language, &index, &reasons_by_site, &mut paths);
    lower_root_export_paths(identities, language, &index, &mut paths);

    // Placement and hierarchy uncertainty are real branches, not global
    // candidate poison. Their open stack tails preserve the exact lookup key
    // that reached the boundary, while their precedence traces let a proven
    // nearer binder discharge only the losing branch.
    for &source in &gap_sources {
        if source.origin == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute)
            && let Some(import) = index.structured_import(source.site)
        {
            assert_eq!(
                language,
                Language::Java,
                "structured Java import facts require Java lowering"
            );
            let timeline = timelines
                .get(&import.root_scope)
                .expect("validated import root has a timeline");
            for &namespace in single_import_namespaces(import.kind) {
                let bound_name = import
                    .bound_name
                    .expect("single-name import has a bound name");
                let (sink, row) = structured_import_gap_lexical_row_with_identities(
                    identities,
                    import.root_scope,
                    source.site,
                    namespace,
                    index.name(bound_name),
                );
                nodes.push((sink, BindingNodeKind::Scope));
                debug_assert_eq!(row.1.start().node(), timeline.head);
                paths.push(row);
            }
        }

        if source.origin
            == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
        {
            let scope = placement_scope(&index, source);
            let timeline = timelines
                .get(&scope.id)
                .expect("validated placement scope has a timeline");
            let (sink, row) =
                placement_gap_lexical_row_with_identities(identities, source.site, scope.id);
            nodes.push((sink, BindingNodeKind::Scope));
            debug_assert_eq!(row.1.start().node(), timeline.head);
            paths.push(row);
        }

        if hierarchy_boundary_gap(source.origin) {
            let owner = index.hierarchy_gap_owner(source.site);
            let Some(type_body) = index.type_body_scope(owner) else {
                // Malformed or incomplete declarations may have no body. The
                // typed and reverse-inventory gaps remain authoritative, but
                // there is no lexical member scope at which to place a
                // hierarchy fallback branch.
                continue;
            };
            let timeline = timelines
                .get(&type_body.id)
                .expect("validated type body has a timeline");
            // Keep every producer reason on its own terminal path. A later
            // selected-context evaluator can then discharge one exact
            // supertype obligation without erasing its siblings.
            let sink = identities.node(gap_sink_node_identity(source.site, b"hierarchy-terminal"));
            nodes.push((sink, BindingNodeKind::Scope));
            let id = identities.path(hierarchy_gap_path_identity(source.site, owner));
            let variable = passthrough_variable(identities, id);
            paths.push((
                id,
                PartialPath::new(
                    open_endpoint(timeline.head, variable),
                    open_endpoint(sink, variable),
                    type_body_hierarchy_precedence(identities, type_body.id),
                    [WitnessStep::Node(sink)],
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(
                            identities
                                .semantic(gap_reason_semantic_identity(source.site, source.origin)),
                        ),
                    ]),
                ),
            ));
        }
    }

    let mut gaps = lower_coverage_gaps(
        identities,
        language,
        GapCoverageSources {
            all: &coverage_gap_sources,
            point: &point_gap_sources,
            enumeration: &reference_enumeration_sources,
            deferred_members: &deferred_member_declarations,
        },
        &index,
        &semantic_by_site,
        &forward_gap_endpoints,
    );
    gaps.sort_unstable();
    gaps.dedup();
    nodes.sort_unstable_by_key(|(id, _)| *id);
    assert!(
        nodes.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "lowering emitted duplicate binding nodes"
    );
    paths.sort_unstable_by_key(|(id, _)| *id);
    assert!(
        paths.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "lowering emitted duplicate partial paths"
    );
    semantics.sort_unstable();
    LoweredResolutionFragment {
        fragment,
        language,
        nodes,
        paths,
        semantics,
        gaps,
    }
}

/// Lower content-owned import demand into a route that stops at the universal
/// root. Selected context later pairs the source-local import token with one or
/// more destination-local export tokens; lowering never chooses that target.
fn lower_root_import_paths(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    index: &FactIndex<'_>,
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    for import in &index.root_imports {
        let mut routes_by_namespace = HashMap::default();
        for demand in &import.demands {
            let route = routes_by_namespace
                .entry(demand.namespace)
                .or_insert_with(|| {
                    import
                        .segments
                        .iter()
                        .map(|&name| {
                            identities.lookup_semantic(language, demand.namespace, index.name(name))
                        })
                        .collect::<Vec<_>>()
                })
                .clone();
            let lookup =
                identities.lookup_semantic(language, demand.namespace, index.name(demand.name));
            let token = identities.semantic(root_import_token_identity(
                import.fact.site,
                demand.namespace,
            ));
            let id = identities.path(root_import_path_identity(
                import.fact.site,
                demand.namespace,
                demand.name,
            ));
            debug_assert_eq!(
                token,
                root_import_token(identities.fragment(), import.fact.site, demand.namespace)
            );
            debug_assert_eq!(
                id,
                root_import_path_id(
                    identities.fragment(),
                    import.fact.site,
                    demand.namespace,
                    demand.name,
                )
            );
            let tail = passthrough_variable(identities, id);
            let mut root_symbols = Vec::with_capacity(route.len().saturating_add(3));
            root_symbols.push(
                identities.semantic(root_import_anchor_semantic_identity(import.fact.anchor)),
            );
            root_symbols.extend(route);
            root_symbols.push(token);
            root_symbols.push(lookup);
            let choice = identities.semantic(scope_choice_identity(
                import.fact.root_scope,
                demand.namespace,
            ));
            paths.push((
                id,
                PartialPath::new(
                    symbol_open_endpoint(
                        identities.node(scope_head_node_identity(import.fact.root_scope)),
                        [lookup],
                        tail,
                    ),
                    symbol_open_endpoint(BindingNodeId::universal_root(), root_symbols, tail),
                    [identities.register_precedence_namespace(
                        PrecedenceStep {
                            tier: PrecedenceTier::WildcardImport,
                            ordinal: 0,
                            semantic: choice,
                        },
                        demand.namespace,
                    )],
                    [WitnessStep::Node(BindingNodeId::universal_root())],
                    ResolutionCompletion::Complete,
                ),
            ));
        }
    }
}

/// Lower a direct root-qualified reference as a closed source-owned route.
/// Unlike an import route this begins at the reference node with an empty
/// stack, so no lexical decoy can satisfy the terminal lookup before the
/// route reaches the universal root.
fn lower_root_reference_paths(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    index: &FactIndex<'_>,
    reasons_by_site: &HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>>,
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    for reference in &index.root_references {
        let identifier = index.reference_identifier(reference.fact.reference);
        let namespace = identifier.namespace;
        let route = reference
            .segments
            .iter()
            .map(|&name| identities.lookup_semantic(language, namespace, index.name(name)))
            .collect::<Vec<_>>();
        let lookup = identities.lookup_semantic(language, namespace, index.name(identifier.name));
        let token = identities.semantic(root_reference_token_identity(
            reference.fact.reference,
            namespace,
        ));
        let id = identities.path(root_reference_path_identity(
            reference.fact.reference,
            namespace,
        ));
        debug_assert_eq!(
            token,
            root_reference_token(identities.fragment(), reference.fact.reference, namespace)
        );
        debug_assert_eq!(
            id,
            root_reference_path_id(identities.fragment(), reference.fact.reference, namespace)
        );
        let mut root_symbols = Vec::with_capacity(route.len().saturating_add(3));
        root_symbols
            .push(identities.semantic(root_import_anchor_semantic_identity(reference.fact.anchor)));
        root_symbols.extend(route);
        root_symbols.push(token);
        root_symbols.push(lookup);
        let choice =
            identities.semantic(scope_choice_identity(reference.fact.root_scope, namespace));
        paths.push((
            id,
            PartialPath::new(
                closed_endpoint(
                    identities.node(reference_node_identity(reference.fact.reference)),
                    Vec::new(),
                ),
                closed_endpoint(BindingNodeId::universal_root(), root_symbols),
                [identities.register_precedence_namespace(
                    PrecedenceStep {
                        tier: PrecedenceTier::PackageOrModule,
                        ordinal: 0,
                        semantic: choice,
                    },
                    namespace,
                )],
                [
                    WitnessStep::Node(
                        identities.node(scope_head_node_identity(reference.fact.root_scope)),
                    ),
                    WitnessStep::Node(BindingNodeId::universal_root()),
                ],
                completion_for_site(reasons_by_site, reference.fact.reference, lexical_gap),
            ),
        ));
    }
}

/// Lower declarations that selected root context may expose. The leading
/// lookup stays Shared for indexed root discovery; the following local token
/// prevents source facts alone from choosing a package or module target.
fn lower_root_export_paths(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    index: &FactIndex<'_>,
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    for &export in &index.root_exports {
        let identifier = index.declaration_identifier(export.declaration);
        let lookup =
            identities.lookup_semantic(language, export.namespace, index.name(identifier.name));
        let token = identities.semantic(root_export_token_identity(
            export.root_scope,
            export.namespace,
        ));
        let id = identities.path(root_export_path_identity(
            export.root_scope,
            export.declaration,
            export.namespace,
        ));
        debug_assert_eq!(
            token,
            root_export_token(identities.fragment(), export.root_scope, export.namespace)
        );
        debug_assert_eq!(
            id,
            root_export_path_id(
                identities.fragment(),
                export.root_scope,
                export.declaration,
                export.namespace,
            )
        );
        let tail = passthrough_variable(identities, id);
        let definition = identities.node(definition_node_identity(export.declaration));
        paths.push((
            id,
            PartialPath::new(
                symbol_open_endpoint(BindingNodeId::universal_root(), [lookup, token], tail),
                symbol_open_endpoint(definition, Vec::new(), tail),
                [identities.register_precedence_namespace(
                    PrecedenceStep {
                        tier: PrecedenceTier::PackageOrModule,
                        ordinal: 0,
                        semantic: token,
                    },
                    export.namespace,
                )],
                [WitnessStep::Node(definition)],
                ResolutionCompletion::Complete,
            ),
        ));
    }
}

struct FactIndex<'facts> {
    names: HashMap<ResolutionNameId, &'facts str>,
    scopes: HashMap<ResolutionScopeId, ResolutionScopeFact>,
    sites: HashMap<ResolutionSiteId, ResolutionSiteFact>,
    identifiers_by_site: HashMap<ResolutionSiteId, Vec<&'facts PositionedIdentifierFact>>,
    additional_definition_namespaces_by_declaration:
        HashMap<ResolutionSiteId, Vec<ResolutionAdditionalDefinitionNamespaceFact>>,
    reference_owner_by_reference: HashMap<ResolutionSiteId, Option<ResolutionSiteId>>,
    callable_receiver_origin_by_reference:
        HashMap<ResolutionSiteId, ResolutionCallableReceiverOrigin>,
    type_slots_by_site: HashMap<ResolutionSiteId, Vec<ResolutionTypeSlotId>>,
    supertype_owner_by_reference: HashMap<ResolutionSiteId, ResolutionSiteId>,
    type_body_scope_by_owner: HashMap<ResolutionSiteId, ResolutionScopeFact>,
    member_owner_by_declaration: HashMap<ResolutionSiteId, ResolutionMemberOwnerFact>,
    structured_import_by_site: HashMap<ResolutionSiteId, StructuredImportFact>,
    root_imports: Vec<IndexedRootImport>,
    root_references: Vec<IndexedRootReference>,
    root_exports: Vec<ResolutionRootExportFact>,
}

#[derive(Clone, Copy)]
struct StructuredImportFact {
    root_scope: ResolutionScopeId,
    kind: ResolutionImportRouteKind,
    bound_name: Option<ResolutionNameId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedRootImport {
    fact: ResolutionRootImportFact,
    segments: Vec<ResolutionNameId>,
    demands: Vec<ResolutionRootImportDemandFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedRootReference {
    fact: ResolutionRootReferenceFact,
    segments: Vec<ResolutionNameId>,
}

impl<'facts> FactIndex<'facts> {
    fn index_root_imports(
        facts: &'facts FileResolutionFacts,
        names: &HashMap<ResolutionNameId, &'facts str>,
        scopes: &HashMap<ResolutionScopeId, ResolutionScopeFact>,
        sites: &HashMap<ResolutionSiteId, ResolutionSiteFact>,
    ) -> Vec<IndexedRootImport> {
        let mut root_import_by_site = HashMap::default();
        for &import in &facts.root_imports {
            let root_scope = scopes.get(&import.root_scope).unwrap_or_else(|| {
                panic!(
                    "root import {} names unknown root scope {}",
                    import.site, import.root_scope
                )
            });
            assert_import_scope(*root_scope, "root import");
            let site = sites
                .get(&import.site)
                .unwrap_or_else(|| panic!("root import names unknown site {}", import.site));
            assert!(
                site.kind == ResolutionSiteKind::ImportDeclaration
                    && site.scope == import.root_scope,
                "root import must be owned by its declared import site and root scope: {import:?}, {site:?}"
            );
            assert!(
                root_import_by_site.insert(import.site, import).is_none(),
                "one root import per import site is required: {import:?}"
            );
        }

        let mut segments_by_site: HashMap<_, Vec<_>> = HashMap::default();
        let mut segment_positions = HashSet::default();
        for &segment in &facts.root_import_segments {
            assert!(
                root_import_by_site.contains_key(&segment.import_site),
                "root-import segment names unknown import site: {segment:?}"
            );
            let spelling = names
                .get(&segment.name)
                .unwrap_or_else(|| panic!("root-import segment names unknown name: {segment:?}"));
            assert!(
                !spelling.is_empty(),
                "root-import segment spelling must be nonempty: {segment:?}"
            );
            assert!(
                segment_positions.insert((segment.import_site, segment.position)),
                "root-import segment positions must be unique: {segment:?}"
            );
            segments_by_site
                .entry(segment.import_site)
                .or_default()
                .push(segment);
        }

        let mut demands_by_site: HashMap<_, Vec<_>> = HashMap::default();
        let mut demand_keys = HashSet::default();
        for &demand in &facts.root_import_demands {
            assert!(
                root_import_by_site.contains_key(&demand.import_site),
                "root-import demand names unknown import site: {demand:?}"
            );
            assert!(
                demand.namespace != ResolutionNamespace::TypeOrValue,
                "root-import demand needs an effective namespace: {demand:?}"
            );
            let spelling = names
                .get(&demand.name)
                .unwrap_or_else(|| panic!("root-import demand names unknown name: {demand:?}"));
            assert!(
                !spelling.is_empty(),
                "root-import demand spelling must be nonempty: {demand:?}"
            );
            assert!(
                demand_keys.insert((demand.import_site, demand.namespace, demand.name)),
                "root-import demands must be unique: {demand:?}"
            );
            demands_by_site
                .entry(demand.import_site)
                .or_default()
                .push(demand);
        }

        let mut root_imports = root_import_by_site
            .into_values()
            .map(|fact| {
                let mut segments = segments_by_site.remove(&fact.site).unwrap_or_default();
                segments.sort_unstable_by_key(|segment| segment.position);
                assert!(
                    !segments.is_empty(),
                    "a root import needs at least one route segment: {fact:?}"
                );
                for (expected, segment) in segments.iter().enumerate() {
                    assert_eq!(
                        segment.position,
                        u32::try_from(expected)
                            .expect("root-import segment count must fit its u32 position"),
                        "root-import segment positions must be dense from zero: {segments:?}"
                    );
                }
                let mut demands = demands_by_site.remove(&fact.site).unwrap_or_default();
                demands.sort_unstable_by_key(|demand| (demand.namespace, demand.name));
                IndexedRootImport {
                    fact,
                    segments: segments.into_iter().map(|segment| segment.name).collect(),
                    demands,
                }
            })
            .collect::<Vec<_>>();
        assert!(segments_by_site.is_empty());
        assert!(demands_by_site.is_empty());
        root_imports.sort_unstable_by_key(|import| import.fact.site);
        root_imports
    }

    fn index_root_references(
        facts: &'facts FileResolutionFacts,
        names: &HashMap<ResolutionNameId, &'facts str>,
        scopes: &HashMap<ResolutionScopeId, ResolutionScopeFact>,
        sites: &HashMap<ResolutionSiteId, ResolutionSiteFact>,
        identifiers_by_site: &HashMap<ResolutionSiteId, Vec<&'facts PositionedIdentifierFact>>,
    ) -> Vec<IndexedRootReference> {
        let mut root_reference_by_site = HashMap::default();
        for &reference in &facts.root_references {
            let root_scope = scopes.get(&reference.root_scope).unwrap_or_else(|| {
                panic!(
                    "root reference {} names unknown root scope {}",
                    reference.reference, reference.root_scope
                )
            });
            assert_import_scope(*root_scope, "root reference");
            let site = sites.get(&reference.reference).unwrap_or_else(|| {
                panic!("root reference names unknown site {}", reference.reference)
            });
            let identifier = identifiers_by_site
                .get(&reference.reference)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!(
                        "root reference names a site without a positioned identifier: {reference:?}"
                    )
                });
            assert_eq!(
                identifier.role,
                ResolutionIdentifierRole::Reference,
                "root reference must name a reference identifier: {reference:?}, {identifier:?}"
            );
            assert_eq!(
                identifier.qualifier, None,
                "root reference must not have a type qualifier: {reference:?}, {identifier:?}"
            );
            assert_ne!(
                identifier.namespace,
                ResolutionNamespace::TypeOrValue,
                "root reference needs an effective namespace: {reference:?}, {identifier:?}"
            );
            assert!(
                root_scope_is_ancestor(*root_scope, *site, scopes),
                "root reference root scope must be an ancestor of its site: {reference:?}, {site:?}, root={root_scope:?}"
            );
            assert!(
                root_reference_by_site
                    .insert(reference.reference, reference)
                    .is_none(),
                "one root reference row per reference site is required: {reference:?}"
            );
        }

        let mut segments_by_reference: HashMap<_, Vec<_>> = HashMap::default();
        let mut segment_positions = HashSet::default();
        for &segment in &facts.root_reference_segments {
            assert!(
                root_reference_by_site.contains_key(&segment.reference),
                "root-reference segment names unknown reference site: {segment:?}"
            );
            let spelling = names.get(&segment.name).unwrap_or_else(|| {
                panic!("root-reference segment names unknown name: {segment:?}")
            });
            assert!(
                !spelling.is_empty(),
                "root-reference segment spelling must be nonempty: {segment:?}"
            );
            assert!(
                segment_positions.insert((segment.reference, segment.position)),
                "root-reference segment positions must be unique: {segment:?}"
            );
            segments_by_reference
                .entry(segment.reference)
                .or_default()
                .push(segment);
        }

        let mut root_references = root_reference_by_site
            .into_values()
            .map(|fact| {
                let mut segments = segments_by_reference
                    .remove(&fact.reference)
                    .unwrap_or_default();
                segments.sort_unstable_by_key(|segment| segment.position);
                for (expected, segment) in segments.iter().enumerate() {
                    assert_eq!(
                        segment.position,
                        u32::try_from(expected)
                            .expect("root-reference segment count must fit its u32 position"),
                        "root-reference segment positions must be dense from zero: {segments:?}"
                    );
                }
                IndexedRootReference {
                    fact,
                    segments: segments.into_iter().map(|segment| segment.name).collect(),
                }
            })
            .collect::<Vec<_>>();
        assert!(segments_by_reference.is_empty());
        root_references.sort_unstable_by_key(|reference| reference.fact.reference);
        root_references
    }

    fn new(facts: &'facts FileResolutionFacts) -> Self {
        let mut names = HashMap::default();
        for name in &facts.names {
            assert!(
                names.insert(name.id, name.spelling.as_str()).is_none(),
                "duplicate resolution name ID {}",
                name.id
            );
        }
        let mut scopes = HashMap::default();
        for &scope in &facts.scopes {
            assert!(scope.start_byte <= scope.end_byte);
            assert!(
                scopes.insert(scope.id, scope).is_none(),
                "duplicate resolution scope ID {}",
                scope.id
            );
        }
        let mut sites = HashMap::default();
        for &site in &facts.sites {
            assert!(site.start_byte <= site.end_byte);
            let scope = scopes
                .get(&site.scope)
                .unwrap_or_else(|| panic!("site {} names unknown scope {}", site.id, site.scope));
            assert!(
                scope.start_byte <= site.start_byte && site.end_byte <= scope.end_byte,
                "site must be contained by its scope: {site:?}, {scope:?}"
            );
            assert!(
                sites.insert(site.id, site).is_none(),
                "duplicate resolution site ID {}",
                site.id
            );
        }
        let mut identifiers_by_site: HashMap<_, Vec<_>> = HashMap::default();
        for identifier in &facts.identifiers {
            assert!(sites.contains_key(&identifier.site));
            assert!(names.contains_key(&identifier.name));
            identifiers_by_site
                .entry(identifier.site)
                .or_default()
                .push(identifier);
        }
        let mut field_declarations = HashSet::default();
        let mut member_owner_by_declaration = HashMap::default();
        for member in &facts.member_owners {
            assert!(
                member_owner_by_declaration
                    .insert(member.member, *member)
                    .is_none(),
                "one member-owner row per declaration is required: {member:?}"
            );
            let declaration = identifiers_by_site
                .get(&member.member)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!(
                        "member ownership names unknown member declaration {}",
                        member.member
                    )
                });
            let owner = identifiers_by_site
                .get(&member.owner)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!(
                        "member ownership names unknown type declaration {}",
                        member.owner
                    )
                });
            let (member_kind, member_namespace) = match member.kind {
                ResolutionMemberKind::NestedType => (
                    ResolutionSiteKind::TypeDeclaration,
                    ResolutionNamespace::Type,
                ),
                ResolutionMemberKind::Method => (
                    ResolutionSiteKind::CallableDeclaration,
                    ResolutionNamespace::Callable,
                ),
                ResolutionMemberKind::Constructor => (
                    ResolutionSiteKind::ConstructorDeclaration,
                    ResolutionNamespace::Constructor,
                ),
                ResolutionMemberKind::Field => (
                    ResolutionSiteKind::ValueDeclaration,
                    ResolutionNamespace::Value,
                ),
                ResolutionMemberKind::AssociatedType => (
                    ResolutionSiteKind::TypeAliasDeclaration,
                    ResolutionNamespace::Type,
                ),
            };
            assert!(
                declaration.role == ResolutionIdentifierRole::Declaration
                    && sites[&member.member].kind == member_kind
                    && declaration.namespace == member_namespace,
                "member-owner member shape is invalid: {member:?}, declaration={declaration:?}"
            );
            assert!(
                owner.role == ResolutionIdentifierRole::Declaration
                    && sites[&member.owner].kind == ResolutionSiteKind::TypeDeclaration
                    && owner.namespace == ResolutionNamespace::Type,
                "member-owner type shape is invalid: {member:?}, owner={owner:?}"
            );
            if member.kind == ResolutionMemberKind::Field {
                assert!(field_declarations.insert(member.member));
            }
        }
        let mut reference_owner_by_reference = HashMap::default();
        for enclosing in &facts.reference_owners {
            let reference = identifiers_by_site
                .get(&enclosing.reference)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!(
                        "reference containment names unknown identifier site {}",
                        enclosing.reference
                    )
                });
            assert_eq!(
                reference.role,
                ResolutionIdentifierRole::Reference,
                "reference containment source must be a positioned reference: {enclosing:?}"
            );
            if let Some(owner) = enclosing.owner {
                let declaration = identifiers_by_site
                    .get(&owner)
                    .and_then(|identifiers| identifiers.first())
                    .unwrap_or_else(|| {
                        panic!("reference containment names unknown declaration site {owner}")
                    });
                assert_eq!(
                    declaration.role,
                    ResolutionIdentifierRole::Declaration,
                    "reference containment owner must be a positioned declaration: {enclosing:?}"
                );
                let owner_kind = sites[&owner].kind;
                let is_field = owner_kind == ResolutionSiteKind::ValueDeclaration
                    && field_declarations.contains(&owner);
                assert!(
                    matches!(
                        owner_kind,
                        ResolutionSiteKind::TypeDeclaration
                            | ResolutionSiteKind::CallableDeclaration
                            | ResolutionSiteKind::ConstructorDeclaration
                    ) || is_field,
                    "reference containment owner must be an analyzer declaration: {enclosing:?}"
                );
            }
            assert!(
                reference_owner_by_reference
                    .insert(enclosing.reference, enclosing.owner)
                    .is_none(),
                "one enclosing declaration per positioned reference is required: {enclosing:?}"
            );
        }
        let mut callable_receiver_origin_by_reference = HashMap::default();
        for receiver in &facts.callable_receiver_origins {
            let reference = identifiers_by_site
                .get(&receiver.reference)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!(
                        "callable receiver origin names unknown identifier site {}",
                        receiver.reference
                    )
                });
            assert_eq!(
                reference.role,
                ResolutionIdentifierRole::Reference,
                "callable receiver origin must name a positioned reference: {receiver:?}"
            );
            assert_eq!(
                reference.namespace,
                ResolutionNamespace::Callable,
                "callable receiver origin must name the callable namespace: {receiver:?}"
            );
            assert!(
                matches!(
                    sites[&receiver.reference].kind,
                    ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
                ),
                "callable receiver origin must name a terminal callable reference: {receiver:?}"
            );
            assert_eq!(
                reference.qualifier.is_none(),
                receiver.origin == ResolutionCallableReceiverOrigin::Implicit,
                "only an implicit callable receiver may omit its qualifier slot: {receiver:?}"
            );
            assert!(
                callable_receiver_origin_by_reference
                    .insert(receiver.reference, receiver.origin)
                    .is_none(),
                "one callable receiver origin per positioned reference is required: {receiver:?}"
            );
        }
        for identifiers in identifiers_by_site.values_mut() {
            identifiers.sort_unstable_by_key(|identifier| {
                (
                    identifier.role,
                    identifier.namespace,
                    identifier.name,
                    identifier.qualifier,
                )
            });
            assert!(
                identifiers.len() == 1,
                "one positioned identifier per semantic site is required: {identifiers:?}"
            );
        }
        let mut additional_definition_namespaces_by_declaration: HashMap<_, Vec<_>> =
            HashMap::default();
        for &additional in &facts.additional_definition_namespaces {
            let identifier = identifiers_by_site
                .get(&additional.declaration)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!(
                        "additional definition namespace names declaration without an identifier: {additional:?}"
                    )
                });
            assert_eq!(
                identifier.role,
                ResolutionIdentifierRole::Declaration,
                "additional definition namespace must name a declaration: {additional:?}"
            );
            assert_ne!(
                additional.namespace,
                ResolutionNamespace::TypeOrValue,
                "additional definition namespace must be effective: {additional:?}"
            );
            let binder = facts
                .binders
                .iter()
                .find(|binder| binder.declaration == additional.declaration)
                .unwrap_or_else(|| {
                    panic!(
                        "additional definition namespace names declaration without a binder: {additional:?}"
                    )
                });
            assert_eq!(
                additional.hoisting, binder.hoisting,
                "definition namespace authority must declare the binder's hoisting: {additional:?}, {binder:?}"
            );
            additional_definition_namespaces_by_declaration
                .entry(additional.declaration)
                .or_default()
                .push(additional);
        }
        for facts in additional_definition_namespaces_by_declaration.values_mut() {
            facts.sort_unstable_by_key(|fact| fact.namespace);
            assert!(
                facts
                    .windows(2)
                    .all(|pair| pair[0].namespace != pair[1].namespace),
                "definition namespace authorities must be unique per namespace: {facts:?}"
            );
        }
        let mut type_slots_by_site: HashMap<_, Vec<_>> = HashMap::default();
        let mut type_slot_ids = HashSet::default();
        for slot in &facts.type_slots {
            assert!(sites.contains_key(&slot.site));
            assert!(
                type_slot_ids.insert(slot.id),
                "duplicate type slot {}",
                slot.id
            );
            type_slots_by_site
                .entry(slot.site)
                .or_default()
                .push(slot.id);
        }
        for identifier in &facts.identifiers {
            if let Some(qualifier) = identifier.qualifier {
                assert!(
                    type_slot_ids.contains(&qualifier),
                    "identifier qualifier names unknown type slot {qualifier}"
                );
            }
        }
        for slots in type_slots_by_site.values_mut() {
            slots.sort_unstable();
        }
        let mut type_body_scope_by_owner = HashMap::default();
        for &scope in scopes.values() {
            if scope.kind != ResolutionScopeKind::TypeBody {
                continue;
            }
            let owner = scope
                .owner
                .expect("a type-body scope must name its owning type declaration");
            let owner_site = sites.get(&owner).unwrap_or_else(|| {
                panic!("type-body scope {} names unknown owner {owner}", scope.id)
            });
            assert_eq!(
                owner_site.kind,
                ResolutionSiteKind::TypeDeclaration,
                "type-body scope owner must be a type declaration: {scope:?}, {owner_site:?}"
            );
            assert!(
                type_body_scope_by_owner.insert(owner, scope).is_none(),
                "one type-body scope per type declaration is required: {scope:?}"
            );
        }
        let mut supertype_owner_by_reference = HashMap::default();
        for supertype in &facts.supertypes {
            let subtype = sites.get(&supertype.subtype).unwrap_or_else(|| {
                panic!(
                    "supertype property names unknown subtype {}",
                    supertype.subtype
                )
            });
            assert_eq!(
                subtype.kind,
                ResolutionSiteKind::TypeDeclaration,
                "supertype owner must be a type declaration: {supertype:?}, {subtype:?}"
            );
            assert!(
                sites.contains_key(&supertype.supertype_reference),
                "supertype property names unknown reference {}: {supertype:?}",
                supertype.supertype_reference
            );
            assert!(
                type_slot_ids.contains(&supertype.supertype_slot),
                "supertype property names unknown type slot {}: {supertype:?}",
                supertype.supertype_slot
            );
            assert!(
                supertype_owner_by_reference
                    .insert(supertype.supertype_reference, supertype.subtype)
                    .is_none(),
                "one supertype owner per reference is required: {supertype:?}"
            );
        }
        for gap in &facts.gaps {
            assert!(sites.contains_key(&gap.site));
        }
        let mut structured_import_by_site = HashMap::default();
        for route in &facts.import_routes {
            assert!(scopes.contains_key(&route.root_scope));
            let site = sites
                .get(&route.site)
                .unwrap_or_else(|| panic!("import route names unknown site {}", route.site));
            assert_eq!(site.kind, ResolutionSiteKind::ImportDeclaration);
            assert_eq!(site.scope, route.root_scope);
            match route.kind {
                ResolutionImportRouteKind::SingleType | ResolutionImportRouteKind::SingleStatic => {
                    assert!(
                        route
                            .bound_name
                            .is_some_and(|name| names.contains_key(&name))
                    );
                }
                ResolutionImportRouteKind::TypeOnDemand
                | ResolutionImportRouteKind::StaticOnDemand => {
                    assert!(route.bound_name.is_none());
                }
            }
            assert!(
                structured_import_by_site
                    .insert(
                        route.site,
                        StructuredImportFact {
                            root_scope: route.root_scope,
                            kind: route.kind,
                            bound_name: route.bound_name,
                        },
                    )
                    .is_none(),
                "one structured import route per site is required: {route:?}"
            );
        }

        let root_imports = Self::index_root_imports(facts, &names, &scopes, &sites);
        let root_references =
            Self::index_root_references(facts, &names, &scopes, &sites, &identifiers_by_site);
        let mut binders_by_declaration: HashMap<_, Vec<_>> = HashMap::default();
        for binder in &facts.binders {
            binders_by_declaration
                .entry(binder.declaration)
                .or_default()
                .push(binder);
        }
        let mut root_export_keys = HashSet::default();
        let mut root_exports = facts.root_exports.clone();
        for export in &root_exports {
            assert!(
                export.namespace != ResolutionNamespace::TypeOrValue,
                "root export needs an effective namespace: {export:?}"
            );
            let root_scope = scopes.get(&export.root_scope).unwrap_or_else(|| {
                panic!(
                    "root export declaration {} names unknown attachment scope {}",
                    export.declaration, export.root_scope
                )
            });
            assert_export_scope(*root_scope);
            let site = sites.get(&export.declaration).unwrap_or_else(|| {
                panic!(
                    "root export names unknown declaration site {}",
                    export.declaration
                )
            });
            let identifier = identifiers_by_site
                .get(&export.declaration)
                .and_then(|identifiers| identifiers.first())
                .unwrap_or_else(|| {
                    panic!("root export names declaration without an identifier: {export:?}")
                });
            let declared_export = declaration_namespace_is_declared(
                facts,
                export.declaration,
                site.kind,
                identifier.namespace,
                export.namespace,
            );
            assert!(
                site.scope == export.root_scope
                    && identifier.role == ResolutionIdentifierRole::Declaration
                    && identifier.qualifier.is_none()
                    && declared_export,
                "root export declaration shape is invalid: {export:?}, {site:?}, {identifier:?}"
            );
            assert!(
                !names[&identifier.name].is_empty(),
                "root export declaration spelling must be nonempty: {export:?}"
            );
            let binders = binders_by_declaration
                .get(&export.declaration)
                .map(Vec::as_slice)
                .unwrap_or_default();
            assert!(
                matches!(binders, [binder]
                if binder.scope == export.root_scope
                    && (binder.hoisting == HoistingClass::ScopeWide
                        || producer_declares_definition_namespace(
                            facts,
                            binder.declaration,
                            export.namespace,
                            binder.hoisting,
                        ))
                    && (binder.hoisting == HoistingClass::SourceOrder
                        || binder.activation_start == root_scope.start_byte)
                    && binder.activation_end == root_scope.end_byte
                    && binder_namespace_is_declared(facts, **binder, identifier.namespace)),
                "root export needs one matching scope-wide binder: {export:?}, {binders:?}"
            );
            assert!(
                root_export_keys.insert((export.root_scope, export.declaration, export.namespace,)),
                "root exports must be unique: {export:?}"
            );
        }
        root_exports.sort_unstable_by_key(|export| {
            (export.root_scope, export.declaration, export.namespace)
        });
        Self {
            names,
            scopes,
            sites,
            identifiers_by_site,
            additional_definition_namespaces_by_declaration,
            reference_owner_by_reference,
            callable_receiver_origin_by_reference,
            type_slots_by_site,
            supertype_owner_by_reference,
            type_body_scope_by_owner,
            member_owner_by_declaration,
            structured_import_by_site,
            root_imports,
            root_references,
            root_exports,
        }
    }

    fn validate_scope_forest(&self) {
        for scope in self.scopes.values() {
            if let Some(parent) = scope.parent {
                let parent = self
                    .scopes
                    .get(&parent)
                    .unwrap_or_else(|| panic!("scope {} names unknown parent {parent}", scope.id));
                assert!(
                    parent.start_byte <= scope.start_byte && scope.end_byte <= parent.end_byte,
                    "child scope must be contained by its parent: {scope:?}, {parent:?}"
                );
            }
            let mut cursor = Some(scope.id);
            let mut visited = HashSet::default();
            while let Some(id) = cursor {
                assert!(visited.insert(id), "resolution scope parent cycle at {id}");
                cursor = self.scope(id).parent;
            }
        }
    }

    fn name(&self, id: ResolutionNameId) -> &str {
        self.names
            .get(&id)
            .copied()
            .unwrap_or_else(|| panic!("unknown resolution name {id}"))
    }

    fn scope(&self, id: ResolutionScopeId) -> ResolutionScopeFact {
        *self
            .scopes
            .get(&id)
            .unwrap_or_else(|| panic!("unknown resolution scope {id}"))
    }

    fn site(&self, id: ResolutionSiteId) -> ResolutionSiteFact {
        *self
            .sites
            .get(&id)
            .unwrap_or_else(|| panic!("unknown resolution site {id}"))
    }

    fn hierarchy_gap_owner(&self, site: ResolutionSiteId) -> ResolutionSiteId {
        let source = self.site(site);
        if source.kind == ResolutionSiteKind::TypeDeclaration {
            return site;
        }
        *self
            .supertype_owner_by_reference
            .get(&site)
            .unwrap_or_else(|| {
                panic!(
                    "hierarchy gap at {site} is neither a type declaration nor a normalized supertype reference"
                )
            })
    }

    fn type_body_scope(&self, owner: ResolutionSiteId) -> Option<ResolutionScopeFact> {
        self.type_body_scope_by_owner.get(&owner).copied()
    }

    fn structured_import(&self, site: ResolutionSiteId) -> Option<StructuredImportFact> {
        self.structured_import_by_site.get(&site).copied()
    }

    fn scopes_sorted(&self) -> Vec<ResolutionScopeFact> {
        let mut scopes = self.scopes.values().copied().collect::<Vec<_>>();
        scopes.sort_unstable_by_key(|scope| scope.id);
        scopes
    }

    fn identifiers_sorted(&self) -> Vec<&'facts PositionedIdentifierFact> {
        let mut identifiers = self
            .identifiers_by_site
            .values()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        identifiers.sort_unstable_by_key(|identifier| identifier.site);
        identifiers
    }

    fn declaration_identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        let identifier = self.identifier(site);
        assert_eq!(identifier.role, ResolutionIdentifierRole::Declaration);
        identifier
    }

    fn reference_identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        let identifier = self.identifier(site);
        assert_eq!(identifier.role, ResolutionIdentifierRole::Reference);
        identifier
    }

    fn root_reference(&self, site: ResolutionSiteId) -> Option<&IndexedRootReference> {
        self.root_references
            .binary_search_by_key(&site, |reference| reference.fact.reference)
            .ok()
            .map(|index| &self.root_references[index])
    }

    fn additional_definition_namespaces(
        &self,
        declaration: ResolutionSiteId,
    ) -> &[ResolutionAdditionalDefinitionNamespaceFact] {
        self.additional_definition_namespaces_by_declaration
            .get(&declaration)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn reference_owner(&self, site: ResolutionSiteId) -> Option<Option<ResolutionSiteId>> {
        self.reference_owner_by_reference.get(&site).copied()
    }

    fn callable_receiver_origin(
        &self,
        site: ResolutionSiteId,
    ) -> Option<ResolutionCallableReceiverOrigin> {
        self.callable_receiver_origin_by_reference
            .get(&site)
            .copied()
    }

    fn identifier(&self, site: ResolutionSiteId) -> &'facts PositionedIdentifierFact {
        self.identifiers_by_site
            .get(&site)
            .and_then(|identifiers| identifiers.first())
            .copied()
            .unwrap_or_else(|| panic!("site {site} has no positioned identifier"))
    }
}

fn assert_import_scope(scope: ResolutionScopeFact, owner: &str) {
    assert!(
        matches!(
            scope.kind,
            ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
        ),
        "{owner} needs a CompilationUnit or Package attachment scope: {scope:?}"
    );
}

fn root_scope_is_ancestor(
    root_scope: ResolutionScopeFact,
    site: ResolutionSiteFact,
    scopes: &HashMap<ResolutionScopeId, ResolutionScopeFact>,
) -> bool {
    let mut cursor = Some(site.scope);
    let mut visited = HashSet::default();
    while let Some(scope_id) = cursor {
        assert!(
            visited.insert(scope_id),
            "resolution scope parent cycle at {scope_id}"
        );
        if scope_id == root_scope.id {
            return true;
        }
        cursor = scopes
            .get(&scope_id)
            .unwrap_or_else(|| panic!("site names unknown scope {scope_id}"))
            .parent;
    }
    false
}

fn assert_export_scope(scope: ResolutionScopeFact) {
    assert!(
        matches!(
            scope.kind,
            ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
        ),
        "root export needs a compilation-unit or module scope: {scope:?}"
    );
}

pub(super) fn lookup_routes(
    namespace: ResolutionNamespace,
) -> &'static [(u32, ResolutionNamespace)] {
    match namespace {
        ResolutionNamespace::TypeOrValue => &[
            (0, ResolutionNamespace::Value),
            (1, ResolutionNamespace::Type),
        ],
        ResolutionNamespace::Type => &[(0, ResolutionNamespace::Type)],
        ResolutionNamespace::Value => &[(0, ResolutionNamespace::Value)],
        ResolutionNamespace::Callable => &[(0, ResolutionNamespace::Callable)],
        ResolutionNamespace::Constructor => &[(0, ResolutionNamespace::Constructor)],
        ResolutionNamespace::Macro => &[(0, ResolutionNamespace::Macro)],
        ResolutionNamespace::Constant => &[(0, ResolutionNamespace::Constant)],
    }
}

fn single_import_namespaces(kind: ResolutionImportRouteKind) -> &'static [ResolutionNamespace] {
    match kind {
        ResolutionImportRouteKind::SingleType => &[ResolutionNamespace::Type],
        ResolutionImportRouteKind::SingleStatic => &[
            ResolutionNamespace::Type,
            ResolutionNamespace::Value,
            ResolutionNamespace::Callable,
        ],
        ResolutionImportRouteKind::TypeOnDemand | ResolutionImportRouteKind::StaticOnDemand => &[],
    }
}

fn effective_declaration_namespace(namespace: ResolutionNamespace) -> ResolutionNamespace {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "declarations cannot occupy an ambiguous TypeOrValue namespace"
    );
    namespace
}

const EFFECTIVE_NAMESPACES: [ResolutionNamespace; 4] = [
    ResolutionNamespace::Type,
    ResolutionNamespace::Value,
    ResolutionNamespace::Callable,
    ResolutionNamespace::Constructor,
];

fn precedence_step(semantic: SemanticId, ordinal: u32) -> PrecedenceStep {
    PrecedenceStep {
        tier: PrecedenceTier::LexicalBinding,
        ordinal,
        semantic,
    }
}

fn registered_precedence_step(
    identities: &mut ResolutionIdentityCatalogBuilder,
    semantic: SemanticId,
    ordinal: u32,
    namespace: ResolutionNamespace,
) -> PrecedenceStep {
    identities.register_precedence_namespace(precedence_step(semantic, ordinal), namespace)
}

fn scope_fallback_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
) -> Vec<PrecedenceStep> {
    EFFECTIVE_NAMESPACES
        .into_iter()
        .map(|namespace| {
            let semantic = identities.semantic(scope_choice_identity(scope, namespace));
            registered_precedence_step(identities, semantic, 1, namespace)
        })
        .collect()
}

fn checkpoint_fallback_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
    position: usize,
) -> Vec<PrecedenceStep> {
    EFFECTIVE_NAMESPACES
        .into_iter()
        .map(|namespace| {
            let semantic =
                identities.semantic(checkpoint_choice_identity(scope, position, namespace));
            registered_precedence_step(identities, semantic, 1, namespace)
        })
        .collect()
}

fn type_body_enclosing_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
) -> Vec<PrecedenceStep> {
    // Each effective namespace has two ordered stages inside a type body:
    // direct-vs-hierarchy, then hierarchy-vs-enclosing. Keeping the stages
    // namespace-local prevents a declaration in one namespace from proving a
    // negative in another.
    EFFECTIVE_NAMESPACES
        .into_iter()
        .flat_map(|namespace| {
            let direct = identities.semantic(scope_choice_identity(scope, namespace));
            let hierarchy = identities.semantic(hierarchy_choice_identity(scope, namespace));
            [
                registered_precedence_step(identities, direct, 1, namespace),
                registered_precedence_step(identities, hierarchy, 1, namespace),
            ]
        })
        .collect()
}

fn type_body_hierarchy_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
) -> Vec<PrecedenceStep> {
    EFFECTIVE_NAMESPACES
        .into_iter()
        .flat_map(|namespace| {
            let direct = identities.semantic(scope_choice_identity(scope, namespace));
            let hierarchy = identities.semantic(hierarchy_choice_identity(scope, namespace));
            [
                registered_precedence_step(identities, direct, 1, namespace),
                registered_precedence_step(identities, hierarchy, 0, namespace),
            ]
        })
        .collect()
}

fn binder_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    timeline: &ScopeTimeline,
    binder: &SupportedBinder<'_>,
) -> Vec<PrecedenceStep> {
    let namespace = effective_declaration_namespace(binder.identifier.namespace);
    let direct_choice = match binder.activation {
        SupportedActivation::ScopeWide => {
            identities.semantic(scope_choice_identity(timeline.fact.id, namespace))
        }
        SupportedActivation::SourceOrder(position) => identities.semantic(
            checkpoint_choice_identity(timeline.fact.id, position, namespace),
        ),
    };
    if timeline.fact.kind == ResolutionScopeKind::TypeBody
        && binder.fact.kind == ResolutionBinderKind::Callable
    {
        // Direct methods tie the unresolved hierarchy stage (overloads may be
        // inherited), but both beat an enclosing lexical method. Fields,
        // nested types, and constructors take direct rank zero and therefore
        // discharge the hierarchy fallback.
        let hierarchy_choice =
            identities.semantic(hierarchy_choice_identity(timeline.fact.id, namespace));
        vec![
            registered_precedence_step(identities, direct_choice, 1, namespace),
            registered_precedence_step(identities, hierarchy_choice, 0, namespace),
        ]
    } else {
        vec![registered_precedence_step(
            identities,
            direct_choice,
            0,
            namespace,
        )]
    }
}

fn lexical_gap(origin: LoweringGapOrigin) -> bool {
    match origin {
        LoweringGapOrigin::QualifiedReference
        | LoweringGapOrigin::UnsupportedActivation(_)
        | LoweringGapOrigin::MissingBinder => true,
        LoweringGapOrigin::Extracted(kind) => matches!(
            kind,
            ResolutionGapKind::UnsupportedRoute
                | ResolutionGapKind::UnsupportedScopeOrBinder
                | ResolutionGapKind::AmbiguousQualifiedType
                | ResolutionGapKind::UnsupportedImplicitReceiver
                | ResolutionGapKind::UnsupportedCallApplicability
                | ResolutionGapKind::MalformedSyntax
        ),
    }
}

fn blocks_fragment(origin: LoweringGapOrigin) -> bool {
    match origin {
        LoweringGapOrigin::QualifiedReference
        | LoweringGapOrigin::UnsupportedActivation(_)
        | LoweringGapOrigin::MissingBinder => false,
        LoweringGapOrigin::Extracted(kind) => matches!(
            kind,
            ResolutionGapKind::UnsupportedRoute
                | ResolutionGapKind::UnsupportedScopeOrBinder
                | ResolutionGapKind::MalformedSyntax
        ),
    }
}

fn has_type_impact(origin: LoweringGapOrigin) -> bool {
    match origin {
        LoweringGapOrigin::Extracted(kind) => !matches!(
            kind,
            ResolutionGapKind::UnsupportedScopeOrBinder
                | ResolutionGapKind::UnsupportedMemberScope
                | ResolutionGapKind::UnsupportedPlacementBoundary
                | ResolutionGapKind::MalformedSyntax
        ),
        LoweringGapOrigin::QualifiedReference => true,
        LoweringGapOrigin::UnsupportedActivation(_) | LoweringGapOrigin::MissingBinder => false,
    }
}

fn hierarchy_boundary_gap(origin: LoweringGapOrigin) -> bool {
    matches!(
        origin,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal)
    )
}

fn placement_scope(index: &FactIndex<'_>, source: GapSource) -> ResolutionScopeFact {
    let scope = index.site(source.site).scope;
    let scope_fact = index.scope(scope);
    assert!(
        scope_fact.parent.is_none()
            && matches!(
                scope_fact.kind,
                ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
            ),
        "placement boundary gap must name a root CompilationUnit or Package scope: {source:?}, {scope_fact:?}"
    );
    scope_fact
}

fn gap_reasons_by_site(
    identities: &mut ResolutionIdentityCatalogBuilder,
    sources: &[GapSource],
) -> HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>> {
    let mut reasons: HashMap<_, Vec<_>> = HashMap::default();
    for source in sources {
        reasons.entry(source.site).or_default().push((
            source.origin,
            identities.semantic(gap_reason_semantic_identity(source.site, source.origin)),
        ));
    }
    for site_reasons in reasons.values_mut() {
        site_reasons.sort_unstable();
        site_reasons.dedup();
    }
    reasons
}

fn completion_for_site(
    reasons_by_site: &HashMap<ResolutionSiteId, Vec<(LoweringGapOrigin, SemanticId)>>,
    site: ResolutionSiteId,
    applies: impl Fn(LoweringGapOrigin) -> bool,
) -> ResolutionCompletion {
    let reasons = reasons_by_site
        .get(&site)
        .into_iter()
        .flatten()
        .filter(|(origin, _)| applies(*origin))
        .map(|(_, semantic)| ResolutionIncompleteReason::UnsupportedSemantic(*semantic))
        .collect::<Vec<_>>();
    if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(reasons)
    }
}

struct GapCoverageSources<'source> {
    all: &'source [GapSource],
    point: &'source HashSet<GapSource>,
    enumeration: &'source HashSet<GapSource>,
    deferred_members: &'source HashSet<ResolutionSiteId>,
}

fn lower_coverage_gaps(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    sources: GapCoverageSources<'_>,
    index: &FactIndex<'_>,
    semantics: &HashMap<(ResolutionSiteId, LoweredSemanticRole), (SemanticId, BindingNodeId)>,
    forward_gap_endpoints: &HashMap<ResolutionSiteId, BindingNodeId>,
) -> Vec<LoweredCoverageGap> {
    let mut output = Vec::new();
    for &source in sources.all {
        let reason_semantic =
            identities.semantic(gap_reason_semantic_identity(source.site, source.origin));
        if !sources.point.contains(&source) {
            assert!(
                sources.enumeration.contains(&source),
                "a non-point coverage source must be owned by reference enumeration"
            );
            let frontier = LoweringCoverageFrontier::Enumeration;
            output.push(LoweredCoverageGap::new(
                coverage_gap_id(identities, reason_semantic, frontier),
                reason_semantic,
                source.site,
                source.origin,
                frontier,
            ));
            continue;
        }
        if source.origin == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute)
            && index.structured_import(source.site).is_some()
        {
            let mut frontiers = Vec::new();
            if sources.point.contains(&source) {
                frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                });
            }
            if sources.enumeration.contains(&source) {
                frontiers.push(LoweringCoverageFrontier::Enumeration);
            }
            frontiers.sort_unstable();
            frontiers.dedup();
            for frontier in frontiers {
                output.push(LoweredCoverageGap::new(
                    coverage_gap_id(identities, reason_semantic, frontier),
                    reason_semantic,
                    source.site,
                    source.origin,
                    frontier,
                ));
            }
            continue;
        }
        let mut frontiers = Vec::new();
        let is_positioned_reference =
            semantics.contains_key(&(source.site, LoweredSemanticRole::Reference));
        if blocks_fragment(source.origin) && !is_positioned_reference {
            frontiers.push(LoweringCoverageFrontier::Fragment);
        }
        if sources.enumeration.contains(&source) {
            frontiers.push(LoweringCoverageFrontier::Enumeration);
            if sources.point.contains(&source) {
                frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                });
            }
        }
        if matches!(
            source.origin,
            LoweringGapOrigin::QualifiedReference
                | LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal,)
        ) {
            // The reference endpoints are known, so broad enumeration remains
            // sound. Reverse lookup is not: qualified and inherited references
            // have no reverse path until the typed evaluator can issue one.
            frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            });
        }
        if source.origin
            == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
        {
            placement_scope(index, source);
            frontiers.push(LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            });
        }

        if let Some(&(semantic, node)) =
            semantics.get(&(source.site, LoweredSemanticRole::Reference))
            && lexical_gap(source.origin)
        {
            frontiers.extend([
                LoweringCoverageFrontier::Reference { semantic, node },
                LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint: node,
                    lookup: None,
                },
            ]);
        }

        if let Some(&(_, definition_node)) =
            semantics.get(&(source.site, LoweredSemanticRole::Definition))
            && lexical_gap(source.origin)
        {
            if !sources.deferred_members.contains(&source.site)
                || forward_gap_endpoints.contains_key(&source.site)
            {
                let identifier = index.declaration_identifier(source.site);
                let lookup = identities.lookup_semantic(
                    language,
                    effective_declaration_namespace(identifier.namespace),
                    index.name(identifier.name),
                );
                let forward_endpoint = *forward_gap_endpoints
                    .get(&source.site)
                    .expect("lexical definition gap has a supported or withheld binder frontier");
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint: forward_endpoint,
                    lookup: Some(lookup),
                });
            }
            frontiers.push(LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Reverse,
                endpoint: definition_node,
                lookup: None,
            });
        }

        if has_type_impact(source.origin) {
            let slots = index.type_slots_by_site.get(&source.site);
            if let Some(slots) = slots {
                for &slot in slots {
                    frontiers.push(LoweringCoverageFrontier::Type {
                        frontier: identities.semantic(type_slot_semantic_identity(slot)),
                    });
                }
            } else {
                // This is a site-local conditional frontier, not a producer-
                // global type gap. In particular, an implicit-constructor gap
                // on one type declaration must not contaminate unrelated type
                // transfers merely because the declaration has no physical
                // type-slot row.
                frontiers.push(LoweringCoverageFrontier::Type {
                    frontier: identities
                        .semantic(site_type_frontier_semantic_identity(source.site)),
                });
            }
        }

        frontiers.sort_unstable();
        frontiers.dedup();
        for frontier in frontiers {
            output.push(LoweredCoverageGap::new(
                coverage_gap_id(identities, reason_semantic, frontier),
                reason_semantic,
                source.site,
                source.origin,
                frontier,
            ));
        }
    }
    output
}

fn closed_endpoint(
    node: BindingNodeId,
    symbols: impl Into<Box<[SemanticId]>>,
) -> EndpointSignature {
    let symbols: Box<[SemanticId]> = symbols.into();
    EndpointSignature::new(
        node,
        StackPattern::closed(symbols),
        StackPattern::closed(Vec::new()),
    )
}

fn open_endpoint(node: BindingNodeId, variable: StackVariableId) -> EndpointSignature {
    EndpointSignature::new(
        node,
        StackPattern::open(Vec::new(), variable),
        StackPattern::closed(Vec::new()),
    )
}

fn symbol_open_endpoint(
    node: BindingNodeId,
    symbols: impl Into<Box<[SemanticId]>>,
    variable: StackVariableId,
) -> EndpointSignature {
    EndpointSignature::new(
        node,
        StackPattern::open(symbols, variable),
        StackPattern::closed(Vec::new()),
    )
}

fn local_digest(domain: &[u8], fields: &[(&str, &[u8])]) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(domain);
    for &(name, value) in fields {
        hasher.field(name, value);
    }
    hasher.finish()
}

fn u32_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn usize_bytes(value: usize) -> [u8; 8] {
    u64::try_from(value)
        .expect("usize fits u64 on supported targets")
        .to_be_bytes()
}

pub(super) fn reference_semantic_identity(site: ResolutionSiteId) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-reference-semantic-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(crate) fn definition_semantic(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
) -> SemanticId {
    definition_semantic_identity(site).mount(fragment)
}

pub(super) fn definition_semantic_identity(site: ResolutionSiteId) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-definition-semantic-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(super) fn type_slot_semantic_identity(
    slot: ResolutionTypeSlotId,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-type-slot-semantic-local:v2",
        &[("slot", &u32_bytes(slot.get()))],
    ))
}

pub(super) fn site_type_frontier_semantic_identity(
    site: ResolutionSiteId,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-site-type-frontier-semantic-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(crate) fn root_import_token(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    root_import_token_identity(site, namespace).mount(fragment)
}

pub(crate) fn root_import_anchor_semantic_identity(
    anchor: ResolutionRootImportAnchor,
) -> ResolutionSemanticIdentity {
    let label = match anchor {
        ResolutionRootImportAnchor::Lexical => b"lexical".as_slice(),
        ResolutionRootImportAnchor::Absolute => b"absolute".as_slice(),
    };
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-root-import-anchor-local:v1");
    hasher.field("anchor", label);
    ResolutionSemanticIdentity::fragment_local(hasher.finish())
}

pub(crate) fn root_import_token_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-import token needs an effective namespace"
    );
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-root-import-token-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

pub(crate) fn root_reference_token(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    root_reference_token_identity(site, namespace).mount(fragment)
}

pub(crate) fn root_reference_token_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-reference token needs an effective namespace"
    );
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-root-reference-token-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

pub(crate) fn root_export_token(
    fragment: BindingFragmentId,
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    root_export_token_identity(root_scope, namespace).mount(fragment)
}

pub(crate) fn root_export_token_identity(
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-export token needs an effective namespace"
    );
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-root-export-token-local:v1",
        &[
            ("root_scope", &u32_bytes(root_scope.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

fn scope_choice_identity(
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-scope-choice-local:v3",
        &[
            ("scope", &u32_bytes(scope.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

fn checkpoint_choice_identity(
    scope: ResolutionScopeId,
    position: usize,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-checkpoint-choice-local:v3",
        &[
            ("scope", &u32_bytes(scope.get())),
            ("position", &usize_bytes(position)),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

fn hierarchy_choice_identity(
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-hierarchy-choice-local:v2",
        &[
            ("scope", &u32_bytes(scope.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

fn reference_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-reference-node-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(super) fn definition_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-definition-node-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(super) fn scope_head_node_identity(scope: ResolutionScopeId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-scope-head-node-local:v1",
        &[("scope", &u32_bytes(scope.get()))],
    ))
}

fn checkpoint_node_identity(scope: ResolutionScopeId, position: usize) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-checkpoint-node-local:v1",
        &[
            ("scope", &u32_bytes(scope.get())),
            ("position", &usize_bytes(position)),
        ],
    ))
}

fn gap_sink_node_identity(site: ResolutionSiteId, role: &[u8]) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-gap-sink-node-local:v1",
        &[("site", &u32_bytes(site.get())), ("role", role)],
    ))
}

fn structured_import_gap_sink_node_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-structured-import-gap-sink-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

fn timeline_path_identity(scope: ResolutionScopeId, position: usize) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-timeline-path-local:v2",
        &[
            ("scope", &u32_bytes(scope.get())),
            ("position", &usize_bytes(position)),
        ],
    ))
}

fn parent_path_identity(scope: ResolutionScopeId) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-parent-path-local:v2",
        &[("scope", &u32_bytes(scope.get()))],
    ))
}

fn reference_path_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-reference-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

fn reference_gap_path_identity(site: ResolutionSiteId) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-reference-gap-path-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

fn binder_path_identity(site: ResolutionSiteId) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-binder-path-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

fn additional_binder_path_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionPathIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "an additional binder path needs an effective namespace"
    );
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-additional-binder-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

pub(crate) fn root_import_path_id(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    name: ResolutionNameId,
) -> PartialPathId {
    root_import_path_identity(site, namespace, name).mount(fragment)
}

pub(crate) fn root_import_path_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    name: ResolutionNameId,
) -> ResolutionPathIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-import path needs an effective namespace"
    );
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-root-import-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
            ("name", &u32_bytes(name.get())),
        ],
    ))
}

pub(crate) fn root_reference_path_id(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> PartialPathId {
    root_reference_path_identity(site, namespace).mount(fragment)
}

pub(crate) fn root_reference_path_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionPathIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-reference path needs an effective namespace"
    );
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-root-reference-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

pub(crate) fn root_export_path_id(
    fragment: BindingFragmentId,
    root_scope: ResolutionScopeId,
    declaration: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> PartialPathId {
    root_export_path_identity(root_scope, declaration, namespace).mount(fragment)
}

pub(crate) fn root_export_path_identity(
    root_scope: ResolutionScopeId,
    declaration: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionPathIdentity {
    assert_ne!(
        namespace,
        ResolutionNamespace::TypeOrValue,
        "a root-export path needs an effective namespace"
    );
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-root-export-path-local:v1",
        &[
            ("root_scope", &u32_bytes(root_scope.get())),
            ("declaration", &u32_bytes(declaration.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

pub(super) fn placement_gap_path_identity(
    site: ResolutionSiteId,
    scope: ResolutionScopeId,
) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-placement-gap-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("scope", &u32_bytes(scope.get())),
        ],
    ))
}

pub(super) fn structured_import_gap_path_identity(
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-structured-import-gap-path-local:v2",
        &[
            ("site", &u32_bytes(site.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
}

pub(super) fn placement_gap_lexical_row_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    site: ResolutionSiteId,
    scope: ResolutionScopeId,
) -> (BindingNodeId, (PartialPathId, PartialPath)) {
    let sink = identities.node(gap_sink_node_identity(site, b"placement-terminal"));
    let id = identities.path(placement_gap_path_identity(site, scope));
    let variable = passthrough_variable(identities, id);
    let scope_head = identities.node(scope_head_node_identity(scope));
    let reason = identities.semantic(gap_reason_semantic_identity(
        site,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary),
    ));
    (
        sink,
        (
            id,
            PartialPath::new(
                open_endpoint(scope_head, variable),
                open_endpoint(sink, variable),
                scope_fallback_precedence(identities, scope),
                [WitnessStep::Node(sink)],
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]),
            ),
        ),
    )
}

pub(super) fn structured_import_gap_lexical_row_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    root_scope: ResolutionScopeId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    bound_name: &str,
) -> (BindingNodeId, (PartialPathId, PartialPath)) {
    let lookup = identities.lookup_semantic(Language::Java, namespace, bound_name);
    let sink = identities.node(structured_import_gap_sink_node_identity(site, namespace));
    let path = identities.path(structured_import_gap_path_identity(site, namespace));
    let root = identities.node(scope_head_node_identity(root_scope));
    let choice = identities.semantic(scope_choice_identity(root_scope, namespace));
    let reason = identities.semantic(gap_reason_semantic_identity(
        site,
        LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedRoute),
    ));
    (
        sink,
        (
            path,
            PartialPath::new(
                closed_endpoint(root, [lookup]),
                closed_endpoint(sink, [lookup]),
                [identities.register_precedence_namespace(
                    PrecedenceStep {
                        tier: PrecedenceTier::ExplicitImport,
                        ordinal: 0,
                        semantic: choice,
                    },
                    namespace,
                )],
                [WitnessStep::Node(sink)],
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]),
            ),
        ),
    )
}

fn hierarchy_gap_path_identity(
    site: ResolutionSiteId,
    owner: ResolutionSiteId,
) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-hierarchy-gap-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("owner", &u32_bytes(owner.get())),
        ],
    ))
}

fn missing_binder_path_identity(site: ResolutionSiteId) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-missing-binder-path-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

fn passthrough_variable(
    identities: &mut ResolutionIdentityCatalogBuilder,
    path: PartialPathId,
) -> StackVariableId {
    let path_identity = identities
        .path_identity(path)
        .expect("passthrough variable path must be registered first");
    identities.stack_variable(ResolutionStackVariableIdentity::new(local_digest(
        b"bifrost-resolution-timeline-stack-variable-local:v2",
        &[("path", &path_identity.digest())],
    )))
}

pub(super) fn gap_reason_semantic_identity(
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-lowering-gap-reason-local:v2",
        &[
            ("site", &u32_bytes(site.get())),
            ("origin", gap_origin_label(origin)),
        ],
    ))
}

fn coverage_gap_id(
    identities: &mut ResolutionIdentityCatalogBuilder,
    reason_semantic: SemanticId,
    frontier: LoweringCoverageFrontier,
) -> SemanticId {
    let reason = identities
        .semantic_identity(reason_semantic)
        .expect("coverage-gap reason semantic must be registered first");
    assert_eq!(
        reason.space(),
        super::local_identity::ResolutionSemanticIdentitySpace::FragmentLocal,
        "coverage-gap reason semantic must be fragment-local"
    );
    let frontier_digest = coverage_frontier_local_digest(identities, frontier);
    identities.semantic(ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-lowering-coverage-gap-local:v2",
        &[("reason", &reason.digest()), ("frontier", &frontier_digest)],
    )))
}

fn gap_origin_label(origin: LoweringGapOrigin) -> &'static [u8] {
    match origin {
        LoweringGapOrigin::Extracted(kind) => match kind {
            ResolutionGapKind::UnsupportedTypeSyntax => b"extracted:unsupported-type-syntax",
            ResolutionGapKind::UnsupportedExpression => b"extracted:unsupported-expression",
            ResolutionGapKind::UnsupportedRoute => b"extracted:unsupported-route",
            ResolutionGapKind::UnsupportedScopeOrBinder => b"extracted:unsupported-scope-or-binder",
            ResolutionGapKind::AmbiguousQualifiedType => b"extracted:ambiguous-qualified-type",
            ResolutionGapKind::InferredType => b"extracted:inferred-type",
            ResolutionGapKind::PostfixArrayDimensions => b"extracted:postfix-array-dimensions",
            ResolutionGapKind::AmbiguousNumericLiteral => b"extracted:ambiguous-numeric-literal",
            ResolutionGapKind::ImplicitConstructor => b"extracted:implicit-constructor",
            ResolutionGapKind::UnsupportedHierarchyTraversal => {
                b"extracted:unsupported-hierarchy-traversal"
            }
            ResolutionGapKind::UnsupportedVisibility => b"extracted:unsupported-visibility",
            ResolutionGapKind::UnsupportedImplicitReceiver => {
                b"extracted:unsupported-implicit-receiver"
            }
            ResolutionGapKind::UnsupportedCallApplicability => {
                b"extracted:unsupported-call-applicability"
            }
            ResolutionGapKind::UnsupportedPlacementBoundary => {
                b"extracted:unsupported-placement-boundary"
            }
            ResolutionGapKind::MalformedSyntax => b"extracted:malformed-syntax",
            ResolutionGapKind::UnsupportedMemberScope => b"extracted:unsupported-member-scope",
        },
        LoweringGapOrigin::QualifiedReference => b"lowering:qualified-reference",
        LoweringGapOrigin::UnsupportedActivation(hoisting) => match hoisting {
            HoistingClass::SourceOrder => b"lowering:activation:source-order",
            HoistingClass::ScopeWide => b"lowering:activation:scope-wide",
            HoistingClass::DeclaredHead => b"lowering:activation:declared-head",
        },
        LoweringGapOrigin::MissingBinder => b"lowering:missing-binder",
    }
}

fn coverage_frontier_local_digest(
    identities: &ResolutionIdentityCatalogBuilder,
    frontier: LoweringCoverageFrontier,
) -> [u8; 32] {
    let mut hasher = CanonicalHasher::new(b"bifrost-resolution-coverage-frontier:v1");
    match frontier {
        LoweringCoverageFrontier::Fragment => hasher.field("kind", b"fragment"),
        LoweringCoverageFrontier::Enumeration => hasher.field("kind", b"enumeration"),
        LoweringCoverageFrontier::CandidateInventory { direction } => {
            hasher.field("kind", b"candidate-inventory");
            hasher.field("direction", candidate_direction_label(direction));
        }
        LoweringCoverageFrontier::Reference { semantic, node } => {
            hasher.field("kind", b"reference");
            let semantic = identities
                .semantic_identity(semantic)
                .expect("coverage reference semantic must be registered first");
            let node = identities
                .node_identity(node)
                .expect("coverage reference node must be registered first");
            hasher.field("semantic_space", semantic_space_label(semantic.space()));
            hasher.field("semantic", &semantic.digest());
            hasher.field("node", &node.digest());
        }
        LoweringCoverageFrontier::Candidate {
            direction,
            endpoint,
            lookup,
        } => {
            hasher.field("kind", b"candidate");
            hasher.field("direction", candidate_direction_label(direction));
            let endpoint = identities
                .node_identity(endpoint)
                .expect("coverage candidate endpoint must be registered first");
            hasher.field("endpoint", &endpoint.digest());
            if let Some(lookup) = lookup {
                let lookup = identities
                    .semantic_identity(lookup)
                    .expect("coverage candidate lookup must be registered first");
                hasher.field("lookup_space", semantic_space_label(lookup.space()));
                hasher.field("lookup", &lookup.digest());
            }
        }
        LoweringCoverageFrontier::Type { frontier } => {
            hasher.field("kind", b"type");
            let frontier = identities
                .semantic_identity(frontier)
                .expect("coverage type frontier must be registered first");
            hasher.field("frontier_space", semantic_space_label(frontier.space()));
            hasher.field("frontier", &frontier.digest());
        }
    }
    hasher.finish()
}

const fn semantic_space_label(
    space: super::local_identity::ResolutionSemanticIdentitySpace,
) -> &'static [u8] {
    match space {
        super::local_identity::ResolutionSemanticIdentitySpace::FragmentLocal => b"fragment-local",
        super::local_identity::ResolutionSemanticIdentitySpace::Shared => b"shared",
    }
}

const fn candidate_direction_label(direction: LoweredCandidateDirection) -> &'static [u8] {
    match direction {
        LoweredCandidateDirection::Forward => b"forward",
        LoweredCandidateDirection::Reverse => b"reverse",
    }
}

pub(crate) fn gap_reason_semantic(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
) -> SemanticId {
    gap_reason_semantic_identity(site, origin).mount(fragment)
}

#[cfg(test)]
pub(super) fn lookup_semantic(
    language: Language,
    namespace: ResolutionNamespace,
    spelling: &str,
) -> SemanticId {
    use super::local_identity::ResolutionLookupSemanticRecipe;
    SemanticId::from_digest(
        ResolutionLookupSemanticRecipe::new(language, namespace, spelling)
            .identity()
            .digest(),
    )
}

pub(crate) fn site_type_frontier_semantic(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
) -> SemanticId {
    site_type_frontier_semantic_identity(site).mount(fragment)
}

#[cfg(test)]
mod tests {
    use super::super::{
        ResolutionSemanticIdentitySpace, lower_resolution_facts_with_identity_catalog,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
        ResolutionBinderFact, ResolutionBinderKind, ResolutionCallFact,
        ResolutionCallableReceiverOriginFact, ResolutionGapFact, ResolutionIdentifierRole,
        ResolutionMemberAccess, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
        ResolutionNameFact, ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact,
        ResolutionRootImportSegmentFact, ResolutionRootReferenceSegmentFact, ResolutionScopeKind,
        ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
        ResolutionTypeSlotFact, ResolutionTypeSlotRole,
    };

    use crate::CancellationToken;

    use super::super::batch::{BatchResolutionEngine, BatchResolutionFragmentSource};
    use super::super::engine::{ResolutionEngine, ResolutionQuery};
    use super::*;

    fn type_slot_semantic(fragment: BindingFragmentId, slot: ResolutionTypeSlotId) -> SemanticId {
        type_slot_semantic_identity(slot).mount(fragment)
    }

    fn root_import_anchor_semantic(
        fragment: BindingFragmentId,
        anchor: ResolutionRootImportAnchor,
    ) -> SemanticId {
        root_import_anchor_semantic_identity(anchor).mount(fragment)
    }

    fn scope_choice(
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
        namespace: ResolutionNamespace,
    ) -> SemanticId {
        scope_choice_identity(scope, namespace).mount(fragment)
    }

    fn checkpoint_choice(
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
        position: usize,
        namespace: ResolutionNamespace,
    ) -> SemanticId {
        checkpoint_choice_identity(scope, position, namespace).mount(fragment)
    }

    fn reference_node(fragment: BindingFragmentId, site: ResolutionSiteId) -> BindingNodeId {
        reference_node_identity(site).mount(fragment)
    }

    fn scope_head_node(fragment: BindingFragmentId, scope: ResolutionScopeId) -> BindingNodeId {
        scope_head_node_identity(scope).mount(fragment)
    }

    fn parent_path_id(fragment: BindingFragmentId, scope: ResolutionScopeId) -> PartialPathId {
        parent_path_identity(scope).mount(fragment)
    }

    fn reference_path_id(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
        namespace: ResolutionNamespace,
    ) -> PartialPathId {
        reference_path_identity(site, namespace).mount(fragment)
    }

    fn binder_path_id(fragment: BindingFragmentId, site: ResolutionSiteId) -> PartialPathId {
        binder_path_identity(site).mount(fragment)
    }

    fn placement_gap_path_id(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
        scope: ResolutionScopeId,
    ) -> PartialPathId {
        placement_gap_path_identity(site, scope).mount(fragment)
    }

    fn hierarchy_gap_path_id(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
        owner: ResolutionSiteId,
    ) -> PartialPathId {
        hierarchy_gap_path_identity(site, owner).mount(fragment)
    }

    fn missing_binder_path_id(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
    ) -> PartialPathId {
        missing_binder_path_identity(site).mount(fragment)
    }

    fn hierarchy_choice(
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
        namespace: ResolutionNamespace,
    ) -> SemanticId {
        hierarchy_choice_identity(scope, namespace).mount(fragment)
    }

    fn fragment() -> BindingFragmentId {
        BindingFragmentId::hash_bytes(b"fact-lowering-test-fragment")
    }

    fn root_route_facts() -> FileResolutionFacts {
        let root_scope = ResolutionScopeId::new(1);
        let import_site = ResolutionSiteId::new(0);
        let declaration = ResolutionSiteId::new(1);
        let reference = ResolutionSiteId::new(2);
        FileResolutionFacts {
            names: ["example.com", "repo", "dep", "Item"]
                .into_iter()
                .enumerate()
                .map(|(index, spelling)| ResolutionNameFact {
                    id: ResolutionNameId::try_from_index(index)
                        .expect("root-route fixture name count fits u32"),
                    spelling: spelling.to_owned(),
                })
                .collect(),
            scopes: vec![
                scope(0, None, 0, 100),
                ResolutionScopeFact {
                    id: root_scope,
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: None,
                    kind: ResolutionScopeKind::Package,
                    start_byte: 0,
                    end_byte: 100,
                },
            ],
            sites: vec![
                site(0, 1, ResolutionSiteKind::ImportDeclaration, 1),
                site(1, 1, ResolutionSiteKind::TypeDeclaration, 10),
                site(2, 1, ResolutionSiteKind::TypeReference, 20),
            ],
            identifiers: vec![
                PositionedIdentifierFact {
                    site: declaration,
                    name: ResolutionNameId::new(3),
                    role: ResolutionIdentifierRole::Declaration,
                    namespace: ResolutionNamespace::Type,
                    qualifier: None,
                },
                PositionedIdentifierFact {
                    site: reference,
                    name: ResolutionNameId::new(3),
                    role: ResolutionIdentifierRole::Reference,
                    namespace: ResolutionNamespace::Type,
                    qualifier: None,
                },
            ],
            binders: vec![ResolutionBinderFact {
                declaration,
                scope: root_scope,
                kind: ResolutionBinderKind::Type,
                hoisting: HoistingClass::ScopeWide,
                activation_start: 0,
                activation_end: 100,
            }],
            root_imports: vec![ResolutionRootImportFact {
                site: import_site,
                root_scope,
                anchor: ResolutionRootImportAnchor::Lexical,
            }],
            root_import_segments: (0..3)
                .map(|position| ResolutionRootImportSegmentFact {
                    import_site,
                    position,
                    name: ResolutionNameId::new(position),
                })
                .collect(),
            root_import_demands: vec![ResolutionRootImportDemandFact {
                import_site,
                namespace: ResolutionNamespace::Type,
                name: ResolutionNameId::new(3),
            }],
            root_references: vec![ResolutionRootReferenceFact {
                reference,
                root_scope,
                anchor: ResolutionRootImportAnchor::Absolute,
            }],
            root_reference_segments: (0..3)
                .map(|position| ResolutionRootReferenceSegmentFact {
                    reference,
                    position,
                    name: ResolutionNameId::new(position),
                })
                .collect(),
            root_exports: vec![ResolutionRootExportFact {
                root_scope,
                declaration,
                namespace: ResolutionNamespace::Type,
            }],
            ..FileResolutionFacts::default()
        }
    }

    #[test]
    fn root_routes_are_source_owned_anchored_and_fragment_local() {
        let facts = root_route_facts();
        let provisional = BindingFragmentId::hash_bytes(b"root-route-provisional");
        let final_fragment = BindingFragmentId::hash_bytes(b"root-route-final");
        let provisional_artifact = lower_file_resolution_facts(provisional, Language::Go, &facts);
        let final_artifact = lower_file_resolution_facts(final_fragment, Language::Go, &facts);
        let provisional_again = lower_file_resolution_facts(provisional, Language::Go, &facts);
        let final_again = lower_file_resolution_facts(final_fragment, Language::Go, &facts);
        let assert_same_artifact =
            |left: &LoweredResolutionFragment, right: &LoweredResolutionFragment| {
                assert_eq!(left, right);
            };
        assert_same_artifact(&provisional_artifact, &provisional_again);
        assert_same_artifact(&final_artifact, &final_again);

        let import_site = ResolutionSiteId::new(0);
        let root_scope = ResolutionScopeId::new(1);
        let declaration = ResolutionSiteId::new(1);
        let demand_name = ResolutionNameId::new(3);
        let reference = ResolutionSiteId::new(2);
        let namespace = ResolutionNamespace::Type;
        let expected_shared_route = ["example.com", "repo", "dep"]
            .map(|spelling| lookup_semantic(Language::Go, namespace, spelling));
        let expected_lookup = lookup_semantic(Language::Go, namespace, "Item");

        let inspect = |artifact: &LoweredResolutionFragment, mounted_fragment| {
            let import_token = root_import_token(mounted_fragment, import_site, namespace);
            let export_token = root_export_token(mounted_fragment, root_scope, namespace);
            let import_id =
                root_import_path_id(mounted_fragment, import_site, namespace, demand_name);
            let export_id =
                root_export_path_id(mounted_fragment, root_scope, declaration, namespace);
            let import_path = artifact
                .paths()
                .iter()
                .find_map(|(id, path)| (*id == import_id).then_some(path))
                .expect("source-owned root import path");
            let export_path = artifact
                .paths()
                .iter()
                .find_map(|(id, path)| (*id == export_id).then_some(path))
                .expect("source-owned root export path");

            assert_eq!(
                import_path.start().node(),
                scope_head_node(mounted_fragment, root_scope)
            );
            assert_eq!(
                import_path
                    .start()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                [expected_lookup]
            );
            assert_eq!(import_path.end().node(), BindingNodeId::universal_root());
            let mut expected_import_root = vec![root_import_anchor_semantic(
                mounted_fragment,
                ResolutionRootImportAnchor::Lexical,
            )];
            expected_import_root.extend(expected_shared_route);
            expected_import_root.extend([import_token, expected_lookup]);
            assert_eq!(
                import_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                expected_import_root
            );
            assert_eq!(
                import_path.start().symbols().tail(),
                import_path.end().symbols().tail()
            );
            assert_eq!(import_path.precedence().len(), 1);
            assert_eq!(
                import_path.precedence()[0],
                PrecedenceStep {
                    tier: PrecedenceTier::WildcardImport,
                    ordinal: 0,
                    semantic: scope_choice(mounted_fragment, root_scope, namespace),
                }
            );
            assert_eq!(
                import_path.witness(),
                [WitnessStep::Node(BindingNodeId::universal_root())]
            );
            assert_eq!(import_path.completion(), &ResolutionCompletion::Complete);

            assert_eq!(export_path.start().node(), BindingNodeId::universal_root());
            assert_eq!(
                export_path
                    .start()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                [expected_lookup, export_token]
            );
            assert!(export_path.end().symbols().fixed().is_empty());
            assert_eq!(
                export_path.start().symbols().tail(),
                export_path.end().symbols().tail()
            );
            assert_eq!(export_path.precedence().len(), 1);
            assert_eq!(
                export_path.precedence()[0].tier,
                PrecedenceTier::PackageOrModule
            );
            assert_eq!(export_path.precedence()[0].semantic, export_token);
            assert_eq!(
                export_path.witness(),
                [WitnessStep::Node(export_path.end().node())]
            );
            assert_eq!(export_path.completion(), &ResolutionCompletion::Complete);

            let reference_id = root_reference_path_id(mounted_fragment, reference, namespace);
            let reference_token = root_reference_token(mounted_fragment, reference, namespace);
            let reference_path = artifact
                .paths()
                .iter()
                .find_map(|(id, path)| (*id == reference_id).then_some(path))
                .expect("source-owned direct root reference path");
            assert_eq!(
                reference_path.start().node(),
                reference_node(mounted_fragment, reference)
            );
            assert!(reference_path.start().symbols().fixed().is_empty());
            assert!(reference_path.start().symbols().tail().is_none());
            let mut expected_reference_root = vec![root_import_anchor_semantic(
                mounted_fragment,
                ResolutionRootImportAnchor::Absolute,
            )];
            expected_reference_root.extend(expected_shared_route);
            expected_reference_root.extend([reference_token, expected_lookup]);
            assert_eq!(
                reference_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                expected_reference_root
            );
            assert!(reference_path.end().symbols().tail().is_none());
            assert_eq!(
                reference_path.precedence(),
                [PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic: scope_choice(mounted_fragment, root_scope, namespace),
                }]
            );
            assert_eq!(
                reference_path.witness(),
                [
                    WitnessStep::Node(scope_head_node(mounted_fragment, root_scope)),
                    WitnessStep::Node(BindingNodeId::universal_root()),
                ]
            );
            assert_eq!(reference_path.completion(), &ResolutionCompletion::Complete);
            assert!(
                artifact
                    .paths()
                    .iter()
                    .all(|(id, _)| *id != reference_path_id(mounted_fragment, reference, namespace)),
                "a direct root reference must not retain a lexical decoy route"
            );
            assert_eq!(
                artifact
                    .semantics()
                    .iter()
                    .find(|semantic| semantic.site() == reference)
                    .and_then(|semantic| semantic.site_metadata())
                    .map(|metadata| metadata.unqualified()),
                Some(false)
            );

            assert!(artifact.nodes().iter().all(|(node, kind)| {
                *node != BindingNodeId::universal_root() && *kind != BindingNodeKind::Root
            }));
            (import_token, export_token, import_id, export_id)
        };

        let provisional_rows = inspect(&provisional_artifact, provisional);
        let final_rows = inspect(&final_artifact, final_fragment);
        assert_ne!(provisional_rows, final_rows);
        let provisional_import_token = provisional_rows.0;
        let final_import_path = final_artifact
            .paths()
            .iter()
            .find_map(|(id, path)| (id == &final_rows.2).then_some(path))
            .expect("final root-import path");
        assert!(
            final_import_path
                .end()
                .symbols()
                .fixed()
                .iter()
                .all(|symbol| symbol.symbol() != provisional_import_token),
            "final lowering must not retain a provisional mounted token"
        );

        let mut permuted = facts.clone();
        permuted.root_import_segments.reverse();
        permuted.root_import_demands.reverse();
        permuted.root_exports.reverse();
        let permuted = lower_file_resolution_facts(final_fragment, Language::Go, &permuted);
        assert_same_artifact(&final_artifact, &permuted);
    }

    #[test]
    fn root_route_fact_index_rejects_sparse_ambiguous_or_unowned_rows() {
        let rejected = |mutate: fn(&mut FileResolutionFacts)| {
            let mut facts = root_route_facts();
            mutate(&mut facts);
            std::panic::catch_unwind(|| {
                let _ = lower_file_resolution_facts(fragment(), Language::Go, &facts);
            })
            .is_err()
        };

        assert!(rejected(|facts| {
            facts.root_import_segments[1].position = 3;
        }));
        assert!(rejected(|facts| {
            facts.root_import_demands[0].namespace = ResolutionNamespace::TypeOrValue;
        }));
        assert!(rejected(|facts| {
            facts
                .identifiers
                .iter_mut()
                .find(|identifier| identifier.site == ResolutionSiteId::new(2))
                .expect("root reference fixture identifier")
                .namespace = ResolutionNamespace::TypeOrValue;
        }));
        assert!(rejected(|facts| {
            facts.root_import_segments[0].import_site = ResolutionSiteId::new(99);
        }));
        assert!(rejected(|facts| {
            facts.root_reference_segments[1].position = 3;
        }));
        assert!(rejected(|facts| {
            facts.root_references[0].root_scope = ResolutionScopeId::new(99);
        }));
        assert!(rejected(|facts| {
            facts.root_reference_segments[0].reference = ResolutionSiteId::new(99);
        }));
        assert!(rejected(|facts| {
            facts
                .identifiers
                .iter_mut()
                .find(|identifier| identifier.site == ResolutionSiteId::new(2))
                .expect("root reference fixture identifier")
                .role = ResolutionIdentifierRole::Declaration;
        }));
        assert!(rejected(|facts| {
            facts.binders[0].hoisting = HoistingClass::SourceOrder;
        }));
    }

    #[test]
    fn root_import_accepts_an_owned_package_attachment_scope() {
        let mut facts = root_route_facts();
        facts.scopes[1].owner = Some(ResolutionSiteId::new(1));

        let lowered = lower_file_resolution_facts(fragment(), Language::Go, &facts);
        assert!(!lowered.paths().is_empty());
    }

    fn scope(
        id: u32,
        parent: Option<u32>,
        start_byte: usize,
        end_byte: usize,
    ) -> ResolutionScopeFact {
        ResolutionScopeFact {
            id: ResolutionScopeId::new(id),
            parent: parent.map(ResolutionScopeId::new),
            owner: None,
            kind: if parent.is_none() {
                ResolutionScopeKind::CompilationUnit
            } else {
                ResolutionScopeKind::Block
            },
            start_byte,
            end_byte,
        }
    }

    fn site(
        id: u32,
        scope: u32,
        kind: ResolutionSiteKind,
        start_byte: usize,
    ) -> ResolutionSiteFact {
        ResolutionSiteFact {
            id: ResolutionSiteId::new(id),
            scope: ResolutionScopeId::new(scope),
            kind,
            start_byte,
            end_byte: start_byte + 1,
        }
    }

    fn identifier(
        site: u32,
        name: u32,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> PositionedIdentifierFact {
        PositionedIdentifierFact {
            site: ResolutionSiteId::new(site),
            name: ResolutionNameId::new(name),
            role,
            namespace,
            qualifier: None,
        }
    }

    #[test]
    fn lowered_definitions_retain_explicit_graph_domain_authority() {
        let facts = FileResolutionFacts {
            names: (0..4)
                .map(|id| ResolutionNameFact {
                    id: ResolutionNameId::new(id),
                    spelling: format!("definition_{id}"),
                })
                .collect(),
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::CallableDeclaration, 10),
                site(2, 0, ResolutionSiteKind::ValueDeclaration, 20),
                site(3, 0, ResolutionSiteKind::ValueDeclaration, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Callable,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    1,
                    0,
                    ResolutionBinderKind::Callable,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    2,
                    0,
                    ResolutionBinderKind::Field,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    3,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::SourceOrder,
                    30,
                    100,
                ),
            ],
            member_owners: vec![ResolutionMemberOwnerFact {
                member: ResolutionSiteId::new(2),
                owner: ResolutionSiteId::new(0),
                kind: ResolutionMemberKind::Field,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
            }],
            ..FileResolutionFacts::default()
        };

        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let domain = |site| {
            lowered
                .semantics()
                .iter()
                .find(|semantic| {
                    semantic.site() == ResolutionSiteId::new(site)
                        && semantic.role() == LoweredSemanticRole::Definition
                })
                .and_then(LoweredSemanticSite::definition_graph_domain)
                .expect("every declaration must carry graph-domain authority")
        };
        assert_eq!(domain(0), FactDefinitionGraphDomain::Type);
        assert_eq!(domain(1), FactDefinitionGraphDomain::Callable);
        assert_eq!(domain(2), FactDefinitionGraphDomain::Field);
        assert_eq!(domain(3), FactDefinitionGraphDomain::OutOfGraphDomain);
    }

    #[test]
    fn lowered_reference_owner_distinguishes_definition_root_and_unknown() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Owner".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "owned".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "root".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(3),
                    spelling: "unknown".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::TypeReference, 10),
                site(2, 0, ResolutionSiteKind::TypeReference, 20),
                site(3, 0, ResolutionSiteKind::TypeReference, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            reference_owners: vec![
                ResolutionReferenceOwnerFact {
                    reference: ResolutionSiteId::new(1),
                    owner: Some(ResolutionSiteId::new(0)),
                },
                ResolutionReferenceOwnerFact {
                    reference: ResolutionSiteId::new(2),
                    owner: None,
                },
            ],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let owner = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let reference_owner = |site| {
            lowered
                .semantics()
                .iter()
                .find(|semantic| semantic.site() == ResolutionSiteId::new(site))
                .expect("reference semantic")
                .reference_owner()
        };
        assert_eq!(reference_owner(1), Some(Some(owner)));
        assert_eq!(reference_owner(2), Some(None));
        assert_eq!(reference_owner(3), None);

        let references =
            [1, 2, 3].map(|site| semantic(&lowered, site, LoweredSemanticRole::Reference));
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let mut transported = Vec::new();
        let completion = source
            .visit_reference_seed_batches(2, &CancellationToken::new(), &mut |batch| {
                transported.extend(
                    batch
                        .seeds()
                        .iter()
                        .map(|seed| (seed.reference(), seed.reference_owner())),
                );
                Ok(true)
            })
            .expect("preloaded reference-owner enumeration");
        assert_eq!(completion, ResolutionCompletion::Complete);
        transported.sort_unstable();
        let mut expected = vec![
            (references[0], Some(Some(owner))),
            (references[1], Some(None)),
            (references[2], None),
        ];
        expected.sort_unstable();
        assert_eq!(transported, expected);
    }

    #[test]
    fn lowered_reference_owner_transports_exact_field_declaration() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Owner".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "field".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "Dependency".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::ValueDeclaration, 10),
                site(2, 0, ResolutionSiteKind::TypeReference, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            member_owners: vec![ResolutionMemberOwnerFact {
                member: ResolutionSiteId::new(1),
                owner: ResolutionSiteId::new(0),
                kind: ResolutionMemberKind::Field,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOnly,
            }],
            reference_owners: vec![ResolutionReferenceOwnerFact {
                reference: ResolutionSiteId::new(2),
                owner: Some(ResolutionSiteId::new(1)),
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let field = semantic(&lowered, 1, LoweredSemanticRole::Definition);
        let reference = semantic(&lowered, 2, LoweredSemanticRole::Reference);
        assert_eq!(
            lowered
                .semantics()
                .iter()
                .find(|semantic| semantic.semantic() == reference)
                .expect("field-owned reference semantic")
                .reference_owner(),
            Some(Some(field))
        );

        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let mut transported = Vec::new();
        let completion = source
            .visit_reference_seed_batches(1, &CancellationToken::new(), &mut |batch| {
                transported.extend(
                    batch
                        .seeds()
                        .iter()
                        .map(|seed| (seed.reference(), seed.reference_owner())),
                );
                Ok(true)
            })
            .expect("preloaded field-owner enumeration");
        assert_eq!(completion, ResolutionCompletion::Complete);
        assert_eq!(transported, vec![(reference, Some(Some(field)))]);
    }

    #[test]
    fn lowered_reference_site_metadata_survives_every_preloaded_seed_shape() {
        let mut explicit = identifier(
            1,
            1,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        explicit.qualifier = Some(ResolutionTypeSlotId::new(0));
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "implicit".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "explicit".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "partial".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::CallableReference, 10),
                site(1, 0, ResolutionSiteKind::MemberReference, 20),
                site(2, 0, ResolutionSiteKind::CallableReference, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
                explicit,
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
            ],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(1),
                role: ResolutionTypeSlotRole::Receiver,
            }],
            callable_receiver_origins: vec![
                ResolutionCallableReceiverOriginFact {
                    reference: ResolutionSiteId::new(0),
                    origin: ResolutionCallableReceiverOrigin::Implicit,
                },
                ResolutionCallableReceiverOriginFact {
                    reference: ResolutionSiteId::new(1),
                    origin: ResolutionCallableReceiverOrigin::ExplicitExpression,
                },
            ],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let references = [0, 1, 2].map(|site| {
            let semantic = lowered
                .semantics()
                .iter()
                .find(|semantic| semantic.site() == ResolutionSiteId::new(site))
                .expect("callable reference semantic");
            (
                semantic.semantic(),
                semantic.node(),
                semantic
                    .site_metadata()
                    .expect("every lowered reference has site metadata"),
            )
        });
        assert_eq!(
            references.map(|(_, _, metadata)| metadata.callable_receiver_origin()),
            [
                Some(ResolutionCallableReceiverOrigin::Implicit),
                Some(ResolutionCallableReceiverOrigin::ExplicitExpression),
                None,
            ],
            "a partial producer may omit receiver-origin metadata"
        );
        assert_eq!(
            references.map(|(_, _, metadata)| (
                metadata.site(),
                metadata.namespace(),
                metadata.site_kind(),
                metadata.start_byte(),
                metadata.end_byte(),
                metadata.unqualified(),
                metadata.reference_owner(),
            )),
            [
                (
                    ResolutionSiteId::new(0),
                    ResolutionNamespace::Callable,
                    ResolutionSiteKind::CallableReference,
                    10,
                    11,
                    true,
                    None,
                ),
                (
                    ResolutionSiteId::new(1),
                    ResolutionNamespace::Callable,
                    ResolutionSiteKind::MemberReference,
                    20,
                    21,
                    false,
                    None,
                ),
                (
                    ResolutionSiteId::new(2),
                    ResolutionNamespace::Callable,
                    ResolutionSiteKind::CallableReference,
                    30,
                    31,
                    true,
                    None,
                ),
            ]
        );

        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let cancellation = CancellationToken::new();
        for (reference, _, expected) in references {
            let seed = source
                .reference_seed(ResolutionQuery::new(reference), &cancellation)
                .expect("preloaded scalar seed read")
                .expect("known callable reference");
            assert_eq!(seed.site_metadata(), Some(expected));
        }

        let queries = references.map(|(reference, _, _)| ResolutionQuery::new(reference));
        let plural = source
            .lookup_reference_seeds(&queries, &cancellation)
            .expect("preloaded plural seed read");
        assert!(plural.is_exhausted());
        assert_eq!(plural.rows().len(), references.len());
        for (row, (_, _, expected)) in plural.rows().iter().zip(references) {
            assert_eq!(
                row.seed()
                    .expect("known plural callable reference")
                    .site_metadata(),
                Some(expected)
            );
        }

        let mut broad = Vec::new();
        let completion = source
            .visit_reference_seed_batches(2, &cancellation, &mut |batch| {
                broad.extend(
                    batch
                        .seeds()
                        .iter()
                        .map(|seed| (seed.reference(), seed.site_metadata())),
                );
                Ok(true)
            })
            .expect("preloaded broad seed enumeration");
        assert_eq!(completion, ResolutionCompletion::Complete);
        broad.sort_unstable();
        let mut expected = references
            .map(|(reference, _, metadata)| (reference, Some(metadata)))
            .to_vec();
        expected.sort_unstable();
        assert_eq!(broad, expected);
    }

    fn binder(
        declaration: u32,
        scope: u32,
        kind: ResolutionBinderKind,
        hoisting: HoistingClass,
        activation_start: usize,
        activation_end: usize,
    ) -> ResolutionBinderFact {
        ResolutionBinderFact {
            declaration: ResolutionSiteId::new(declaration),
            scope: ResolutionScopeId::new(scope),
            kind,
            hoisting,
            activation_start,
            activation_end,
        }
    }

    fn semantic(
        lowered: &LoweredResolutionFragment,
        site: u32,
        role: LoweredSemanticRole,
    ) -> SemanticId {
        lowered
            .semantics()
            .iter()
            .find(|semantic| {
                semantic.site() == ResolutionSiteId::new(site) && semantic.role() == role
            })
            .unwrap_or_else(|| panic!("missing semantic for site {site}"))
            .semantic()
    }

    fn resolve(
        lowered: LoweredResolutionFragment,
        reference_site: u32,
    ) -> super::super::model::ResolutionAnswer {
        let reference = semantic(&lowered, reference_site, LoweredSemanticRole::Reference);
        let (fragment, gaps) = lowered.into_preloaded_parts();
        assert!(
            gaps.is_empty(),
            "fixture unexpectedly lowered gaps: {gaps:?}"
        );
        let source = super::super::engine::PreloadedFragmentSource::from_fragments([fragment]);
        ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("resolution")
    }

    fn resolve_with_coverage(
        lowered: LoweredResolutionFragment,
        reference_site: u32,
    ) -> super::super::model::ResolutionAnswer {
        let reference = semantic(&lowered, reference_site, LoweredSemanticRole::Reference);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("resolution with normalized coverage")
    }

    #[test]
    fn deferred_member_uncertainty_does_not_withhold_a_free_binder() {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionDeferredMemberOwnerFact, ResolutionMemberKind,
        };

        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "method".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::CallableDeclaration, 10),
                site(1, 0, ResolutionSiteKind::CallableDeclaration, 20),
                site(2, 0, ResolutionSiteKind::CallableReference, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Callable,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            additional_definition_namespaces: vec![ResolutionAdditionalDefinitionNamespaceFact {
                declaration: ResolutionSiteId::new(0),
                namespace: ResolutionNamespace::Value,
                hoisting: HoistingClass::ScopeWide,
            }],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(1),
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            }],
            deferred_member_owners: vec![ResolutionDeferredMemberOwnerFact {
                member: ResolutionSiteId::new(1),
                owner_type: ResolutionTypeSlotId::new(0),
                kind: ResolutionMemberKind::Method,
                access: ResolutionMemberAccess::Instance,
                qualifier_compatibility: ResolutionMemberQualifierCompatibility::RuntimeOrType,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Rust, &facts);
        assert!(!lowered.paths().iter().any(|(id, _)| {
            *id == missing_binder_path_id(fragment(), ResolutionSiteId::new(1))
        }));
        assert!(lowered.gaps().iter().any(|gap| {
            gap.site() == ResolutionSiteId::new(1)
                && matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        ..
                    }
                )
        }));
        let target = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let answer = resolve_with_coverage(lowered, 2);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        assert_eq!(answer.targets(), &[target]);
    }

    #[test]
    fn additional_definition_namespace_adds_a_route_to_the_same_definition() {
        let declaration = ResolutionSiteId::new(0);
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "Tuple".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 10),
                site(1, 0, ResolutionSiteKind::TypeReference, 20),
                site(2, 0, ResolutionSiteKind::ValueReference, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            additional_definition_namespaces: vec![ResolutionAdditionalDefinitionNamespaceFact {
                declaration,
                namespace: ResolutionNamespace::Value,
                hoisting: HoistingClass::ScopeWide,
            }],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            ..FileResolutionFacts::default()
        };

        let mut mismatched_hoisting = facts.clone();
        mismatched_hoisting.additional_definition_namespaces[0].hoisting =
            HoistingClass::SourceOrder;
        assert!(
            std::panic::catch_unwind(|| {
                lower_file_resolution_facts(fragment(), Language::Rust, &mismatched_hoisting)
            })
            .is_err(),
            "definition namespace authority must match its binder hoisting"
        );

        let lowered = lower_file_resolution_facts(fragment(), Language::Rust, &facts);
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        assert!(
            lowered
                .paths()
                .iter()
                .any(|(id, _)| *id == binder_path_id(fragment(), declaration)),
            "the primary binder path identity must remain stable"
        );
        assert!(lowered.paths().iter().any(|(id, _)| {
            *id == additional_binder_path_identity(declaration, ResolutionNamespace::Value)
                .mount(fragment())
        }));

        let type_answer = resolve(lowered.clone(), 1);
        let value_answer = resolve(lowered, 2);
        assert_eq!(type_answer.targets(), &[definition]);
        assert_eq!(value_answer.targets(), &[definition]);
    }

    #[test]
    fn positioned_reference_gap_does_not_contaminate_an_unrelated_point() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Target".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "T".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 10),
                site(1, 0, ResolutionSiteKind::TypeReference, 20),
                site(2, 0, ResolutionSiteKind::TypeReference, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    2,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(2),
                kind: ResolutionGapKind::UnsupportedScopeOrBinder,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Rust, &facts);
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);

        let unrelated = resolve_with_coverage(lowered.clone(), 1);
        assert_eq!(unrelated.targets(), &[definition]);
        assert_eq!(unrelated.completion(), &ResolutionCompletion::Complete);

        let bounded = resolve_with_coverage(lowered, 2);
        assert!(bounded.targets().is_empty());
        assert_ne!(bounded.completion(), &ResolutionCompletion::Complete);
    }

    fn nested_type_body_facts(reference_namespace: ResolutionNamespace) -> FileResolutionFacts {
        FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Outer".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "Inner".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "member".into(),
                },
            ],
            scopes: vec![
                scope(0, None, 0, 300),
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(1),
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: Some(ResolutionSiteId::new(0)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 10,
                    end_byte: 290,
                },
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(2),
                    parent: Some(ResolutionScopeId::new(1)),
                    owner: Some(ResolutionSiteId::new(1)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 50,
                    end_byte: 250,
                },
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 1, ResolutionSiteKind::TypeDeclaration, 20),
                site(2, 2, reference_site_kind(reference_namespace), 100),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Reference,
                    reference_namespace,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    300,
                ),
                binder(
                    1,
                    1,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    10,
                    290,
                ),
            ],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            }],
            ..FileResolutionFacts::default()
        }
    }

    fn reference_site_kind(namespace: ResolutionNamespace) -> ResolutionSiteKind {
        match namespace {
            ResolutionNamespace::Type => ResolutionSiteKind::TypeReference,
            ResolutionNamespace::Value
            | ResolutionNamespace::Constant
            | ResolutionNamespace::TypeOrValue => ResolutionSiteKind::ValueReference,
            ResolutionNamespace::Callable => ResolutionSiteKind::CallableReference,
            ResolutionNamespace::Constructor => ResolutionSiteKind::ConstructorReference,
            ResolutionNamespace::Macro => ResolutionSiteKind::MacroReference,
        }
    }

    fn add_scope_wide_declaration(
        facts: &mut FileResolutionFacts,
        site_id: u32,
        scope_id: u32,
        name_id: u32,
        site_kind: ResolutionSiteKind,
        binder_kind: ResolutionBinderKind,
        namespace: ResolutionNamespace,
    ) {
        let scope = facts
            .scopes
            .iter()
            .find(|scope| scope.id == ResolutionScopeId::new(scope_id))
            .copied()
            .expect("fixture declaration scope");
        facts
            .sites
            .push(site(site_id, scope_id, site_kind, scope.start_byte + 2));
        facts.identifiers.push(identifier(
            site_id,
            name_id,
            ResolutionIdentifierRole::Declaration,
            namespace,
        ));
        facts.binders.push(binder(
            site_id,
            scope_id,
            binder_kind,
            HoistingClass::ScopeWide,
            scope.start_byte,
            scope.end_byte,
        ));
    }

    #[test]
    fn parameter_and_source_order_local_discharge_root_placement_fallback() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "x".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "before".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "after".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 2),
                site(1, 0, ResolutionSiteKind::ValueDeclaration, 20),
                site(2, 0, ResolutionSiteKind::ValueReference, 10),
                site(3, 0, ResolutionSiteKind::ValueReference, 30),
                site(4, 0, ResolutionSiteKind::UnsupportedRoute, 0),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    3,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Parameter,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    1,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::SourceOrder,
                    21,
                    100,
                ),
            ],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(4),
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let parameter = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let local = semantic(&lowered, 1, LoweredSemanticRole::Definition);

        let before = resolve_with_coverage(lowered.clone(), 2);
        assert_eq!(before.targets(), &[parameter]);
        assert_eq!(before.completion(), &ResolutionCompletion::Complete);
        let after = resolve_with_coverage(lowered, 3);
        assert_eq!(after.targets(), &[local]);
        assert_eq!(after.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn source_order_activation_includes_the_declarations_own_initializer() {
        // JLS 6.3 Example 6.3-2: the local `x` shadows the outer field
        // throughout its own initializer. Definite-assignment checking may
        // reject the read later, but binding must never resolve it to the
        // field.
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "x".into(),
            }],
            scopes: vec![scope(0, None, 0, 100), scope(1, Some(0), 20, 90)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 10),
                site(1, 1, ResolutionSiteKind::ValueDeclaration, 40),
                site(2, 1, ResolutionSiteKind::ValueReference, 50),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Field,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    1,
                    1,
                    ResolutionBinderKind::Local,
                    HoistingClass::SourceOrder,
                    50,
                    90,
                ),
            ],
            ..FileResolutionFacts::default()
        };

        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let local = semantic(&lowered, 1, LoweredSemanticRole::Definition);
        let field = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let answer = resolve(lowered, 2);

        assert_eq!(answer.targets(), &[local]);
        assert!(!answer.targets().contains(&field));
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn nearest_scope_wins_and_siblings_are_excluded() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "x".into(),
            }],
            scopes: vec![
                scope(0, None, 0, 200),
                scope(1, Some(0), 10, 90),
                scope(2, Some(0), 100, 190),
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 1, ResolutionSiteKind::ValueDeclaration, 11),
                site(2, 2, ResolutionSiteKind::ValueDeclaration, 101),
                site(3, 1, ResolutionSiteKind::ValueReference, 40),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    3,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::ScopeWide,
                    0,
                    200,
                ),
                binder(
                    1,
                    1,
                    ResolutionBinderKind::Local,
                    HoistingClass::ScopeWide,
                    10,
                    90,
                ),
                binder(
                    2,
                    2,
                    ResolutionBinderKind::Local,
                    HoistingClass::ScopeWide,
                    100,
                    190,
                ),
            ],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let inner = semantic(&lowered, 1, LoweredSemanticRole::Definition);
        let sibling = semantic(&lowered, 2, LoweredSemanticRole::Definition);
        let answer = resolve(lowered, 3);
        assert_eq!(answer.targets(), &[inner]);
        assert!(!answer.targets().contains(&sibling));
    }

    #[test]
    fn type_or_value_prefers_value_and_constructor_is_a_distinct_key() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "Thing".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::ValueDeclaration, 2),
                site(2, 0, ResolutionSiteKind::ConstructorDeclaration, 3),
                site(3, 0, ResolutionSiteKind::ValueReference, 10),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Constructor,
                ),
                identifier(
                    3,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::TypeOrValue,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    1,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    2,
                    0,
                    ResolutionBinderKind::Constructor,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
            ],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let value = semantic(&lowered, 1, LoweredSemanticRole::Definition);
        let constructor = semantic(&lowered, 2, LoweredSemanticRole::Definition);
        let answer = resolve(lowered, 3);
        assert_eq!(answer.targets(), &[value]);
        assert!(!answer.targets().contains(&constructor));
    }

    #[test]
    fn direct_field_and_nested_type_discharge_hierarchy_and_enclosing_fallbacks() {
        for (namespace, site_kind, binder_kind) in [
            (
                ResolutionNamespace::Value,
                ResolutionSiteKind::ValueDeclaration,
                ResolutionBinderKind::Field,
            ),
            (
                ResolutionNamespace::Type,
                ResolutionSiteKind::TypeDeclaration,
                ResolutionBinderKind::Type,
            ),
        ] {
            let mut facts = nested_type_body_facts(namespace);
            add_scope_wide_declaration(&mut facts, 3, 2, 2, site_kind, binder_kind, namespace);
            add_scope_wide_declaration(&mut facts, 4, 1, 2, site_kind, binder_kind, namespace);
            let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
            let direct = semantic(&lowered, 3, LoweredSemanticRole::Definition);
            let enclosing = semantic(&lowered, 4, LoweredSemanticRole::Definition);
            let answer = resolve_with_coverage(lowered, 2);
            assert_eq!(answer.targets(), &[direct]);
            assert!(!answer.targets().contains(&enclosing));
            assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
        }
    }

    #[test]
    fn direct_method_ties_hierarchy_but_rejects_enclosing_method() {
        let mut facts = nested_type_body_facts(ResolutionNamespace::Callable);
        add_scope_wide_declaration(
            &mut facts,
            3,
            2,
            2,
            ResolutionSiteKind::CallableDeclaration,
            ResolutionBinderKind::Callable,
            ResolutionNamespace::Callable,
        );
        add_scope_wide_declaration(
            &mut facts,
            4,
            1,
            2,
            ResolutionSiteKind::CallableDeclaration,
            ResolutionBinderKind::Callable,
            ResolutionNamespace::Callable,
        );
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let direct = semantic(&lowered, 3, LoweredSemanticRole::Definition);
        let enclosing = semantic(&lowered, 4, LoweredSemanticRole::Definition);
        let direct_path = lowered
            .paths()
            .iter()
            .find(|(id, _)| *id == binder_path_id(fragment(), ResolutionSiteId::new(3)))
            .map(|(_, path)| path)
            .expect("direct method binder path");
        assert_eq!(
            direct_path.precedence(),
            &[
                precedence_step(
                    scope_choice(
                        fragment(),
                        ResolutionScopeId::new(2),
                        ResolutionNamespace::Callable,
                    ),
                    1,
                ),
                precedence_step(
                    hierarchy_choice(
                        fragment(),
                        ResolutionScopeId::new(2),
                        ResolutionNamespace::Callable,
                    ),
                    0,
                ),
            ]
        );
        let answer = resolve_with_coverage(lowered, 2);
        assert_eq!(answer.targets(), &[direct]);
        assert!(!answer.targets().contains(&enclosing));
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(
                    gap_reason_semantic(
                        fragment(),
                        ResolutionSiteId::new(1),
                        LoweringGapOrigin::Extracted(
                            ResolutionGapKind::UnsupportedHierarchyTraversal,
                        ),
                    ),
                ))
        ));
    }

    #[test]
    fn direct_constructor_discharges_nonaffirmative_hierarchy_evidence() {
        let mut facts = nested_type_body_facts(ResolutionNamespace::Constructor);
        facts
            .identifiers
            .iter_mut()
            .find(|identifier| identifier.site == ResolutionSiteId::new(2))
            .expect("constructor reference")
            .name = ResolutionNameId::new(1);
        add_scope_wide_declaration(
            &mut facts,
            3,
            2,
            1,
            ResolutionSiteKind::ConstructorDeclaration,
            ResolutionBinderKind::Constructor,
            ResolutionNamespace::Constructor,
        );
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let direct = semantic(&lowered, 3, LoweredSemanticRole::Definition);
        let answer = resolve_with_coverage(lowered, 2);
        assert_eq!(answer.targets(), &[direct]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn type_or_value_keeps_only_choice_relevant_hierarchy_uncertainty() {
        let mut facts = nested_type_body_facts(ResolutionNamespace::TypeOrValue);
        facts.gaps.clear();
        add_scope_wide_declaration(
            &mut facts,
            3,
            2,
            2,
            ResolutionSiteKind::TypeDeclaration,
            ResolutionBinderKind::Type,
            ResolutionNamespace::Type,
        );
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let type_target = semantic(&lowered, 3, LoweredSemanticRole::Definition);
        let closed_type_only = resolve_with_coverage(lowered, 2);
        assert_eq!(closed_type_only.targets(), &[type_target]);
        assert_eq!(
            closed_type_only.completion(),
            &ResolutionCompletion::Complete
        );

        let mut facts = nested_type_body_facts(ResolutionNamespace::TypeOrValue);
        add_scope_wide_declaration(
            &mut facts,
            3,
            2,
            2,
            ResolutionSiteKind::TypeDeclaration,
            ResolutionBinderKind::Type,
            ResolutionNamespace::Type,
        );
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let type_target = semantic(&lowered, 3, LoweredSemanticRole::Definition);
        let type_only = resolve_with_coverage(lowered, 2);
        assert_eq!(type_only.targets(), &[type_target]);
        assert!(matches!(
            type_only.completion(),
            ResolutionCompletion::Incomplete(_)
        ));

        let mut facts = nested_type_body_facts(ResolutionNamespace::TypeOrValue);
        add_scope_wide_declaration(
            &mut facts,
            3,
            2,
            2,
            ResolutionSiteKind::TypeDeclaration,
            ResolutionBinderKind::Type,
            ResolutionNamespace::Type,
        );
        add_scope_wide_declaration(
            &mut facts,
            4,
            2,
            2,
            ResolutionSiteKind::ValueDeclaration,
            ResolutionBinderKind::Field,
            ResolutionNamespace::Value,
        );
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let value_target = semantic(&lowered, 4, LoweredSemanticRole::Definition);
        let value_and_type = resolve_with_coverage(lowered, 2);
        assert_eq!(value_and_type.targets(), &[value_target]);
        assert_eq!(value_and_type.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn topology_is_linear_and_never_materializes_reference_to_definition_paths() {
        let count = 64_u32;
        let mut facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "x".into(),
            }],
            scopes: vec![scope(0, None, 0, 10_000)],
            ..FileResolutionFacts::default()
        };
        for index in 0..count {
            let declaration = index * 2;
            let reference = declaration + 1;
            let position = usize::try_from(index).expect("small test index") * 100 + 2;
            facts.sites.extend([
                site(
                    declaration,
                    0,
                    ResolutionSiteKind::ValueDeclaration,
                    position,
                ),
                site(
                    reference,
                    0,
                    ResolutionSiteKind::ValueReference,
                    position + 2,
                ),
            ]);
            facts.identifiers.extend([
                identifier(
                    declaration,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    reference,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ]);
            facts.binders.push(binder(
                declaration,
                0,
                ResolutionBinderKind::Local,
                HoistingClass::SourceOrder,
                position + 1,
                10_000,
            ));
        }
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let input_rows =
            facts.scopes.len() + facts.sites.len() + facts.identifiers.len() + facts.binders.len();
        assert!(lowered.nodes().len() + lowered.paths().len() <= input_rows * 2);
        assert!(
            lowered
                .paths()
                .iter()
                .all(|(_, path)| path.precedence().len() <= EFFECTIVE_NAMESPACES.len() * 2),
            "namespace and TypeBody choice traces have a constant bound"
        );
        let references = lowered
            .nodes()
            .iter()
            .filter_map(|(node, kind)| {
                matches!(kind, BindingNodeKind::Reference(_)).then_some(*node)
            })
            .collect::<HashSet<_>>();
        let definitions = lowered
            .nodes()
            .iter()
            .filter_map(|(node, kind)| {
                matches!(kind, BindingNodeKind::Definition(_)).then_some(*node)
            })
            .collect::<HashSet<_>>();
        assert!(lowered.paths().iter().all(|(_, path)| {
            !(references.contains(&path.start().node()) && definitions.contains(&path.end().node()))
        }));
    }

    #[test]
    fn scope_and_checkpoint_choices_are_namespace_scoped() {
        let scope = ResolutionScopeId::new(7);
        let position = 19;
        let scope_choices = EFFECTIVE_NAMESPACES
            .into_iter()
            .map(|namespace| scope_choice(fragment(), scope, namespace))
            .collect::<HashSet<_>>();
        let checkpoint_choices = EFFECTIVE_NAMESPACES
            .into_iter()
            .map(|namespace| checkpoint_choice(fragment(), scope, position, namespace))
            .collect::<HashSet<_>>();
        assert_eq!(scope_choices.len(), EFFECTIVE_NAMESPACES.len());
        assert_eq!(checkpoint_choices.len(), EFFECTIVE_NAMESPACES.len());
        assert!(scope_choices.is_disjoint(&checkpoint_choices));
    }

    #[test]
    fn permuting_normalized_rows_preserves_every_output_identity() {
        let mut facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "x".into(),
            }],
            scopes: vec![scope(0, None, 0, 100), scope(1, Some(0), 20, 80)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 1, ResolutionSiteKind::ValueReference, 30),
                site(2, 0, ResolutionSiteKind::UnsupportedRoute, 0),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Local,
                HoistingClass::SourceOrder,
                2,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(2),
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }],
            ..FileResolutionFacts::default()
        };
        let expected = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        facts.names.reverse();
        facts.scopes.reverse();
        facts.sites.reverse();
        facts.identifiers.reverse();
        facts.binders.reverse();
        facts.gaps.reverse();
        let actual = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert_eq!(actual, expected);
    }

    #[test]
    fn route_gap_without_affirmative_rows_retains_fragment_and_enumeration_gaps() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedRoute, 20)],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedRoute,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedRoute,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(lowered.semantics().is_empty());
        assert!(
            lowered
                .gaps()
                .iter()
                .any(|gap| { gap.frontier() == LoweringCoverageFrontier::Fragment })
        );
        assert!(
            lowered
                .gaps()
                .iter()
                .any(|gap| { gap.frontier() == LoweringCoverageFrontier::Enumeration })
        );
        assert!(lowered.gaps().iter().any(|gap| {
            gap.frontier()
                == LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                }
        }));
        let (_, gaps) = lowered.into_preloaded_parts();
        assert!(!gaps.is_empty());
    }

    #[test]
    fn unsupported_expression_blocks_enumeration_but_not_fragment_candidates() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(
            lowered
                .gaps()
                .iter()
                .any(|gap| { gap.frontier() == LoweringCoverageFrontier::Enumeration })
        );
        assert!(
            !lowered
                .gaps()
                .iter()
                .any(|gap| { gap.frontier() == LoweringCoverageFrontier::Fragment })
        );
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let mut visited_batches = 0;
        let summary = BatchResolutionEngine::new(&source)
            .stream_all_reference_batches(8, &CancellationToken::new(), &mut |_| {
                visited_batches += 1;
                Ok(())
            })
            .expect("empty broad stream");
        assert_eq!(visited_batches, 0);
        assert!(matches!(
            summary.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    fn member_scope_gap_preserves_lexical_points_but_keeps_reverse_open() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "target".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::CallableDeclaration, 1),
                site(1, 0, ResolutionSiteKind::CallableReference, 20),
                site(2, 0, ResolutionSiteKind::UnsupportedDeclaration, 40),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Callable,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Callable,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(2),
                kind: ResolutionGapKind::UnsupportedMemberScope,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(2),
                kind: ResolutionGapKind::UnsupportedMemberScope,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Rust, &facts);
        let member_frontiers = lowered
            .gaps()
            .iter()
            .filter(|gap| {
                gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedMemberScope)
            })
            .map(LoweredCoverageGap::frontier)
            .collect::<HashSet<_>>();
        let expected = [
            LoweringCoverageFrontier::Enumeration,
            LoweringCoverageFrontier::CandidateInventory {
                direction: LoweredCandidateDirection::Reverse,
            },
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(member_frontiers, expected);

        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let point = resolve_with_coverage(lowered.clone(), 1);
        assert_eq!(point.targets(), &[definition]);
        assert_eq!(point.completion(), &ResolutionCompletion::Complete);

        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let broad = BatchResolutionEngine::new(&source)
            .stream_all_reference_batches(8, &CancellationToken::new(), &mut |_| Ok(()))
            .expect("broad member-scope lookup");
        assert!(matches!(
            broad.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    fn unsupported_type_subtree_blocks_enumeration_and_reverse_inventory() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedTypeSyntax,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedTypeSyntax,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(
            lowered
                .gaps()
                .iter()
                .any(|gap| { gap.frontier() == LoweringCoverageFrontier::Enumeration })
        );
        assert!(lowered.gaps().iter().any(|gap| {
            gap.frontier()
                == LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                }
        }));
    }

    #[test]
    fn typing_gap_with_enumerated_child_keeps_reference_enumeration_complete() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "known_child".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20),
                site(1, 0, ResolutionSiteKind::ValueReference, 21),
            ],
            identifiers: vec![identifier(
                1,
                0,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Value,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(!lowered.gaps().iter().any(|gap| {
            matches!(
                gap.frontier(),
                LoweringCoverageFrontier::Enumeration
                    | LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
            )
        }));
        assert!(lowered.gaps().iter().any(|gap| {
            gap.frontier()
                == LoweringCoverageFrontier::Type {
                    frontier: site_type_frontier_semantic(fragment(), ResolutionSiteId::new(0)),
                }
        }));

        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let mut visited = 0;
        BatchResolutionEngine::new(&source)
            .stream_all_reference_batches(8, &CancellationToken::new(), &mut |_| {
                visited += 1;
                Ok(())
            })
            .expect("the enumerated child must stream");
        assert_eq!(visited, 1, "the positioned child must remain enumerable");
    }

    #[test]
    fn reference_enumeration_gap_is_independent_of_point_resolution_gaps() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            reference_enumeration_gaps: vec![ResolutionReferenceEnumerationGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedTypeSyntax,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(lowered.gaps().iter().any(|gap| {
            gap.frontier() == LoweringCoverageFrontier::Enumeration
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedTypeSyntax)
        }));
        assert!(!lowered.gaps().iter().any(|gap| {
            gap.frontier()
                == LoweringCoverageFrontier::CandidateInventory {
                    direction: LoweredCandidateDirection::Reverse,
                }
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedTypeSyntax)
        }));
        assert!(lowered.gaps().iter().any(|gap| {
            gap.frontier()
                == LoweringCoverageFrontier::Type {
                    frontier: site_type_frontier_semantic(fragment(), ResolutionSiteId::new(0)),
                }
                && gap.origin()
                    == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedExpression)
        }));
    }

    #[test]
    #[should_panic(expected = "duplicate reference-enumeration gap")]
    fn reference_enumeration_gap_rejects_duplicate_ownership() {
        let row = ResolutionReferenceEnumerationGapFact {
            site: ResolutionSiteId::new(0),
            kind: ResolutionGapKind::UnsupportedExpression,
        };
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::UnsupportedExpression, 20)],
            gaps: vec![ResolutionGapFact {
                site: row.site,
                kind: row.kind,
            }],
            reference_enumeration_gaps: vec![row, row],
            ..FileResolutionFacts::default()
        };
        let _ = lower_file_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    fn visibility_gap_is_type_property_only_and_does_not_poison_lexical_lookup() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "Owner".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::TypeReference, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedVisibility,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert_eq!(lowered.gaps().len(), 1);
        assert_eq!(
            lowered.gaps()[0].frontier(),
            LoweringCoverageFrontier::Type {
                frontier: site_type_frontier_semantic(fragment(), ResolutionSiteId::new(0)),
            }
        );
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let answer = resolve_with_coverage(lowered, 1);
        assert_eq!(answer.targets(), &[definition]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn implicit_receiver_gap_is_reference_and_type_local_without_reverse_poisoning() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "field".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 0, ResolutionSiteKind::ValueReference, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Field,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedImplicitReceiver,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(
            lowered.gaps().iter().any(|gap| {
                matches!(gap.frontier(), LoweringCoverageFrontier::Reference { .. })
            })
        );
        assert!(lowered.gaps().iter().any(|gap| {
            gap.frontier()
                == LoweringCoverageFrontier::Type {
                    frontier: site_type_frontier_semantic(fragment(), ResolutionSiteId::new(1)),
                }
        }));
        assert!(!lowered.gaps().iter().any(|gap| {
            matches!(
                gap.frontier(),
                LoweringCoverageFrontier::Fragment
                    | LoweringCoverageFrontier::Enumeration
                    | LoweringCoverageFrontier::CandidateInventory { .. }
                    | LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        ..
                    }
            )
        }));
        let answer = resolve_with_coverage(lowered, 1);
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    fn qualified_reference_keeps_reverse_inventory_incomplete_without_blocking_enumeration() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "member".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 0, ResolutionSiteKind::MemberReference, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                PositionedIdentifierFact {
                    site: ResolutionSiteId::new(1),
                    name: ResolutionNameId::new(0),
                    role: ResolutionIdentifierRole::Reference,
                    namespace: ResolutionNamespace::Value,
                    qualifier: Some(ResolutionTypeSlotId::new(0)),
                },
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Field,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(1),
                role: ResolutionTypeSlotRole::Receiver,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(lowered.gaps().iter().any(|gap| {
            gap.origin() == LoweringGapOrigin::QualifiedReference
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
        assert!(!lowered.gaps().iter().any(|gap| {
            gap.origin() == LoweringGapOrigin::QualifiedReference
                && gap.frontier() == LoweringCoverageFrontier::Enumeration
        }));
    }

    #[test]
    fn pending_call_applicability_is_local_across_point_and_broad_reads() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "call".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::CallableDeclaration, 1),
                site(1, 0, ResolutionSiteKind::CallableReference, 20),
                site(2, 0, ResolutionSiteKind::Call, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Callable,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Callable,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(2),
                role: ResolutionTypeSlotRole::CallResult,
            }],
            calls: vec![ResolutionCallFact {
                call: ResolutionSiteId::new(2),
                callee: ResolutionSiteId::new(1),
                receiver: None,
                result: ResolutionTypeSlotId::new(0),
                explicit_type_argument_count: 0,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(!lowered.gaps().iter().any(|gap| {
            matches!(
                gap.frontier(),
                LoweringCoverageFrontier::Fragment
                    | LoweringCoverageFrontier::Enumeration
                    | LoweringCoverageFrontier::CandidateInventory { .. }
            )
        }));
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let point = resolve_with_coverage(lowered.clone(), 1);
        assert_eq!(point.targets(), &[definition]);
        assert!(matches!(
            point.completion(),
            ResolutionCompletion::Incomplete(_)
        ));

        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let broad = BatchResolutionEngine::new(&source)
            .stream_all_reference_batches(8, &CancellationToken::new(), &mut |_| Ok(()))
            .expect("broad callable lookup");
        assert!(matches!(
            broad.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    fn placement_boundary_keeps_cross_fragment_negative_incomplete_and_local_target_usable() {
        let declaration_fragment = BindingFragmentId::hash_bytes(b"placement-declaration");
        let reference_fragment = BindingFragmentId::hash_bytes(b"placement-reference");
        let declaration_facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "A".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::UnsupportedRoute, 0),
            ],
            identifiers: vec![identifier(
                0,
                0,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            )],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }],
            ..FileResolutionFacts::default()
        };
        let reference_facts = FileResolutionFacts {
            names: declaration_facts.names.clone(),
            scopes: declaration_facts.scopes.clone(),
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeReference, 20),
                site(1, 0, ResolutionSiteKind::UnsupportedRoute, 0),
            ],
            identifiers: vec![identifier(
                0,
                0,
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }],
            ..FileResolutionFacts::default()
        };
        let declaration =
            lower_file_resolution_facts(declaration_fragment, Language::Java, &declaration_facts);
        let reference =
            lower_file_resolution_facts(reference_fragment, Language::Java, &reference_facts);
        let cross_reference = semantic(&reference, 0, LoweredSemanticRole::Reference);
        assert!(!reference.gaps().iter().any(|gap| {
            gap.origin()
                == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
                && matches!(
                    gap.frontier(),
                    LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Forward,
                        ..
                    }
                )
        }));
        assert!(reference.gaps().iter().any(|gap| {
            gap.origin()
                == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
        assert!(!reference.gaps().iter().any(|gap| {
            matches!(
                gap.frontier(),
                LoweringCoverageFrontier::Fragment
                    | LoweringCoverageFrontier::Enumeration
                    | LoweringCoverageFrontier::Reference { .. }
                    | LoweringCoverageFrontier::Type { .. }
            )
        }));
        let placement_reason = gap_reason_semantic(
            reference_fragment,
            ResolutionSiteId::new(1),
            LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary),
        );
        let placement_path = reference
            .paths()
            .iter()
            .find(|(id, _)| {
                *id == placement_gap_path_id(
                    reference_fragment,
                    ResolutionSiteId::new(1),
                    ResolutionScopeId::new(0),
                )
            })
            .map(|(_, path)| path)
            .expect("placement terminal path");
        assert_eq!(
            placement_path.start().node(),
            scope_head_node(reference_fragment, ResolutionScopeId::new(0))
        );
        assert!(placement_path.start().symbols().fixed().is_empty());
        assert_eq!(
            placement_path.start().symbols().tail(),
            placement_path.end().symbols().tail()
        );
        assert_eq!(
            placement_path.precedence().len(),
            EFFECTIVE_NAMESPACES.len()
        );
        assert!(matches!(
            placement_path.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.len() == 1
                    && reasons.get(0)
                        == Some(&ResolutionIncompleteReason::UnsupportedSemantic(placement_reason))
        ));

        let source = super::super::engine::PreloadedFragmentSource::from_lowered_fragments([
            declaration,
            reference,
        ]);
        let point = BatchResolutionEngine::new(&source)
            .resolve_reference(
                ResolutionQuery::new(cross_reference),
                &CancellationToken::new(),
            )
            .expect("cross-fragment point lookup");
        assert!(point.targets().is_empty());
        assert!(matches!(
            point.completion(),
            ResolutionCompletion::Incomplete(_)
        ));

        let mut local_facts = declaration_facts;
        local_facts
            .sites
            .push(site(2, 0, ResolutionSiteKind::TypeReference, 20));
        local_facts.identifiers.push(identifier(
            2,
            0,
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Type,
        ));
        let local_fragment = BindingFragmentId::hash_bytes(b"placement-local");
        let local = lower_file_resolution_facts(local_fragment, Language::Java, &local_facts);
        let local_definition = semantic(&local, 0, LoweredSemanticRole::Definition);
        let local_reference = semantic(&local, 2, LoweredSemanticRole::Reference);
        let local_source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([local]);
        let local_answer = BatchResolutionEngine::new(&local_source)
            .resolve_reference(
                ResolutionQuery::new(local_reference),
                &CancellationToken::new(),
            )
            .expect("same-file lookup");
        assert_eq!(local_answer.targets(), &[local_definition]);
        assert_eq!(local_answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    #[should_panic(
        expected = "placement boundary gap must name a root CompilationUnit or Package scope"
    )]
    fn nested_placement_boundary_is_rejected_at_lowering() {
        let facts = FileResolutionFacts {
            scopes: vec![scope(0, None, 0, 100), scope(1, Some(0), 10, 90)],
            sites: vec![site(0, 1, ResolutionSiteKind::UnsupportedRoute, 20)],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }],
            ..FileResolutionFacts::default()
        };
        let _ = lower_file_resolution_facts(fragment(), Language::Java, &facts);
    }

    #[test]
    fn unqualified_lookup_crossing_an_open_type_hierarchy_is_incomplete() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Sub".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "inherited".into(),
                },
            ],
            scopes: vec![
                scope(0, None, 0, 100),
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(1),
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: Some(ResolutionSiteId::new(0)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 10,
                    end_byte: 90,
                },
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 5),
                site(1, 1, ResolutionSiteKind::CallableReference, 50),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let reference = semantic(&lowered, 1, LoweredSemanticRole::Reference);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("unqualified hierarchy lookup");
        assert!(answer.targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    fn assert_explicit_supertype_hierarchy_is_incomplete(
        kind: ResolutionSupertypeKind,
        include_enclosing_target: bool,
    ) {
        let mut facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Outer".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "Sub".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "Base".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(3),
                    spelling: "inherited".into(),
                },
            ],
            scopes: vec![
                scope(0, None, 0, 200),
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(1),
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: Some(ResolutionSiteId::new(0)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 10,
                    end_byte: 190,
                },
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(2),
                    parent: Some(ResolutionScopeId::new(1)),
                    owner: Some(ResolutionSiteId::new(1)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 40,
                    end_byte: 170,
                },
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 1, ResolutionSiteKind::TypeDeclaration, 20),
                site(2, 1, ResolutionSiteKind::TypeReference, 30),
                site(3, 2, ResolutionSiteKind::CallableReference, 100),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    3,
                    3,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    200,
                ),
                binder(
                    1,
                    1,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    10,
                    190,
                ),
            ],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(2),
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            }],
            supertypes: vec![ResolutionSupertypeFact {
                subtype: ResolutionSiteId::new(1),
                supertype_reference: ResolutionSiteId::new(2),
                supertype_slot: ResolutionTypeSlotId::new(0),
                kind,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(2),
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            }],
            ..FileResolutionFacts::default()
        };
        if include_enclosing_target {
            facts
                .sites
                .push(site(4, 1, ResolutionSiteKind::CallableDeclaration, 150));
            facts.identifiers.push(identifier(
                4,
                3,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Callable,
            ));
            facts.binders.push(binder(
                4,
                1,
                ResolutionBinderKind::Callable,
                HoistingClass::ScopeWide,
                10,
                190,
            ));
        }

        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        let reference = semantic(&lowered, 3, LoweredSemanticRole::Reference);
        let expected_target = include_enclosing_target
            .then(|| semantic(&lowered, 4, LoweredSemanticRole::Definition));
        let reason = gap_reason_semantic(
            fragment(),
            ResolutionSiteId::new(2),
            LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal),
        );
        let hierarchy_path = lowered
            .paths()
            .iter()
            .find(|(id, _)| {
                *id == hierarchy_gap_path_id(
                    fragment(),
                    ResolutionSiteId::new(2),
                    ResolutionSiteId::new(1),
                )
            })
            .map(|(_, path)| path)
            .expect("exact supertype hierarchy terminal");
        assert_eq!(
            hierarchy_path.start().node(),
            scope_head_node(fragment(), ResolutionScopeId::new(2))
        );
        assert!(hierarchy_path.start().symbols().fixed().is_empty());
        assert_eq!(
            hierarchy_path.start().symbols().tail(),
            hierarchy_path.end().symbols().tail()
        );
        let mut identities = ResolutionIdentityCatalogBuilder::new(fragment());
        let expected_precedence =
            type_body_hierarchy_precedence(&mut identities, ResolutionScopeId::new(2));
        assert_eq!(hierarchy_path.precedence(), expected_precedence.as_slice());
        assert!(matches!(
            hierarchy_path.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.len() == 1
                    && reasons.get(0)
                        == Some(&ResolutionIncompleteReason::UnsupportedSemantic(reason))
        ));
        let enclosing_path = lowered
            .paths()
            .iter()
            .find(|(id, _)| *id == parent_path_id(fragment(), ResolutionScopeId::new(2)))
            .map(|(_, path)| path)
            .expect("type-body enclosing path");
        assert_eq!(enclosing_path.completion(), &ResolutionCompletion::Complete);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("explicit-supertype hierarchy lookup");
        assert_eq!(answer.targets(), expected_target.as_slice());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(reasons)
                if reasons.contains(&ResolutionIncompleteReason::UnsupportedSemantic(reason))
        ));
    }

    #[test]
    fn explicit_class_supertype_keeps_empty_and_enclosing_lookup_incomplete() {
        assert_explicit_supertype_hierarchy_is_incomplete(
            ResolutionSupertypeKind::Superclass,
            false,
        );
        assert_explicit_supertype_hierarchy_is_incomplete(
            ResolutionSupertypeKind::Superclass,
            true,
        );
    }

    #[test]
    fn explicit_interface_supertype_keeps_empty_and_enclosing_lookup_incomplete() {
        assert_explicit_supertype_hierarchy_is_incomplete(
            ResolutionSupertypeKind::Interface,
            false,
        );
        assert_explicit_supertype_hierarchy_is_incomplete(ResolutionSupertypeKind::Interface, true);
    }

    #[test]
    fn hierarchy_reasons_have_independent_terminal_paths_and_stable_ids() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Owner".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "Base".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "Contract".into(),
                },
            ],
            scopes: vec![
                scope(0, None, 0, 100),
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(1),
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: Some(ResolutionSiteId::new(0)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 10,
                    end_byte: 90,
                },
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 0, ResolutionSiteKind::TypeReference, 2),
                site(2, 0, ResolutionSiteKind::TypeReference, 3),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    2,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            type_slots: vec![
                ResolutionTypeSlotFact {
                    id: ResolutionTypeSlotId::new(0),
                    site: ResolutionSiteId::new(1),
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                },
                ResolutionTypeSlotFact {
                    id: ResolutionTypeSlotId::new(1),
                    site: ResolutionSiteId::new(2),
                    role: ResolutionTypeSlotRole::TargetTypeIdentity,
                },
            ],
            supertypes: vec![
                ResolutionSupertypeFact {
                    subtype: ResolutionSiteId::new(0),
                    supertype_reference: ResolutionSiteId::new(1),
                    supertype_slot: ResolutionTypeSlotId::new(0),
                    kind: ResolutionSupertypeKind::Superclass,
                },
                ResolutionSupertypeFact {
                    subtype: ResolutionSiteId::new(0),
                    supertype_reference: ResolutionSiteId::new(2),
                    supertype_slot: ResolutionTypeSlotId::new(1),
                    kind: ResolutionSupertypeKind::Interface,
                },
            ],
            gaps: vec![
                ResolutionGapFact {
                    site: ResolutionSiteId::new(1),
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
                ResolutionGapFact {
                    site: ResolutionSiteId::new(2),
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
            ],
            ..FileResolutionFacts::default()
        };
        let expected = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        for site_id in [1, 2] {
            let reason = gap_reason_semantic(
                fragment(),
                ResolutionSiteId::new(site_id),
                LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal),
            );
            let path = expected
                .paths()
                .iter()
                .find(|(id, _)| {
                    *id == hierarchy_gap_path_id(
                        fragment(),
                        ResolutionSiteId::new(site_id),
                        ResolutionSiteId::new(0),
                    )
                })
                .map(|(_, path)| path)
                .expect("one terminal per hierarchy reason");
            assert!(matches!(
                path.completion(),
                ResolutionCompletion::Incomplete(reasons)
                    if reasons.len() == 1
                        && reasons.get(0)
                            == Some(&ResolutionIncompleteReason::UnsupportedSemantic(reason))
            ));
        }
        assert_eq!(
            expected
                .paths()
                .iter()
                .find(|(id, _)| *id == parent_path_id(fragment(), ResolutionScopeId::new(1)))
                .map(|(_, path)| path.completion()),
            Some(&ResolutionCompletion::Complete)
        );

        let mut permuted = facts;
        permuted.names.reverse();
        permuted.scopes.reverse();
        permuted.sites.reverse();
        permuted.identifiers.reverse();
        permuted.binders.reverse();
        permuted.type_slots.reverse();
        permuted.supertypes.reverse();
        permuted.gaps.reverse();
        assert_eq!(
            lower_file_resolution_facts(fragment(), Language::Java, &permuted),
            expected
        );
    }

    #[test]
    fn inherited_reference_gap_preserves_reverse_inventory_uncertainty() {
        let subclass_fragment = BindingFragmentId::hash_bytes(b"hierarchy-subclass");
        let subclass_facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "Sub".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "member".into(),
                },
            ],
            scopes: vec![
                scope(0, None, 0, 100),
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(1),
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: Some(ResolutionSiteId::new(0)),
                    kind: ResolutionScopeKind::TypeBody,
                    start_byte: 10,
                    end_byte: 90,
                },
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::TypeDeclaration, 1),
                site(1, 1, ResolutionSiteKind::CallableReference, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Callable,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Type,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
            }],
            ..FileResolutionFacts::default()
        };
        let subclass =
            lower_file_resolution_facts(subclass_fragment, Language::Java, &subclass_facts);
        assert!(subclass.gaps().iter().any(|gap| {
            gap.origin()
                == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal)
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
    }

    #[test]
    fn unsupported_activation_of_one_name_does_not_taint_an_unrelated_lookup() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "x".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "y".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 0, ResolutionSiteKind::ValueDeclaration, 2),
                site(2, 0, ResolutionSiteKind::ValueReference, 20),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    1,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Pattern,
                    HoistingClass::DeclaredHead,
                    0,
                    100,
                ),
                binder(
                    1,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
            ],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(!lowered.gaps().iter().any(|gap| matches!(
            gap.frontier(),
            LoweringCoverageFrontier::Fragment | LoweringCoverageFrontier::Enumeration
        )));
        let forward_gap = lowered
            .gaps()
            .iter()
            .find_map(|gap| match gap.frontier() {
                LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint,
                    lookup: Some(lookup),
                } if gap.origin()
                    == LoweringGapOrigin::UnsupportedActivation(HoistingClass::DeclaredHead) =>
                {
                    Some((endpoint, lookup))
                }
                _ => None,
            })
            .expect("keyed forward candidate gap");
        let incomplete_route = lowered
            .paths()
            .iter()
            .map(|(_, path)| path)
            .find(|path| matches!(path.completion(), ResolutionCompletion::Incomplete(_)))
            .expect("withheld binder path");
        assert_eq!(forward_gap.0, incomplete_route.start().node());
        assert_eq!(
            incomplete_route.start().symbols().fixed()[0].symbol(),
            forward_gap.1
        );
        let target = semantic(&lowered, 1, LoweredSemanticRole::Definition);
        let reference = semantic(&lowered, 2, LoweredSemanticRole::Reference);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("resolution");
        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn type_gap_maps_to_its_slot_without_tainting_an_unrelated_reference() {
        let facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "x".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 0, ResolutionSiteKind::ValueReference, 20),
                site(2, 0, ResolutionSiteKind::Literal, 40),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
            ],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Local,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(2),
                role: ResolutionTypeSlotRole::ExpressionValue,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(2),
                kind: ResolutionGapKind::AmbiguousNumericLiteral,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(
            lowered
                .gaps()
                .iter()
                .all(|gap| matches!(gap.frontier(), LoweringCoverageFrontier::Type { .. }))
        );
        let target = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let reference = semantic(&lowered, 1, LoweredSemanticRole::Reference);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let legacy_error = ResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect_err("legacy engine must reject normalized coverage");
        assert!(
            legacy_error
                .to_string()
                .contains("cannot represent normalized lowering coverage")
        );
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("resolution");
        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }

    #[test]
    fn bodyless_constructor_and_hierarchy_gaps_remain_on_typed_and_reverse_frontiers() {
        let facts = FileResolutionFacts {
            names: vec![
                ResolutionNameFact {
                    id: ResolutionNameId::new(0),
                    spelling: "x".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(1),
                    spelling: "Child".into(),
                },
                ResolutionNameFact {
                    id: ResolutionNameId::new(2),
                    spelling: "Parent".into(),
                },
            ],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ValueDeclaration, 1),
                site(1, 0, ResolutionSiteKind::ValueReference, 10),
                site(2, 0, ResolutionSiteKind::TypeDeclaration, 20),
                site(3, 0, ResolutionSiteKind::TypeReference, 30),
            ],
            identifiers: vec![
                identifier(
                    0,
                    0,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    1,
                    0,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                ),
                identifier(
                    2,
                    1,
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                ),
                identifier(
                    3,
                    2,
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                ),
            ],
            binders: vec![
                binder(
                    0,
                    0,
                    ResolutionBinderKind::Local,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
                binder(
                    2,
                    0,
                    ResolutionBinderKind::Type,
                    HoistingClass::ScopeWide,
                    0,
                    100,
                ),
            ],
            type_slots: vec![ResolutionTypeSlotFact {
                id: ResolutionTypeSlotId::new(0),
                site: ResolutionSiteId::new(3),
                role: ResolutionTypeSlotRole::TargetTypeIdentity,
            }],
            supertypes: vec![ResolutionSupertypeFact {
                subtype: ResolutionSiteId::new(2),
                supertype_reference: ResolutionSiteId::new(3),
                supertype_slot: ResolutionTypeSlotId::new(0),
                kind: ResolutionSupertypeKind::Superclass,
            }],
            gaps: vec![
                ResolutionGapFact {
                    site: ResolutionSiteId::new(2),
                    kind: ResolutionGapKind::ImplicitConstructor,
                },
                ResolutionGapFact {
                    site: ResolutionSiteId::new(3),
                    kind: ResolutionGapKind::UnsupportedHierarchyTraversal,
                },
            ],
            ..FileResolutionFacts::default()
        };
        let lowered = lower_file_resolution_facts(fragment(), Language::Java, &facts);
        assert!(
            lowered.paths().iter().all(|(id, _)| {
                *id != hierarchy_gap_path_id(
                    fragment(),
                    ResolutionSiteId::new(3),
                    ResolutionSiteId::new(2),
                )
            }),
            "a bodyless malformed type has no lexical hierarchy frontier"
        );
        assert_eq!(lowered.gaps().len(), 3);
        assert!(lowered.gaps().iter().any(|gap| {
            gap.site() == ResolutionSiteId::new(3)
                && gap.origin()
                    == LoweringGapOrigin::Extracted(
                        ResolutionGapKind::UnsupportedHierarchyTraversal,
                    )
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
        let typed_frontiers = lowered
            .gaps()
            .iter()
            .filter_map(|gap| match gap.frontier() {
                LoweringCoverageFrontier::Type { frontier } => Some((gap.site(), frontier)),
                _ => None,
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(typed_frontiers.len(), 2);
        assert_eq!(
            typed_frontiers[&ResolutionSiteId::new(2)],
            site_type_frontier_semantic(fragment(), ResolutionSiteId::new(2))
        );
        assert_eq!(
            typed_frontiers[&ResolutionSiteId::new(3)],
            type_slot_semantic(fragment(), ResolutionTypeSlotId::new(0))
        );
        assert_ne!(
            typed_frontiers[&ResolutionSiteId::new(2)],
            typed_frontiers[&ResolutionSiteId::new(3)]
        );

        let target = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let reference = semantic(&lowered, 1, LoweredSemanticRole::Reference);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let answer = BatchResolutionEngine::new(&source)
            .resolve_reference(ResolutionQuery::new(reference), &CancellationToken::new())
            .expect("resolution");
        assert_eq!(answer.targets(), &[target]);
        assert_eq!(answer.completion(), &ResolutionCompletion::Complete);
    }
    #[test]
    fn root_routes_combined_catalog_is_exact_and_fragment_independent() {
        let facts = root_route_facts();
        let provisional = BindingFragmentId::hash_bytes(b"root-route-provisional");
        let final_fragment = BindingFragmentId::hash_bytes(b"root-route-final");
        let provisional_artifact =
            lower_resolution_facts_with_identity_catalog(provisional, Language::Go, &facts);
        let final_artifact =
            lower_resolution_facts_with_identity_catalog(final_fragment, Language::Go, &facts);
        let provisional_again =
            lower_resolution_facts_with_identity_catalog(provisional, Language::Go, &facts);
        let final_again =
            lower_resolution_facts_with_identity_catalog(final_fragment, Language::Go, &facts);
        let assert_same_artifact =
            |left: &super::super::LoweredResolutionFactsWithIdentityCatalog,
             right: &super::super::LoweredResolutionFactsWithIdentityCatalog| {
                assert_eq!(left.lexical(), right.lexical());
                assert_eq!(left.typed(), right.typed());
                assert_eq!(left.identities(), right.identities());
            };
        assert_same_artifact(&provisional_artifact, &provisional_again);
        assert_same_artifact(&final_artifact, &final_again);

        let import_site = ResolutionSiteId::new(0);
        let root_scope = ResolutionScopeId::new(1);
        let declaration = ResolutionSiteId::new(1);
        let demand_name = ResolutionNameId::new(3);
        let reference = ResolutionSiteId::new(2);
        let namespace = ResolutionNamespace::Type;
        let expected_shared_route = ["example.com", "repo", "dep"]
            .map(|spelling| lookup_semantic(Language::Go, namespace, spelling));
        let expected_lookup = lookup_semantic(Language::Go, namespace, "Item");

        let inspect = |artifact: &super::super::LoweredResolutionFactsWithIdentityCatalog,
                       mounted_fragment| {
            let import_token = root_import_token(mounted_fragment, import_site, namespace);
            let export_token = root_export_token(mounted_fragment, root_scope, namespace);
            let import_id =
                root_import_path_id(mounted_fragment, import_site, namespace, demand_name);
            let export_id =
                root_export_path_id(mounted_fragment, root_scope, declaration, namespace);
            let import_path = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| (*id == import_id).then_some(path))
                .expect("source-owned root import path");
            let export_path = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| (*id == export_id).then_some(path))
                .expect("source-owned root export path");

            assert_eq!(
                import_path.start().node(),
                scope_head_node(mounted_fragment, root_scope)
            );
            assert_eq!(
                import_path
                    .start()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                [expected_lookup]
            );
            assert_eq!(import_path.end().node(), BindingNodeId::universal_root());
            let mut expected_import_root = vec![root_import_anchor_semantic(
                mounted_fragment,
                ResolutionRootImportAnchor::Lexical,
            )];
            expected_import_root.extend(expected_shared_route);
            expected_import_root.extend([import_token, expected_lookup]);
            assert_eq!(
                import_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                expected_import_root
            );
            assert_eq!(
                import_path.start().symbols().tail(),
                import_path.end().symbols().tail()
            );
            assert_eq!(import_path.precedence().len(), 1);
            assert_eq!(
                import_path.precedence()[0],
                PrecedenceStep {
                    tier: PrecedenceTier::WildcardImport,
                    ordinal: 0,
                    semantic: scope_choice(mounted_fragment, root_scope, namespace),
                }
            );
            assert_eq!(
                import_path.witness(),
                [WitnessStep::Node(BindingNodeId::universal_root())]
            );
            assert_eq!(import_path.completion(), &ResolutionCompletion::Complete);

            assert_eq!(export_path.start().node(), BindingNodeId::universal_root());
            assert_eq!(
                export_path
                    .start()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                [expected_lookup, export_token]
            );
            assert!(export_path.end().symbols().fixed().is_empty());
            assert_eq!(
                export_path.start().symbols().tail(),
                export_path.end().symbols().tail()
            );
            assert_eq!(export_path.precedence().len(), 1);
            assert_eq!(
                export_path.precedence()[0].tier,
                PrecedenceTier::PackageOrModule
            );
            assert_eq!(export_path.precedence()[0].semantic, export_token);
            assert_eq!(
                export_path.witness(),
                [WitnessStep::Node(export_path.end().node())]
            );
            assert_eq!(export_path.completion(), &ResolutionCompletion::Complete);

            let reference_id = root_reference_path_id(mounted_fragment, reference, namespace);
            let reference_token = root_reference_token(mounted_fragment, reference, namespace);
            let reference_path = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| (*id == reference_id).then_some(path))
                .expect("source-owned direct root reference path");
            assert_eq!(
                reference_path.start().node(),
                reference_node(mounted_fragment, reference)
            );
            assert!(reference_path.start().symbols().fixed().is_empty());
            assert!(reference_path.start().symbols().tail().is_none());
            let mut expected_reference_root = vec![root_import_anchor_semantic(
                mounted_fragment,
                ResolutionRootImportAnchor::Absolute,
            )];
            expected_reference_root.extend(expected_shared_route);
            expected_reference_root.extend([reference_token, expected_lookup]);
            assert_eq!(
                reference_path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| symbol.symbol())
                    .collect::<Vec<_>>(),
                expected_reference_root
            );
            assert!(reference_path.end().symbols().tail().is_none());
            assert_eq!(
                reference_path.precedence(),
                [PrecedenceStep {
                    tier: PrecedenceTier::PackageOrModule,
                    ordinal: 0,
                    semantic: scope_choice(mounted_fragment, root_scope, namespace),
                }]
            );
            assert_eq!(
                reference_path.witness(),
                [
                    WitnessStep::Node(scope_head_node(mounted_fragment, root_scope)),
                    WitnessStep::Node(BindingNodeId::universal_root()),
                ]
            );
            assert_eq!(reference_path.completion(), &ResolutionCompletion::Complete);
            assert!(
                artifact
                    .lexical()
                    .paths()
                    .iter()
                    .all(|(id, _)| *id != reference_path_id(mounted_fragment, reference, namespace)),
                "a direct root reference must not retain a lexical decoy route"
            );
            assert_eq!(
                artifact
                    .lexical()
                    .semantics()
                    .iter()
                    .find(|semantic| semantic.site() == reference)
                    .and_then(|semantic| semantic.site_metadata())
                    .map(|metadata| metadata.unqualified()),
                Some(false)
            );

            let catalog = artifact.identities();
            assert_eq!(
                catalog
                    .semantic_identity(import_token)
                    .expect("root-import token identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal
            );
            assert_eq!(
                catalog
                    .semantic_identity(export_token)
                    .expect("root-export token identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal
            );
            assert_eq!(
                catalog
                    .semantic_identity(reference_token)
                    .expect("root-reference token identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal
            );
            assert_eq!(
                catalog
                    .semantic_identity(import_path.end().symbols().fixed()[0].symbol())
                    .expect("root-import anchor identity")
                    .space(),
                ResolutionSemanticIdentitySpace::FragmentLocal,
            );
            for root_first in [
                import_path.end().symbols().fixed()[1].symbol(),
                export_path.start().symbols().fixed()[0].symbol(),
            ] {
                assert_eq!(
                    catalog
                        .semantic_identity(root_first)
                        .expect("root-leading lookup identity")
                        .space(),
                    ResolutionSemanticIdentitySpace::Shared,
                    "indexed root endpoints must lead with a Shared lookup semantic"
                );
            }
            assert_eq!(
                catalog
                    .paths()
                    .iter()
                    .find_map(|(id, identity)| (*id == import_id).then_some(*identity)),
                Some(root_import_path_identity(
                    import_site,
                    namespace,
                    demand_name
                ))
            );
            assert_eq!(
                catalog
                    .paths()
                    .iter()
                    .find_map(|(id, identity)| (*id == export_id).then_some(*identity)),
                Some(root_export_path_identity(
                    root_scope,
                    declaration,
                    namespace,
                ))
            );
            assert!(artifact.lexical().nodes().iter().all(|(node, kind)| {
                *node != BindingNodeId::universal_root() && *kind != BindingNodeKind::Root
            }));
            (import_token, export_token, import_id, export_id)
        };

        let provisional_rows = inspect(&provisional_artifact, provisional);
        let final_rows = inspect(&final_artifact, final_fragment);
        assert_ne!(provisional_rows, final_rows);
        assert_eq!(
            root_import_token_identity(import_site, namespace),
            provisional_artifact
                .identities()
                .semantic_identity(provisional_rows.0)
                .expect("provisional root-import token identity")
        );
        assert_eq!(
            root_import_token_identity(import_site, namespace),
            final_artifact
                .identities()
                .semantic_identity(final_rows.0)
                .expect("final root-import token identity")
        );

        let provisional_import_token = provisional_rows.0;
        let final_import_path = final_artifact
            .lexical()
            .paths()
            .iter()
            .find_map(|(id, path)| (id == &final_rows.2).then_some(path))
            .expect("final root-import path");
        assert!(
            final_import_path
                .end()
                .symbols()
                .fixed()
                .iter()
                .all(|symbol| symbol.symbol() != provisional_import_token),
            "final lowering must not retain a provisional mounted token"
        );

        let mut permuted = facts.clone();
        permuted.root_import_segments.reverse();
        permuted.root_import_demands.reverse();
        permuted.root_exports.reverse();
        let permuted =
            lower_resolution_facts_with_identity_catalog(final_fragment, Language::Go, &permuted);
        assert_same_artifact(&final_artifact, &permuted);
    }
    #[test]
    fn nested_variable_and_coverage_gap_recipes_rebase_exactly() {
        let fragments = [
            BindingFragmentId::hash_bytes(b"nested-identity-a"),
            BindingFragmentId::hash_bytes(b"nested-identity-b"),
        ];
        let lowered = fragments.map(|fragment| {
            let mut identities = ResolutionIdentityCatalogBuilder::new(fragment);
            let path = identities.path(timeline_path_identity(ResolutionScopeId::new(7), 11));
            let variable = passthrough_variable(&mut identities, path);
            let semantic =
                identities.semantic(reference_semantic_identity(ResolutionSiteId::new(13)));
            let node = identities.node(reference_node_identity(ResolutionSiteId::new(13)));
            let reason = identities.semantic(gap_reason_semantic_identity(
                ResolutionSiteId::new(13),
                LoweringGapOrigin::QualifiedReference,
            ));
            let gap = coverage_gap_id(
                &mut identities,
                reason,
                LoweringCoverageFrontier::Reference { semantic, node },
            );
            (variable, gap, identities.finish())
        });

        let variable_identities = lowered.each_ref().map(|(variable, _, catalog)| {
            catalog
                .stack_variables()
                .iter()
                .find_map(|(id, identity)| (id == variable).then_some(*identity))
                .expect("registered passthrough variable")
        });
        let gap_identities = lowered.each_ref().map(|(_, gap, catalog)| {
            catalog
                .semantic_identity(*gap)
                .expect("registered coverage gap")
        });
        assert_eq!(variable_identities[0], variable_identities[1]);
        assert_eq!(gap_identities[0], gap_identities[1]);
        assert_eq!(variable_identities[0].mount(fragments[1]), lowered[1].0);
        assert_eq!(gap_identities[0].mount(fragments[1]), lowered[1].1);
        assert_ne!(lowered[0].0, lowered[1].0);
        assert_ne!(lowered[0].1, lowered[1].1);
    }
}
