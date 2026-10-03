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

pub(crate) mod package;

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
    ResolutionBinderFact, ResolutionBinderKind, ResolutionCallableReceiverOrigin,
    ResolutionEngineRuleKind, ResolutionGapKind, ResolutionIdentifierRole,
    ResolutionImportRouteKind, ResolutionMemberKind, ResolutionNameId, ResolutionNamespace,
    ResolutionRootExportFact, ResolutionRootImportAnchor, ResolutionRootImportDemandFact,
    ResolutionRootImportDemandTarget, ResolutionRootImportFact, ResolutionRootImportKind,
    ResolutionRootImportSegmentFact, ResolutionRootReferenceFact,
    ResolutionRootReferenceSegmentFact, ResolutionScopeFact, ResolutionScopeId,
    ResolutionScopeInheritance, ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId,
    ResolutionSiteKind, ResolutionTypeSlotId,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    BoundaryStatus, HoistingClass, ResolutionCompletionReasonKind, ResolutionGapOriginKind,
};

use crate::analyzer::structural::PrecedenceTier;
use crate::hash::{HashMap, HashSet};

use super::batch::FactReferenceSiteMetadata;
use super::engine::PreloadedFragment;
use super::local_identity::{
    ResolutionIdentityCatalogBuilder, ResolutionLookupSemanticRecipe, ResolutionNodeIdentity,
    ResolutionPathIdentity, ResolutionSemanticIdentity, ResolutionStackVariableIdentity,
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

/// The direction whose candidate inventory is known to be incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweredCandidateDirection {
    Forward,
    Reverse,
}

/// One normalized read frontier contaminated by a lowering gap.
///
/// Fragment and enumeration rows affect broad negative answers. Reference,
/// candidate, and type rows stay local to the semantic dependency that the
/// producer could not model; a point query for an unrelated reference remains
/// exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweringCoverageFrontier {
    Fragment,
    Enumeration,
    /// The producer may have omitted an endpoint in this direction entirely,
    /// so no endpoint-keyed candidate row can carry the gap. This remains
    /// separate from `Fragment`: reverse inventory can be incomplete without
    /// poisoning an unrelated point lookup whose reference node is present.
    CandidateInventory {
        direction: LoweredCandidateDirection,
    },
    Reference {
        semantic: SemanticId,
        node: BindingNodeId,
    },
    Candidate {
        direction: LoweredCandidateDirection,
        endpoint: BindingNodeId,
        /// Exact first lookup symbol whose inventory is incomplete. `None`
        /// applies to every symbol state at the endpoint. A source must apply
        /// keyed gaps conservatively to an open variable-only symbol stack,
        /// because its eventual first symbol is not known yet.
        lookup: Option<SemanticId>,
    },
    /// One actual type slot or stable site-property frontier. Site-property
    /// frontiers let a later projection evaluator attach conditional evidence
    /// (for example an implicit constructor) to the resolved declaration that
    /// owns it without poisoning unrelated type work.
    Type {
        frontier: SemanticId,
    },
}

/// Why the fact-to-fragment bridge withheld an exact claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoweringGapOrigin {
    Extracted(ResolutionGapKind),
    QualifiedReference,
    UnsupportedActivation(HoistingClass),
    MissingBinder,
    /// One root route head names a crate that the build reaches through an
    /// implicit language prelude whose source Bifrost never indexes. Unlike
    /// every other origin this is not a producer shortfall: the boundary is a
    /// property of the workspace, and the persisted row states it as an open
    /// boundary with a declared-but-unindexed status.
    ExternalPreludeBoundary,
}

impl LoweringGapOrigin {
    pub const fn kind(self) -> ResolutionGapOriginKind {
        match self {
            Self::Extracted(kind) => match kind {
                ResolutionGapKind::UnsupportedTypeSyntax => {
                    ResolutionGapOriginKind::UnsupportedTypeSyntax
                }
                ResolutionGapKind::UnsupportedExpression => {
                    ResolutionGapOriginKind::UnsupportedExpression
                }
                ResolutionGapKind::UnsupportedRoute => ResolutionGapOriginKind::UnsupportedRoute,
                ResolutionGapKind::UnprovenActivation => {
                    ResolutionGapOriginKind::UnprovenActivation
                }
                ResolutionGapKind::UnsupportedScopeOrBinder => {
                    ResolutionGapOriginKind::UnsupportedScopeOrBinder
                }
                ResolutionGapKind::AmbiguousQualifiedType => {
                    ResolutionGapOriginKind::AmbiguousQualifiedType
                }
                ResolutionGapKind::InferredType => ResolutionGapOriginKind::InferredType,
                ResolutionGapKind::PostfixArrayDimensions => {
                    ResolutionGapOriginKind::PostfixArrayDimensions
                }
                ResolutionGapKind::AmbiguousNumericLiteral => {
                    ResolutionGapOriginKind::AmbiguousNumericLiteral
                }
                ResolutionGapKind::ImplicitConstructor => {
                    ResolutionGapOriginKind::ImplicitConstructor
                }
                ResolutionGapKind::UnsupportedHierarchyTraversal => {
                    ResolutionGapOriginKind::UnsupportedHierarchyTraversal
                }
                ResolutionGapKind::UnsupportedVisibility => {
                    ResolutionGapOriginKind::UnsupportedVisibility
                }
                ResolutionGapKind::UnsupportedImplicitReceiver => {
                    ResolutionGapOriginKind::UnsupportedImplicitReceiver
                }
                ResolutionGapKind::UnsupportedCallApplicability => {
                    ResolutionGapOriginKind::UnsupportedCallApplicability
                }
                ResolutionGapKind::UnsupportedPlacementBoundary => {
                    ResolutionGapOriginKind::UnsupportedPlacementBoundary
                }
                ResolutionGapKind::MalformedSyntax => ResolutionGapOriginKind::MalformedSyntax,
                ResolutionGapKind::UnsupportedMemberScope => {
                    ResolutionGapOriginKind::UnsupportedMemberScope
                }
                ResolutionGapKind::GeneratedItemSurface => {
                    ResolutionGapOriginKind::GeneratedItemSurface
                }
                ResolutionGapKind::MacroArgument => ResolutionGapOriginKind::MacroArgument,
                ResolutionGapKind::UnexpandedItemMacro => {
                    ResolutionGapOriginKind::UnexpandedItemMacro
                }
                ResolutionGapKind::UnexpandedImplMacro => {
                    ResolutionGapOriginKind::UnexpandedImplMacro
                }
            },
            Self::QualifiedReference => ResolutionGapOriginKind::QualifiedReference,
            Self::UnsupportedActivation(HoistingClass::SourceOrder) => {
                ResolutionGapOriginKind::UnsupportedActivationSourceOrder
            }
            Self::UnsupportedActivation(HoistingClass::ScopeWide) => {
                ResolutionGapOriginKind::UnsupportedActivationScopeWide
            }
            Self::UnsupportedActivation(HoistingClass::DeclaredHead) => {
                ResolutionGapOriginKind::UnsupportedActivationDeclaredHead
            }
            Self::MissingBinder => ResolutionGapOriginKind::MissingBinder,
            Self::ExternalPreludeBoundary => ResolutionGapOriginKind::ExternalPreludeBoundary,
        }
    }

    pub const fn from_kind(kind: ResolutionGapOriginKind) -> Self {
        match kind {
            ResolutionGapOriginKind::UnsupportedTypeSyntax => {
                Self::Extracted(ResolutionGapKind::UnsupportedTypeSyntax)
            }
            ResolutionGapOriginKind::UnsupportedExpression => {
                Self::Extracted(ResolutionGapKind::UnsupportedExpression)
            }
            ResolutionGapOriginKind::UnprovenActivation => {
                Self::Extracted(ResolutionGapKind::UnprovenActivation)
            }
            ResolutionGapOriginKind::UnsupportedRoute => {
                Self::Extracted(ResolutionGapKind::UnsupportedRoute)
            }
            ResolutionGapOriginKind::UnsupportedScopeOrBinder => {
                Self::Extracted(ResolutionGapKind::UnsupportedScopeOrBinder)
            }
            ResolutionGapOriginKind::AmbiguousQualifiedType => {
                Self::Extracted(ResolutionGapKind::AmbiguousQualifiedType)
            }
            ResolutionGapOriginKind::InferredType => {
                Self::Extracted(ResolutionGapKind::InferredType)
            }
            ResolutionGapOriginKind::PostfixArrayDimensions => {
                Self::Extracted(ResolutionGapKind::PostfixArrayDimensions)
            }
            ResolutionGapOriginKind::AmbiguousNumericLiteral => {
                Self::Extracted(ResolutionGapKind::AmbiguousNumericLiteral)
            }
            ResolutionGapOriginKind::ImplicitConstructor => {
                Self::Extracted(ResolutionGapKind::ImplicitConstructor)
            }
            ResolutionGapOriginKind::UnsupportedHierarchyTraversal => {
                Self::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal)
            }
            ResolutionGapOriginKind::UnsupportedVisibility => {
                Self::Extracted(ResolutionGapKind::UnsupportedVisibility)
            }
            ResolutionGapOriginKind::UnsupportedImplicitReceiver => {
                Self::Extracted(ResolutionGapKind::UnsupportedImplicitReceiver)
            }
            ResolutionGapOriginKind::UnsupportedCallApplicability => {
                Self::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
            }
            ResolutionGapOriginKind::UnsupportedPlacementBoundary => {
                Self::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
            }
            ResolutionGapOriginKind::MalformedSyntax => {
                Self::Extracted(ResolutionGapKind::MalformedSyntax)
            }
            ResolutionGapOriginKind::UnsupportedMemberScope => {
                Self::Extracted(ResolutionGapKind::UnsupportedMemberScope)
            }
            ResolutionGapOriginKind::GeneratedItemSurface => {
                Self::Extracted(ResolutionGapKind::GeneratedItemSurface)
            }
            ResolutionGapOriginKind::UnexpandedItemMacro => {
                Self::Extracted(ResolutionGapKind::UnexpandedItemMacro)
            }
            ResolutionGapOriginKind::UnexpandedImplMacro => {
                Self::Extracted(ResolutionGapKind::UnexpandedImplMacro)
            }
            ResolutionGapOriginKind::MacroArgument => {
                Self::Extracted(ResolutionGapKind::MacroArgument)
            }
            ResolutionGapOriginKind::QualifiedReference => Self::QualifiedReference,
            ResolutionGapOriginKind::UnsupportedActivationSourceOrder => {
                Self::UnsupportedActivation(HoistingClass::SourceOrder)
            }
            ResolutionGapOriginKind::UnsupportedActivationScopeWide => {
                Self::UnsupportedActivation(HoistingClass::ScopeWide)
            }
            ResolutionGapOriginKind::UnsupportedActivationDeclaredHead => {
                Self::UnsupportedActivation(HoistingClass::DeclaredHead)
            }
            ResolutionGapOriginKind::MissingBinder => Self::MissingBinder,
            ResolutionGapOriginKind::ExternalPreludeBoundary => Self::ExternalPreludeBoundary,
        }
    }

    /// The persisted completion reason and boundary status this origin states.
    ///
    /// Every producer shortfall persists as an unsupported semantic. An
    /// external prelude boundary is the one origin that states a boundary the
    /// build declares but no mounted source indexes.
    pub const fn completion_reason(
        self,
    ) -> (ResolutionCompletionReasonKind, Option<BoundaryStatus>) {
        match self {
            Self::ExternalPreludeBoundary => (
                ResolutionCompletionReasonKind::OpenBoundary,
                Some(BoundaryStatus::ExternalDeclaredUnindexed),
            ),
            Self::Extracted(_)
            | Self::QualifiedReference
            | Self::UnsupportedActivation(_)
            | Self::MissingBinder => (ResolutionCompletionReasonKind::UnsupportedSemantic, None),
        }
    }
}

/// One stable normalized gap row.
///
/// A gap is not a catalog semantic. `digest` is its content identity inside
/// one lowering: it decides deduplication and gives the fragment's gaps one
/// context-independent order. A gap's runtime identity is its position in that
/// order (`LoweredResolutionFragment::gap_id`), a key space of its own that
/// shares no positions with the semantic catalog (#3737: one catalog row per
/// gap was 36,014 of 83,742 rows for one Go file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoweredCoverageGap {
    digest: [u8; 32],
    reason_semantic: SemanticId,
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
    frontier: LoweringCoverageFrontier,
}

impl LoweredCoverageGap {
    pub(super) const fn new(
        digest: [u8; 32],
        reason_semantic: SemanticId,
        site: ResolutionSiteId,
        origin: LoweringGapOrigin,
        frontier: LoweringCoverageFrontier,
    ) -> Self {
        Self {
            digest,
            reason_semantic,
            site,
            origin,
            frontier,
        }
    }

    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub const fn reason_semantic(&self) -> SemanticId {
        self.reason_semantic
    }

    pub const fn site(&self) -> ResolutionSiteId {
        self.site
    }

    pub const fn origin(&self) -> LoweringGapOrigin {
        self.origin
    }

    pub const fn frontier(&self) -> LoweringCoverageFrontier {
        self.frontier
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
    go_definition_namespaces: Option<super::model::GoDefinitionNamespaces>,
}

impl LoweredSemanticSite {
    pub(super) const fn new(
        site: ResolutionSiteId,
        namespace: ResolutionNamespace,
        role: LoweredSemanticRole,
        semantic: SemanticId,
        node: BindingNodeId,
        site_metadata: Option<FactReferenceSiteMetadata>,
    ) -> Self {
        Self {
            site,
            namespace,
            role,
            semantic,
            node,
            site_metadata,
            go_definition_namespaces: None,
        }
    }

    pub const fn go_definition_namespaces(&self) -> Option<super::model::GoDefinitionNamespaces> {
        self.go_definition_namespaces
    }

    pub(super) const fn with_go_definition_namespaces(
        mut self,
        namespaces: Option<super::model::GoDefinitionNamespaces>,
    ) -> Self {
        assert!(namespaces.is_none() || matches!(self.role, LoweredSemanticRole::Definition));
        self.go_definition_namespaces = namespaces;
        self
    }

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

    /// The site metadata a reference publishes to readers. A synthetic
    /// reference is the producer's own device, not a reference a user wrote,
    /// so it publishes no kind or range and no point or usage row stands for
    /// it. Persisted rows and the preloaded source both read through this.
    pub(crate) fn published_site_metadata(&self) -> Option<FactReferenceSiteMetadata> {
        self.site_metadata
            .filter(|metadata| metadata.site_kind() != ResolutionSiteKind::SyntheticReference)
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
    #[cfg(any(test, feature = "test-support"))]
    hierarchy_terminals: Vec<(SemanticId, BindingNodeId)>,
}

impl LoweredResolutionFragment {
    pub(crate) fn selected_include_glob(
        fragment: BindingFragmentId,
        names: &dyn super::local_identity::SharedNameInterner,
        import: &brokk_bifrost_core::analyzer::rust_facts::RustImportTargetFact,
        demand: &ResolutionLookupSemanticRecipe,
    ) -> (Self, super::local_identity::ResolutionIdentityCatalog) {
        assert!(import.is_glob);
        let scope = import
            .native_scope
            .expect("selected glob has native scope authority");
        let import_id = import
            .source_import_id
            .expect("selected glob has canonical import identity");
        let namespace = demand.namespace();
        let mut identities = ResolutionIdentityCatalogBuilder::new(fragment, names);
        let mut hash = CanonicalHasher::new(b"bifrost-selected-include-glob-token:v1");
        hash.field("import", &import_id.get().to_le_bytes());
        hash.field("namespace", namespace.identity_label().as_bytes());
        let token_digest = hash.finish();
        let token = identities.semantic(ResolutionSemanticIdentity::fragment_local(token_digest));
        let mut hash = CanonicalHasher::new(b"bifrost-selected-include-glob-path:v1");
        hash.field("import", &token_digest);
        hash.field("name", demand.spelling().as_bytes());
        let path = identities.path(ResolutionPathIdentity::new(hash.finish()));
        let tail = passthrough_variable(&mut identities, path);
        let lookup = identities.lookup_semantic(Language::Rust, namespace, demand.spelling());
        let anchor = if import.leading_absolute {
            ResolutionRootImportAnchor::Absolute
        } else {
            ResolutionRootImportAnchor::Lexical
        };
        let mut symbols = vec![identities.semantic(root_import_anchor_semantic_identity(anchor))];
        symbols.extend(
            import
                .module_path
                .iter()
                .map(|name| identities.lookup_semantic(Language::Rust, namespace, name)),
        );
        symbols.extend([token, lookup]);
        let choice = identities.semantic(scope_choice_identity(scope, namespace));
        let scope = identities.source_scope_node(scope);
        let row = PartialPath::new(
            symbol_open_endpoint(scope, [lookup], tail),
            symbol_open_endpoint(BindingNodeId::universal_root(), symbols, tail),
            [identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::WildcardImport,
                    ordinal: 0,
                    semantic: choice,
                },
                namespace,
            )],
            [WitnessStep::Node(BindingNodeId::universal_root())],
            ResolutionCompletion::Complete,
        );
        (
            Self::new(
                fragment,
                Language::Rust,
                vec![(scope, BindingNodeKind::Scope)],
                vec![(path, row)],
                Vec::new(),
                Vec::new(),
            ),
            identities.finish(),
        )
    }

    pub(crate) fn selected_include_binding(
        fragment: BindingFragmentId,
        scope: BindingNodeId,
        boundary: BindingNodeId,
        path: PartialPathId,
        original: &PartialPath,
    ) -> Self {
        let start = original.start();
        Self::new(
            fragment,
            Language::Rust,
            vec![(scope, BindingNodeKind::Scope)],
            vec![(
                path,
                PartialPath::new(
                    EndpointSignature::new_scoped(
                        scope,
                        start.symbols().clone(),
                        start.scopes().clone(),
                    ),
                    EndpointSignature::new_scoped(
                        boundary,
                        start.symbols().clone(),
                        start.scopes().clone(),
                    ),
                    Vec::new(),
                    Vec::new(),
                    ResolutionCompletion::Complete,
                ),
            )],
            Vec::new(),
            Vec::new(),
        )
    }

    pub(crate) fn selected_include_continuation(
        fragment: BindingFragmentId,
        boundary: BindingNodeId,
        path: PartialPathId,
        end_kind: BindingNodeKind,
        original: &PartialPath,
    ) -> Self {
        let start = original.start();
        let nodes = if original.end().node() == BindingNodeId::universal_root() {
            Vec::new()
        } else {
            vec![(original.end().node(), end_kind)]
        };
        Self::new(
            fragment,
            Language::Rust,
            nodes,
            vec![(
                path,
                PartialPath::new(
                    EndpointSignature::new_scoped(
                        boundary,
                        start.symbols().clone(),
                        start.scopes().clone(),
                    ),
                    original.end().clone(),
                    original.precedence().to_vec(),
                    std::iter::once(WitnessStep::Node(boundary))
                        .chain(original.witness().iter().copied())
                        .collect::<Vec<_>>(),
                    original.completion().clone(),
                ),
            )],
            Vec::new(),
            Vec::new(),
        )
    }

    pub(crate) fn selected_macro_head_bridge(
        fragment: BindingFragmentId,
        reference: SemanticId,
        node: BindingNodeId,
        definition: BindingNodeId,
        path: PartialPathId,
    ) -> Self {
        Self::new(
            fragment,
            Language::Rust,
            vec![(node, BindingNodeKind::Reference(reference))],
            vec![(
                path,
                PartialPath::new(
                    closed_endpoint(node, Vec::new()),
                    closed_endpoint(definition, Vec::new()),
                    Vec::new(),
                    vec![WitnessStep::Node(definition)],
                    ResolutionCompletion::Complete,
                ),
            )],
            Vec::new(),
            Vec::new(),
        )
    }

    pub(crate) fn selected_macro_head_definition(
        fragment: BindingFragmentId,
        definition: SemanticId,
        node: BindingNodeId,
        boundary: BindingNodeId,
        path: PartialPathId,
    ) -> Self {
        Self::new(
            fragment,
            Language::Rust,
            vec![(node, BindingNodeKind::Definition(definition))],
            vec![(
                path,
                PartialPath::new(
                    closed_endpoint(boundary, Vec::new()),
                    closed_endpoint(node, Vec::new()),
                    Vec::new(),
                    vec![WitnessStep::Node(node)],
                    ResolutionCompletion::Complete,
                ),
            )],
            Vec::new(),
            Vec::new(),
        )
    }

    pub(super) fn attach_macro_module_witnesses(
        &mut self,
        anchors: &dyn super::selected_context::SelectedRootImportAnchors,
        module: BindingNodeId,
    ) -> Option<()> {
        // The capture's lexical root is the invocation checkpoint. A root route
        // separately witnesses the enclosing module that owns crate/self paths.
        if self.nodes.iter().all(|(node, _)| *node != module) {
            self.nodes.push((module, BindingNodeKind::Scope));
        }
        let uncancelled = crate::CancellationToken::default();
        for (id, path) in &mut self.paths {
            let half = super::selected_context::classify_selected_root_path_half(
                anchors,
                super::batch::CandidatePathIdentity::new(self.fragment, *id),
                path,
                &uncancelled,
            )
            .ok()?;
            if !matches!(
                half,
                Some(super::selected_context::SelectedRootPathHalf::Reference { .. })
            ) {
                continue;
            }
            let mut witness = path.witness().to_vec();
            let module_index = witness.len() - 2;
            witness[module_index] = WitnessStep::Node(module);
            *path = PartialPath::new(
                path.start().clone(),
                path.end().clone(),
                path.precedence().to_vec(),
                witness,
                path.completion().clone(),
            );
        }
        let known = self
            .nodes
            .iter()
            .map(|(node, _)| *node)
            .collect::<HashSet<_>>();
        for (id, path) in &self.paths {
            for endpoint in [path.start().node(), path.end().node()] {
                assert!(
                    endpoint == BindingNodeId::universal_root() || known.contains(&endpoint),
                    "macro path {id} has unknown local endpoint {endpoint}; module={module}"
                );
            }
            for step in path.witness() {
                if let WitnessStep::Node(node) = step {
                    assert!(
                        *node == BindingNodeId::universal_root() || known.contains(node),
                        "macro path {id} has unknown witness node {node}; module={module}"
                    );
                }
            }
        }
        Some(())
    }

    pub(crate) fn append_selected_macro_fragment(&mut self, added: Self) {
        assert_eq!(
            (self.fragment, self.language),
            (added.fragment, added.language)
        );
        self.nodes.extend(added.nodes);
        self.nodes.sort_unstable();
        self.nodes.dedup();
        assert!(
            self.nodes.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "selected macro graft has conflicting node kinds"
        );
        self.paths.extend(added.paths);
        self.paths.sort_unstable_by_key(|(id, _)| *id);
        assert!(
            self.paths.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "selected macro paths must have distinct identities"
        );
        self.semantics.extend(added.semantics);
        self.semantics.sort_unstable();
        self.gaps.extend(added.gaps);
        self.gaps.sort_unstable();
        self.gaps.dedup();
    }

    pub(super) fn new(
        fragment: BindingFragmentId,
        language: Language,
        mut nodes: Vec<(BindingNodeId, BindingNodeKind)>,
        mut paths: Vec<(PartialPathId, PartialPath)>,
        mut semantics: Vec<LoweredSemanticSite>,
        mut gaps: Vec<LoweredCoverageGap>,
    ) -> Self {
        assert_ne!(
            language,
            Language::None,
            "resolution fragment needs a language"
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
        Self {
            fragment,
            language,
            nodes,
            paths,
            semantics,
            gaps,
            #[cfg(any(test, feature = "test-support"))]
            hierarchy_terminals: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        fragment: BindingFragmentId,
        language: Language,
        nodes: Vec<(BindingNodeId, BindingNodeKind)>,
        paths: Vec<(PartialPathId, PartialPath)>,
    ) -> Self {
        Self {
            fragment,
            language,
            nodes,
            paths,
            semantics: Vec::new(),
            gaps: Vec::new(),
            #[cfg(any(test, feature = "test-support"))]
            hierarchy_terminals: Vec::new(),
        }
    }

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

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn hierarchy_terminals(&self) -> &[(SemanticId, BindingNodeId)] {
        &self.hierarchy_terminals
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn with_hierarchy_terminals(
        mut self,
        mut terminals: Vec<(SemanticId, BindingNodeId)>,
    ) -> Self {
        assert!(self.hierarchy_terminals.is_empty());
        terminals.sort_unstable();
        assert!(terminals.windows(2).all(|pair| pair[0].0 != pair[1].0));
        self.hierarchy_terminals = terminals;
        self
    }

    /// The fragment's gaps in their one canonical order: by content digest.
    pub fn gaps(&self) -> &[LoweredCoverageGap] {
        &self.gaps
    }

    /// The runtime identity of the gap at `ordinal` in [`Self::gaps`].
    ///
    /// Gaps have a key space of their own: the position in the digest-ordered
    /// gap list, which is what a persisted `resolution_gaps.gap` holds for the
    /// same content. It shares no positions with the semantic catalog.
    pub fn gap_id(&self, ordinal: usize) -> SemanticId {
        assert!(
            ordinal < self.gaps.len(),
            "gap ordinal {ordinal} is outside the fragment's {} gaps",
            self.gaps.len()
        );
        SemanticId::local(
            self.fragment.ordinal(),
            u32::try_from(ordinal).expect("a blob's gap ordinal fits u32"),
        )
    }

    /// Consume the operation-local artifact without losing coverage metadata.
    ///
    /// The tuple intentionally makes gaps a mandatory return value. The
    /// current preload source accepts only affirmative rows; a caller cannot
    /// obtain a `PreloadedFragment` through this API without also receiving
    /// the rows it must apply to fragment, enumeration, candidate, and type
    /// completion.
    pub fn into_preloaded_parts(
        self,
    ) -> (PreloadedFragment, Box<[(SemanticId, LoweredCoverageGap)]>) {
        let gaps = self
            .gaps
            .iter()
            .enumerate()
            .map(|(ordinal, gap)| (self.gap_id(ordinal), *gap))
            .collect();
        let Self {
            fragment,
            nodes,
            paths,
            semantics,
            ..
        } = self;
        let mut reference_metadata = Vec::new();
        let mut go_definitions = Vec::new();
        for semantic in semantics {
            if let Some(namespaces) = semantic.go_definition_namespaces {
                go_definitions.push((semantic.semantic, namespaces));
            }
            if semantic.role != LoweredSemanticRole::Reference {
                continue;
            }
            assert!(
                semantic.site_metadata.is_some(),
                "every lowered reference has source-site metadata"
            );
            if let Some(metadata) = semantic.published_site_metadata() {
                reference_metadata.push((semantic.semantic, metadata));
            }
        }
        (
            PreloadedFragment::new(fragment, nodes, paths)
                .with_reference_metadata(reference_metadata)
                .with_go_definition_namespaces(go_definitions),
            gaps,
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
    /// The producer published this binder as the weaker half of a conditional
    /// binder row, so every enclosing lexical route outranks it.
    superseded: bool,
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
    language: Language,
    index: &FactIndex<'_>,
    activation_positions: &HashMap<ResolutionScopeId, Vec<usize>>,
) -> LoweredScopeTimelines {
    let mut timelines = HashMap::default();
    let mut nodes = Vec::new();
    for scope in index.scopes_sorted() {
        let head = identities.source_scope_node(scope.id);
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
                    if language == Language::Go {
                        go_spelling_precedence(
                            identities,
                            timeline.fact.id,
                            Some(checkpoint.position),
                            1,
                        )
                    } else {
                        checkpoint_fallback_precedence(
                            identities,
                            timeline.fact.id,
                            checkpoint.position,
                        )
                    },
                    [WitnessStep::Node(previous)],
                    ResolutionCompletion::Complete,
                ),
            ));
            previous = checkpoint.node;
        }

        // A scope the producer marked as a lookup root keeps its parent link,
        // which placement and containment still read, but contributes no
        // outward lexical path: a name this scope does not declare is not
        // found by continuing into the parent's timeline. The producer is the
        // only authority on which of its scopes are roots
        // (`ResolutionScopeInheritance`), and the lowering reads the flag
        // without asking which language wrote it.
        if let Some(parent) = timeline
            .fact
            .parent
            .filter(|_| timeline.fact.inheritance == ResolutionScopeInheritance::Lexical)
        {
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
                    if language == Language::Go {
                        go_spelling_precedence(identities, timeline.fact.id, None, 1)
                    } else if timeline.fact.kind == ResolutionScopeKind::TypeBody {
                        type_body_enclosing_precedence(identities, timeline.fact.id)
                    } else if language == Language::Rust {
                        rust_scope_outward_precedence(identities, timeline.fact.id)
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

/// How a fixture names an identity.
///
/// A fixture writes what it means -- `type_slot_semantic(fragment, slot)` --
/// and the answer is the position that identity occupies in the catalog that
/// numbered it. The production helpers of the same names take the builder,
/// because the lowering has one in hand; a fixture does not, and threading one
/// through every fixture would say nothing a fixture does not already know: it
/// just lowered this fragment.
///
/// So [`lower_for_test`] records the catalog it produced, under the mount it
/// produced it at, and these read it back. A fixture that lowers the same
/// fragment twice keeps the later catalog, which is the one it is about to ask
/// about. Nothing here exists outside a test binary.
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod fixture_names {
    use super::super::local_identity::ResolutionIdentityCatalog;
    use super::*;
    use crate::hash::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn catalogs() -> &'static Mutex<HashMap<u32, std::sync::Arc<ResolutionIdentityCatalog>>> {
        static CATALOGS: OnceLock<Mutex<HashMap<u32, std::sync::Arc<ResolutionIdentityCatalog>>>> =
            OnceLock::new();
        CATALOGS.get_or_init(|| Mutex::new(HashMap::default()))
    }

    pub(crate) fn record(catalog: &ResolutionIdentityCatalog) {
        catalogs()
            .lock()
            .expect("the fixture catalog table is not poisoned")
            .insert(
                catalog.fragment().ordinal(),
                std::sync::Arc::new(catalog.clone()),
            );
    }

    fn catalog(fragment: BindingFragmentId) -> std::sync::Arc<ResolutionIdentityCatalog> {
        catalogs()
            .lock()
            .expect("the fixture catalog table is not poisoned")
            .get(&fragment.ordinal())
            .cloned()
            .unwrap_or_else(|| {
                panic!("no fixture lowered {fragment}, so nothing numbered its identities")
            })
    }

    fn semantic_of(
        fragment: BindingFragmentId,
        identity: ResolutionSemanticIdentity,
    ) -> SemanticId {
        catalog_semantic(&catalog(fragment), identity)
    }

    fn node_of(fragment: BindingFragmentId, identity: ResolutionNodeIdentity) -> BindingNodeId {
        catalog_node(&catalog(fragment), identity)
    }

    fn path_of(fragment: BindingFragmentId, identity: ResolutionPathIdentity) -> PartialPathId {
        catalog(fragment)
            .path_for_identity(identity)
            .unwrap_or_else(|| panic!("the fixture's catalog has no position for {identity:?}"))
    }

    /// The anchors of everything a fixture lowered.
    ///
    /// A fixture that hands a preloaded source to the root-half reader needs
    /// the same question answered that a selection answers from the mount's
    /// catalog. Every artifact the fixture built came through
    /// [`super::lower_for_test`], so every catalog it needs is in the table
    /// above, indexed by the mount the identity names itself.
    pub(crate) struct FixtureRootImportAnchors;

    impl super::super::selected_context::SelectedRootImportAnchors for FixtureRootImportAnchors {
        fn anchor_of(
            &self,
            semantic: SemanticId,
            _cancellation: &crate::CancellationToken,
        ) -> crate::analyzer::store::Result<
            Option<brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor>,
        > {
            use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;
            let Some(ordinal) = semantic.ordinal() else {
                return Ok(None);
            };
            let Some(catalog) = catalogs()
                .lock()
                .expect("the fixture catalog table is not poisoned")
                .get(&ordinal)
                .cloned()
            else {
                return Ok(None);
            };
            let Some(identity) = catalog.semantic_identity(semantic) else {
                return Ok(None);
            };
            Ok([
                ResolutionRootImportAnchor::Lexical,
                ResolutionRootImportAnchor::Absolute,
            ]
            .into_iter()
            .find(|anchor| root_import_anchor_semantic_identity(*anchor) == identity))
        }
    }

    /// A site's semantic and node are its own number in both catalogs, so
    /// these need nothing recorded.
    pub(crate) fn definition_semantic(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
    ) -> SemanticId {
        mounted_site_semantic(fragment, site)
    }

    pub(crate) fn reference_semantic(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
    ) -> SemanticId {
        mounted_site_semantic(fragment, site)
    }

    pub(crate) fn definition_node(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
    ) -> BindingNodeId {
        mounted_site_node(fragment, site)
    }

    pub(crate) fn reference_node(
        fragment: BindingFragmentId,
        site: ResolutionSiteId,
    ) -> BindingNodeId {
        mounted_site_node(fragment, site)
    }

    macro_rules! fixture_name {
        ($name:ident, $identity:path, $of:ident, $result:ty $(, $argument:ident : $type:ty)*) => {
            pub(crate) fn $name(
                fragment: BindingFragmentId
                $(, $argument: $type)*
            ) -> $result {
                $of(fragment, $identity($($argument),*))
            }
        };
    }

    fixture_name!(scope_head_node, scope_head_node_identity, node_of, BindingNodeId,
        scope: ResolutionScopeId);
    fixture_name!(checkpoint_node, super::checkpoint_node_identity, node_of, BindingNodeId,
        scope: ResolutionScopeId, position: usize);
    fixture_name!(gap_sink_node, super::gap_sink_node_identity, node_of, BindingNodeId,
        site: ResolutionSiteId, role: &[u8]);
    fixture_name!(structured_import_gap_sink_node, super::structured_import_gap_sink_node_identity,
        node_of, BindingNodeId, site: ResolutionSiteId, namespace: ResolutionNamespace);

    fixture_name!(type_slot_semantic, super::type_slot_semantic_identity, semantic_of, SemanticId,
        slot: brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId);
    fixture_name!(site_type_frontier_semantic, super::site_type_frontier_semantic_identity,
        semantic_of, SemanticId, site: ResolutionSiteId);
    fixture_name!(gap_reason_semantic, super::gap_reason_semantic_identity, semantic_of, SemanticId,
        site: ResolutionSiteId, origin: LoweringGapOrigin);
    fixture_name!(root_export_token, root_export_token_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, namespace: ResolutionNamespace);
    fixture_name!(root_import_token, root_import_token_identity, semantic_of, SemanticId,
        site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(root_reference_token, root_reference_token_identity, semantic_of, SemanticId,
        site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(root_import_anchor_semantic, root_import_anchor_semantic_identity, semantic_of,
        SemanticId,
        anchor: brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor);
    fixture_name!(scope_choice, super::scope_choice_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, namespace: ResolutionNamespace);
    fixture_name!(hierarchy_choice, super::hierarchy_choice_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, namespace: ResolutionNamespace);
    fixture_name!(checkpoint_choice, super::checkpoint_choice_identity, semantic_of, SemanticId,
        scope: ResolutionScopeId, position: usize, namespace: ResolutionNamespace);

    fixture_name!(binder_path_id, super::binder_path_identity, path_of, PartialPathId,
        site: ResolutionSiteId);
    fixture_name!(hierarchy_gap_path_id, super::hierarchy_gap_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, owner: ResolutionSiteId);
    fixture_name!(additional_binder_path_id, super::additional_binder_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(placement_gap_path_id, super::placement_gap_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, scope: ResolutionScopeId);
    fixture_name!(root_export_path_id, super::root_export_path_identity, path_of, PartialPathId,
        scope: ResolutionScopeId, declaration: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(root_import_path_id, super::root_import_path_identity, path_of, PartialPathId,
        site: ResolutionSiteId, namespace: ResolutionNamespace,
        name: brokk_bifrost_core::analyzer::resolution_facts::ResolutionNameId);
    fixture_name!(root_reference_path_id, super::root_reference_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId, namespace: ResolutionNamespace);
    fixture_name!(parent_path_id, super::parent_path_identity, path_of, PartialPathId,
        scope: ResolutionScopeId);
    fixture_name!(missing_binder_path_id, super::missing_binder_path_identity, path_of,
        PartialPathId, site: ResolutionSiteId);
    fixture_name!(reference_path_id, super::reference_path_identity, path_of, PartialPathId,
        site: ResolutionSiteId, namespace: ResolutionNamespace);
}

/// One fixture's lexical half and the catalog that numbered it.
///
/// A fixture that supplies only lexical facts cannot go through the whole
/// lowering: the typed lowering validates its own inventories and a
/// lexical-only fixture has none. This is still one builder and one catalog,
/// which is the property that matters; what it is not is two lowerings of one
/// file, which is what `lower_file_resolution_facts` made easy and what gave
/// two catalogs that agree only on the sites.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn lower_lexical_for_test(
    fragment: BindingFragmentId,
    language: Language,
    facts: &FileResolutionFacts,
) -> (
    LoweredResolutionFragment,
    super::local_identity::ResolutionIdentityCatalog,
) {
    let mut identities =
        ResolutionIdentityCatalogBuilder::new(fragment, super::local_identity::test_shared_names());
    let lexical = lower_file_resolution_facts_with_identities(&mut identities, language, facts);
    let (package_references, package_members) =
        package::lower_metadata(&mut identities, language, facts);
    let common = super::common_fact_lowering::LoweredCommonFacts {
        package_references,
        package_members,
        ..Default::default()
    };
    // The same dense rekeying the whole lowering ends with, and then the
    // fixture's own mount. Without the rekeying every id is still the
    // provisional counter the builder handed out; without the mount every
    // fixture's artifact sits at the one unmounted ordinal and two of them
    // collide.
    let lowered = super::LoweredResolutionFactsWithIdentityCatalog::from_lexical_for_test(
        lexical,
        common,
        identities.finish(),
        language,
    )
    .remount(fragment, &crate::CancellationToken::default())
    .expect("a fixture remount runs under an uncancelled token");
    fixture_names::record(lowered.identities());
    (lowered.lexical().clone(), lowered.identities().clone())
}

/// One fixture's whole lowered artifact, with the catalog that numbered it.
///
/// This replaces `lower_file_resolution_facts` and
/// `lower_typed_resolution_facts`, which lowered one half each and dropped the
/// catalog. That was free while a mounted id was a pure function of its
/// identity: two lowerings of one file produced the same ids, and no caller
/// needed a catalog to name one. A local id is a catalog position now, so two
/// lowerings build two catalogs whose positions agree only on the sites, and
/// an artifact assembled from two of them disagrees with itself about every
/// other identity. One lowering, one catalog, and the catalog is how a fixture
/// names a position.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn lower_for_test(
    fragment: BindingFragmentId,
    language: Language,
    facts: &FileResolutionFacts,
) -> super::LoweredResolutionFactsWithIdentityCatalog {
    // Mounted at the fixture's own ordinal. A lowering mints under the
    // unmounted ordinal and production splices the mount's in as a value
    // crosses to the engine; a fixture hands its artifact to the engine
    // directly, so it mounts it here instead, and two fixtures' artifacts
    // cannot collide at the one unmounted ordinal.
    let lowered = super::lower_resolution_facts_for_selection(
        fragment,
        super::local_identity::test_shared_names(),
        language,
        facts,
    )
    .remount(fragment, &crate::CancellationToken::default())
    .expect("a fixture remount runs under an uncancelled token");
    fixture_names::record(lowered.identities());
    lowered
}

/// The runtime semantic one fixture's catalog gives a producer identity.
///
/// A fixture used to write `type_slot_semantic(fragment, slot)` and compare;
/// the position that answers is the catalog's, so the fixture asks the catalog
/// it lowered with.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn catalog_semantic(
    catalog: &super::local_identity::ResolutionIdentityCatalog,
    identity: ResolutionSemanticIdentity,
) -> SemanticId {
    catalog
        .semantic_for_identity(identity)
        .unwrap_or_else(|| panic!("the fixture's catalog has no position for {identity:?}"))
}

/// The runtime node one fixture's catalog gives a producer identity. See
/// [`catalog_semantic`].
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn catalog_node(
    catalog: &super::local_identity::ResolutionIdentityCatalog,
    identity: ResolutionNodeIdentity,
) -> BindingNodeId {
    catalog
        .node_for_identity(identity)
        .unwrap_or_else(|| panic!("the fixture's catalog has no position for {identity:?}"))
}

/// Lower one file's target-independent facts into compositional lexical paths.
///
/// `fragment` identifies the immutable file-local artifact. `language` is part
/// of effective lookup keys so equal spellings in unrelated language domains
/// never stitch. Entity, node, and path IDs include the fragment plus typed
/// local IDs and producer roles; reordering normalized input rows therefore
/// cannot change output identity or order.
pub(super) fn lower_file_resolution_facts_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    facts: &FileResolutionFacts,
) -> LoweredResolutionFragment {
    let fragment = identities.fragment();
    #[cfg(any(test, feature = "test-support"))]
    let mut hierarchy_terminals = Vec::new();
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
    // A conditional binder is the weaker half of one token that is both a
    // reference and a declaration. Its binder route is published below every
    // enclosing lexical route, so a visible declaration of the same name wins
    // and the binder answers only where the outward lookup proves empty.
    let mut superseded_declarations = HashSet::default();
    for conditional in &facts.conditional_binders {
        let reference = index.site(conditional.reference);
        let declaration = index.site(conditional.declaration);
        assert_eq!(
            (reference.start_byte, reference.end_byte),
            (declaration.start_byte, declaration.end_byte),
            "a conditional binder's two halves are one token: {conditional:?}, {reference:?}, {declaration:?}"
        );
        assert_eq!(
            reference.scope, declaration.scope,
            "a conditional binder's two halves share one scope: {conditional:?}"
        );
        assert_eq!(
            index.declaration_identifier(conditional.declaration).name,
            index.reference_identifier(conditional.reference).name,
            "a conditional binder's two halves spell one name: {conditional:?}"
        );
        assert!(
            superseded_declarations.insert(conditional.declaration),
            "one conditional row per declaration is required: {conditional:?}"
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
                superseded: superseded_declarations.contains(&binder.declaration),
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
    let route_owned_modules = facts
        .route_owned_module_declarations
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    for &module in &route_owned_modules {
        let identifier = index.declaration_identifier(module);
        assert!(
            index.site(module).kind == ResolutionSiteKind::ModuleDeclaration
                && identifier.namespace == ResolutionNamespace::Type
                && !declarations_with_binders.contains(&module),
            "a route-owned module is a Type module declaration with no binder: {identifier:?}"
        );
    }
    for identifier in &facts.identifiers {
        if identifier.role == ResolutionIdentifierRole::Declaration
            && !declarations_with_binders.contains(&identifier.site)
            // An explicit member owner supplies a non-lexical binding route.
            // Missing lexical authority is a gap only for declarations that
            // have no such structured ownership, not for associated members.
            && !deferred_member_declarations.contains(&identifier.site)
            // A route-owned module is reached through the crate's module walk
            // and export rows, never through a binder, so it withholds no
            // lexical binding either.
            && !route_owned_modules.contains(&identifier.site)
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
    } = lower_scope_timelines_and_paths(identities, language, &index, &activation_positions);

    let go_package_qualifiers = if language == Language::Go {
        facts
            .root_references
            .iter()
            .filter_map(|reference| reference.prefix_reference)
            .collect::<HashSet<_>>()
    } else {
        HashSet::default()
    };
    let mut go_definition_namespaces = HashMap::default();
    if language == Language::Go {
        for binder in &supported_binders {
            if !matches!(
                binder.fact.kind,
                ResolutionBinderKind::Type
                    | ResolutionBinderKind::Local
                    | ResolutionBinderKind::Parameter
                    | ResolutionBinderKind::Callable
            ) {
                continue;
            }
            let mut bits = 0;
            for namespace in std::iter::once(binder.identifier.namespace).chain(
                index
                    .additional_definition_namespaces(binder.fact.declaration)
                    .iter()
                    .map(|fact| fact.namespace),
            ) {
                bits |= match namespace {
                    ResolutionNamespace::Type => 1,
                    ResolutionNamespace::Value => 2,
                    ResolutionNamespace::Callable => 4,
                    _ => panic!("unsupported Go lexical binder namespace: {namespace:?}"),
                };
            }
            assert!(
                go_definition_namespaces
                    .insert(
                        binder.fact.declaration,
                        super::model::GoDefinitionNamespaces::from_bits(bits)
                    )
                    .is_none()
            );
        }
    }
    let mut semantics = Vec::new();
    let mut semantic_by_site = HashMap::default();
    // The schema numbers a site, its semantic and its node with one integer
    // (`.agents/docs/stack-graph-schema-draft-2026-09-18.md` section 3), which
    // requires that a site carry exactly one role. Lane LD measured it on every
    // Rust blob of tract (419,000 sites, 419,000 distinct site semantics,
    // 419,000 distinct site nodes, zero semantics in both roles); this is where
    // every other producer is held to the same rule.
    let mut role_by_site: HashMap<ResolutionSiteId, LoweredSemanticRole> = HashMap::default();
    for identifier in index.identifiers_sorted() {
        let site = index.site(identifier.site);
        let (role, semantic, node, kind) = match identifier.role {
            ResolutionIdentifierRole::Reference => {
                let semantic = identities.source_reference_semantic(identifier.site);
                let node = identities.source_reference_node(identifier.site);
                (
                    LoweredSemanticRole::Reference,
                    semantic,
                    node,
                    BindingNodeKind::Reference(semantic),
                )
            }
            ResolutionIdentifierRole::Declaration => {
                let semantic = identities.source_definition_semantic(identifier.site);
                let node = identities.source_definition_node(identifier.site);
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
        if let Some(previous) = role_by_site.insert(identifier.site, role) {
            assert_eq!(
                previous, role,
                "a resolution site carries one role, so that its site, semantic and node \
                 can share one number: {identifier:?}"
            );
        }
        semantics.push(LoweredSemanticSite {
            site: identifier.site,
            namespace: identifier.namespace,
            role,
            semantic,
            node,
            go_definition_namespaces: go_definition_namespaces.get(&identifier.site).copied(),
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
                        owner.map(|owner| identities.source_definition_semantic(owner))
                    }),
                    index.callable_receiver_origin(identifier.site),
                )
                .with_go_spelling_namespace(
                    (language == Language::Go
                        && identifier.qualifier.is_none()
                        && index.root_reference(identifier.site).is_none())
                    .then_some(identifier.namespace),
                )
                .with_go_package_qualifier(go_package_qualifiers.contains(&identifier.site))
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
        let completion = completion_for_site(&reasons_by_site, semantic.site, |origin| {
            index.lexical_reference_gap(semantic.site, origin)
        });
        if index.keyword_references.contains(&identifier.site) {
            // A keyword the language binds implicitly (Rust `Self`) is
            // answered by its typed identity alone. Its lookup ends at a sink
            // of its own instead of entering a scope: no binder, glob,
            // prelude or unexpanded macro of any scope can supply it, and
            // the path still states the lookup the reference spells, which
            // route readers use to recognize the keyword.
            let sink = identities.node(gap_sink_node_identity(semantic.site, b"keyword"));
            nodes.push((sink, BindingNodeKind::Scope));
            for &(_, namespace) in lookup_routes(identifier.namespace) {
                let lookup =
                    identities.lookup_semantic(language, namespace, index.name(identifier.name));
                let id = identities.path(reference_path_identity(semantic.site, namespace));
                paths.push((
                    id,
                    PartialPath::new(
                        closed_endpoint(semantic.node, []),
                        closed_endpoint(sink, [lookup]),
                        Vec::new(),
                        [WitnessStep::Node(sink)],
                        completion.clone(),
                    ),
                ));
            }
            continue;
        }
        if index.root_reference(identifier.site).is_some() {
            // A root-qualified reference has an explicit source-owned route.
            // Its terminal semantic remains ordinary, but it must not also
            // publish a lexical route that could close through a local decoy.
            continue;
        }
        if identifier.qualifier.is_some() {
            if language == Language::Go
                && site.kind == ResolutionSiteKind::CompositeLiteralKeyReference
            {
                // A Go keyed literal's bare identifier is either a struct
                // field label or an ordinary map-key expression. The owner
                // type is resolved later, so publish both structured lookup
                // routes and let FactEvaluation select one after resolving
                // that owner. No name is interpreted here.
                let timeline = timelines
                    .get(&site.scope)
                    .expect("validated reference scope has a timeline");
                let checkpoint = timeline.active_node_at(site.start_byte);
                for namespace in super::local_identity::GO_SPELLING_NAMESPACES {
                    let lookup = identities.lookup_semantic(
                        language,
                        namespace,
                        index.name(identifier.name),
                    );
                    let id = identities.path(reference_path_identity(semantic.site, namespace));
                    paths.push((
                        id,
                        PartialPath::new(
                            closed_endpoint(semantic.node, []),
                            closed_endpoint(checkpoint, [lookup]),
                            Vec::new(),
                            [WitnessStep::Node(checkpoint)],
                            completion.clone(),
                        ),
                    ));
                }
            }
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
        let go_spelling = semantic
            .site_metadata
            .and_then(FactReferenceSiteMetadata::go_spelling_namespace)
            .is_some();
        let go_routes =
            super::local_identity::GO_SPELLING_NAMESPACES.map(|namespace| (0, namespace));
        let routes = if go_spelling {
            &go_routes[..]
        } else {
            lookup_routes(identifier.namespace)
        };
        for &(route_ordinal, namespace) in routes {
            let lookup =
                identities.lookup_semantic(language, namespace, index.name(identifier.name));
            let precedence = (!go_spelling
                && identifier.namespace == ResolutionNamespace::TypeOrValue)
                .then(|| {
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
        let (_definition, definition_node) = semantic_by_site
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
                    if language == Language::Go {
                        go_spelling_precedence(
                            identities,
                            timeline.fact.id,
                            match binder.activation {
                                SupportedActivation::ScopeWide => None,
                                SupportedActivation::SourceOrder(position) => Some(position),
                            },
                            if binder.superseded { 2 } else { 0 },
                        )
                    } else {
                        binder_precedence(identities, timeline, &binder)
                    },
                    [WitnessStep::Node(definition_node)],
                    completion_for_site(
                        &reasons_by_site,
                        binder.fact.declaration,
                        lexical_declaration_gap,
                    ),
                ),
            ));
        }
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
    lower_root_export_paths(identities, language, &index, &gap_sources, &mut paths);
    package::lower_paths(
        identities,
        language,
        facts,
        &reasons_by_site,
        &gap_sources,
        &mut paths,
    );

    // Placement and hierarchy uncertainty are real branches, not global
    // candidate poison. Their open stack tails preserve the exact lookup key
    // that reached the boundary, while their precedence traces let a proven
    // nearer binder discharge only the losing branch.
    let mut unexpanded_item_macros =
        std::collections::BTreeMap::<ResolutionScopeId, Vec<GapSource>>::new();
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
            let (sink, row) = placement_gap_lexical_row_with_identities(
                identities,
                language,
                source.site,
                scope.id,
            );
            nodes.push((sink, BindingNodeKind::Scope));
            debug_assert_eq!(row.1.start().node(), timeline.head);
            paths.push(row);
        }

        if source.origin == LoweringGapOrigin::Extracted(ResolutionGapKind::UnexpandedItemMacro) {
            unexpanded_item_macros
                .entry(index.site(source.site).scope)
                .or_default()
                .push(source);
        }

        if hierarchy_boundary_gap(source.origin)
            && let Some(owner) = index.hierarchy_gap_owner(source.site)
        {
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
            let sink = identities.node(hierarchy_terminal_node_identity(source.site));
            #[cfg(any(test, feature = "test-support"))]
            hierarchy_terminals.push((
                identities.semantic(gap_reason_semantic_identity(source.site, source.origin)),
                sink,
            ));
            nodes.push((sink, BindingNodeKind::Scope));
            let reason = ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(
                    identities.semantic(gap_reason_semantic_identity(source.site, source.origin)),
                ),
            ]);
            if index.is_implicit_superclass_reference(source.site) {
                // The implicit superclass is java.lang.Object, whose members
                // JLS 4.3.2 fixes: methods only. Only a callable lookup of one
                // of its method names can reach this unindexed edge, so the
                // branch is closed on exactly those lookups; member-type,
                // field and constructor lookups never meet it.
                for name in JAVA_OBJECT_METHOD_NAMES {
                    let lookup =
                        identities.lookup_semantic(language, ResolutionNamespace::Callable, name);
                    let id = identities.path(implicit_object_hierarchy_path_identity(
                        source.site,
                        owner,
                        name,
                    ));
                    paths.push((
                        id,
                        PartialPath::new(
                            closed_endpoint(timeline.head, [lookup]),
                            closed_endpoint(sink, [lookup]),
                            type_body_hierarchy_precedence(identities, type_body.id),
                            [WitnessStep::Node(sink)],
                            reason.clone(),
                        ),
                    ));
                }
                continue;
            }
            let id = identities.path(hierarchy_gap_path_identity(source.site, owner));
            let variable = passthrough_variable(identities, id);
            paths.push((
                id,
                PartialPath::new(
                    open_endpoint(timeline.head, variable),
                    open_endpoint(sink, variable),
                    type_body_hierarchy_precedence(identities, type_body.id),
                    [WitnessStep::Node(sink)],
                    reason,
                ),
            ));
        }
    }

    for (scope, sources) in unexpanded_item_macros {
        lower_unexpanded_item_macro_branches(
            identities, &index, scope, &sources, &mut nodes, &mut paths,
        );
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
    gaps.extend(lower_external_prelude_boundary_gaps(
        identities, language, &index,
    ));
    gaps.sort_unstable();
    gaps.dedup();
    package::lower_import_definitions(identities, language, facts, &mut nodes, &mut semantics);
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
    #[cfg(any(test, feature = "test-support"))]
    hierarchy_terminals.sort_unstable();
    LoweredResolutionFragment {
        fragment,
        language,
        nodes,
        paths,
        semantics,
        gaps,
        #[cfg(any(test, feature = "test-support"))]
        hierarchy_terminals,
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
                        identities.source_scope_node(import.fact.root_scope),
                        [lookup],
                        tail,
                    ),
                    symbol_open_endpoint(BindingNodeId::universal_root(), root_symbols, tail),
                    root_import_precedence(identities, language, import, choice, demand.namespace),
                    [WitnessStep::Node(BindingNodeId::universal_root())],
                    ResolutionCompletion::Complete,
                ),
            ));
        }
    }
}

/// A root import's rank at its scope's choice point.
///
/// Rust ranks a scope's imports above the scope's outward continuation, as
/// rustc does: a block's own items and imports, globs included, win over
/// every enclosing scope, and a named import wins over a glob. Both take the
/// continuation's rank on the scope choice and are ordered after it on the
/// scope's import choice (`rust_scope_outward_precedence`): named first, then
/// globs together with an unexpanded item macro's fallback branch
/// (`lower_unexpanded_item_macro_branches`), then the continuation. Java single
/// imports rank above on-demand imports at the same compilation-unit choice.
/// Other languages keep one wildcard-tier step, below their outward lookup.
fn root_import_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    import: &IndexedRootImport,
    choice: SemanticId,
    namespace: ResolutionNamespace,
) -> Vec<PrecedenceStep> {
    if language == Language::Go {
        return go_spelling_precedence(identities, import.fact.root_scope, None, 0);
    }
    if language != Language::Rust {
        return vec![identities.register_precedence_namespace(
            PrecedenceStep {
                tier: if language == Language::Java && import.named {
                    PrecedenceTier::ExplicitImport
                } else {
                    PrecedenceTier::WildcardImport
                },
                ordinal: 0,
                semantic: choice,
            },
            namespace,
        )];
    }
    let import_choice =
        identities.semantic(import_choice_identity(import.fact.root_scope, namespace));
    vec![
        registered_precedence_step(identities, choice, 1, namespace),
        registered_precedence_step(
            identities,
            import_choice,
            if import.named {
                RUST_NAMED_IMPORT_RANK
            } else {
                RUST_GLOB_IMPORT_RANK
            },
            namespace,
        ),
    ]
}

/// Ranks on a Rust scope's import choice (`import_choice_identity`).
const RUST_NAMED_IMPORT_RANK: u32 = 0;
const RUST_GLOB_IMPORT_RANK: u32 = 1;
const RUST_OUTWARD_RANK: u32 = 2;

/// A Rust scope's outward continuation: the ordinary fallback on the scope
/// choice, then the last rank on the scope's import choice, below the scope's
/// own named and glob imports.
fn rust_scope_outward_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
) -> Vec<PrecedenceStep> {
    let mut steps = scope_fallback_precedence(identities, scope);
    for namespace in EFFECTIVE_NAMESPACES {
        let semantic = identities.semantic(import_choice_identity(scope, namespace));
        steps.push(registered_precedence_step(
            identities,
            semantic,
            RUST_OUTWARD_RANK,
            namespace,
        ));
    }
    steps
}

/// The choice point that orders a Rust scope's named imports, glob imports
/// (with an unexpanded item macro's fallback branch) and outward
/// continuation, after they tie on the scope choice. Nothing else shares it.
fn import_choice_identity(
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-import-choice-local:v1",
        &[
            ("scope", &u32_bytes(scope.get())),
            ("namespace", namespace.identity_label().as_bytes()),
        ],
    ))
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
        assert!(
            identifier.namespace != ResolutionNamespace::TypeOrValue
                || (language == Language::Go && reference.fact.prefix_reference.is_some()),
            "only prefixed Go root references may retain type-or-value ambiguity: {reference:?}, {identifier:?}"
        );
        let (route_namespace, lookup_scope, prefix_reference) =
            if let Some(prefix_reference) = reference.fact.prefix_reference {
                let prefix_identifier = index.reference_identifier(prefix_reference);
                match language {
                    Language::Rust | Language::Java => assert_eq!(
                        prefix_identifier.namespace,
                        ResolutionNamespace::Type,
                        "Rust and Java qualified type prefixes use the Type namespace"
                    ),
                    Language::Go => {
                        assert_eq!(
                            prefix_identifier.namespace,
                            ResolutionNamespace::TypeOrValue,
                            "Go package or runtime qualifier retains both lexical categories"
                        );
                        assert_eq!(
                            reference.segments.len(),
                            1,
                            "Go selected package continuation has one positioned qualifier"
                        );
                    }
                    _ => panic!("positioned root prefixes are unsupported for {language:?}"),
                }
                (
                    ResolutionNamespace::Type,
                    index.site(prefix_reference).scope,
                    Some(identities.source_reference_semantic(prefix_reference)),
                )
            } else {
                (identifier.namespace, reference.fact.root_scope, None)
            };
        // Rust and Go continue from a resolved lexical prefix. Java instead
        // retains the whole package spelling: its prefix is a shadowing guard,
        // and only an absent lexical type permits package interpretation.
        let route = reference
            .segments
            .iter()
            .skip(usize::from(
                prefix_reference.is_some() && language != Language::Java,
            ))
            .map(|&name| identities.lookup_semantic(language, route_namespace, index.name(name)))
            .collect::<Vec<_>>();
        for &(route_ordinal, namespace) in lookup_routes(identifier.namespace) {
            let lookup =
                identities.lookup_semantic(language, namespace, index.name(identifier.name));
            let token = identities.semantic(root_reference_token_identity(
                reference.fact.reference,
                namespace,
            ));
            let id = identities.path(root_reference_path_identity(
                reference.fact.reference,
                namespace,
            ));
            let mut root_symbols = Vec::with_capacity(route.len().saturating_add(4));
            root_symbols.push(
                identities.semantic(root_import_anchor_semantic_identity(reference.fact.anchor)),
            );
            if let Some(prefix_reference) = prefix_reference {
                // This is the canonical semantic of the positioned Type lookup,
                // not a spelling marker. Selected operations can therefore resolve
                // the prefix through the native lexical graph before continuing
                // through the selected module/type route.
                root_symbols.push(prefix_reference);
            }
            root_symbols.extend(route.iter().copied());
            root_symbols.push(token);
            root_symbols.push(lookup);
            let choice_namespace = if identifier.namespace == ResolutionNamespace::TypeOrValue {
                ResolutionNamespace::TypeOrValue
            } else {
                namespace
            };
            let choice = identities.semantic(scope_choice_identity(
                reference.fact.root_scope,
                choice_namespace,
            ));
            let witness = if prefix_reference.is_some() {
                vec![
                    WitnessStep::Node(identities.source_scope_node(lookup_scope)),
                    WitnessStep::Node(identities.source_scope_node(reference.fact.root_scope)),
                    WitnessStep::Node(BindingNodeId::universal_root()),
                ]
            } else {
                vec![
                    WitnessStep::Node(identities.source_scope_node(reference.fact.root_scope)),
                    WitnessStep::Node(BindingNodeId::universal_root()),
                ]
            };
            paths.push((
                id,
                PartialPath::new(
                    closed_endpoint(
                        identities.source_reference_node(reference.fact.reference),
                        Vec::new(),
                    ),
                    closed_endpoint(BindingNodeId::universal_root(), root_symbols),
                    [identities.register_precedence_namespace(
                        PrecedenceStep {
                            tier: PrecedenceTier::PackageOrModule,
                            ordinal: route_ordinal,
                            semantic: choice,
                        },
                        namespace,
                    )],
                    witness,
                    completion_for_site(reasons_by_site, reference.fact.reference, |origin| {
                        index.lexical_reference_gap(reference.fact.reference, origin)
                    }),
                ),
            ));
        }
    }
}

/// Lower declarations that selected root context may expose. The leading
/// lookup stays Shared for indexed root discovery; the following local token
/// prevents source facts alone from choosing a package or module target.
fn root_scope_gap_reasons(
    identities: &mut ResolutionIdentityCatalogBuilder,
    index: &FactIndex<'_>,
    gap_sources: &[GapSource],
) -> HashMap<ResolutionScopeId, Vec<ResolutionIncompleteReason>> {
    let mut scope_reasons: HashMap<ResolutionScopeId, Vec<ResolutionIncompleteReason>> =
        HashMap::default();
    for source in gap_sources {
        if source.origin
            == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedScopeOrBinder)
            && !index
                .identifiers_by_site
                .get(&source.site)
                .is_some_and(|identifiers| {
                    identifiers
                        .iter()
                        .any(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                })
        {
            scope_reasons
                .entry(index.site(source.site).scope)
                .or_default()
                .push(ResolutionIncompleteReason::UnsupportedSemantic(
                    identities.semantic(gap_reason_semantic_identity(source.site, source.origin)),
                ));
        }
    }
    scope_reasons
}

fn lower_root_export_paths(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    index: &FactIndex<'_>,
    gap_sources: &[GapSource],
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    let scope_reasons = root_scope_gap_reasons(identities, index, gap_sources);
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
        let tail = passthrough_variable(identities, id);
        let definition = identities.source_definition_node(export.declaration);
        // Exact selected bridges bypass lexical lookup. Carry omitted-binder
        // evidence with the exported authority so that forward proof cannot
        // become stronger merely by crossing a module boundary.
        let completion = scope_reasons
            .get(&index.site(export.declaration).scope)
            .map_or(ResolutionCompletion::Complete, |reasons| {
                ResolutionCompletion::incomplete(reasons.iter().copied())
            });
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
                completion,
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
    argument_independent_references: HashSet<ResolutionSiteId>,
    keyword_references: HashSet<ResolutionSiteId>,
    type_slots_by_site: HashMap<ResolutionSiteId, Vec<ResolutionTypeSlotId>>,
    supertype_owner_by_reference: HashMap<ResolutionSiteId, ResolutionSiteId>,
    /// Supertype references the producer supplied as a class's implicit
    /// `java.lang.Object` superclass.
    implicit_superclass_references: HashSet<ResolutionSiteId>,
    type_body_scope_by_owner: HashMap<ResolutionSiteId, ResolutionScopeFact>,
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
    /// The producer stated this import names its leaves (`use a::B;`), not a
    /// wildcard. See [`root_import_precedence`].
    named: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedRootReference {
    fact: ResolutionRootReferenceFact,
    segments: Vec<ResolutionNameId>,
}

impl<'facts> FactIndex<'facts> {
    fn index_argument_independent_references(
        facts: &FileResolutionFacts,
    ) -> HashSet<ResolutionSiteId> {
        let calls = facts
            .calls
            .iter()
            .map(|call| (call.call, call.callee))
            .collect::<HashMap<_, _>>();
        facts
            .engine_rule_eligibilities
            .iter()
            .filter(|eligibility| {
                eligibility.rule == ResolutionEngineRuleKind::ArgumentIndependentBinding
            })
            .map(|eligibility| {
                *calls
                    .get(&eligibility.site)
                    .expect("binding eligibility names an existing call")
            })
            .collect()
    }

    fn lexical_reference_gap(
        &self,
        reference: ResolutionSiteId,
        origin: LoweringGapOrigin,
    ) -> bool {
        // The producer authorizes declaration lookup independently of checking
        // the invocation. Keep its canonical gap and typed frontier, but do
        // not attach invocation uncertainty to lexical paths or inverse coverage.
        !(origin == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
            && self.argument_independent_references.contains(&reference))
            && lexical_gap(origin)
    }

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
            assert!(
                matches!(
                    root_scope.kind,
                    ResolutionScopeKind::CompilationUnit
                        | ResolutionScopeKind::File
                        | ResolutionScopeKind::Package
                        | ResolutionScopeKind::Executable
                        | ResolutionScopeKind::Block
                ),
                "root import needs a lexical attachment scope: {root_scope:?}"
            );
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
                // A route may be empty. `use serde as s;` and
                // `use serde::{self as s};` name the path root itself, so the
                // import states an anchor, the root token and the demand with
                // no segment between them, and the stack
                // `lower_root_import_paths` builds is exactly three symbols.
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
                    named: facts.root_import_kinds.iter().any(|kind| {
                        kind.import_site == fact.site
                            && kind.kind == ResolutionRootImportKind::Named
                    }) || facts.import_routes.iter().any(|route| {
                        route.site == fact.site
                            && matches!(
                                route.kind,
                                ResolutionImportRouteKind::SingleType
                                    | ResolutionImportRouteKind::SingleStatic
                            )
                    }),
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

    /// Validate the exact named-leaf and wildcard provenance published with
    /// every root import demand.
    ///
    /// Grouped and renamed leaves share one import site, one outer source
    /// range and one route prefix, so a containment join cannot name the
    /// target occurrence of a demand. The producer therefore states the
    /// discriminator: a named demand owns one exact target reference, and a
    /// wildcard demand reuses its own name. Reject a fact set that does not
    /// state it exactly, at the point where the index is built, rather than
    /// handing an ambiguous route to the selected bridge compilers.
    fn validate_root_import_demand_targets(
        facts: &'facts FileResolutionFacts,
        root_imports: &[IndexedRootImport],
        root_references: &[IndexedRootReference],
    ) {
        let mut kinds = HashMap::default();
        for fact in &facts.root_import_kinds {
            assert!(
                root_imports
                    .binary_search_by_key(&fact.import_site, |import| import.fact.site)
                    .is_ok(),
                "root-import kind names an unknown import site: {fact:?}"
            );
            assert!(
                kinds.insert(fact.import_site, fact.kind).is_none(),
                "one named/glob discriminator per root import is required: {fact:?}"
            );
        }
        let mut stated = HashSet::default();
        for fact in &facts.root_import_demand_targets {
            let index = root_imports
                .binary_search_by_key(&fact.import_site, |import| import.fact.site)
                .unwrap_or_else(|_| {
                    panic!("root-import demand target names an unknown import site: {fact:?}")
                });
            let import = &root_imports[index];
            assert!(
                import
                    .demands
                    .iter()
                    .any(|demand| demand.namespace == fact.namespace && demand.name == fact.name),
                "root-import demand target names an unknown demand: {fact:?}, {import:?}"
            );
            assert!(
                stated.insert((fact.import_site, fact.namespace, fact.name)),
                "one exact target per root-import demand is required: {fact:?}"
            );
            let kind = kinds.get(&fact.import_site).copied().unwrap_or_else(|| {
                panic!("root-import demand target needs named/glob provenance: {fact:?}")
            });
            match fact.target {
                ResolutionRootImportDemandTarget::NamedReference(reference) => {
                    assert_eq!(
                        kind,
                        ResolutionRootImportKind::Named,
                        "an exact target reference belongs to a named import: {fact:?}"
                    );
                    let target = root_references
                        .binary_search_by_key(&reference, |target| target.fact.reference)
                        .ok()
                        .map(|index| &root_references[index])
                        .unwrap_or_else(|| {
                            panic!("named import target must be an exact root reference: {fact:?}")
                        });
                    let identifier = facts
                        .identifiers
                        .iter()
                        .find(|identifier| {
                            identifier.site == reference
                                && identifier.role == ResolutionIdentifierRole::Reference
                                && identifier.namespace == fact.namespace
                        })
                        .unwrap_or_else(|| {
                            panic!(
                                "named import target must carry its reference identifier: {fact:?}"
                            )
                        });
                    let mut route_scope = import.fact.root_scope;
                    while !matches!(
                        facts.scopes[route_scope.index()].kind,
                        ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
                    ) {
                        route_scope = facts.scopes[route_scope.index()]
                            .parent
                            .expect("a lexical import scope has a containing module scope");
                    }
                    assert!(
                        facts.sites[reference.index()].scope == import.fact.root_scope
                            && target.fact.root_scope == route_scope
                            && target.fact.anchor == import.fact.anchor
                            && target.fact.prefix_reference.is_none()
                            && target.segments == import.segments,
                        "named import target must retain the exact root route: {fact:?}, {target:?}, {identifier:?}, {import:?}"
                    );
                }
                ResolutionRootImportDemandTarget::SameNameGlob => {
                    assert_eq!(
                        kind,
                        ResolutionRootImportKind::Glob,
                        "same-name reuse belongs to a wildcard import: {fact:?}"
                    );
                }
            }
        }
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
            assert!(
                root_scope_is_ancestor(*root_scope, *site, scopes),
                "root reference root scope must be an ancestor of its site: {reference:?}, {site:?}, root={root_scope:?}"
            );
            if let Some(prefix_reference) = reference.prefix_reference {
                let prefix_site = sites.get(&prefix_reference).unwrap_or_else(|| {
                    panic!("root reference names unknown lexical prefix site: {reference:?}")
                });
                let prefix_identifier = identifiers_by_site
                    .get(&prefix_reference)
                    .and_then(|identifiers| identifiers.first())
                    .unwrap_or_else(|| {
                        panic!(
                            "root reference lexical prefix has no positioned identifier: {reference:?}"
                        )
                    });
                assert_eq!(
                    prefix_identifier.role,
                    ResolutionIdentifierRole::Reference,
                    "root reference lexical prefix must be a reference: {reference:?}"
                );
                assert!(
                    matches!(
                        prefix_identifier.namespace,
                        ResolutionNamespace::Type | ResolutionNamespace::TypeOrValue
                    ),
                    "root reference lexical prefix needs a type or qualified-name lookup: {reference:?}"
                );
                assert_eq!(
                    prefix_identifier.qualifier, None,
                    "root reference lexical prefix must be unqualified: {reference:?}"
                );
                assert_eq!(
                    prefix_site.scope, site.scope,
                    "root reference lexical prefix and terminal share a scope: {reference:?}"
                );
                assert!(
                    root_scope_is_ancestor(*root_scope, *prefix_site, scopes),
                    "root reference root scope must be an ancestor of its lexical prefix: {reference:?}"
                );
            }
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
                // A terminal keeps a structured type qualifier only where a
                // route prefix is its receiver: a bare route names that prefix
                // as its lexical prefix reference, and an explicit module
                // route (`crate::m::Type::member`) keeps its whole route, whose
                // final segment is the receiver and so names an item rather
                // than a module anchor.
                let qualified = identifiers_by_site
                    .get(&fact.reference)
                    .and_then(|identifiers| identifiers.first())
                    .expect("validated root reference identifier")
                    .qualifier
                    .is_some();
                assert!(
                    !qualified
                        || fact.prefix_reference.is_some()
                        || (segments.len() >= 2
                            && segments.last().is_some_and(|segment| {
                                !matches!(names[&segment.name], "crate" | "self" | "super")
                            })),
                    "a root route retains a structured type qualifier only when a bare lexical prefix \
                     or the final segment of an explicit module route is its receiver: {fact:?}, {segments:?}"
                );
                if let Some(prefix_reference) = fact.prefix_reference {
                    let prefix_name = identifiers_by_site
                        .get(&prefix_reference)
                        .and_then(|identifiers| identifiers.first())
                        .expect("validated root lexical prefix identifier")
                        .name;
                    assert_eq!(
                        segments.first().map(|segment| segment.name),
                        Some(prefix_name),
                        "root reference lexical prefix agrees with its first route segment: {fact:?}"
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
        let mut members = HashSet::default();
        for member in &facts.member_owners {
            assert!(
                members.insert(member.member),
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
                    && matches!(
                        (sites[&member.owner].kind, owner.namespace),
                        (
                            ResolutionSiteKind::TypeDeclaration,
                            ResolutionNamespace::Type
                        ) | (
                            ResolutionSiteKind::ConstructorDeclaration,
                            ResolutionNamespace::Constructor
                        )
                    ),
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
                            | ResolutionSiteKind::TypeAliasDeclaration
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
            assert!(
                matches!(
                    owner_site.kind,
                    ResolutionSiteKind::TypeDeclaration
                        | ResolutionSiteKind::ConstructorDeclaration
                ),
                "type-body scope owner must be a type or constructor declaration: {scope:?}, {owner_site:?}"
            );
            assert!(
                type_body_scope_by_owner.insert(owner, scope).is_none(),
                "one type-body scope per type declaration is required: {scope:?}"
            );
        }
        let mut supertype_owner_by_reference = HashMap::default();
        let implicit_superclass_references = facts
            .supertypes
            .iter()
            .filter(|supertype| {
                supertype.kind
                    == brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind::ImplicitSuperclass
            })
            .map(|supertype| supertype.supertype_reference)
            .collect::<HashSet<_>>();
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

        let root_references =
            Self::index_root_references(facts, &names, &scopes, &sites, &identifiers_by_site);
        let root_imports = Self::index_root_imports(facts, &names, &scopes, &sites);
        Self::validate_root_import_demand_targets(facts, &root_imports, &root_references);
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
            // A route-owned module is exported without a binder: the crate's
            // module walk, not a lexical scope, is what places it, so neither
            // a binder nor a definition-namespace authority (which names a
            // binder) declares its namespace; its site kind does.
            let route_owned = facts
                .route_owned_module_declarations
                .contains(&export.declaration)
                && site.kind == ResolutionSiteKind::ModuleDeclaration
                && identifier.namespace == ResolutionNamespace::Type
                && export.namespace == ResolutionNamespace::Type;
            let declared_export = route_owned
                || declaration_namespace_is_declared(
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
                (route_owned && binders.is_empty())
                    || matches!(binders, [binder]
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
            argument_independent_references: Self::index_argument_independent_references(facts),
            keyword_references: facts.keyword_references.iter().copied().collect(),
            type_slots_by_site,
            supertype_owner_by_reference,
            implicit_superclass_references,
            type_body_scope_by_owner,
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

    /// A hierarchy gap that a declaration owns -- directly, or through its
    /// normalized supertype reference -- places a lexical fallback branch in
    /// that declaration's type body. Producers also record the same hierarchy
    /// incompleteness where no declaration owns it: a trait's abstract `Self`
    /// frontier, and the `dyn`, `impl Trait` and bounded heads of a declared
    /// type. Those sites name no type body, so they carry the typed frontier
    /// gap alone and get no lexical branch. Any other site kind is a producer
    /// error.
    fn hierarchy_gap_owner(&self, site: ResolutionSiteId) -> Option<ResolutionSiteId> {
        let source = self.site(site);
        if source.kind == ResolutionSiteKind::TypeDeclaration {
            return Some(site);
        }
        if let Some(owner) = self.supertype_owner_by_reference.get(&site) {
            return Some(*owner);
        }
        assert!(
            matches!(
                source.kind,
                ResolutionSiteKind::TypeReference
                    | ResolutionSiteKind::SyntheticReference
                    | ResolutionSiteKind::UnsupportedExpression
            ),
            "hierarchy gap must name a type declaration, a normalized supertype reference, a type reference, a synthetic reference or an unsupported expression: {source:?}"
        );
        None
    }

    fn is_implicit_superclass_reference(&self, site: ResolutionSiteId) -> bool {
        self.implicit_superclass_references.contains(&site)
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
            ResolutionScopeKind::CompilationUnit
                | ResolutionScopeKind::Package
                | ResolutionScopeKind::TypeBody
        ),
        "root export needs a compilation-unit, module, or type container scope: {scope:?}"
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
        ResolutionNamespace::Package => &[(0, ResolutionNamespace::Package)],
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

/// Every namespace a declaration can occupy, and so every namespace whose
/// choice points a scope, checkpoint or import rank publishes.
///
/// `Macro` is Rust's alone. A `macro_rules!` item is a source-order binder
/// (textual scope), and rustc resolves a single-segment macro name in textual
/// scope first: a visible `macro_rules!` beats every import, glob or named,
/// of the scope (checked with rustc 1.97), and a macro-expanded definition
/// cannot shadow it (E0659). Without a macro rank on the checkpoint
/// continuation, the binder did not shadow that continuation, so a glob from
/// an unindexed crate kept its open boundary beside the found macro.
const EFFECTIVE_NAMESPACES: [ResolutionNamespace; 5] = [
    ResolutionNamespace::Type,
    ResolutionNamespace::Value,
    ResolutionNamespace::Callable,
    ResolutionNamespace::Constructor,
    ResolutionNamespace::Macro,
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

pub(super) fn go_spelling_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
    activation_start: Option<usize>,
    ordinal: u32,
) -> Vec<PrecedenceStep> {
    use super::local_identity::GoSpellingChoiceAuthority;
    let authority = GoSpellingChoiceAuthority {
        scope,
        activation_start,
    };
    let identity = go_spelling_choice_identity(scope, activation_start);
    let semantic = identities.semantic(identity);
    vec![identities.register_go_spelling_choice(precedence_step(semantic, ordinal), authority)]
}

fn go_spelling_choice_identity(
    scope: ResolutionScopeId,
    activation_start: Option<usize>,
) -> ResolutionSemanticIdentity {
    match activation_start {
        None => ResolutionSemanticIdentity::fragment_local(local_digest(
            b"bifrost-go-spelling-scope-choice:v1",
            &[("scope", &u32_bytes(scope.get()))],
        )),
        Some(position) => ResolutionSemanticIdentity::fragment_local(local_digest(
            b"bifrost-go-spelling-checkpoint-choice:v1",
            &[
                ("scope", &u32_bytes(scope.get())),
                ("position", &usize_bytes(position)),
            ],
        )),
    }
}

/// A Java compilation unit's placement boundary is the external-root edge of
/// its choice: every enumerated continuation of the unit (single-type imports,
/// the unit's own package, on-demand imports) is a nearer binder than the
/// unindexed inventory beyond it. A witness found through any of those
/// continuations therefore discharges the boundary terminal, while a lookup
/// that no continuation answers keeps it. Ranking the boundary at the unit's
/// lexical outward rank instead made it shadow every import-tier
/// continuation, so no Java answer that crossed its compilation unit could
/// ever become complete (2026-09-29). Rust states this boundary only for a
/// cfg-gated `mod name;` whose attachment is genuinely unknown, and Go's
/// package authority is still being established, so both keep the lexical
/// outward rank until their own evidence justifies the change.
fn placement_boundary_precedence(
    identities: &mut ResolutionIdentityCatalogBuilder,
    scope: ResolutionScopeId,
) -> Vec<PrecedenceStep> {
    EFFECTIVE_NAMESPACES
        .into_iter()
        .map(|namespace| {
            let semantic = identities.semantic(scope_choice_identity(scope, namespace));
            identities.register_precedence_namespace(
                PrecedenceStep {
                    tier: PrecedenceTier::ExternalRoot,
                    ordinal: 0,
                    semantic,
                },
                namespace,
            )
        })
        .collect()
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
    if binder.superseded {
        // One rank below the outward continuation, which every scope timeline
        // and every parent link already publishes at rank 1 on this same
        // choice. A nearer declaration and an enclosing one both discharge
        // this binder; nothing else does, so the binder answers exactly where
        // the outward lookup proves empty.
        assert_ne!(
            timeline.fact.kind,
            ResolutionScopeKind::TypeBody,
            "a conditional binder is a pattern binder, never a type member: {binder:?}"
        );
        return vec![registered_precedence_step(
            identities,
            direct_choice,
            2,
            namespace,
        )];
    }
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
        // The prelude boundary is keyed at the shared root by one route head.
        // It says nothing about any positioned reference in this fragment.
        LoweringGapOrigin::ExternalPreludeBoundary => false,
        LoweringGapOrigin::Extracted(kind) => matches!(
            kind,
            ResolutionGapKind::UnprovenActivation
                | ResolutionGapKind::UnsupportedRoute
                | ResolutionGapKind::UnsupportedScopeOrBinder
                | ResolutionGapKind::AmbiguousQualifiedType
                | ResolutionGapKind::UnsupportedImplicitReceiver
                | ResolutionGapKind::UnsupportedCallApplicability
                | ResolutionGapKind::MalformedSyntax
        ),
    }
}

fn lexical_declaration_gap(origin: LoweringGapOrigin) -> bool {
    // A signature can have unresolved invocation requirements while its
    // declaration remains an exact lexical target. Calls read this evidence
    // through the callable signature; non-call references do not request it.
    origin != LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedCallApplicability)
        && lexical_gap(origin)
}

fn blocks_fragment(origin: LoweringGapOrigin) -> bool {
    match origin {
        LoweringGapOrigin::QualifiedReference
        | LoweringGapOrigin::UnsupportedActivation(_)
        | LoweringGapOrigin::MissingBinder
        | LoweringGapOrigin::ExternalPreludeBoundary => false,
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
                // The expansion adds impls beside the item. It does not change
                // the type of anything the item itself writes.
                | ResolutionGapKind::GeneratedItemSurface
        ),
        LoweringGapOrigin::QualifiedReference => true,
        LoweringGapOrigin::UnsupportedActivation(_)
        | LoweringGapOrigin::MissingBinder
        | LoweringGapOrigin::ExternalPreludeBoundary => false,
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
        matches!(
            scope_fact.kind,
            ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
        ) && (scope_fact.kind == ResolutionScopeKind::Package || scope_fact.parent.is_none()),
        "placement boundary gap must name a root CompilationUnit or Package attachment scope: {source:?}, {scope_fact:?}"
    );
    if scope_fact.kind == ResolutionScopeKind::Package
        && let Some(owner) = scope_fact.owner
    {
        let owner = index.site(owner);
        assert!(
            owner.kind == ResolutionSiteKind::ModuleDeclaration
                && Some(owner.scope) == scope_fact.parent,
            "an owned Package attachment scope needs a module declaration in its parent scope: {scope_fact:?}, owner={owner:?}"
        );
    }
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

/// The crates a language reaches through an implicit prelude rather than a
/// declared dependency edge.
///
/// Rust always has `std`, `core`, and `alloc` in the extern prelude of every
/// crate. Bifrost never mounts their source, so a route through one of these
/// heads reaches a boundary the build declares and no index covers. This is
/// the one boundary that one file's content decides on its own, which is what
/// lets it live in the content-addressed fragment. Whether a registry or git
/// dependency such as `serde` is mounted depends on the selected Cargo
/// manifests, so that boundary stays route-local in the selected context.
const fn implicit_prelude_crates(language: Language) -> &'static [&'static str] {
    match language {
        Language::Rust => &["alloc", "core", "std"],
        Language::Java
        | Language::Go
        | Language::Cpp
        | Language::JavaScript
        | Language::TypeScript
        | Language::Python
        | Language::Php
        | Language::Scala
        | Language::CSharp
        | Language::Ruby
        | Language::Kotlin
        | Language::None => &[],
    }
}

/// Retain each root import whose head names an implicit prelude crate as an
/// open boundary at the shared root.
///
/// The gap is keyed by the exact head lookup symbol, so it states that the
/// candidate inventory for that one name at the universal root is open. Every
/// other root lookup this fragment publishes stays exact, and no positioned
/// reference in the fragment is contaminated.
fn lower_external_prelude_boundary_gaps(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    index: &FactIndex<'_>,
) -> Vec<LoweredCoverageGap> {
    let prelude = implicit_prelude_crates(language);
    if prelude.is_empty() {
        return Vec::new();
    }
    let mut output = Vec::new();
    for import in &index.root_imports {
        let Some(&head) = import.segments.first() else {
            continue;
        };
        let head = index.name(head);
        if !prelude.contains(&head) {
            continue;
        }
        let reason_semantic = identities.semantic(gap_reason_semantic_identity(
            import.fact.site,
            LoweringGapOrigin::ExternalPreludeBoundary,
        ));
        for demand in &import.demands {
            let lookup = identities.lookup_semantic(language, demand.namespace, head);
            let frontier = LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Forward,
                endpoint: BindingNodeId::universal_root(),
                lookup: Some(lookup),
            };
            output.push(LoweredCoverageGap {
                digest: coverage_gap_digest(identities, reason_semantic, frontier),
                reason_semantic,
                site: import.fact.site,
                origin: LoweringGapOrigin::ExternalPreludeBoundary,
                frontier,
            });
        }
    }
    output
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
    let mut definitions_by_scope: HashMap<ResolutionScopeId, Vec<BindingNodeId>> =
        HashMap::default();
    for (&(site, role), &(_, node)) in semantics {
        if role == LoweredSemanticRole::Definition {
            definitions_by_scope
                .entry(index.site(site).scope)
                .or_default()
                .push(node);
        }
    }
    for &source in sources.all {
        let reason_semantic =
            identities.semantic(gap_reason_semantic_identity(source.site, source.origin));
        if !sources.point.contains(&source) {
            assert!(
                sources.enumeration.contains(&source),
                "a non-point coverage source must be owned by reference enumeration"
            );
            let frontier = LoweringCoverageFrontier::Enumeration;
            output.push(LoweredCoverageGap {
                digest: coverage_gap_digest(identities, reason_semantic, frontier),
                reason_semantic,
                site: source.site,
                origin: source.origin,
                frontier,
            });
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
                output.push(LoweredCoverageGap {
                    digest: coverage_gap_digest(identities, reason_semantic, frontier),
                    reason_semantic,
                    site: source.site,
                    origin: source.origin,
                    frontier,
                });
            }
            continue;
        }
        let mut frontiers = Vec::new();
        let is_positioned_reference =
            semantics.contains_key(&(source.site, LoweredSemanticRole::Reference));
        // A gap whose own site is a declaration publishes an exact, name-keyed
        // candidate gap further down: the scope's binder set is known and only
        // that one name's projection is open. Opening the whole scope as well
        // would make every unrelated lookup through it incomplete, which is
        // what left a read beside a block-local `fn` unproven even though the
        // read resolved exactly.
        let names_its_own_declaration = semantics
            .contains_key(&(source.site, LoweredSemanticRole::Definition))
            && lexical_declaration_gap(source.origin)
            && (!sources.deferred_members.contains(&source.site)
                || forward_gap_endpoints.contains_key(&source.site));
        if matches!(
            source.origin,
            LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnsupportedScopeOrBinder | ResolutionGapKind::MalformedSyntax
            )
        ) && !is_positioned_reference
        {
            if !names_its_own_declaration {
                // An omitted binder or damaged syntax can change lookup in its
                // lexical scope, not every file mounted in the selected
                // workspace. Import paths entering this scope still encounter
                // the wildcard candidate gap; enumeration retains the missing
                // source evidence.
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint: identities.source_scope_node(index.site(source.site).scope),
                    lookup: None,
                });
                // An exact export bridge may jump straight to a declaration.
                // Reverse lookup of that declaration must retain the scope's
                // omitted-binder boundary, even when the importing source lies
                // in another admitted fragment.
                for &definition in definitions_by_scope
                    .get(&index.site(source.site).scope)
                    .into_iter()
                    .flatten()
                {
                    frontiers.push(LoweringCoverageFrontier::Candidate {
                        direction: LoweredCandidateDirection::Reverse,
                        endpoint: definition,
                        lookup: None,
                    });
                }
            }
        } else if matches!(
            source.origin,
            LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnexpandedItemMacro | ResolutionGapKind::UnexpandedImplMacro
            )
        ) {
            // The forward reach is the lexical fallback branch and the member
            // branches `lower_unexpanded_item_macro_branches` publishes, not
            // the whole scope. The expansion can still use any declaration of
            // the scope, so their reverse inventory stays open.
            for &definition in definitions_by_scope
                .get(&index.site(source.site).scope)
                .into_iter()
                .flatten()
            {
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Reverse,
                    endpoint: definition,
                    lookup: None,
                });
            }
        } else if blocks_fragment(source.origin) && !is_positioned_reference {
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
        if source.origin == LoweringGapOrigin::QualifiedReference
            || (hierarchy_boundary_gap(source.origin)
                && index.hierarchy_gap_owner(source.site).is_some())
        {
            // The reference endpoints are known, so broad enumeration remains
            // sound. Qualified references and declaration-owned hierarchy
            // branches need typed reverse paths. A type-only frontier (such
            // as abstract Self) has no lexical hierarchy branch; its own
            // completion remains on the typed consumer instead.
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
            // The exact reference obligation is mandatory publication
            // provenance even when it does not constrain lexical paths.
            frontiers.push(LoweringCoverageFrontier::Reference { semantic, node });
            if index.lexical_reference_gap(source.site, source.origin) {
                frontiers.push(LoweringCoverageFrontier::Candidate {
                    direction: LoweredCandidateDirection::Forward,
                    endpoint: node,
                    lookup: None,
                });
            }
        }

        if let Some(&(_, definition_node)) =
            semantics.get(&(source.site, LoweredSemanticRole::Definition))
            && lexical_declaration_gap(source.origin)
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
            if let Some(slots) = index.type_slots_by_site.get(&source.site) {
                for &slot in slots {
                    frontiers.push(LoweringCoverageFrontier::Type {
                        frontier: identities.semantic(type_slot_semantic_identity(slot)),
                    });
                }
            } else if frontiers.is_empty() {
                // Completion only asks about real type slots, so a slotless site needs no
                // type frontier. But resolution_gap_reasons and stage gap rows derive
                // provenance from coverage rows, so keep this row to publish reason, site,
                // and origin.
                frontiers.push(LoweringCoverageFrontier::Type {
                    frontier: identities
                        .semantic(site_type_frontier_semantic_identity(source.site)),
                });
            }
        }

        frontiers.sort_unstable();
        frontiers.dedup();
        for frontier in frontiers {
            output.push(LoweredCoverageGap {
                digest: coverage_gap_digest(identities, reason_semantic, frontier),
                reason_semantic,
                site: source.site,
                origin: source.origin,
                frontier,
            });
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

pub(crate) fn reference_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> SemanticId {
    identities.semantic(reference_semantic_identity(site))
}

/// The semantic of one site, read from the numbering rather than a catalog.
///
/// Site `n`'s semantic occupies catalog position `n`
/// (`ResolutionIdentityCatalogBuilder::finish` reserves it, filler and all),
/// and a local id is its mount's ordinal and its catalog position, so a reader
/// that holds the mount and the site number has the semantic without asking
/// anything. This is what the schema's numbering buys, and it is why a reader
/// outside the lowering no longer needs a mounted-identity helper per role:
/// the site carries one role, which `lower_file_resolution_facts_with_identities`
/// asserts for every language.
pub(crate) fn site_semantic(fragment: BindingFragmentId, site: ResolutionSiteId) -> SemanticId {
    SemanticId::local(fragment.ordinal(), site.get())
}

pub(super) fn reference_semantic_identity(site: ResolutionSiteId) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-reference-semantic-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

/// The runtime semantic one mount gives the site numbered `site`.
///
/// `ResolutionIdentityCatalogBuilder::finish` numbers site `n`'s semantic at
/// catalog position `n` and site `n`'s node at node position `n`, for every
/// language, and asserts both. A local identity is the mount ordinal and the
/// catalog position, so a site's semantic and node are a pure function of the
/// mount and the site number again, with no catalog to open. A site that
/// mints neither holds its position with a filler, so the answer is still
/// that site's own number and never another site's.
pub(crate) fn mounted_site_semantic(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
) -> SemanticId {
    SemanticId::local(fragment.ordinal(), site_catalog_position(site))
}

/// The runtime node one mount gives the site numbered `site`. See
/// [`mounted_site_semantic`].
pub(crate) fn mounted_site_node(
    fragment: BindingFragmentId,
    site: ResolutionSiteId,
) -> BindingNodeId {
    BindingNodeId::local(fragment.ordinal(), site_catalog_position(site))
}

fn site_catalog_position(site: ResolutionSiteId) -> u32 {
    u32::try_from(site.index())
        .unwrap_or_else(|_| panic!("a site ordinal is a catalog position and fits u32: {site:?}"))
}

pub(crate) fn definition_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> SemanticId {
    identities.semantic(definition_semantic_identity(site))
}

pub(super) fn definition_semantic_identity(site: ResolutionSiteId) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-definition-semantic-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(super) fn type_slot_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    slot: ResolutionTypeSlotId,
) -> SemanticId {
    identities.semantic(type_slot_semantic_identity(slot))
}

pub(super) fn type_slot_semantic_identity(
    slot: ResolutionTypeSlotId,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-type-slot-semantic-local:v2",
        &[("slot", &u32_bytes(slot.get()))],
    ))
}

pub(crate) fn site_type_frontier_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> SemanticId {
    identities.semantic(site_type_frontier_semantic_identity(site))
}

pub(super) fn site_type_frontier_semantic_identity(
    site: ResolutionSiteId,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-site-type-frontier-semantic-local:v2",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(crate) fn lookup_semantic(
    names: &dyn super::local_identity::SharedNameInterner,
    language: Language,
    namespace: ResolutionNamespace,
    spelling: &str,
) -> SemanticId {
    ResolutionLookupSemanticRecipe::new(language, namespace, spelling).semantic(names)
}

pub(crate) fn root_import_token(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(root_import_token_identity(site, namespace))
}

pub(crate) fn root_import_anchor_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    anchor: ResolutionRootImportAnchor,
) -> SemanticId {
    identities.semantic(root_import_anchor_semantic_identity(anchor))
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
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(root_reference_token_identity(site, namespace))
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
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    root_scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(root_export_token_identity(root_scope, namespace))
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

pub(super) fn scope_choice(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(scope_choice_identity(scope, namespace))
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

fn checkpoint_choice(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
    position: usize,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(checkpoint_choice_identity(scope, position, namespace))
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

fn hierarchy_choice(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
    namespace: ResolutionNamespace,
) -> SemanticId {
    identities.semantic(hierarchy_choice_identity(scope, namespace))
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

pub(super) fn reference_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> BindingNodeId {
    identities.node(reference_node_identity(site))
}

pub(crate) fn reference_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-reference-node-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(crate) fn definition_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> BindingNodeId {
    identities.node(definition_node_identity(site))
}

pub(crate) fn definition_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-definition-node-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

/// The semantic that holds the catalog position of a site that mints none.
///
/// Site `n`, its semantic and its node carry one number, so catalog position
/// `n` belongs to site `n` whether or not the site has a semantic. About a
/// quarter of a blob's sites are expression sites with no positioned
/// identifier (measured over two corpora in
/// `.agents/docs/stack-graph-numbering-lane-2026-09-18.md`); they mint no
/// semantic and no node, and these fillers keep their positions occupied so
/// that every other site is still its own number.
pub(super) fn site_filler_semantic_identity(site: ResolutionSiteId) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::fragment_local(local_digest(
        b"bifrost-resolution-site-filler-semantic-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

/// The node that holds the catalog position of a site that mints none. See
/// [`site_filler_semantic_identity`].
pub(super) fn site_filler_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-site-filler-node-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(crate) fn scope_head_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
) -> BindingNodeId {
    identities.node(scope_head_node_identity(scope))
}

pub(crate) fn scope_head_node_identity(scope: ResolutionScopeId) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-scope-head-node-local:v1",
        &[("scope", &u32_bytes(scope.get()))],
    ))
}

fn checkpoint_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
    position: usize,
) -> BindingNodeId {
    identities.node(checkpoint_node_identity(scope, position))
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

fn gap_sink_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    role: &[u8],
) -> BindingNodeId {
    identities.node(gap_sink_node_identity(site, role))
}

pub(crate) fn hierarchy_terminal_node_identity(site: ResolutionSiteId) -> ResolutionNodeIdentity {
    gap_sink_node_identity(site, b"hierarchy-terminal")
}

fn gap_sink_node_identity(site: ResolutionSiteId, role: &[u8]) -> ResolutionNodeIdentity {
    ResolutionNodeIdentity::new(local_digest(
        b"bifrost-resolution-gap-sink-node-local:v1",
        &[("site", &u32_bytes(site.get())), ("role", role)],
    ))
}

fn structured_import_gap_sink_node(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> BindingNodeId {
    identities.node(structured_import_gap_sink_node_identity(site, namespace))
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

fn timeline_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
    position: usize,
) -> PartialPathId {
    identities.path(timeline_path_identity(scope, position))
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

fn parent_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    scope: ResolutionScopeId,
) -> PartialPathId {
    identities.path(parent_path_identity(scope))
}

fn parent_path_identity(scope: ResolutionScopeId) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-parent-path-local:v2",
        &[("scope", &u32_bytes(scope.get()))],
    ))
}

pub(super) fn reference_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> PartialPathId {
    identities.path(reference_path_identity(site, namespace))
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

pub(super) fn reference_gap_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> PartialPathId {
    identities.path(reference_gap_path_identity(site))
}

fn reference_gap_path_identity(site: ResolutionSiteId) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-reference-gap-path-local:v1",
        &[("site", &u32_bytes(site.get()))],
    ))
}

pub(super) fn binder_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> PartialPathId {
    identities.path(binder_path_identity(site))
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
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    name: ResolutionNameId,
) -> PartialPathId {
    identities.path(root_import_path_identity(site, namespace, name))
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
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> PartialPathId {
    identities.path(root_reference_path_identity(site, namespace))
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
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    root_scope: ResolutionScopeId,
    declaration: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> PartialPathId {
    identities.path(root_export_path_identity(
        root_scope,
        declaration,
        namespace,
    ))
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

pub(crate) fn placement_gap_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    scope: ResolutionScopeId,
) -> PartialPathId {
    identities.path(placement_gap_path_identity(site, scope))
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

pub(crate) fn structured_import_gap_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
) -> PartialPathId {
    identities.path(structured_import_gap_path_identity(site, namespace))
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

/// The branches the unexpanded item-position macros of one scope leave,
/// reaching exactly what their expansions can change by Rust's rules.
///
/// A bare lookup in the scope takes an incomplete fallback branch ranked with
/// the scope's glob imports. A local declaration of the scope outranks it at
/// the scope's choice point, and a named import at the scope's import choice
/// point, and either discharges it: an expansion declaring that name again
/// would be a duplicate definition. A name the scope does not bind that way --
/// one a glob import, an enclosing scope or the prelude supplies, or none at
/// all -- keeps the branch, because an expansion can shadow the first three
/// and declare the last.
///
/// Each type the scope declares takes an incomplete member branch at its body,
/// ranked with the type's hierarchy, as an unsupported supertype does: an
/// expansion can add impls to the type, so a member lookup on it keeps the
/// branch unless the type's own body answers.
///
/// Every invocation of the scope reaches the same names at the same rank, so
/// the scope has one fallback branch and one member branch per type, and each
/// carries every invocation's reason. A branch per invocation answered the
/// same lookup once for each invocation: a module with eighteen invocations
/// made every bare lookup through it walk eighteen copies of one branch.
fn lower_unexpanded_item_macro_branches(
    identities: &mut ResolutionIdentityCatalogBuilder,
    index: &FactIndex<'_>,
    scope: ResolutionScopeId,
    sources: &[GapSource],
    nodes: &mut Vec<(BindingNodeId, BindingNodeKind)>,
    paths: &mut Vec<(PartialPathId, PartialPath)>,
) {
    let first = sources
        .iter()
        .map(|source| source.site)
        .min()
        .expect("a scope with an unexpanded item macro has its invocation");
    let reason = ResolutionCompletion::incomplete(sources.iter().map(|source| {
        ResolutionIncompleteReason::UnsupportedSemantic(
            identities.semantic(gap_reason_semantic_identity(source.site, source.origin)),
        )
    }));
    let sink = identities.node(gap_sink_node_identity(first, b"unexpanded-item-macro"));
    nodes.push((sink, BindingNodeKind::Scope));
    let id = identities.path(unexpanded_item_macro_path_identity(first, None));
    let variable = passthrough_variable(identities, id);
    // Ranked as a glob import of the scope (`root_import_precedence`).
    let mut precedence = Vec::with_capacity(EFFECTIVE_NAMESPACES.len() * 2);
    for namespace in EFFECTIVE_NAMESPACES {
        let scope_choice = identities.semantic(scope_choice_identity(scope, namespace));
        precedence.push(registered_precedence_step(
            identities,
            scope_choice,
            1,
            namespace,
        ));
        let import_choice = identities.semantic(import_choice_identity(scope, namespace));
        precedence.push(registered_precedence_step(
            identities,
            import_choice,
            RUST_GLOB_IMPORT_RANK,
            namespace,
        ));
    }
    paths.push((
        id,
        PartialPath::new(
            open_endpoint(identities.source_scope_node(scope), variable),
            open_endpoint(sink, variable),
            precedence,
            [WitnessStep::Node(sink)],
            reason.clone(),
        ),
    ));
    let mut owners = index
        .type_body_scope_by_owner
        .iter()
        .filter(|(owner, _)| index.site(**owner).scope == scope)
        .map(|(owner, body)| (*owner, *body))
        .collect::<Vec<_>>();
    owners.sort_unstable_by_key(|(owner, _)| *owner);
    for (owner, body) in owners {
        let mut role = b"unexpanded-item-macro-member:".to_vec();
        role.extend_from_slice(&u32_bytes(owner.get()));
        let sink = identities.node(gap_sink_node_identity(first, &role));
        nodes.push((sink, BindingNodeKind::Scope));
        let id = identities.path(unexpanded_item_macro_path_identity(first, Some(owner)));
        let variable = passthrough_variable(identities, id);
        paths.push((
            id,
            PartialPath::new(
                open_endpoint(identities.source_scope_node(body.id), variable),
                open_endpoint(sink, variable),
                type_body_hierarchy_precedence(identities, body.id),
                [WitnessStep::Node(sink)],
                reason.clone(),
            ),
        ));
    }
}

fn unexpanded_item_macro_path_identity(
    site: ResolutionSiteId,
    owner: Option<ResolutionSiteId>,
) -> ResolutionPathIdentity {
    let owner = owner.map_or(u32::MAX, ResolutionSiteId::get);
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-unexpanded-item-macro-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("owner", &u32_bytes(owner)),
        ],
    ))
}

pub(super) fn placement_gap_lexical_row_with_identities(
    identities: &mut ResolutionIdentityCatalogBuilder,
    language: Language,
    site: ResolutionSiteId,
    scope: ResolutionScopeId,
) -> (BindingNodeId, (PartialPathId, PartialPath)) {
    let sink = identities.node(gap_sink_node_identity(site, b"placement-terminal"));
    let id = identities.path(placement_gap_path_identity(site, scope));
    let variable = passthrough_variable(identities, id);
    let scope_head = identities.source_scope_node(scope);
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
                if language == Language::Java {
                    placement_boundary_precedence(identities, scope)
                } else {
                    scope_fallback_precedence(identities, scope)
                },
                [WitnessStep::Node(sink)],
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(reason),
                ]),
            ),
        ),
    )
}

pub(super) fn structured_import_gap_lexical_row(
    fragment: BindingFragmentId,
    names: &dyn super::local_identity::SharedNameInterner,
    root_scope: ResolutionScopeId,
    site: ResolutionSiteId,
    namespace: ResolutionNamespace,
    bound_name: &str,
) -> (BindingNodeId, (PartialPathId, PartialPath)) {
    let mut identities = ResolutionIdentityCatalogBuilder::new(fragment, names);
    structured_import_gap_lexical_row_with_identities(
        &mut identities,
        root_scope,
        site,
        namespace,
        bound_name,
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
    let root = identities.source_scope_node(root_scope);
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

fn hierarchy_gap_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    owner: ResolutionSiteId,
) -> PartialPathId {
    identities.path(hierarchy_gap_path_identity(site, owner))
}

/// The methods `java.lang.Object` declares (JLS 4.3.2). `wait` has three
/// overloads under one name.
const JAVA_OBJECT_METHOD_NAMES: [&str; 9] = [
    "getClass",
    "hashCode",
    "equals",
    "clone",
    "toString",
    "notify",
    "notifyAll",
    "wait",
    "finalize",
];

fn implicit_object_hierarchy_path_identity(
    site: ResolutionSiteId,
    owner: ResolutionSiteId,
    name: &str,
) -> ResolutionPathIdentity {
    ResolutionPathIdentity::new(local_digest(
        b"bifrost-resolution-implicit-object-hierarchy-path-local:v1",
        &[
            ("site", &u32_bytes(site.get())),
            ("owner", &u32_bytes(owner.get())),
            ("name", name.as_bytes()),
        ],
    ))
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

fn missing_binder_path_id(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
) -> PartialPathId {
    identities.path(missing_binder_path_identity(site))
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

pub(crate) fn gap_reason_semantic(
    identities: &mut ResolutionIdentityCatalogBuilder<'_>,
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
) -> SemanticId {
    identities.semantic(gap_reason_semantic_identity(site, origin))
}

pub(super) fn gap_reason_semantic_identity(
    site: ResolutionSiteId,
    origin: LoweringGapOrigin,
) -> ResolutionSemanticIdentity {
    ResolutionSemanticIdentity::gap_reason(local_digest(
        b"bifrost-resolution-lowering-gap-reason-local:v2",
        &[
            ("site", &u32_bytes(site.get())),
            ("origin", gap_origin_label(origin)),
        ],
    ))
}

/// The content identity of one gap inside its lowering. It is a digest, not a
/// registered semantic: nothing reads a gap by catalog identity, and a catalog
/// row per gap was the widest index the writer maintained (#3737).
fn coverage_gap_digest(
    identities: &ResolutionIdentityCatalogBuilder,
    reason_semantic: SemanticId,
    frontier: LoweringCoverageFrontier,
) -> [u8; 32] {
    let reason = identities
        .semantic_identity(reason_semantic)
        .expect("coverage-gap reason semantic must be registered first");
    assert_eq!(
        reason.space(),
        super::local_identity::ResolutionSemanticIdentitySpace::FragmentLocal,
        "coverage-gap reason semantic must be fragment-local"
    );
    let frontier_digest = coverage_frontier_local_digest(identities, frontier);
    local_digest(
        b"bifrost-resolution-lowering-coverage-gap-local:v2",
        &[
            ("reason", &reason.fragment_local_digest()),
            ("frontier", &frontier_digest),
        ],
    )
}

fn gap_origin_label(origin: LoweringGapOrigin) -> &'static [u8] {
    match origin {
        LoweringGapOrigin::Extracted(kind) => match kind {
            ResolutionGapKind::UnsupportedTypeSyntax => b"extracted:unsupported-type-syntax",
            ResolutionGapKind::UnsupportedExpression => b"extracted:unsupported-expression",
            ResolutionGapKind::UnsupportedRoute => b"extracted:unsupported-route",
            ResolutionGapKind::UnprovenActivation => b"extracted:unproven-activation",
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
            ResolutionGapKind::GeneratedItemSurface => b"extracted:generated-item-surface",
            ResolutionGapKind::MacroArgument => b"extracted:macro-argument",
            ResolutionGapKind::UnexpandedItemMacro => b"extracted:unexpanded-item-macro",
            ResolutionGapKind::UnexpandedImplMacro => b"extracted:unexpanded-impl-macro",
        },
        LoweringGapOrigin::QualifiedReference => b"lowering:qualified-reference",
        LoweringGapOrigin::UnsupportedActivation(hoisting) => match hoisting {
            HoistingClass::SourceOrder => b"lowering:activation:source-order",
            HoistingClass::ScopeWide => b"lowering:activation:scope-wide",
            HoistingClass::DeclaredHead => b"lowering:activation:declared-head",
        },
        LoweringGapOrigin::MissingBinder => b"lowering:missing-binder",
        LoweringGapOrigin::ExternalPreludeBoundary => b"lowering:external-prelude-boundary",
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
            hasher.field("semantic", &identities.identity_hash_bytes(semantic));
            hasher.field("node", &node.digest());
        }
        LoweringCoverageFrontier::Candidate {
            direction,
            endpoint,
            lookup,
        } => {
            hasher.field("kind", b"candidate");
            hasher.field("direction", candidate_direction_label(direction));
            // The universal root is the shared boundary every fragment reaches.
            // It has no fragment-local node identity, so it is named directly.
            if endpoint == BindingNodeId::universal_root() {
                hasher.field("endpoint", b"universal-root");
            } else {
                let endpoint = identities
                    .node_identity(endpoint)
                    .expect("coverage candidate endpoint must be registered first");
                hasher.field("endpoint", &endpoint.digest());
            }
            if let Some(lookup) = lookup {
                let lookup = identities
                    .semantic_identity(lookup)
                    .expect("coverage candidate lookup must be registered first");
                hasher.field("lookup_space", semantic_space_label(lookup.space()));
                hasher.field("lookup", &identities.identity_hash_bytes(lookup));
            }
        }
        LoweringCoverageFrontier::Type { frontier } => {
            hasher.field("kind", b"type");
            let frontier = identities
                .semantic_identity(frontier)
                .expect("coverage type frontier must be registered first");
            hasher.field("frontier_space", semantic_space_label(frontier.space()));
            hasher.field("frontier", &identities.identity_hash_bytes(frontier));
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

#[cfg(test)]
mod tests {
    use super::fixture_names::{
        additional_binder_path_id, binder_path_id, checkpoint_choice, gap_reason_semantic,
        hierarchy_choice, hierarchy_gap_path_id, missing_binder_path_id, parent_path_id,
        placement_gap_path_id, reference_node, root_export_token, root_import_anchor_semantic,
        root_import_token, root_reference_token, scope_choice, scope_head_node,
        site_type_frontier_semantic, type_slot_semantic,
    };

    use brokk_bifrost_core::analyzer::resolution_facts::{
        PositionedIdentifierFact, ResolutionAdditionalDefinitionNamespaceFact,
        ResolutionBinderFact, ResolutionBinderKind, ResolutionCallFact,
        ResolutionCallableReceiverOriginFact, ResolutionGapFact, ResolutionIdentifierRole,
        ResolutionMemberAccess, ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility,
        ResolutionNameFact, ResolutionReferenceEnumerationGapFact, ResolutionReferenceOwnerFact,
        ResolutionScopeKind, ResolutionSiteKind, ResolutionSupertypeFact, ResolutionSupertypeKind,
        ResolutionTypeSlotFact, ResolutionTypeSlotRole,
    };

    use crate::CancellationToken;

    use super::super::batch::{BatchResolutionEngine, BatchResolutionFragmentSource};
    use super::super::engine::{ResolutionEngine, ResolutionQuery};
    use super::super::local_identity::{
        MountRebaser, ResolutionSemanticIdentitySpace, SelectedResolutionMountOrdinal,
        SelectedSemanticProvenance,
    };
    use super::super::lower_resolution_facts_with_identity_catalog;
    use super::*;

    fn fragment() -> BindingFragmentId {
        BindingFragmentId::for_test(b"fact-lowering-test-fragment")
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
                    inheritance: ResolutionScopeInheritance::Lexical,
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
                prefix_reference: None,
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
    fn root_routes_are_source_owned_anchored_and_remount_provisional_to_final() {
        let facts = root_route_facts();
        let provisional = BindingFragmentId::for_test(b"root-route-provisional");
        let final_fragment = BindingFragmentId::for_test(b"root-route-final");
        let provisional_artifact =
            crate::analyzer::resolution::lower_for_test(provisional, Language::Go, &facts);
        let final_artifact =
            crate::analyzer::resolution::lower_for_test(final_fragment, Language::Go, &facts);
        let provisional_again =
            crate::analyzer::resolution::lower_for_test(provisional, Language::Go, &facts);
        let final_again =
            crate::analyzer::resolution::lower_for_test(final_fragment, Language::Go, &facts);
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
        let reference = ResolutionSiteId::new(2);
        let namespace = ResolutionNamespace::Type;
        let expected_shared_route = ["example.com", "repo", "dep"].map(|spelling| {
            lookup_semantic(
                crate::analyzer::resolution::test_shared_names(),
                Language::Go,
                namespace,
                spelling,
            )
        });
        let expected_lookup = lookup_semantic(
            crate::analyzer::resolution::test_shared_names(),
            Language::Go,
            namespace,
            "Item",
        );

        let inspect = |artifact: &super::super::LoweredResolutionFactsWithIdentityCatalog,
                       mounted_fragment| {
            let import_token = root_import_token(mounted_fragment, import_site, namespace);
            let export_token = root_export_token(mounted_fragment, root_scope, namespace);
            let (import_id, import_path) = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| {
                    path.end()
                        .symbols()
                        .fixed()
                        .iter()
                        .any(|symbol| symbol.symbol() == import_token)
                        .then_some((*id, path))
                })
                .expect("source-owned root import path");
            let (export_id, export_path) = artifact
                .lexical()
                .paths()
                .iter()
                .find_map(|(id, path)| {
                    path.start()
                        .symbols()
                        .fixed()
                        .iter()
                        .any(|symbol| symbol.symbol() == export_token)
                        .then_some((*id, path))
                })
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
                    tier: PrecedenceTier::LexicalBinding,
                    ordinal: 0,
                    semantic: artifact
                        .identities()
                        .semantic_for_identity(go_spelling_choice_identity(root_scope, None))
                        .expect("Go dot import uses its lexical spelling choice"),
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

            let reference_token = root_reference_token(mounted_fragment, reference, namespace);
            let mut reference_paths = artifact.lexical().paths().iter().filter_map(|(_, path)| {
                (path.start().node() == reference_node(mounted_fragment, reference)).then_some(path)
            });
            let reference_path = reference_paths
                .next()
                .expect("source-owned direct root reference path");
            assert!(
                reference_paths.next().is_none(),
                "a direct root reference must not retain a lexical decoy route"
            );
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
            let import_identity = catalog
                .path_identity(import_id)
                .expect("dense root-import path identity");
            let export_identity = catalog
                .path_identity(export_id)
                .expect("dense root-export path identity");
            assert_ne!(import_identity, export_identity);
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

        let mut rebaser = MountRebaser::new();
        let ordinal = SelectedResolutionMountOrdinal::new(final_fragment.ordinal());
        let mount = rebaser.register_mount(ordinal);
        assert!(rebaser.register_identity_catalog(
            ordinal,
            final_artifact.identities(),
            &CancellationToken::new(),
        ));
        let SelectedSemanticProvenance::FragmentLocal(provenance) = rebaser
            .registered_semantic_provenance(final_rows.0)
            .expect("mounted root-import token provenance")
        else {
            panic!("root-import token lost fragment-local provenance")
        };
        assert_eq!(provenance.mount(), mount);
        assert_eq!(
            provenance.identity(),
            root_import_token_identity(import_site, namespace)
        );
        assert_eq!(
            rebaser.registered_semantic_provenance(expected_shared_route[0]),
            Some(SelectedSemanticProvenance::Shared(
                ResolutionLookupSemanticRecipe::new(Language::Go, namespace, "example.com")
                    .identity(crate::analyzer::resolution::test_shared_names()),
            ))
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
            crate::analyzer::resolution::lower_for_test(final_fragment, Language::Go, &permuted);
        assert_same_artifact(&final_artifact, &permuted);
    }

    #[test]
    fn root_route_fact_index_rejects_sparse_ambiguous_or_unowned_rows() {
        let rejected = |mutate: fn(&mut FileResolutionFacts)| {
            let mut facts = root_route_facts();
            mutate(&mut facts);
            std::panic::catch_unwind(|| {
                let _ = crate::analyzer::resolution::lower_lexical_for_test(
                    fragment(),
                    Language::Go,
                    &facts,
                )
                .0;
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
    fn go_root_reference_lowers_both_type_or_value_routes() {
        let facts = root_route_facts();
        let mut ambiguous_facts = facts.clone();
        ambiguous_facts.names.push(ResolutionNameFact {
            id: ResolutionNameId::new(4),
            spelling: "model".to_owned(),
        });
        ambiguous_facts
            .sites
            .push(site(3, 1, ResolutionSiteKind::ValueReference, 30));
        ambiguous_facts.identifiers.push(PositionedIdentifierFact {
            site: ResolutionSiteId::new(3),
            name: ResolutionNameId::new(4),
            role: ResolutionIdentifierRole::Reference,
            namespace: ResolutionNamespace::TypeOrValue,
            qualifier: None,
        });
        ambiguous_facts.root_references[0].anchor = ResolutionRootImportAnchor::Lexical;
        ambiguous_facts.root_references[0].prefix_reference = Some(ResolutionSiteId::new(3));
        ambiguous_facts.root_reference_segments = vec![ResolutionRootReferenceSegmentFact {
            reference: ResolutionSiteId::new(2),
            position: 0,
            name: ResolutionNameId::new(4),
        }];
        ambiguous_facts
            .identifiers
            .iter_mut()
            .find(|identifier| identifier.site == ResolutionSiteId::new(2))
            .expect("root reference fixture identifier")
            .namespace = ResolutionNamespace::TypeOrValue;
        let (ambiguous, identities) = crate::analyzer::resolution::lower_lexical_for_test(
            fragment(),
            Language::Go,
            &ambiguous_facts,
        );
        for namespace in [ResolutionNamespace::Value, ResolutionNamespace::Type] {
            let identity = root_reference_path_identity(ResolutionSiteId::new(2), namespace);
            assert!(
                ambiguous
                    .paths()
                    .iter()
                    .any(|(path, _)| { identities.path_identity(*path) == Some(identity) }),
                "Go root terminal keeps its {namespace:?} route"
            );
        }
        let anchors = super::super::selected_context::CatalogRootImportAnchors::new(&identities);
        let reference_halves = ambiguous
            .paths()
            .iter()
            .filter_map(|(path, partial)| {
                super::super::selected_context::classify_selected_root_path_half(
                    &anchors,
                    super::super::batch::CandidatePathIdentity::new(fragment(), *path),
                    partial,
                    &crate::CancellationToken::default(),
                )
                .expect("catalog answers its own root import anchors")
            })
            .filter_map(|half| match half {
                super::super::selected_context::SelectedRootPathHalf::Reference {
                    prefix_reference: Some(_),
                    route,
                    ..
                } => Some(route),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(reference_halves.len(), 2);
        assert!(reference_halves.iter().all(|route| route.is_empty()));
        assert!(
            std::panic::catch_unwind(|| {
                let _ = crate::analyzer::resolution::lower_lexical_for_test(
                    fragment(),
                    Language::Java,
                    &ambiguous_facts,
                );
            })
            .is_err()
        );
    }

    #[test]
    fn root_import_accepts_an_owned_package_attachment_scope() {
        let mut facts = root_route_facts();
        facts.scopes[1].owner = Some(ResolutionSiteId::new(1));

        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Go, &facts).0;
        assert!(!lowered.paths().is_empty());
    }

    #[test]
    fn nested_variable_recipe_rebases_exactly() {
        let fragments = [
            BindingFragmentId::for_test(b"nested-identity-a"),
            BindingFragmentId::for_test(b"nested-identity-b"),
        ];
        let lowered = fragments.map(|fragment| {
            let mut identities = ResolutionIdentityCatalogBuilder::new(
                fragment,
                crate::analyzer::resolution::test_shared_names(),
            );
            let path = identities.path(timeline_path_identity(ResolutionScopeId::new(7), 11));
            let variable = passthrough_variable(&mut identities, path);
            let semantic = identities.source_reference_semantic(ResolutionSiteId::new(13));
            let node = identities.source_reference_node(ResolutionSiteId::new(13));
            let reason = identities.semantic(gap_reason_semantic_identity(
                ResolutionSiteId::new(13),
                LoweringGapOrigin::QualifiedReference,
            ));
            let gap = coverage_gap_digest(
                &identities,
                reason,
                LoweringCoverageFrontier::Reference { semantic, node },
            );
            (variable, gap, identities.finish())
        });

        let variable_identities = lowered.each_ref().map(|(variable, _, catalog)| {
            catalog
                .stack_variable_identity(*variable)
                .expect("registered passthrough variable")
        });
        assert_eq!(variable_identities[0], variable_identities[1]);
        assert_eq!(
            lowered[0].1, lowered[1].1,
            "a gap digest is content only and names no mount"
        );
        assert_eq!(
            variable_identities[0], variable_identities[1],
            "one content position, two mounts"
        );
        // The builder mints unmounted, so both fragments' ids are the same
        // number, which is the point: one content position. They separate
        // when each is spliced into its own mount, which is what the fixture
        // remount and the production mount splice both do.
        assert_eq!(lowered[0].0, lowered[1].0);
        assert_ne!(
            lowered[0].0.at_ordinal(fragments[0].ordinal()),
            lowered[1].0.at_ordinal(fragments[1].ordinal())
        );
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
            inheritance: ResolutionScopeInheritance::Lexical,
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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

        let requests = references.map(|(reference, node, _)| {
            super::super::batch::ReverseReferenceSeedRequest::new(reference, node)
        });
        let reverse = source
            .issue_reverse_reference_seeds(&requests, &cancellation)
            .expect("preloaded reverse seed issue");
        assert_eq!(reverse.len(), references.len());
        for (seed, (_, _, expected)) in reverse.iter().zip(references) {
            assert_eq!(seed.site_metadata(), Some(expected));
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
    fn deferred_member_signature_uncertainty_does_not_withhold_a_free_binder() {
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
        let (lowered, catalog) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Rust, &facts);
        // A local id is a catalog position, so an identity the lowering never
        // minted has no position at all; that absence is the assertion, and a
        // position that does exist must name no lowered path.
        assert!(
            catalog
                .path_for_identity(super::missing_binder_path_identity(ResolutionSiteId::new(
                    1
                )))
                .is_none_or(|missing| !lowered.paths().iter().any(|(id, _)| *id == missing))
        );
        assert!(lowered.gaps().iter().any(|gap| {
            gap.site() == ResolutionSiteId::new(1)
                && matches!(gap.frontier(), LoweringCoverageFrontier::Type { .. })
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
                crate::analyzer::resolution::lower_lexical_for_test(
                    fragment(),
                    Language::Rust,
                    &mismatched_hoisting,
                )
                .0
            })
            .is_err(),
            "definition namespace authority must match its binder hoisting"
        );

        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Rust, &facts)
                .0;
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        assert!(
            lowered
                .paths()
                .iter()
                .any(|(id, _)| *id == binder_path_id(fragment(), declaration)),
            "the primary binder path identity must remain stable"
        );
        assert!(lowered.paths().iter().any(|(id, _)| {
            *id == additional_binder_path_id(fragment(), declaration, ResolutionNamespace::Value)
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Rust, &facts)
                .0;
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
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: 10,
                    end_byte: 290,
                },
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(2),
                    parent: Some(ResolutionScopeId::new(1)),
                    owner: Some(ResolutionSiteId::new(1)),
                    kind: ResolutionScopeKind::TypeBody,
                    inheritance: ResolutionScopeInheritance::Lexical,
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
            | ResolutionNamespace::TypeOrValue
            | ResolutionNamespace::Package => ResolutionSiteKind::ValueReference,
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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

        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
            let lowered = crate::analyzer::resolution::lower_lexical_for_test(
                fragment(),
                Language::Java,
                &facts,
            )
            .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        // A choice's runtime id is the position it occupies in a catalog, and
        // this pin lowers nothing, so what it compares is the identities: one
        // per namespace, and a scope's never a checkpoint's.
        let scope_choices = EFFECTIVE_NAMESPACES
            .into_iter()
            .map(|namespace| scope_choice_identity(scope, namespace))
            .collect::<HashSet<_>>();
        let checkpoint_choices = EFFECTIVE_NAMESPACES
            .into_iter()
            .map(|namespace| checkpoint_choice_identity(scope, position, namespace))
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
        let expected =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
        facts.names.reverse();
        facts.scopes.reverse();
        facts.sites.reverse();
        facts.identifiers.reverse();
        facts.binders.reverse();
        facts.gaps.reverse();
        let actual =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Rust, &facts)
                .0;
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
        let reference = semantic(&lowered, 1, LoweredSemanticRole::Reference);
        let point = resolve_with_coverage(lowered.clone(), 1);
        assert_eq!(point.targets(), &[definition]);
        assert_eq!(point.completion(), &ResolutionCompletion::Complete);

        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let reverse = BatchResolutionEngine::new(&source)
            .references_to(definition, &CancellationToken::new())
            .expect("reverse member-scope lookup");
        assert_eq!(reverse.references(), &[reference]);
        assert!(matches!(
            reverse.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let _ =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
    fn implicit_receiver_gap_is_reference_local_without_reverse_poisoning() {
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
        assert!(
            lowered.gaps().iter().any(|gap| {
                matches!(gap.frontier(), LoweringCoverageFrontier::Reference { .. })
            })
        );
        assert!(
            !lowered
                .gaps()
                .iter()
                .any(|gap| matches!(gap.frontier(), LoweringCoverageFrontier::Type { .. }))
        );
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let definition = semantic(&lowered, 0, LoweredSemanticRole::Definition);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([lowered]);
        let answer = BatchResolutionEngine::new(&source)
            .references_to(definition, &CancellationToken::new())
            .expect("reverse qualified lookup");
        assert!(answer.references().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }

    #[test]
    fn pending_call_applicability_is_local_across_point_reverse_and_broad_reads() {
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
                extra_result_slots: Vec::new(),
                explicit_type_argument_count: 0,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(1),
                kind: ResolutionGapKind::UnsupportedCallApplicability,
            }],
            ..FileResolutionFacts::default()
        };
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let reverse = BatchResolutionEngine::new(&source)
            .references_to(definition, &CancellationToken::new())
            .expect("reverse callable lookup");
        assert_eq!(reverse.references().len(), 1);
        assert!(matches!(
            reverse.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
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
        let declaration_fragment = BindingFragmentId::for_test(b"placement-declaration");
        let reference_fragment = BindingFragmentId::for_test(b"placement-reference");
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
        let declaration = crate::analyzer::resolution::lower_lexical_for_test(
            declaration_fragment,
            Language::Java,
            &declaration_facts,
        )
        .0;
        let reference = crate::analyzer::resolution::lower_lexical_for_test(
            reference_fragment,
            Language::Java,
            &reference_facts,
        )
        .0;
        let definition = semantic(&declaration, 0, LoweredSemanticRole::Definition);
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
        let reverse = BatchResolutionEngine::new(&source)
            .references_to(definition, &CancellationToken::new())
            .expect("cross-fragment reverse lookup");
        assert!(reverse.references().is_empty());
        assert!(matches!(
            reverse.completion(),
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
        let local_fragment = BindingFragmentId::for_test(b"placement-local");
        let local = crate::analyzer::resolution::lower_lexical_for_test(
            local_fragment,
            Language::Java,
            &local_facts,
        )
        .0;
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
        expected = "placement boundary gap must name a root CompilationUnit or Package attachment scope"
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
        let _ =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
    }

    #[test]
    fn nested_module_package_is_an_exact_placement_attachment() {
        let module = ResolutionSiteId::new(0);
        let boundary = ResolutionSiteId::new(1);
        let package = ResolutionScopeId::new(1);
        let facts = FileResolutionFacts {
            scopes: vec![
                scope(0, None, 0, 100),
                ResolutionScopeFact {
                    id: package,
                    parent: Some(ResolutionScopeId::new(0)),
                    owner: Some(module),
                    kind: ResolutionScopeKind::Package,
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: 10,
                    end_byte: 90,
                },
            ],
            sites: vec![
                site(0, 0, ResolutionSiteKind::ModuleDeclaration, 5),
                site(1, 1, ResolutionSiteKind::UnsupportedRoute, 20),
            ],
            gaps: vec![ResolutionGapFact {
                site: boundary,
                kind: ResolutionGapKind::UnsupportedPlacementBoundary,
            }],
            ..FileResolutionFacts::default()
        };

        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Rust, &facts)
                .0;
        let placement = lowered
            .paths()
            .iter()
            .find(|(identity, _)| *identity == placement_gap_path_id(fragment(), boundary, package))
            .map(|(_, path)| path)
            .expect("nested module placement path");
        assert_eq!(
            placement.start().node(),
            scope_head_node(fragment(), package)
        );
        assert!(lowered.gaps().iter().any(|gap| {
            gap.origin()
                == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedPlacementBoundary)
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
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
                    inheritance: ResolutionScopeInheritance::Lexical,
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
                    inheritance: ResolutionScopeInheritance::Lexical,
                    start_byte: 10,
                    end_byte: 190,
                },
                ResolutionScopeFact {
                    id: ResolutionScopeId::new(2),
                    parent: Some(ResolutionScopeId::new(1)),
                    owner: Some(ResolutionSiteId::new(1)),
                    kind: ResolutionScopeKind::TypeBody,
                    inheritance: ResolutionScopeInheritance::Lexical,
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

        let (lowered, catalog) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts);
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
        // A fresh builder hands out provisional counters at the unmounted
        // ordinal, so it cannot restate what the artifact's catalog numbered.
        // What this pin is about is the sequence the helper produces: one
        // direct choice and one hierarchy choice per effective namespace, in
        // that order, at those ordinals. So it compares the identities the
        // steps carry, which the artifact's own catalog states.
        let expected_precedence = EFFECTIVE_NAMESPACES
            .into_iter()
            .flat_map(|namespace| {
                [
                    (
                        scope_choice_identity(ResolutionScopeId::new(2), namespace),
                        1_u32,
                    ),
                    (
                        hierarchy_choice_identity(ResolutionScopeId::new(2), namespace),
                        0,
                    ),
                ]
            })
            .collect::<Vec<_>>();
        assert_eq!(
            hierarchy_path
                .precedence()
                .iter()
                .map(|step| {
                    (
                        catalog
                            .semantic_identity(step.semantic)
                            .expect("a precedence step names this blob's own semantic"),
                        step.ordinal,
                    )
                })
                .collect::<Vec<_>>(),
            expected_precedence
        );
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
                    inheritance: ResolutionScopeInheritance::Lexical,
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
        let expected =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
            crate::analyzer::resolution::lower_lexical_for_test(
                fragment(),
                Language::Java,
                &permuted
            )
            .0,
            expected
        );
    }

    #[test]
    fn inherited_reference_gap_keeps_reverse_lookup_of_base_definition_incomplete() {
        let base_fragment = BindingFragmentId::for_test(b"hierarchy-base");
        let subclass_fragment = BindingFragmentId::for_test(b"hierarchy-subclass");
        let base_facts = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "member".into(),
            }],
            scopes: vec![scope(0, None, 0, 100)],
            sites: vec![site(0, 0, ResolutionSiteKind::CallableDeclaration, 1)],
            identifiers: vec![identifier(
                0,
                0,
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Callable,
            )],
            binders: vec![binder(
                0,
                0,
                ResolutionBinderKind::Callable,
                HoistingClass::ScopeWide,
                0,
                100,
            )],
            ..FileResolutionFacts::default()
        };
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
                    inheritance: ResolutionScopeInheritance::Lexical,
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
        let base = crate::analyzer::resolution::lower_lexical_for_test(
            base_fragment,
            Language::Java,
            &base_facts,
        )
        .0;
        let subclass = crate::analyzer::resolution::lower_lexical_for_test(
            subclass_fragment,
            Language::Java,
            &subclass_facts,
        )
        .0;
        assert!(subclass.gaps().iter().any(|gap| {
            gap.origin()
                == LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal)
                && gap.frontier()
                    == LoweringCoverageFrontier::CandidateInventory {
                        direction: LoweredCandidateDirection::Reverse,
                    }
        }));
        let definition = semantic(&base, 0, LoweredSemanticRole::Definition);
        let source =
            super::super::engine::PreloadedFragmentSource::from_lowered_fragments([base, subclass]);
        let reverse = BatchResolutionEngine::new(&source)
            .references_to(definition, &CancellationToken::new())
            .expect("inherited reverse lookup");
        assert!(reverse.references().is_empty());
        assert!(matches!(
            reverse.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let lowered =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts)
                .0;
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
        let (lowered, catalog) =
            crate::analyzer::resolution::lower_lexical_for_test(fragment(), Language::Java, &facts);
        // A local id is a catalog position, so an identity the lowering never
        // minted has no position at all; that absence is the assertion, and a
        // position that does exist must name no lowered path.
        assert!(
            catalog
                .path_for_identity(super::hierarchy_gap_path_identity(
                    ResolutionSiteId::new(3),
                    ResolutionSiteId::new(2),
                ))
                .is_none_or(|gap| lowered.paths().iter().all(|(id, _)| *id != gap)),
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
}
